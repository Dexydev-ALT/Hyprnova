// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 2b/2c — Filesystem Monitor, Entropy Analyser,
//                                    Mass-Modification Watchdog
//
// Two kernel mechanisms, used for what each is actually good at:
//
//   fanotify  -> reports the *pid* that touched a file, and with FAN_OPEN_PERM
//                can BLOCK the open before it happens. Needs CAP_SYS_ADMIN +
//                CAP_DAC_READ_SEARCH. This is the ransomware stopper.
//   inotify   -> reports the *path* and a rich event mask, recursively watchable
//                via per-directory watch descriptors, but has NO pid. Cheap,
//                unprivileged, and available everywhere.
//
// The agent runs both. fanotify supplies attribution and the blocking decision;
// inotify supplies breadth (whole download trees) and works when fanotify cannot
// be initialised. Neither is trusted alone: pid attribution without path breadth
// misses the sweep, and path breadth without pid cannot suspend the encryptor.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/fanotify.h>
#include <sys/inotify.h>

#include "anti_ransomware/canary.hpp"
#include "core/config.hpp"
#include "core/fd.hpp"
#include "core/sensor.hpp"

namespace hyprnova::anti_ransomware {

// ---------------------------------------------------------------------------
// Write-behaviour profile (feeds the entropy analyser)
// ---------------------------------------------------------------------------

struct WriteSample {
    core::SteadyClock::time_point when{};
    pid_t pid{0};
    std::string path;
    std::uint64_t bytes{0};
    double entropy{0.0};
    core::hash::FileFlavour flavour{core::hash::FileFlavour::Unknown};
    bool canary{false};
};

/// Sliding-window per-actor write profile. This is where "encrypted chunks over
/// structured personal files at rapid rates" is actually decided.
struct WriteProfile {
    pid_t pid{0};
    std::string exe;
    std::string comm;
    uid_t uid{0xFFFFFFFF};

    std::uint64_t total_writes{0};
    std::uint64_t total_bytes{0};
    std::uint64_t high_entropy_writes{0};
    std::uint64_t target_flavour_writes{0};   // documents/source/images/data/media
    std::uint64_t canary_writes{0};
    std::uint64_t distinct_files{0};
    std::unordered_set<std::string> unique_paths;
    std::deque<WriteSample> window;           // bounded by window duration
    double max_entropy{0.0};
    double mean_entropy{0.0};
    core::SteadyClock::time_point first_write{};
    core::SteadyClock::time_point last_write{};

    /// Files per second over the window: the rate that separates a backup job
    /// from an encryptor is usually an order of magnitude, not a few percent.
    [[nodiscard]] double files_per_second() const noexcept;
    [[nodiscard]] double high_entropy_ratio() const noexcept;
};

/// Shannon-entropy verdict for one write.
struct EntropyVerdict {
    bool suspicious{false};
    double entropy{0.0};
    double threshold{0.0};
    std::string reason;
    core::Severity severity{core::Severity::Info};
    /// 0..1000 contribution to the actor's cumulative risk score.
    std::uint16_t risk{0};
};

/// Analyse a buffer that a process just wrote.
///
/// `prior_entropy` is the entropy of the file *before* the write when known:
/// a low->high transition over a document flavour is the ransomware signature,
/// whereas a file that was already high-entropy (an archive being appended to)
/// is not.
[[nodiscard]] EntropyVerdict analyse_write(std::span<const std::byte> written,
                                           core::hash::FileFlavour flavour,
                                           const core::RansomwareConfig& cfg,
                                           double prior_entropy = -1.0) noexcept;

/// Detect a ransom note being dropped.
[[nodiscard]] bool looks_like_ransom_note(std::string_view path, std::string_view head_bytes,
                                          const core::RansomwareConfig& cfg) noexcept;

/// Detect the "delete my own shadow copies / backups" step. Linux analogue of
/// vssadmin delete shadows: recursive deletion of backup trees, wipefs, shred,
/// or truncation of /var/backups.
[[nodiscard]] bool looks_like_backup_destruction(std::string_view cmdline,
                                                 const core::RansomwareConfig& cfg) noexcept;

// ---------------------------------------------------------------------------
// Mass-modification watchdog
// ---------------------------------------------------------------------------

struct MassModifyVerdict {
    bool tripped{false};
    pid_t pid{0};
    std::size_t files_in_window{0};
    std::chrono::milliseconds window{};
    double files_per_second{0.0};
    std::string reason;
    core::Severity severity{core::Severity::Critical};
    std::uint16_t risk{0};
};

/// Feed one modification; returns a verdict when the threshold trips. The
/// per-actor deque is pruned on every call so memory is bounded by the window,
/// not by how long the daemon has been up.
class MassModifyDetector {
public:
    explicit MassModifyDetector(core::RansomwareConfig cfg) : cfg_{std::move(cfg)} {}

    MassModifyVerdict observe(pid_t pid, std::string_view path, bool is_canary = false) noexcept;

    /// Forget an actor (on exit) so the map does not grow forever.
    void forget(pid_t pid) noexcept;
    /// Global prune of idle actors; called from the sensor loop.
    void prune_idle(std::chrono::seconds max_idle) noexcept;

    [[nodiscard]] std::size_t tracked_actors() const noexcept;
    [[nodiscard]] std::vector<WriteProfile> snapshot(std::size_t max_actors = 32) const noexcept;

private:
    core::RansomwareConfig cfg_;
    mutable std::mutex mu_;
    std::unordered_map<pid_t, WriteProfile> actors_;
    std::unordered_map<pid_t, core::SteadyClock::time_point> tripped_at_;
};

// ---------------------------------------------------------------------------
// inotify watcher (epoll-driven, recursive)
// ---------------------------------------------------------------------------

class InotifyWatcher {
public:
    InotifyWatcher() = default;
    ~InotifyWatcher();

    InotifyWatcher(const InotifyWatcher&) = delete;
    InotifyWatcher& operator=(const InotifyWatcher&) = delete;

    [[nodiscard]] bool init() noexcept;
    [[nodiscard]] bool valid() const noexcept { return static_cast<bool>(inotify_); }

    /// Add a watch. `recursive` walks subdirectories and adds a wd for each,
    /// and IN_CREATE|IN_ISDIR events add new subdirectories on the fly -- the
    /// standard trick for tracking a moving target like a Downloads folder.
    bool watch(std::string_view path, std::uint32_t mask, bool recursive = true) noexcept;
    bool unwatch(std::string_view path) noexcept;

    /// One decoded inotify record. `struct inotify_event` ends in a flexible
    /// array member, so it cannot live inside a std::pair or std::vector element;
    /// this plain struct is the decoded, self-contained form.
    struct Record {
        int wd{0};
        std::uint32_t mask{0};
        std::uint32_t cookie{0};
        std::string name;   // file name within the watched directory (may be empty)
        std::string dir;    // resolved path of the watch descriptor
        [[nodiscard]] std::string full_path() const {
            if (name.empty()) return dir;
            return dir.empty() ? name : dir + "/" + name;
        }
    };

    /// Non-blocking drain. Returns the number of records appended to `out`.
    std::size_t poll(std::vector<Record>& out) noexcept;

    [[nodiscard]] int fd() const noexcept { return inotify_.get(); }
    [[nodiscard]] std::size_t watch_count() const noexcept;
    [[nodiscard]] std::size_t max_watches() const noexcept;
    /// True when we hit /proc/sys/fs/inotify/max_user_watches. Reported to the
    /// GUI: silently partial coverage is the worst failure mode for a watcher.
    [[nodiscard]] bool watch_limit_reached() const noexcept { return limit_reached_; }

    [[nodiscard]] std::string path_for(int wd) const noexcept;

private:
    bool add_one(const std::string& path, std::uint32_t mask) noexcept;
    void walk(const std::string& root, std::uint32_t mask, std::size_t depth) noexcept;

    core::UniqueFd inotify_;
    mutable std::shared_mutex mu_;
    std::unordered_map<int, std::string> wd_to_path_;
    std::unordered_map<std::string, int> path_to_wd_;
    bool limit_reached_{false};
};

// ---------------------------------------------------------------------------
// The sensor
// ---------------------------------------------------------------------------

class FileMonitorSensor final : public core::ISensor {
public:
    FileMonitorSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool,
                      CanarySensor* canaries);

    [[nodiscard]] const MassModifyDetector& detector() const noexcept { return detector_; }
    [[nodiscard]] const InotifyWatcher& watcher() const noexcept { return watcher_; }
    [[nodiscard]] std::uint64_t events_seen() const noexcept {
        return events_seen_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] bool fanotify_available() const noexcept { return fanotify_ok_; }

    /// Called by the escalation pipeline once it has decided: suspend the actor.
    /// Returns false if the actor is protected or dry_run is set.
    [[nodiscard]] bool suspend_actor(pid_t pid, std::string_view reason) noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    void on_stop() override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    bool init_fanotify() noexcept;
    void handle_fanotify() noexcept;
    void handle_inotify() noexcept;
    void on_write(const WriteSample& s, double prior_entropy) noexcept;
    /// Single decision point: combines the entropy verdict, the mass-modify
    /// verdict, the canary flag and the extension check into ONE event, then
    /// hands the actor to the escalation pipeline.
    void evaluate_actor_after_write(const WriteSample& s, const EntropyVerdict& ev_verdict,
                                    const MassModifyVerdict& mv, bool bad_extension) noexcept;
    void evaluate_actor(const WriteProfile& p) noexcept;
    void handle_new_directory(int wd, std::string_view name) noexcept;

    CanarySensor* canaries_;
    MassModifyDetector detector_;
    InotifyWatcher watcher_;
    core::UniqueFd fanotify_fd_;
    core::EpollSet epoll_;
    core::WakeupEvent* wake_{nullptr};
    std::unique_ptr<core::WakeupEvent> wake_owner_;
    bool fanotify_ok_{false};
    bool blocking_mode_{false};  // FAN_OPEN_PERM granted
    std::atomic<std::uint64_t> events_seen_{0};
    std::atomic<std::uint64_t> writes_analysed_{0};
    std::atomic<std::uint64_t> entropy_hits_{0};
    /// pid -> entropy of the file before its last write, so a low->high
    /// transition can be detected rather than a file that was always encrypted.
    mutable std::mutex prior_mu_;
    std::unordered_map<std::string, double> prior_entropy_;
};

}  // namespace hyprnova::anti_ransomware
