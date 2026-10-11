// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 2b/2c implementation

#include "anti_ransomware/file_monitor.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstring>
#include <dirent.h>
#include <format>
#include <fcntl.h>
#include <linux/limits.h>
#include <poll.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "core/hash.hpp"
#include "core/proc.hpp"

namespace hyprnova::anti_ransomware {

namespace fsx = core::fsx;
using core::hash::FileFlavour;
using core::hash::shannon_entropy;
using namespace std::chrono_literals;

// ===========================================================================
// Entropy analysis
// ===========================================================================

EntropyVerdict analyse_write(std::span<const std::byte> written, FileFlavour flavour,
                             const core::RansomwareConfig& cfg, double prior_entropy) noexcept {
    EntropyVerdict v;
    v.threshold = cfg.entropy_threshold;

    if (written.size() < cfg.min_entropy_bytes) {
        // Small writes are dominated by their own structure (headers, JSON keys)
        // and produce meaningless entropy. Skipping them is not a gap: an
        // encryptor writing 1 KB chunks still produces thousands of samples.
        return v;
    }

    // Cap the sample: entropy converges well before 64 KB and reading a 2 GB
    // write into the analyser would be the agent's own DoS.
    const auto sample = written.subspan(0, std::min<std::size_t>(written.size(), 65536));
    v.entropy = shannon_entropy(sample);

    const bool high = v.entropy >= cfg.entropy_threshold;
    const bool target = core::hash::is_ransomware_target(flavour);

    if (!high) return v;

    v.suspicious = true;
    std::string reason = std::format("entropy {:.3f}/8.000 >= threshold {:.2f}", v.entropy,
                                     cfg.entropy_threshold);

    if (prior_entropy >= 0.0 && prior_entropy < cfg.entropy_threshold) {
        reason += std::format("; LOW->HIGH transition (was {:.3f})", prior_entropy);
        v.risk = target ? 420 : 220;
        v.severity = target ? core::Severity::Critical : core::Severity::High;
    } else if (target) {
        reason += "; target flavour is a structured personal file";
        v.risk = 340;
        v.severity = core::Severity::High;
    } else {
        // High entropy over an already-compressed or already-encrypted target is
        // normal: appending to a .zip, writing a .sqlite WAL, saving an image.
        reason += "; target flavour is not a typical ransomware target";
        v.risk = 90;
        v.severity = core::Severity::Medium;
        v.suspicious = false;
    }
    v.reason = std::move(reason);
    return v;
}

bool looks_like_ransom_note(std::string_view path, std::string_view head_bytes,
                            const core::RansomwareConfig& cfg) noexcept {
    const std::size_t slash = path.find_last_of('/');
    const std::string_view base = slash == std::string_view::npos ? path : path.substr(slash + 1);

    std::string upper_base{base};
    std::transform(upper_base.begin(), upper_base.end(), upper_base.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    bool name_hit = false;
    for (const auto& n : cfg.ransom_note_names) {
        std::string un{n};
        std::transform(un.begin(), un.end(), un.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        if (upper_base.find(un) != std::string::npos) { name_hit = true; break; }
    }

    // Content markers. A ransom note is almost always low-entropy human-readable
    // text mentioning payment; that combination is distinctive.
    std::string low{head_bytes};
    std::transform(low.begin(), low.end(), low.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // A real note hits the name OR several content markers at once. ONE marker
    // (".locked", "payment", "wallet" ...) appears in logs, journals, config
    // dumps and code that merely TALK about ransomware -- the daemon's own log
    // echoed IOC text and tripped the old single-marker rule forever.
    if (name_hit) return true;
    int markers = 0;
    for (const char* marker : {"bitcoin", "btc", "monero", "xmr", "decrypt", "ransom", "tor browser",
                               "onion", "your files have been encrypted", "recover your files",
                               "payment", "wallet", "private key", "renamed", ".locked"}) {
        if (low.find(marker) != std::string::npos) ++markers;
    }
    return markers >= 2 && head_bytes.size() > 40;
}

bool looks_like_backup_destruction(std::string_view cmdline, const core::RansomwareConfig& cfg) noexcept {
    std::string low{cmdline};
    std::transform(low.begin(), low.end(), low.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& pat : cfg.backup_destroy_cmds) {
        std::string lp{pat};
        std::transform(lp.begin(), lp.end(), lp.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!lp.empty() && low.find(lp) != std::string::npos) return true;
    }
    // Linux analogues of `vssadmin delete shadows`.
    for (const char* pat : {"--delete-snapshot", "lvremove -f", "vgremove", "pvremove",
                            "zfs destroy", "btrfs subvolume delete", "restic forget --prune",
                            "borg delete", "duplicity remove"}) {
        if (low.find(pat) != std::string::npos) return true;
    }
    return false;
}

// ===========================================================================
// WriteProfile
// ===========================================================================

double WriteProfile::files_per_second() const noexcept {
    if (window.empty()) return 0.0;
    const double secs = std::chrono::duration<double>(window.back().when - window.front().when).count();
    if (secs <= 0.0001) return static_cast<double>(distinct_files) * 1000.0;  // sub-ms burst
    return static_cast<double>(distinct_files) / secs;
}

double WriteProfile::high_entropy_ratio() const noexcept {
    if (total_writes == 0) return 0.0;
    return static_cast<double>(high_entropy_writes) / static_cast<double>(total_writes);
}

// ===========================================================================
// MassModifyDetector
// ===========================================================================

MassModifyVerdict MassModifyDetector::observe(pid_t pid, std::string_view path, bool is_canary) noexcept {
    MassModifyVerdict v;
    v.pid = pid;
    const auto now = core::SteadyClock::now();

    std::lock_guard lk{mu_};
    WriteProfile& p = actors_[pid];
    if (p.pid == 0) {
        p.pid = pid;
        p.exe = core::proc::exe_of(pid);
        p.comm = core::proc::comm_of(pid);
        if (auto u = core::proc::uid_of(pid)) p.uid = *u;
        p.first_write = now;
    }
    p.last_write = now;

    WriteSample s;
    s.when = now;
    s.pid = pid;
    s.path = std::string(path);
    s.canary = is_canary;
    p.window.push_back(std::move(s));

    ++p.total_writes;
    const bool fresh = p.unique_paths.insert(std::string(path)).second;
    if (fresh) ++p.distinct_files;
    if (is_canary) ++p.canary_writes;

    // Prune to the configured window so the deque is bounded by time, not count.
    const auto cutoff = now - std::chrono::duration_cast<core::SteadyClock::duration>(
                                  cfg_.mass_modify_window * 4);
    while (!p.window.empty() && p.window.front().when < cutoff) p.window.pop_front();

    // Count distinct paths inside the *exact* window.
    std::unordered_set<std::string_view> in_window;
    const auto exact_cutoff = now - std::chrono::duration_cast<core::SteadyClock::duration>(cfg_.mass_modify_window);
    for (const auto& w : p.window) {
        if (w.when >= exact_cutoff) in_window.insert(std::string_view(w.path));
    }
    v.files_in_window = in_window.size();
    v.window = cfg_.mass_modify_window;
    v.files_per_second = p.files_per_second();

    // Do not re-trip on the same actor inside a cooldown: one SIGSTOP decision
    // per actor per 30 s, otherwise a single `rm -rf` produces hundreds of
    // Critical events and drowns the real signal.
    auto it = tripped_at_.find(pid);
    if (it != tripped_at_.end() && now - it->second < 30s) return v;

    const bool threshold_met = v.files_in_window >= cfg_.mass_modify_file_threshold;
    const bool canary_tripped = p.canary_writes > 0;
    if (!threshold_met && !canary_tripped) return v;

    tripped_at_[pid] = now;
    v.tripped = true;
    if (canary_tripped && threshold_met) {
        v.severity = core::Severity::Critical;
        v.risk = 950;
        v.reason = std::format("{} distinct files modified in {}ms AND a canary was written",
                               v.files_in_window, cfg_.mass_modify_window.count());
    } else if (canary_tripped) {
        v.severity = core::Severity::Critical;
        v.risk = 900;
        v.reason = "a planted canary was written by this process";
    } else {
        // Mass modification alone is High, not Critical: a build system, a git
        // checkout, an rsync or a package manager does exactly this legitimately.
        // The heuristic engine combines it with entropy and lineage to decide.
        v.severity = core::Severity::High;
        v.risk = 620;
        v.reason = std::format("{} distinct files modified in {}ms ({:.0f} files/s)",
                               v.files_in_window, cfg_.mass_modify_window.count(), v.files_per_second);
    }
    return v;
}

void MassModifyDetector::forget(pid_t pid) noexcept {
    std::lock_guard lk{mu_};
    actors_.erase(pid);
    tripped_at_.erase(pid);
}

void MassModifyDetector::prune_idle(std::chrono::seconds max_idle) noexcept {
    const auto cutoff = core::SteadyClock::now() - max_idle;
    std::lock_guard lk{mu_};
    for (auto it = actors_.begin(); it != actors_.end();) {
        if (it->second.last_write < cutoff) it = actors_.erase(it);
        else ++it;
    }
    for (auto it = tripped_at_.begin(); it != tripped_at_.end();) {
        if (it->second < cutoff) it = tripped_at_.erase(it);
        else ++it;
    }
}

std::size_t MassModifyDetector::tracked_actors() const noexcept {
    std::lock_guard lk{mu_};
    return actors_.size();
}

std::vector<WriteProfile> MassModifyDetector::snapshot(std::size_t max_actors) const noexcept {
    std::vector<WriteProfile> out;
    std::lock_guard lk{mu_};
    out.reserve(std::min(max_actors, actors_.size()));
    for (const auto& [pid, p] : actors_) {
        if (out.size() >= max_actors) break;
        WriteProfile copy = p;
        copy.window.clear();  // the GUI wants counters, not the raw deque
        out.push_back(std::move(copy));
    }
    std::sort(out.begin(), out.end(), [](const WriteProfile& a, const WriteProfile& b) {
        return a.distinct_files > b.distinct_files;
    });
    return out;
}

// ===========================================================================
// InotifyWatcher
// ===========================================================================

InotifyWatcher::~InotifyWatcher() {
    // The kernel releases every watch descriptor when the inotify fd closes;
    // nothing to unwind by hand, which is exactly why RAII on the fd is enough.
}

bool InotifyWatcher::init() noexcept {
    const int fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) return false;
    inotify_ = core::UniqueFd{fd};
    return true;
}

std::size_t InotifyWatcher::max_watches() const noexcept {
    const std::string v = fsx::read_trimmed("/proc/sys/fs/inotify/max_user_watches");
    std::size_t n = 0;
    if (std::from_chars(v.data(), v.data() + v.size(), n).ec != std::errc{}) return 0;
    return n;
}

bool InotifyWatcher::add_one(const std::string& path, std::uint32_t mask) noexcept {
    if (!inotify_) return false;
    {
        std::shared_lock lk{mu_};
        if (path_to_wd_.count(path)) return true;  // already watched
    }
    // IN_MASK_ADD merges with any existing mask rather than replacing it.
    const int wd = ::inotify_add_watch(inotify_.get(), path.c_str(), mask | IN_MASK_ADD | IN_ONLYDIR);
    if (wd < 0) {
        if (errno == ENOSPC) limit_reached_ = true;
        return false;
    }
    std::unique_lock lk{mu_};
    wd_to_path_[wd] = path;
    path_to_wd_[path] = wd;
    return true;
}

void InotifyWatcher::walk(const std::string& root, std::uint32_t mask, std::size_t depth) noexcept {
    if (depth > 24) return;  // symlink-loop / absurd-tree guard
    if (!add_one(root, mask)) return;

    core::UniqueDir d{::opendir(root.c_str())};
    if (!d) return;
    while (const dirent* e = ::readdir(d.get())) {
        if (e->d_name[0] == '.' && (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        if (limit_reached_) return;

        // d_type is unreliable on some filesystems; fall back to stat.
        bool is_dir = e->d_type == DT_DIR;
        const std::string child = root + "/" + e->d_name;
        if (e->d_type == DT_UNKNOWN) {
            struct stat st {};
            is_dir = ::stat(child.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
        }
        if (!is_dir) continue;

        // Never recurse into the configured skip list: .git and node_modules
        // alone would consume the entire watch budget on a developer machine.
        bool skip = false;
        for (const auto& s : {"node_modules", ".git", "__pycache__", ".cache", ".venv", "venv",
                              ".cargo", ".npm", ".gradle", ".m2"}) {
            if (std::string_view(e->d_name) == s) { skip = true; break; }
        }
        if (skip) continue;
        walk(child, mask, depth + 1);
    }
}

bool InotifyWatcher::watch(std::string_view path, std::uint32_t mask, bool recursive) noexcept {
    if (!inotify_) return false;
    const std::string p{path};
    if (recursive) {
        walk(p, mask, 0);
        return true;
    }
    return add_one(p, mask);
}

bool InotifyWatcher::unwatch(std::string_view path) noexcept {
    if (!inotify_) return false;
    std::unique_lock lk{mu_};
    auto it = path_to_wd_.find(std::string(path));
    if (it == path_to_wd_.end()) return false;
    const int wd = it->second;
    const bool ok = ::inotify_rm_watch(inotify_.get(), wd) == 0;
    wd_to_path_.erase(wd);
    path_to_wd_.erase(it);
    return ok;
}

std::size_t InotifyWatcher::watch_count() const noexcept {
    std::shared_lock lk{mu_};
    return wd_to_path_.size();
}

std::string InotifyWatcher::path_for(int wd) const noexcept {
    std::shared_lock lk{mu_};
    auto it = wd_to_path_.find(wd);
    return it == wd_to_path_.end() ? std::string{} : it->second;
}

std::size_t InotifyWatcher::poll(std::vector<Record>& out) noexcept {
    if (!inotify_) return 0;
    out.clear();

    // inotify reads are a stream of variable-length records; over-read into a
    // buffer and walk it. 64 KB is the documented practical maximum per read.
    alignas(struct inotify_event) char buf[65536];
    std::size_t total = 0;
    for (int pass = 0; pass < 8; ++pass) {
        const ssize_t n = ::read(inotify_.get(), buf, sizeof(buf));
        if (n <= 0) {
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                // EINVAL means the buffer was too small for one record, which
                // cannot happen at 64 KB; anything else is a real failure.
            }
            break;
        }
        total += static_cast<std::size_t>(n);

        const char* p = buf;
        const char* end = buf + n;
        while (p + sizeof(inotify_event) <= end) {
            const auto* ev = reinterpret_cast<const inotify_event*>(p);
            std::string name;
            if (ev->len > 0 && p + sizeof(inotify_event) + ev->len <= end) {
                // ev->name is NUL-padded to ev->len; trim at the first NUL.
                const char* np = p + sizeof(inotify_event);
                const std::size_t maxl = std::min<std::size_t>(ev->len, static_cast<std::size_t>(end - np));
                std::size_t l = 0;
                while (l < maxl && np[l] != '\0') ++l;
                name.assign(np, l);
            }
            Record rec;
            rec.wd = ev->wd;
            rec.mask = ev->mask;
            rec.cookie = ev->cookie;
            rec.name = std::move(name);
            rec.dir = path_for(ev->wd);
            out.push_back(std::move(rec));
            p += sizeof(inotify_event) + ev->len;
        }
        if (static_cast<std::size_t>(n) < sizeof(buf)) break;  // drained
    }
    return out.size();
}

// ===========================================================================
// FileMonitorSensor
// ===========================================================================

FileMonitorSensor::FileMonitorSensor(core::EventBus& bus, const core::AgentConfig& cfg,
                                     core::ThreadPool& pool, CanarySensor* canaries)
    : core::ISensor("file-monitor", core::SensorId::MassModify, bus, cfg, pool),
      canaries_{canaries},
      detector_{cfg.ransomware} {}

bool FileMonitorSensor::init_fanotify() noexcept {
    // FAN_CLASS_CONTENT + FAN_REPORT_FID + FAN_REPORT_PIDFD gives us:
    //   * the pid that touched the file
    //   * a pidfd we can signal without a pid-reuse race
    //   * the ability to make a blocking PERM decision
    // FAN_CLASS_NOTIF is the fallback when we lack CAP_DAC_READ_SEARCH.
    unsigned int flags = FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_REPORT_FID;
#ifdef FAN_REPORT_PIDFD
    flags |= FAN_REPORT_PIDFD;
#endif
#ifdef FAN_REPORT_TARGET_FID
    flags |= FAN_REPORT_TARGET_FID;
#endif

    int fd = ::fanotify_init(flags, O_RDONLY | O_CLOEXEC | O_LARGEFILE);
    if (fd < 0) {
        // Retry without FID reporting: kernels < 5.1 do not support it.
        fd = ::fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
                             O_RDONLY | O_CLOEXEC | O_LARGEFILE);
    }
    if (fd < 0) {
        fd = ::fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0) return false;
    fanotify_fd_ = core::UniqueFd{fd};

    // Mark the interesting filesystems. FAN_MARK_FILESYSTEM needs CAP_SYS_ADMIN;
    // FAN_MARK_MOUNT is the portable equivalent.
    unsigned mark_flags = FAN_MARK_ADD;
#ifdef FAN_MARK_FILESYSTEM
    mark_flags |= FAN_MARK_FILESYSTEM;
#endif
    std::uint64_t mask = FAN_CREATE | FAN_DELETE | FAN_DELETE_SELF | FAN_MOVE | FAN_MODIFY |
                         FAN_CLOSE_WRITE | FAN_ATTRIB | FAN_OPEN;
    // Blocking permission events are what let us stop the encryptor mid-sweep
    // rather than merely observing it. Attempted, never assumed.
    if (::geteuid() == 0) {
        mask |= FAN_OPEN_PERM;
    }

    int rc = ::fanotify_mark(fanotify_fd_.get(), mark_flags, mask, AT_FDCWD, "/");
    if (rc != 0) {
        mark_flags = FAN_MARK_ADD | FAN_MARK_MOUNT;
        rc = ::fanotify_mark(fanotify_fd_.get(), mark_flags, mask, AT_FDCWD, "/");
    }
    if (rc != 0) {
        // No global mark: fall back to marking each configured root.
        bool any = false;
        for (const auto& r : cfg_.scan.roots) {
            if (::fanotify_mark(fanotify_fd_.get(), FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD,
                                r.path.c_str()) == 0)
                any = true;
        }
        if (!any) return false;
    }
    blocking_mode_ = (mask & FAN_OPEN_PERM) != 0;
    return true;
}

bool FileMonitorSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.ransomware.enabled;
}

bool FileMonitorSensor::on_start() {
    fanotify_ok_ = init_fanotify();

    if (!watcher_.init()) {
        if (!fanotify_ok_) {
            note_error("neither fanotify nor inotify could be initialised: module is blind");
            return false;
        }
        mark_degraded("inotify unavailable; running on fanotify only");
    }

    // inotify covers the breadth that a global fanotify mark does not give us
    // path attribution for, plus every canary root explicitly.
    if (watcher_.valid()) {
        std::uint32_t mask = IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_CLOSE_WRITE |
                             IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_MOVE_SELF;
        if (cfg_.canary.monitor_access) mask |= IN_ACCESS;

        for (const auto& r : cfg_.scan.roots) {
            if (!fsx::is_dir(r.path)) continue;
            if (!watcher_.watch(r.path, mask, r.recursive)) {
                note_error("could not watch " + r.path);
            }
        }
        if (canaries_) {
            for (const auto& c : canaries_->planted()) {
                const std::size_t slash = c.path.find_last_of('/');
                if (slash == std::string::npos) continue;
                watcher_.watch(c.path.substr(0, slash), mask, false);
            }
        }
        SWARN("file-monitor", "inotify watches: {} of max {}{}", watcher_.watch_count(),
              watcher_.max_watches(), watcher_.watch_limit_reached() ? " (LIMIT REACHED)" : "");
    }

    auto ep = core::EpollSet::create();
    if (!ep) {
        note_error("epoll_create1 failed: " + ep.message());
        return false;
    }
    epoll_ = std::move(*ep);

    auto w = core::WakeupEvent::create();
    if (!w) {
        note_error("eventfd failed: " + w.message());
        return false;
    }
    wake_owner_ = std::make_unique<core::WakeupEvent>(std::move(*w));
    wake_ = wake_owner_.get();

    static constexpr int kTagWake = 1, kTagFan = 2, kTagIno = 3;
    // A failed epoll_ctl here means a silently deaf sensor, which is the worst
    // possible failure mode -- so each registration is checked and reported.
    if (!epoll_.add(wake_->fd(), EPOLLIN, reinterpret_cast<void*>(static_cast<intptr_t>(kTagWake)))) {
        note_error(std::string("epoll_ctl(wakeup) failed: ") + std::strerror(errno));
        return false;
    }
    if (fanotify_ok_ &&
        !epoll_.add(fanotify_fd_.get(), EPOLLIN, reinterpret_cast<void*>(static_cast<intptr_t>(kTagFan)))) {
        note_error(std::string("epoll_ctl(fanotify) failed: ") + std::strerror(errno));
        fanotify_ok_ = false;
    }
    if (watcher_.valid() &&
        !epoll_.add(watcher_.fd(), EPOLLIN, reinterpret_cast<void*>(static_cast<intptr_t>(kTagIno)))) {
        note_error(std::string("epoll_ctl(inotify) failed: ") + std::strerror(errno));
    }

    std::vector<std::string> missing;
    if (!fanotify_ok_) missing.push_back("fanotify (CAP_SYS_ADMIN / CAP_DAC_READ_SEARCH)");
    if (fanotify_ok_ && !blocking_mode_) missing.push_back("fanotify FAN_OPEN_PERM (blocking mode)");
    if (!watcher_.valid()) missing.push_back("inotify");
    if (watcher_.watch_limit_reached()) missing.push_back("inotify watch budget exhausted");
    if (!missing.empty()) {
        std::string j;
        for (const auto& m : missing) { if (!j.empty()) j += "; "; j += m; }
        mark_degraded(j);
    } else {
        mark_running(std::format("fanotify(blocking={}) + inotify({} watches)",
                                 blocking_mode_ ? "yes" : "no", watcher_.watch_count()));
    }
    return true;
}

void FileMonitorSensor::on_stop() {
    if (wake_) wake_->signal();
}

void FileMonitorSensor::loop(std::stop_token st) {
    static constexpr int kTagWake = 1, kTagFan = 2, kTagIno = 3;
    auto last_prune = core::SteadyClock::now();

    while (!st.stop_requested()) {
        const auto evs = epoll_.wait(250);
        for (const epoll_event& ev : evs) {
            const auto tag = static_cast<int>(reinterpret_cast<intptr_t>(ev.data.ptr));
            switch (tag) {
                case kTagWake: wake_->drain(); break;
                case kTagFan: handle_fanotify(); break;
                case kTagIno: handle_inotify(); break;
                default: break;
            }
        }
        if (epoll_.last_error() != 0 && epoll_.last_error() != EINTR) {
            note_error(std::string("epoll_wait failed: ") + std::strerror(epoll_.last_error()));
        }

        if (core::SteadyClock::now() - last_prune > 60s) {
            detector_.prune_idle(300s);
            last_prune = core::SteadyClock::now();
            {
                std::lock_guard lk{prior_mu_};
                if (prior_entropy_.size() > 200000) prior_entropy_.clear();
            }
        }
    }
}

void FileMonitorSensor::handle_fanotify() noexcept {
    alignas(struct fanotify_event_metadata) char buf[16384];
    for (int pass = 0; pass < 16; ++pass) {
        const ssize_t n = ::read(fanotify_fd_.get(), buf, sizeof(buf));
        if (n <= 0) break;

        auto* m = reinterpret_cast<struct fanotify_event_metadata*>(buf);
        // FAN_EVENT_NEXT decrements its length argument, so hand it a copy
        // rather than aliasing `n`, which the outer loop still needs.
        std::size_t remaining = static_cast<std::size_t>(n);
        while (FAN_EVENT_OK(m, remaining)) {
            events_seen_.fetch_add(1, std::memory_order_relaxed);

            // Resolve the path. With FAN_REPORT_FID we get a file handle in the
            // info record; without it we get an fd we can readlink from /proc/self/fd.
            std::string path;
            if (m->fd >= 0) {
                if (auto l = fsx::read_symlink(std::format("/proc/self/fd/{}", m->fd))) path = *l;
                ::close(m->fd);  // MUST be closed: fanotify leaks fds otherwise
            } else {
                // FID mode: walk the info records for the file handle and resolve
                // it with name_to_handle_at's inverse, open_by_handle_at.
                auto* info = reinterpret_cast<struct fanotify_event_info_header*>(m + 1);
                std::size_t consumed = sizeof(struct fanotify_event_metadata);
                const std::size_t total = static_cast<std::size_t>(n);
                while (consumed + sizeof(struct fanotify_event_info_header) <= total) {
                    if (info->info_type == FAN_EVENT_INFO_TYPE_FID ||
                        info->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                        auto* fid = reinterpret_cast<struct fanotify_event_info_fid*>(info);
                        auto* fh = const_cast<struct file_handle*>(
                            reinterpret_cast<const struct file_handle*>(fid->handle));
                        const int mfd = ::open_by_handle_at(AT_FDCWD, fh, O_RDONLY | O_PATH);
                        if (mfd >= 0) {
                            if (auto l = fsx::read_symlink(std::format("/proc/self/fd/{}", mfd))) path = *l;
                            ::close(mfd);
                        }
                        if (info->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                            // The name follows the handle, NUL-terminated.
                            const auto* namep = reinterpret_cast<const char*>(fh->f_handle) + fh->handle_bytes;
                            const std::size_t room =
                                consumed + info->len < total ? total - consumed - info->len : 0;
                            if (room > 0 && *namep) {
                                std::string nm{namep};
                                if (!path.empty() && path.back() != '/') path += '/';
                                path += nm;
                            }
                        }
                    }
                    if (info->len == 0) break;  // malformed record: stop walking
                    consumed += info->len;
                    info = reinterpret_cast<struct fanotify_event_info_header*>(
                        reinterpret_cast<char*>(info) + info->len);
                }
            }

            const pid_t pid = m->pid;
            const bool is_write = (m->mask & (FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CREATE | FAN_MOVE)) != 0;

            if ((m->mask & FAN_OPEN_PERM) != 0) {
                // Blocking decision point. Default is ALLOW: denying on a
                // heuristic is how you turn an EDR into an outage. Denial is
                // reserved for a canary write by a non-allowlisted process,
                // which is unambiguous.
                struct fanotify_response resp{};
                resp.fd = m->fd;
                resp.response = FAN_ALLOW;

                if (canaries_ && !path.empty() && canaries_->find(path) != nullptr) {
                    const std::string comm = core::proc::comm_of(pid);
                    const bool allowlisted =
                        std::find(cfg_.canary.reader_allowlist.begin(), cfg_.canary.reader_allowlist.end(),
                                  comm) != cfg_.canary.reader_allowlist.end();
                    if (!allowlisted && pid != ::getpid() && !cfg_.dry_run) {
                        resp.response = FAN_DENY;
                        SWARN(name_, "DENIED open of canary {} by pid {} ({})", path, pid, comm);
                    }
                    if (canaries_) canaries_->on_filesystem_event(pid, path, core::EventKind::FileCanaryHit, false);
                }
                if (m->fd >= 0) {
                    const ssize_t w = ::write(fanotify_fd_.get(), &resp, sizeof(resp));
                    (void)w;
                }
            }

            if (!path.empty() && is_write) {
                WriteSample s;
                s.when = core::SteadyClock::now();
                s.pid = pid;
                s.path = path;
                s.canary = canaries_ && canaries_->find(path) != nullptr;

                struct stat st {};
                if (::stat(path.c_str(), &st) == 0) s.bytes = static_cast<std::uint64_t>(st.st_size);

                // Read a sample of what was just written for entropy analysis.
                // Bounded to 64 KB: enough for a stable entropy estimate.
                double prior = -1.0;
                {
                    std::lock_guard lk{prior_mu_};
                    auto it = prior_entropy_.find(path);
                    if (it != prior_entropy_.end()) prior = it->second;
                }
                auto mf = core::MappedFile::open(path, 65536);
                if (mf) {
                    const auto bytes = mf->bytes();
                    s.flavour = core::hash::classify(path, bytes.subspan(0, std::min<std::size_t>(bytes.size(), 16)));
                    s.entropy = shannon_entropy(bytes);
                    {
                        std::lock_guard lk{prior_mu_};
                        prior_entropy_[path] = s.entropy;
                        if (prior_entropy_.size() > 200000) prior_entropy_.clear();
                    }
                }
                on_write(s, prior);
            } else if (!path.empty() && (m->mask & (FAN_DELETE | FAN_DELETE_SELF | FAN_MOVE)) != 0) {
                if (canaries_ && canaries_->find(path)) {
                    canaries_->on_filesystem_event(pid, path, core::EventKind::FileDelete, false);
                }
                detector_.observe(pid, path, canaries_ && canaries_->find(path) != nullptr);
            }

            m = FAN_EVENT_NEXT(m, remaining);
        }
        if (static_cast<std::size_t>(n) < sizeof(buf)) break;
    }
}

void FileMonitorSensor::handle_inotify() noexcept {
    std::vector<InotifyWatcher::Record> events;
    watcher_.poll(events);

    for (const auto& rec : events) {
        events_seen_.fetch_add(1, std::memory_order_relaxed);
        const auto& ev = rec;
        const std::string& name = rec.name;
        if (ev.mask & IN_IGNORED) continue;
        if (ev.mask & IN_Q_OVERFLOW) {
            note_error("inotify queue OVERFLOWED: events were lost. Raise "
                       "/proc/sys/fs/inotify/max_queued_events or narrow the watch set.");
            emit(core::EventKind::SensorDown, core::Severity::High,
                 "inotify queue overflow: filesystem coverage was interrupted");
            continue;
        }

        const std::string path = rec.full_path();

        // Never profile the agent's own writes. Our state dir, log, quarantine
        // and shadow stores churn constantly, and a monitor that watches itself
        // feeds on its own output: the log echoes IOC text, the note detector
        // flags the log, the log grows, repeat. Compiled-in self knowledge, not
        // an exclusions file malware could edit.
        {
            static const std::string_view kOwnPrefixes[] = {
                "/proc", "/sys", "/dev", "/run",
            };
            bool own = false;
            for (const auto pre : kOwnPrefixes) {
                if (path.starts_with(pre)) { own = true; break; }
            }
            if (!own) {
                auto under = [&](const std::string& root_path) {
                    if (root_path.empty()) return false;
                    if (path.starts_with(root_path)) {
                        return path.size() == root_path.size() ||
                               path[root_path.size()] == '/';
                    }
                    return false;
                };
                own = under(cfg_.state_dir) || under(cfg_.remediation.quarantine_dir) ||
                      path == cfg_.log_path;
            }
            if (own) continue;
        }

        if ((ev.mask & IN_CREATE) && (ev.mask & IN_ISDIR)) {
            handle_new_directory(ev.wd, name);
            continue;
        }

        const bool is_canary = canaries_ && canaries_->find(path) != nullptr;

        if (ev.mask & IN_ACCESS) {
            // inotify gives no pid, so an IN_ACCESS on a canary can only be
            // reported as "canary was read by an unattributed actor". Useful,
            // but the fanotify path is what supplies attribution.
            // Suppress our own integrity-check reads: without pid attribution
            // (degraded, inotify-only mode) the dominant reader of a canary is the
            // agent verifying it, and reporting that as "accessed" every 30 s is
            // noise. A read we did not cause is still reported.
            if (is_canary && cfg_.canary.monitor_access &&
                !(canaries_ && canaries_->self_read_recent(path))) {
                core::TelemetryEvent tev;
                tev.sensor = core::SensorId::Canary;
                tev.kind = core::EventKind::FileCanaryHit;
                tev.severity = core::Severity::Medium;
                tev.target.path = path;
                tev.message = "canary accessed (inotify: actor unattributed)";
                tev.risk_score = 200;
                emit(std::move(tev));
            }
            continue;
        }

        if ((ev.mask & (IN_DELETE | IN_DELETE_SELF | IN_MOVED_FROM)) && is_canary && canaries_) {
            canaries_->on_filesystem_event(0, path, core::EventKind::FileDelete, false);
            core::TelemetryEvent tev;
            tev.sensor = core::SensorId::Canary;
            tev.kind = core::EventKind::FileCanaryHit;
            tev.severity = core::Severity::High;
            tev.target.path = path;
            tev.message = "CANARY removed or moved: " + path;
            tev.risk_score = 680;
            emit(std::move(tev));
            continue;
        }

        if ((ev.mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE)) == 0) continue;

        WriteSample s;
        s.when = core::SteadyClock::now();
        s.pid = 0;  // inotify cannot attribute
        s.path = path;
        s.canary = is_canary;

        double prior = -1.0;
        {
            std::lock_guard lk{prior_mu_};
            auto it = prior_entropy_.find(path);
            if (it != prior_entropy_.end()) prior = it->second;
        }

        struct stat st {};
        if (::stat(path.c_str(), &st) == 0) s.bytes = static_cast<std::uint64_t>(st.st_size);
        auto mf = core::MappedFile::open(path, 65536);
        if (mf) {
            const auto bytes = mf->bytes();
            s.flavour = core::hash::classify(path, bytes.subspan(0, std::min<std::size_t>(bytes.size(), 16)));
            s.entropy = shannon_entropy(bytes);
            std::lock_guard lk{prior_mu_};
            prior_entropy_[path] = s.entropy;
        }

        // Ransom-note detection: cheap, high-signal, and independent of entropy.
        if (cfg_.ransomware.detect_ransom_notes && mf) {
            const auto bytes = mf->bytes();
            const std::string_view head{reinterpret_cast<const char*>(bytes.data()),
                                        std::min<std::size_t>(bytes.size(), 4096)};
            if (looks_like_ransom_note(path, head, cfg_.ransomware)) {
                core::TelemetryEvent tev;
                tev.sensor = core::SensorId::Entropy;
                tev.kind = core::EventKind::EntropyVerdict;
                tev.severity = core::Severity::Critical;
                tev.target.path = path;
                tev.message = "RANSOM NOTE detected: " + path;
                tev.risk_score = 980;
                tev.triggers.push_back("ransom_note");
                emit(std::move(tev));
            }
        }

        on_write(s, prior);
    }
}

void FileMonitorSensor::handle_new_directory(int wd, std::string_view name) noexcept {
    // Track directories created after the initial walk, otherwise a dropper that
    // mkdir's a fresh tree and fills it is invisible.
    const std::string dir = watcher_.path_for(wd);
    if (dir.empty() || name.empty()) return;
    const std::string child = dir + "/" + std::string(name);
    std::uint32_t mask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM |
                         IN_MOVED_TO | IN_ATTRIB | IN_MOVE_SELF;
    if (cfg_.canary.monitor_access) mask |= IN_ACCESS;
    watcher_.watch(child, mask, true);
}

void FileMonitorSensor::on_write(const WriteSample& s, double prior_entropy) noexcept {
    writes_analysed_.fetch_add(1, std::memory_order_relaxed);

    auto verdict = analyse_write({}, s.flavour, cfg_.ransomware, prior_entropy);
    // analyse_write needs the bytes; when we only have the post-write file we
    // approximate with the mapped head, which is what a streaming encryptor
    // leaves behind.
    auto mf = core::MappedFile::open(s.path, 65536);
    if (mf) verdict = analyse_write(mf->bytes(), s.flavour, cfg_.ransomware, prior_entropy);

    WriteSample enriched = s;
    enriched.entropy = verdict.entropy;

    // Suspicious extension appended by an encryptor ("file.docx.locked").
    bool bad_ext = false;
    for (const auto& e : cfg_.ransomware.suspicious_extensions) {
        if (s.path.size() > e.size() && s.path.compare(s.path.size() - e.size(), e.size(), e) == 0) {
            bad_ext = true;
            break;
        }
    }

    const auto mv = detector_.observe(s.pid, s.path, s.canary);

    if (verdict.suspicious || bad_ext || mv.tripped || s.canary) {
        evaluate_actor_after_write(enriched, verdict, mv, bad_ext);
    }
}

void FileMonitorSensor::evaluate_actor_after_write(const WriteSample& s,
                                                   const EntropyVerdict& entropy,
                                                   const MassModifyVerdict& mv,
                                                   bool bad_extension) noexcept {
    // ---------------------------------------------------------------------
    // Risk accumulation. Each independent signal contributes; the sum decides
    // severity. Independent corroboration is what keeps false positives down:
    // a build system trips mass-modify alone, a backup job trips entropy alone,
    // but only an encryptor trips all of them together.
    // ---------------------------------------------------------------------
    std::uint16_t risk = 0;
    std::vector<std::string> triggers;

    if (entropy.suspicious) {
        risk = static_cast<std::uint16_t>(risk + entropy.risk);
        triggers.push_back("high_entropy_write");
    }
    if (s.canary) {
        risk = static_cast<std::uint16_t>(risk + 500);
        triggers.push_back("canary_written");
    }
    if (mv.tripped) {
        risk = static_cast<std::uint16_t>(risk + mv.risk / 2);
        triggers.push_back("mass_modification");
    }
    if (bad_extension) {
        risk = static_cast<std::uint16_t>(risk + 400);
        triggers.push_back("ransomware_extension_appended");
    }
    if (core::proc::is_world_writable_runtime_dir(s.path)) {
        risk = static_cast<std::uint16_t>(risk + 60);
        triggers.push_back("write_in_world_writable_dir");
    }
    if (core::proc::runs_from_suspicious_path(core::proc::exe_of(s.pid))) {
        risk = static_cast<std::uint16_t>(risk + 120);
        triggers.push_back("actor_binary_in_user_writable_path");
    }
    risk = static_cast<std::uint16_t>(std::min<int>(risk, 1000));
    if (risk < 200) return;  // below the noise floor: do not spend bus capacity

    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Entropy;
    ev.kind = core::EventKind::EntropyVerdict;
    ev.actor.pid = s.pid;
    ev.target.path = s.path;
    ev.target.rule_id = triggers.empty() ? "write-anomaly" : triggers.front();
    ev.metric = entropy.entropy;
    ev.count = mv.files_in_window;
    ev.risk_score = risk;
    ev.escalated = risk >= cfg_.heuristic.alert_threshold;
    ev.triggers = std::move(triggers);
    ev.fields["entropy"] = std::format("{:.3f}", entropy.entropy);
    ev.fields["flavour"] = std::string(core::hash::flavour_name(s.flavour));
    ev.fields["files_in_window"] = std::to_string(mv.files_in_window);
    ev.fields["window_ms"] = std::to_string(mv.window.count());
    ev.fields["canary"] = s.canary ? "yes" : "no";
    ev.fields["bytes"] = std::to_string(s.bytes);
    ev.fields["unattributed"] = s.pid == 0 ? "yes" : "no";

    ev.severity = risk >= cfg_.heuristic.auto_respond_threshold ? core::Severity::Critical
                  : risk >= cfg_.heuristic.critical_threshold   ? core::Severity::High
                  : risk >= cfg_.heuristic.alert_threshold      ? core::Severity::Medium
                                                                : core::Severity::Low;

    if (s.pid == 0) {
        ev.message = std::format("suspicious write to {} (entropy {:.2f}, flavour {}, unattributed: "
                                 "inotify has no pid -- fanotify unavailable or blocked)",
                                 s.path, entropy.entropy, core::hash::flavour_name(s.flavour));
    } else {
        ev.message = std::format("suspicious write to {} by pid {} (entropy {:.2f}, flavour {}, {} files "
                                 "in {}ms, risk {}/1000)",
                                 s.path, s.pid, entropy.entropy, core::hash::flavour_name(s.flavour),
                                 mv.files_in_window, mv.window.count(), risk);
    }
    if (!entropy.reason.empty()) ev.fields["entropy_reason"] = entropy.reason;

    entropy_hits_.fetch_add(1, std::memory_order_relaxed);
    emit(std::move(ev));

    // ---------------------------------------------------------------------
    // Automatic containment. Only when: not dry-run, the actor is attributed,
    // the risk clears the auto-respond bar, and policy permits suspension.
    // Everything else is a GUI prompt -- a false-positive SIGSTOP of a build
    // server is an incident, so the default is human-in-the-loop.
    // ---------------------------------------------------------------------
    if (!cfg_.ransomware.auto_suspend || s.pid == 0) return;
    if (!ev.escalated || risk < cfg_.heuristic.auto_respond_threshold) return;

    if (cfg_.ransomware.auto_suspend_unprivileged_only) {
        if (auto uid = core::proc::uid_of(s.pid); uid && *uid == 0) {
            SWARN(name_, "risk {}/1000 for ROOT pid {} but auto_suspend_unprivileged_only is set: "
                         "escalating to the GUI instead of suspending",
                  risk, s.pid);
            return;
        }
    }
    // Never suspend ourselves, the GUI, or anything on the protected list.
    const std::string comm = core::proc::comm_of(s.pid);
    for (const auto& p : cfg_.remediation.protected_processes) {
        if (p == comm) return;
    }
    if (s.pid == ::getpid()) return;

    (void)suspend_actor(s.pid, std::format("risk {}/1000 -- {}", risk, ev.message));
}

void FileMonitorSensor::evaluate_actor(const WriteProfile& p) noexcept {
    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Entropy;
    ev.kind = core::EventKind::EntropyVerdict;
    ev.actor.pid = p.pid;
    ev.actor.uid = p.uid;
    ev.actor.exe = p.exe;
    ev.actor.comm = p.comm;
    ev.message = std::format("write-profile pid={} exe={} files={} bytes={} high_entropy_ratio={:.2f} "
                             "rate={:.0f}/s",
                             p.pid, p.exe.empty() ? "?" : p.exe, p.distinct_files, p.total_bytes,
                             p.high_entropy_ratio(), p.files_per_second());
    ev.metric = p.high_entropy_ratio();
    ev.count = p.distinct_files;
    ev.severity = core::Severity::High;
    emit(std::move(ev));
}

bool FileMonitorSensor::suspend_actor(pid_t pid, std::string_view reason) noexcept {
    if (pid <= 1) return false;
    if (cfg_.dry_run) {
        SWARN(name_, "dry_run: would SIGSTOP pid {} ({})", pid, reason);
        return false;
    }
    const core::ProcessHandle h{pid};
    if (!h.alive()) return false;
    if (!h.stop()) {
        note_error(std::format("SIGSTOP to pid {} failed: {}", pid, std::strerror(errno)));
        return false;
    }
    SINFO(name_, "SIGSTOP pid {} -- {}", pid, reason);
    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::MassModify;
    ev.kind = core::EventKind::RemediationApplied;
    ev.severity = core::Severity::Critical;
    ev.actor.pid = pid;
    ev.message = std::format("process {} suspended (SIGSTOP): {}", pid, reason);
    ev.fields["action"] = "SIGSTOP";
    emit(std::move(ev));
    return true;
}

}  // namespace hyprnova::anti_ransomware
