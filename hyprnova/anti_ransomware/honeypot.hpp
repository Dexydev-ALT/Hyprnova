// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 2c — Honeypot decoy configs (gap #11)
//
// Canary files catch RANSOMWARE (who touches bait documents). Honeypot decoy
// configs catch the OTHER early actor: a human operator or stealer poking
// around for credentials. A process that opens "aws/credentials",
// "id_rsa", ".env" or "kubeconfig" inside the agent's own state dir has no
// business doing so -- reading one is a high-severity signal on its own.
//
// Design constraints, stated honestly:
//   * Files live ONLY in state_dir/honeypots/ (0700/0600). We never plant
//     fake secrets into real user or system locations: that would be writing
//     into the operator's environment (spec rule 3) and could itself leak.
//   * Content is plausible but INVALID (structurally right, cryptographically
//     dead), and every file carries a greppable "hyprnova decoy" marker so
//     forensics never mistakes a decoy for a real leaked secret.
//   * Read detection uses atime (relatime may coalesce reads; a first read
//     after plant always updates it) + open-fd attribution via /proc scan.
//     Modification/deletion use sha256 + existence, which are exact.

#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/sensor.hpp"

struct inotify_event;  // <sys/inotify.h>, forward-declared to keep the header light

namespace hyprnova::anti_ransomware {

/// What changed between two observations of one honeypot file.
enum class HoneyVerdict : std::uint8_t {
    Untouched = 0,
    Read,       // atime advanced past the plant/last-check timestamp
    Modified,   // sha256 differs
    Gone,       // deleted or moved
};

/// PURE: classify two observations. Floor of the sensor logic.
[[nodiscard]] HoneyVerdict honey_classify(bool existed_before, bool exists_now,
                                          bool hash_equal, bool atime_advanced) noexcept;

/// PURE: the decoy profile library. Deterministic content per profile name so
/// tests can assert structure; INVALID keys (fixed non-secret material), each
/// ending with the decoy marker line.
[[nodiscard]] std::string honey_profile_body(std::string_view profile) noexcept;
[[nodiscard]] std::vector<std::string> honey_profile_names() noexcept;

/// Which processes currently hold an OPEN fd on `path`? Best effort, honest
/// about coverage: same-uid and root processes only (other users' /proc is
/// invisible to an unprivileged agent).
struct HoneyOpener {
    pid_t pid{0};
    std::string comm;
};
[[nodiscard]] std::vector<HoneyOpener> honey_find_openers(std::string_view path) noexcept;

class HoneypotSensor final : public core::ISensor {
public:
    HoneypotSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    /// Plant every configured decoy (idempotent: existing files with matching
    /// hashes are left untouched, so atimes of untouched bait stay stable).
    [[nodiscard]] bool plant_all() noexcept;

    /// One verification sweep. Emits one event per change found.
    void check_all() noexcept;

    [[nodiscard]] std::size_t planted_count() const noexcept { return planted_count_; }

    /// Read-only view of one planted decoy (for snapshots/CLI; never the bait body).
    struct HoneyView {
        std::string rel;      // profile-relative path
        std::string root;     // honeypot root the decoy lives under
        std::string sha256;   // hash of the planted content (tamper baseline)
    };
    /// Copy of the planted set. Safe from any thread: writers only exist during
    /// start(); from then on the set is immutable and the copy is lock-guarded.
    [[nodiscard]] std::vector<HoneyView> planted() const noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    struct Honey {
        std::string rel;      // profile-relative path inside the honeypot root
        std::string abs;      // root + rel
        std::string sha256;   // of the planted content
        int wd{-1};           // inotify watch descriptor (per file)
    };
    std::string root_;
    std::vector<Honey> planted_;
    mutable std::mutex planted_mu_;  // guards the copies plant_all() publishes
    std::size_t planted_count_{0};
    std::atomic<bool> self_sweep_{false};
    int ino_fd_{-1};

    [[nodiscard]] bool arm_watches() noexcept;
    void handle_event(const struct inotify_event* ev) noexcept;

public:
    ~HoneypotSensor() override;
};

}  // namespace hyprnova::anti_ransomware
