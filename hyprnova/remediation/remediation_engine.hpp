// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 6 — Active Remediation
//
// Three families of action, in escalating order of destructiveness:
//
//   1. Process containment -- SIGSTOP (reversible, preserves the memory image),
//      cgroup freezer/quota isolation (reversible, contains the whole tree),
//      SIGKILL (irreversible, last resort).
//   2. Network containment -- nftables rules dropping traffic to a suspected C2,
//      installed in a dedicated table so they never collide with the operator's
//      own ruleset and can be removed atomically.
//   3. Operator notification -- desktop notification plus a GUI prompt carrying
//      the full lineage and risk score.
//
// Everything here is *reversible by default* and *auditable always*. Every action
// is written to a journal on disk and published on the event bus before and after,
// so an operator can reconstruct exactly what the agent did and when. An EDR that
// silently kills processes is a liability, not a control.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "heuristics/heuristics_engine.hpp"

namespace hyprnova::remediation {

enum class Action : std::uint8_t {
    None = 0,
    Suspend,        // SIGSTOP
    Resume,         // SIGCONT + release from cgroup
    Isolate,        // cgroup freezer + cpu/pids limits
    Kill,           // SIGKILL
    BlockC2,        // nftables drop rule for a remote endpoint
    UnblockC2,
    BlockExe,       // cgroup + nftables cgroupv2 drop for a whole executable
    UnblockExe,
    QuarantineFile, // move to a 0000-mode quarantine dir
    RestoreFile,    // move back (or from backup)
    Harden,         // apply a kernel hardening sysctl
    Notify,         // desktop notification
    Prompt,         // GUI decision prompt
};

constexpr std::string_view action_name(Action a) noexcept {
    switch (a) {
        case Action::None: return "none";
        case Action::Suspend: return "suspend";
        case Action::Resume: return "resume";
        case Action::Isolate: return "isolate";
        case Action::Kill: return "kill";
        case Action::BlockC2: return "block-c2";
        case Action::UnblockC2: return "unblock-c2";
        case Action::BlockExe: return "block-exe";
        case Action::UnblockExe: return "unblock-exe";
        case Action::QuarantineFile: return "quarantine-file";
        case Action::RestoreFile: return "restore-file";
        case Action::Harden: return "harden";
        case Action::Notify: return "notify";
        case Action::Prompt: return "prompt";
    }
    return "none";
}

enum class Outcome : std::uint8_t {
    Skipped = 0,   // policy said no (protected, dry-run, not enabled)
    Attempted,     // ran, result unknown
    Success,
    Failure,
    Reverted,
};

constexpr std::string_view outcome_name(Outcome o) noexcept {
    switch (o) {
        case Outcome::Skipped: return "skipped";
        case Outcome::Attempted: return "attempted";
        case Outcome::Success: return "success";
        case Outcome::Failure: return "failure";
        case Outcome::Reverted: return "reverted";
    }
    return "skipped";
}

struct ActionRecord {
    std::uint64_t id{0};
    Action action{Action::None};
    Outcome outcome{Outcome::Skipped};
    pid_t pid{0};
    std::string target;      // path, ip:port, sysctl key
    std::string reason;
    std::string detail;      // kernel/tool output or our failure text
    std::string undo_hint;   // how to reverse it, for the GUI
    double risk{0.0};
    core::Severity severity{core::Severity::Info};
    core::SysClock::time_point when{};
    std::chrono::milliseconds duration{};
    bool dry_run{false};
    bool reversible{true};
};

/// A pending decision awaiting an operator, raised by Module 5's escalation
/// pipeline. The GUI shows these as modal prompts; a decision resolves one.
struct PendingDecision {
    std::uint64_t id{0};
    heuristics::EscalationReport report;
    std::string recommendation;   // what we would do if auto_respond were on
    core::SysClock::time_point raised{};
    bool answered{false};
    std::string answer;           // "allow" | "kill" | "suspend" | "quarantine"
    std::string answered_by;
};

/// Network block installed by BlockC2. Tracked so it can be listed and removed.
/// A per-executable network block: the executable's pid tree lives in a
/// dedicated cgroup, and nftables drops every socket belonging to that cgroup.
/// Reversal migrates the surviving pids back and removes rule + cgroup.
struct ExeBlock {
    std::uint64_t id{0};
    std::string exe;              // resolved /proc/<pid>/exe target
    std::string slug;             // filesystem-safe stable name (hash of exe)
    std::string cgroup;           // absolute cgroup path holding the tree
    std::vector<pid_t> pids;      // tasks we moved (best effort; may exit)
    std::string reason;
    core::SysClock::time_point installed{};
    std::chrono::seconds ttl{0};
    bool active{false};
};

/// Pure escalation bookkeeping for the "unknown exe phoning home" policy:
/// record(exe, endpoint) counts DISTINCT blocked endpoints per executable and
/// reports when the exe crosses the threshold. No I/O, no clock, fully
/// unit-testable; the agent owns when to act on a crossing.
class ExeEscalation {
public:
    explicit ExeEscalation(int threshold) noexcept : threshold_(threshold < 1 ? 1 : threshold) {}

    /// Returns true exactly when this endpoint is NEW for the exe AND the exe
    /// now touches threshold_ distinct endpoints (the crossing event).
    [[nodiscard]] bool record(std::string_view exe, std::string_view endpoint) noexcept {
        if (exe.empty() || endpoint.empty()) return false;
        auto& eps = by_exe_[std::string{exe}];
        if (eps.size() >= static_cast<std::size_t>(threshold_)) return false;  // already crossed
        const bool fresh = eps.emplace(std::string{endpoint}).second;
        return fresh && eps.size() == static_cast<std::size_t>(threshold_);
    }
    void forget(std::string_view exe) noexcept { by_exe_.erase(std::string{exe}); }
    [[nodiscard]] std::size_t tracked() const noexcept { return by_exe_.size(); }
    [[nodiscard]] int threshold() const noexcept { return threshold_; }
    [[nodiscard]] std::size_t distinct_for(std::string_view exe) const noexcept {
        const auto it = by_exe_.find(std::string{exe});
        return it == by_exe_.end() ? 0 : it->second.size();
    }

private:
    int threshold_{2};
    std::unordered_map<std::string, std::unordered_set<std::string>> by_exe_;
};

struct C2Block {
    std::uint64_t id{0};
    std::string remote_ip;
    std::uint16_t remote_port{0};
    std::string rule_handle;     // nft rule handle, for `delete rule ... handle N`
    std::string reason;
    core::SysClock::time_point installed{};
    std::chrono::seconds ttl{};  // auto-expire so a false positive self-heals
    bool active{false};
};

/// Capability report so the GUI can show what remediation is actually possible.
struct Capabilities {
    bool can_signal{false};       // we are root / have CAP_KILL
    bool can_cgroup{false};       // cgroup v2 unified hierarchy writable
    bool can_nftables{false};     // nft binary present (or libnftables linked)
    bool can_quarantine{false};   // quarantine dir creatable
    bool can_notify{false};       // notify-send present
    std::string cgroup_root;
    std::string nft_binary;
    std::vector<std::string> notes;
};

class RemediationEngine final : public heuristics::IEscalationBackend,
                                public std::enable_shared_from_this<RemediationEngine> {
public:
    RemediationEngine(core::EventBus& bus, const core::AgentConfig& cfg);

    /// Called once at startup: discovers what we can actually do on this host.
    void probe_capabilities() noexcept;
    [[nodiscard]] const Capabilities& capabilities() const noexcept { return caps_; }

    // ---- process containment -------------------------------------------
    /// SIGSTOP. Refuses protected pids and our own tree.
    bool suspend(pid_t pid, std::string_view reason, std::uint64_t expected_start_ticks = 0) override;
    /// SIGCONT.
    bool resume(pid_t pid) override;
    /// Move the process (and its descendants) into a frozen, resource-capped
    /// cgroup. Reversible; far more thorough than SIGSTOP alone because it stops
    /// the whole tree and its memory/fork growth at once.
    bool isolate(pid_t pid, std::string_view reason) noexcept;
    /// Release from isolation.
    bool release(pid_t pid) noexcept;
    /// SIGKILL. Only reachable above the critical threshold, and never for a
    /// protected pid.
    bool kill(pid_t pid, std::string_view reason, std::uint64_t expected_start_ticks = 0) noexcept;

    // ---- network containment -------------------------------------------
    /// Drop all traffic to remote_ip:port. TTL-bounded so it self-heals.
    /// Block all network access for the executable behind `pid` (its whole pid
    /// tree, present and future children) via cgroup v2 + nftables cgroupv2
    /// match. `resolved_exe` receives the /proc symlink target for reporting.
    bool block_exe(pid_t pid, std::string_view reason, std::chrono::seconds ttl,
                   std::string& resolved_exe) noexcept;
    bool unblock_exe(std::uint64_t block_id) noexcept;
    [[nodiscard]] std::vector<ExeBlock> active_exe_blocks() const noexcept;
    /// Stable, filesystem-safe per-exe slug (pure; unit-tested).
    [[nodiscard]] static std::string exe_slug(std::string_view exe) noexcept;
    /// nft text for the exe cgroup drops (pure; unit-tested). Empty set =>
    /// empty string; a cgroup outside /sys/fs/cgroup => false.
    [[nodiscard]] static bool build_exe_rules(const std::vector<ExeBlock>& blocks,
                                              const std::string& cgroup_root,
                                              std::string& out_rules) noexcept;
    bool block_c2(std::string_view remote_ip, std::uint16_t remote_port,
                  std::string_view reason, std::chrono::seconds ttl) noexcept;
    bool unblock_c2(std::uint64_t block_id) noexcept;
    [[nodiscard]] std::vector<C2Block> active_blocks() const noexcept;
    /// Drop expired blocks; called on the engine's tick.
    void expire_blocks() noexcept;

    // ---- file remediation ----------------------------------------------
    /// Move a file into the quarantine dir with mode 0000 and a metadata sidecar.
    bool quarantine_file(std::string_view path, std::string_view reason) noexcept;
    /// Restore a quarantined file by quarantine id.
    bool restore_file(std::uint64_t quarantine_id, std::string_view dest,
                      bool force_overwrite = false) noexcept;
    [[nodiscard]] std::vector<std::pair<std::uint64_t, std::string>> quarantined() const noexcept;

    // ---- hardening ------------------------------------------------------
    bool apply_sysctl(std::string_view key, std::string_view value, std::string_view reason) noexcept;

    // ---- notification ---------------------------------------------------
    void notify(std::string_view title, std::string_view body, core::Severity sev) noexcept;

    // ---- IEscalationBackend --------------------------------------------
    std::vector<std::string> batch_scan(const std::vector<std::string>& paths) override;
    std::vector<std::string> match_strings(const std::vector<std::string>& strings,
                                           std::string_view label) override;
    void prompt_user(const heuristics::EscalationReport& report) override;

    /// Wire in the pieces owned by other modules (set after construction).
    void set_scanner(std::shared_ptr<class ScannerBridge> s) { scanner_ = std::move(s); }

    // ---- operator-facing API -------------------------------------------
    [[nodiscard]] std::vector<PendingDecision> pending(std::size_t n = 32) const noexcept;
    /// Resolve a prompt. Returns the action taken.
    Action answer(std::uint64_t decision_id, std::string_view answer, std::string_view who = "operator") noexcept;

    [[nodiscard]] std::vector<ActionRecord> history(std::size_t n = 200) const noexcept;
    [[nodiscard]] std::optional<ActionRecord> last(Action a) const noexcept;
    [[nodiscard]] std::uint64_t total_actions() const noexcept { return next_id_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::size_t protected_count() const noexcept;
    [[nodiscard]] std::vector<pid_t> suspended_pids() const noexcept;
    /// Resume everything we suspended -- used on shutdown so we never leave a
    /// frozen process behind.
    void resume_all() noexcept;

    /// Policy gate used by every mutating method.
    [[nodiscard]] bool permitted(Action a, pid_t pid, std::string_view target) const noexcept;

private:
    ActionRecord begin(Action a, pid_t pid, std::string_view target, std::string_view reason,
                       bool reversible) noexcept;
    void finish(ActionRecord& r, Outcome o, std::string_view detail, std::string_view undo = {}) noexcept;
    void journal(const ActionRecord& r) const noexcept;

    bool nft_available() const noexcept;
    bool cgroup_available() const noexcept;
    std::string isolate_cgroup_path(pid_t pid) const noexcept;
    bool write_file_str(std::string_view path, std::string_view content) const noexcept;

    /// Run nft with a program read from a temp file, so rulesets are never
    /// passed through a shell.
    bool run_nft(std::string_view program, std::string& detail) const noexcept;
    /// Rebuild the whole hyprnova table from the current block set.
    ///
    /// nftables can only delete a rule by handle or by an exact textual match,
    /// and both are brittle (handles shift when anything else is inserted; exact
    /// match fails if one field differs). Rebuilding from the authoritative in-
    /// memory set is idempotent, cannot leak stale rules, and costs one nft
    /// invocation per change -- cheap, because the set is bounded and changes are
    /// rare.
    bool apply_block_set(std::string& detail) noexcept;

    core::EventBus& bus_;
    const core::AgentConfig& cfg_;
    Capabilities caps_;

    mutable std::mutex mu_;
    std::deque<ActionRecord> history_;
    std::map<std::uint64_t, PendingDecision> pending_;
    std::unordered_map<std::uint64_t, C2Block> blocks_;
    std::unordered_map<std::uint64_t, ExeBlock> exeblocks_;
    std::unordered_map<std::string, std::string> quarantined_;   // original path -> quarantine path
    std::unordered_map<pid_t, std::string> suspended_by_us_;     // pid -> reason
    mutable std::unordered_set<pid_t> protected_pids_;

    std::shared_ptr<class ScannerBridge> scanner_;
    std::atomic<std::uint64_t> next_id_{1};
    static constexpr std::size_t kMaxHistory = 4096;
};

/// Narrow seam between remediation and the scanning engine, so Module 6 does not
/// depend on Module 3's types. Implemented in scanning/scanner.cpp.
class ScannerBridge {
public:
    virtual ~ScannerBridge() = default;
    /// Scan these paths, return "path: rule" for each detection.
    virtual std::vector<std::string> scan_paths(const std::vector<std::string>& paths) = 0;
    /// Signature-match in-memory strings; return matched rule names.
    virtual std::vector<std::string> scan_strings(const std::vector<std::string>& strings,
                                                  std::string_view label) = 0;
};

}  // namespace hyprnova::remediation
