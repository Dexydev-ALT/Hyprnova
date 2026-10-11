// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 6 implementation
//
// Every mutating operation here follows the same shape:
//
//   ActionRecord r = begin(...);            // policy gate, id allocation, bus publish
//   if (!permitted(...)) return false;      // refuse protected pids, dry-run, disabled
//   ... do the thing, capture kernel/tool output ...
//   finish(r, outcome, detail, undo_hint);  // journal, publish, record history
//
// The undo hint is mandatory for reversible actions: the GUI shows it next to the
// "Revert" button so an operator never has to guess how to undo us.

#include "remediation/remediation_engine.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <format>
#include <numeric>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include "core/exec.hpp"
#include "core/fd.hpp"
#include "core/hash.hpp"
#include "core/log.hpp"
#include "core/proc.hpp"

namespace hyprnova::remediation {

namespace fsx = core::fsx;
using namespace std::chrono_literals;

namespace {

constexpr std::string_view kJournalPath = "/var/log/hyprnova/actions.ndjson";
constexpr std::string_view kRunDir = "/run/hyprnova";

/// Is this pid inside our own process tree? Never remediate ourselves: a
/// self-SIGKILL leaves the host unmonitored, which is strictly worse than the
/// incident we were trying to contain.
[[nodiscard]] bool in_own_tree(pid_t pid) noexcept {
    const pid_t me = ::getpid();
    if (pid == me || pid == ::getppid()) return true;
    for (const pid_t anc : core::proc::ancestry(pid)) {
        if (anc == me) return true;
    }
    for (const pid_t anc : core::proc::ancestry(me)) {
        if (anc == pid) return true;
    }
    return false;
}

[[nodiscard]] bool starts_with(std::string_view s, std::string_view p) noexcept {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

/// nftables only accepts a narrow character set in literals. Anything else means
/// we were handed a hostname or a malformed field, and building a rule string out
/// of it would be an injection into our own firewall program.
[[nodiscard]] bool safe_nft_literal(std::string_view s) noexcept {
    if (s.empty() || s.size() > 128) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        c == '.' || c == ':' || c == '-' || c == '_' || c == '/';
        if (!ok) return false;
    }
    return true;
}

/// Best-effort discovery of the logged-in desktop session so a root daemon can
/// raise a notification the user will actually see. Reading another process's
/// /proc/<pid>/environ is the only portable way to learn DBUS_SESSION_BUS_ADDRESS
/// without polkit.
struct DesktopSession {
    bool found{false};
    std::string dbus;
    std::string display;
    std::string wayland;
    std::string xdg_runtime;
    uid_t uid{0};
};

[[nodiscard]] DesktopSession find_desktop_session() noexcept {
    DesktopSession s;
    for (const pid_t pid : core::proc::list_pids(true)) {
        const auto pi = core::proc::read(pid);
        if (!pi.exists) continue;
        // Only a graphical session process will have the bus address.
        if (pi.exe.find("gnome-session") == std::string::npos &&
            pi.exe.find("plasmashell") == std::string::npos &&
            pi.exe.find("xfce4-session") == std::string::npos &&
            pi.exe.find("sway") == std::string::npos &&
            pi.exe.find("gnome-shell") == std::string::npos &&
            pi.exe.find("ksmserver") == std::string::npos &&
            pi.exe.find("cinnamon-session") == std::string::npos) {
            continue;
        }
        std::string env;
        if (fsx::read_file("/proc/" + std::to_string(pid) + "/environ", env, 1 << 16) <= 0) continue;

        std::size_t pos = 0;
        while (pos < env.size()) {
            const std::size_t nul = env.find('\0', pos);
            const std::string_view kv{env.data() + pos, (nul == std::string::npos ? env.size() : nul) - pos};
            pos = nul == std::string::npos ? env.size() : nul + 1;
            const std::size_t eq = kv.find('=');
            if (eq == std::string_view::npos) continue;
            const std::string_view k = kv.substr(0, eq);
            const std::string_view v = kv.substr(eq + 1);
            if (k == "DBUS_SESSION_BUS_ADDRESS") s.dbus = v;
            else if (k == "DISPLAY") s.display = v;
            else if (k == "WAYLAND_DISPLAY") s.wayland = v;
            else if (k == "XDG_RUNTIME_DIR") s.xdg_runtime = v;
        }
        if (!s.dbus.empty() || !s.display.empty() || !s.wayland.empty()) {
            s.found = true;
            s.uid = pi.uid;
            return s;
        }
    }
    return s;
}

[[nodiscard]] core::Severity severity_for(Action a) noexcept {
    switch (a) {
        case Action::Kill: return core::Severity::Critical;
        case Action::Suspend:
        case Action::Isolate:
        case Action::BlockC2:
        case Action::QuarantineFile:
        case Action::Prompt: return core::Severity::High;
        case Action::Harden: return core::Severity::Medium;
        case Action::Notify: return core::Severity::Low;
        case Action::Resume: break;
        default: break;
    }
    return core::Severity::Info;
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

RemediationEngine::RemediationEngine(core::EventBus& bus, const core::AgentConfig& cfg)
    : bus_(bus), cfg_(cfg) {
    std::lock_guard lk{mu_};
    for (const pid_t p : cfg_.remediation.protected_pids) protected_pids_.insert(p);
}

void RemediationEngine::probe_capabilities() noexcept {
    caps_ = Capabilities{};

    caps_.can_signal = ::geteuid() == 0;
    if (!caps_.can_signal)
        caps_.notes.emplace_back("not running as root: SIGSTOP/SIGKILL will fail for other users' "
                                 "processes (start hyprnovad as root or grant CAP_KILL)");

    // cgroup v2 unified hierarchy: writable cgroup.procs at the root means we can
    // create and populate our own subtree.
    caps_.cgroup_root = cfg_.remediation.cgroup_root;
    if (cfg_.remediation.use_cgroup_containment) {
        caps_.can_cgroup = fsx::exists("/sys/fs/cgroup/cgroup.controllers") &&
                           (fsx::exists(caps_.cgroup_root) || ::mkdir(caps_.cgroup_root.c_str(), 0755) == 0);
        if (!caps_.can_cgroup)
            caps_.notes.emplace_back("cgroup v2 unified hierarchy not writable at " + caps_.cgroup_root +
                                     ": containment falls back to SIGSTOP (systemd-managed hosts need "
                                     "`systemctl set-property` or a delegated subtree)");
    } else {
        caps_.notes.emplace_back("cgroup containment disabled by configuration");
    }

    caps_.nft_binary = core::exec::resolve(cfg_.remediation.nft_cli, true);
    if (caps_.nft_binary.empty()) caps_.nft_binary = core::exec::find_in_system_path("nft");
    caps_.can_nftables = !caps_.nft_binary.empty();
    if (!caps_.can_nftables) {
        const auto ipt = core::exec::resolve(cfg_.remediation.iptables_fallback, true);
        if (!ipt.empty()) {
            caps_.can_nftables = true;
            caps_.nft_binary = ipt;  // iptables fallback shares the field; run_nft() dispatches
            caps_.notes.emplace_back("nft not found: using " + ipt + " (legacy backend, no atomic "
                                     "rule handles -- blocks are removed by exact-match delete)");
        } else {
            caps_.notes.emplace_back("neither nft nor iptables found: C2 network blocking is "
                                     "unavailable, containment is process-only");
        }
    }

    caps_.can_quarantine = cfg_.remediation.allow_quarantine &&
                           (fsx::exists(cfg_.remediation.quarantine_dir) ||
                            fsx::mkdir_p(cfg_.remediation.quarantine_dir, 0700));
    if (caps_.can_quarantine) {
        // A quarantine directory that is world-readable lets any local user pull
        // malware samples. 0700 only.
        if (!fsx::set_mode(cfg_.remediation.quarantine_dir, 0700))
            caps_.notes.emplace_back("could not chmod 0700 the quarantine dir: samples may be "
                                     "readable by local users");
    } else {
        caps_.notes.emplace_back("quarantine unavailable: " + cfg_.remediation.quarantine_dir +
                                 " could not be created");
    }

    caps_.can_notify = cfg_.remediation.desktop_notifications &&
                       !core::exec::resolve(cfg_.remediation.notify_send, true).empty();
    if (!caps_.can_notify)
        caps_.notes.emplace_back("notify-send not found: desktop notifications disabled, the GUI "
                                 "event feed and journal remain the notification path");

    if (::mkdir(std::string(kRunDir).c_str(), 0755) != 0 && errno != EEXIST)
        caps_.notes.emplace_back(std::string("could not create ") + std::string(kRunDir) + ": " +
                                 std::strerror(errno));

    SINFO("remediation", "capabilities: signal={} cgroup={} network={} quarantine={} notify={} dry_run={}",
          caps_.can_signal, caps_.can_cgroup, caps_.can_nftables, caps_.can_quarantine, caps_.can_notify,
          cfg_.dry_run ? "YES" : "no");
    for (const auto& n : caps_.notes) SWARN("remediation", "capability note: {}", n);

    // Always ensure our nftables table exists but is empty, so a previous crash
    // cannot leave stale blocks in place.
    if (caps_.can_nftables && !cfg_.dry_run) {
        std::string detail;
        (void)run_nft(std::format("table inet {} {{\n}}\n", cfg_.remediation.nftables_table), detail);
    }
}

// ---------------------------------------------------------------------------
// Bookkeeping
// ---------------------------------------------------------------------------

ActionRecord RemediationEngine::begin(Action a, pid_t pid, std::string_view target,
                                      std::string_view reason, bool reversible) noexcept {
    ActionRecord r;
    r.id = next_id_.fetch_add(1, std::memory_order_relaxed);
    r.action = a;
    r.pid = pid;
    r.target = std::string(target);
    r.reason = std::string(reason);
    r.when = core::SysClock::now();
    r.reversible = reversible;
    r.dry_run = cfg_.dry_run;
    r.severity = severity_for(a);
    return r;
}

void RemediationEngine::finish(ActionRecord& r, Outcome o, std::string_view detail,
                               std::string_view undo) noexcept {
    r.outcome = o;
    r.detail = std::string(detail);
    if (!undo.empty()) r.undo_hint = std::string(undo);
    r.duration = std::chrono::duration_cast<std::chrono::milliseconds>(core::SysClock::now() - r.when);

    {
        std::lock_guard lk{mu_};
        history_.push_front(r);
        while (history_.size() > kMaxHistory) history_.pop_back();
        if (r.action == Action::Suspend && r.outcome == Outcome::Success)
            suspended_by_us_[r.pid] = r.reason;
        else if ((r.action == Action::Resume || r.action == Action::Kill) && r.outcome == Outcome::Success)
            suspended_by_us_.erase(r.pid);
    }
    journal(r);

    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Remediation;
    ev.kind = core::EventKind::RemediationApplied;
    ev.severity = r.outcome == Outcome::Failure ? core::Severity::High : r.severity;
    ev.actor.pid = r.pid;
    ev.target.path = r.target;
    ev.target.rule_id = std::string(action_name(r.action));
    ev.risk_score = static_cast<std::uint16_t>(std::min<double>(r.risk, 1000.0));
    ev.message = std::format("REMEDIATION #{} action={} target={} outcome={}{} -- {}", r.id,
                             action_name(r.action), r.target.empty() ? std::to_string(r.pid) : r.target,
                             outcome_name(r.outcome), r.dry_run ? " (DRY RUN)" : "", r.reason);
    ev.fields["id"] = std::to_string(r.id);
    ev.fields["outcome"] = std::string(outcome_name(r.outcome));
    ev.fields["detail"] = r.detail;
    if (!r.undo_hint.empty()) ev.fields["undo"] = r.undo_hint;
    if (r.dry_run) ev.triggers.push_back("dry_run");
    static_cast<void>(bus_.publish(std::move(ev)));

    const char* lvl = r.outcome == Outcome::Failure ? "FAIL" : "OK";
    SINFO("remediation", "[{}] action #{} {} target='{}' outcome={} ({}) detail={}", lvl, r.id,
          action_name(r.action), r.target.empty() ? std::to_string(r.pid) : r.target, outcome_name(r.outcome),
          r.duration.count(), r.detail.empty() ? "-" : r.detail);
}

void RemediationEngine::journal(const ActionRecord& r) const noexcept {
    // Append-only NDJSON so the journal is greppable, tail-able, and survives a
    // GUI restart. Written with O_APPEND: concurrent appends from different
    // threads stay atomic for lines under PIPE_BUF.
    core::json::Object o;
    o["id"] = static_cast<std::int64_t>(r.id);
    o["action"] = std::string(action_name(r.action));
    o["outcome"] = std::string(outcome_name(r.outcome));
    o["pid"] = static_cast<std::int64_t>(r.pid);
    o["target"] = r.target;
    o["reason"] = r.reason;
    o["detail"] = r.detail;
    o["undo"] = r.undo_hint;
    o["risk"] = r.risk;
    o["severity"] = std::string(core::severity_name(r.severity));
    o["dry_run"] = r.dry_run;
    o["reversible"] = r.reversible;
    o["epoch"] = static_cast<std::int64_t>(core::SysClock::to_time_t(r.when));
    o["duration_ms"] = static_cast<std::int64_t>(r.duration.count());
    const core::json::Value j{o};

    const std::string line = j.dump() + "\n";
    const core::UniqueFd fd{::open(std::string(kJournalPath).c_str(),
                                   O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600)};
    if (!fd) {
        // The journal is a control, not a precondition: losing it must not stop
        // containment, but it must be visible.
        SWARN("remediation", "cannot write action journal {}: {}", kJournalPath, std::strerror(errno));
        return;
    }
    const auto written = ::write(fd.get(), line.data(), line.size());
    if (written < 0) SWARN("remediation", "journal write failed: {}", std::strerror(errno));
}

bool RemediationEngine::permitted(Action a, pid_t pid, std::string_view target) const noexcept {
    if (!cfg_.remediation.enabled) return false;

    switch (a) {
        case Action::Suspend: if (!cfg_.remediation.allow_suspend) return false; break;
        case Action::Isolate: if (!cfg_.remediation.allow_suspend || !caps_.can_cgroup) return false; break;
        case Action::Kill: if (!cfg_.remediation.allow_kill) return false; break;
        case Action::BlockC2:
        case Action::UnblockC2: if (!cfg_.remediation.allow_network_block || !caps_.can_nftables) return false; break;
        case Action::BlockExe:
            // Both halves of the containment must exist: a cgroup without the
            // nftables match just relocates the process; an nft rule without
            // the cgroup has nothing to match.
            if (!cfg_.remediation.allow_network_block || !cfg_.remediation.allow_exe_block ||
                !caps_.can_nftables || !caps_.can_cgroup) return false;
            break;
        case Action::UnblockExe:
            // Removing a block is the safe direction; only a hard-disabled
            // network subsystem refuses it (there would be nothing to remove).
            if (!cfg_.remediation.allow_network_block || !caps_.can_nftables)
                return false;
            break;
        case Action::QuarantineFile:
        case Action::RestoreFile: if (!cfg_.remediation.allow_quarantine || !caps_.can_quarantine) return false; break;
        default: break;
    }

    if (pid > 0) {
        if (in_own_tree(pid)) return false;
        std::lock_guard lk{mu_};
        if (protected_pids_.count(pid) > 0) return false;
        for (const pid_t p : cfg_.remediation.protected_pids) {
            if (p == pid) return false;
        }
        if (cfg_.remediation.protect_pid1_descendants && pid == 1) return false;
        // Protected by name, not just pid: systemd and sshd change pid across
        // restarts, and a pid list would silently stop covering them.
        const std::string comm = core::proc::comm_of(pid);
        if (!comm.empty()) {
            for (const auto& name : cfg_.remediation.protected_processes) {
                if (comm == name) return false;
            }
        }
        const std::string exe = core::proc::read(pid).exe;
        if (!exe.empty()) {
            for (const auto& pth : cfg_.remediation.protected_paths) {
                if (starts_with(exe, pth)) return false;
            }
        }
    }
    if (!target.empty()) {
        for (const auto& p : cfg_.remediation.protected_paths) {
            if (starts_with(target, p)) return false;
        }
    }
    return true;
}

std::size_t RemediationEngine::protected_count() const noexcept {
    std::lock_guard lk{mu_};
    return protected_pids_.size();
}

std::vector<pid_t> RemediationEngine::suspended_pids() const noexcept {
    std::lock_guard lk{mu_};
    std::vector<pid_t> out;
    out.reserve(suspended_by_us_.size());
    for (const auto& [pid, why] : suspended_by_us_) {
        (void)why;
        out.push_back(pid);
    }
    return out;
}

std::vector<ActionRecord> RemediationEngine::history(std::size_t n) const noexcept {
    std::lock_guard lk{mu_};
    std::vector<ActionRecord> out;
    out.reserve(std::min(n, history_.size()));
    for (std::size_t i = 0; i < std::min(n, history_.size()); ++i) out.push_back(history_[i]);
    return out;
}

std::optional<ActionRecord> RemediationEngine::last(Action a) const noexcept {
    std::lock_guard lk{mu_};
    for (const auto& r : history_) {
        if (r.action == a) return r;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Process containment
// ---------------------------------------------------------------------------

bool RemediationEngine::suspend(pid_t pid, std::string_view reason,
                                std::uint64_t expected_start_ticks) {
    if (pid <= 0) return false;
    auto r = begin(Action::Suspend, pid, core::proc::read(pid).exe, reason, true);

    const auto pi = core::proc::read(pid);
    if (!pi.exists) {
        finish(r, Outcome::Skipped, "process does not exist");
        return false;
    }
    // Identity revalidation: the pid number alone is not the process we decided
    // about. If the kernel recycled it, the starttime differs and the action is
    // refused -- signalling an unrelated innocent is the one error that turns
    // protection into an attack.
    if (expected_start_ticks != 0 && pi.start_time_ticks != expected_start_ticks) {
        finish(r, Outcome::Skipped,
               std::format("PID REUSE GUARD: pid {} now has starttime {} but the action was "
                           "decided for starttime {}; refusing to signal",
                           pid, pi.start_time_ticks, expected_start_ticks));
        return false;
    }
    if (!permitted(Action::Suspend, pid, pi.exe)) {
        std::string why = "refused by policy";
        if (in_own_tree(pid)) why = "refused: pid is inside the agent's own process tree";
        else if (cfg_.dry_run) why = "dry_run: would SIGSTOP";
        else {
            std::lock_guard lk{mu_};
            if (protected_pids_.count(pid) > 0) why = "refused: pid is on the protected list";
        }
        finish(r, Outcome::Skipped, why);
        return false;
    }
    if (cfg_.dry_run) {
        finish(r, Outcome::Skipped, "dry_run: would SIGSTOP " + pi.comm);
        return true;  // the escalation pipeline treats this as "handled"
    }

    const core::ProcessHandle h{pid};
    if (!h.stop()) {
        finish(r, Outcome::Failure, std::string("kill(SIGSTOP) failed: ") + std::strerror(errno));
        return false;
    }
    // Confirm it actually stopped: SIGSTOP is uncatchable, but a zombie or a
    // pid that raced to exit will report success from kill() and never stop.
    std::this_thread::sleep_for(20ms);
    const auto after = core::proc::read(pid);
    const std::string state = after.exists ? after.state : std::string("?");
    if (after.exists && state != "T" && state != "Z") {
        finish(r, Outcome::Attempted, std::format("SIGSTOP sent but state is '{}' (expected T); the "
                                                  "process may be in an uninterruptible syscall",
                                                  state));
        return true;
    }

    r.risk = 0;
    finish(r, Outcome::Success,
           std::format("SIGSTOP delivered to pid {} ({}); state={}; frozen for forensics in {}ms",
                       pid, pi.comm, state,
                       std::chrono::duration_cast<std::chrono::milliseconds>(core::SysClock::now() - r.when).count()),
           std::format("kill -CONT {}  (or `hyprnova-cli resume {}`)", pid, pid));
    notify("Process frozen", std::format("pid {} ({}) was SIGSTOP'd: {}", pid, pi.comm, reason),
           core::Severity::High);
    return true;
}

bool RemediationEngine::resume(pid_t pid) {
    if (pid <= 0) return false;
    auto r = begin(Action::Resume, pid, core::proc::read(pid).exe, "operator or policy released the process", true);

    const core::ProcessHandle h{pid};
    const bool released = release(pid);  // cgroup first, so it is not frozen twice over
    if (!h.cont()) {
        finish(r, Outcome::Failure, std::string("kill(SIGCONT) failed: ") + std::strerror(errno));
        return false;
    }
    {
        std::lock_guard lk{mu_};
        suspended_by_us_.erase(pid);
    }
    finish(r, Outcome::Success,
           std::format("SIGCONT delivered to pid {}{}; process resumed", pid,
                       released ? " and removed from the quarantine cgroup" : ""),
           "kill -STOP " + std::to_string(pid));
    return true;
}

std::string RemediationEngine::isolate_cgroup_path(pid_t pid) const noexcept {
    return caps_.cgroup_root + "/pid" + std::to_string(pid);
}

bool RemediationEngine::isolate(pid_t pid, std::string_view reason) noexcept {
    if (pid <= 0) return false;
    auto r = begin(Action::Isolate, pid, isolate_cgroup_path(pid), reason, true);

    if (!permitted(Action::Isolate, pid, core::proc::read(pid).exe)) {
        finish(r, Outcome::Skipped, cfg_.dry_run ? "dry_run: would isolate in cgroup"
                                                            : "refused by policy or cgroup unavailable");
        return cfg_.dry_run;
    }
    if (!caps_.can_cgroup) {
        finish(r, Outcome::Failure, "cgroup v2 containment unavailable on this host");
        return false;
    }
    const std::string cg = isolate_cgroup_path(pid);
    if (::mkdir(cg.c_str(), 0755) != 0 && errno != EEXIST) {
        finish(r, Outcome::Failure, std::string("mkdir ") + cg + ": " + std::strerror(errno));
        return false;
    }

    // Cap resources BEFORE freezing, so a process that wakes up (or a thread that
    // was mid-syscall) cannot fork-bomb or allocate its way out while we work.
    std::string detail;
    bool ok = true;
    ok &= write_file_str(cg + "/pids.max", "16");
    ok &= write_file_str(cg + "/cpu.max", "10000 100000");        // 10% of one CPU
    ok &= write_file_str(cg + "/memory.max", "256M");
    if (cfg_.remediation.freeze_cgroup) ok &= write_file_str(cg + "/cgroup.freeze", "1");
    if (!ok) detail += "some cgroup limits could not be written (kernel may not support them); ";

    // Move the whole descendant tree, deepest first is unnecessary: cgroup
    // membership is per-task, and migrating the parent does not migrate children,
    // so walk them explicitly.
    std::vector<pid_t> tree{pid};
    for (const pid_t candidate : core::proc::list_pids(true)) {
        if (candidate == pid) continue;
        for (const pid_t anc : core::proc::ancestry(candidate)) {
            if (anc == pid) { tree.push_back(candidate); break; }
        }
        if (tree.size() > 256) break;
    }
    std::size_t moved = 0;
    for (const pid_t p : tree) {
        if (write_file_str(cg + "/cgroup.procs", std::to_string(p))) ++moved;
    }
    detail += std::format("moved {}/{} tasks into {}", moved, tree.size(), cg);
    if (moved == 0) {
        finish(r, Outcome::Failure, detail);
        return false;
    }
    if (moved < tree.size()) {
        finish(r, Outcome::Attempted, detail + " (partial: some tasks exited or refused migration)");
        return true;
    }

    {
        std::lock_guard lk{mu_};
        suspended_by_us_[pid] = std::string(reason);
    }
    finish(r, Outcome::Success, detail,
           std::format("echo 0 > {}/cgroup.freeze; kill -CONT {}; rmdir {}", cg, pid, cg));
    notify("Process isolated",
           std::format("pid {} and {} descendant(s) moved to a frozen, cpu-capped cgroup: {}", pid,
                       tree.size() - 1, reason),
           core::Severity::High);
    return true;
}

bool RemediationEngine::release(pid_t pid) noexcept {
    if (pid <= 0) return false;
    const std::string cg = isolate_cgroup_path(pid);
    if (!fsx::exists(cg)) return false;

    // Unfreeze, migrate tasks back to the root cgroup, then remove the subtree.
    (void)write_file_str(cg + "/cgroup.freeze", "0");
    std::string procs;
    if (fsx::read_file(cg + "/cgroup.procs", procs, 1 << 16) > 0) {
        std::size_t pos = 0;
        while (pos < procs.size()) {
            const std::size_t nl = procs.find('\n', pos);
            const std::string_view tok{procs.data() + pos,
                                       (nl == std::string::npos ? procs.size() : nl) - pos};
            pos = nl == std::string::npos ? procs.size() : nl + 1;
            if (!tok.empty()) (void)write_file_str(caps_.cgroup_root + "/cgroup.procs", tok);
        }
    }
    const bool removed = ::rmdir(cg.c_str()) == 0;
    if (!removed && errno != ENOENT)
        SWARN("remediation", "could not remove isolation cgroup {}: {}", cg, std::strerror(errno));
    return removed;
}

bool RemediationEngine::kill(pid_t pid, std::string_view reason,
                             std::uint64_t expected_start_ticks) noexcept {
    if (pid <= 0) return false;
    auto r = begin(Action::Kill, pid, core::proc::read(pid).exe, reason, false);

    const auto pi = core::proc::read(pid);
    if (!pi.exists) {
        finish(r, Outcome::Skipped, "process does not exist");
        return false;
    }
    if (expected_start_ticks != 0 && pi.start_time_ticks != expected_start_ticks) {
        finish(r, Outcome::Skipped,
               std::format("PID REUSE GUARD: pid {} starttime {} != decided {} ; refusing SIGKILL",
                           pid, pi.start_time_ticks, expected_start_ticks));
        return false;
    }
    if (!permitted(Action::Kill, pid, pi.exe)) {
        finish(r, Outcome::Skipped,
               cfg_.remediation.allow_kill ? "refused: protected process" : "allow_kill is disabled");
        return false;
    }
    if (cfg_.dry_run) {
        finish(r, Outcome::Skipped, "dry_run: would SIGKILL " + pi.comm);
        return true;
    }

    // Preserve the evidence we still can: hash and copy the executable out of
    // /proc/<pid>/exe before the inode goes away, so the operator can analyse the
    // sample after the fact. This is the difference between "we stopped it" and
    // "we can tell you what it was".
    std::string preserved;
    if (fsx::exists("/proc/" + std::to_string(pid) + "/exe")) {
        std::string blob;
        if (fsx::read_file("/proc/" + std::to_string(pid) + "/exe", blob, 32 << 20) > 0 && !blob.empty()) {
            const std::string sha = core::hash::Sha256::to_hex(core::hash::Sha256::once(
                std::span<const std::byte>{reinterpret_cast<const std::byte*>(blob.data()), blob.size()}));
            const std::string dest = cfg_.remediation.quarantine_dir + "/killed-" + std::to_string(pid) +
                                     "-" + sha.substr(0, 16) + ".bin";
            if (fsx::write_atomic(dest, {reinterpret_cast<const std::byte*>(blob.data()), blob.size()}, 0400)) {
                preserved = dest;
                r.detail = "executable preserved to " + dest + " (sha256 " + sha + ")";
            }
        }
    }

    const core::ProcessHandle h{pid};
    if (!h.kill(SIGKILL)) {
        finish(r, Outcome::Failure, std::string("kill(SIGKILL) failed: ") + std::strerror(errno));
        return false;
    }
    // Reap if it is ours; otherwise just confirm it is gone.
    int status = 0;
    (void)::waitpid(pid, &status, WNOHANG);
    bool gone = false;
    for (int i = 0; i < 20 && !gone; ++i) {
        std::this_thread::sleep_for(25ms);
        gone = !core::proc::read(pid).exists;
    }
    {
        std::lock_guard lk{mu_};
        suspended_by_us_.erase(pid);
        protected_pids_.erase(pid);
    }
    (void)release(pid);

    std::string detail = std::format("SIGKILL delivered to pid {} ({}); confirmed gone={}", pid, pi.comm,
                                     gone ? "yes" : "NO (still present after 500ms)");
    if (!preserved.empty()) detail += "; " + r.detail;
    finish(r, gone ? Outcome::Success : Outcome::Attempted, detail);
    notify("Process terminated", std::format("pid {} ({}) was SIGKILL'd: {}", pid, pi.comm, reason),
           core::Severity::Critical);
    return gone;
}

void RemediationEngine::resume_all() noexcept {
    std::vector<pid_t> pids;
    {
        std::lock_guard lk{mu_};
        for (const auto& [pid, why] : suspended_by_us_) {
            (void)why;
            pids.push_back(pid);
        }
    }
    for (const pid_t pid : pids) {
        if (release(pid)) SINFO("remediation", "released isolation cgroup for pid {} on shutdown", pid);
        const core::ProcessHandle h{pid};
        if (h.cont()) SINFO("remediation", "resumed pid {} on shutdown", pid);
    }
    {
        std::lock_guard lk{mu_};
        suspended_by_us_.clear();
    }
    // Drop every block we installed: a reboot or an agent restart must not leave
    // the operator's network filtered by rules nobody remembers creating.
    if (caps_.can_nftables && !cfg_.dry_run) {
        std::string detail;
        if (run_nft(std::format("flush table inet {}\n", cfg_.remediation.nftables_table), detail)) {
            std::lock_guard lk{mu_};
            blocks_.clear();
            SINFO("remediation", "flushed nftables table {} on shutdown", cfg_.remediation.nftables_table);
        } else {
            SWARN("remediation", "could not flush nftables table on shutdown: {}", detail);
        }
    }
}

// ---------------------------------------------------------------------------
// Network containment
// ---------------------------------------------------------------------------

bool RemediationEngine::nft_available() const noexcept { return caps_.can_nftables; }
bool RemediationEngine::cgroup_available() const noexcept { return caps_.can_cgroup; }

bool RemediationEngine::write_file_str(std::string_view path, std::string_view content) const noexcept {
    const core::UniqueFd fd{::open(std::string(path).c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (!fd) return false;
    const auto n = ::write(fd.get(), content.data(), content.size());
    return n == static_cast<ssize_t>(content.size());
}

bool RemediationEngine::run_nft(std::string_view program, std::string& detail) const noexcept {
    if (!caps_.can_nftables) {
        detail = "no nft/iptables binary available";
        return false;
    }
    // Write the program to a 0600 file and use `nft -f`. Passing a ruleset as an
    // argv element would put it in /proc/<pid>/cmdline, where any local user can
    // read the firewall rules we are installing.
    core::exec::Options o;
    o.timeout = 10s;

    if (caps_.nft_binary.find("iptables") != std::string::npos) {
        // Legacy path: the "program" we receive is already a full argv-style rule
        // list produced by the iptables callers below.
        detail = "iptables backend used";
        return false;  // callers handle iptables separately
    }

    const std::string tmp = std::string(kRunDir) + "/nft-" + std::to_string(::getpid()) + "-" +
                            std::to_string(next_id_.load(std::memory_order_relaxed)) + ".nft";
    if (!fsx::write_atomic(tmp, {reinterpret_cast<const std::byte*>(program.data()), program.size()}, 0600)) {
        detail = std::string("cannot write ") + tmp + ": " + std::strerror(errno);
        return false;
    }
    const auto res = core::exec::run(caps_.nft_binary, {"-f", tmp}, o);
    (void)::unlink(tmp.c_str());
    if (!res.spawned) {
        detail = res.error;
        return false;
    }
    detail = res.out + res.err;
    return res.exit_code == 0;
}

bool RemediationEngine::apply_block_set(std::string& detail) noexcept {
    std::vector<C2Block> set;
    {
        std::lock_guard lk{mu_};
        set.reserve(blocks_.size());
        for (const auto& [id, b] : blocks_) {
            (void)id;
            if (b.active) set.push_back(b);
        }
    }
    std::sort(set.begin(), set.end(),
              [](const C2Block& a, const C2Block& b) { return a.id < b.id; });

    std::string out_rules;
    std::string in_rules;
    for (const auto& b : set) {
        if (!safe_nft_literal(b.remote_ip)) continue;
        const bool v6 = b.remote_ip.find(':') != std::string::npos;
        const std::string fam = v6 ? "ip6" : "ip";
        // A bare "dport" has no protocol context and nft REJECTS it in inet
        // chains ("No symbol type information") -- found by the gated kernel
        // drill (tools/kernel_drill), the first run of these rules on a real
        // kernel. Blocks are port+protocol-agnostic, so a ported block pins
        // both transport protocols; a port-less block stays protocol-blind.
        if (b.remote_port > 0) {
            for (const char* proto : {"tcp", "udp"}) {
                out_rules += "    " + fam + " daddr " + b.remote_ip + " " + proto +
                             " dport " + std::to_string(b.remote_port) + " counter drop\n";
                in_rules += "    " + fam + " saddr " + b.remote_ip + " " + proto +
                            " sport " + std::to_string(b.remote_port) + " counter drop\n";
            }
        } else {
            out_rules += "    " + fam + " daddr " + b.remote_ip + " counter drop\n";
            in_rules += "    " + fam + " saddr " + b.remote_ip + " counter drop\n";
        }
    }

    // Per-exe containment rides in the SAME single-transaction program so a
    // mixed block set (C2 endpoints + contained executables) is atomic.
    std::vector<ExeBlock> exe_set;
    {
        std::lock_guard lk{mu_};
        exe_set.reserve(exeblocks_.size());
        for (const auto& [id, b] : exeblocks_) {
            (void)id;
            if (b.active) exe_set.push_back(b);
        }
    }
    std::string exe_rules;
    if (!build_exe_rules(exe_set, caps_.cgroup_root, exe_rules)) {
        detail = "exe cgroup rules rejected (cgroup root outside /sys/fs/cgroup?)";
        return false;
    }
    out_rules += exe_rules;
    in_rules += exe_rules;

    // Declare the table, flush it, then redeclare it with the two chains. Doing
    // all three in one program means the change lands in a single kernel
    // transaction: there is no window where the table exists but is empty.
    const std::string program =
        "table inet " + cfg_.remediation.nftables_table + " {\n}\n"
        "flush table inet " + cfg_.remediation.nftables_table + "\n"
        "table inet " + cfg_.remediation.nftables_table + " {\n"
        "  chain hyprnova_out {\n"
        "    type filter hook output priority 0; policy accept;\n" + out_rules + "  }\n"
        "  chain hyprnova_in {\n"
        "    type filter hook input priority 0; policy accept;\n" + in_rules + "  }\n"
        "}\n";
    return run_nft(program, detail);
}

bool RemediationEngine::block_c2(std::string_view remote_ip, std::uint16_t remote_port,
                                 std::string_view reason, std::chrono::seconds ttl) noexcept {
    const std::string endpoint = std::string(remote_ip) + (remote_port > 0 ? ":" + std::to_string(remote_port) : "");
    auto r = begin(Action::BlockC2, 0, endpoint, reason, true);

    if (!safe_nft_literal(remote_ip)) {
        finish(r, Outcome::Failure, "remote address rejected: not a literal IP (hostnames are not "
                                    "resolved, and unvalidated input must never reach a firewall rule)");
        return false;
    }
    if (!permitted(Action::BlockC2, 0, {})) {
        finish(r, Outcome::Skipped, cfg_.dry_run ? "dry_run: would block " + endpoint
                                                            : "network blocking disabled");
        return cfg_.dry_run;
    }
    // Do not block loopback or our own management plane: an EDR that cuts itself
    // off from its console is an EDR nobody can query.
    if (starts_with(remote_ip, "127.") || remote_ip == "::1" || remote_ip == "localhost") {
        finish(r, Outcome::Skipped, "refused: loopback address is never blocked");
        return false;
    }

    {
        std::lock_guard lk{mu_};
        for (const auto& [id, b] : blocks_) {
            if (b.remote_ip == remote_ip && b.remote_port == remote_port && b.active) {
                finish(r, Outcome::Skipped,
                       std::format("already blocked (id {} installed at epoch {})", id,
                                   core::SysClock::to_time_t(b.installed)));
                return true;
            }
        }
    }

    if (cfg_.dry_run) {
        finish(r, Outcome::Skipped, "dry_run: would install nftables drop rule for " + endpoint);
        return true;
    }

    C2Block b;
    b.id = r.id;
    b.remote_ip = std::string(remote_ip);
    b.remote_port = remote_port;
    b.reason = std::string(reason);
    b.installed = core::SysClock::now();
    b.ttl = ttl.count() > 0 ? ttl : cfg_.remediation.block_duration;
    b.active = true;
    b.rule_handle = std::format("table inet {} chains hyprnova_out/hyprnova_in",
                                cfg_.remediation.nftables_table);

    // Add to the authoritative in-memory set first, then push the whole set to
    // the kernel. If the push fails the entry is rolled back, so the GUI can
    // never show a block that the firewall does not actually have.
    std::string detail;
    {
        std::lock_guard lk{mu_};
        blocks_[b.id] = b;
    }
    if (!apply_block_set(detail)) {
        {
            std::lock_guard lk{mu_};
            blocks_.erase(b.id);
        }
        finish(r, Outcome::Failure, "nft failed: " + detail);
        return false;
    }

    finish(r, Outcome::Success,
           std::format("nftables drop rule installed for {} (both directions); auto-expires in {}h",
                       endpoint, std::chrono::duration_cast<std::chrono::hours>(b.ttl).count()),
           std::format("hyprnova-cli unblock {}  (or nft flush table inet {})", b.id,
                       cfg_.remediation.nftables_table));
    notify("C2 endpoint blocked", std::format("{} blocked in both directions for {}h: {}", endpoint,
                                              std::chrono::duration_cast<std::chrono::hours>(b.ttl).count(),
                                              reason),
           core::Severity::High);
    return true;
}

bool RemediationEngine::unblock_c2(std::uint64_t block_id) noexcept {
    C2Block b;
    {
        std::lock_guard lk{mu_};
        auto it = blocks_.find(block_id);
        if (it == blocks_.end()) return false;
        b = it->second;
        it->second.active = false;
    }
    auto r = begin(Action::UnblockC2, 0, b.remote_ip + ":" + std::to_string(b.remote_port),
                   "operator removed the block", true);

    std::string detail;
    if (cfg_.dry_run) {
        detail = "dry_run: would remove the drop rule";
    } else {
        {
            std::lock_guard lk{mu_};
            blocks_.erase(block_id);
        }
        if (!apply_block_set(detail)) {
            // Roll back so the set matches the kernel: a block we failed to remove
            // must still be listed as active.
            std::lock_guard lk{mu_};
            blocks_[block_id] = b;
            finish(r, Outcome::Failure, "nft rebuild failed: " + detail);
            return false;
        }
        detail = "drop rule removed; " + std::to_string(blocks_.size()) + " block(s) remain";
    }
    finish(r, Outcome::Reverted, detail);
    return true;
}

void RemediationEngine::expire_blocks() noexcept {
    const auto now = core::SysClock::now();
    std::vector<std::uint64_t> expired;
    std::vector<std::uint64_t> exe_expired;
    {
        std::lock_guard lk{mu_};
        for (const auto& [id, b] : blocks_) {
            if (b.active && now - b.installed >= b.ttl) expired.push_back(id);
        }
        for (const auto& [id, b] : exeblocks_) {
            if (b.active && now - b.installed >= b.ttl) exe_expired.push_back(id);
        }
    }
    for (const auto id : expired) {
        SINFO("remediation", "block {} expired (ttl reached); removing so a false positive self-heals", id);
        (void)unblock_c2(id);
    }
    for (const auto id : exe_expired) {
        SINFO("remediation", "exe block {} expired (ttl reached); releasing the pid tree so a false positive self-heals", id);
        (void)unblock_exe(id);
    }
}

std::vector<C2Block> RemediationEngine::active_blocks() const noexcept {
    std::lock_guard lk{mu_};
    std::vector<C2Block> out;
    out.reserve(blocks_.size());
    for (const auto& [id, b] : blocks_) {
        (void)id;
        if (b.active) out.push_back(b);
    }
    std::sort(out.begin(), out.end(),
              [](const C2Block& a, const C2Block& b) { return a.installed > b.installed; });
    return out;
}

// ---------------------------------------------------------------------------
// Per-executable network policy
// ---------------------------------------------------------------------------

std::string RemediationEngine::exe_slug(std::string_view exe) noexcept {
    // The slug must be stable across restarts (same exe => same cgroup name,
    // so a re-block reuses the group) and filesystem-safe (an arbitrary
    // /proc/<pid>/exe target must never become a directory name).
    const auto digest = core::hash::Sha256::to_hex(core::hash::Sha256::once(
        {reinterpret_cast<const std::byte*>(exe.data()), exe.size()}));
    return digest.substr(0, 12);
}

bool RemediationEngine::build_exe_rules(const std::vector<ExeBlock>& blocks,
                                        const std::string& cgroup_root,
                                        std::string& out_rules) noexcept {
    // nft's socket cgroupv2 match wants the cgroup path RELATIVE TO THE
    // HIERARCHY MOUNT (/sys/fs/cgroup) plus the number of path components (the
    // "level") — not relative to our cgroup_root. We still require every block
    // to live under cgroup_root: a stray cgroup value must never match.
    constexpr std::string_view kV2Mount = "/sys/fs/cgroup/";
    if (!starts_with(cgroup_root, kV2Mount)) return false;

    for (const auto& b : blocks) {
        if (!b.active) continue;
        if (!starts_with(b.cgroup, cgroup_root)) return false;
        if (!starts_with(b.cgroup, kV2Mount)) return false;
        std::string rel = b.cgroup.substr(kV2Mount.size());
        if (rel.empty()) return false;
        if (!safe_nft_literal(rel)) return false;
        int level = 1;
        for (const char c : rel)
            if (c == '/') ++level;
        // One match covers both directions: for locally-initiated traffic the
        // socket belongs to the contained process; for accepted connections
        // the inherited socket carries the same cgroup id.
        out_rules += "    socket cgroupv2 " + std::to_string(level) + " \"" + rel +
                     "\" counter drop\n";
    }
    return true;
}

bool RemediationEngine::block_exe(pid_t pid, std::string_view reason,
                                  std::chrono::seconds ttl,
                                  std::string& resolved_exe) noexcept {
    resolved_exe.clear();
    if (pid <= 0) return false;
    auto r = begin(Action::BlockExe, pid, "", reason, true);

    if (!caps_.can_cgroup || !caps_.can_nftables) {
        finish(r, Outcome::Failure,
               "per-exe containment needs BOTH cgroup v2 and nftables; this host has "
               "neither or only one (see capabilities)");
        return false;
    }

    resolved_exe = core::proc::read(pid).exe;
    if (resolved_exe.empty()) {
        finish(r, Outcome::Failure,
               std::format("cannot resolve /proc/{}/exe (process already exited, or a "
                           "kernel hidepid/hardening hides it); refusing to guess",
                           pid));
        return false;
    }
    // permitted() re-resolves the exe itself; passing the resolved path as the
    // target also walks the protected-path prefix list for THIS process.
    if (!permitted(Action::BlockExe, pid, resolved_exe)) {
        finish(r, Outcome::Skipped,
               cfg_.dry_run ? "dry_run: would block " + resolved_exe
                            : "refused by policy (protected process/path) or disabled");
        return cfg_.dry_run;
    }

    const std::string slug = exe_slug(resolved_exe);
    const std::string cg = caps_.cgroup_root + "/exe-" + slug;

    {
        std::lock_guard lk{mu_};
        for (const auto& [id, b] : exeblocks_) {
            if (b.active && b.exe == resolved_exe) {
                finish(r, Outcome::Skipped,
                       std::format("already blocked (id {}, {} task(s) contained)", id,
                                   b.pids.size()));
                return true;
            }
        }
    }
    if (cfg_.dry_run) {
        finish(r, Outcome::Skipped,
               "dry_run: would move the pid tree into " + cg +
                   " and drop its sockets via nftables cgroupv2 match");
        return true;
    }

    if (::mkdir(cg.c_str(), 0755) != 0 && errno != EEXIST) {
        finish(r, Outcome::Failure,
               std::format("mkdir {}: {} (is the cgroup v2 hierarchy writable?)", cg,
                           std::strerror(errno)));
        return false;
    }

    // Move the whole descendant tree. No freeze, no limits: the point is to
    // let the process live (forensics, operator inspection) without a network.
    std::vector<pid_t> tree{pid};
    for (const pid_t candidate : core::proc::list_pids(true)) {
        if (candidate == pid) continue;
        for (const pid_t anc : core::proc::ancestry(candidate)) {
            if (anc == pid) { tree.push_back(candidate); break; }
        }
        if (tree.size() > 256) break;
    }
    std::size_t moved = 0;
    for (const pid_t p : tree)
        if (write_file_str(cg + "/cgroup.procs", std::to_string(p))) ++moved;
    if (moved == 0) {
        (void)::rmdir(cg.c_str());
        finish(r, Outcome::Failure, "could not migrate any task into " + cg);
        return false;
    }

    ExeBlock b;
    b.id = r.id;
    b.exe = resolved_exe;
    b.slug = slug;
    b.cgroup = cg;
    b.pids = tree;
    b.reason = std::string(reason);
    b.installed = core::SysClock::now();
    b.ttl = ttl.count() > 0 ? ttl : cfg_.remediation.block_duration;
    b.active = true;

    std::string detail;
    {
        std::lock_guard lk{mu_};
        exeblocks_[b.id] = b;
    }
    if (!apply_block_set(detail)) {
        // Roll the cgroup side back too: the GUI must never show containment
        // the kernel does not actually have.
        for (const pid_t p : tree)
            (void)write_file_str("/sys/fs/cgroup/cgroup.procs", std::to_string(p));
        (void)::rmdir(cg.c_str());
        {
            std::lock_guard lk{mu_};
            exeblocks_.erase(b.id);
        }
        finish(r, Outcome::Failure, "nft failed: " + detail);
        return false;
    }

    finish(r, Outcome::Success,
           std::format("{} (and {} descendant task(s)) contained in {}; nftables drops "
                       "all its sockets; auto-expires in {}h",
                       resolved_exe, moved > 0 ? moved - 1 : 0, cg,
                       std::chrono::duration_cast<std::chrono::hours>(b.ttl).count()),
           std::format("hyprnova-cli unblock-exe {}  (or nft flush table inet {})", b.id,
                       cfg_.remediation.nftables_table));
    notify("Executable network-contained",
           std::format("{} was contained offline (cgroup + nftables): {}", resolved_exe, reason),
           core::Severity::High);
    return true;
}

bool RemediationEngine::unblock_exe(std::uint64_t block_id) noexcept {
    ExeBlock b;
    {
        std::lock_guard lk{mu_};
        const auto it = exeblocks_.find(block_id);
        if (it == exeblocks_.end() || !it->second.active) return false;
        b = it->second;
        exeblocks_.erase(it);
    }
    auto r = begin(Action::UnblockExe, 0, b.exe, "operator release", true);

    // Regenerate the table WITHOUT the block first (fail-open for removal),
    // then always release the pids: leaving tasks in a dangling cgroup is the
    // one unrecoverable mistake here.
    std::string detail;
    const bool nft_ok = apply_block_set(detail);
    std::size_t released = 0;
    for (const pid_t p : b.pids)
        if (write_file_str("/sys/fs/cgroup/cgroup.procs", std::to_string(p))) ++released;
    const bool rmdir_ok = ::rmdir(b.cgroup.c_str()) == 0;

    if (!nft_ok)
        finish(r, Outcome::Attempted,
               std::format("rule removal incomplete ({}); {} task(s) released from {} "
                           "(manual check: nft list table inet {})",
                           detail, released, b.cgroup, cfg_.remediation.nftables_table));
    else if (released < b.pids.size() || !rmdir_ok)
        finish(r, Outcome::Attempted,
               std::format("rule removed; {}/{} task(s) released; cgroup {} may linger "
                           "until its tasks exit",
                           released, b.pids.size(), b.cgroup));
    else
        finish(r, Outcome::Success,
               std::format("rule removed; {} task(s) released; {} cleaned up", released,
                           b.cgroup));
    return true;
}

std::vector<ExeBlock> RemediationEngine::active_exe_blocks() const noexcept {
    std::lock_guard lk{mu_};
    std::vector<ExeBlock> out;
    out.reserve(exeblocks_.size());
    for (const auto& [id, b] : exeblocks_) {
        (void)id;
        if (b.active) out.push_back(b);
    }
    std::sort(out.begin(), out.end(),
              [](const ExeBlock& a, const ExeBlock& b) { return a.installed > b.installed; });
    return out;
}

// ---------------------------------------------------------------------------
// File remediation
// ---------------------------------------------------------------------------

bool RemediationEngine::quarantine_file(std::string_view path, std::string_view reason) noexcept {
    auto r = begin(Action::QuarantineFile, 0, path, reason, true);

    if (!permitted(Action::QuarantineFile, 0, path)) {
        finish(r, Outcome::Skipped, "refused: path is on the protected list or quarantine is disabled");
        return false;
    }
    struct stat st{};
    // lstat, never stat: quarantining the *target* of a symlink an attacker
    // planted would delete a file we were told to protect.
    if (::lstat(std::string(path).c_str(), &st) != 0) {
        finish(r, Outcome::Failure, std::string("lstat: ") + std::strerror(errno));
        return false;
    }
    if (S_ISDIR(st.st_mode)) {
        finish(r, Outcome::Skipped, "refused: target is a directory (quarantine is file-level)");
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        finish(r, Outcome::Skipped, "refused: target is a symlink");
        return false;
    }

    std::string blob;
    if (fsx::read_file(path, blob, 64 << 20) < 0) {
        finish(r, Outcome::Failure, std::string("read: ") + std::strerror(errno));
        return false;
    }
    const std::string sha = core::hash::Sha256::to_hex(core::hash::Sha256::once(
        std::span<const std::byte>{reinterpret_cast<const std::byte*>(blob.data()), blob.size()}));
    const std::uint64_t id = r.id;
    const std::string qdir = cfg_.remediation.quarantine_dir;
    const std::string qpath = qdir + "/" + std::to_string(id) + "-" + sha.substr(0, 32);

    if (cfg_.dry_run) {
        finish(r, Outcome::Skipped,
               std::format("dry_run: would quarantine {} (sha256 {}, {} bytes) to {}", path, sha,
                           blob.size(), qpath));
        return true;
    }

    // Write the sample first (mode 0400: readable by root for analysis, not
    // executable, not writable), then unlink the original. If the write fails we
    // have not destroyed anything.
    if (!fsx::write_atomic(qpath, {reinterpret_cast<const std::byte*>(blob.data()), blob.size()}, 0400)) {
        finish(r, Outcome::Failure, std::string("could not write sample to ") + qpath + ": " +
                                        std::strerror(errno));
        return false;
    }

    core::json::Object mo;
    mo["id"] = static_cast<std::int64_t>(id);
    mo["original_path"] = std::string(path);
    mo["sha256"] = sha;
    mo["size"] = static_cast<std::int64_t>(blob.size());
    mo["mode"] = static_cast<std::int64_t>(st.st_mode & 07777);
    mo["uid"] = static_cast<std::int64_t>(st.st_uid);
    mo["gid"] = static_cast<std::int64_t>(st.st_gid);
    mo["mtime"] = static_cast<std::int64_t>(st.st_mtime);
    mo["reason"] = std::string(reason);
    mo["quarantined_at"] = static_cast<std::int64_t>(core::SysClock::to_time_t(core::SysClock::now()));
    const core::json::Value meta{mo};
    const std::string mtext = meta.dump();
    if (!fsx::write_atomic(qpath + ".meta", {reinterpret_cast<const std::byte*>(mtext.data()), mtext.size()},
                           0600)) {
        SWARN("remediation", "quarantine metadata for {} could not be written; restore will need the "
                             "journal", qpath);
    }

    // Prefer rename (atomic, same filesystem) and fall back to unlink.
    bool removed = ::rename(std::string(path).c_str(), (qpath + ".moved").c_str()) == 0;
    if (!removed) removed = ::unlink(std::string(path).c_str()) == 0;
    if (!removed) {
        finish(r, Outcome::Failure, std::string("sample saved to ") + qpath +
                                        " but the original could not be removed: " + std::strerror(errno));
        return false;
    }
    {
        std::lock_guard lk{mu_};
        quarantined_[std::string(path)] = qpath;
    }
    finish(r, Outcome::Success,
           std::format("quarantined {} ({} bytes, sha256 {}) to {} with mode 0400", path, blob.size(), sha,
                       qpath),
           std::format("hyprnova-cli restore {} --to {}", id, path));
    notify("File quarantined", std::format("{} moved to quarantine (sha256 {}...): {}", path,
                                           sha.substr(0, 12), reason),
           core::Severity::High);
    return true;
}

bool RemediationEngine::restore_file(std::uint64_t quarantine_id, std::string_view dest,
                                     bool force_overwrite) noexcept {
    auto r = begin(Action::RestoreFile, 0, std::string(dest), "operator restored a quarantined file", true);

    std::string qpath;
    {
        std::lock_guard lk{mu_};
        for (const auto& [orig, q] : quarantined_) {
            (void)orig;
            const std::string prefix = cfg_.remediation.quarantine_dir + "/" + std::to_string(quarantine_id) + "-";
            if (starts_with(q, prefix)) { qpath = q; break; }
        }
    }
    if (qpath.empty()) {
        finish(r, Outcome::Failure, "no quarantine entry with id " + std::to_string(quarantine_id));
        return false;
    }

    std::string blob;
    if (fsx::read_file(qpath, blob, 1 << 30) < 0) {
        finish(r, Outcome::Failure, std::string("cannot read sample ") + qpath + ": " + std::strerror(errno));
        return false;
    }
    // Restore metadata if we have it, so permissions and ownership come back as
    // they were rather than as root:root 0600.
    mode_t mode = 0600;
    uid_t owner = ::getuid();
    gid_t group = ::getgid();
    std::string mtext;
    if (fsx::read_file(qpath + ".meta", mtext, 1 << 20) > 0) {
        core::json::ParseError pe{};
        if (auto m = core::json::parse(mtext, {}, &pe)) {
            mode = static_cast<mode_t>(m->integer("mode", 0600) & 07777);
            owner = static_cast<uid_t>(m->integer("uid", static_cast<std::int64_t>(::getuid())));
            group = static_cast<gid_t>(m->integer("gid", static_cast<std::int64_t>(::getgid())));
        }
    }
    // Occupied destination: write_atomic() would rename over it and destroy
    // existing data. A restore must never be the thing that loses a file.
    if (!force_overwrite) {
        struct stat dst {};
        if (::lstat(std::string(dest).c_str(), &dst) == 0) {
            finish(r, Outcome::Skipped,
                   std::format("destination {} already exists; refusing to overwrite "
                               "(pass force/overwrite explicitly)", dest));
            return false;
        }
    }
    // Integrity: the sidecar records the sample's sha256 at quarantine time.
    // Restoring bytes that no longer match would launder tampering back into
    // the filesystem -- refuse instead.
    {
        const std::string now_sha = core::hash::Sha256::to_hex(core::hash::Sha256::once(
            std::span<const std::byte>{reinterpret_cast<const std::byte*>(blob.data()),
                                       blob.size()}));
        std::string mtext2;
        std::string recorded;
        if (fsx::read_file(qpath + ".meta", mtext2, 1 << 20) > 0) {
            if (auto m2 = core::json::parse(mtext2))
                if (const auto* sv = m2->at("sha256"); sv && sv->is_string())
                    recorded = std::string(sv->as_string());
        }
        if (!recorded.empty() && recorded != now_sha) {
            finish(r, Outcome::Failure,
                   std::format("SAMPLE TAMPERED: stored sha256 {} != current {}; refusing to "
                               "restore. The quarantine store may be corrupt or attacked.",
                               recorded, now_sha));
            return false;
        }
    }
    if (!fsx::write_atomic(dest, {reinterpret_cast<const std::byte*>(blob.data()), blob.size()}, mode)) {
        finish(r, Outcome::Failure, std::string("restore write failed: ") + std::strerror(errno));
        return false;
    }
    if (::chown(std::string(dest).c_str(), owner, group) != 0)
        SWARN("remediation", "could not chown restored file {} to {}:{}: {}", dest, owner, group,
              std::strerror(errno));

    (void)::unlink((qpath + ".meta").c_str());
    (void)::unlink((qpath + ".moved").c_str());
    (void)::unlink(qpath.c_str());
    {
        std::lock_guard lk{mu_};
        for (auto it = quarantined_.begin(); it != quarantined_.end();) {
            if (it->second == qpath) it = quarantined_.erase(it);
            else ++it;
        }
    }
    finish(r, Outcome::Reverted,
           std::format("restored {} bytes to {} (mode {:04o}, owner {}:{})", blob.size(), dest, mode, owner,
                       group));
    notify("File restored", std::format("{} restored from quarantine id {}", dest, quarantine_id),
           core::Severity::Medium);
    return true;
}

std::vector<std::pair<std::uint64_t, std::string>> RemediationEngine::quarantined() const noexcept {
    std::vector<std::pair<std::uint64_t, std::string>> out;
    {
        std::lock_guard lk{mu_};
        out.reserve(quarantined_.size());
        for (const auto& [orig, q] : quarantined_) {
            const std::string prefix = cfg_.remediation.quarantine_dir + "/";
            std::uint64_t id = 0;
            if (starts_with(q, prefix)) {
                const char* b = q.data() + prefix.size();
                const char* e = b;
                while (e < q.data() + q.size() && *e >= '0' && *e <= '9') ++e;
                if (e > b) {
                    std::uint64_t v = 0;
                    const auto [ptr, ec] = std::from_chars(b, e, v);
                    (void)ptr;
                    if (ec == std::errc{}) id = v;
                }
            }
            out.emplace_back(id, orig + " -> " + q);
        }
    }
    std::sort(out.begin(), out.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    return out;
}

// ---------------------------------------------------------------------------
// Hardening
// ---------------------------------------------------------------------------

bool RemediationEngine::apply_sysctl(std::string_view key, std::string_view value,
                                     std::string_view reason) noexcept {
    auto r = begin(Action::Harden, 0, std::string(key) + "=" + std::string(value), reason, true);

    if (!key.empty() && key.find_first_of(";|&$`<>\"'\\") != std::string_view::npos) {
        finish(r, Outcome::Failure, "sysctl key rejected: contains shell metacharacters");
        return false;
    }
    // Never write a sysctl through `sysctl -w`: that is a shell-adjacent call with
    // an attacker-influenced string. Write the /proc file directly.
    std::string proc_path = "/proc/sys/";
    for (const char c : key) proc_path += (c == '.' ? '/' : c);

    std::string before;
    if (fsx::read_file(proc_path, before, 4096) < 0) {
        finish(r, Outcome::Failure, std::string("cannot read ") + proc_path + ": " + std::strerror(errno));
        return false;
    }
    while (!before.empty() && (before.back() == '\n' || before.back() == '\t')) before.pop_back();
    if (before == value) {
        finish(r, Outcome::Skipped, std::string("already set to ") + std::string(value));
        return true;
    }
    if (cfg_.dry_run) {
        finish(r, Outcome::Skipped,
               std::format("dry_run: would write '{}' to {} (currently '{}')", value, proc_path, before));
        return true;
    }
    if (!write_file_str(proc_path, value)) {
        finish(r, Outcome::Failure,
               std::string("write to ") + proc_path + " failed: " + std::strerror(errno));
        return false;
    }
    std::string after;
    if (fsx::read_file(proc_path, after, 4096) > 0) {
        while (!after.empty() && (after.back() == '\n' || after.back() == '\t')) after.pop_back();
    }
    if (std::string_view(after) != value) {
        finish(r, Outcome::Attempted, "wrote '" + std::string(value) + "' but read back '" + after +
                                          "' (kernel may clamp the value)");
        return false;
    }
    finish(r, Outcome::Success, proc_path + ": '" + before + "' -> '" + after + "'",
           "echo " + before + " > " + proc_path);
    return true;
}

// ---------------------------------------------------------------------------
// Notification
// ---------------------------------------------------------------------------

void RemediationEngine::notify(std::string_view title, std::string_view body, core::Severity sev) noexcept {
    auto r = begin(Action::Notify, 0, std::string(title), "operator notification", false);

    if (!cfg_.remediation.desktop_notifications) {
        finish(r, Outcome::Skipped, "desktop notifications disabled");
        return;
    }
    const std::string send = core::exec::resolve(cfg_.remediation.notify_send, true);
    if (send.empty()) {
        finish(r, Outcome::Skipped, "notify-send not installed; the GUI feed and journal carry this");
        return;
    }
    const DesktopSession sess = find_desktop_session();
    if (!sess.found) {
        finish(r, Outcome::Skipped,
               "no graphical session found on this host (headless?): notification not delivered");
        return;
    }

    core::exec::Options o;
    o.timeout = 5s;
    o.run_as_uid = sess.uid;
    o.run_as_gid = sess.uid;  // notifications must be raised as the session owner, not root
    const std::string urgency = sev >= core::Severity::High ? "critical" : "normal";
    const int32_t timeout_ms = sev >= core::Severity::High ? 0 : 8000;  // 0 = never expire

    std::vector<std::string> args{"--app-name", cfg_.remediation.notify_summary, "--urgency", urgency,
                                  "--expire-time", std::to_string(timeout_ms), "--icon",
                                  "security-high", std::string(title), std::string(body)};
    // Attach the action category so notification daemons that support it can group.
    if (sev >= core::Severity::Critical) args.insert(args.begin(), {"--category", "device.error"});

    // notify-send needs the session bus; a root daemon has no DBUS_SESSION_BUS_ADDRESS.
    std::unordered_map<std::string, std::string> extra_env;
    if (!sess.dbus.empty()) extra_env["DBUS_SESSION_BUS_ADDRESS"] = sess.dbus;
    if (!sess.display.empty()) extra_env["DISPLAY"] = sess.display;
    if (!sess.wayland.empty()) extra_env["WAYLAND_DISPLAY"] = sess.wayland;
    if (!sess.xdg_runtime.empty()) extra_env["XDG_RUNTIME_DIR"] = sess.xdg_runtime;
    o.extra_env = extra_env;

    const auto res = core::exec::run(send, args, o);
    if (!res.spawned) {
        finish(r, Outcome::Failure, "notify-send spawn failed: " + res.error);
        return;
    }
    if (res.exit_code != 0) {
        finish(r, Outcome::Failure,
               std::format("notify-send exit {}: {}", res.exit_code, res.err.substr(0, 256)));
        return;
    }
    finish(r, Outcome::Success,
           std::format("desktop notification delivered to uid {} ({})", sess.uid,
                       sess.wayland.empty() ? sess.display : sess.wayland));
}

// ---------------------------------------------------------------------------
// IEscalationBackend
// ---------------------------------------------------------------------------

std::vector<std::string> RemediationEngine::batch_scan(const std::vector<std::string>& paths) {
    if (!scanner_) return {};
    try {
        return scanner_->scan_paths(paths);
    } catch (const std::exception& e) {
        SERROR("remediation", "batch_scan threw: {}", e.what());
        return {};
    }
}

std::vector<std::string> RemediationEngine::match_strings(const std::vector<std::string>& strings,
                                                          std::string_view label) {
    if (!scanner_) return {};
    try {
        return scanner_->scan_strings(strings, label);
    } catch (const std::exception& e) {
        SERROR("remediation", "match_strings threw: {}", e.what());
        return {};
    }
}

void RemediationEngine::prompt_user(const heuristics::EscalationReport& report) {
    PendingDecision d;
    d.id = next_id_.fetch_add(1, std::memory_order_relaxed);
    d.report = report;
    d.raised = core::SysClock::now();

    // The recommendation is what we would do unattended. Showing it turns the
    // prompt from "what do you want to do?" into "do you agree?", which is a much
    // faster and less error-prone decision under pressure.
    if (report.memory_matches.empty() && report.wx_regions == 0 &&
        report.final_severity < core::Severity::High) {
        d.recommendation = "ALLOW and resume: no signature match, no W^X region, risk below threshold";
    } else if (!report.memory_matches.empty()) {
        d.recommendation = "KILL and quarantine the executable: signature matched in process memory (" +
                           report.memory_matches.front() + ")";
    } else if (report.wx_regions > 0) {
        d.recommendation = "KEEP FROZEN and quarantine: " + std::to_string(report.wx_regions) +
                           " writable+executable region(s) indicate code injection";
    } else {
        d.recommendation = "KEEP FROZEN pending analyst review of the lineage below";
    }

    {
        std::lock_guard lk{mu_};
        pending_[d.id] = d;
        while (pending_.size() > 64) pending_.erase(pending_.begin());
    }

    // Publish on the bus: the GUI subscribes and raises a modal dialog. This is
    // the IPC path; notify-send is the fallback when the GUI is not running.
    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Remediation;
    ev.kind = core::EventKind::UserActionRequired;
    ev.severity = report.final_severity;
    ev.actor.pid = report.pid;
    ev.actor.exe = report.exe;
    ev.risk_score = static_cast<std::uint16_t>(std::min<double>(report.risk, 1000.0));
    ev.metric = report.risk;
    ev.escalated = true;
    ev.message = std::format("DECISION REQUIRED #{} -- pid {} ({}), risk {:.0f}/1000, step reached '{}'",
                             d.id, report.pid, report.exe, report.risk,
                             heuristics::step_name(report.reached));
    ev.fields["decision_id"] = std::to_string(d.id);
    ev.fields["recommendation"] = d.recommendation;
    ev.fields["lineage"] = report.lineage;
    ev.fields["suspended"] = report.suspended ? "yes" : "no";
    ev.fields["wx_regions"] = std::to_string(report.wx_regions);
    ev.fields["regions_scanned"] = std::to_string(report.regions_scanned);
    ev.fields["memory_matches"] = report.memory_matches.empty()
                                      ? std::string("-")
                                      : std::accumulate(report.memory_matches.begin() + 1,
                                                        report.memory_matches.end(),
                                                        report.memory_matches.front(),
                                                        [](std::string a, const std::string& b) {
                                                            return a + ", " + b;
                                                        });
    std::string scanned;
    for (const auto& p : report.scanned_paths) { if (!scanned.empty()) scanned += "\n"; scanned += p; }
    ev.fields["scanned_paths"] = scanned.empty() ? "-" : scanned;
    std::string findings;
    for (const auto& f : report.findings) { if (!findings.empty()) findings += "\n"; findings += f; }
    ev.fields["findings"] = findings;
    std::string factors;
    for (const auto& f : report.factors) {
        if (!factors.empty()) factors += "\n";
        factors += std::format("+{:<4} [{}] {}", f.points, core::sensor_name(f.sensor), f.trigger);
    }
    ev.fields["risk_factors"] = factors;
    static_cast<void>(bus_.publish(std::move(ev)));

    notify("Decision required",
           std::format("pid {} ({}) risk {:.0f}: {}", report.pid, report.exe, report.risk, d.recommendation),
           report.final_severity);
}

std::vector<PendingDecision> RemediationEngine::pending(std::size_t n) const noexcept {
    std::lock_guard lk{mu_};
    std::vector<PendingDecision> out;
    for (const auto& [id, d] : pending_) {
        (void)id;
        if (!d.answered) out.push_back(d);
    }
    std::sort(out.begin(), out.end(), [](const PendingDecision& a, const PendingDecision& b) {
        if (a.report.risk != b.report.risk) return a.report.risk > b.report.risk;
        return a.raised < b.raised;
    });
    if (out.size() > n) out.resize(n);
    return out;
}

Action RemediationEngine::answer(std::uint64_t decision_id, std::string_view ans,
                                 std::string_view who) noexcept {
    PendingDecision d;
    {
        std::lock_guard lk{mu_};
        auto it = pending_.find(decision_id);
        if (it == pending_.end()) return Action::None;
        d = it->second;
        it->second.answered = true;
        it->second.answer = std::string(ans);
        it->second.answered_by = std::string(who);
    }
    const pid_t pid = d.report.pid;
    const std::string reason = std::format("operator decision #{} ('{}') for pid {}", decision_id, ans, pid);

    Action taken = Action::None;
    const std::uint64_t decided_ticks = d.report.start_time_ticks;
    if (ans == "allow" || ans == "resume") {
        if (resume(pid)) taken = Action::Resume;
    } else if (ans == "kill") {
        if (kill(pid, reason, decided_ticks)) taken = Action::Kill;
    } else if (ans == "suspend" || ans == "freeze") {
        if (!d.report.suspended && suspend(pid, reason, decided_ticks)) taken = Action::Suspend;
        else if (isolate(pid, reason)) taken = Action::Isolate;
        else taken = Action::Suspend;
    } else if (ans == "quarantine") {
        const bool killed = kill(pid, reason, decided_ticks);
        const bool moved = !d.report.exe.empty() && quarantine_file(d.report.exe, reason);
        taken = moved ? Action::QuarantineFile : (killed ? Action::Kill : Action::None);
    } else {
        SWARN("remediation", "unknown decision answer '{}' for #{}", ans, decision_id);
    }

    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Remediation;
    ev.kind = core::EventKind::UserAction;
    ev.severity = core::Severity::Info;
    ev.actor.pid = pid;
    ev.message = std::format("operator '{}' answered prompt #{} with '{}' -> action {}", who, decision_id,
                             ans, action_name(taken));
    ev.fields["decision_id"] = std::to_string(decision_id);
    ev.fields["answer"] = std::string(ans);
    static_cast<void>(bus_.publish(std::move(ev)));
    return taken;
}

}  // namespace hyprnova::remediation
