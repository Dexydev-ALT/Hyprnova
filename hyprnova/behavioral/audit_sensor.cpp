// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4b implementation

#include "behavioral/audit_sensor.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <format>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "core/proc.hpp"

namespace hyprnova::behavioral {

using namespace std::chrono_literals;

// The kernel's audit netlink payload type is not exported by <linux/audit.h>
// in every version, and its layout has been stable since 2.6. Defined locally so
// the module has no dependency on libaudit's headers or ABI.
namespace {

struct audit_message {
    struct nlmsghdr nlh;
    char data[];  // NOLINT: kernel-defined flexible array layout
};

constexpr int kAuditGet = AUDIT_GET;
constexpr int kAuditSet = AUDIT_SET;
constexpr int kAuditAddRule = AUDIT_ADD_RULE;
constexpr int kAuditDelRule = AUDIT_DEL_RULE;
constexpr int kAuditListRules = AUDIT_LIST_RULES;

/// NLMSG_DATA is a kernel macro that expands to a C-style cast. Wrapping it here
/// keeps -Wold-style-cast clean at every call site without weakening the warning
/// for the rest of the translation unit.
template <typename T>
T* nlmsg_data(struct nlmsghdr* nlh) noexcept {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
    return static_cast<T*>(NLMSG_DATA(nlh));
#pragma GCC diagnostic pop
}
template <typename T>
const T* nlmsg_data(const struct nlmsghdr* nlh) noexcept {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
    return static_cast<const T*>(NLMSG_DATA(const_cast<struct nlmsghdr*>(nlh)));
#pragma GCC diagnostic pop
}

}  // namespace

// ===========================================================================
// Field decoding
// ===========================================================================

std::string audit_unescape(std::string_view token) noexcept {
    if (token.empty()) return {};

    // Quoted form: "...". The kernel quotes values containing spaces, and the
    // content inside may itself be hex-encoded.
    std::string_view body = token;
    if (body.size() >= 2 && body.front() == '"' && body.back() == '"') {
        body = body.substr(1, body.size() - 2);
    }
    if (is_hex_encoded(body)) {
        std::string out;
        out.reserve(body.size() / 2);
        for (std::size_t i = 0; i + 1 < body.size(); i += 2) {
            unsigned v = 0;
            const auto* p = body.data() + i;
            if (std::from_chars(p, p + 2, v, 16).ec != std::errc{}) break;
            out.push_back(static_cast<char>(v));
        }
        return out;
    }
    std::string out{body};
    // Unquoted values escape nothing else, but the kernel does emit \( and \).
    std::string cleaned;
    cleaned.reserve(out.size());
    for (std::size_t i = 0; i < out.size(); ++i) {
        if (out[i] == '\\' && i + 1 < out.size()) { cleaned.push_back(out[i + 1]); ++i; continue; }
        cleaned.push_back(out[i]);
    }
    return cleaned;
}

std::string AuditRecord::get(std::string_view key, std::string_view def) const noexcept {
    auto it = fields.find(std::string(key));
    return it == fields.end() ? std::string(def) : it->second;
}

std::uint64_t AuditRecord::get_u64(std::string_view key, std::uint64_t def) const noexcept {
    const std::string s = get(key);
    if (s.empty()) return def;
    std::uint64_t v = 0;
    if (std::from_chars(s.data(), s.data() + s.size(), v).ec != std::errc{}) return def;
    return v;
}

pid_t AuditRecord::get_pid(std::string_view key) const noexcept {
    return static_cast<pid_t>(get_u64(key, 0));
}

std::optional<AuditRecord> parse_audit_record(std::string_view line) noexcept {
    // Formats seen in the wild:
    //   type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 ...
    //   node=host type=SYSCALL msg=audit(...): ...
    AuditRecord r;
    r.raw = std::string(line);

    std::size_t pos = 0;
    const auto next_token = [&]() -> std::string_view {
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;
        const std::size_t s = pos;
        bool in_quote = false;
        while (pos < line.size()) {
            const char c = line[pos];
            if (c == '"') in_quote = !in_quote;
            if (!in_quote && std::isspace(static_cast<unsigned char>(c))) break;
            // A value may contain '=' (e.g. a0=1b) but a KEY never follows an
            // unquoted value without whitespace, so splitting on space is safe.
            ++pos;
        }
        return line.substr(s, pos - s);
    };

    // type= and msg=audit(...) may appear in either order; node= may precede.
    bool have_type = false, have_msg = false;
    std::vector<std::pair<std::string, std::string>> rest;

    while (pos < line.size()) {
        const std::string_view tok = next_token();
        if (tok.empty()) break;
        const std::size_t eq = tok.find('=');
        if (eq == std::string_view::npos) continue;
        const std::string key{tok.substr(0, eq)};
        const std::string_view val = tok.substr(eq + 1);

        if (key == "type" && !have_type) {
            r.type = std::string(val);
            have_type = true;
            continue;
        }
        if (key == "msg" && !have_msg) {
            // msg=audit(1700000000.123:456): rest...
            const std::size_t lp = val.find('(');
            const std::size_t rp = val.find(')');
            if (lp != std::string_view::npos && rp != std::string_view::npos && rp > lp) {
                const std::string_view inside = val.substr(lp + 1, rp - lp - 1);
                const std::size_t colon = inside.find(':');
                const std::string_view ep = colon == std::string_view::npos ? inside : inside.substr(0, colon);
                const std::string_view se = colon == std::string_view::npos ? "" : inside.substr(colon + 1);
                double epoch = 0;
                if (std::sscanf(std::string(ep).c_str(), "%lf", &epoch) == 1) {
                    r.epoch = static_cast<std::uint64_t>(epoch);
                }
                std::uint64_t serial = 0;
                if (!se.empty())
                    std::from_chars(se.data(), se.data() + se.size(), serial);
                r.serial = serial;
                have_msg = true;
                // Anything after ") :" belongs to the field set.
                if (rp + 1 < val.size()) {
                    std::string_view tail = val.substr(rp + 1);
                    while (!tail.empty() && (tail.front() == ':' || std::isspace(static_cast<unsigned char>(tail.front()))))
                        tail.remove_prefix(1);
                    if (!tail.empty()) {
                        std::size_t tpos = 0;
                        const std::size_t teq = tail.find('=');
                        if (teq != std::string_view::npos) {
                            rest.emplace_back(std::string(tail.substr(0, teq)), std::string(tail.substr(teq + 1)));
                        }
                        (void)tpos;
                    }
                }
            }
            continue;
        }
        rest.emplace_back(key, std::string(val));
    }

    if (!have_type) return std::nullopt;
    for (auto& [k, v] : rest) r.fields.emplace(k, audit_unescape(v));
    return r;
}

core::SysClock::time_point AuditEvent::timestamp() const noexcept {
    return core::SysClock::from_time_t(static_cast<std::time_t>(epoch));
}

std::string AuditEvent::summary() const {
    return std::format("type={} syscall={} pid={} auid={} exe={} key='{}' paths=[{}]",
                       records.empty() ? "?" : records.front().type, syscall, pid, auid, exe, key,
                       [&] {
                           std::string j;
                           for (const auto& p : paths) { if (!j.empty()) j += ", "; j += p; }
                           return j;
                       }());
}

// ===========================================================================
// Correlator
// ===========================================================================

void AuditCorrelator::add(AuditRecord rec) {
    const std::uint64_t id = (rec.epoch << 20) ^ rec.serial;
    std::lock_guard lk{mu_};

    auto it = open_.find(id);
    if (it == open_.end()) {
        first_seen_[id] = core::SteadyClock::now();
        it = open_.emplace(id, AuditEvent{}).first;
        it->second.epoch = rec.epoch;
        it->second.serial = rec.serial;
    }
    AuditEvent& ev = it->second;
    ev.records.push_back(rec);

    const std::string& t = rec.type;
    if (t == "SYSCALL") {
        ev.pid = rec.get_pid("pid");
        ev.ppid = rec.get_pid("ppid");
        ev.uid = static_cast<uid_t>(rec.get_u64("uid", 0xFFFFFFFF));
        ev.auid = static_cast<uid_t>(rec.get_u64("auid", 0xFFFFFFFF));
        ev.gid = static_cast<gid_t>(rec.get_u64("gid", 0xFFFFFFFF));
        ev.sessionid = rec.get_u64("ses", 0xFFFFFFFF);
        ev.exe = rec.get("exe");
        ev.comm = rec.get("comm");
        ev.key = rec.get("key");
        ev.success = rec.get("success") == "yes" ? 1 : 0;
        ev.exit_code = static_cast<long>(rec.get_u64("exit", 0));

        // syscall= is a number on x86_64; translate the common ones so findings
        // are readable without shipping a full syscall table.
        const std::uint64_t sc = rec.get_u64("syscall", 0);
        static const std::unordered_map<std::uint64_t, const char*> kX8664 = {
            {0, "read"}, {1, "write"}, {2, "open"}, {3, "close"}, {9, "mmap"}, {10, "mprotect"},
            {16, "ioctl"}, {21, "access"}, {39, "fork"}, {41, "socket"}, {42, "connect"},
            {43, "accept"}, {56, "clone"}, {57, "vfork"}, {59, "execve"}, {60, "exit"},
            {78, "getdents"}, {79, "getcwd"}, {80, "chdir"}, {82, "rename"}, {83, "mkdir"},
            {84, "rmdir"}, {86, "link"}, {87, "unlink"}, {89, "readlink"}, {90, "chmod"},
            {91, "fchmod"}, {92, "chown"}, {93, "fchown"}, {94, "lchown"}, {101, "ptrace"},
            {102, "getuid"}, {157, "prctl"}, {165, "mount"}, {166, "umount2"},
            {175, "init_module"}, {186, "gettid"}, {200, "tkill"}, {202, "futex"},
            {203, "sched_setaffinity"}, {208, "fadvise64"}, {232, "epoll_wait"},
            {237, "mbind"}, {238, "set_mempolicy"}, {253, "ioprio_set"}, {257, "openat"},
            {262, "newfstatat"}, {263, "unlinkat"}, {264, "renameat"}, {268, "fchmodat"},
            {269, "faccessat"}, {272, "unshare"}, {273, "set_robust_list"},
            {280, "utimensat"}, {302, "name_to_handle_at"}, {304, "open_by_handle_at"},
            {313, "finit_module"}, {317, "kexec_file_load"}, {319, "memfd_create"},
            {321, "bpf"}, {322, "execveat"}, {334, "userfaultfd"}, {435, "clone3"},
            {439, "faccessat2"}, {441, "epoll_pwait2"}, {451, "cachestat"}, {452, "fchmodat2"},
        };
        auto sit = kX8664.find(sc);
        ev.syscall = sit != kX8664.end() ? sit->second : "syscall_" + std::to_string(sc);
    } else if (t == "PATH") {
        const std::string p = rec.get("name");
        if (!p.empty()) ev.paths.push_back(p);
        const std::string nt = rec.get("nametype");
        if (!nt.empty()) ev.nametype = nt;
        ev.oflag = static_cast<std::uint32_t>(rec.get_u64("oflag", 0));
    } else if (t == "CWD") {
        ev.cwd = rec.get("cwd");
    } else if (t == "EXECVE") {
        // argc=3 a0="cmd" a1="arg" ...
        const std::uint64_t argc = rec.get_u64("argc", 0);
        for (std::uint64_t i = 0; i < argc && i < 64; ++i) {
            const std::string a = rec.get("a" + std::to_string(i));
            if (!a.empty()) ev.argv.push_back(a);
        }
        if (!ev.argv.empty()) {
            std::string joined;
            for (const auto& a : ev.argv) { if (!joined.empty()) joined += ' '; joined += a; }
            ev.cmdline = joined;
        }
    } else if (t == "USER_AUTH" || t == "USER_LOGIN" || t == "CRED_ACQ" || t == "USER_START" ||
               t == "USER_AVC" || t == "CRED_DISP") {
        if (ev.auid == 0xFFFFFFFF) ev.auid = static_cast<uid_t>(rec.get_u64("auid", 0xFFFFFFFF));
        if (ev.pid == 0) ev.pid = rec.get_pid("pid");
        if (ev.exe.empty()) ev.exe = rec.get("exe");
        if (rec.get("res") == "failure") ev.success = 0;
    }
}

std::vector<AuditEvent> AuditCorrelator::flush_older_than(std::chrono::milliseconds max_age) noexcept {
    std::vector<AuditEvent> out;
    const auto cutoff = core::SteadyClock::now() - max_age;
    std::lock_guard lk{mu_};
    for (auto it = first_seen_.begin(); it != first_seen_.end();) {
        if (it->second < cutoff) {
            auto ev_it = open_.find(it->first);
            if (ev_it != open_.end()) {
                // SYSCALL is the anchor: an event with no SYSCALL and no USER_*
                // record carries no attribution and is dropped rather than
                // published as noise.
                const bool has_anchor = std::any_of(
                    ev_it->second.records.begin(), ev_it->second.records.end(),
                    [](const AuditRecord& r) {
                        return r.type == "SYSCALL" || r.type.starts_with("USER_") ||
                               r.type == "CRED_ACQ" || r.type == "SYSTEM_BOOT" ||
                               r.type == "DAEMON_" + r.type;
                    });
                if (has_anchor) {
                    partial_.fetch_add(1, std::memory_order_relaxed);
                    out.push_back(std::move(ev_it->second));
                }
                open_.erase(ev_it);
            }
            it = first_seen_.erase(it);
        } else {
            ++it;
        }
    }
    completed_.fetch_add(out.size(), std::memory_order_relaxed);
    return out;
}

std::size_t AuditCorrelator::pending() const noexcept {
    std::lock_guard lk{mu_};
    return open_.size();
}

// ===========================================================================
// Analysis
// ===========================================================================

namespace {

bool path_is_under(std::string_view path, std::string_view prefix) noexcept {
    if (path.size() < prefix.size()) return false;
    if (path.compare(0, prefix.size(), prefix) != 0) return false;
    return path.size() == prefix.size() || path[prefix.size()] == '/' || prefix.back() == '/';
}

bool write_syscall(std::string_view sc) noexcept {
    static constexpr std::string_view kWrite[] = {"write", "open", "openat", "creat", "rename",
                                                  "renameat", "renameat2", "link", "symlink",
                                                  "chmod", "fchmod", "fchmodat", "chown", "fchown",
                                                  "fchownat", "truncate", "ftruncate", "mkdir",
                                                  "unlink", "unlinkat", "rmdir", "utimensat"};
    for (const auto w : kWrite) {
        if (sc == w) return true;
    }
    return false;
}

bool read_syscall(std::string_view sc) noexcept {
    return sc == "read" || sc == "open" || sc == "openat" || sc == "access" || sc == "faccessat" ||
           sc == "faccessat2" || sc == "readlink";
}

}  // namespace

AuditAnalysis analyse(const AuditEvent& ev, const core::AuditdConfig& cfg) noexcept {
    AuditAnalysis a;
    if (ev.records.empty()) return a;

    const std::string& primary_type = ev.records.front().type;
    const std::string first_path = ev.paths.empty() ? std::string{} : ev.paths.front();

    // ---- Audit subsystem tampering: highest priority, because it means every
    // other finding from this sensor is now unreliable.
    if (ev.exe.find("auditctl") != std::string::npos || ev.comm == "auditctl") {
        const bool deletes = std::any_of(ev.argv.begin(), ev.argv.end(),
                                         [](const std::string& s) { return s == "-D" || s == "-d"; });
        const bool disables = std::any_of(ev.argv.begin(), ev.argv.end(),
                                          [](const std::string& s) { return s == "-e"; });
        if (deletes || disables) {
            a.finding = AuditFinding::AuditSubsystemTampered;
            a.kind = core::EventKind::ProcAnomaly;
            a.severity = core::Severity::Critical;
            a.risk = 950;
            a.message = std::format("auditd rules being modified by pid {} (auid {}) exe '{}': {}", ev.pid,
                                    ev.auid, ev.exe, ev.cmdline.empty() ? "(no EXECVE record)" : ev.cmdline);
            a.triggers = {"audit_rules_modified", "defence_evasion"};
            return a;
        }
    }
    if (first_path == "/proc/sys/kernel/audit" || first_path == "/proc/sys/kernel/audit_enabled") {
        if (write_syscall(ev.syscall)) {
            a.finding = AuditFinding::AuditSubsystemTampered;
            a.kind = core::EventKind::ProcAnomaly;
            a.severity = core::Severity::Critical;
            a.risk = 960;
            a.message = std::format("kernel audit subsystem toggled via {} by pid {} (auid {})",
                                    first_path, ev.pid, ev.auid);
            a.triggers = {"audit_disabled_via_procfs"};
            return a;
        }
    }

    // ---- ld.so.preload: userspace rootkit installation vector.
    if (first_path == "/etc/ld.so.preload") {
        a.finding = AuditFinding::LdPreloadModified;
        a.kind = write_syscall(ev.syscall) ? core::EventKind::FileWrite : core::EventKind::FileOpen;
        a.severity = write_syscall(ev.syscall) ? core::Severity::Critical : core::Severity::High;
        a.risk = write_syscall(ev.syscall) ? 920 : 500;
        a.message = std::format("/etc/ld.so.preload {} by pid {} (auid {}) exe '{}'",
                                write_syscall(ev.syscall) ? "MODIFIED" : "accessed", ev.pid, ev.auid,
                                ev.exe);
        a.triggers = {"ld_preload_tamper", "userspace_rootkit"};
        return a;
    }

    // ---- Kernel module load.
    if (ev.syscall == "init_module" || ev.syscall == "finit_module") {
        a.finding = AuditFinding::KernelModuleLoaded;
        a.kind = core::EventKind::KernelModuleLoad;
        a.severity = core::Severity::High;
        a.risk = 620;
        a.message = std::format("kernel module loaded via {} by pid {} (auid {}) exe '{}'", ev.syscall,
                                ev.pid, ev.auid, ev.exe);
        a.triggers = {"kernel_module_load"};
        if (!first_path.empty()) a.message += " source=" + first_path;
        return a;
    }

    // ---- Authentication results.
    if (primary_type == "USER_AUTH" || primary_type == "USER_LOGIN" || primary_type == "CRED_ACQ") {
        if (ev.success == 0) {
            a.finding = AuditFinding::AuthenticationFailure;
            a.kind = core::EventKind::PrivEscalation;
            a.severity = core::Severity::Medium;
            a.risk = 180;
            a.message = std::format("{} failure: pid {} auid {} exe '{}'{}", primary_type, ev.pid, ev.auid,
                                    ev.exe, ev.cmdline.empty() ? "" : " " + ev.cmdline);
            a.triggers = {"auth_failure"};
            return a;
        }
        // A successful privilege transition where the login uid differs from the
        // effective uid is the definition of a privilege escalation event.
        if (primary_type == "CRED_ACQ" || (ev.auid != 0xFFFFFFFF && ev.uid == 0 && ev.auid != 0)) {
            a.finding = AuditFinding::PrivilegeEscalation;
            a.kind = core::EventKind::PrivEscalation;
            a.severity = core::Severity::High;
            a.risk = 520;
            a.message = std::format("privilege transition: auid {} -> uid {} via pid {} exe '{}'", ev.auid,
                                    ev.uid, ev.pid, ev.exe);
            a.triggers = {"privilege_transition"};
            return a;
        }
    }

    // ---- execve into a privileged binary.
    if (ev.syscall == "execve" || ev.syscall == "execveat") {
        const std::string target = first_path.empty() ? ev.exe : first_path;
        const std::size_t slash = target.find_last_of('/');
        const std::string base = slash == std::string::npos ? target : target.substr(slash + 1);

        const bool privileged = std::find(cfg.privileged_cmds.begin(), cfg.privileged_cmds.end(), base) !=
                                cfg.privileged_cmds.end();
        if (privileged && cfg.detect_sudo_abuse) {
            bool red_flag = false;
            std::vector<std::string> flags;
            for (const auto& arg : ev.argv) {
                for (const auto& rf : cfg.sudo_red_flags) {
                    if (arg == rf || (rf.size() > 1 && rf[0] == '-' && arg.starts_with("-") &&
                                      arg.find(rf.substr(1)) != std::string::npos)) {
                        red_flag = true;
                        flags.push_back(arg);
                    }
                }
            }
            // Repeated failure is the other half of sudo abuse.
            const bool failed = ev.success == 0 || ev.exit_code != 0;
            if (red_flag || failed) {
                a.finding = AuditFinding::SudoAbuse;
                a.kind = core::EventKind::SudoAbuse;
                a.severity = red_flag ? core::Severity::High : core::Severity::Medium;
                a.risk = red_flag ? 560 : 240;
                a.message = std::format("{} {} by pid {} (auid {}): {}{}", base,
                                        failed ? "FAILED" : "invoked with escalation flags", ev.pid,
                                        ev.auid, ev.cmdline.empty() ? target : ev.cmdline,
                                        flags.empty() ? "" : " [" + [&] {
                                            std::string j;
                                            for (const auto& f : flags) { if (!j.empty()) j += " "; j += f; }
                                            return j;
                                        }() + "]");
                a.triggers = {"sudo_abuse"};
                if (red_flag) a.triggers.push_back("sudo_escalation_flag");
                return a;
            }
        }

        // execve from a world-writable location.
        if (core::proc::runs_from_suspicious_path(target)) {
            a.finding = AuditFinding::PrivilegeEscalation;
            a.kind = core::EventKind::ProcExec;
            a.severity = core::Severity::High;
            a.risk = 480;
            a.message = std::format("execve of '{}' from a user-writable location by pid {} (auid {})",
                                    target, ev.pid, ev.auid);
            a.triggers = {"exec_from_writable_path"};
            return a;
        }
    }

    // ---- Sensitive path access.
    if (!first_path.empty()) {
        const bool watched = std::any_of(cfg.watch_paths.begin(), cfg.watch_paths.end(),
                                         [&](const std::string& w) { return path_is_under(first_path, w); });
        if (watched || !ev.key.empty()) {
            // Persistence targets.
            static constexpr std::string_view kPersist[] = {"/etc/cron", "/etc/systemd/system",
                                                            "authorized_keys", "/etc/rc.local",
                                                            "/etc/profile.d", ".bashrc", ".profile"};
            for (const auto p : kPersist) {
                if (first_path.find(p) != std::string::npos && write_syscall(ev.syscall)) {
                    a.finding = AuditFinding::PersistenceInstalled;
                    a.kind = core::EventKind::FileWrite;
                    a.severity = core::Severity::High;
                    a.risk = 640;
                    a.message = std::format("persistence mechanism modified: {} by pid {} (auid {}) "
                                            "exe '{}' syscall {}",
                                            first_path, ev.pid, ev.auid, ev.exe, ev.syscall);
                    a.triggers = {"persistence_install", "autostart_modified"};
                    return a;
                }
            }

            if (path_is_under(first_path, "/boot") && write_syscall(ev.syscall)) {
                a.finding = AuditFinding::BootPathModified;
                a.kind = core::EventKind::FileWrite;
                a.severity = core::Severity::Critical;
                a.risk = 880;
                a.message = std::format("/boot modified: {} by pid {} (auid {}) exe '{}'", first_path,
                                        ev.pid, ev.auid, ev.exe);
                a.triggers = {"boot_path_write", "bootkit_precursor"};
                return a;
            }

            const bool write = write_syscall(ev.syscall);
            if (write) {
                const bool sudoers = first_path.find("sudoers") != std::string::npos;
                a.finding = AuditFinding::SensitiveFileWrite;
                a.kind = sudoers ? core::EventKind::SudoersChange : core::EventKind::FileWrite;
                a.severity = sudoers || first_path.find("shadow") != std::string::npos
                                 ? core::Severity::Critical
                                 : core::Severity::High;
                a.risk = sudoers ? 900 : 620;
                a.message = std::format("sensitive file WRITTEN: {} by pid {} (auid {}) exe '{}' "
                                        "syscall {} success={}",
                                        first_path, ev.pid, ev.auid, ev.exe, ev.syscall,
                                        ev.success ? "yes" : "no");
                a.triggers = {"sensitive_file_write"};
                if (sudoers) a.triggers = {"sudoers_modified", "privilege_grant"};
                return a;
            }
            if (read_syscall(ev.syscall)) {
                const bool shadow = first_path.find("shadow") != std::string::npos;
                a.finding = AuditFinding::SensitiveFileRead;
                a.kind = shadow ? core::EventKind::ShadowAccess : core::EventKind::FileOpen;
                a.severity = shadow ? core::Severity::High : core::Severity::Medium;
                a.risk = shadow ? 560 : 220;
                a.message = std::format("sensitive file READ: {} by pid {} (auid {}) exe '{}'", first_path,
                                        ev.pid, ev.auid, ev.exe);
                a.triggers = {"sensitive_file_read"};
                if (shadow) a.triggers = {"shadow_read", "credential_harvest_precursor"};
                return a;
            }
        }
    }

    (void)primary_type;
    return a;
}

// ===========================================================================
// AuthFailureTracker
// ===========================================================================

void AuthFailureTracker::observe(uid_t auid, std::string_view target_user, bool success) noexcept {
    if (success) return;
    std::lock_guard lk{mu_};
    Entry& e = by_auid_[auid];
    e.failures.push_back(core::SteadyClock::now());
    e.last_target = std::string(target_user);
    while (e.failures.size() > 256) e.failures.pop_front();
}

std::optional<AuthFailureTracker::Burst> AuthFailureTracker::check(std::size_t threshold,
                                                                   std::chrono::seconds window) const noexcept {
    const auto cutoff = core::SteadyClock::now() - window;
    std::lock_guard lk{mu_};
    for (const auto& [auid, e] : by_auid_) {
        std::size_t n = 0;
        for (const auto& t : e.failures) {
            if (t >= cutoff) ++n;
        }
        if (n >= threshold) {
            Burst b;
            b.auid = auid;
            b.target = e.last_target;
            b.failures = n;
            b.window = window;
            return b;
        }
    }
    return std::nullopt;
}

std::size_t AuthFailureTracker::tracked() const noexcept {
    std::lock_guard lk{mu_};
    return by_auid_.size();
}

// ===========================================================================
// AuditSensor
// ===========================================================================

AuditSensor::AuditSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool)
    : core::ISensor("auditd", core::SensorId::Auditd, bus, cfg, pool) {}

bool AuditSensor::init_netlink() noexcept {
    const int fd = ::socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_AUDIT);
    if (fd < 0) return false;

    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = static_cast<__u32>(::getpid());
    // AUDIT_NLGRP_READ_LOG lets us receive the record stream without displacing
    // auditd; joining the group is the difference between coexisting with the
    // system's auditd and stealing its events.
    addr.nl_groups = 0;
#ifdef AUDIT_NLGRP_READ_LOG
    addr.nl_groups = 1u << (AUDIT_NLGRP_READ_LOG - 1);
#endif
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        // nl_pid collision (another instance running) or insufficient privilege.
        addr.nl_pid = 0;  // let the kernel assign
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(fd);
            return false;
        }
    }

    // Enlarge the receive buffer: the audit stream bursts hard during a fork
    // storm, and a small buffer means silently lost records.
    const int sz = static_cast<int>(cfg_.auditd.netlink_buf_bytes);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));

    nl_ = core::UniqueFd{fd};
    netlink_ok_ = true;
    return true;
}

bool AuditSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.auditd.enabled;
}

bool AuditSensor::on_start() {
    if (!cfg_.auditd.enabled) {
        mark_degraded("auditd sensor disabled by configuration");
        return true;
    }

    const auto caps = core::proc::capabilities();
    if (!caps.cap_audit_read && !caps.euid0) {
        mark_degraded("CAP_AUDIT_READ missing: audit netlink stream unavailable, will attempt log tail");
    }

    if (cfg_.auditd.use_netlink && init_netlink()) {
        // Ask for the current status so we can detect blinding immediately.
        auto st = query_status();
        for (const auto& f : st.findings) {
            emit(core::EventKind::ProcAnomaly, core::Severity::High, f);
        }
        const std::size_t installed = install_rules();
        mark_running(std::format("netlink active, {} watch rules installed, auditd pid={}", installed,
                                 st.pid));
        if (installed == 0 && !cfg_.auditd.watch_paths.empty()) {
            mark_degraded("netlink connected but no watch rules could be installed "
                          "(CAP_AUDIT_CONTROL missing): relying on pre-existing audit rules");
        }
        return true;
    }

    // Fallback: tail /var/log/audit/audit.log. Loses real-time response and
    // cannot install rules, but keeps the findings flowing.
    const int fd = ::open(cfg_.auditd.fallback_log.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        tailing_log_ = true;
        const off_t end = ::lseek(fd, 0, SEEK_END);
        log_offset_ = end > 0 ? static_cast<std::size_t>(end) : 0;
        nl_ = core::UniqueFd{fd};
        mark_degraded("audit netlink unavailable; tailing " + cfg_.auditd.fallback_log +
                      " (no real-time response, no rule installation)");
        return true;
    }

    mark_degraded("neither audit netlink nor " + cfg_.auditd.fallback_log +
                  " is available: Module 4b is inactive");
    return true;
}

void AuditSensor::on_stop() {
    // Removing our rules on shutdown is deliberate: leaving them behind means the
    // next agent instance double-counts, and an operator who stops the agent
    // expects the audit ruleset to return to its prior state.
    if (netlink_ok_) {
        const std::size_t removed = remove_rules();
        SINFO(name_, "removed {} audit watch rules on shutdown", removed);
    }
}

std::size_t AuditSensor::install_rules() noexcept {
    if (!netlink_ok_ || !nl_) return 0;
    std::size_t installed = 0;

    for (const auto& watch : cfg_.auditd.watch_paths) {
        if (watch.empty()) continue;
        if (!core::fsx::exists(watch)) {
            SDEBUG(name_, "audit watch target absent, skipping: {}", watch);
            continue;
        }

        // audit_rule_data with one WATCH field: field=AUDIT_WATCH, op=AUDIT_EQUAL
        alignas(struct audit_rule_data) std::byte buf[sizeof(struct audit_rule_data) + 512]{};
        auto* rule = reinterpret_cast<struct audit_rule_data*>(buf);
        rule->flags = AUDIT_FILTER_EXIT;
        rule->action = AUDIT_ALWAYS;
        rule->field_count = 1;

        const std::size_t pathlen = watch.size();
        if (pathlen > 400) continue;
        rule->fields[0] = AUDIT_WATCH | AUDIT_EQUAL;
        rule->values[0] = static_cast<std::uint32_t>(pathlen);
        std::memcpy(buf + sizeof(struct audit_rule_data), watch.data(), pathlen);
        rule->buflen = static_cast<std::uint32_t>(pathlen);

        const std::string key = "hyprnova_" + std::to_string(installed);
        // Second field for the key would require more room; keep one watch per
        // rule and derive the key from the path when analysing.

        struct {
            struct nlmsghdr nlh;
            char payload[sizeof(buf)];
        } req{};
        req.nlh.nlmsg_len = static_cast<std::uint32_t>(NLMSG_LENGTH(sizeof(struct audit_rule_data) + rule->buflen));
        req.nlh.nlmsg_type = static_cast<std::uint16_t>(kAuditAddRule);
        req.nlh.nlmsg_flags = static_cast<std::uint16_t>(NLM_F_REQUEST | NLM_F_ACK);
        req.nlh.nlmsg_seq = ++our_status_seq_;
        req.nlh.nlmsg_pid = static_cast<std::uint32_t>(::getpid());
        std::memcpy(req.payload, rule, sizeof(struct audit_rule_data) + rule->buflen);

        sockaddr_nl dest{};
        dest.nl_family = AF_NETLINK;
        const ssize_t sent = ::sendto(nl_.get(), &req, req.nlh.nlmsg_len, 0,
                                      reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
        if (sent > 0) {
            ++installed;
            installed_keys_.push_back(key);
        } else {
            // EEXIST means the rule is already there, which is success for us.
            if (errno == EEXIST) ++installed;
            else SDEBUG(name_, "AUDIT_ADD_RULE for {} failed: {}", watch, std::strerror(errno));
        }
    }
    return installed;
}

std::size_t AuditSensor::remove_rules() noexcept {
    if (!netlink_ok_ || !nl_) return 0;
    std::size_t removed = 0;
    for (const auto& watch : cfg_.auditd.watch_paths) {
        if (watch.empty() || !core::fsx::exists(watch)) continue;
        alignas(struct audit_rule_data) std::byte buf[sizeof(struct audit_rule_data) + 512]{};
        auto* rule = reinterpret_cast<struct audit_rule_data*>(buf);
        rule->flags = AUDIT_FILTER_EXIT;
        rule->action = AUDIT_ALWAYS;
        rule->field_count = 1;
        const std::size_t pathlen = std::min<std::size_t>(watch.size(), 400);
        rule->fields[0] = AUDIT_WATCH | AUDIT_EQUAL;
        rule->values[0] = static_cast<std::uint32_t>(pathlen);
        std::memcpy(buf + sizeof(struct audit_rule_data), watch.data(), pathlen);
        rule->buflen = static_cast<std::uint32_t>(pathlen);

        struct {
            struct nlmsghdr nlh;
            char payload[sizeof(buf)];
        } req{};
        req.nlh.nlmsg_len = static_cast<std::uint32_t>(NLMSG_LENGTH(sizeof(struct audit_rule_data) + rule->buflen));
        req.nlh.nlmsg_type = static_cast<std::uint16_t>(kAuditDelRule);
        req.nlh.nlmsg_flags = static_cast<std::uint16_t>(NLM_F_REQUEST);
        req.nlh.nlmsg_seq = ++our_status_seq_;
        req.nlh.nlmsg_pid = static_cast<std::uint32_t>(::getpid());
        std::memcpy(req.payload, rule, sizeof(struct audit_rule_data) + rule->buflen);

        sockaddr_nl dest{};
        dest.nl_family = AF_NETLINK;
        if (::sendto(nl_.get(), &req, req.nlh.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&dest),
                     sizeof(dest)) > 0)
            ++removed;
    }
    installed_keys_.clear();
    return removed;
}

AuditSensor::AuditStatus AuditSensor::query_status() noexcept {
    AuditStatus s;
    if (!nl_) {
        s.findings.push_back("audit netlink socket unavailable; status cannot be queried");
        return s;
    }

    struct {
        struct nlmsghdr nlh;
        struct audit_status st;
    } req{};
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct audit_status));
    req.nlh.nlmsg_type = static_cast<std::uint16_t>(kAuditGet);
    req.nlh.nlmsg_flags = static_cast<std::uint16_t>(NLM_F_REQUEST | NLM_F_ACK);
    req.nlh.nlmsg_seq = ++our_status_seq_;
    req.nlh.nlmsg_pid = static_cast<std::uint32_t>(::getpid());

    sockaddr_nl dest{};
    dest.nl_family = AF_NETLINK;
    if (::sendto(nl_.get(), &req, req.nlh.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&dest),
                 sizeof(dest)) < 0) {
        s.findings.push_back(std::string("AUDIT_GET sendto failed: ") + std::strerror(errno));
        return s;
    }

    alignas(struct audit_message) char rbuf[8192]{};
    pollfd pfd{nl_.get(), POLLIN, 0};
    if (::poll(&pfd, 1, 1000) <= 0) {
        s.findings.push_back("AUDIT_GET reply timed out");
        return s;
    }
    const ssize_t n = ::recv(nl_.get(), rbuf, sizeof(rbuf), MSG_DONTWAIT);
    if (n <= 0) {
        s.findings.push_back(std::string("AUDIT_GET recv failed: ") + std::strerror(errno));
        return s;
    }

    const auto* nlh = reinterpret_cast<struct nlmsghdr*>(rbuf);
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        s.findings.push_back("AUDIT_GET returned NLMSG_ERROR (likely missing CAP_AUDIT_WRITE/CONTROL)");
        return s;
    }
    const auto* st = nlmsg_data<struct audit_status>(nlh);
    s.readable = true;
    if (st->mask & AUDIT_STATUS_ENABLED) s.enabled = static_cast<int>(st->enabled);
    if (st->mask & AUDIT_STATUS_PID) s.pid = static_cast<int>(st->pid);
    if (st->mask & AUDIT_STATUS_BACKLOG_LIMIT) s.backlog_limit = st->backlog_limit;
    if (st->mask & AUDIT_STATUS_LOST) {
        s.lost = st->lost;
        lost_.store(st->lost, std::memory_order_relaxed);
    }

    if (s.enabled == 0) {
        s.findings.push_back("kernel auditing is DISABLED (audit_status.enabled=0): every auditd-derived "
                             "finding from this point is unreliable. An attacker with root disables "
                             "audit first.");
    } else if (s.enabled == 2) {
        s.findings.push_back("kernel auditing is locked (enabled=2): rules cannot be changed until "
                             "reboot. This is the hardened setting.");
    }
    if (s.pid == 0) {
        s.findings.push_back("no auditd daemon is consuming the netlink backlog (audit_status.pid=0). "
                             "Records will accumulate until the backlog limit is hit and then be "
                             "DROPPED by the kernel.");
    }
    if (s.lost > 0) {
        s.findings.push_back(std::format("the kernel has DROPPED {} audit message(s) (audit_status.lost). "
                                         "There is a gap in the audit record; raise backlog_limit or "
                                         "audit_rate_limit.",
                                         s.lost));
    }
    return s;
}

void AuditSensor::ingest_line(std::string_view line) noexcept {
    auto rec = parse_audit_record(line);
    if (!rec) return;
    records_.fetch_add(1, std::memory_order_relaxed);

    if (rec->type == "USER_AUTH" || rec->type == "USER_LOGIN") {
        const bool ok = rec->get("res") != "failure";
        auth_.observe(static_cast<uid_t>(rec->get_u64("auid", 0xFFFFFFFF)), rec->get("acct"), ok);
        if (const auto burst = auth_.check(5, 120s)) {
            core::TelemetryEvent ev;
            ev.sensor = core::SensorId::Auditd;
            ev.kind = core::EventKind::SshSpawn;
            ev.severity = core::Severity::High;
            ev.actor.uid = burst->auid;
            ev.risk_score = 540;
            ev.count = burst->failures;
            ev.message = std::format("authentication brute-force: {} failures in {}s for auid {} "
                                     "(last target account '{}')",
                                     burst->failures, burst->window.count(), burst->auid, burst->target);
            ev.triggers = {"auth_brute_force"};
            emit(std::move(ev));
        }
    }

    correlator_.add(std::move(*rec));
}

void AuditSensor::read_netlink() noexcept {
    alignas(struct audit_message) char buf[65536]{};
    for (int pass = 0; pass < 16; ++pass) {
        const ssize_t n = ::recv(nl_.get(), buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0) {
            if (n < 0 && errno == ENOBUFS) {
                // ENOBUFS on an audit netlink socket means the kernel dropped
                // messages. That is a detection gap and must be surfaced.
                lost_.fetch_add(1, std::memory_order_relaxed);
                note_error("audit netlink ENOBUFS: kernel dropped audit messages, coverage gap");
            }
            break;
        }

        // One audit record per netlink message, but a recv() can carry several
        // messages, so walk the chain. NLMSG_NEXT mutates its length argument,
        // hence the local copy rather than aliasing `n`.
        std::size_t remaining = static_cast<std::size_t>(n);
        const auto* nlh = reinterpret_cast<const struct nlmsghdr*>(buf);
        while (NLMSG_OK(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE) break;
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                SDEBUG("auditd", "netlink error message received (seq {})", nlh->nlmsg_seq);
                break;
            }
            if (nlh->nlmsg_type != static_cast<std::uint16_t>(kAuditListRules) &&
                nlh->nlmsg_type >= AUDIT_FIRST_USER_MSG - 1) {
                const auto* payload = nlmsg_data<const char>(nlh);
                const std::size_t plen = NLMSG_PAYLOAD(nlh, 0);
                if (plen > 0) ingest_line(std::string_view{payload, plen});
            }
            nlh = NLMSG_NEXT(nlh, remaining);
        }
    }
}

void AuditSensor::tail_log() noexcept {
    std::string chunk;
    chunk.resize(64 * 1024);
    for (int pass = 0; pass < 8; ++pass) {
        const ssize_t n = ::pread(nl_.get(), chunk.data(), chunk.size(), static_cast<off_t>(log_offset_));
        if (n <= 0) {
            if (n < 0 && (core::would_block(errno))) break;
            break;
        }
        log_offset_ += static_cast<std::size_t>(n);
        log_buffer_.append(chunk.data(), static_cast<std::size_t>(n));

        std::size_t consumed = 0;
        for (;;) {
            const std::size_t nl = log_buffer_.find('\n', consumed);
            if (nl == std::string::npos) break;
            const std::string_view line{log_buffer_.data() + consumed, nl - consumed};
            consumed = nl + 1;
            if (!line.empty()) ingest_line(line);
        }
        if (consumed > 0) log_buffer_.erase(0, consumed);
        // A line without a newline that exceeds 1 MB is malformed; drop it.
        if (log_buffer_.size() > (1 << 20)) log_buffer_.clear();
        if (static_cast<std::size_t>(n) < chunk.size()) break;
    }
}

void AuditSensor::handle_event(AuditEvent ev) noexcept {
    analysed_.fetch_add(1, std::memory_order_relaxed);
    const AuditAnalysis a = analyse(ev, cfg_.auditd);
    if (a.finding == AuditFinding::None) return;

    core::TelemetryEvent tev;
    tev.sensor = core::SensorId::Auditd;
    tev.kind = a.kind;
    tev.severity = a.severity;
    tev.ts = ev.timestamp();
    tev.actor.pid = ev.pid;
    tev.actor.ppid = ev.ppid;
    tev.actor.uid = ev.uid;
    tev.actor.exe = ev.exe;
    tev.actor.comm = ev.comm;
    tev.actor.cmdline = ev.cmdline.empty() ? ev.exe : ev.cmdline;
    tev.actor.cwd = ev.cwd;
    if (!ev.paths.empty()) tev.target.path = ev.paths.front();
    tev.target.rule_id = std::string(finding_name(a.finding));
    tev.risk_score = a.risk;
    tev.message = a.message;
    tev.triggers = a.triggers;
    tev.fields["auid"] = std::to_string(ev.auid);
    tev.fields["syscall"] = ev.syscall;
    tev.fields["sessionid"] = std::to_string(ev.sessionid);
    tev.fields["audit_key"] = ev.key;
    tev.fields["audit_serial"] = std::to_string(ev.serial);
    if (!ev.argv.empty()) {
        std::string j;
        for (const auto& arg : ev.argv) { if (!j.empty()) j += ' '; j += arg; }
        tev.fields["argv"] = j;
    }
    if (ev.paths.size() > 1) {
        std::string j;
        for (const auto& p : ev.paths) { if (!j.empty()) j += ", "; j += p; }
        tev.fields["all_paths"] = j;
    }
    emit(std::move(tev));
}

void AuditSensor::loop(std::stop_token st) {
    auto last_flush = core::SteadyClock::now();
    auto last_status = core::SteadyClock::now();

    while (!st.stop_requested()) {
        if (netlink_ok_) read_netlink();
        else if (tailing_log_) tail_log();

        // Correlation window: 250 ms is long enough for the kernel to deliver
        // SYSCALL+CWD+PATH+EXECVE for one execve, short enough that the finding
        // is still actionable in real time.
        if (core::SteadyClock::now() - last_flush >= 250ms) {
            for (auto& ev : correlator_.flush_older_than(250ms)) handle_event(std::move(ev));
            last_flush = core::SteadyClock::now();
        }

        // Re-query audit status periodically: blinding happens at runtime.
        if (netlink_ok_ && core::SteadyClock::now() - last_status >= 60s) {
            const auto s = query_status();
            for (const auto& f : s.findings) {
                if (f.find("DISABLED") != std::string::npos || f.find("DROPPED") != std::string::npos) {
                    core::TelemetryEvent ev;
                    ev.sensor = core::SensorId::Auditd;
                    ev.kind = core::EventKind::ProcAnomaly;
                    ev.severity = core::Severity::Critical;
                    ev.risk_score = 900;
                    ev.message = f;
                    ev.triggers = {"audit_blinded"};
                    emit(std::move(ev));
                }
            }
            last_status = core::SteadyClock::now();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    for (auto& ev : correlator_.flush_older_than(0ms)) handle_event(std::move(ev));
}

}  // namespace hyprnova::behavioral
