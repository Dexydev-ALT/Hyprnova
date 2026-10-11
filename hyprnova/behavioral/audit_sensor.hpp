// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4b — Linux Audit (auditd) sensor
//
// The kernel audit subsystem is the only in-tree mechanism that reports *who*
// (auid, uid, pid, sessionid) touched a sensitive file, survives across execve,
// and cannot be disabled by the audited process. It is also the sensor an
// attacker tries hardest to blind, so this module treats auditd's own state as a
// monitored object: a rule that disappears or a backlog that overflows is an
// incident, not a statistic.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/fd.hpp"
#include "core/sensor.hpp"

namespace hyprnova::behavioral {

using namespace std::chrono_literals;

/// Decodes the kernel's `name=616263` / auid=4294967295 style fields.
/// Audit hex-encodes any value containing characters outside a small safe set,
/// so decoding is mandatory to get a readable path or comm.
[[nodiscard]] std::string audit_unescape(std::string_view token) noexcept;

[[nodiscard]] inline bool is_hex_encoded(std::string_view token) noexcept {
    if (token.size() < 2 || (token.size() % 2) != 0) return false;
    for (const char c : token) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

/// Parse one audit record line ("type=X msg=audit(epoch:serial): k=v k2=v2").
struct AuditRecord {
    std::string type;
    std::uint64_t epoch{0};
    std::uint64_t serial{0};
    std::unordered_map<std::string, std::string> fields;  // values already unescaped
    std::string raw;

    [[nodiscard]] std::string get(std::string_view key, std::string_view def = {}) const noexcept;
    [[nodiscard]] std::uint64_t get_u64(std::string_view key, std::uint64_t def = 0) const noexcept;
    [[nodiscard]] pid_t get_pid(std::string_view key) const noexcept;
};

[[nodiscard]] std::optional<AuditRecord> parse_audit_record(std::string_view line) noexcept;

/// Records sharing (epoch, serial) form one event. The correlator reassembles
/// SYSCALL + CWD + PATH + EXECVE into a single attributed action, which is what
/// makes "who wrote /etc/shadow" answerable instead of "something did".
struct AuditEvent {
    std::uint64_t epoch{0};
    std::uint64_t serial{0};
    std::vector<AuditRecord> records;

    // From SYSCALL
    pid_t pid{0};
    pid_t ppid{0};
    uid_t uid{0xFFFFFFFF};
    uid_t auid{0xFFFFFFFF};   // login uid: survives `sudo su`, so it is the actor
    gid_t gid{0xFFFFFFFF};
    std::uint64_t sessionid{0xFFFFFFFF};
    std::string syscall;
    std::string exe;
    std::string comm;
    std::string cmdline;
    std::string cwd;
    std::string key;          // the -k audit key, i.e. which of our watches fired
    int success{1};
    long exit_code{0};

    // From PATH (may be several: the file and its parent directory)
    std::vector<std::string> paths;
    std::string nametype;     // NORMAL / PARENT / DELETE / CREATE
    std::uint32_t oflag{0};

    // From EXECVE
    std::vector<std::string> argv;

    [[nodiscard]] core::SysClock::time_point timestamp() const noexcept;
    [[nodiscard]] std::string summary() const;
};

class AuditCorrelator {
public:
    /// Add a record; returns a completed event when the record set for that
    /// (epoch, serial) is complete or has aged out. Incomplete events are flushed
    /// by `flush_older_than`.
    void add(AuditRecord rec);

    /// Emit everything older than `max_age`. Called on a timer: a partial event
    /// must still be analysed, because a missing PATH record is often exactly
    /// what an attacker arranged.
    [[nodiscard]] std::vector<AuditEvent> flush_older_than(std::chrono::milliseconds max_age) noexcept;

    [[nodiscard]] std::size_t pending() const noexcept;
    [[nodiscard]] std::uint64_t completed() const noexcept { return completed_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t partial_flushed() const noexcept {
        return partial_.load(std::memory_order_relaxed);
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::uint64_t, AuditEvent> open_;
    std::unordered_map<std::uint64_t, core::SteadyClock::time_point> first_seen_;
    std::atomic<std::uint64_t> completed_{0};
    std::atomic<std::uint64_t> partial_{0};
};

/// Classification of a correlated audit event into what we actually care about.
enum class AuditFinding : std::uint8_t {
    None = 0,
    SensitiveFileRead,      // /etc/shadow, /etc/gshadow, SSH private keys
    SensitiveFileWrite,     // /etc/sudoers, /etc/passwd, sshd_config, cron
    PrivilegeEscalation,    // successful setuid/execve to root by a non-root auid
    SudoAbuse,              // sudo with red-flag options, or repeated failures
    AuthenticationFailure,  // USER_AUTH exit!=0 bursts
    PersistenceInstalled,   // cron, systemd unit, authorized_keys, rc.local
    KernelModuleLoaded,     // finit_module / init_module
    AuditSubsystemTampered, // auditctl -D, -e 0, backlog limit lowered
    BootPathModified,       // anything under /boot
    LdPreloadModified,      // /etc/ld.so.preload -- userspace rootkit vector
};

constexpr std::string_view finding_name(AuditFinding f) noexcept {
    switch (f) {
        case AuditFinding::None: return "none";
        case AuditFinding::SensitiveFileRead: return "sensitive-file-read";
        case AuditFinding::SensitiveFileWrite: return "sensitive-file-write";
        case AuditFinding::PrivilegeEscalation: return "privilege-escalation";
        case AuditFinding::SudoAbuse: return "sudo-abuse";
        case AuditFinding::AuthenticationFailure: return "authentication-failure";
        case AuditFinding::PersistenceInstalled: return "persistence-installed";
        case AuditFinding::KernelModuleLoaded: return "kernel-module-loaded";
        case AuditFinding::AuditSubsystemTampered: return "audit-subsystem-tampered";
        case AuditFinding::BootPathModified: return "boot-path-modified";
        case AuditFinding::LdPreloadModified: return "ld-preload-modified";
    }
    return "none";
}

struct AuditAnalysis {
    AuditFinding finding{AuditFinding::None};
    core::EventKind kind{core::EventKind::ProcAnomaly};
    core::Severity severity{core::Severity::Info};
    std::uint16_t risk{0};
    std::string message;
    std::vector<std::string> triggers;
};

[[nodiscard]] AuditAnalysis analyse(const AuditEvent& ev, const core::AuditdConfig& cfg) noexcept;

/// Auth-failure burst detection: N failures for one auid/target in a window is a
/// brute-force, and it is the earliest network-adjacent signal auditd gives us.
class AuthFailureTracker {
public:
    void observe(uid_t auid, std::string_view target_user, bool success) noexcept;
    struct Burst {
        uid_t auid{0};
        std::string target;
        std::size_t failures{0};
        std::chrono::seconds window{};
    };
    [[nodiscard]] std::optional<Burst> check(std::size_t threshold = 5,
                                             std::chrono::seconds window = 120s) const noexcept;
    [[nodiscard]] std::size_t tracked() const noexcept;

private:
    mutable std::mutex mu_;
    struct Entry {
        std::deque<core::SteadyClock::time_point> failures;
        std::string last_target;
    };
    std::unordered_map<uid_t, Entry> by_auid_;
};

class AuditSensor final : public core::ISensor {
public:
    AuditSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    /// Install our watch rules via AUDIT_ADD_RULE. Returns the number installed.
    /// Requires CAP_AUDIT_CONTROL; without it we degrade to log-tailing.
    std::size_t install_rules() noexcept;
    /// Remove only the rules we added (keyed by `key`).
    std::size_t remove_rules() noexcept;

    /// Query the running audit configuration. A daemon that reports "enabled=0"
    /// or a shrinking rule set is being blinded, and we say so.
    struct AuditStatus {
        bool readable{false};
        int enabled{-1};
        int pid{-1};              // 0 == no auditd consuming the netlink
        std::uint32_t backlog_limit{0};
        std::uint32_t lost{0};    // messages dropped by the kernel
        std::vector<std::string> findings;
    };
    [[nodiscard]] AuditStatus query_status() noexcept;

    [[nodiscard]] bool netlink_active() const noexcept { return netlink_ok_; }
    [[nodiscard]] std::uint64_t records_seen() const noexcept {
        return records_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t events_analysed() const noexcept { return analysed_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t kernel_lost() const noexcept { return lost_.load(std::memory_order_relaxed); }
    [[nodiscard]] const AuditCorrelator& correlator() const noexcept { return correlator_; }

    /// Feed one raw audit line. Used by the log-tail path and by tests.
    void ingest_line(std::string_view line) noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    void on_stop() override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    bool init_netlink() noexcept;
    void read_netlink() noexcept;
    void tail_log() noexcept;
    void handle_event(AuditEvent ev) noexcept;

    core::UniqueFd nl_;
    std::uint32_t our_status_seq_{0};
    bool netlink_ok_{false};
    bool tailing_log_{false};
    std::size_t log_offset_{0};
    std::string log_buffer_;

    AuditCorrelator correlator_;
    AuthFailureTracker auth_;
    std::atomic<std::uint64_t> records_{0};
    std::atomic<std::uint64_t> analysed_{0};
    std::atomic<std::uint64_t> lost_{0};
    std::vector<std::string> installed_keys_;
};

}  // namespace hyprnova::behavioral
