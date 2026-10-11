// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/event.hpp
// The single normalised telemetry record every sensor produces and every
// consumer (heuristic engine, GUI bridge, forensic journal) subscribes to.
//
// Normalising at the sensor edge is the key architectural decision: Falco JSON,
// auditd netlink, fanotify structs, osquery rows and inotify masks are wildly
// different shapes, but downstream logic only ever sees `TelemetryEvent`.
// That is what makes the heuristic rules readable and testable.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "core/ring_buffer.hpp"

namespace hyprnova::core {

using SteadyClock = std::chrono::steady_clock;
using SysClock = std::chrono::system_clock;
using TimePoint = SysClock::time_point;

/// Which sensor produced the event. Used for attribution in the GUI and to
/// decide whether an event may trigger active remediation on its own.
enum class SensorId : std::uint8_t {
    Unknown = 0,
    BootAudit,        // Module 1
    KernelHardening,  // Module 1
    MacProfile,       // Module 1
    Canary,           // Module 2
    Entropy,          // Module 2
    MassModify,       // Module 2
    ProcessPoll,      // Module 4b: unprivileged exec visibility (/proc sweep)
    StaticWatch,      // Module 3
    YaraMatch,        // Module 3
    BatchScan,        // Module 3 (KVRT / clamdscan)
    Falco,            // Module 4
    Auditd,           // Module 4
    Osquery,          // Module 4
    Suricata,         // Module 4
    Heuristic,        // Module 5
    Remediation,      // Module 6
    Agent,            // lifecycle / self-test
    Gui,              // user action from the Qt dashboard
};

constexpr std::string_view sensor_name(SensorId s) noexcept {
    switch (s) {
        case SensorId::BootAudit: return "boot-audit";
        case SensorId::KernelHardening: return "kernel-hardening";
        case SensorId::MacProfile: return "mac-profile";
        case SensorId::Canary: return "canary";
        case SensorId::Entropy: return "entropy";
        case SensorId::MassModify: return "mass-modify";
        case SensorId::ProcessPoll: return "proc-poll";
        case SensorId::StaticWatch: return "static-watch";
        case SensorId::YaraMatch: return "yara";
        case SensorId::BatchScan: return "batch-scan";
        case SensorId::Falco: return "falco";
        case SensorId::Auditd: return "auditd";
        case SensorId::Osquery: return "osquery";
        case SensorId::Suricata: return "suricata";
        case SensorId::Heuristic: return "heuristic";
        case SensorId::Remediation: return "remediation";
        case SensorId::Agent: return "agent";
        case SensorId::Gui: return "gui";
        case SensorId::Unknown: return "unknown";
    }
    return "unknown";
}

enum class EventKind : std::uint16_t {
    None = 0,
    // process lifecycle
    ProcExec,
    ProcExit,
    ProcFork,
    ProcAnomaly,
    // filesystem
    FileCreate,
    FileOpen,
    FileWrite,
    FileDelete,
    FileRename,
    FileChmod,
    FileChown,
    FileCanaryHit,
    // credential / privilege
    PrivEscalation,
    SudoAbuse,
    ShadowAccess,
    SudoersChange,
    SshSpawn,
    TtyFromDaemon,
    // network
    NetConnect,
    NetListen,
    NetC2Suspect,
    // module / integrity
    KernelModuleLoad,
    BootIntegrity,
    HardeningDrift,
    MacEnforcement,
    // scanning
    ScanVerdict,
    YaraVerdict,
    EntropyVerdict,
    // lifecycle
    SensorUp,
    SensorDown,
    ConfigReload,
    Heartbeat,
    RemediationApplied,
    UserAction,
    UserActionRequired,  // Module 5/6 escalation prompt awaiting an operator decision
    // recovery
    ShadowSnapshot,      // Module 6: a shadow copy was taken
    ShadowRestore,       // Module 6: a shadow copy was restored or verified
    ToolFinding,         // Module 8: a combined scan / external tool found something
};

constexpr std::string_view kind_name(EventKind k) noexcept {
    switch (k) {
        case EventKind::None: return "none";
        case EventKind::ProcExec: return "proc.exec";
        case EventKind::ProcExit: return "proc.exit";
        case EventKind::ProcFork: return "proc.fork";
        case EventKind::ProcAnomaly: return "proc.anomaly";
        case EventKind::FileCreate: return "file.create";
        case EventKind::FileOpen: return "file.open";
        case EventKind::FileWrite: return "file.write";
        case EventKind::FileDelete: return "file.delete";
        case EventKind::FileRename: return "file.rename";
        case EventKind::FileChmod: return "file.chmod";
        case EventKind::FileChown: return "file.chown";
        case EventKind::FileCanaryHit: return "file.canary";
        case EventKind::PrivEscalation: return "priv.escalation";
        case EventKind::SudoAbuse: return "priv.sudo_abuse";
        case EventKind::ShadowAccess: return "priv.shadow_access";
        case EventKind::SudoersChange: return "priv.sudoers_change";
        case EventKind::SshSpawn: return "svc.ssh_spawn";
        case EventKind::TtyFromDaemon: return "svc.tty_from_daemon";
        case EventKind::NetConnect: return "net.connect";
        case EventKind::NetListen: return "net.listen";
        case EventKind::NetC2Suspect: return "net.c2_suspect";
        case EventKind::KernelModuleLoad: return "kern.module_load";
        case EventKind::BootIntegrity: return "boot.integrity";
        case EventKind::HardeningDrift: return "boot.hardening_drift";
        case EventKind::MacEnforcement: return "boot.mac_enforcement";
        case EventKind::ScanVerdict: return "scan.verdict";
        case EventKind::YaraVerdict: return "scan.yara";
        case EventKind::EntropyVerdict: return "scan.entropy";
        case EventKind::SensorUp: return "agent.sensor_up";
        case EventKind::SensorDown: return "agent.sensor_down";
        case EventKind::ConfigReload: return "agent.config_reload";
        case EventKind::Heartbeat: return "agent.heartbeat";
        case EventKind::RemediationApplied: return "response.applied";
        case EventKind::UserAction: return "gui.user_action";
        case EventKind::UserActionRequired: return "gui.decision_required";
        case EventKind::ShadowSnapshot: return "shadow.snapshot";
        case EventKind::ShadowRestore: return "shadow.restore";
        case EventKind::ToolFinding: return "tool.finding";
    }
    return "none";
}

/// Severity is the *sensor's* opinion. The heuristic engine may raise it, never
/// silently lower it, and the GUI colour-codes on the post-heuristic value.
enum class Severity : std::uint8_t { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 };

constexpr std::string_view severity_name(Severity s) noexcept {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "info";
}

constexpr int severity_rank(Severity s) noexcept { return static_cast<int>(s); }

/// Everything we know about an actor. Populated best-effort: a sensor that only
/// has a pid fills `pid`, and the enrichment stage in the agent back-fills the
/// exe path, cgroup and lineage from /proc before the event is published.
struct Actor {
    pid_t pid{0};
    pid_t tgid{0};
    pid_t ppid{0};
    uid_t uid{0xFFFFFFFF};
    gid_t gid{0xFFFFFFFF};
    std::string exe;       // resolved /proc/<pid>/exe
    std::string comm;      // 15-char kernel name
    std::string cmdline;   // NUL-joined
    std::string cwd;
    std::string cgroup;
    std::string container_id;  // derived from cgroup; empty == host process
    bool in_container{false};
    std::vector<pid_t> ancestry;  // root-most first

    [[nodiscard]] bool known() const noexcept { return pid > 0; }
};

struct Target {
    std::string path;
    std::string peer_ip;
    std::uint16_t peer_port{0};
    std::uint16_t local_port{0};
    std::string rule_id;   // Falco rule / YARA rule / audit key
    std::string family;    // malware family label if known
};

/// One telemetry record. Copyable and cheap enough to move across rings;
/// strings are SSO-friendly and the hot fields sit in the first cache line.
struct TelemetryEvent {
    TimePoint ts{};
    SteadyClock::time_point mono{};
    SensorId sensor{SensorId::Unknown};
    EventKind kind{EventKind::None};
    Severity severity{Severity::Info};

    Actor actor;
    Target target;

    std::string message;          // human-readable one-liner for the GUI feed
    std::uint64_t monotonic_id{0};  // dense, for GUI list keys

    // Numeric side-channel used by the heuristic engine (entropy, byte count,
    // files-per-window, risk score, osquery column, ...).
    double metric{0.0};
    std::uint64_t count{0};

    // Free-form key/values for sensor-specific detail. Kept small on purpose;
    // anything large belongs in the forensic journal, not the event bus.
    std::unordered_map<std::string, std::string> fields;

    // Set by the heuristic engine when it promotes an event.
    bool escalated{false};
    std::uint16_t risk_score{0};  // 0..1000
    std::vector<std::string> triggers;

    [[nodiscard]] std::string one_line() const;
};

// ---------------------------------------------------------------------------
// EventBus — fan-out hub
// ---------------------------------------------------------------------------

using EventSink = std::function<void(const TelemetryEvent&)>;
using SubscriptionId = std::uint64_t;

/// Publish/subscribe hub.
///
/// Threading contract:
///   * `publish()` is called from sensor threads. It performs ONE ring push and
///     returns; it never runs subscriber code inline, so a slow GUI can never
///     stall a kernel sensor.
///   * A dedicated dispatcher jthread drains the ring and invokes subscribers.
///   * Subscriber list mutations take a shared_mutex; dispatch takes the shared
///     (read) side, so adding a GUI panel costs nothing on the hot path.
class EventBus {
public:
    explicit EventBus(std::size_t ring_capacity = 65536);
    ~EventBus();

    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;

    SubscriptionId subscribe(std::string name, EventSink sink);
    void unsubscribe(SubscriptionId id);

    /// Sensor-thread entry point. Non-blocking; returns false when the ring is
    /// saturated (the caller must count the drop).
    [[nodiscard]] bool publish(TelemetryEvent ev) noexcept;

    /// Convenience overload for the common "log a finding" case.
    void emit(SensorId sensor, EventKind kind, Severity sev, std::string msg) noexcept;

    void start();
    void stop();

    [[nodiscard]] std::uint64_t published() const noexcept { return published_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t dispatched() const noexcept { return dispatched_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t dropped() const noexcept { return dropped_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::size_t subscriber_count() const;

    /// Snapshot of per-subscriber delivery counters, rendered by the GUI's
    /// "pipeline health" panel so drops are never invisible.
    struct SubscriberStat {
        std::string name;
        std::uint64_t delivered{0};
        std::uint64_t slow{0};  // deliveries that took > 5 ms
    };
    [[nodiscard]] std::vector<SubscriberStat> stats() const;

private:
    void dispatch_loop(std::stop_token st);

    SpscRing<TelemetryEvent> ring_;
    mutable std::shared_mutex mu_;
    struct Sub {
        SubscriptionId id;
        std::string name;
        EventSink sink;
        std::atomic<std::uint64_t> delivered{0};
        std::atomic<std::uint64_t> slow{0};
    };
    std::vector<std::shared_ptr<Sub>> subs_;
    SubscriptionId next_id_{1};

    std::atomic<std::uint64_t> published_{0};
    std::atomic<std::uint64_t> dispatched_{0};
    std::atomic<std::uint64_t> dropped_{0};
    std::atomic<std::uint64_t> seq_{0};

    std::unique_ptr<class WakeupEvent> wake_;
    std::jthread dispatcher_;
    bool started_{false};
};

}  // namespace hyprnova::core

template <>
struct std::formatter<hyprnova::core::Severity> : std::formatter<std::string_view> {
    auto format(hyprnova::core::Severity s, auto& ctx) const {
        return std::formatter<std::string_view>::format(hyprnova::core::severity_name(s), ctx);
    }
};
