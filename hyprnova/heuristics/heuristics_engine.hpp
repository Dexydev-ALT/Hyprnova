// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 5 — Heuristic Anomaly Engine
//
// Everything upstream produces *observations*. This module produces *judgement*:
// it maintains a decaying risk score per actor, correlates observations across
// sensors, detects the specific anomaly classes named in the design (anomalous
// SSH invocation, tty from a web daemon, unexpected child of sshd/systemd, mass
// file modification), and drives the four-step escalation pipeline.
//
// The design principle is corroboration. Any single signal has a false-positive
// rate too high to act on: a backup job mass-modifies files, an admin runs sudo,
// a developer shells into /tmp. Risk accumulates across *independent* signals
// per actor, and only the accumulated score crosses an action threshold. That is
// what makes an unsupervised EDR deployable without becoming an outage generator.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/sensor.hpp"

namespace hyprnova::heuristics {

// ---------------------------------------------------------------------------
// Per-actor risk state
// ---------------------------------------------------------------------------

/// One contribution to an actor's score. Kept so the GUI can show *why* a process
/// is at risk 812 rather than just the number -- an analyst who cannot see the
/// reasoning cannot triage.
struct RiskFactor {
    std::string trigger;
    std::uint16_t points{0};
    core::SensorId sensor{core::SensorId::Unknown};
    core::Severity severity{core::Severity::Info};
    core::SysClock::time_point when{};
    std::string evidence;   // the event message that produced it
};

struct ActorRisk {
    pid_t pid{0};
    std::string exe;
    std::string comm;
    std::string cmdline;
    uid_t uid{0xFFFFFFFF};
    uid_t auid{0xFFFFFFFF};
    std::string container_id;
    std::vector<pid_t> ancestry;
    std::string lineage;          // "systemd(1) -> sshd(812) -> bash(9001)"

    double score{0.0};            // current decayed score, 0..1000
    double peak_score{0.0};
    core::SysClock::time_point first_seen{};
    core::SysClock::time_point last_update{};
    core::SteadyClock::time_point last_decay{};

    std::vector<RiskFactor> factors;      // newest last, bounded
    std::unordered_set<std::string> trigger_set;
    std::uint64_t event_count{0};
    std::uint64_t distinct_triggers{0};

    core::Severity severity{core::Severity::Info};
    bool suspended{false};        // we SIGSTOP'd it
    bool inspected{false};        // escalation step 2 done
    bool scanned{false};          // escalation step 3 done
    bool prompted{false};         // escalation step 4 done
    bool resolved{false};

    [[nodiscard]] core::Severity severity_for(double s, const core::HeuristicConfig& cfg) const noexcept;
};

// ---------------------------------------------------------------------------
// Baseline: what this host normally does
// ---------------------------------------------------------------------------

/// Learned normality. Persisted so a restart does not re-learn from scratch, and
/// so "learning" is a bounded phase rather than a permanent excuse for silence.
struct Baseline {
    /// parent comm -> set of child comms observed
    std::unordered_map<std::string, std::unordered_set<std::string>> parent_to_children;
    /// executable path -> times observed
    std::unordered_map<std::string, std::uint64_t> exec_frequency;
    /// uid -> executables that uid normally runs
    std::unordered_map<uid_t, std::unordered_set<std::string>> uid_to_exes;
    /// daemons that normally listen
    std::unordered_set<std::string> listening_daemons;
    /// comm -> normal outbound peer count
    std::unordered_map<std::string, std::uint64_t> outbound_peers;

    /// Default FALSE: learning is an operator CHOICE, not a default. A default
    /// of true meant a fresh install spent its first days unable to contain
    /// anything (risk halved, actions suppressed) unless the operator happened
    /// to find the toggle.
    bool learning{false};
    core::SysClock::time_point learning_started{};
    core::SysClock::time_point learning_ends{};
    std::uint64_t observations{0};

    [[nodiscard]] bool knows_child(std::string_view parent, std::string_view child) const noexcept;
    [[nodiscard]] bool knows_exe(std::string_view exe) const noexcept;
    [[nodiscard]] bool knows_exe_for_uid(uid_t uid, std::string_view exe) const noexcept;
};

[[nodiscard]] std::string serialise_baseline(const Baseline& b) noexcept;
[[nodiscard]] bool deserialise_baseline(std::string_view text, Baseline& out) noexcept;

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

/// Sliding-window burst counter keyed by an arbitrary string. Used for SSH spawn
/// bursts, repeated auth failures, and repeated execve of the same binary.
class BurstCounter {
public:
    void hit(std::string_view key, core::SteadyClock::time_point when = {}) noexcept;
    [[nodiscard]] std::size_t count(std::string_view key, std::chrono::milliseconds window) const noexcept;
    void prune(std::chrono::seconds max_age) noexcept;
    [[nodiscard]] std::size_t keys() const noexcept;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::deque<core::SteadyClock::time_point>> hits_;
};

/// Tracks which daemons have spawned shells, and which parents have spawned
/// which children. Both are "is this normal for this parent" questions.
struct LineageAnomaly {
    bool anomaly{false};
    std::string reason;
    std::string parent;
    std::string child;
    core::Severity severity{core::Severity::Info};
    std::uint16_t risk{0};
    std::vector<std::string> triggers;
};

// ---------------------------------------------------------------------------
// Escalation pipeline
// ---------------------------------------------------------------------------

enum class EscalationStep : std::uint8_t {
    None = 0,
    Freeze,        // 1. SIGSTOP the candidate
    MemoryInspect, // 2. dump /proc/<pid>/maps, match strings against rules
    BatchScan,     // 3. KVRT/clamdscan the parent + child executables
    PromptUser,    // 4. GUI prompt with full lineage and risk score
    Complete,
};

constexpr std::string_view step_name(EscalationStep s) noexcept {
    switch (s) {
        case EscalationStep::None: return "none";
        case EscalationStep::Freeze: return "freeze";
        case EscalationStep::MemoryInspect: return "memory-inspect";
        case EscalationStep::BatchScan: return "batch-scan";
        case EscalationStep::PromptUser: return "prompt-user";
        case EscalationStep::Complete: return "complete";
    }
    return "none";
}

struct EscalationReport {
    pid_t pid{0};
    /// /proc/<pid>/stat starttime captured when the decision was made. Every
    /// signal executed later revalidates against it: a recycled pid must never
    /// receive an action decided for its predecessor.
    std::uint64_t start_time_ticks{0};
    std::string exe;
    std::string lineage;
    double risk{0.0};
    std::vector<RiskFactor> factors;
    std::vector<std::string> findings;      // human-readable per step
    std::vector<std::string> memory_matches;
    std::size_t regions_scanned{0};
    std::size_t wx_regions{0};              // writable AND executable: W^X violation
    std::vector<std::string> scanned_paths;
    bool suspended{false};
    bool resumed{false};
    EscalationStep reached{EscalationStep::None};
    core::Severity final_severity{core::Severity::Info};
    core::SysClock::time_point started{};
    core::SysClock::time_point finished{};
};

/// Callbacks the engine needs from other modules. Injected as an interface so the
/// heuristic engine has no compile-time dependency on Modules 2/3/6, and so a
/// test can substitute fakes.
class IEscalationBackend {
public:
    virtual ~IEscalationBackend() = default;

    /// Step 1: freeze. Returns false if protected/dry-run/dead.
    virtual bool suspend(pid_t pid, std::string_view reason,
                         std::uint64_t expected_start_ticks = 0) = 0;
    /// Undo step 1 once the decision is made.
    virtual bool resume(pid_t pid) = 0;
    /// Step 3: signature-scan these paths and report detections.
    virtual std::vector<std::string> batch_scan(const std::vector<std::string>& paths) = 0;
    /// Signature-match a set of memory strings; returns matched rule names.
    virtual std::vector<std::string> match_strings(const std::vector<std::string>& strings,
                                                   std::string_view label) = 0;
    /// Step 4: raise the GUI prompt.
    virtual void prompt_user(const EscalationReport& report) = 0;
};

// ---------------------------------------------------------------------------
// The sensor
// ---------------------------------------------------------------------------

class HeuristicSensor final : public core::ISensor {
public:
    HeuristicSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);
    ~HeuristicSensor() override;

    /// Wire in the escalation backend. Must be called before start().
    void set_backend(std::shared_ptr<IEscalationBackend> b);

    /// Primary entry point: the bus subscriber installed by the agent.
    void on_event(const core::TelemetryEvent& ev) noexcept;

    /// Decay all actor scores. Called on a 1 s tick; scores fall so a burst of
    /// activity ages out instead of pinning an actor at Critical forever.
    void decay_tick() noexcept;

    /// Prune actors that have exited or gone quiet.
    void prune() noexcept;

    [[nodiscard]] std::vector<ActorRisk> top_actors(std::size_t n = 50) const noexcept;
    [[nodiscard]] std::optional<ActorRisk> actor(pid_t pid) const noexcept;
    [[nodiscard]] const Baseline& baseline() const noexcept { return baseline_; }

    [[nodiscard]] bool learning() const noexcept;
    [[nodiscard]] double learning_progress() const noexcept;
    [[nodiscard]] std::uint64_t observations() const noexcept;
    [[nodiscard]] std::uint64_t alerts_raised() const noexcept {
        return alerts_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t escalations_run() const noexcept {
        return escalations_.load(std::memory_order_relaxed);
    }

    /// A per-app behaviour profile, loaded from heuristic.profiles_dir. Authored
    /// as JSON by a trusted third party (vendor hardening guide, another team):
    /// {"app": "nginx", "allowed_children": ["php-fpm"], "forbidden_children": ["curl"]}.
    struct AppProfile {
        std::string app;
        std::vector<std::string> allowed_children;
        std::vector<std::string> forbidden_children;
    };
    /// Load every *.json in profiles_dir. Called once from on_start; the map is
    /// read-only afterwards, so check_lineage needs no lock. A malformed file is
    /// skipped with a warning -- one bad profile must not disable the others.
    void load_app_profiles() noexcept;
    [[nodiscard]] std::size_t app_profiles_loaded() const noexcept { return app_profiles_loaded_; }
    [[nodiscard]] const std::string& app_profiles_dir() const noexcept { return cfg_.heuristic.profiles_dir; }

    /// SSH / service-spawn state, for the GUI's service panel.
    struct ServiceState {
        std::string daemon;
        std::size_t child_count{0};
        std::size_t spawn_rate_per_min{0};
        bool shell_spawned{false};
        bool anomalous_child{false};
        std::vector<std::string> children;
        core::Severity severity{core::Severity::Info};
    };
    [[nodiscard]] std::vector<ServiceState> services() const noexcept;

    /// Run the escalation pipeline for one pid synchronously (GUI "Investigate").
    [[nodiscard]] EscalationReport escalate(pid_t pid, std::string_view reason) noexcept;

    /// Operator action: clear an actor's score after review.
    void dismiss(pid_t pid, std::string_view analyst_note) noexcept;

    [[nodiscard]] bool save_baseline() const noexcept;
    [[nodiscard]] bool load_baseline() noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    void on_stop() override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    void apply_risk(ActorRisk& a, std::string_view trigger, std::uint16_t points,
                    core::SensorId sensor, core::Severity sev, std::string_view evidence) noexcept;
    LineageAnomaly check_lineage(const core::TelemetryEvent& ev) const noexcept;
    void observe_baseline(const core::TelemetryEvent& ev) noexcept;
    void detect_service_anomalies(const core::TelemetryEvent& ev) noexcept;
    void maybe_escalate(ActorRisk& a) noexcept;
    void publish_alert(const ActorRisk& a) noexcept;

    core::SubscriptionId sub_id_{0};
    std::shared_ptr<IEscalationBackend> backend_;

    mutable std::shared_mutex mu_;
    std::unordered_map<pid_t, ActorRisk> actors_;
    Baseline baseline_;

    mutable std::mutex burst_mu_;
    BurstCounter ssh_spawns_;
    BurstCounter auth_failures_;
    BurstCounter exec_bursts_;

    mutable std::mutex svc_mu_;
    std::unordered_map<std::string, ServiceState> services_;

    std::unordered_map<std::string, AppProfile> app_profiles_;
    std::size_t app_profiles_loaded_{0};

    std::atomic<std::uint64_t> alerts_{0};
    std::atomic<std::uint64_t> escalations_{0};
    std::atomic<std::uint64_t> observations_{0};
    std::atomic<bool> running_{false};
};

}  // namespace hyprnova::heuristics
