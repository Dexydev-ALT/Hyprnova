// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Agent — the daemon
//
// Owns the long-lived objects (config, bus, pool, sensors, remediation), wires the
// escalation backend into the heuristic engine, enforces the remediation policy
// that Module 5 deliberately does not know about, and shuts down in an order that
// cannot leave the host in a worse state than it found it:
//
//   sensors stopped -> suspended processes resumed -> nftables table flushed ->
//   baseline + state persisted -> bus drained -> pool joined
//
// Reversing that order would leave frozen processes behind, or leave the operator's
// firewall filtered by rules nothing remembers creating.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/sensor.hpp"
#include "core/thread_pool.hpp"
#include "heuristics/heuristics_engine.hpp"
#include "remediation/remediation_engine.hpp"
#include "ai/analyst.hpp"
#include "remediation/rescue_boot.hpp"
#include "remediation/shredder.hpp"
#include "remediation/shadow_copy.hpp"
#include "tools/toolbox.hpp"
namespace hyprnova::forensics { class MemInspector; }

namespace hyprnova {

class GuiBridge;

struct AgentStats {
    std::uint64_t events_published{0};
    std::uint64_t events_dispatched{0};
    std::uint64_t events_dropped{0};
    std::uint64_t uptime_seconds{0};
    std::size_t sensors_running{0};
    std::size_t sensors_degraded{0};
    std::size_t pending_decisions{0};
    std::size_t active_blocks{0};
    std::size_t suspended_pids{0};
    double heuristic_learning_progress{0.0};
    std::string version;
    std::string config_path;
};

class Agent {
public:
    Agent();
    ~Agent();

    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    /// Load configuration, validate it, construct every module. Returns false only
    /// for conditions that make running pointless (unparseable config, cannot
    /// create the runtime dir). Missing optional dependencies are *not* fatal.
    [[nodiscard]] bool init(std::string_view config_path);

    /// Start the bus, the pool, the GUI bridge and every sensor.
    [[nodiscard]] bool start();

    /// Block until a termination signal arrives, then shut down cleanly.
    void run();

    /// Ordered shutdown; safe to call more than once.
    void stop() noexcept;

    /// Request shutdown from a signal handler (async-signal-safe).
    void request_stop() noexcept;

    /// Reload configuration without losing sensor state where possible.
    [[nodiscard]] bool reload_config(std::string_view why = "SIGHUP") noexcept;

    /// Verify the pieces that must work for the agent to be trustworthy.
    struct SelfTestResult {
        bool passed{false};
        std::vector<std::string> checks;   // "ok: ..." / "FAIL: ..."
        std::vector<std::string> fatal;
    };
    [[nodiscard]] SelfTestResult self_test() noexcept;

    [[nodiscard]] core::EventBus& bus() noexcept { return bus_; }
    [[nodiscard]] const core::AgentConfig& config() const noexcept { return cfg_; }
    [[nodiscard]] const std::string& config_path() const noexcept { return config_path_; }
    /// Command-line override. Called before start(), so sensors see the final
    /// value; observe-only mode must not be settable at runtime by an attacker
    /// who has reached the GUI socket.
    void force_dry_run() noexcept { cfg_.dry_run = true; }
    [[nodiscard]] core::ThreadPool& pool() noexcept { return pool_; }
    [[nodiscard]] core::SensorManager& sensors() noexcept { return sensors_; }
    [[nodiscard]] remediation::RemediationEngine& remediation() noexcept { return *remediation_; }
    /// Shadow-copy engine. Null only before init(); take/list/restore are safe to
    /// call from the bridge and CLI afterwards.
    [[nodiscard]] remediation::ShadowCopyEngine* shadow() noexcept { return shadow_.get(); }
    /// Ecosystem Toolbox (Module 8). Null only before init(); probe()/snapshot are
    /// safe to call from the bridge afterwards.
    [[nodiscard]] tools::Toolbox* toolbox() noexcept { return toolbox_.get(); }
    /// Rescue-environment boot planner (Module 8d). Null only before init().
    [[nodiscard]] remediation::RescueBoot* rescue() noexcept { return rescue_.get(); }
    /// AI analyst (Module 9). Null only before init(); ask() is inert until
    /// ai.enabled + a key are configured.
    [[nodiscard]] ai::AiAnalyst* ai() noexcept { return ai_.get(); }
    /// The Shredder (Module 10). Plan/execute are always available; execute
    /// additionally requires the operator's confirmation flag.
    [[nodiscard]] remediation::Shredder* shredder() noexcept { return shredder_.get(); }

    /// User-friendly feature toggles. Mutates the in-memory config, persists it
    /// to the config file, then runs the standard reload path so every sensor
    /// picks the change up race-free. Returns false for unknown keys.
    bool set_feature(std::string_view key, bool on) noexcept;
    struct FeatureState {
        std::string key;
        bool on{false};
        std::string description;
    };
    [[nodiscard]] std::vector<FeatureState> feature_states() const noexcept;
    [[nodiscard]] heuristics::HeuristicSensor& heuristics() noexcept { return *heuristics_; }

    /// Borrowed access to a concrete sensor by id, so the GUI bridge and the CLI
    /// can reach module-specific APIs (counters, caches, rule lists) without the
    /// orchestrator depending on every module header. Returns nullptr when the
    /// sensor is disabled or absent.
    template <typename T>
    [[nodiscard]] T* sensor(core::SensorId id) const noexcept {
        return dynamic_cast<T*>(sensors_.find(id));
    }
    /// Disambiguation by NAME: two sensors may share a SensorId (CanarySensor
    /// and HoneypotSensor are both SensorId::Canary), and find(id) returns the
    /// first registered. Use this overload when the module under the shared id
    /// matters.
    template <typename T>
    [[nodiscard]] T* sensor(std::string_view name) const noexcept {
        return dynamic_cast<T*>(sensors_.find(name));
    }
    [[nodiscard]] AgentStats stats() const noexcept;
    [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_acquire); }
    /// Module 4c: process-memory inspection (raw pointer, daemon-owned).
    [[nodiscard]] forensics::MemInspector* meminspector() const noexcept { return mem_.get(); }

    /// Headline posture 0..100: the single number the dashboard's big indicator
    /// shows. Computed here rather than in the GUI bridge so the heartbeat event,
    /// the overview snapshot and the console all report the SAME number -- a
    /// heartbeat that disagreed with the dashboard would be worse than none.
    [[nodiscard]] int posture_score() const noexcept;
    [[nodiscard]] std::string posture_label() const noexcept;

private:
    void build_sensors() noexcept;
    void on_event(const core::TelemetryEvent& ev) noexcept;
    void enforce_policy(const core::TelemetryEvent& ev) noexcept;
    void heartbeat() noexcept;
    void install_signal_handlers() noexcept;

    core::AgentConfig cfg_;
    std::string config_path_;
    core::EventBus bus_;
    core::ThreadPool pool_;
    core::SensorManager sensors_;

    std::shared_ptr<remediation::RemediationEngine> remediation_;
    std::unique_ptr<remediation::ShadowCopyEngine> shadow_;
    std::unique_ptr<remediation::RescueBoot> rescue_;
    std::unique_ptr<ai::AiAnalyst> ai_;
    std::unique_ptr<remediation::Shredder> shredder_;
    std::unique_ptr<forensics::MemInspector> mem_;
    std::unique_ptr<tools::Toolbox> toolbox_;
    std::shared_ptr<heuristics::HeuristicSensor> heuristics_;
    std::unique_ptr<GuiBridge> gui_;

    core::SubscriptionId sub_id_{0};
    core::SubscriptionId policy_sub_id_{0};
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    core::SysClock::time_point started_at_{};
    std::atomic<std::uint64_t> policy_actions_{0};
    /// Per-exe escalation bookkeeping (row 12): distinct blocked endpoints per
    /// executable. Touched only from the policy (bus dispatcher) thread.
    std::optional<remediation::ExeEscalation> exe_escalation_;
};

/// Installed as the SIGTERM/SIGINT/SIGHUP handler. Set by Agent::init().
void install_agent_signal_hook(Agent* a) noexcept;

}  // namespace hyprnova
