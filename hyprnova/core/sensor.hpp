// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/sensor.hpp
// The uniform module contract. Every one of Modules 1-6 implements ISensor, so
// the orchestrator can start, health-check, hot-reload and stop them uniformly
// without knowing what any of them does.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <mutex>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/log.hpp"
#include "core/thread_pool.hpp"

namespace hyprnova::core {

enum class SensorState : std::uint8_t {
    Stopped = 0,
    Starting,
    Running,
    Degraded,   // running but with reduced capability (missing binary, no CAP)
    Failed,     // could not start; reason in last_error()
    Stopping,
};

constexpr std::string_view state_name(SensorState s) noexcept {
    switch (s) {
        case SensorState::Stopped: return "stopped";
        case SensorState::Starting: return "starting";
        case SensorState::Running: return "running";
        case SensorState::Degraded: return "degraded";
        case SensorState::Failed: return "failed";
        case SensorState::Stopping: return "stopping";
    }
    return "stopped";
}

struct SensorHealth {
    std::string name;
    SensorState state{SensorState::Stopped};
    std::string detail;            // why degraded/failed, rendered verbatim in the GUI
    std::uint64_t events_emitted{0};
    std::uint64_t events_dropped{0};
    std::uint64_t errors{0};
    std::uint64_t restarts{0};
    double cpu_percent{0.0};       // self-measured over the last interval
    std::size_t rss_bytes{0};      // self-measured delta
    SysClock::time_point last_activity{};
    SysClock::time_point started_at{};
    std::vector<std::string> capabilities_missing;
    std::vector<std::string> optional_deps_missing;  // binaries/sockets we probed for
};

/// Common base. Concrete sensors override `on_start` / `on_stop` and optionally
/// `run()` when they own their own event loop thread.
class ISensor {
public:
    ISensor(std::string name, SensorId id, EventBus& bus, const AgentConfig& cfg, ThreadPool& pool)
        : name_{std::move(name)}, id_{id}, bus_{bus}, cfg_{cfg}, pool_{pool} {}
    virtual ~ISensor() = default;

    ISensor(const ISensor&) = delete;
    ISensor& operator=(const ISensor&) = delete;

    /// Start the sensor. Implemented by the base class: transitions state,
    /// measures resources, calls on_start(), and never lets an exception escape.
    bool start();
    void stop();

    [[nodiscard]] const std::string& name() const noexcept { return name_; }
    [[nodiscard]] SensorId id() const noexcept { return id_; }
    [[nodiscard]] SensorState state() const noexcept { return state_.load(std::memory_order_acquire); }
    [[nodiscard]] SensorHealth health() const;

    /// Called on SIGHUP / config change. Default: restart.
    virtual void reload(const AgentConfig& cfg);

    /// Is this sensor's module switched on in the given config? Default: yes.
    /// The manager consults this on every start AND every hot reload, which is
    /// what makes the Settings ON/OFF switches real: a toggled-off module stops
    /// and reports "disabled in settings" instead of silently running on with
    /// stale config. (Before this, the enabled flags were consulted only when
    /// the sensor list was BUILT -- flipping a toggle reloaded a sensor that
    /// then ran exactly as before.)
    [[nodiscard]] virtual bool enabled(const AgentConfig& cfg) const noexcept { (void)cfg; return true; }
    [[nodiscard]] const AgentConfig& config() const noexcept { return cfg_; }
    /// Park a sensor that is intentionally switched off (not an error).
    void mark_disabled(std::string_view reason) noexcept;

protected:
    /// Emit through the bus with our identity stamped on, enriched and counted.
    void emit(TelemetryEvent ev) noexcept;
    void emit(EventKind kind, Severity sev, std::string msg) noexcept;
    void note_error(std::string_view what) noexcept;
    void mark_degraded(std::string reason) noexcept;
    void mark_running(std::string detail = {}) noexcept;

    /// Module-specific startup. Return false to signal a hard failure.
    virtual bool on_start() = 0;
    virtual void on_stop() {}

    /// If the sensor wants its own dedicated thread, override and return true;
    /// the base class will spawn a jthread running `loop()` with a stop_token.
    [[nodiscard]] virtual bool wants_thread() const noexcept { return false; }
    virtual void loop(std::stop_token st) { (void)st; }

    /// Declared in constructor-initialisation order (name, id, bus, cfg, pool).
    std::string name_;
    SensorId id_;
    EventBus& bus_;
    const AgentConfig& cfg_;
    ThreadPool& pool_;

private:
    std::atomic<SensorState> state_{SensorState::Stopped};
    std::string detail_;
    mutable std::mutex health_mu_;
    std::uint64_t emitted_{0};
    std::uint64_t dropped_{0};
    std::uint64_t errors_{0};
    std::uint64_t restarts_{0};
    SysClock::time_point last_activity_{};
    SysClock::time_point started_at_{};
    std::vector<std::string> caps_missing_;
    std::vector<std::string> deps_missing_;
    std::jthread worker_;
    mutable std::atomic<std::uint64_t> last_utime_{0};
};

/// Aggregate lifecycle manager. Owns sensors in dependency order and publishes
/// SensorUp/SensorDown so the GUI dashboard can render the pipeline topology.
class SensorManager {
public:
    SensorManager(EventBus& bus, const AgentConfig& cfg, ThreadPool& pool);
    ~SensorManager();

    void add(std::unique_ptr<ISensor> sensor);
    /// Shared ownership, for a sensor another component also needs a typed handle
    /// to (the heuristic engine is both a sensor on the manager's list and the
    /// escalation backend the agent holds directly).
    void add_shared(std::shared_ptr<ISensor> sensor);

    /// Starts in insertion order. A failed non-critical sensor does not abort
    /// the daemon; a failed critical sensor does.
    bool start_all();
    void stop_all();
    void reload_all(const AgentConfig& cfg);

    /// Borrowed pointer to a registered sensor, or nullptr. Ownership stays with
    /// the manager; the caller must not outlive it. Used by the GUI bridge and the
    /// escalation pipeline to reach a specific sensor's richer API without the
    /// orchestrator knowing every module's concrete type.
    [[nodiscard]] ISensor* find(SensorId id) const noexcept;
    [[nodiscard]] ISensor* find(std::string_view name) const noexcept;

    [[nodiscard]] std::vector<SensorHealth> health_snapshot() const;
    [[nodiscard]] std::size_t count() const;
    [[nodiscard]] std::size_t degraded_count() const;
    [[nodiscard]] std::size_t failed_count() const;

    /// Mark a sensor whose failure must abort startup (e.g. the canary sensor on
    /// a ransomware-protection product).
    void mark_critical(std::string_view name);

private:
    EventBus& bus_;
    const AgentConfig& cfg_;
    ThreadPool& pool_;
    mutable std::mutex mu_;
    std::vector<std::shared_ptr<ISensor>> sensors_;
    std::vector<std::string> critical_;
};

}  // namespace hyprnova::core
