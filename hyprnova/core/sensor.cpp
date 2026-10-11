// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/sensor.cpp

#include "core/sensor.hpp"

#include <algorithm>
#include <cstdio>
#include <format>
#include <fstream>

#include "core/fd.hpp"
#include "core/proc.hpp"

namespace hyprnova::core {

namespace {

/// Self-measured CPU time of this process from /proc/self/stat, in clock ticks.
std::uint64_t self_utime_ticks() noexcept {
    std::string s;
    if (fsx::read_file("/proc/self/stat", s, 8192) < 0) return 0;
    // Fields 14 (utime) and 15 (stime), after the parenthesised comm.
    const std::size_t rp = s.rfind(')');
    if (rp == std::string::npos) return 0;
    std::string_view rest{s.data() + rp + 2, s.size() - rp - 2};
    std::uint64_t u = 0, st = 0;
    if (std::sscanf(std::string(rest).c_str(), "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
                    &u, &st) != 2)
        return 0;
    return u + st;
}

std::size_t self_rss_bytes() noexcept {
    std::string s;
    if (fsx::read_file("/proc/self/status", s, 16384) < 0) return 0;
    std::size_t pos = 0;
    while (pos < s.size()) {
        const std::size_t nl = s.find('\n', pos);
        const std::string_view line{s.data() + pos, (nl == std::string::npos ? s.size() : nl) - pos};
        if (line.starts_with("VmRSS:")) {
            std::uint64_t kb = 0;
            if (std::sscanf(std::string(line).c_str(), "VmRSS: %lu", &kb) == 1)
                return static_cast<std::size_t>(kb) * 1024;
            return 0;
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// ISensor
// ---------------------------------------------------------------------------

bool ISensor::start() {
    SensorState expected = SensorState::Stopped;
    if (!state_.compare_exchange_strong(expected, SensorState::Starting, std::memory_order_acq_rel)) {
        // Already started or failed. Restarting a Failed sensor is legitimate
        // (that is what SensorManager does after a remediation of its own), but
        // a double start() on a Running sensor is a programming error we log.
        if (expected == SensorState::Running || expected == SensorState::Starting ||
            expected == SensorState::Degraded) {
            SDEBUG(name_, "start() called while in state {}", state_name(expected));
            return true;
        }
        state_.store(SensorState::Starting);
    }

    bool ok = false;
    try {
        ok = on_start();
    } catch (const std::exception& e) {
        note_error(std::string("on_start threw: ") + e.what());
        ok = false;
    } catch (...) {
        note_error("on_start threw unknown exception");
        ok = false;
    }

    if (!ok) {
        state_.store(SensorState::Failed);
        SERROR(name_, "failed to start: {}", detail_);
        bus_.emit(id_, EventKind::SensorDown, Severity::High,
                  std::format("sensor '{}' failed to start: {}", name_, detail_));
        return false;
    }

    {
        std::lock_guard lk{health_mu_};
        started_at_ = SysClock::now();
        last_activity_ = started_at_;
        ++restarts_;
    }
    last_utime_.store(self_utime_ticks(), std::memory_order_relaxed);

    if (state_.load() == SensorState::Starting) mark_running("initialised");

    if (wants_thread()) {
        worker_ = std::jthread([this](std::stop_token st) {
            try {
                loop(st);
            } catch (const std::exception& e) {
                note_error(std::string("loop threw: ") + e.what());
                state_.store(SensorState::Failed);
            } catch (...) {
                note_error("loop threw unknown exception");
                state_.store(SensorState::Failed);
            }
        });
    }

    SINFO(name_, "started ({})", detail_.empty() ? "ok" : detail_);
    bus_.emit(id_, EventKind::SensorUp, Severity::Info, std::format("sensor '{}' is {}", name_, state_name(state())));
    return true;
}

void ISensor::stop() {
    const SensorState cur = state_.load();
    if (cur == SensorState::Stopped) return;
    state_.store(SensorState::Stopping);

    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    try {
        on_stop();
    } catch (const std::exception& e) {
        SERROR(name_, "on_stop threw: {}", e.what());
    } catch (...) {
        SERROR(name_, "on_stop threw unknown exception");
    }
    state_.store(SensorState::Stopped);
    SINFO(name_, "stopped");
    bus_.emit(id_, EventKind::SensorDown, Severity::Info, std::format("sensor '{}' stopped", name_));
}

void ISensor::reload(const AgentConfig& cfg) {
    (void)cfg;
    SINFO(name_, "reload requested -> restarting sensor");
    const bool was_running = state_.load() == SensorState::Running || state_.load() == SensorState::Degraded;
    if (was_running) {
        stop();
        start();
    }
}

void ISensor::emit(TelemetryEvent ev) noexcept {
    if (ev.sensor == SensorId::Unknown) ev.sensor = id_;
    if (ev.ts == TimePoint{}) ev.ts = SysClock::now();

    // Enrichment happens here, on the sensor thread, exactly once per event.
    proc::enrich(ev);

    if (bus_.publish(std::move(ev))) {
        std::lock_guard lk{health_mu_};
        ++emitted_;
        last_activity_ = SysClock::now();
    } else {
        std::lock_guard lk{health_mu_};
        ++dropped_;
    }
}

void ISensor::emit(EventKind kind, Severity sev, std::string msg) noexcept {
    TelemetryEvent ev;
    ev.sensor = id_;
    ev.kind = kind;
    ev.severity = sev;
    ev.message = std::move(msg);
    emit(std::move(ev));
}

void ISensor::note_error(std::string_view what) noexcept {
    {
        std::lock_guard lk{health_mu_};
        ++errors_;
        detail_ = std::string(what);
    }
    SWARN(name_, "{}", what);
}

void ISensor::mark_degraded(std::string reason) noexcept {
    {
        std::lock_guard lk{health_mu_};
        detail_ = reason;
    }
    state_.store(SensorState::Degraded);
    SWARN(name_, "degraded: {}", reason);
}

void ISensor::mark_running(std::string detail) noexcept {
    {
        std::lock_guard lk{health_mu_};
        if (!detail.empty()) detail_ = std::move(detail);
    }
    if (state_.load() != SensorState::Degraded) state_.store(SensorState::Running);
}

SensorHealth ISensor::health() const {
    SensorHealth h;
    h.name = name_;
    h.state = state_.load(std::memory_order_acquire);
    {
        std::lock_guard lk{health_mu_};
        h.detail = detail_;
        h.events_emitted = emitted_;
        h.events_dropped = dropped_;
        h.errors = errors_;
        h.restarts = restarts_;
        h.last_activity = last_activity_;
        h.started_at = started_at_;
        h.capabilities_missing = caps_missing_;
        h.optional_deps_missing = deps_missing_;
    }
    // CPU% attributed to the sensor is approximated from process delta since the
    // last health read. Good enough for a dashboard; not a profiler.
    const std::uint64_t now_ticks = self_utime_ticks();
    const std::uint64_t prev = last_utime_.exchange(now_ticks, std::memory_order_relaxed);
    h.rss_bytes = self_rss_bytes();
    if (now_ticks > prev && h.started_at != SysClock::time_point{}) {
        const double secs = std::chrono::duration<double>(SysClock::now() - h.started_at).count();
        if (secs > 1.0)
            h.cpu_percent = 100.0 * static_cast<double>(now_ticks - prev) /
                            (static_cast<double>(proc::ticks_per_second()) * secs);
    }
    return h;
}

// ---------------------------------------------------------------------------
// SensorManager
// ---------------------------------------------------------------------------

SensorManager::SensorManager(EventBus& bus, const AgentConfig& cfg, ThreadPool& pool)
    : bus_{bus}, cfg_{cfg}, pool_{pool} {}

SensorManager::~SensorManager() { stop_all(); }

void SensorManager::add(std::unique_ptr<ISensor> sensor) {
    if (!sensor) return;
    std::lock_guard lk{mu_};
    sensors_.push_back(std::shared_ptr<ISensor>(std::move(sensor)));
}

void SensorManager::add_shared(std::shared_ptr<ISensor> sensor) {
    if (!sensor) return;
    std::lock_guard lk{mu_};
    sensors_.push_back(std::move(sensor));
}

void SensorManager::mark_critical(std::string_view name) {
    std::lock_guard lk{mu_};
    critical_.emplace_back(name);
}

bool SensorManager::start_all() {
    std::lock_guard lk{mu_};
    bool all_ok = true;
    for (auto& s : sensors_) {
        if (!s->enabled(s->config())) {
            s->mark_disabled("disabled in settings");
            continue;
        }
        if (!s->start()) {
            all_ok = false;
            const bool critical =
                std::find(critical_.begin(), critical_.end(), s->name()) != critical_.end();
            if (critical) {
                SERROR("sensor-manager", "CRITICAL sensor '{}' failed to start; aborting startup",
                       s->name());
                return false;
            }
            SWARN("sensor-manager", "non-critical sensor '{}' failed to start; continuing degraded",
                  s->name());
        }
    }
    return all_ok;
}

void ISensor::mark_disabled(std::string_view reason) noexcept {
    // Stopped (not Failed): an operator switching a module off is intent, not
    // an error. The detail still says WHY, so the GUI shows an honest state.
    state_.store(SensorState::Stopped, std::memory_order_release);
    std::lock_guard lk{health_mu_};
    detail_ = std::string(reason);
}

void SensorManager::stop_all() {
    std::lock_guard lk{mu_};
    // Stop in reverse: remediation last so nothing acts on a half-torn-down bus.
    for (auto it = sensors_.rbegin(); it != sensors_.rend(); ++it) (*it)->stop();
}

void SensorManager::reload_all(const AgentConfig& cfg) {
    std::lock_guard lk{mu_};
    for (auto& s : sensors_) s->reload(cfg);
}

std::vector<SensorHealth> SensorManager::health_snapshot() const {
    std::lock_guard lk{mu_};
    std::vector<SensorHealth> out;
    out.reserve(sensors_.size());
    for (const auto& s : sensors_) out.push_back(s->health());
    return out;
}

ISensor* SensorManager::find(SensorId id) const noexcept {
    std::lock_guard lk{mu_};
    for (const auto& s : sensors_) {
        if (s->id() == id) return s.get();
    }
    return nullptr;
}

ISensor* SensorManager::find(std::string_view name) const noexcept {
    std::lock_guard lk{mu_};
    for (const auto& s : sensors_) {
        if (s->name() == name) return s.get();
    }
    return nullptr;
}

std::size_t SensorManager::count() const {
    std::lock_guard lk{mu_};
    return sensors_.size();
}

std::size_t SensorManager::degraded_count() const {
    std::lock_guard lk{mu_};
    return static_cast<std::size_t>(
        std::count_if(sensors_.begin(), sensors_.end(), [](const auto& s) {
            return s->state() == SensorState::Degraded;
        }));
}

std::size_t SensorManager::failed_count() const {
    std::lock_guard lk{mu_};
    return static_cast<std::size_t>(std::count_if(
        sensors_.begin(), sensors_.end(),
        [](const auto& s) { return s->state() == SensorState::Failed; }));
}

}  // namespace hyprnova::core
