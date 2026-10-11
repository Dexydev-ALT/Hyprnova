// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4a — Falco / eBPF telemetry sensor
//
// Falco (and any eBPF loader that emits the same ndjson shape) gives us kernel-
// level syscall events with rule-based interpretation already applied. We consume
// its JSON stream, normalise it into TelemetryEvent, and -- importantly -- treat
// it as ONE input among several rather than the whole story: a Falco rule firing
// is a lead, and Module 5 decides whether that lead becomes an incident.

#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "behavioral/socket_source.hpp"
#include "core/config.hpp"
#include "core/event.hpp"
#include "core/sensor.hpp"

namespace hyprnova::behavioral {

/// A normalised Falco output record.
struct FalcoAlert {
    core::SysClock::time_point ts{};
    std::string rule;
    std::string priority;
    std::string output;
    std::string source;           // syscall | k8s_audit | plugins
    std::vector<std::string> tags;

    pid_t pid{0};
    pid_t tid{0};
    std::string proc_name;
    std::string proc_exe;
    std::string proc_cmdline;
    std::string proc_pname;
    pid_t ppid{0};
    std::vector<std::string> ancestry;
    uid_t uid{0xFFFFFFFF};
    std::string user;
    std::string container_id;
    std::string container_name;
    std::string container_image;
    bool in_container{false};
    std::string fd_name;          // file / socket name
    std::string k8s_namespace;
    std::string k8s_pod;
    std::string tty;
    std::string cwd;

    core::Severity severity{core::Severity::Info};
    core::EventKind kind{core::EventKind::ProcAnomaly};
    /// Set when this rule is not in our interesting-priority list; such alerts
    /// are counted but not published, which is what keeps Falco's Debug stream
    //  from drowning the bus.
    bool filtered{false};
};

[[nodiscard]] FalcoAlert parse_falco_json(const core::json::Value& v) noexcept;

/// Map a Falco rule name to our EventKind using the configured rule_map, with a
/// keyword-based fallback so an unmapped new rule still lands somewhere sane.
[[nodiscard]] core::EventKind map_rule_to_kind(std::string_view rule, std::string_view output,
                                               const core::FalcoConfig& cfg) noexcept;

class FalcoSensor final : public core::ISensor {
public:
    FalcoSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    /// Feed a raw ndjson line. Exposed for tests and for the "replay a capture"
    /// diagnostic mode.
    void ingest(std::string_view line) noexcept;
    void ingest_value(const core::json::Value& v) noexcept;

    [[nodiscard]] const UnixSocketSource& source() const noexcept { return *src_; }
    [[nodiscard]] std::uint64_t alerts_seen() const noexcept {
        return alerts_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t alerts_filtered() const noexcept {
        return filtered_.load(std::memory_order_relaxed);
    }
    /// Top rules by frequency, for the GUI's "what is this host actually doing"
    /// panel. Bounded to the 24 most frequent.
    struct RuleCount {
        std::string rule;
        std::uint64_t count{0};
        core::Severity severity{core::Severity::Info};
        std::string last_output;
        core::SysClock::time_point last_seen{};
    };
    [[nodiscard]] std::vector<RuleCount> top_rules(std::size_t n = 24) const noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    void on_stop() override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    void publish(const FalcoAlert& a) noexcept;

    std::unique_ptr<UnixSocketSource> src_;
    std::atomic<std::uint64_t> alerts_{0};
    std::atomic<std::uint64_t> filtered_{0};
    std::atomic<std::uint64_t> parse_errors_{0};
    mutable std::mutex rule_mu_;
    std::unordered_map<std::string, RuleCount> rules_;
};

// ---------------------------------------------------------------------------
// Suricata EVE consumer (same transport, different schema)
// ---------------------------------------------------------------------------

/// Beacon detection over EVE flow/http/dns records. A C2 channel is usually not
/// a known-bad IP; it is a *metronome*. This is the cheap, high-precision half
/// of network detection, and it needs no signature database.
struct BeaconProfile {
    std::string peer;         // ip:port
    std::string process;
    std::vector<double> intervals_seconds;
    std::uint64_t hits{0};
    double mean_interval{0.0};
    double jitter{0.0};       // stdev / mean
    std::uint64_t bytes_out{0};
    std::uint64_t bytes_in{0};
    double score{0.0};        // 0..1
    bool beacon_like{false};
};

class SuricataSensor final : public core::ISensor {
public:
    SuricataSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    void ingest_value(const core::json::Value& v) noexcept;

    [[nodiscard]] std::vector<BeaconProfile> beacons(std::size_t n = 32) const noexcept;
    [[nodiscard]] std::uint64_t alerts_seen() const noexcept { return alerts_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t flows_seen() const noexcept { return flows_.load(std::memory_order_relaxed); }

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    void on_stop() override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    void evaluate_beacons() noexcept;

    std::unique_ptr<UnixSocketSource> src_;   // when eve_socket is configured
    core::UniqueFd eve_file_;                 // otherwise tail eve.json
    std::size_t eve_offset_{0};
    core::json::NdjsonReader nd_{1 << 20};

    mutable std::mutex beacon_mu_;
    std::unordered_map<std::string, BeaconProfile> beacons_;
    std::atomic<std::uint64_t> alerts_{0};
    std::atomic<std::uint64_t> flows_{0};
    core::SteadyClock::time_point last_eval_{};
};

}  // namespace hyprnova::behavioral
