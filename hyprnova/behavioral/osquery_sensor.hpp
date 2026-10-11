// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4c — osquery interface
//
// osquery answers questions that a syscall stream cannot: "which processes are
// executing out of /dev/shm right now?", "what is listening on which port and who
// owns it?", "which SUID binaries exist on this host?". Those are *state* queries,
// not events, and polling state on a slow cadence is both cheaper and more
// reliable than trying to derive it from a stream.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/json.hpp"
#include "core/sensor.hpp"

namespace hyprnova::behavioral {

struct QueryResult {
    std::string name;
    std::string sql;
    bool ok{false};
    std::string error;
    std::vector<core::json::Value> rows;   // each row is a JSON object
    std::chrono::milliseconds elapsed{};
    core::SysClock::time_point ran_at{};
};

/// Row-level classifier: turns a row from a named query into a finding. Keeping
/// this table-driven means new detection is a config change, not a code change.
struct RowFinding {
    bool report{false};
    core::EventKind kind{core::EventKind::ProcAnomaly};
    core::Severity severity{core::Severity::Info};
    std::uint16_t risk{0};
    std::string message;
    std::vector<std::string> triggers;
    std::string path;
    pid_t pid{0};
};

/// Classify one row of one named query. Pure, so it is unit-testable without
/// osquery installed.
[[nodiscard]] RowFinding classify_row(std::string_view query_name, const core::json::Value& row) noexcept;

class OsquerySensor final : public core::ISensor {
public:
    OsquerySensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    /// Run one query synchronously. Used by the GUI ("run this SQL now") and by
    /// the escalation pipeline.
    [[nodiscard]] QueryResult run_query(std::string_view name, std::string_view sql) noexcept;

    /// Run every configured query; called on the interval by loop().
    void run_all() noexcept;

    [[nodiscard]] bool available() const noexcept { return available_; }
    [[nodiscard]] const std::string& binary() const noexcept { return binary_; }
    [[nodiscard]] std::vector<QueryResult> last_results() const noexcept;
    [[nodiscard]] std::uint64_t queries_run() const noexcept { return run_count_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t rows_returned() const noexcept { return rows_.load(std::memory_order_relaxed); }

    /// The interesting subset: rows that produced a finding, newest first.
    struct Anomaly {
        std::string query;
        std::string message;
        core::Severity severity{core::Severity::Info};
        std::uint16_t risk{0};
        core::SysClock::time_point when{};
    };
    [[nodiscard]] std::vector<Anomaly> anomalies(std::size_t n = 64) const noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    bool available_{false};
    std::string binary_;
    mutable std::mutex mu_;
    std::vector<QueryResult> results_;
    std::deque<Anomaly> anomalies_;
    static constexpr std::size_t kMaxAnomalies = 512;
    std::atomic<std::uint64_t> run_count_{0};
    std::atomic<std::uint64_t> rows_{0};
    core::SysClock::time_point last_run_{};
};

}  // namespace hyprnova::behavioral
