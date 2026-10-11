// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4b — Process Poll (unprivileged exec visibility)
//
// fanotify exec events need CAP_SYS_ADMIN; the audit netlink socket needs
// CAP_AUDIT_READ; eBPF needs CAP_BPF. A directory sweep of /proc needs none of
// those, and it is how the agent keeps its promises on an unprivileged install:
// every process we can see is attributed, its executable is pushed through the
// on-demand scanner, and the resulting verdict carries the pid -- which is what
// lets the heuristic engine score an ACTOR and the response engine suspend one.
//
// Honest limits, stated up front:
//   * a process that execs and exits within one poll interval is never seen;
//   * visibility stops at our uid boundary (other users' processes appear as
//     stat-able pids whose exe/cmdline we cannot read -- they are ignored);
//   * this is polling, not a syscall tap: latency is the interval, not zero.

#pragma once

#include <atomic>
#include <chrono>
#include <string>
#include <unordered_map>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/sensor.hpp"

namespace hyprnova::scanning { class ScannerSensor; }

namespace hyprnova::behavioral {

class ProcPollSensor final : public core::ISensor {
public:
    ProcPollSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool)
        : core::ISensor("proc-poll", core::SensorId::ProcessPoll, bus, cfg, pool) {}

    /// Wired by the agent after both sensors exist. The manager owns both; the
    /// raw pointer never outlives the manager.
    void set_scanner(scanning::ScannerSensor* scanner) noexcept { scanner_ = scanner; }

    /// One sweep. Public so the self-test can drive it deterministically.
    /// Returns the pids discovered as newly-exec'd by THIS sweep.
    std::vector<pid_t> poll_once();

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override {
        return c.proc_poll.enabled;
    }
    bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    struct ProcIdentity {
        unsigned long long start_ticks{0}; // /proc/<pid>/stat field 22
        std::chrono::steady_clock::time_point last_scan{};
    };

    scanning::ScannerSensor* scanner_{nullptr};
    std::mutex mu_;  // known_ and path_scans_ are touched by loop + poll_once
    std::unordered_map<pid_t, ProcIdentity> known_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> path_scans_;
    std::atomic<std::uint64_t> sweeps_{0};
    std::atomic<std::uint64_t> execs_seen_{0};
    std::atomic<std::uint64_t> scans_started_{0};
};

}  // namespace hyprnova::behavioral
