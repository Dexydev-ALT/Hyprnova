// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4b — Process Poll implementation.

#include "behavioral/proc_poll.hpp"

#include <dirent.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <mutex>

#include "core/log.hpp"
#include "core/proc.hpp"
#include "scanning/scanner.hpp"

namespace hyprnova::behavioral {

using core::EventKind;
using core::Severity;
using core::TelemetryEvent;

std::vector<pid_t> ProcPollSensor::poll_once() {
    std::vector<pid_t> discovered;
    const pid_t self = ::getpid();

    // ---- snapshot /proc ---------------------------------------------------
    std::vector<pid_t> pids;
    if (DIR* d = ::opendir("/proc")) {
        while (const auto* ent = ::readdir(d)) {
            pid_t pid = 0;
            const auto [p, ec] =
                std::from_chars(ent->d_name, ent->d_name + std::strlen(ent->d_name), pid);
            if (ec != std::errc{} || *p != '\0' || pid <= 0) continue;
            pids.push_back(pid);
        }
        ::closedir(d);
    } else {
        note_error("cannot read /proc");
        return discovered;
    }

    for (const pid_t pid : pids) {
        if (pid == self) continue;
        const core::proc::ProcessInfo pi = core::proc::read(pid);
        if (!pi.exists || pi.start_time_ticks == 0) continue;

        {
            std::lock_guard lk{mu_};
            const auto it = known_.find(pid);
            if (it != known_.end()) {
                if (it->second.start_ticks == pi.start_time_ticks) continue;  // already seen
                // Same pid number, different start time: the kernel recycled
                // the pid. That is a brand-new process.
                it->second.start_ticks = pi.start_time_ticks;
            } else {
                known_[pid] = ProcIdentity{pi.start_time_ticks, {}};
            }
        }

        // Kernel threads and processes we cannot read have no exe: attribution
        // stops there, honestly, rather than guessing from comm alone.
        if (pi.exe.empty()) continue;

        discovered.push_back(pid);   // discovery is independent of scanning
        ++execs_seen_;
        TelemetryEvent ev;
        ev.sensor = core::SensorId::ProcessPoll;
        ev.kind = EventKind::ProcExec;
        ev.severity = Severity::Info;
        ev.actor.pid = pid;
        ev.actor.ppid = pi.ppid;
        ev.actor.uid = pi.uid;
        ev.actor.exe = pi.exe;
        ev.actor.comm = pi.comm;
        ev.actor.cmdline = pi.cmdline;
        ev.message = std::format("exec observed: pid {} ({}) exe={}", pid, pi.comm, pi.exe);
        emit(std::move(ev));

        // ---- attributed on-exec scan --------------------------------------
        // The verdict event carries this pid back to the heuristic engine; that
        // is how a signature hit becomes an ACTOR score (suspendable) instead
        // of a note about a file.
        if (!cfg_.scan.enabled || !scanner_) continue;
        if (pi.exe.ends_with(" (deleted)")) continue;  // nothing sane to open

        bool scan = true;
        {
            std::lock_guard lk{mu_};
            const auto now = core::SteadyClock::now();
            // Path-level cooldown: fork servers and build systems exec the same
            // binaries constantly; the scanner's hash cache dedups the work but
            // we skip the open+read entirely. Bounded: stale paths age out.
            if (path_scans_.size() > 4096)
                std::erase_if(path_scans_, [now, this](const auto& kv) {
                    return now - kv.second > cfg_.proc_poll.rescan_cooldown;
                });
            const auto it = path_scans_.find(pi.exe);
            if (it != path_scans_.end() && now - it->second < cfg_.proc_poll.rescan_cooldown)
                scan = false;
            else
                path_scans_[pi.exe] = now;
        }
        if (!scan) continue;
        ++scans_started_;
        (void)scanner_->scan_now(pi.exe, scanning::ScanReason::ExecDetected, pid);
        discovered.push_back(pid);
    }

    // Forget dead pids so the map cannot grow without bound on a long-lived
    // host (pid recycling also makes stale entries actively wrong).
    {
        std::lock_guard lk{mu_};
        std::erase_if(known_, [&pids](const auto& kv) {
            return std::find(pids.begin(), pids.end(), kv.first) == pids.end();
        });
    }
    ++sweeps_;
    return discovered;
}

bool ProcPollSensor::on_start() {
    // Seed WITHOUT emitting: at daemon start every running process is "new",
    // and eight hundred exec events at boot are noise, not signal. Only
    // processes that appear (or re-exec) AFTER we start are attributed.
    if (DIR* d = ::opendir("/proc")) {
        while (const auto* ent = ::readdir(d)) {
            pid_t pid = 0;
            const auto [p, ec] =
                std::from_chars(ent->d_name, ent->d_name + std::strlen(ent->d_name), pid);
            if (ec != std::errc{} || *p != '\0' || pid <= 0 || pid == ::getpid()) continue;
            const auto pi = core::proc::read(pid);
            if (pi.exists) known_[pid] = ProcIdentity{pi.start_time_ticks, core::SteadyClock::now()};
        }
        ::closedir(d);
    }
    mark_running(std::format("sweeping /proc every {} ms (unprivileged exec visibility)",
                             cfg_.proc_poll.interval.count()));
    return true;
}

void ProcPollSensor::loop(std::stop_token st) {
    using std::chrono::steady_clock;
    auto next = steady_clock::now() + cfg_.proc_poll.interval;
    while (!st.stop_requested()) {
        if (steady_clock::now() >= next) {
            (void)poll_once();
            next += cfg_.proc_poll.interval;
            if (steady_clock::now() > next + std::chrono::seconds{5})
                next = steady_clock::now() + cfg_.proc_poll.interval;  // fell far behind: resync
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
}

}  // namespace hyprnova::behavioral
