// SPDX-License-Identifier: Apache-2.0
// HyprNova :: spec §8 — behavioural ransomware response drill, sandboxed.
//
// Uses the REAL sandbox fixtures (samples/sandbox/systemupdate, photo-backup)
// against a REAL FileMonitorSensor watching a REAL directory tree. Everything
// happens inside /tmp/sbx (the fixtures' compiled-in, documented disposable
// root — TESTING_GUIDE §3): never host data, never a real payload. The benign
// control (photo-backup) must stay silent; the trojan must trip the monitor's
// ransomware channels; the response invariants (suspend-not-kill, reversible,
// dry-run refuses) are verified on a controlled slow actor so no assertion
// races the fixture's exit.
#include "test_main.hpp"

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <fstream>
#include <mutex>
#include <thread>
#include <vector>

#include "anti_ransomware/file_monitor.hpp"
#include "core/event.hpp"
#include "core/proc.hpp"
#include "core/thread_pool.hpp"

namespace {

using namespace hyprnova;
using hyprnova::testing::check;
using hyprnova::testing::skip;

namespace fs = std::filesystem;

struct EventCap {
    std::mutex mu;
    std::vector<core::TelemetryEvent> events;

    void add(const core::TelemetryEvent& ev) {
        std::lock_guard lk{mu};
        events.push_back(ev);
    }
    std::size_t count_matching(const std::function<bool(const core::TelemetryEvent&)>& pred,
                               std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            {
                std::lock_guard lk{mu};
                for (const auto& ev : events)
                    if (pred(ev)) return 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        std::lock_guard lk{mu};
        for (const auto& ev : events)
            if (pred(ev)) return 1;
        return 0;
    }
};

/// The documented disposable root the fixtures are compiled against.
bool make_sbx_tree(const std::string& root, int victim_files) {
    std::error_code ec;
    (void)fs::remove_all(root, ec);
    if (!fs::create_directories(root + "/victims", ec)) return false;
    for (int i = 0; i < victim_files; ++i) {
        std::ofstream o(std::format("{}/victims/report-{}.docx", root, i), std::ios::trunc);
        if (!o) return false;
        o << "quarterly numbers; benign filler for the sandbox drill\n";
    }
    return true;
}

/// Spawn a SLOW writer (our own /bin/sh loop) in the victim tree: a controlled
/// stand-in for the response-invariant checks (the real fixture exits too fast
/// to freeze deterministically). Returns -1 on failure.
pid_t spawn_slow_writer(const std::string& root) {
    std::fflush(nullptr);
    const pid_t pid = ::fork();
    if (pid == 0) {
        const std::string cmd = std::format(
            "for i in $(seq 1 60); do echo x >> {}/victims/slow-$i.docx; sleep 0.05; done",
            root);
        ::execl("/bin/sh", "sh", "-c", cmd.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    return pid;
}

struct ResponseE2ESuite {
    ResponseE2ESuite() {
        // ---- prerequisites ---------------------------------------------------
        const std::string fixture = "samples/sandbox/systemupdate";
        const std::string control = "samples/sandbox/photo-backup";
        if (!fs::exists(fixture) || !fs::exists(control)) {
            skip("e2e: systemupdate drill", "samples/sandbox fixtures missing");
            skip("e2e: photo-backup control", "samples/sandbox fixtures missing");
            skip("e2e: response invariants", "prerequisite missing with the fixtures");
            return;
        }
        const std::string sbx = "/tmp/sbx";  // the fixtures' compiled-in root
        if (!make_sbx_tree(sbx, 24)) {
            skip("e2e: systemupdate drill", "could not create the disposable /tmp/sbx tree");
            skip("e2e: photo-backup control", "could not create the disposable /tmp/sbx tree");
            skip("e2e: response invariants", "could not create the disposable /tmp/sbx tree");
            return;
        }

        core::EventBus bus{4096};
        bus.start();
        EventCap cap;
        const auto sub = bus.subscribe("e2e-cap", [&](const core::TelemetryEvent& ev) {
            if (ev.severity >= core::Severity::Medium) cap.add(ev);
        });

        core::AgentConfig cfg = core::default_config();
        cfg.state_dir = "/tmp/sbx-state";
        cfg.remediation.quarantine_dir = "/tmp/sbx-state/quarantine";
        cfg.scan.roots.clear();
        core::ScanRoot root;
        root.path = sbx + "/victims";
        root.recursive = true;
        root.label = "sbx";
        cfg.scan.roots.push_back(root);
        cfg.ransomware.mass_modify_file_threshold = 8;
        cfg.dry_run = false;

        core::ThreadPool pool{core::ThreadPoolConfig{}};
        anti_ransomware::FileMonitorSensor monitor(bus, cfg, pool, nullptr);
        const bool started = monitor.start();
        check(started, "e2e: the file monitor starts on the sandbox tree");

        // ---- §8 drill step 1: the trojan fixture trips the channels ----------
        // Workspace restores (and checkouts) can drop the exec bit; the drill
        // must fail on DETECTION grounds, never on a silent exit-126 no-op.
        (void)::chmod(fixture.c_str(), 0755);
        (void)::chmod(control.c_str(), 0755);
        std::fflush(nullptr);  // fork: children must not inherit pending buffers
        const pid_t trojan = ::fork();
        if (trojan == 0) {
            ::freopen("/dev/null", "w", stdout);
            ::execl(fixture.c_str(), "systemupdate", static_cast<char*>(nullptr));
            _exit(127);
        }
        int st = 0;
        ::waitpid(trojan, &st, 0);

        const bool tripped = cap.count_matching(
            [](const core::TelemetryEvent& ev) {
                const std::string m = ev.message;
                const bool ransom_channel =
                    m.find(".locked") != std::string::npos ||
                    m.find("README_RESTORE") != std::string::npos ||
                    m.find("ransom") != std::string::npos ||
                    m.find("mass") != std::string::npos;
                return ev.severity >= core::Severity::High && ransom_channel;
            },
            std::chrono::seconds{8});
        if (!tripped) {
            // Failure forensics: what DID the monitor see (file, not stdout --
            // this suite forks, and forked children must never inherit buffers).
            std::lock_guard lk{cap.mu};
            std::ofstream dump("/tmp/e2e_seen.txt", std::ios::trunc);
            for (const auto& ev : cap.events)
                dump << std::format("[{}] sensor={} {}\n", core::severity_name(ev.severity),
                                    core::sensor_name(ev.sensor), ev.message);
        }
        check(tripped, "e2e: systemupdate trips a High ransomware channel (locked/rename/note/mass)");

        // ---- §8 drill step 2: the benign control stays quiet -----------------
        cap.add(core::TelemetryEvent{});  // barrier: flush nothing, just a marker
        const std::size_t before = [&] {
            std::lock_guard lk{cap.mu};
            return cap.events.size();
        }();
        std::fflush(nullptr);
        const pid_t benign = ::fork();
        if (benign == 0) {
            ::freopen("/dev/null", "w", stdout);
            ::execl(control.c_str(), "photo-backup", static_cast<char*>(nullptr));
            _exit(127);
        }
        ::waitpid(benign, &st, 0);
        std::this_thread::sleep_for(std::chrono::seconds{2});
        bool control_noisy = false;
        {
            std::lock_guard lk{cap.mu};
            for (std::size_t i = before; i < cap.events.size(); ++i) {
                const auto& ev = cap.events[i];
                if (ev.severity >= core::Severity::High &&
                    (ev.message.find("photo") != std::string::npos ||
                     ev.message.find("fakebackup") != std::string::npos ||
                     ev.message.find("mass") != std::string::npos))
                    control_noisy = true;
            }
        }
        check(!control_noisy, "e2e: photo-backup (benign control) raises no High alert");

        // ---- §8 drill step 3: response invariants on a controlled actor ------
        const pid_t actor = spawn_slow_writer(sbx);
        std::this_thread::sleep_for(std::chrono::milliseconds{400});
        if (actor <= 0 || !core::ProcessHandle{actor}.alive()) {
            skip("e2e: response invariants", "could not spawn the controlled writer");
        } else {
            check(monitor.suspend_actor(actor, "e2e: invariant check"),
                  "e2e: suspend_actor SIGSTOPs the writing actor");
            check(core::proc::read(actor).state == "T",
                  "e2e: the actor is SUSPENDED (state T), not killed");
            check(core::ProcessHandle{actor}.alive(),
                  "e2e: the memory image and pid survive (suspend-not-kill)");
            // dry_run refusal: a separate monitor with dry_run=true must refuse.
            core::AgentConfig dry = cfg;
            dry.dry_run = true;
            anti_ransomware::FileMonitorSensor dry_monitor(bus, dry, pool, nullptr);
            check(dry_monitor.suspend_actor(actor, "e2e: dry_run must refuse") == false,
                  "e2e: dry_run REFUSES to stop the actor (observe-only)");
            check(core::proc::read(actor).state == "T",
                  "e2e: the dry_run refusal left the suspended actor suspended");
            // Reversibility: SIGCONT resumes; the actor is ours to kill after.
            ::kill(actor, SIGCONT);
            std::this_thread::sleep_for(std::chrono::milliseconds{150});
            check(core::proc::read(actor).state != "T",
                  "e2e: SIGCONT releases the actor (containment is reversible)");
            ::kill(actor, SIGKILL);
            ::waitpid(actor, &st, 0);
        }

        monitor.stop();
        bus.unsubscribe(sub);
        bus.stop();
        std::error_code ec;
        (void)fs::remove_all(sbx, ec);
        (void)fs::remove_all("/tmp/sbx-state", ec);
    }
};
const ResponseE2ESuite response_e2e_suite_instance;

}  // namespace
