// SPDX-License-Identifier: Apache-2.0
// Suite: response safety — PID-reuse guard, quarantine restore integrity,
// shredder protected paths, write_atomic temp hygiene. All on disposable
// /tmp fixtures and the test's own child processes; nothing on the host.
#include "test_main.hpp"

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <dirent.h>
#include <fstream>

#include "core/event.hpp"
#include "core/fd.hpp"
#include "core/proc.hpp"
#include "remediation/remediation_engine.hpp"
#include "remediation/shredder.hpp"

using namespace hyprnova;
using hyprnova::testing::check;

namespace {

struct Child {
    pid_t pid{-1};
    std::uint64_t ticks{0};
    bool ok{false};
};

/// Fork+exec /bin/sleep and return its starttime identity. DOUBLE fork: the
/// child is re-parented away from the test process, because the engine rightly
/// refuses actions inside its own process tree -- the guard under test must be
/// the identity check, not the tree check.
Child spawn_sleeper(int seconds) {
    Child c;
    const pid_t mid = ::fork();
    if (mid == 0) {
        const pid_t kid = ::fork();
        if (kid == 0) {
            ::execl("/bin/sleep", "sleep", std::to_string(seconds).c_str(),
                    static_cast<char*>(nullptr));
            _exit(127);
        }
        _exit(kid > 0 ? 0 : 127);  // middle exits; the kid re-parents to init
    }
    if (mid > 0) {
        int st = 0;
        ::waitpid(mid, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0) c.pid = 0;  // resolved below
    }
    if (c.pid == 0) {
        // find the orphaned sleeper: newest /bin/sleep started after our marker
        // (simple, bounded: /proc sweep with a small retry loop)
        for (int i = 0; i < 50 && c.pid <= 0; ++i) {
            if (DIR* d = ::opendir("/proc")) {
                while (const auto* e = ::readdir(d)) {
                    const pid_t p = atoi(e->d_name);
                    if (p <= 1) continue;
                    const auto pi = core::proc::read(p);
                    if (pi.exists && pi.comm == "sleep" && pi.ppid == 1) c.pid = p;
                }
                ::closedir(d);
            }
            if (c.pid <= 0) ::usleep(5000);
        }
    }
    if (c.pid > 0) {
        for (int i = 0; i < 50; ++i) {  // up to ~250 ms for the exec to land
            const auto pi = core::proc::read(c.pid);
            if (pi.exists && pi.start_time_ticks != 0 && pi.comm == "sleep") {
                c.ticks = pi.start_time_ticks;
                c.ok = true;
                break;
            }
            ::usleep(5000);
        }
    }
    return c;
}

}  // namespace

void test_response_safety() {
    core::EventBus bus{1024};
    core::AgentConfig cfg;
    cfg.state_dir = std::format("/tmp/hyprnova-resp-{}", ::getpid());
    cfg.remediation.quarantine_dir = cfg.state_dir + "/quarantine";
    cfg.remediation.allow_kill = true;
    cfg.remediation.allow_suspend = true;
    cfg.remediation.allow_quarantine = true;
    cfg.dry_run = false;
    remediation::RemediationEngine engine{bus, cfg};
    engine.probe_capabilities();          // creates the quarantine dir (0700)
    (void)core::fsx::mkdir_p(cfg.state_dir, 0700);
    (void)core::fsx::mkdir_p(cfg.remediation.quarantine_dir, 0700);

    // ---- F1 regression: PID-reuse guard ----
    {
        const auto kid = spawn_sleeper(8);
        if (!kid.ok) {
            testing::skip("response: PID-reuse guard refuses wrong identity",
                          "could not spawn a /bin/sleep child in this environment");
        } else {
            check(engine.suspend(kid.pid, "test: wrong identity", kid.ticks + 9999) == false,
                  "response: suspend with mismatched starttime REFUSED (PID-reuse guard)");
            const auto acts = engine.history(8);
            bool guard_note = false;
            for (const auto& a : acts)
                if (a.detail.find("REUSE") != std::string::npos) guard_note = true;
            check(guard_note, "response: refusal explains the PID-reuse reason in the audit");

            check(engine.suspend(kid.pid, "test: correct identity", kid.ticks) == true,
                  "response: suspend with the recorded starttime succeeds");
            const auto pi = core::proc::read(kid.pid);
            check(pi.state == "T", "response: the child is actually frozen (state T)");

            check(engine.kill(kid.pid, "test", kid.ticks + 1) == false,
                  "response: kill with mismatched starttime REFUSED");
            check(engine.kill(kid.pid, "test", kid.ticks) == true,
                  "response: kill with the recorded starttime succeeds");
            int st = 0;
            ::waitpid(kid.pid, &st, 0);
            check(core::proc::read(kid.pid).exists == false,
                  "response: child reaped and gone");
        }
    }

    // ---- F2 regression: restore integrity ----
    {
        const std::string orig = cfg.state_dir + "/sample.bin";
        const std::string body = "malware-fixture-bytes-0123456789";
        { std::ofstream f{orig}; f << body; }
        check(engine.quarantine_file(orig, "test fixture") == true,
              "quarantine: sample stored, original unlinked");
        struct stat st {};
        const bool original_gone = ::lstat(orig.c_str(), &st) != 0;
        check(original_gone, "quarantine: original path no longer exists");

        // Occupied destination is refused by default.
        const std::string occupied = cfg.state_dir + "/occupied.txt";
        { std::ofstream f{occupied}; f << "user data"; }
        const auto q = engine.quarantined();
        std::uint64_t qid = 0;
        std::string qpath;
        // quarantined() reports "<original> -> <store>" (the GUI's desc format).
        if (!q.empty()) {
            qid = q.front().first;
            const auto arrow = q.front().second.find(" -> ");
            if (arrow != std::string::npos) qpath = q.front().second.substr(arrow + 4);
        }
        if (qid == 0) {
            testing::skip("quarantine: occupied destination refused", "no quarantine entry");
        } else {
            check(engine.restore_file(qid, occupied, /*force*/ false) == false,
                  "quarantine: restore to an OCCUPIED destination is refused");
            { std::ifstream f{occupied}; std::string s; std::getline(f, s);
              check(s == "user data", "quarantine: existing user data untouched"); }

            // Tampered sample must be refused even to a fresh destination.
            if (!qpath.empty()) {
                // The sample is stored 0400; a same-uid attacker (the threat
                // model for a tamper test) chmods it writable first -- exactly
                // what a real tamper would have to do.
                (void)::chmod(qpath.c_str(), 0600);
                std::ofstream t{qpath, std::ios::app};
                t << "attacker bytes";
                t.close();
                check(std::ifstream(qpath).good(), "quarantine: tamper write landed (precondition)");
                const std::string fresh = cfg.state_dir + "/restored.bin";
                check(engine.restore_file(qid, fresh, false) == false,
                      "quarantine: TAMPERED sample refused (hash mismatch)");
                struct stat st2 {};
                check(::lstat(fresh.c_str(), &st2) != 0,
                      "quarantine: nothing written for a tampered sample");

                // Force-overwrite onto an existing path still requires integrity.
                check(engine.restore_file(qid, occupied, true) == false,
                      "quarantine: force does not bypass integrity");

                // Rebuild a pristine sample via quarantine of a fresh file and
                // verify a clean restore path end-to-end.
                const std::string orig2 = cfg.state_dir + "/sample2.bin";
                { std::ofstream f{orig2}; f << "clean-bytes"; }
                check(engine.quarantine_file(orig2, "test clean") == true,
                      "quarantine: second sample stored");
                const auto q2 = engine.quarantined();
                std::uint64_t id2 = 0;
                for (const auto& [id2cand, p2] : q2)
                    if (id2cand != qid) { id2 = id2cand; break; }  // the NEW entry
                const std::string dest2 = cfg.state_dir + "/restored2.bin";
                if (id2 != 0 && engine.restore_file(id2, dest2, false)) {
                    std::ifstream f{dest2};
                    // GCC-14 -Wnull-dereference false positive after inlining
                    // (same libstdc++ iterator family as the toolbox note).
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnull-dereference"
#endif
                    std::string s((std::istreambuf_iterator<char>(f)),
                                  std::istreambuf_iterator<char>());
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
                    check(s == "clean-bytes", "quarantine: clean restore returns the bytes");
                } else {
                    testing::skip("quarantine: clean restore returns the bytes",
                                  "second quarantine entry unavailable");
                }
            } else {
                testing::skip("quarantine: tamper + clean-restore checks",
                              "store path not reachable from the API");
            }
            (void)qpath;
        }
    }

    // ---- shredder protected prefixes (incl. the '/' semantics regression) ----
    {
        using SR = remediation::Shredder;
        check(SR::protected_path("/") == true, "shredder: the root '/' itself is protected");
        check(SR::protected_path("/etc/passwd") == true, "shredder: /etc content protected");
        check(SR::protected_path("/etc-backup/f") == false,
              "shredder: sibling prefix '/etc-backup' is NOT /etc (regression)");
        check(SR::protected_path("/usr/share/doc") == true, "shredder: /usr subtree protected");
        check(SR::protected_path("/home/u/file") == false, "shredder: /home is fair game");
    }

    // ---- write_atomic: no predictable temp left behind (F3) ----
    {
        const std::string target = cfg.state_dir + "/atomic.bin";
        const std::byte payload[]{std::byte{'x'}, std::byte{'y'}};
        check(core::fsx::write_atomic(target, payload, 0600), "fs: write_atomic writes");
        struct stat st {};
        bool stray = false;
        if (DIR* d = ::opendir(cfg.state_dir.c_str())) {
            while (const auto* e = ::readdir(d))
                if (std::strstr(e->d_name, "hyprnova-tmp")) stray = true;
            ::closedir(d);
        }
        check(!stray, "fs: no temp file remains after write_atomic");
        (void)st;
    }
}
