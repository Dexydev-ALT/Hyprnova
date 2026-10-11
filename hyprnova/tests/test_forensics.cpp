// SPDX-License-Identifier: Apache-2.0
// Suite: Module 4c — memory inspection (identity guard, honest limits,
// external-tool probing, bounded dump). Runs on the test's own child process.
#include "test_main.hpp"

#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "core/config.hpp"
#include "forensics/mem_inspect.hpp"

using namespace hyprnova;
using hyprnova::testing::check;

namespace {
struct Kid {
    pid_t pid{-1};
    bool ok{false};
};
Kid spawn_sleeper(int seconds) {
    Kid k;
    k.pid = ::fork();
    if (k.pid == 0) {
        ::execl("/bin/sleep", "sleep", std::to_string(seconds).c_str(),
                static_cast<char*>(nullptr));
        _exit(127);
    }
    if (k.pid > 0) {
        for (int i = 0; i < 50; ++i) {
            const auto pi = core::proc::read(k.pid);
            if (pi.exists && pi.comm == "sleep") { k.ok = true; break; }
            ::usleep(5000);
        }
    }
    return k;
}
}  // namespace

void test_forensics_mem() {
    core::AgentConfig cfg;
    cfg.state_dir = std::format("/tmp/hyprnova-mem-{}", ::getpid());
    forensics::MemInspector mi{cfg};

    // Limits text exists and says what it is NOT (the honesty contract).
    const auto limits = forensics::MemInspector::limits_text();
    check(limits.find("NOT full system-memory") != std::string_view::npos,
          "mem: limits text states the boundary explicitly");

    // External tools: three probes, each with an honest detail either way.
    {
        const auto tools = forensics::MemInspector::external_tools();
        check(tools.size() == 3, "mem: probes Volatility3 + MemProcFS + LiME");
        bool all_have_detail = true;
        for (const auto& t : tools)
            if (t.detail.empty()) all_have_detail = false;
        check(all_have_detail, "mem: every external tool reports presence OR why absent");
    }

    // Inspect our own child (same uid => readable in the usual case).
    const auto kid = spawn_sleeper(8);
    if (!kid.ok) {
        testing::skip("mem: inspect on a live child", "cannot spawn /bin/sleep here");
    } else {
        const auto rep = mi.inspect(kid.pid);
        check(rep.pid == kid.pid && rep.start_time_ticks != 0,
              "mem: inspection anchors the process identity (starttime recorded)");
        check(rep.regions_scanned > 0, "mem: maps parsed",
              std::format("{} region(s)", rep.regions_scanned));
        check(!rep.limit_note.empty() || rep.readable,
              "mem: readability reported or the reason stated");
        // /bin/sleep is a normal binary: no W^X expected. A FP here would be a
        // detector bug, not a property of sleep.
        check(rep.wx.empty(), "mem: no W^X reported for a clean binary",
              std::format("{} wx", rep.wx.size()));
        ::kill(kid.pid, SIGKILL);
        int st = 0;
        ::waitpid(kid.pid, &st, 0);
    }

    // Dump: opt-in path, bounded, 0600, refuses a second dump of the same
    // identity (evidence preservation), cleans up after itself.
    const auto kid2 = spawn_sleeper(8);
    if (!kid2.ok) {
        testing::skip("mem: bounded 0600 dump", "cannot spawn /bin/sleep here");
    } else {
        const auto d = mi.dump(kid2.pid, 1 << 20);
        if (d.ok) {
            struct stat st {};
            check(::stat(d.path.c_str(), &st) == 0 && (st.st_mode & 07777) == 0600,
                  "mem: dump written 0600");
            check(d.bytes > 0, "mem: dump contains data",
                  std::format("{} bytes", d.bytes));
            const auto again = mi.dump(kid2.pid, 1 << 20);
            check(!again.ok && again.error.find("already exists") != std::string::npos,
                  "mem: a second dump of the same identity is refused (evidence)");
        } else {
            // Unprivileged containers can deny /proc/pid/mem; the honest refusal
            // IS the correct behaviour.
            check(d.error.find("cannot") != std::string::npos ||
                      d.error.find("mem") != std::string::npos,
                  "mem: unreadable address space fails with the reason",
                  d.error);
        }
        ::kill(kid2.pid, SIGKILL);
        int st = 0;
        ::waitpid(kid2.pid, &st, 0);
        // Remove the evidence dir the test created.
        std::string cmd = std::format("rm -rf {}", cfg.state_dir);
        (void)::system(cmd.c_str());
    }

    // A dead pid reports honestly.
    {
        const auto rep = mi.inspect(4000000);
        check(!rep.findings.empty() && rep.findings.front().find("does not exist") !=
                                           std::string::npos,
              "mem: absent pid inspected without crashing, says so");
    }
}

// ---- REGRESSION: W^X perms off-by-one (F7, found live 2026-10-10) ----
// A real maps line "rw-p"/"rwxp" must classify correctly; perms[0] is r/-.
namespace {
struct WxClassifier {
    WxClassifier() {
        using hyprnova::core::proc::region_wx;
        using hyprnova::core::proc::region_exec;
        check(region_wx("rwxp") && !region_wx("rw-p") && !region_wx("r-xp"),
              "proc: W^X classifier (rwxp true, rw-p/r-xp false) [F7 regression]");
        check(region_exec("r-xp") && region_exec("rwxp") && !region_exec("rw-p"),
              "proc: exec classifier honours index 2");
        check(!region_wx("r") && !region_exec("r"), "proc: short perms string is safe");
    }
};
const WxClassifier wx_classifier_instance;
}  // namespace
