// SPDX-License-Identifier: Apache-2.0
// HyprNova :: GAP row 12 — per-executable network policy ("unknown exe phoning
// home"). The rule GENERATION and escalation bookkeeping are pure and tested
// everywhere; the kernel side (cgroup migration + nftables cgroupv2 match) is
// environment-gated and honestly reported as unavailable when it is.
#include "test_main.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <signal.h>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/fd.hpp"
#include "core/proc.hpp"
#include "remediation/remediation_engine.hpp"

namespace {



using namespace hyprnova;
using hyprnova::testing::check;
using hyprnova::testing::skip;
using remediation::ExeBlock;
using remediation::ExeEscalation;

void check_rules(const std::string& rules, const std::string& needle, bool expect,
                 std::string_view name) {
    const bool found = rules.find(needle) != std::string::npos;
    check(found == expect, name,
          found ? "found (expected absent)" : "not found; rules were:\n" + rules);
}

struct Child {
    pid_t pid{-1};
    bool ok{false};
};

// Same double-fork pattern as test_response_safety: the sleeper re-parents to
// init so the engine can treat it as an ordinary background process.
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
        _exit(kid > 0 ? 0 : 127);
    }
    if (mid > 0) {
        int st = 0;
        ::waitpid(mid, &st, 0);
        c.ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }
    if (c.ok) {
        for (int i = 0; i < 50 && c.pid <= 0; ++i) {
            if (DIR* d = ::opendir("/proc")) {
                while (const auto* e = ::readdir(d)) {
                    const pid_t p = ::atoi(e->d_name);
                    if (p <= 1) continue;
                    const auto pi = core::proc::read(p);
                    if (pi.exists && pi.comm == "sleep" && pi.ppid == 1) c.pid = p;
                }
                ::closedir(d);
            }
            if (c.pid <= 0) ::usleep(20'000);
        }
        c.ok = c.pid > 0;
    }
    return c;
}

struct NetPolicySuite {
    NetPolicySuite() {
        // ---- exe_slug: stable, filesystem-safe, distinct --------------------
        const std::string s1 = remediation::RemediationEngine::exe_slug("/usr/bin/curl");
        const std::string s2 = remediation::RemediationEngine::exe_slug("/usr/bin/curl");
        const std::string s3 = remediation::RemediationEngine::exe_slug("/tmp/evil.elf");
        check(s1 == s2 && s1.size() == 12, "netpolicy: slug is stable and 12 chars");
        bool hexish = !s1.empty();
        for (char c : s1)
            if (!std::isxdigit(static_cast<unsigned char>(c))) hexish = false;
        check(hexish, "netpolicy: slug is plain lowercase hex (filesystem-safe)");
        check(s1 != s3, "netpolicy: different exes hash to different slugs");

        // ---- build_exe_rules: level math + quoting ---------------------------
        std::vector<ExeBlock> blocks;
        ExeBlock b;
        b.id = 7;
        b.exe = "/usr/bin/curl";
        b.slug = s1;
        b.cgroup = "/sys/fs/cgroup/hyprnova_quarantine/exe-" + s1;
        b.active = true;
        blocks.push_back(b);
        std::string rules;
        check(remediation::RemediationEngine::build_exe_rules(
                  blocks, "/sys/fs/cgroup/hyprnova_quarantine", rules),
              "netpolicy: rules build for a v2-hierarchy cgroup root");
        check_rules(rules,
                    std::format("socket cgroupv2 2 \"hyprnova_quarantine/exe-{}\" counter drop\n", s1),
                    true,
                    "netpolicy: default-depth cgroup matches at level 2");

        // deeper root: /sys/fs/cgroup/a/b + <root>/exe-x => rel "a/b/exe-x" => level 3
        std::vector<ExeBlock> deep{b};
        deep[0].cgroup = "/sys/fs/cgroup/a/b/exe-" + s1;
        std::string deep_rules;
        check(remediation::RemediationEngine::build_exe_rules(deep, "/sys/fs/cgroup/a/b",
                                                              deep_rules),
              "netpolicy: rules build for a nested cgroup root");
        check_rules(deep_rules, std::format("socket cgroupv2 3 \"a/b/exe-{}\" counter drop\n", s1),
                    true, "netpolicy: level equals the relative path depth");

        // two active blocks => two rules; inactive blocks are skipped
        ExeBlock b2{b};
        b2.id = 8;
        b2.slug = s3;
        b2.cgroup = "/sys/fs/cgroup/hyprnova_quarantine/exe-" + s3;
        ExeBlock dead = b2;
        dead.active = false;
        std::vector<ExeBlock> multi{b, dead, b2};
        std::string multi_rules;
        check(remediation::RemediationEngine::build_exe_rules(
                  multi, "/sys/fs/cgroup/hyprnova_quarantine", multi_rules),
              "netpolicy: mixed active/inactive set still builds");
        check(multi_rules.find(s1) != std::string::npos &&
                  multi_rules.find(s3) != std::string::npos &&
                  std::count(multi_rules.begin(), multi_rules.end(), '\n') == 2,
              "netpolicy: exactly one rule per active block, none for inactive");

        std::string none;
        check(remediation::RemediationEngine::build_exe_rules({}, "/sys/fs/cgroup/x", none) &&
                  none.empty(),
              "netpolicy: an empty block set produces no rules");

        std::string bad;
        check(!remediation::RemediationEngine::build_exe_rules(blocks, "/not-a-cgroup", bad),
              "netpolicy: a cgroup root outside /sys/fs/cgroup is refused");
        std::vector<ExeBlock> stray{b};
        stray[0].cgroup = "/sys/fs/cgroup/elsewhere/exe-" + s1;
        std::string bad2;
        check(!remediation::RemediationEngine::build_exe_rules(
                  stray, "/sys/fs/cgroup/hyprnova_quarantine", bad2),
              "netpolicy: a block cgroup outside the configured root is refused");
        std::vector<ExeBlock> hostile{b};
        hostile[0].cgroup = "/sys/fs/cgroup/hyprnova_quarantine/exe-\"quote\nnewline";
        std::string bad3;
        check(!remediation::RemediationEngine::build_exe_rules(
                  hostile, "/sys/fs/cgroup/hyprnova_quarantine", bad3),
              "netpolicy: nft metacharacters in a cgroup path are refused");

        // ---- ExeEscalation: distinct-endpoint bookkeeping --------------------
        ExeEscalation esc{2};
        check(!esc.record("/usr/bin/curl", "1.2.3.4:443"),
              "netpolicy: first endpoint does not cross the threshold");
        check(esc.record("/usr/bin/curl", "5.6.7.8:443"),
              "netpolicy: the second DISTINCT endpoint crosses (block now)");
        check(esc.record("/usr/bin/curl", "9.9.9.9:443") == false,
              "netpolicy: an already-crossed exe does not re-fire");
        ExeEscalation esc2{2};
        (void)esc2.record("/usr/bin/curl", "1.2.3.4:443");
        check(!esc2.record("/usr/bin/curl", "1.2.3.4:443"),
              "netpolicy: a repeated endpoint is not double-counted");
        check(esc2.distinct_for("/usr/bin/curl") == 1,
              "netpolicy: distinct_for reflects the deduped count");
        esc2.forget("/usr/bin/curl");
        check(esc2.distinct_for("/usr/bin/curl") == 0 && esc2.tracked() == 0,
              "netpolicy: forget() clears the exe (e.g. after an operator release)");
        ExeEscalation esc3{0};
        check(esc3.threshold() == 1 && esc3.record("/x", "e"),
              "netpolicy: a zero threshold clamps to 1 (never auto-blocks silently)");
        check(!esc3.record("", "e") && !esc3.record("/x", ""),
              "netpolicy: empty exe or endpoint is ignored");

        // ---- engine honesty on a host without cgroup/nftables ----------------
        core::EventBus bus{1024};
        core::AgentConfig cfg;
        cfg.state_dir = std::format("/tmp/hyprnova-netpol-{}", ::getpid());
        cfg.remediation.quarantine_dir = cfg.state_dir + "/quarantine";
        cfg.dry_run = false;
        remediation::RemediationEngine engine{bus, cfg};
        engine.probe_capabilities();
        (void)core::fsx::mkdir_p(cfg.state_dir, 0700);

        const auto caps = engine.capabilities();
        const bool have_net = caps.can_nftables && caps.can_cgroup;
        if (!have_net) {
            const auto kid = spawn_sleeper(8);
            if (!kid.ok) {
                testing::skip("netpolicy: block_exe reports the missing subsystem",
                              "could not spawn a /bin/sleep child in this environment");
            } else {
                std::string resolved;
                check(engine.block_exe(kid.pid, "test: honesty", std::chrono::seconds{60},
                                       resolved) == false,
                      "netpolicy: block_exe FAILS (not skips) when containment is unavailable");
                bool named = false;
                for (const auto& a : engine.history(8))
                    if (a.detail.find("cgroup v2 and nftables") != std::string::npos)
                        named = true;
                check(named, "netpolicy: the failure names BOTH missing subsystems");
                check(engine.active_exe_blocks().empty(),
                      "netpolicy: a failed block leaves no phantom entry");
                check(!engine.unblock_exe(999999),
                      "netpolicy: unblock of an unknown id returns false");
                ::kill(kid.pid, SIGKILL);
            }
        } else {
            // Environment HAS both subsystems: verify the real containment
            // end-to-end on a disposable sleeper, then release it.
            const auto kid = spawn_sleeper(8);
            if (!kid.ok) {
                testing::skip("netpolicy: real exe containment round-trip",
                              "could not spawn a /bin/sleep child in this environment");
            } else {
                std::string resolved;
                // Protected-pid policy sits in front of the kernel work.
                check(engine.block_exe(1, "test: pid1", std::chrono::seconds{60}, resolved) ==
                          false,
                      "netpolicy: pid 1 is refused by the protected-pid policy");
                bool protected_note = false;
                for (const auto& a : engine.history(8))
                    if (a.detail.find("refused by policy") != std::string::npos)
                        protected_note = true;
                check(protected_note, "netpolicy: the refusal is audited as policy, not failure");
                check(engine.block_exe(kid.pid, "test: real containment",
                                       std::chrono::seconds{60}, resolved) &&
                          resolved.find("/sleep") != std::string::npos,
                      "netpolicy: real block_exe contains the exe and resolves its path");
                const auto live = engine.active_exe_blocks();
                check(live.size() == 1 && live[0].cgroup.find("exe-") != std::string::npos,
                      "netpolicy: the block is listed with its cgroup");
                check(engine.unblock_exe(live[0].id),
                      "netpolicy: release removes the rule and the cgroup");
                check(engine.active_exe_blocks().empty(),
                      "netpolicy: the released block is gone from the set");
                ::kill(kid.pid, SIGKILL);
            }
        }
    }
};
const NetPolicySuite netpolicy_suite_instance;

}  // namespace
