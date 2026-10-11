// SPDX-License-Identifier: Apache-2.0
// HyprNova :: GAP row 13 — analysis workflow tests. Everything here is PURE:
// link/plan/sandbox-argv generation pinned against exact expected shapes.
// (The sandbox argv is what an operator would run; HyprNova executing it is a
// separate, operator-initiated action this suite deliberately does not do.)
#include "test_main.hpp"

#include <algorithm>
#include <format>
#include <string>

#include "tools/analysis.hpp"

namespace {

using namespace hyprnova;
using hyprnova::testing::check;
namespace an = hyprnova::tools::analysis;

const std::string kSha(64, 'a');  // 64 hex chars: valid shape for the parsers

struct AnalysisSuite {
    AnalysisSuite() {
        // ---- deep links: exact URL shapes per service ------------------------
        auto vt = an::deep_link("virustotal", kSha);
        check(vt && *vt == std::format("https://www.virustotal.com/gui/file/{}/", kSha),
              "analysis: VirusTotal link shape");
        auto ar = an::deep_link("anyrun", kSha);
        check(ar && ar->starts_with("https://app.any.run/") &&
                  ar->find(kSha) != std::string::npos,
              "analysis: ANY.RUN link carries the hash");
        auto joe = an::deep_link("joesandbox", kSha);
        check(joe && joe->starts_with("https://www.joesandbox.com/search?q="),
              "analysis: Joe Sandbox search link shape");
        auto hy = an::deep_link("hybrid", kSha);
        check(hy && hy->starts_with("https://www.hybrid-analysis.com/search?query="),
              "analysis: Hybrid Analysis search link shape");
        check(!an::deep_link("unknown-service", kSha),
              "analysis: an unknown service yields no link");
        check(!an::deep_link("virustotal", "ABCD"),   // wrong length
              "analysis: a short hash is refused");
        check(!an::deep_link("virustotal", std::string(64, 'A')),  // uppercase
              "analysis: an uppercase hash is refused (lowercase canonical form)");
        check(!an::deep_link("virustotal", std::string(64, 'g')),  // non-hex
              "analysis: a non-hex hash is refused");
        check(!an::deep_link("virustotal", ""),
              "analysis: an empty hash is refused");

        // ---- plan_for: honest local/online split -----------------------------
        an::Probed none;  // nothing installed
        auto bare = an::plan_for(kSha, none);
        check(bare.in_tree_static && bare.local_steps.size() >= 3,
              "analysis: the in-tree static steps exist with NO tools installed");
        check(!bare.local_detonation_available &&
                  bare.detonation_note.find("will not execute") != std::string::npos,
              "analysis: no backend -> policy note refuses local detonation");
        bool named_all_missing = true;
        for (const char* t : {"capa", "ghidra", "cutter"})
            if (std::find(bare.missing_local.begin(), bare.missing_local.end(), t) ==
                bare.missing_local.end())
                named_all_missing = false;
        check(named_all_missing, "analysis: absent tools are NAMED, not hidden");
        check(bare.links.size() == 4, "analysis: all four online links are offered");

        an::Probed full;
        full.capa = full.ghidra = full.cutter = true;
        full.bubblewrap = true;
        auto rich = an::plan_for(kSha, full);
        check(rich.missing_local.empty(),
              "analysis: a fully-tooled host has no missing_local entries");
        bool capa_step = false;
        for (const auto& s : rich.local_steps)
            if (s.find("capa") != std::string::npos) capa_step = true;
        check(capa_step, "analysis: an installed tool becomes an actionable step");
        check(rich.local_detonation_available &&
                  rich.detonation_note.find("operator-initiated") != std::string::npos,
              "analysis: a backend exists -> detonation stays operator-initiated");
        check(rich.sha256 == kSha, "analysis: the plan carries the hash");

        // ---- sandbox argv: firejail ------------------------------------------
        an::SandboxOptions opts;  // detonation-grade defaults
        auto fj = an::firejail_argv("/opt/samples/sample.elf", {}, opts);
        check(fj && (*fj)[0] == "/usr/bin/firejail",
              "analysis: firejail argv starts with the absolute backend path");
        bool has_net_none = false, has_private_tmp = false;
        for (const auto& a : *fj) {
            if (a == "--net=none") has_net_none = true;
            if (a == "--private-tmp") has_private_tmp = true;
        }
        check(has_net_none && has_private_tmp,
              "analysis: firejail defaults cut the network and privatize /tmp");
        check(fj && fj->back() == "/opt/samples/sample.elf",
              "analysis: the target is the last firejail argv element");

        an::SandboxOptions bind_opts;
        bind_opts.ro_binds = {"/opt/samples"};
        auto fj_bind = an::firejail_argv("/bin/true", {"--flag"}, bind_opts);
        bool ro_ok = false;
        for (std::size_t i = 0; fj_bind && i + 1 < fj_bind->size(); ++i)
            if ((*fj_bind)[i] == "--read-only=/opt/samples") ro_ok = true;
        check(ro_ok, "analysis: explicit ro-binds become --read-only flags");
        check(fj_bind && fj_bind->back() == "--flag",
              "analysis: target arguments are passed through");

        check(!an::firejail_argv("sample.elf", {}, opts),
              "analysis: a RELATIVE target path is refused (trusted-path policy)");
        an::SandboxOptions bad_bind;
        bad_bind.ro_binds = {"relative/dir"};
        check(!an::firejail_argv("/bin/true", {}, bad_bind),
              "analysis: a relative ro-bind is refused");

        // ---- sandbox argv: bubblewrap ----------------------------------------
        auto bw = an::bubblewrap_argv("/opt/samples/sample.elf", {"run"}, opts);
        check(bw && (*bw)[0] == "/usr/bin/bwrap", "analysis: bwrap argv starts correctly");
        bool net = false, tmpfs = false, sep = false;
        for (std::size_t i = 0; bw && i < bw->size(); ++i) {
            if ((*bw)[i] == "--unshare-net") net = true;
            if ((*bw)[i] == "--tmpfs" && i + 1 < bw->size() && (*bw)[i + 1] == "/tmp")
                tmpfs = true;
            if ((*bw)[i] == "--") sep = true;
        }
        check(net && tmpfs && sep, "analysis: bwrap unshares net, tmpfs-mounts /tmp");
        check(bw && bw->size() >= 3 && (*bw)[bw->size() - 2] == "/opt/samples/sample.elf" &&
                  bw->back() == "run",
              "analysis: bwrap keeps the target after the -- separator");
        check(!an::bubblewrap_argv("evil", {}, opts),
              "analysis: bwrap refuses a relative target");

        // ---- backend preference + honest absence ------------------------------
        std::string err;
        auto best = an::sandbox_argv(full, "/bin/true", {}, opts, err);
        check(best && (*best)[0] == "/usr/bin/bwrap",
              "analysis: bubblewrap is preferred over firejail when both exist");
        an::Probed only_fj;
        only_fj.firejail = true;
        auto fj_only = an::sandbox_argv(only_fj, "/bin/true", {}, opts, err);
        check(fj_only && (*fj_only)[0] == "/usr/bin/firejail",
              "analysis: firejail is used when bwrap is absent");
        an::Probed no_backend;
        check(!an::sandbox_argv(no_backend, "/bin/true", {}, opts, err) &&
                  err.find("no sandbox backend installed") != std::string::npos,
              "analysis: no backend -> honest refusal naming the gap");
        check(!an::sandbox_argv(full, "relative", {}, opts, err) &&
                  err.find("absolute path") != std::string::npos,
              "analysis: relative target refused even with a backend present");
    }
};
const AnalysisSuite analysis_suite_instance;

}  // namespace
