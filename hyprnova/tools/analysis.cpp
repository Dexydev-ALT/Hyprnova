// SPDX-License-Identifier: Apache-2.0
#include "analysis.hpp"

#include <algorithm>
#include <format>
#include <iterator>

namespace hyprnova::tools::analysis {

namespace {

[[nodiscard]] bool is_sha256_hex(std::string_view s) noexcept {
    if (s.size() != 64) return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

}  // namespace

std::optional<std::string> deep_link(std::string_view service,
                                     std::string_view sha256_hex) noexcept {
    if (!is_sha256_hex(sha256_hex)) return std::nullopt;
    // Hash-only URLs: nothing about the sample beyond its fingerprint leaves
    // the host by building these strings.
    if (service == "virustotal")
        return std::format("https://www.virustotal.com/gui/file/{}/", sha256_hex);
    if (service == "anyrun")
        // ANY.RUN indexes submissions by hash search.
        return std::format("https://app.any.run/submissions/#{}", sha256_hex);
    if (service == "joesandbox")
        return std::format("https://www.joesandbox.com/search?q={}", sha256_hex);
    if (service == "hybrid")
        return std::format("https://www.hybrid-analysis.com/search?query={}", sha256_hex);
    return std::nullopt;
}

core::json::Value AnalysisPlan::to_json() const noexcept {
    using namespace core::json;
    Object o;
    o["sha256"] = sha256;
    o["in_tree_static"] = in_tree_static;
    Array local;
    for (const auto& s : local_steps) local.emplace_back(Value{s});
    o["local_steps"] = Value{std::move(local)};
    Array missing;
    for (const auto& s : missing_local) missing.emplace_back(Value{s});
    o["missing_local"] = Value{std::move(missing)};
    Array ls;
    for (const auto& l : links) {
        Object lo;
        lo["service"] = l.service;
        lo["url"] = l.url;
        ls.emplace_back(Value{std::move(lo)});
    }
    o["links"] = Value{std::move(ls)};
    o["local_detonation_available"] = local_detonation_available;
    o["detonation_note"] = detonation_note;
    return Value{std::move(o)};
}

AnalysisPlan plan_for(std::string_view sha256_hex, const Probed& probed) noexcept {
    AnalysisPlan p;
    p.sha256 = std::string(sha256_hex);
    p.in_tree_static = true;  // entropy + strings + header triage: always available

    // Local, actionable NOW (in-tree, no external tools): the row-10 static
    // triage chain over the sample on disk.
    p.local_steps.emplace_back(
        "static triage: entropy map, embedded strings, header/section inventory "
        "(in-tree; hyprnova-cli investigate <path>)");
    p.local_steps.emplace_back(
        "file carving of embedded artifacts (opt-in; hyprnova-cli carve <path>)");
    p.local_steps.emplace_back("signature scan with the in-tree YaraLite engine");
    if (probed.capa)
        p.local_steps.emplace_back("capability mapping with capa (installed)");
    else
        p.missing_local.emplace_back("capa");
    if (probed.ghidra)
        p.local_steps.emplace_back("headless decompilation with Ghidra (installed)");
    else
        p.missing_local.emplace_back("ghidra");
    if (probed.cutter)
        p.local_steps.emplace_back("interactive RE with Cutter (installed)");
    else
        p.missing_local.emplace_back("cutter");

    p.links.reserve(4);
    for (const char* svc : {"virustotal", "anyrun", "joesandbox", "hybrid"})
        if (auto url = deep_link(svc, sha256_hex))
            p.links.push_back({svc, std::move(*url)});

    p.local_detonation_available = probed.cape || probed.firejail || probed.bubblewrap ||
                                   probed.qemu;
    if (p.local_detonation_available) {
        p.detonation_note =
            "a sandbox/detonation backend is installed; local execution remains an "
            "explicit, operator-initiated action inside that backend — HyprNova never "
            "detonates a sample on its own";
    } else {
        p.detonation_note =
            "no local sandbox or detonation backend is installed; use the online links "
            "for dynamic analysis, or install firejail/bubblewrap/CAPE and re-probe. "
            "HyprNova will not execute the sample on this host";
    }
    return p;
}

std::optional<std::vector<std::string>> firejail_argv(std::string_view app,
                                                      const std::vector<std::string>& app_args,
                                                      const SandboxOptions& opts) noexcept {
    if (app.empty() || app.front() != '/') return std::nullopt;
    std::vector<std::string> argv{"/usr/bin/firejail"};
    auto& a = argv;
    if (opts.no_network) a.emplace_back("--net=none");
    if (opts.private_tmp) a.emplace_back("--private-tmp");
    if (opts.private_home) a.emplace_back("--private");
    if (opts.new_pidns) a.emplace_back("--caps.drop=all");  // firejail uses pid+net ns by default
    for (const auto& ro : opts.ro_binds) {
        if (ro.empty() || ro.front() != '/') return std::nullopt;  // absolute paths only
        a.emplace_back(std::format("--read-only={}", ro));
    }
    a.emplace_back(std::string(app));
    a.insert(a.end(), app_args.begin(), app_args.end());
    return argv;
}

std::optional<std::vector<std::string>>
bubblewrap_argv(std::string_view app, const std::vector<std::string>& app_args,
                const SandboxOptions& opts) noexcept {
    if (app.empty() || app.front() != '/') return std::nullopt;
    std::vector<std::string> argv{"/usr/bin/bwrap"};
    auto& a = argv;
    // Minimal dev/proc shape: enough for a static binary to run and log.
    a.emplace_back("--dev");
    a.emplace_back("/dev");
    a.emplace_back("--proc");
    a.emplace_back("/proc");
    if (opts.no_network) a.emplace_back("--unshare-net");
    if (opts.private_tmp) {
        a.emplace_back("--tmpfs");
        a.emplace_back("/tmp");
    }
    if (opts.new_pidns) a.emplace_back("--unshare-pid");
    for (const auto& ro : opts.ro_binds) {
        if (ro.empty() || ro.front() != '/') return std::nullopt;
        a.emplace_back("--ro-bind");
        a.emplace_back(ro);
        a.emplace_back(ro);
    }
    a.emplace_back("--");
    a.emplace_back(std::string(app));
    a.insert(a.end(), app_args.begin(), app_args.end());
    return argv;
}

std::optional<std::vector<std::string>> sandbox_argv(const Probed& probed,
                                                     std::string_view app,
                                                     const std::vector<std::string>& app_args,
                                                     const SandboxOptions& opts,
                                                     std::string& err) noexcept {
    if (probed.bubblewrap) {
        auto argv = bubblewrap_argv(app, app_args, opts);
        if (!argv && (app.empty() || app.front() != '/'))
            err = "the target must be an absolute path (trusted-path policy)";
        return argv;
    }
    if (probed.firejail) {
        auto argv = firejail_argv(app, app_args, opts);
        if (!argv && (app.empty() || app.front() != '/'))
            err = "the target must be an absolute path (trusted-path policy)";
        return argv;
    }
    err = "no sandbox backend installed (probed: bubblewrap=no, firejail=no); "
          "HyprNova will not run an untrusted binary unsandboxed";
    if (app.empty() || app.front() != '/')
        err = "the target must be an absolute path (trusted-path policy)";
    return std::nullopt;
}

}  // namespace hyprnova::tools::analysis
