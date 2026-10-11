// SPDX-License-Identifier: Apache-2.0
// HyprNova :: GAP row 13 — the malware-analysis workflow.
//
// The Toolbox knows WHICH analysis tools exist on this host (Ghidra, capa,
// Cutter, CAPE, Firejail, Bubblewrap, QEMU...). What was missing is the
// workflow that TIES them together for one sample: what we can do here, what
// needs an online service, and how an operator sandboxes an untrusted binary.
// This module is deliberately pure: it builds plans, links and sandbox argv
// vectors from facts the Toolbox probed — it never executes anything and never
// touches the sample. Everything here is unit-tested on every host, installed
// tools or not; the honest absence ("Ghidra not installed") is part of the
// output, never an error.
//
// Policy baked in:
//   * HyprNova NEVER detonates a sample locally by itself. Local execution is
//     only ever an operator-initiated action inside a REAL sandbox backend,
//     and the plan says so explicitly when no backend exists.
//   * Only hashes ever appear in online links. There is no upload path here.
//   * Sandbox argv vectors use absolute paths for both backend and target,
//     matching the exec hardening used everywhere else in the agent.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <core/json.hpp>

namespace hyprnova::tools::analysis {

/// The online services worth linking for a sample hash. Keys match the
/// Toolbox's integration names so the console can grey out unconfigured ones.
struct OnlineLink {
    std::string service;  // "virustotal", "anyrun", "joesandbox", "hybrid"
    std::string url;
};

/// Browser deep link for a sample hash, or nullopt for a malformed hash or an
/// unknown service. Pure; the URL shapes live here so tests pin them.
[[nodiscard]] std::optional<std::string>
deep_link(std::string_view service, std::string_view sha256_hex) noexcept;

/// Which local capabilities an analysis could draw on. Populated from the
/// Toolbox probe (name -> installed); names are the Toolbox integration ids.
struct Probed {
    bool capa{false};        // MITRE-capability mapping for a PE/ELF
    bool ghidra{false};      // headless decompilation
    bool cutter{false};      // interactive RE (operator-driven)
    bool cape{false};        // local automated detonation (their sandbox, their risk)
    bool firejail{false};    // sandbox backend
    bool bubblewrap{false};  // sandbox backend
    bool qemu{false};        // full-system detonation backend
};

/// The operator-facing plan for one sample: what happens HERE (static only),
/// what COULD happen here with more tooling, and what the online services add.
/// No I/O, no clock — fully unit-testable.
struct AnalysisPlan {
    std::string sha256;
    bool in_tree_static{true};     // entropy/strings/header triage always exists
    std::vector<std::string> local_steps;    // actionable on THIS host now
    std::vector<std::string> missing_local;  // probed-but-absent tooling, named
    std::vector<OnlineLink> links;
    bool local_detonation_available{false};  // a real sandbox/detonation backend exists
    std::string detonation_note;             // policy text; never "go run it"

    [[nodiscard]] core::json::Value to_json() const noexcept;
};

/// Build the plan. `sha256_hex` must be 64 lowercase hex chars (it is what the
/// online links are built from; anything else returns a plan with no links and
/// the reason in `detonation_note`).
[[nodiscard]] AnalysisPlan plan_for(std::string_view sha256_hex, const Probed& probed) noexcept;

/// Options for the sandbox argv builders. All fields become literal flags.
struct SandboxOptions {
    bool no_network{true};     // detonation-grade default
    bool private_tmp{true};    // private /tmp, never the host's
    bool private_home{false};  // off: some operator workflows want -b ~/project
    bool new_pidns{true};
    /// Read-only bindings the operator explicitly asked for (already absolute).
    std::vector<std::string> ro_binds;
};

/// Build the argv vector to run `app` under Firejail. `app` must be an
/// absolute path (the same trusted-path rule core::exec enforces); returns
/// nullopt otherwise. Pure — the CALLER decides whether to run it.
[[nodiscard]] std::optional<std::vector<std::string>>
firejail_argv(std::string_view app, const std::vector<std::string>& app_args,
              const SandboxOptions& opts) noexcept;

/// Same for Bubblewrap. Needs a writable scratch dir for the private /tmp
/// (bubblewrap has no built-in tmpfs source); `opts.private_tmp` mounts a
/// tmpfs, so no host dir is shared.
[[nodiscard]] std::optional<std::vector<std::string>>
bubblewrap_argv(std::string_view app, const std::vector<std::string>& app_args,
                const SandboxOptions& opts) noexcept;

/// Convenience: the best installed backend's argv, or nullopt with `err`
/// explaining what is missing. Backend preference: bubblewrap (minimal,
/// unprivileged) then firejail.
[[nodiscard]] std::optional<std::vector<std::string>>
sandbox_argv(const Probed& probed, std::string_view app,
             const std::vector<std::string>& app_args, const SandboxOptions& opts,
             std::string& err) noexcept;

}  // namespace hyprnova::tools::analysis
