// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 8 -- the Toolbox.
//
// A Linux anti-malware product does not win by pretending it is the whole
// ecosystem; it wins by KNOWING the ecosystem. This module is the inventory of
// every security tool an operator is likely to have installed -- AVs, rootkit
// scanners, FIM, MAC frameworks, sandboxes, runtime sensors, sandboxes-as-a-
// service, RE tooling, firewalls, vulnerability scanners, disk/boot integrity,
// credential stores and log stacks -- and it does four things with that list:
//
//   1. PROBE   which of them exist on this host (binary, config, unit, device),
//              so the console can show a truthful coverage matrix instead of a
//              marketing checkbox. Absent tools are never an error: a missing
//              rkhunter degrades to "not installed", never to a crash.
//   2. RUN     the ones that are present, on demand, as allow-listed opt-in
//              runners through core::exec (absolute path, minimal environment,
//              hard timeout, kill-group, capped output). HyprNova never launches
//              a tool that was not registered here, and never with a relative
//              path -- a PATH-hijacked "rkhunter" would be the perfect rootkit
//              hiding place.
//   3. PARSE   the output of the classic scanners into structured findings
//              (rkhunter warnings, chkrootkit INFECTED lines, ClamAV FOUND
//              lines, the Lynis hardening index) so results land in the journal
//              and the console instead of scrolling past in a terminal.
//   4. ENRICH  verdicts with the online services that are worth having
//              (VirusTotal hash lookups; deep links for ANY.RUN / Joe Sandbox /
//              Hybrid Analysis / CAPE). Only hashes ever leave the host, only
//              when the operator configured an API key, and file *upload* is a
//              separate, default-off policy switch -- samples can contain
//              secrets; that decision belongs to the owner, not the AV.
//
// Always-on, no dependencies: proc_security() audits seccomp + capabilities of
// every running process straight from /proc, so even on a bare host the Toolbox
// reports something real.

#pragma once

#include "core/config.hpp"
#include "core/json.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Module 6 owns the scanner bridge type; the toolbox only holds a handle.
namespace hyprnova::remediation { class ScannerBridge; }

namespace hyprnova::tools {

/// How HyprNova uses a tool. Ordered by how much it is trusted to do.
enum class Integration {
    BuiltIn,   // functionality lives inside HyprNova (auditd, nftables, ...)
    Sensor,    // consumes its output as telemetry
    Runner,    // on-demand scan/audit the operator triggers
    Enforcer,  // we drive it to block/contain
    Exporter,  // we ship telemetry to it
    Analyzer,  // offline analysis / RE support
    Service,   // online API (key-gated)
    Detect,    // inventory only: presence is the value
};

[[nodiscard]] std::string_view to_string(Integration i) noexcept;

/// One registered ecosystem tool.
struct ToolSpec {
    std::string_view name;               // canonical id used by `tool-run`
    std::string_view label;              // human-readable
    std::string_view category;           // the 12 operator-facing categories
    std::string_view role;               // one line: what HyprNova does with it
    std::vector<std::string> binaries;   // resolved via the trusted system path
    std::vector<std::string> paths;      // config/db/device paths probed for existence
    std::vector<std::string> default_args; // used by tool-run when none are given
    Integration integration{Integration::Detect};
    bool root_to_run{false};             // runner is only useful as root
};

/// What the probe learned about one spec.
struct ToolState {
    bool installed{false};
    std::string binary_path;             // first executable binary, absolute
    std::vector<std::string> paths_found;
    std::string note;                    // why it is not runnable, what it gives us
};

/// Live seccomp/capabilities posture of the whole process table.
struct ProcSecurity {
    std::size_t processes{0};
    std::size_t seccomp_none{0};
    std::size_t seccomp_classic{0};
    std::size_t seccomp_filter{0};
    /// Up to 8 (pid, comm) of root-owned processes with NO seccomp filtering --
    /// the softest targets for a kernel exploit.
    std::vector<std::pair<std::string, std::string>> unfiltered_samples;
};

class Toolbox {
public:
    explicit Toolbox(const core::IntegrationsConfig& cfg) noexcept : cfg_(cfg) {}
    ~Toolbox();   // out-of-line: holds a forward-declared scanner bridge

    /// Re-stat every registered tool. Cheap (stat + trusted PATH lookup), safe
    /// to call from the pool on startup and on every `toolbox` request.
    void probe() noexcept;

    /// The coverage matrix for the CLI and the console's Tools page.
    [[nodiscard]] core::json::Value snapshot_json() const noexcept;

    struct RunOutcome {
        bool ok{false};
        bool timed_out{false};
        int exit_code{-1};
        std::string tool;
        std::string binary;                 // what we actually executed
        std::vector<std::string> args;
        std::string output;                 // capped by integrations.max_output_bytes
        std::vector<std::string> findings;  // parser output, when a parser exists
        std::string summary;                // one human line
        std::string error;
    };

    /// Run a REGISTERED tool by name. Refuses anything unknown, uninstalled,
    /// without arguments when the spec demands them, or when runners are
    /// disabled by policy. Blocking; dispatch on the pool.
    [[nodiscard]] RunOutcome run_tool(std::string_view name,
                                      const std::vector<std::string>& args) noexcept;

    /// VirusTotal v3 hash lookup (GET /files/<sha256>) via the system curl.
    /// Hash-only, key-gated, never uploads content.
    [[nodiscard]] RunOutcome vt_lookup(std::string_view sha256_hex) noexcept;

    [[nodiscard]] static std::optional<RunOutcome> parse_vt_json(std::string_view body) noexcept;

    [[nodiscard]] const core::IntegrationsConfig& config() const noexcept { return cfg_; }

    // ---- combined scanning (Module 8b) ------------------------------------
    // One operator command, many engines. The profiles always include the
    // in-tree YaraLite engine, so a scan is REAL even on a host with none of
    // the external tools installed; every external tool found on the host is
    // added on top, and tools that are missing are reported as skipped rather
    // than silently omitted.

    /// Wire the agent's signature engine so profiles can scan with it.
    void set_internal_scanner(std::shared_ptr<remediation::ScannerBridge> s) noexcept;

    struct CombinedSection {
        std::string tool;               // "engine", "clamav", "rkhunter", "systemd"
        std::string label;              // human one-liner
        bool ran{false};
        bool ok{false};
        int exit_code{-1};
        std::vector<std::string> findings;
        std::string note;               // why skipped / extra context
    };

    struct CombinedReport {
        std::string profile;            // quick | deep | kernel | audit
        std::string target;
        std::size_t total_findings{0};
        std::size_t malicious{0};
        std::string verdict;            // clean | suspicious | INFECTED
        std::vector<CombinedSection> sections;
        std::chrono::milliseconds elapsed{};
        std::string summary;            // one human line
        bool ok{false};
        std::string error;

        [[nodiscard]] core::json::Value to_json() const noexcept;
    };

    /// Run a combined scan profile. Blocking (minutes for `deep`); the bridge
    /// dispatches it on the pool, exactly like `investigate`.
    [[nodiscard]] CombinedReport combined_scan(
        std::string_view profile, const std::vector<std::string>& paths) noexcept;

    [[nodiscard]] static bool valid_profile(std::string_view p) noexcept {
        return p == "quick" || p == "deep" || p == "kernel" || p == "audit";
    }

    // ---- systemd unit exposure (Module 8c) ---------------------------------
    struct SystemdUnit {
        std::string unit;
        double exposure{0.0};
        std::string grade;              // OK | MEDIUM | EXPOSED | UNSAFE (verbatim)
        std::vector<std::string> suggestions;   // per-unit detail, worst units only
    };

    /// `systemd-analyze security` across every unit + per-unit suggestions for
    /// the worst offenders. Degrades to a finding when systemd is absent.
    [[nodiscard]] std::vector<SystemdUnit> systemd_security(
        int detail_units = 3) noexcept;

    [[nodiscard]] static std::vector<SystemdUnit> parse_systemd_table(
        std::string_view output) noexcept;

    /// Kernel taint: 0 when clean, else the raw value (meanings in Module 1).
    [[nodiscard]] static long kernel_taint() noexcept;

    /// Parse a rescue-environment report (written by the rescue image's clean
    /// script into the real root). Returns nullopt when absent/malformed.
    [[nodiscard]] static std::optional<core::json::Value> parse_rescue_report(
        std::string_view path) noexcept;

    /// ---- pure parsers (fixture-tested by the startup self-test) ----
    [[nodiscard]] static std::vector<std::string> parse_rkhunter(std::string_view output) noexcept;
    [[nodiscard]] static std::vector<std::string> parse_chkrootkit(std::string_view output) noexcept;
    [[nodiscard]] static std::vector<std::string> parse_clamav(std::string_view output) noexcept;
    /// KVRT stdout/report parsing (Module 8d: KVRT is the DEFAULT second-opinion
    /// engine for quick/deep/full scans).
    [[nodiscard]] static std::vector<std::string> parse_kvrt(std::string_view output) noexcept;
    /// Package-manager integrity: classifies each verify hit as [MISSING],
    /// [UNEXPLAINED] (package-owned binary/lib changed) or [ADMIN] (/etc).
    [[nodiscard]] static std::vector<std::string> parse_pkg_verify(
        std::string_view backend, std::string_view output) noexcept;
    /// CrowdSec LAPI/cscli decisions JSON: one finding per active ban.
    /// Built-in SSH weak-settings audit: config text -> one finding per weak
    /// knob ("key=value — why [fix] ..."). Pure; drives audit_sshd_config.
    [[nodiscard]] static std::vector<std::string> parse_sshd_audit(
        std::string_view config_text) noexcept;

    [[nodiscard]] static std::vector<std::string> parse_crowdsec_decisions(
        std::string_view json_body) noexcept;
    /// Lynis "Hardening index : NN" -> NN.
    [[nodiscard]] static std::optional<long> parse_lynis_index(std::string_view output) noexcept;

    [[nodiscard]] static ProcSecurity proc_security() noexcept;

    [[nodiscard]] static const std::vector<ToolSpec>& registry() noexcept;

private:
    core::IntegrationsConfig cfg_;   // copy: the toolbox outlives config reloads
    std::vector<ToolState> states_;  // parallel to registry()
    std::shared_ptr<remediation::ScannerBridge> engine_;  // the in-tree scanner
};

}  // namespace hyprnova::tools
