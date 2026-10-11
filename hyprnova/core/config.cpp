// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/config.cpp

#include "core/config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <format>
#include <mutex>
#include <unistd.h>

#include "core/fd.hpp"

namespace hyprnova::core {

namespace {

// Tiny tolerant readers: a missing key keeps the compiled-in default, a wrong
// type is recorded as a ConfigError rather than silently coercing.
struct Reader {
    const json::Value& root;
    std::vector<ConfigError>& errors;

    const json::Value* find(std::string_view path) const noexcept { return root.at(path); }

    void err(std::string_view path, std::string_view msg) const {
        errors.push_back({std::string(path), std::string(msg)});
    }

    bool get_bool(std::string_view path, bool& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        if (!v->is_bool()) { err(path, "expected boolean"); return false; }
        out = v->as_bool();
        return true;
    }

    bool get_u64(std::string_view path, std::uint64_t& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        if (!v->is_number()) { err(path, "expected number"); return false; }
        const auto i = v->as_int();
        if (i < 0) { err(path, "must be >= 0"); return false; }
        out = static_cast<std::uint64_t>(i);
        return true;
    }

    bool get_size(std::string_view path, std::size_t& out) const {
        std::uint64_t tmp = 0;
        if (!get_u64(path, tmp)) return false;
        out = static_cast<std::size_t>(tmp);
        return true;
    }

    bool get_i64(std::string_view path, std::int64_t& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        if (!v->is_number()) { err(path, "expected number"); return false; }
        out = v->as_int();
        return true;
    }

    bool get_double(std::string_view path, double& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        if (!v->is_number()) { err(path, "expected number"); return false; }
        out = v->as_double();
        return true;
    }

    bool get_string(std::string_view path, std::string& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        if (!v->is_string()) { err(path, "expected string"); return false; }
        out = std::string(v->as_string());
        return true;
    }

    bool get_strings(std::string_view path, std::vector<std::string>& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        const json::Array* arr = v->as_array();
        if (!arr) { err(path, "expected array of strings"); return false; }
        out.clear();
        for (const auto& e : *arr) {
            if (e.is_string()) out.emplace_back(e.as_string());
            else err(path, "array element is not a string");
        }
        return true;
    }

    /// Duration expressed as a bare number of milliseconds, or a string with a
    /// unit suffix ("500ms", "15s", "6h"). Strings are far more readable in an
    /// ops-managed config file.
    template <typename D>
    bool get_duration(std::string_view path, D& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        if (v->is_number()) {
            out = D{static_cast<typename D::rep>(v->as_int())};
            return true;
        }
        if (!v->is_string()) { err(path, "expected number or duration string"); return false; }

        const std::string s{v->as_string()};
        std::size_t i = 0;
        while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])) || s[i] == '.')) ++i;
        if (i == 0) { err(path, "duration must start with a number"); return false; }
        double num = 0;
        if (std::sscanf(s.substr(0, i).c_str(), "%lf", &num) != 1) {
            err(path, "unparsable duration");
            return false;
        }
        std::string unit = s.substr(i);
        std::transform(unit.begin(), unit.end(), unit.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        double mult = 1.0;  // default: milliseconds
        if (unit == "ms") mult = 1.0;
        else if (unit == "s" || unit == "sec" || unit.empty()) mult = 1000.0;
        else if (unit == "m" || unit == "min") mult = 60'000.0;
        else if (unit == "h" || unit == "hr") mult = 3'600'000.0;
        else if (unit == "d") mult = 86'400'000.0;
        else { err(path, "unknown duration unit '" + unit + "'"); return false; }

        out = std::chrono::duration_cast<D>(std::chrono::duration<double, std::milli>(num * mult));
        return true;
    }

    bool get_pairs(std::string_view path, std::vector<std::pair<std::string, std::string>>& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        const json::Array* arr = v->as_array();
        if (!arr) { err(path, "expected array of [key, value] pairs"); return false; }
        out.clear();
        for (const auto& e : *arr) {
            const json::Array* pair = e.as_array();
            if (!pair || pair->size() != 2 || !(*pair)[0].is_string()) {
                err(path, "pair must be [string, string]");
                continue;
            }
            out.emplace_back(std::string((*pair)[0].as_string()), (*pair)[1].as_string_copy());
        }
        return true;
    }

    bool get_pair_list(std::string_view path,
                       std::vector<std::pair<std::string, std::vector<std::string>>>& out) const {
        const json::Value* v = find(path);
        if (!v) return false;
        const json::Array* arr = v->as_array();
        if (!arr) { err(path, "expected array of [key, [values...]]"); return false; }
        out.clear();
        for (const auto& e : *arr) {
            const json::Array* pair = e.as_array();
            if (!pair || pair->size() != 2 || !(*pair)[0].is_string()) {
                err(path, "entry must be [string, [strings]]");
                continue;
            }
            std::vector<std::string> vals;
            if (const json::Array* va = (*pair)[1].as_array()) {
                for (const auto& x : *va) {
                    if (x.is_string()) vals.emplace_back(x.as_string());
                }
            }
            out.emplace_back(std::string((*pair)[0].as_string()), std::move(vals));
        }
        return true;
    }
};

/// Reverse of kind_name(); keeps the config file in terms humans can read and
/// guarantees the two can never drift apart.
std::optional<EventKind> kind_from_name(std::string_view name) noexcept {
    static constexpr EventKind kAll[] = {
        EventKind::ProcExec,      EventKind::ProcExit,      EventKind::ProcFork,
        EventKind::ProcAnomaly,   EventKind::FileCreate,    EventKind::FileOpen,
        EventKind::FileWrite,     EventKind::FileDelete,    EventKind::FileRename,
        EventKind::FileChmod,     EventKind::FileChown,     EventKind::FileCanaryHit,
        EventKind::PrivEscalation, EventKind::SudoAbuse,    EventKind::ShadowAccess,
        EventKind::SudoersChange, EventKind::SshSpawn,      EventKind::TtyFromDaemon,
        EventKind::NetConnect,    EventKind::NetListen,     EventKind::NetC2Suspect,
        EventKind::KernelModuleLoad, EventKind::BootIntegrity, EventKind::HardeningDrift,
        EventKind::MacEnforcement, EventKind::ScanVerdict,  EventKind::YaraVerdict,
        EventKind::EntropyVerdict, EventKind::SensorUp,     EventKind::SensorDown,
        EventKind::ConfigReload,  EventKind::Heartbeat,     EventKind::RemediationApplied,
        EventKind::UserAction,
    };
    for (const EventKind k : kAll) {
        if (kind_name(k) == name) return k;
    }
    return std::nullopt;
}

std::string backend_name(ScanBackend b) noexcept {
    switch (b) {
        case ScanBackend::YaraLite: return "yara-lite (built-in)";
        case ScanBackend::LibYara: return "libyara";
        case ScanBackend::ClamAv: return "clamdscan";
        case ScanBackend::Kvrt: return "kvrt";
    }
    return "unknown";
}

}  // namespace
// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------
// Declared in config.hpp and therefore defined at namespace scope: a definition
// inside the anonymous namespace would have internal linkage and silently not be
// the function the header promises.

void validate(AgentConfig& c, std::vector<ConfigError>& errors) {
    auto range = [&](double v, double lo, double hi, std::string_view path) {
        if (!(v >= lo && v <= hi))
            errors.push_back({std::string(path), std::format("{} out of range [{}, {}]", v, lo, hi)});
    };

    range(c.ransomware.entropy_threshold, 0.0, 8.0, "ransomware.entropy_threshold");
    range(c.heuristic.risk_decay_per_second, 0.0, 100.0, "heuristic.risk_decay_per_second");

    if (c.ransomware.mass_modify_file_threshold == 0)
        errors.push_back({"ransomware.mass_modify_file_threshold", "must be > 0"});
    if (c.ransomware.mass_modify_window.count() == 0)
        errors.push_back({"ransomware.mass_modify_window", "must be > 0ms"});

    if (c.heuristic.critical_threshold <= c.heuristic.alert_threshold)
        errors.push_back({"heuristic.critical_threshold",
                          "must exceed alert_threshold, otherwise every alert is critical"});
    if (c.heuristic.auto_respond_threshold < c.heuristic.critical_threshold)
        errors.push_back({"heuristic.auto_respond_threshold",
                          "must be >= critical_threshold: auto-response needs the highest bar"});

    if (c.gui.telemetry_hz < 1) c.gui.telemetry_hz = 1;
    if (c.gui.telemetry_hz > 10) {
        errors.push_back({"gui.telemetry_hz", "capped at 10 Hz: higher rates starve the QML render loop"});
        c.gui.telemetry_hz = 10;
    }

    if (c.scan.batch_flush_interval.count() < 1)
        errors.push_back({"scan.batch_flush_interval", "must be >= 1s"});
    if (c.scan.batch_max_paths == 0) c.scan.batch_max_paths = 1;

    if (c.bus_ring_depth < 1024) {
        errors.push_back({"agent.bus_ring_depth", "raised to 1024: a smaller ring drops kernel events"});
        c.bus_ring_depth = 1024;
    }

    if (c.canary.canaries_per_root == 0)
        errors.push_back({"canary.canaries_per_root", "must be > 0 or disable the canary module"});

    if (c.remediation.allow_kill && c.dry_run)
        errors.push_back({"agent.dry_run", "dry_run is set: all kill/block/quarantine actions are suppressed"});

    // A remediation engine with an empty protected list is a self-inflicted outage.
    if (c.shadow.enabled && c.shadow.keep == 0)
        errors.push_back({"shadow.keep",
                          "must exceed 0 when shadow copies are enabled: keeping nothing makes the "
                          "feature a no-op and an operator will only discover that during an incident"});
    if (c.integrations.virustotal_enabled && c.integrations.virustotal_api_key.empty())
        errors.push_back({"integrations.virustotal_api_key",
                          "must be set when virustotal_enabled is true: lookups without a key fail "
                          "at run time, so refuse the config now rather than mid-incident"});
    if (c.proc_poll.enabled &&
        (c.proc_poll.interval < std::chrono::milliseconds{50} ||
         c.proc_poll.interval > std::chrono::milliseconds{5000}))
        errors.push_back({"proc_poll.interval_ms", "must be 50..5000 ms: faster burns CPU on every "
                                                     "pid, slower misses short-lived processes"});
    if (c.integrations.tool_timeout <= std::chrono::seconds{0})
        errors.push_back({"integrations.tool_timeout_seconds", "must be positive"});
    if (c.ai.enabled && c.ai.api_key.empty())
        errors.push_back({"ai.api_key",
                          "must be set when ai.enabled is true: enabling the analyst without a "
                          "key would leave every consult failing at run time"});
    if (c.rescue.enabled && c.rescue.iso_path.empty())
        errors.push_back({"rescue.iso_path",
                          "must point at a readable rescue ISO when rescue.enabled is true: "
                          "the GRUB entry would reference an image that was never staged"});

    if (c.remediation.allow_kill && c.remediation.protected_processes.empty())
        errors.push_back({"remediation.protected_processes",
                          "empty protection list with allow_kill=true is unsafe; refusing"});

    for (const auto& r : c.scan.roots) {
        if (r.path.empty() || r.path == "/")
            errors.push_back({"scan.roots", "refusing to watch '/' recursively: use explicit subtrees"});
    }

    if (c.instance_id.empty()) {
        // Derive a stable instance id from machine-id so a fleet console can
        // identify this host without extra configuration.
        const std::string mid = fsx::read_trimmed("/etc/machine-id");
        if (!mid.empty()) {
            c.instance_id = "hyprnova-" + mid.substr(0, 12);
        } else {
            char host[256] = {};
            if (::gethostname(host, sizeof(host) - 1) == 0) c.instance_id = std::string("hyprnova-") + host;
            else c.instance_id = "hyprnova-unknown";
        }
    }
}

AgentConfig default_config() noexcept { return AgentConfig{}; }

std::optional<AgentConfig> load_config(const std::string& path, std::vector<ConfigError>* errors) noexcept {
    std::vector<ConfigError> local_errors;
    std::vector<ConfigError>& errs = errors ? *errors : local_errors;
    errs.clear();

    AgentConfig cfg = default_config();

    std::string text;
    if (fsx::read_file(path, text, 8 << 20) < 0) {
        // A missing config file is NOT fatal: run on built-in defaults. A
        // malformed one IS fatal -- a silently wrong policy is worse than a
        // stopped agent.
        errs.push_back({path, "not readable; using built-in defaults"});
        validate(cfg, errs);
        return cfg;
    }

    json::ParseError perr{};
    auto doc = json::parse(text, {}, &perr);
    if (!doc) {
        errs.push_back({path, std::format("JSON parse error at offset {}: {}", perr.offset, perr.message)});
        return std::nullopt;
    }

    const Reader r{*doc, errs};

    // ---- agent ----
    r.get_string("agent.instance_id", cfg.instance_id);
    r.get_string("agent.version", cfg.version);
    r.get_string("agent.state_dir", cfg.state_dir);
    r.get_string("agent.run_dir", cfg.run_dir);
    r.get_string("agent.forensic_journal", cfg.forensic_journal);
    r.get_bool("agent.forensic_journal_enabled", cfg.forensic_journal_enabled);
    r.get_bool("agent.dry_run", cfg.dry_run);
    r.get_bool("agent.self_test_on_start", cfg.self_test_on_start);
    r.get_string("agent.log_path", cfg.log_path);
    r.get_bool("agent.log_to_stderr", cfg.log_to_stderr);
    r.get_size("agent.log_max_bytes", cfg.log_max_bytes);
    r.get_duration("agent.heartbeat_interval", cfg.heartbeat_interval);
    r.get_size("agent.bus_ring_depth", cfg.bus_ring_depth);
    if (std::string lvl; r.get_string("agent.log_level", lvl)) {
        std::transform(lvl.begin(), lvl.end(), lvl.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lvl == "trace") cfg.log_level = LogLevel::Trace;
        else if (lvl == "debug") cfg.log_level = LogLevel::Debug;
        else if (lvl == "info") cfg.log_level = LogLevel::Info;
        else if (lvl == "warn") cfg.log_level = LogLevel::Warn;
        else if (lvl == "error") cfg.log_level = LogLevel::Error;
        else errs.push_back({"agent.log_level", "must be trace|debug|info|warn|error"});
    }

    // ---- boot integrity ----
    r.get_bool("boot.enabled", cfg.boot.enabled);
    r.get_bool("boot.require_secure_boot", cfg.boot.require_secure_boot);
    r.get_strings("boot.efi_var_paths", cfg.boot.efi_var_paths);
    r.get_strings("boot.sbctl_paths", cfg.boot.sbctl_paths);
    r.get_string("boot.baseline_path", cfg.boot.baseline_path);
    r.get_bool("boot.verify_initramfs", cfg.boot.verify_initramfs);
    r.get_strings("boot.initramfs_paths", cfg.boot.initramfs_paths);
    r.get_bool("boot.audit_kernel_cmdline", cfg.boot.audit_kernel_cmdline);
    r.get_strings("boot.forbidden_cmdline", cfg.boot.forbidden_cmdline);
    r.get_strings("boot.expected_cmdline", cfg.boot.expected_cmdline);

    // ---- kernel hardening ----
    r.get_bool("hardening.enabled", cfg.hardening.enabled);
    r.get_pairs("hardening.sysctls", cfg.hardening.sysctls);
    r.get_pair_list("hardening.sysctl_alternatives", cfg.hardening.sysctl_alternatives);
    r.get_string("hardening.lockdown_path", cfg.hardening.lockdown_path);
    r.get_strings("hardening.acceptable_lockdown", cfg.hardening.acceptable_lockdown);
    r.get_bool("hardening.require_lockdown", cfg.hardening.require_lockdown);
    r.get_string("hardening.ksplice_marker", cfg.hardening.ksplice_marker);
    r.get_bool("hardening.flag_ksplice", cfg.hardening.flag_ksplice);
    r.get_duration("hardening.rescan_interval", cfg.hardening.rescan_interval);

    // ---- MAC ----
    r.get_bool("mac.enabled", cfg.mac.enabled);
    r.get_string("mac.apparmor_root", cfg.mac.apparmor_root);
    r.get_bool("mac.require_apparmor_enforce", cfg.mac.require_apparmor_enforce);
    r.get_string("mac.selinux_path", cfg.mac.selinux_path);
    r.get_strings("mac.profile_dirs", cfg.mac.profile_dirs);
    r.get_strings("mac.critical_daemons", cfg.mac.critical_daemons);
    r.get_bool("mac.audit_unconfined_daemons", cfg.mac.audit_unconfined_daemons);

    // ---- canaries ----
    r.get_bool("canary.enabled", cfg.canary.enabled);
    r.get_string("canary.key_path", cfg.canary.key_path);
    r.get_strings("canary.home_roots", cfg.canary.home_roots);
    r.get_strings("canary.extra_roots", cfg.canary.extra_roots);
    r.get_string("canary.subdir", cfg.canary.subdir);
    r.get_size("canary.canaries_per_root", cfg.canary.canaries_per_root);
    r.get_string("canary.prefix", cfg.canary.prefix);
    r.get_strings("canary.extensions", cfg.canary.extensions);
    r.get_bool("canary.hidden_files", cfg.canary.hidden_files);
    r.get_duration("canary.resign_interval", cfg.canary.resign_interval);
    r.get_duration("canary.integrity_check_interval", cfg.canary.integrity_check_interval);
    r.get_bool("canary.monitor_access", cfg.canary.monitor_access);
    r.get_bool("canary.honeypots_enabled", cfg.canary.honeypots_enabled);
    r.get_bool("canary.monitor_modify", cfg.canary.monitor_modify);
    r.get_bool("canary.monitor_delete", cfg.canary.monitor_delete);
    r.get_bool("canary.monitor_move", cfg.canary.monitor_move);
    r.get_strings("canary.reader_allowlist", cfg.canary.reader_allowlist);

    // ---- ransomware ----
    r.get_bool("ransomware.enabled", cfg.ransomware.enabled);
    r.get_double("ransomware.entropy_threshold", cfg.ransomware.entropy_threshold);
    r.get_size("ransomware.min_entropy_bytes", cfg.ransomware.min_entropy_bytes);
    r.get_size("ransomware.mass_modify_file_threshold", cfg.ransomware.mass_modify_file_threshold);
    r.get_duration("ransomware.mass_modify_window", cfg.ransomware.mass_modify_window);
    r.get_bool("ransomware.auto_suspend", cfg.ransomware.auto_suspend);
    r.get_bool("ransomware.auto_suspend_unprivileged_only", cfg.ransomware.auto_suspend_unprivileged_only);
    r.get_size("ransomware.entropy_burst_files", cfg.ransomware.entropy_burst_files);
    r.get_duration("ransomware.entropy_burst_window", cfg.ransomware.entropy_burst_window);
    r.get_strings("ransomware.suspicious_extensions", cfg.ransomware.suspicious_extensions);
    r.get_strings("ransomware.ransom_note_names", cfg.ransomware.ransom_note_names);
    r.get_bool("ransomware.detect_ransom_notes", cfg.ransomware.detect_ransom_notes);
    r.get_bool("ransomware.detect_vss_deletion", cfg.ransomware.detect_vss_deletion);
    r.get_strings("ransomware.backup_destroy_cmds", cfg.ransomware.backup_destroy_cmds);

    // ---- scan ----
    r.get_bool("scan.enabled", cfg.scan.enabled);
    if (const json::Value* roots = r.find("scan.roots")) {
        if (const json::Array* arr = roots->as_array()) {
            cfg.scan.roots.clear();
            for (const auto& e : *arr) {
                if (e.is_string()) {
                    cfg.scan.roots.push_back({e.as_string_copy(), true, true, "configured"});
                    continue;
                }
                ScanRoot sr;
                sr.path = e.str("path");
                sr.recursive = e.at("recursive") ? e.at("recursive")->as_bool(true) : true;
                sr.on_write_only = e.at("on_write_only") ? e.at("on_write_only")->as_bool(true) : true;
                sr.label = e.str("label", "configured");
                if (!sr.path.empty()) cfg.scan.roots.push_back(std::move(sr));
                else errs.push_back({"scan.roots", "entry missing 'path'"});
            }
        } else {
            errs.push_back({"scan.roots", "expected array"});
        }
    }
    r.get_strings("scan.download_suffixes", cfg.scan.download_suffixes);
    r.get_size("scan.max_file_bytes", cfg.scan.max_file_bytes);
    r.get_size("scan.min_file_bytes", cfg.scan.min_file_bytes);
    r.get_strings("scan.skip_extensions", cfg.scan.skip_extensions);
    r.get_strings("scan.skip_dirs", cfg.scan.skip_dirs);
    r.get_strings("scan.rule_files", cfg.scan.rule_files);
    if (std::string b; r.get_string("scan.backend", b)) {
        std::transform(b.begin(), b.end(), b.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (b == "yara-lite" || b == "lite") cfg.scan.backend = ScanBackend::YaraLite;
        else if (b == "libyara" || b == "yara") cfg.scan.backend = ScanBackend::LibYara;
        else if (b == "clamav" || b == "clamdscan") cfg.scan.backend = ScanBackend::ClamAv;
        else if (b == "kvrt") cfg.scan.backend = ScanBackend::Kvrt;
        else errs.push_back({"scan.backend", "must be yara-lite|libyara|clamav|kvrt"});
    }
    r.get_string("scan.libyara_rules_dir", cfg.scan.libyara_rules_dir);
    r.get_size("scan.yara_timeout_ms", cfg.scan.yara_timeout_ms);
    r.get_duration("scan.batch_flush_interval", cfg.scan.batch_flush_interval);
    r.get_size("scan.batch_max_paths", cfg.scan.batch_max_paths);
    r.get_string("scan.kvrt_path", cfg.scan.kvrt_path);
    r.get_strings("scan.kvrt_args", cfg.scan.kvrt_args);
    r.get_string("scan.clamdscan_path", cfg.scan.clamdscan_path);
    r.get_strings("scan.clamdscan_args", cfg.scan.clamdscan_args);
    r.get_bool("scan.prefer_clamd", cfg.scan.prefer_clamd);
    r.get_duration("scan.clamd_timeout", cfg.scan.clamd_timeout);
    r.get_duration("scan.kvrt_timeout", cfg.scan.kvrt_timeout);
    r.get_bool("scan.use_list_file", cfg.scan.use_list_file);
    r.get_bool("scan.carving_enabled", cfg.scan.carve.enabled);
    r.get_size("scan.carve_max_artifact_bytes", cfg.scan.carve.max_artifact_bytes);
    r.get_size("scan.carve_max_artifacts", cfg.scan.carve.max_artifacts);
    r.get_string("scan.carve_out_dir", cfg.scan.carve.out_dir);
    r.get_size("scan.scan_workers", cfg.scan.scan_workers);
    r.get_size("scan.scan_queue_depth", cfg.scan.scan_queue_depth);
    r.get_bool("scan.hash_cache", cfg.scan.hash_cache);
    r.get_size("scan.hash_cache_entries", cfg.scan.hash_cache_entries);

    // ---- falco ----
    r.get_bool("falco.enabled", cfg.falco.enabled);
    r.get_string("falco.socket_path", cfg.falco.socket_path);
    r.get_string("falco.grpc_socket", cfg.falco.grpc_socket);
    r.get_duration("falco.reconnect_backoff_max", cfg.falco.reconnect_backoff_max);
    r.get_duration("falco.poll_timeout", cfg.falco.poll_timeout);
    r.get_size("falco.max_line_bytes", cfg.falco.max_line_bytes);
    r.get_strings("falco.interesting_priorities", cfg.falco.interesting_priorities);
    if (std::vector<std::pair<std::string, std::string>> raw; r.get_pairs("falco.rule_map", raw)) {
        cfg.falco.rule_map.clear();
        for (auto& [rule, kind_str] : raw) {
            std::optional<EventKind> k = kind_from_name(kind_str);
            if (!k) {
                errs.push_back({"falco.rule_map",
                                std::format("unknown event kind '{}' for rule '{}'", kind_str, rule)});
                continue;
            }
            cfg.falco.rule_map.emplace_back(std::move(rule), *k);
        }
    }

    // ---- proc poll (Module 4b) ----
    r.get_bool("proc_poll.enabled", cfg.proc_poll.enabled);
    r.get_duration("proc_poll.interval_ms", cfg.proc_poll.interval);
    r.get_duration("proc_poll.rescan_cooldown_ms", cfg.proc_poll.rescan_cooldown);

    // ---- auditd ----
    r.get_bool("auditd.enabled", cfg.auditd.enabled);
    r.get_bool("auditd.use_netlink", cfg.auditd.use_netlink);
    r.get_string("auditd.fallback_log", cfg.auditd.fallback_log);
    r.get_strings("auditd.watch_paths", cfg.auditd.watch_paths);
    r.get_strings("auditd.privileged_cmds", cfg.auditd.privileged_cmds);
    r.get_bool("auditd.detect_sudo_abuse", cfg.auditd.detect_sudo_abuse);
    r.get_strings("auditd.sudo_red_flags", cfg.auditd.sudo_red_flags);
    r.get_size("auditd.netlink_buf_bytes", cfg.auditd.netlink_buf_bytes);

    // ---- osquery ----
    r.get_bool("osquery.enabled", cfg.osquery.enabled);
    r.get_string("osquery.osqueryi_path", cfg.osquery.osqueryi_path);
    r.get_duration("osquery.query_interval", cfg.osquery.query_interval);
    r.get_duration("osquery.query_timeout", cfg.osquery.query_timeout);
    r.get_pairs("osquery.queries", cfg.osquery.queries);

    // ---- suricata ----
    r.get_bool("suricata.enabled", cfg.suricata.enabled);
    r.get_string("suricata.eve_path", cfg.suricata.eve_path);
    r.get_string("suricata.eve_socket", cfg.suricata.eve_socket);
    r.get_duration("suricata.poll_interval", cfg.suricata.poll_interval);
    r.get_double("suricata.c2_beacon_score_threshold", cfg.suricata.c2_beacon_score_threshold);
    r.get_duration("suricata.beacon_window", cfg.suricata.beacon_window);
    r.get_size("suricata.beacon_min_hits", cfg.suricata.beacon_min_hits);
    r.get_double("suricata.beacon_interval_jitter_max", cfg.suricata.beacon_interval_jitter_max);

    // ---- heuristics ----
    r.get_bool("heuristic.enabled", cfg.heuristic.enabled);
    r.get_duration("heuristic.decay_window", cfg.heuristic.decay_window);
    r.get_double("heuristic.risk_decay_per_second", cfg.heuristic.risk_decay_per_second);
    if (std::int64_t v = 0; r.get_i64("heuristic.alert_threshold", v))
        cfg.heuristic.alert_threshold = static_cast<std::uint16_t>(v);
    if (std::int64_t v = 0; r.get_i64("heuristic.critical_threshold", v))
        cfg.heuristic.critical_threshold = static_cast<std::uint16_t>(v);
    if (std::int64_t v = 0; r.get_i64("heuristic.auto_respond_threshold", v))
        cfg.heuristic.auto_respond_threshold = static_cast<std::uint16_t>(v);
    r.get_bool("heuristic.auto_respond", cfg.heuristic.auto_respond);
    r.get_bool("heuristic.detect_ssh_anomaly", cfg.heuristic.detect_ssh_anomaly);
    r.get_size("heuristic.ssh_spawn_burst", cfg.heuristic.ssh_spawn_burst);
    r.get_duration("heuristic.ssh_spawn_window", cfg.heuristic.ssh_spawn_window);
    r.get_strings("heuristic.web_daemons", cfg.heuristic.web_daemons);
    r.get_strings("heuristic.shells", cfg.heuristic.shells);
    r.get_bool("heuristic.detect_tty_from_daemon", cfg.heuristic.detect_tty_from_daemon);
    r.get_pair_list("heuristic.forbidden_children", cfg.heuristic.forbidden_children);
    r.get_bool("heuristic.learn_baseline", cfg.heuristic.learn_baseline);
    r.get_string("heuristic.baseline_path", cfg.heuristic.baseline_path);
    r.get_duration("heuristic.baseline_learning_period", cfg.heuristic.baseline_learning_period);
    r.get_bool("heuristic.suppress_actions_during_learning", cfg.heuristic.suppress_actions_during_learning);
    r.get_string("heuristic.profiles_dir", cfg.heuristic.profiles_dir);

    // ---- remediation ----
    r.get_bool("remediation.enabled", cfg.remediation.enabled);
    r.get_bool("remediation.allow_kill", cfg.remediation.allow_kill);
    r.get_bool("remediation.allow_suspend", cfg.remediation.allow_suspend);
    r.get_bool("remediation.allow_network_block", cfg.remediation.allow_network_block);
    r.get_bool("remediation.allow_exe_block", cfg.remediation.allow_exe_block);
    r.get_bool("remediation.auto_block_by_exe", cfg.remediation.auto_block_by_exe);
    {
        std::int64_t v = cfg.remediation.exe_block_after_endpoints;
        if (r.get_i64("remediation.exe_block_after_endpoints", v))
            cfg.remediation.exe_block_after_endpoints = static_cast<int>(std::clamp(v, std::int64_t{1}, std::int64_t{64}));
    }
    r.get_bool("remediation.allow_quarantine", cfg.remediation.allow_quarantine);
    r.get_string("remediation.quarantine_dir", cfg.remediation.quarantine_dir);
    r.get_strings("remediation.protected_processes", cfg.remediation.protected_processes);
    r.get_strings("remediation.protected_paths", cfg.remediation.protected_paths);
    r.get_bool("remediation.protect_pid1_descendants", cfg.remediation.protect_pid1_descendants);
    r.get_duration("remediation.block_duration", cfg.remediation.block_duration);
    r.get_string("remediation.nftables_table", cfg.remediation.nftables_table);
    r.get_string("remediation.nft_cli", cfg.remediation.nft_cli);
    r.get_bool("remediation.use_libnftables", cfg.remediation.use_libnftables);
    r.get_string("remediation.iptables_fallback", cfg.remediation.iptables_fallback);
    r.get_bool("remediation.use_cgroup_containment", cfg.remediation.use_cgroup_containment);
    r.get_string("remediation.cgroup_root", cfg.remediation.cgroup_root);
    r.get_bool("remediation.freeze_cgroup", cfg.remediation.freeze_cgroup);
    r.get_string("remediation.notify_summary", cfg.remediation.notify_summary);
    r.get_bool("remediation.desktop_notifications", cfg.remediation.desktop_notifications);
    r.get_string("remediation.notify_send", cfg.remediation.notify_send);

    // ---- shadow copies ----
    r.get_bool("shadow.enabled", cfg.shadow.enabled);
    r.get_strings("shadow.roots", cfg.shadow.roots);
    r.get_size("shadow.keep", cfg.shadow.keep);
    r.get_size("shadow.max_snapshot_bytes", cfg.shadow.max_snapshot_bytes);
    r.get_size("shadow.max_files", cfg.shadow.max_files);

    // ---- ecosystem integrations (Toolbox) ----
    r.get_bool("integrations.enabled", cfg.integrations.enabled);
    r.get_bool("integrations.runner_enabled", cfg.integrations.runner_enabled);
    if (std::int64_t v = 0; r.get_i64("integrations.tool_timeout_seconds", v) && v > 0)
        cfg.integrations.tool_timeout = std::chrono::seconds{v};
    r.get_size("integrations.max_output_bytes", cfg.integrations.max_output_bytes);
    r.get_bool("integrations.virustotal_enabled", cfg.integrations.virustotal_enabled);
    r.get_bool("integrations.crowdsec_enabled", cfg.integrations.crowdsec_enabled);
    r.get_string("integrations.virustotal_api_key", cfg.integrations.virustotal_api_key);
    r.get_bool("integrations.online_submission", cfg.integrations.online_submission);

    // ---- rescue environment ----
    r.get_bool("rescue.enabled", cfg.rescue.enabled);
    r.get_string("rescue.iso_path", cfg.rescue.iso_path);
    r.get_string("rescue.boot_dir", cfg.rescue.boot_dir);
    r.get_string("rescue.grub_entry_file", cfg.rescue.grub_entry_file);
    r.get_string("rescue.entry_title", cfg.rescue.entry_title);
    r.get_bool("rescue.auto_reboot", cfg.rescue.auto_reboot);

    // ---- AI analyst ----
    r.get_bool("ai.enabled", cfg.ai.enabled);
    r.get_string("ai.provider", cfg.ai.provider);
    r.get_string("ai.api_key", cfg.ai.api_key);
    r.get_string("ai.model", cfg.ai.model);
    if (std::int64_t v = 0; r.get_i64("ai.timeout_seconds", v) && v > 0)
        cfg.ai.timeout = std::chrono::seconds{v};
    if (std::int64_t v = 0; r.get_i64("ai.max_answer_tokens", v) && v > 0)
        cfg.ai.max_answer_tokens = static_cast<std::size_t>(v);

    // ---- gui ----
    r.get_bool("gui.enabled", cfg.gui.enabled);
    r.get_string("gui.ipc_socket", cfg.gui.ipc_socket);
    r.get_string("gui.ipc_group", cfg.gui.ipc_group);
    r.get_bool("gui.start_with_agent", cfg.gui.start_with_agent);
    r.get_string("gui.theme", cfg.gui.theme);
    if (std::int64_t v = 0; r.get_i64("gui.telemetry_hz", v)) cfg.gui.telemetry_hz = static_cast<int>(v);
    r.get_size("gui.event_feed_max", cfg.gui.event_feed_max);
    r.get_bool("gui.show_kernel_events", cfg.gui.show_kernel_events);
    r.get_bool("gui.vibrancy", cfg.gui.vibrancy);

    validate(cfg, errs);

    const bool fatal = std::any_of(errs.begin(), errs.end(), [](const ConfigError& e) {
        // Only structural/parse problems and the unsafe-policy checks are fatal.
        return e.message.find("refusing") != std::string::npos ||
               e.message.find("must exceed") != std::string::npos ||
               e.message.find("unsafe") != std::string::npos ||
               e.message.find("JSON parse error") != std::string::npos ||
               e.message.find("expected") != std::string::npos;
    });

    if (fatal) return std::nullopt;
    return cfg;
}

/// Lowercase spelling the reader accepts for agent.log_level.
std::string config_level_name(LogLevel l) noexcept {
    switch (l) {
        case LogLevel::Trace: return "trace";
        case LogLevel::Debug: return "debug";
        case LogLevel::Info: return "info";
        case LogLevel::Warn: return "warn";
        case LogLevel::Error: [[fallthrough]];
        case LogLevel::Fatal: return "error";  // fatal is not a configurable level
    }
    return "info";
}

// GCC 14 -Wmaybe-uninitialized fires inside std::variant<Rb_tree>/vector inlining
// of these emplace_back chains (stl_tree.h:193) although every Value is
// constructed before use. Verified as an inliner false positive (the same
// pattern warns on -O2 in unrelated TUs); scoped suppression with the reason,
// not a global kill of the warning.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

json::Value to_json(const AgentConfig& cfg) noexcept {
    // Round-trip fidelity is the contract: every key the reader looks up must be
    // present here, with the default value, so that `--dump-config` output is a
    // complete, loadable config. A section that is missing from this function is
    // a section the operator cannot see or tune from the documented authoring path.
    //
    // Durations are written as "<count>s" / "<count>ms"; the reader accepts those
    // units (and bare numbers, interpreted in the target duration's own rep).
    // Pair-shaped settings (sysctls, osquery queries, the Falco rule map) are
    // written as [[key, value], ...] because that is the shape get_pairs() and
    // get_pair_list() parse.

    auto secs = [](auto d) {
        return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(d).count()) + "s";
    };
    auto millis = [](auto d) {
        return std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(d).count()) + "ms";
    };
    auto strs = [](const std::vector<std::string>& v) {
        json::Array a;
        a.reserve(v.size());
        for (const auto& x : v) a.emplace_back(x);
        return json::Value{std::move(a)};
    };
    auto pairs = [](const auto& v) {
        json::Array a;
        a.reserve(v.size());
        for (const auto& [k, val] : v) {
            json::Array p;
            p.emplace_back(k);
            p.emplace_back(val);
            a.emplace_back(json::Value{std::move(p)});
        }
        return json::Value{std::move(a)};
    };
    auto pair_lists = [](const auto& v) {
        json::Array a;
        a.reserve(v.size());
        for (const auto& [k, vals] : v) {
            json::Array p;
            p.emplace_back(k);
            json::Array inner;
            inner.reserve(vals.size());
            for (const auto& x : vals) inner.emplace_back(x);
            p.emplace_back(json::Value{std::move(inner)});
            a.emplace_back(json::Value{std::move(p)});
        }
        return json::Value{std::move(a)};
    };

    json::Object root;

    // ---- agent ----
    {
        json::Object o;
        o["instance_id"] = cfg.instance_id;
        o["version"] = cfg.version;
        o["state_dir"] = cfg.state_dir;
        o["run_dir"] = cfg.run_dir;
        o["forensic_journal"] = cfg.forensic_journal;
        o["forensic_journal_enabled"] = cfg.forensic_journal_enabled;
        o["journal_max_bytes"] = static_cast<std::int64_t>(cfg.journal_max_bytes);
        o["dry_run"] = cfg.dry_run;
        o["self_test_on_start"] = cfg.self_test_on_start;
        o["heartbeat_interval"] = secs(cfg.heartbeat_interval);
        o["bus_ring_depth"] = static_cast<std::int64_t>(cfg.bus_ring_depth);
        // The reader's vocabulary is lowercase; level_tag() is the padded
        // LOG-LINE tag ("INFO ") and must never appear in a config file.
        // (Regression: this used to write level_tag(), so every config saved
        // by the agent failed to reload its log level.)
        o["log_level"] = config_level_name(cfg.log_level);
        o["log_path"] = cfg.log_path;
        o["log_max_bytes"] = static_cast<std::int64_t>(cfg.log_max_bytes);
        o["log_to_stderr"] = cfg.log_to_stderr;
        root["agent"] = json::Value{std::move(o)};
    }

    // ---- boot ----
    {
        json::Object o;
        o["enabled"] = cfg.boot.enabled;
        o["require_secure_boot"] = cfg.boot.require_secure_boot;
        o["efi_var_paths"] = strs(cfg.boot.efi_var_paths);
        o["sbctl_paths"] = strs(cfg.boot.sbctl_paths);
        o["baseline_path"] = cfg.boot.baseline_path;
        o["verify_initramfs"] = cfg.boot.verify_initramfs;
        o["initramfs_paths"] = strs(cfg.boot.initramfs_paths);
        o["audit_kernel_cmdline"] = cfg.boot.audit_kernel_cmdline;
        o["forbidden_cmdline"] = strs(cfg.boot.forbidden_cmdline);
        o["expected_cmdline"] = strs(cfg.boot.expected_cmdline);
        root["boot"] = json::Value{std::move(o)};
    }

    // ---- hardening ----
    {
        json::Object o;
        o["enabled"] = cfg.hardening.enabled;
        o["sysctls"] = pairs(cfg.hardening.sysctls);
        o["sysctl_alternatives"] = pair_lists(cfg.hardening.sysctl_alternatives);
        o["lockdown_path"] = cfg.hardening.lockdown_path;
        o["acceptable_lockdown"] = strs(cfg.hardening.acceptable_lockdown);
        o["require_lockdown"] = cfg.hardening.require_lockdown;
        o["ksplice_marker"] = cfg.hardening.ksplice_marker;
        o["flag_ksplice"] = cfg.hardening.flag_ksplice;
        o["rescan_interval"] = secs(cfg.hardening.rescan_interval);
        root["hardening"] = json::Value{std::move(o)};
    }

    // ---- mac ----
    {
        json::Object o;
        o["enabled"] = cfg.mac.enabled;
        o["apparmor_root"] = cfg.mac.apparmor_root;
        o["require_apparmor_enforce"] = cfg.mac.require_apparmor_enforce;
        o["selinux_path"] = cfg.mac.selinux_path;
        o["critical_daemons"] = strs(cfg.mac.critical_daemons);
        o["audit_unconfined_daemons"] = cfg.mac.audit_unconfined_daemons;
        o["profile_dirs"] = strs(cfg.mac.profile_dirs);
        root["mac"] = json::Value{std::move(o)};
    }

    // ---- canary ----
    {
        json::Object o;
        o["enabled"] = cfg.canary.enabled;
        o["key_path"] = cfg.canary.key_path;
        o["home_roots"] = strs(cfg.canary.home_roots);
        o["extra_roots"] = strs(cfg.canary.extra_roots);
        o["subdir"] = cfg.canary.subdir;
        o["canaries_per_root"] = static_cast<std::int64_t>(cfg.canary.canaries_per_root);
        o["prefix"] = cfg.canary.prefix;
        o["extensions"] = strs(cfg.canary.extensions);
        o["hidden_files"] = cfg.canary.hidden_files;
        o["resign_interval"] = secs(cfg.canary.resign_interval);
        o["integrity_check_interval"] = secs(cfg.canary.integrity_check_interval);
        o["honeypots_enabled"] = cfg.canary.honeypots_enabled;
        o["monitor_access"] = cfg.canary.monitor_access;
        o["monitor_modify"] = cfg.canary.monitor_modify;
        o["monitor_delete"] = cfg.canary.monitor_delete;
        o["monitor_move"] = cfg.canary.monitor_move;
        o["reader_allowlist"] = strs(cfg.canary.reader_allowlist);
        root["canary"] = json::Value{std::move(o)};
    }

    // ---- ransomware ----
    {
        json::Object o;
        o["enabled"] = cfg.ransomware.enabled;
        o["entropy_threshold"] = cfg.ransomware.entropy_threshold;
        o["min_entropy_bytes"] = static_cast<std::int64_t>(cfg.ransomware.min_entropy_bytes);
        o["mass_modify_file_threshold"] = static_cast<std::int64_t>(cfg.ransomware.mass_modify_file_threshold);
        o["mass_modify_window"] = millis(cfg.ransomware.mass_modify_window);
        o["auto_suspend"] = cfg.ransomware.auto_suspend;
        o["auto_suspend_unprivileged_only"] = cfg.ransomware.auto_suspend_unprivileged_only;
        o["entropy_burst_files"] = static_cast<std::int64_t>(cfg.ransomware.entropy_burst_files);
        o["entropy_burst_window"] = secs(cfg.ransomware.entropy_burst_window);
        o["suspicious_extensions"] = strs(cfg.ransomware.suspicious_extensions);
        o["ransom_note_names"] = strs(cfg.ransomware.ransom_note_names);
        o["detect_ransom_notes"] = cfg.ransomware.detect_ransom_notes;
        o["detect_vss_deletion"] = cfg.ransomware.detect_vss_deletion;
        o["backup_destroy_cmds"] = strs(cfg.ransomware.backup_destroy_cmds);
        root["ransomware"] = json::Value{std::move(o)};
    }

    // ---- scan ----
    {
        json::Object o;
        o["enabled"] = cfg.scan.enabled;
        json::Array roots;
        roots.reserve(cfg.scan.roots.size());
        for (const auto& sr : cfg.scan.roots) {
            json::Object ro;
            ro["path"] = sr.path;
            ro["recursive"] = sr.recursive;
            ro["on_write_only"] = sr.on_write_only;
            ro["label"] = sr.label;
            roots.emplace_back(json::Value{std::move(ro)});
        }
        o["roots"] = json::Value{std::move(roots)};
        o["download_suffixes"] = strs(cfg.scan.download_suffixes);
        o["max_file_bytes"] = static_cast<std::int64_t>(cfg.scan.max_file_bytes);
        o["min_file_bytes"] = static_cast<std::int64_t>(cfg.scan.min_file_bytes);
        o["skip_extensions"] = strs(cfg.scan.skip_extensions);
        o["skip_dirs"] = strs(cfg.scan.skip_dirs);
        o["rule_files"] = strs(cfg.scan.rule_files);
        // Canonical reader vocabulary, NOT the display name: backend_name()
        // returns "yara-lite (built-in)" for humans, which the reader rejects.
        // (Regression: same class as the log_level serializer bug.)
        switch (cfg.scan.backend) {
            case ScanBackend::YaraLite: o["backend"] = "yara-lite"; break;
            case ScanBackend::LibYara: o["backend"] = "libyara"; break;
            case ScanBackend::ClamAv: o["backend"] = "clamav"; break;
            case ScanBackend::Kvrt: o["backend"] = "kvrt"; break;
        }
        o["libyara_rules_dir"] = cfg.scan.libyara_rules_dir;
        o["yara_timeout_ms"] = static_cast<std::int64_t>(cfg.scan.yara_timeout_ms);
        o["batch_flush_interval"] = secs(cfg.scan.batch_flush_interval);
        o["batch_max_paths"] = static_cast<std::int64_t>(cfg.scan.batch_max_paths);
        o["kvrt_path"] = cfg.scan.kvrt_path;
        o["kvrt_args"] = strs(cfg.scan.kvrt_args);
        o["clamdscan_path"] = cfg.scan.clamdscan_path;
        o["clamdscan_args"] = strs(cfg.scan.clamdscan_args);
        o["prefer_clamd"] = cfg.scan.prefer_clamd;
        o["clamd_timeout"] = secs(cfg.scan.clamd_timeout);
        o["kvrt_timeout"] = secs(cfg.scan.kvrt_timeout);
        o["use_list_file"] = cfg.scan.use_list_file;
        o["carving_enabled"] = cfg.scan.carve.enabled;
        o["carve_max_artifact_bytes"] = static_cast<std::int64_t>(cfg.scan.carve.max_artifact_bytes);
        o["carve_max_artifacts"] = static_cast<std::int64_t>(cfg.scan.carve.max_artifacts);
        o["carve_out_dir"] = cfg.scan.carve.out_dir;
        o["scan_workers"] = static_cast<std::int64_t>(cfg.scan.scan_workers);
        o["scan_queue_depth"] = static_cast<std::int64_t>(cfg.scan.scan_queue_depth);
        o["hash_cache"] = cfg.scan.hash_cache;
        o["hash_cache_entries"] = static_cast<std::int64_t>(cfg.scan.hash_cache_entries);
        root["scan"] = json::Value{std::move(o)};
    }

    // ---- falco ----
    {
        json::Object o;
        o["enabled"] = cfg.falco.enabled;
        o["socket_path"] = cfg.falco.socket_path;
        o["grpc_socket"] = cfg.falco.grpc_socket;
        o["reconnect_backoff_max"] = secs(cfg.falco.reconnect_backoff_max);
        o["poll_timeout"] = millis(cfg.falco.poll_timeout);
        o["max_line_bytes"] = static_cast<std::int64_t>(cfg.falco.max_line_bytes);
        o["interesting_priorities"] = strs(cfg.falco.interesting_priorities);
        // rule_map values are EventKind; serialise with kind_name() so the file
        // stays human-readable and kind_from_name() can parse it back.
        json::Array rm;
        rm.reserve(cfg.falco.rule_map.size());
        for (const auto& [rule, kind] : cfg.falco.rule_map) {
            json::Array p;
            p.emplace_back(rule);
            p.emplace_back(std::string(core::kind_name(kind)));
            rm.emplace_back(json::Value{std::move(p)});
        }
        o["rule_map"] = json::Value{std::move(rm)};
        root["falco"] = json::Value{std::move(o)};
    }

    // ---- auditd ----
    {
        json::Object o;
        o["enabled"] = cfg.auditd.enabled;
        o["use_netlink"] = cfg.auditd.use_netlink;
        o["fallback_log"] = cfg.auditd.fallback_log;
        o["watch_paths"] = strs(cfg.auditd.watch_paths);
        o["privileged_cmds"] = strs(cfg.auditd.privileged_cmds);
        o["detect_sudo_abuse"] = cfg.auditd.detect_sudo_abuse;
        o["sudo_red_flags"] = strs(cfg.auditd.sudo_red_flags);
        o["netlink_buf_bytes"] = static_cast<std::int64_t>(cfg.auditd.netlink_buf_bytes);
        o["emit_all_auid_changes"] = cfg.auditd.emit_all_auid_changes;
        root["auditd"] = json::Value{std::move(o)};
    }

    // ---- proc poll (Module 4b) ----
    {
        json::Object o;
        o["enabled"] = cfg.proc_poll.enabled;
        o["interval_ms"] = static_cast<std::int64_t>(cfg.proc_poll.interval.count());
        o["rescan_cooldown_ms"] = static_cast<std::int64_t>(cfg.proc_poll.rescan_cooldown.count());
        root["proc_poll"] = json::Value{std::move(o)};
    }

    // ---- osquery ----
    {
        json::Object o;
        o["enabled"] = cfg.osquery.enabled;
        o["osqueryi_path"] = cfg.osquery.osqueryi_path;
        o["query_interval"] = secs(cfg.osquery.query_interval);
        o["query_timeout"] = secs(cfg.osquery.query_timeout);
        o["queries"] = pairs(cfg.osquery.queries);
        root["osquery"] = json::Value{std::move(o)};
    }

    // ---- suricata ----
    {
        json::Object o;
        o["enabled"] = cfg.suricata.enabled;
        o["eve_path"] = cfg.suricata.eve_path;
        o["eve_socket"] = cfg.suricata.eve_socket;
        o["poll_interval"] = millis(cfg.suricata.poll_interval);
        o["c2_beacon_score_threshold"] = cfg.suricata.c2_beacon_score_threshold;
        o["beacon_window"] = secs(cfg.suricata.beacon_window);
        o["beacon_min_hits"] = static_cast<std::int64_t>(cfg.suricata.beacon_min_hits);
        o["beacon_interval_jitter_max"] = cfg.suricata.beacon_interval_jitter_max;
        root["suricata"] = json::Value{std::move(o)};
    }

    // ---- heuristic ----
    {
        json::Object o;
        o["enabled"] = cfg.heuristic.enabled;
        o["decay_window"] = secs(cfg.heuristic.decay_window);
        o["risk_decay_per_second"] = cfg.heuristic.risk_decay_per_second;
        o["alert_threshold"] = static_cast<std::int64_t>(cfg.heuristic.alert_threshold);
        o["critical_threshold"] = static_cast<std::int64_t>(cfg.heuristic.critical_threshold);
        o["auto_respond_threshold"] = static_cast<std::int64_t>(cfg.heuristic.auto_respond_threshold);
        o["auto_respond"] = cfg.heuristic.auto_respond;
        o["detect_ssh_anomaly"] = cfg.heuristic.detect_ssh_anomaly;
        o["ssh_spawn_burst"] = static_cast<std::int64_t>(cfg.heuristic.ssh_spawn_burst);
        o["ssh_spawn_window"] = secs(cfg.heuristic.ssh_spawn_window);
        o["web_daemons"] = strs(cfg.heuristic.web_daemons);
        o["shells"] = strs(cfg.heuristic.shells);
        o["detect_tty_from_daemon"] = cfg.heuristic.detect_tty_from_daemon;
        o["forbidden_children"] = pair_lists(cfg.heuristic.forbidden_children);
        o["learn_baseline"] = cfg.heuristic.learn_baseline;
        o["baseline_path"] = cfg.heuristic.baseline_path;
        o["baseline_learning_period"] = secs(cfg.heuristic.baseline_learning_period);
        o["suppress_actions_during_learning"] = cfg.heuristic.suppress_actions_during_learning;
        o["profiles_dir"] = cfg.heuristic.profiles_dir;
        root["heuristic"] = json::Value{std::move(o)};
    }

    // ---- remediation ----
    {
        json::Object o;
        o["enabled"] = cfg.remediation.enabled;
        o["allow_kill"] = cfg.remediation.allow_kill;
        o["allow_suspend"] = cfg.remediation.allow_suspend;
        o["allow_network_block"] = cfg.remediation.allow_network_block;
        o["allow_exe_block"] = cfg.remediation.allow_exe_block;
        o["auto_block_by_exe"] = cfg.remediation.auto_block_by_exe;
        o["exe_block_after_endpoints"] = static_cast<std::int64_t>(cfg.remediation.exe_block_after_endpoints);
        o["allow_quarantine"] = cfg.remediation.allow_quarantine;
        o["quarantine_dir"] = cfg.remediation.quarantine_dir;
        json::Array pp;
        pp.reserve(cfg.remediation.protected_pids.size());
        for (const pid_t p : cfg.remediation.protected_pids)
            pp.emplace_back(static_cast<std::int64_t>(p));
        o["protected_pids"] = json::Value{std::move(pp)};
        o["protected_processes"] = strs(cfg.remediation.protected_processes);
        o["protected_paths"] = strs(cfg.remediation.protected_paths);
        o["protect_pid1_descendants"] = cfg.remediation.protect_pid1_descendants;
        o["block_duration"] = secs(cfg.remediation.block_duration);
        o["nftables_table"] = cfg.remediation.nftables_table;
        o["nft_cli"] = cfg.remediation.nft_cli;
        o["use_libnftables"] = cfg.remediation.use_libnftables;
        o["iptables_fallback"] = cfg.remediation.iptables_fallback;
        o["use_cgroup_containment"] = cfg.remediation.use_cgroup_containment;
        o["cgroup_root"] = cfg.remediation.cgroup_root;
        o["freeze_cgroup"] = cfg.remediation.freeze_cgroup;
        o["notify_summary"] = cfg.remediation.notify_summary;
        o["desktop_notifications"] = cfg.remediation.desktop_notifications;
        o["notify_send"] = cfg.remediation.notify_send;
        root["remediation"] = json::Value{std::move(o)};
    }

    // ---- shadow ----
    {
        json::Object o;
        o["enabled"] = cfg.shadow.enabled;
        o["roots"] = strs(cfg.shadow.roots);
        o["keep"] = static_cast<std::int64_t>(cfg.shadow.keep);
        o["max_snapshot_bytes"] = static_cast<std::int64_t>(cfg.shadow.max_snapshot_bytes);
        o["max_files"] = static_cast<std::int64_t>(cfg.shadow.max_files);
        root["shadow"] = json::Value{std::move(o)};
    }

    // ---- gui ----
    {
        json::Object o;
        o["enabled"] = cfg.gui.enabled;
        o["ipc_socket"] = cfg.gui.ipc_socket;
        o["ipc_group"] = cfg.gui.ipc_group;
        o["start_with_agent"] = cfg.gui.start_with_agent;
        o["theme"] = cfg.gui.theme;
        o["telemetry_hz"] = static_cast<std::int64_t>(cfg.gui.telemetry_hz);
        o["event_feed_max"] = static_cast<std::int64_t>(cfg.gui.event_feed_max);
        o["show_kernel_events"] = cfg.gui.show_kernel_events;
        o["vibrancy"] = cfg.gui.vibrancy;
        o["wayland_display_override"] = cfg.gui.wayland_display_override;
        root["gui"] = json::Value{std::move(o)};
    }

    // ---- ai ----
    {
        json::Object o;
        o["enabled"] = cfg.ai.enabled;
        o["provider"] = cfg.ai.provider;
        o["api_key"] = cfg.ai.api_key.empty() ? std::string("") : std::string("(set -- hidden)");
        o["model"] = cfg.ai.model;
        o["timeout_seconds"] = static_cast<std::int64_t>(cfg.ai.timeout.count());
        o["max_answer_tokens"] = static_cast<std::int64_t>(cfg.ai.max_answer_tokens);
        root["ai"] = json::Value{std::move(o)};
    }

    // ---- rescue ----
    {
        json::Object o;
        o["enabled"] = cfg.rescue.enabled;
        o["iso_path"] = cfg.rescue.iso_path;
        o["boot_dir"] = cfg.rescue.boot_dir;
        o["grub_entry_file"] = cfg.rescue.grub_entry_file;
        o["entry_title"] = cfg.rescue.entry_title;
        o["auto_reboot"] = cfg.rescue.auto_reboot;
        root["rescue"] = json::Value{std::move(o)};
    }

    // ---- integrations ----
    {
        json::Object o;
        o["enabled"] = cfg.integrations.enabled;
        o["runner_enabled"] = cfg.integrations.runner_enabled;
        o["tool_timeout_seconds"] = static_cast<std::int64_t>(cfg.integrations.tool_timeout.count());
        o["max_output_bytes"] = static_cast<std::int64_t>(cfg.integrations.max_output_bytes);
        o["virustotal_enabled"] = cfg.integrations.virustotal_enabled;
        o["crowdsec_enabled"] = cfg.integrations.crowdsec_enabled;
        o["virustotal_api_key"] = cfg.integrations.virustotal_api_key;
        o["online_submission"] = cfg.integrations.online_submission;
        root["integrations"] = json::Value{std::move(o)};
    }

    return json::Value{std::move(root)};
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

}

bool save_config(const AgentConfig& cfg, const std::string& path) noexcept {
    const std::string text = to_json(cfg).dump();
    return fsx::write_atomic(path, {reinterpret_cast<const std::byte*>(text.data()), text.size()}, 0600);
}

std::string describe(const AgentConfig& c) {
    std::string out;
    out += std::format("HyprNova configuration\n");
    out += std::format("==========================\n");
    out += std::format("instance         : {}\n", c.instance_id);
    out += std::format("version          : {}\n", c.version);
    out += std::format("log level        : {}\n", level_tag(c.log_level));
    out += std::format("dry-run          : {}\n", c.dry_run ? "YES (observe only)" : "no");
    out += std::format("state dir        : {}\n", c.state_dir);
    out += std::format("bus ring depth   : {}\n", c.bus_ring_depth);
    out += "\n";
    out += std::format("[1] boot integrity : {} (secure-boot required: {})\n", c.boot.enabled ? "on" : "off",
                       c.boot.require_secure_boot ? "yes" : "no");
    out += std::format("[1] kernel hardening: {} ({} sysctl policies, lockdown required: {})\n",
                       c.hardening.enabled ? "on" : "off", c.hardening.sysctls.size(),
                       c.hardening.require_lockdown ? "yes" : "no");
    out += std::format("[1] MAC profiles   : {} ({} critical daemons)\n", c.mac.enabled ? "on" : "off",
                       c.mac.critical_daemons.size());
    out += std::format("[2] canaries       : {} ({} per root, {} roots, integrity every {}s)\n",
                       c.canary.enabled ? "on" : "off", c.canary.canaries_per_root,
                       c.canary.home_roots.size() + c.canary.extra_roots.size(),
                       c.canary.integrity_check_interval.count());
    out += std::format("[2] ransomware     : {} (entropy>={}, mass-modify >={} files / {}ms, auto-SIGSTOP: {})\n",
                       c.ransomware.enabled ? "on" : "off", c.ransomware.entropy_threshold,
                       c.ransomware.mass_modify_file_threshold, c.ransomware.mass_modify_window.count(),
                       c.ransomware.auto_suspend ? "yes" : "no");
    out += std::format("[3] static scan    : {} (backend {}, {} roots, batch flush {}s / {} paths)\n",
                       c.scan.enabled ? "on" : "off", backend_name(c.scan.backend), c.scan.roots.size(),
                       c.scan.batch_flush_interval.count(), c.scan.batch_max_paths);
    out += std::format("[4] falco          : {} ({})\n", c.falco.enabled ? "on" : "off",
                       c.falco.socket_path);
    out += std::format("[4] auditd         : {} (netlink {}, {} watches)\n", c.auditd.enabled ? "on" : "off",
                       c.auditd.use_netlink ? "yes" : "no", c.auditd.watch_paths.size());
    out += std::format("[4] osquery        : {} ({} queries every {}s)\n", c.osquery.enabled ? "on" : "off",
                       c.osquery.queries.size(), c.osquery.query_interval.count());
    out += std::format("[4] suricata       : {} ({})\n", c.suricata.enabled ? "on" : "off",
                       c.suricata.eve_path);
    out += std::format("[5] heuristics     : {} (alert>={}, critical>={}, auto-respond>{}: {})\n",
                       c.heuristic.enabled ? "on" : "off", c.heuristic.alert_threshold,
                       c.heuristic.critical_threshold, c.heuristic.auto_respond_threshold,
                       c.heuristic.auto_respond ? "yes" : "NO (human in the loop)");
    out += std::format("[6] remediation    : {} (kill={}, suspend={}, netblock={}, quarantine={})\n",
                       c.remediation.enabled ? "on" : "off", c.remediation.allow_kill ? "y" : "n",
                       c.remediation.allow_suspend ? "y" : "n",
                       c.remediation.allow_network_block ? "y" : "n",
                       c.remediation.allow_quarantine ? "y" : "n");
    out += std::format("[7] gui            : {} ({} @ {} Hz, {})\n", c.gui.enabled ? "on" : "off",
                       c.gui.ipc_socket, c.gui.telemetry_hz, c.gui.theme);
    return out;
}

}  // namespace hyprnova::core
