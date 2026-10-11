// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 1c implementation

#include <filesystem>

#include "hardening/mac_profile.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <format>
#include <sys/stat.h>
#include <thread>
#include <unordered_map>

#include "core/fd.hpp"
#include "core/proc.hpp"

namespace hyprnova::hardening {

namespace fsx = core::fsx;
using core::proc::ProcessInfo;
using namespace std::string_view_literals;

namespace {

std::vector<pid_t> pids_by_comm(std::string_view comm) {
    std::vector<pid_t> out;
    for (const pid_t pid : core::proc::list_pids(true)) {
        const std::string c = core::proc::comm_of(pid);
        if (c == comm) out.push_back(pid);
    }
    return out;
}

std::vector<pid_t> pids_by_exe_basename(std::string_view base) {
    std::vector<pid_t> out;
    for (const pid_t pid : core::proc::list_pids(true)) {
        const std::string exe = core::proc::exe_of(pid);
        if (exe.empty()) continue;
        const std::size_t slash = exe.find_last_of('/');
        const std::string_view name = slash == std::string::npos ? exe : std::string_view(exe).substr(slash + 1);
        if (name == base) out.push_back(pid);
    }
    return out;
}

/// Listening TCP/UDP ports per pid, parsed from /proc/net/tcp{,6} + udp{,6}.
/// Done by hand rather than shelling out to `ss`: an auditor must not depend on
/// a binary that a rootkit can replace.
std::unordered_map<pid_t, std::vector<std::uint16_t>> listening_ports() {
    std::unordered_map<pid_t, std::vector<std::uint16_t>> out;

    // inode -> port for LISTEN sockets
    std::unordered_map<std::uint64_t, std::uint16_t> inode_to_port;
    for (const char* f : {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}) {
        std::string raw;
        if (fsx::read_file(f, raw, 4 << 20) < 0) continue;
        std::size_t pos = 0;
        bool first = true;
        while (pos < raw.size()) {
            const std::size_t nl = raw.find('\n', pos);
            const std::string_view line{raw.data() + pos,
                                        (nl == std::string_view::npos ? raw.size() : nl) - pos};
            pos = nl == std::string::npos ? raw.size() : nl + 1;
            if (first) { first = false; continue; }  // header
            if (line.empty()) continue;

            // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
            char local[64] = {};
            char rem[64] = {};
            char st[8] = {};
            unsigned txq = 0, rxq = 0, tr = 0;
            unsigned long long tm_when = 0, retrns = 0, inode = 0;
            unsigned uid = 0, timeout = 0;
            // No assignment suppression combined with length modifiers: that
            // combination is a GNU extension and -Wformat=2 rejects it.
            const int n = std::sscanf(std::string(line).c_str(),
                                      "%*d: %63s %63s %7s %x:%x %x:%llu %llu %u %u %llu",
                                      local, rem, st, &txq, &rxq, &tr, &tm_when, &retrns, &uid,
                                      &timeout, &inode);
            (void)txq; (void)rxq; (void)tr; (void)tm_when; (void)retrns; (void)timeout;
            if (n < 11) continue;

            // 0A == TCP_LISTEN. For UDP, "07" is close enough to "listening".
            const bool listen = std::strcmp(st, "0A") == 0 || std::strcmp(st, "07") == 0;
            if (!listen || inode == 0) continue;

            // local_address is "ADDR:PORT" with PORT in hex.
            const std::string_view lv{local};
            const std::size_t colon = lv.find_last_of(':');
            if (colon == std::string_view::npos) continue;
            unsigned port = 0;
            const auto* hp = lv.data() + colon + 1;
            if (std::from_chars(hp, hp + (lv.size() - colon - 1), port, 16).ec != std::errc{}) continue;
            if (port == 0 || port > 65535) continue;
            inode_to_port[inode] = static_cast<std::uint16_t>(port);
        }
    }

    // Map sockets to pids via /proc/<pid>/fd symlinks.
    for (const pid_t pid : core::proc::list_pids(true)) {
        const std::string fddir = std::format("/proc/{}/fd", pid);
        core::UniqueDir d{::opendir(fddir.c_str())};
        if (!d) continue;
        while (const dirent* e = ::readdir(d.get())) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            auto link = fsx::read_symlink(fddir + "/" + e->d_name);
            if (!link) continue;
            if (!link->starts_with("socket:[")) continue;
            const std::size_t s = link->find('[') + 1;
            const std::size_t en = link->find(']', s);
            if (en == std::string::npos) continue;
            std::uint64_t inode = 0;
            const std::string_view num{link->data() + s, en - s};
            if (std::from_chars(num.data(), num.data() + num.size(), inode).ec != std::errc{}) continue;
            auto it = inode_to_port.find(inode);
            if (it != inode_to_port.end()) out[pid].push_back(it->second);
        }
    }
    for (auto& [pid, ports] : out) {
        std::sort(ports.begin(), ports.end());
        ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// LSM detection
// ---------------------------------------------------------------------------

LsmInfo detect_lsm() noexcept {
    LsmInfo info;
    std::string raw;
    if (fsx::read_file("/sys/kernel/security/lsm", raw, 512) >= 0) {
        while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r')) raw.pop_back();
        info.raw = raw;
    } else {
        // Pre-5.1 kernels: infer from CONFIG_LSM in /proc/config.gz or from the
        // presence of the securityfs subtrees.
        info.raw = "(kernel does not expose /sys/kernel/security/lsm)";
    }

    auto has = [&](std::string_view tok) { return info.raw.find(tok) != std::string_view::npos; };

    info.apparmor = has("apparmor") || fsx::is_dir("/sys/kernel/security/apparmor");
    info.selinux = has("selinux") || fsx::is_dir("/sys/fs/selinux");
    info.bpf_lsm = has("bpf");
    info.landlock = has("landlock");

    if (info.apparmor) info.active.push_back(LsmKind::AppArmor);
    if (info.selinux) info.active.push_back(LsmKind::SELinux);
    if (info.bpf_lsm) info.active.push_back(LsmKind::Bpf);
    if (info.landlock) info.active.push_back(LsmKind::Landlock);
    if (has("smack")) info.active.push_back(LsmKind::Smack);
    if (has("tomoyo")) info.active.push_back(LsmKind::Tomoyo);

    if (info.active.empty()) {
        info.findings.push_back(
            "NO Linux Security Module is active. There is no mandatory access control on this host: "
            "any root process has unrestricted access to every file, socket and kernel interface. "
            "Module 6 containment cannot rely on confinement.");
    } else {
        std::string list;
        for (const auto k : info.active) {
            if (!list.empty()) list += ", ";
            list += std::string(lsm_name(k));
        }
        info.findings.push_back("Active LSM stack: " + list);
    }
    if (!info.bpf_lsm) {
        info.findings.push_back(
            "CONFIG_LSM does not include 'bpf': eBPF LSM hooks are unavailable, so fine-grained "
            "runtime policy (e.g. denying exec from /dev/shm for a specific cgroup) cannot be "
            "attached without a kernel rebuild.");
    }
    return info;
}

// ---------------------------------------------------------------------------
// AppArmor
// ---------------------------------------------------------------------------

/// Trusted third-party profile lookup. A profile "exists" for an app when a
/// regular file named <app> (optionally .profile) sits in one of cfg.profile_dirs,
/// or the distribution already ships /etc/apparmor.d/<app>. The agent never loads
/// or edits these; loading stays the admin's apparmor_parser call.
[[nodiscard]] bool third_party_profile_exists(const core::MacProfileConfig& cfg,
                                              std::string_view app) noexcept {
    if (app.empty() || app.find('/') != std::string_view::npos) return false;
    for (const auto& dir : cfg.profile_dirs) {
        if (dir.empty()) continue;
        if (fsx::is_file(dir + "/" + std::string{app})) return true;
        if (fsx::is_file(dir + "/" + std::string{app} + ".profile")) return true;
    }
    return fsx::is_file("/etc/apparmor.d/" + std::string{app});
}

AppArmorStatus read_apparmor(const core::MacProfileConfig& cfg) noexcept {
    AppArmorStatus s;
    // Inventory the trusted third-party profiles FIRST: they live in ordinary
    // directories and are meaningful even when the AppArmor securityfs is not
    // mounted (the profile exists; the admin simply has not loaded it yet -- on
    // this box, that is exactly the finding).
    for (const auto& dir : cfg.profile_dirs) {
        std::error_code ec;
        if (dir.empty() || !std::filesystem::is_directory(dir, ec)) continue;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            if (ec) break;
            if (entry.is_regular_file(ec))
                s.trusted_profiles.emplace_back(entry.path().filename().generic_string());
        }
    }
    std::error_code d_ec;
    if (std::filesystem::is_directory("/etc/apparmor.d", d_ec)) {
        for (const auto& entry : std::filesystem::directory_iterator("/etc/apparmor.d", d_ec)) {
            if (d_ec) break;
            if (entry.is_regular_file(d_ec) && entry.path().filename().generic_string() != "tunables" &&
                entry.path().filename().generic_string() != "abstractions")
                s.trusted_profiles.emplace_back(entry.path().filename().generic_string());
        }
    }
    s.filesystem_present = fsx::is_dir(cfg.apparmor_root);
    if (!s.filesystem_present) {
        s.findings.push_back("AppArmor securityfs not present at " + cfg.apparmor_root);
        if (!s.trusted_profiles.empty())
            s.findings.push_back(std::format("{} trusted third-party profile(s) are on disk in the "
                                             "configured profile directories but AppArmor is not active",
                                             s.trusted_profiles.size()));
        return s;
    }
    s.enabled = fsx::read_trimmed(cfg.apparmor_root + "/enabled") == "Y" ||
                fsx::exists(cfg.apparmor_root + "/profiles");

    std::string raw;
    if (fsx::read_file(cfg.apparmor_root + "/profiles", raw, 8 << 20) < 0) {
        s.findings.push_back("Cannot read " + cfg.apparmor_root + "/profiles (need root)");
        return s;
    }
    s.raw_summary = std::to_string(raw.size()) + " bytes";

    // Format: "<profile name> (enforce)" / "(complain)" / "(kill)" per line.
    std::size_t pos = 0;
    while (pos < raw.size()) {
        const std::size_t nl = raw.find('\n', pos);
        const std::string_view line{raw.data() + pos, (nl == std::string_view::npos ? raw.size() : nl) - pos};
        pos = nl == std::string::npos ? raw.size() : nl + 1;
        if (line.empty()) continue;

        AppArmorProfile p;
        const std::size_t paren = line.find('(');
        if (paren == std::string_view::npos) continue;
        std::string_view name = line.substr(0, paren);
        while (!name.empty() && name.back() == ' ') name.remove_suffix(1);
        p.name = std::string(name);

        const std::string_view mode = line.substr(paren);
        if (mode.find("enforce") != std::string_view::npos) { p.mode = ProfileMode::Enforce; ++s.profiles_enforce; }
        else if (mode.find("complain") != std::string_view::npos) { p.mode = ProfileMode::Complain; ++s.profiles_complain; }
        else if (mode.find("kill") != std::string_view::npos) { p.mode = ProfileMode::Kill; ++s.profiles_kill; }
        else if (mode.find("disabled") != std::string_view::npos) { p.mode = ProfileMode::Disabled; }
        else p.mode = ProfileMode::Unknown;

        ++s.profiles_loaded;
        s.profiles.push_back(std::move(p));
    }

    if (s.profiles_loaded == 0) {
        s.findings.push_back("AppArmor is enabled but ZERO profiles are loaded: MAC is nominally "
                             "present and functionally absent.");
    }
    if (s.profiles_complain > 0) {
        s.findings.push_back(std::format("{} AppArmor profile(s) are in COMPLAIN mode. Violations are "
                                         "logged but NOT blocked -- this is a monitoring posture, not "
                                         "an enforcement posture.",
                                         s.profiles_complain));
    }
    if (s.profiles_enforce == 0 && s.profiles_loaded > 0) {
        s.findings.push_back("No AppArmor profile is in enforce mode.");
    }

    // Which profile each running process is actually under.
    for (const pid_t pid : core::proc::list_pids(true)) {
        const std::string attr = fsx::read_trimmed(std::format("/proc/{}/attr/current", pid));
        if (attr.empty() || attr == "unconfined") continue;
        // attr looks like "/usr/sbin/sshd (enforce)"
        const std::size_t paren = attr.find('(');
        const std::string pname = paren == std::string::npos
                                      ? attr
                                      : [&] {
                                            std::string_view v{attr.data(), paren};
                                            while (!v.empty() && v.back() == ' ') v.remove_suffix(1);
                                            return std::string(v);
                                        }();
        for (auto& p : s.profiles) {
            if (p.name != pname) continue;
            p.attached_to_running_process = true;
            if (p.pids.size() < 16) p.pids.push_back(pid);
            if (p.executable.empty()) p.executable = core::proc::exe_of(pid);
        }
    }
    return s;
}

// ---------------------------------------------------------------------------
// SELinux
// ---------------------------------------------------------------------------

SelinuxStatus read_selinux(const core::MacProfileConfig& cfg) noexcept {
    SelinuxStatus s;
    if (!fsx::is_dir("/sys/fs/selinux")) {
        s.disabled = true;
        s.findings.push_back("SELinux is not active on this host.");
        return s;
    }
    s.enabled = true;
    const std::string enf = fsx::read_trimmed(cfg.selinux_path);
    if (!enf.empty()) {
        s.enforce_raw = enf == "1" ? 1 : enf == "0" ? 0 : -1;
        s.enforcing = s.enforce_raw == 1;
        s.permissive = s.enforce_raw == 0;
    }
    s.policy_name = fsx::read_trimmed("/sys/fs/selinux/policyvers");
    const std::string deny = fsx::read_trimmed("/sys/fs/selinux/avc/hash_stats");
    if (!deny.empty()) s.findings.push_back("SELinux avc hash_stats: " + deny);

    if (s.permissive) {
        s.findings.push_back("SELinux is PERMISSIVE: policy violations are logged but permitted. "
                             "A compromised daemon is not contained.");
    } else if (s.enforcing) {
        s.findings.push_back("SELinux is enforcing (policy version " + s.policy_name + ").");
    }
    return s;
}

// ---------------------------------------------------------------------------
// Daemon confinement
// ---------------------------------------------------------------------------

std::vector<DaemonConfinement> audit_daemon_confinement(const core::MacProfileConfig& cfg) noexcept {
    std::vector<DaemonConfinement> out;
    const auto ports = listening_ports();

    // Build a pid -> apparmor profile map once; scanning /proc/attr per daemon
    // per check is wasteful.
    std::unordered_map<pid_t, std::pair<std::string, ProfileMode>> aa_map;
    for (const pid_t pid : core::proc::list_pids(true)) {
        const std::string attr = fsx::read_trimmed(std::format("/proc/{}/attr/current", pid));
        if (attr.empty()) continue;
        const std::size_t paren = attr.find('(');
        std::string name = paren == std::string::npos ? attr : std::string(attr.substr(0, paren));
        while (!name.empty() && name.back() == ' ') name.pop_back();
        ProfileMode m = ProfileMode::Unknown;
        if (paren != std::string::npos) {
            const std::string_view tail = attr.substr(paren);
            if (tail.find("enforce") != std::string_view::npos) m = ProfileMode::Enforce;
            else if (tail.find("complain") != std::string_view::npos) m = ProfileMode::Complain;
            else if (tail.find("kill") != std::string_view::npos) m = ProfileMode::Kill;
        }
        if (name == "unconfined" || name == "-") m = ProfileMode::Unconfined;
        aa_map.emplace(pid, std::make_pair(std::move(name), m));
    }

    for (const auto& daemon : cfg.critical_daemons) {
        DaemonConfinement d;
        d.name = daemon;
        d.pids = pids_by_comm(daemon);
        if (d.pids.empty()) d.pids = pids_by_exe_basename(daemon);
        d.running = !d.pids.empty();
        if (!d.running) continue;  // not installed / not running: nothing to confine

        for (const pid_t pid : d.pids) {
            auto it = ports.find(pid);
            if (it != ports.end() && !it->second.empty()) {
                d.network_reachable = true;
                for (const auto p : it->second) d.listen_ports.push_back(p);
            }
            auto aa = aa_map.find(pid);
            if (aa != aa_map.end()) {
                if (d.profile.empty() || aa->second.first != "unconfined") d.profile = aa->second.first;
                d.mode = aa->second.second;
            }
            const std::string sel = fsx::read_trimmed(std::format("/proc/{}/attr/current", pid));
            if (!sel.empty() && sel.find(":") != std::string::npos) d.selinux_context = sel;
        }
        std::sort(d.listen_ports.begin(), d.listen_ports.end());
        d.listen_ports.erase(std::unique(d.listen_ports.begin(), d.listen_ports.end()),
                             d.listen_ports.end());

        const bool aa_confined = d.mode == ProfileMode::Enforce || d.mode == ProfileMode::Kill;
        const bool sel_confined = !d.selinux_context.empty() &&
                                  d.selinux_context.find(":unconfined_") == std::string::npos &&
                                  d.selinux_context.find("unconfined_t") == std::string::npos;
        d.confined = aa_confined || sel_confined;

        if (d.confined) {
            d.severity = core::Severity::Info;
            d.findings.push_back(std::format("{} (pid {}) is confined by {} in {} mode", d.name,
                                             d.pids.front(), aa_confined ? "AppArmor" : "SELinux",
                                             aa_confined ? std::string(mode_name(d.mode)) : "enforcing"));
        } else if (d.mode == ProfileMode::Complain) {
            d.complain = true;
            d.severity = d.network_reachable ? core::Severity::High : core::Severity::Medium;
            d.findings.push_back(std::format("{} (pid {}) has AppArmor profile '{}' in COMPLAIN mode: "
                                             "violations are logged but permitted",
                                             d.name, d.pids.front(), d.profile));
        } else {
            d.severity = d.network_reachable ? core::Severity::Critical : core::Severity::High;
            // A trusted profile EXISTS for this daemon and it is running without
            // it. That upgrades the finding from "nobody wrote a profile" (a gap)
            // to "a profile someone trusted wrote is not being used" (an action).
            if (third_party_profile_exists(cfg, d.name)) {
                d.findings.push_back(std::format(
                    "a trusted AppArmor profile for {} exists in the configured profile "
                    "directories (or /etc/apparmor.d) but the process is running UNCONFINED -- "
                    "load it (apparmor_parser -r) to close this gap without writing anything new",
                    d.name));
            }
            d.findings.push_back(std::format(
                "{} (pid {}) is UNCONFINED{}: a remote code execution in this daemon is an immediate "
                "full-host compromise with no MAC barrier",
                d.name, d.pids.front(),
                d.network_reachable
                    ? std::format(" and is NETWORK REACHABLE on port(s) {}",
                                  [&] {
                                      std::string s;
                                      for (const auto p : d.listen_ports) {
                                          if (!s.empty()) s += ",";
                                          s += std::to_string(p);
                                      }
                                      return s;
                                  }())
                    : std::string()));
        }
        out.push_back(std::move(d));
    }
    return out;
}

MacReport verify_mac(const core::MacProfileConfig& cfg) noexcept {
    MacReport r;
    r.lsm = detect_lsm();
    r.apparmor = read_apparmor(cfg);
    r.selinux = read_selinux(cfg);
    if (cfg.audit_unconfined_daemons) r.daemons = audit_daemon_confinement(cfg);
    r.checked_at = core::SysClock::now();

    for (const auto& d : r.daemons) {
        if (d.confined) ++r.confined_count;
        else if (d.mode == ProfileMode::Complain) ++r.complain_count;
        else ++r.unconfined_count;
        if (d.severity > r.worst_severity) r.worst_severity = d.severity;
    }
    if (r.apparmor.profiles_complain > 0 && r.worst_severity < core::Severity::Medium)
        r.worst_severity = core::Severity::Medium;
    if (r.lsm.active.empty() && r.worst_severity < core::Severity::Critical)
        r.worst_severity = core::Severity::Critical;

    const std::size_t total = std::max<std::size_t>(r.daemons.size(), 1);
    int daemon_score = static_cast<int>(((r.confined_count * 100) + (r.complain_count * 40)) / total);
    if (r.daemons.empty()) daemon_score = r.lsm.active.empty() ? 0 : 60;

    int lsm_score = 0;
    if (r.apparmor.enabled && r.apparmor.profiles_enforce > 0) lsm_score = 100;
    else if (r.selinux.enforcing) lsm_score = 100;
    else if (r.selinux.permissive || r.apparmor.profiles_complain > 0) lsm_score = 40;
    else if (r.lsm.active.empty()) lsm_score = 0;
    else lsm_score = 30;

    r.score = std::clamp((daemon_score * 60 + lsm_score * 40) / 100, 0, 100);
    return r;
}

// ---------------------------------------------------------------------------
// Sensor
// ---------------------------------------------------------------------------

MacProfileSensor::MacProfileSensor(core::EventBus& bus, const core::AgentConfig& cfg,
                                   core::ThreadPool& pool)
    : core::ISensor("mac-profile", core::SensorId::MacProfile, bus, cfg, pool) {}

bool MacProfileSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.mac.enabled;
}

bool MacProfileSensor::on_start() {
    rescan();
    return true;
}

void MacProfileSensor::loop(std::stop_token st) {
    while (!st.stop_requested()) {
        // Interruptible wait: one flat 5 s sleep made daemon shutdown lag up
        // to 15 s (three sensors joined sequentially). 250 ms slices keep the
        // same cadence but honour stop_request within a quarter second.
        for (int slice = 0; slice < 20 && !st.stop_requested(); ++slice)
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        if (last_publish_ != core::SysClock::time_point{} &&
            core::SysClock::now() - last_publish_ >= cfg_.hardening.rescan_interval) {
            rescan();
        }
    }
}

void MacProfileSensor::rescan() {
    report_ = verify_mac(cfg_.mac);
    publish();
    last_publish_ = core::SysClock::now();
}

void MacProfileSensor::publish() {
    for (const auto& f : report_.lsm.findings) {
        if (f.starts_with("Active LSM")) continue;  // informational, not a finding
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::MacProfile;
        ev.kind = core::EventKind::MacEnforcement;
        ev.severity = report_.lsm.active.empty() ? core::Severity::Critical : core::Severity::Low;
        ev.message = f;
        ev.risk_score = report_.lsm.active.empty() ? 400 : 30;
        emit(std::move(ev));
    }

    for (const auto& f : report_.apparmor.findings) {
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::MacProfile;
        ev.kind = core::EventKind::MacEnforcement;
        ev.severity = f.find("ZERO profiles") != std::string::npos ? core::Severity::High
                      : f.find("COMPLAIN") != std::string::npos    ? core::Severity::Medium
                                                                   : core::Severity::Low;
        ev.message = f;
        ev.risk_score = ev.severity == core::Severity::High ? 320 : 120;
        emit(std::move(ev));
    }

    for (const auto& d : report_.daemons) {
        for (const auto& f : d.findings) {
            core::TelemetryEvent ev;
            ev.sensor = core::SensorId::MacProfile;
            ev.kind = core::EventKind::MacEnforcement;
            ev.severity = d.severity;
            ev.message = f;
            ev.target.rule_id = d.profile.empty() ? d.selinux_context : d.profile;
            if (!d.pids.empty()) ev.actor.pid = d.pids.front();
            ev.actor.comm = d.name;
            ev.actor.exe = d.name;
            ev.count = d.listen_ports.size();
            ev.risk_score = static_cast<std::uint16_t>(
                d.severity == core::Severity::Critical ? 480
                : d.severity == core::Severity::High ? 340
                : d.severity == core::Severity::Medium ? 180 : 20);
            if (d.network_reachable) ev.fields["listen_ports"] = [&] {
                std::string s;
                for (const auto p : d.listen_ports) { if (!s.empty()) s += ","; s += std::to_string(p); }
                return s;
            }();
            ev.fields["confined"] = d.confined ? "yes" : "no";
            ev.fields["mode"] = std::string(mode_name(d.mode));
            emit(std::move(ev));
        }
    }

    core::TelemetryEvent summary;
    summary.sensor = core::SensorId::MacProfile;
    summary.kind = core::EventKind::MacEnforcement;
    summary.severity = report_.unconfined_count == 0 && report_.complain_count == 0
                           ? core::Severity::Info
                           : report_.worst_severity;
    summary.metric = static_cast<double>(report_.score);
    summary.message = std::format("MAC score {}/100 | lsm={} apparmor={}({} enforce/{} complain) "
                                  "selinux={} daemons confined={} unconfined={}",
                                  report_.score, report_.lsm.raw.empty() ? "?" : report_.lsm.raw,
                                  report_.apparmor.enabled ? "on" : "off",
                                  report_.apparmor.profiles_enforce, report_.apparmor.profiles_complain,
                                  report_.selinux.enforcing ? "enforcing"
                                  : report_.selinux.permissive ? "permissive" : "inactive",
                                  report_.confined_count, report_.unconfined_count);
    emit(std::move(summary));

    mark_running(std::format("score {}/100, {} daemons confined, {} unconfined", report_.score,
                             report_.confined_count, report_.unconfined_count));
}

}  // namespace hyprnova::hardening
