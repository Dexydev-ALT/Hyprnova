// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 8 -- the Toolbox (implementation).

#include "tools/toolbox.hpp"
#include "hardening/sshd_audit.hpp"

#include "remediation/remediation_engine.hpp"

#include "core/exec.hpp"
#include "core/fd.hpp"
#include "core/log.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace hyprnova::tools {

namespace {

using core::json::Array;
using core::json::Object;
using core::json::Value;

namespace fs = std::filesystem;

// ---- tiny string_view line helpers (kept local; core has no split_lines) ----

void for_each_line(std::string_view text, auto&& fn) noexcept {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const auto nl = text.find('\n', pos);
        const auto end = nl == std::string_view::npos ? text.size() : nl;
        std::string_view line = text.substr(pos, end - pos);
        if (line.ends_with('\r')) line.remove_suffix(1);
        fn(line);
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
}

std::string_view trim_sv(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

std::string clip(std::string_view s, std::size_t max) noexcept {
    std::string out{s.substr(0, max)};
    return out;
}

// ---- registry ---------------------------------------------------------------

/// Extra directories the trusted path search must cover: root-only management
/// binaries live in sbin and are invisible to a non-root agent's PATH.
constexpr std::string_view kSbinDirs[] = {"/usr/sbin", "/sbin", "/usr/local/sbin"};

/// The registry: the ecosystem, in the owner's twelve categories. Order is the
/// display order; `name` is the tool-run key and must be unique.
const std::vector<ToolSpec>& build_registry() {
    static const std::vector<ToolSpec> reg = {

        // ---- 1. antivirus & malware detection --------------------------------
        {"clamav", "ClamAV", "Antivirus & malware detection",
         "on-demand `clamscan -r PATH` runner; engine + signature dir probed; "
         "findings parsed from 'FOUND' lines",
         {"clamscan", "clamdscan"}, {"/var/lib/clamav", "/var/log/clamav"},
         {"--version"}, Integration::Runner},
        {"maldet", "Linux Malware Detect (LMD)", "Antivirus & malware detection",
         "on-demand `maldet -a PATH` scan runner; report dir probed",
         {"maldet"}, {"/usr/local/maldetect"},
         {"-a", "."}, Integration::Runner, true},
        {"yara", "YARA", "Antivirus & malware detection",
         "the compiled-in YaraLite engine is primary; the standalone `yara` binary "
         "is probed so operator rule-sets can be driven per-path",
         {"yara"}, {},
         {"--version"}, Integration::Runner},
        {"kvrt", "Kaspersky Virus Removal Tool", "Antivirus & malware detection",
         "on-demand second-opinion scanner, auto-accepted, report parsed",
         {"kvrt", "/opt/kaspersky/kvrt/kvrt"}, {},
         {"--accepteula", "-auto", "-silent"}, Integration::Runner, true},
        {"crowdsec", "CrowdSec", "Network & zero-day protection",
         "community + local ban decisions read via cscli; our C2 blocks are "
         "pushed back so the whole CrowdSec network benefits (zero-day tripwire)",
         {"cscli"}, {"/etc/crowdsec", "/var/lib/crowdsec"},
         {"decisions", "list", "-o", "json"}, Integration::Detect},
        {"sshd-config", "SSH server hardening", "Weak-settings audit",
         "built-in audit of /etc/ssh/sshd_config (PermitRootLogin, password auth, "
         "empty passwords, ...); first-wins sshd_config(5) semantics; report only "
         "-- we never edit your sshd_config",
         {}, {"/etc/ssh/sshd_config"},
         {}, Integration::BuiltIn, false},
        {"pkg-verify", "Package integrity", "Rootkit & file integrity",
         "dpkg --verify / rpm -Va / pacman -Qkk: detects replaced package-owned "
         "binaries (supply-chain & rootkit class); /etc changes are admin work, "
         "/usr changes are UNEXPLAINED until proven otherwise",
         {"dpkg", "rpm", "pacman"}, {},
         {}, Integration::Detect, true},

        // ---- 2. rootkit detection & file integrity ---------------------------
        {"rkhunter", "Rootkit Hunter", "Rootkit & file integrity",
         "on-demand `rkhunter --check`; warnings parsed into findings",
         {"rkhunter"}, {"/etc/rkhunter.conf"},
         {"--check", "--sk", "--nocolors"}, Integration::Runner, true},
        {"chkrootkit", "chkrootkit", "Rootkit & file integrity",
         "on-demand full sweep; INFECTED lines parsed into findings",
         {"chkrootkit"}, {},
         {}, Integration::Runner, true},
        {"aide", "AIDE", "Rootkit & file integrity",
         "on-demand integrity check against the AIDE database",
         {"aide", "aide.wrapper"}, {"/etc/aide/aide.conf", "/etc/aide.conf", "/var/lib/aide"},
         {"--check"}, Integration::Runner, true},
        {"tripwire", "Tripwire", "Rootkit & file integrity",
         "on-demand integrity check against the Tripwire policy",
         {"tripwire"}, {"/etc/tripwire"},
         {"--check", "--quiet"}, Integration::Runner, true},
        {"samhain", "Samhain", "Rootkit & file integrity",
         "host-based integrity + log verification, run on demand",
         {"samhain"}, {"/etc/samhainrc", "/var/lib/samhain"},
         {"-t", "check"}, Integration::Runner, true},

        // ---- 3. MAC & kernel security ----------------------------------------
        {"apparmor", "AppArmor", "MAC & kernel security",
         "fully integrated: profile inventory, per-daemon confinement audit, "
         "third-party trusted profiles respected (Module 1)",
         {"aa-status"}, {"/sys/kernel/security/apparmor", "/etc/apparmor.d"},
         {}, Integration::BuiltIn},
        {"selinux", "SELinux", "MAC & kernel security",
         "integrated: enforcing/permissive state, policy and denial audit (Module 1)",
         {"getenforce", "sestatus"}, {"/sys/fs/selinux", "/etc/selinux/config"},
         {}, Integration::BuiltIn},
        {"landlock", "Landlock", "MAC & kernel security",
         "availability probe via the kernel LSM list; unprivileged restriction is "
         "a candidate sandboxing primitive for future containment",
         {}, {"/sys/kernel/security/lsm"},
         {}, Integration::Detect},
        {"tomoyo", "TOMOYO", "MAC & kernel security",
         "availability probe; policy tools probed for audit support",
         {"tomoyo-editpolicy"}, {"/sys/kernel/security/tomoyo"},
         {}, Integration::Detect},
        {"seccomp", "seccomp", "MAC & kernel security",
         "built-in live audit: seccomp mode of every process straight from /proc "
         "(Toolbox snapshot), root processes running unfiltered are flagged",
         {}, {},
         {}, Integration::BuiltIn},
        {"capabilities", "Linux capabilities", "MAC & kernel security",
         "built-in: CapEff/CapBnd parsed from /proc (libcap when present, in-tree "
         "parser otherwise); feeds the hardening score",
         {"capsh"}, {},
         {}, Integration::BuiltIn},

        // ---- 4. sandboxing & isolation ---------------------------------------
        {"firejail", "Firejail", "Sandboxing & isolation",
         "probed + offered as a 'run this app sandboxed' action from the console",
         {"firejail"}, {"/etc/firejail"},
         {"--list"}, Integration::Runner},
        {"bubblewrap", "Bubblewrap", "Sandboxing & isolation",
         "probed as the minimal unprivileged sandbox backend for auxiliary work",
         {"bwrap"}, {},
         {"--version"}, Integration::Runner},
        {"flatpak", "Flatpak", "Sandboxing & isolation",
         "probed; installed apps inherit per-app heuristic profiles by name",
         {"flatpak"}, {"/var/lib/flatpak"},
         {"list"}, Integration::Detect},
        {"docker", "Docker", "Sandboxing & isolation",
         "probed; containers are attributed on every event (actor.container)",
         {"docker"}, {"/var/run/docker.sock"},
         {"ps"}, Integration::Detect},
        {"podman", "Podman", "Sandboxing & isolation",
         "probed; rootless containers attributed like Docker",
         {"podman"}, {"/run/podman/podman.sock"},
         {"ps"}, Integration::Detect},
        {"gvisor", "gVisor", "Sandboxing & isolation",
         "runsc runtime probed; sandboxed workloads tagged in attribution",
         {"runsc"}, {"/usr/local/bin/runsc"},
         {"--version"}, Integration::Detect},
        {"kata", "Kata Containers", "Sandboxing & isolation",
         "kata-runtime probed; VM-isolated workloads tagged in attribution",
         {"kata-runtime"}, {"/usr/share/kata-containers"},
         {"--version"}, Integration::Detect},
        {"qemu", "QEMU/KVM", "Sandboxing & isolation",
         "probed as the throwaway-VM analysis backend when present",
         {"qemu-system-x86_64"}, {"/dev/kvm"},
         {"--version"}, Integration::Detect},
        {"systemd-sandboxing", "systemd sandboxing", "Sandboxing & isolation",
         "`systemd-analyze security [UNIT]` on demand; exposure level reported verbatim",
         {"systemd-analyze"}, {"/usr/lib/systemd/system"},
         {"security", "--no-pager"}, Integration::Runner},

        // ---- 5. runtime monitoring & intrusion detection ---------------------
        {"falco", "Falco", "Runtime monitoring & IDS",
         "integrated sensor: Falco events consumed live with reconnect backoff",
         {"falco"}, {"/etc/falco/falco.yaml", "/etc/falco"},
         {}, Integration::Sensor},
        {"auditd", "auditd / Linux audit", "Runtime monitoring & IDS",
         "integrated sensor: NETLINK_AUDIT client, watch rules, auid attribution",
         {"auditctl", "auditd"}, {"/etc/audit/audit.rules", "/var/log/audit"},
         {}, Integration::BuiltIn},
        {"osquery", "osquery", "Runtime monitoring & IDS",
         "integrated sensor: pooled SQL queries through osqueryi/osqueryd socket",
         {"osqueryi", "osqueryd"}, {"/etc/osquery/osquery.conf", "/var/osquery"},
         {}, Integration::Sensor},
        {"wazuh", "Wazuh", "Runtime monitoring & IDS",
         "agent probed; HyprNova telemetry export to the Wazuh manager is the "
         "planned exporter path",
         {"agent_control", "/var/ossec/bin/agent_control"}, {"/var/ossec/etc/ossec.conf"},
         {}, Integration::Exporter},
        {"ossec", "OSSEC", "Runtime monitoring & IDS",
         "probed alongside Wazuh (same lineage, same /var/ossec layout)",
         {"/var/ossec/bin/ossec-control"}, {"/var/ossec/etc/ossec.conf"},
         {}, Integration::Detect},
        {"tetragon", "Tetragon", "Runtime monitoring & IDS",
         "eBPF policy engine probed; events dir watched when present",
         {"tetragon"}, {"/var/run/cilium/tetragon", "/etc/tetragon"},
         {}, Integration::Sensor},
        {"tracee", "Tracee", "Runtime monitoring & IDS",
         "Aqua eBPF tracer probed as an additional kernel-event source",
         {"tracee"}, {},
         {"--version"}, Integration::Sensor},
        {"crowdsec", "CrowdSec", "Runtime monitoring & IDS",
         "probed; cscli decisions are candidates for the network block pipeline",
         {"cscli"}, {"/etc/crowdsec", "/var/lib/crowdsec"},
         {"decisions", "list"}, Integration::Sensor},

        // ---- 6. online malware scanning & analysis APIs ----------------------
        {"virustotal", "VirusTotal", "Online analysis APIs",
         "hash lookups (SHA-256 only) through the system curl; key required, "
         "file upload is a separate default-off switch",
         {"curl"}, {},
         {}, Integration::Service},
        {"hybrid-analysis", "Hybrid Analysis", "Online analysis APIs",
         "deep links for quarantined samples; submission key-gated, upload off "
         "unless integrations.online_submission is true",
         {"curl"}, {},
         {}, Integration::Service},
        {"anyrun", "ANY.RUN", "Online analysis APIs",
         "interactive sandbox deep links per sample hash",
         {"curl"}, {},
         {}, Integration::Service},
        {"joesandbox", "Joe Sandbox", "Online analysis APIs",
         "deep links + optional submission when a key is configured",
         {"curl"}, {},
         {}, Integration::Service},

        // ---- 7. local malware analysis & reverse engineering -----------------
        {"cape", "CAPE Sandbox", "Local analysis & RE",
         "detected deployment (/opt/CAPEv2); submission util probed",
         {"cuckoo", "/opt/CAPEv2/cuckoo.py"}, {"/opt/CAPEv2", "/opt/cape"},
         {}, Integration::Analyzer},
        {"cuckoo", "Cuckoo Sandbox", "Local analysis & RE",
         "detected deployment; legacy automated analysis",
         {"cuckoo"}, {"/opt/cuckoo"},
         {}, Integration::Analyzer},
        {"capa", "MITRE capa", "Local analysis & RE",
         "capability detection for extracted samples, run on demand",
         {"capa"}, {},
         {"--version"}, Integration::Analyzer},
        {"ghidra", "Ghidra", "Local analysis & RE",
         "headless analyzer probed; 'open sample in Ghidra' console action",
         {"analyzeHeadless", "/opt/ghidra/analyzeHeadless"}, {"/opt/ghidra"},
         {}, Integration::Analyzer},
        {"radare2", "radare2", "Local analysis & RE",
         "probed for quick triage of quarantined samples",
         {"r2", "radare2"}, {},
         {"-v"}, Integration::Analyzer},
        {"strace", "strace", "Local analysis & RE",
         "on-demand attach to a suspect PID (operator-triggered, never automatic)",
         {"strace"}, {},
         {"-V"}, Integration::Analyzer},
        {"gdb", "GDB", "Local analysis & RE",
         "probed as the last-resort core-dump inspector",
         {"gdb"}, {},
         {"--version"}, Integration::Analyzer},

        // ---- 8. firewalls & network security ---------------------------------
        {"nftables", "nftables", "Firewalls & network security",
         "integrated enforcer: table rebuild with rollback, TTL blocks (Module 6)",
         {"nft"}, {"/etc/nftables.conf"},
         {}, Integration::BuiltIn},
        {"ufw", "UFW", "Firewalls & network security",
         "probed; status surfaced in the network page when present",
         {"ufw"}, {"/etc/ufw"},
         {"status"}, Integration::Detect, true},
        {"firewalld", "firewalld", "Firewalls & network security",
         "probed via firewall-cmd; zones surfaced when present",
         {"firewall-cmd"}, {"/etc/firewalld"},
         {"--state"}, Integration::Detect},
        {"suricata", "Suricata", "Firewalls & network security",
         "integrated sensor: EVE JSON tail, C2 beacon scoring",
         {"suricata"}, {"/var/log/suricata/eve.json", "/etc/suricata"},
         {}, Integration::Sensor},
        {"snort", "Snort", "Firewalls & network security",
         "probed; alert file watched when present",
         {"snort"}, {"/etc/snort", "/var/log/snort"},
         {"-V"}, Integration::Sensor},
        {"zeek", "Zeek", "Firewalls & network security",
         "probed; logs dir watched for conn/notice series when present",
         {"zeek"}, {"/opt/zeek", "/usr/local/zeek", "/var/log/zeek"},
         {"--version"}, Integration::Sensor},
        {"fail2ban", "Fail2ban", "Firewalls & network security",
         "probed; banned IPs surfaced and cross-checked against our blocks",
         {"fail2ban-client"}, {"/etc/fail2ban", "/var/run/fail2ban"},
         {"status"}, Integration::Sensor},
        {"opensnitch", "OpenSnitch", "Firewalls & network security",
         "probed; per-app egress rules complement our lineage heuristics",
         {"opensnitch-ui"}, {"/etc/opensnitchd", "/etc/opensnitch"},
         {}, Integration::Detect},
        {"wireguard", "WireGuard", "Firewalls & network security",
         "interfaces probed so remote management traffic is attributed",
         {"wg", "wg-quick"}, {"/etc/wireguard"},
         {"show"}, Integration::Detect, true},

        // ---- 9. vulnerability scanning & security auditing -------------------
        {"lynis", "Lynis", "Vulnerability & audit",
         "on-demand `lynis audit system`; hardening index parsed and tracked",
         {"lynis"}, {"/usr/sbin/lynis", "/opt/lynis"},
         {"audit", "system", "--quick", "--no-colors"}, Integration::Runner, true},
        {"openscap", "OpenSCAP", "Vulnerability & audit",
         "oscap probed; profile scans on demand with results parsed",
         {"oscap"}, {"/usr/share/xml/scap"},
         {"--version"}, Integration::Runner},
        {"openvas", "Greenbone / OpenVAS", "Vulnerability & audit",
         "probed; remote scan orchestration when the GVM stack exists",
         {"gvm-cli", "openvas", "gvmd"}, {"/etc/gvm", "/var/lib/gvm"},
         {}, Integration::Detect},
        {"nmap", "Nmap", "Vulnerability & audit",
         "on-demand local surface check against the host's own listeners",
         {"nmap"}, {},
         {"--version"}, Integration::Runner},
        {"nuclei", "Nuclei", "Vulnerability & audit",
         "probed; template scans are operator-triggered only",
         {"nuclei"}, {},
         {"-version"}, Integration::Runner},
        {"trivy", "Trivy", "Vulnerability & audit",
         "on-demand fs/rootfs scans; output kept verbatim for the journal",
         {"trivy"}, {},
         {"--version"}, Integration::Runner},
        {"grype", "Grype", "Vulnerability & audit",
         "probed; SBOM vulnerability scans on demand",
         {"grype"}, {},
         {"--version"}, Integration::Runner},
        {"osv-scanner", "OSV-Scanner", "Vulnerability & audit",
         "probed; dependency audit for managed dirs on demand",
         {"osv-scanner"}, {},
         {"--version"}, Integration::Runner},

        // ---- 10. file, disk & boot integrity ---------------------------------
        {"secure-boot", "Secure Boot / MOK", "File, disk & boot integrity",
         "integrated: UEFI SB state, setup mode, MOK list, sbctl (Module 1)",
         {"sbctl", "efibootmgr"}, {"/sys/firmware/efi/efivars"},
         {}, Integration::BuiltIn},
        {"tpm2", "TPM 2.0", "File, disk & boot integrity",
         "device + tools probed; PCR state read when tpm2_tools present",
         {"tpm2_getcap"}, {"/dev/tpmrm0", "/dev/tpm0"},
         {"-c", "properties-fixed"}, Integration::Detect},
        {"fs-verity", "fs-verity", "File, disk & boot integrity",
         "fsverity tool probed; protected-file enablement is a roadmap item",
         {"fsverity"}, {},
         {"version"}, Integration::Detect},
        {"dm-verity", "dm-verity", "File, disk & boot integrity",
         "veritysetup probed; root hash verification reported when configured",
         {"veritysetup"}, {},
         {"--version"}, Integration::Detect},
        {"ima", "IMA/EVM", "File, disk & boot integrity",
         "runtime measurement list probed; appraisal policy presence reported",
         {}, {"/sys/kernel/security/ima", "/sys/kernel/security/evm",
              "/sys/kernel/ima/ascii_runtime_measurements"},
         {}, Integration::Detect},

        // ---- 11. encryption & credential protection --------------------------
        {"luks", "LUKS / dm-crypt", "Encryption & credentials",
         "cryptsetup probed; block-device encryption surfaced in hardening",
         {"cryptsetup"}, {"/etc/crypttab"},
         {"--version"}, Integration::Detect},
        {"fscrypt", "fscrypt", "Encryption & credentials",
         "filesystem-level encryption probed (tool + config)",
         {"fscrypt"}, {"/etc/fscrypt.conf"},
         {"version"}, Integration::Detect},
        {"gnupg", "GnuPG", "Encryption & credentials",
         "probed; keyring presence feeds the credential-hygiene view",
         {"gpg", "gpg2"}, {"$HOME/.gnupg"},
         {"--version"}, Integration::Detect},
        {"age", "age", "Encryption & credentials",
         "probed as the modern file-encryption helper",
         {"age"}, {},
         {"--version"}, Integration::Detect},
        {"keepassxc", "KeePassXC", "Encryption & credentials",
         "probed; secret store hygiene noted in hardening",
         {"keepassxc", "keepassxc-cli"}, {},
         {"--version"}, Integration::Detect},
        {"gnome-keyring", "GNOME Keyring", "Encryption & credentials",
         "probed; secret service availability for desktop integration",
         {"gnome-keyring-daemon"}, {},
         {"--version"}, Integration::Detect},
        {"kwallet", "KWallet", "Encryption & credentials",
         "probed on KDE desktops",
         {"kwalletd", "kwalletd5"}, {},
         {}, Integration::Detect},

        // ---- 12. logging & security dashboards -------------------------------
        {"journald", "journald", "Logging & dashboards",
         "integrated: the daemon logs to stderr under systemd, journald captures",
         {"journalctl"}, {"/var/log/journal", "/run/log/journal"},
         {}, Integration::BuiltIn},
        {"rsyslog", "rsyslog", "Logging & dashboards",
         "probed; classic syslog shipping path for our journal",
         {"rsyslogd"}, {"/etc/rsyslog.conf"},
         {"-v"}, Integration::Exporter},
        {"elastic", "Elastic Stack", "Logging & dashboards",
         "probed; Filebeat/Elasticsearch export endpoints configurable",
         {"elasticsearch", "filebeat"}, {"/etc/elasticsearch", "/etc/filebeat"},
         {}, Integration::Exporter},
        {"graylog", "Graylog", "Logging & dashboards",
         "probed; GELF export endpoint configurable",
         {"graylogctl"}, {"/etc/graylog"},
         {}, Integration::Exporter},
        {"loki", "Grafana Loki", "Logging & dashboards",
         "probed; promtail/loki push export configurable",
         {"loki", "promtail"}, {"/etc/loki", "/etc/promtail"},
         {}, Integration::Exporter},
        {"openobserve", "OpenObserve", "Logging & dashboards",
         "probed; OTLP/HTTP export configurable",
         {"openobserve"}, {"/etc/openobserve", "/opt/openobserve"},
         {}, Integration::Exporter},
    };
    return reg;
}

std::string_view integration_note(Integration i) noexcept {
    switch (i) {
        case Integration::BuiltIn:  return "built into HyprNova";
        case Integration::Sensor:   return "telemetry source";
        case Integration::Runner:   return "on-demand runner";
        case Integration::Enforcer: return "enforcement backend";
        case Integration::Exporter: return "telemetry exporter";
        case Integration::Analyzer: return "offline analysis";
        case Integration::Service:  return "online API (key-gated)";
        case Integration::Detect:   return "inventory";
    }
    return "inventory";
}

/// Probe helper: first absolute executable among the candidates. Absolute
/// candidates are checked directly; bare names go through the trusted search.
std::string resolve_first(const std::vector<std::string>& binaries) noexcept {
    for (const auto& b : binaries) {
        if (!b.empty() && b[0] == '/') {
            if (core::exec::is_executable(b)) return b;
            continue;
        }
        if (auto p = core::exec::find_in_system_path(b); !p.empty()) return p;
        // sbin is root-only territory and often missing from a user PATH
        for (const auto& dir : kSbinDirs) {
            std::string cand = std::string(dir) + "/" + b;
            if (core::exec::is_executable(cand)) return cand;
        }
    }
    return {};
}

const ToolSpec* find_spec(std::string_view name) noexcept {
    for (const auto& spec : Toolbox::registry())
        if (spec.name == name) return &spec;
    return nullptr;
}

bool hex_sha256(std::string_view s) noexcept {
    return s.size() == 64 &&
           std::all_of(s.begin(), s.end(), [](unsigned char c) {
               return std::isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
           });
}

}  // namespace

// ---------------------------------------------------------------------------
// registry + probe
// ---------------------------------------------------------------------------

const std::vector<ToolSpec>& Toolbox::registry() noexcept { return build_registry(); }

std::string_view to_string(Integration i) noexcept { return integration_note(i); }

void Toolbox::probe() noexcept {
    const auto& reg = registry();
    states_.assign(reg.size(), ToolState{});

    for (std::size_t i = 0; i < reg.size(); ++i) {
        ToolState& st = states_[i];
        const ToolSpec& spec = reg[i];

        st.binary_path = resolve_first(spec.binaries);

        for (const auto& p : spec.paths) {
            std::string real = p;
            // $HOME expansion: the probe runs as the agent user
            if (real.starts_with("$HOME")) {
                if (const char* h = ::getenv("HOME")) real = std::string(h) + real.substr(5);
            }
            std::error_code ec;
            if (!real.empty() && fs::exists(real, ec)) st.paths_found.push_back(real);
        }

        st.installed = !st.binary_path.empty() || !st.paths_found.empty() ||
                       spec.integration == Integration::BuiltIn;

        // Notes make the matrix truthful rather than a wall of check marks.
        if (spec.integration == Integration::BuiltIn) {
            st.note = integration_note(spec.integration);
        } else if (!st.binary_path.empty()) {
            st.note = std::string(integration_note(spec.integration));
            if (spec.root_to_run) st.note += " (run as root)";
        } else if (!st.paths_found.empty()) {
            st.note = "config present, binary not in trusted path";
        } else {
            st.note = "not installed";
        }
    }
}

// ---------------------------------------------------------------------------
// parsers
// ---------------------------------------------------------------------------

std::vector<std::string> Toolbox::parse_rkhunter(std::string_view output) noexcept {
    // `rkhunter --check --nocolors` prints one "Warning: ..." (or "[ Warning ]")
    // line per finding; everything else is progress noise.
    std::vector<std::string> findings;
    for_each_line(output, [&](std::string_view line) {
        const auto t = trim_sv(line);
        if (t.starts_with("Warning:") || t.starts_with("[ Warning ]") ||
            t.find("Warning: ") != std::string_view::npos) {
            findings.push_back(clip(t, 220));
        }
    });
    return findings;
}

std::vector<std::string> Toolbox::parse_chkrootkit(std::string_view output) noexcept {
    // chkrootkit is silent-when-clean; infections print as "INFECTED: <test>"
    // (older builds: "<path> has rootkit hint").
    std::vector<std::string> findings;
    for_each_line(output, [&](std::string_view line) {
        const auto t = trim_sv(line);
        if (t.starts_with("INFECTED") ||
            t.find("has rootkit hint") != std::string_view::npos ||
            t.find("is infected") != std::string_view::npos) {
            findings.push_back(clip(t, 220));
        }
    });
    return findings;
}

std::vector<std::string> Toolbox::parse_clamav(std::string_view output) noexcept {
    // clamscan -r -i prints one line per hit: "<path>: <SIGNATURE> FOUND"
    std::vector<std::string> findings;
    for_each_line(output, [&](std::string_view line) {
        const auto t = trim_sv(line);
        if (t.ends_with("FOUND")) findings.push_back(clip(t, 300));
    });
    return findings;
}

std::vector<std::string> Toolbox::parse_kvrt(std::string_view output) noexcept {
    // KVRT console output is terse; the useful signals are detection lines and
    // the report path. Anything that names a detected object becomes a finding.
    std::vector<std::string> out;
    for_each_line(output, [&](std::string_view line) {
        const auto t = trim_sv(line);
        if (t.empty()) return;
        std::string low{t};
        std::transform(low.begin(), low.end(), low.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (low.find("detected") != std::string::npos ||
            low.find("infected") != std::string::npos ||
            low.find("suspicious") != std::string::npos ||
            low.find("deleted:") != std::string::npos) {
            if (out.size() < 50) out.emplace_back(t);
        }
    });
    return out;
}

std::vector<std::string> Toolbox::parse_pkg_verify(std::string_view backend,
                                                   std::string_view output) noexcept {
    // dpkg --verify:  "??5??????  /usr/bin/foo" | "missing /usr/bin/foo"
    // rpm -Va:        "SM5....T.  /usr/bin/x"  | "missing  /usr/bin/x"
    // pacman -Qkk:    "pkg 5.1: file ... "Modification time"/"Size" mismatch"
    // Classification: /etc (and a few documented-config dirs) are ADMIN change;
    // anything else under a package-owned path is UNEXPLAINED and matters.
    std::vector<std::string> out;
    auto classify = [&](std::string_view path) {
        static constexpr std::string_view kAdminPrefixes[] = {"/etc/", "/usr/share/", "/var/"};
        for (const auto p : kAdminPrefixes)
            if (path.starts_with(p)) return "ADMIN";
        return "UNEXPLAINED";
    };
    for_each_line(output, [&](std::string_view line) {
        const auto t = trim_sv(line);
        if (t.empty()) return;
        // dpkg / rpm "missing"
        std::string low{t};
        std::transform(low.begin(), low.end(), low.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const auto mis = low.find("missing ");
        if (mis != std::string::npos) {
            const auto path = trim_sv(t.substr(mis + 8));
            if (!path.empty() && out.size() < 50)
                out.push_back(std::format("[MISSING] package file deleted: {}", path));
            return;
        }
        // dpkg --verify: 9 verification chars, ' ' or code, then two spaces + path
        if (backend == "dpkg" && t.size() > 12 && t[9] == ' ' && t[10] == ' ' && t[11] == '/') {
            const auto path = trim_sv(t.substr(11));
            const auto codes = t.substr(0, 9);
            if (path.empty() || codes.find_first_not_of("? ") == std::string_view::npos) return;
            if (out.size() < 50)
                out.push_back(std::format("[{}] modified package file: {} (dpkg flags '{}')",
                                          classify(path), path, codes));
            return;
        }
        // rpm -Va: 9 flag chars then two spaces + path
        if (backend == "rpm" && t.size() > 12 && t[9] == ' ' && t[10] == ' ' && t[11] == '/') {
            const auto path = trim_sv(t.substr(11));
            const auto codes = t.substr(0, 9);
            if (path.empty() || codes.find_first_not_of(". ") == std::string_view::npos) return;
            if (out.size() < 50)
                out.push_back(std::format("[{}] modified package file: {} (rpm flags '{}')",
                                          classify(path), path, codes));
            return;
        }
        // pacman -Qkk: "name version: path: "check" failed" style lines
        if (backend == "pacman" && (low.find("mismatch") != std::string::npos ||
                                    low.find("missing") != std::string::npos)) {
            if (out.size() < 50) out.push_back(std::format("[UNEXPLAINED] {}", t));
            return;
        }
    });
    return out;
}

std::vector<std::string> Toolbox::parse_sshd_audit(std::string_view config_text) noexcept {
    std::vector<std::string> out;
    for (const auto& w : hardening::audit_sshd_config(config_text)) {
        std::string line = w.key;
        if (!w.value.empty()) line += "=" + w.value;
        line += " -- " + w.why;
        if (!w.fix.empty()) line += " [fix] " + w.fix;
        out.push_back(std::move(line));
    }
    return out;
}

std::vector<std::string> Toolbox::parse_crowdsec_decisions(std::string_view json_body) noexcept {
    // cscli decisions list -o json -> {"decisions":[{"value":"1.2.3.4",
    //   "type":"ban","reason":"...","until":"...","scope":"ip"},...]}
    std::vector<std::string> out;
    auto parsed = core::json::parse(json_body);
    if (!parsed) return out;
    const auto* arr = parsed->at("decisions");
    if (!arr || !arr->is_array()) return out;
    for (const auto& d : *arr->as_array()) {
        const auto value = d.at("value");
        const auto type = d.at("type");
        const auto reason = d.at("reason");
        const auto until = d.at("until");
        if (!value || !value->is_string()) continue;
        std::string line = std::format("[CROWDSEC {}] {}",
                                       type && type->is_string()
                                           ? std::string(type->as_string()).c_str()
                                           : "ban",
                                       std::string(value->as_string()).c_str());
        if (reason && reason->is_string() && !reason->as_string().empty())
            line += std::format(" -- {}", std::string(reason->as_string()).c_str());
        if (until && until->is_string())
            line += std::format(" (until {})", std::string(until->as_string()).c_str());
        if (out.size() < 50) out.push_back(std::move(line));
    }
    return out;
}

std::optional<long> Toolbox::parse_lynis_index(std::string_view output) noexcept {
    std::optional<long> out;
    for_each_line(output, [&](std::string_view line) {
        const auto t = trim_sv(line);
        // "Hardening index : 66"
        if (t.starts_with("Hardening index")) {
            const auto pos = t.find(':');
            if (pos == std::string_view::npos) return;
            const auto num = trim_sv(t.substr(pos + 1));
            long v = 0;
            const auto* first = num.data();
            const auto* last = num.data() + num.size();
            if (std::from_chars(first, last, v).ec == std::errc{} && v >= 0 && v <= 100)
                out = v;
        }
    });
    return out;
}

// ---------------------------------------------------------------------------
// /proc seccomp + capability audit (always available, zero dependencies)
// ---------------------------------------------------------------------------

ProcSecurity Toolbox::proc_security() noexcept {
    ProcSecurity ps;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator("/proc", ec)) {
        const std::string name = entry.path().filename().string();
        if (name.empty() || name[0] < '0' || name[0] > '9') continue;

        std::ifstream in(entry.path() / "status");
        if (!in) continue;
        std::string line, comm, uid_line, seccomp;
        while (std::getline(in, line)) {
            if (line.starts_with("Name:")) comm = std::string{trim_sv(line.substr(5))};
            else if (line.starts_with("Uid:")) uid_line = line;
            else if (line.starts_with("Seccomp:")) seccomp = std::string{trim_sv(line.substr(8))};
        }
        if (comm.empty()) continue;
        ++ps.processes;
        if (seccomp == "2") ++ps.seccomp_filter;
        else if (seccomp == "1") ++ps.seccomp_classic;
        else {
            ++ps.seccomp_none;
            // root-owned (first Uid field == 0) unfiltered processes are the
            // interesting ones for a kernel-exploit story.
            const auto u0 = uid_line.find_first_not_of("Uid:\t ");
            if (u0 != std::string::npos && uid_line[u0] == '0' &&
                ps.unfiltered_samples.size() < 8) {
                ps.unfiltered_samples.emplace_back(name, comm);
            }
        }
    }
    return ps;
}

// ---------------------------------------------------------------------------
// snapshot
// ---------------------------------------------------------------------------

core::json::Value Toolbox::snapshot_json() const noexcept {
    Object root;

    std::size_t found = 0, builtin = 0, runners = 0;
    std::vector<std::string> cat_names;   // registry order, deduped
    for (const auto& spec : registry()) {
        const std::string c{spec.category};
        if (std::find(cat_names.begin(), cat_names.end(), c) == cat_names.end())
            cat_names.push_back(c);
    }

    Array tools;
    const std::size_t n = std::min(registry().size(), states_.size());
    for (std::size_t i = 0; i < n; ++i) {
        const auto& spec = registry()[i];
        const auto& st = states_[i];
        if (st.installed) {
            ++found;
            if (spec.integration == Integration::BuiltIn) ++builtin;
            if (spec.integration == Integration::Runner && !st.binary_path.empty()) ++runners;
        }
        Object o;
        o["name"] = std::string(spec.name);
        o["label"] = std::string(spec.label);
        o["category"] = std::string(spec.category);
        o["role"] = std::string(spec.role);
        o["integration"] = std::string(integration_note(spec.integration));
        o["installed"] = st.installed;
        o["binary"] = st.binary_path;
        o["paths_found"] = Value{Array(st.paths_found.begin(), st.paths_found.end())};
        o["note"] = st.note;
        o["root_to_run"] = spec.root_to_run;
        tools.push_back(Value{std::move(o)});
    }

    Object summary;
    summary["total"] = static_cast<std::int64_t>(registry().size());
    summary["installed"] = static_cast<std::int64_t>(found);
    summary["builtin"] = static_cast<std::int64_t>(builtin);
    summary["runners_ready"] = static_cast<std::int64_t>(runners);
    summary["categories"] = Value{Array(cat_names.begin(), cat_names.end())};
    root["summary"] = Value{std::move(summary)};

    const auto sec = proc_security();
    Object psec;
    psec["processes"] = static_cast<std::int64_t>(sec.processes);
    psec["seccomp_filter"] = static_cast<std::int64_t>(sec.seccomp_filter);
    psec["seccomp_classic"] = static_cast<std::int64_t>(sec.seccomp_classic);
    psec["seccomp_none"] = static_cast<std::int64_t>(sec.seccomp_none);
    Array uns;
    for (const auto& [pid, comm] : sec.unfiltered_samples) {
        Object u;
        u["pid"] = pid;
        u["comm"] = comm;
        uns.push_back(Value{std::move(u)});
    }
    psec["unfiltered_root"] = Value{std::move(uns)};
    root["proc_security"] = Value{std::move(psec)};

    root["tools"] = Value{std::move(tools)};

    Object cfg;
    cfg["runners_enabled"] = cfg_.runner_enabled;
    cfg["tool_timeout_seconds"] = static_cast<std::int64_t>(cfg_.tool_timeout.count());
    cfg["virustotal_enabled"] = cfg_.virustotal_enabled && !cfg_.virustotal_api_key.empty();
    cfg["online_submission"] = cfg_.online_submission;
    root["policy"] = Value{std::move(cfg)};

    return Value{std::move(root)};
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

Toolbox::RunOutcome Toolbox::run_tool(std::string_view name,
                                      const std::vector<std::string>& args) noexcept {
    RunOutcome r;
    r.tool = std::string(name);

    if (!cfg_.runner_enabled) {
        r.error = "external runners are disabled by policy (integrations.runner_enabled)";
        return r;
    }
    const ToolSpec* spec = find_spec(name);
    if (!spec) {
        r.error = std::format("unknown tool '{}'; see `hyprnova-cli toolbox`", r.tool);
        return r;
    }
    if (states_.size() < registry().size()) probe();

    // Built-in tools need no binary: their logic lives in HyprNova.
    if (spec->integration == Integration::BuiltIn) {
        if (name == "sshd-config") {
            const std::string text = hardening::load_sshd_config();
            if (text.empty()) {
                r.error = "no readable /etc/ssh/sshd_config (openssh-server installed?)";
                return r;
            }
            r.findings = parse_sshd_audit(text);
            r.summary = std::format("sshd-config: {} weak setting(s)", r.findings.size());
            r.output = "(built-in audit of the effective first-wins config)";
            r.exit_code = 0;
            return r;
        }
        r.error = std::format("built-in tool '{}' has no runner", r.tool);
        return r;
    }

    // Re-resolve at run time: the binary could have appeared or vanished since
    // the last probe, and we must never execute a stale absolute path.
    const std::string binary = resolve_first(spec->binaries);
    if (binary.empty()) {
        r.error = std::format("{} is not installed on this host", std::string(spec->label));
        return r;
    }
    r.binary = binary;

    r.args = args.empty() ? spec->default_args : args;
    if (r.args.empty()) {
        r.error = std::format("{} requires arguments (e.g. a path to scan)", std::string(spec->label));
        return r;
    }

    core::exec::Options opts;
    opts.timeout = cfg_.tool_timeout;
    opts.max_output_bytes = cfg_.max_output_bytes;
    const auto res = core::exec::run(binary, r.args, opts);
    r.timed_out = res.timed_out;
    r.exit_code = res.exit_code;
    r.output = res.ok() ? res.out : (res.out.empty() ? res.err : res.out);
    if (res.timed_out) {
        r.error = std::format("timed out after {}s (killed, partial output kept)",
                              std::chrono::duration_cast<std::chrono::seconds>(opts.timeout).count());
        return r;
    }
    if (!res.spawned) {
        r.error = res.error.empty() ? "failed to spawn" : res.error;
        return r;
    }

    // Parse when we know how; summarise honestly when we do not.
    if (name == "rkhunter") {
        r.findings = parse_rkhunter(res.out);
        r.summary = std::format("rkhunter: {} warning(s)", r.findings.size());
    } else if (name == "chkrootkit") {
        r.findings = parse_chkrootkit(res.out);
        r.summary = r.findings.empty() ? std::string("chkrootkit: nothing reported INFECTED")
                                       : std::format("chkrootkit: {} INFECTED line(s)", r.findings.size());
    } else if (name == "clamav") {
        r.findings = parse_clamav(res.out);
        r.summary = std::format("clamav: {} hit(s)", r.findings.size());
    } else if (name == "kvrt") {
        r.findings = parse_kvrt(res.out);
        r.summary = std::format("kvrt: {} detection line(s)", r.findings.size());
    } else if (name == "crowdsec") {
        r.findings = parse_crowdsec_decisions(res.out);
        r.summary = std::format("crowdsec: {} active ban(s)", r.findings.size());
    } else if (name == "pkg-verify") {
        r.findings = parse_pkg_verify("dpkg", res.out);  // backend refined in combined_scan
        r.summary = std::format("pkg-verify: {} divergence(s)", r.findings.size());
    } else if (name == "lynis") {
        if (const auto idx = parse_lynis_index(res.out)) {
            r.summary = std::format("lynis: hardening index {}", *idx);
            r.findings.push_back(std::format("hardening index: {}", *idx));
        } else {
            r.summary = "lynis: audit finished (no index line found)";
        }
    } else {
        r.summary = std::format("{} exited with code {}", r.tool, res.exit_code);
    }

    r.ok = res.exit_code == 0 || !r.findings.empty() ||
           (name == "lynis" && parse_lynis_index(res.out).has_value());
    return r;
}

// ---------------------------------------------------------------------------
// combined scanning (Module 8b)
// ---------------------------------------------------------------------------

Toolbox::~Toolbox() = default;

void Toolbox::set_internal_scanner(std::shared_ptr<remediation::ScannerBridge> s) noexcept {
    engine_ = std::move(s);
}

core::json::Value Toolbox::CombinedReport::to_json() const noexcept {
    using core::json::Array;
    using core::json::Object;
    using core::json::Value;
    Object root;
    root["profile"] = profile;
    root["target"] = target;
    root["total_findings"] = static_cast<std::int64_t>(total_findings);
    root["malicious"] = static_cast<std::int64_t>(malicious);
    root["verdict"] = verdict;
    root["summary"] = summary;
    root["ok"] = ok;
    root["elapsed_ms"] = static_cast<std::int64_t>(elapsed.count());
    if (!error.empty()) root["error"] = error;

    Array secs;
    for (const auto& s : sections) {
        Object o;
        o["tool"] = s.tool;
        o["label"] = s.label;
        o["ran"] = s.ran;
        o["ok"] = s.ok;
        o["exit_code"] = static_cast<std::int64_t>(s.exit_code);
        o["findings"] = Value{Array(s.findings.begin(), s.findings.end())};
        o["note"] = s.note;
        secs.push_back(Value{std::move(o)});
    }
    root["sections"] = Value{std::move(secs)};
    return Value{std::move(root)};
}

void expand_targets(const std::vector<std::string>& requested,
                    std::vector<std::string>& files_out, std::string& label) noexcept {
    // Directory expansion with the same caps as a sweep: a runaway tree must
    // not turn an operator-initiated scan into a whole-day event.
    constexpr std::size_t kMaxFiles = 20000;
    constexpr int kMaxDepth = 8;
    namespace fs = std::filesystem;
    std::error_code ec;
    std::size_t dirs = 0;
    // Self-exclusion prefixes: the shadow store, the quarantine dir, the rescue
    // staging area and the pseudo-filesystems are never scanned. Scanning our
    // own recovery data would (a) waste the budget and (b) let a false
    // positive DAMAGE the lifeline -- the one mistake this product must never
    // make. (Supply-chain rule: no exclusions file that malware could edit;
    // these are compiled in.)
    static const std::string_view kSkipPrefixes[] = {
        "/proc", "/sys", "/dev", "/run", "/boot/hyprnova", "/var/lib/hyprnova",
    };
    auto skipped = [&](const std::string& p) {
        for (const auto pre : kSkipPrefixes) {
            if (p == pre) return true;
            if (p.starts_with(pre) && p.size() > pre.size() && p[pre.size()] == '/') return true;
        }
        return false;
    };

    for (const auto& raw : requested) {
        if (raw.empty() || skipped(raw)) continue;
        const fs::path p{raw};
        if (!fs::exists(p, ec)) continue;
        if (fs::is_regular_file(p, ec)) {
            files_out.push_back(raw);
            continue;
        }
        ++dirs;
        for (auto it = fs::recursive_directory_iterator(
                 p, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (it.depth() > kMaxDepth || files_out.size() >= kMaxFiles) break;
            if (it->is_symlink(ec) || !it->is_regular_file(ec)) continue;
            auto ps = it->path().string();
            if (skipped(ps)) continue;
            files_out.push_back(std::move(ps));
        }
    }
    label = dirs > 0
              ? std::format("{} director{}, {} files", dirs, dirs == 1 ? "y" : "ies", files_out.size())
              : std::format("{} file(s)", files_out.size());
}

Toolbox::CombinedReport Toolbox::combined_scan(
    std::string_view profile, const std::vector<std::string>& paths) noexcept {
    CombinedReport r;
    r.profile = std::string(profile);
    if (!valid_profile(profile)) {
        r.error = std::format("unknown profile '{}': quick | deep | kernel | audit", r.profile);
        return r;
    }
    if (states_.size() < registry().size()) probe();
    const auto started = std::chrono::steady_clock::now();
    auto finish = [&] {
        r.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started);
        r.total_findings = 0;
        r.malicious = 0;
        for (const auto& s : r.sections) {
            r.total_findings += s.findings.size();
            // "malicious" counts only high-confidence results: AV FOUND lines
            // and rootkit warnings. The engine's own hits stay "suspicious" --
            // they are heuristics, and the verdict words must mean what they say.
            if (s.tool == "clamav" || s.tool == "rkhunter" || s.tool == "chkrootkit" ||
                s.tool == "kvrt")
                r.malicious += s.findings.size();
        }
        r.verdict = r.malicious > 0        ? "INFECTED"
                  : r.total_findings > 0 ? "suspicious"
                                         : "clean";
        r.ok = true;
        r.summary = std::format("{} scan ({}): {} -- {} finding(s){}", profile, r.target,
                                r.verdict, r.total_findings,
                                r.malicious > 0
                                    ? std::format(", {} HIGH-CONFIDENCE", r.malicious)
                                    : std::string());
    };

    auto sec = [&]() -> CombinedSection& {
        r.sections.emplace_back();
        return r.sections.back();
    };

    // ---- engine-based profiles -------------------------------------------
    if (profile == "quick" || profile == "deep") {
        std::vector<std::string> requested = paths;
        if (requested.empty()) {
            for (const auto* d : {"/home", "/tmp", "/dev/shm", "/var/tmp"})
                if (core::fsx::exists(d)) requested.emplace_back(d);
        }
        std::vector<std::string> files;
        expand_targets(requested, files, r.target);
        if (profile == "deep" && paths.empty()) {
            for (const auto* d : {"/opt", "/srv", "/root"})
                if (core::fsx::exists(d)) expand_targets({d}, files, r.target);
        }

        auto& engine_sec = sec();
        engine_sec.tool = "engine";
        engine_sec.label = std::format("in-tree YaraLite + Aho-Corasick over {}", r.target);
        if (engine_) {
            engine_sec.ran = true;
            constexpr std::size_t kChunk = 512;
            for (std::size_t i = 0; i < files.size(); i += kChunk) {
                const auto end = std::min(files.size(), i + kChunk);
                const std::vector<std::string> chunk(files.begin() + static_cast<long>(i),
                                                     files.begin() + static_cast<long>(end));
                for (auto& d : engine_->scan_paths(chunk))
                    engine_sec.findings.push_back(std::move(d));
            }
            engine_sec.ok = true;
        } else {
            engine_sec.note = "scanner module unavailable (sensor disabled?)";
        }

        auto add_tool = [&](std::string_view name, const std::vector<std::string>& args,
                            const char* label) {
            auto& s = sec();
            s.tool = std::string(name);
            s.label = label;
            const ToolSpec* spec = find_spec(name);
            const std::string bin =
                resolve_first(spec ? spec->binaries : std::vector<std::string>{});
            if (bin.empty()) {
                s.note = "not installed on this host";
                return;
            }
            core::exec::Options opts;
            opts.timeout = cfg_.tool_timeout;
            opts.max_output_bytes = cfg_.max_output_bytes;
            const auto res = core::exec::run(bin, args.empty() ? spec->default_args : args, opts);
            s.ran = true;
            s.exit_code = res.exit_code;
            if (res.timed_out) {
                s.note = "timed out";
                return;
            }
            if (name == "clamav") {
                s.findings = parse_clamav(res.out);
                s.ok = true;
            } else if (name == "rkhunter") {
                s.findings = parse_rkhunter(res.out);
                s.ok = true;
            } else if (name == "chkrootkit") {
                s.findings = parse_chkrootkit(res.out);
                s.ok = true;
            } else if (name == "maldet") {
                s.ok = res.exit_code == 0;
                for_each_line(res.out, [&](std::string_view line) {
                    if (line.find("{ HIT }") != std::string_view::npos ||
                        line.find("MALWARE") != std::string_view::npos)
                        s.findings.push_back(std::string{trim_sv(line)});
                });
            } else if (name == "aide") {
                s.ok = res.exit_code == 0;
                if (res.exit_code != 0)
                    for_each_line(res.out, [&](std::string_view line) {
                        const auto t = trim_sv(line);
                        if ((t.find("added:") != std::string_view::npos ||
                             t.find("changed:") != std::string_view::npos ||
                             t.find("removed:") != std::string_view::npos) &&
                            s.findings.size() < 50)
                            s.findings.push_back(std::string{t});
                    });
            } else {
                s.ok = res.exit_code == 0;
            }
        };

        add_tool("clamav", {"-r", "--infected", "--suppress-ok-results"},
                 "ClamAV recursive scan of the same targets");
        // KVRT is the DEFAULT second-opinion engine for every filesystem scan
        // (quick and deep alike): the operator asked for Kaspersky-class
        // coverage without a second product install. Absent -> honest note
        // with the fetch script; never a silent skip.
        add_tool("kvrt", {}, "KVRT full second opinion (default AV engine)");
        if (profile == "deep") {
            add_tool("rkhunter", {}, "Rootkit Hunter full check");
            add_tool("chkrootkit", {}, "chkrootkit sweep");
            add_tool("aide", {}, "AIDE integrity check against its database");
            add_tool("maldet", {"-a", "/home"}, "LMD scan of /home");
        }
        finish();
        return r;
    }

    // ---- package integrity + crowdsec (deep + audit) ---------------------
    if (profile == "deep" || profile == "audit") {
        // Package-manager verify: the supply-chain tripwire. Every file a
        // package owns is checksummed against the local DB.
        {
            auto& s2 = sec();
            s2.tool = "pkg-verify";
            s2.label = "package-manager integrity (dpkg/rpm/pacman)";
            const char* backends[][2] = {
                {"/usr/bin/dpkg", "--verify"},
                {"/usr/bin/rpm", "-Va"},
                {"/usr/bin/pacman", "-Qkk"},
            };
            for (const auto& b : backends) {
                if (!core::fsx::exists(b[0])) continue;
                core::exec::Options opts;
                opts.timeout = std::chrono::seconds{120};
                opts.max_output_bytes = cfg_.max_output_bytes;
                const auto res = core::exec::run(b[0], {b[1]}, opts);
                s2.ran = true;
                s2.exit_code = res.exit_code;
                for (auto& f2 : parse_pkg_verify(
                         std::filesystem::path{b[0]}.filename().string(), res.out))
                    s2.findings.push_back(std::move(f2));
                s2.ok = true;
                break;  // one package manager governs this host
            }
            if (!s2.ran) s2.note = "no supported package manager found";
        }
        // CrowdSec: the community zero-day tripwire. Read-only here: active
        // bans, their reasons and expiries.
        {
            auto& s3 = sec();
            s3.tool = "crowdsec";
            s3.label = "CrowdSec community ban decisions (cscli)";
            const ToolSpec* spec = find_spec("crowdsec");
            const std::string bin = resolve_first(spec ? spec->binaries
                                                       : std::vector<std::string>{});
            if (bin.empty()) {
                s3.note = "cscli not installed -- crowdsec agent absent; install it to join "
                          "the community blocklist (scripts/install-deps.sh hints)";
            } else {
                core::exec::Options opts;
                opts.timeout = std::chrono::seconds{30};
                const auto res = core::exec::run(bin, {"decisions", "list", "-o", "json"}, opts);
                s3.ran = true;
                s3.exit_code = res.exit_code;
                s3.findings = parse_crowdsec_decisions(res.out);
                s3.ok = true;
                if (s3.findings.empty()) s3.note = "no active bans (or LAPI unreachable)";
            }
        }
        // SSH weak-settings audit: the built-in parser, report-only.
        {
            auto& s4 = sec();
            s4.tool = "sshd-config";
            s4.label = "SSH weak-settings audit (built-in, report-only)";
            const std::string text = hardening::load_sshd_config();
            if (text.empty()) {
                s4.note = "no readable /etc/ssh/sshd_config (no SSH server, or perms) -- skipped";
            } else {
                s4.ran = true;
                s4.ok = true;
                s4.findings = parse_sshd_audit(text);
                if (s4.findings.empty())
                    s4.note = "no weak settings found in the effective config";
            }
        }
    }

    // ---- kernel (rootkit focus) ------------------------------------------
    if (profile == "kernel") {
        r.target = "kernel state";
        auto add_tool = [&](std::string_view name, const char* label) {
            auto& s = sec();
            s.tool = std::string(name);
            s.label = label;
            const ToolSpec* spec = find_spec(name);
            const std::string bin =
                resolve_first(spec ? spec->binaries : std::vector<std::string>{});
            if (bin.empty()) {
                s.note = "not installed on this host";
                return;
            }
            core::exec::Options opts;
            opts.timeout = cfg_.tool_timeout;
            const auto res = core::exec::run(bin, spec->default_args, opts);
            s.ran = true;
            s.exit_code = res.exit_code;
            s.findings = name == "rkhunter" ? parse_rkhunter(res.out)
                                            : parse_chkrootkit(res.out);
            s.ok = true;
        };
        add_tool("rkhunter", "Rootkit Hunter kernel/userland checks");
        add_tool("chkrootkit", "chkrootkit sweep");

        auto& taint = sec();
        taint.tool = "taint";
        taint.label = "kernel taint bits (/proc/sys/kernel/tainted)";
        if (const long t = kernel_taint(); t != 0) {
            taint.ran = true;
            taint.ok = true;
            taint.findings.push_back(std::format(
                "kernel is TAINTED ({:#x}) -- see the Hardening page for the bit meanings", t));
        } else {
            taint.ran = true;
            taint.ok = true;
            taint.note = "taint 0 -- clean";
        }

        auto& psec = sec();
        psec.tool = "seccomp";
        psec.label = "/proc seccomp posture of every process";
        const auto ps = proc_security();
        psec.ran = true;
        psec.ok = true;
        psec.findings.push_back(std::format("{} processes: {} seccomp-filtered, {} unfiltered",
                                            ps.processes, ps.seccomp_filter, ps.seccomp_none));
        for (const auto& [pid, comm] : ps.unfiltered_samples)
            psec.findings.push_back(std::format("root process without seccomp: pid {} {}", pid, comm));
        finish();
        return r;
    }

    // ---- audit ------------------------------------------------------------
    r.target = "system audit";
    auto& lynis = sec();
    lynis.tool = "lynis";
    lynis.label = "Lynis system audit (hardening index)";
    {
        const ToolSpec* spec = find_spec("lynis");
        const std::string bin = resolve_first(spec ? spec->binaries : std::vector<std::string>{});
        if (bin.empty()) lynis.note = "not installed on this host";
        else {
            core::exec::Options opts;
            opts.timeout = cfg_.tool_timeout;
            const auto res = core::exec::run(bin, spec->default_args, opts);
            lynis.ran = true;
            lynis.ok = true;
            if (const auto idx = parse_lynis_index(res.out))
                lynis.findings.push_back(std::format("hardening index: {}", *idx));
            else lynis.note = "no index line in output";
        }
    }

    auto& sd = sec();
    sd.tool = "systemd";
    sd.label = "systemd unit sandboxing (systemd-analyze security)";
    for (const auto& u : systemd_security(0)) {
        sd.ran = true;
        if (u.exposure >= 5.0)
            sd.findings.push_back(std::format("{}: exposure {:.1f} ({})", u.unit, u.exposure,
                                              u.grade));
    }
    if (sd.ran) sd.ok = true;
    else sd.note = "systemd-analyze not available";
    finish();
    return r;
}

// ---------------------------------------------------------------------------
// systemd security (Module 8c)
// ---------------------------------------------------------------------------

std::vector<Toolbox::SystemdUnit> Toolbox::parse_systemd_table(
    std::string_view output) noexcept {
    // "chrony.service   3.5  OK    :-)" -- unit, exposure, grade, face.
    std::vector<SystemdUnit> out;
    for_each_line(output, [&](std::string_view line) {
        const auto t = trim_sv(line);
        if (!t.ends_with(":-)") && !t.ends_with(":-|") && !t.ends_with(":-{")) return;
        const auto unit_end = t.find_first_of(" \t");
        if (unit_end == std::string_view::npos) return;
        SystemdUnit u;
        u.unit = std::string{t.substr(0, unit_end)};
        if (u.unit.empty() || u.unit[0] < 'a') return;
        const auto rest = trim_sv(t.substr(unit_end));
        double v = 0.0;
        const auto* first = rest.data();
        const auto* last = rest.data() + rest.size();
        if (std::from_chars(first, last, v).ec != std::errc{}) return;
        u.exposure = v;
        u.grade = v >= 9.0 ? "UNSAFE" : v >= 7.0 ? "EXPOSED" : v >= 4.0 ? "MEDIUM" : "OK";
        out.push_back(std::move(u));
    });
    std::sort(out.begin(), out.end(),
              [](const auto& a, const auto& b) { return a.exposure > b.exposure; });
    return out;
}

std::vector<Toolbox::SystemdUnit> Toolbox::systemd_security(int detail_units) noexcept {
    const std::string analyze =
        resolve_first({"systemd-analyze", "/usr/bin/systemd-analyze"});
    if (analyze.empty()) return {};

    core::exec::Options opts;
    opts.timeout = std::chrono::seconds{60};
    const auto table = core::exec::run(analyze, {"security", "--no-pager"}, opts);
    if (!table.ok() && table.out.empty()) return {};
    auto units = parse_systemd_table(table.out);

    // Per-unit detail for the worst few units: the "✗" lines are concrete,
    // actionable sandboxing suggestions straight from systemd.
    int done = 0;
    for (auto& u : units) {
        if (done >= detail_units) break;
        if (u.exposure < 5.0) break;
        if (u.unit.find('@') != std::string::npos) continue;   // template instances
        core::exec::Options o2;
        o2.timeout = std::chrono::seconds{30};
        const auto detail = core::exec::run(analyze, {"security", "--no-pager", u.unit}, o2);
        if (!detail.ok() && detail.out.empty()) continue;
        for_each_line(detail.out, [&](std::string_view line) {
            const auto t = trim_sv(line);
            // systemd-analyze prints UTF-6 cross marks on a TTY and plain
            // "- " markers when piped; both mean "insecure".
            const bool insecure =
                t.starts_with("✗") || t.starts_with("- ") ||
                t.starts_with("\u2717");
            if (insecure && u.suggestions.size() < 8)
                u.suggestions.emplace_back(t.substr(2));
        });
        if (u.suggestions.empty())
            u.suggestions.push_back("overall exposure high (no per-line detail)");
        ++done;
    }
    return units;
}

long Toolbox::kernel_taint() noexcept {
    const std::string v = core::fsx::read_trimmed("/proc/sys/kernel/tainted");
    if (v.empty()) return 0;
    long t = 0;
    if (std::from_chars(v.data(), v.data() + v.size(), t).ec != std::errc{}) return 0;
    return t;
}

std::optional<core::json::Value> Toolbox::parse_rescue_report(std::string_view path) noexcept {
    std::ifstream in{std::string(path)};
    if (!in) return std::nullopt;
    // GCC 14 -Wnull-dereference fires on the istreambuf_iterator string ctor
    // here (streambuf:492/495) after full inlining; libstdc++ guarantees the
    // iterator is never null for an open stream. Scoped suppression with the
    // reason -- core/fsx read-with-cap would work, but the parsing contract
    // for this file is "slurp then parse", and the noise is stdlib-internal.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnull-dereference"
#endif
    std::string body{(std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()};
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
    auto v = core::json::parse(body);
    if (!v || !v->is_object()) return std::nullopt;
    return v;
}

// ---------------------------------------------------------------------------
// VirusTotal
// ---------------------------------------------------------------------------

std::optional<Toolbox::RunOutcome> Toolbox::parse_vt_json(std::string_view body) noexcept {
    auto v = core::json::parse(body);
    if (!v || !v->is_object()) return std::nullopt;

    RunOutcome r;
    const auto stats = v->integer("data.attributes.last_analysis_stats.malicious", -1);
    const auto susp = v->integer("data.attributes.last_analysis_stats.suspicious", -1);
    if (stats < 0) return std::nullopt;
    const std::string name = v->str("data.attributes.meaningful_name", "(unnamed)");

    r.findings.push_back(std::format("file: {}", name));
    r.findings.push_back(std::format("engines flagging malicious: {}", stats));
    r.findings.push_back(std::format("engines flagging suspicious: {}", susp));
    if (stats > 0 || susp > 0) {
        r.summary = std::format("VirusTotal: MALICIOUS ({} malicious, {} suspicious)", stats, susp);
    } else {
        r.summary = "VirusTotal: no engine currently flags this hash";
    }
    r.ok = true;
    return r;
}

Toolbox::RunOutcome Toolbox::vt_lookup(std::string_view sha256_hex) noexcept {
    RunOutcome r;
    r.tool = "virustotal";

    if (!hex_sha256(sha256_hex)) {
        r.error = "pass a SHA-256 hash (64 hex characters); hashes only -- HyprNova "
                  "never uploads file contents without integrations.online_submission";
        return r;
    }
    if (!cfg_.virustotal_enabled || cfg_.virustotal_api_key.empty()) {
        r.error = "VirusTotal is disabled: set integrations.virustotal_enabled=true and "
                  "integrations.virustotal_api_key in the agent config";
        return r;
    }
    const std::string curl = resolve_first({"curl", "/usr/bin/curl", "/usr/local/bin/curl"});
    if (curl.empty()) {
        r.error = "curl not found in the trusted path (the lookup shell is deliberately "
                  "not used -- no popen, no /bin/sh)";
        return r;
    }

    core::exec::Options opts;
    opts.timeout = std::chrono::seconds{20};
    opts.max_output_bytes = 1 << 20;
    const std::string url = std::format("https://www.virustotal.com/api/v3/files/{}",
                                        std::string(sha256_hex));
    const auto res = core::exec::run(curl, {"-sS", "-H",
                                            "x-apikey: " + cfg_.virustotal_api_key,
                                            url},
                                     opts);
    if (!res.spawned) {
        r.error = res.error.empty() ? "failed to spawn curl" : res.error;
        return r;
    }
    if (res.timed_out) {
        r.error = "VirusTotal lookup timed out after 20s";
        return r;
    }
    if (res.exit_code != 0) {
        r.error = std::format("curl exit {}: {}", res.exit_code,
                              clip(trim_sv(res.err.empty() ? res.out : res.err), 200));
        return r;
    }
    if (res.out.find("\"error\"") != std::string::npos &&
        res.out.find("NotFoundError") != std::string::npos) {
        r.ok = true;
        r.summary = "VirusTotal: hash unknown (never seen -- suspicious in itself for executables)";
        return r;
    }
    if (const auto parsed = parse_vt_json(res.out)) {
        r.ok = parsed->ok;
        r.summary = parsed->summary;
        r.findings = parsed->findings;
        return r;
    }
    r.error = "could not parse the VirusTotal response (API change?)";
    return r;
}

}  // namespace hyprnova::tools
