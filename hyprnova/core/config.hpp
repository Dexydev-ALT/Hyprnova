// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/config.hpp
// Typed, validated runtime configuration.
//
// Loaded from /etc/hyprnova/agent.json, overridable per-field by CLI flags and
// by SIGHUP-triggered reload. Every module takes a const reference to a fully
// validated Config: no module reads environment variables or files itself, which
// keeps the trust boundary in exactly one place.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/event.hpp"
#include "core/json.hpp"
#include "core/log.hpp"

namespace hyprnova::core {

using namespace std::chrono_literals;

struct ScanRoot {
    std::string path;
    bool recursive{true};
    bool on_write_only{true};  // inotify-triggered vs. full sweep
    std::string label;
};

struct BootIntegrityConfig {
    bool enabled{true};
    bool require_secure_boot{false};          // warn vs. hard-fail
    std::vector<std::string> efi_var_paths{"/sys/firmware/efi/efivars"};
    std::vector<std::string> sbctl_paths{"/usr/bin/sbctl", "/bin/sbctl"};
    std::string baseline_path{"/var/lib/hyprnova/boot-baseline.json"};
    bool verify_initramfs{true};
    std::vector<std::string> initramfs_paths{"/boot/initramfs-linux.img", "/boot/initrd.img"};
    bool audit_kernel_cmdline{true};
    /// Parameters that weaken the kernel if present.
    std::vector<std::string> forbidden_cmdline{"init=/bin/bash", "rd.break", "single",
                                               "systemd.debug_shell=1", "lsm=", "apparmor=0",
                                               "selinux=0", "audit=0", "module.sig_enforce=0",
                                               "lockdown=none", "iomem=relaxed", "kasan=off"};
    /// Parameters that should be present on a hardened fleet.
    std::vector<std::string> expected_cmdline{"init_on_alloc=1", "init_on_free=1",
                                              "slab_nomerge", "page_alloc.shuffle=1",
                                              "randomize_kstack_offset=1", "vsyscall=none",
                                              "debugfs=none", "oops=panic", "module.sig_enforce=1",
                                              "lockdown=confidentiality", "mce=0", "quiet"};
};

struct KernelHardeningConfig {
    bool enabled{true};
    /// sysctl path -> required value. Drift raises a HardeningDrift event.
    std::vector<std::pair<std::string, std::string>> sysctls{
        {"kernel.randomize_va_space", "2"},
        {"kernel.yama.ptrace_scope", "2"},
        {"kernel.kptr_restrict", "2"},
        {"kernel.dmesg_restrict", "1"},
        {"kernel.unprivileged_bpf_disabled", "1"},
        {"kernel.perf_event_paranoid", "3"},
        {"kernel.panic_on_warn", "0"},
        {"net.ipv4.conf.all.rp_filter", "1"},
        {"net.ipv4.conf.all.accept_redirects", "0"},
        {"net.ipv4.conf.all.send_redirects", "0"},
        {"net.ipv4.conf.all.accept_source_route", "0"},
        {"net.ipv4.conf.all.log_martians", "1"},
        {"net.ipv4.tcp_syncookies", "1"},
        {"net.ipv6.conf.all.accept_redirects", "0"},
        {"fs.protected_hardlinks", "1"},
        {"fs.protected_symlinks", "1"},
        {"fs.suid_dumpable", "0"},
        {"user.max_user_namespaces", "15000"},
    };
    /// Values that are acceptable *alternatives* (e.g. ptrace_scope 1 on a dev box).
    std::vector<std::pair<std::string, std::vector<std::string>>> sysctl_alternatives{
        {"kernel.yama.ptrace_scope", {"1", "2", "3"}},
    };
    std::string lockdown_path{"/sys/kernel/security/lockdown"};
    std::vector<std::string> acceptable_lockdown{"[integrity]", "[confidentiality]"};
    bool require_lockdown{false};
    std::string ksplice_marker{"/sys/kernel/ksplice"};
    bool flag_ksplice{true};  // live kernel patching == integrity baseline is stale
    std::chrono::seconds rescan_interval{6h};
};

struct MacProfileConfig {
    bool enabled{true};
    std::string apparmor_root{"/sys/kernel/security/apparmor"};
    bool require_apparmor_enforce{false};
    std::string selinux_path{"/sys/fs/selinux/enforce"};
    /// Daemons that MUST have a confining profile in enforce mode.
    std::vector<std::string> critical_daemons{"sshd", "nginx", "httpd", "apache2", "vsftpd",
                                              "proftpd", "smbd", "named", "postfix", "dovecot",
                                              "redis-server", "mysqld", "postgres"};
    bool audit_unconfined_daemons{true};
    /// Directories holding trusted AppArmor profiles for other apps -- written by
    /// the distribution, a vendor, or another trusted party, and dropped here for
    /// the agent to (a) count and report, and (b) flag any daemon that has a
    /// profile available but is running UNCONFINED anyway. The agent never edits
    /// or loads these itself; loading stays the admin's `apparmor_parser` call.
    std::vector<std::string> profile_dirs{"/etc/hyprnova/apparmor.d"};
};

struct CanaryConfig {
    bool enabled{true};
    std::string key_path{"/var/lib/hyprnova/canary.key"};
    /// Directories scanned for homes to plant canaries under.
    std::vector<std::string> home_roots{"/home"};
    std::vector<std::string> extra_roots{"/tmp", "/var/tmp", "/var/www", "/srv", "/opt", "/usr/share"};
    std::string subdir{".canaries"};
    std::size_t canaries_per_root{5};
    std::string prefix{"invoice_2024_Q"};  // bait naming that ransomware sorts first
    std::vector<std::string> extensions{".docx", ".pdf", ".xlsx", ".odt", ".txt", ".csv"};
    bool hidden_files{true};                 // also plant dot-prefixed decoys
    std::chrono::seconds resign_interval{24h};
    std::chrono::seconds integrity_check_interval{30s};
    /// Honeypot decoy configs (fake credentials) planted in state_dir/honeypots.
    bool honeypots_enabled{true};
    /// fanotify/inotify mask we care about for canaries.
    bool monitor_access{true};   // IN_ACCESS: a read of every canary is ransomware enumeration
    bool monitor_modify{true};
    bool monitor_delete{true};
    bool monitor_move{true};
    /// Any access to a canary by a non-allowlisted process is suspicious.
    std::vector<std::string> reader_allowlist{"hyprnovad", "hyprnova-gui", "grep", "find", "ls"};
};

struct RansomwareConfig {
    bool enabled{true};
    /// Shannon entropy above which a written buffer looks encrypted.
    double entropy_threshold{7.4};
    /// Only buffers of at least this size are entropy-analysed (avoids noise on
    /// small metadata writes).
    std::size_t min_entropy_bytes{1024};
    /// Writes per actor within the window that constitute "mass modification".
    std::size_t mass_modify_file_threshold{10};
    std::chrono::milliseconds mass_modify_window{500ms};
    /// Auto-SIGSTOP on mass modification. Off => observe-only (recommended for
    /// the first 30 days of a fleet rollout).
    bool auto_suspend{true};
    bool auto_suspend_unprivileged_only{true};
    /// Sustained high-entropy write rate to ransomware-target flavours.
    std::size_t entropy_burst_files{5};
    std::chrono::seconds entropy_burst_window{3s};
    /// Known-encoder extension patterns appended by ransomware families.
    std::vector<std::string> suspicious_extensions{".locked", ".encrypted", ".enc", ".crypt",
                                                   ".wncry", ".locky", ".zepto", ".djvu",
                                                   ".phobos", ".makop", ".888", ".pay"};
    /// Ransom note filenames.
    std::vector<std::string> ransom_note_names{"README_RESTORE", "HOW_TO_DECRYPT", "_readme.txt",
                                                "RESTORE_FILES", "DECRYPT_INFO", "ransom_note",
                                                "!RECOVER", "YOUR_FILES_ARE_ENCRYPTED"};
    bool detect_ransom_notes{true};
    bool detect_vss_deletion{true};  // vssadmin / shadow copy deletion analogues on Linux
    std::vector<std::string> backup_destroy_cmds{"rm -rf /backup", "rm -rf /var/backups",
                                                 "wipefs", "dd if=/dev/zero", "shred -u",
                                                 "truncate -s 0 /var/backups"};
};

enum class ScanBackend : std::uint8_t { YaraLite = 0, LibYara, ClamAv, Kvrt };

/// File carving (spec 5E). Strictly opt-in: OFF unless the operator turns it
/// on, because carving reads whole files and writes derived copies.
struct CarveConfig {
    bool enabled{false};
    std::size_t max_artifact_bytes{32ull << 20};  // one artifact cap
    std::size_t max_artifacts{64};                // per source file cap
    std::string out_dir{"carved"};                // relative to state_dir
};

struct ScanConfig {
    bool enabled{true};
    std::vector<ScanRoot> roots{
        {"/home", true, false, "user-homes"},
        {"/tmp", true, true, "world-writable-tmp"},
        {"/var/tmp", true, true, "world-writable-vartmp"},
        {"/dev/shm", true, true, "memory-fs"},
        {"/usr/local/bin", true, true, "local-binaries"},
        {"/opt", true, false, "opt"},
    };
    std::vector<std::string> download_suffixes{"/Downloads", "/downloads", "/.downloads"};
    std::size_t max_file_bytes{256ull << 20};
    std::size_t min_file_bytes{64};
    std::vector<std::string> skip_extensions{".mp4", ".mkv", ".avi", ".iso", ".img", ".vmdk",
                                             ".qcow2", ".vdi", ".snap"};
    std::vector<std::string> skip_dirs{"/proc", "/sys", "/dev", "/run", ".git", "node_modules",
                                       ".cache", "__pycache__", ".venv", "venv", ".cargo"};

    // YARA
    std::vector<std::string> rule_files{"/etc/hyprnova/rules/hyprnova-lite.yar",
                                        "/etc/hyprnova/rules/hyprnova-ioc.yar"};
    ScanBackend backend{ScanBackend::YaraLite};
    std::string libyara_rules_dir{"/etc/hyprnova/rules/yara"};
    std::size_t yara_timeout_ms{3000};

    // Batch queue
    std::chrono::seconds batch_flush_interval{15s};
    std::size_t batch_max_paths{512};
    std::string kvrt_path{"/opt/kvrt/kvrt.run"};
    std::vector<std::string> kvrt_args{"-customlist", "-customonly", "-q"};
    std::string clamdscan_path{"/usr/bin/clamdscan"};
    std::vector<std::string> clamdscan_args{"--fdpass", "--multiscan", "--no-summary", "--file-list="};
    bool prefer_clamd{true};
    std::chrono::seconds clamd_timeout{120s};
    std::chrono::seconds kvrt_timeout{600s};
    bool use_list_file{true};  // write paths to a 0600 list file rather than argv (ARG_MAX + privacy)

    // Worker pool
    std::size_t scan_workers{4};
    std::size_t scan_queue_depth{8192};
    bool hash_cache{true};
    std::size_t hash_cache_entries{200000};

    CarveConfig carve;  // spec 5E: embedded-artifact carving, opt-in
};

struct FalcoConfig {
    bool enabled{true};
    std::string socket_path{"/var/run/falco.sock"};
    std::string grpc_socket{"/run/falco/falco.sock"};
    std::chrono::seconds reconnect_backoff_max{60s};
    std::chrono::milliseconds poll_timeout{200ms};
    std::size_t max_line_bytes{1 << 20};
    /// Falco priorities we surface (drop Debug/Informational by default).
    std::vector<std::string> interesting_priorities{"Notice", "Warning", "Error", "Critical",
                                                    "Alert", "Emergency"};
    /// Falco rule -> our EventKind mapping.
    std::vector<std::pair<std::string, EventKind>> rule_map{
        {"Terminal shell in container", EventKind::TtyFromDaemon},
        {"Run shell untrusted", EventKind::ProcExec},
        {"Write below etc", EventKind::FileWrite},
        {"Read sensitive file untrusted", EventKind::ShadowAccess},
        {"Unexpected UDP traffic", EventKind::NetC2Suspect},
        {"Contact K8S API Server From Container", EventKind::NetConnect},
        {"Launch Privileged Container", EventKind::PrivEscalation},
        {"Load Kernel Module", EventKind::KernelModuleLoad},
        {"Schedule Cron Jobs", EventKind::ProcAnomaly},
        {"Delete Bash History", EventKind::FileDelete},
        {"Redirect STDOUT/STDIN to Network Connection", EventKind::NetC2Suspect},
        {"Container Drift Detected", EventKind::ProcAnomaly},
    };
};

/// Module 4b: /proc polling. fanotify and audit netlink need privileges; a
/// plain directory sweep of /proc does not. Every new pid (or a pid whose start
/// time changed, i.e. it re-exec'd) is attributed and its executable pushed
/// through the on-demand scanner. This is the exec-visibility fallback that
/// keeps real-time behavioural response working for unprivileged installs --
/// with the honest limit that a process that execs and exits inside one poll
/// interval is never seen.
struct ProcPollConfig {
    bool enabled{true};
    std::chrono::milliseconds interval{250ms};
    /// Same-path scan cooldown: a path scanned this recently is not re-read
    /// (fork servers and build systems exec the same binaries constantly).
    std::chrono::milliseconds rescan_cooldown{2s};
};

struct AuditdConfig {
    bool enabled{true};
    bool use_netlink{true};
    std::string fallback_log{"/var/log/audit/audit.log"};
    std::vector<std::string> watch_paths{"/etc/shadow", "/etc/passwd", "/etc/sudoers",
                                         "/etc/sudoers.d", "/etc/pam.d", "/etc/ssh/sshd_config",
                                         "/root/.ssh/authorized_keys", "/etc/crontab", "/etc/cron.d",
                                         "/etc/systemd/system", "/boot", "/etc/ld.so.preload",
                                         "/lib/modules"};
    std::vector<std::string> privileged_cmds{"sudo", "su", "pkexec", "doas", "run0", "newgrp"};
    bool detect_sudo_abuse{true};
    /// sudo invoked with these flags is high severity.
    std::vector<std::string> sudo_red_flags{"-i", "-s", "NOPASSWD", "-E", "env_reset=off"};
    std::size_t netlink_buf_bytes{1 << 20};
    bool emit_all_auid_changes{false};
};

struct OsqueryConfig {
    bool enabled{false};
    std::string osqueryi_path{"/usr/bin/osqueryi"};
    std::chrono::seconds query_interval{60s};
    std::chrono::seconds query_timeout{20s};
    /// Named query -> SQL. Results become TelemetryEvents.
    std::vector<std::pair<std::string, std::string>> queries{
        {"procs_in_tmp",
         "select pid,name,path,uid from processes where path like '/tmp/%' or path like '/dev/shm/%' "
         "or path like '/var/tmp/%' or path like '/home/%/%';"},
        {"listening_ports",
         "select pid,port,address,protocol from listening_ports where port != 0;"},
        {"socket_to_process",
         "select p.name,p.path,s.remote_address,s.remote_port,s.state from process_open_sockets s "
         "join processes p on p.pid=s.pid where s.remote_port != 0 and s.state='ESTABLISHED';"},
        {"kern_modules_unsigned", "select name,size,status from kernel_modules;"},
        {"suid_binaries", "select * from suid_bin;"},
        {"crontab_entries", "select * from crontab;"},
        {"deleted_exes",
         "select pid,name,path from processes where path = '' or path is null;"},  // exe unlinked:
        // a running process whose executable no longer exists is either patched in place or deleted
        // after launch; /etc/ld.so.preload is covered by the auditd watch instead
        {"startup_items", "select name,path,source,status from startup_items;"},
        {"logged_in_users", "select user,tty,host,pid from logged_in_users;"},
        {"shell_history_grep",
         "select username,command from shell_history where command like '%curl%|%base64 -d%' "
         "or command like '%chmod +x /tmp%' or command like '%nc -e%' limit 200;"},
    };
};

struct SuricataConfig {
    bool enabled{false};
    std::string eve_path{"/var/log/suricata/eve.json"};
    std::string eve_socket;  // optional UNIX socket EVE output
    std::chrono::milliseconds poll_interval{500ms};
    double c2_beacon_score_threshold{0.65};
    /// Regular-interval small-payload connections are the beacon signature.
    std::chrono::seconds beacon_window{300s};
    std::size_t beacon_min_hits{5};
    double beacon_interval_jitter_max{0.15};  // 15% jitter == machine, not human
};

struct HeuristicConfig {
    bool enabled{true};
    std::chrono::seconds decay_window{300s};   // risk score half-life window
    double risk_decay_per_second{0.35};
    std::uint16_t alert_threshold{450};        // 0..1000
    std::uint16_t critical_threshold{750};
    std::uint16_t auto_respond_threshold{850}; // only above this may Module 6 act alone
    bool auto_respond{false};                  // default: human-in-the-loop

    // Anomalous SSH / service spawn detection
    bool detect_ssh_anomaly{true};
    std::size_t ssh_spawn_burst{6};
    std::chrono::seconds ssh_spawn_window{60s};
    std::vector<std::string> web_daemons{"nginx", "apache2", "httpd", "php-fpm", "node", "java",
                                         "tomcat", "uwsgi", "gunicorn", "caddy", "lighttpd"};
    std::vector<std::string> shells{"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh",
                                    "/usr/bin/perl", "/usr/bin/python", "/usr/bin/python3",
                                    "/usr/bin/ruby", "/usr/bin/php", "/bin/nc", "/usr/bin/socat"};
    bool detect_tty_from_daemon{true};

    // Unexpected children
    std::vector<std::pair<std::string, std::vector<std::string>>> forbidden_children{
        {"sshd", {"wget", "curl", "python", "python3", "perl", "nc", "ncat", "socat", "bash", "sh"}},
        {"nginx", {"sh", "bash", "wget", "curl", "python3", "nc"}},
        {"apache2", {"sh", "bash", "wget", "curl", "python3", "nc"}},
        {"php-fpm", {"sh", "bash", "wget", "curl", "nc", "python3"}},
        {"mysqld", {"sh", "bash", "wget", "curl", "nc"}},
        {"postgres", {"sh", "bash", "wget", "curl", "nc"}},
        {"redis-server", {"sh", "bash", "wget", "curl", "nc", "python3"}},
        {"systemd", {"wget", "curl", "nc"}},
    };

    // Baseline learning
    bool learn_baseline{true};
    std::string baseline_path{"/var/lib/hyprnova/baseline.json"};
    std::chrono::hours baseline_learning_period{72h};
    /// During learning, findings are emitted at reduced severity and never auto-responded.
    bool suppress_actions_during_learning{true};
    /// Per-app behaviour profiles (JSON, written by a trusted third party):
    /// {"app": "nginx", "allowed_children": ["php-fpm"], "forbidden_children": ["curl"]}.
    /// allowed_children are exempt from the forbidden-pair check; forbidden_children
    /// add app-specific pairs on top of the global list.
    std::string profiles_dir{"/etc/hyprnova/profiles"};
};

/// Shadow-copy (snapshot/restore) policy. A snapshot is taken at every agent
/// start and on demand; retention keeps the newest `keep` and deletes the rest.
/// Roots are usually config + rules; the agent's state directory is always
/// included implicitly, so the canary key and baselines survive a very bad host.
struct ShadowConfig {
    bool enabled{true};
    std::vector<std::string> roots{"/etc/hyprnova"};
    std::size_t keep{5};
    std::uint64_t max_snapshot_bytes{512ull << 20};
    std::size_t max_files{20000};
};
struct RemediationConfig {
    bool enabled{true};
    bool allow_kill{true};
    bool allow_suspend{true};
    bool allow_network_block{true};
    bool allow_quarantine{true};
    std::string quarantine_dir{"/var/lib/hyprnova/quarantine"};
    /// Never touch these; a false positive here is an outage.
    std::vector<pid_t> protected_pids{1};
    std::vector<std::string> protected_processes{"systemd", "init", "kthreadd", "hyprnovad",
                                                 "hyprnova-gui", "sshd", "dbus-daemon", "udevd",
                                                 "journald", "NetworkManager", "kernel"};
    std::vector<std::string> protected_paths{"/usr/lib/systemd", "/usr/bin/systemd", "/sbin/init",
                                             "/usr/bin/bash", "/usr/lib/hyprnova"};
    bool protect_pid1_descendants{true};
    std::chrono::seconds block_duration{24h};
    std::string nftables_table{"hyprnova_edr"};
    /// Per-executable network policy (the "unknown exe phoning home" case):
    /// contain a whole executable -- its pid tree, in a cgroup -- behind an
    /// nftables `socket cgroupv2` drop, instead of blocking one endpoint at a
    /// time. Needs BOTH nftables and a writable cgroup v2 hierarchy.
    bool allow_exe_block{true};
    /// Automatic escalation (one exe -> N distinct C2 endpoints => block the
    /// exe) defaults OFF: containment of everything an exe may ever dial is a
    /// human decision. When off, the agent only recommends the block.
    bool auto_block_by_exe{false};
    /// Distinct blocked endpoints from one executable before escalation.
    int exe_block_after_endpoints{2};
    std::string nft_cli{"/usr/sbin/nft"};
    bool use_libnftables{true};   // compiled in when HYPRNOVA_HAVE_LIBNFTABLES
    std::string iptables_fallback{"/usr/sbin/iptables"};
    /// cgroup containment: move a suspect into a frozen, cpu-starved cgroup
    /// instead of killing it, so forensics remain possible.
    bool use_cgroup_containment{true};
    std::string cgroup_root{"/sys/fs/cgroup/hyprnova_quarantine"};
    bool freeze_cgroup{true};
    std::string notify_summary{"HyprNova Anti-Malware Sec"};
    bool desktop_notifications{true};
    std::string notify_send{"/usr/bin/notify-send"};
};

struct GuiConfig {
    bool enabled{true};
    std::string ipc_socket{"/run/hyprnova/gui.sock"};
    /// Operator group for the IPC socket (root installs chown the socket to
    /// this group; members may connect). Empty disables group auth. The group
    /// is resolved at start; an absent group is an honest log line, never an
    /// error — same-uid auth continues to apply.
    std::string ipc_group{"hyprnova"};
    bool start_with_agent{true};
    std::string theme{"midnight"};
    int telemetry_hz{4};             // GUI refresh rate; never above 10
    std::size_t event_feed_max{2000};
    bool show_kernel_events{false};  // hides noise by default
    /// Vibrancy: frameless window with a rounded, semi-transparent base plate.
    /// Elements and text are always opaque; only the shell backdrop is
    /// translucent. Requires a compositor -- without one Qt renders opaque and
    /// everything still works, just without the see-through.
    bool vibrancy{true};
    std::string wayland_display_override;
};

/// Ecosystem integrations: probing the installed tool set, external on-demand
/// runners and the key-gated online services (Module 8, the Toolbox).
struct IntegrationsConfig {
    bool enabled{true};                 // probe the ecosystem at startup
    bool runner_enabled{true};          // allow `tool-run` to launch registered tools
    std::chrono::seconds tool_timeout{300s};
    std::size_t max_output_bytes{4ull << 20};
    /// VirusTotal v3 hash lookups. Hash-only: file contents never leave the host
    /// through this path.
    bool virustotal_enabled{false};
    std::string virustotal_api_key;
    /// Master privacy gate for uploading samples to ANY.RUN / Joe Sandbox /
    /// Hybrid Analysis. Default off -- samples can contain secrets; that call
    /// belongs to the machine's owner.
    bool online_submission{false};
    /// CrowdSec: read community/local ban decisions via cscli and push our own
    /// C2 blocks back so every HyprNova host strengthens the community
    /// blocklist. Read-only unless a C2 block succeeds locally.
    bool crowdsec_enabled{true};
};

/// AI analyst (Groq). Disabled and inert until the operator consents with a key.
struct AiConfig {
    bool enabled{false};
    std::string provider{"groq"};
    std::string api_key;                       // never logged, never dumped
    std::string model{"llama-3.3-70b-versatile"};
    std::chrono::seconds timeout{45s};
    std::size_t max_answer_tokens{1024};
    std::string request_temp_path{"/var/lib/hyprnova/ai-request.json"};
};

/// Rescue-environment boot: reboot-scanning for host-owned-the-kernel rootkits.
struct RescueConfig {
    bool enabled{false};                 // arming is an explicit operator decision
    std::string iso_path;                // operator-supplied rescue ISO
    std::string boot_dir{"/boot/hyprnova"};
    std::string grub_entry_file{"/etc/grub.d/41_hyprnova-rescue"};
    std::string entry_title{"HyprNova Anti-Malware Sec -- Rescue"};
    bool auto_reboot{false};             // allow `rescue-boot` to reboot immediately
};

struct AgentConfig {
    std::string instance_id;
    std::string version{"1.0.0"};
    LogLevel log_level{LogLevel::Info};
    /// Daemon log file. journald captures stdout anyway when run under systemd,
    /// but a rotated file is what survives a journald vacuum and what an air-gapped
    /// site can actually collect.
    std::string log_path{"/var/log/hyprnova/agent.log"};
    std::size_t log_max_bytes{16ull << 20};
    /// Also write to stderr; useful under systemd and useless when daemonised.
    bool log_to_stderr{true};
    std::string state_dir{"/var/lib/hyprnova"};
    std::string run_dir{"/run/hyprnova"};
    std::string forensic_journal{"/var/lib/hyprnova/journal.ndjson"};
    std::size_t journal_max_bytes{512ull << 20};
    bool forensic_journal_enabled{true};
    std::chrono::seconds heartbeat_interval{30s};
    /// Depth of the EventBus SPSC ring. Sized for a burst of ~65k kernel events
    /// (an `rm -rf` on a home dir) without back-pressuring the sensor threads.
    std::size_t bus_ring_depth{65536};
    bool dry_run{false};  // observe-only: no signals, no firewall, no quarantine
    bool self_test_on_start{true};

    BootIntegrityConfig boot;
    KernelHardeningConfig hardening;
    MacProfileConfig mac;
    CanaryConfig canary;
    RansomwareConfig ransomware;
    ScanConfig scan;
    FalcoConfig falco;
    ProcPollConfig proc_poll;
    AuditdConfig auditd;
    OsqueryConfig osquery;
    SuricataConfig suricata;
    HeuristicConfig heuristic;
    RemediationConfig remediation;
    ShadowConfig shadow;
    GuiConfig gui;
    IntegrationsConfig integrations;
    RescueConfig rescue;
    AiConfig ai;
};

struct ConfigError {
    std::string path;
    std::string message;
};

/// Validate an already-loaded config in place. `validate()` also *repairs* a few
/// things that are unsafe rather than merely wrong (e.g. clamps a scan root of "/"
/// away, forces `allow_kill=false` under dry_run) so callers cannot forget.
void validate(AgentConfig& c, std::vector<ConfigError>& errors);

/// Serialise the effective configuration back to JSON. Used by --dump-config, by
/// the GUI's configuration panel, and by save_config().
[[nodiscard]] json::Value to_json(const AgentConfig& cfg) noexcept;

/// Load + validate. On any validation failure the returned optional is empty and
/// `errors` explains why; the agent then refuses to start rather than running
/// with a silently wrong policy (a blind EDR is worse than a stopped one).
[[nodiscard]] std::optional<AgentConfig> load_config(const std::string& path,
                                                     std::vector<ConfigError>* errors = nullptr) noexcept;

/// Built-in defaults, valid on a typical systemd Linux desktop/server.
[[nodiscard]] AgentConfig default_config() noexcept;

[[nodiscard]] bool save_config(const AgentConfig& cfg, const std::string& path) noexcept;

/// Human-readable summary printed by `hyprnovad --print-config`.
[[nodiscard]] std::string describe(const AgentConfig& cfg);

}  // namespace hyprnova::core
