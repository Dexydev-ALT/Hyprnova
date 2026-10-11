// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 1b implementation

#include "hardening/kernel_hardening.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <format>
#include <fstream>
#include <sys/stat.h>
#include <thread>

#include "core/fd.hpp"
#include "core/hash.hpp"

namespace hyprnova::hardening {

namespace fsx = core::fsx;
using namespace std::string_view_literals;

// ---------------------------------------------------------------------------
// sysctl plumbing
// ---------------------------------------------------------------------------

std::string sysctl_to_proc_path(std::string_view name) {
    std::string p{name};
    std::replace(p.begin(), p.end(), '.', '/');
    // A few names live outside the /proc/sys/<dotted> mapping.
    if (p == "init_on_alloc" || p == "init_on_free") return "/sys/kernel/mm/" + p;
    return "/proc/sys/" + p;
}

std::optional<std::string> read_sysctl(std::string_view name) noexcept {
    const std::string path = sysctl_to_proc_path(name);
    std::string v;
    if (fsx::read_file(path, v, 4096) < 0) return std::nullopt;
    while (!v.empty() && (v.back() == '\n' || v.back() == '\r' || v.back() == ' ' || v.back() == '\t'))
        v.pop_back();
    return v;
}

std::string_view sysctl_rationale(std::string_view name) noexcept {
    struct Entry { std::string_view name; std::string_view why; };
    static constexpr Entry kTable[] = {
        {"kernel.randomize_va_space",
         "ASLR. Level 2 randomises stack, mmap, brk and VDSO. Below 2, use-after-free and stack "
         "overflow exploitation becomes materially easier."},
        {"kernel.yama.ptrace_scope",
         "Restricts PTRACE_ATTACH. 0 lets any same-uid process read another's memory, which is how "
         "credential stealers harvest SSH agents and browsers. 2 blocks all non-root tracing."},
        {"kernel.kptr_restrict",
         "Hides kernel symbol addresses from /proc/kallsyms. Leaked pointers defeat KASLR, which "
         "is the prerequisite for most modern kernel exploits."},
        {"kernel.dmesg_restrict",
         "dmesg routinely leaks kernel pointers and hardware details to unprivileged users."},
        {"kernel.unprivileged_bpf_disabled",
         "Unprivileged eBPF has been the source of multiple local privilege escalation CVEs. Only "
         "root (and this agent) should be loading programs."},
        {"kernel.perf_event_paranoid",
         "perf_event_open exposes cross-process sampling and kernel PMU counters usable for "
         "side-channel attacks and process fingerprinting."},
        {"net.ipv4.conf.all.rp_filter",
         "Reverse-path filtering drops asymmetric-source spoofed packets, the first line of "
         "defence against IP-spoofed lateral movement."},
        {"net.ipv4.conf.all.accept_redirects",
         "ICMP redirects let an on-link attacker silently rewrite your routing table."},
        {"net.ipv4.conf.all.send_redirects",
         "This host should not be acting as a router for its neighbours."},
        {"net.ipv4.conf.all.accept_source_route",
         "Source-routed packets bypass routing policy and are a classic firewall-evasion vector."},
        {"net.ipv4.conf.all.log_martians",
         "Logs packets with impossible source addresses -- a cheap early indicator of spoofing or "
         "misconfigured tunnelling into your segment."},
        {"net.ipv4.tcp_syncookies",
         "Keeps listening sockets survivable under SYN-flood."},
        {"net.ipv6.conf.all.accept_redirects",
         "IPv6 redirect acceptance, same class of attack as IPv4."},
        {"fs.protected_hardlinks",
         "Prevents hardlinking a file you cannot read: the classic /etc/shadow-in-world-writable-dir "
         "privilege escalation."},
        {"fs.protected_symlinks",
         "Blocks symlink-following in world-writable sticky dirs, removing a large family of /tmp "
         "race conditions."},
        {"fs.suid_dumpable",
         "Core dumps of setuid processes leak the memory of privileged programs into readable files."},
        {"user.max_user_namespaces",
         "Unbounded user namespaces are the entry point for most unprivileged kernel exploits "
         "(the LPE surface of the last five years is overwhelmingly userns-reachable)."},
    };
    for (const auto& e : kTable) {
        if (e.name == name) return e.why;
    }
    return "Policy-defined hardening knob.";
}

std::string_view sysctl_remediation(std::string_view name, std::string_view value) noexcept {
    static thread_local std::string buf;
    buf = std::string(name) + " = " + std::string(value);
    return buf;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

namespace {

core::Severity severity_for_drift(std::string_view name) noexcept {
    // Not all knobs are equal: these are the ones that turn a hard exploit into
    // a trivial one.
    static constexpr std::string_view kCritical[] = {
        "kernel.randomize_va_space", "kernel.unprivileged_bpf_disabled", "fs.suid_dumpable",
        "fs.protected_symlinks", "fs.protected_hardlinks", "kernel.yama.ptrace_scope"};
    static constexpr std::string_view kHigh[] = {
        "kernel.kptr_restrict", "kernel.dmesg_restrict", "kernel.perf_event_paranoid",
        "net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.all.rp_filter"};
    for (const auto c : kCritical) {
        if (c == name) return core::Severity::Critical;
    }
    for (const auto c : kHigh) {
        if (c == name) return core::Severity::High;
    }
    return core::Severity::Medium;
}

}  // namespace

std::vector<SysctlCheck> verify_sysctls(const core::KernelHardeningConfig& cfg) noexcept {
    std::vector<SysctlCheck> out;
    out.reserve(cfg.sysctls.size());

    for (const auto& [name, expected] : cfg.sysctls) {
        SysctlCheck c;
        c.sysctl_name = name;
        c.path = sysctl_to_proc_path(name);
        c.expected = expected;
        c.rationale = std::string(sysctl_rationale(name));
        c.remediation = std::string(sysctl_remediation(name, expected));

        const auto actual = read_sysctl(name);
        if (!actual) {
            // Absent knob. For most of these that means an old kernel; for a few
            // it means the feature was compiled out, which is itself the finding.
            c.verdict = SysctlVerdict::Missing;
            c.severity = core::Severity::Low;
            c.actual = "(absent)";
            if (name == "kernel.unprivileged_bpf_disabled") {
                c.severity = core::Severity::High;
                c.rationale += " The knob is absent, which on most kernels means unprivileged BPF is "
                               "compiled in and NOT gated at all.";
            }
        } else {
            c.actual = *actual;
            if (*actual == expected) {
                c.verdict = SysctlVerdict::Compliant;
            } else {
                // Accept an explicitly allowlisted alternative before calling drift.
                bool alt = false;
                for (const auto& [altname, vals] : cfg.sysctl_alternatives) {
                    if (altname != name) continue;
                    for (const auto& v : vals) {
                        if (v == *actual) { alt = true; break; }
                    }
                    if (alt) break;
                }
                if (alt) {
                    c.verdict = SysctlVerdict::Acceptable;
                } else {
                    c.verdict = SysctlVerdict::Drift;
                    c.severity = severity_for_drift(name);
                }
            }
        }
        out.push_back(std::move(c));
    }
    return out;
}

LockdownStatus verify_lockdown(const core::KernelHardeningConfig& cfg) noexcept {
    LockdownStatus s;
    std::string raw;
    if (fsx::read_file(cfg.lockdown_path, raw, 256) < 0) {
        s.mode = LockdownMode::Unavailable;
        s.raw = "(unreadable)";
        s.findings.push_back("Kernel lockdown state is unavailable (" + cfg.lockdown_path +
                             "). Either CONFIG_SECURITY_LOCKDOWN_LSM is not enabled or securityfs "
                             "is not mounted at /sys/kernel/security.");
        s.compliant = !cfg.require_lockdown;
        return s;
    }
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r')) raw.pop_back();
    s.raw = raw;

    // Format: "none [integrity] confidentiality" -- the bracketed one is active.
    if (raw.find("[confidentiality]") != std::string::npos) s.mode = LockdownMode::Confidentiality;
    else if (raw.find("[integrity]") != std::string::npos) s.mode = LockdownMode::Integrity;
    else if (raw.find("[none]") != std::string::npos) s.mode = LockdownMode::None;
    else s.mode = LockdownMode::Unavailable;

    bool acceptable = false;
    for (const auto& a : cfg.acceptable_lockdown) {
        if (raw.find(a) != std::string::npos) { acceptable = true; break; }
    }
    s.compliant = acceptable;

    switch (s.mode) {
        case LockdownMode::None:
            s.findings.push_back("Kernel lockdown is NONE: root can write to /dev/mem, /dev/kmem, "
                                 "load unsigned modules and read MSR/PCI config space. Full kernel "
                                 "compromise from any root foothold.");
            break;
        case LockdownMode::Integrity:
            s.findings.push_back("Kernel lockdown is INTEGRITY: kernel-image modification is blocked, "
                                 "but confidentiality-level restrictions (MSR, /dev/mem reads, "
                                 "kprobes on arbitrary addresses) are not.");
            break;
        case LockdownMode::Confidentiality:
            break;
        case LockdownMode::Unavailable:
            break;
    }
    if (!s.compliant && cfg.require_lockdown) {
        s.findings.push_back("Policy requires lockdown in one of: " +
                             [&] {
                                 std::string j;
                                 for (const auto& a : cfg.acceptable_lockdown) { if (!j.empty()) j += ", "; j += a; }
                                 return j;
                             }());
    }
    return s;
}

AslrStatus verify_aslr_and_introspection() noexcept {
    AslrStatus a;
    auto rd = [](std::string_view n) -> int {
        if (auto v = read_sysctl(n)) {
            int i = 0;
            if (std::sscanf(v->c_str(), "%d", &i) == 1) return i;
        }
        return -1;
    };
    a.randomize_va_space = rd("kernel.randomize_va_space");
    a.ptrace_scope = rd("kernel.yama.ptrace_scope");
    a.kptr_restrict = rd("kernel.kptr_restrict");
    a.dmesg_restrict = rd("kernel.dmesg_restrict");
    a.unprivileged_bpf_disabled = rd("kernel.unprivileged_bpf_disabled");
    a.perf_event_paranoid = rd("kernel.perf_event_paranoid");
    a.suid_dumpable = rd("fs.suid_dumpable");
    a.protected_symlinks = rd("fs.protected_symlinks");
    a.protected_hardlinks = rd("fs.protected_hardlinks");
    a.unprivileged_userns = rd("user.max_user_namespaces");

    int score = 0;
    if (a.randomize_va_space == 2) score += 25;
    else if (a.randomize_va_space == 1) { score += 10; a.findings.push_back("ASLR is partial (1); set kernel.randomize_va_space=2"); }
    else if (a.randomize_va_space == 0) a.findings.push_back("ASLR is DISABLED");

    if (a.ptrace_scope >= 2) score += 20;
    else if (a.ptrace_scope == 1) { score += 10; a.findings.push_back("ptrace_scope=1 still allows same-uid process memory reads"); }
    else a.findings.push_back("ptrace_scope=0: any same-uid process may ptrace another (credential theft)");

    if (a.kptr_restrict >= 1) score += 10;
    if (a.dmesg_restrict == 1) score += 10;
    else a.findings.push_back("dmesg is world-readable and routinely leaks kernel pointers");

    if (a.unprivileged_bpf_disabled == 1) score += 15;
    else a.findings.push_back("Unprivileged eBPF is permitted: the single largest source of "
                              "unprivileged-to-root CVEs in recent kernels");

    if (a.perf_event_paranoid >= 3) score += 10;
    else if (a.perf_event_paranoid >= 2) score += 5;

    if (a.suid_dumpable == 0) score += 5;
    else a.findings.push_back("fs.suid_dumpable != 0: setuid process memory may be dumped to disk");

    if (a.protected_symlinks == 1 && a.protected_hardlinks == 1) score += 5;
    else a.findings.push_back("fs.protected_symlinks/hardlinks not both enabled: /tmp race conditions");

    if (a.unprivileged_userns >= 0 && a.unprivileged_userns <= 15000) {
        // Non-zero and bounded is the pragmatic target; a value of 0 breaks
        // containers and browsers, so we do not demand it.
        score += 0;
    }
    a.score = std::clamp(score, 0, 100);
    return a;
}

LivePatchStatus verify_live_patching(const core::KernelHardeningConfig& cfg) noexcept {
    LivePatchStatus s;
    s.ksplice_present = fsx::is_dir(cfg.ksplice_marker) || fsx::exists("/usr/sbin/ksplice-uptrack");
    s.kpatch_present = fsx::exists("/usr/sbin/kpatch") || fsx::is_dir("/var/lib/kpatch");

    // sysfs livepatch interface is the authoritative source.
    if (fsx::is_dir("/sys/kernel/livepatch")) {
        s.livepatch_enabled = true;
        core::UniqueDir d{::opendir("/sys/kernel/livepatch")};  // NOLINT
        if (d) {
            while (const dirent* e = ::readdir(d.get())) {
                if (e->d_name[0] == '.') continue;
                s.applied_patches.emplace_back(e->d_name);
                const std::string enabled = fsx::read_trimmed(std::string("/sys/kernel/livepatch/") +
                                                              e->d_name + "/enabled");
                if (enabled == "1") {
                    s.findings.push_back("Live kernel patch '" + std::string(e->d_name) +
                                         "' is ACTIVE: the running kernel differs from the kernel "
                                         "image on disk. All file-integrity baselines for /boot and "
                                         "/lib/modules are therefore stale.");
                }
            }
        }
    }
    if (s.ksplice_present && cfg.flag_ksplice) {
        s.findings.push_back("Oracle Ksplice is installed. Live patching means the in-memory kernel "
                             "is not the on-disk kernel; Module 1 integrity assertions must be read "
                             "with that caveat.");
    }
    if (s.kpatch_present && cfg.flag_ksplice) {
        s.findings.push_back("kpatch is installed; same caveat as Ksplice applies.");
    }
    return s;
}

HardeningReport verify_hardening(const core::KernelHardeningConfig& cfg) noexcept {
    HardeningReport r;
    r.sysctls = verify_sysctls(cfg);
    r.lockdown = verify_lockdown(cfg);
    r.aslr = verify_aslr_and_introspection();
    r.livepatch = verify_live_patching(cfg);
    r.checked_at = core::SysClock::now();

    for (const auto& c : r.sysctls) {
        switch (c.verdict) {
            case SysctlVerdict::Compliant:
            case SysctlVerdict::Acceptable: ++r.compliant; break;
            case SysctlVerdict::Drift: ++r.drift; break;
            case SysctlVerdict::Missing: ++r.missing; break;
            case SysctlVerdict::Unreadable: ++r.unacceptable; break;
        }
        if (c.severity > r.worst_severity) r.worst_severity = c.severity;
    }
    if (!r.lockdown.compliant && r.worst_severity < core::Severity::High)
        r.worst_severity = core::Severity::High;
    if (r.lockdown.mode == LockdownMode::None && r.worst_severity < core::Severity::Critical)
        r.worst_severity = core::Severity::Critical;

    const std::size_t total = std::max<std::size_t>(r.sysctls.size(), 1);
    const int sysctl_score = static_cast<int>((r.compliant * 100) / total);
    // 60% sysctl policy, 30% ASLR/introspection posture, 10% lockdown.
    int lock_score = 0;
    switch (r.lockdown.mode) {
        case LockdownMode::Confidentiality: lock_score = 100; break;
        case LockdownMode::Integrity: lock_score = 70; break;
        case LockdownMode::None: lock_score = 0; break;
        case LockdownMode::Unavailable: lock_score = 20; break;
    }
    r.score = std::clamp((sysctl_score * 60 + r.aslr.score * 30 + lock_score * 10) / 100, 0, 100);
    return r;
}

// ---------------------------------------------------------------------------
// Sensor
// ---------------------------------------------------------------------------

KernelHardeningSensor::KernelHardeningSensor(core::EventBus& bus, const core::AgentConfig& cfg,
                                             core::ThreadPool& pool)
    : core::ISensor("kernel-hardening", core::SensorId::KernelHardening, bus, cfg, pool) {}

bool KernelHardeningSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.hardening.enabled;
}

bool KernelHardeningSensor::on_start() {
    rescan();
    return true;
}

void KernelHardeningSensor::loop(std::stop_token st) {
    // Re-verification matters because sysctls drift at runtime: an operator
    // script, a container runtime, or an attacker with root can flip
    // kernel.randomize_va_space back to 0 in a single write.
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

void KernelHardeningSensor::rescan() {
    report_ = verify_hardening(cfg_.hardening);
    publish();
    last_publish_ = core::SysClock::now();
}

void KernelHardeningSensor::publish() {
    for (const auto& c : report_.sysctls) {
        if (c.verdict == SysctlVerdict::Compliant || c.verdict == SysctlVerdict::Acceptable) continue;

        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::KernelHardening;
        ev.kind = core::EventKind::HardeningDrift;
        ev.severity = c.verdict == SysctlVerdict::Missing ? core::Severity::Low : c.severity;
        ev.target.path = c.path;
        ev.target.rule_id = c.sysctl_name;
        ev.message = std::format("{} = '{}' (policy '{}'): {}", c.sysctl_name, c.actual, c.expected,
                                 c.verdict == SysctlVerdict::Missing ? "knob absent" : "drifted");
        ev.fields["rationale"] = c.rationale;
        ev.fields["remediation"] = c.remediation;
        ev.risk_score = static_cast<std::uint16_t>(
            ev.severity == core::Severity::Critical ? 400
            : ev.severity == core::Severity::High ? 300
            : ev.severity == core::Severity::Medium ? 180 : 60);
        emit(std::move(ev));
    }

    for (const auto& f : report_.lockdown.findings) {
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::KernelHardening;
        ev.kind = core::EventKind::HardeningDrift;
        ev.severity = report_.lockdown.mode == LockdownMode::None ? core::Severity::Critical
                                                                  : core::Severity::Medium;
        ev.message = f;
        ev.fields["lockdown_raw"] = report_.lockdown.raw;
        ev.risk_score = report_.lockdown.mode == LockdownMode::None ? 420 : 150;
        emit(std::move(ev));
    }

    for (const auto& f : report_.aslr.findings) {
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::KernelHardening;
        ev.kind = core::EventKind::HardeningDrift;
        ev.severity = core::Severity::Medium;
        ev.message = f;
        ev.risk_score = 140;
        emit(std::move(ev));
    }

    for (const auto& f : report_.livepatch.findings) {
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::KernelHardening;
        ev.kind = core::EventKind::HardeningDrift;
        ev.severity = core::Severity::Low;
        ev.message = f;
        ev.risk_score = 40;
        emit(std::move(ev));
    }

    core::TelemetryEvent summary;
    summary.sensor = core::SensorId::KernelHardening;
    summary.kind = core::EventKind::HardeningDrift;
    summary.severity = report_.drift == 0 && report_.unacceptable == 0 ? core::Severity::Info
                                                                       : report_.worst_severity;
    summary.metric = static_cast<double>(report_.score);
    summary.message = std::format("kernel hardening score {}/100 | sysctls compliant={} drift={} "
                                  "missing={} | aslr={} ptrace_scope={} lockdown='{}' livepatch={}",
                                  report_.score, report_.compliant, report_.drift, report_.missing,
                                  report_.aslr.randomize_va_space, report_.aslr.ptrace_scope,
                                  report_.lockdown.raw, report_.livepatch.livepatch_enabled ? "yes" : "no");
    emit(std::move(summary));

    mark_running(std::format("score {}/100, {} drift, {} missing", report_.score, report_.drift,
                             report_.missing));
}

bool KernelHardeningSensor::apply_remediation(const std::string& out_path) noexcept {
    const std::string path = out_path.empty() ? "/etc/sysctl.d/99-hyprnova-hardening.conf" : out_path;
    std::string body;
    body += "# Generated by HyprNova -- do not edit by hand.\n";
    body += "# Each line corresponds to a policy check that reported drift.\n";
    body += "# Rationale is included so an operator can review before applying.\n\n";

    std::size_t n = 0;
    for (const auto& c : report_.sysctls) {
        if (c.verdict == SysctlVerdict::Compliant || c.verdict == SysctlVerdict::Acceptable) continue;
        if (c.verdict == SysctlVerdict::Missing) continue;  // cannot set an absent knob
        body += "# " + c.rationale + "\n";
        body += c.sysctl_name + " = " + c.expected + "\n\n";
        ++n;
    }
    if (n == 0) {
        SINFO(name_, "no drift to remediate");
        return true;
    }
    if (cfg_.dry_run) {
        SWARN(name_, "dry_run: would write {} sysctl lines to {}", n, path);
        return false;
    }
    if (!fsx::write_atomic(path, {reinterpret_cast<const std::byte*>(body.data()), body.size()}, 0644)) {
        note_error("failed to write " + path + " (need root)");
        return false;
    }
    emit(core::EventKind::RemediationApplied, core::Severity::Info,
         std::format("wrote {} sysctl remediations to {}; run 'sysctl --system' to apply", n, path));
    return true;
}

}  // namespace hyprnova::hardening
