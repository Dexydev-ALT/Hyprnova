// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 1b — Kernel Hardening Verifier

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/sensor.hpp"

namespace hyprnova::hardening {

enum class SysctlVerdict : std::uint8_t {
    Compliant = 0,
    Drift,          // value differs from policy
    Missing,        // knob absent (kernel too old or built without the feature)
    Unreadable,     // permission denied
    Acceptable,     // matched an explicit alternative
};

constexpr std::string_view verdict_name(SysctlVerdict v) noexcept {
    switch (v) {
        case SysctlVerdict::Compliant: return "compliant";
        case SysctlVerdict::Drift: return "drift";
        case SysctlVerdict::Missing: return "missing";
        case SysctlVerdict::Unreadable: return "unreadable";
        case SysctlVerdict::Acceptable: return "acceptable";
    }
    return "unknown";
}

struct SysctlCheck {
    std::string path;         // /proc/sys/...
    std::string sysctl_name;  // kernel.randomize_va_space
    std::string expected;
    std::string actual;
    SysctlVerdict verdict{SysctlVerdict::Missing};
    core::Severity severity{core::Severity::Info};
    std::string rationale;    // why this knob matters, shown in the GUI
    std::string remediation;  // the exact sysctl line that fixes it
};

/// Human-readable rationale for the default policy set. Used by both the sensor
/// and the GUI's "why is this flagged?" panel.
[[nodiscard]] std::string_view sysctl_rationale(std::string_view name) noexcept;
[[nodiscard]] std::string_view sysctl_remediation(std::string_view name, std::string_view value) noexcept;

[[nodiscard]] std::vector<SysctlCheck> verify_sysctls(const core::KernelHardeningConfig& cfg) noexcept;

/// Read one knob. Returns nullopt when absent/unreadable; never throws.
[[nodiscard]] std::optional<std::string> read_sysctl(std::string_view name) noexcept;
[[nodiscard]] std::string sysctl_to_proc_path(std::string_view name);

enum class LockdownMode : std::uint8_t { None = 0, Integrity, Confidentiality, Unavailable };

struct LockdownStatus {
    LockdownMode mode{LockdownMode::Unavailable};
    std::string raw;
    bool compliant{false};
    std::vector<std::string> findings;
};

[[nodiscard]] LockdownStatus verify_lockdown(const core::KernelHardeningConfig& cfg) noexcept;

/// ASLR, ptrace scope, kptr_restrict, dmesg_restrict, unprivileged BPF and the
/// other knobs that decide how hard a zero-day exploit has to work.
struct AslrStatus {
    int randomize_va_space{-1};   // 0=off 1=partial 2=full
    int ptrace_scope{-1};         // 0=classic 1=restricted 2=admin 3=disabled
    int kptr_restrict{-1};
    int dmesg_restrict{-1};
    int unprivileged_bpf_disabled{-1};
    int perf_event_paranoid{-100};
    int suid_dumpable{-1};
    int protected_symlinks{-1};
    int protected_hardlinks{-1};
    int unprivileged_userns{-1};
    std::vector<std::string> findings;
    /// 0..100 kernel-ASLR-and-introspection-hardening score.
    int score{0};
};

[[nodiscard]] AslrStatus verify_aslr_and_introspection() noexcept;

/// Live kernel patching (ksplice / kpatch / livepatch) means the running kernel
/// is not the kernel on disk, so every file-integrity baseline is stale. Not
/// malicious, but it MUST be surfaced: an operator cannot reason about a system
/// whose in-memory kernel differs from /boot.
struct LivePatchStatus {
    bool ksplice_present{false};
    bool kpatch_present{false};
    bool livepatch_enabled{false};
    std::vector<std::string> applied_patches;
    std::vector<std::string> findings;
};

[[nodiscard]] LivePatchStatus verify_live_patching(const core::KernelHardeningConfig& cfg) noexcept;

/// Aggregate hardening posture, 0..100, for the dashboard dial.
struct HardeningReport {
    std::vector<SysctlCheck> sysctls;
    LockdownStatus lockdown;
    AslrStatus aslr;
    LivePatchStatus livepatch;
    std::size_t compliant{0};
    std::size_t drift{0};
    std::size_t missing{0};
    std::size_t unacceptable{0};
    int score{0};
    core::Severity worst_severity{core::Severity::Info};
    core::SysClock::time_point checked_at{};
};

[[nodiscard]] HardeningReport verify_hardening(const core::KernelHardeningConfig& cfg) noexcept;

class KernelHardeningSensor final : public core::ISensor {
public:
    KernelHardeningSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    [[nodiscard]] const HardeningReport& report() const noexcept { return report_; }

    /// Re-run every check now. Also triggered by the GUI's "Rescan" button.
    void rescan();

    /// Write the compliant subset to /etc/sysctl.d/99-hyprnova-hardening.conf.
    /// Operator-initiated only; returns false on any permission problem.
    [[nodiscard]] bool apply_remediation(const std::string& out_path = {}) noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    void publish();

    HardeningReport report_;
    core::SysClock::time_point last_publish_{};
};

}  // namespace hyprnova::hardening
