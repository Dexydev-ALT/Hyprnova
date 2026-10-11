// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 1a — Secure Boot Auditor
//
// Static hash lookups cannot see a boot-chain compromise: the malicious code is
// already resident before the first userspace instruction executes. This auditor
// establishes whether the platform's measured boot chain is intact and whether
// the keys that anchor it are the ones the operator enrolled.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/sensor.hpp"

namespace hyprnova::hardening {

/// State of one UEFI variable we care about.
struct EfiVariable {
    std::string name;
    std::string guid;
    std::size_t size{0};
    bool readable{false};
    bool exists{false};
    std::string sha256;          // digest of the raw variable payload
    std::vector<std::string> subjects;  // parsed CN= fields for key databases
    bool immutable{false};       // EFI_VARIABLE_APPEND_WRITE / time-based auth present
};

struct SecureBootStatus {
    bool platform_supports_uefi{false};
    bool efivarfs_mounted{false};
    bool secure_boot_enabled{false};
    bool setup_mode{false};           // SecureBoot=0 because keys are not enrolled
    bool manufacturer_keys_only{false};
    bool mok_list_present{false};     // shim/MokList (Ubuntu/Fedora path)
    std::string secure_boot_var;      // raw "1"/"0"
    std::vector<EfiVariable> variables;
    std::vector<std::string> findings;
    std::vector<std::string> missing_tools;
    bool sbctl_available{false};
    std::string sbctl_status_raw;
    /// 0..100; 100 == enrolled, enabled, no setup mode, PK owned by the operator.
    int score{0};
    bool trustworthy{false};
};

/// One-shot audit. Pure functions, no side effects, safe to call from the GUI.
[[nodiscard]] SecureBootStatus audit_secure_boot(const core::BootIntegrityConfig& cfg) noexcept;

/// Parsed /proc/cmdline.
struct KernelCmdline {
    std::string raw;
    std::vector<std::string> tokens;
    std::vector<std::string> forbidden_present;   // weaken the kernel
    std::vector<std::string> expected_present;    // hardening we want
    std::vector<std::string> expected_missing;
    std::string init;          // init= value, if overridden
    std::string root;
    bool debug_shell{false};
    bool audit_disabled{false};
    bool lsm_overridden{false};
    std::string lockdown_param;
    std::vector<std::string> findings;
};

[[nodiscard]] KernelCmdline audit_kernel_cmdline(const core::BootIntegrityConfig& cfg) noexcept;

/// Kernel release / flavour detection: is this a hardened build?
struct KernelIdentity {
    std::string release;          // uname -r
    std::string version;          // /proc/version
    bool is_hardened_flavour{false};   // linux-hardened, grsec, -ck, KSPP-aligned
    bool is_lts{false};
    bool tainted{false};
    std::string taint_flags;      // P O E ... from /proc/sys/kernel/tainted
    std::vector<std::string> taint_meanings;
    bool module_signature_enforced{false};
    std::string loaded_modules_digest;  // sha256 over sorted lsmod, for drift detection
    std::size_t loaded_module_count{0};
    std::vector<std::string> findings;
};

[[nodiscard]] KernelIdentity audit_kernel_identity() noexcept;

/// initramfs presence + digest, for the "was the early boot payload replaced?"
/// question. We do not attempt to unpack it; we baseline its digest and alert on
/// change, which is what actually catches tampering between reboots.
struct InitramfsStatus {
    std::string path;
    bool exists{false};
    std::uint64_t size{0};
    std::string sha256;
    std::int64_t mtime_unix{0};
    bool changed_since_baseline{false};
    std::string baseline_sha256;
    std::vector<std::string> findings;
};

[[nodiscard]] InitramfsStatus audit_initramfs(const std::string& path,
                                              const std::string& baseline_sha256) noexcept;

/// Bootloader config drift: /boot/grub/grub.cfg, /boot/loader/entries, and the
/// systemd-boot / BLS layout. A rootkit that survives reboot edits one of these.
struct BootloaderStatus {
    std::string flavour;  // "grub2" | "systemd-boot" | "unknown"
    std::vector<std::string> config_paths;
    std::vector<std::pair<std::string, std::string>> digests;  // path -> sha256
    bool world_writable_config{false};
    std::vector<std::string> findings;
};

[[nodiscard]] BootloaderStatus audit_bootloader() noexcept;

/// Kernel module load integrity: modules loaded out-of-tree, unsigned, or from a
/// writable path. This is the supply-chain / LKM-rootkit surface.
struct ModuleIntegrity {
    std::string name;
    std::string path;
    bool in_tree{false};           // under /lib/modules/$(uname -r)/kernel
    bool from_writable_path{false};
    bool signed_{false};
    bool live{false};
    std::uint64_t size{0};
};

[[nodiscard]] std::vector<ModuleIntegrity> audit_kernel_modules(std::size_t max_modules = 512) noexcept;

/// The sensor that runs all of the above on a schedule and publishes findings.
class BootAuditSensor final : public core::ISensor {
public:
    BootAuditSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    [[nodiscard]] const SecureBootStatus& secure_boot() const noexcept { return sb_; }
    [[nodiscard]] const KernelCmdline& cmdline() const noexcept { return cmdline_; }
    [[nodiscard]] const KernelIdentity& kernel() const noexcept { return kernel_; }
    [[nodiscard]] const BootloaderStatus& bootloader() const noexcept { return bootloader_; }
    [[nodiscard]] const std::vector<InitramfsStatus>& initramfs() const noexcept { return initramfs_; }

    /// Full audit; also called by `hyprnovactl audit boot` on demand.
    void run_full_audit();

    /// 0..100 aggregate boot-trust score rendered as the GUI's big dial.
    [[nodiscard]] int trust_score() const noexcept;

    /// Persist the current digests as the reference baseline. Operator action,
    /// never automatic: an agent that re-baselines itself defeats the purpose.
    [[nodiscard]] bool write_baseline() noexcept;
    [[nodiscard]] bool load_baseline() noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    void on_stop() override {}
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    void publish_findings();

    SecureBootStatus sb_;
    KernelCmdline cmdline_;
    KernelIdentity kernel_;
    BootloaderStatus bootloader_;
    std::vector<InitramfsStatus> initramfs_;
    std::string baseline_text_;
    core::SysClock::time_point last_audit_{};
};

}  // namespace hyprnova::hardening
