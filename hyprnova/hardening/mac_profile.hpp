// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 1c — MAC Profile Enforcement
//
// AppArmor / SELinux are what stop a compromised sshd or nginx from becoming a
// full-host compromise. An EDR that does not verify their enforcement state is
// reporting a false sense of containment: the policy may be loaded but in
// complain mode, or the daemon may be running unconfined entirely.

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

enum class LsmKind : std::uint8_t { None = 0, AppArmor, SELinux, Smack, Tomoyo, Landlock, Bpf };

struct LsmInfo {
    std::vector<LsmKind> active;
    std::string raw;            // contents of /sys/kernel/security/lsm
    bool apparmor{false};
    bool selinux{false};
    bool bpf_lsm{false};        // eBPF LSM hooks: the modern path for custom policy
    bool landlock{false};
    std::vector<std::string> findings;
};

[[nodiscard]] LsmInfo detect_lsm() noexcept;
[[nodiscard]] constexpr std::string_view lsm_name(LsmKind k) noexcept {
    switch (k) {
        case LsmKind::AppArmor: return "apparmor";
        case LsmKind::SELinux: return "selinux";
        case LsmKind::Smack: return "smack";
        case LsmKind::Tomoyo: return "tomoyo";
        case LsmKind::Landlock: return "landlock";
        case LsmKind::Bpf: return "bpf";
        case LsmKind::None: return "none";
    }
    return "none";
}

// ---------------------------------------------------------------------------
// AppArmor
// ---------------------------------------------------------------------------

enum class ProfileMode : std::uint8_t { Unknown = 0, Enforce, Complain, Kill, Disabled, Unconfined };

constexpr std::string_view mode_name(ProfileMode m) noexcept {
    switch (m) {
        case ProfileMode::Enforce: return "enforce";
        case ProfileMode::Complain: return "complain";
        case ProfileMode::Kill: return "kill";
        case ProfileMode::Disabled: return "disabled";
        case ProfileMode::Unconfined: return "unconfined";
        case ProfileMode::Unknown: return "unknown";
    }
    return "unknown";
}

struct AppArmorProfile {
    std::string name;
    ProfileMode mode{ProfileMode::Unknown};
    bool attached_to_running_process{false};
    std::vector<pid_t> pids;
    std::string executable;   // the profile's attachment path, if resolvable
};

struct AppArmorStatus {
    bool enabled{false};
    bool filesystem_present{false};
    std::size_t profiles_loaded{0};
    std::size_t profiles_enforce{0};
    std::size_t profiles_complain{0};
    std::size_t profiles_kill{0};
    std::string raw_summary;    // /sys/kernel/security/apparmor/profiles digest
    std::vector<AppArmorProfile> profiles;
    std::vector<std::string> findings;
    /// Trusted third-party profiles found on disk (mac.profile_dirs plus the
    /// distribution's /etc/apparmor.d). These were written by someone the admin
    /// trusts for OTHER apps; the agent's job is to know they exist and to say so
    /// loudly when a daemon they cover is running unconfined anyway.
    std::vector<std::string> trusted_profiles;
};

[[nodiscard]] AppArmorStatus read_apparmor(const core::MacProfileConfig& cfg) noexcept;

// ---------------------------------------------------------------------------
// SELinux
// ---------------------------------------------------------------------------

struct SelinuxStatus {
    bool enabled{false};
    bool enforcing{false};
    bool permissive{false};
    bool disabled{false};
    int enforce_raw{-1};
    std::string policy_name;
    std::int64_t denials{0};
    std::vector<std::string> findings;
};

[[nodiscard]] SelinuxStatus read_selinux(const core::MacProfileConfig& cfg) noexcept;

// ---------------------------------------------------------------------------
// Per-daemon confinement
// ---------------------------------------------------------------------------

struct DaemonConfinement {
    std::string name;
    std::vector<pid_t> pids;
    bool running{false};
    bool confined{false};
    std::string profile;
    ProfileMode mode{ProfileMode::Unknown};
    std::string selinux_context;
    /// True when the daemon is listening on a socket -- confinement matters most
    /// for network-reachable processes.
    bool network_reachable{false};
    bool complain{false};       // profile loaded but only logging, not blocking
    std::vector<std::uint16_t> listen_ports;
    std::vector<std::string> findings;
    core::Severity severity{core::Severity::Info};
};

/// The core Module 1c question: are the internet-facing daemons actually
/// confined, and in enforce mode?
[[nodiscard]] std::vector<DaemonConfinement> audit_daemon_confinement(
    const core::MacProfileConfig& cfg) noexcept;

struct MacReport {
    LsmInfo lsm;
    AppArmorStatus apparmor;
    SelinuxStatus selinux;
    std::vector<DaemonConfinement> daemons;
    std::size_t confined_count{0};
    std::size_t unconfined_count{0};
    std::size_t complain_count{0};
    int score{0};
    core::Severity worst_severity{core::Severity::Info};
    core::SysClock::time_point checked_at{};
};

[[nodiscard]] MacReport verify_mac(const core::MacProfileConfig& cfg) noexcept;

class MacProfileSensor final : public core::ISensor {
public:
    MacProfileSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    [[nodiscard]] const MacReport& report() const noexcept { return report_; }
    void rescan();

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    void publish();
    MacReport report_;
    core::SysClock::time_point last_publish_{};
};

}  // namespace hyprnova::hardening
