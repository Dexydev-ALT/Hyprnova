// SPDX-License-Identifier: Apache-2.0
// HyprNova :: GUI <-> daemon IPC bridge
//
// The Qt dashboard is a *separate process* from the agent, and deliberately so:
//
//   * A crashing GUI must never take down detection. The agent keeps running with
//     no console attached.
//   * The GUI runs as the desktop user, unprivileged. It cannot signal processes,
//     read other users' /proc, or touch nftables. Every privileged operation goes
//     through this socket and is authorised by the agent, so a compromised GUI
//     gets the agent's policy engine, not the agent's root.
//   * Restarting the GUI is free: it reconnects and receives a full state snapshot.
//
// Protocol: newline-delimited JSON over a SOCK_STREAM AF_UNIX socket at
// cfg.gui.ipc_socket. Requests carry {"cmd": "..."}; responses are
// {"ok":bool,"cmd":...,"data":{...}}. The agent additionally pushes unsolicited
// {"event":...} frames for the live feed.
//
// The socket is peer-credentialed: SO_PEERCRED gives us the connecting uid, and
// anything other than root or the configured operator uid is refused before a
// single byte of state is sent.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <sys/types.h>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/fd.hpp"
#include "core/json.hpp"

namespace hyprnova {

class Agent;

class GuiBridge {
public:
    GuiBridge(Agent& agent, core::EventBus& bus, const core::AgentConfig& cfg);
    ~GuiBridge();

    GuiBridge(const GuiBridge&) = delete;
    GuiBridge& operator=(const GuiBridge&) = delete;

    /// Bind, listen, start the acceptor thread and the event broadcaster.
    [[nodiscard]] bool start() noexcept;
    void stop() noexcept;

    [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_acquire); }
    [[nodiscard]] const std::string& path() const noexcept { return path_; }
    [[nodiscard]] std::size_t clients() const noexcept;
    [[nodiscard]] std::uint64_t frames_sent() const noexcept { return frames_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t commands_handled() const noexcept {
        return commands_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::string last_error() const noexcept;

    /// Ring of recent events for a client that connects mid-flight. The GUI never
    /// starts from an empty screen.
    void prime_history(std::size_t n) noexcept;
    [[nodiscard]] std::vector<core::TelemetryEvent> history(std::size_t n) const noexcept;

    /// Uids allowed to connect. root is always allowed.
    void allow_uid(uid_t uid) noexcept;

    /// The auth DECISION, factored out pure so tests pin every branch:
    /// root -> yes; the daemon's own uid -> yes; a member of the operator
    /// group -> yes; otherwise no. `in_group` is the precomputed membership
    /// (see os_user_in_group).
    [[nodiscard]] static bool auth_decision(uid_t uid, uid_t daemon_uid,
                                            const std::optional<gid_t>& operator_gid,
                                            bool in_group) noexcept;

    /// OS-level group membership of a uid (getpwuid + getgrouplist; cached
    /// results live in the bridge instance, this static is the uncached read).
    [[nodiscard]] static bool os_user_in_group(uid_t uid, gid_t gid) noexcept;

private:
    struct Client {
        core::UniqueFd fd;
        uid_t uid{0};
        pid_t pid{0};
        std::string rx;             // partial line accumulator
        std::uint64_t frames{0};
        bool wants_events{true};
        core::SysClock::time_point connected{};
    };

    void accept_loop(std::stop_token st) noexcept;
    void on_readable(Client& c) noexcept;
    bool handle_line(Client& c, std::string_view line) noexcept;
    core::json::Value dispatch(std::string_view cmd, const core::json::Value& req, uid_t uid) noexcept;
    void broadcast(std::string_view frame) noexcept;
    void send_to(Client& c, std::string_view frame) noexcept;
    void on_event(const core::TelemetryEvent& ev) noexcept;
    [[nodiscard]] bool authorised(uid_t uid) noexcept;
    [[nodiscard]] bool group_member_cached(uid_t uid) const;

    // Snapshot builders: one per GUI panel. Each returns a JSON object.
    [[nodiscard]] core::json::Value snapshot_overview() const noexcept;
    [[nodiscard]] core::json::Value snapshot_sensors() const noexcept;
    [[nodiscard]] core::json::Value snapshot_events(std::size_t n) const noexcept;
    [[nodiscard]] core::json::Value snapshot_risk() const noexcept;
    [[nodiscard]] core::json::Value snapshot_decisions() const noexcept;
    [[nodiscard]] core::json::Value snapshot_remediation() const noexcept;
    [[nodiscard]] core::json::Value snapshot_scans() const noexcept;
    [[nodiscard]] core::json::Value snapshot_hardening() const noexcept;
    [[nodiscard]] core::json::Value snapshot_canaries() const noexcept;
    [[nodiscard]] core::json::Value snapshot_processes(std::size_t n) const noexcept;
    [[nodiscard]] core::json::Value snapshot_baseline() const noexcept;
    [[nodiscard]] core::json::Value snapshot_network() const noexcept;
    [[nodiscard]] core::json::Value snapshot_shadows() const noexcept;

    Agent& agent_;
    core::EventBus& bus_;
    const core::AgentConfig& cfg_;
    std::string path_;

    core::UniqueFd listen_fd_;
    ino_t own_sock_ino_{0};   // filesystem node bind() created (see stop())
    dev_t own_sock_dev_{0};
    std::jthread acceptor_;
    std::atomic<bool> running_{false};

    mutable std::mutex clients_mu_;
    std::unordered_map<int, Client> clients_;
    std::vector<uid_t> allowed_uids_;
    std::string ipc_group_;                  // resolved at start()
    std::optional<gid_t> ipc_group_gid_;     // set when the group exists
    mutable std::unordered_map<uid_t, bool> group_cache_;  // uid -> in operator group

    mutable std::mutex hist_mu_;
    std::deque<core::TelemetryEvent> history_;

    core::SubscriptionId sub_id_{0};
    std::atomic<std::uint64_t> frames_{0};
    std::atomic<std::uint64_t> commands_{0};
    std::string last_error_;
};

}  // namespace hyprnova
