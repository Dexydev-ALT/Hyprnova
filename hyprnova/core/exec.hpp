// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/exec.hpp
// Subprocess execution for a security daemon.
//
// Every external tool this agent invokes (sbctl, clamdscan, kvrt, osqueryi, nft,
// notify-send) goes through this one function, and it is deliberately NOT
// popen()/system(): those go through /bin/sh, which means a compromised shell --
// or a PATH hijack in a world-writable directory -- silently redirects every
// "verification" the agent performs. execve with an absolute path and a minimal
// environment removes that class of attack entirely.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <string_view>
#include <vector>

namespace hyprnova::core::exec {

using namespace std::chrono_literals;

struct Options {
    std::chrono::milliseconds timeout{30s};
    std::size_t max_output_bytes{4 << 20};
    /// Environment passed to the child. Empty == a single PATH entry only.
    std::vector<std::string> env;
    /// Run in a fresh session so a hung child cannot keep our terminal/process
    /// group, and so we can kill the whole tree on timeout.
    bool new_session{true};
    bool capture_stderr{true};
    /// Kill the whole process group on timeout, not just the direct child.
    bool kill_group_on_timeout{true};
    /// Working directory; empty == inherit.
    std::string cwd;
    /// Run the child as this user (setgroups -> setgid -> setuid, in that order,
    /// in the forked child before execve). Used by the notification path: a root
    /// daemon cannot raise a desktop notification unless it becomes the session
    /// owner first. A value of 0xFFFFFFFF means "do not change identity".
    uid_t run_as_uid{0xFFFFFFFF};
    uid_t run_as_gid{0xFFFFFFFF};
    /// Appended to the minimal environment above. Only for variables that cannot
    /// be attacker-influenced (DBUS_SESSION_BUS_ADDRESS, DISPLAY, XDG_RUNTIME_DIR
    /// read out of the target session's own /proc/<pid>/environ).
    std::unordered_map<std::string, std::string> extra_env;
};

struct Result {
    bool spawned{false};      // fork+execve succeeded
    bool timed_out{false};
    int exit_code{-1};        // -1 when not exited normally
    int signal{-1};           // signal that killed it, if any
    std::string out;
    std::string err;
    std::string error;        // our own failure reason (ENOENT, EACCES, ...)
    std::chrono::milliseconds elapsed{};

    [[nodiscard]] bool ok() const noexcept { return spawned && !timed_out && exit_code == 0; }
};

/// Absolute-path resolution. Refuses to execute a relative path or one that
/// resolves through a world-writable directory unless `allow_relative`.
[[nodiscard]] std::string resolve(std::string_view command, bool allow_relative = false) noexcept;

[[nodiscard]] bool is_executable(std::string_view path) noexcept;

/// The core primitive. Blocks the *calling* thread until the child exits or the
/// timeout fires; callers on a sensor thread must dispatch this to the pool.
[[nodiscard]] Result run(const std::string& path, const std::vector<std::string>& args,
                         const Options& opts = {}) noexcept;

/// Convenience: run and return trimmed stdout, or nullopt on any failure.
[[nodiscard]] std::optional<std::string> capture(const std::string& path,
                                                 const std::vector<std::string>& args,
                                                 std::chrono::milliseconds timeout = 10s) noexcept;

/// Which of these candidate absolute paths is the first executable one?
[[nodiscard]] std::string first_executable(const std::vector<std::string>& candidates) noexcept;

/// Search $PATH-equivalent for a binary name, restricted to trusted system
/// directories. Never searches /tmp, /home or the caller's cwd.
[[nodiscard]] std::string find_in_system_path(std::string_view name) noexcept;

/// PID 1 of a container, when we are inside one. Used to avoid "remediating" a
/// container's init from the host and taking down every workload in it.
[[nodiscard]] bool inside_container() noexcept;

}  // namespace hyprnova::core::exec
