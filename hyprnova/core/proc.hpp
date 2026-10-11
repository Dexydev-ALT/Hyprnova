// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/proc.hpp
// /proc introspection. This is the enrichment layer: sensors hand us a pid and
// this module resolves everything the GUI and the heuristic engine need.
//
// All reads are best-effort and race-tolerant. A process can exit between any
// two of these calls; every function therefore degrades to an empty value
// rather than reporting an error, because "process gone" is not an error.

#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <unordered_map>
#include <string_view>
#include <sys/types.h>
#include <vector>

#include "core/event.hpp"

namespace hyprnova::core::proc {

struct ProcessInfo {
    pid_t pid{0};
    pid_t ppid{0};
    pid_t tgid{0};
    uid_t uid{0xFFFFFFFF};
    gid_t gid{0xFFFFFFFF};
    uid_t euid{0xFFFFFFFF};
    std::string comm;
    std::string exe;       // symlink target; "(deleted)" suffix if unlinked
    std::string cmdline;   // NUL -> space
    std::vector<std::string> argv;
    std::string cwd;
    std::string cgroup;
    std::string container_id;
    std::string state;     // R/S/D/Z/T
    std::uint64_t start_time_ticks{0};
    std::uint64_t vsize{0};
    std::uint64_t rss_pages{0};
    bool traced{false};
    bool deleted_exe{false};
    bool exists{false};
};

[[nodiscard]] ProcessInfo read(pid_t pid) noexcept;

/// Populate the Actor fields of an event from /proc in one pass. Called by the
/// agent's enrichment stage before publish(), so subscribers never re-read /proc.
void enrich(TelemetryEvent& ev) noexcept;

[[nodiscard]] std::string exe_of(pid_t pid) noexcept;
[[nodiscard]] std::string comm_of(pid_t pid) noexcept;
[[nodiscard]] std::string cmdline_of(pid_t pid) noexcept;
[[nodiscard]] std::optional<uid_t> uid_of(pid_t pid) noexcept;

/// Full ancestry, root-most first. Capped to avoid pathological loops in a
/// corrupted /proc or a re-parent storm.
[[nodiscard]] std::vector<pid_t> ancestry(pid_t pid, std::size_t max_depth = 32) noexcept;

/// "process lineage" string for the GUI threat dialog, e.g.
///   systemd(1) -> sshd(812) -> bash(9001) -> curl(9002)
[[nodiscard]] std::string lineage_string(pid_t pid, std::size_t max_depth = 8) noexcept;

/// True when the executable lives in a world-writable or noexec-ish location.
/// This is one of the highest-signal cheap heuristics there is.
[[nodiscard]] bool runs_from_suspicious_path(std::string_view exe) noexcept;

[[nodiscard]] inline bool is_world_writable_runtime_dir(std::string_view dir) noexcept {
    return dir == "/tmp" || dir == "/var/tmp" || dir == "/dev/shm" || dir.starts_with("/tmp/") ||
           dir.starts_with("/var/tmp/") || dir.starts_with("/dev/shm/");
}

/// /proc/<pid>/maps reader for the escalation pipeline step 2.
struct MemoryRegion {
    std::uint64_t start{0};
    std::uint64_t end{0};
    std::string perms;
    std::string path;
    bool anon{false};
    bool executable{false};
    bool writable_and_executable{false};  // W^X violation: strong IOC
};

[[nodiscard]] std::vector<MemoryRegion> maps(pid_t pid, std::size_t max_regions = 4096) noexcept;

/// Perms-string classifiers shared with tests ("rwxp" layout: r w x p).
[[nodiscard]] bool region_exec(std::string_view perms) noexcept;
[[nodiscard]] bool region_wx(std::string_view perms) noexcept;

/// Extract printable ASCII strings of length >= min_len from a memory region by
/// reading /proc/<pid>/mem. Used to match YARA rules against a frozen suspect's
/// address space without dumping to disk.
[[nodiscard]] std::vector<std::string> strings_from_region(pid_t pid, const MemoryRegion& region,
                                                           std::size_t min_len = 6,
                                                           std::size_t max_bytes = 4 << 20) noexcept;

/// Enumerate live pids (skipping kernel threads when `userspace_only`).
[[nodiscard]] std::vector<pid_t> list_pids(bool userspace_only = true) noexcept;

/// Process start time as a wall-clock instant, derived from /proc/stat btime +
/// the process's starttime field. Needed to tell "just spawned" from "long-lived".
[[nodiscard]] std::optional<TimePoint> start_wall_time(pid_t pid) noexcept;

/// Seconds the process has been alive; nullopt if it no longer exists.
[[nodiscard]] std::optional<double> age_seconds(pid_t pid) noexcept;

/// Snapshot of open file descriptors -> paths. Used to attribute mass file
/// modification to a specific actor without fanotify permission events.
[[nodiscard]] std::vector<std::string> open_files(pid_t pid, std::size_t max_fds = 512) noexcept;

/// Cached system boot time (read once per daemon lifetime).
[[nodiscard]] TimePoint boot_time() noexcept;

/// Host clock ticks per second.
[[nodiscard]] long ticks_per_second() noexcept;

/// Is the daemon running with the capabilities it needs? Reported to the GUI so
/// a mis-deployed agent shows a visible warning instead of silently blind spots.
struct CapabilityReport {
    bool root{false};
    bool cap_sys_admin{false};
    bool cap_sys_ptrace{false};
    bool cap_dac_read_search{false};  // fanotify FAN_OPEN_PERM needs this
    bool cap_net_admin{false};        // nftables
    bool cap_audit_read{false};
    bool euid0{false};
    std::vector<std::string> missing;
};
[[nodiscard]] CapabilityReport capabilities() noexcept;

// ---------------------------------------------------------------------------
// Network introspection
// ---------------------------------------------------------------------------
// Parsed straight out of /proc/net/{tcp,tcp6,udp,udp6} and attributed by walking
// /proc/<pid>/fd for socket inodes. `ss` and `netstat` are deliberately NOT used:
// they are ordinary binaries, and an attacker with root has usually replaced them
// before an EDR arrives. /proc is kernel-provided and cannot be swapped out by a
// userspace rootkit that has not also loaded a kernel module -- which Module 1
// detects separately.

/// Owner of a socket inode, discovered from /proc/<pid>/fd.
struct SocketOwner {
    pid_t pid{0};
    uid_t uid{0xFFFFFFFF};
    std::string exe;
    std::string comm;
};

/// One row of /proc/net/*.
struct NetSocket {
    std::string protocol;      // "tcp", "tcp6", "udp", "udp6"
    std::string local_address;
    std::uint16_t local_port{0};
    std::string remote_address;
    std::uint16_t remote_port{0};
    std::string state;         // TCP state name; "-" for UDP
    std::uint64_t inode{0};
    uid_t uid{0xFFFFFFFF};
    pid_t pid{0};              // 0 == owner not identified
    std::string exe;
    std::string comm;
    bool listening{false};
};

/// inode -> owner. Bounded on purpose: on a busy host /proc/*/fd can hold tens of
/// thousands of links, and the GUI only needs attribution for the rows it shows.
[[nodiscard]] std::unordered_map<std::uint64_t, SocketOwner> socket_owner_map(std::size_t max_pids = 4096) noexcept;

/// Every TCP/UDP socket, attributed where possible. `only_listening` skips
/// established rows, which is what the "what is exposed on this host" panel wants.
[[nodiscard]] std::vector<NetSocket> net_sockets(bool only_listening = false,
                                                 std::size_t max_rows = 512) noexcept;

}  // namespace hyprnova::core::proc
