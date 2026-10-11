// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/proc.cpp

#include "core/proc.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <format>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HYPRNOVA_HAVE_LIBCAP
#include <sys/capability.h>
#endif

#include "core/fd.hpp"

namespace hyprnova::core::proc {

namespace {

long g_ticks = 0;
std::once_flag g_ticks_once;
std::uint64_t g_btime = 0;
std::once_flag g_btime_once;

std::uint64_t parse_u64(std::string_view s) noexcept {
    std::uint64_t v = 0;
    const auto* first = s.data();
    const auto [p, ec] = std::from_chars(first, first + s.size(), v);
    return ec == std::errc{} ? v : 0;
}

/// /proc/<pid>/stat is space-delimited but field 2 (comm) is parenthesised and
/// may itself contain spaces and ')'. Parse by anchoring on the LAST ')'.
bool parse_stat(std::string_view raw, ProcessInfo& out) noexcept {
    const std::size_t lp = raw.find('(');
    const std::size_t rp = raw.rfind(')');
    if (lp == std::string_view::npos || rp == std::string_view::npos || rp <= lp) return false;

    out.comm = std::string(raw.substr(lp + 1, rp - lp - 1));
    std::string_view rest = raw.substr(rp + 2);  // skip ") "

    // Fields after comm, 0-indexed: state(0) ppid(1) pgrp(2) session(3) tty(4)
    // tpgid(5) flags(6) minflt(7) ... utime(11) stime(12) cutime(13) cstime(14)
    // priority(15) nice(16) num_threads(17) ... starttime(19) vsize(20) rss(21)
    std::vector<std::string_view> f;
    f.reserve(52);
    std::size_t start = 0;
    while (start <= rest.size()) {
        const std::size_t sp = rest.find(' ', start);
        if (sp == std::string_view::npos) {
            f.push_back(rest.substr(start));
            break;
        }
        f.push_back(rest.substr(start, sp - start));
        start = sp + 1;
    }
    if (f.size() < 22) return false;

    out.state = std::string(f[0]);
    out.ppid = static_cast<pid_t>(parse_u64(f[1]));
    out.start_time_ticks = parse_u64(f[19]);
    out.vsize = parse_u64(f[20]);
    out.rss_pages = parse_u64(f[21]);
    return true;
}

std::string read_cmdline_raw(pid_t pid) noexcept {
    std::string s;
    if (fsx::read_file(std::format("/proc/{}/cmdline", pid), s) < 0) return {};
    return s;
}

}  // namespace

long ticks_per_second() noexcept {
    std::call_once(g_ticks_once, [] {
        const long t = ::sysconf(_SC_CLK_TCK);
        g_ticks = t > 0 ? t : 100;
    });
    return g_ticks;
}

TimePoint boot_time() noexcept {
    std::call_once(g_btime_once, [] {
        std::string s;
        if (fsx::read_file("/proc/stat", s, 1 << 16) >= 0) {
            std::size_t pos = 0;
            while (pos < s.size()) {
                const std::size_t nl = s.find('\n', pos);
                const std::string_view line{s.data() + pos, (nl == std::string::npos ? s.size() : nl) - pos};
                if (line.starts_with("btime ")) {
                    g_btime = parse_u64(line.substr(6));
                    break;
                }
                if (nl == std::string::npos) break;
                pos = nl + 1;
            }
        }
        if (g_btime == 0) g_btime = 1;
    });
    return SysClock::from_time_t(static_cast<std::time_t>(g_btime));
}

std::string exe_of(pid_t pid) noexcept {
    if (auto l = fsx::read_symlink(std::format("/proc/{}/exe", pid))) return *l;
    return {};
}

std::string comm_of(pid_t pid) noexcept { return fsx::read_trimmed(std::format("/proc/{}/comm", pid)); }

std::string cmdline_of(pid_t pid) noexcept {
    std::string raw = read_cmdline_raw(pid);
    if (raw.empty()) return {};
    // Kernel threads have an empty cmdline; fall back to comm in brackets.
    if (raw.size() == 1 && raw[0] == '\0') return "[" + comm_of(pid) + "]";
    for (auto& c : raw) {
        if (c == '\0') c = ' ';
    }
    while (!raw.empty() && raw.back() == ' ') raw.pop_back();
    return raw;
}

std::optional<uid_t> uid_of(pid_t pid) noexcept {
    ProcessInfo pi = read(pid);
    if (!pi.exists) return std::nullopt;
    return pi.uid;
}

ProcessInfo read(pid_t pid) noexcept {
    ProcessInfo out;
    out.pid = pid;
    if (pid <= 0) return out;

    std::string stat_raw;
    if (fsx::read_file(std::format("/proc/{}/stat", pid), stat_raw, 8192) < 0) return out;
    out.exists = true;
    if (!parse_stat(stat_raw, out)) return out;

    out.exe = exe_of(pid);
    out.deleted_exe = out.exe.ends_with(" (deleted)");
    if (out.deleted_exe) out.exe.resize(out.exe.size() - std::strlen(" (deleted)"));

    const std::string raw_cmd = read_cmdline_raw(pid);
    if (!raw_cmd.empty()) {
        std::size_t pos = 0;
        while (pos < raw_cmd.size()) {
            const std::size_t nul = raw_cmd.find('\0', pos);
            const std::size_t end = nul == std::string::npos ? raw_cmd.size() : nul;
            if (end > pos) out.argv.emplace_back(raw_cmd.substr(pos, end - pos));
            if (nul == std::string::npos) break;
            pos = nul + 1;
        }
        out.cmdline = cmdline_of(pid);
    }

    if (auto cwd = fsx::read_symlink(std::format("/proc/{}/cwd", pid))) out.cwd = *cwd;

    // /proc/<pid>/status -> Uid/Gid/EUid/TracerPid/Tgid
    std::string status;
    if (fsx::read_file(std::format("/proc/{}/status", pid), status, 16384) >= 0) {
        std::size_t pos = 0;
        while (pos < status.size()) {
            const std::size_t nl = status.find('\n', pos);
            const std::string_view line{status.data() + pos,
                                        (nl == std::string::npos ? status.size() : nl) - pos};
            if (line.starts_with("Uid:")) {
                std::uint64_t real = 0, eff = 0;
                if (std::sscanf(std::string(line).c_str(), "Uid: %lu %lu", &real, &eff) >= 1) {
                    out.uid = static_cast<uid_t>(real);
                    out.euid = static_cast<uid_t>(eff);
                }
            } else if (line.starts_with("Gid:")) {
                std::uint64_t real = 0;
                if (std::sscanf(std::string(line).c_str(), "Gid: %lu", &real) >= 1)
                    out.gid = static_cast<gid_t>(real);
            } else if (line.starts_with("Tgid:")) {
                out.tgid = static_cast<pid_t>(parse_u64(line.substr(5)));
            } else if (line.starts_with("TracerPid:")) {
                out.traced = parse_u64(line.substr(10)) != 0;
            }
            if (nl == std::string::npos) break;
            pos = nl + 1;
        }
    }
    if (out.tgid == 0) out.tgid = pid;

    // /proc/<pid>/cgroup -> container attribution
    std::string cg;
    if (fsx::read_file(std::format("/proc/{}/cgroup", pid), cg, 8192) >= 0) {
        out.cgroup = cg;
        while (!out.cgroup.empty() && (out.cgroup.back() == '\n' || out.cgroup.back() == '\r'))
            out.cgroup.pop_back();
        // cgroup v2: "0::/system.slice/docker-<64hex>.scope"
        for (const char* marker : {"docker-", "crio-", "containerd-", "podman-"}) {
            const std::size_t at = out.cgroup.find(marker);
            if (at != std::string::npos) {
                std::size_t s = at + std::strlen(marker);
                std::size_t e = s;
                while (e < out.cgroup.size() && std::isxdigit(static_cast<unsigned char>(out.cgroup[e]))) ++e;
                if (e - s >= 12) {
                    out.container_id = out.cgroup.substr(s, e - s);
                    break;
                }
            }
        }
        if (out.container_id.empty() && out.cgroup.find(".slice/") == std::string::npos &&
            out.cgroup.find("/lxc/") != std::string::npos) {
            out.container_id = "lxc";
        }
    }

    return out;
}

void enrich(TelemetryEvent& ev) noexcept {
    if (ev.actor.pid <= 0) return;
    const ProcessInfo pi = read(ev.actor.pid);
    if (!pi.exists) return;

    if (ev.actor.exe.empty()) ev.actor.exe = pi.exe;
    if (ev.actor.comm.empty()) ev.actor.comm = pi.comm;
    if (ev.actor.cmdline.empty()) ev.actor.cmdline = pi.cmdline;
    if (ev.actor.cwd.empty()) ev.actor.cwd = pi.cwd;
    if (ev.actor.cgroup.empty()) ev.actor.cgroup = pi.cgroup;
    if (ev.actor.container_id.empty()) ev.actor.container_id = pi.container_id;
    ev.actor.in_container = !pi.container_id.empty();
    if (ev.actor.ppid == 0) ev.actor.ppid = pi.ppid;
    if (ev.actor.uid == 0xFFFFFFFF) ev.actor.uid = pi.uid;
    if (ev.actor.gid == 0xFFFFFFFF) ev.actor.gid = pi.gid;
    if (ev.actor.tgid == 0) ev.actor.tgid = pi.tgid;
    if (ev.actor.ancestry.empty()) ev.actor.ancestry = ancestry(pi.pid, 16);

    // A deleted executable is an IOC in itself: the file was unlinked after
    // exec, which is how fileless droppers stay resident.
    if (pi.deleted_exe && ev.severity < Severity::High) {
        ev.severity = Severity::High;
        ev.triggers.push_back("exe_deleted_after_exec");
        ev.message += " [executable unlinked after exec]";
    }
    if (runs_from_suspicious_path(pi.exe) && ev.severity < Severity::Medium) {
        ev.severity = Severity::Medium;
        ev.triggers.push_back("runs_from_world_writable_path");
    }
}

std::vector<pid_t> ancestry(pid_t pid, std::size_t max_depth) noexcept {
    std::vector<pid_t> chain;
    std::vector<pid_t> seen;
    pid_t cur = pid;
    for (std::size_t i = 0; i < max_depth && cur > 0; ++i) {
        if (std::find(seen.begin(), seen.end(), cur) != seen.end()) break;  // loop guard
        seen.push_back(cur);
        chain.push_back(cur);
        const std::string stat_raw = [&] {
            std::string s;
            (void)fsx::read_file(std::format("/proc/{}/stat", cur), s, 8192);
            return s;
        }();
        ProcessInfo tmp;
        if (!parse_stat(stat_raw, tmp)) break;
        if (tmp.ppid == cur) break;
        cur = tmp.ppid;
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

std::string lineage_string(pid_t pid, std::size_t max_depth) noexcept {
    const auto chain = ancestry(pid, max_depth);
    std::string out;
    for (std::size_t i = 0; i < chain.size(); ++i) {
        if (i) out += " -> ";
        std::string c = comm_of(chain[i]);
        if (c.empty()) c = "?";
        out += std::format("{}({})", c, chain[i]);
    }
    return out.empty() ? std::format("pid({})", pid) : out;
}

bool runs_from_suspicious_path(std::string_view exe) noexcept {
    if (exe.empty()) return false;
    return is_world_writable_runtime_dir(exe) || exe.starts_with("/home/") || exe.starts_with("/root/") ||
           exe.starts_with("/mnt/") || exe.starts_with("/media/") || exe.starts_with("/run/user/") ||
           exe.find("/.cache/") != std::string_view::npos || exe.find("/.local/") != std::string_view::npos;
}

/// "rwxp" -> executable? (index 2). /proc/pid/maps perms layout is rwxp.
bool region_exec(std::string_view perms) noexcept {
    return perms.size() >= 3 && perms[2] == 'x';
}

/// W^X violation: writable AND executable. Index 1 is the write bit -- index 0
/// is always 'r' or '-'. (Regression: this used to test perms[0]=='w', which no
/// real mapping can match, silently disabling W^X detection.)
bool region_wx(std::string_view perms) noexcept {
    return perms.size() >= 3 && perms[1] == 'w' && perms[2] == 'x';
}

std::vector<MemoryRegion> maps(pid_t pid, std::size_t max_regions) noexcept {
    std::vector<MemoryRegion> out;
    std::string raw;
    if (fsx::read_file(std::format("/proc/{}/maps", pid), raw, 8 << 20) < 0) return out;

    std::size_t pos = 0;
    while (pos < raw.size() && out.size() < max_regions) {
        const std::size_t nl = raw.find('\n', pos);
        const std::string_view line{raw.data() + pos, (nl == std::string::npos ? raw.size() : nl) - pos};
        pos = nl == std::string::npos ? raw.size() : nl + 1;
        if (line.empty()) continue;

        MemoryRegion r;
        char perms[8] = {};
        unsigned long long start = 0, end = 0;
        int matched = std::sscanf(std::string(line).c_str(), "%llx-%llx %7s", &start, &end, perms);
        if (matched < 3) continue;
        r.start = start;
        r.end = end;
        r.perms = perms;
        r.executable = region_exec(r.perms);
        r.writable_and_executable = region_wx(r.perms);

        // Path is the last whitespace-delimited token, if present.
        const std::size_t pathpos = line.find('/');
        if (pathpos != std::string_view::npos) {
            r.path = std::string(line.substr(pathpos));
            while (!r.path.empty() && (r.path.back() == '\n' || r.path.back() == '\r')) r.path.pop_back();
            r.anon = false;
        } else {
            r.anon = line.find("[heap]") == std::string_view::npos &&
                     line.find("[stack]") == std::string_view::npos;
            const std::size_t br = line.find('[');
            if (br != std::string_view::npos) r.path = std::string(line.substr(br));
        }
        out.push_back(std::move(r));
    }
    return out;
}

std::vector<std::string> strings_from_region(pid_t pid, const MemoryRegion& region, std::size_t min_len,
                                             std::size_t max_bytes) noexcept {
    std::vector<std::string> out;
    const std::uint64_t span = region.end - region.start;
    if (span == 0 || span > (1ull << 34)) return out;  // refuse absurd regions
    const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(span, max_bytes));

    auto mem = fsx::open_nofollow(std::format("/proc/{}/mem", pid), O_RDONLY);
    if (!mem) return out;
    if (::lseek(mem->get(), static_cast<off_t>(region.start), SEEK_SET) < 0) return out;

    std::string chunk;
    chunk.resize(want);
    std::size_t got = 0;
    while (got < want) {
        const ssize_t n = ::read(mem->get(), chunk.data() + got, want - got);
        if (n <= 0) break;
        got += static_cast<std::size_t>(n);
    }
    chunk.resize(got);

    std::string cur;
    cur.reserve(64);
    for (const char c : chunk) {
        const auto uc = static_cast<unsigned char>(c);
        if (uc >= 0x20 && uc < 0x7f) {
            cur.push_back(c);
        } else {
            if (cur.size() >= min_len) out.push_back(std::move(cur));
            cur.clear();
            cur.reserve(64);
            if (out.size() > 20000) break;  // bound memory on a huge heap scan
        }
    }
    if (cur.size() >= min_len) out.push_back(std::move(cur));
    return out;
}

std::vector<pid_t> list_pids(bool userspace_only) noexcept {
    std::vector<pid_t> out;
    UniqueDir d{::opendir("/proc")};
    if (!d) return out;
    while (const dirent* e = ::readdir(d.get())) {
        if (e->d_type != DT_DIR) continue;
        std::uint64_t v = 0;
        const auto* first = e->d_name;
        const auto [p, ec] = std::from_chars(first, first + std::strlen(first), v);
        if (ec != std::errc{} || *p != '\0' || v == 0) continue;
        if (userspace_only) {
            const std::string cmd = read_cmdline_raw(static_cast<pid_t>(v));
            if (cmd.empty()) continue;  // kernel thread
        }
        out.push_back(static_cast<pid_t>(v));
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::optional<TimePoint> start_wall_time(pid_t pid) noexcept {
    const ProcessInfo pi = read(pid);
    if (!pi.exists || pi.start_time_ticks == 0) return std::nullopt;
    const auto bt = boot_time();
    const auto secs = static_cast<double>(pi.start_time_ticks) / static_cast<double>(ticks_per_second());
    return bt + std::chrono::duration_cast<SysClock::duration>(std::chrono::duration<double>(secs));
}

std::optional<double> age_seconds(pid_t pid) noexcept {
    auto st = start_wall_time(pid);
    if (!st) return std::nullopt;
    return std::chrono::duration<double>(SysClock::now() - *st).count();
}

std::vector<std::string> open_files(pid_t pid, std::size_t max_fds) noexcept {
    std::vector<std::string> out;
    UniqueDir d{::opendir(std::format("/proc/{}/fd", pid).c_str())};
    if (!d) return out;
    while (const dirent* e = ::readdir(d.get())) {
        if (out.size() >= max_fds) break;
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        if (auto l = fsx::read_symlink(std::format("/proc/{}/fd/{}", pid, e->d_name))) out.push_back(*l);
    }
    return out;
}

CapabilityReport capabilities() noexcept {
    CapabilityReport r;
    r.euid0 = ::geteuid() == 0;
    r.root = ::getuid() == 0;

#ifdef HYPRNOVA_HAVE_LIBCAP
    cap_t caps = ::cap_get_proc();
    if (caps) {
        auto has = [&](cap_value_t v) {
            cap_flag_value_t fv = CAP_CLEAR;
            return ::cap_get_flag(caps, v, CAP_EFFECTIVE, &fv) == 0 && fv == CAP_SET;
        };
        r.cap_sys_admin = has(CAP_SYS_ADMIN);
        r.cap_sys_ptrace = has(CAP_SYS_PTRACE);
        r.cap_dac_read_search = has(CAP_DAC_READ_SEARCH);
        r.cap_net_admin = has(CAP_NET_ADMIN);
        r.cap_audit_read = has(CAP_AUDIT_READ);
        ::cap_free(caps);
    }
#else
    // Without libcap, approximate: a real root process has full caps unless a
    // bounding-set restriction was applied. We report conservatively and let the
    // GUI show "capability introspection unavailable".
    r.cap_sys_admin = r.euid0;
    r.cap_sys_ptrace = r.euid0;
    r.cap_dac_read_search = r.euid0;
    r.cap_net_admin = r.euid0;
    r.cap_audit_read = r.euid0;
#endif

    if (!r.euid0) r.missing.push_back("not running as uid 0 (fanotify PERM, auditd, kmod sensors degraded)");
    if (!r.cap_sys_ptrace) r.missing.push_back("CAP_SYS_PTRACE (cross-uid /proc/<pid>/mem reads)");
    if (!r.cap_dac_read_search) r.missing.push_back("CAP_DAC_READ_SEARCH (fanotify FAN_OPEN_PERM blocking)");
    if (!r.cap_net_admin) r.missing.push_back("CAP_NET_ADMIN (nftables remediation)");
    if (!r.cap_audit_read) r.missing.push_back("CAP_AUDIT_READ (auditd netlink stream)");
    return r;
}


// ---------------------------------------------------------------------------
// Network introspection
// ---------------------------------------------------------------------------

namespace {

/// Decode the kernel's little-endian hex address. v4 is 8 hex chars, v6 is 32 in
/// four 32-bit words, each word host-endian -- the ordering surprises everyone
/// once, so it is spelled out here.
[[nodiscard]] std::string decode_address(std::string_view hex, bool v6) noexcept {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    auto byte_from = [&](std::string_view two) -> int {
        const int hi = nibble(two[0]);
        const int lo = two.size() > 1 ? nibble(two[1]) : -1;
        if (hi < 0 || lo < 0) return -1;
        return (hi << 4) | lo;
    };
    if (!v6) {
        if (hex.size() != 8) return std::string(hex);
        // Stored as one host-endian 32-bit word: reverse the byte order.
        int b[4] = {-1, -1, -1, -1};
        for (int i = 0; i < 4; ++i) b[i] = byte_from(hex.substr(static_cast<std::size_t>(i * 2), 2));
        if (b[0] < 0) return std::string(hex);
        return std::format("{}.{}.{}.{}", b[3], b[2], b[1], b[0]);
    }
    if (hex.size() != 32) return std::string(hex);
    std::uint8_t bytes[16] = {};
    for (int word = 0; word < 4; ++word) {
        const std::string_view w = hex.substr(static_cast<std::size_t>(word * 8), 8);
        for (int i = 0; i < 4; ++i) {
            const int v = byte_from(w.substr(static_cast<std::size_t>(i * 2), 2));
            if (v < 0) return std::string(hex);
            // Each 32-bit word is host-endian, so its bytes are reversed too.
            bytes[static_cast<std::size_t>(word * 4 + (3 - i))] = static_cast<std::uint8_t>(v);
        }
    }
    // Compress the longest zero run, the way inet_ntop does.
    int best_start = -1;
    int best_len = 0;
    for (int i = 0; i < 8; ++i) {
        if (bytes[static_cast<std::size_t>(i * 2)] == 0 && bytes[static_cast<std::size_t>(i * 2 + 1)] == 0) {
            int len = 1;
            while (i + len < 8 && bytes[static_cast<std::size_t>((i + len) * 2)] == 0 &&
                   bytes[static_cast<std::size_t>((i + len) * 2 + 1)] == 0) {
                ++len;
            }
            if (len > best_len) { best_len = len; best_start = i; }
            i += len - 1;
        }
    }
    std::string out;
    for (int i = 0; i < 8;) {
        if (i == best_start && best_len > 1) {
            out += "::";
            i += best_len;
            if (i >= 8) break;
        } else {
            if (!out.empty() && out.back() != ':') out += ':';
            const auto group = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(bytes[static_cast<std::size_t>(i * 2)]) << 8) |
                bytes[static_cast<std::size_t>(i * 2 + 1)]);
            out += std::format("{:x}", group);
            ++i;
        }
    }
    if (out.empty()) out = "::";
    return out;
}

[[nodiscard]] std::string tcp_state_name(std::uint64_t st) noexcept {
    // include/net/tcp_states.h
    static constexpr std::string_view names[] = {
        "?",        "ESTABLISHED", "SYN_SENT",   "SYN_RECV",   "FIN_WAIT1", "FIN_WAIT2",
        "TIME_WAIT", "CLOSE",       "CLOSE_WAIT", "LAST_ACK",   "LISTEN",    "CLOSING",
        "NEW_SYN_RECV"};
    if (st >= std::size(names)) return std::format("state-{}", st);
    return std::string(names[st]);
}

[[nodiscard]] bool split_endpoint(std::string_view field, std::string& addr, std::uint16_t& port,
                                  bool v6) noexcept {
    const std::size_t colon = field.rfind(':');
    if (colon == std::string_view::npos || colon + 1 >= field.size()) return false;
    addr = decode_address(field.substr(0, colon), v6);
    std::uint64_t p = 0;
    const std::string_view ps = field.substr(colon + 1);
    if (std::from_chars(ps.data(), ps.data() + ps.size(), p, 16).ec != std::errc{}) return false;
    port = static_cast<std::uint16_t>(p);
    return true;
}

}  // namespace

std::unordered_map<std::uint64_t, SocketOwner> socket_owner_map(std::size_t max_pids) noexcept {
    std::unordered_map<std::uint64_t, SocketOwner> owners;
    std::size_t pids = 0;
    for (const pid_t pid : list_pids(false)) {
        if (++pids > max_pids) break;
        UniqueDir d{::opendir(std::format("/proc/{}/fd", pid).c_str())};
        if (!d) continue;   // not ours to read, or already gone
        const ProcessInfo pi = read(pid);
        while (const dirent* e = ::readdir(d.get())) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            const auto link = fsx::read_symlink(std::format("/proc/{}/fd/{}", pid, e->d_name));
            if (!link) continue;
            constexpr std::string_view prefix = "socket:[";
            if (link->compare(0, prefix.size(), prefix) != 0) continue;
            const std::size_t close = link->find(']', prefix.size());
            if (close == std::string::npos) continue;
            const std::string_view num = link->substr(prefix.size(), close - prefix.size());
            std::uint64_t inode = 0;
            if (std::from_chars(num.data(), num.data() + num.size(), inode).ec != std::errc{}) continue;
            if (inode == 0) continue;
            SocketOwner o;
            o.pid = pid;
            o.uid = pi.uid;
            o.exe = pi.exe;
            o.comm = pi.comm;
            owners.emplace(inode, std::move(o));
        }
        if (owners.size() > 65536) break;   // hard bound on a socket-bombing host
    }
    return owners;
}

std::vector<NetSocket> net_sockets(bool only_listening, std::size_t max_rows) noexcept {
    std::vector<NetSocket> out;
    const auto owners = socket_owner_map();

    struct Source {
        const char* path;
        const char* proto;
        bool v6;
        bool tcp;
    };
    static constexpr Source sources[] = {{"/proc/net/tcp", "tcp", false, true},
                                         {"/proc/net/tcp6", "tcp6", true, true},
                                         {"/proc/net/udp", "udp", false, false},
                                         {"/proc/net/udp6", "udp6", true, false}};

    for (const auto& src : sources) {
        std::string text;
        if (fsx::read_file(src.path, text, 8 << 20) <= 0) continue;

        std::size_t pos = 0;
        bool first = true;
        while (pos < text.size() && out.size() < max_rows) {
            const std::size_t nl = text.find('\n', pos);
            const std::string_view line{text.data() + pos,
                                        (nl == std::string_view::npos ? text.size() : nl) - pos};
            pos = nl == std::string_view::npos ? text.size() : nl + 1;
            if (first) { first = false; continue; }   // header row
            if (line.size() < 40) continue;

            // sl local remote st tx:rx tr:tm retrnsmt uid timeout inode ...
            std::string_view rest = line;
            const auto next_field = [&rest]() -> std::string_view {
                std::size_t b = 0;
                while (b < rest.size() && (rest[b] == ' ' || rest[b] == '\t')) ++b;
                std::size_t e = b;
                while (e < rest.size() && rest[e] != ' ' && rest[e] != '\t') ++e;
                const std::string_view f = rest.substr(b, e - b);
                rest = e < rest.size() ? rest.substr(e) : std::string_view{};
                return f;
            };

            (void)next_field();                       // sl
            const std::string_view local = next_field();
            const std::string_view remote = next_field();
            const std::string_view state_hex = next_field();
            (void)next_field();                       // tx:rx
            (void)next_field();                       // tr:tm-when
            (void)next_field();                       // retrnsmt
            const std::string_view uid_s = next_field();
            (void)next_field();                       // timeout
            const std::string_view inode_s = next_field();

            NetSocket ns;
            ns.protocol = src.proto;
            if (!split_endpoint(local, ns.local_address, ns.local_port, src.v6)) continue;
            if (!split_endpoint(remote, ns.remote_address, ns.remote_port, src.v6)) continue;

            std::uint64_t st = 0;
            if (std::from_chars(state_hex.data(), state_hex.data() + state_hex.size(), st, 16).ec ==
                std::errc{}) {
                ns.state = src.tcp ? tcp_state_name(st) : std::string("-");
                ns.listening = src.tcp && st == 10;   // TCP_LISTEN
            }
            std::uint64_t uid_v = 0;
            if (std::from_chars(uid_s.data(), uid_s.data() + uid_s.size(), uid_v).ec == std::errc{})
                ns.uid = static_cast<uid_t>(uid_v);
            std::uint64_t inode = 0;
            if (std::from_chars(inode_s.data(), inode_s.data() + inode_s.size(), inode).ec == std::errc{})
                ns.inode = inode;

            if (only_listening && !ns.listening) continue;

            auto oit = owners.find(ns.inode);
            if (oit != owners.end()) {
                ns.pid = oit->second.pid;
                ns.exe = oit->second.exe;
                ns.comm = oit->second.comm;
                if (ns.uid == 0xFFFFFFFF) ns.uid = oit->second.uid;
            }
            out.push_back(std::move(ns));
        }
    }

    // Listeners first, then by port: that is the order an operator reads the
    // "what is exposed" panel in.
    std::stable_sort(out.begin(), out.end(), [](const NetSocket& a, const NetSocket& b) {
        if (a.listening != b.listening) return a.listening;
        if (a.local_port != b.local_port) return a.local_port < b.local_port;
        return a.protocol < b.protocol;
    });
    return out;
}

}  // namespace hyprnova::core::proc
