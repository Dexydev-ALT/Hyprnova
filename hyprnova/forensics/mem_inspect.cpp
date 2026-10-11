// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4c — memory inspection implementation.

#include "forensics/mem_inspect.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>

#include "core/fd.hpp"
#include "core/log.hpp"
#include "scanning/yara_engine.hpp"

namespace hyprnova::forensics {

using core::proc::MemoryRegion;

std::string MemInspector::dump_dir() const noexcept {
    return cfg_.state_dir + "/memory";
}

std::string_view MemInspector::limits_text() noexcept {
    return "Per-process inspection reads /proc/<pid>/maps and /proc/<pid>/mem of processes "
           "this agent can see. It is NOT full system-memory forensics: no kernel objects, "
           "no other users' processes without root, no timeline reconstruction. Dumps may "
           "contain credentials -- store and share them accordingly.";
}

std::vector<ExternalTool> MemInspector::external_tools() noexcept {
    std::vector<ExternalTool> out;
    auto probe_bin = [&out](std::string_view name, std::initializer_list<const char*> paths,
                            std::string_view note_absent) {
        ExternalTool t;
        t.name = std::string(name);
        for (const char* p : paths) {
            struct stat st {};
            if (::stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
                t.available = true;
                t.detail = p;
                break;
            }
        }
        if (!t.available) t.detail = std::string(note_absent);
        out.push_back(std::move(t));
    };
    // Volatility3: standalone binary or the python module entry point.
    probe_bin("Volatility3", {"/usr/bin/vol", "/usr/local/bin/vol", "/usr/bin/vol.py",
                              "/usr/local/bin/vol.py"},
              "not installed (pip install volatility3); only useful with a full-memory "
              "acquisition, which needs root");
    // MemProcFS: TheLivingOne's userspace forensic framework.
    probe_bin("MemProcFS", {"/usr/bin/memprocfs", "/opt/memprocfs/memprocfs"},
              "not installed; needs a physical memory dump or driver to be useful");
    // LiME: the loadable kernel module used to ACQUIRE full memory.
    {
        ExternalTool t;
        t.name = "LiME";
        bool have = false;
        if (DIR* d = ::opendir("/sys/module/lime")) {   // loaded module
            ::closedir(d);
            have = true;
            t.detail = "kernel module loaded at /sys/module/lime";
        } else {
            // source tree present but module not loaded
            struct stat st {};
            if (::stat("/usr/src/lime", &st) == 0 || ::stat("/opt/lime", &st) == 0) {
                have = true;
                t.detail = "source present but module NOT loaded (acquisition unavailable)";
            } else {
                t.detail = "not installed (full-memory acquisition needs this + root)";
            }
        }
        t.available = have;
        out.push_back(std::move(t));
    }
    return out;
}

MemInspection MemInspector::inspect(pid_t pid) const noexcept {
    MemInspection rep;
    rep.pid = pid;

    // Identity anchor FIRST: every later read validates against it.
    const core::proc::ProcessInfo pi = core::proc::read(pid);
    if (!pi.exists) {
        rep.findings.emplace_back("process does not exist");
        rep.limit_note = "process exited before inspection";
        return rep;
    }
    rep.exe = pi.exe;
    rep.start_time_ticks = pi.start_time_ticks;

    // Can we read this address space at all? Other users' processes are
    // invisible to an unprivileged agent; that is a coverage boundary, not an
    // error, and it is reported as such.
    {
        std::error_code ec;
        const std::string mem = std::format("/proc/{}/mem", pid);
        const bool mem_readable = ::access(mem.c_str(), R_OK) == 0;
        rep.readable = mem_readable;
        if (!mem_readable) {
            rep.limit_note = ::geteuid() == pi.uid
                                 ? "cannot read /proc/pid/mem (ptrace_scope or seccomp?)"
                                 : "process belongs to another user; no root: address space "
                                   "not readable from this install";
        }
    }

    const auto regions = core::proc::maps(pid, cfg_.proc_poll.enabled ? 8192 : 4096);
    if (regions.empty()) {
        rep.limit_note = rep.limit_note.empty() ? "no readable regions (exited? protected?)"
                                                : rep.limit_note;
        return rep;
    }
    rep.regions_scanned = regions.size();

    std::vector<std::string> strings;
    for (const auto& rg : regions) {
        if (rg.writable_and_executable)
            rep.wx.push_back({rg.start, rg.end, rg.path});
        const bool interesting = rg.executable && (rg.anon || rg.writable_and_executable);
        if (!interesting || !rep.readable) continue;
        // Identity re-check between batches: a recycled pid changes starttime.
        const auto now_ticks = core::proc::read(pid).start_time_ticks;
        if (now_ticks != rep.start_time_ticks) {
            rep.findings.emplace_back("PID REUSE mid-inspection: starttime changed; "
                                      "inspection aborted at the boundary (results below "
                                      "are partial but untainted)");
            rep.limit_note = "aborted: pid recycled during inspection";
            break;
        }
        if (rep.bytes_scanned >= (64u << 20)) {
            rep.limit_note = "byte budget (64 MiB of anon-exec text) exhausted; coverage "
                             "stopped early and is stated as partial";
            break;
        }
        auto part = core::proc::strings_from_region(pid, rg, 6, 1 << 20);
        rep.bytes_scanned += part.size() * 8;  // rough; bounded bookkeeping
        if (strings.size() < 200000)
            strings.insert(strings.end(), part.begin(), part.end());
    }

    if (rep.wx.empty() && rep.readable)
        rep.findings.emplace_back(std::format("no W^X violations across {} regions",
                                              rep.regions_scanned));
    for (const auto& w : rep.wx)
        rep.findings.emplace_back(std::format("W^X VIOLATION: region {:x}-{:x} is writable "
                                              "AND executable ({})",
                                              w.start, w.end,
                                              w.path.empty() ? "anonymous" : w.path));

    if (engine_ && !strings.empty()) {
        for (const auto& m : engine_->scan_strings(strings, pi.exe.empty() ? "pid" : pi.exe))
            rep.matches.push_back(m.rule);
        if (!rep.matches.empty()) {
            std::string joined;
            for (const auto& m : rep.matches) {
                if (!joined.empty()) joined += ", ";
                joined += m;
            }
            rep.findings.emplace_back("signature match in memory: " + joined);
        } else {
            rep.findings.emplace_back("no signature matches in extracted memory strings");
        }
    } else if (!rep.readable) {
        rep.findings.emplace_back("strings not extracted (address space unreadable)");
    }
    return rep;
}

MemDumpResult MemInspector::dump(pid_t pid, std::uint64_t max_bytes) const noexcept {
    MemDumpResult out;
    const core::proc::ProcessInfo pi = core::proc::read(pid);
    if (!pi.exists) {
        out.error = "process does not exist";
        return out;
    }
    const std::uint64_t ticks = pi.start_time_ticks;

    const std::string dir = dump_dir();
    if (!core::fsx::mkdir_p(dir, 0700)) {
        out.error = "cannot create " + dir;
        return out;
    }
    (void)core::fsx::set_mode(dir, 0700);  // dumps may hold credentials
    const std::string path =
        std::format("{}/{}-{}.dump", dir, pid, ticks);

    // Never overwrite: an existing dump of the same pid+starttime is evidence.
    struct stat st {};
    if (::stat(path.c_str(), &st) == 0) {
        out.error = "dump already exists for this pid+starttime: " + path;
        return out;
    }

    core::UniqueFd fd{::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)};
    if (!fd) {
        out.error = std::string("open: ") + std::strerror(errno);
        return out;
    }

    // Header: what this dump is (and is not), so the file never lies offline.
    {
        const std::string header = std::format(
            "HyprNova process-memory dump\npid={}\nstarttime={}\nexe={}\n"
            "scope=per-process, readable regions only; NOT a full system image\n",
            pid, ticks, pi.exe);
        std::size_t off = 0;
        while (off < header.size()) {
            const ssize_t w = ::write(fd.get(), header.data() + off, header.size() - off);
            if (w <= 0) break;
            off += static_cast<std::size_t>(w);
        }
    }

    const auto regions = core::proc::maps(pid, 8192);
    std::uint64_t written = 0, skipped = 0;
    core::UniqueFd mem{::open(std::format("/proc/{}/mem", pid).c_str(), O_RDONLY | O_CLOEXEC)};
    if (!mem) {
        out.error = std::string("cannot open /proc/pid/mem: ") + std::strerror(errno);
        ::unlink(path.c_str());
        return out;
    }
    for (const auto& rg : regions) {
        if (rg.perms.find('r') == std::string::npos) continue;
        if (rg.path == "[vvar]" || rg.path == "[vdso]" || rg.path == "[vsyscall]") continue;
        const std::uint64_t len = rg.end - rg.start;
        if (written + len > max_bytes) {
            skipped += len;
            continue;
        }
        // Identity guard per region: stop on recycle rather than dump the wrong
        // process's memory into this file.
        if (core::proc::read(pid).start_time_ticks != ticks) {
            out.error = "PID REUSE during dump; partial file kept with what was captured";
            break;
        }
        std::vector<std::byte> buf(static_cast<std::size_t>(std::min<std::uint64_t>(len, 1u << 20)));
        std::uint64_t at = rg.start;
        while (at < rg.end) {
            const std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uint64_t>(buf.size(), rg.end - at));
            const auto n = ::pread(mem.get(), buf.data(), chunk,
                                   static_cast<off_t>(at));
            if (n <= 0) break;  // unmapped hole; move on
            std::size_t off = 0;
            while (off < static_cast<std::size_t>(n)) {
                const ssize_t w = ::write(fd.get(), buf.data() + off,
                                          static_cast<std::size_t>(n) - off);
                if (w <= 0) {
                    out.error = std::string("write: ") + std::strerror(errno);
                    break;
                }
                off += static_cast<std::size_t>(w);
                written += static_cast<std::uint64_t>(w);
            }
            if (!out.error.empty()) break;
            at += static_cast<std::uint64_t>(n);
        }
        if (!out.error.empty()) break;
    }
    fd.reset();

    out.ok = out.error.empty();
    out.path = path;
    out.bytes = written;
    if (skipped > 0)
        out.error = std::format("completed with budget cap: {} bytes skipped "
                                "(raise the limit for full coverage)", skipped);
    else if (out.ok)
        out.error.clear();
    SINFO("mem-inspect", "dump pid {} -> {} ({} bytes){}", pid, path, written,
          out.error.empty() ? "" : " -- " + out.error);
    return out;
}

}  // namespace hyprnova::forensics
