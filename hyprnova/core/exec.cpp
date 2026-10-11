// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/exec.cpp

#include "core/exec.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <grp.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include "core/fd.hpp"
#include "core/log.hpp"

namespace hyprnova::core::exec {

namespace {

constexpr std::array<const char*, 8> kTrustedDirs = {"/usr/sbin", "/usr/bin", "/sbin", "/bin",
                                                     "/usr/local/sbin", "/usr/local/bin", "/opt",
                                                     "/usr/libexec"};

bool dir_is_world_writable(std::string_view path) noexcept {
    struct stat st {};
    if (::stat(std::string(path).c_str(), &st) != 0) return false;
    return (st.st_mode & S_IWOTH) != 0;
}

}  // namespace

bool is_executable(std::string_view path) noexcept {
    if (path.empty()) return false;
    struct stat st {};
    if (::stat(std::string(path).c_str(), &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;
    return ::access(std::string(path).c_str(), X_OK) == 0;
}

std::string resolve(std::string_view command, bool allow_relative) noexcept {
    if (command.empty()) return {};
    if (command[0] == '/') {
        // Absolute: verify it is not inside a world-writable directory, which is
        // how a local attacker redirects a root-run helper.
        const std::size_t slash = command.find_last_of('/');
        const std::string dir{command.substr(0, slash)};
        if (dir_is_world_writable(dir)) {
            SERROR("exec", "refusing to run '{}': its directory {} is world-writable", command, dir);
            return {};
        }
        return is_executable(command) ? std::string(command) : std::string{};
    }
    if (!allow_relative) {
        return find_in_system_path(command);
    }
    return {};
}

std::string find_in_system_path(std::string_view name) noexcept {
    if (name.empty() || name.find('/') != std::string_view::npos) return {};
    for (const char* d : kTrustedDirs) {
        const std::string candidate = std::string(d) + "/" + std::string(name);
        if (is_executable(candidate)) return candidate;
    }
    return {};
}

std::string first_executable(const std::vector<std::string>& candidates) noexcept {
    for (const auto& c : candidates) {
        const std::string r = resolve(c, false);
        if (!r.empty()) return r;
    }
    return {};
}

bool inside_container() noexcept {
    // cgroup v2 / v1 markers, plus the container-injection env files.
    std::string cg;
    if (fsx::read_file("/proc/self/cgroup", cg, 8192) >= 0 &&
        (cg.find("docker") != std::string::npos || cg.find("kubepods") != std::string::npos ||
         cg.find("containerd") != std::string::npos || cg.find("lxc") != std::string::npos))
        return true;
    struct stat st {};
    if (::stat("/.dockerenv", &st) == 0) return true;
    if (::stat("/run/.containerenv", &st) == 0) return true;
    // systemd-detect-virt is authoritative but costs a fork; check /proc/1/environ
    // for the container marker first.
    std::string env;
    if (fsx::read_file("/proc/1/environ", env, 1 << 16) >= 0 &&
        env.find("container=") != std::string::npos)
        return true;
    return false;
}

Result run(const std::string& path, const std::vector<std::string>& args, const Options& opts) noexcept {
    Result res;
    const auto t0 = std::chrono::steady_clock::now();

    const std::string resolved = resolve(path, false);
    if (resolved.empty()) {
        res.error = "not executable or not in a trusted directory: " + path;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return res;
    }

    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (::pipe(out_pipe) != 0) {
        res.error = std::string("pipe: ") + std::strerror(errno);
        return res;
    }
    if (::pipe(err_pipe) != 0) {
        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        res.error = std::string("pipe: ") + std::strerror(errno);
        return res;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(out_pipe[0]); ::close(out_pipe[1]);
        ::close(err_pipe[0]); ::close(err_pipe[1]);
        res.error = std::string("fork: ") + std::strerror(errno);
        return res;
    }

    if (pid == 0) {
        // ---------------- child ----------------
        if (opts.new_session) ::setsid();
        ::dup2(out_pipe[1], STDOUT_FILENO);
        if (opts.capture_stderr) ::dup2(err_pipe[1], STDERR_FILENO);
        else {
            int devnull = ::open("/dev/null", O_WRONLY);
            if (devnull >= 0) { ::dup2(devnull, STDERR_FILENO); ::close(devnull); }
        }
        ::close(out_pipe[0]); ::close(out_pipe[1]);
        ::close(err_pipe[0]); ::close(err_pipe[1]);
        {
            int devnull = ::open("/dev/null", O_RDONLY);
            if (devnull >= 0) { ::dup2(devnull, STDIN_FILENO); ::close(devnull); }
        }
        if (!opts.cwd.empty()) {
            if (::chdir(opts.cwd.c_str()) != 0) ::_exit(126);
        }

        std::vector<char*> argv;
        argv.reserve(args.size() + 2);
        argv.push_back(const_cast<char*>(resolved.c_str()));
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);

        // Minimal, explicit environment. Never inherit ours: an attacker who can
        // influence the agent's environment (e.g. via a systemd drop-in) would
        // otherwise control LD_PRELOAD for every helper we run as root.
        std::vector<std::string> env_storage = opts.env;
        if (env_storage.empty()) {
            env_storage = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "IFS= "};
        }
        for (const auto& [k, v] : opts.extra_env) env_storage.push_back(k + "=" + v);

        // Drop privileges last, and in the only order that works: setuid() is
        // irreversible for an unprivileged child, so groups and gid must go first.
        if (opts.run_as_uid != 0xFFFFFFFF) {
            if (::setgroups(0, nullptr) != 0) ::_exit(125);
            const gid_t gid = opts.run_as_gid != 0xFFFFFFFF ? opts.run_as_gid : opts.run_as_uid;
            if (::setgid(gid) != 0) ::_exit(125);
            if (::setuid(opts.run_as_uid) != 0) ::_exit(125);
            // Verify: a silent failure to drop would run a helper as root.
            if (::getuid() != opts.run_as_uid) ::_exit(125);
        }
        std::vector<char*> envp;
        envp.reserve(env_storage.size() + 1);
        for (auto& e : env_storage) envp.push_back(const_cast<char*>(e.c_str()));
        envp.push_back(nullptr);

        ::execve(resolved.c_str(), argv.data(), envp.data());
        ::_exit(127);
    }

    // ---------------- parent ----------------
    ::close(out_pipe[1]);
    ::close(err_pipe[1]);
    res.spawned = true;

    const auto deadline = t0 + opts.timeout;
    bool child_done = false;
    int status = 0;

    auto drain = [&](int fd, std::string& into) {
        std::array<char, 8192> buf{};
        for (;;) {
            const int remaining_ms = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
                    .count());
            if (remaining_ms <= 0) return false;
            pollfd pfd{fd, POLLIN, 0};
            const int pr = ::poll(&pfd, 1, std::min(remaining_ms, 100));
            if (pr < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (pr == 0) {
                // Poll timed out but the deadline may not have passed; check the child.
                if (::waitpid(pid, &status, WNOHANG) == pid) { child_done = true; return true; }
                continue;
            }
            const ssize_t n = ::read(fd, buf.data(), buf.size());
            if (n < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (n == 0) return true;  // EOF
            if (into.size() < opts.max_output_bytes)
                into.append(buf.data(), std::min<std::size_t>(static_cast<std::size_t>(n),
                                                              opts.max_output_bytes - into.size()));
        }
    };

    // Interleave stdout and stderr so a chatty child on one pipe cannot starve
    // the other and wedge us past the deadline.
    std::array<pollfd, 2> pfds{};
    pfds[0] = {out_pipe[0], POLLIN, 0};
    pfds[1] = {err_pipe[0], POLLIN, 0};
    bool out_open = true, err_open = opts.capture_stderr;

    while ((out_open || err_open) && !child_done) {
        const int remaining_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
                .count());
        if (remaining_ms <= 0) break;
        pfds[0].events = out_open ? POLLIN : 0;
        pfds[1].events = err_open ? POLLIN : 0;
        const int pr = ::poll(pfds.data(), 2, std::min(remaining_ms, 200));
        if (pr < 0 && errno != EINTR) break;
        if (pr == 0) {
            if (::waitpid(pid, &status, WNOHANG) == pid) child_done = true;
            continue;
        }
        std::array<char, 8192> buf{};
        if (out_open && (pfds[0].revents & (POLLIN | POLLHUP))) {
            const ssize_t n = ::read(out_pipe[0], buf.data(), buf.size());
            if (n > 0 && res.out.size() < opts.max_output_bytes)
                res.out.append(buf.data(), static_cast<std::size_t>(n));
            if (n <= 0) out_open = false;
        }
        if (err_open && (pfds[1].revents & (POLLIN | POLLHUP))) {
            const ssize_t n = ::read(err_pipe[0], buf.data(), buf.size());
            if (n > 0 && res.err.size() < opts.max_output_bytes)
                res.err.append(buf.data(), static_cast<std::size_t>(n));
            if (n <= 0) err_open = false;
        }
        if (::waitpid(pid, &status, WNOHANG) == pid) child_done = true;
    }
    (void)drain;

    ::close(out_pipe[0]);
    ::close(err_pipe[0]);

    if (!child_done) {
        // Deadline reached with the child still alive.
        res.timed_out = true;
        if (opts.kill_group_on_timeout && opts.new_session) ::kill(-pid, SIGKILL);
        else ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
        res.error = "timed out after " + std::to_string(opts.timeout.count()) + "ms";
    }

    if (WIFEXITED(status)) {
        res.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        res.signal = WTERMSIG(status);
        res.exit_code = -1;
    }

    res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    return res;
}

std::optional<std::string> capture(const std::string& path, const std::vector<std::string>& args,
                                   std::chrono::milliseconds timeout) noexcept {
    Options o;
    o.timeout = timeout;
    auto r = run(path, args, o);
    if (!r.spawned) return std::nullopt;
    std::string out = r.out;
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) out.pop_back();
    return out;
}

}  // namespace hyprnova::core::exec
