// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/fd.hpp
// RAII ownership for every raw C resource the daemon touches: file descriptors,
// epoll sets, inotify/fanotify instances, mmap'd regions, POSIX processes.
//
// Rule enforced across the codebase: no bare `new`/`delete`, no bare `close()`,
// no `int fd` that outlives the scope that opened it. Move-only semantics make
// double-close and leak-on-early-return structurally impossible.

#pragma once

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace hyprnova::core {

/// Thrown by the throwing helpers below; the hot path uses `noexcept` variants
/// that report through std::expected-ish Result<T> instead of unwinding.
class SyscallError : public std::system_error {
public:
    SyscallError(int err, std::string_view what)
        : std::system_error(err, std::generic_category(), std::string(what)), errno_{err} {}
    [[nodiscard]] int err() const noexcept { return errno_; }

private:
    int errno_;
};

template <typename T>
struct Result {
    std::optional<T> value;
    int error{0};
    std::string context;

    [[nodiscard]] explicit operator bool() const noexcept { return value.has_value(); }
    [[nodiscard]] T& operator*() & { return *value; }
    [[nodiscard]] const T& operator*() const& { return *value; }
    [[nodiscard]] T* operator->() { return &*value; }
    [[nodiscard]] std::string message() const {
        return context.empty() ? std::strerror(error) : context + ": " + std::strerror(error);
    }
};

// ---------------------------------------------------------------------------
// UniqueFd
// ---------------------------------------------------------------------------

class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : fd_{fd} {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& o) noexcept : fd_{std::exchange(o.fd_, -1)} {}
    UniqueFd& operator=(UniqueFd&& o) noexcept {
        if (this != &o) {
            reset();
            fd_ = std::exchange(o.fd_, -1);
        }
        return *this;
    }

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] explicit operator bool() const noexcept { return fd_ >= 0; }
    [[nodiscard]] int release() noexcept { return std::exchange(fd_, -1); }

private:
    int fd_{-1};
};

/// Owning FILE* (used for /proc parsing where fgets is far faster than read()).
struct FileCloser {
    void operator()(std::FILE* f) const noexcept {
        if (f) std::fclose(f);
    }
};
using UniqueFile = std::unique_ptr<std::FILE, FileCloser>;

struct DirCloser {
    void operator()(DIR* d) const noexcept {
        if (d) ::closedir(d);
    }
};
using UniqueDir = std::unique_ptr<DIR, DirCloser>;

/// RAII mmap. Used by the static scanner to map candidate binaries once and
/// feed the same span to hash, YARA-lite and entropy analysis without copies.
class MappedFile {
public:
    MappedFile() noexcept = default;
    ~MappedFile() { unmap(); }

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& o) noexcept
        : fd_{std::move(o.fd_)}, base_{std::exchange(o.base_, nullptr)}, size_{std::exchange(o.size_, 0)} {}
    MappedFile& operator=(MappedFile&& o) noexcept {
        if (this != &o) {
            unmap();
            fd_ = std::move(o.fd_);
            base_ = std::exchange(o.base_, nullptr);
            size_ = std::exchange(o.size_, 0);
        }
        return *this;
    }

    /// Maps `path` read-only. Fails cleanly (empty span) on any error: a scanner
    /// must skip unreadable files, never crash the daemon.
    static Result<MappedFile> open(std::string_view path, std::size_t max_bytes = 0) noexcept;

    [[nodiscard]] std::span<const std::byte> bytes() const noexcept {
        if (!base_ || size_ == 0) return {};
        return {static_cast<const std::byte*>(base_), size_};
    }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool valid() const noexcept { return base_ != nullptr; }

    /// Advise the kernel we will read sequentially -> fewer minor faults.
    void advise_sequential() const noexcept {
        if (base_ && size_) ::madvise(base_, size_, MADV_SEQUENTIAL | MADV_WILLNEED);
    }

private:
    void unmap() noexcept {
        if (base_ && size_) ::munmap(base_, size_);
        base_ = nullptr;
        size_ = 0;
    }

    UniqueFd fd_;
    void* base_{nullptr};
    std::size_t size_{0};
};

// ---------------------------------------------------------------------------
// EpollSet — owning wrapper around epoll_create1/epoll_ctl/epoll_wait
// ---------------------------------------------------------------------------

class EpollSet {
public:
    EpollSet() noexcept = default;
    EpollSet(EpollSet&&) noexcept = default;
    EpollSet& operator=(EpollSet&&) noexcept = default;
    EpollSet(const EpollSet&) = delete;
    EpollSet& operator=(const EpollSet&) = delete;

    static Result<EpollSet> create(int flags = EPOLL_CLOEXEC) noexcept;

    [[nodiscard]] bool add(int fd, std::uint32_t events, void* data) noexcept {
        epoll_event ev{};
        ev.events = events;
        ev.data.ptr = data;
        return ::epoll_ctl(ep_.get(), EPOLL_CTL_ADD, fd, &ev) == 0;
    }

    [[nodiscard]] bool modify(int fd, std::uint32_t events, void* data) noexcept {
        epoll_event ev{};
        ev.events = events;
        ev.data.ptr = data;
        return ::epoll_ctl(ep_.get(), EPOLL_CTL_MOD, fd, &ev) == 0;
    }

    [[nodiscard]] bool remove(int fd) noexcept {
        return ::epoll_ctl(ep_.get(), EPOLL_CTL_DEL, fd, nullptr) == 0;
    }

    /// Blocks at most `timeout_ms`; -1 = block until eventfd wake-up.
    [[nodiscard]] std::span<epoll_event> wait(int timeout_ms) noexcept {
        const int n = ::epoll_wait(ep_.get(), events_.data(), static_cast<int>(events_.size()), timeout_ms);
        last_count_ = n > 0 ? static_cast<std::size_t>(n) : 0;
        last_error_ = n < 0 ? errno : 0;
        return std::span<epoll_event>{events_.data(), last_count_};
    }

    [[nodiscard]] int last_error() const noexcept { return last_error_; }
    [[nodiscard]] int fd() const noexcept { return ep_.get(); }

private:
    explicit EpollSet(UniqueFd fd) noexcept : ep_{std::move(fd)} {}
    friend class WakeupEvent;

    UniqueFd ep_;
    std::array<epoll_event, 64> events_{};
    std::size_t last_count_{0};
    int last_error_{0};
};

/// Self-pipe replacement: an eventfd registered in the EpollSet so a stop_token
/// request from the orchestrator can interrupt a blocking epoll_wait instantly.
class WakeupEvent {
public:
    static Result<WakeupEvent> create() noexcept;
    void signal() const noexcept;
    void drain() const noexcept;
    [[nodiscard]] int fd() const noexcept { return fd_.get(); }

private:
    explicit WakeupEvent(UniqueFd fd) noexcept : fd_{std::move(fd)} {}
    UniqueFd fd_;
};

// ---------------------------------------------------------------------------
// Process handles
// ---------------------------------------------------------------------------

/// Owning pid_t with explicit, auditable lifecycle. Every signal the agent
/// sends goes through this so the GUI can show exactly what was signalled.
class ProcessHandle {
public:
    explicit ProcessHandle(pid_t pid) noexcept : pid_{pid} {}
    [[nodiscard]] pid_t pid() const noexcept { return pid_; }
    [[nodiscard]] bool alive() const noexcept { return pid_ > 0 && ::kill(pid_, 0) == 0; }

    [[nodiscard]] bool stop() const noexcept { return pid_ > 0 && ::kill(pid_, SIGSTOP) == 0; }
    [[nodiscard]] bool cont() const noexcept { return pid_ > 0 && ::kill(pid_, SIGCONT) == 0; }
    [[nodiscard]] bool kill(int sig = SIGKILL) const noexcept {
        return pid_ > 0 && ::kill(pid_, sig) == 0;
    }

private:
    pid_t pid_{-1};
};

// ---------------------------------------------------------------------------
// Small filesystem helpers used by every module
// ---------------------------------------------------------------------------

/// EAGAIN and EWOULDBLOCK are the same value on Linux but POSIX permits them to
/// differ, so portable code tests both. Funnelled through one function so the
/// comparison exists in exactly one place (and so -Wlogical-op, which correctly
/// reports the redundancy on this platform, stays quiet everywhere else).
[[nodiscard]] inline bool would_block(int err) noexcept {
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || (EWOULDBLOCK != EAGAIN))
    return err == EAGAIN || err == EWOULDBLOCK;
#else
    return err == EAGAIN;
#endif
}

namespace fsx {

/// Reads a whole small file (<= max_bytes) into `out`. Returns bytes read, or
/// -1 with errno preserved. Never throws — used from signal-adjacent paths.
[[nodiscard]] std::ptrdiff_t read_file(std::string_view path, std::string& out,
                                       std::size_t max_bytes = 1 << 20) noexcept;

[[nodiscard]] inline std::string read_trimmed(std::string_view path) noexcept {
    std::string s;
    if (read_file(path, s) < 0) return {};
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    std::size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t')) ++b;
    return s.substr(b);
}

[[nodiscard]] bool exists(std::string_view path) noexcept;

/// Recursive mkdir (0755 per level, `mode` for the leaf). Returns true if the
/// directory exists afterwards, false with errno preserved otherwise.
[[nodiscard]] bool mkdir_p(std::string_view path, mode_t mode = 0755) noexcept;

/// chmod that reports failure rather than silently ignoring it: a quarantine
/// directory left world-readable is a real exposure, not a cosmetic issue.
[[nodiscard]] bool set_mode(std::string_view path, mode_t mode) noexcept;
[[nodiscard]] bool is_dir(std::string_view path) noexcept;

/// True when `path` exists and is a regular file (symlinks to files count: the
/// caller decides whether O_NOFOLLOW matters).
[[nodiscard]] bool is_file(std::string_view path) noexcept;
[[nodiscard]] std::optional<std::uint64_t> file_size(std::string_view path) noexcept;
[[nodiscard]] std::optional<std::string> read_symlink(std::string_view path) noexcept;

/// Atomic write via temp file + rename: used for canary files and remediation
/// state so a crash mid-write never leaves a truncated artefact.
[[nodiscard]] bool write_atomic(std::string_view path, std::span<const std::byte> data,
                                mode_t mode = 0600) noexcept;

/// Resolve a path with O_NOFOLLOW|O_PATH semantics to defeat symlink swaps
/// between "check" and "use" (classic TOCTOU in scanners).
[[nodiscard]] Result<UniqueFd> open_nofollow(std::string_view path, int flags) noexcept;

}  // namespace fsx
}  // namespace hyprnova::core
