// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/fd.cpp

#include "core/fd.hpp"

#include <array>
#include <cstdio>
#include <fcntl.h>
#include <format>
#include <string>
#include <sys/eventfd.h>
#include <sys/syscall.h>

namespace hyprnova::core {

// ---------------------------------------------------------------------------
// MappedFile
// ---------------------------------------------------------------------------

Result<MappedFile> MappedFile::open(std::string_view path, std::size_t max_bytes) noexcept {
    MappedFile mf;
    const std::string p{path};

    // O_NOFOLLOW: refuse to map through a symlink an attacker may have swapped in.
    int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);  // deliberate fallback
        if (fd < 0) return {std::nullopt, errno, "open " + p};
    }
    mf.fd_ = UniqueFd{fd};

    struct stat st {};
    if (::fstat(mf.fd_.get(), &st) != 0) return {std::nullopt, errno, "fstat " + p};
    if (!S_ISREG(st.st_mode)) return {std::nullopt, EINVAL, "not a regular file: " + p};

    std::size_t want = static_cast<std::size_t>(st.st_size);
    if (max_bytes && want > max_bytes) want = max_bytes;
    if (want == 0) {
        mf.base_ = nullptr;
        mf.size_ = 0;
        return {std::move(mf), 0, {}};
    }

    void* base = ::mmap(nullptr, want, PROT_READ, MAP_PRIVATE | MAP_POPULATE, mf.fd_.get(), 0);
    if (base == MAP_FAILED) return {std::nullopt, errno, "mmap " + p};
    mf.base_ = base;
    mf.size_ = want;
    return {std::move(mf), 0, {}};
}

// ---------------------------------------------------------------------------
// EpollSet / WakeupEvent
// ---------------------------------------------------------------------------

Result<EpollSet> EpollSet::create(int flags) noexcept {
    int fd = ::epoll_create1(flags);
    if (fd < 0) return {std::nullopt, errno, "epoll_create1"};
    return {EpollSet{UniqueFd{fd}}, 0, {}};
}

Result<WakeupEvent> WakeupEvent::create() noexcept {
    int fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE);
    if (fd < 0) return {std::nullopt, errno, "eventfd"};
    return {WakeupEvent{UniqueFd{fd}}, 0, {}};
}

void WakeupEvent::signal() const noexcept {
    const std::uint64_t one = 1;
    // EAGAIN is fine: a pending wake-up already exists.
    const ssize_t r = ::write(fd_.get(), &one, sizeof(one));
    (void)r;
}

void WakeupEvent::drain() const noexcept {
    std::uint64_t v = 0;
    while (::read(fd_.get(), &v, sizeof(v)) == static_cast<ssize_t>(sizeof(v))) {}
}

// ---------------------------------------------------------------------------
// fsx
// ---------------------------------------------------------------------------

namespace fsx {

std::ptrdiff_t read_file(std::string_view path, std::string& out, std::size_t max_bytes) noexcept {
    out.clear();
    UniqueFile f{std::fopen(std::string(path).c_str(), "rbe")};
    if (!f) return -1;

    std::array<char, 8192> buf{};
    std::size_t total = 0;
    for (;;) {
        const std::size_t want = std::min(buf.size(), max_bytes - total);
        if (want == 0) break;
        const std::size_t n = std::fread(buf.data(), 1, want, f.get());
        out.append(buf.data(), n);
        total += n;
        if (n < want) break;
    }
    return static_cast<std::ptrdiff_t>(total);
}

bool exists(std::string_view path) noexcept {
    struct stat st {};
    return ::stat(std::string(path).c_str(), &st) == 0;
}

bool is_dir(std::string_view path) noexcept {
    struct stat st {};
    if (::stat(std::string(path).c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

bool is_file(std::string_view path) noexcept {
    struct stat st {};
    return ::stat(std::string{path}.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::optional<std::uint64_t> file_size(std::string_view path) noexcept {
    struct stat st {};
    if (::stat(std::string(path).c_str(), &st) != 0) return std::nullopt;
    return static_cast<std::uint64_t>(st.st_size);
}

std::optional<std::string> read_symlink(std::string_view path) noexcept {
    std::string buf(4096, '\0');
    const ssize_t n = ::readlink(std::string(path).c_str(), buf.data(), buf.size() - 1);
    if (n < 0) return std::nullopt;
    buf.resize(static_cast<std::size_t>(n));
    return buf;
}

bool mkdir_p(std::string_view path, mode_t mode) noexcept {
    if (path.empty()) return false;
    std::string built;
    built.reserve(path.size());
    std::size_t i = 0;
    if (path[0] == '/') { built = "/"; i = 1; }
    while (i <= path.size()) {
        const bool at_end = i == path.size();
        if (at_end || path[i] == '/') {
            if (!built.empty() && built != "/" && !is_dir(built)) {
                if (::mkdir(built.c_str(), at_end ? mode : 0755) != 0 && errno != EEXIST) return false;
            }
        }
        if (!at_end) built += path[i];
        ++i;
    }
    return is_dir(path);
}

bool set_mode(std::string_view path, mode_t mode) noexcept {
    if (path.empty()) return false;
    const std::string p{path};
    return ::chmod(p.c_str(), mode) == 0;
}

bool write_atomic(std::string_view path, std::span<const std::byte> data, mode_t mode) noexcept {
    const std::string p{path};
    // Unique temp name + O_EXCL: a predictable ".tmp" in a shared directory is
    // a classic symlink-race foot-gun. Retry a few times; ENOENT on rename
    // means someone removed our path mid-write and that stays fatal.
    std::string tmp;
    UniqueFd fd;
    for (int attempt = 0; attempt < 4 && !fd; ++attempt) {
        tmp = std::format("{}.hyprnova-tmp-{}-{}", p, ::getpid(), attempt);
        fd = UniqueFd{::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode)};
        if (!fd && errno != EEXIST) return false;
    }
    if (!fd) return false;

    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t w = ::write(fd.get(), data.data() + off, data.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            ::unlink(tmp.c_str());
            return false;
        }
        off += static_cast<std::size_t>(w);
    }
    fd.reset();  // close before rename so the data is durable-ordered
    if (::rename(tmp.c_str(), p.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    ::chmod(p.c_str(), mode);
    return true;
}

Result<UniqueFd> open_nofollow(std::string_view path, int flags) noexcept {
    const int fd = ::open(std::string(path).c_str(), flags | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return {std::nullopt, errno, "open_nofollow " + std::string(path)};
    return {UniqueFd{fd}, 0, {}};
}

}  // namespace fsx
}  // namespace hyprnova::core
