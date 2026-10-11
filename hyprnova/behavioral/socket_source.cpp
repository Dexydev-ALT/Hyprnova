// SPDX-License-Identifier: Apache-2.0
// HyprNova :: behavioral/socket_source.cpp

#include "behavioral/socket_source.hpp"

#include <algorithm>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/log.hpp"

namespace hyprnova::behavioral {

using namespace std::chrono_literals;

UnixSocketSource::UnixSocketSource(Options opts)
    : opts_{std::move(opts)},
      nd_{opts_.max_line_bytes},
      backoff_{opts_.reconnect_initial} {}

UnixSocketSource::~UnixSocketSource() { close(); }

void UnixSocketSource::close() noexcept {
    if (fd_) {
        ::shutdown(fd_.get(), SHUT_RDWR);
        fd_.reset();
    }
    state_ = State::Disconnected;
}

std::string UnixSocketSource::state_string() const noexcept {
    switch (state_) {
        case State::Disconnected: return "disconnected";
        case State::Connecting: return "connecting";
        case State::Connected: return "connected";
        case State::Failed: return "failed";
        case State::Disabled: return "disabled";
    }
    return "disconnected";
}

bool UnixSocketSource::connect_now() noexcept {
    if (opts_.path.empty()) {
        state_ = State::Disabled;
        last_error_ = "no socket path configured";
        return false;
    }
    if (!core::fsx::exists(opts_.path)) {
        state_ = State::Disconnected;
        last_error_ = "socket path does not exist: " + opts_.path;
        return false;
    }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        last_error_ = std::string("socket: ") + std::strerror(errno);
        state_ = State::Failed;
        return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (opts_.path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        last_error_ = "socket path too long for sockaddr_un: " + opts_.path;
        state_ = State::Failed;
        return false;
    }
    std::strncpy(addr.sun_path, opts_.path.c_str(), sizeof(addr.sun_path) - 1);

    state_ = State::Connecting;
    const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc != 0 && errno != EINPROGRESS && errno != EAGAIN) {
        ::close(fd);
        last_error_ = std::string("connect: ") + std::strerror(errno);
        state_ = State::Disconnected;
        return false;
    }

    // Wait for the connection to complete without blocking the sensor thread for
    // more than a short bounded poll: a wedged Falco socket must not stall us.
    if (rc != 0) {
        pollfd pfd{fd, POLLOUT, 0};
        const int pr = ::poll(&pfd, 1, 1000);
        if (pr <= 0) {
            ::close(fd);
            last_error_ = "connect timed out";
            state_ = State::Disconnected;
            return false;
        }
        int so_err = 0;
        socklen_t len = sizeof(so_err);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len);
        if (so_err != 0) {
            ::close(fd);
            last_error_ = std::string("connect failed: ") + std::strerror(so_err);
            state_ = State::Disconnected;
            return false;
        }
    }

    fd_ = core::UniqueFd{fd};
    state_ = State::Connected;
    backoff_ = opts_.reconnect_initial;
    ++reconnects_;
    last_error_.clear();

    if (!opts_.handshake.empty()) {
        if (!send(opts_.handshake)) {
            SDEBUG("socket-source", "handshake write to {} failed", opts_.path);
        }
    }
    SINFO("socket-source", "connected to {}", opts_.path);
    return true;
}

bool UnixSocketSource::send(std::string_view payload) noexcept {
    if (!fd_) return false;
    std::size_t off = 0;
    while (off < payload.size()) {
        const ssize_t n = ::send(fd_.get(), payload.data() + off, payload.size() - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (core::would_block(errno)) {
                pollfd pfd{fd_.get(), POLLOUT, 0};
                if (::poll(&pfd, 1, 500) <= 0) return false;
                continue;
            }
            last_error_ = std::string("send: ") + std::strerror(errno);
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

std::size_t UnixSocketSource::pump() noexcept {
    if (state_ != State::Connected || !fd_) return 0;

    std::string chunk;
    chunk.resize(opts_.read_chunk);
    std::size_t total = 0;

    // Drain until EAGAIN. Bounded passes so a flooding producer cannot keep us
    // inside pump() indefinitely and starve the other sensors on this thread.
    for (int pass = 0; pass < 16; ++pass) {
        const ssize_t n = ::recv(fd_.get(), chunk.data(), chunk.size(), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (core::would_block(errno)) break;
            last_error_ = std::string("recv: ") + std::strerror(errno);
            close();
            next_attempt_ = core::SteadyClock::now() + backoff_;
            return total;
        }
        if (n == 0) {
            // Peer closed. Falco restarts do this; reconnect with backoff.
            last_error_ = "peer closed the socket";
            close();
            next_attempt_ = core::SteadyClock::now() + backoff_;
            return total;
        }
        const std::size_t got = static_cast<std::size_t>(n);
        total += got;
        bytes_ += got;
        nd_.feed(std::string_view{chunk.data(), got});
        if (got < chunk.size()) break;
    }

    if (nd_.truncated_line_seen() && malformed_ == 0) {
        // Only report this once per connection: it means the peer is sending a
        // frame larger than our cap, which is itself worth knowing.
        ++malformed_;
        SWARN("socket-source", "{} sent a line longer than {} bytes; truncating", opts_.path,
              opts_.max_line_bytes);
    }
    messages_ += nd_.pending_lines();
    return total;
}

void UnixSocketSource::tick() noexcept {
    if (state_ == State::Connected || state_ == State::Disabled) return;
    if (core::SteadyClock::now() < next_attempt_) return;

    if (connect_now()) return;

    // Exponential backoff with a cap. A producer that is genuinely absent
    // (Falco not installed) must not spin: after the cap we retry once a minute
    // forever, which is cheap and picks up a later install without a restart.
    const auto capped = std::min(backoff_ * 2,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(opts_.reconnect_max));
    backoff_ = capped;
    next_attempt_ = core::SteadyClock::now() + backoff_;
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

core::Severity severity_from_priority(std::string_view priority) noexcept {
    std::string p{priority};
    std::transform(p.begin(), p.end(), p.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (p == "emergency" || p == "critical" || p == "alert") return core::Severity::Critical;
    if (p == "error") return core::Severity::High;
    if (p == "warning") return core::Severity::Medium;
    if (p == "notice") return core::Severity::Low;
    return core::Severity::Info;
}

core::Severity severity_from_eve(std::string_view event_type, std::int64_t severity) noexcept {
    std::string t{event_type};
    std::transform(t.begin(), t.end(), t.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (t == "alert") {
        // Suricata alert severity is 1 (high) .. 4 (low).
        if (severity <= 1) return core::Severity::Critical;
        if (severity == 2) return core::Severity::High;
        if (severity == 3) return core::Severity::Medium;
        return core::Severity::Low;
    }
    if (t == "dns" || t == "http" || t == "tls" || t == "flow") return core::Severity::Info;
    if (t == "fileinfo") return core::Severity::Low;
    return core::Severity::Info;
}

}  // namespace hyprnova::behavioral
