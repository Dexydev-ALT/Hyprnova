// SPDX-License-Identifier: Apache-2.0
// HyprNova :: behavioral/socket_source.hpp
// Reusable non-blocking UNIX-domain-socket client.
//
// Falco, Suricata (unix socket mode) and any eBPF loader that speaks ndjson over
// a socket all need the same thing: connect, reconnect with backoff, read into an
// ndjson splitter, never block the sensor thread. This class is that, once.

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "core/event.hpp"
#include "core/fd.hpp"
#include "core/json.hpp"

namespace hyprnova::behavioral {

using namespace std::chrono_literals;

class UnixSocketSource {
public:
    enum class State : std::uint8_t { Disconnected, Connecting, Connected, Failed, Disabled };

    struct Options {
        std::string path;
        std::chrono::seconds reconnect_max{60s};
        std::chrono::milliseconds reconnect_initial{500ms};
        std::size_t max_line_bytes{1 << 20};
        std::size_t read_chunk{64 * 1024};
        /// Some producers (Suricata unix socket) expect a command frame on
        /// connect before they emit anything.
        std::string handshake;
        bool require_handshake_ack{false};
    };

    explicit UnixSocketSource(Options opts);
    ~UnixSocketSource();

    UnixSocketSource(const UnixSocketSource&) = delete;
    UnixSocketSource& operator=(const UnixSocketSource&) = delete;

    /// Attempt a (re)connect. Non-blocking semantics: returns immediately.
    [[nodiscard]] bool connect_now() noexcept;

    /// Read whatever is available. Returns the number of complete JSON values
    /// now retrievable via next(). Never blocks longer than a single recv().
    std::size_t pump() noexcept;

    [[nodiscard]] std::optional<core::json::Value> next() noexcept { return nd_.next(); }
    [[nodiscard]] bool has_pending() const noexcept { return nd_.pending_lines() > 0; }

    [[nodiscard]] int fd() const noexcept { return fd_.get(); }
    [[nodiscard]] State state() const noexcept { return state_; }
    [[nodiscard]] const std::string& path() const noexcept { return opts_.path; }
    [[nodiscard]] std::string state_string() const noexcept;
    [[nodiscard]] std::string last_error() const noexcept { return last_error_; }

    [[nodiscard]] std::uint64_t messages() const noexcept { return messages_; }
    [[nodiscard]] std::uint64_t bytes_read() const noexcept { return bytes_; }
    [[nodiscard]] std::uint64_t reconnects() const noexcept { return reconnects_; }
    [[nodiscard]] std::uint64_t malformed() const noexcept { return malformed_; }
    [[nodiscard]] bool truncated_line_seen() const noexcept { return nd_.truncated_line_seen(); }

    /// Send a command frame (Suricata's unix socket protocol, or a Falco
    /// keepalive). Returns false when not connected.
    [[nodiscard]] bool send(std::string_view payload) noexcept;

    /// Called by the sensor loop each iteration; handles backoff and reconnect.
    void tick() noexcept;

    void close() noexcept;

private:
    Options opts_;
    core::UniqueFd fd_;
    core::json::NdjsonReader nd_;
    State state_{State::Disconnected};
    std::string last_error_;
    std::chrono::milliseconds backoff_;
    core::SteadyClock::time_point next_attempt_{};
    std::uint64_t messages_{0};
    std::uint64_t bytes_{0};
    std::uint64_t reconnects_{0};
    std::uint64_t malformed_{0};
};

/// Map a producer's textual priority to our Severity, used by both Falco and
/// Suricata so their severities are comparable in the GUI.
[[nodiscard]] core::Severity severity_from_priority(std::string_view priority) noexcept;
[[nodiscard]] core::Severity severity_from_eve(std::string_view event_type, std::int64_t severity) noexcept;

}  // namespace hyprnova::behavioral
