// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/log.hpp
// Lock-free-ish structured logger. Never throws, never blocks the caller on I/O:
// formatted records are pushed into a bounded SPSC ring and drained by a jthread.

#pragma once

#include <atomic>
#include <unistd.h>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <memory>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "core/ring_buffer.hpp"

namespace hyprnova::core {

using SysClock = std::chrono::system_clock;

enum class LogLevel : std::uint8_t { Trace = 0, Debug, Info, Warn, Error, Fatal };

constexpr std::string_view level_tag(LogLevel l) noexcept {
    switch (l) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
    }
    return "?????";
}

/// One formatted log record, owned by the ring buffer slot.
struct LogRecord {
    std::chrono::system_clock::time_point ts{};
    LogLevel level{LogLevel::Info};
    std::string component;
    std::string message;
    std::string location;
};

/// Backend contract: the daemon can tee to stdout *and* to a UNIX socket the
/// Qt6 GUI subscribes to, without the producers knowing about either.
class ILogSink {
public:
    virtual ~ILogSink() = default;
    virtual void write(const LogRecord& rec) = 0;
};

class StdioSink final : public ILogSink {
public:
    explicit StdioSink(bool colour = true) noexcept : colour_{colour} {}
    void write(const LogRecord& rec) override;

private:
    bool colour_;
};

class Logger {
public:
    /// Ring depth is the back-pressure valve: at 512k events/s a full ring drops
    /// rather than allocating, which is the correct EDR failure mode.
    explicit Logger(std::size_t ring_capacity = 8192);
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void add_sink(std::shared_ptr<ILogSink> sink);
    /// Drop every sink. Used by config reload so a log path change does not
    /// accumulate duplicate writers.
    void clear_sinks() noexcept;
    void set_level(LogLevel lvl) noexcept { level_.store(lvl, std::memory_order_relaxed); }
    [[nodiscard]] LogLevel level() const noexcept { return level_.load(std::memory_order_relaxed); }

    /// NOTE: source_location is deliberately NOT a trailing default on this
    /// variadic template -- a defaulted parameter after a pack makes deduction
    /// ambiguous. Location capture lives on log_raw(), which the macro layer
    /// routes warnings and errors through.
    template <typename... Args>
    void log(LogLevel lvl, std::string_view component, std::format_string<Args...> fmt,
             Args&&... args) noexcept {
        if (lvl < level_.load(std::memory_order_relaxed)) return;
        push(lvl, component, std::format(fmt, std::forward<Args>(args)...), {});
    }

    void log_loc(LogLevel lvl, std::string_view component, std::string msg,
                 const std::source_location& loc) noexcept {
        if (lvl < level_.load(std::memory_order_relaxed)) return;
        push(lvl, component, std::move(msg), loc);
    }

    void log_raw(LogLevel lvl, std::string_view component, std::string msg,
                 std::source_location loc = std::source_location::current()) noexcept;

    /// Drops are observable — a GUI counter, not a silent failure.
    [[nodiscard]] std::uint64_t dropped() const noexcept { return dropped_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t emitted() const noexcept { return emitted_.load(std::memory_order_relaxed); }

    void flush();

private:
    void push(LogLevel lvl, std::string_view component, std::string msg,
              const std::source_location& loc) noexcept;
    void push(LogLevel lvl, std::string_view component, std::string msg, std::nullptr_t) noexcept {
        push(lvl, component, std::move(msg), std::source_location{});
    }
    void drain_loop(std::stop_token st);

    SpscRing<LogRecord> ring_;
    std::atomic<LogLevel> level_{LogLevel::Info};
    std::atomic<std::uint64_t> dropped_{0};
    std::atomic<std::uint64_t> emitted_{0};
    std::jthread worker_;
    std::mutex sink_mu_;
    std::vector<std::shared_ptr<ILogSink>> sinks_;
};

/// Append-only file sink with size-based rotation, for the daemon case where
/// there is no console. Rotation keeps a single .1 generation: an EDR that fills
/// a disk has replaced one incident with another, and the journal in
/// /var/lib/hyprnova is the durable forensic record anyway.
class FileSink final : public ILogSink {
public:
    FileSink(std::string path, std::size_t max_bytes = 16 << 20) noexcept
        : path_{std::move(path)}, max_bytes_{max_bytes} {}
    ~FileSink() override {
        if (fd_ >= 0) ::close(fd_);
    }

    FileSink(const FileSink&) = delete;
    FileSink& operator=(const FileSink&) = delete;

    void write(const LogRecord& rec) override;
    [[nodiscard]] std::uint64_t dropped() const noexcept { return dropped_.load(std::memory_order_relaxed); }
    [[nodiscard]] const std::string& path() const noexcept { return path_; }

private:
    bool ensure_open() noexcept;
    void rotate() noexcept;

    std::string path_;
    std::size_t max_bytes_;
    int fd_{-1};
    std::uint64_t written_{0};
    std::atomic<std::uint64_t> dropped_{0};
};

namespace detail {
template <typename... Args>
inline std::string format_or_plain(std::format_string<Args...> fmt, Args&&... args) {
    return std::format(fmt, std::forward<Args>(args)...);
}
}  // namespace detail

/// Process-wide instance, injected explicitly (no hidden globals in module code).
Logger& logger() noexcept;
void set_global_logger(Logger* lg) noexcept;

#define SLOG(component, lvl, ...)                                                                  \
    ::hyprnova::core::logger().log(lvl, component __VA_OPT__(, ) __VA_ARGS__)

#define STRACE(c, ...) SLOG(c, ::hyprnova::core::LogLevel::Trace __VA_OPT__(, ) __VA_ARGS__)
#define SDEBUG(c, ...) SLOG(c, ::hyprnova::core::LogLevel::Debug __VA_OPT__(, ) __VA_ARGS__)
#define SINFO(c, ...)  SLOG(c, ::hyprnova::core::LogLevel::Info  __VA_OPT__(, ) __VA_ARGS__)
#define SLOC_LOG(component, lvl, ...)                                                              \
    ::hyprnova::core::logger().log_loc(                                                            \
        lvl, component, ::hyprnova::core::detail::format_or_plain(__VA_ARGS__),                    \
        std::source_location::current())

#define SWARN(c, ...)  SLOC_LOG(c, ::hyprnova::core::LogLevel::Warn  __VA_OPT__(, ) __VA_ARGS__)
#define SERROR(c, ...) SLOC_LOG(c, ::hyprnova::core::LogLevel::Error __VA_OPT__(, ) __VA_ARGS__)

}  // namespace hyprnova::core
