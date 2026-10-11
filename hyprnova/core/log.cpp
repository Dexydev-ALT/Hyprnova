// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/log.cpp

#include "core/log.hpp"

#include <unistd.h>

#include <string>

#include <chrono>

#include <ctime>

#include <fcntl.h>

#include <sys/stat.h>

#include <cstdio>
#include <mutex>

namespace hyprnova::core {

// ---------------------------------------------------------------------------
// StdioSink
// ---------------------------------------------------------------------------

namespace {
const char* colour_for(LogLevel l) noexcept {
    switch (l) {
        case LogLevel::Trace: return "\033[90m";
        case LogLevel::Debug: return "\033[36m";
        case LogLevel::Info:  return "\033[32m";
        case LogLevel::Warn:  return "\033[33m";
        case LogLevel::Error: return "\033[31m";
        case LogLevel::Fatal: return "\033[1;41m";
    }
    return "";
}
}  // namespace

void StdioSink::write(const LogRecord& rec) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(rec.ts.time_since_epoch())
                        .count() %
                    1000;
    const std::time_t tt = SysClock::to_time_t(rec.ts);
    std::tm tmv{};
    ::localtime_r(&tt, &tmv);

    std::FILE* out = rec.level >= LogLevel::Warn ? stderr : stdout;
    if (colour_) {
        std::fprintf(out, "\033[90m%02d:%02d:%02d.%03ld\033[0m %s%-5s\033[0m \033[1m[%s]\033[0m %s",
                     tmv.tm_hour, tmv.tm_min, tmv.tm_sec, static_cast<long>(ms), colour_for(rec.level),
                     std::string(level_tag(rec.level)).c_str(), rec.component.c_str(),
                     rec.message.c_str());
    } else {
        std::fprintf(out, "%02d:%02d:%02d.%03ld %s [%s] %s", tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                     static_cast<long>(ms), std::string(level_tag(rec.level)).c_str(),
                     rec.component.c_str(), rec.message.c_str());
    }
    if (!rec.location.empty()) std::fprintf(out, "  \033[90m(%s)\033[0m", rec.location.c_str());
    std::fputc('\n', out);
    std::fflush(out);
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

Logger::Logger(std::size_t ring_capacity)
    : ring_{ring_capacity}, worker_{[this](std::stop_token st) { drain_loop(st); }} {}

Logger::~Logger() {
    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    drain_loop(std::stop_token{});  // final flush
}

void Logger::add_sink(std::shared_ptr<ILogSink> sink) {
    std::lock_guard lk{sink_mu_};
    sinks_.push_back(std::move(sink));
}

void Logger::log_raw(LogLevel lvl, std::string_view component, std::string msg,
                     std::source_location loc) noexcept {
    if (lvl < level_.load(std::memory_order_relaxed)) return;
    push(lvl, component, std::move(msg), loc);
}

void Logger::push(LogLevel lvl, std::string_view component, std::string msg,
                  const std::source_location& loc) noexcept {
    LogRecord rec;
    rec.ts = SysClock::now();
    rec.level = lvl;
    rec.component.assign(component);
    rec.message = std::move(msg);
    if (lvl >= LogLevel::Warn) {
        rec.location = std::string(loc.file_name()) + ":" + std::to_string(loc.line());
    }
    if (!ring_.try_push(std::move(rec))) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
    }
}

void Logger::drain_loop(std::stop_token st) {
    std::array<LogRecord, 128> batch;
    for (;;) {
        const std::size_t n = ring_.drain(batch.begin(), batch.size());
        if (n == 0) {
            if (!st.stop_possible()) break;
            if (st.stop_requested()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }

        std::vector<std::shared_ptr<ILogSink>> sinks;
        {
            std::lock_guard lk{sink_mu_};
            sinks = sinks_;
        }
        for (std::size_t i = 0; i < n; ++i) {
            emitted_.fetch_add(1, std::memory_order_relaxed);
            for (auto& s : sinks) {
                try {
                    s->write(batch[i]);
                } catch (...) {
                    // A broken sink must never take down the logger.
                }
            }
        }
    }
}

void Logger::flush() {
    std::array<LogRecord, 128> batch;
    for (;;) {
        const std::size_t n = ring_.drain(batch.begin(), batch.size());
        if (n == 0) break;
        std::vector<std::shared_ptr<ILogSink>> sinks;
        {
            std::lock_guard lk{sink_mu_};
            sinks = sinks_;
        }
        for (std::size_t i = 0; i < n; ++i) {
            for (auto& s : sinks) s->write(batch[i]);
        }
    }
}

// ---------------------------------------------------------------------------
// Global instance (explicitly injectable)
// ---------------------------------------------------------------------------

// F10: these used to be namespace-scope statics. A static library's link order
// makes OTHER TUs' static initialisers (test registrars, module objects) run
// BEFORE this TU's -- the first log line during static init then dereferenced
// a ring that had not been constructed yet (SEGV, found by the honeypot suite
// 2026-10-10). Function-local statics are constructed on FIRST USE, which
// removes the order dependency for every current and future caller.
namespace {
Logger& default_logger() noexcept {
    static Logger inst{8192};
    return inst;
}
std::atomic<Logger*>& current_slot() noexcept {
    static std::atomic<Logger*> slot{nullptr};  // null = nobody injected yet
    return slot;
}
}  // namespace

Logger& logger() noexcept {
    Logger* c = current_slot().load(std::memory_order_relaxed);
    return c ? *c : default_logger();
}

void set_global_logger(Logger* lg) noexcept {
    current_slot().store(lg ? lg : &default_logger(), std::memory_order_relaxed);
}
// ---------------------------------------------------------------------------
// FileSink
// ---------------------------------------------------------------------------

void Logger::clear_sinks() noexcept {
    std::lock_guard lk{sink_mu_};
    sinks_.clear();
}

bool FileSink::ensure_open() noexcept {
    if (fd_ >= 0) return true;
    // Create the parent directory rather than failing: on a fresh install
    // /var/log/hyprnova does not exist yet and losing the log is the worse outcome.
    const std::size_t slash = path_.find_last_of('/');
    if (slash != std::string::npos && slash > 0) {
        const std::string dir = path_.substr(0, slash);
        std::string built;
        for (std::size_t i = 0; i < dir.size(); ++i) {
            built += dir[i];
            if ((dir[i] == '/' && i > 0) || i + 1 == dir.size()) {
                if (built.size() > 1) (void)::mkdir(built.c_str(), 0750);
            }
        }
    }
    fd_ = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (fd_ < 0) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    struct stat st {};
    if (::fstat(fd_, &st) == 0) written_ = static_cast<std::uint64_t>(st.st_size);
    return true;
}

void FileSink::rotate() noexcept {
    ::close(fd_);
    fd_ = -1;
    const std::string old = path_ + ".1";
    (void)::rename(path_.c_str(), old.c_str());
    written_ = 0;
    (void)ensure_open();
}

void FileSink::write(const LogRecord& rec) {
    if (path_.empty()) return;
    if (!ensure_open()) return;

    const std::time_t t = std::chrono::system_clock::to_time_t(rec.ts);
    std::tm tm_buf {};
    ::localtime_r(&t, &tm_buf);
    char stamp[32] = {0};
    std::strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        rec.ts.time_since_epoch())
                        .count() %
                    1000;

    std::string line;
    line.reserve(rec.message.size() + rec.component.size() + rec.location.size() + 64);
    line += stamp;
    line += '.';
    line += std::to_string(ms);
    line += ' ';
    line += level_tag(rec.level);
    line += " [";
    line += rec.component;
    line += "] ";
    line += rec.message;
    if (!rec.location.empty()) {
        line += " (";
        line += rec.location;
        line += ')';
    }
    line += '\n';

    const auto n = ::write(fd_, line.data(), line.size());
    if (n < 0) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        // A transient ENOSPC or a rotated-away fd should recover on the next
        // record, so reopen rather than giving up permanently.
        ::close(fd_);
        fd_ = -1;
        return;
    }
    written_ += static_cast<std::uint64_t>(n);
    if (max_bytes_ > 0 && written_ >= max_bytes_) rotate();
}

}  // namespace hyprnova::core
