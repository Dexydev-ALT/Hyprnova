// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/thread_pool.hpp
// Bounded worker pool for off-thread blocking work: YARA evaluation, mmap'd
// hashing, clamdscan execve, osquery subprocesses.
//
// The sensor threads (epoll loops) NEVER block. Anything that can block goes
// here, with a bounded queue so a flood of candidate files produces back-pressure
// and a visible drop counter instead of unbounded memory growth.

#pragma once

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "core/log.hpp"

namespace hyprnova::core {

struct ThreadPoolConfig {
    std::size_t workers = std::max(2u, std::thread::hardware_concurrency() / 2);
    std::size_t queue_depth = 4096;
    std::string name = "hyprnova-pool";
    /// Real-time-ish priority for scan workers is deliberately NOT set: an EDR
    /// agent that starves the host's own workloads creates an availability
    /// incident worse than the detection gap.
};

class ThreadPool {
public:
    explicit ThreadPool(ThreadPoolConfig cfg = {});
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /// Enqueue blocking work. Returns false when the queue is saturated; the
    /// caller decides whether to drop, coalesce or escalate.
    [[nodiscard]] bool submit(std::function<void()> task, std::string label = {});

    /// Priority lane for remediation-triggered deep inspection. These jump ahead
    /// of routine download-folder scans.
    [[nodiscard]] bool submit_urgent(std::function<void()> task, std::string label = {});

    void shutdown();

    [[nodiscard]] std::size_t queued() const;
    [[nodiscard]] std::uint64_t completed() const noexcept { return completed_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t rejected() const noexcept { return rejected_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t failures() const noexcept { return failures_.load(std::memory_order_relaxed); }
    [[nodiscard]] const std::string& name() const noexcept { return cfg_.name; }

private:
    void worker_loop(std::stop_token st);

    struct Task {
        std::function<void()> fn;
        std::string label;
    };

    ThreadPoolConfig cfg_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Task> urgent_;
    std::deque<Task> normal_;
    std::vector<std::jthread> workers_;
    std::atomic<std::uint64_t> completed_{0};
    std::atomic<std::uint64_t> rejected_{0};
    std::atomic<std::uint64_t> failures_{0};
    bool shutdown_{false};
};

}  // namespace hyprnova::core
