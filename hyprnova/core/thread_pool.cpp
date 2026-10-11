// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/thread_pool.cpp

#include "core/thread_pool.hpp"

namespace hyprnova::core {

ThreadPool::ThreadPool(ThreadPoolConfig cfg) : cfg_{std::move(cfg)} {
    if (cfg_.workers == 0) cfg_.workers = 2;
    workers_.reserve(cfg_.workers);
    for (std::size_t i = 0; i < cfg_.workers; ++i) {
        workers_.emplace_back([this](std::stop_token st) { worker_loop(st); });
    }
    SINFO("thread-pool", "{} started with {} workers, queue depth {}", cfg_.name, cfg_.workers,
          cfg_.queue_depth);
}

ThreadPool::~ThreadPool() { shutdown(); }

void ThreadPool::shutdown() {
    {
        std::lock_guard lk{mu_};
        shutdown_ = true;
    }
    cv_.notify_all();
    for (auto& w : workers_) {
        if (w.joinable()) {
            w.request_stop();
            w.join();
        }
    }
    workers_.clear();
}

std::size_t ThreadPool::queued() const {
    std::lock_guard lk{mu_};
    return urgent_.size() + normal_.size();
}

bool ThreadPool::submit(std::function<void()> task, std::string label) {
    if (!task) return false;
    {
        std::lock_guard lk{mu_};
        if (shutdown_) return false;
        if (urgent_.size() + normal_.size() >= cfg_.queue_depth) {
            rejected_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        normal_.push_back({std::move(task), std::move(label)});
    }
    cv_.notify_one();
    return true;
}

bool ThreadPool::submit_urgent(std::function<void()> task, std::string label) {
    if (!task) return false;
    {
        std::lock_guard lk{mu_};
        if (shutdown_) return false;
        if (urgent_.size() >= cfg_.queue_depth / 4) {
            rejected_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        urgent_.push_front({std::move(task), std::move(label)});
    }
    cv_.notify_one();
    return true;
}

void ThreadPool::worker_loop(std::stop_token st) {
    for (;;) {
        Task task;
        {
            std::unique_lock lk{mu_};
            cv_.wait(lk, [&] { return shutdown_ || st.stop_requested() || !urgent_.empty() || !normal_.empty(); });
            if ((!urgent_.empty() || !normal_.empty())) {
                if (!urgent_.empty()) {
                    task = std::move(urgent_.front());
                    urgent_.pop_front();
                } else {
                    task = std::move(normal_.front());
                    normal_.pop_front();
                }
            } else {
                return;  // shutdown or stop requested with an empty queue
            }
        }

        try {
            task.fn();
            completed_.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            failures_.fetch_add(1, std::memory_order_relaxed);
            SERROR("thread-pool", "task '{}' failed: {}", task.label, e.what());
        } catch (...) {
            failures_.fetch_add(1, std::memory_order_relaxed);
            SERROR("thread-pool", "task '{}' failed with unknown exception", task.label);
        }
    }
}

}  // namespace hyprnova::core
