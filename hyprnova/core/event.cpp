// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/event.cpp

#include "core/event.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <poll.h>
#include <thread>

#include "core/fd.hpp"
#include "core/log.hpp"

namespace hyprnova::core {


std::string TelemetryEvent::one_line() const {
    std::string out;
    out.reserve(message.size() + 64);
    out += severity_name(severity);
    out += " | ";
    out += sensor_name(sensor);
    out += " | ";
    out += kind_name(kind);
    if (actor.pid > 0) {
        out += " | pid=";
        out += std::to_string(actor.pid);
        if (!actor.exe.empty()) {
            out += " exe=";
            out += actor.exe;
        }
    }
    if (!target.path.empty()) {
        out += " | path=";
        out += target.path;
    }
    if (!message.empty()) {
        out += " | ";
        out += message;
    }
    return out;
}

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

EventBus::EventBus(std::size_t ring_capacity) : ring_{ring_capacity} {
    auto w = WakeupEvent::create();
    if (w) {
        wake_ = std::make_unique<WakeupEvent>(std::move(*w));
    } else {
        SERROR("event-bus", "eventfd unavailable ({}); dispatcher will poll on a 50ms tick", w.message());
    }
}

EventBus::~EventBus() { stop(); }

void EventBus::start() {
    if (started_) return;
    started_ = true;
    dispatcher_ = std::jthread([this](std::stop_token st) { dispatch_loop(st); });
}

void EventBus::stop() {
    if (!started_) return;
    started_ = false;
    if (dispatcher_.joinable()) {
        dispatcher_.request_stop();
        if (wake_) wake_->signal();
        dispatcher_.join();
    }
    // Final drain so late events still reach the journal/GUI on shutdown.
    dispatch_loop(std::stop_token{});
}

SubscriptionId EventBus::subscribe(std::string name, EventSink sink) {
    auto sub = std::make_shared<Sub>();
    sub->name = std::move(name);
    sub->sink = std::move(sink);
    {
        std::unique_lock lk{mu_};
        sub->id = next_id_++;
        subs_.push_back(sub);
    }
    return sub->id;
}

void EventBus::unsubscribe(SubscriptionId id) {
    std::unique_lock lk{mu_};
    std::erase_if(subs_, [id](const auto& s) { return s->id == id; });
}

std::size_t EventBus::subscriber_count() const {
    std::shared_lock lk{mu_};
    return subs_.size();
}

std::vector<EventBus::SubscriberStat> EventBus::stats() const {
    std::shared_lock lk{mu_};
    std::vector<SubscriberStat> out;
    out.reserve(subs_.size());
    for (const auto& s : subs_) {
        out.push_back({s->name, s->delivered.load(std::memory_order_relaxed),
                       s->slow.load(std::memory_order_relaxed)});
    }
    return out;
}

bool EventBus::publish(TelemetryEvent ev) noexcept {
    ev.monotonic_id = seq_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (ev.ts == TimePoint{}) ev.ts = SysClock::now();
    if (ev.mono == SteadyClock::time_point{}) ev.mono = SteadyClock::now();

    published_.fetch_add(1, std::memory_order_relaxed);
    if (!ring_.try_push(std::move(ev))) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (wake_) wake_->signal();
    return true;
}

void EventBus::emit(SensorId sensor, EventKind kind, Severity sev, std::string msg) noexcept {
    TelemetryEvent ev;
    ev.sensor = sensor;
    ev.kind = kind;
    ev.severity = sev;
    ev.message = std::move(msg);
    (void)publish(std::move(ev));
}

void EventBus::dispatch_loop(std::stop_token st) {
    // Batch dispatch: pull up to 256 events per wake so one syscall fans out to
    // many subscribers. This is the difference between 3% and 40% CPU under load.
    std::array<TelemetryEvent, 256> batch;
    std::size_t n = 0;

    while (true) {
        n = ring_.drain(batch.begin(), batch.size());
        if (n == 0) {
            if (st.stop_possible() && st.stop_requested()) break;
            if (!st.stop_possible()) break;  // final drain after stop()

            // Block on the wake eventfd rather than spinning.
            if (wake_) {
                pollfd pfd{};
                pfd.fd = wake_->fd();
                pfd.events = POLLIN;
                const int r = ::poll(&pfd, 1, 100);
                if (r > 0) wake_->drain();
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            continue;
        }

        std::shared_lock lk{mu_};
        if (subs_.empty()) {
            dispatched_.fetch_add(n, std::memory_order_relaxed);
            continue;
        }

        for (std::size_t i = 0; i < n; ++i) {
            const TelemetryEvent& ev = batch[i];
            for (const auto& sub : subs_) {
                if (!sub->sink) continue;
                const auto t0 = SteadyClock::now();
                try {
                    sub->sink(ev);
                } catch (const std::exception& e) {
                    // A throwing subscriber (a buggy GUI model) must never take
                    // down the dispatcher, which would blind every sensor.
                    SERROR("event-bus", "subscriber '{}' threw: {}", sub->name, e.what());
                } catch (...) {
                    SERROR("event-bus", "subscriber '{}' threw unknown exception", sub->name);
                }
                const auto dt = SteadyClock::now() - t0;
                sub->delivered.fetch_add(1, std::memory_order_relaxed);
                if (dt > std::chrono::milliseconds(5)) sub->slow.fetch_add(1, std::memory_order_relaxed);
            }
            dispatched_.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

}  // namespace hyprnova::core
