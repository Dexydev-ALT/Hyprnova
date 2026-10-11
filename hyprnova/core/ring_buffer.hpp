// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/ring_buffer.hpp
// Bounded single-producer / single-consumer ring buffer.
//
// Design notes for the EDR hot path:
//   * Power-of-two capacity -> index masking instead of modulo.
//   * Each slot carries its own sequence number (Vyukov-style), so the producer
//     and consumer never share a cache line for the common case and no lock is
//     ever taken. This is what lets the fanotify/inotify producer thread run at
//     kernel speed while the scanner consumer batches at its own pace.
//   * try_push returns false on a full ring. Callers MUST count that as a drop
//     and surface it; blocking here would propagate kernel back-pressure into
//     the audit subsystem and cost us events.
//   * MpscRing is provided for the fan-in case (N sensors -> 1 heuristic engine).

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

namespace hyprnova::core {

namespace detail {
// Fixed rather than std::hardware_destructive_interference_size: that constant
// can vary with -mtune, and an EDR daemon's ring buffers must have a stable,
// ABI-independent cache-line stride across the sensors and the GUI process.
inline constexpr std::size_t kCacheLine = 64;
}

/// Lock-free SPSC ring over a heap-allocated slot array.
template <typename T>
    requires std::is_nothrow_destructible_v<T>
class SpscRing {
public:
    explicit SpscRing(std::size_t capacity)
        : mask_{round_up_pow2(capacity < 2 ? 2 : capacity) - 1},
          slots_{std::make_unique<Cell[]>(mask_ + 1)} {
        const std::size_t n = mask_ + 1;
        for (std::size_t i = 0; i < n; ++i) slots_[i].seq.store(i, std::memory_order_relaxed);
    }

    SpscRing(const SpscRing&) = delete;
    SpscRing& operator=(const SpscRing&) = delete;
    SpscRing(SpscRing&&) = delete;
    SpscRing& operator=(SpscRing&&) = delete;

    ~SpscRing() {
        while (try_pop_one()) {}  // release any live slots
    }

    [[nodiscard]] std::size_t capacity() const noexcept { return mask_ + 1; }

    [[nodiscard]] std::size_t size_approx() const noexcept {
        const auto w = head_.load(std::memory_order_acquire);
        const auto r = tail_.load(std::memory_order_acquire);
        return static_cast<std::size_t>(w - r);
    }

    /// Non-blocking enqueue. Returns false if the ring is full (caller counts a drop).
    template <typename U>
        requires std::constructible_from<T, U&&>
    [[nodiscard]] bool try_push(U&& value) noexcept(std::is_nothrow_constructible_v<T, U&&>) {
        const std::size_t pos = head_.load(std::memory_order_relaxed);
        Cell& cell = slots_[pos & mask_];
        const std::size_t seq = cell.seq.load(std::memory_order_acquire);
        const auto diff = static_cast<std::ptrdiff_t>(seq) - static_cast<std::ptrdiff_t>(pos);
        if (diff < 0) return false;  // full
        std::construct_at<T>(slot_ptr(cell), std::forward<U>(value));
        cell.seq.store(pos + 1, std::memory_order_release);
        head_.store(pos + 1, std::memory_order_release);
        return true;
    }

    /// Non-blocking dequeue.
    [[nodiscard]] std::optional<T> try_pop() noexcept {
        const std::size_t pos = tail_.load(std::memory_order_relaxed);
        Cell& cell = slots_[pos & mask_];
        const std::size_t seq = cell.seq.load(std::memory_order_acquire);
        const auto diff = static_cast<std::ptrdiff_t>(seq) - static_cast<std::ptrdiff_t>(pos + 1);
        if (diff < 0) return std::nullopt;  // empty
        T* p = std::launder(slot_ptr(cell));
        std::optional<T> out{std::move(*p)};
        std::destroy_at(p);
        cell.seq.store(pos + mask_ + 1, std::memory_order_release);
        tail_.store(pos + 1, std::memory_order_release);
        return out;
    }

    /// Bulk drain used by the 15 s KVRT/clamdscan batch flusher: amortises the
    /// atomics over the whole batch instead of per item.
    template <typename OutIt>
    std::size_t drain(OutIt out, std::size_t max_items) noexcept {
        std::size_t n = 0;
        while (n < max_items) {
            auto v = try_pop();
            if (!v.has_value()) break;
            *out++ = std::move(*v);
            ++n;
        }
        return n;
    }

    [[nodiscard]] bool try_pop_one() noexcept { return try_pop().has_value(); }

private:
    static constexpr std::size_t round_up_pow2(std::size_t v) noexcept {
        std::size_t p = 1;
        while (p < v) p <<= 1;
        return p;
    }

    struct Cell {
        std::atomic<std::size_t> seq{0};
        alignas(T) std::byte storage[sizeof(T)];
    };

    static T* slot_ptr(Cell& c) noexcept {
        return std::launder(reinterpret_cast<T*>(std::addressof(c.storage)));
    }

    const std::size_t mask_;
    std::unique_ptr<Cell[]> slots_;

    alignas(detail::kCacheLine) std::atomic<std::size_t> head_{0};
    alignas(detail::kCacheLine) std::atomic<std::size_t> tail_{0};
};

/// Multi-producer / single-consumer variant for sensor fan-in.
/// Producers CAS-claim a slot; the single consumer drains in order.
template <typename T>
    requires std::is_nothrow_destructible_v<T>
class MpscRing {
public:
    explicit MpscRing(std::size_t capacity)
        : mask_{round_up_pow2(capacity < 2 ? 2 : capacity) - 1},
          slots_{std::make_unique<Cell[]>(mask_ + 1)} {
        // Slot i must start at seq == i. A Vyukov cell's sequence is the
        // "position this slot is next free at" counter, so leaving every slot at
        // seq 0 makes the producer's (seq - pos) test report FULL for every slot
        // except slot 0 -- the ring would accept exactly one item and then wedge.
        const std::size_t n = mask_ + 1;
        for (std::size_t i = 0; i < n; ++i) slots_[i].seq.store(i, std::memory_order_relaxed);
    }

    MpscRing(const MpscRing&) = delete;
    MpscRing& operator=(const MpscRing&) = delete;

    ~MpscRing() {
        while (try_pop().has_value()) {}
    }

    [[nodiscard]] std::size_t capacity() const noexcept { return mask_ + 1; }

    template <typename U>
        requires std::constructible_from<T, U&&>
    [[nodiscard]] bool try_push(U&& value) noexcept {
        std::size_t pos = head_.load(std::memory_order_relaxed);
        for (;;) {
            Cell& cell = slots_[pos & mask_];
            const std::size_t seq = cell.seq.load(std::memory_order_acquire);
            const auto diff = static_cast<std::ptrdiff_t>(seq) - static_cast<std::ptrdiff_t>(pos);
            if (diff < 0) return false;  // full
            if (head_.compare_exchange_weak(pos, pos + 1, std::memory_order_acq_rel,
                                            std::memory_order_relaxed)) {
                std::construct_at<T>(slot_ptr(cell), std::forward<U>(value));
                cell.seq.store(pos + 1, std::memory_order_release);
                return true;
            }
        }
    }

    [[nodiscard]] std::optional<T> try_pop() noexcept {
        const std::size_t pos = tail_.load(std::memory_order_relaxed);
        Cell& cell = slots_[pos & mask_];
        const std::size_t seq = cell.seq.load(std::memory_order_acquire);
        const auto diff = static_cast<std::ptrdiff_t>(seq) - static_cast<std::ptrdiff_t>(pos + 1);
        if (diff < 0) return std::nullopt;
        T* p = std::launder(slot_ptr(cell));
        std::optional<T> out{std::move(*p)};
        std::destroy_at(p);
        cell.seq.store(pos + mask_ + 1, std::memory_order_release);
        tail_.store(pos + 1, std::memory_order_release);
        return out;
    }

    /// Bulk drain for the single consumer. Amortises the tail_ store over the
    /// whole batch, which matters when N sensors push into one engine.
    template <typename OutIt>
    std::size_t drain(OutIt out_it, std::size_t max_items) noexcept {
        std::size_t n = 0;
        while (n < max_items) {
            auto v = try_pop();
            if (!v.has_value()) break;
            *out_it++ = std::move(*v);
            ++n;
        }
        return n;
    }

    [[nodiscard]] std::size_t size_approx() const noexcept {
        const auto w = head_.load(std::memory_order_acquire);
        const auto r = tail_.load(std::memory_order_acquire);
        return static_cast<std::size_t>(w - r);
    }

private:
    static constexpr std::size_t round_up_pow2(std::size_t v) noexcept {
        std::size_t p = 1;
        while (p < v) p <<= 1;
        return p;
    }

    struct Cell {
        std::atomic<std::size_t> seq{0};
        alignas(T) std::byte storage[sizeof(T)];
    };

    static T* slot_ptr(Cell& c) noexcept {
        return std::launder(reinterpret_cast<T*>(std::addressof(c.storage)));
    }

    const std::size_t mask_;
    std::unique_ptr<Cell[]> slots_;
    alignas(detail::kCacheLine) std::atomic<std::size_t> head_{0};
    alignas(detail::kCacheLine) std::atomic<std::size_t> tail_{0};
};

}  // namespace hyprnova::core
