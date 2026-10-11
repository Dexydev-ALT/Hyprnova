// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 3b/3c — Static Scanner + Batch Queue Orchestrator

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/config.hpp"
#include "core/ring_buffer.hpp"
#include "core/sensor.hpp"
#include "scanning/yara_engine.hpp"

namespace hyprnova::scanning {

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Scan request / verdict
// ---------------------------------------------------------------------------

enum class ScanPriority : std::uint8_t { Low = 0, Normal, High, Urgent };

enum class ScanReason : std::uint8_t {
    InotifyCreate = 0,
    InotifyModify,
    DownloadDrop,
    ExecDetected,
    CanaryEscalation,   // Module 5 asked for a deep look at this file
    HeuristicEscalation,
    OnDemand,           // GUI "scan this path"
    FullSweep,
    MemoryStrings,      // escalation pipeline step 2
};

constexpr std::string_view reason_name(ScanReason r) noexcept {
    switch (r) {
        case ScanReason::InotifyCreate: return "inotify:create";
        case ScanReason::InotifyModify: return "inotify:modify";
        case ScanReason::DownloadDrop: return "download-drop";
        case ScanReason::ExecDetected: return "exec-detected";
        case ScanReason::CanaryEscalation: return "canary-escalation";
        case ScanReason::HeuristicEscalation: return "heuristic-escalation";
        case ScanReason::OnDemand: return "on-demand";
        case ScanReason::FullSweep: return "full-sweep";
        case ScanReason::MemoryStrings: return "memory-strings";
    }
    return "unknown";
}

struct ScanRequest {
    std::string path;
    ScanReason reason{ScanReason::OnDemand};
    ScanPriority priority{ScanPriority::Normal};
    pid_t attributing_pid{0};   // who created/wrote it, when known
    core::SysClock::time_point queued_at{};
    /// Set when Module 5 escalated this; the result then feeds straight back
    /// into the actor's risk score rather than only the file's verdict.
    bool escalated{false};
    std::uint64_t dedup_key{0};
};

enum class Verdict : std::uint8_t { Clean = 0, Suspicious, Malicious, Unknown, Skipped, Error };

constexpr std::string_view verdict_name(Verdict v) noexcept {
    switch (v) {
        case Verdict::Clean: return "clean";
        case Verdict::Suspicious: return "suspicious";
        case Verdict::Malicious: return "MALICIOUS";
        case Verdict::Unknown: return "unknown";
        case Verdict::Skipped: return "skipped";
        case Verdict::Error: return "error";
    }
    return "unknown";
}

struct ScanResult {
    std::string path;
    Verdict verdict{Verdict::Unknown};
    std::vector<Match> matches;
    std::string sha256;
    std::uint64_t size{0};
    double entropy{0.0};
    core::hash::FileFlavour flavour{core::hash::FileFlavour::Unknown};
    std::chrono::milliseconds elapsed{};
    ScanReason reason{ScanReason::OnDemand};
    pid_t attributing_pid{0};
    std::string engine;      // "yara-lite" | "libyara" | "clamdscan" | "kvrt"
    std::string detail;
    std::uint16_t risk{0};   // 0..1000
    bool from_cache{false};
};

// ---------------------------------------------------------------------------
// Hash cache
// ---------------------------------------------------------------------------

/// sha256 -> previous verdict. A file whose digest we already judged does not
/// need re-judging; this is what makes a full sweep of a home directory with
/// 40 GB of unchanged data cheap. Bounded LRU by insertion order.
class VerdictCache {
public:
    explicit VerdictCache(std::size_t max_entries = 200000) : max_{max_entries} {}

    struct Entry {
        Verdict verdict{Verdict::Unknown};
        std::uint64_t size{0};
        std::int64_t mtime{0};
        std::uint16_t risk{0};
        std::vector<std::string> rules;
        core::SysClock::time_point when{};
    };

    [[nodiscard]] std::optional<Entry> lookup(std::string_view sha256, std::uint64_t size,
                                              std::int64_t mtime) const noexcept;
    void insert(std::string_view sha256, Entry e) noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] std::uint64_t hits() const noexcept { return hits_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t misses() const noexcept { return misses_.load(std::memory_order_relaxed); }
    void clear() noexcept;

private:
    std::size_t max_;
    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, Entry> map_;
    std::deque<std::string> order_;
    mutable std::atomic<std::uint64_t> hits_{0};
    mutable std::atomic<std::uint64_t> misses_{0};
};

// ---------------------------------------------------------------------------
// Batch queue — the cold-start bypass
// ---------------------------------------------------------------------------

/// Accumulates unverified paths and flushes them as ONE external-scanner
/// invocation. Spawning clamdscan per file costs ~40 ms of process setup each
/// time and re-warms nothing; a single 512-path batch amortises that to nothing
/// and lets clamd's multiscan use its own thread pool.
class BatchQueue {
public:
    struct Config {
        std::chrono::seconds flush_interval{15s};
        std::size_t max_paths{512};
        std::string list_dir{"/run/hyprnova"};
        bool use_list_file{true};
    };

    explicit BatchQueue(Config cfg) : cfg_{std::move(cfg)} {}

    /// Lock-free-ish enqueue. Duplicate paths within the same batch collapse.
    /// Returns false only when the pending set exceeds max_paths * 4, at which
    /// point we force an immediate flush rather than grow without bound.
    [[nodiscard]] bool add(std::string path, ScanReason reason) noexcept;

    /// Take everything currently pending. Called by the flush timer and by
    /// `force_flush()`.
    [[nodiscard]] std::vector<std::string> take() noexcept;

    [[nodiscard]] bool due() const noexcept;
    [[nodiscard]] std::size_t pending() const noexcept;
    [[nodiscard]] std::uint64_t enqueued() const noexcept { return enqueued_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t flushed() const noexcept { return flushed_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t batches() const noexcept { return batches_.load(std::memory_order_relaxed); }
    [[nodiscard]] std::chrono::seconds seconds_until_due() const noexcept;

private:
    Config cfg_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, ScanReason> pending_;
    core::SteadyClock::time_point last_flush_{core::SteadyClock::now()};
    std::atomic<std::uint64_t> enqueued_{0};
    std::atomic<std::uint64_t> flushed_{0};
    std::atomic<std::uint64_t> batches_{0};
};

/// Result of one external scanner invocation.
struct ExternalScanOutcome {
    bool ran{false};
    bool available{false};   // the binary existed and was executable
    std::string engine;      // "clamdscan" | "kvrt"
    int exit_code{-1};
    std::size_t scanned{0};
    std::vector<std::pair<std::string, std::string>> detections;  // path -> signature name
    std::string raw_output;
    std::string error;
    std::chrono::milliseconds elapsed{};
};

/// Detect which external scanners exist. Never assumed.
struct ExternalScannerInventory {
    std::string clamdscan;
    std::string kvrt;
    bool clamd_socket_alive{false};
    std::string clamd_socket;
    bool kvrt_runnable{false};
    std::vector<std::string> findings;
};

[[nodiscard]] ExternalScannerInventory probe_external_scanners(const core::ScanConfig& cfg) noexcept;

/// Run one batch. Writes the path list to a 0600 file and passes it with
/// `--file-list=` so we never hit ARG_MAX and never leak filenames into the
/// process table (visible to every local user via /proc/<pid>/cmdline).
[[nodiscard]] ExternalScanOutcome run_batch(const std::vector<std::string>& paths,
                                            const core::ScanConfig& cfg,
                                            const ExternalScannerInventory& inv) noexcept;

// ---------------------------------------------------------------------------
// The sensor
// ---------------------------------------------------------------------------

class ScannerSensor final : public core::ISensor {
public:
    ScannerSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    /// Enqueue a path. Cheap; called from the file monitor and the GUI.
    [[nodiscard]] bool enqueue(ScanRequest req) noexcept;

    /// Blocking scan of one path, used by the escalation pipeline which needs the
    /// answer now rather than at the next flush.
    /// Synchronous scan of one path. `attributing_pid` stamps the requesting
    /// process into the result/event so a verdict scores the ACTOR (Module 5).
    [[nodiscard]] ScanResult scan_now(std::string_view path, ScanReason reason,
                                      pid_t attributing_pid = 0) noexcept;

    /// Sweep every configured root. Runs on the pool; progress is published.
    void start_full_sweep(ScanPriority prio = ScanPriority::Low);

    [[nodiscard]] const SignatureEngine& engine() const noexcept { return engine_; }
    [[nodiscard]] const VerdictCache& cache() const noexcept { return cache_; }
    [[nodiscard]] const BatchQueue& queue() const noexcept { return queue_; }
    [[nodiscard]] const ExternalScannerInventory& inventory() const noexcept { return inventory_; }

    struct Counters {
        std::uint64_t scanned{0};
        std::uint64_t clean{0};
        std::uint64_t suspicious{0};
        std::uint64_t malicious{0};
        std::uint64_t skipped{0};
        std::uint64_t cache_hits{0};
        std::uint64_t enqueued{0};
        std::uint64_t batches{0};
        std::uint64_t external_detections{0};
        double mean_scan_ms{0.0};
        std::size_t queue_depth{0};
        bool sweep_running{false};
        double sweep_progress{0.0};
        std::string sweep_current;
    };
    [[nodiscard]] Counters counters() const noexcept;

    /// Last N results, newest first, for the GUI table.
    [[nodiscard]] std::vector<ScanResult> recent(std::size_t n = 50) const noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    void on_stop() override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    ScanResult scan_path_locked(const ScanRequest& req) noexcept;
    void publish(const ScanResult& r, const ScanRequest& req) noexcept;
    void flush_batch() noexcept;
    void sweep_worker(std::stop_token st, ScanPriority prio) noexcept;
    [[nodiscard]] bool should_skip(std::string_view path) const noexcept;
    void drain_ring() noexcept;

    SignatureEngine engine_;
    VerdictCache cache_;
    BatchQueue queue_;
    ExternalScannerInventory inventory_;

    /// Producers (file monitor, GUI, escalation pipeline) push here; the sensor
    /// loop pops. An MpscRing because there are several producers and one
    /// consumer, and the producer side must never block.
    core::MpscRing<ScanRequest> ring_{16384};

    mutable std::mutex result_mu_;
    std::deque<ScanResult> recent_;
    static constexpr std::size_t kRecentMax = 500;

    mutable std::mutex stat_mu_;
    Counters stats_;

    std::atomic<bool> sweeping_{false};
    std::atomic<double> sweep_progress_{0.0};
    mutable std::mutex sweep_mu_;
    std::string sweep_current_;
    std::atomic<std::uint64_t> total_ns_{0};
};

}  // namespace hyprnova::scanning
