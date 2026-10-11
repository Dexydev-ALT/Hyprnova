// SPDX-License-Identifier: Apache-2.0
#include "bench.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <cstdio>
#include <fstream>
#include <thread>

#include <anti_ransomware/honeypot.hpp>
#include <core/event.hpp>
#include <core/hash.hpp>
#include <core/thread_pool.hpp>
#include <scanning/carver.hpp>

namespace hyprnova::bench {

namespace {

using Clock = std::chrono::steady_clock;

[[nodiscard]] double mibs_to_bytes(double mib) noexcept { return mib * 1024.0 * 1024.0; }

[[nodiscard]] double mbps(std::uint64_t bytes, Clock::duration d) noexcept {
    const double s = std::chrono::duration<double>(d).count();
    return s > 0.0 ? static_cast<double>(bytes) / (1024.0 * 1024.0) / s : 0.0;
}

[[nodiscard]] double us(Clock::duration d) noexcept {
    return std::chrono::duration<double, std::micro>(d).count();
}

/// Deterministic pseudo-random buffer (xorshift), so runs are reproducible
/// while the content stays incompressible-looking (honest throughput).
void fill_pattern(std::vector<std::byte>& buf, std::uint64_t seed) noexcept {
    std::uint64_t x = seed ? seed : 0x9E3779B97F4A7C15ull;
    for (auto& b : buf) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b = static_cast<std::byte>(x & 0xFF);
    }
}

// ---- individual benches -----------------------------------------------------

Result bench_sha256(std::size_t mib) noexcept {
    const std::size_t total = static_cast<std::size_t>(mibs_to_bytes(static_cast<double>(mib)));
    std::vector<std::byte> buf(1u << 20);  // 1 MiB chunks
    fill_pattern(buf, 1337);
    const auto t0 = Clock::now();
    std::uint64_t sink = 0;
    for (std::size_t done = 0; done < total; done += buf.size()) {
        const auto d = core::hash::Sha256::once(
            std::span<const std::byte>{buf.data(), buf.size()});
        sink += d[0];
    }
    const auto d = Clock::now() - t0;
    (void)sink;
    return {"sha256.throughput", mbps(total, d), "MB/s", mib,
            std::format("{} MiB in {} MiB chunks", mib, 1)};
}

Result bench_json(std::size_t doc_kb) noexcept {
    // Build a document of ~doc_kb KiB: an array of objects with strings and
    // numbers, then parse it repeatedly until ~8 MiB has been through.
    const int objects = std::max(1, static_cast<int>(doc_kb * 1024 / 150));
    std::string one;
    one.reserve(doc_kb * 1024 + 256);
    for (int i = 0; i < objects; ++i) {
        if (i) one += ',';
        one += std::format(
            R"({{"sensor":"bench{}","severity":{},"message":"measurement frame {}","metric":{:.4f},"fields":{{"path":"/tmp/bench/file{}.bin","actor":"/usr/bin/bench"}}}})",
            i, i % 5, i, i * 1.5, i);
    }
    const std::string doc = "[" + one + "]";
    const std::uint64_t doc_bytes = doc.size();
    const std::uint64_t target = static_cast<std::uint64_t>(8u << 20);
    const std::size_t iters = std::max<std::size_t>(
        1, static_cast<std::size_t>(target / std::max<std::uint64_t>(doc_bytes, 1)));
    const auto t0 = Clock::now();
    std::size_t ok = 0;
    for (std::size_t i = 0; i < iters; ++i)
        if (core::json::parse(doc)) ++ok;
    const auto d = Clock::now() - t0;
    return {"json.parse_throughput", mbps(doc_bytes * ok, d), "MB/s", ok,
            std::format("{} docs x {} B", ok, doc_bytes)};
}

Result bench_bus(std::size_t n_events) noexcept {
    core::EventBus bus{4096};
    bus.start();
    std::atomic<std::size_t> delivered{0};
    std::atomic<double> last_us{0.0};
    double total_us = 0.0;
    double max_us = 0.0;
    std::size_t samples = 0;
    const auto sub = bus.subscribe("bench", [&](const core::TelemetryEvent& ev) {
        const double lat = us(Clock::now() - ev.mono);
        last_us.store(lat, std::memory_order_release);
        delivered.fetch_add(1, std::memory_order_release);
    });
    const auto t0 = Clock::now();
    for (std::size_t i = 0; i < n_events; ++i) {
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::Unknown;
        ev.kind = core::EventKind::None;
        ev.message = "bench";
        // Bounded spin: the dispatcher thread usually wakes in single-digit us.
        bool sent = bus.publish(std::move(ev));
        for (int spin = 0; sent && delivered.load(std::memory_order_acquire) <= i && spin < 200000;
             ++spin)
            std::this_thread::yield();
        if (sent) {
            const double lat = last_us.load(std::memory_order_acquire);
            total_us += lat;
            max_us = std::max(max_us, lat);
            ++samples;
        }
    }
    const auto wall = Clock::now() - t0;
    bus.unsubscribe(sub);
    bus.stop();
    Result r;
    r.name = "bus.publish_dispatch";
    r.unit = "us";
    r.iterations = samples;
    r.note = std::format("{}/{} delivered", samples, n_events);
    r.value = samples ? total_us / static_cast<double>(samples) : 0.0;
    (void)wall;
    return r;
}

Result bench_carver(std::size_t mib, const std::string& scratch) noexcept {
    const std::string path = scratch + "/bench-carver.bin";
    const std::size_t total = static_cast<std::size_t>(mibs_to_bytes(static_cast<double>(mib)));
    {
        std::vector<std::byte> buf(1u << 20);
        fill_pattern(buf, 4242);
        std::ofstream o(path, std::ios::binary | std::ios::trunc);
        for (std::size_t done = 0; done < total; done += buf.size()) {
            // Plant recognizable magic bytes so the carver has work to do.
            if (done == 0) std::memcpy(buf.data(), "\x7f"
                                                  "ELF",
                                       4);
            buf[64] = static_cast<std::byte>(0xFF);
            buf[65] = static_cast<std::byte>(0xD8);
            o.write(reinterpret_cast<const char*>(buf.data()),
                    static_cast<std::streamsize>(buf.size()));
        }
    }
    const auto t0 = Clock::now();
    const auto rep = scanning::Carver::inventory(path);
    const auto d = Clock::now() - t0;
    std::error_code fec;
    std::uint64_t sz = static_cast<std::uint64_t>(std::filesystem::file_size(path, fec));
    if (fec) sz = 0;
    std::error_code ec;
    (void)std::filesystem::remove(path, ec);
    return {"carver.inventory_throughput", mbps(sz, d), "MB/s", mib,
            std::format("{} artifact(s) found", rep.artifacts.size())};
}

Result bench_honeypot(std::size_t decoys_n, const std::string& scratch) noexcept {
    core::EventBus bus{512};
    bus.start();
    core::AgentConfig cfg = core::default_config();
    cfg.state_dir = scratch + "/hn-bench";
    std::error_code ec;
    (void)std::filesystem::remove_all(cfg.state_dir, ec);
    (void)std::filesystem::create_directories(cfg.state_dir, ec);
    core::ThreadPool pool{core::ThreadPoolConfig{}};
    anti_ransomware::HoneypotSensor sensor{bus, cfg, pool};

    const auto t0 = Clock::now();
    const bool planted = sensor.start();
    const auto plant_d = Clock::now() - t0;
    if (!planted) {
        bus.stop();
        return {"honeypot.plant_check_all", 0.0, "ms", 0, "sensor failed to start (skipped)"};
    }
    // Warm the watches, then time sweep-only passes (no events in flight).
    sensor.check_all();
    const auto t1 = Clock::now();
    constexpr int kPasses = 5;
    for (int i = 0; i < kPasses; ++i) sensor.check_all();
    const auto sweep_d = Clock::now() - t1;
    bus.stop();
    pool.shutdown();
    std::error_code ec2;
    (void)std::filesystem::remove_all(cfg.state_dir, ec2);
    return {"honeypot.plant_check_all",
            us(plant_d) / 1000.0 + us(sweep_d) / 1000.0 / kPasses, "ms", decoys_n,
            std::format("{} decoy(s): plant {} ms + sweep {} ms/pass", decoys_n,
                        us(plant_d) / 1000.0, us(sweep_d) / 1000.0 / kPasses)};
}

}  // namespace

core::json::Value Result::to_json() const noexcept {
    using namespace core::json;
    Object o;
    o["name"] = name;
    o["value"] = value;
    o["unit"] = unit;
    o["iterations"] = static_cast<std::int64_t>(iterations);
    o["note"] = note;
    return Value{std::move(o)};
}

core::json::Value Report::to_json() const noexcept {
    using namespace core::json;
    Object o;
    o["host_note"] = host_note;
    o["elapsed_ms"] = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    Array rs;
    for (const auto& r : results) rs.emplace_back(r.to_json());
    o["results"] = Value{std::move(rs)};
    return Value{std::move(o)};
}

std::string Report::to_human() const noexcept {
    std::string out = "HyprNova benchmark -- " + host_note + "\n";
    for (const auto& r : results) {
        out += std::format("  {:<34} {:>10.2f} {:<8} (n={}, {})\n", r.name, r.value, r.unit,
                           r.iterations, r.note);
    }
    out += std::format("  total wall: {} ms\n", std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    return out;
}

Report run(const Config& cfg) noexcept {
    Report rep;
    rep.host_note =
        "environment-specific throughput/latency of in-tree components on THIS host "
        "-- not portable performance claims";
    const auto t0 = Clock::now();
    try {
        rep.results.push_back(bench_sha256(cfg.hash_mib));
        rep.results.push_back(bench_json(cfg.json_doc_kb));
        rep.results.push_back(bench_bus(cfg.bus_events));
        if (!cfg.scratch_dir.empty()) {
            std::error_code ec;
            (void)std::filesystem::create_directories(cfg.scratch_dir, ec);
            rep.results.push_back(bench_carver(cfg.carver_mib, cfg.scratch_dir));
            rep.results.push_back(bench_honeypot(cfg.decoys, cfg.scratch_dir));
        }
    } catch (...) {
        // A benchmark must never take the caller down; what completed is reported.
        rep.results.emplace_back(Result{"harness.error", 1.0, "bool", 0, "a bench threw; results above are partial"});
    }
    rep.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0);
    return rep;
}

}  // namespace hyprnova::bench
