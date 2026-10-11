// SPDX-License-Identifier: Apache-2.0
// HyprNova :: GAP row 14 — the metrics/benchmark harness (spec §9/§10).
//
// Measures the REAL in-tree components on THIS host and reports exactly that:
// environment-specific numbers, never universal claims. Every result carries
// its unit and iteration count; the JSON output is machine-readable so runs
// can be diffed across builds/hosts. Nothing here is synthesized into a
// "detection rate" — throughput and latency of plumbing only.
//
// Standalone binary (hyprnova-bench) so a benchmark never perturbs a running
// agent; the test suite exercises the harness on the tiny settings and only
// asserts SHAPE (positive finite values, complete JSON), never magnitudes.
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <core/json.hpp>

namespace hyprnova::bench {

struct Result {
    std::string name;         // stable machine id ("json.parse_throughput")
    double value{0.0};        // the measured number
    std::string unit;         // "MB/s", "us", "ms", "events/s"
    std::size_t iterations{0};
    std::string note;         // input size / method, for honest reporting

    [[nodiscard]] core::json::Value to_json() const noexcept;
};

struct Report {
    std::string host_note;    // how to read these numbers (env-specific)
    std::vector<Result> results;
    std::chrono::milliseconds elapsed{};

    [[nodiscard]] core::json::Value to_json() const noexcept;
    [[nodiscard]] std::string to_human() const noexcept;
};

/// Knobs. The defaults are what `hyprnova-bench` runs; the test suite uses
/// small counts so the suite stays fast while still executing the same code.
struct Config {
    std::size_t bus_events{2000};        // event-bus publish + dispatch count
    std::size_t hash_mib{32};            // sha256 throughput input size
    std::size_t json_doc_kb{512};        // JSON parse input size
    std::size_t carver_mib{8};           // carver inventory input size
    std::size_t decoys{8};               // honeypot plant+sweep decoy count
    std::string scratch_dir;             // required for honeypot benches
};

/// Run the full battery. Blocking, single-threaded except the bus's own
/// dispatcher. Never throws.
[[nodiscard]] Report run(const Config& cfg) noexcept;

}  // namespace hyprnova::bench
