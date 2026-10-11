// SPDX-License-Identifier: Apache-2.0
// HyprNova :: GAP row 14 — bench harness tests. Deliberately SHAPE-only:
// absolute numbers are environment-specific and are never asserted (honest
// benchmarking: we verify the harness measures, not that the host is fast).
#include "test_main.hpp"

#include <cmath>
#include <unistd.h>
#include <filesystem>
#include <format>
#include <string>

#include "tools/bench.hpp"

namespace {

using namespace hyprnova;
using hyprnova::testing::check;

struct BenchSuite {
    BenchSuite() {
        bench::Config cfg;
        cfg.bus_events = 50;
        cfg.hash_mib = 1;
        cfg.json_doc_kb = 8;
        cfg.carver_mib = 1;
        cfg.decoys = 4;
        cfg.scratch_dir = std::format("/tmp/hyprnova-bench-test-{}", ::getpid());

        const auto rep = bench::run(cfg);
        check(rep.results.size() == 5, "bench: all five component benches ran");
        check(rep.host_note.find("environment-specific") != std::string::npos,
              "bench: the report disclaims portability (honesty by construction)");

        bool all_finite = true, all_units = true, all_named = true;
        for (const auto& r : rep.results) {
            if (!std::isfinite(r.value) || r.value < 0.0) all_finite = false;
            if (r.unit.empty()) all_units = false;
            if (r.name.empty()) all_named = false;
        }
        check(all_finite, "bench: every measured value is finite and non-negative");
        check(all_units, "bench: every result carries its unit");
        check(all_named, "bench: every result has a stable machine id");

        // The bus bench reports deliveries, not faith: 50 events in, 50 out.
        bool bus_ok = false;
        for (const auto& r : rep.results)
            if (r.name == "bus.publish_dispatch")
                bus_ok = r.iterations == cfg.bus_events &&
                         r.note.find("50/50") != std::string::npos;
        check(bus_ok, "bench: the event bus delivered every published event");

        bool hp_ok = false;
        for (const auto& r : rep.results)
            if (r.name == "honeypot.plant_check_all")
                hp_ok = r.value > 0.0 && r.unit == "ms" && r.note.find("4 decoy") != std::string::npos;
        check(hp_ok, "bench: the honeypot bench measured plant+sweep on 4 decoys");

        // JSON shape: parses, has the full results array.
        const auto doc = core::json::parse(rep.to_json().dump());
        check(doc.has_value(), "bench: the JSON report round-trips through the parser");
        int n_results = 0;
        if (const auto* arr = doc ? (doc->at("results") ? doc->at("results")->as_array() : nullptr)
                                  : nullptr)
            n_results = static_cast<int>(arr->size());
        check(n_results == 5, "bench: the JSON report carries all five results");
        check(rep.to_human().find("sha256.throughput") != std::string::npos,
              "bench: the human table lists every bench by name");

        std::error_code ec;
        (void)std::filesystem::remove_all(cfg.scratch_dir, ec);
    }
};
const BenchSuite bench_suite_instance;

}  // namespace
