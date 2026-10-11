// SPDX-License-Identifier: Apache-2.0
// hyprnova-bench: standalone harness so a benchmark never perturbs a running
// agent. Human table by default, --json FILE for machine-readable runs.
#include "bench.hpp"

#include <cstdio>
#include <fstream>
#include <string>

int main(int argc, char** argv) {
    hyprnova::bench::Config cfg;
    if (const char* scratch = ::getenv("HN_BENCH_SCRATCH"); scratch && *scratch)
        cfg.scratch_dir = scratch;
    else
        cfg.scratch_dir = "/tmp/hyprnova-bench";
    std::string json_out;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a{argv[i]};
        if (a == "--json" && i + 1 < argc) json_out = argv[++i];
        else if (a == "--quick") {
            cfg.bus_events = 200;
            cfg.hash_mib = 4;
            cfg.carver_mib = 2;
            cfg.json_doc_kb = 64;
        }
    }
    const auto rep = hyprnova::bench::run(cfg);
    std::fputs(rep.to_human().c_str(), stdout);
    if (!json_out.empty()) {
        std::ofstream o(json_out, std::ios::trunc);
        o << rep.to_json().dump() << "\n";
        std::printf("json report written to %s\n", json_out.c_str());
    }
    return 0;
}
