// SPDX-License-Identifier: Apache-2.0
// HyprNova :: test harness (no external framework — see docs/TEST_PLAN.md).
//
// One assertion = one case. SKIPPED cases (prerequisite missing) are counted
// separately and never as passes. --json emits a machine-readable report.
#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace hyprnova::testing {

struct Case {
    std::string name;
    bool passed{false};
    bool skipped{false};
    std::string detail;
};

inline std::vector<Case>& cases() {
    static std::vector<Case> c;
    return c;
}

inline void check(bool ok, std::string_view name, std::string detail = {}) {
    cases().push_back({std::string(name), ok, false, std::move(detail)});
    const auto& c = cases().back();
    std::printf("[%s] %s%s%s\n", c.passed ? "PASS" : "FAIL", c.name.c_str(),
                c.detail.empty() ? "" : "  -- ", c.detail.c_str());
}

inline void skip(std::string_view name, std::string_view why) {
    cases().push_back({std::string(name), false, true, std::string(why)});
    std::printf("[SKIP] %s  -- %s\n", name.data(), why.data());
}

inline int exit_code(const char* json_path = nullptr) {
    std::size_t passed = 0, failed = 0, skipped = 0;
    for (const auto& c : cases()) {
        if (c.skipped) ++skipped;
        else if (c.passed) ++passed;
        else ++failed;
    }
    std::printf("\n=== %zu case(s): %zu passed, %zu failed, %zu skipped ===\n",
                cases().size(), passed, failed, skipped);
    if (json_path) {
        if (FILE* f = std::fopen(json_path, "w")) {
            std::fprintf(f, "{\"total\":%zu,\"passed\":%zu,\"failed\":%zu,\"skipped\":%zu,"
                            "\"cases\":[",
                         cases().size(), passed, failed, skipped);
            for (std::size_t i = 0; i < cases().size(); ++i) {
                const auto& c = cases()[i];
                static auto esc = [](const std::string& s) {
                    std::string o;
                    for (char ch : s) {
                        if (ch == '"' || ch == '\\') o += '\\';
                        if (ch == '\n') { o += "\\n"; continue; }
                        o += ch;
                    }
                    return o;
                };
                std::fprintf(f, "%s{\"name\":\"%s\",\"state\":\"%s\",\"detail\":\"%s\"}", i ? "," : "",
                             esc(c.name).c_str(),
                             c.skipped ? "SKIPPED" : (c.passed ? "PASSED" : "FAILED"),
                             esc(c.detail).c_str());
            }
            std::fprintf(f, "]}\n");
            std::fclose(f);
        }
    }
    return failed == 0 ? 0 : 1;
}

}  // namespace hyprnova::testing
