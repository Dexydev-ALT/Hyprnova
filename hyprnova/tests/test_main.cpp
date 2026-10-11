// SPDX-License-Identifier: Apache-2.0
// HyprNova test binary entry point. Suites are plain functions; the runner
// prints per-case results and (with --json) writes a machine-readable report.
#include "test_main.hpp"

#include <unistd.h>

#include <cstring>
#include <cstdlib>
#include <ctime>

extern void test_core_json();
extern void test_config();
extern void test_parsers();
extern void test_response_safety();
extern void test_forensics_mem();

int main(int argc, char** argv) {
    std::srand(static_cast<unsigned>(::getpid()));
    const char* json_path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--json") == 0 && i + 1 < argc) json_path = argv[++i];
    }

    std::printf("== HyprNova test suite ==\n");
    test_core_json();
    test_config();
    test_parsers();
    test_response_safety();
    test_forensics_mem();

    return hyprnova::testing::exit_code(json_path);
}
