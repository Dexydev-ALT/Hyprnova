// SPDX-License-Identifier: Apache-2.0
// HyprNova :: synthetic W^X fixture (spec §5D / TESTING_GUIDE §3 discipline).
//
// WHAT IT IS: a tiny program that creates one anonymous RWX mapping and sits
// on it, so the memory-forensics module (forensics/mem_inspect: W^X
// classification over /proc/<pid>/maps) has something REAL to find during a
// drill. The classifier's unit tests (tests/test_forensics.cpp, F7
// regression) pin the string logic; this fixture exercises it LIVE.
//
// WHAT IT IS NOT: not malware, no payload, no network, no persistence — it
// mmaps 4096 bytes, writes one marker byte, prints its pid and sleeps.
// Legitimate JITs (V8, luaJIT, HHVM) look exactly like this from the maps
// file, which is precisely why W^X alone is a MEDIUM signal and why HyprNova
// correlates it with identity, lineage and behaviour instead of killing on
// sight.
//
// Drill (VM or any host, as an unprivileged user):
//   cc -O0 -o /tmp/rwx_fixture tests/fixtures/rwx_fixture.c
//   /tmp/rwx_fixture &            # note the printed pid
//   hyprnova-cli processes        # the fixture's [anon] RWX region is listed
//   hyprnova-cli scan-mem <pid>   # expect: W^X finding (MEDIUM), identity re-checked
//   kill %1
//
// HyprNova never builds or runs this fixture by itself; it is an operator
// drill asset, the same policy as samples/sandbox/.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    void* p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    // One benign write: a marker the drill can grep for in a dump.
    memcpy(p, "HYPRNOVA-RWX-DRILL", 18);
    printf("rwx_fixture: pid %d, RWX page at %p\n", getpid(), p);
    fflush(stdout);
    for (;;) pause();  // sit still; the operator inspects, then kills
    return 0;
}
