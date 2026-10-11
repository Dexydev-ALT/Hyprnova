# HyprNova — Testing Guide

## 0. Handoff: what professional testers should know first

Current gate at handoff (all reproducible with the commands below): **248/248 C++
cases · self-test 58/58 · zero-warning release build · KERNEL-DRILL PASS (real
kernel, namespaced) · QML 33 objects, 0 errors · runner 6/6 sections passed ·
ASan clean (suite + full live daemon cycle) · live IPC smoke of every CLI verb,
honeypot snapshot/detection, malformed-JSON frame, rescue-report ingest, and
graceful shutdown (≤2 s, socket unlinked).**

Entry points, in the order you will want them:

| You want to… | Command |
|---|---|
| Verify everything at once | `tests/run_tests.sh` (6 sections; `NOT RUN` lines are honest prerequisites, never hidden failures) |
| Machine-readable results | `tests/run_tests.sh --json` · `./build/hyprnova-tests --json FILE` · `./build/hyprnova-bench --json FILE` |
| Catch memory bugs | ASan recipe in §5 (suite is ASan-clean at handoff) |
| Exercise a REAL firewall kernel-side, unprivileged | §6 kernel drill (user namespaces) |
| Run the behavioural ransomware scenario by hand | §3 sandbox drill (automated twin: `tests/test_response_e2e.cpp`) |
| Bring up a full-coverage VM (root paths: fanotify, auditd, cgroup freeze, nftables on the real ruleset, systemd install) | docs/VM-BRINGUP.md |

Honesty contract, kept across every suite and doc: one case = one assertion;
SKIPPED/NOT RUN are counted separately and never as passes; synthetic-fixture
results are never reported as real-world detection rates; benchmarks assert
shape, never magnitudes; nothing touches host data, and kernel operations run
only inside namespaces/process trees the test owns.

Known-rough-edges list before you start: docs/KNOWN_LIMITATIONS.md (short, and
each line says what is NOT possible and why). Remaining environment-gated
items: fanotify/auditd attribution, per-exe cgroup migration, real `dpkg -i`
install/start, rescue-ISO boot, Qt6-native GUI run, real AV/malware runs —
each unlocks on a root VM; see VM-BRINGUP.md.

## 1. The one entry point

```bash
tests/run_tests.sh            # build + unit/integration suites + self-test + QML check
tests/run_tests.sh --json     # machine-readable report (tests/report.json)
```

`run_tests.sh` never needs root and never touches host data: all fixtures live under a
mktemp dir that is removed on exit. Prerequisite-gated sections (root-only, external
tools) print `NOT RUN (<prerequisite>)` and are excluded from the pass count.

## 2. Fast inner loop

```bash
cmake --build build -j2 && ./build/hyprnova-tests            # C++ suites
./build/hyprnovad --self-test                                # the daemon's own 58+ checks
LD_LIBRARY_PATH=/tmp/xkblib/usr/lib/x86_64-linux-gnu \
  python3 scripts/qml_load_check.py                          # QML: 27 files, real type resolution
```

`qml_load_check.py` instantiates every page/component offscreen with a stub backend;
syntax/type/module errors fail the run, stub-property noise is filtered and counted.

## 3. Behavioural ransomware drill (disposable, safe)

```bash
mkdir -p /tmp/sbx && <create agent.json pointing state/gui/quarantine at /tmp/sbx>
cp samples/sandbox/systemupdate samples/sandbox/photo-backup /tmp/sbx/
mkdir /tmp/sbx/victims && echo data > /tmp/sbx/victims/report-1.docx
hyprnovad -f -c /tmp/sbx/agent.json &
/tmp/sbx/systemupdate                 # user-style run; expect: exec event -> MALICIOUS -> Ts
hyprnova-cli decisions                # expect: DECISION with evidence + lineage
hyprnova-cli answer <id> quarantine   # operator verdict
/tmp/sbx/photo-backup                 # benign control: zero alerts, runs to completion
```

Everything stays inside /tmp/sbx. The fixtures damage only paths they are pointed at, in
the sandbox tree, and are documented in samples/README.md.

## 5. AddressSanitizer pass (bug gate)

```bash
cmake -S . -B /tmp/hn-asan -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -O0 -g -fno-var-tracking-assignments"
cmake --build /tmp/hn-asan -j1 --target hyprnova-tests hyprnovad
ASAN_OPTIONS=detect_leaks=1 /tmp/hn-asan/hyprnova-tests
```

Expect `=== 248 case(s): 248 passed ...` and no ASan reports. `-O0` is deliberate:
at `-O1 -g` the ASan compile of `gui/gui_bridge.cpp` needs more RAM than a
constrained box (or CI container) usually has and cc1plus gets OOM-killed; the
check's value does not depend on optimisation level. Verified at handoff: suite
clean, plus a full live daemon cycle under ASan (start → `status`/`canaries` →
SIGTERM) with zero reports and leak detection on. A report is a bug: file it
against the exact case.

## 6. Kernel drill (nftables containment, no root needed)

```bash
# one-time prep when nft is not installed (recipe also in tools/kernel_drill.cpp):
mkdir -p /tmp/nftroot && cd /tmp/nftroot
for p in nftables libnftables1 libnftnl11 libmnl0; do apt-get download $p; done
for d in *.deb; do dpkg -x "$d" /tmp/nftroot/; done
printf '#!/bin/sh\nexport LD_LIBRARY_PATH=/tmp/nftroot/usr/lib/x86_64-linux-gnu\nexec /tmp/nftroot/usr/sbin/nft "$@"\n' \
  > /tmp/nftroot/nft-wrapper.sh && chmod +x /tmp/nftroot/nft-wrapper.sh

# the drill: a user+mount+net namespace owned by this process; host ruleset untouched
unshare -Urnm sh -c 'mount -t tmpfs none /run 2>/dev/null; mkdir -p /run/hyprnova;
  ip link set lo up; ip addr replace 10.9.9.1/32 dev lo;
  HN_NFT=/tmp/nftroot/nft-wrapper.sh exec ./build/hyprnova-kernel-drill'
# expect: KERNEL-DRILL PASS: real-kernel nftables containment verified end-to-end
```

`tests/run_tests.sh` §5 runs exactly this and prints NOT RUN honestly when
`unshare` or nft are missing.

## 7. Rules for new tests

* One assertion per case; name it after the behaviour, not the function.
* Every SECURITY_AUDIT.md "Fixed" entry gets a regression case in the same batch.
* Synthetic inputs only; no real malware, no host data, no network beyond localhost.
* Explicit timeouts; a hanging test is a failing test.
* If a prerequisite is missing, emit `NOT RUN` — never fake a pass.
