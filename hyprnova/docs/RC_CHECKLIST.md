# HyprNova — RC acceptance checklist (spec §12)

Status at the close of the "fix all known limitations and gaps" sweep,
2026-10-10. Every line is a measured fact from this session or an explicit,
reasoned NOT RUN — nothing is assumed.

## Automated gates (all green)

| Gate | Result |
|---|---|
| Full release build (`RelWithDebInfo`, all five targets, fresh objects) | **EXIT 0, 0 warnings** — including forced recompiles of the noisy TUs; the only two GCC-14 false-positive families (variant inlining in config.cpp to_json, istreambuf_iterator in toolbox.cpp) are scope-suppressed IN FILE with the reason, never globally |
| C++ suite (`build/hyprnova-tests`) | **248/248 passed, 0 failed, 0 skipped** (includes the `sameid:` BUG #1 regression cases) |
| Daemon self-test (`hyprnovad --self-test`) | **58/58** |
| Runner (`tests/run_tests.sh`, 6 sections) | **ALL RUN SECTIONS PASSED** (build, suite, self-test, bench smoke, env-gated honesty, QML loader: 0 errors) |
| Spec §8 ransomware drill | **Automated + passing** (`tests/test_response_e2e.cpp`): systemupdate trips live monitor channels; photo-backup control silent; suspend-not-kill / reversible / dry-run-refuses all pinned |
| KERNEL drill (nftables containment) | **PASS on a real kernel**: `tools/kernel_drill.cpp` runs the engine's full block_c2 -> nft -> enforce -> unblock cycle inside a user+mount+net namespace (runner §5). Found + fixed a REAL bug on its first run: bare `dport` rules were rejected by nft in inet chains ("No symbol type information") -- blocks now pin tcp+udp explicitly |
| ASan (bug gate) | **CLEAN**: 248/248 under `-fsanitize=address` + LeakSanitizer, zero reports; plus a full live daemon cycle under ASan (start → status/canaries → SIGTERM) clean. Recipe uses `-O0 -g` deliberately (`-O1` OOM-kills cc1plus on constrained boxes); see TESTING_GUIDE §5 |
| Live IPC smoke (pre-handoff) | **PASS**: every CLI verb, `canaries` honeypots block (planted=8), live HONEYPOT READ event, malformed-JSON error frame, events limit coercion, analysis-plan honesty, rescue-report ingest E2E (malformed kept+WARN; valid → events + `.consumed`), graceful shutdown ≤2 s with socket unlinked (25+ cycles; one unreproduced hang documented in KNOWN_LIMITATIONS) |
| GUI navigation refresh | **FIXED + parsed clean**: `goTo()` covered only cases 0–9 while the pages array grew to 16 — Memory/Backups/Recovery/Timeline/Settings pulled stale data on navigation; all 16 routes now refresh the snapshot their page binds |
| Machine-readable runs | `hyprnova-tests --json PATH`, `hyprnova-bench --json PATH` |

## Gap rows (GAP_ANALYSIS.md) — sweep result

| Row | State |
|---|---|
| 10 file carving | DONE (prior batch): CarverConfig opt-in, `hyprnova-cli carve`, 17 cases |
| 11 honeypots | DONE: event-driven inotify decoy sensor; live drills: 0 idle events ×4, exact read/modify/delete attribution; startup ghost-read ROOT-CAUSED (shadow-copy engine read its own bait) and fixed at source |
| 12 nftables by-exe | DONE: cgroup v2 + `socket cgroupv2` drop in one transaction; CLI/GUI verbs; honest failure without both subsystems (verified live). nftables half verified ON A REAL KERNEL in an owned netns (kernel drill); the cgroup-migration half stays root-gated (cgroup2 userns-mount denied by this kernel) |
| 13 analysis sandbox | DONE: `tools/analysis` (plan/deep-links/sandbox-argv, HyprNova never detonates by itself); Ghidra/capa/CAPE/etc. remain probed-honestly, installation env-gated |
| 14 metrics/bench | DONE: `hyprnova-bench` (sha256/json/bus-latency/carver/honeypot), human+JSON, shape-pinned in suite; numbers environment-specific by construction |
| 15 heartbeat removal | **Deferred by owner (P3), stays deferred** |

## Known-limitations items

| Item | State |
|---|---|
| IPC group auth (sandbox boundary) | DONE: `gui.ipc_group`, pure decision table unit-pinned, socket 0660 root:<group>, honest degrade when group absent (verified live both branches); multi-uid connect drills root-gated |
| GUI pages | DONE and verified: all 16 pages load clean (PySide6, 0 errors). Batch 5 added the two missing surfaces: Honeypot decoys panel (CanariesPage, fed by the new `honeypots` block in the canaries snapshot) and Network-contained executables (NetworkPage, fed by `exe_blocks` + Release action; Qt backend gained the exeBlocks property and unblockExe/blockExe invokables) |
| Packaging | .deb REBUILT from the current tree (18.4 MB) and extraction-verified without root: layout matches install.sh, conffiles correct, postinst now creates the operator group (parity with install.sh), scripts syntax-checked, systemd unit verify-clean, packaged binaries execute. `dpkg -i` itself still NOT RUN (needs real root) |

## Explicitly NOT RUN (prerequisite-gated, VM-BRINGUP.md)

fanotify write attribution · auditd netlink · per-exe cgroup MIGRATION (the
kernel denies cgroup2 userns-mounts here; the nftables half of that path is now
kernel-verified in an owned netns) · systemd unit install/start (`dpkg -i`/`dnf
install` on a real root fs) · rescue-ISO boot · Qt6-native GUI run (QML verified
via the PySide6 loader) · KVRT/ClamAV/CrowdSec real runs · real-malware samples
(owner sources and authorizes) · a single from-scratch build
of every target in ONE invocation (this box OOM-killed `cc1plus` once at -j2
early on; the same full tree rebuilds clean at -j1, as the runner does). The userns-scoped drills DO run real kernel
operations, but always inside namespaces this process owns: nothing touches the
host ruleset, and everything dies with the drill.

## Owner decisions still open (not code)

1. Groq + VirusTotal API keys (AI analyst, adv-scan VT rung) — honest-inert until set.
2. Real-sample testing authorization + VM snapshot procedure (docs/VM-BRINGUP.md).
3. Heartbeat removal timing (row 15, P3).
4. Qt6 native GUI build on a real desktop.

## Sample bench numbers (environment-specific — NOT portable claims)

`hyprnova-bench --quick` in this container: sha256 ≈ 190–212 MB/s · json parse
≈ 118 MB/s · bus publish→dispatch ≈ 23–26 µs (200/200 delivered) · carver
inventory ≈ 265 MB/s · honeypot plant+sweep ≈ 0.5 ms for 8 decoys.
