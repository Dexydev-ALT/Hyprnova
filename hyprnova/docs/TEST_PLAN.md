# HyprNova — Test Plan

Framework: the in-tree self-test pattern (58 checks) promoted to a real suite. **No
external dependency (GTest/Catch2) is added**: the binary is fully static-ish, the existing
pattern already provides checks/sections/fatals, and a header-only framework would add
nothing but download risk. `tests/hyprnova-tests (incl. test_corpus.cpp — manifest-driven corpus; a missing fixture file is a FAIL, never a skip)` prints human output AND `--json` for
machine-readable runs; `tests/run_tests.sh` is the single documented entry point.

## Case accounting (honest, per spec §9)
Current suite: **159 cases, all passing** (2026-10-10). Live counts come from the binary
itself (`hyprnova-tests` prints the totals; `tests/run_tests.sh` enforces them):

| Suite | Cases |
|---|---|
| honeypot (decoy plant/watch/classify/E2E via real inotify events) | 29 |
| config (validate/read/save round-trip, incl. rescue section) | 18 |
| json (parse/malformed/bounds/ndjson) | 17 |
| carver (file carving fixtures) | 17 |
| corpus (manifest-driven signatures; missing fixture = FAIL) | 15 |
| mem (identity revalidation, W⁰X classify, limits) | 11 |
| quarantine (verify/occupied/tamper/missing-meta) | 10 |
| sshd (config audit parser) | 8 |
| response (safe-response policy) | 7 |
| pkg-verify (package integrity parser) | 6 |
| shredder + paths + proc/fs | 10 |
| parsers (kvrt/crowdsec/rkhunter/clamav) | 7 |
| netpolicy (per-exe policy: rules, escalation, refusals) | 25 |
| analysis (deep links, plan split, sandbox argv) | 32 |
| ipcauth (pure auth decision + membership read) | 9 |
| bench (harness shape; values never asserted) | 10 |
| e2e (§8 drill: fixtures vs live monitor + response invariants) | 9 |
| sameid (SensorId collision disambiguation; BUG #1 regression) | 4 |
| **Total** | **248** (target 1,000 over time, never inflated) |

Honeypot E2E discipline: the read/modify/delete cases perform REAL file operations against
planted decoys and wait for bus delivery of the resulting event — no atime manipulation
(relatime made the old probe machine-dependent; it was removed with the atime design).

Counter-rules: one case = one assertion with a distinct input; fixtures count as samples,
not cases; skipped/NOT RUN are reported separately and never as passes.

## NOT RUN in this environment (unprivileged container, offline)
fanotify live attribution · audit netlink · cgroup freezing · nftables install/remove ·
systemd unit install/start · rescue ISO boot · root-only file ops · KVRT/ClamAV/CrowdSec
real runs · Qt6 native GUI run (QML verified via offscreen loader with PySide6) ·
full-memory acquisition (needs root + kernel module). Each has a documented prerequisite
and is exercised by `tests/run_tests.sh` only when the prerequisite is detected.

## Security test matrix (synthetic inputs only)
Path traversal (restore/shred/scan targets) · symlink+hardlink edges · oversized IPC frames
(>8 MiB) and malformed JSON to the socket · tampered quarantine meta (hash mismatch) ·
corrupt configs · special files (fifo/dev nodes) as scan/shred targets · event floods ·
untrusted filenames with newlines/quotes · unauthorised-uid IPC connect.

## Ransomware response tests (spec §8)
AUTOMATED as tests/test_response_e2e.cpp (mirrors the manual procedure in
TESTING_GUIDE.md §3): the systemupdate fixture runs against a LIVE
FileMonitorSensor on the disposable /tmp/sbx tree (trips the entropy/.locked
channels), the photo-backup control stays silent, and the response invariants
-- suspend-not-kill, reversible via SIGCONT, dry_run refuses, forensic image
preserved -- are pinned on a controlled slow actor. Never host data, never a
real payload; the fixtures' compiled-in paths are the documented sandbox root.
