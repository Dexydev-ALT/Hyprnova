# HyprNova — Security Audit (living document)

Last audit: 2026-10-10 (post batch-2). Method: manual inspection of privileged paths
(IPC, response engine, quarantine, filesystem ops) against the OWASP-style checklist in
TEST_PLAN.md. This file lists CONFIRMED findings with file/function references. A finding
stays listed until fixed AND regression-tested; fixed findings move to "Fixed" with the
test that covers them.

## Status legend
`OPEN` · `FIXED` · `MITIGATED` (partial) · `ACCEPTED` (documented, deliberate)

## Findings

### F1 · HIGH · FIXED · PID-reuse before signalling
`remediation/remediation_engine.cpp: RemediationEngine::suspend()/kill()` act on a bare
`pid_t` handed in by the heuristic escalation or an operator decision. The process is read
for enrichment but its **starttime identity is not revalidated** at signal time. A pid that
exits and is recycled between the escalation decision and the signal would hit an unrelated,
innocent process. The pid-recycling problem is already understood in
`behavioral/proc_poll.cpp` (starttime comparison) — the response engine must apply the same
rule. Fix: escalation records `start_time_ticks`; suspend/kill accept an optional expected
starttime and abort on mismatch.

### F2 · HIGH · FIXED · restore_file: no hash verify, occupied destination
`remediation/remediation_engine.cpp: RemediationEngine::restore_file()` reads the `.meta`
sidecar (which stores `sha256` and `size` — written at `quarantine_file()`) but **never
verifies the sample hash before restoring**: a tampered or truncated sample would be
restored silently. Additionally `core/fd.cpp: write_atomic()` rename-replaces the
destination unconditionally, so restoring to an **occupied path silently overwrites user
data**. Fix: verify sha256+size against the sample before writing; refuse an existing
destination unless the operator explicitly forces overwrite.

### F3 · MEDIUM · FIXED · predictable temp name in write_atomic
`core/fd.cpp: write_atomic()` uses `path + ".hyprnova-tmp"` (fixed name, `O_CREAT|O_TRUNC`
without `O_EXCL`). Within the 0700 quarantine/state dirs the race window is closed by
directory permissions, but the pattern is wrong for any future world-writable use.
Fix: `O_CREAT|O_EXCL` with pid-randomised suffix.

### F4 · MEDIUM · FIXED · no version control
The working tree has **no git repository**: no audit trail, no diff review, no safe revert.
Fix: `git init` + initial commit of the untouched tree BEFORE further changes (nothing is
discarded; this preserves the current state by definition).

### F5 · ACCEPTED · IPC surface is sound (verified, not assumed)
`gui/gui_bridge.cpp`: SO_PEERCRED before any response content (line ~355), uid allowlist +
root (authorised(), ~174), 8 MiB frame cap (kMaxFrameBytes, ~69, ~529), bounded client
count with zombie reaping (~361), socket chmod 0660 (~219). Unknown commands are refused;
every request is validated via typed accessors (`req.str/integer/at`). Per-command
authorisation relies on the connection-level uid check: root always allowed, other uids
only when the daemon's own (unprivileged installs) — a local attacker in the same uid is
IN the trust boundary (documented in KNOWN_LIMITATIONS.md).

### F6 · ACCEPTED · dry_run gates every mutating action at the engine
`RemediationEngine::permitted()/begin()` honour `cfg_.dry_run` per action; the shredder
refuses execution without explicit confirmation (separate, stronger gate).

### F7 · HIGH · FIXED (found live 2026-10-10) · W^X detection dead since inception
`core/proc.cpp` `maps()` classified `writable_and_executable` with `perms[0]=='w'` — but the
`/proc/pid/maps` perms layout is `rwxp`, so index 0 is always `r` or `-`. No real mapping could
ever match: Module 4c reported "no W^X violations" for processes carrying live RWX regions.
FIX: `region_wx()`/`region_exec()` classifiers (index 1 = write bit, index 2 = exec bit) in
`core/proc.{hpp,cpp}`; regression tests in `tests/test_forensics.cpp` ("F7 regression");
live-verified against a synthetic RWX-mapping process: violation now flagged, `suspicious=1`.

### F8 · LOW · FIXED (found live 2026-10-10) · CLI mem-dump parsed args[1] as PID unconditionally
`agent/cli.cpp` mem-dump loop collected `--yes`/dest correctly but then read `args[1]` — with
`mem-dump PID --yes` that is the flag, producing "'--yes' is not a number". FIX: pid = first
non-flag token; usage error only when absent.

## Environment constraints of this audit
Audit and tests ran in an unprivileged container: fanotify, audit netlink, cgroup freeze,
nftables, root-only paths and systemd integration could NOT be exercised → they are marked
NOT RUN in TEST_PLAN.md and KNOWN_LIMITATIONS.md rather than counted as passes.
