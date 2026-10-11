# HyprNova — Known Limitations (honest, permanent home)

## Memory forensics (Module 4c)
* In-process inspection reads `/proc/<pid>/maps` + `/proc/<pid>/mem` of a process the agent
  can already see. It is **not** full system-memory forensics: no kernel objects, no
  other-uid processes without root, no timeline reconstruction, no Volatility profiles.
* Volatility3 / MemProcFS / LiME are **probed and reported**, not driven: acquisition with
  them requires root and a kernel module (LiME) and is deliberately a separate opt-in
  subsystem. The GUI shows their real status and never invents results.
* Memory dumps may contain credentials. Dumps are written 0600 into the state dir, named by
  pid+starttime, and the UI warns before every dump.

## Attribution
* fanotify (write attribution, denial) needs CAP_SYS_ADMIN/CAP_DAC_READ_SEARCH. Without it
  the file monitor is inotify-only: writes are analysed but **unattributed** (pid=0);
  process-level response then depends on proc-poll + heuristics.
* proc-poll is a sweep, not a syscall tap: a process that execs and exits within one
  interval is never seen.

## Sandbox boundary (IPC auth)
* SO_PEERCRED decides: root and the daemon's own uid are always allowed; members of
  `gui.ipc_group` (default `hyprnova`, created by install.sh, socket chowned to it) are
  allowed; everyone else is refused — with the socket ALSO 0660 root:<group> so a
  refused uid usually cannot even connect.
* Group membership (getpwuid + getgrouplist, primary + supplementary) is resolved per
  uid at first connect and cached for the daemon's lifetime: adding a user to the group
  requires a daemon restart to take effect.
* An absent operator group degrades honestly (log line; root + same-uid only) and never
  fails the bridge. Multi-uid connect/refuse drills are root-gated NOT RUN in this
  container; the decision table itself is unit-tested exhaustively (tests/test_ipc_auth).

## Signals and survival
* SIGSTOP preserves a process's memory but does not undo file damage that already happened;
  shadow copies + snapshots are the recovery path.
* Cgroup containment needs a writable cgroup v2 subtree; without it, fallback is SIGSTOP
  only (stated in capability notes).

## Honeypots (decoy sensors)
* Read detection is **event-driven** (per-decoy inotify watches: ACCESS/MODIFY/DELETE).
  A reader is named only if its fd is still open at event time (`/proc` attribution);
  otherwise the event says so honestly — relatime makes atime forensics unreliable for
  same-uid readers, so no atime claims are made.
* The agent never reads its own bait except with `O_NOATIME` inside the sweep, whose
  inotify events are drained-and-discarded while the sweep guard is up. There is
  deliberately **no time-based grace after planting**: any read the watches see is
  reported. Other agent subsystems that walk user trees must skip
  `<state_dir>/honeypots` (the scanner and the shadow-copy engine do; this was the root
  cause of a startup ghost-read race, fixed in the shadow engine).
* Decoys are bait: the shadow-copy engine excludes them from snapshots (they are
  regenerated, hash-verified, at every start — snapshotting them has no recovery value).
* The periodic sweep is an integrity net (sha256 + existence): tamper/deletion are
  detected even if a watch event was missed; a deletion+recreation within one sweep
  interval that restores the exact original bytes is indistinguishable from untouched.

## Per-executable network policy (row 12)
* Containing a whole executable needs BOTH a writable cgroup v2 hierarchy AND nftables.
  With only one of them (or an iptables-only host, which the per-IP path tolerates but
  the cgroupv2 match cannot express) `block-exe` FAILS with that exact reason — it never
  falls back to a weaker containment silently.
* The containment is network-only by design: the pid tree stays unfrozen and observable
  (forensics), capped only by nothing new. It expires with the block TTL and always
  releases pids even if rule removal was incomplete (fail-open on release).
* Rule generation, level math and escalation are unit-tested everywhere. The nftables
  half of the containment IS kernel-verified: tools/kernel_drill.cpp runs the engine's
  real block/unblock cycle against a real kernel inside user+mount+net namespaces the
  runner creates (host ruleset untouched). The cgroup-migration half stays root/VM-gated:
  this kernel denies cgroup2 userns-mounts, and the drill asserts the honest refusal
  rather than pretending.
* Automatic escalation (exe -> N endpoints => contain the exe) defaults OFF: the agent
  only recommends. `remediation.auto_block_by_exe` turns it on deliberately.

## Analysis workflow (row 13)
* HyprNova plans and hands over analysis work; it never detonates a sample by itself.
  With no sandbox backend installed the plan says exactly that and offers the online
  (hash-only) links instead. The Ghidra/capa/Cutter/CAPE/AFL++ integrations are probed
  and drive the plan when present — their ABSENCE in this container is reported, not
  hidden, and installing them is a VM/env decision, not part of the agent.
* Sandbox argv builders generate commands; running them stays an explicit operator
  action. Absolute target paths are enforced (same trusted-path policy as core::exec).

## Synthetic fixtures vs reality
Detection results from `samples/` and `tests/corpus` fixtures measure the PIPELINE, not a
real-world detection rate. No detection-rate claims are made from synthetic tests.

## Environment-restricted (NOT RUN in the current container)
fanotify, audit netlink, per-exe cgroup migration (this kernel denies cgroup2
userns-mounts), nftables on the HOST ruleset (the containment path IS kernel-verified
inside namespaces the tests own — see row 12 above), systemd unit install/start,
rescue boot, Qt6-native GUI run, root-only file ops, real third-party scanner runs.
Each is gated in tests/run_tests.sh behind a prerequisite check, and every one has a
named unlock in docs/VM-BRINGUP.md (root + a VM).

## Shutdown
* Graceful SIGTERM shutdown completes in ≤2 s (sensor stop cascade is now
  interruptible). A single shutdown hang was observed once during pre-handoff
  testing and never reproduced in 25+ subsequent cycles; if a shutdown appears
  stuck, allow ~15 s, then check `pgrep -x hyprnovad` and the log tail and file
  a report with the log attached.
* The IPC socket is unlinked on graceful shutdown only when it is still the node
  this daemon bound (inode+dev match). After a crash the socket intentionally
  remains and is cleaned up by the next start's stale-socket path.
