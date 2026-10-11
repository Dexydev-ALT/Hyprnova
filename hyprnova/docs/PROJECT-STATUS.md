# HyprNova Anti-Malware Sec — Full Project Status

Date: 2026-10-10 · Build: EXIT 0, 0 warnings · Self-test: **58/58** · C++ suite: **244/244** · QML loader: clean (0 errors) · RC gate: see docs/RC_CHECKLIST.md

---

## Batch 6 — pre-handoff QA (current)

Four real defects found by the pre-handoff live smoke, all fixed with regression
coverage or doc'd recipes; nothing known outstanding:

1. **`canaries` snapshot returned an empty honeypots section.** CanarySensor and
   HoneypotSensor both register under `SensorId::Canary`; the bridge looked the
   honeypot up by id and `dynamic_cast` silently returned the canary. Fixed by
   name-based lookup (`sensor<T>("honeypot")` overload + regression cases
   `sameid:*` in tests/test_honeypot.cpp). Verified live: planted=8, decoy read
   fires HONEYPOT READ.
2. **Graceful shutdown lagged up to 15 s.** Three hardening sensors slept 5 s in
   one flat `sleep_for`, ignoring stop during the sleep; joins are sequential.
   Now interruptible 250 ms slices → shutdown measured ≤2 s.
3. **The IPC socket was never unlinked on graceful shutdown** (latent since the
   bridge was written; masked by the stale-socket cleanup on next start).
   `fstat` on a bound AF_UNIX socket returns the sockfs pseudo-inode, which can
   never match the filesystem node, so the ownership comparison always failed.
   Fixed by recording the node's inode at bind time and unlinking only on an
   exact inode+dev match (a successor's socket is left alone).
4. **Rescue-report ingest verified end-to-end live** (was "not yet live-tested"):
   malformed report → kept unconsumed + WARN; valid report → ingested at start,
   2 ToolFinding events in history, file renamed `.consumed`.

Also: one TERM shutdown observed hanging once >120 s; not reproduced in 25+
targeted cycles (all ≤2 s) — documented in KNOWN_LIMITATIONS as an unreproduced
observation with the operator recipe (allow ~15 s, then check log tail).

## 1. What this is

A Linux anti-malware / EDR suite named **HyprNova Anti-Malware Sec** (that exact name,
`core/brand.hpp`). Three components:

| Component | What it is |
|---|---|
| `hyprnovad` | the daemon: sensors, heuristics, response engine, IPC socket |
| `hyprnova-cli` | operator console (~40 verbs: scan, settings, shred, decisions, ai-ask, adv-scan…) |
| Qt6/QML GUI | the desktop console (vibrancy theme, 10 pages, right-click Advanced scan) |

Language: strict C++20 (jthread/stop_token, span, string_view, concepts, RAII, zero raw
new/delete, epoll/io_uring background workers, lock-free event bus). Missing dependencies
degrade **visibly and honestly** — nothing pretends to work.

---

## 2. Every module, its state, and what is proven

### Module 1 — Boot / kernel hardening ✅ live-tested
- Boot audit: Secure Boot, kernel cmdline (forbidden/expected flags), initramfs digests, sbctl.
- Kernel hardening: 18 sysctl policies with drift detection (live: score 28/100, 12 drifts on
  the sandbox), lockdown/ASLR/livepatch checks, per-drift severity.
- **Fixer**: `harden-all` / `apply_remediation` writes `/etc/sysctl.d/99-hyprnova-hardening.conf`
  with the compliant subset (operator-initiated, needs root).
- MAC profile: AppArmor/SELinux inventory, unconfined critical daemons (live: flagged sshd).
- **NEW (batch 2)**: sshd weak-settings audit (`hardening/sshd_audit.{hpp,cpp}`) —
  PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding,
  ClientAliveInterval, MaxAuthTries, LoginGraceTime, AllowTcpForwarding+password combos.
  First-value-wins parsing per sshd_config(5); every weakness carries the exact fix line.
  HyprNova never edits sshd_config itself (a broken sshd locks you out of a remote box).

### Module 2 — Anti-ransomware ✅ live-tested end-to-end
- **Canary files**: HMAC-SHA256-signed bait in home roots + /tmp,/var/tmp,/var/www,/srv,/opt,
  /usr/share; reader allowlist; modify/delete/move/access monitoring; resign interval.
- **File monitor**: fanotify primary (needs CAP_SYS_ADMIN), inotify fallback (pid=0 honesty),
  entropy analysis (LOW→HIGH transitions), mass-modify detector, ransom-note detector
  (name hit OR ≥2 content markers), suspicious-extension detector.
- **Containment**: risk 850+ (auto-respond bar) → SIGSTOP (suspend, never kill), root processes
  excluded by default (`auto_suspend_unprivileged_only`), protected process list.
- **Shadow copies**: snapshots at start + after changes, keep 5, verify, restore in place or to
  a quarantine dir.
- **Never profiles itself**: state dir, quarantine, logs and /proc,/sys,/dev,/run are suppressed
  at the sensor (compiled in, not an editable exclusions file malware could touch).
- Proven live: the `systemupdate` trojan fixture tripped entropy + mass-modify + note + canary
  paths and was suspended in ~20 ms.

### Module 3 — Signature scanning ✅ live-tested
- In-tree **yara-lite + Aho-Corasick** engine (no libyara/Qt6 needed; uses OpenSSL for hashing
  when present).
- 12 builtin rules (behaviour-artifact class, not hash matching): EICAR (engine test only),
  **Ransomware_Dropper_Traits** (generic: 3+ of .locked/ransom text/bitcoin/shadow copies/…),
  Ransomware_Behaviour, ShellcodeLoader, C2_BeaconTooling, Rootkit_Artifacts, ELF/MZ mismatch,
  Cryptominer, Webshell_PHP, Persistence_Cron, plus more.
- Hash-verdict cache (200k entries), size/extension policy for *passive* scans; **explicit
  operator scans (OnDemand) bypass size/extension policy** but never directory exclusions.
- Verdict logic: a CRITICAL-severity signature alone = MALICIOUS (no dilution to "suspicious").
- `scan_now(path, reason, attributing_pid)` **publishes** its verdict (attributed) so the
  heuristic engine scores the actor — this was a real bug that got fixed.

### Module 4 — Behavioural sensors ✅ (with honest degradations)
- **proc-poll (NEW, the centrepiece of the user-style test)**: sweeps /proc every 250 ms, no
  capabilities needed. Detects new pids + pid-recycling via starttime, emits attributed
  `proc.exec` events and triggers **on-exec attributed scans**. Per-path rescan cooldown (2 s).
  Honest limits stated in code: short-lived processes inside one interval are missed; other
  users' exes unreadable.
- Falco sensor (socket consumer; degraded+explained when Falco absent), auditd sensor
  (netlink primary, log-tail fallback), osquery (10 queries), Suricata EVE consumer.
- **Every one of these parks itself with "disabled in settings"** when its toggle is off
  (`ISensor::enabled()` consulted on every start AND hot reload).

### Module 5 — Heuristic engine ✅ live-tested (the brain)
- Actor risk scoring: trigger novelty weighting (repeats contribute 25%), distinct-trigger
  tracking, time decay, per-actor lineage strings.
- Detection of: exec from world-writable paths, forbidden parent→child pairs (sshd/nginx/mysqld
  spawning shells/curl/nc), TTY-from-daemon, SSH spawn bursts, service anomalies.
- **Escalation pipeline** (score ≥750): freeze first (SIGSTOP, memory preserved) → memory
  inspection (W⁰X regions, signature match on extracted strings) → lineage batch scan →
  **DECISION REQUIRED** prompt with recommendation + full evidence. Evidence below High ⇒
  auto-resume (a frozen innocent is worse than a false positive).
- Loop guard: sensor never scores its own emissions; response/echo events are evidence-free
  (this fixed a real 324-duplicate-suspend storm).
- Learning baseline: **honors the toggle** (was broken — a default-on learning window halved
  all risk and silently disabled containment for 3 days on fresh installs).

### Module 6 — Response / remediation ✅ live-tested
- Actions: suspend (SIGSTOP), isolate (cgroup, best-effort), kill, **quarantine** (sample moved
  to 0600 dir, stored mode 0400 + `.meta` sidecar with sha256/mode/uid/gid, original unlinked),
  C2 network blocks (nftables, TTL + auto-expire).
- Protected lists: pids (1), process names (systemd/sshd/dbus/…), paths, own tree.
- **Decision queue**: GUI modal + `decisions` + `answer <id> allow|suspend|quarantine|kill`.
- Capability probe prints exactly what's possible as root vs user.

### Module 8 — Toolbox / combined scans ✅ live-tested
- Registry of ~30 ecosystem tools in 12 categories, each probed (binary + config/db paths).
- **Profiles** (KVRT is the DEFAULT second-opinion engine in all filesystem profiles):
  - `quick`: in-tree engine over /home,/tmp,/dev/shm,/var/tmp + ClamAV + **KVRT**
  - `deep`: quick targets + /opt,/srv,/root + rkhunter + chkrootkit + AIDE + maldet +
    **pkg-verify** + **crowdsec**
  - `kernel`: taint + seccomp focus
  - `audit`: Lynis index + systemd exposure + **pkg-verify** + **crowdsec**
- **systemd exposure analyzer**: parses systemd-analyze, 25 units graded, 19 UNSAFE (max 9.6)
  with per-unit hardening suggestions (accepts both TTY "✗" and piped "- " markers).
- **Package integrity (batch 2)**: `dpkg --verify` / `rpm -Va` / `pacman -Qkk` classified as
  `[MISSING]`, `[UNEXPLAINED]` (package-owned /usr changed — supply-chain/rootkit class) or
  `[ADMIN]` (/etc — normal admin work). Live-verified against real dpkg.
- **CrowdSec (batch 2)**: reads active community+local bans (`cscli decisions list -o json`),
  honest skip + install hint when absent; **every C2 block HyprNova installs is pushed back
  into CrowdSec** (`cscli decisions add`) so the community blocklist learns the indicator.
- **vt_lookup**: VirusTotal v3, **hash-only** (contents never leave the host through this path).

### Rescue environment (Module 8e) ✅ dry-run verified, E2E pending
- ISO staging → /boot/hyprnova, GRUB entry, offline cleaner script, rescue-report.json ingest
  path. Blockers reported honestly; snapshot-first guidance in docs. Ingest E2E + agent.json
  rescue section still pending (below).

### Module 9 — Shredder ✅ live-tested
- Plan/execute split: dry-run preview (paths, sizes, types, per-item notes) is the default;
  execution requires explicit confirmation; protected system prefixes always refused
  (selectively — the rest of a mixed list still shreds); symlinks unlink-only, never followed;
  50k item cap; deepest-first removal (parents last); optional zero-fill overwrite pass;
  audit line without contents. Fixed two real bugs: `/`-prefix protecting *everything*, and
  directory removal order leaving roots behind.

### Module 10 — AI analyst ✅ built, inert until YOU add a key
- Provider: **Groq** (default model `llama-3.3-70b-versative` — actually
  `llama-3.3-70b-versatile`), called via hardened exec of system curl (no shell), request body
  staged at 0600 temp file, deleted after; consult journal (no key, no content).
- Evidence bundles: `ai-ask` = posture + last 40 events; `ai-review PID` = pid bundle + fresh
  scan verdict + pending decision.
- System prompt forbids fabrication and forbids authorizing destructive actions — **advises
  only, you decide**. Inert without a key, saying exactly why.
- ⚠️ **Needs a Groq API key from you (section 5).**

### GUI ✅ 10 pages, 27 QML files load clean
Dashboard (shield hero, posture dial, sparklines) · Threats (actors, decisions, event feed) ·
Processes (tree, right-click actions) · Network (listeners, C2 blocks) · Scanning (results,
sweep) · Hardening (drift + apply) · Canaries · Remediation (actions/frozen/blocks/quarantine) ·
Tools (deep-scan launcher with profile chips) · Settings (**21 ON/OFF switches**, live) .
**Right-click → Advanced scan on 5 surfaces**: scan findings, event-feed rows, process rows,
quarantined samples (re-verifies the stored sample), threat cards (actor's exe).
Loader check instantiates ALL 27 pages/components with real type resolution (this caught the
Panel glyph bug that had been silently breaking 9 of 11 pages).

### Infrastructure
`scripts/install-deps.sh` (apt/dnf/pacman/zypper; build/gui/tools groups; CrowdSec hint) ·
`scripts/fetch-kvrt.sh` (official Kaspersky CDN, honest about checksums) ·
`scripts/qml_load_check.py` · `docs/VM-BRINGUP.md` (KVM/virt-install/OVMF + snapshot workflow) ·
`README.md` (full operator docs) · `samples/` (the two behavioural fixtures, documented).

---

## 3. The trojan test (the one you asked for) — full transcript of what happens

1. I built `samples/sandbox/systemupdate.c`: masquerades as a system updater, carries a
   112 KiB generated high-entropy "packed stage" (entropy 7.68), mass-rewrites victims with
   `.locked` renames, drops `README_RESTORE.txt`, `rm -rf`s a fake backup dir, beacons to
   localhost. **No EICAR, no magic test string — detection must be earned.**
2. You (me) run `./systemupdate` like a normal user. No `scan` command is invoked by anyone.
3. proc-poll sees the exec within 250 ms → attributed on-exec scan →
   **MALICIOUS, risk 1000/1000** (Dropper_Traits + Ransomware_Behaviour + entropy + path).
4. Heuristics hit 1000 → **SIGSTOP** (state `Ts`) in ~20 ms, memory image preserved.
5. Escalation: memory inspected → lineage batch-scanned → **DECISION REQUIRED** with
   recommendation and evidence.
6. Operator answers `quarantine` → sample stored (0400 + sidecar), original unlinked, process
   killed. (Answer `allow` would resume it; `kill` kills.)
7. **False-positive control**: `photo-backup` (slow, low-entropy, benign) runs to completion
   with score 0 and zero alerts.
8. Toggle matrix proven behaviorally: realtime_protection off → still caught by on-exec
   scanning (defense in depth); + realtime_scanning off → runs free; auto_respond off →
   detected 1000 but NOT suspended, decision raised with "step 1: skipped, auto_respond is
   disabled (observation only)"; process_polling off → no attribution/no on-exec scan;
   learning off → full-severity scoring from minute zero.

---

## 4. Real bugs found & fixed (highlights — all regression-covered by self-tests)

1. `Panel.qml` declared `icon` but 9 pages assigned `glyph` → **9 of 11 GUI pages failed to
   load silently** (lazy Loaders hid it). Loader now instantiates every file.
2. Attached `ToolTip.wrapMode` (invalid) aborted 6 more pages.
3. Shredder: `"/"` prefix matched every path as protected; parents removed before children.
4. Critical signature hit diluted to "suspicious" (single match < threshold).
5. Explicit operator scans skipped small/mistyped files via realtime policy.
6. **`scan_now` never published** — attributed on-exec verdicts died in the hash cache.
7. Learning window ignored the toggle (default-on + saved-baseline reopening it).
8. Response-echo storm: remediation events re-scored by heuristics (324 duplicate suspends).
9. The daemon watched its own log; the ransom-note detector flagged IOC text echoed there.
   Fixed with ≥2-content-marker rule + compiled-in own-write suppression.
10. `decisions` count computed after `std::move` → always "none pending".
11. Feature-toggle mirror table drift (twice) — self-test now cross-checks both tables.
12. Piped systemd-analyze emits "- " not "✗" (parser accepts both).
13. Various C++/QML/JSON-API fixes (as_string view semantics, lambda deduction, escapes).

---

## 5. ⚠️ WHAT YOU NEED TO PROVIDE / DO (the honest checklist)

### Keys (the two big ones)
1. **Groq API key** (AI analyst):
   - Go to **https://console.groq.com** → sign in → **API Keys** → *Create API Key* → copy it
     (starts with `gsk_`). Free tier is enough to start.
   - Put it in the agent config (`/etc/hyprnova/agent.json` or your test config):
     ```json
     "ai": { "enabled": true, "api_key": "gsk_…", "model": "llama-3.3-70b-versatile" }
     ```
   - Then `hyprnova-cli set ai_analyst on` (or restart the daemon). Without the key everything
     stays honest-inert: "ai.enabled is false…". The key is never logged, never printed, never
     sent anywhere except Groq over HTTPS; the request body is staged 0600 and deleted.
2. **VirusTotal API key** (for the adv-scan VT rung):
   - **https://www.virustotal.com** → Sign up free → API key from your profile.
   - Config: `"integrations": { "virustotal_enabled": true, "virustotal_api_key": "…" }`
   - Hash-only lookups (4/min free tier). **any.run needs no key for the deep links**; an
     account only matters if you do interactive detonations yourself.

### Installs on a real machine (all optional; everything degrades honestly)
3. **KVRT**: `sudo scripts/fetch-kvrt.sh` (internet) — becomes the default second-opinion
   engine automatically. Or download manually from kaspersky.com to /opt/kaspersky/kvrt/kvrt.
4. **ClamAV**: `scripts/install-deps.sh --tools` or `apt install clamav clamdscan` + freshen sigs.
5. **CrowdSec**: official repo per doc.crowdsec.net (hint in install-deps.sh) — enables the
   community-blocklist read + push paths that are currently honest-skips.
6. **Qt6** for the GUI: `scripts/install-deps.sh --gui` (in this sandbox we only verify QML via
   PySide6; the real console wants system Qt6).
7. **Optional extras**: Falco, osquery, Suricata, rkhunter, chkrootkit, AIDE, maldet, Lynis
   (`--tools` group). Each shows up as a live/degrading sensor with reasons.

### Deployment reality
8. **Run the daemon as root on a real box** for full coverage: fanotify (write attribution),
   audit netlink, cgroup freezing, nftables blocks, cross-user visibility. Unprivileged mode
   still detects/suspends own-uid processes thanks to proc-poll — and says so.
9. **Real-malware testing** (you asked for real samples, not just EICAR — acknowledged, and the
   behavioural fixtures stand in for now): use **docs/VM-BRINGUP.md**: KVM VM, snapshot first,
   run samples only inside the VM. Real-sample runs are yours to source and authorize; the
   pipeline (proc-poll → on-exec scan → suspend → decision → quarantine) is exactly what they
   will exercise, and KVRT/ClamAV bring the commercial signature coverage for them.

---

## 6. What is NOT done yet (the honest gap list)

| Area | State |
|---|---|
| Memory-forensics module | In-process inspection (W⁰X + strings + signatures) live-tested, rwx_fixture drill asset persisted, Memory page exists; **no Volatility3/MemProcFS/LiME acquisition, no timelines** |
| File carving | **DONE (batch 4)**: opt-in CarveConfig, `hyprnova-cli carve/triage`, 17 cases |
| System repair | Rescue env exists (staging/GRUB/cleaner); **no chroot/btrfs/Timeshift/Snapper/grub-repair module** |
| Malware-analysis sandbox | **DONE (batch 4)**: tools/analysis plans the work, deep links, firejail/bwrap argv; Ghidra/capa/CAPE installs stay probed-honestly env-gated |
| GUI pages | **DONE (batch 5)**: all 16 pages load clean; batch 5 wired the last data surfaces (honeypot decoys on the Canaries page, network-contained executables on the Network page). What remains is polish, not absence |
| Honeypots | **DONE (batch 4)**: event-driven inotify decoy sensor, real reads/tampers/deletes detected live; Cowrie/OpenCanary federation stays registered-only |
| nftables by-executable policy | **DONE (batch 4)**: block-exe (cgroup v2 + cgroupv2 match), escalation, CLI/GUI verbs; kernel path NOT RUN (needs root VM) |
| rescue-report ingest E2E | **LIVE-TESTED (pre-handoff)**: malformed report kept+WARN; valid report → ToolFinding events in history + `.consumed` rename |
| Heartbeat | Still present **by design** — removal planned once the app is "done" (your instruction, row 15, P3) |
| Packaging | **DONE (batch 3)**: .deb built (conffile, purge-safe), RPM spec + build scripts, systemd unit, install/uninstall; real dpkg/dnf installs NOT RUN (VM-gated) |
| Formal tests/ | **244 cases green** (self-test 58/58 + runner 6 sections); no gtest/CI by design (in-tree, offline) |
| Qt6 native build in VM | Fallbacks in place; native Qt6 GUI build on a real host pending |
| Real-malware runs | Not performed here (offline sandbox, and sourcing real samples is your call) — §8 drill is now AUTOMATED with the sandbox fixtures (tests/test_response_e2e.cpp) |

---

## 7. Cheat sheet (everything that exists today)

```bash
scripts/install-deps.sh [--yes|--tools-only]      # deps (apt/dnf/pacman/zypper)
scripts/fetch-kvrt.sh                             # stage KVRT (default scan engine)
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && cmake --build build -j2
./build/hyprnovad -f -c /etc/hyprnova/agent.json  # run the daemon (root for full coverage)
./build/hyprnovad --self-test                     # 58 checks

hyprnova-cli status | sensors | events | risk | processes | network | decisions
hyprnova-cli scan PATH | deep-scan quick|deep|kernel|audit [PATH]
hyprnova-cli adv-scan PATH                        # right-click equivalent
hyprnova-cli settings | set KEY on|off            # 21 switches, live
hyprnova-cli shred PATH... [--overwrite] [--yes]  # preview first, always
hyprnova-cli ai-ask "…" | ai-review PID           # needs your Groq key
hyprnova-cli snapshots | verify-snapshot ID | restore-snapshot ID [DEST]
hyprnova-cli systemd-check | rescue-status | rescue-prepare [--write] | harden-all
hyprnova-cli investigate PID | answer ID allow|suspend|quarantine|kill
```

Config keys you'll actually touch: `ai.api_key`, `integrations.virustotal_api_key`,
`integrations.virustotal_enabled`, `integrations.crowdsec_enabled`, and the 21 toggles via
`hyprnova-cli set …`.

## Batch 5 — 2026-10-11 (root/VM-gated items + GUI data surfaces)

- **Kernel drill**: `tools/kernel_drill.cpp` — the engine's REAL nftables path
  (probe -> apply_block_set -> block_c2 -> kernel ENFORCES (connect times out)
  -> unblock -> traffic restored) executed inside user+mount+net namespaces the
  runner creates. First run on a real kernel found a genuine bug: bare `dport`
  rules are rejected in inet chains; blocks now pin tcp+udp. Runner section 5
  gates the drill (skip lines stay honest when unshare or nft are absent).
- **GUI data surfaces**: Honeypot decoys panel on the Canaries page (new
  `honeypots` section in the canaries snapshot; bait bodies/hashes never leave
  the daemon beyond the tamper-baseline prefix) and Network-contained
  executables on the Network page (`exe_blocks` + Release; Qt backend gained
  exeBlocks/unblockExe/blockExe). QML loader: 33 root objects, 0 errors.
- **Packaging**: .deb rebuilt from the current tree and extraction-verified
  without root (layout == install.sh, conffiles correct, postinst now creates
  the hyprnova operator group); exec bits restored on the scripts a snapshot
  restore dropped; e2e drill now chmods its fixtures before exec so a bit-loss
  can never silently no-op the §8 drill again.

## Batch 4 — 2026-10-10 ("fix all known limitations and gaps" sweep)

GAP rows 11–14 + the actionable KNOWN_LIMITATIONS items, each live-drilled and
regression-tested (full gate: docs/RC_CHECKLIST.md):

- **Honeypots rewritten** to an event-driven inotify decoy sensor (reads fire at
  event time with /proc fd attribution; sweep = O_NOATIME sha256 integrity net;
  self-events drain-discarded under guard). The month-long "ghost reader" hunt
  ended with a ROOT CAUSE: the startup shadow-copy snapshot read the decoy bait
  itself — the shadow engine now excludes `<state_dir>/honeypots`. Live drills:
  0 idle events ×4 runs; exactly one correctly-named event per read/modify/delete.
- **Per-exe nftables policy (row 12)**: `block-exe` contains a whole executable
  (pid tree in a cgroup, sockets dropped by `socket cgroupv2` match) with
  auto-escalation OFF by default (human-in-the-loop), TTL self-healing, and an
  honest FAILURE when cgroup v2 + nftables are not both present (verified live).
- **Analysis workflow (row 13)**: `tools/analysis` — per-sample plans (in-tree
  static steps, installed tools become steps, absent tools are NAMED), hash-only
  deep links, firejail/bwrap argv builders; HyprNova never detonates by itself.
- **Bench harness (row 14)**: `hyprnova-bench` measures sha256/json/bus-latency/
  carver/honeypot with human + JSON reports; suite pins SHAPE, never magnitudes.
- **IPC group auth**: operator group on the socket (pure decision table pinned in
  tests), honest degrade when the group is absent, install.sh creates the group.
- **Spec §8 automated**: the TESTING_GUIDE §3 sandbox drill now runs in the
  suite (`tests/test_response_e2e.cpp`) — fixtures vs a LIVE file monitor,
  benign control silent, suspend-not-kill / reversible / dry-run-refuses pinned.
- **Runner**: 6 sections incl. bench smoke and honest env-gated NOT RUN lines;
  build at -j1 (constrained-builder OOM at -j2). W^X drill fixture persisted
  (tests/fixtures/rwx_fixture.c). 19-warning from-scratch pass reduced to a
  **0-warning incremental release build**; suite 244/244; self-test 58/58.


## Batch 3 — 2026-10-10 (new-spec execution: found bugs fixed live, all P1s closed)

**Verification state: 109/109 C++ cases, self-test 58/58, QML loader 33/33, full runner ALL SECTIONS PASSED, machine-readable `tests/report.json` green. Git repo on `main`, tree committed through `440d79b`.**

New findings this batch (all FIXED, regression-tested):
- **F7 (HIGH)** — W^X detection dead since inception: `maps()` tested `perms[0]=='w'`, never true on `rwxp` lines (`region_wx()` classifier now; live-verified against a synthetic RWX process).
- **F8 (LOW)** — CLI `mem-dump PID --yes` parsed the flag as PID.
- **Config serializer ×2 (HIGH for saved configs)** — `to_json` wrote `log_level` as the padded log tag (`"INFO "`) and `scan.backend` as display names (`"yara-lite (built-in)"`); every agent-saved config failed reload. Full default-config roundtrip now enforced by test.
- Rescue ingest hardened: per-finding events (cap 50), `/var/lib` fallback, malformed report kept unconsumed + WARN; cleaner script now writes a findings array. Live E2E verified both paths.

Delivered this batch:
- Module 4c live drill: inspect (anchor ticks match /proc), dump 0600 with header, CLI verbs.
- sshd weak-settings audit surfaced into toolbox + deep/audit profiles (report-only; live: 7 findings on this host).
- **All five remaining GUI pages** (AI analyst, Integrations, Backups, File recovery, Timeline) + backend invokables (`askAi/reviewAi/runTool/vtLookup/snapshot/restoreShadow/verifySnapshot`, `settingsRaw`); nav = 16 pages; QML loader 33/33.
- **Detection corpus** (spec §7): `tests/corpus` 10 synthetic fixtures + MANIFEST enforced by `test_corpus.cpp` (missing fixture = FAIL; EICAR excluded by rule); trait fixtures c2/miner/rootkit closed.
- **Packaging** (spec §5B): systemd unit (verify-clean; PrivateTmp/ProtectProc deliberately permissive with reasons), install/uninstall scripts (uninstall preserves config+quarantine; purge typed-confirm), **.deb built** (conffile; purge archives recovery data to /var/backups), RPM spec written. **NOT RUN (needs disposable VM): real dpkg -i / dnf installs.**

Remaining (P2, in order): file-carving opt-in workflow; honeypots; per-exe firewall; metrics/benchmarks harness (spec §9/§10); then VM drills (install, real-malware matrix).
