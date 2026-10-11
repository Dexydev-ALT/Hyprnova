# HyprNova Anti-Malware Sec

A behavioural, low-overhead EDR/anti-malware agent for Linux, in idiomatic C++20,
with a Qt6/QML console. One agent, three surfaces:

```
hyprnovad       the daemon: sensors -> event bus -> detection -> response
hyprnova-cli    the operator console (scripts, SSH, incident work)
hyprnova-gui    the Qt6/QML desktop console (dark, keyboard-driven)
```

## What it does

| Layer | Module | Highlights |
|---|---|---|
| Boot & platform trust | `hardening/` | Secure Boot/MOK/UEFI, kernel taint, sysctl drift + remediation, AppArmor/SELinux audit **including third-party trusted profiles**, per-daemon confinement findings |
| Anti-ransomware | `anti_ransomware/` | HMAC canaries (bait names, magic bytes), inotify/fanotify, sliding-window entropy + mass-modify scoring, self-read suppression |
| Static detection | `scanning/` | in-tree YaraLite (+ optional libyara/clamav/KVRT), Aho-Corasick, sha256 LRU cache (200k), batched execve scans, capped sweeps |
| Runtime sensors | `behavioral/` | Falco, auditd (netlink, watch rules, auid attribution), Suricata EVE (C2 beacon scoring), osquery — all optional, all non-blocking |
| Behavioural engine | `heuristics/` | corroboration-first actor scoring, decay, baseline learning, forbidden-lineage rules, **per-app profiles authored by trusted third parties**, escalation: freeze → memory YARA → lineage scan → prompt |
| Response & recovery | `remediation/` | journaled actions, nftables blocks with rollback + TTL, cgroup-v2 freeze, evidence-preserving kill, hash-verified quarantine, **shadow copies** (snapshot every start, retention, manifest-verified restore) |
| Ecosystem | `tools/` | the Toolbox: 78 registered tools (rkhunter, chkrootkit, AIDE, Tripwire, Samhain, Lynis, OpenSCAP, Trivy, Grype, Nuclei, Nmap, Firejail, Docker, TPM, LUKS, Wazuh, CrowdSec, Zeek, Snort, Fail2ban, Elastic/Loki/Graylog, …), allow-listed on-demand runners, VirusTotal hash lookups (hash-only), live /proc seccomp audit |
| Console | `gui/` | Qt6/QML: sidebar + hero verdict + real recommendation cards + Quick Scan; opaque elements on a translucent ("vibrancy") base plate; `Tools` page = the truthful coverage matrix |

Every optional dependency degrades visibly instead of crashing: a missing
library or tool is a *reported fact*, never a failed start.

## Build

```bash
# Debian/Ubuntu
sudo apt install -y build-essential cmake
sudo apt install -y qt6-base-dev qt6-declarative-dev \
  qml6-module-qtquick-controls qml6-module-qtquick-layouts   # optional: GUI
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j$(nproc)

./build/hyprnovad --self-test
./build/hyprnovad -c /etc/hyprnova/agent.json        # or run under systemd
./build/hyprnova-cli -s /run/hyprnova/gui.sock status
```

Zero external dependencies are required: SHA-256/HMAC, YARA-subset, netlink
audit and nftables all have compiled-in fallbacks and use the system libraries
when present.

## Verify the QML without Qt (optional)

```bash
pip install PySide6-Essentials
python3 scripts/qml_load_check.py     # loads the whole UI offscreen under real Qt
```

## Recovery when the PC is "very bad"

A shadow copy is taken at every agent start and after big changes; old ones are
pruned (default keep 5). Restore into place or into a quarantine dir:

```bash
hyprnova-cli snapshots
hyprnova-cli verify-snapshot <id>
sudo hyprnova-cli restore-snapshot <id>            # in place
sudo hyprnova-cli restore-snapshot <id> /safe/dest # into a dir
```

## Sign of life

The daemon broadcasts a heartbeat (default every 30 s): alive flag, uptime,
posture, counters. (Temporary scaffolding — it goes away once the full app is
done.)

```bash
hyprnova-cli watch        # ♥ alive uptime=… posture=… published=…
```

The GUI's connection dot and posture tile are driven by the same beats — if
they stop, the console says *disconnected* instead of showing stale data.

## Settings, shredder, advanced scan, AI analyst

Everything is a simple ON/OFF switch — 19 of them, validated, applied, persisted
and hot-reloaded by the daemon in one step:

```bash
hyprnova-cli settings               # the whole table, with descriptions
hyprnova-cli set dry_run on         # observe-only: detect but never act
hyprnova-cli set realtime_protection off
hyprnova-cli set realtime_protection on
```

The GUI's Settings page shows the same table as toggle switches.

Deleting incident leftovers — full preview first, execution only with an
explicit confirmation, protected system paths always refused, symlinks never
followed:

```bash
hyprnova-cli shred /tmp/drop/            # DRY RUN: list + sizes + method note
hyprnova-cli shred /tmp/drop/ --yes      # execute exactly what was previewed
hyprnova-cli shred /tmp/drop/ --overwrite --yes   # zero-fill pass before unlink
```

One right-click equivalent for a suspicious file — local engine verdict,
sha256 and the VirusTotal escalation ladder in a single call (GUI: right-click
a finding, a feed event, or a process → "Advanced scan"):

```bash
hyprnova-cli adv-scan /tmp/drop/payload
```

The AI analyst (Groq; key arrives later, inert until then) advises only — it
never executes anything, and it refuses to answer without saying why when it
is not configured:

```bash
hyprnova-cli ai-ask "Summarise the last hour of detections"
hyprnova-cli ai-review 1234        # evidence bundle for one PID
```

## Second-opinion engines: KVRT, CrowdSec, package integrity

KVRT (Kaspersky Virus Removal Tool) is the DEFAULT second-opinion engine for
every filesystem scan profile — quick, deep and full all run it after the
in-tree engine and ClamAV. Absent installations are told the truth and how to
fix it:

```bash
scripts/fetch-kvrt.sh               # stages KVRT from the official CDN
hyprnova-cli deep-scan quick        # engine + ClamAV + KVRT
hyprnova-cli deep-scan deep         # + rootkit tools, package verify, CrowdSec
```

CrowdSec is the zero-day tripwire: `deep-scan audit` / `deep-scan deep` read
active community and local ban decisions via `cscli` (honest skip when it is
not installed), and every C2 block HyprNova installs is pushed back into
CrowdSec so the whole community blocklist learns the indicator. Toggle:
`hyprnova-cli set crowdsec off`.

Package-manager integrity (`dpkg --verify` / `rpm -Va` / `pacman -Qkk`) runs in
the deep and audit profiles: changes to package-owned files under /usr are
UNEXPLAINED until proven otherwise; /etc changes are marked as admin work.

## Right-click anywhere = Advanced scan

Every file surface in the console has the real-AV context menu:

* scan-finding rows — right-click → Advanced scan
* the live event feed — right-click a file event
* process rows — "Advanced scan (engine + VirusTotal ladder)"
* quarantined samples — right-click re-verifies the stored sample
* threat cards — right-click the actor's executable

The ladder in one call: local engine verdict + sha256 + VirusTotal
(key-gated, hash-only) → MALICIOUS ⇒ quarantine-and-suspend guidance and an
ANY.RUN deep link; suspicious-but-unconfirmed ⇒ ANY.RUN detonation link + a
KVRT deep-scan command. Nothing is ever uploaded without
`integrations.online_submission`.

## Docs

* `docs/VM-BRINGUP.md` — full bring-up and per-module test plan
* `core/brand.hpp` — the single naming point (product name lives exactly there)
