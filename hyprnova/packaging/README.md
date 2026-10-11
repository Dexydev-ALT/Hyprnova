# Packaging

| Artifact | Status | Notes |
|---|---|---|
| `hyprnovad.service` | built + `systemd-analyze verify` clean | sandboxing tuned line-by-line; PrivateTmp/ProtectProc deliberately left permissive — a private /tmp or hidden /proc would silently blind the sensors (each has an honest comment) |
| `install.sh` / `uninstall.sh` | syntax-checked (`sh -n`) | root, target-host only; `--dump-config` seeds a first-run config; uninstall PRESERVES config + quarantine; `--purge` requires typed `PURGE` |
| `hyprnova_1.0.0_amd64.deb` | **BUILT** (rebuild anytime: `packaging/build-deb.sh`; recipe uses `control/` staging files) (`dpkg-deb --build --root-owner-group`), contents + control verified with `dpkg-deb -I/-c` | conffile `/etc/hyprnova/agent.json`; `postrm purge` ARCHIVES quarantine/snapshots/dumps to `/var/backups/` before deletion — the lifeline is never destroyed silently |
| actual `dpkg -i` install/remove | **NOT RUN** | needs root on a disposable VM (sandbox is unprivileged); do the drill from TESTING_GUIDE before shipping |
| `hyprnova.spec` + `build-rpm.sh` | written; **NOT RUN** | no rpm-build in sandbox; spec uses `%config(noreplace)` so operator config survives upgrades |

Upgrade behaviour: conffile/noreplace semantics keep the operator's `agent.json`
and all of `/var/lib/hyprnova` (quarantine, snapshots, memory dumps, rescue
report) across package upgrades on both formats.
