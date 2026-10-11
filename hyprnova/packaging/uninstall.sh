#!/bin/sh
# HyprNova uninstall. PRESERVES operator data by default: config, state,
# quarantine, snapshots and memory dumps are kept (spec rule: recovery data
# must survive the agent). --purge removes them WITH an explicit second look.
set -eu
PREFIX=${PREFIX:-/usr}
SYSCONF=/etc/hyprnova
STATE=/var/lib/hyprnova

[ "$(id -u)" = 0 ] || { echo "refusing: run as root" >&2; exit 1; }

systemctl disable --now hyprnovad.service 2>/dev/null || true
rm -f /etc/systemd/system/hyprnovad.service
systemctl daemon-reload 2>/dev/null || true
rm -f "$PREFIX/bin/hyprnovad" "$PREFIX/bin/hyprnova-cli" "$PREFIX/bin/hyprnova-gui"
rm -rf "$PREFIX/share/hyprnova"

if [ "$1" = "--purge" ]; then
    echo "about to DELETE: $SYSCONF (config) and $STATE (quarantine, snapshots, dumps)"
    printf "type PURGE to confirm: "
    read -r answer
    [ "$answer" = "PURGE" ] || { echo "aborted; nothing removed"; exit 1; }
    rm -rf "$SYSCONF" "$STATE"
    echo "purged."
else
    echo "kept: $SYSCONF (config), $STATE (quarantine + recovery data)."
    echo "Re-install reuses them. Remove permanently later with: $0 --purge"
fi
