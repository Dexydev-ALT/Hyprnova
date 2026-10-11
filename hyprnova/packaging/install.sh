#!/bin/sh
# HyprNova install -- honest, idempotent, reviewable. Run as root on the TARGET
# host (never inside the build sandbox). Layout:
#   /usr/bin/hyprnovad /usr/bin/hyprnova-cli /usr/bin/hyprnova-gui
#   /etc/hyprnova/agent.json          (created on first install; NEVER overwritten)
#   /etc/hyprnova/rules/              (empty by default; built-in floor always active)
#   /var/lib/hyprnova/                (state, quarantine, snapshots, memory dumps)
#   /etc/systemd/system/hyprnovad.service
set -eu
PREFIX=${PREFIX:-/usr}
SYSCONF=/etc/hyprnova
STATE=/var/lib/hyprnova
SRC=$(cd "$(dirname "$0")/.." && pwd)

[ "$(id -u)" = 0 ] || { echo "refusing: run as root on the target host" >&2; exit 1; }
[ -x "$SRC/build/hyprnovad" ] || { echo "refusing: $SRC/build/hyprnovad missing -- build first (cmake -S . -B build && cmake --build build)" >&2; exit 1; }

install -D -m755 "$SRC/build/hyprnovad"      "$PREFIX/bin/hyprnovad"
install -D -m755 "$SRC/build/hyprnova-cli"   "$PREFIX/bin/hyprnova-cli"
[ -x "$SRC/build/hyprnova-gui" ] && install -D -m755 "$SRC/build/hyprnova-gui" "$PREFIX/bin/hyprnova-gui" || echo "note: GUI binary absent (Qt6 not built) -- installing agent + CLI only"
install -D -m644 "$SRC/packaging/hyprnovad.service" /etc/systemd/system/hyprnovad.service
install -D -m755 "$SRC/scripts/install-deps.sh"     "$PREFIX/share/hyprnova/install-deps.sh"

# First-run config: only if absent. An existing operator policy is never touched.
if [ ! -f "$SYSCONF/agent.json" ]; then
    install -D -m600 /dev/null "$SYSCONF/agent.json"
    "$PREFIX/bin/hyprnovad" --dump-config > "$SYSCONF/agent.json"
    chmod 600 "$SYSCONF/agent.json"
    echo "wrote $SYSCONF/agent.json (defaults; edit ai.api_key / integrations keys as needed)"
else
    echo "keeping existing $SYSCONF/agent.json"
fi
install -d -m700 "$STATE" "$STATE/quarantine" "$STATE/memory"
install -d -m755 "$SYSCONF/rules"

# Operator group (gui.ipc_group default "hyprnova"): members may connect to the
# IPC socket without being root. Absent group is not fatal -- the daemon logs
# honestly and falls back to root/same-uid auth -- but a real install wants it.
if ! getent group hyprnova >/dev/null 2>&1; then
    groupadd --system hyprnova 2>/dev/null || addgroup --system hyprnova 2>/dev/null ||
        echo "note: could not create the hyprnova group; operators will need root or gui allow-list" >&2
fi
# To let an operator account use the console:  usermod -aG hyprnova <name>

systemctl daemon-reload 2>/dev/null || echo "note: systemctl unavailable -- enable manually"
systemctl enable --now hyprnovad.service 2>/dev/null || echo "note: service not started automatically -- systemctl enable --now hyprnovad"
echo "installed. verify: hyprnova-cli status"
