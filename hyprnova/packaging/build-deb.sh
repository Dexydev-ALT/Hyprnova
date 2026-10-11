#!/bin/sh
# Rebuild the .deb from the repo (idempotent; recreates the staging tree).
set -eu
SRC=$(cd "$(dirname "$0")/.." && pwd)
cd "$SRC/packaging"
[ -x "$SRC/build/hyprnovad" ] || { echo "build first: cmake -S . -B build && cmake --build build" >&2; exit 1; }
rm -rf deb
mkdir -p deb/DEBIAN deb/usr/bin deb/usr/share/doc/hyprnova deb/usr/share/hyprnova \
         deb/etc/systemd/system deb/etc/hyprnova
cp control/* deb/DEBIAN/ 2>/dev/null || true
chmod 755 deb/DEBIAN/postinst deb/DEBIAN/postrm
install -m755 "$SRC/build/hyprnovad"    deb/usr/bin/
install -m755 "$SRC/build/hyprnova-cli" deb/usr/bin/
[ -x "$SRC/build/hyprnova-gui" ] && install -m755 "$SRC/build/hyprnova-gui" deb/usr/bin/ || true
install -m644 hyprnovad.service deb/etc/systemd/system/
[ -f "$SRC/scripts/install-deps.sh" ] && install -m755 "$SRC/scripts/install-deps.sh" deb/usr/share/hyprnova/
[ -f "$SRC/README.md" ] && install -m644 "$SRC/README.md" deb/usr/share/doc/hyprnova/
"$SRC/build/hyprnovad" --dump-config > deb/etc/hyprnova/agent.json
chmod 600 deb/etc/hyprnova/agent.json
dpkg-deb --build --root-owner-group deb hyprnova_1.0.0_amd64.deb
# Remove the staging tree: it duplicates the ~75 MB daemon binary and pushed the
# workspace over the snapshot cap once (files got silently dropped). Rebuilt on
# every run anyway.
rm -rf deb
echo "built packaging/hyprnova_1.0.0_amd64.deb"
