#!/bin/sh
# Build the RPM. Requires rpm-build + the sources laid out as rpmbuild expects.
# NOT RUN in the build sandbox (no rpm-build): run on an RPM host or VM.
set -eu
[ "$(id -u)" != 0 ] || true
command -v rpmbuild >/dev/null || { echo "rpmbuild missing -- install rpm-build (NOT RUN here)" >&2; exit 1; }
SRC=$(cd "$(dirname "$0")/.." && pwd)
VER=1.0.0
TAR="/tmp/hyprnova-$VER.tar.gz"
tar -czf "$TAR" -C "$SRC/.." "hyprnova" \
  --exclude=hyprnova/build --exclude=hyprnova/.git || tar -czf "$TAR" -C "$SRC/.." hyprnova
mkdir -p ~/rpmbuild/SPECS ~/rpmbuild/SOURCES
cp "$SRC/packaging/hyprnova.spec" ~/rpmbuild/SPECS/
cp "$TAR" ~/rpmbuild/SOURCES/
rpmbuild -ba ~/rpmbuild/SPECS/hyprnova.spec
echo "RPM(s) under ~/rpmbuild/RPMS/"
