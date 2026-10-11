#!/usr/bin/env bash
# HyprNova — single documented test entry point.
#   tests/run_tests.sh [--json PATH]
# Builds what it needs, runs the C++ suites, the daemon self-test and (when a
# Qt6/PySide6 environment is present) the QML loader check. Sections whose
# prerequisites are missing print NOT RUN and are excluded from the pass count.
set -u
cd "$(dirname "$0")/.."
JSON=""
[ "${1:-}" = "--json" ] && JSON="${2:-tests/report.json}"
FAILURES=0

echo "== [1/6] build =="
export PATH="$HOME/.local/bin:$PATH"
if [ ! -f build/hyprnovad ]; then
  cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null || exit 1
fi
# -j1: the release build OOMs at -j2 on constrained builders; one job is the
# honest default and always safe.
cmake --build build -j1 >/tmp/hyprnova-build.log 2>&1 || { tail -20 /tmp/hyprnova-build.log; exit 1; }
echo "   build OK"

echo "== [2/6] C++ suites (tests/hyprnova-tests) =="
if [ -x build/hyprnova-tests ]; then
  if [ -n "$JSON" ]; then
    ./build/hyprnova-tests --json "$JSON" || FAILURES=$((FAILURES+1))
  else
    ./build/hyprnova-tests || FAILURES=$((FAILURES+1))
  fi
else
  echo "   NOT RUN (configure with -DHYPRNOVA_BUILD_TESTS=ON)"
fi

echo "== [3/6] daemon self-test =="
./build/hyprnovad --self-test >/tmp/hyprnova-selftest.log 2>&1 \
  && grep -h "SELF-TEST" /tmp/hyprnova-selftest.log \
  || { echo "   self-test FAILED"; tail -5 /tmp/hyprnova-selftest.log; FAILURES=$((FAILURES+1)); }

echo "== [4/6] bench smoke (shape only; magnitudes are environment-specific) =="
if [ -x build/hyprnova-bench ]; then
  HN_BENCH_SCRATCH=/tmp/hyprnova-bench-smoke ./build/hyprnova-bench --quick >/tmp/hyprnova-bench.log 2>&1 \
    && grep -E "sha256.throughput|bus.publish_dispatch" /tmp/hyprnova-bench.log \
    || { echo "   bench FAILED"; tail -5 /tmp/hyprnova-bench.log; FAILURES=$((FAILURES+1)); }
else
  echo "   NOT RUN (build/hyprnova-bench missing)"
fi

echo "== [5/6] kernel drills (user-namespace scoped; NOT RUN is honest) =="
if unshare -Urnm true 2>/dev/null; then
  NFT_BIN=""
  for cand in /tmp/nftroot/nft-wrapper.sh "$(command -v nft 2>/dev/null)"; do
    [ -n "$cand" ] && [ -x "$cand" ] && { NFT_BIN="$cand"; break; }
  done
  if [ -n "$NFT_BIN" ]; then
    export NFT_BIN
    unshare -Urnm sh -c '
      mount -t tmpfs none /run 2>/dev/null; mkdir -p /run/hyprnova
      ip link set lo up 2>/dev/null; ip addr replace 10.9.9.1/32 dev lo 2>/dev/null
      HN_NFT="$NFT_BIN" exec "$PWD/build/hyprnova-kernel-drill"
    ' || FAILURES=$((FAILURES+1))
  else
    echo "   NOT RUN: nft kernel drill (nft binary absent;"
    echo "            recipe in tools/kernel_drill.cpp header)"
  fi
else
  echo "   NOT RUN: user namespaces unavailable; fanotify/auditd/cgroup/nft"
  echo "            drills need root + a VM (see VM-BRINGUP.md)"
fi
[ -w /sys/fs/cgroup/cgroup.controllers ] 2>/dev/null ||
  echo "   NOT RUN: per-exe cgroup migration (cgroup2 userns-mount denied here)"

echo "== [6/6] QML loader check =="
if python3 -c "import PySide6" 2>/dev/null && [ -d /tmp/xkblib/usr/lib/x86_64-linux-gnu ]; then
  LD_LIBRARY_PATH=/tmp/xkblib/usr/lib/x86_64-linux-gnu \
    python3 scripts/qml_load_check.py 2>&1 | grep -E "^---" || FAILURES=$((FAILURES+1))
else
  echo "   NOT RUN (PySide6 + /tmp/xkblib prerequisites missing)"
fi

echo
[ "$FAILURES" -eq 0 ] && echo "== ALL RUN SECTIONS PASSED ==" || echo "== $FAILURES section(s) FAILED =="
exit "$FAILURES"
