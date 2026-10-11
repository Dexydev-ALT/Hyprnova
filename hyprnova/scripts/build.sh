#!/usr/bin/env bash
# HyprNova :: incremental build harness used during development.
# Filters the known GCC 14 false positives that fire inside libstdc++ headers for
# the recursive json::Value variant (stl_tree.h _M_move_data / _Rb_tree move ctor
# reporting "-Wmaybe-uninitialized" on std::map members of a std::variant).
set -uo pipefail
cd "$(dirname "$0")/.."

CXX=${CXX:-g++}
STD=${STD:--std=c++20}
OPT=${OPT:--O2}
WARN="-Wall -Wextra -Wshadow -Wold-style-cast -Wnon-virtual-dtor -Woverloaded-virtual \
-Wcast-align -Wunused -Wconversion -Wsign-conversion -Wnull-dereference \
-Wdouble-promotion -Wimplicit-fallthrough -Wformat=2"
DEFS="${DEFS:-}"
OUT=${OUT:-/tmp/hyprnova-obj}
mkdir -p "$OUT"

fail=0
built=0
for f in "$@"; do
  o="$OUT/$(echo "${f%.cpp}" | tr '/' '_').o"
  if [ -f "$o" ] && [ "$o" -nt "$f" ]; then continue; fi
  log=$("$CXX" $STD $OPT $WARN $DEFS -I. -c "$f" -o "$o" 2>&1)
  # Keep only diagnostics from OUR files, or any error.
  interesting=$(printf '%s\n' "$log" | grep -E "(error:|^[a-z].*\.(hpp|cpp):[0-9]+:[0-9]+: warning)" | \
                grep -vE "/usr/include/c\+\+/")
  if printf '%s\n' "$log" | grep -q "error:"; then
    echo "FAIL $f"
    printf '%s\n' "$log" | grep -E "error:" | head -12
    fail=1
  elif [ -n "$interesting" ]; then
    echo "WARN $f"
    printf '%s\n' "$interesting" | head -12
    built=$((built+1))
  else
    built=$((built+1))
  fi
done
echo "built=$built fail=$fail"
exit $fail
