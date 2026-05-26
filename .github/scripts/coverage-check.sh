#!/usr/bin/env bash
# Per-crate coverage floor enforcement.
# Usage: scripts/coverage-check.sh <crate> <floor-percent>
# Exits non-zero if `cargo llvm-cov` line coverage for the crate is below the floor.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <crate> <floor>" >&2
  exit 2
fi

crate="$1"
floor="$2"

# llvm-cov writes the summary table; we want the TOTAL row's "Lines" cover %.
# Output format (column "Cover" for Lines is the second-to-last %).
# Capture exit code separately so cargo panics (exit 101) surface their output
# instead of vanishing into $out.
set +e
out=$(cargo llvm-cov -p "$crate" --summary-only --ignore-filename-regex 'vendor/' 2>&1)
rc=$?
set -e

if [[ $rc -ne 0 ]]; then
  echo "::error::cargo llvm-cov exited $rc for crate $crate" >&2
  printf '%s\n' "$out" >&2
  exit "$rc"
fi

# The TOTAL line looks like:
#  TOTAL  N  N  XX.XX%  N  N  YY.YY%  N  N  ZZ.ZZ%  N  N  WW.WW%
# Region% Function% Line% Branch%
# We want Line% (the third percentage).
actual=$(printf '%s\n' "$out" | awk '
  /^TOTAL/ {
    gsub("%","")
    # Print the line coverage column. Row layout:
    # TOTAL <regions> <missed> <region%> <funcs> <missed> <func%> <lines> <missed> <line%> <branches> <missed> <branch%>
    print $10
  }
')

if [[ -z "$actual" ]]; then
  echo "::error::Failed to parse coverage for crate $crate" >&2
  printf '%s\n' "$out" | tail -20 >&2
  exit 1
fi

if awk -v a="$actual" -v f="$floor" 'BEGIN { exit !(a+0 >= f+0) }'; then
  printf 'OK: %s line coverage %s%% >= floor %s%%\n' "$crate" "$actual" "$floor"
else
  printf '::error::%s line coverage %s%% < floor %s%%\n' "$crate" "$actual" "$floor" >&2
  exit 1
fi
