#!/usr/bin/env bash
# usage: run.sh OUTDIR [TARGETS]   scan every .deb in TARGETS (default OUTDIR/targets.txt)
# Resumable: re-running skips anything with a marker in OUTDIR/done.
set -eu
. "$(dirname "$0")/env.sh"
out=$1 targets=${2:-$1/targets.txt}
[ -x "${SCAN%% *}" ] || { echo "build the scanner first: cargo build --release" >&2; exit 1; }
mkdir -p "$out"/{res,err,done}
total=$(wc -l < "$targets")
echo "$total targets, $(ls "$out/done" | wc -l) already done, ${JOBS:-$(nproc)} jobs"
xargs -P "${JOBS:-$(nproc)}" -n1 "$(dirname "$0")/scan-deb.sh" "$out" < "$targets"
echo "done=$(ls "$out/done" | wc -l) failed=$( [ -f "$out/failed" ] && sort -u "$out/failed" | wc -l || echo 0 )"
