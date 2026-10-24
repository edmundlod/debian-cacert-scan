#!/usr/bin/env bash
# usage: run.sh OUTDIR [TARGETS]   scan every .deb in TARGETS (default OUTDIR/targets.txt)
# Resumable: re-running skips anything with a marker in OUTDIR/done.
# Prints progress every PROGRESS_INTERVAL seconds (default 10, 0 to silence).
set -eu
. "$(dirname "$0")/env.sh"
out=$1 targets=${2:-$1/targets.txt}
[ -x "${SCAN%% *}" ] || { echo "build the scanner first: cargo build --release" >&2; exit 1; }
mkdir -p "$out"/{res,err,done}

# readdir only, no stat and no sort: cheap enough to call on a 70k-entry directory
count() { find "$out/done" -type f -printf . 2>/dev/null | wc -c; }

total=$(wc -l < "$targets")
start=$(count)
jobs=${JOBS:-$(nproc)}
echo "$total targets, $start already done, $jobs jobs"

# -size +0: scan-deb.sh writes res/KEY.jsonl then deletes it when the deb had
# nothing, so counting every file would include ones about to go away
hitcount() { find "$out/res" -type f -size +0 -printf . 2>/dev/null | wc -c; }

hms() { # seconds -> 2h31m / 31m12s / 12s
  local s=$1
  if [ "$s" -ge 3600 ]; then printf '%dh%02dm' $((s / 3600)) $((s % 3600 / 60))
  elif [ "$s" -ge 60 ]; then printf '%dm%02ds' $((s / 60)) $((s % 60))
  else printf '%ds' "$s"; fi
}

tick() {
  local t0=$SECONDS n el done_now eta
  while sleep "${PROGRESS_INTERVAL:-10}"; do
    n=$(count)
    el=$((SECONDS - t0))
    done_now=$((n - start))
    [ "$el" -gt 0 ] && [ "$done_now" -gt 0 ] || continue
    eta=$(hms $(((total - n) * el / done_now)))
    if [ -t 2 ]; then
      printf '\033[2K\r%d/%d (%d%%)  %d/min  %d hits  eta %s' \
        "$n" "$total" $((n * 100 / total)) $((done_now * 60 / el)) "$(hitcount)" "$eta" >&2
    else
      printf '%d/%d (%d%%)  %d/min  %d hits  eta %s\n' \
        "$n" "$total" $((n * 100 / total)) $((done_now * 60 / el)) "$(hitcount)" "$eta" >&2
    fi
  done
}

if [ "${PROGRESS_INTERVAL:-10}" != 0 ]; then
  tick & tickpid=$!
  # Ctrl-C kills xargs too; the trap stops the ticker and lets the summary print
  trap 'kill $tickpid 2>/dev/null; [ -t 2 ] && printf "\033[2K\r" >&2; :' EXIT INT TERM
fi

xargs -P "$jobs" -n1 "$(dirname "$0")/scan-deb.sh" "$out" < "$targets" || true
echo "done=$(count) failed=$([ -f "$out/failed" ] && sort -u "$out/failed" | wc -l || echo 0)"
