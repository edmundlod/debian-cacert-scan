#!/usr/bin/env bash
# usage: status.sh OUTDIR [TARGETS]   how far a scan got, running or stopped
# Safe to run from another shell while run.sh works, and after you abort it.
set -eu
out=$1 targets=${2:-$1/targets.txt}
python3 - "$out" "$targets" <<'EOF'
import csv, os, sys
out, targets = sys.argv[1], sys.argv[2]

done = set(os.listdir(f"{out}/done")) if os.path.isdir(f"{out}/done") else set()
# an aborted job leaves an empty res file behind, so only non-empty ones are hits
hits = sum(1 for e in os.scandir(f"{out}/res") if e.is_file() and e.stat().st_size) \
    if os.path.isdir(f"{out}/res") else 0
failed = len(set(open(f"{out}/failed").read().split())) if os.path.exists(f"{out}/failed") else 0

size = {}
if os.path.exists(f"{out}/index.tsv"):
    size = {r["filename"]: int(r["size"]) for r in csv.DictReader(open(f"{out}/index.tsv"), delimiter="\t")}

n = nd = 0
tot = bdone = 0
for fn in open(targets).read().split():
    n += 1
    s = size.get(fn, 0)
    tot += s
    if fn.rsplit("/", 1)[-1][:-4] in done:
        nd += 1
        bdone += s

def human(b):
    return f"{b / 2**30:.1f} GiB" if b >= 2**30 else f"{b / 2**20:.0f} MiB"

pct = 100 * nd / n if n else 0
print(f"{nd}/{n} debs ({pct:.1f}%)   {human(bdone)} of {human(tot)} streamed")
print(f"{hits} debs with findings, {failed} failed")
if nd < n:
    print(f"{n - nd} left; resume with: scripts/debian/run.sh {out} {targets}")

# markers in done/ that this target list does not cover, e.g. an earlier narrower pass
extra = len(done) - nd
if extra > 0:
    print(f"({extra} done markers are from a different target list)")
EOF
