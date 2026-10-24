#!/usr/bin/env bash
# usage: index.sh OUTDIR   fetch the suite indices and build OUTDIR/index.tsv
# env: SUITE ARCH COMPONENTS MIRROR (see env.sh)
set -eu
. "$(dirname "$0")/env.sh"
out=$1
mkdir -p "$out/idx"

get() { # get URL DEST  -- returns 1 on 404 so optional components can be skipped
  curl -4 -sfL --retry 5 --retry-all-errors -o "$2" "$1"
}

for c in $COMPONENTS; do
  for f in "$c/binary-$ARCH/Packages.xz" "$c/source/Sources.xz" "$c/Contents-$ARCH.gz" "$c/Contents-all.gz"; do
    d="$out/idx/$(echo "$c-${f##*/}" | tr / -)"
    [ -s "$d" ] && continue
    if get "$MIRROR/dists/$SUITE/$f" "$d.part"; then
      mv "$d.part" "$d"
      echo "got $SUITE/$f"
    else
      rm -f "$d.part"
      echo "skip $SUITE/$f (not published)" >&2
    fi
  done
done

python3 "$(dirname "$0")/mkindex.py" "$out"
wc -l < "$out/index.tsv" | xargs printf '%s binary packages indexed\n'
