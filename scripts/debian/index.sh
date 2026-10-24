#!/usr/bin/env bash
# usage: index.sh OUTDIR   fetch the suite indices and build OUTDIR/index.tsv
# env: SUITE ARCH COMPONENTS MIRROR SECURITY_MIRROR OVERLAYS (see env.sh)
set -eu
. "$(dirname "$0")/env.sh"
out=$1
mkdir -p "$out/idx"

get() { # get URL DEST  -- returns 1 on 404 so an unpublished component is skipped
  curl -4 -sfL --retry 5 --retry-all-errors -o "$2" "$1"
}

fetch_suite() { # fetch_suite SUITE MIRROR
  local suite=$1 mirror=$2 c f d
  for c in $COMPONENTS; do
    for f in "binary-$ARCH/Packages.xz" "source/Sources.xz" "Contents-$ARCH.gz" "Contents-all.gz"; do
      d="$out/idx/${suite}__${c}__${f##*/}"
      [ -s "$d" ] && continue
      if get "$mirror/dists/$suite/$c/$f" "$d.part"; then
        mv "$d.part" "$d"
        echo "got $suite/$c/${f##*/}"
      else
        rm -f "$d.part"
        echo "skip $suite/$c/${f##*/} (not published)" >&2
      fi
    done
  done
}

fetch_suite "$SUITE" "$MIRROR"
for o in ${OVERLAYS-}; do
  case $o in
    *-security) fetch_suite "$o" "$SECURITY_MIRROR" ;;
    *) fetch_suite "$o" "$MIRROR" ;;
  esac
done

python3 "$(dirname "$0")/mkindex.py" "$out"
