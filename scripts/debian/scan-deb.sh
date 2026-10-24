#!/usr/bin/env bash
# usage: scan-deb.sh OUTDIR POOL_PATH   scan one .deb straight from the mirror
# Nothing is written to disk: curl | dpkg-deb --fsys-tarfile | cacert-scan --tar.
# env: SCAN, MIRROR (see env.sh)
set -o pipefail
out=$1 fn=$2
deb=${fn##*/} key=${deb%.deb}
[ -e "$out/done/$key" ] && exit 0
if curl -4 -sf --retry 5 --retry-all-errors "$MIRROR/$fn" \
    | dpkg-deb --fsys-tarfile /dev/stdin \
    | $SCAN --tar "$deb" > "$out/res/$key.jsonl" 2> "$out/err/$key"; then
  touch "$out/done/$key"
  [ -s "$out/err/$key" ] || rm -f "$out/err/$key"
  [ -s "$out/res/$key.jsonl" ] || rm -f "$out/res/$key.jsonl"   # most debs have nothing
else
  echo "$fn" >> "$out/failed"
  rm -f "$out/res/$key.jsonl"
fi
exit 0
