#!/usr/bin/env bash
# usage: scan-local.sh [PATH...]   scan installed files (default /usr) and name the package
# Stage 1: same detection as the archive pass, but on this machine, in seconds.
set -eu
. "$(dirname "$0")/env.sh"
$SCAN --path "${@:-/usr}" \
| jq -r 'select((.known_roots | length) >= 20)
         | [ .file, (.known_roots | length),
             ([ (if (.watch | index("emSign ECC Root CA - G3")) then "ECC G3" else empty end),
                (if (.watch | index("AAA Certificate Services")) then "AAA" else empty end) ] | join(",")) ]
         | @tsv' \
| while IFS=$'\t' read -r file n watch; do
    real=${file%%!*}                      # strip "!member" for a hit inside an archive
    pkg=$(dpkg -S "$real" 2>/dev/null | head -1 | cut -d: -f1)
    printf '%s\t%s\t%s roots\t%s\n' "${pkg:-<unpackaged>}" "$file" "$n" "${watch:--}"
  done \
| sort -u
