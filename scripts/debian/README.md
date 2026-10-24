# Debian archive pass

Same scanner, Debian corpus. `nix-cacert-scan`'s detection (`../../DETECTION.md`) does
not care where the bytes come from; only the corpus driver was Nix-specific. These
scripts replace it:

| nixpkgs | here |
|---|---|
| `store-paths.xz` from the channel | `Packages.xz` per suite/component → `index.tsv` |
| `narinfo` + NAR from `cache.nixos.org` | `.deb` from a mirror → `dpkg-deb --fsys-tarfile` |
| `cacert-scan --nar LABEL` | `cacert-scan --tar LABEL` (`0001-tar-stdin-mode.patch`) |
| per store path | per `.deb`, rolled up to the **source** package |

Nothing is written to disk: each `.deb` is streamed, scanned and dropped.

## Build

Trixie's rustc is 1.85.1, so three crates in the shipped `Cargo.lock` need pinning
down (`time`, `time-core`/`time-macros`, `zopfli` want 1.88):

    cargo update time --precise 0.3.41
    cargo update time-core --precise 0.1.4
    cargo update time-macros --precise 0.2.22
    cargo update zopfli --precise 0.8.1
    cargo build --release        # needs libssl-dev, pkg-config

## 1. This machine

    scripts/debian/scan-local.sh /usr

One line per installed trust store: package, path, root count, and whether it holds
`emSign ECC Root CA - G3` or `AAA Certificate Services`. ~1 minute per 5 GB per core.

## 2. Targeted archive pass (3,121 packages, 5.3 GiB)

    scripts/debian/index.sh out                        # indices -> out/index.tsv
    python3 scripts/debian/mkcandidates.py out targeted
    JOBS=3 scripts/debian/run.sh out
    python3 scripts/debian/analyze.py out out/report

`targeted` is the union of two filters: packages shipping a file whose *name* looks
like a trust store (from `Contents-*`), and packages built by Go, Rust or Node (from
`Sources` `Build-Depends`), which is where compiled-in roots live. It is a shortlist,
not an answer — a C program with a root array in a `.c` file is invisible to both.

## 3. Whole archive (69,913 packages, 120.2 GiB — trixie amd64, all four components)

    python3 scripts/debian/mkcandidates.py out all
    JOBS=3 scripts/debian/run.sh out

Resumable: `run.sh` skips anything with a marker in `out/done`, so interrupt it
freely. Scanning runs at roughly 90 MB/s per core on decompressed bytes, so the
wall time is set by the download link, not the CPU. Set `MIRROR` to a plain mirror —
pointing this at apt-cacher-ng would cache all 120 GiB.

`arch:all` packages are in the `binary-amd64` index, so one architecture covers them.
Add `ARCH=` passes only if you care about per-architecture binaries.

### Memory

The scanner reads a file whole into memory up to 1 GiB, so `JOBS` parallel scanners
can ask for `JOBS` GiB. On a 2 GB box with no swap the OOM killer takes one out, and
`run.sh` records that deb in `out/failed` — the pipeline fails, so nothing silently
goes missing, but those debs do need a second pass. Cap the buffer instead:

    CACERT_SCAN_MAX_MB=128 JOBS=4 scripts/debian/run.sh out

Budget `JOBS × CACERT_SCAN_MAX_MB` plus a few hundred MB. The cap costs nothing for
plain files — a 55 MB `libnode.so` yields the same 142 roots at 1 MB as at 1 GiB, via
the chunked path — but an archive *larger* than the cap is not unpacked, so a huge jar
or wheel would be skipped. Re-run those few at a higher cap with `JOBS=1`:

    sort -u out/failed > out/retry.txt && : > out/failed
    JOBS=1 scripts/debian/run.sh out out/retry.txt

## Output

`out/report/`:

- `findings.tsv` — one row per file: class, source, binary package, version, path,
  root count, `ecc_g3`, `aaa_anchor`, the compromised intermediates seen, sha256.
- `packages.tsv` — one row per source package.
- `list.md` — the markdown checklist, grouped by fix class.
- `summary.txt` — counts per class.

Classes needing a fix: `vendored-pem-file`, `vendored-in-archive`, `vendored-keystore`,
`compiled-in`, `vendored-other`. Classed apart and kept out of `list.md`:
`system-store` (ca-certificates itself), `copy-of-system-store` (byte-identical),
`test-data` (`t/`, `testdata/`, `_test.go` — the archive is full of these),
`source-shipment` (`/usr/share/gocode/src`, `/usr/src` — source for others to build
against, where per-OS variants Debian never compiles live), `docs-or-examples`, and
the sub-threshold `partial-root-set` / `fixture-or-other`.

A hit means the bundle is *in* the package, not that the program uses it. Debian's
`nodejs` configures `--openssl-use-def-ca-store` (`debian/rules`), so the 142 roots
in `libnode.so` are reachable only via `--use-bundled-ca`. Check each package's
build before calling a hit a vulnerability. Same caveat as upstream's README.
