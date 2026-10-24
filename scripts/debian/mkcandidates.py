"""usage: mkcandidates.py OUTDIR MODE — write OUTDIR/targets.txt (pool paths to scan).

MODE:
  contents   packages shipping a file whose *name* looks like a trust store.
             Cheap, but blind to roots compiled into a binary.
  build      packages from source packages built with Go, Rust or Node, where
             compiled-in roots actually come from (webpki-roots, Go x509, node).
             Drops -dev/-doc/-source, which ship source, not binaries.
  targeted   union of the two. The default first pass.
  all        every .deb in the suite. The honest answer; ~111 GiB for trixie
             main amd64, so run it once the earlier passes look right.
"""
import csv, glob, gzip, lzma, re, sys

out, mode = sys.argv[1], sys.argv[2]

index = list(csv.DictReader(open(f"{out}/index.tsv"), delimiter="\t"))
by_pkg, by_src = {}, {}
for r in index:
    by_pkg[r["package"]] = r
    by_src.setdefault(r["source"], []).append(r)

# filenames that are trust stores, or hold one
STORE_NAME = re.compile(
    r"(cacert|ca-bundle|ca-certificates\.crt|/cacerts$|roots?\.pem|certdata\.txt"
    r"|rootcert|truststore|\.jks$|\.p12$|\.pfx$|cert9\.db$|cert8\.db$)", re.I)
# build systems whose output can carry its own root list
VENDORING_BUILD = re.compile(r"\b(golang-any|golang-go|dh-golang|dh-cargo|cargo|rustc|nodejs|npm|yarnpkg)\b")
NOT_A_BINARY = re.compile(r"-(dev|doc|source|dbgsym|common|data)$")

want = {}

if mode in ("contents", "targeted"):
    for path in glob.glob(f"{out}/idx/*Contents-*.gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()            # "path  section/pkg,section/pkg"; path may hold spaces
                if len(parts) < 2 or not STORE_NAME.search(" ".join(parts[:-1])):
                    continue
                for p in parts[-1].split(","):
                    r = by_pkg.get(p.rsplit("/", 1)[-1])
                    if r:
                        want[r["deb"]] = r

if mode in ("build", "targeted"):
    for path in glob.glob(f"{out}/idx/*Sources.xz"):
        with lzma.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            src, bd = None, ""
            for line in fh:
                if line == "\n":
                    if src and VENDORING_BUILD.search(bd):
                        for r in by_src.get(src, []):
                            if not NOT_A_BINARY.search(r["package"]):
                                want[r["deb"]] = r
                    src, bd = None, ""
                elif line.startswith("Package: "):
                    src = line[9:].strip()
                elif line.startswith(("Build-Depends:", "Build-Depends-Arch:", "Build-Depends-Indep:")):
                    bd += line
                elif line[:1] in (" ", "\t"):
                    bd += line                      # folded continuation of the last field

if mode == "all":
    want = {r["deb"]: r for r in index}

with open(f"{out}/targets.txt", "w") as fh:
    for r in sorted(want.values(), key=lambda r: r["filename"]):
        print(r["filename"], file=fh)

size = sum(int(r["size"]) for r in want.values())
print(f"{len(want)} packages, {size / 2**30:.1f} GiB to stream -> {out}/targets.txt")
