"""usage: mkindex.py OUTDIR — turn OUTDIR/idx/*__Packages.xz into OUTDIR/index.tsv.

One row per binary package: the .deb basename is the join key used by every later
stage, because cacert-scan labels each finding with it (--tar LABEL).

A package indexed from more than one suite (trixie and trixie-security) appears
once, at its newest version, so a scan describes what an updated machine runs
rather than what the release first shipped.
"""
import glob, lzma, os, sys, csv

try:
    import apt_pkg
    apt_pkg.init_system()
    def newer(a, b):
        return apt_pkg.version_compare(a, b) > 0
except ImportError:                                  # no python3-apt: ask dpkg
    import subprocess
    def newer(a, b):
        return subprocess.run(["dpkg", "--compare-versions", a, "gt", b],
                              check=False).returncode == 0

out = sys.argv[1]
best = {}
counts = {}

for path in sorted(glob.glob(f"{out}/idx/*__Packages.xz")):
    suite, component, _ = os.path.basename(path).split("__")
    with lzma.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        stanza = {}
        for line in fh:
            if line != "\n":
                if line[0] in " \t":                 # continuation of a folded field
                    continue
                k, _, v = line.partition(":")
                stanza[k] = v.strip()
                continue
            if stanza.get("Filename"):
                name = stanza["Package"]
                prev = best.get(name)
                if prev is None or newer(stanza.get("Version", ""), prev[2].get("Version", "")):
                    best[name] = (suite, component, stanza)
                counts[suite] = counts.get(suite, 0) + 1
            stanza = {}

with open(f"{out}/index.tsv", "w", newline="") as fh:
    w = csv.writer(fh, delimiter="\t")
    w.writerow(["deb", "filename", "package", "version", "arch", "source",
                "component", "suite", "sha256", "size"])
    for name, (suite, component, s) in sorted(best.items()):
        src = (s.get("Source") or name).split(" ")[0]
        w.writerow([s["Filename"].rsplit("/", 1)[-1], s["Filename"], name,
                    s.get("Version", ""), s.get("Architecture", ""), src,
                    component, suite, s.get("SHA256", ""), s.get("Size", "0")])

for suite, n in sorted(counts.items()):
    print(f"{suite:20s} {n} stanzas")
print(f"{len(best)} binary packages indexed, newest version of each")
