"""usage: mkindex.py OUTDIR — turn OUTDIR/idx/*Packages.xz into OUTDIR/index.tsv.

One row per binary package: the .deb basename is the join key used by every later
stage, because cacert-scan labels each finding with it (--tar LABEL).
"""
import glob, lzma, os, sys, csv

out = sys.argv[1]
rows = []

for path in sorted(glob.glob(f"{out}/idx/*Packages.xz")):
    component = os.path.basename(path).split("-binary")[0]
    with lzma.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        stanza = {}
        for line in fh:
            if line == "\n":
                if stanza:
                    rows.append((component, stanza))
                stanza = {}
                continue
            if line[0] in " \t":          # continuation of a folded field
                continue
            k, _, v = line.partition(":")
            stanza[k] = v.strip()
        if stanza:
            rows.append((component, stanza))

with open(f"{out}/index.tsv", "w", newline="") as fh:
    w = csv.writer(fh, delimiter="\t")
    w.writerow(["deb", "filename", "package", "version", "arch", "source", "component", "sha256", "size"])
    seen = set()
    for component, s in rows:
        fn = s.get("Filename")
        if not fn:
            continue
        deb = fn.rsplit("/", 1)[-1]
        if deb in seen:                   # same name+version+arch is the same file
            continue
        seen.add(deb)
        src = (s.get("Source") or s["Package"]).split(" ")[0]
        w.writerow([deb, fn, s["Package"], s.get("Version", ""), s.get("Architecture", ""),
                    src, component, s.get("SHA256", ""), s.get("Size", "0")])
