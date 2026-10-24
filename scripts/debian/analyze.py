"""usage: analyze.py OUTDIR REPORTDIR — aggregate cacert-scan findings into Debian source packages.

Reads OUTDIR/res/*.jsonl (one JSON object per file of interest, labelled with the
.deb basename) and OUTDIR/index.tsv, and writes findings.tsv, packages.tsv,
summary.txt and list.md.

Classification follows scripts/analyze.py, with three Debian differences:
  - findings are rolled up per *source* package, since that is what gets an upload;
  - a file byte-identical to one ca-certificates itself ships is a copy, not a
    vendored store (Debian has no inject-at-build step to credit it to);
  - the archive carries a lot of source and test data (golang-*-dev, t/, testdata/),
    so those paths are classed apart and kept out of list.md.
"""
import json, os, re, sys, csv, collections

out, rep = sys.argv[1], sys.argv[2]
os.makedirs(rep, exist_ok=True)

TRUST_STORE_MIN = 20
EMSIGN_PATH_ROOT = "emSign ECC Root CA - G3"
AAA = "AAA Certificate Services"
SYSTEM_STORE_PKGS = ("ca-certificates", "ca-certificates-java", "ca-certificates-mono")
TEST_PATH = re.compile(r"(^|/)(t|test|tests|testdata|fixtures?|examples?)/|_test\.go$|\.t$")
DOC_PATH = re.compile(r"^/usr/share/(doc|man|info)/")
# source shipped for other packages to build against, not to run here: a
# golang-*-dev package ships upstream's whole tree under /usr/share/gocode/src,
# including per-OS variants (root_darwin_armx.go) never compiled on Debian
SOURCE_PATH = re.compile(r"^/usr/(share/gocode/src|src)/")

index = {r["deb"]: r for r in csv.DictReader(open(f"{out}/index.tsv"), delimiter="\t")}

# Only results from a deb that finished count: an aborted job can leave an empty
# or half-written res file, which the next run.sh overwrites when it redoes the deb.
complete = set(os.listdir(f"{out}/done")) if os.path.isdir(f"{out}/done") else set()
findings, partial = [], 0
for fn in os.listdir(f"{out}/res"):
    if complete and fn[:-6] not in complete:
        partial += 1
        continue
    with open(f"{out}/res/{fn}") as fh:
        for line in fh:
            try:
                f = json.loads(line)
            except json.JSONDecodeError:
                partial += 1
                continue
            f["deb"] = index.get(f["nar"], {})
            findings.append(f)
if partial:
    print(f"skipped {partial} incomplete result file(s)/line(s) — re-run run.sh to redo those debs",
          file=sys.stderr)

def pkg(f):
    return f["deb"].get("package") or f["nar"]

def src(f):
    return f["deb"].get("source") or f["nar"].split("_")[0]

system_hashes = {f["sha256"] for f in findings
                 if pkg(f) in SYSTEM_STORE_PKGS and f.get("sha256")
                 and len(f["known_roots"]) >= TRUST_STORE_MIN}

def classify(f):
    roots = len(f["known_roots"])
    archive = "!" in f["file"]
    elf = f.get("magic") == "elf"
    fmts = set(f["formats"])
    if pkg(f) in SYSTEM_STORE_PKGS:
        return "system-store"
    if f.get("sha256") in system_hashes:
        return "copy-of-system-store"
    if roots >= TRUST_STORE_MIN:
        if DOC_PATH.search(f["file"].split("!")[0]):
            return "docs-or-examples"
        if TEST_PATH.search(f["file"]):
            return "test-data"
        if SOURCE_PATH.search(f["file"].split("!")[0]):
            return "source-shipment"
        if archive:
            return "vendored-in-archive"
        if f.get("magic") in ("jks", "jceks", "pkcs12"):
            return "vendored-keystore"
        if elf or f.get("magic") in (None, "sqlite") and "der" in fmts and "pem" not in fmts:
            return "compiled-in"
        if "pem" in fmts and f["pem_certs"] >= TRUST_STORE_MIN and not elf:
            return "vendored-pem-file"
        return "compiled-in" if "der" in fmts else "vendored-other"
    if roots >= 3:
        return "partial-root-set"
    if any(w.startswith("EM ") for w in f["spki_hash"]):
        return "has-emudhra-spki-blocklist"
    if f.get("magic") in ("jks", "jceks", "pkcs12") and not re.search(r"META-INF/[^/]*\.(RSA|DSA|EC)$", f["file"]):
        return "keystore-locked" if "password not in list" in (f.get("note") or "") else "keystore-no-known-roots"
    return "fixture-or-other"

FIX = {
    "vendored-pem-file": ("Vendored PEM bundle",
        "Replace the file with a symlink to `/etc/ssl/certs/ca-certificates.crt` and depend on "
        "`ca-certificates`, or point the program at it (`SSL_CERT_FILE`, `--cafile`, `--with-ca-bundle`). "
        "Strip the bundle from the orig tarball (`+ds`) where policy §4.13 applies, as python3-certifi does."),
    "vendored-in-archive": ("Bundle inside a wheel, jar or zip",
        "Patch the bundle inside the archive at build time, or patch the code to use the system store."),
    "vendored-keystore": ("Java keystore",
        "Generate the keystore from `/etc/ssl/certs/ca-certificates.crt` at build time, as "
        "`ca-certificates-java` does, instead of shipping a frozen one."),
    "compiled-in": ("Compiled into a binary",
        "No file to replace: rebuild against the system store — `rustls-native-certs` or `openssl-probe` "
        "instead of `webpki-roots`, Go's `x509.SystemCertPool`, `--use-system-ca` — or, failing that, bump "
        "the embedded root crate and rebuild."),
    "vendored-other": ("Trust store, form unclear", "Inspect."),
}

rows = []
for f in findings:
    f["class"] = classify(f)
    rows.append(f)

with open(f"{rep}/findings.tsv", "w", newline="") as fh:
    w = csv.writer(fh, delimiter="\t")
    w.writerow(["class", "source", "package", "version", "path", "magic", "formats", "pem_certs",
                "known_roots", "ecc_g3", "aaa_anchor", "emudhra_roots", "compromised_ca", "spki_hash", "sha256"])
    for f in sorted(rows, key=lambda f: (f["class"], src(f), f["file"])):
        w.writerow([f["class"], src(f), pkg(f), f["deb"].get("version", ""), f["file"],
                    f.get("magic") or "", ",".join(f["formats"]), f["pem_certs"], len(f["known_roots"]),
                    int(EMSIGN_PATH_ROOT in f["watch"]), int(AAA in f["watch"]),
                    ",".join(w for w in f["watch"] if w.startswith("emSign")),
                    ",".join(w for w in f["watch"] if w.startswith("EM ")),
                    ",".join(f["spki_hash"]), f.get("sha256") or ""])

pkgs = collections.defaultdict(lambda: {"classes": collections.Counter(), "files": [], "bins": set(),
                                        "ecc_g3": False, "aaa": False})
for f in rows:
    if f["class"] not in FIX:
        continue
    p = pkgs[src(f)]
    p["classes"][f["class"]] += 1
    p["files"].append(f["file"])
    p["bins"].add(pkg(f))
    p["ecc_g3"] |= EMSIGN_PATH_ROOT in f["watch"]
    p["aaa"] |= AAA in f["watch"]

with open(f"{rep}/packages.tsv", "w", newline="") as fh:
    w = csv.writer(fh, delimiter="\t")
    w.writerow(["source", "binary_packages", "classes", "ecc_g3", "aaa_anchor", "n_files", "example_files"])
    for name, p in sorted(pkgs.items()):
        w.writerow([name, " ".join(sorted(p["bins"])), ",".join(f"{k}:{v}" for k, v in p["classes"].most_common()),
                    int(p["ecc_g3"]), int(p["aaa"]), len(p["files"]), " ".join(sorted(p["files"])[:3])])

with open(f"{rep}/list.md", "w") as fh:
    print(f"Source packages carrying their own CA trust store ({len(pkgs)}).\n", file=fh)
    for c, (title, fix) in FIX.items():
        sel = sorted((n, p) for n, p in pkgs.items() if p["classes"].get(c))
        print(f"### {title} ({len(sel)})\n\nFix: {fix}\n", file=fh)
        for n, p in sel:
            files = sorted({f for f in p["files"]}, key=lambda f: (len(f), f))
            more = f" (+{len(files) - 1} more)" if len(files) > 1 else ""
            stale = " · has ECC G3" if p["ecc_g3"] else " · stale bundle, no ECC G3"
            aaa = " · trusts AAA" if p["aaa"] else ""
            print(f"- [ ] **{n}** — `{files[0]}`{more}{stale}{aaa}", file=fh)
        print(file=fh)

done = len(os.listdir(f"{out}/done")) if os.path.isdir(f"{out}/done") else 0
failed = len(set(open(f"{out}/failed").read().split())) if os.path.exists(f"{out}/failed") else 0
cls = collections.Counter(f["class"] for f in rows)
by_class = collections.defaultdict(set)
for f in rows:
    by_class[f["class"]].add(src(f))
with open(f"{rep}/summary.txt", "w") as fh:
    print(f"debs scanned: {done}  failed: {failed}  findings: {len(rows)}", file=fh)
    print(f"source packages to fix: {len(pkgs)}", file=fh)
    print(f"system-store hashes used to spot plain copies: {len(system_hashes)}", file=fh)
    for c, n in cls.most_common():
        print(f"{c:28s} files={n:6d} source-packages={len(by_class[c]):5d}", file=fh)
    for c in FIX:
        print(f"\n== {c}\n   " + " ".join(sorted(by_class.get(c, ()))), file=fh)
print(open(f"{rep}/summary.txt").read())
