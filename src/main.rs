use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::Path;

const MAX_IN_MEMORY: u64 = 1 << 30;
const CHUNK: usize = 256 << 20;
const OVERLAP: usize = 64 << 10;
const TRUST_STORE_HINT: usize = 3;
const MAX_DEPTH: usize = 4;
const MAX_UNPACKED: u64 = 1 << 30;
const MIN_BARE_B64: usize = 600;
// common store passwords seen in Java truststores; "" covers password-less PKCS12
const P12_PASSWORDS: &[&str] = &["changeit", "", "changeme", "password", "secret", "123456", "truststore", "keystore", "notasecret"];

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Root,
    Watch,
    WatchSpki,
    BlockHash,
}

struct Pat {
    kind: Kind,
    name: String,
}

struct Matcher {
    ac: AhoCorasick,
    pats: Vec<Vec<Pat>>,
}

#[derive(Default, Serialize)]
struct Finding {
    nar: String,
    file: String,
    size: u64,
    magic: Option<&'static str>,
    formats: BTreeSet<&'static str>,
    pem_certs: usize,
    known_roots: BTreeSet<String>,
    watch: BTreeSet<String>,
    watch_spki: BTreeSet<String>,
    spki_hash: BTreeSet<String>,
    sha256: Option<String>,
    note: Option<String>,
}

impl Finding {
    fn interesting(&self) -> bool {
        self.known_roots.len() >= 3
            || self.pem_certs >= 2
            || !self.watch.is_empty()
            || !self.watch_spki.is_empty()
            || !self.spki_hash.is_empty()
            || matches!(self.magic, Some("jks" | "jceks" | "pkcs12"))
    }
}

fn der_inner(der: &[u8]) -> &[u8] {
    // webpki-style anchors store Name/SPKI contents without the outer SEQUENCE header,
    // so match on the contents: it is a substring of the full DER as well.
    if der.len() < 2 {
        return der;
    }
    let l = der[1];
    let hdr = if l & 0x80 == 0 { 2 } else { 2 + (l & 0x7f) as usize };
    der.get(hdr..).unwrap_or(der)
}

fn cn_of(c: &x509_parser::certificate::X509Certificate) -> String {
    c.subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| c.subject().to_string())
}

fn pem_ders(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (_, block) in pem_blocks(data) {
        if let Some(d) = block {
            out.push(d);
        }
    }
    out
}

fn build_matcher(roots: &[u8], watch: &[u8]) -> Matcher {
    let mut map: HashMap<Vec<u8>, Vec<Pat>> = HashMap::new();
    let mut add = |k: Vec<u8>, kind, name: String| {
        let v = map.entry(k).or_default();
        if !v.iter().any(|p| p.kind == kind && p.name == name) {
            v.push(Pat { kind, name });
        }
    };
    for der in pem_ders(roots) {
        if let Ok((_, c)) = x509_parser::parse_x509_certificate(&der) {
            add(der_inner(c.subject().as_raw()).to_vec(), Kind::Root, cn_of(&c));
        }
    }
    for der in pem_ders(watch) {
        if let Ok((_, c)) = x509_parser::parse_x509_certificate(&der) {
            let name = cn_of(&c);
            add(der_inner(c.subject().as_raw()).to_vec(), Kind::Watch, name.clone());
            let spki = c.public_key().raw;
            add(der_inner(spki).to_vec(), Kind::WatchSpki, name.clone());
            let h = Sha256::digest(spki);
            add(h.to_vec(), Kind::BlockHash, format!("{name} (raw sha256)"));
            add(hex::encode(h).into_bytes(), Kind::BlockHash, format!("{name} (hex)"));
            add(hex::encode_upper(h).into_bytes(), Kind::BlockHash, format!("{name} (HEX)"));
            let b64 = base64::engine::general_purpose::STANDARD.encode(h);
            add(b64.into_bytes(), Kind::BlockHash, format!("{name} (base64)"));
        }
    }
    let (keys, pats): (Vec<_>, Vec<_>) = map.into_iter().unzip();
    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(&keys)
        .expect("aho-corasick");
    eprintln!("patterns: {}", keys.len());
    Matcher { ac, pats }
}

fn apply(m: &Matcher, data: &[u8], f: &mut Finding, fmt: &'static str) {
    let mut hit = false;
    for mat in m.ac.find_overlapping_iter(data) {
        hit = true;
        for p in &m.pats[mat.pattern().as_usize()] {
            match p.kind {
                Kind::Root => f.known_roots.insert(p.name.clone()),
                Kind::Watch => f.watch.insert(p.name.clone()),
                Kind::WatchSpki => f.watch_spki.insert(p.name.clone()),
                Kind::BlockHash => f.spki_hash.insert(p.name.clone()),
            };
        }
    }
    if hit {
        f.formats.insert(fmt);
    }
}

fn clean_b64(body: &[u8]) -> Vec<u8> {
    // tolerate PEM embedded in C/JS/Go string literals: "...\n" + "..."
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        if c == b'\\' && i + 1 < body.len() {
            i += 2;
            continue;
        }
        if c == b'"' || c == b'\'' {
            // skip a string-literal break such as `" +\n  "` or `"\n"`
            let mut j = i + 1;
            while j < body.len() && matches!(body[j], b' ' | b'\t' | b'\r' | b'\n' | b'+' | b',' | b'&' | b'.' | b'_') {
                j += 1;
            }
            if j < body.len() && (body[j] == b'"' || body[j] == b'\'') {
                i = j + 1;
                continue;
            }
            i += 1;
            continue;
        }
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' {
            out.push(c);
        }
        i += 1;
    }
    out
}

fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let e = &base64::engine::general_purpose::STANDARD;
    e.decode(s).ok().or_else(|| {
        let t: Vec<u8> = s.iter().copied().filter(|&c| c != b'=').collect();
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(&t).ok()
    })
}

/// Returns (start, decoded DER if the body decoded) for every certificate PEM block.
fn pem_blocks(data: &[u8]) -> Vec<(usize, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let begin = memchr::memmem::Finder::new(b"-----BEGIN ");
    let end = memchr::memmem::Finder::new(b"-----END ");
    let mut pos = 0;
    while let Some(b) = begin.find(&data[pos..]) {
        let start = pos + b;
        let label_end = match memchr::memmem::find(&data[start + 11..(start + 80).min(data.len())], b"-----") {
            Some(e) => start + 11 + e,
            None => {
                pos = start + 11;
                continue;
            }
        };
        let label = &data[start + 11..label_end];
        let body_start = label_end + 5;
        let Some(e) = end.find(&data[body_start..(body_start + 64 * 1024).min(data.len())]) else {
            pos = body_start;
            continue;
        };
        pos = body_start + e + 9;
        if !label.ends_with(b"CERTIFICATE") {
            continue;
        }
        let der = b64_decode(&clean_b64(&data[body_start..body_start + e]));
        out.push((start, der));
    }
    out
}

fn bare_base64(m: &Matcher, data: &[u8], f: &mut Finding) {
    let finder = memchr::memmem::Finder::new(b"MII");
    let mut pos = 0;
    while let Some(i) = finder.find(&data[pos..]) {
        let s = pos + i;
        let mut e = s;
        while e < data.len() && (data[e].is_ascii_alphanumeric() || matches!(data[e], b'+' | b'/' | b'=')) {
            e += 1;
        }
        if e - s >= MIN_BARE_B64 {
            if let Some(der) = b64_decode(&data[s..e]) {
                apply(m, &der, f, "base64");
            }
        }
        pos = e.max(s + 3);
    }
}

fn certdata_octal(m: &Matcher, data: &[u8], f: &mut Finding) {
    let finder = memchr::memmem::Finder::new(b"MULTILINE_OCTAL");
    let mut pos = 0;
    while let Some(i) = finder.find(&data[pos..]) {
        let mut j = pos + i + 15;
        let mut der = Vec::new();
        while j + 3 < data.len() {
            if data[j] == b'\\' && data[j + 1..j + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                der.push((data[j + 1] - b'0') * 64 + (data[j + 2] - b'0') * 8 + (data[j + 3] - b'0'));
                j += 4;
            } else if data[j..].starts_with(b"END") {
                break;
            } else {
                j += 1;
            }
        }
        if !der.is_empty() {
            apply(m, &der, f, "certdata-octal");
        }
        pos = j;
    }
}

fn load_openssl_providers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // RC2-40 / 3DES cert bags from JDK <= 11 need the legacy provider
        for name in ["default", "legacy"] {
            if let Ok(p) = openssl::provider::Provider::try_load(None, name, true) {
                std::mem::forget(p);
            }
        }
    });
}

fn pkcs12_decrypt(m: &Matcher, data: &[u8], f: &mut Finding) {
    load_openssl_providers();
    let Ok(p12) = openssl::pkcs12::Pkcs12::from_der(data) else { return };
    for pw in P12_PASSWORDS {
        let Ok(parsed) = p12.parse2(pw) else { continue };
        let mut n = 0;
        for c in parsed.ca.iter().flatten().map(|c| c.to_owned()).chain(parsed.cert) {
            if let Ok(der) = c.to_der() {
                apply(m, &der, f, "pkcs12-decrypted");
                n += 1;
            }
        }
        f.note = Some(format!("pkcs12 opened with password {pw:?}: {n} certs"));
        return;
    }
    f.note = Some("pkcs12: password not in list, contents not checked".into());
}

fn magic(data: &[u8]) -> Option<&'static str> {
    const P12_BAG: &[u8] = &[0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01];
    const P7_DATA: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
    match data {
        [0xfe, 0xed, 0xfe, 0xed, ..] => Some("jks"),
        [0xce, 0xce, 0xce, 0xce, ..] => Some("jceks"),
        [0x1f, 0x8b, ..] => Some("gzip"),
        [b'P', b'K', 3, 4, ..] => Some("zip"),
        [0xfd, b'7', b'z', b'X', b'Z', 0, ..] => Some("xz"),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Some("zstd"),
        [0x7f, b'E', b'L', b'F', ..] => Some("elf"),
        [0x30, ..] if data.len() < 4 << 20
            && memchr::memmem::find(&data[..data.len().min(256)], P7_DATA).is_some()
            && (memchr::memmem::find(data, P12_BAG).is_some() || data.len() > 1024) =>
        {
            Some("pkcs12")
        }
        _ if data.len() > 262 && &data[257..262] == b"ustar" => Some("tar"),
        _ if data.starts_with(b"SQLite format 3\0") => Some("sqlite"),
        _ => None,
    }
}

struct Ctx<'a> {
    m: &'a Matcher,
    nar: String,
    out: io::StdoutLock<'static>,
    files: u64,
    bytes: u64,
    findings: u64,
}

impl Ctx<'_> {
    fn emit(&mut self, f: &Finding) {
        if f.interesting() {
            self.findings += 1;
            serde_json::to_writer(&mut self.out, f).unwrap();
            self.out.write_all(b"\n").unwrap();
        }
    }

    fn scan_buf(&mut self, path: &str, data: &[u8], depth: usize) {
        let mut f = Finding { nar: self.nar.clone(), file: path.to_owned(), size: data.len() as u64, ..Default::default() };
        f.magic = magic(data);
        apply(self.m, data, &mut f, "der");
        let blocks = pem_blocks(data);
        f.pem_certs = blocks.len();
        for (_, der) in &blocks {
            if let Some(d) = der {
                apply(self.m, d, &mut f, "pem");
            }
        }
        bare_base64(self.m, data, &mut f);
        certdata_octal(self.m, data, &mut f);
        if f.magic == Some("pkcs12") && f.known_roots.len() < TRUST_STORE_HINT {
            pkcs12_decrypt(self.m, data, &mut f);
        }
        if f.interesting() {
            f.sha256 = Some(hex::encode(Sha256::digest(data)));
        }
        self.emit(&f);
        if depth >= MAX_DEPTH {
            return;
        }
        match f.magic {
            Some("gzip") => self.unpack(path, "gunzip", flate2::read::MultiGzDecoder::new(data), depth),
            Some("xz") => self.unpack(path, "unxz", xz2::read::XzDecoder::new(data), depth),
            Some("zstd") => {
                if let Ok(d) = zstd::stream::read::Decoder::new(data) {
                    self.unpack(path, "unzstd", d, depth)
                }
            }
            Some("zip") => self.zip(path, data, depth),
            Some("tar") => self.tar(path, data, depth),
            _ => {}
        }
    }

    fn unpack(&mut self, path: &str, how: &str, r: impl Read, depth: usize) {
        let mut buf = Vec::new();
        if r.take(MAX_UNPACKED).read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            self.scan_buf(&format!("{path}!{how}"), &buf, depth + 1);
        }
    }

    fn zip(&mut self, path: &str, data: &[u8], depth: usize) {
        let Ok(mut z) = zip::ZipArchive::new(Cursor::new(data)) else { return };
        for i in 0..z.len() {
            let Ok(mut e) = z.by_index(i) else { continue };
            if !e.is_file() || e.size() > MAX_UNPACKED {
                continue;
            }
            let name = format!("{path}!{}", e.name());
            let mut buf = Vec::with_capacity(e.size() as usize);
            if e.read_to_end(&mut buf).is_ok() {
                drop(e);
                self.scan_buf(&name, &buf, depth + 1);
            }
        }
    }

    fn tar(&mut self, path: &str, data: &[u8], depth: usize) {
        let mut a = tar::Archive::new(data);
        let Ok(entries) = a.entries() else { return };
        for e in entries.flatten() {
            let mut e = e;
            if !e.header().entry_type().is_file() || e.size() > MAX_UNPACKED {
                continue;
            }
            let name = format!("{path}!{}", e.path().map(|p| p.display().to_string()).unwrap_or_default());
            let mut buf = Vec::new();
            if e.read_to_end(&mut buf).is_ok() {
                self.scan_buf(&name, &buf, depth + 1);
            }
        }
    }

    fn scan_reader(&mut self, path: &str, mut r: impl Read, len: u64) -> io::Result<()> {
        self.files += 1;
        self.bytes += len;
        if len <= MAX_IN_MEMORY {
            let mut buf = Vec::with_capacity(len as usize);
            r.read_to_end(&mut buf)?;
            self.scan_buf(path, &buf, 0);
            return Ok(());
        }
        let mut f = Finding {
            nar: self.nar.clone(),
            file: path.to_owned(),
            size: len,
            note: Some("chunked: archives not unpacked".into()),
            ..Default::default()
        };
        let mut buf = vec![0u8; CHUNK + OVERLAP];
        let mut have = 0;
        loop {
            let n = read_full(&mut r, &mut buf[have..])?;
            if n == 0 && have == 0 {
                break;
            }
            let end = have + n;
            let view = &buf[..end];
            if f.magic.is_none() {
                f.magic = magic(view);
            }
            apply(self.m, view, &mut f, "der");
            for (_, der) in pem_blocks(view) {
                f.pem_certs += 1;
                if let Some(d) = der {
                    apply(self.m, &d, &mut f, "pem");
                }
            }
            if n == 0 || end < buf.len() {
                break;
            }
            buf.copy_within(end - OVERLAP..end, 0);
            have = OVERLAP;
        }
        self.emit(&f);
        Ok(())
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

fn nar_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn nar_pad(r: &mut impl Read, len: u64) -> io::Result<()> {
    let pad = (8 - len % 8) % 8;
    let mut b = [0u8; 8];
    r.read_exact(&mut b[..pad as usize])
}

fn nar_str(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = nar_u64(r)?;
    if len > 4096 {
        return Err(bad("nar token too long"));
    }
    let mut s = vec![0u8; len as usize];
    r.read_exact(&mut s)?;
    nar_pad(r, len)?;
    Ok(s)
}

fn nar_expect(r: &mut impl Read, tok: &[u8]) -> io::Result<()> {
    let s = nar_str(r)?;
    if s != tok {
        return Err(bad(&format!("expected {:?}, got {:?}", String::from_utf8_lossy(tok), String::from_utf8_lossy(&s))));
    }
    Ok(())
}

fn nar_node(ctx: &mut Ctx, r: &mut impl Read, path: &str) -> io::Result<()> {
    nar_expect(r, b"(")?;
    nar_expect(r, b"type")?;
    match nar_str(r)?.as_slice() {
        b"regular" => {
            let mut tok = nar_str(r)?;
            if tok == b"executable" {
                nar_expect(r, b"")?;
                tok = nar_str(r)?;
            }
            if tok != b"contents" {
                return Err(bad("expected contents"));
            }
            let len = nar_u64(r)?;
            let mut t = r.take(len);
            ctx.scan_reader(path, &mut t, len)?;
            io::copy(&mut t, &mut io::sink())?;
            nar_pad(r, len)?;
            nar_expect(r, b")")
        }
        b"symlink" => {
            nar_expect(r, b"target")?;
            nar_str(r)?;
            nar_expect(r, b")")
        }
        b"directory" => loop {
            let tok = nar_str(r)?;
            if tok == b")" {
                return Ok(());
            }
            if tok != b"entry" {
                return Err(bad("expected entry"));
            }
            nar_expect(r, b"(")?;
            nar_expect(r, b"name")?;
            let name = String::from_utf8_lossy(&nar_str(r)?).into_owned();
            nar_expect(r, b"node")?;
            nar_node(ctx, r, &format!("{path}/{name}"))?;
            nar_expect(r, b")")?;
        },
        t => Err(bad(&format!("bad type {:?}", String::from_utf8_lossy(t)))),
    }
}

fn walk(ctx: &mut Ctx, p: &Path) -> io::Result<()> {
    let md = std::fs::symlink_metadata(p)?;
    if md.is_dir() {
        let mut ents: Vec<_> = std::fs::read_dir(p)?.flatten().map(|e| e.path()).collect();
        ents.sort();
        for e in ents {
            walk(ctx, &e)?;
        }
    } else if md.is_file() {
        ctx.scan_reader(&p.display().to_string(), BufReader::new(std::fs::File::open(p)?), md.len())?;
    }
    Ok(())
}

// top-level tar on stdin: one entry per member, so huge members still take the chunked path
fn tar_stream(ctx: &mut Ctx, r: impl Read) -> io::Result<()> {
    let mut a = tar::Archive::new(r);
    for e in a.entries()? {
        let mut e = e?;
        if !e.header().entry_type().is_file() {
            continue;
        }
        let size = e.size();
        let name = e.path().map(|p| p.display().to_string()).unwrap_or_default();
        let name = name.strip_prefix("./").unwrap_or(&name).to_owned();
        ctx.scan_reader(&format!("/{name}"), &mut e, size)?;
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: cacert-scan [--roots ROOTS.pem] [--watch WATCH.pem] (--nar LABEL < file.nar | --tar LABEL < file.tar | --path DIR...)\n\
                 --roots and --watch default to $CACERT_SCAN_ROOTS and $CACERT_SCAN_WATCH";
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let roots = get("--roots").or_else(|| std::env::var("CACERT_SCAN_ROOTS").ok());
    let watch = get("--watch").or_else(|| std::env::var("CACERT_SCAN_WATCH").ok());
    let (Some(roots), Some(watch)) = (roots, watch) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    let m = build_matcher(&std::fs::read(roots).expect("roots"), &std::fs::read(watch).expect("watch"));
    let out = io::stdout().lock();
    let mut ctx = Ctx { m: &m, nar: String::new(), out, files: 0, bytes: 0, findings: 0 };
    let res = if let Some(label) = get("--nar") {
        ctx.nar = label.clone();
        let mut r = BufReader::with_capacity(1 << 20, io::stdin().lock());
        nar_expect(&mut r, b"nix-archive-1").and_then(|_| nar_node(&mut ctx, &mut r, &label))
    } else if let Some(label) = get("--tar") {
        ctx.nar = label.clone();
        tar_stream(&mut ctx, BufReader::with_capacity(1 << 20, io::stdin().lock()))
    } else if let Some(i) = args.iter().position(|a| a == "--path") {
        args[i + 1..].iter().try_for_each(|p| {
            ctx.nar = p.clone();
            walk(&mut ctx, Path::new(p))
        })
    } else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    eprintln!("files={} bytes={} findings={}", ctx.files, ctx.bytes, ctx.findings);
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
