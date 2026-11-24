//! Pure-Rust FIPS 180-4 SHA-256 and run-bundle `MANIFEST.sha256` writer/verifier.

use crate::json::{cat2, cat3, err_io, push_u64, read_str, sort_strings, write_file};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Incremental FIPS 180-4 SHA-256 hasher.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = data.len().min(need);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            compress(&mut self.state, &block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buf.fill(0);
            self.buf_len = 0;
        } else {
            self.buf[self.buf_len..56].fill(0);
        }

        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        compress(&mut self.state, &block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn finalize_hex(self) -> String {
        hex_encode(&self.finalize())
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

pub fn hash_hex(data: &[u8]) -> String {
    hex_encode(&hash(data))
}

pub fn hash_file(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| err_io("cannot open", path, &e))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(err_io("cannot read", path, &e)),
        }
    }
    Ok(h.finalize_hex())
}

/// Structured result of verifying `MANIFEST.sha256` inside a run directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestCheck {
    pub verified: usize,
    pub missing: Vec<String>,
    pub mismatched: Vec<String>,
    pub extra: Vec<String>,
    pub invalid_entries: Vec<String>,
}

impl ManifestCheck {
    pub fn is_ok(&self) -> bool {
        self.missing.is_empty()
            && self.mismatched.is_empty()
            && self.extra.is_empty()
            && self.invalid_entries.is_empty()
    }
}

const MANIFEST_NAME: &str = "MANIFEST.sha256";
const DEFAULT_ALLOW_EXTRA: &[&str] = &["pick.json", "score.json"];

fn collect_files(root: &Path, rel_prefix: &str, out: &mut Vec<String>) -> Result<(), String> {
    let dir = if rel_prefix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel_prefix)
    };
    let entries = fs::read_dir(&dir).map_err(|e| err_io("cannot read directory", &dir, &e))?;
    for entry in entries {
        let entry = entry.map_err(|e| err_io("directory entry error in", &dir, &e))?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(cat2("non-UTF-8 filename in ", &dir.to_string_lossy()));
        };
        let rel = if rel_prefix.is_empty() {
            name_str.to_string()
        } else {
            cat3(rel_prefix, "/", name_str)
        };
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| err_io("cannot stat", &path, &e))?;
        if meta.file_type().is_symlink() {
            return Err(cat2("refusing symlink in run bundle: ", &rel));
        }
        if meta.is_dir() {
            collect_files(root, &rel, out)?;
        } else if meta.is_file() && rel != MANIFEST_NAME {
            out.push(rel);
        }
    }
    Ok(())
}

fn validate_rel_posix_path(rel: &str) -> bool {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.ends_with('/')
        || rel.contains('\\')
        || rel.contains('\0')
    {
        return false;
    }
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return false;
        }
    }
    true
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn line_err(line_no: usize, msg: &str, rel: Option<&str>) -> String {
    let mut s = String::with_capacity(msg.len() + 32);
    s.push_str("line ");
    push_u64(&mut s, line_no as u64);
    s.push_str(": ");
    s.push_str(msg);
    if let Some(r) = rel {
        s.push_str(" '");
        s.push_str(r);
        s.push('\'');
    }
    s
}

/// Recursively hashes every regular file under `root` (skipping `MANIFEST.sha256`),
/// sorts by relative POSIX path, and writes `<hex>  <relpath>\n` to `root/MANIFEST.sha256`.
pub fn write_manifest(root: &Path) -> Result<usize, String> {
    let mut files = Vec::new();
    collect_files(root, "", &mut files)?;
    sort_strings(&mut files);

    let mut body = String::new();
    for rel in &files {
        let full = root.join(rel);
        let digest = hash_file(&full)?;
        body.push_str(&digest);
        body.push_str("  ");
        body.push_str(rel);
        body.push('\n');
    }

    write_file(&root.join(MANIFEST_NAME), body.as_bytes())?;
    Ok(files.len())
}

/// Verify `root/MANIFEST.sha256`, allowing optional post-run `pick.json` and `score.json`
/// files if they were added after manifest creation.
pub fn verify_manifest(root: &Path) -> Result<ManifestCheck, String> {
    verify_manifest_with_allowed(root, DEFAULT_ALLOW_EXTRA)
}

/// Verify `root/MANIFEST.sha256` with an explicit list of allowed unlisted extra relative paths.
pub fn verify_manifest_with_allowed(
    root: &Path,
    allow_extra: &[&str],
) -> Result<ManifestCheck, String> {
    let content = read_str(&root.join(MANIFEST_NAME))?;

    let mut check = ManifestCheck {
        verified: 0,
        missing: Vec::new(),
        mismatched: Vec::new(),
        extra: Vec::new(),
        invalid_entries: Vec::new(),
    };
    let mut seen: Vec<String> = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        if raw_line.is_empty() {
            continue;
        }
        let Some((digest, rel)) = raw_line.split_once("  ") else {
            check
                .invalid_entries
                .push(line_err(line_no, "malformed entry", None));
            continue;
        };
        if !is_lower_hex64(digest) {
            check
                .invalid_entries
                .push(line_err(line_no, "invalid sha256 hex", None));
            continue;
        }
        if !validate_rel_posix_path(rel) || rel == MANIFEST_NAME {
            check
                .invalid_entries
                .push(line_err(line_no, "unsafe path", Some(rel)));
            continue;
        }
        match seen.binary_search_by(|s| s.as_str().cmp(rel)) {
            Ok(_) => {
                check
                    .invalid_entries
                    .push(line_err(line_no, "duplicate path", Some(rel)));
                continue;
            }
            Err(pos) => seen.insert(pos, rel.to_string()),
        }

        let full = root.join(rel);
        let meta = match fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(_) => {
                check.missing.push(rel.to_string());
                continue;
            }
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            check
                .invalid_entries
                .push(line_err(line_no, "non-regular file", Some(rel)));
            continue;
        }

        match hash_file(&full) {
            Ok(actual) if actual == digest => {
                check.verified += 1;
            }
            Ok(_) => {
                check.mismatched.push(rel.to_string());
            }
            Err(_) => {
                check.missing.push(rel.to_string());
            }
        }
    }

    let mut actual_files = Vec::new();
    collect_files(root, "", &mut actual_files)?;
    sort_strings(&mut actual_files);
    for rel in actual_files {
        if seen.binary_search(&rel).is_err() && !allow_extra.contains(&rel.as_str()) {
            check.extra.push(rel);
        }
    }

    Ok(check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("psgen-sha256-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create temp test dir");
        p
    }

    #[test]
    fn nist_fips_180_4_vectors() {
        assert_eq!(
            hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );

        // 1,000,000 repetitions of 'a' streamed across uneven chunk sizes.
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            h.finalize_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn manifest_roundtrip_and_tamper_detection() {
        let dir = test_dir("roundtrip");
        fs::create_dir_all(dir.join("deep/1234")).unwrap();
        fs::write(dir.join("profile.json"), b"{\"schema\":1}\n").unwrap();
        fs::write(dir.join("deep/1234/status"), b"Name:\tci-runner\n").unwrap();

        let count = write_manifest(&dir).unwrap();
        assert_eq!(count, 2);

        let ok = verify_manifest(&dir).unwrap();
        assert!(ok.is_ok());
        assert_eq!(ok.verified, 2);

        // Optional pick.json / score.json allowed by default verify_manifest,
        // rejected when allow_extra is empty.
        fs::write(dir.join("pick.json"), b"{}\n").unwrap();
        assert!(verify_manifest(&dir).unwrap().is_ok());
        let strict = verify_manifest_with_allowed(&dir, &[]).unwrap();
        assert_eq!(strict.extra, vec!["pick.json"]);

        // Unexpected extra file is flagged.
        fs::write(dir.join("sneaky.txt"), b"extra").unwrap();
        let extra = verify_manifest(&dir).unwrap();
        assert_eq!(extra.extra, vec!["sneaky.txt"]);
        let _ = fs::remove_file(dir.join("sneaky.txt"));

        // Mutating a file is caught as mismatch.
        fs::write(dir.join("profile.json"), b"{\"schema\":2}\n").unwrap();
        let tampered = verify_manifest(&dir).unwrap();
        assert_eq!(tampered.mismatched, vec!["profile.json"]);

        // Removing a file is caught as missing.
        fs::remove_file(dir.join("deep/1234/status")).unwrap();
        let missing = verify_manifest(&dir).unwrap();
        assert_eq!(missing.missing, vec!["deep/1234/status"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_rejects_path_traversal() {
        let dir = test_dir("traversal");
        let zeros = "0".repeat(64);
        let evil = format!("{zeros}  ../escape.txt\n{zeros}  /etc/passwd\n");
        fs::write(dir.join(MANIFEST_NAME), evil).unwrap();

        let res = verify_manifest(&dir).unwrap();
        assert!(!res.is_ok());
        assert_eq!(res.invalid_entries.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }
}
