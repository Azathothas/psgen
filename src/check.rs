//! Corpus validation: no grey terms, no unexpanded placeholders, no control
//! bytes, and optionally a check that each executable exists.

use crate::corpus;
use crate::gen::{self, Opts};
use crate::rng::Rng;
use crate::str::{self, Buf};
use crate::sys;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::vec::Vec;

/// Terms that must never appear in generated output. Word boundaries are
/// enforced, so `cryptography` does not match `crypto`.
static DENY: &[&[u8]] = &[
    b"botnet",
    b"bruteforce",
    b"brute-force",
    b"cryptomin",
    b"cryptomining",
    b"cryptominer",
    b"crypto",
    b"mining",
    b"stratum",
    b"xmrig",
    b"hashcat",
    b"hydra",
    b"nmap",
    b"masscan",
    b"metasploit",
    b"msfconsole",
    b"cobalt",
    b"beacon",
    b"payload",
    b"exploit",
    b"backdoor",
    b"keylog",
    b"mimikatz",
    b"lazagne",
    b"sqlmap",
    b"nikto",
    b"wpscan",
    b"gobuster",
    b"ffuf",
    b"dirb",
    b"nuclei",
    b"reverse shell",
    b"/dev/tcp",
    b"nc -e",
    b"ncat -e",
    b"socat exec",
    b"chisel",
    b"ligolo",
    b"ngrok",
    b"ransomware",
    b"rootkit",
    b"rkhunter",
    b"memdump",
    b"volatility",
    b"lsass",
    b"procdump",
    b"sekurlsa",
    b"kerberoast",
    b"bloodhound",
    b"impacket",
    b"responder",
    b"ettercap",
    b"arpspoof",
    b"aircrack",
    b"reaver",
    b"wifite",
    b"kismet",
    b"bettercap",
    b"empire",
    b"sliver",
    b"havoc",
    b"covenant",
    b"mythic",
    b"ganache",
    b"simcity",
    b"tor",
    b"i2p",
];

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub fn contains_word(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        let mut equal = true;
        let mut j = 0;
        while j < needle.len() {
            let a = haystack[i + j].to_ascii_lowercase();
            let b = needle[j].to_ascii_lowercase();
            if a != b {
                equal = false;
                break;
            }
            j += 1;
        }
        if equal {
            let before_ok = i == 0 || !is_word_char(haystack[i - 1]);
            let after = i + needle.len();
            let after_ok = after == haystack.len() || !is_word_char(haystack[after]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn executable(cmd: &[u8]) -> Option<&[u8]> {
    let first = match cmd.iter().position(|b| *b == b' ') {
        Some(p) => &cmd[..p],
        None => cmd,
    };
    if first.is_empty() || first[0] == b'(' {
        return None;
    }
    let name = if let Some(rest) = first.strip_suffix(b":") {
        rest
    } else if let Some(p) = first.iter().position(|b| *b == b':') {
        &first[..p]
    } else {
        first
    };
    if name.is_empty() {
        None
    } else if name.starts_with(b"/") {
        // Only a leading slash names a location on this host. A relative
        // command such as `dovecot/anvil` is a template name, and checking it
        // against the caller's working directory makes the answer depend on
        // where `check` was run.
        Some(name)
    } else {
        Some(str::basename(name))
    }
}

/// A regular file the caller may execute.
///
/// `access(X_OK)` alone is not enough: it is true for a searchable directory,
/// so a directory at the path a template names was counted as an installed
/// binary. This is the same predicate `gen` uses to decide a path is runnable,
/// so `check` and `inject` cannot disagree about one string.
fn is_exec_file(path: &[u8]) -> bool {
    use std::os::unix::fs::MetadataExt;
    let p = Path::new(OsStr::from_bytes(path));
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && m.mode() & 0o111 != 0 && sys::access(path, sys::X_OK),
        Err(_) => false,
    }
}

fn exists_in(dir: &[u8], name: &[u8]) -> bool {
    let mut path = Vec::with_capacity(dir.len() + name.len() + 1);
    path.extend_from_slice(dir);
    if !dir.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    is_exec_file(&path)
}

/// Whether a name or an absolute path is installed here.
///
/// A bare name is looked up the way the shell would, in `PATH` and then the
/// standard directories. An absolute path is checked as given, and never
/// against the caller's working directory.
fn exists(name: &[u8]) -> bool {
    if name.starts_with(b"/") {
        return is_exec_file(name);
    }
    if let Some(path) = std::env::var_os("PATH") {
        use std::os::unix::ffi::OsStrExt;
        for dir in path.as_os_str().as_bytes().split(|b| *b == b':') {
            if !dir.is_empty() && exists_in(dir, name) {
                return true;
            }
        }
    }
    for dir in [
        &b"/usr/local/bin"[..],
        &b"/usr/bin"[..],
        &b"/bin"[..],
        &b"/usr/sbin"[..],
        &b"/sbin"[..],
    ] {
        if exists_in(dir, name) {
            return true;
        }
    }
    false
}

/// Whether a command line names an executable at all.
///
/// A kernel thread such as `(sd-pam)` has no binary to look for, and the
/// `--binaries` totals must account for it as "not checked" rather than
/// silently omitting a row from `expanded`.
fn nameable(cmd: &[u8]) -> bool {
    executable(cmd).is_some()
}

/// The path `inject` would run for a template, if it is installed here.
///
/// `gen::template_exe` owns the name-to-location maps that `inject` uses, so
/// asking it is the only way `check` can agree with `inject`: most daemons in
/// the corpus are bare names whose location is hardcoded there
/// (`postgres`, `qmgr`, `dovecot/anvil`), and a second, narrower resolver
/// reported them missing while `inject` happily ran them.
fn installed(tmpl: &corpus::Tmpl) -> Option<Vec<u8>> {
    let want = gen::template_exe(tmpl);
    if !want.is_empty() && is_exec_file(&want) {
        return Some(want);
    }
    let by_name = executable(tmpl.cmd.as_bytes())?;
    if exists(by_name) {
        return Some(by_name.to_vec());
    }
    // A template whose command is `dovecot/anvil` has a bare-name form that no
    // `PATH` entry holds; its mapped location is the one `inject` uses.
    None
}

pub fn run(rng: &mut Rng, opts: &Opts, binaries: bool, require_binaries: bool) -> i32 {
    let cmds = gen::all_commands(rng, opts);
    // `all_commands` yields one command per template, in corpus order, so the
    // template that a command came from is known and its mapped install
    // location can be asked for. Without it, a bare-name daemon whose location
    // `gen` hardcodes is reported missing while `inject` runs it.
    let tmpls: Vec<&corpus::Tmpl> = corpus::CORPUS
        .iter()
        .filter(|t| opts.family.map(|f| t.fam == f).unwrap_or(true))
        .collect();
    let mut deny_hits = 0usize;
    let mut placeholder_hits = 0usize;
    let mut control_hits = 0usize;
    let mut empty_hits = 0usize;
    let mut missing = 0usize;
    let mut found = 0usize;
    let mut checked = 0usize;
    let mut unchecked = 0usize;
    let mut report = Buf::new();

    for (idx, cmd) in cmds.iter().enumerate() {
        if cmd.is_empty() {
            empty_hits += 1;
            continue;
        }
        if cmd.iter().any(|b| *b < 0x20 || *b == 0x7f) {
            control_hits += 1;
            report.push_str("control: ");
            report.push_bytes(cmd);
            report.push(b'\n');
        }
        if cmd.contains(&b'{') || cmd.contains(&b'}') {
            placeholder_hits += 1;
            report.push_str("placeholder: ");
            report.push_bytes(cmd);
            report.push(b'\n');
        }
        for term in DENY {
            if contains_word(cmd, term) {
                deny_hits += 1;
                report.push_str("deny: ");
                report.push_bytes(cmd);
                report.push(b'\n');
                break;
            }
        }
        if binaries && nameable(cmd) {
            if let Some(name) = executable(cmd) {
                checked += 1;
                // The plain lookup answers for a bare name; `inject` may still
                // run a different location, and that map belongs to `gen`, so
                // the answer comes from there rather than from a second
                // resolver here. A second resolver reported an installed
                // daemon missing while `inject` ran it.
                let mapped = tmpls.get(idx).and_then(|t| installed(t));
                if exists(name) || mapped.is_some() {
                    found += 1;
                } else {
                    missing += 1;
                    report.push_str("missing: ");
                    report.push_bytes(name);
                    report.push_str("  <- ");
                    report.push_bytes(cmd);
                    report.push(b'\n');
                }
            }
        } else if binaries {
            // A row whose command names no executable (a kernel thread such as
            // `(sd-pam)`) is not a binary to look for, so it is not in either
            // total. It is counted so the totals can be reconciled.
            unchecked += 1;
        }
    }

    let mut out = Buf::new();
    // The seed changes which placeholder expansion is checked, so it is part
    // of the report: without it, `check -s 1` and `check -s 2` print the same
    // thing and the option looks like a no-op.
    out.push_str("seed:      ");
    out.push_u64(opts.seed);
    out.push_str("\ntemplates: ");
    out.push_u64(corpus::CORPUS.len() as u64);
    if let Some(f) = opts.family {
        out.push_str(" (");
        out.push_u64(cmds.len() as u64);
        out.push_str(" in family ");
        out.push_str(corpus::family_name(f));
        out.push(b')');
    }
    out.push_str("\nexpanded:  ");
    out.push_u64(cmds.len() as u64);
    out.push_str("\ndeny hits: ");
    out.push_u64(deny_hits as u64);
    out.push_str("\nplaceholders: ");
    out.push_u64(placeholder_hits as u64);
    out.push_str("\ncontrol bytes: ");
    out.push_u64(control_hits as u64);
    out.push_str("\nempty: ");
    out.push_u64(empty_hits as u64);
    if binaries {
        out.push_str("\nbinaries found: ");
        out.push_u64(found as u64);
        out.push_str("\nbinaries missing: ");
        out.push_u64(missing as u64);
        // found + missing is `checked`; `checked` + `not a binary` is the
        // expanded count. Printing both makes a row that the resolver dropped
        // visible, which is how a name-mapped daemon used to go unreported.
        out.push_str("\nbinaries checked: ");
        out.push_u64(checked as u64);
        out.push_str("\nbinaries not a binary: ");
        out.push_u64(unchecked as u64);
    }
    out.push(b'\n');
    sys::out(out.as_bytes());
    if !report.as_bytes().is_empty() {
        sys::out(report.as_bytes());
    }
    // A missing executable is a fact about the host, not about the corpus, so
    // `--binaries` reports and `--require-binaries` fails. Exiting 0 with 148
    // of 181 missing made the flag useless as a CI step.
    let corpus_bad = deny_hits + placeholder_hits + control_hits + empty_hits > 0;
    let host_bad = require_binaries && missing > 0;
    if corpus_bad || host_bad {
        1
    } else {
        0
    }
}
