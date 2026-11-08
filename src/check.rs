//! Corpus validation: no grey terms, no unexpanded placeholders, no control
//! bytes, and optionally a check that each executable exists.

use crate::corpus;
use crate::gen::{self, Opts};
use crate::rng::Rng;
use crate::str::{self, Buf};
use crate::sys;
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
        str::basename(first)
    };
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn exists(name: &[u8]) -> bool {
    if name.contains(&b'/') {
        return sys::access(name, 1);
    }
    for dir in [
        &b"/usr/local/bin/"[..],
        &b"/usr/bin/"[..],
        &b"/bin/"[..],
        &b"/usr/sbin/"[..],
        &b"/sbin/"[..],
    ] {
        let mut path = Vec::with_capacity(dir.len() + name.len());
        path.extend_from_slice(dir);
        path.extend_from_slice(name);
        if sys::access(&path, 1) {
            return true;
        }
    }
    false
}

pub fn run(rng: &mut Rng, opts: &Opts, binaries: bool) -> i32 {
    let cmds = gen::all_commands(rng, opts);
    let mut deny_hits = 0usize;
    let mut placeholder_hits = 0usize;
    let mut control_hits = 0usize;
    let mut empty_hits = 0usize;
    let mut missing = 0usize;
    let mut found = 0usize;
    let mut report = Buf::new();

    for cmd in &cmds {
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
        if binaries {
            if let Some(name) = executable(cmd) {
                if exists(name) {
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
        }
    }

    let mut out = Buf::new();
    out.push_str("templates: ");
    out.push_u64(corpus::CORPUS.len() as u64);
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
    }
    out.push(b'\n');
    sys::out(out.as_bytes());
    if !report.as_bytes().is_empty() {
        sys::out(report.as_bytes());
    }
    if deny_hits + placeholder_hits + control_hits + empty_hits > 0 {
        1
    } else {
        0
    }
}
