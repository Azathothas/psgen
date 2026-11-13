//! `psgen doctor`: report which capabilities this environment permits.
//!
//! The same probe data is what inject acts on. A cage that denies `/dev/ptmx`,
//! memfd or user namespaces is reported as DENY with the errno that produced
//! it, so a later run can degrade instead of claiming parity it does not have.

use crate::probe;
use crate::str::Buf;
use crate::sys;
use crate::util;
use std::vec::Vec;

/// Write one JSON string literal.
///
/// JSON strings are UTF-8, so a valid sequence is copied through and every byte
/// that is not part of one is escaped as `\u00XX`. The previous version replaced
/// every byte outside printable ASCII with `?`, which made `/tmp/aéb.pid` and
/// `/tmp/aèb.pid` the same JSON value: two paths a consumer could not tell
/// apart, and the one the tool had just probed was unrecoverable.
fn json_string(out: &mut Buf, s: &[u8]) {
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'"' => {
                out.push_str("\\\"");
                i += 1;
            }
            b'\\' => {
                out.push_str("\\\\");
                i += 1;
            }
            b'\n' => {
                out.push_str("\\n");
                i += 1;
            }
            b'\r' => {
                out.push_str("\\r");
                i += 1;
            }
            b'\t' => {
                out.push_str("\\t");
                i += 1;
            }
            b if b < 0x20 => {
                push_u_escape(out, b);
                i += 1;
            }
            _ => {
                // Copy a whole UTF-8 sequence, not one byte at a time: a
                // continuation byte is not valid on its own, so a per-byte
                // copy escaped the tail of a valid two-byte character.
                let n = utf8_len(s[i]);
                if n > 1 && i + n <= s.len() && core::str::from_utf8(&s[i..i + n]).is_ok() {
                    out.push_bytes(&s[i..i + n]);
                    i += n;
                } else {
                    push_u_escape(out, s[i]);
                    i += 1;
                }
            }
        }
    }
    out.push(b'"');
}

/// `\u00XX` for one byte, so no byte the input carries is lost.
fn push_u_escape(out: &mut Buf, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u00");
    out.push(HEX[(b >> 4) as usize]);
    out.push(HEX[(b & 0xf) as usize]);
}

/// The length a UTF-8 sequence starting with `b` claims, or 1 when `b` cannot
/// start one.
fn utf8_len(b: u8) -> usize {
    match b {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 1,
    }
}

fn json_number(out: &mut Buf, n: u64) {
    out.push_u64(n);
}

/// Whether an environment key is a number. Deciding by "every byte is a digit"
/// made a cwd of `/1234` a string and a cwd of `1234` a number.
fn env_is_number(key: &str) -> bool {
    matches!(
        key,
        "uid" | "euid" | "mem_total_kb" | "cgroup_mem_limit_kb" | "page_kb" | "hz"
    )
}

fn bool_txt(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}

fn environment() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = vec![
        ("uid", sys::getuid().to_string().into_bytes()),
        ("euid", sys::geteuid().to_string().into_bytes()),
        (
            "mem_total_kb",
            util::mem_total_kb().to_string().into_bytes(),
        ),
        (
            "cgroup_mem_limit_kb",
            util::cgroup_mem_limit_kb().to_string().into_bytes(),
        ),
        ("page_kb", sys::page_kb().to_string().into_bytes()),
        ("hz", sys::hz().to_string().into_bytes()),
    ];
    let mut cwd = [0u8; 4096];
    let c = match sys::getcwd(&mut cwd) {
        Some(n) => cwd[..n].to_vec(),
        None => Vec::new(),
    };
    v.push(("cwd", c));
    v
}

fn read_status_field(field: &[u8], buf: &[u8]) -> Option<Vec<u8>> {
    for line in buf.split(|b| *b == b'\n') {
        if line.len() >= field.len() && &line[..field.len()] == field {
            let rest = &line[field.len()..];
            let mut out: Vec<u8> = rest
                .iter()
                .skip_while(|b| **b == b'\t' || **b == b' ')
                .cloned()
                .collect();
            while out.last() == Some(&b'\r') {
                out.pop();
            }
            return Some(out);
        }
    }
    None
}

fn trimmed(buf: &[u8]) -> Vec<u8> {
    let mut v = buf.to_vec();
    while matches!(v.last(), Some(b'\n') | Some(b'\r')) {
        v.pop();
    }
    if v.is_empty() {
        b"unknown".to_vec()
    } else {
        v
    }
}

/// Facts about the sandbox that do not change what inject can do, but decide
/// whether a probe or a trace is worth attempting here. Kept separate from
/// the capability table so the summary counts only the capability table, not
/// the posture block.
fn posture() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let mut status_buf = [0u8; 16384];
    let n = sys::read_file(b"/proc/self/status", &mut status_buf).unwrap_or(0);
    let status = &status_buf[..n];
    let cap_eff = read_status_field(b"CapEff:", status).unwrap_or_default();
    let has_caps = if cap_eff.iter().any(|b| *b != b'0') {
        b"yes".to_vec()
    } else {
        b"no".to_vec()
    };
    v.push(("cap_eff", cap_eff));
    v.push(("has_caps", has_caps));
    v.push((
        "seccomp_mode",
        read_status_field(b"Seccomp:", status).unwrap_or_else(|| b"0".to_vec()),
    ));
    v.push((
        "no_new_privs",
        read_status_field(b"NoNewPrivs:", status).unwrap_or_else(|| b"0".to_vec()),
    ));
    v.push((
        "bpf",
        if probe::bpf_allowed() {
            b"allowed".to_vec()
        } else {
            b"blocked".to_vec()
        },
    ));
    v.push((
        "seccomp_user_notif",
        if probe::seccomp_user_notif() {
            b"reachable".to_vec()
        } else {
            b"blocked".to_vec()
        },
    ));
    let mut buf = [0u8; 256];
    let n = sys::read_file(b"/proc/sys/kernel/yama/ptrace_scope", &mut buf).unwrap_or(0);
    v.push(("ptrace_scope", trimmed(&buf[..n])));
    let mut buf = [0u8; 256];
    let n = sys::read_file(b"/proc/sys/kernel/unprivileged_bpf_disabled", &mut buf).unwrap_or(0);
    v.push(("unprivileged_bpf_disabled", trimmed(&buf[..n])));
    let mut proc1 = [0u8; 4096];
    let ok = matches!(sys::read_file(b"/proc/1/cmdline", &mut proc1), Some(n) if n > 0);
    v.push((
        "proc_1_cmdline",
        if ok {
            b"read ok".to_vec()
        } else {
            b"read failed".to_vec()
        },
    ));
    v
}

/// What `inject` would do with `pidfile`, in one verdict.
///
/// `doctor` promises to say whether a pidfile can be used, and `inject` has
/// more reasons to refuse than the write preflight covers: a pidfile that
/// still records live stubs is refused too, because the pending rewrite would
/// erase the only record of the old run. Reporting `ALLOW` for such a file sent
/// the caller from `doctor` into a refusal from `inject`. `live` is the number
/// of rows still alive, and is `None` when the file exists but cannot be read.
pub struct PidfileVerdict {
    /// Whether `inject` would accept the path: it must be writable *and* name
    /// no live row.
    pub allowed: bool,
    pub writable: bool,
    pub live_rows: Option<usize>,
    pub detail: Vec<u8>,
}

pub fn pidfile_verdict(pidfile: &[u8]) -> PidfileVerdict {
    let writable = probe::pidfile_creatable(pidfile);
    let live_rows = crate::inject::live_pidfile_rows(pidfile);
    let allowed = writable && matches!(live_rows, Some(0));
    let detail = if !writable {
        let e = probe::pidfile_creatable_errno(pidfile);
        std::io::Error::from_raw_os_error(e)
            .to_string()
            .into_bytes()
    } else {
        match live_rows {
            Some(0) => b"writable, no live rows".to_vec(),
            Some(n) => {
                let mut d = Buf::new();
                d.push_str("records ");
                d.push_u64(n as u64);
                d.push_str(" live processes");
                d.v
            }
            None => b"the existing file cannot be read".to_vec(),
        }
    };
    PidfileVerdict {
        allowed,
        writable,
        live_rows,
        detail,
    }
}

pub fn run(as_json: bool, pidfile: Option<&[u8]>) -> i32 {
    let checks = probe::checks();
    let env = environment();
    let posture = posture();

    let mut denied = 0usize;
    for c in &checks {
        if !c.ok {
            denied += 1;
        }
    }
    let verdict = pidfile.map(pidfile_verdict);

    // Doctor reports on everything but only fails when a capability that
    // injection cannot work without is missing. A non-root run always denies
    // user_switch, and that is not an error.
    let core = ["proc_exe", "fork", "prctl_name"];
    let core_ok = core
        .iter()
        .all(|name| checks.iter().any(|c| c.name == *name && c.ok));

    if as_json {
        let mut out = Buf::new();
        out.push(b'{');
        out.push_str("\"version\":\"");
        out.push_str(crate::version::VERSION);
        out.push_str("\",\"ok\":");
        out.push_str(bool_txt(core_ok));
        out.push_str(",\"core_ok\":");
        out.push_str(bool_txt(core_ok));
        out.push_str(",\"core\":[");
        for (i, name) in core.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json_string(&mut out, name.as_bytes());
        }
        out.push_str("],\"env\":{");
        for (i, (k, v)) in env.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json_string(&mut out, k.as_bytes());
            out.push(b':');
            let numeric = env_is_number(k) && !v.is_empty() && v.iter().all(|b| b.is_ascii_digit());
            if numeric {
                out.push_bytes(v);
            } else {
                json_string(&mut out, v);
            }
        }
        out.push_str("},\"checks\":[");
        for (i, c) in checks.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.push(b'{');
            out.push_str("\"name\":");
            json_string(&mut out, c.name.as_bytes());
            out.push_str(",\"ok\":");
            out.push_str(if c.ok { "true" } else { "false" });
            out.push_str(",\"detail\":");
            json_string(&mut out, &c.detail);
            if !c.ok {
                out.push_str(",\"errno\":");
                json_number(&mut out, c.errno.max(0) as u64);
            }
            out.push(b'}');
        }
        out.push(b']');
        out.push_str(",\"probe\":{");
        for (i, (k, v)) in posture.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json_string(&mut out, k.as_bytes());
            out.push(b':');
            json_string(&mut out, v);
        }
        out.push(b'}');
        if let Some(v) = &verdict {
            // A path is not a JSON key: it may not be valid UTF-8, and a
            // consumer cannot read it back as a field. The path is a value.
            out.push_str(",\"pidfile\":{\"path\":");
            json_string(&mut out, pidfile.unwrap_or(b""));
            out.push_str(",\"allowed\":");
            out.push_str(bool_txt(v.allowed));
            out.push_str(",\"writable\":");
            out.push_str(bool_txt(v.writable));
            out.push_str(",\"live_rows\":");
            match v.live_rows {
                Some(n) => json_number(&mut out, n as u64),
                None => out.push_str("null"),
            }
            out.push_str(",\"detail\":");
            json_string(&mut out, &v.detail);
            out.push(b'}');
        }
        out.push_str("}\n");
        sys::out(out.as_bytes());
    } else {
        let mut out = Buf::new();
        out.push_bytes(crate::version::BARE);
        out.push_str(" doctor\n");
        out.push_str("env\n");
        for (k, v) in &env {
            out.push_str("  ");
            out.push_str(k);
            out.push_str("\t");
            out.push_bytes(v);
            out.push(b'\n');
        }
        out.push_str("capability\tverdict\tdetail\n");
        for c in &checks {
            out.push_bytes(c.name.as_bytes());
            out.push(b'\t');
            out.push_str(if c.ok { "ALLOW" } else { "DENY" });
            out.push(b'\t');
            out.push_bytes(&c.detail);
            if !c.ok {
                out.push_str(" (errno ");
                out.push_u64(c.errno.max(0) as u64);
                out.push(b')');
            }
            out.push(b'\n');
        }
        out.push_str("probe\n");
        for (k, v) in &posture {
            out.push_str("  ");
            out.push_str(k);
            out.push_str("\t");
            out.push_bytes(v);
            out.push(b'\n');
        }
        if let (Some(p), Some(v)) = (pidfile, &verdict) {
            out.push_str("pidfile\t");
            out.push_str(if v.allowed { "ALLOW" } else { "DENY" });
            out.push(b'\t');
            out.push_bytes(p);
            if !v.allowed {
                out.push_str(" (");
                out.push_bytes(&v.detail);
                out.push(b')');
            }
            out.push(b'\n');
        }
        out.push_str("summary\t");
        out.push_u64((checks.len() - denied) as u64);
        out.push(b'/');
        out.push_u64(checks.len() as u64);
        out.push_str(" capabilities available\n");
        sys::out(out.as_bytes());
    }
    if core_ok {
        0
    } else {
        1
    }
}
