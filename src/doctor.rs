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
/// Printable ASCII is copied as-is and only what JSON requires is escaped.
/// Valid UTF-8 sequences are copied whole. A byte that is not part of one is
/// escaped as `\u00XX` so the buffer stays well-formed, but U+00XX is not the
/// original byte and the function returns `false` to say so. The caller must
/// refuse the report rather than emit a path a consumer cannot recover: `0xFF`
/// and `0xC3 0xBF` would otherwise be the same JSON string.
fn json_string(out: &mut Buf, s: &[u8]) -> bool {
    out.push(b'"');
    let mut i = 0;
    let mut valid = true;
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
            b if b < 0x20 || b == 0x7f => {
                push_u_escape(out, b);
                i += 1;
            }
            b if b < 0x7f => {
                out.push(b);
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
                    valid = false;
                    i += 1;
                }
            }
        }
    }
    out.push(b'"');
    valid
}

/// Whether `s` is a single valid UTF-8 string.
fn valid_utf8(s: &[u8]) -> bool {
    core::str::from_utf8(s).is_ok()
}

/// Write one text-report field so it cannot split the row it belongs to.
///
/// A path or an environment value can contain a newline, and the text report
/// uses `\n` as the row separator. Control bytes and bytes that are not valid
/// UTF-8 become `\xNN`, and a literal `\` becomes `\\` so `\x0a` cannot
/// collide with a real newline; all other printable text is copied unchanged.
fn text_field(out: &mut Buf, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b == b'\\' {
            out.push_str("\\\\");
            i += 1;
            continue;
        }
        if b < 0x20 || b == 0x7f {
            out.push_str("\\x");
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
            i += 1;
            continue;
        }
        if b < 0x7f {
            out.push(b);
            i += 1;
            continue;
        }
        let n = utf8_len(b);
        if n > 1 && i + n <= s.len() && core::str::from_utf8(&s[i..i + n]).is_ok() {
            out.push_bytes(&s[i..i + n]);
            i += n;
        } else {
            out.push_str("\\x");
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
            i += 1;
        }
    }
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
        match probe::bpf_allowed() {
            Some(true) => b"allowed".to_vec(),
            Some(false) => b"blocked".to_vec(),
            None => b"not attempted".to_vec(),
        },
    ));
    v.push((
        "seccomp_user_notif",
        match probe::seccomp_user_notif() {
            Some(true) => b"reachable".to_vec(),
            Some(false) => b"blocked".to_vec(),
            None => b"not attempted".to_vec(),
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

fn live_rows_detail(n: usize) -> Vec<u8> {
    let mut d = Buf::new();
    d.push_str("records ");
    d.push_u64(n as u64);
    d.push_str(if n == 1 {
        " live process"
    } else {
        " live processes"
    });
    d.v
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
            Some(n) => live_rows_detail(n),
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

fn write_check_json(out: &mut Buf, c: &probe::Check) -> bool {
    let mut json_ok = true;
    out.push(b'{');
    out.push_str("\"name\":");
    json_ok &= json_string(out, c.name.as_bytes());
    out.push_str(",\"ok\":");
    out.push_str(if c.ok { "true" } else { "false" });
    out.push_str(",\"detail\":");
    json_ok &= json_string(out, &c.detail);
    if !c.ok {
        out.push_str(",\"errno\":");
        json_number(out, c.errno.max(0) as u64);
    }
    if c.not_attempted {
        out.push_str(",\"not_attempted\":true");
    }
    out.push(b'}');
    json_ok
}

fn write_check_text(out: &mut Buf, c: &probe::Check) {
    text_field(out, c.name.as_bytes());
    out.push(b'\t');
    out.push_str(if c.ok { "ALLOW" } else { "DENY" });
    out.push(b'\t');
    if c.not_attempted {
        out.push_str("[not attempted] ");
    }
    text_field(out, &c.detail);
    if !c.ok {
        out.push_str(" (errno ");
        out.push_u64(c.errno.max(0) as u64);
        out.push(b')');
    }
    out.push(b'\n');
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
        let mut json_ok = true;
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
            json_ok &= json_string(&mut out, name.as_bytes());
        }
        out.push_str("],\"env\":{");
        for (i, (k, v)) in env.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json_ok &= json_string(&mut out, k.as_bytes());
            out.push(b':');
            let numeric = env_is_number(k) && !v.is_empty() && v.iter().all(|b| b.is_ascii_digit());
            if numeric {
                out.push_bytes(v);
            } else {
                json_ok &= json_string(&mut out, v);
            }
        }
        out.push_str("},\"checks\":[");
        for (i, c) in checks.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json_ok &= write_check_json(&mut out, c);
        }
        out.push(b']');
        out.push_str(",\"probe\":{");
        for (i, (k, v)) in posture.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json_ok &= json_string(&mut out, k.as_bytes());
            out.push(b':');
            json_ok &= json_string(&mut out, v);
        }
        out.push(b'}');
        if let Some(v) = &verdict {
            // A path is not a JSON key: it may not be valid UTF-8, and a
            // consumer cannot read it back as a field. The path is a value.
            out.push_str(",\"pidfile\":{\"path\":");
            let path_ok = valid_utf8(pidfile.unwrap_or(b""));
            json_ok &= json_string(&mut out, pidfile.unwrap_or(b""));
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
            json_ok &= json_string(&mut out, &v.detail);
            out.push(b'}');
            if !path_ok {
                sys::err(b"psgen: doctor --json cannot represent the pidfile path: it is not valid UTF-8, so the byte that was probed cannot be recovered from the report; use the text report\n");
                return 1;
            }
        }
        out.push_str("}\n");
        // The report is only emitted if every value could be represented.
        // Refusing beats emitting two different paths as the same string.
        if !json_ok {
            sys::err(b"psgen: doctor --json cannot represent this environment: a value it would report is not valid UTF-8; use the text report\n");
            return 1;
        }
        sys::out(out.as_bytes());
    } else {
        let mut out = Buf::new();
        out.push_bytes(crate::version::BARE);
        out.push_str(" doctor\n");
        out.push_str("env\n");
        for (k, v) in &env {
            out.push_str("  ");
            text_field(&mut out, k.as_bytes());
            out.push_str("\t");
            text_field(&mut out, v);
            out.push(b'\n');
        }
        out.push_str("capability\tverdict\tdetail\n");
        for c in &checks {
            write_check_text(&mut out, c);
        }
        out.push_str("probe\n");
        for (k, v) in &posture {
            out.push_str("  ");
            text_field(&mut out, k.as_bytes());
            out.push_str("\t");
            text_field(&mut out, v);
            out.push(b'\n');
        }
        if let (Some(p), Some(v)) = (pidfile, &verdict) {
            out.push_str("pidfile\t");
            out.push_str(if v.allowed { "ALLOW" } else { "DENY" });
            out.push(b'\t');
            text_field(&mut out, p);
            if !v.allowed {
                out.push_str(" (");
                text_field(&mut out, &v.detail);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_keeps_printable_ascii_and_valid_utf8() {
        let mut out = Buf::new();
        assert!(json_string(&mut out, b"/tmp/psgen_1-a.pid"));
        assert_eq!(out.as_bytes(), b"\"/tmp/psgen_1-a.pid\"");
        assert!(!String::from_utf8_lossy(out.as_bytes()).contains("\\u00"));

        let mut escaped = Buf::new();
        assert!(json_string(&mut escaped, b"a\"b\\c\nd\re\tf\x00\x1f\x7f"));
        assert_eq!(
            escaped.as_bytes(),
            b"\"a\\\"b\\\\c\\nd\\re\\tf\\u0000\\u001f\\u007f\""
        );

        let mut cafe = Buf::new();
        assert!(json_string(&mut cafe, "café".as_bytes()));
        assert_eq!(cafe.as_bytes(), "\"café\"".as_bytes());
    }

    #[test]
    fn json_string_refuses_invalid_utf8_and_distinguishes_x_ff_from_utf8() {
        let mut valid_out = Buf::new();
        assert!(json_string(&mut valid_out, b"x\xc3\xbf"));
        assert_eq!(valid_out.as_bytes(), "\"x\u{00ff}\"".as_bytes());

        let mut invalid_out = Buf::new();
        assert!(!json_string(&mut invalid_out, b"x\xff"));
        assert_ne!(invalid_out.as_bytes(), valid_out.as_bytes());
    }

    #[test]
    fn text_field_escapes_controls_invalid_utf8_and_backslashes() {
        let mut out = Buf::new();
        text_field(&mut out, b"/tmp/a\nb\rc\td\x00e\x7ff\xff");
        assert_eq!(out.as_bytes(), b"/tmp/a\\x0ab\\x0dc\\x09d\\x00e\\x7ff\\xff");
        assert!(!out.as_bytes().contains(&b'\n'));

        let mut raw_ff = Buf::new();
        text_field(&mut raw_ff, b"x\xff");
        let mut utf8_ff = Buf::new();
        text_field(&mut utf8_ff, b"x\xc3\xbf");
        assert_ne!(raw_ff.as_bytes(), utf8_ff.as_bytes());
        assert_eq!(raw_ff.as_bytes(), b"x\\xff");
        assert_eq!(utf8_ff.as_bytes(), "x\u{00ff}".as_bytes());

        // Literal `\x0a` cannot collide with an actual newline byte `0x0a`.
        let mut lit = Buf::new();
        text_field(&mut lit, b"\\x0a");
        let mut nl = Buf::new();
        text_field(&mut nl, b"\n");
        assert_ne!(lit.as_bytes(), nl.as_bytes());
        assert_eq!(lit.as_bytes(), b"\\\\x0a");
        assert_eq!(nl.as_bytes(), b"\\x0a");
    }

    #[test]
    fn live_rows_detail_pluralizes_correctly() {
        assert_eq!(live_rows_detail(1), b"records 1 live process");
        assert_eq!(live_rows_detail(2), b"records 2 live processes");
    }

    #[test]
    fn check_formatters_mark_not_attempted_without_breaking_normal_checks() {
        let denied = probe::Check {
            name: "memfd",
            ok: false,
            errno: libc::ENOSYS,
            detail: b"memfd_create with MFD_ALLOW_SEALING failed".to_vec(),
            not_attempted: false,
        };
        let mut j = Buf::new();
        assert!(write_check_json(&mut j, &denied));
        let js = String::from_utf8(j.v).unwrap();
        assert!(!js.contains("not_attempted"), "{}", js);
        assert!(js.contains("\"ok\":false"), "{}", js);

        let skipped = probe::Check {
            name: "memfd",
            ok: false,
            errno: libc::EAGAIN,
            detail: b"the probe could not fork, so memfd_create was not tried".to_vec(),
            not_attempted: true,
        };
        let mut j2 = Buf::new();
        assert!(write_check_json(&mut j2, &skipped));
        let js2 = String::from_utf8(j2.v).unwrap();
        assert!(js2.contains("\"not_attempted\":true"), "{}", js2);
        assert!(js2.contains("\"ok\":false"), "{}", js2);
        assert!(js2.contains("\"errno\":"), "{}", js2);

        let mut t2 = Buf::new();
        write_check_text(&mut t2, &skipped);
        let ts2 = String::from_utf8(t2.v).unwrap();
        assert!(ts2.starts_with("memfd\tDENY\t[not attempted] "), "{}", ts2);
    }
}
