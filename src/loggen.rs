//! Log record encodings for `psgen log`.
//!
//! `activity` decides what the record says. This module decides how it is
//! written: a common-log-format access line, a JSON object, or an RFC 3164
//! syslog line. Every encoder takes the same record so the three formats
//! describe the same event.

use crate::rng::Rng;
use crate::str::Buf;
use std::vec::Vec;

#[derive(Clone, Copy, PartialEq)]
pub enum Format {
    Apache,
    Json,
    Syslog,
}

impl Format {
    pub fn parse(name: &[u8]) -> Option<Format> {
        match name {
            b"apache" | b"clf" | b"common" => Some(Format::Apache),
            b"json" | b"jsonl" => Some(Format::Json),
            b"syslog" | b"rfc3164" => Some(Format::Syslog),
            _ => None,
        }
    }
}

/// One HTTP request, as an access log would record it.
pub struct WebRecord {
    pub ip: Vec<u8>,
    pub method: &'static str,
    pub path: Vec<u8>,
    pub status: u16,
    pub bytes: u64,
    pub ua: &'static str,
    pub ms: u64,
}

pub const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Split a unix timestamp into UTC civil fields.
pub fn civil(ts: u64) -> (u64, u64, u64, u64, u64, u64) {
    let days = ts / 86400;
    let secs = ts % 86400;
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (
        year as u64,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
    )
}

fn month(ts: u64) -> &'static str {
    let (_, m, _, _, _, _) = civil(ts);
    MONTHS[(m.clamp(1, 12) - 1) as usize]
}

/// `08/Nov/2026:12:34:56 +0000`
pub fn apache_time(ts: u64) -> Vec<u8> {
    let (y, _, d, h, mi, s) = civil(ts);
    let mut b = Buf::new();
    if d < 10 {
        b.push(b'0');
    }
    b.push_u64(d);
    b.push(b'/');
    b.push_str(month(ts));
    b.push(b'/');
    b.push_u64_width(y, 4);
    b.push(b':');
    b.push_two(h);
    b.push(b':');
    b.push_two(mi);
    b.push(b':');
    b.push_two(s);
    b.push_str(" +0000");
    b.as_bytes().to_vec()
}

/// `2026-11-08T12:34:56Z`
pub fn iso_time(ts: u64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil(ts);
    let mut b = Buf::new();
    b.push_u64_width(y, 4);
    b.push(b'-');
    b.push_two(mo);
    b.push(b'-');
    b.push_two(d);
    b.push(b'T');
    b.push_two(h);
    b.push(b':');
    b.push_two(mi);
    b.push(b':');
    b.push_two(s);
    b.push(b'Z');
    b.as_bytes().to_vec()
}

/// `Nov  8 12:34:56`
pub fn syslog_time(ts: u64) -> Vec<u8> {
    let (_, _, d, h, mi, s) = civil(ts);
    let mut b = Buf::new();
    b.push_str(month(ts));
    b.push(b' ');
    if d < 10 {
        b.push(b' ');
    }
    b.push_u64(d);
    b.push(b' ');
    b.push_two(h);
    b.push(b':');
    b.push_two(mi);
    b.push(b':');
    b.push_two(s);
    b.as_bytes().to_vec()
}

pub fn escape_json(out: &mut Buf, s: &[u8]) {
    for b in s {
        match *b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1f => {
                out.push_str("\\u00");
                let hi = b >> 4;
                let lo = b & 0xf;
                out.push(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 });
                out.push(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 });
            }
            _ => out.push(*b),
        }
    }
}

pub fn apache_line(r: &WebRecord, ts: u64) -> Vec<u8> {
    let mut b = Buf::new();
    b.push_bytes(&r.ip);
    b.push_str(" - - [");
    b.push_bytes(&apache_time(ts));
    b.push_str("] \"");
    b.push_str(r.method);
    b.push(b' ');
    b.push_bytes(&r.path);
    b.push_str(" HTTP/1.1\" ");
    b.push_u64(r.status as u64);
    b.push(b' ');
    b.push_u64(r.bytes);
    b.push_str(" \"-\" \"");
    b.push_str(r.ua);
    b.push_str("\"\n");
    b.as_bytes().to_vec()
}

pub fn json_web_line(r: &WebRecord, ts: u64) -> Vec<u8> {
    let mut b = Buf::new();
    b.push_str("{\"ts\":\"");
    b.push_bytes(&iso_time(ts));
    b.push_str("\",\"level\":\"INFO\",\"service\":\"web\",\"msg\":\"request\",\"ip\":\"");
    b.push_bytes(&r.ip);
    b.push_str("\",\"method\":\"");
    b.push_str(r.method);
    b.push_str("\",\"path\":");
    b.push(b'"');
    escape_json(&mut b, &r.path);
    b.push_str("\",\"status\":");
    b.push_u64(r.status as u64);
    b.push_str(",\"bytes\":");
    b.push_u64(r.bytes);
    b.push_str(",\"ms\":");
    b.push_u64(r.ms);
    b.push_str(",\"ua\":");
    b.push(b'"');
    escape_json(&mut b, r.ua.as_bytes());
    b.push(b'"');
    b.push_str("}\n");
    b.as_bytes().to_vec()
}

pub fn syslog_web_line(r: &WebRecord, ts: u64, host: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    b.push_bytes(&syslog_time(ts));
    b.push(b' ');
    b.push_bytes(host);
    b.push_str(" nginx[");
    b.push_u64(1200 + (r.ms % 800));
    b.push_str("]: ");
    b.push_str(r.method);
    b.push(b' ');
    b.push_bytes(&r.path);
    b.push_str(" -> ");
    b.push_u64(r.status as u64);
    b.push(b' ');
    b.push_u64(r.bytes);
    b.push_str("B ");
    b.push_u64(r.ms);
    b.push_str("ms\n");
    b.as_bytes().to_vec()
}

/// Encode one plain text line for a module that is not an access log.
pub fn text_line(fmt: Format, ts: u64, service: &str, level: &str, msg: &[u8]) -> Vec<u8> {
    match fmt {
        Format::Json => {
            let mut b = Buf::new();
            b.push_str("{\"ts\":\"");
            b.push_bytes(&iso_time(ts));
            b.push_str("\",\"level\":\"");
            b.push_str(level);
            b.push_str("\",\"service\":\"");
            b.push_str(service);
            b.push_str("\",\"msg\":");
            b.push(b'"');
            escape_json(&mut b, msg);
            b.push_str("\"}\n");
            b.as_bytes().to_vec()
        }
        Format::Syslog => {
            let mut b = Buf::new();
            b.push_bytes(&syslog_time(ts));
            b.push_str(" buildhost ");
            b.push_str(service);
            b.push_str("[");
            b.push_u64(400 + (ts % 600));
            b.push_str("]: ");
            b.push_bytes(msg);
            b.push(b'\n');
            b.as_bytes().to_vec()
        }
        // The caller rejects apache for these modules before reaching here.
        Format::Apache => {
            let mut b = Buf::new();
            b.push_bytes(msg);
            b.push(b'\n');
            b.as_bytes().to_vec()
        }
    }
}

pub fn rand_ip(rng: &mut Rng) -> Vec<u8> {
    let mut b = Buf::new();
    b.push_u64(192);
    b.push(b'.');
    b.push_u64(168);
    b.push(b'.');
    b.push_u64(rng.range(0, 255));
    b.push(b'.');
    b.push_u64(rng.range(1, 254));
    b.as_bytes().to_vec()
}

pub fn pick_status(rng: &mut Rng) -> u16 {
    let n = rng.below(100);
    if n < 82 {
        200
    } else if n < 84 {
        201
    } else if n < 88 {
        304
    } else if n < 93 {
        400
    } else if n < 97 {
        404
    } else {
        500
    }
}
