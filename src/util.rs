//! Small system queries: users, memory, uptime, boot identity.

use crate::str;
use crate::sys;
use crate::users::{self, User};

pub fn current_user() -> User {
    users::current()
}

pub fn lookup_user(name: &[u8]) -> Option<(u32, u32)> {
    users::lookup_name(name)
}

fn status_kb(field: &[u8]) -> u64 {
    let mut buf = [0u8; 8192];
    let n = match sys::read_file(b"/proc/self/status", &mut buf) {
        Some(n) => n,
        None => return 0,
    };
    for line in buf[..n].split(|b| *b == b'\n') {
        if str::starts_with(line, field) {
            let rest = str::trim(&line[field.len()..]);
            let mut end = 0;
            while end < rest.len() && rest[end].is_ascii_digit() {
                end += 1;
            }
            return str::parse_u64(&rest[..end]).unwrap_or(0);
        }
    }
    0
}

pub fn self_rss_kb() -> u64 {
    status_kb(b"VmRSS:")
}

pub fn self_vsz_kb() -> u64 {
    status_kb(b"VmSize:")
}

pub fn mem_total_kb() -> u64 {
    let mut buf = [0u8; 8192];
    let n = match sys::read_file(b"/proc/meminfo", &mut buf) {
        Some(n) => n,
        None => return 0,
    };
    for line in buf[..n].split(|b| *b == b'\n') {
        if str::starts_with(line, b"MemTotal:") {
            let rest = str::trim(&line[9..]);
            let mut end = 0;
            while end < rest.len() && rest[end].is_ascii_digit() {
                end += 1;
            }
            return str::parse_u64(&rest[..end]).unwrap_or(0);
        }
    }
    0
}

pub fn uptime_secs() -> u64 {
    let mut buf = [0u8; 256];
    let n = match sys::read_file(b"/proc/uptime", &mut buf) {
        Some(n) => n,
        None => return 0,
    };
    let mut end = 0;
    while end < n && buf[end].is_ascii_digit() {
        end += 1;
    }
    str::parse_u64(&buf[..end]).unwrap_or(0)
}

pub fn boot_time_secs() -> u64 {
    let mut buf = [0u8; 8192];
    let n = match sys::read_file(b"/proc/stat", &mut buf) {
        Some(n) => n,
        None => return 0,
    };
    for line in buf[..n].split(|b| *b == b'\n') {
        if str::starts_with(line, b"btime ") {
            return str::parse_u64(&line[6..]).unwrap_or(0);
        }
    }
    0
}

pub fn boot_id() -> Vec<u8> {
    let mut buf = [0u8; 128];
    match sys::read_file(b"/proc/sys/kernel/random/boot_id", &mut buf) {
        Some(n) => str::trim(&buf[..n]).to_vec(),
        None => Vec::new(),
    }
}

/// The memory limit of the current cgroup, in kB, or 0 when unlimited.
pub fn cgroup_mem_limit_kb() -> u64 {
    // Read the limit of the cgroup this process actually belongs to. The
    // root cgroup's limit is not the limit that will OOM the stubs.
    let mut buf = [0u8; 4096];
    if let Some(n) = sys::read_file(b"/proc/self/cgroup", &mut buf) {
        for line in buf[..n].split(|b| *b == b'\n') {
            if let Some(path) = line.strip_prefix(b"0::") {
                let mut p = b"/sys/fs/cgroup".to_vec();
                p.extend_from_slice(path);
                p.extend_from_slice(b"/memory.max");
                let mut v = [0u8; 64];
                if let Some(m) = sys::read_file(&p, &mut v) {
                    let s = str::trim(&v[..m]);
                    if s == b"max" {
                        return 0;
                    }
                    if let Some(x) = str::parse_u64(s) {
                        return x / 1024;
                    }
                }
            }
            if line.starts_with(b"1:memory:") || str::find(line, b":memory:").is_some() {
                let path = match line.iter().rposition(|b| *b == b':') {
                    Some(i) => &line[i + 1..],
                    None => continue,
                };
                let mut p = b"/sys/fs/cgroup/memory".to_vec();
                p.extend_from_slice(path);
                p.extend_from_slice(b"/memory.limit_in_bytes");
                let mut v = [0u8; 64];
                if let Some(m) = sys::read_file(&p, &mut v) {
                    if let Some(x) = str::parse_u64(str::trim(&v[..m])) {
                        if x < (1u64 << 60) {
                            return x / 1024;
                        }
                    }
                }
            }
        }
    }
    // Fallback for a host where /proc/self/cgroup is not readable.
    let mut v = [0u8; 64];
    if let Some(n) = sys::read_file(b"/sys/fs/cgroup/memory.max", &mut v) {
        let s = str::trim(&v[..n]);
        if s == b"max" {
            return 0;
        }
        if let Some(x) = str::parse_u64(s) {
            return x / 1024;
        }
    }
    if let Some(n) = sys::read_file(b"/sys/fs/cgroup/memory/memory.limit_in_bytes", &mut v) {
        if let Some(x) = str::parse_u64(str::trim(&v[..n])) {
            if x < (1u64 << 60) {
                return x / 1024;
            }
        }
    }
    0
}
