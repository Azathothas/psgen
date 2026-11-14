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

/// `MemAvailable` in kB, or 0 when the kernel does not report it.
pub fn mem_available_kb() -> u64 {
    let mut buf = [0u8; 8192];
    let n = match sys::read_file(b"/proc/meminfo", &mut buf) {
        Some(n) => n,
        None => return 0,
    };
    for line in buf[..n].split(|b| *b == b'\n') {
        if str::starts_with(line, b"MemAvailable:") {
            let rest = str::trim(&line[13..]);
            let mut end = 0;
            while end < rest.len() && rest[end].is_ascii_digit() {
                end += 1;
            }
            return str::parse_u64(&rest[..end]).unwrap_or(0);
        }
    }
    0
}

/// `/proc/sys/kernel/pid_max`, or 0 when it cannot be read.
pub fn pid_max() -> u64 {
    let mut buf = [0u8; 64];
    match sys::read_file(b"/proc/sys/kernel/pid_max", &mut buf) {
        Some(n) => str::parse_u64(str::trim(&buf[..n])).unwrap_or(0),
        None => 0,
    }
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
    // Read the whole file: with many CPUs or a long `intr` line, `btime`
    // can sit past the first 8 KiB, and a fixed buffer returned 0 and made
    // every start time fall back to a different clock domain.
    let text = match sys::read_file_nofollow(b"/proc/stat", 1 << 20) {
        Some(t) => t,
        None => {
            if std::path::Path::new("/proc/stat").exists() {
                sys::err(
                    b"psgen: cannot read /proc/stat within 1 MiB; start times fall back to /proc/uptime\n",
                );
            }
            return 0;
        }
    };
    for line in text.split(|b| *b == b'\n') {
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

/// The directories that may hold this process's cgroup memory files.
///
/// The namespace-relative path from `/proc/self/cgroup` comes first, then the
/// controller mounts as a fallback. `memory.max` is v2 and
/// `memory.limit_in_bytes` is v1, so the caller tries both names in each
/// directory.
fn cgroup_dirs() -> Vec<Vec<u8>> {
    let mut dirs: Vec<Vec<u8>> = Vec::new();
    let mut buf = [0u8; 4096];
    if let Some(n) = sys::read_file(b"/proc/self/cgroup", &mut buf) {
        for line in buf[..n].split(|b| *b == b'\n') {
            if let Some(path) = line.strip_prefix(b"0::") {
                let mut p = b"/sys/fs/cgroup".to_vec();
                p.extend_from_slice(path);
                dirs.push(p);
            } else if line.starts_with(b"1:memory:") || str::find(line, b":memory:").is_some() {
                if let Some(i) = line.iter().rposition(|b| *b == b':') {
                    let mut p = b"/sys/fs/cgroup/memory".to_vec();
                    p.extend_from_slice(&line[i + 1..]);
                    dirs.push(p);
                }
            }
        }
    }
    dirs.push(b"/sys/fs/cgroup".to_vec());
    dirs.push(b"/sys/fs/cgroup/memory".to_vec());
    dirs
}

/// One cgroup memory field in kB. `None` means no file in this directory;
/// `Some(None)` means the file says `max` (v2) or the v1 unlimited sentinel.
fn cgroup_mem_field(dir: &[u8], names: &[&[u8]]) -> Option<Option<u64>> {
    for name in names {
        let mut p = dir.to_vec();
        p.push(b'/');
        p.extend_from_slice(name);
        let mut v = [0u8; 64];
        let Some(n) = sys::read_file(&p, &mut v) else {
            continue;
        };
        let s = str::trim(&v[..n]);
        if s == b"max" {
            return Some(None);
        }
        if let Some(x) = str::parse_u64(s) {
            // v1 reports "unlimited" as a number near u64::MAX.
            if x >= (1u64 << 60) {
                return Some(None);
            }
            return Some(Some(x / 1024));
        }
        return Some(None);
    }
    None
}

/// The memory limit of the current cgroup, in kB, or 0 when unlimited.
pub fn cgroup_mem_limit_kb() -> u64 {
    for dir in cgroup_dirs() {
        if let Some(v) = cgroup_mem_field(&dir, &[b"memory.max", b"memory.limit_in_bytes"]) {
            return v.unwrap_or(0);
        }
    }
    0
}

/// Memory already charged to the current cgroup, in kB.
///
/// `None` means the field could not be read. That is not the same as zero:
/// a guard that treats it as zero accepts a request larger than the cgroup's
/// remaining headroom and hands the caller to the OOM killer.
pub fn cgroup_mem_current_kb() -> Option<u64> {
    for dir in cgroup_dirs() {
        if let Some(v) = cgroup_mem_field(&dir, &[b"memory.current", b"memory.usage_in_bytes"]) {
            return v;
        }
    }
    None
}
