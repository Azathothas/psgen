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

/// Parse the `btime <epoch>` entry from `/proc/stat`.
pub fn parse_btime(raw: &[u8]) -> Option<u64> {
    for line in raw.split(|b| *b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"btime ") {
            return str::parse_u64(rest);
        }
    }
    None
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
                    b"psgen: cannot read /proc/stat within 1 MiB; start times fall back to CLOCK_BOOTTIME\n",
                );
            }
            return 0;
        }
    };
    parse_btime(&text).unwrap_or(0)
}

pub fn boot_id() -> Vec<u8> {
    let mut buf = [0u8; 128];
    match sys::read_file(b"/proc/sys/kernel/random/boot_id", &mut buf) {
        Some(n) => str::trim(&buf[..n]).to_vec(),
        None => Vec::new(),
    }
}

/// Memory constraints discovered by walking this process's cgroup hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupMem {
    /// Tightest finite memory limit across the cgroup hierarchy, in KiB.
    pub limit_kb: u64,
    /// Minimum remaining headroom (`limit_kb.saturating_sub(current_kb)`)
    /// across every constrained ancestor in the hierarchy, or `None` if
    /// any constrained ancestor's current usage could not be read.
    pub headroom_kb: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CgroupVer {
    V2,
    V1,
}

/// Parse `/proc/self/cgroup` into `(version, relative_path)` entries for the
/// unified v2 hierarchy and any v1 hierarchy that mounts `memory` (including
/// co-mounted controllers such as `4:cpu,memory:/...`).
fn parse_proc_cgroup(raw: &[u8]) -> Vec<(CgroupVer, Vec<u8>)> {
    let mut out = Vec::new();
    for line in raw.split(|b| *b == b'\n') {
        let line = str::trim(line);
        if line.is_empty() {
            continue;
        }
        let Some(c1) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let rest = &line[c1 + 1..];
        let Some(c2) = rest.iter().position(|b| *b == b':') else {
            continue;
        };
        let id = &line[..c1];
        let controllers = &rest[..c2];
        let path = &rest[c2 + 1..];
        if id == b"0" && controllers.is_empty() {
            out.push((CgroupVer::V2, path.to_vec()));
        } else if controllers.split(|b| *b == b',').any(|c| c == b"memory") {
            out.push((CgroupVer::V1, path.to_vec()));
        }
    }
    out
}

/// Every directory from `root/rel` up to `root`, leaf first.
fn cgroup_ancestors(root: &[u8], rel: &[u8]) -> Vec<Vec<u8>> {
    let root = root.strip_suffix(b"/").unwrap_or(root);
    let mut comps: Vec<&[u8]> = Vec::new();
    for part in rel.split(|b| *b == b'/') {
        if part.is_empty() || part == b"." || part == b".." {
            continue;
        }
        comps.push(part);
    }
    let mut dirs = Vec::with_capacity(comps.len() + 1);
    for depth in (0..=comps.len()).rev() {
        let mut p = if root.is_empty() {
            b"/".to_vec()
        } else {
            root.to_vec()
        };
        for c in &comps[..depth] {
            if !p.ends_with(b"/") {
                p.push(b'/');
            }
            p.extend_from_slice(c);
        }
        dirs.push(p);
    }
    dirs
}

fn cgroup_entries(proc_cgroup: &[u8]) -> Vec<(CgroupVer, Vec<u8>)> {
    let mut entries = parse_proc_cgroup(proc_cgroup);
    if !entries.iter().any(|(v, _)| *v == CgroupVer::V2) {
        entries.push((CgroupVer::V2, b"/".to_vec()));
    }
    if !entries.iter().any(|(v, _)| *v == CgroupVer::V1) {
        entries.push((CgroupVer::V1, b"/".to_vec()));
    }
    entries
}

fn read_cgroup_limit_kb(dir: &[u8], name: &[u8]) -> Option<u64> {
    let mut p = dir.to_vec();
    if !p.ends_with(b"/") {
        p.push(b'/');
    }
    p.extend_from_slice(name);
    let mut v = [0u8; 64];
    let n = sys::read_file(&p, &mut v)?;
    let s = str::trim(&v[..n]);
    if s == b"max" {
        return None;
    }
    let x = str::parse_u64(s)?;
    // v1 reports "unlimited" as a number near u64::MAX.
    if x >= (1u64 << 60) {
        return None;
    }
    Some(x / 1024)
}

fn read_cgroup_current_kb(dir: &[u8], name: &[u8]) -> Option<u64> {
    let mut p = dir.to_vec();
    if !p.ends_with(b"/") {
        p.push(b'/');
    }
    p.extend_from_slice(name);
    let mut v = [0u8; 64];
    let n = sys::read_file(&p, &mut v)?;
    let s = str::trim(&v[..n]);
    str::parse_u64(s).map(|x| x / 1024)
}

fn cgroup_mem_limits_in(proc_cgroup: &[u8], v2_root: &[u8], v1_root: &[u8]) -> Option<CgroupMem> {
    let mut min_limit: Option<u64> = None;
    let mut min_headroom: Option<u64> = None;
    let mut any_current_missing = false;

    for (ver, rel) in cgroup_entries(proc_cgroup) {
        let (root, limit_file, current_file) = match ver {
            CgroupVer::V2 => (v2_root, &b"memory.max"[..], &b"memory.current"[..]),
            CgroupVer::V1 => (
                v1_root,
                &b"memory.limit_in_bytes"[..],
                &b"memory.usage_in_bytes"[..],
            ),
        };
        for dir in cgroup_ancestors(root, &rel) {
            let Some(lim) = read_cgroup_limit_kb(&dir, limit_file) else {
                continue;
            };
            min_limit = Some(match min_limit {
                Some(prev) => prev.min(lim),
                None => lim,
            });
            match read_cgroup_current_kb(&dir, current_file) {
                Some(cur) => {
                    let head = lim.saturating_sub(cur);
                    min_headroom = Some(match min_headroom {
                        Some(prev) => prev.min(head),
                        None => head,
                    });
                }
                None => {
                    any_current_missing = true;
                }
            }
        }
    }

    let limit_kb = min_limit?;
    let headroom_kb = if any_current_missing {
        None
    } else {
        min_headroom
    };
    Some(CgroupMem {
        limit_kb,
        headroom_kb,
    })
}

fn read_proc_cgroup() -> Vec<u8> {
    sys::read_file_nofollow(b"/proc/self/cgroup", 65_536).unwrap_or_default()
}

/// Tightest memory limit and minimum headroom across this process's cgroup
/// hierarchy, or `None` when no ancestor sets a finite limit.
pub fn cgroup_mem_limits() -> Option<CgroupMem> {
    let raw = read_proc_cgroup();
    cgroup_mem_limits_in(&raw, b"/sys/fs/cgroup", b"/sys/fs/cgroup/memory")
}

/// The memory limit of the current cgroup hierarchy, in kB, or 0 when unlimited.
pub fn cgroup_mem_limit_kb() -> u64 {
    cgroup_mem_limits().map(|c| c.limit_kb).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("psgen-util-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp test dir");
        p
    }

    #[test]
    fn parse_btime_finds_entry_past_16_kib() {
        let mut raw = Vec::new();
        for cpu in 0..256 {
            raw.extend_from_slice(format!("cpu{cpu} 100 20 300 40000 50 0 10 0 0 0\n").as_bytes());
        }
        raw.extend_from_slice(b"intr");
        for _ in 0..4000 {
            raw.extend_from_slice(b" 0");
        }
        raw.extend_from_slice(b"\nctxt 987654321\nbtime 1700000123\nprocesses 42000\n");
        assert!(raw.len() > 16 * 1024);
        assert_eq!(parse_btime(&raw), Some(1_700_000_123));
        assert_eq!(parse_btime(b"cpu 1 2 3\nprocesses 10\n"), None);
    }

    #[test]
    fn parse_proc_cgroup_handles_v2_and_comounted_v1() {
        let raw = b"\
12:cpu,cpuacct:/ignored
4:cpu,memory:/kubepods/burstable/pod1
5:memory,blkio:/nested:colon/leaf
1:name=systemd:/user.slice
0::/user.slice/user-1000.slice/session-1.scope
";
        let got = parse_proc_cgroup(raw);
        assert_eq!(
            got,
            vec![
                (CgroupVer::V1, b"/kubepods/burstable/pod1".to_vec()),
                (CgroupVer::V1, b"/nested:colon/leaf".to_vec()),
                (
                    CgroupVer::V2,
                    b"/user.slice/user-1000.slice/session-1.scope".to_vec()
                ),
            ]
        );
    }

    #[test]
    fn cgroup_ancestor_walk_finds_parent_limit_when_child_is_max() {
        let base = test_dir("ancestor-walk");
        let v2 = base.join("v2");
        let v1 = base.join("v1");
        let parent = v2.join("parent");
        let child = parent.join("child");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::create_dir_all(&v1).unwrap();

        // Child is unlimited (`max`), parent sets 100 MiB with 40 MiB used.
        std::fs::write(child.join("memory.max"), "max\n").unwrap();
        std::fs::write(child.join("memory.current"), "10485760\n").unwrap();
        std::fs::write(parent.join("memory.max"), "104857600\n").unwrap();
        std::fs::write(parent.join("memory.current"), "41943040\n").unwrap();

        let proc_cg = b"0::/parent/child\n";
        let res = cgroup_mem_limits_in(
            proc_cg,
            v2.as_os_str().as_bytes(),
            v1.as_os_str().as_bytes(),
        );
        assert_eq!(
            res,
            Some(CgroupMem {
                limit_kb: 102_400,
                headroom_kb: Some(61_440),
            })
        );

        // Tighter headroom on an ancestor with a larger limit wins for headroom
        // while the smaller limit wins for limit_kb.
        std::fs::write(child.join("memory.max"), "104857600\n").unwrap(); // 100 MiB
        std::fs::write(child.join("memory.current"), "20971520\n").unwrap(); // 20 MiB -> 80 MiB headroom
        std::fs::write(parent.join("memory.max"), "157286400\n").unwrap(); // 150 MiB
        std::fs::write(parent.join("memory.current"), "146800640\n").unwrap(); // 140 MiB -> 10 MiB headroom
        let res2 = cgroup_mem_limits_in(
            proc_cg,
            v2.as_os_str().as_bytes(),
            v1.as_os_str().as_bytes(),
        );
        assert_eq!(
            res2,
            Some(CgroupMem {
                limit_kb: 102_400,
                headroom_kb: Some(10_240),
            })
        );

        // Co-mounted v1 memory hierarchy works the same way.
        let v1_parent = v1.join("slice");
        let v1_child = v1_parent.join("job");
        std::fs::create_dir_all(&v1_child).unwrap();
        std::fs::write(
            v1_child.join("memory.limit_in_bytes"),
            "9223372036854771712\n",
        )
        .unwrap();
        std::fs::write(v1_parent.join("memory.limit_in_bytes"), "67108864\n").unwrap(); // 64 MiB
        std::fs::write(v1_parent.join("memory.usage_in_bytes"), "16777216\n").unwrap(); // 16 MiB
        let res_v1 = cgroup_mem_limits_in(
            b"4:cpu,memory:/slice/job\n",
            v2.as_os_str().as_bytes(),
            v1.as_os_str().as_bytes(),
        );
        assert_eq!(
            res_v1,
            Some(CgroupMem {
                limit_kb: 65_536,
                headroom_kb: Some(49_152),
            })
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn cgroup_current_at_or_above_limit_yields_zero_headroom() {
        let base = test_dir("zero-headroom");
        let v2 = base.join("v2");
        let v1 = base.join("v1");
        let leaf = v2.join("app");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::create_dir_all(&v1).unwrap();

        std::fs::write(leaf.join("memory.max"), "52428800\n").unwrap(); // 50 MiB
        std::fs::write(leaf.join("memory.current"), "62914560\n").unwrap(); // 60 MiB
        let over = cgroup_mem_limits_in(
            b"0::/app\n",
            v2.as_os_str().as_bytes(),
            v1.as_os_str().as_bytes(),
        );
        assert_eq!(
            over,
            Some(CgroupMem {
                limit_kb: 51_200,
                headroom_kb: Some(0),
            })
        );

        std::fs::write(leaf.join("memory.current"), "52428800\n").unwrap(); // equal
        let equal = cgroup_mem_limits_in(
            b"0::/app\n",
            v2.as_os_str().as_bytes(),
            v1.as_os_str().as_bytes(),
        );
        assert_eq!(
            equal,
            Some(CgroupMem {
                limit_kb: 51_200,
                headroom_kb: Some(0),
            })
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn cgroup_missing_current_fails_closed_with_none_headroom() {
        let base = test_dir("missing-current");
        let v2 = base.join("v2");
        let v1 = base.join("v1");
        let parent = v2.join("parent");
        let child = parent.join("child");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::create_dir_all(&v1).unwrap();

        // Child has both limit and current, but constrained parent is missing
        // memory.current; must fail closed with headroom_kb = None.
        std::fs::write(child.join("memory.max"), "104857600\n").unwrap();
        std::fs::write(child.join("memory.current"), "10485760\n").unwrap();
        std::fs::write(parent.join("memory.max"), "209715200\n").unwrap();

        let res = cgroup_mem_limits_in(
            b"0::/parent/child\n",
            v2.as_os_str().as_bytes(),
            v1.as_os_str().as_bytes(),
        );
        assert_eq!(
            res,
            Some(CgroupMem {
                limit_kb: 102_400,
                headroom_kb: None,
            })
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
