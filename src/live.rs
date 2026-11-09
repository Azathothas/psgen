//! Reading the real process table for `table --live` and `inject --table`.

use crate::gen::Proc;
use crate::str::{self, Buf};
use crate::sys;
use crate::users;
use crate::util;

pub struct StatInfo {
    pub pid: i32,
    pub comm: Vec<u8>,
    pub state: u8,
    pub pgrp: i64,
    pub session: i64,
    pub tty_nr: i64,
    pub tpgid: i64,
    pub num_threads: i64,
    pub utime: u64,
    pub stime: u64,
    pub starttime: u64,
}

fn field<'a>(fields: &'a [&'a [u8]], i: usize) -> &'a [u8] {
    fields.get(i).copied().unwrap_or(b"0")
}

pub fn read_stat(pid: i32) -> Option<StatInfo> {
    let mut path = b"/proc/".to_vec();
    let mut b = Buf::new();
    b.push_u64(pid as u64);
    path.extend_from_slice(b.as_bytes());
    path.extend_from_slice(b"/stat");
    let mut buf = [0u8; 4096];
    let n = sys::read_file(&path, &mut buf)?;
    let s = &buf[..n];
    let open = s.iter().position(|b| *b == b'(')?;
    let close = s.iter().rposition(|b| *b == b')')?;
    let comm = s[open + 1..close].to_vec();
    let rest = &s[close + 1..];
    let fields: Vec<&[u8]> = rest
        .split(|b| *b == b' ')
        .filter(|x| !x.is_empty())
        .collect();
    if fields.len() < 20 {
        return None;
    }
    Some(StatInfo {
        pid,
        comm,
        state: field(&fields, 0).first().copied().unwrap_or(b'?'),
        pgrp: str::parse_i64(field(&fields, 2)).unwrap_or(0),
        session: str::parse_i64(field(&fields, 3)).unwrap_or(0),
        tty_nr: str::parse_i64(field(&fields, 4)).unwrap_or(0),
        tpgid: str::parse_i64(field(&fields, 5)).unwrap_or(-1),
        utime: str::parse_u64(field(&fields, 11)).unwrap_or(0),
        stime: str::parse_u64(field(&fields, 12)).unwrap_or(0),
        num_threads: str::parse_i64(field(&fields, 17)).unwrap_or(1),
        starttime: str::parse_u64(field(&fields, 19)).unwrap_or(0),
    })
}

pub fn read_comm(pid: i32) -> Option<Vec<u8>> {
    let mut path = b"/proc/".to_vec();
    let mut b = Buf::new();
    b.push_u64(pid as u64);
    path.extend_from_slice(b.as_bytes());
    path.extend_from_slice(b"/comm");
    let mut buf = [0u8; 64];
    let n = sys::read_file(&path, &mut buf)?;
    Some(str::trim(&buf[..n]).to_vec())
}

pub fn read_starttime(pid: i32) -> Option<u64> {
    read_stat(pid).map(|s| s.starttime)
}

pub fn read_sizes(pid: i32) -> Option<(u64, u64)> {
    Some((
        status_value(pid, b"VmSize:")?,
        status_value(pid, b"VmRSS:")?,
    ))
}

fn status_value(pid: i32, key: &[u8]) -> Option<u64> {
    let mut path = b"/proc/".to_vec();
    let mut b = Buf::new();
    b.push_u64(pid as u64);
    path.extend_from_slice(b.as_bytes());
    path.extend_from_slice(b"/status");
    let mut buf = [0u8; 8192];
    let n = sys::read_file(&path, &mut buf)?;
    for line in buf[..n].split(|b| *b == b'\n') {
        if str::starts_with(line, key) {
            let rest = str::trim(&line[key.len()..]);
            let mut end = 0;
            while end < rest.len() && rest[end].is_ascii_digit() {
                end += 1;
            }
            return str::parse_u64(&rest[..end]);
        }
    }
    None
}

fn status_uid(pid: i32) -> Option<u32> {
    let mut path = b"/proc/".to_vec();
    let mut b = Buf::new();
    b.push_u64(pid as u64);
    path.extend_from_slice(b.as_bytes());
    path.extend_from_slice(b"/status");
    let mut buf = [0u8; 8192];
    let n = sys::read_file(&path, &mut buf)?;
    for line in buf[..n].split(|b| *b == b'\n') {
        if str::starts_with(line, b"Uid:") {
            let rest = str::trim(&line[4..]);
            let mut end = 0;
            while end < rest.len() && rest[end].is_ascii_digit() {
                end += 1;
            }
            return str::parse_u64(&rest[..end]).map(|v| v as u32);
        }
    }
    None
}

fn read_cmdline(pid: i32) -> Vec<u8> {
    let mut path = b"/proc/".to_vec();
    let mut b = Buf::new();
    b.push_u64(pid as u64);
    path.extend_from_slice(b.as_bytes());
    path.extend_from_slice(b"/cmdline");
    let mut buf = [0u8; 8192];
    let n = match sys::read_file(&path, &mut buf) {
        Some(n) => n,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(n);
    for b in &buf[..n] {
        if *b == 0 {
            if out.last() != Some(&b' ') {
                out.push(b' ');
            }
        } else {
            out.push(*b);
        }
    }
    str::trim(&out).to_vec()
}

fn tty_name(tty_nr: i64) -> Vec<u8> {
    if tty_nr <= 0 {
        return Vec::new();
    }
    let n = tty_nr as u32;
    let major = (n >> 8) & 0xfff;
    let minor = (n & 0xff) | ((n >> 12) & 0xfff00);
    if (136..=143).contains(&major) {
        let idx = (major - 136) * 256 + minor;
        let mut b = Buf::new();
        b.push_str("pts/");
        b.push_u64(idx as u64);
        b.v
    } else if major == 4 {
        let mut b = Buf::new();
        // Minor 0..63 is ttyN. Minor 64.. are the serial ports, which
        // Linux names ttyS0, ttyS1 and so on. Printing tty64 for 4:64
        // named a device that does not exist.
        if minor >= 64 {
            b.push_str("ttyS");
            b.push_u64((minor - 64) as u64);
        } else {
            b.push_str("tty");
            b.push_u64(minor as u64);
        }
        b.v
    } else {
        Vec::new()
    }
}

fn user_name(uid: u32) -> Vec<u8> {
    if let Some((name, _)) = users::lookup_uid(uid) {
        name
    } else {
        let mut b = Buf::new();
        b.push_u64(uid as u64);
        b.v
    }
}

pub fn read_pid(pid: i32, btime: u64, hz: u64, now: u64, mem_total: u64) -> Option<Proc> {
    let stat = read_stat(pid)?;
    let uid = status_uid(pid).unwrap_or(0);
    let vsz = status_value(pid, b"VmSize:").unwrap_or(0).min(u32::MAX as u64) as u32;
    let rss = status_value(pid, b"VmRSS:").unwrap_or(0).min(u32::MAX as u64) as u32;
    let cmd = read_cmdline(pid);
    let cmd = if cmd.is_empty() {
        let mut b = Buf::new();
        b.push(b'[');
        b.push_bytes(&stat.comm);
        b.push(b']');
        b.v
    } else {
        cmd
    };
    let start_epoch = btime.saturating_add(stat.starttime / hz.max(1));
    let age = now.saturating_sub(start_epoch);
    let now_ticks = now.saturating_mul(hz);
    let start_ticks = btime.saturating_mul(hz).saturating_add(stat.starttime);
    let elapsed_ticks = now_ticks.saturating_sub(start_ticks);
    let ticks = stat.utime.saturating_add(stat.stime);
    let cpu = if elapsed_ticks == 0 {
        0
    } else {
        ((ticks.saturating_mul(1000) / elapsed_ticks).min(65535)) as u16
    };
    let mut st = Vec::with_capacity(4);
    st.push(stat.state);
    if stat.pid as i64 == stat.session {
        st.push(b's');
    }
    if stat.num_threads > 1 {
        st.push(b'l');
    }
    if stat.tpgid > 0 && stat.tpgid == stat.pgrp {
        st.push(b'+');
    }
    let _ = mem_total;
    Some(Proc {
        cmd,
        tty: tty_name(stat.tty_nr),
        user: user_name(uid),
        uid,
        gid: 0,
        vsz,
        rss,
        cpu,
        flags: 0,
        age,
        pid,
        tmpl: 0,
        parent: None,
        stat_override: Some(st),
    })
}

fn boot_time(now: u64) -> u64 {
    let b = util::boot_time_secs();
    if b == 0 {
        now.saturating_sub(util::uptime_secs())
    } else {
        b
    }
}

pub fn read_all() -> Vec<Proc> {
    let hz = sys::hz();
    let now = sys::now_secs();
    let btime = boot_time(now);
    let mem_total = util::mem_total_kb();
    let mut pids: Vec<i32> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if let Ok(pid) = name.parse::<i32>() {
                    pids.push(pid);
                }
            }
        }
    }
    pids.sort_unstable();
    let mut rows = Vec::with_capacity(pids.len());
    for pid in pids {
        if let Some(p) = read_pid(pid, btime, hz, now, mem_total) {
            rows.push(p);
        }
    }
    rows
}

pub fn read_pids(pids: &[i32]) -> Vec<Proc> {
    let hz = sys::hz();
    let now = sys::now_secs();
    let btime = boot_time(now);
    let mem_total = util::mem_total_kb();
    let mut rows = Vec::with_capacity(pids.len());
    for pid in pids {
        if let Some(p) = read_pid(*pid, btime, hz, now, mem_total) {
            rows.push(p);
        }
    }
    rows
}
