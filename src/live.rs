//! Reading the real process table for `table --live` and `inject --table`.

use crate::gen::Proc;
use crate::str::{self, Buf};
use crate::sys;
use crate::users;
use crate::util;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// `ps` bounds every printed field by its `OUTBUF_SIZE` buffer, so the whole
/// row it writes excluding the line break is at most this many bytes. A longer
/// command line is truncated, never replaced by `[comm]`: a row with arguments
/// is not a kernel thread.
pub const ROW_BYTES: usize = 131_072;

/// The same bound on the command line alone, used while reading: `/proc` can
/// hold much more than the row can print.
const CMD_READ: u64 = 512 * 1024;

pub struct StatInfo {
    pub pid: i32,
    pub ppid: i64,
    pub comm: Vec<u8>,
    pub state: u8,
    pub pgrp: i64,
    pub session: i64,
    pub tty_nr: i64,
    pub tpgid: i64,
    pub nice: i64,
    pub num_threads: i64,
    pub utime: u64,
    pub stime: u64,
    pub starttime: u64,
}

fn field<'a>(fields: &'a [&'a [u8]], i: usize) -> &'a [u8] {
    fields.get(i).copied().unwrap_or(b"0")
}

fn proc_path(pid: i32, leaf: &[u8]) -> Vec<u8> {
    let mut path = b"/proc/".to_vec();
    let mut b = Buf::new();
    b.push_u64(pid as u64);
    path.extend_from_slice(b.as_bytes());
    path.extend_from_slice(leaf);
    path
}

pub fn read_stat(pid: i32) -> Option<StatInfo> {
    let path = proc_path(pid, b"/stat");
    let mut buf = [0u8; 4096];
    let n = sys::read_file(&path, &mut buf)?;
    let s = &buf[..n];
    let open = s.iter().position(|b| *b == b'(')?;
    let close = s.iter().rposition(|b| *b == b')')?;
    let comm = s[open + 1..close].to_vec();
    // The fields after the parenthesised comm, so index 0 is the state. `nice`
    // is `proc(5)`'s 19th field and index 16 here, `starttime` the 22nd and
    // index 19.
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
        ppid: str::parse_i64(field(&fields, 1)).unwrap_or(0),
        comm,
        state: field(&fields, 0).first().copied().unwrap_or(b'?'),
        pgrp: str::parse_i64(field(&fields, 2)).unwrap_or(0),
        session: str::parse_i64(field(&fields, 3)).unwrap_or(0),
        tty_nr: str::parse_i64(field(&fields, 4)).unwrap_or(0),
        tpgid: str::parse_i64(field(&fields, 5)).unwrap_or(-1),
        nice: str::parse_i64(field(&fields, 16)).unwrap_or(0),
        utime: str::parse_u64(field(&fields, 11)).unwrap_or(0),
        stime: str::parse_u64(field(&fields, 12)).unwrap_or(0),
        num_threads: str::parse_i64(field(&fields, 17)).unwrap_or(1),
        starttime: str::parse_u64(field(&fields, 19)).unwrap_or(0),
    })
}

pub fn read_comm(pid: i32) -> Option<Vec<u8>> {
    let path = proc_path(pid, b"/comm");
    let mut buf = [0u8; 64];
    let n = sys::read_file(&path, &mut buf)?;
    Some(str::trim(&buf[..n]).to_vec())
}

pub fn read_starttime(pid: i32) -> Option<u64> {
    read_stat(pid).map(|s| s.starttime)
}

pub fn read_sizes(pid: i32) -> Option<(u64, u64)> {
    let st = read_status(pid)?;
    Some((st.vsz, st.rss))
}

/// The `/proc/PID/status` fields a row needs, from one read: the sizes, the
/// effective uid `ps aux` shows as USER, and the locked size `pr_stat` shows as
/// `L`.
struct Status {
    vsz: u64,
    rss: u64,
    euid: u32,
    vmlck: u64,
}

fn status_number(rest: &[u8]) -> u64 {
    let rest = str::trim(rest);
    let mut end = 0;
    while end < rest.len() && rest[end].is_ascii_digit() {
        end += 1;
    }
    str::parse_u64(&rest[..end]).unwrap_or(0)
}

fn read_status(pid: i32) -> Option<Status> {
    let path = proc_path(pid, b"/status");
    let mut buf = [0u8; 8192];
    let n = sys::read_file(&path, &mut buf)?;
    let mut st = Status {
        vsz: 0,
        rss: 0,
        euid: 0,
        vmlck: 0,
    };
    for line in buf[..n].split(|b| *b == b'\n') {
        if str::starts_with(line, b"VmSize:") {
            st.vsz = status_number(&line[7..]);
        } else if str::starts_with(line, b"VmRSS:") {
            st.rss = status_number(&line[6..]);
        } else if str::starts_with(line, b"VmLck:") {
            st.vmlck = status_number(&line[6..]);
        } else if str::starts_with(line, b"Uid:") {
            // `Uid: real effective saved fs`, whitespace separated. `ps aux`
            // USER is procps `pr_euser`, so the *effective* uid is the one to
            // show; the first field is the real uid.
            let mut it = str::trim(&line[4..])
                .split(|b| *b == b' ' || *b == b'\t')
                .filter(|f| !f.is_empty());
            it.next();
            if let Some(e) = it.next().and_then(str::parse_u64) {
                st.euid = e as u32;
            }
        }
    }
    Some(st)
}

/// `major(3)`: the kernel packs a device number as 12 bits of major above 20
/// bits of minor.
fn dev_major(dev: u64) -> u32 {
    ((dev >> 8) & 0xfff) as u32
}

fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & 0xfff00)) as u32
}

fn rdev_of(path: &[u8]) -> Option<(u32, u32)> {
    let meta = std::fs::metadata(Path::new(OsStr::from_bytes(path))).ok()?;
    let dev = meta.rdev();
    Some((dev_major(dev), dev_minor(dev)))
}

/// One line of `/proc/tty/drivers`: `name /dev/prefix major lo-hi type`.
struct TtyDriver {
    /// The `/dev` prefix without `/dev/`, e.g. `hvc`, `pts` or `ttyS`.
    name: Vec<u8>,
    /// True when the prefix ended in `%d`, i.e. one node for the whole range.
    devfs: bool,
    major: u32,
    lo: u32,
    hi: u32,
}

/// The kernel's own device table, newest entry first: procps prepends each
/// line, so the first entry that matches a `(major, minor)` pair is the last
/// one in the file to cover it.
fn tty_drivers() -> Vec<TtyDriver> {
    let mut buf = [0u8; 10000];
    let n = match sys::read_file(b"/proc/tty/drivers", &mut buf) {
        Some(n) => n,
        None => return Vec::new(),
    };
    let mut out: Vec<TtyDriver> = Vec::new();
    for line in buf[..n].split(|b| *b == b'\n') {
        let f: Vec<&[u8]> = line
            .split(|b| *b == b' ')
            .filter(|x| !x.is_empty())
            .collect();
        if f.len() < 4 {
            continue;
        }
        let prefix = match f[1].strip_prefix(b"/dev/".as_slice()) {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };
        let major = match str::parse_u64(f[2]) {
            Some(v) => v as u32,
            None => continue,
        };
        let (lo, hi) = match str::find(f[3], b"-") {
            Some(i) => (
                str::parse_u64(&f[3][..i]).unwrap_or(0) as u32,
                str::parse_u64(&f[3][i + 1..]).unwrap_or(0) as u32,
            ),
            None => {
                let v = str::parse_u64(f[3]).unwrap_or(0) as u32;
                (v, v)
            }
        };
        let (name, devfs) = match prefix.strip_suffix(b"%d".as_slice()) {
            Some(p) => (p.to_vec(), true),
            None => (prefix.to_vec(), false),
        };
        out.push(TtyDriver {
            name,
            devfs,
            major,
            lo,
            hi,
        });
    }
    out.reverse();
    out
}

fn dev_path(name: &[u8], rest: Option<&[u8]>) -> Vec<u8> {
    let mut p = b"/dev/".to_vec();
    p.extend_from_slice(name);
    if let Some(r) = rest {
        p.extend_from_slice(r);
    }
    p
}

/// procps `driver_name`: the name from `/proc/tty/drivers`, checked against the
/// device the kernel actually has at that path, so a stale table cannot invent
/// a name.
fn driver_name(major: u32, minor: u32, drivers: &[TtyDriver]) -> Option<Vec<u8>> {
    let num = minor.to_string();
    for d in drivers {
        if d.major != major || minor < d.lo || minor > d.hi {
            continue;
        }
        // procps tries the numbered node, then the directory form, then the
        // bare prefix, and takes the first whose device number agrees.
        let mut candidates: Vec<Vec<u8>> = Vec::with_capacity(3);
        if !d.devfs {
            candidates.push(dev_path(&d.name, Some(num.as_bytes())));
        }
        candidates.push(dev_path(&d.name, Some(b"/")));
        if let Some(last) = candidates.last_mut() {
            last.extend_from_slice(num.as_bytes());
        }
        if !d.devfs {
            candidates.push(dev_path(&d.name, None));
        }
        for c in candidates {
            if rdev_of(&c) == Some((major, minor)) {
                return Some(c[5..].to_vec());
            }
        }
    }
    None
}

/// procps `link_name`: the path a process's own descriptor points at, when its
/// device number is the one asked for. `ps` tries `fd/2` first and `fd/255`
/// last, because a shell keeps its terminal on a high descriptor.
fn link_name(pid: i32, major: u32, minor: u32, leaf: &[u8]) -> Option<Vec<u8>> {
    let path = proc_path(pid, leaf);
    let target = sys::read_link(&path)?;
    if target.first() != Some(&b'/') {
        return None;
    }
    if rdev_of(&target) != Some((major, minor)) {
        return None;
    }
    Some(match target.strip_prefix(b"/dev/".as_slice()) {
        Some(rest) => rest.to_vec(),
        None => target,
    })
}

/// The names a device number has without `/proc/tty/drivers`: procps
/// `guess_name`, limited to the shapes a Linux host has.
fn guess_tty(major: u32, minor: u32) -> Vec<u8> {
    let mut b = Buf::new();
    if (136..=143).contains(&major) {
        b.push_str("pts/");
        b.push_u64(((major - 136) * 256 + minor) as u64);
    } else if major == 4 && minor >= 64 {
        b.push_str("ttyS");
        b.push_u64((minor - 64) as u64);
    } else if major == 4 {
        b.push_str("tty");
        b.push_u64(minor as u64);
    }
    b.v
}

/// procps `dev_to_tty` with `ABBREV_DEV`: the name of the device a row's
/// controlling terminal refers to, or empty when there is none.
fn tty_name(pid: i32, tty_nr: i64, drivers: &[TtyDriver]) -> Vec<u8> {
    if tty_nr <= 0 {
        return Vec::new();
    }
    let n = tty_nr as u32;
    let major = (n >> 8) & 0xfff;
    let minor = (n & 0xff) | ((n >> 12) & 0xfff00);
    if let Some(name) = driver_name(major, minor, drivers) {
        return name;
    }
    if let Some(name) = link_name(pid, major, minor, b"/fd/2") {
        return name;
    }
    let guessed = guess_tty(major, minor);
    if !guessed.is_empty() {
        return guessed;
    }
    link_name(pid, major, minor, b"/fd/255").unwrap_or_default()
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

/// `/proc/uptime` in nanoseconds. Its fractional field is CLOCK_BOOTTIME with
/// more resolution than `/proc/stat`'s whole-second `btime`, and `%CPU`'s
/// elapsed-time denominator needs that resolution.
fn uptime_ns() -> u64 {
    let mut buf = [0u8; 256];
    let n = match sys::read_file(b"/proc/uptime", &mut buf) {
        Some(n) => n,
        None => return 0,
    };
    let s = &buf[..n];
    let mut secs = 0u64;
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        secs = secs.saturating_mul(10).saturating_add((s[i] - b'0') as u64);
        i += 1;
    }
    let mut frac = 0u64;
    let mut scale = 100_000_000u64;
    if s.get(i) == Some(&b'.') {
        i += 1;
        while i < s.len() && s[i].is_ascii_digit() {
            frac = frac.saturating_add((s[i] - b'0') as u64 * scale);
            scale /= 10;
            i += 1;
        }
    }
    secs.saturating_mul(1_000_000_000).saturating_add(frac)
}

/// Whether a code point is printable, for the points that reach the second
/// pass of the escape.
///
/// `iswprint` needs a `wchar_t` and a loaded locale, so this covers the
/// non-printable classes a command line actually carries: the line and
/// paragraph separators, and the Unicode noncharacters. A code point that is
/// merely unassigned in one glibc version is not worth guessing at.
fn wc_is_printable(wc: u32) -> bool {
    if wc == 0x2028 || wc == 0x2029 {
        return false;
    }
    // U+FDD0..U+FDEF and U+xFFFE, U+xFFFF in every plane.
    !((0xfdd0..=0xfdef).contains(&wc) || (wc & 0xfffe) == 0xfffe)
}

/// procps `u8charlen`, the first pass: one `?` for every byte that is not part
/// of a valid UTF-8 sequence, and the valid sequences copied through.
///
/// The ranges are procps' own, including the private-use areas, which it
/// escapes one byte at a time rather than one code point at a time.
fn u8_first_pass(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len().min(CMD_READ as usize));
    let mut i = 0;
    while i < raw.len() {
        let b0 = raw[i];
        let cont = |k: usize| raw.get(i + k).map(|c| c & 0xc0 == 0x80).unwrap_or(false);
        let mut n = 0usize;
        let mut esc = true;
        if b0 <= 0x7f {
            n = 1;
            esc = b0 < 0x20 || b0 == 0x7f;
        } else if cont(1) {
            if (0xc2..=0xdf).contains(&b0) {
                n = 2;
                // U+0080..U+009F are the C1 controls.
                esc = b0 == 0xc2 && (0x80..=0x9f).contains(&raw[i + 1]);
            } else if cont(2) {
                let pua = ((b0 as u32) << 16) + ((raw[i + 1] as u32) << 8) + raw[i + 2] as u32;
                let x = ((b0 as u32) << 6) | (raw[i + 1] as u32 & 0x3f);
                if (0xee8080..=0xefa3bf).contains(&pua) {
                    // Primary private use: one `?` per byte.
                } else if (0x3820..=0x3b5f).contains(&x) || (0x3b80..=0x3bff).contains(&x) {
                    n = 3;
                    esc = false;
                } else if cont(3) {
                    // The two supplemental private-use areas are escaped one
                    // byte at a time, from their raw bytes and not from `x`, so
                    // the check below covers U+10FFFD as well as U+FFFFD.
                    let y = ((b0 as u32) << 24)
                        + ((raw[i + 1] as u32) << 16)
                        + ((raw[i + 2] as u32) << 8)
                        + raw[i + 3] as u32;
                    let pua = (0xf3b08080..=0xf3bfbfbd).contains(&y)
                        || (0xf4808080..=0xf48fbfbd).contains(&y);
                    // U+010000..U+10FFFF, minus the private-use areas.
                    if !pua && (0x3c10..=0x3d0f).contains(&x) {
                        n = 4;
                        esc = false;
                    }
                }
            }
        }
        if esc || n == 0 {
            out.push(b'?');
            i += 1;
        } else {
            out.extend_from_slice(&raw[i..i + n]);
            i += n;
        }
    }
    out
}

/// The length of the valid UTF-8 sequence at the start of `b`, or None.
///
/// RFC 3629: no overlongs, no surrogates, nothing above U+10FFFF.
fn utf8_len(b: &[u8]) -> Option<usize> {
    let b0 = *b.first()?;
    if b0 < 0x80 {
        return Some(1);
    }
    let (n, lo, hi) = match b0 {
        0xc2..=0xdf => (2, 0x80, 0xbf),
        0xe0 => (3, 0xa0, 0xbf),
        0xed => (3, 0x80, 0x9f),
        0xe1..=0xef => (3, 0x80, 0xbf),
        0xf0 => (4, 0x90, 0xbf),
        0xf4 => (4, 0x80, 0x8f),
        0xf1..=0xf3 => (4, 0x80, 0xbf),
        _ => return None,
    };
    if !(lo..=hi).contains(b.get(1)?) {
        return None;
    }
    for i in 2..n {
        if b.get(i)? & 0xc0 != 0x80 {
            return None;
        }
    }
    Some(n)
}

fn utf8_code(b: &[u8]) -> u32 {
    match b.len() {
        1 => b[0] as u32,
        2 => (((b[0] as u32) & 0x1f) << 6) | (b[1] as u32 & 0x3f),
        3 => (((b[0] as u32) & 0x0f) << 12) | (((b[1] as u32) & 0x3f) << 6) | (b[2] as u32 & 0x3f),
        _ => {
            (((b[0] as u32) & 0x07) << 18)
                | (((b[1] as u32) & 0x3f) << 12)
                | (((b[2] as u32) & 0x3f) << 6)
                | (b[3] as u32 & 0x3f)
        }
    }
}

/// procps `escape_str`, the second pass: a printable ASCII byte is itself, a
/// printable multi-byte character is copied through, and anything else is one
/// `?` per character.
fn u8_second_pass(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match utf8_len(&raw[i..]) {
            Some(1) => {
                let b = raw[i];
                out.push(if (0x20..0x7f).contains(&b) { b } else { b'?' });
                i += 1;
            }
            Some(n) => {
                let wc = utf8_code(&raw[i..i + n]);
                if wc_is_printable(wc) {
                    out.extend_from_slice(&raw[i..i + n]);
                } else {
                    out.push(b'?');
                }
                i += n;
            }
            None => {
                out.push(b'?');
                i += 1;
            }
        }
    }
    out
}

/// procps `escape_str` applied to a joined command line.
///
/// The `u` spec escapes in two passes: the reader validates the bytes and the
/// printer validates the characters, so a byte that is not valid UTF-8 and a
/// character the locale cannot print both become `?`, while valid text passes
/// through unchanged. A NUL separator and a line break are the argument
/// separators `ps` joins on.
fn escape_cmdline(raw: &[u8]) -> Vec<u8> {
    let mut joined = Vec::with_capacity(raw.len().min(CMD_READ as usize));
    for b in raw {
        if *b == 0 || *b == b'\n' {
            joined.push(b' ');
        } else {
            joined.push(*b);
        }
    }
    u8_second_pass(&u8_first_pass(&joined))
}

/// The command line of a process, bounded and escaped the way `ps` prints it.
///
/// A bound that discarded the whole line made the row fall back to `[comm]`,
/// which is how `ps` shows a kernel thread: a process with a 600 kB argv then
/// claimed to be one. The prefix is returned instead.
fn read_cmdline(pid: i32) -> Option<Vec<u8>> {
    let path = proc_path(pid, b"/cmdline");
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(Path::new(OsStr::from_bytes(&path)))
        .ok()?;
    let mut raw = Vec::new();
    f.take(CMD_READ + 1).read_to_end(&mut raw).ok()?;
    // `ps` skips the trailing NUL run before it joins the vector on spaces, so
    // an argument that itself ends in a space keeps it; a NUL or a line break
    // in the middle is a separator. When the read did not end in a NUL the
    // buffer filled mid-argument, and one trailing space is dropped.
    let mut end = raw.len();
    while end > 0 && raw[end - 1] == 0 {
        end -= 1;
    }
    if end == raw.len() && raw.last() == Some(&b' ') {
        end -= 1;
    }
    raw.truncate(end);
    Some(escape_cmdline(&raw))
}

fn cmd_field(pid: i32, stat: &StatInfo) -> Vec<u8> {
    match read_cmdline(pid) {
        Some(raw) if !raw.is_empty() => raw,
        _ => {
            // An empty command line is a kernel thread, and `ps` shows the
            // comm in brackets for it.
            let mut b = Vec::with_capacity(stat.comm.len() + 2);
            b.push(b'[');
            b.extend_from_slice(&escape_cmdline(&stat.comm));
            b.push(b']');
            b
        }
    }
}

/// `%MEM`'s denominator is chosen once, here, and never by a caller.
///
/// Both live tables divide by `/proc/meminfo`'s MemTotal, which is what `ps`
/// divides by; in a container that is the host's total, not the cgroup limit,
/// so a cgroup budget would make the table disagree with the `ps` beside it.
pub fn mem_total_kb() -> u64 {
    util::mem_total_kb()
}

fn read_pid(
    pid: i32,
    btime: u64,
    hz: u64,
    now: u64,
    up_ns: u64,
    drivers: &[TtyDriver],
) -> Option<Proc> {
    let stat = read_stat(pid)?;
    let status = read_status(pid);
    let (vsz, rss) = match &status {
        Some(s) => (s.vsz, s.rss),
        None => (0, 0),
    };
    let euid = status.as_ref().map(|s| s.euid).unwrap_or(0);
    let mut cmd = cmd_field(pid, &stat);
    if stat.state == b'Z' {
        // `ps` marks a zombie's COMMAND; a container whose PID 1 does not reap
        // is full of them, and a table without the marker does not match.
        cmd.extend_from_slice(b" <defunct>");
    }
    let start_epoch = btime.saturating_add(stat.starttime / hz.max(1));
    let age = now.saturating_sub(start_epoch);
    // procps divides by `CLOCK_BOOTTIME` minus the start time, both in ticks
    // with the sub-second part kept. Truncating either to whole seconds
    // inflates a young process's elapsed time by seconds and reads its %CPU
    // several times low.
    let tick_ns = 1_000_000_000u64 / hz.max(1);
    let started_ns = stat.starttime.saturating_mul(tick_ns);
    let elapsed_ns = up_ns.saturating_sub(started_ns).max(1);
    let ticks = stat.utime.saturating_add(stat.stime);
    let cpu = ticks
        .saturating_mul(tick_ns)
        .saturating_mul(1000)
        .checked_div(elapsed_ns)
        .unwrap_or(0)
        .min(u16::MAX as u64) as u16;
    // `pr_stat` order: state, nice, locked, session leader, threads, foreground.
    let mut st = Vec::with_capacity(6);
    st.push(stat.state);
    if stat.nice < 0 {
        st.push(b'<');
    }
    if stat.nice > 0 {
        st.push(b'N');
    }
    if status.as_ref().map(|s| s.vmlck).unwrap_or(0) > 0 {
        st.push(b'L');
    }
    if stat.pid as i64 == stat.session {
        st.push(b's');
    }
    if stat.num_threads > 1 {
        st.push(b'l');
    }
    if stat.tpgid == stat.pgrp {
        st.push(b'+');
    }
    Some(Proc {
        cmd,
        tty: tty_name(pid, stat.tty_nr, drivers),
        user: user_name(euid),
        // `ps aux` USER is the effective uid; a caller that needs the owner
        // (a `stop` check) reads it from `read_status` directly.
        uid: euid,
        gid: 0,
        vsz: vsz.min(u32::MAX as u64) as u32,
        rss: rss.min(u32::MAX as u64) as u32,
        cpu,
        flags: 0,
        age,
        start_epoch,
        time_secs: Some(ticks / hz.max(1)),
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
    let up_ns = uptime_ns();
    let drivers = tty_drivers();
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
        if let Some(p) = read_pid(pid, btime, hz, now, up_ns, &drivers) {
            rows.push(p);
        }
    }
    rows
}

pub fn read_pids(pids: &[i32]) -> Vec<Proc> {
    let hz = sys::hz();
    let now = sys::now_secs();
    let btime = boot_time(now);
    let up_ns = uptime_ns();
    let drivers = tty_drivers();
    let mut rows = Vec::with_capacity(pids.len());
    for pid in pids {
        if let Some(p) = read_pid(*pid, btime, hz, now, up_ns, &drivers) {
            rows.push(p);
        }
    }
    // `ps aux` is PID-ordered, so a caller that diffs or greps by position
    // needs the same order even when the input list is not sorted.
    rows.sort_unstable_by_key(|p| p.pid);
    rows
}

/// Whether a PID is a live process.
///
/// A zombie is already dead: its `/proc` entry outlives it whenever its parent
/// does not reap, and signalling it succeeds and does nothing. Everything that
/// reports "stopped" has to use this rather than `/proc/<pid>` existing.
pub fn alive(pid: i32) -> bool {
    match read_stat(pid) {
        Some(s) => s.state != b'Z',
        None => false,
    }
}

/// Whether `pid` is still the process that had `start` as its start time, and
/// still alive.
///
/// The start time proves the PID was not recycled. The liveness check excludes
/// a zombie, which keeps its `/proc` entry (and therefore its start time) after
/// it has died whenever its parent does not reap it.
pub fn same_process(pid: i32, start: u64) -> bool {
    read_starttime(pid) == Some(start) && alive(pid)
}
