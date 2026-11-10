//! `ps aux` table rendering, synthetic and live.

use crate::gen::Proc;
use crate::str::Buf;

fn month(day_index: u64) -> (&'static str, u64, u64) {
    // Howard Hinnant's civil_from_days.
    let z = day_index as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    const NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    (NAMES[(m - 1) as usize], d, year as u64)
}

fn push_two(out: &mut Buf, n: u64) {
    out.push(b'0' + (n / 10) as u8);
    out.push(b'0' + (n % 10) as u8);
}

fn start_field(out: &mut Buf, p: &Proc, offset_min: i64, local: bool) {
    // The absolute start time, not `now - age`: a second `now` drifts by the
    // time between the read and the render, which can cross a minute.
    let start = (p.start_epoch as i64).saturating_add(offset_min.saturating_mul(60));
    let delta = p.age;
    if local {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // The parameter type of localtime_r fixes time_t without naming the
        // deprecated alias, which is 32-bit on some targets and 64-bit here.
        let t = start as _;
        let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
        if ok {
            if delta < 86400 {
                push_two(out, tm.tm_hour as u64);
                out.push(b':');
                push_two(out, tm.tm_min as u64);
            } else if delta < 365 * 86400 {
                const NAMES: [&str; 12] = [
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                    "Dec",
                ];
                out.push_str(NAMES[(tm.tm_mon.clamp(0, 11)) as usize]);
                if tm.tm_mday < 10 {
                    out.push(b' ');
                }
                out.push_u64(tm.tm_mday as u64);
            } else {
                out.push_u64_width((tm.tm_year + 1900) as u64, 5);
            }
            return;
        }
    }
    if delta < 86400 {
        let secs = start.rem_euclid(86400);
        push_two(out, (secs / 3600) as u64);
        out.push(b':');
        push_two(out, ((secs % 3600) / 60) as u64);
    } else if delta < 365 * 86400 {
        let (name, day, _year) = month(start.div_euclid(86400) as u64);
        out.push_str(name);
        if day < 10 {
            out.push(b' ');
        }
        out.push_u64(day);
    } else {
        let (_name, _day, year) = month(start.div_euclid(86400) as u64);
        out.push_u64_width(year, 5);
    }
}

fn stat_field(out: &mut Buf, p: &Proc) {
    let start = out.v.len();
    if let Some(s) = &p.stat_override {
        out.push_bytes(s);
    } else {
        let base = if p.flags & crate::corpus::F_BUSY != 0 {
            b'R'
        } else {
            b'S'
        };
        out.push(base);
        if p.flags & crate::corpus::F_SESSION != 0 {
            out.push(b's');
        }
        if p.flags & crate::corpus::F_THREADS != 0 {
            out.push(b'l');
        }
        if p.flags & crate::corpus::F_TTY != 0 {
            out.push(b'+');
        }
    }
    let len = out.v.len() - start;
    let mut pad = 4usize.saturating_sub(len);
    while pad > 0 {
        out.push(b' ');
        pad -= 1;
    }
}

fn tty_field(out: &mut Buf, p: &Proc) {
    if p.tty.is_empty() {
        out.push(b'?');
    } else {
        out.push_bytes(&p.tty);
    }
}

fn user_field(out: &mut Buf, user: &[u8]) {
    if user.len() > 8 {
        out.push_bytes(&user[..7]);
        out.push(b'+');
    } else {
        out.push_bytes(user);
        let mut pad = 8 - user.len();
        while pad > 0 {
            out.push(b' ');
            pad -= 1;
        }
    }
}

pub fn round_up(v: u64, page_kb: u64) -> u64 {
    if page_kb <= 1 {
        return v;
    }
    v.div_ceil(page_kb) * page_kb
}

/// The memory a *synthetic* table's `%MEM` is a percentage of: MemTotal,
/// lowered to the cgroup limit when that is smaller, because a generated table
/// is a model of the machine the tool is running on.
///
/// The live table must not use this: `ps` divides by `MemTotal` from
/// `/proc/meminfo`, which in a container is the host's total, not the cgroup
/// limit. `table --live` therefore passes `util::mem_total_kb()` directly, so
/// its `%MEM` agrees with the `ps` beside it.
pub fn mem_budget_kb() -> u64 {
    let mut mem = crate::util::mem_total_kb();
    let cg = crate::util::cgroup_mem_limit_kb();
    if cg > 0 && (mem == 0 || cg < mem) {
        mem = cg;
    }
    mem
}

/// Header column offsets, from the header printed below. A numeric field that
/// overflows its slot eats the padding after it, the way procps does, instead
/// of pushing STAT, START, TIME and COMMAND to the right.
const STAT_COL: usize = 49;
const START_COL: usize = 54;
const TIME_COL: usize = 62;

fn pad_to(out: &mut Buf, row_start: usize, col: usize) {
    if out.v.len() - row_start < col {
        while out.v.len() - row_start < col {
            out.push(b' ');
        }
    } else {
        out.push(b' ');
    }
}

pub fn render(rows: &[Proc], mem_total_kb: u64, offset_min: i64, local: bool, page_kb: u64) -> Buf {
    let mut out = Buf::with_capacity(rows.len() * 120 + 128);
    out.push_str("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n");
    for p in rows {
        let row_start = out.v.len();
        let vsz = round_up(p.vsz as u64, page_kb);
        let rss = round_up(p.rss as u64, page_kb);
        user_field(&mut out, &p.user);
        out.push(b' ');
        out.push_u64_width(p.pid as u64, 7);
        out.push(b' ');
        out.push_tenths_width(p.cpu as u32, 4);
        out.push(b' ');
        // procps computes `%MEM` as `rss * 1000 / MemTotal` in integer
        // arithmetic, so it truncates rather than rounds: an RSS of 0.377%
        // prints as 0.3, which is what `ps aux` shows and what `table --live`
        // has to match. One process cannot use more than the whole machine,
        // and the field is four characters wide, so the value is capped at
        // 999 (99.9).
        let mem = rss
            .saturating_mul(1000)
            .checked_div(mem_total_kb)
            .unwrap_or(0)
            .min(999) as u32;
        out.push_tenths_width(mem, 4);
        out.push(b' ');
        out.push_u64_width(vsz, 6);
        out.push(b' ');
        out.push_u64_width(rss, 5);
        out.push(b' ');
        tty_field(&mut out, p);
        pad_to(&mut out, row_start, STAT_COL);
        stat_field(&mut out, p);
        pad_to(&mut out, row_start, START_COL);
        start_field(&mut out, p, offset_min, local);
        // TIME is right-aligned in its six columns and COMMAND follows one
        // space later, so COMMAND starts at the header offset whatever the
        // time is.
        pad_to(&mut out, row_start, TIME_COL - 2);
        // The live table knows the real CPU time; a synthetic row models it
        // from the age and the %CPU it claims.
        let time_secs = p
            .time_secs
            .unwrap_or_else(|| p.age.saturating_mul(p.cpu as u64) / 1000);
        let time_start = out.v.len();
        out.push_time(time_secs);
        let time_len = out.v.len() - time_start;
        if time_len < 6 {
            let pad = 6 - time_len;
            for _ in 0..pad {
                out.v.insert(time_start, b' ');
            }
        }
        out.push(b' ');
        out.push_bytes(&p.cmd);
        out.push(b'\n');
    }
    out
}
