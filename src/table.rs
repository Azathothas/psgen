//! `ps aux` table rendering, synthetic and live.

use crate::gen::Proc;
use crate::str::Buf;
use crate::sys;

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

fn start_field(out: &mut Buf, age: u64, offset_min: i64, local: bool) {
    let now = (sys::now_secs() as i64).saturating_add(offset_min.saturating_mul(60));
    let start = now.saturating_sub(age as i64);
    let delta = now.saturating_sub(start);
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
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                    "Nov", "Dec",
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

pub fn render(rows: &[Proc], mem_total_kb: u64, offset_min: i64, local: bool, page_kb: u64) -> Buf {
    let mut out = Buf::with_capacity(rows.len() * 120 + 128);
    out.push_str("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n");
    for p in rows {
        let vsz = round_up(p.vsz as u64, page_kb);
        let rss = round_up(p.rss as u64, page_kb);
        user_field(&mut out, &p.user);
        out.push(b' ');
        out.push_u64_width(p.pid as u64, 7);
        out.push(b' ');
        out.push_tenths_width(p.cpu as u32, 4);
        out.push(b' ');
        let mem = if mem_total_kb == 0 {
            0
        } else {
            ((rss * 1000 + mem_total_kb / 2) / mem_total_kb) as u32
        };
        out.push_tenths_width(mem, 4);
        out.push(b' ');
        out.push_u64_width(vsz, 6);
        out.push(b' ');
        out.push_u64_width(rss, 5);
        out.push(b' ');
        let tty_start = out.v.len();
        tty_field(&mut out, p);
        let tty_len = out.v.len() - tty_start;
        let mut pad = 8usize.saturating_sub(tty_len);
        while pad > 0 {
            out.push(b' ');
            pad -= 1;
        }
        out.push(b' ');
        stat_field(&mut out, p);
        out.push(b' ');
        start_field(&mut out, p.age, offset_min, local);
        out.push(b' ');
        let time_secs = p.age.saturating_mul(p.cpu as u64) / 1000;
        let time_start = out.v.len();
        out.push_time(time_secs);
        let time_len = out.v.len() - time_start;
        if time_len < 6 {
            let mut pad = 6 - time_len;
            while pad > 0 {
                out.v.insert(time_start, b' ');
                pad -= 1;
            }
        }
        out.push(b' ');
        out.push_bytes(&p.cmd);
        out.push(b'\n');
    }
    out
}
