//! `ps aux` table rendering, synthetic and live.

use crate::gen::Proc;
use crate::str::Buf;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The civil date of an epoch day (Howard Hinnant's `civil_from_days`), as
/// `(year, month index, day of month, day of year)`.
fn civil(day_index: i64) -> (i64, usize, u64, i64) {
    let z = day_index + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, (m - 1) as usize, d, doy as i64)
}

/// One instant as the renderer needs to read it: the calendar day, the year,
/// and the clock time, all in the rendering zone.
struct Parts {
    year: i64,
    /// `tm_yday`: 0-based day of the year.
    yday: i64,
    mon: usize,
    mday: u64,
    hour: u64,
    min: u64,
}

/// The instant in the host's zone, from `localtime_r`, or None when the
/// conversion fails (a `time_t` outside the kernel's range).
fn parts_local(t: i64) -> Option<Parts> {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // The parameter type of localtime_r fixes time_t without naming the
    // deprecated alias, which is 32-bit on some targets and 64-bit here.
    let secs = t as _;
    let ok = unsafe { !libc::localtime_r(&secs, &mut tm).is_null() };
    if !ok {
        return None;
    }
    Some(Parts {
        year: tm.tm_year as i64 + 1900,
        yday: tm.tm_yday as i64,
        mon: tm.tm_mon.clamp(0, 11) as usize,
        mday: tm.tm_mday.clamp(0, 31) as u64,
        hour: tm.tm_hour.clamp(0, 23) as u64,
        min: tm.tm_min.clamp(0, 59) as u64,
    })
}

/// The instant in UTC shifted by `offset_min`, without `libc`.
fn parts_offset(t: i64, offset_min: i64) -> Parts {
    let shifted = t.saturating_add(offset_min.saturating_mul(60));
    let (year, mon, mday, yday) = civil(shifted.div_euclid(86400));
    let secs = shifted.rem_euclid(86400) as u64;
    Parts {
        year,
        yday,
        mon,
        mday,
        hour: secs / 3600,
        min: (secs % 3600) / 60,
    }
}

/// Everything a START/TIME field needs that is not per-row.
pub struct Clock {
    pub now_epoch: u64,
    /// `tm_yday` and `tm_year` of `now_epoch` in the rendering zone.
    pub today_yday: i32,
    pub this_year: i32,
    /// Minutes to add to a row's epoch before formatting.
    pub offset_min: i64,
    /// True: `localtime_r` decides the zone. False: UTC plus `offset_min`.
    pub local: bool,
}

impl Clock {
    /// The synthetic table's clock: `now` plus the caller's offset choice.
    pub fn synthetic(now: u64, offset_min: i64, local: bool) -> Clock {
        let clock = Clock {
            now_epoch: now,
            today_yday: 0,
            this_year: 1970,
            offset_min,
            local,
        };
        // An unreadable zone (a `time_t` out of range) must not turn every row
        // into a year: fall back to UTC, which is what the no-`libc` branch
        // computes.
        let today = clock
            .parts(now as i64)
            .unwrap_or_else(|| parts_offset(now as i64, 0));
        Clock {
            today_yday: today.yday as i32,
            this_year: today.year as i32,
            ..clock
        }
    }

    /// The live table's clock: the host's own zone, no offset.
    pub fn live(now: u64) -> Clock {
        Clock::synthetic(now, 0, true)
    }

    /// The instant in this clock's rendering zone.
    fn parts(&self, t: i64) -> Option<Parts> {
        if self.local {
            parts_local(t)
        } else {
            Some(parts_offset(t, self.offset_min))
        }
    }

    /// The calendar day `now_epoch` falls on, in the rendering zone.
    ///
    /// The constructors fill the cached pair, so the per-row loop never repeats
    /// the `now` conversion. A `Clock` assembled by hand leaves `this_year` at
    /// the sentinel 0, which no `tm_year + 1900` can be, so the day is derived
    /// from `now_epoch` instead of rendering every row as year 0.
    fn today(&self) -> (i64, i64) {
        if self.this_year != 0 {
            return (self.today_yday as i64, self.this_year as i64);
        }
        match self.parts(self.now_epoch as i64) {
            Some(p) => (p.yday, p.year),
            None => (0, 1970),
        }
    }

    /// `pr_stime`: `HH:MM`, `%b%d` when the render-zone day differs, `%Y` when
    /// the year differs.
    ///
    /// The branch is the process's own calendar day, never its age: a process
    /// started 10 hours ago on the previous local day is `Nov11`, and a 25-hour
    /// DST day does not make a same-day process look like yesterday. The day of
    /// month is zero-padded, which is what `%d` does.
    pub fn start_field(&self, start_epoch: u64, out: &mut Buf) {
        let p = match self.parts(start_epoch as i64) {
            Some(p) => p,
            None => return,
        };
        let (today_yday, this_year) = self.today();
        if p.year != this_year {
            out.push_u64_width(p.year.max(0) as u64, 5);
        } else if p.yday != today_yday {
            out.push_str(MONTHS[p.mon.min(11)]);
            out.push_two(p.mday);
        } else {
            out.push_two(p.hour);
            out.push(b':');
            out.push_two(p.min);
        }
    }
}

/// `pr_bsdtime`: total minutes and seconds, `75:00`. Six columns right-aligned.
///
/// `ps aux` TIME is not `pr_time`: it never carries an hours field and never a
/// day prefix, so a process with 75 minutes of CPU prints `75:00`.
pub fn push_bsdtime(out: &mut Buf, secs: u64) {
    out.push_u64_width(secs / 60, 3);
    out.push(b':');
    out.push_two(secs % 60);
}

/// `pr_pcpu`: one decimal below 100.0, an integer at or above it.
///
/// `milli` is procps' own `pcpu` scale, thousandths of a percent (`999` is
/// 99.9%), which is what `Proc.cpu` carries. Above 99.9 the fraction is
/// dropped, so a busy process keeps its four-column field instead of shifting
/// every column after it.
pub fn push_pcpu(out: &mut Buf, milli: u32) {
    if milli > 999 {
        out.push_u64_width((milli / 10) as u64, 4);
    } else {
        out.push_tenths_width(milli, 4);
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
/// A live table must not use this: `ps` divides by `MemTotal` from
/// `/proc/meminfo`, which in a container is the host's total, not the cgroup
/// limit. Both live tables take the denominator from `live::mem_total_kb`.
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
/// The TIME header sits in the right half of its six-column field.
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

pub fn render(rows: &[Proc], mem_total_kb: u64, clock: &Clock, page_kb: u64) -> Buf {
    let mut out = Buf::with_capacity(rows.len() * 120 + 128);
    out.push_str("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n");
    for p in rows {
        let row_start = out.v.len();
        let vsz = round_up(p.vsz, page_kb);
        let rss = round_up(p.rss, page_kb);
        user_field(&mut out, &p.user);
        out.push(b' ');
        out.push_u64_width(p.pid as u64, 7);
        out.push(b' ');
        push_pcpu(&mut out, p.cpu);
        out.push(b' ');
        // procps computes `%MEM` as `rss * 1000 / MemTotal` in integer
        // arithmetic, so it truncates rather than rounds: an RSS of 0.377%
        // prints as 0.3, which is what `ps aux` shows and what `table --live`
        // has to match. One process cannot use more than the whole machine,
        // and the field is four characters wide, so the value is capped at
        // 999 (99.9). A caller with no denominator of its own (an unreadable
        // `/proc/meminfo`, or a `Fit` that was never filled in) gets this
        // machine's budget rather than a table of zeros.
        let mem_total_kb = if mem_total_kb == 0 {
            mem_budget_kb()
        } else {
            mem_total_kb
        };
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
        clock.start_field(p.start_epoch, &mut out);
        // TIME is right-aligned in its six columns and COMMAND follows one
        // space later, so COMMAND starts at the header offset whatever the
        // time is. `push_bsdtime` cannot produce a short field, so no
        // post-hoc padding is needed.
        pad_to(&mut out, row_start, TIME_COL - 2);
        // The live table knows the real CPU time; a synthetic row models it
        // from the age and the %CPU it claims.
        let time_secs = p
            .time_secs
            .unwrap_or_else(|| p.age.saturating_mul(p.cpu as u64) / 1000);
        push_bsdtime(&mut out, time_secs);
        out.push(b' ');
        // `ps` writes the row through one `OUTBUF_SIZE` buffer, so a long
        // command line is cut where the buffer ends rather than at a fixed
        // command-line width.
        let room = crate::live::ROW_BYTES.saturating_sub(out.v.len() - row_start);
        out.push_bytes(&p.cmd[..p.cmd.len().min(room)]);
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(f: impl Fn(&mut Buf)) -> String {
        let mut b = Buf::new();
        f(&mut b);
        String::from_utf8_lossy(&b.v).into_owned()
    }

    fn start(now: u64, offset_min: i64, local: bool, at: u64) -> String {
        fmt(|b| Clock::synthetic(now, offset_min, local).start_field(at, b))
    }

    /// 2026-11-12 00:00:00 UTC.
    const NOON: u64 = 1_794_441_600;

    #[test]
    fn bsdtime_is_total_minutes_never_hours() {
        // procps `%3u:%02u` of `ticks/Hertz`: 75 minutes of CPU is `75:00`,
        // not `1:15:00`, and an hour is `60:00`.
        assert_eq!(fmt(|b| push_bsdtime(b, 4500)), " 75:00");
        assert_eq!(fmt(|b| push_bsdtime(b, 3600)), " 60:00");
        assert_eq!(fmt(|b| push_bsdtime(b, 59)), "  0:59");
        assert_eq!(fmt(|b| push_bsdtime(b, 0)), "  0:00");
        // A day of CPU stays minutes, with no day prefix.
        assert_eq!(fmt(|b| push_bsdtime(b, 86_400)), "1440:00");
    }

    #[test]
    fn pcpu_drops_the_decimal_above_99_9() {
        assert_eq!(fmt(|b| push_pcpu(b, 999)), "99.9");
        assert_eq!(fmt(|b| push_pcpu(b, 1000)), " 100");
        assert_eq!(fmt(|b| push_pcpu(b, 1520)), " 152");
        assert_eq!(fmt(|b| push_pcpu(b, 0)), " 0.0");
    }

    #[test]
    fn start_is_decided_by_the_calendar_day_not_the_age() {
        // A row started 10 hours ago on the previous day prints MmmDD even
        // though its age is under 24 hours; the age is what the old code
        // tested, and it said HH:MM.
        assert_eq!(start(NOON, 0, false, NOON - 10 * 3600), "Nov11");
        // A row started 20 minutes ago on the same day prints the clock.
        assert_eq!(start(NOON, 0, false, NOON + 20 * 60), "00:20");
        // A row started 25 hours ago on the previous day still prints MmmDD.
        assert_eq!(start(NOON, 0, false, NOON - 25 * 3600), "Nov10");
    }

    #[test]
    fn start_pads_the_day_with_a_zero() {
        // `pr_stime` uses `%b%d`, so a single-digit day is `Nov05`, not `Nov 5`.
        // Nov 5 2026 is 7 days before Nov 12.
        assert_eq!(start(NOON, 0, false, NOON - 7 * 86400), "Nov05");
    }

    #[test]
    fn start_shows_the_year_across_a_year_boundary() {
        // 357 days before 2026-11-12 is 2025-11-20, and `ps` prints the year no
        // matter how small the age is. The old rule tested `age < 365 days`
        // and printed a month and a day here.
        assert_eq!(start(NOON, 0, false, NOON - 357 * 86400), " 2025");
        // A row from the same year is never a year, however old.
        assert_eq!(start(NOON, 0, false, NOON - 300 * 86400), "Jan16");
    }

    #[test]
    fn start_uses_the_offset_zone_for_the_day_boundary() {
        // At 20:00 UTC the +05:45 zone is already 01:45 the next day, so a row
        // started two hours earlier is on the render zone's previous day even
        // though its age is two hours.
        let now: u64 = 1_794_513_600;
        let at = now - 7200;
        assert_eq!(start(now, 0, false, at), "18:00");
        assert_eq!(start(now, 345, false, at), "Nov12");
        assert_eq!(start(now, 345, false, now), "01:45");
    }

    fn proc_with(cmd: Vec<u8>) -> Proc {
        Proc {
            cmd,
            tty: Vec::new(),
            user: b"root".to_vec(),
            uid: 0,
            gid: 0,
            vsz: 4096,
            rss: 4096,
            cpu: 0,
            flags: 0,
            age: 0,
            start_epoch: NOON - 60,
            time_secs: Some(0),
            pid: 1,
            tmpl: 0,
            parent: None,
            stat_override: None,
        }
    }

    #[test]
    fn render_bounds_the_row_where_ps_bounds_its_buffer() {
        let rows = [proc_with(vec![b'B'; 400_000])];
        let out = render(&rows, 1024, &Clock::synthetic(NOON, 0, false), 1);
        let nl = out.v.iter().rposition(|b| *b == b'\n').unwrap();
        let row_start = out.v[..nl].iter().rposition(|b| *b == b'\n').unwrap() + 1;
        let row = &out.v[row_start..nl];
        assert_eq!(row.len(), crate::live::ROW_BYTES);
        // A long command line is a prefix of the real one, never a bracket.
        assert_eq!(row[67], b'B');
        let rows = [proc_with(b"short".to_vec())];
        let out = render(&rows, 1024, &Clock::synthetic(NOON, 0, false), 1);
        assert!(out.v.ends_with(b" short\n"));
    }
}
