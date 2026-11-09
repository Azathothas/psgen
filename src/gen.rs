//! Process generation: template expansion, realistic jitter, table rows.

use crate::corpus::{self, Tmpl};
use crate::rng::Rng;
use crate::str::{self, Buf};
use crate::sys;
use crate::util;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::vec::Vec;

pub struct Proc {
    pub cmd: Vec<u8>,
    pub tty: Vec<u8>,
    pub user: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
    pub vsz: u32,
    pub rss: u32,
    pub cpu: u16,
    pub flags: u8,
    pub age: u64,
    pub pid: i32,
    pub tmpl: usize,
    pub parent: Option<usize>,
    pub stat_override: Option<Vec<u8>>,
}

pub struct Opts {
    pub count: usize,
    pub profile: Vec<u8>,
    pub family: Option<u8>,
    pub self_user: Vec<u8>,
    pub uniq: bool,
}

/// Virtual size the stub needs before the template's own mappings. The std
/// binary, its loader and one malloc arena sit below this; the synthetic RSS
/// is clamped so that base plus RSS still fits the template's VSZ.
pub const BASE_RESERVE_KB: u32 = 4096;

/// Host limits a synthetic table has to respect. The corpus carries absolute
/// sizes, so on a host smaller than the largest template the rows would claim
/// more RSS than exists and a `%MEM` above 100.
pub struct Fit {
    /// The memory budget a row may claim, in kB. 0 means "unknown, do not fit".
    pub mem_kb: u64,
    /// `/proc/sys/kernel/pid_max`, or 0 when it cannot be read.
    pub pid_max: u64,
}

impl Fit {
    /// The limits of this host: MemTotal, lowered to the cgroup limit when
    /// that is smaller, and pid_max.
    pub fn host() -> Fit {
        let mut mem = util::mem_total_kb();
        let cg = util::cgroup_mem_limit_kb();
        if cg > 0 && (mem == 0 || cg < mem) {
            mem = cg;
        }
        Fit {
            mem_kb: mem,
            pid_max: util::pid_max(),
        }
    }

    /// No fitting: used where the caller already planned sizes (inject).
    pub fn none() -> Fit {
        Fit {
            mem_kb: 0,
            pid_max: util::pid_max(),
        }
    }
}

/// How many times one template may contribute rows to a single population.
///
/// `inst` raises the bound for the daemons that really do run several
/// instances. A table with one command 74 times, or two `cargo build` jobs
/// per core, is not a table any host shows.
fn repeat_cap(t: &Tmpl, _want: usize) -> usize {
    let inst = if t.inst == 0 { 1 } else { t.inst as usize };
    // A realistic table shows each fixed command a handful of times, not
    // dozens. Spreading the repeats by the number of repeatable templates in
    // scope (see `fill`) keeps a large request from collapsing onto one row.
    (inst * 2).clamp(4, 16)
}

/// Whether a template may be picked more than once in one run.
///
/// `inst` says how many rows a template represents (six nginx workers), which
/// is not the same question as "may this command appear twice". A template
/// with a placeholder produces a different command line every time, so it may
/// repeat; a fixed single-instance daemon may not. `F_REPEAT` marks the rows
/// that legitimately appear more than once on a real host (builds, sessions,
/// shims).
/// `inst` says how many rows one draw emits, which is not the same question as
/// "may this template be drawn again". Re-picking is allowed for the rows
/// marked `F_REPEAT` and for a template whose placeholder changes the command
/// line; anything else would put the same command in the table twice.
pub fn repeatable(t: &Tmpl) -> bool {
    t.flags & corpus::F_REPEAT != 0 || has_variants(t)
}

/// The placeholders that expand to a different value every time.
///
/// `{user}` and `{uid}` are fixed for a whole run, so a template whose only
/// placeholder is one of those produces the same command line on every draw:
/// it may appear once, and it cannot pad a large count.
const VARIABLE_PLACEHOLDERS: &[&str] = &[
    "{hex6}", "{hex8}", "{hex12}", "{hex64}", "{n}", "{n2}", "{pid}", "{port}", "{cport}", "{ip}",
];

/// Whether re-expanding this template can yield a different command line,
/// which is what makes it usable as padding for a large count.
pub fn has_variants(t: &Tmpl) -> bool {
    VARIABLE_PLACEHOLDERS.iter().any(|p| t.cmd.contains(p))
}

const COMMON_PORTS: [u16; 14] = [
    80, 443, 3000, 5000, 5432, 6379, 8000, 8080, 8443, 9000, 9090, 11211, 27017, 9200,
];

fn expand(cmd: &str, rng: &mut Rng, self_user: &[u8], uid: Option<u32>) -> Vec<u8> {
    let bytes = cmd.as_bytes();
    let mut out = Buf::with_capacity(bytes.len() + 32);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(rel) = str::find(&bytes[i..], b"}") {
                let key = &bytes[i + 1..i + rel];
                match key {
                    b"hex6" => {
                        let mut h = [0u8; 6];
                        rng.hex(6, &mut h);
                        out.push_bytes(&h);
                    }
                    b"hex8" => {
                        let mut h = [0u8; 8];
                        rng.hex(8, &mut h);
                        out.push_bytes(&h);
                    }
                    b"hex12" => {
                        let mut h = [0u8; 12];
                        rng.hex(12, &mut h);
                        out.push_bytes(&h);
                    }
                    b"hex64" => {
                        let mut h = [0u8; 64];
                        rng.hex(64, &mut h);
                        out.push_bytes(&h);
                    }
                    b"n" => out.push_u64(rng.range(1, 9)),
                    b"n2" => out.push_u64(rng.range(10, 999)),
                    b"pid" => out.push_u64(rng.range(100, 40000)),
                    b"uid" => match uid {
                        Some(u) => out.push_u64(u as u64),
                        None => out.push_u64(rng.range(1000, 1005)),
                    },
                    b"port" => {
                        let p = COMMON_PORTS[rng.below(COMMON_PORTS.len() as u64) as usize];
                        out.push_u64(p as u64);
                    }
                    b"cport" => out.push_u64(rng.range(30000, 65000)),
                    b"ip" => {
                        out.push_str("10.0.");
                        out.push_u64(rng.range(0, 3));
                        out.push(b'.');
                        out.push_u64(rng.range(2, 250));
                    }
                    b"user" => out.push_bytes(self_user),
                    _ => {
                        // Unknown placeholder: keep it visible so `check` fails.
                        out.push(b'{');
                        out.push_bytes(key);
                        out.push(b'}');
                    }
                }
                i += rel + 1;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out.v
}

fn weighted_total(weights: &[u16; 10], family: Option<u8>) -> u64 {
    let mut total = 0u64;
    for t in corpus::CORPUS.iter() {
        if let Some(f) = family {
            if t.fam != f {
                continue;
            }
        }
        let w = match family {
            Some(_) => t.weight as u64,
            None => weights[t.fam as usize] as u64 * t.weight as u64,
        };
        total += w;
    }
    total
}

fn weighted_index(rng: &mut Rng, weights: &[u16; 10], family: Option<u8>) -> usize {
    let total = weighted_total(weights, family);
    if total == 0 {
        return 0;
    }
    let mut n = rng.below(total);
    for (idx, t) in corpus::CORPUS.iter().enumerate() {
        if let Some(f) = family {
            if t.fam != f {
                continue;
            }
        }
        let w = match family {
            Some(_) => t.weight as u64,
            None => weights[t.fam as usize] as u64 * t.weight as u64,
        };
        if n < w {
            return idx;
        }
        n -= w;
    }
    0
}

/// Draw one index from `pool` with probability proportional to its template's
/// weight, and return its position in `pool`.
fn weighted_pick(pool: &[usize], rng: &mut Rng, weights: &[u16; 10]) -> usize {
    let total: u64 = pool
        .iter()
        .map(|i| {
            let t = &corpus::CORPUS[*i];
            weights[t.fam as usize] as u64 * t.weight as u64
        })
        .sum();
    if total == 0 {
        return 0;
    }
    let mut n = rng.below(total);
    for (pos, idx) in pool.iter().enumerate() {
        let t = &corpus::CORPUS[*idx];
        let w = weights[t.fam as usize] as u64 * t.weight as u64;
        if n < w {
            return pos;
        }
        n -= w;
    }
    0
}

/// Single-instance daemons are picked at most once, so a generated table does
/// not show two sshd listeners or two PID-1 processes. Build tools and desktop
/// applications are allowed to repeat.
fn pick_index(rng: &mut Rng, weights: &[u16; 10], family: Option<u8>, used: &[usize]) -> usize {
    let mut fallback = 0;
    for _ in 0..80 {
        let idx = weighted_index(rng, weights, family);
        let t = &corpus::CORPUS[idx];
        if !repeatable(t) && used.contains(&idx) {
            fallback = idx;
            continue;
        }
        return idx;
    }
    fallback
}

fn jitter(rng: &mut Rng, base: u32, pct: u64) -> u32 {
    let delta = (base as u64 * pct) / 100;
    if delta == 0 {
        return base;
    }
    let v = base as u64 + rng.range(0, delta * 2) - delta;
    v.max(1024) as u32
}

fn resolve_user(t: &Tmpl, opts: &Opts) -> (Vec<u8>, u32, u32) {
    if t.user == corpus::SELF_USER {
        let (uid, gid) = util::lookup_user(&opts.self_user).unwrap_or_else(|| {
            let me = util::current_user();
            (me.uid, me.gid)
        });
        return (opts.self_user.clone(), uid, gid);
    }
    let name = t.user.as_bytes().to_vec();
    match util::lookup_user(&name) {
        Some((uid, gid)) => (name, uid, gid),
        None => {
            let (uid, gid) = util::lookup_user(&opts.self_user).unwrap_or_else(|| {
                let me = util::current_user();
                (me.uid, me.gid)
            });
            (name, uid, gid)
        }
    }
}

fn make_proc(t: &Tmpl, tmpl: usize, rng: &mut Rng, opts: &Opts, uptime: u64) -> Proc {
    let (user, uid, gid) = resolve_user(t, opts);
    let vsz = jitter(rng, t.vsz, 12);
    let mut rss = jitter(rng, t.rss, 18);
    if rss > vsz {
        rss = vsz / 2;
    }
    let room = vsz.saturating_sub(BASE_RESERVE_KB);
    if room > 0 && rss > room {
        rss = room;
    }
    let cpu = (t.cpu as i32 + rng.range(0, 4) as i32 - 2).clamp(0, 999);
    let age = if t.flags & (corpus::F_LONG | corpus::F_SESSION) != 0 {
        // One draw with a fixed modulus: a second draw on a short-uptime
        // host would move every later value in the stream and break the
        // same-seed contract.
        let base = uptime.saturating_sub(rng.fraction(90));
        if base == 0 {
            30 + rng.fraction(570)
        } else {
            base
        }
    } else if t.flags & (corpus::F_BUSY | corpus::F_SHORT) != 0 {
        rng.range(3, 1800)
    } else if t.flags & corpus::F_CHILD != 0 {
        // Pick a boot-relative start with a fixed-point draw. A plain
        // rng.range(5, up) reduces a fresh random word modulo `up`, and
        // `up` grows by one every second, so the same seed produced a
        // different age on every run. Scaling a 32-bit draw keeps the
        // start stable to within a second as uptime advances.
        let up = uptime.max(60);
        up.saturating_sub(rng.fraction(up.saturating_sub(5).max(1)))
    } else if t.fam == corpus::FAM_DEV {
        rng.range(5, 6 * 3600)
    } else if t.fam == corpus::FAM_DESK {
        rng.range(60, 7 * 86400)
    } else {
        rng.range(3600, 30 * 86400)
    };
    let cmd = expand(t.cmd, rng, &opts.self_user, Some(uid));
    let tty = if t.flags & corpus::F_TTY != 0 {
        let mut found: Option<Vec<u8>> = None;
        for token in cmd.split(|b| *b == b' ') {
            if let Some(p) = str::find(token, b"pts/") {
                let mut e = p + 4;
                while e < token.len() && token[e].is_ascii_digit() {
                    e += 1;
                }
                found = Some(token[p..e].to_vec());
                break;
            }
            if token.starts_with(b"tty") {
                let mut e = 3;
                while e < token.len() && token[e].is_ascii_digit() {
                    e += 1;
                }
                if e > 3 {
                    found = Some(token[..e].to_vec());
                    break;
                }
            }
            if token.starts_with(b"vt") {
                let mut e = 2;
                while e < token.len() && token[e].is_ascii_digit() {
                    e += 1;
                }
                if e > 2 {
                    let mut v = b"tty".to_vec();
                    v.extend_from_slice(&token[2..e]);
                    found = Some(v);
                    break;
                }
            }
        }
        match found {
            Some(v) => v,
            None => {
                let mut b = Buf::new();
                b.push_str("pts/");
                b.push_u64(rng.below(8));
                b.v
            }
        }
    } else {
        Vec::new()
    };
    let age = if uptime == 0 { age } else { age.min(uptime) };
    Proc {
        cmd,
        tty,
        user,
        uid,
        gid,
        vsz,
        rss,
        cpu: cpu as u16,
        flags: t.flags,
        age,
        pid: 0,
        tmpl,
        parent: None,
        stat_override: None,
    }
}

/// Expand every template once, in corpus order.
pub fn all_commands(rng: &mut Rng, opts: &Opts) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for t in corpus::CORPUS.iter() {
        if let Some(f) = opts.family {
            if t.fam != f {
                continue;
            }
        }
        out.push(expand(t.cmd, rng, &opts.self_user, None));
    }
    out
}

/// Generate `count` command lines (distinct unless `--no-uniq`). `count == 0`
/// means one per template.
///
/// A theme is drawn first, so `-p` is honoured for the short and long cases
/// alike: the list keeps the corpus order that `tests/invariants.py` and the
/// README promise for the first row, but which templates are picked and how
/// often is weighted by the profile.
pub fn gen_list(rng: &mut Rng, opts: &Opts) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    // A BTreeSet keeps the duplicate check O(log n) per line: the linear scan
    // over every line already kept made `list -n 2000` quadratic.
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let uniq = opts.uniq;
    if opts.count == 0 {
        for t in corpus::CORPUS.iter() {
            if let Some(f) = opts.family {
                if t.fam != f {
                    continue;
                }
            }
            out.push(expand(t.cmd, rng, &opts.self_user, None));
        }
        return out;
    }

    let weights = corpus::profile_weights(&opts.profile);
    let target = opts.count.min(2000);
    let push = |cmd: Vec<u8>, out: &mut Vec<Vec<u8>>, seen: &mut BTreeSet<Vec<u8>>| {
        if !uniq || seen.insert(cmd.clone()) {
            out.push(cmd);
        }
    };

    // First pass: each in-scope template once. The first line is the first
    // in-scope corpus row, which the README and tests/invariants.py promise;
    // the rest are drawn by profile weight, so `-p` changes a short list too
    // instead of only the rows above the template count.
    let mut fixed_used: Vec<usize> = Vec::new();
    let mut drawn: Vec<usize> = Vec::new();
    for (idx, t) in corpus::CORPUS.iter().enumerate() {
        if opts.family.map(|f| f == t.fam).unwrap_or(true) {
            drawn.push(idx);
            push(
                expand(t.cmd, rng, &opts.self_user, None),
                &mut out,
                &mut seen,
            );
            fixed_used.push(idx);
            break;
        }
    }
    let mut pool: Vec<usize> = Vec::new();
    for (idx, t) in corpus::CORPUS.iter().enumerate() {
        if let Some(f) = opts.family {
            if t.fam != f {
                continue;
            }
        }
        if !drawn.contains(&idx) {
            pool.push(idx);
        }
    }
    while out.len() < target && !pool.is_empty() {
        let pick = weighted_pick(&pool, rng, &weights);
        let idx = pool.swap_remove(pick);
        let t = &corpus::CORPUS[idx];
        push(
            expand(t.cmd, rng, &opts.self_user, None),
            &mut out,
            &mut seen,
        );
        if !has_variants(t) {
            fixed_used.push(idx);
        }
    }

    // Second pass: weighted draws to fill the remainder. Only templates that
    // can produce a new command line (placeholders) are useful here; a fixed
    // command cannot add a distinct line, so retrying it is wasted work.
    let mut guard = 0usize;
    let limit = target.saturating_mul(40).saturating_add(1000);
    while out.len() < target && guard < limit {
        let idx = weighted_index(rng, &weights, opts.family);
        let t = &corpus::CORPUS[idx];
        guard += 1;
        if !has_variants(t) {
            if fixed_used.contains(&idx) {
                continue;
            }
            fixed_used.push(idx);
            push(
                expand(t.cmd, rng, &opts.self_user, None),
                &mut out,
                &mut seen,
            );
            continue;
        }
        push(
            expand(t.cmd, rng, &opts.self_user, None),
            &mut out,
            &mut seen,
        );
    }

    // The profile pass skipped the corpus-order prefix once the target was
    // reached; a target above the template count has already been filled by
    // the weighted loop above.
    out
}

fn find_idx(prefix: &str) -> Option<usize> {
    corpus::CORPUS
        .iter()
        .position(|t| t.cmd.starts_with(prefix))
}

/// The daemon a worker belongs to. Workers without their master look wrong in
/// a process table, so `gen_table` and `gen_inject` add the master first.
fn parent_index(idx: usize) -> Option<usize> {
    let cmd = corpus::CORPUS[idx].cmd;
    if cmd.starts_with("nginx: worker") || cmd.starts_with("nginx: cache") {
        find_idx("nginx: master process")
    } else if cmd.starts_with("apache2 -k start") {
        find_idx("apache2 -DFOREGROUND")
    } else if cmd.starts_with("php-fpm: pool") {
        find_idx("php-fpm: master process")
    } else if cmd.starts_with("gunicorn: worker") {
        find_idx("gunicorn: master")
    } else if cmd.starts_with("postgres: 17/main: ") {
        // The postmaster forks every backend and background worker, so all
        // of them belong to its session, not their own.
        find_idx("/usr/lib/postgresql/17/bin/postgres -D")
    } else if cmd.starts_with("containerd-shim") || cmd.starts_with("/usr/bin/containerd-shim") {
        find_idx("/usr/bin/containerd")
    } else if cmd.starts_with("docker-proxy") {
        find_idx("/usr/sbin/dockerd")
    } else if cmd.starts_with("sshd: ") && !cmd.starts_with("sshd: /usr/sbin/sshd -D") {
        find_idx("sshd: /usr/sbin/sshd -D [listener]")
    } else if cmd.starts_with("(sd-pam)") || cmd.starts_with("/usr/bin/dbus-daemon --session") {
        find_idx("/usr/lib/systemd/systemd --user")
    } else if cmd.starts_with("dovecot/anvil") || cmd.starts_with("dovecot/auth") {
        find_idx("/usr/sbin/dovecot -F")
    } else if cmd.starts_with("qmgr") || cmd.starts_with("pickup") || cmd.starts_with("tlsmgr") {
        find_idx("/usr/lib/postfix/sbin/master -w")
    } else {
        None
    }
}

/// PIDs drawn for a synthetic table stay below `pid_max`, which is 32768 on
/// some embedded and container-tuned kernels. The sequence wraps rather than
/// running past it.
struct Pids {
    next: i64,
    max: i64,
    base: i64,
}

impl Pids {
    fn new(rng: &mut Rng, fit: &Fit) -> Pids {
        let max = if fit.pid_max >= 1024 {
            fit.pid_max as i64 - 1
        } else {
            i64::MAX
        };
        let base = (rng.range(300, 2500) as i64).min(max.max(2));
        Pids {
            next: base,
            max,
            base,
        }
    }

    fn step(&mut self, rng: &mut Rng) -> i32 {
        let delta = rng.range(1, 24) as i64;
        self.next = self.next.saturating_add(delta);
        if self.next > self.max {
            // Wrap to the low end rather than printing a PID the kernel
            // cannot allocate.
            self.next = self.base.max(2).saturating_add(delta);
            if self.next > self.max {
                self.next = 2;
            }
        }
        self.next as i32
    }
}

/// Generate a realistic `ps aux` population. PID 1 is init when the system
/// family is in scope and the corpus contains it; daemons share the boot time.
pub fn gen_table(rng: &mut Rng, opts: &Opts, fit: &Fit) -> Vec<Proc> {
    let weights = corpus::profile_weights(&opts.profile);
    let uptime = util::uptime_secs();
    let mut rows: Vec<Proc> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    let want = if opts.count == 0 { 30 } else { opts.count };

    let sys_in_scope = opts.family.is_none() || opts.family == Some(corpus::FAM_SYS);
    if sys_in_scope {
        if let Some(init_idx) = corpus::CORPUS.iter().position(|t| t.cmd == "/sbin/init") {
            let init = &corpus::CORPUS[init_idx];
            let mut p = make_proc(init, init_idx, rng, opts, uptime);
            p.pid = 1;
            rows.push(p);
            used.push(init_idx);
        }
    }

    let mut pids = Pids::new(rng, fit);
    let mut guard = 0usize;
    let limit = want.saturating_mul(40).saturating_add(1000);
    let mut counts = vec![0usize; corpus::CORPUS.len()];
    while rows.len() < want && guard < limit {
        let idx = pick_index(rng, &weights, opts.family, &used);
        guard += 1;
        if counts[idx] > 0
            && (!repeatable(&corpus::CORPUS[idx])
                || counts[idx] >= repeat_cap(&corpus::CORPUS[idx], want))
        {
            continue;
        }
        counts[idx] += 1;
        if let Some(pidx) = parent_index(idx) {
            if pidx != idx && !used.contains(&pidx) && rows.len() < want {
                let parent = &corpus::CORPUS[pidx];
                let mut pp = make_proc(parent, pidx, rng, opts, uptime);
                pp.pid = pids.step(rng);
                rows.push(pp);
                used.push(pidx);
            }
        }
        used.push(idx);
        let t = &corpus::CORPUS[idx];
        let instances = if t.inst == 0 { 1 } else { t.inst as usize };
        let take = instances.min(want - rows.len());
        for _ in 0..take {
            let mut p = make_proc(t, idx, rng, opts, uptime);
            p.pid = pids.step(rng);
            rows.push(p);
        }
    }
    // Fill a large request from templates that produce a different command
    // line every time. A fixed command is never repeated: `sys -n 200` used to
    // come back as 120 copies of `sshd: user [priv]`, which is not a table a
    // host could produce.
    let mut pending: Vec<Proc> = Vec::new();
    fill(
        rng,
        opts,
        &weights,
        &mut pending,
        want.saturating_sub(rows.len()),
        &mut counts,
        uptime,
    );
    for mut p in pending {
        p.pid = pids.step(rng);
        rows.push(p);
    }
    rows.sort_unstable_by_key(|p| p.pid);
    fit_rows(&mut rows, fit);
    rows
}

/// Fill a population up to `want` with rows the corpus can legitimately
/// supply more than once.
///
/// `-n` is honoured (the tests and the README promise the count), but reaching
/// a large count must not come from one command repeated without limit
/// (`sys -n 200` used to be 120 copies of `sshd: user [priv]`). The remainder
/// is handed out as a *quota* to the templates that may repeat, proportional to
/// their weight, and each template then generates up to its quota. A template
/// whose placeholder changes the command line is also allowed to repeat, so a
/// quota never has to become duplicates of one string.
fn fill(
    rng: &mut Rng,
    opts: &Opts,
    weights: &[u16; 10],
    out: &mut Vec<Proc>,
    want: usize,
    counts: &mut [usize],
    uptime: u64,
) {
    if want == 0 {
        return;
    }
    let mut candidates: Vec<usize> = Vec::new();
    let mut total_w = 0u64;
    for (idx, t) in corpus::CORPUS.iter().enumerate() {
        if opts.family.map(|f| f != t.fam).unwrap_or(false) {
            continue;
        }
        if t.cmd == "/sbin/init" {
            continue;
        }
        if corpus::F_REPEAT & t.flags == 0 && !has_variants(t) {
            continue;
        }
        // A worker added without its master would show PPID 1, which is the
        // shape this fill pass exists to avoid; the main pass links them.
        if parent_index(idx).map(|p| p != idx).unwrap_or(false) {
            continue;
        }
        candidates.push(idx);
        total_w += weights[t.fam as usize] as u64 * t.weight as u64;
    }
    if candidates.is_empty() || total_w == 0 {
        return;
    }
    // Quota per candidate, in proportion to weight, at least one each.
    let mut quota: Vec<usize> = Vec::with_capacity(candidates.len());
    for idx in &candidates {
        let t = &corpus::CORPUS[*idx];
        let w = weights[t.fam as usize] as u64 * t.weight as u64;
        quota.push((want as u64 * w / total_w) as usize);
    }
    // No single command may take more than a small share of the table: a host
    // with 5000 processes has a handful of `cargo build` jobs, not a hundred.
    let cap = (want / 50).max(4);
    for q in quota.iter_mut() {
        if *q > cap {
            *q = cap;
        }
    }
    let mut extra = want.saturating_sub(quota.iter().sum::<usize>());
    // Any leftover goes round-robin, so it is spread instead of accumulating
    // on the first candidate.
    let mut pos = 0usize;
    while extra > 0 {
        quota[pos % candidates.len()] += 1;
        pos += 1;
        extra -= 1;
    }
    for (pos, idx) in candidates.iter().enumerate() {
        let t = &corpus::CORPUS[*idx];
        let mut made = 0usize;
        let mut guard = 0usize;
        while made < quota[pos] && guard < quota[pos].saturating_mul(8) + 16 {
            guard += 1;
            counts[*idx] += 1;
            let mut p = make_proc(t, *idx, rng, opts, uptime);
            p.parent = None;
            out.push(p);
            made += 1;
        }
    }
}

/// Generate processes for injection. The same population as `gen_table`, but
/// no synthetic PIDs: the kernel assigns real ones.
pub fn gen_inject(rng: &mut Rng, opts: &Opts, fit: &Fit) -> Vec<Proc> {
    let weights = corpus::profile_weights(&opts.profile);
    let uptime = util::uptime_secs();
    let want = if opts.count == 0 { 12 } else { opts.count };
    let mut rows: Vec<Proc> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    let mut guard = 0usize;
    let limit = want.saturating_mul(40).saturating_add(1000);
    let mut counts = vec![0usize; corpus::CORPUS.len()];
    while rows.len() < want && guard < limit {
        let idx = pick_index(rng, &weights, opts.family, &used);
        guard += 1;
        if corpus::CORPUS[idx].cmd == "/sbin/init" {
            continue;
        }
        // The first appearance of a template is always allowed; a second one
        // needs a template that may repeat (`F_REPEAT`, or a placeholder that
        // changes the command line) and room under its bound.
        if counts[idx] > 0
            && (!repeatable(&corpus::CORPUS[idx])
                || counts[idx] >= repeat_cap(&corpus::CORPUS[idx], want))
        {
            continue;
        }
        counts[idx] += 1;
        let parent_row = if let Some(pidx) = parent_index(idx) {
            if pidx != idx && !used.contains(&pidx) && rows.len() < want {
                let mut pp = make_proc(&corpus::CORPUS[pidx], pidx, rng, opts, uptime);
                pp.parent = None;
                rows.push(pp);
                used.push(pidx);
                Some(rows.len() - 1)
            } else {
                rows.iter().position(|r| r.tmpl == pidx)
            }
        } else {
            None
        };
        used.push(idx);
        let t = &corpus::CORPUS[idx];
        let instances = if t.inst == 0 { 1 } else { t.inst as usize };
        let take = instances.min(want - rows.len());
        for _ in 0..take {
            let mut p = make_proc(t, idx, rng, opts, uptime);
            p.parent = parent_row;
            rows.push(p);
        }
    }
    // See pad_table: only a template with a placeholder can add a row without
    // repeating a command line.
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut pad_guard = 0usize;
    let pad_limit = want.saturating_mul(40).saturating_add(1000);
    while rows.len() < want && pad_guard < pad_limit {
        pad_guard += 1;
        let idx = weighted_index(rng, &weights, opts.family);
        if counts[idx] >= repeat_cap(&corpus::CORPUS[idx], want) {
            continue;
        }
        counts[idx] += 1;
        let mut p = make_proc(&corpus::CORPUS[idx], idx, rng, opts, uptime);
        if !seen.insert(p.cmd.clone()) {
            continue;
        }
        p.parent = None;
        rows.push(p);
    }
    fit_rows(&mut rows, fit);
    rows
}

/// Lower any planned size a row cannot physically have on this host.
///
/// The corpus carries absolute VSZ/RSS values, so on a container smaller than
/// the largest template the table would claim more RSS than exists and a
/// `%MEM` above 100. The relative shape is kept: every scale is applied to the
/// whole population, never to one row.
pub fn fit_rows(rows: &mut [Proc], fit: &Fit) {
    if fit.mem_kb == 0 || rows.is_empty() {
        return;
    }
    let page = sys::page_kb().max(1);
    let budget = fit.mem_kb.saturating_sub(fit.mem_kb / 20).max(page);
    let total: u64 = rows.iter().map(|p| p.rss as u64).sum();
    if total > budget {
        // The sum of every RSS is the strictest reading: a real host can hold
        // them all resident at once. Scale every row by the same factor, with
        // one page as the floor so a tiny template is not reduced to nothing.
        let factor = budget as f64 / total as f64;
        for p in rows.iter_mut() {
            let v = ((p.rss as f64) * factor).max(page as f64);
            p.rss = crate::table::round_up(v as u64, page).min(u32::MAX as u64) as u32;
            if p.vsz < p.rss {
                p.vsz = p.rss;
            }
        }
    }
    // A single row still cannot exceed the host, whatever the sum says.
    for p in rows.iter_mut() {
        let cap = budget.min(u32::MAX as u64);
        if p.rss as u64 > cap {
            p.rss = crate::table::round_up(cap, page).min(u32::MAX as u64) as u32;
        }
        if p.vsz < p.rss {
            p.vsz = p.rss;
        }
    }
}

fn is_file(path: &[u8]) -> bool {
    std::fs::metadata(Path::new(OsStr::from_bytes(path)))
        .map(|m| m.is_file())
        .unwrap_or(false)
}

fn is_exec_file(path: &[u8]) -> bool {
    is_file(path) && sys::access(path, sys::X_OK)
}

fn strip_colon(first: &[u8]) -> &[u8] {
    if let Some(rest) = first.strip_suffix(b":") {
        rest
    } else if let Some(pos) = first.iter().position(|b| *b == b':') {
        &first[..pos]
    } else {
        first
    }
}

fn which(name: &[u8]) -> Option<Vec<u8>> {
    for dir in [
        &b"/usr/local/sbin/"[..],
        &b"/usr/local/bin/"[..],
        &b"/usr/sbin/"[..],
        &b"/usr/bin/"[..],
        &b"/sbin/"[..],
        &b"/bin/"[..],
    ] {
        let mut path = Vec::with_capacity(dir.len() + name.len());
        path.extend_from_slice(dir);
        path.extend_from_slice(name);
        if is_exec_file(&path) {
            return Some(path);
        }
    }
    None
}

/// The executable path a template's process would have on a real system.
/// The path does not have to exist on this host: `inject` creates it inside
/// the stub's private mount namespace.
pub fn template_exe(t: &Tmpl) -> Vec<u8> {
    let bytes = t.cmd.as_bytes();
    let mut tokens = bytes.split(|b| *b == b' ');
    let first = tokens.next().unwrap_or(bytes);
    let name = strip_colon(first);
    let base = str::basename(name);

    if first.starts_with(b"/") && is_exec_file(first) {
        return first.to_vec();
    }
    if first == b"(sd-pam)" {
        return b"/usr/lib/systemd/systemd".to_vec();
    }
    if first.starts_with(b"dovecot/") {
        let mut p = b"/usr/lib/dovecot/".to_vec();
        p.extend_from_slice(&first[8..]);
        return p;
    }
    if base == b"nginx" {
        return b"/usr/sbin/nginx".to_vec();
    }
    if base == b"apache2" {
        return b"/usr/sbin/apache2".to_vec();
    }
    if base == b"php-fpm" {
        return b"/usr/sbin/php-fpm".to_vec();
    }
    if base == b"gunicorn" {
        return b"/usr/local/bin/gunicorn".to_vec();
    }
    if base == b"postgres" {
        return b"/usr/lib/postgresql/17/bin/postgres".to_vec();
    }
    if base.starts_with(b"containerd-shim") {
        return b"/usr/bin/containerd-shim-runc-v2".to_vec();
    }
    if base == b"docker-proxy" {
        return b"/usr/bin/docker-proxy".to_vec();
    }
    if base == b"sshd" {
        return b"/usr/sbin/sshd".to_vec();
    }
    if base == b"qmgr" || base == b"pickup" || base == b"tlsmgr" {
        let mut p = b"/usr/lib/postfix/sbin/".to_vec();
        p.extend_from_slice(base);
        return p;
    }
    if let Some(p) = which(name) {
        return p;
    }
    for token in tokens {
        if token.starts_with(b"/") && !token.contains(&b'{') && is_exec_file(token) {
            return token.to_vec();
        }
    }
    if first.starts_with(b"/") && !first.contains(&b'{') {
        let p = Path::new(OsStr::from_bytes(first));
        if !p.exists() || is_exec_file(first) {
            return first.to_vec();
        }
    }
    let mut p = b"/usr/sbin/".to_vec();
    p.extend_from_slice(name);
    p
}

pub fn stub_name(cmd: &[u8]) -> &[u8] {
    let first = match cmd.iter().position(|b| *b == b' ') {
        Some(p) => &cmd[..p],
        None => cmd,
    };
    if let Some(rest) = first.strip_suffix(b":") {
        rest
    } else if let Some(p) = first.iter().position(|b| *b == b':') {
        &first[..p]
    } else {
        str::basename(first)
    }
}
