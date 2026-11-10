//! Process generation: template expansion, realistic jitter, table rows.

use crate::corpus::{self, Tmpl};
use crate::rng::Rng;
use crate::str::{self, Buf};
use crate::sys;
use crate::util;
use std::collections::{BTreeMap, BTreeSet};
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
    /// The seed the caller used, for reports that have to name it.
    pub seed: u64,
    /// `--host-uptime`: pretend the host has been up this long. `None` reads
    /// `/proc/uptime`.
    pub uptime: Option<u64>,
    pub profile: Vec<u8>,
    pub family: Option<u8>,
    pub self_user: Vec<u8>,
    pub uniq: bool,
    /// `--repeat-max`: raise the per-command repeat bound so a count the corpus
    /// cannot supply realistically is still met. `None` keeps the bound.
    pub repeat_max: Option<usize>,
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
    /// How many distinct PIDs a synthetic table can show.
    ///
    /// PID 1 is always init in a generated table, so the usable space is
    /// `2 .. pid_max - 1`: PID 0 and the negative PIDs the kernel reserves are
    /// not something `ps` ever shows. A `pid_max` below 3 leaves no room at
    /// all, which is a property of the host, not something to paper over with
    /// a duplicate. 0 means "unknown": no cap.
    pub fn pid_capacity(&self) -> Option<usize> {
        if self.pid_max == 0 {
            return None;
        }
        Some(self.pid_max.saturating_sub(2) as usize)
    }

    /// Why a table cannot hold `want` rows, if the host limits it.
    pub fn shortfall_reason(&self, want: usize) -> Option<String> {
        let cap = self.pid_capacity()?;
        // PID 1 is init, so the table can show `cap` more rows.
        let room = cap.saturating_add(1);
        if want <= room {
            return None;
        }
        let pids = if self.pid_max > 3 {
            format!("PID 1 and 2..{}", self.pid_max - 1)
        } else {
            "PID 1 alone".to_string()
        };
        Some(format!(
            "pid_max is {}, so a snapshot can hold {} {} ({})",
            self.pid_max,
            room,
            if room == 1 { "process" } else { "processes" },
            pids
        ))
    }
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

    /// The limits of a host named on the command line, falling back to this
    /// one for whichever value was not given.
    ///
    /// This exists so a table can be generated *for* another machine — a 512 MiB
    /// container, or a host with a small `pid_max` — and so the fit logic can be
    /// exercised end to end in a test on a machine that has neither.
    pub fn target(mem_mb: Option<u64>, pid_max: Option<u64>) -> Fit {
        let host = Fit::host();
        Fit {
            mem_kb: mem_mb
                .map(|m| m.saturating_mul(1024))
                .unwrap_or(host.mem_kb),
            pid_max: pid_max.unwrap_or(host.pid_max),
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
fn repeat_cap(t: &Tmpl, opts: &Opts) -> usize {
    if let Some(n) = opts.repeat_max {
        // The caller asked for the count no matter what: 0 means no cap.
        return if n == 0 { usize::MAX } else { n };
    }
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

fn cand_weight(t: &Tmpl, weights: &[u16; 10], family: Option<u8>) -> u64 {
    match family {
        Some(_) => t.weight as u64,
        None => weights[t.fam as usize] as u64 * t.weight as u64,
    }
}

fn weighted_total(weights: &[u16; 10], family: Option<u8>) -> u64 {
    let mut total = 0u64;
    for t in corpus::CORPUS.iter() {
        if let Some(f) = family {
            if t.fam != f {
                continue;
            }
        }
        total += cand_weight(t, weights, family);
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
        let w = cand_weight(t, weights, family);
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

fn resolve_user_cached(
    t: &Tmpl,
    opts: &Opts,
    cache: &mut BTreeMap<Vec<u8>, (u32, u32)>,
) -> (Vec<u8>, u32, u32) {
    let lookup = |name: &[u8], cache: &mut BTreeMap<Vec<u8>, (u32, u32)>| -> (u32, u32) {
        if let Some(v) = cache.get(name) {
            return *v;
        }
        let v = util::lookup_user(name).unwrap_or_else(|| {
            if let Some(sv) = cache.get(&opts.self_user) {
                *sv
            } else {
                let sv = util::lookup_user(&opts.self_user).unwrap_or_else(|| {
                    let me = util::current_user();
                    (me.uid, me.gid)
                });
                cache.insert(opts.self_user.clone(), sv);
                sv
            }
        });
        cache.insert(name.to_vec(), v);
        v
    };
    if t.user == corpus::SELF_USER {
        let (uid, gid) = lookup(&opts.self_user, cache);
        return (opts.self_user.clone(), uid, gid);
    }
    let name = t.user.as_bytes().to_vec();
    let (uid, gid) = lookup(&name, cache);
    (name, uid, gid)
}

fn boot_age(rng: &mut Rng, uptime: u64) -> u64 {
    // One draw with a fixed modulus. The fallback reuses that draw rather
    // than taking a second one: a second draw on a short-uptime host would
    // move every later value in the stream and break the same-seed contract
    // between uptime 10 and uptime 11.
    let age = rng.fraction(90);
    // A row cannot have started before the host booted. `uptime.saturating_sub`
    // used to fall through to a 30..600 s age when the draw was longer than
    // the uptime, which invented a START before boot on a host up seconds.
    age.min(uptime)
}

fn make_proc(
    t: &Tmpl,
    tmpl: usize,
    rng: &mut Rng,
    opts: &Opts,
    uptime: u64,
    cache: &mut BTreeMap<Vec<u8>, (u32, u32)>,
) -> Proc {
    let (user, uid, gid) = resolve_user_cached(t, opts, cache);
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
        boot_age(rng, uptime)
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
    // No row can have started before the host booted. The branch above only
    // bounded `boot_age`; the dev, desk and default ages ignored the uptime
    // entirely, so `--host-uptime 0` still showed rows from weeks earlier.
    let age = age.min(uptime);
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
    let mut fixed_used = vec![false; corpus::CORPUS.len()];
    let mut drawn = vec![false; corpus::CORPUS.len()];
    for (idx, t) in corpus::CORPUS.iter().enumerate() {
        if opts.family.map(|f| f == t.fam).unwrap_or(true) {
            drawn[idx] = true;
            push(
                expand(t.cmd, rng, &opts.self_user, None),
                &mut out,
                &mut seen,
            );
            fixed_used[idx] = true;
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
        if !drawn[idx] {
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
            fixed_used[idx] = true;
        }
    }

    // Second pass: weighted draws over templates that can still produce a new
    // command line (those with variable placeholders, plus any fixed template
    // not yet emitted).
    let mut var_pool: Vec<usize> = Vec::new();
    for (idx, t) in corpus::CORPUS.iter().enumerate() {
        if let Some(f) = opts.family {
            if t.fam != f {
                continue;
            }
        }
        if has_variants(t) || !fixed_used[idx] {
            var_pool.push(idx);
        }
    }
    let mut guard = 0usize;
    let limit = target.saturating_mul(20).saturating_add(500);
    while out.len() < target && guard < limit && !var_pool.is_empty() {
        let pos = weighted_pick(&var_pool, rng, &weights);
        let idx = var_pool[pos];
        let t = &corpus::CORPUS[idx];
        guard += 1;
        if !has_variants(t) {
            fixed_used[idx] = true;
            var_pool.swap_remove(pos);
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
/// Allocates the synthetic PIDs of one table.
///
/// The host decides the space: PID 1 is init, so usable PIDs are
/// `2 .. pid_max - 1`. Every PID handed out is unique for the life of the
/// allocator, and an allocator that runs out says so instead of wrapping into a
/// duplicate: a `ps` snapshot cannot show two processes with the same PID, and
/// silently repeating one is exactly the defect the review found.
struct Pids {
    next: i64,
    /// Highest PID this allocator may return; 0 means unlimited.
    max: i64,
    used: BTreeSet<i32>,
    /// Free PIDs left, when the space is bounded.
    free: Option<usize>,
}

impl Pids {
    fn new(rng: &mut Rng, fit: &Fit) -> Pids {
        let (max, free) = match fit.pid_capacity() {
            // pid_max below 3 leaves no usable PID at all.
            Some(0) => (0, Some(0)),
            Some(cap) => (fit.pid_max as i64 - 1, Some(cap)),
            None => (0, None),
        };
        let lo = 2i64;
        let hi = if max > 0 { max } else { 2_500 };
        let base = (rng.range(300, 2500) as i64).clamp(lo, hi.max(lo));
        Pids {
            next: base,
            max,
            used: BTreeSet::new(),
            free,
        }
    }

    /// The next unused PID, or `None` when the space is exhausted.
    ///
    /// A `ps` snapshot has one row per PID, so a collision steps forward one at
    /// a time: a stride that shares a factor with the PID space cannot cycle
    /// past the free PIDs. The search is bounded by the space itself, so an
    /// exhausted allocator returns `None` rather than a duplicate.
    fn step(&mut self, rng: &mut Rng) -> Option<i32> {
        if let Some(0) = self.free {
            // `pid_max` below 3: the host has no PID to give.
            return None;
        }
        let tries = match self.max {
            0 => 2_500, // unknown space: practically unbounded
            m => (m as usize).max(2),
        };
        let delta = rng.range(1, 24) as i64;
        let mut step = delta;
        for attempt in 0..tries {
            if attempt > 0 {
                // Walk one by one after the first collision, so every free PID
                // in the space is reachable.
                step = 1;
            }
            self.next = self.next.saturating_add(step);
            if self.max > 0 && self.next > self.max {
                self.next = 2;
            }
            if self.next < 2 {
                self.next = 2;
            }
            let pid = self.next as i32;
            if self.used.insert(pid) {
                if let Some(f) = &mut self.free {
                    *f = f.saturating_sub(1);
                }
                return Some(pid);
            }
            if let Some(0) = self.free {
                return None;
            }
        }
        None
    }
}

/// Generate a realistic `ps aux` population. PID 1 is init when the system
/// family is in scope and the corpus contains it; daemons share the boot time.
pub fn gen_table(rng: &mut Rng, opts: &Opts, fit: &Fit) -> Vec<Proc> {
    let weights = corpus::profile_weights(&opts.profile);
    let uptime = opts.uptime.unwrap_or_else(util::uptime_secs);
    let mut rows: Vec<Proc> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    let mut user_cache: BTreeMap<Vec<u8>, (u32, u32)> = BTreeMap::new();
    let mut emitted: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    let want = if opts.count == 0 { 30 } else { opts.count };

    let sys_in_scope = opts.family.is_none() || opts.family == Some(corpus::FAM_SYS);
    if sys_in_scope {
        if let Some(init_idx) = corpus::CORPUS.iter().position(|t| t.cmd == "/sbin/init") {
            let init = &corpus::CORPUS[init_idx];
            let p = make_proc(init, init_idx, rng, opts, uptime, &mut user_cache);
            *emitted.entry(p.cmd.clone()).or_insert(0) += 1;
            rows.push(p);
            used.push(init_idx);
        }
    }

    let mut guard = 0usize;
    let limit = want.saturating_mul(40).saturating_add(1000);
    let mut counts = vec![0usize; corpus::CORPUS.len()];
    while rows.len() < want && guard < limit {
        let idx = pick_index(rng, &weights, opts.family, &used);
        guard += 1;
        if counts[idx] > 0
            && (!repeatable(&corpus::CORPUS[idx])
                || counts[idx] >= repeat_cap(&corpus::CORPUS[idx], opts))
        {
            continue;
        }
        counts[idx] += 1;
        if let Some(pidx) = parent_index(idx) {
            if pidx != idx && !used.contains(&pidx) && rows.len() < want {
                let parent = &corpus::CORPUS[pidx];
                let pp = make_proc(parent, pidx, rng, opts, uptime, &mut user_cache);
                if opts
                    .repeat_max
                    .map(|b| b == 0 || *emitted.get(&pp.cmd).unwrap_or(&0) < b)
                    .unwrap_or(true)
                {
                    *emitted.entry(pp.cmd.clone()).or_insert(0) += 1;
                    rows.push(pp);
                    used.push(pidx);
                }
            }
        }
        used.push(idx);
        let t = &corpus::CORPUS[idx];
        let instances = if t.inst == 0 { 1 } else { t.inst as usize };
        let take = instances.min(want - rows.len());
        for _ in 0..take {
            let p = make_proc(t, idx, rng, opts, uptime, &mut user_cache);
            if let Some(bound) = opts.repeat_max {
                if bound != 0 && *emitted.get(&p.cmd).unwrap_or(&0) >= bound {
                    continue;
                }
            }
            *emitted.entry(p.cmd.clone()).or_insert(0) += 1;
            rows.push(p);
        }
    }
    fill(
        rng,
        opts,
        &weights,
        &mut rows,
        want,
        &mut counts,
        uptime,
        &mut user_cache,
    );
    // PIDs last: the host's PID space decides how many rows can exist at all,
    // and one pass over the finished population honours it exactly.
    let mut pids = Pids::new(rng, fit);
    let mut out: Vec<Proc> = Vec::with_capacity(rows.len());
    for (i, mut p) in rows.into_iter().enumerate() {
        let pid = if i == 0 && p.cmd == b"/sbin/init"[..] {
            1
        } else {
            match pids.step(rng) {
                Some(pid) => pid,
                None => break,
            }
        };
        p.pid = pid;
        out.push(p);
    }
    out.sort_unstable_by_key(|p| p.pid);
    fit_rows(&mut out, fit);
    out
}

/// Fill a population up to `want` with rows the corpus can legitimately supply
/// more than once.
///
/// `-n` is a guarantee for `table` and `inject`, so this pass reaches the count
/// whenever any in-scope template can repeat. With `k` candidates and `need`
/// rows, the pigeonhole minimum for the busiest command is `ceil(need / k)`, so
/// that is the bound: the remainder is split *evenly* rather than
/// weight-proportionally, which is the most realistic table the count allows and
/// the least dominant distribution that can still reach it. Weight decides only
/// the leftover when `need` does not divide by `k`.
///
/// `--repeat-max N` overrides the bound (0 = unlimited). A caller who would
/// rather have fewer rows than a repeated command gets that with
/// `--repeat-max 1`, at the cost of the count.
///
/// A template whose row costs more than one (a worker needs its master) links to
/// an existing master when the main pass produced one, and adds one only when it
/// must.
#[allow(clippy::too_many_arguments)]
fn fill(
    rng: &mut Rng,
    opts: &Opts,
    weights: &[u16; 10],
    out: &mut Vec<Proc>,
    want: usize,
    counts: &mut [usize],
    uptime: u64,
    user_cache: &mut BTreeMap<Vec<u8>, (u32, u32)>,
) {
    if out.len() >= want {
        return;
    }
    let mut candidates: Vec<(usize, usize)> = Vec::new();
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
        let extra = parent_index(idx).map(|p| p != idx).unwrap_or(false) as usize;
        // A candidate must be able to afford its own row plus, if it is a
        // worker, a master that is not there yet.
        candidates.push((idx, extra));
    }
    if candidates.is_empty() {
        return;
    }
    let need = want - out.len();
    let k = candidates.len();
    let bound = match opts.repeat_max {
        Some(0) => usize::MAX,
        Some(n) => n,
        None => need.div_ceil(k).max(1),
    };
    // Even split; the remainder goes to the heavier templates first.
    let mut quota: Vec<usize> = vec![(need / k).min(bound); k];
    let mut rest = need.saturating_sub(quota.iter().sum::<usize>());
    let shares: Vec<u64> = candidates
        .iter()
        .map(|(idx, _)| cand_weight(&corpus::CORPUS[*idx], weights, opts.family))
        .collect();
    let total: u64 = shares.iter().sum::<u64>().max(1);
    let mut frac: Vec<(u64, usize)> = shares
        .iter()
        .enumerate()
        .map(|(i, w)| (w * need as u64 % total, i))
        .collect();
    frac.sort_unstable_by(|a, b| b.cmp(a));
    let mut fi = 0usize;
    while rest > 0 {
        let pos = frac[fi % k].1;
        fi += 1;
        if quota[pos] >= bound {
            // Everything is at the bound; the caller asked for a cap that
            // cannot reach the count, and `shortfall` reports the gap.
            if frac.iter().all(|(_, p)| quota[*p] >= bound) {
                break;
            }
            continue;
        }
        quota[pos] += 1;
        rest -= 1;
    }
    // `--repeat-max` bounds how often one *command line* may appear, not how
    // often one template may be drawn: two templates can expand to the same
    // command, and a caller who asked for no repeats means no repeats.
    let mut emitted: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for p in out.iter() {
        *emitted.entry(p.cmd.clone()).or_insert(0) += 1;
    }
    let command_bound = opts.repeat_max;
    for (pos, (idx, _)) in candidates.iter().enumerate() {
        let t = &corpus::CORPUS[*idx];
        let mut parent_row = parent_index(*idx).and_then(|pidx| {
            if pidx == *idx {
                None
            } else {
                out.iter().position(|r| r.tmpl == pidx)
            }
        });
        for _ in 0..quota[pos] {
            if out.len() >= want {
                return;
            }
            if parent_row.is_none() {
                if let Some(pidx) = parent_index(*idx) {
                    if pidx != *idx && out.len() + 1 < want {
                        let mut pp =
                            make_proc(&corpus::CORPUS[pidx], pidx, rng, opts, uptime, user_cache);
                        pp.parent = None;
                        if command_bound
                            .map(|b| b == 0 || *emitted.get(&pp.cmd).unwrap_or(&0) < b)
                            .unwrap_or(true)
                        {
                            *emitted.entry(pp.cmd.clone()).or_insert(0) += 1;
                            out.push(pp);
                            parent_row = Some(out.len() - 1);
                        }
                    }
                }
            }
            let mut p = make_proc(t, *idx, rng, opts, uptime, user_cache);
            let seen = *emitted.get(&p.cmd).unwrap_or(&0);
            if let Some(bound) = command_bound {
                if bound != 0 && seen >= bound {
                    continue;
                }
            }
            *emitted.entry(p.cmd.clone()).or_insert(0) += 1;
            counts[*idx] += 1;
            p.parent = parent_row;
            out.push(p);
        }
    }
}

/// Generate processes for injection. The same population as `gen_table`, but
/// no synthetic PIDs: the kernel assigns real ones.
pub fn gen_inject(rng: &mut Rng, opts: &Opts, fit: &Fit) -> Vec<Proc> {
    let weights = corpus::profile_weights(&opts.profile);
    let uptime = opts.uptime.unwrap_or_else(util::uptime_secs);
    let want = if opts.count == 0 { 12 } else { opts.count };
    let mut rows: Vec<Proc> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    let mut user_cache: BTreeMap<Vec<u8>, (u32, u32)> = BTreeMap::new();
    let mut emitted: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    let mut guard = 0usize;
    let limit = want.saturating_mul(40).saturating_add(1000);
    let mut counts = vec![0usize; corpus::CORPUS.len()];
    while rows.len() < want && guard < limit {
        let idx = pick_index(rng, &weights, opts.family, &used);
        guard += 1;
        if corpus::CORPUS[idx].cmd == "/sbin/init" {
            continue;
        }
        if counts[idx] > 0
            && (!repeatable(&corpus::CORPUS[idx])
                || counts[idx] >= repeat_cap(&corpus::CORPUS[idx], opts))
        {
            continue;
        }
        counts[idx] += 1;
        let parent_row = if let Some(pidx) = parent_index(idx) {
            if pidx != idx && !used.contains(&pidx) && rows.len() < want {
                let mut pp = make_proc(
                    &corpus::CORPUS[pidx],
                    pidx,
                    rng,
                    opts,
                    uptime,
                    &mut user_cache,
                );
                pp.parent = None;
                if opts
                    .repeat_max
                    .map(|b| b == 0 || *emitted.get(&pp.cmd).unwrap_or(&0) < b)
                    .unwrap_or(true)
                {
                    *emitted.entry(pp.cmd.clone()).or_insert(0) += 1;
                    rows.push(pp);
                    used.push(pidx);
                    Some(rows.len() - 1)
                } else {
                    rows.iter().position(|r| r.tmpl == pidx)
                }
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
            let mut p = make_proc(t, idx, rng, opts, uptime, &mut user_cache);
            if let Some(bound) = opts.repeat_max {
                if bound != 0 && *emitted.get(&p.cmd).unwrap_or(&0) >= bound {
                    continue;
                }
            }
            *emitted.entry(p.cmd.clone()).or_insert(0) += 1;
            p.parent = parent_row;
            rows.push(p);
        }
    }
    fill(
        rng,
        opts,
        &weights,
        &mut rows,
        want,
        &mut counts,
        uptime,
        &mut user_cache,
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn proc_of(rss: u32, vsz: u32) -> Proc {
        Proc {
            cmd: b"x".to_vec(),
            tty: Vec::new(),
            user: b"root".to_vec(),
            uid: 0,
            gid: 0,
            vsz,
            rss,
            cpu: 0,
            flags: 0,
            age: 0,
            pid: 0,
            tmpl: 0,
            parent: None,
            stat_override: None,
        }
    }

    #[test]
    fn fit_lowers_a_row_the_host_cannot_hold() {
        // 1 GiB host, two rows that each claim 2 GiB.
        let mut rows = vec![proc_of(2_097_152, 4_194_304), proc_of(2_097_152, 4_194_304)];
        let fit = Fit {
            mem_kb: 1_048_576,
            pid_max: 4_194_304,
        };
        fit_rows(&mut rows, &fit);
        for p in &rows {
            assert!(
                (p.rss as u64) <= fit.mem_kb,
                "rss {} above the 1 GiB host",
                p.rss
            );
            assert!(p.vsz >= p.rss, "vsz {} below rss {}", p.vsz, p.rss);
        }
    }

    #[test]
    fn fit_leaves_a_host_that_fits_alone() {
        let mut rows = vec![proc_of(1024, 4096)];
        let fit = Fit {
            mem_kb: 12 * 1024 * 1024,
            pid_max: 4_194_304,
        };
        fit_rows(&mut rows, &fit);
        assert_eq!(rows[0].rss, 1024);
        assert_eq!(rows[0].vsz, 4096);
    }

    #[test]
    fn pids_stay_below_pid_max() {
        let mut rng = Rng::new(7);
        let fit = Fit {
            mem_kb: 0,
            pid_max: 32768,
        };
        let mut pids = Pids::new(&mut rng, &fit);
        for _ in 0..5000 {
            let p = pids.step(&mut rng).expect("plenty of space") as u64;
            assert!(p < fit.pid_max, "pid {} at or above pid_max", p);
            assert!(p > 1, "pid {} is reserved", p);
        }
    }

    #[test]
    fn a_tiny_pid_space_yields_exactly_that_many_unique_pids() {
        for pid_max in [3u64, 4, 5, 10, 100] {
            let mut rng = Rng::new(11);
            let fit = Fit { mem_kb: 0, pid_max };
            let mut pids = Pids::new(&mut rng, &fit);
            let want = (pid_max - 2) as usize;
            let mut seen = BTreeSet::new();
            for i in 0..want {
                let p = pids
                    .step(&mut rng)
                    .unwrap_or_else(|| panic!("pid_max {} ran out at {}", pid_max, i));
                assert!(p >= 2, "pid {} is below 2", p);
                assert!(
                    (p as u64) < pid_max,
                    "pid {} is at or above pid_max {}",
                    p,
                    pid_max
                );
                assert!(seen.insert(p), "pid {} was handed out twice", p);
            }
            assert!(
                pids.step(&mut rng).is_none(),
                "pid_max {} gave out more than its {} usable PIDs",
                pid_max,
                want
            );
        }
    }

    #[test]
    fn pid_max_below_three_has_no_usable_space() {
        for pid_max in [0u64, 1, 2] {
            let fit = Fit { mem_kb: 0, pid_max };
            if pid_max == 0 {
                // 0 means "unknown", which must not be read as "no PIDs".
                assert!(fit.pid_capacity().is_none());
                continue;
            }
            assert_eq!(fit.pid_capacity(), Some(0));
            let mut rng = Rng::new(3);
            let mut pids = Pids::new(&mut rng, &fit);
            assert!(
                pids.step(&mut rng).is_none(),
                "pid_max {} produced a PID",
                pid_max
            );
            // And the table says so rather than printing a PID the host cannot
            // have.
            let opts = Opts {
                count: 50,
                seed: 0,
                profile: b"server".to_vec(),
                family: None,
                self_user: b"root".to_vec(),
                uniq: true,
                repeat_max: None,
                uptime: None,
            };
            let mut rng = Rng::new(3);
            let rows = gen_table(&mut rng, &opts, &fit);
            for p in &rows {
                assert!(
                    p.pid >= 1 && (p.pid as u64) <= pid_max,
                    "pid {} out of range",
                    p.pid
                );
            }
            assert!(
                fit.shortfall_reason(50).is_some(),
                "pid_max {} did not report a shortfall",
                pid_max
            );
        }
    }

    #[test]
    fn a_table_never_repeats_a_pid_when_the_space_is_small() {
        let opts = Opts {
            count: 60,
            seed: 0,
            profile: b"server".to_vec(),
            family: None,
            self_user: b"root".to_vec(),
            uniq: true,
            repeat_max: None,
            uptime: None,
        };
        for pid_max in [10u64, 37, 100, 500] {
            let fit = Fit { mem_kb: 0, pid_max };
            let mut rng = Rng::new(5);
            let rows = gen_table(&mut rng, &opts, &fit);
            let mut seen = BTreeSet::new();
            for p in &rows {
                assert!(
                    (p.pid as u64) < pid_max,
                    "pid {} at or above pid_max {}",
                    p.pid,
                    pid_max
                );
                assert!(seen.insert(p.pid), "pid {} appeared twice", p.pid);
            }
            let room = (pid_max - 1) as usize;
            assert!(
                rows.len() <= room,
                "pid_max {} produced {} rows with room for {}",
                pid_max,
                rows.len(),
                room
            );
            if rows.len() < 60 {
                assert!(
                    fit.shortfall_reason(60).is_some(),
                    "pid_max {} silently under-delivered",
                    pid_max
                );
            }
        }
    }

    #[test]
    fn pids_are_unique_within_one_table() {
        let mut rng = Rng::new(7);
        let fit = Fit {
            mem_kb: 0,
            pid_max: 32768,
        };
        let mut pids = Pids::new(&mut rng, &fit);
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..5000 {
            let p = pids.step(&mut rng).expect("plenty of space");
            assert!(seen.insert(p), "pid {} repeated at {}", p, i);
        }
    }

    #[test]
    fn boot_age_keeps_the_stream_at_low_uptime() {
        // The same seed must produce the same later values whether the host
        // has been up 10 or 11 seconds. Only the age itself may differ.
        let mut a = Rng::new(165);
        let mut b = Rng::new(165);
        let _ = boot_age(&mut a, 10);
        let _ = boot_age(&mut b, 11);
        for _ in 0..16 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn only_a_varying_template_counts_as_repeatable_on_its_own() {
        let sshd = corpus::CORPUS
            .iter()
            .find(|t| t.cmd.starts_with("sshd: {user} @") || t.cmd.starts_with("sshd: {user}@"))
            .expect("the sshd pty row");
        // `{user}` is the same for a whole run, so it is not a variant.
        if !(sshd.flags & corpus::F_REPEAT != 0) {
            assert!(!has_variants(sshd));
        }
        let init = corpus::CORPUS
            .iter()
            .find(|t| t.cmd == "/sbin/init")
            .expect("/sbin/init");
        assert!(!has_variants(init));
        assert!(!repeatable(init));
        let shim = corpus::CORPUS
            .iter()
            .find(|t| t.cmd.starts_with("containerd-shim-runc-v2"))
            .expect("a shim");
        assert!(has_variants(shim));
        assert!(repeatable(shim));
    }
}
