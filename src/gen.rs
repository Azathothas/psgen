//! Process generation: template expansion, realistic jitter, table rows.

use crate::corpus::{self, Tmpl};
use crate::rng::Rng;
use crate::str::{self, Buf};
use crate::sys;
use crate::util;
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

/// Single-instance daemons are picked at most once, so a generated table does
/// not show two sshd listeners or two PID-1 processes. Build tools and desktop
/// applications are allowed to repeat.
fn pick_index(rng: &mut Rng, weights: &[u16; 10], family: Option<u8>, used: &[usize]) -> usize {
    let mut fallback = 0;
    for _ in 0..80 {
        let idx = weighted_index(rng, weights, family);
        let t = &corpus::CORPUS[idx];
        let single = t.inst <= 1;
        let unique_family = t.fam != corpus::FAM_DEV;
        if single && unique_family && used.contains(&idx) {
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
    let mut cpu = t.cpu as i32 + rng.range(0, 4) as i32 - 2;
    if cpu < 0 {
        cpu = 0;
    }
    if cpu > 999 {
        cpu = 999;
    }
    let age = if t.flags & (corpus::F_LONG | corpus::F_SESSION) != 0 {
        let base = uptime.saturating_sub(rng.range(0, 90));
        if base == 0 {
            rng.range(30, 600)
        } else {
            base
        }
    } else if t.flags & (corpus::F_BUSY | corpus::F_SHORT) != 0 {
        rng.range(3, 1800)
    } else if t.flags & corpus::F_CHILD != 0 {
        let up = uptime.max(60);
        // Pick a boot-relative start with a fixed-point draw. A plain
        // rng.range(5, up) reduces a fresh random word modulo `up`, and
        // `up` grows by one every second, so the same seed produced a
        // different age on every run. Scaling a 32-bit draw keeps the
        // start stable to within a second as uptime advances.
        let span = up.saturating_sub(5).max(1);
        let draw = rng.next_u64() >> 32;
        let offset = span.saturating_mul(draw) / (1u64 << 32);
        up.saturating_sub(offset)
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
/// means one per template. Beyond the template count, placeholders are
/// re-expanded to produce new variants.
pub fn gen_list(rng: &mut Rng, opts: &Opts) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let uniq = opts.uniq;
    let push = |cmd: Vec<u8>, out: &mut Vec<Vec<u8>>, seen: &mut Vec<Vec<u8>>| {
        if !uniq || !seen.iter().any(|s| s == &cmd) {
            seen.push(cmd.clone());
            out.push(cmd);
        }
    };

    if opts.count == 0 {
        for t in corpus::CORPUS.iter() {
            if let Some(f) = opts.family {
                if t.fam != f {
                    continue;
                }
            }
            push(expand(t.cmd, rng, &opts.self_user, None), &mut out, &mut seen);
        }
        return out;
    }

    let weights = corpus::profile_weights(&opts.profile);
    // The corpus can only produce so many distinct lines. Placeholder-bearing
    // templates have many variants; fixed ones have exactly one. Capping here
    // keeps memory bounded while duplicates are rejected.
    let target = opts.count.min(2000);
    let mut fixed_used: Vec<usize> = Vec::new();
    // First pass: the first `target` templates in corpus order.
    for (idx, t) in corpus::CORPUS.iter().enumerate() {
        if out.len() >= target {
            break;
        }
        if let Some(f) = opts.family {
            if t.fam != f {
                continue;
            }
        }
        push(expand(t.cmd, rng, &opts.self_user, None), &mut out, &mut seen);
        if !t.cmd.contains('{') {
            fixed_used.push(idx);
        }
    }
    // Second pass: weighted variants until the requested count is reached.
    let mut guard = 0usize;
    while out.len() < target && guard < target * 40 + 1000 {
        let idx = weighted_index(rng, &weights, opts.family);
        let t = &corpus::CORPUS[idx];
        if !t.cmd.contains('{') && fixed_used.contains(&idx) {
            guard += 1;
            continue;
        }
        push(expand(t.cmd, rng, &opts.self_user, None), &mut out, &mut seen);
        if !t.cmd.contains('{') {
            fixed_used.push(idx);
        }
        guard += 1;
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

/// Generate a realistic `ps aux` population. PID 1 is init when the system
/// family is in scope and the corpus contains it; daemons share the boot time.
pub fn gen_table(rng: &mut Rng, opts: &Opts) -> Vec<Proc> {
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

    let mut pid = rng.range(300, 2500) as i32;
    let mut guard = 0usize;
    while rows.len() < want && guard < want * 40 + 1000 {
        let idx = pick_index(rng, &weights, opts.family, &used);
        if corpus::CORPUS[idx].inst <= 1
            && corpus::CORPUS[idx].fam != corpus::FAM_DEV
            && used.contains(&idx)
        {
            guard += 1;
            continue;
        }
        if let Some(pidx) = parent_index(idx) {
            if pidx != idx && !used.contains(&pidx) && rows.len() < want {
                let parent = &corpus::CORPUS[pidx];
                let mut pp = make_proc(parent, pidx, rng, opts, uptime);
                pid += rng.range(1, 24) as i32;
                pp.pid = pid;
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
            pid += rng.range(1, 24) as i32;
            p.pid = pid;
            rows.push(p);
        }
        guard += 1;
    }
    rows.sort_unstable_by_key(|p| p.pid);
    rows
}

/// Generate processes for injection. The same population as `gen_table`, but
/// no synthetic PIDs: the kernel assigns real ones.
pub fn gen_inject(rng: &mut Rng, opts: &Opts) -> Vec<Proc> {
    let weights = corpus::profile_weights(&opts.profile);
    let uptime = util::uptime_secs();
    let want = if opts.count == 0 { 12 } else { opts.count };
    let mut rows: Vec<Proc> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    let mut guard = 0usize;
    while rows.len() < want && guard < want * 40 + 1000 {
        let idx = pick_index(rng, &weights, opts.family, &used);
        if corpus::CORPUS[idx].cmd == "/sbin/init" {
            guard += 1;
            continue;
        }
        if corpus::CORPUS[idx].inst <= 1
            && corpus::CORPUS[idx].fam != corpus::FAM_DEV
            && used.contains(&idx)
        {
            guard += 1;
            continue;
        }
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
        guard += 1;
    }
    rows
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
