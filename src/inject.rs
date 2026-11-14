//! Spawning the synthetic process tree and stopping it again.

use crate::cli::Args;
use crate::corpus;
use crate::gen::{self, Proc};
use crate::live;
use crate::probe;
use crate::str::{self, Buf};
use crate::stub;
use crate::sys;
use crate::users;
use crate::util;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::vec::Vec;

const DEFAULT_DURATION_SHORT: u32 = 120;

/// How `/proc/PID/exe` is made to look right, best tier first.
#[derive(Clone, Copy, PartialEq)]
pub enum ExeTier {
    /// Bind the template path over the stub inside a private mount namespace.
    Bind,
    /// Exec a copy of this binary from the shadow root.
    Shadow,
    /// Exec `/proc/self/exe`.
    ProcSelf,
}

impl ExeTier {
    pub fn name(self) -> &'static str {
        match self {
            ExeTier::Bind => "bind",
            ExeTier::Shadow => "shadow",
            ExeTier::ProcSelf => "proc-self",
        }
    }
}

pub struct Prep {
    pub created: Vec<Vec<u8>>,
    pub warnings: Vec<String>,
    pub phys_scale: f64,
    pub phys_estimate_kb: u64,
    pub phys_budget_kb: u64,
    pub caps: probe::Caps,
    pub tier: ExeTier,
    /// Root directory for the shadow copy. `--shadow-dir` when given,
    /// otherwise `./.psgen-stubs` when a bind is denied.
    pub shadow_root: Option<Vec<u8>>,
}

pub struct SpawnResult {
    pub pids: Vec<i32>,
    /// Root PIDs with the starttime read at spawn time. `--wait` checks this
    /// identity before signalling the root's process group. The comm is not
    /// stored here: it is still the parent's name at fork time, because the
    /// stub sets its own comm only after exec.
    pub roots: Vec<(i32, u64)>,
    pub failed: usize,
    pub warned: usize,
    pub missing: usize,
    pub mismatches: Vec<(i32, u32, u64, u64, u64, u64)>,
    pub failed_ids: Vec<(u32, i32)>,
    pub pidfile_ok: bool,
    pub tty_wanted: usize,
    pub tty_real: usize,
    pub tty_degraded: usize,
    pub dev_exe: usize,
    pub dev_user: usize,
    pub dev_disk: usize,
    pub dev_mem: usize,
    /// Exe tier the run actually used, after any fallback.
    pub tier: ExeTier,
    /// Temp directories this run created, so a caller that kills the stubs
    /// itself can remove them.
    pub temps: Vec<std::path::PathBuf>,
    /// Each spawned PID with the starttime and comm read back at spawn time,
    /// so a later signal can prove the PID was not reused. It covers the rows
    /// that reported a status record, plus every identity the run's live
    /// markers name: a stub that was frozen or detached before it could report
    /// has no status record, and leaving it out of this list made it unnameable
    /// to the cleanup that runs after the duration.
    pub ident: Vec<(i32, u64, Vec<u8>)>,
}

fn auto_phys_budget_kb() -> u64 {
    let mem = util::mem_total_kb();
    let cg = util::cgroup_mem_limit_kb();
    let a = if mem > 0 { mem / 4 } else { 0 };
    let b = if cg > 0 { cg / 2 } else { u64::MAX };
    if a == 0 {
        b
    } else {
        a.min(b)
    }
}

fn scale_rss(rows: &mut [Proc], budget_kb: u64, base_kb: u64, page_kb: u64) -> f64 {
    let sum: u64 = rows.iter().map(|p| p.rss).sum();
    let max = rows.iter().map(|p| p.rss).max().unwrap_or(0);
    let ptes = sum / 512;
    let avail = budget_kb.saturating_sub(base_kb);
    let cost = max.saturating_add(ptes);
    if cost == 0 || avail == 0 {
        return 1.0;
    }
    let factor = (avail as f64) / (cost as f64);
    if factor >= 1.0 {
        return 1.0;
    }
    let floor = 4096u64;
    for p in rows.iter_mut() {
        let v = (p.rss as f64 * factor) as u64;
        let v = v.max(floor);
        p.rss = crate::table::round_up(v, page_kb);
    }
    factor
}

pub fn prepare(rows: &mut [Proc], args: &Args, create_users: bool) -> Prep {
    let me = util::current_user();
    let root = sys::geteuid() == 0;
    let mut warnings: Vec<String> = Vec::new();
    let mut created: Vec<Vec<u8>> = Vec::new();
    let mut warned_names: Vec<Vec<u8>> = Vec::new();
    // One `useradd` per name, not one per row: a family can name the same
    // missing account in dozens of rows, and each later attempt would fail
    // with "already exists" and hide the first error.
    struct Answer {
        name: Vec<u8>,
        found: Option<(u32, u32)>,
        created: bool,
        err: Option<String>,
    }
    let mut resolved: Vec<Answer> = Vec::new();
    let switch_users = args.user && !args.no_root;

    if switch_users && !root {
        warnings.push(format!(
            "user switching needs root; running as {} (use sudo, --elevate, or --no-root)",
            String::from_utf8_lossy(&me.name)
        ));
    }
    if args.no_root && args.user {
        warnings.push(
            "--no-root disables user switching and the bind tier; --shadow-dir still selects a shadow copy".to_string(),
        );
    }
    if args.create_users && args.no_root {
        warnings.push("--create-users has no effect with --no-root".to_string());
    } else if args.create_users && !args.user {
        warnings.push("--create-users has no effect with --no-user".to_string());
    } else if args.create_users && !root {
        // `useradd` needs root as well, so saying only "user switching needs
        // root" leaves the caller thinking sudo would fix both.
        warnings.push("--create-users needs root; no accounts were created".to_string());
    }
    if !args.mem && args.mem_cap_mb > 0 {
        warnings.push("--mem-cap has no effect with --no-mem".to_string());
    }
    if !args.mem && args.phys_cap.is_some() {
        warnings.push("--phys-cap has no effect with --no-mem".to_string());
    }
    if args.verify && !args.mem {
        warnings.push("--verify has no effect with --no-mem".to_string());
    }

    for p in rows.iter_mut() {
        if !switch_users {
            p.user = me.name.clone();
            p.uid = me.uid;
            p.gid = me.gid;
            continue;
        }
        // A dry run creates nothing, but it must not fall back to the caller's
        // identity either: the plan has to name what the real run would do.
        // Reporting the caller here made `--create-users --dry-run` byte
        // identical to the same command without the flag.
        if args.dry_run && args.create_users {
            if users::lookup_name(&p.user).is_none() {
                // The account does not exist yet, so its uid is not known. The
                // generated row carries a uid guessed from the passwd database
                // (the caller's when the name is absent), and leaving it there
                // made every such row claim uid 0 in the JSON preview.
                p.uid = u32::MAX;
                p.gid = u32::MAX;
                if !warned_names.contains(&p.user) {
                    warned_names.push(p.user.clone());
                    let mut msg = String::from("would create ");
                    msg.push_str(&String::from_utf8_lossy(&p.user));
                    msg.push_str(" (--dry-run creates nothing)");
                    warnings.push(msg);
                }
            }
            continue;
        }
        if !root {
            p.user = me.name.clone();
            p.uid = me.uid;
            p.gid = me.gid;
            continue;
        }
        if p.uid == me.uid && p.user == me.name {
            continue;
        }
        let (found, was_created, err) = match resolved.iter().find(|r| r.name == p.user) {
            Some(r) => (r.found, r.created, r.err.clone()),
            None => {
                let answer = users::ensure(&p.user, create_users);
                resolved.push(Answer {
                    name: p.user.clone(),
                    found: answer.0,
                    created: answer.1,
                    err: answer.2.clone(),
                });
                answer
            }
        };
        match found {
            Some((uid, gid)) => {
                p.uid = uid;
                p.gid = gid;
                if was_created && !created.contains(&p.user) {
                    created.push(p.user.clone());
                }
            }
            None => {
                if !warned_names.contains(&p.user) {
                    warned_names.push(p.user.clone());
                    let mut msg = String::from("no such user ");
                    msg.push_str(&String::from_utf8_lossy(&p.user));
                    msg.push_str("; running as ");
                    msg.push_str(&String::from_utf8_lossy(&me.name));
                    if !args.create_users {
                        msg.push_str(" (pass --create-users to create it)");
                    }
                    if let Some(e) = err {
                        msg.push_str(": ");
                        msg.push_str(&e);
                    }
                    warnings.push(msg);
                }
                p.user = me.name.clone();
                p.uid = me.uid;
                p.gid = me.gid;
            }
        }
    }

    let page = sys::page_kb();
    for p in rows.iter_mut() {
        if args.mem {
            p.vsz = crate::table::round_up(p.vsz, page);
            p.rss = crate::table::round_up(p.rss, page);
        } else {
            p.vsz = 0;
            p.rss = 0;
        }
    }

    if let Some(target) = args.mem_target_kb {
        if !args.mem {
            warnings.push("--mem-target has no effect with --no-mem".to_string());
        } else {
            let target = target as u64;
            for p in rows.iter_mut() {
                // Leave the base reserve below the template's VSZ, and never
                // claim an RSS the stub cannot find room for.
                let cap = p.vsz.saturating_sub(gen::BASE_RESERVE_KB as u64);
                let v = target.min(cap.max(page));
                p.rss = crate::table::round_up(v, page);
            }
        }
    }

    if args.mem_cap_mb > 0 && args.mem {
        let cap = args.mem_cap_mb.saturating_mul(1024);
        let sum: u64 = rows.iter().map(|p| p.rss).sum();
        if sum > cap && !rows.is_empty() {
            // The 4 MiB per-stub reserve is taken off the cap first; what is
            // left is shared in proportion to each row's RSS above it.
            let floor = 4096u64;
            let base = floor.saturating_mul(rows.len() as u64);
            if base >= cap {
                warnings.push(format!(
                    "--mem-cap {} MiB is at or below the {} MiB floor of {} {}; the reported RSS will be at least {} MiB",
                    args.mem_cap_mb,
                    base / 1024,
                    rows.len(),
                    if rows.len() == 1 { "stub" } else { "stubs" },
                    base / 1024
                ));
                for p in rows.iter_mut() {
                    p.rss = floor;
                }
            } else {
                let extra = cap - base;
                let weight: u64 = rows.iter().map(|p| p.rss.saturating_sub(floor)).sum();
                for p in rows.iter_mut() {
                    let v = floor + p.rss.saturating_sub(floor) * extra / weight;
                    p.rss = crate::table::round_up(v, page);
                }
            }
        }
    }

    if args.mem && !rows.is_empty() {
        if let Some(limit) = sys::rlimit_fsize() {
            // Every stub maps the same arena file, and the arena is as large
            // as the biggest RSS target. A fault past RLIMIT_FSIZE kills the
            // stub with SIGXFSZ, so keep the targets below the limit.
            let cap_kb = (limit / 1024).saturating_sub(16 * 1024);
            let max = rows.iter().map(|p| p.rss).max().unwrap_or(0);
            if cap_kb < page {
                warnings.push(
                    "RLIMIT_FSIZE is too small for an RSS arena; memory padding disabled"
                        .to_string(),
                );
                for p in rows.iter_mut() {
                    p.rss = 0;
                }
            } else if max > cap_kb {
                warnings.push(format!(
                    "RLIMIT_FSIZE is {} MiB; RSS targets capped at {} MiB",
                    limit / 1024 / 1024,
                    cap_kb / 1024
                ));
                let v = cap_kb / page * page;
                for p in rows.iter_mut() {
                    if p.rss > v {
                        p.rss = v;
                    }
                }
            }
        }
    }

    let base_kb = rows.len() as u64 * 2048;
    let mut phys_scale = 1.0;
    let budget = match args.phys_cap {
        Some(0) => 0,
        Some(n) => n.saturating_mul(1024),
        None => auto_phys_budget_kb(),
    };
    let mut phys_estimate_kb = 0;
    if args.mem && !rows.is_empty() {
        let sum: u64 = rows.iter().map(|p| p.rss).sum();
        let max = rows.iter().map(|p| p.rss).max().unwrap_or(0);
        let ptes = sum / 512;
        let est = max.saturating_add(ptes).saturating_add(base_kb);
        phys_estimate_kb = est;
        if budget > 0 && est > budget && max > 0 {
            phys_scale = scale_rss(rows, budget, base_kb, page);
            let sum2: u64 = rows.iter().map(|p| p.rss).sum();
            let max2 = rows.iter().map(|p| p.rss).max().unwrap_or(0);
            phys_estimate_kb = max2.saturating_add(sum2 / 512).saturating_add(base_kb);
        }
        if budget > 0 && phys_estimate_kb > budget {
            // Integer MiB truncation made this sentence compare 30 with 30
            // when the gap was below 1 MiB. KiB shows the actual difference.
            warnings.push(format!(
                "the estimated physical cost is about {} KiB, above the {} KiB budget",
                phys_estimate_kb, budget
            ));
        }
    }

    for p in rows.iter_mut() {
        if !args.tty {
            // A root detaches the whole subtree from the caller's terminal.
            // Children inherit the new session; making every row a session
            // leader would change worker STAT and session semantics.
            p.flags &= !(corpus::F_SESSION | corpus::F_TTY);
            if p.parent.is_none() {
                p.flags |= corpus::F_SESSION;
            }
        } else if p.flags & corpus::F_TTY != 0 {
            p.flags |= corpus::F_SESSION;
        }
        if !args.threads {
            p.flags &= !corpus::F_THREADS;
        }
        if !args.busy {
            p.flags &= !corpus::F_BUSY;
        }
    }

    // --busy makes the CPU column true: every row that claims CPU in the
    // table actually burns that share of a core. Without it the stubs sleep
    // and ps reports 0.0, which is correct but not what the table said.
    if args.busy {
        for p in rows.iter_mut() {
            if p.cpu > 0 {
                p.flags |= corpus::F_BUSY;
            }
        }
    }

    // An explicit --cpu target replaces every row's duty cycle and forces the
    // row onto the busy path, including rows the corpus does not normally mark.
    if let Some(pct) = args.cpu_pct {
        let tenths = pct.saturating_mul(10);
        for p in rows.iter_mut() {
            p.cpu = tenths;
            if pct == 0 {
                p.flags &= !corpus::F_BUSY;
            } else {
                p.flags |= corpus::F_BUSY;
            }
        }
    }

    if args.disk_mb.unwrap_or(0) > 0 && rows.is_empty() {
        warnings.push("--disk has no rows to write for".to_string());
    }

    let caps = probe::caps();
    let mut shadow_root = args.shadow_dir.clone();
    if shadow_root.is_none() && !args.no_root && !args.no_exe && !caps.can_spoof_exe() {
        // Keep the default so a cage without mount namespaces still gets a
        // plausible `/proc/PID/exe`. The root does not depend on the caller's
        // working directory: a run's cwd is not reproducible by any later run,
        // so a cwd-derived root could never be reclaimed, and every run in a
        // cage leaked one. The temporary directory is shared by every run of
        // this caller and is what the prune already scans. The path is
        // absolute so a child can exec the copy whatever working directory it
        // inherits.
        let dir = std::env::temp_dir().join(".psgen-stubs");
        let mut v = dir.as_os_str().as_bytes().to_vec();
        if !v.ends_with(b"/") {
            v.push(b'/');
        }
        shadow_root = Some(v);
    }
    // --no-exe means /proc/PID/exe points at psgen, whatever else is set.
    // --no-root alone keeps the shadow/proc-self choice.
    let tier = if args.no_exe {
        ExeTier::ProcSelf
    } else if args.no_root {
        if args.shadow_dir.is_some() {
            ExeTier::Shadow
        } else {
            ExeTier::ProcSelf
        }
    } else if caps.can_spoof_exe() {
        ExeTier::Bind
    } else if shadow_root.is_some() {
        ExeTier::Shadow
    } else {
        ExeTier::ProcSelf
    };
    if tier == ExeTier::ProcSelf && !args.no_exe && !args.no_root {
        warnings.push(format!(
            "cannot bind the template path here ({}); /proc/PID/exe will point at psgen",
            if !caps.mount_ns {
                "mount namespaces denied"
            } else {
                "the bind was denied"
            }
        ));
    }

    Prep {
        created,
        warnings,
        phys_scale,
        phys_estimate_kb,
        phys_budget_kb: budget,
        caps,
        tier,
        shadow_root,
    }
}

fn children_of(rows: &[Proc]) -> Vec<Vec<usize>> {
    let mut children = vec![Vec::new(); rows.len()];
    for (i, p) in rows.iter().enumerate() {
        if let Some(par) = p.parent {
            if par < rows.len() && par != i {
                children[par].push(i);
            }
        }
    }
    children
}

fn subtree(node: usize, children: &[Vec<usize>], out: &mut Vec<usize>) {
    out.push(node);
    for c in &children[node] {
        subtree(*c, children, out);
    }
}

fn descendants(node: usize, children: &[Vec<usize>], out: &mut Vec<usize>) {
    for c in &children[node] {
        out.push(*c);
        descendants(*c, children, out);
    }
}

fn duration_for(p: &Proc, args: &Args) -> u32 {
    if args.duration > 0 {
        args.duration
    } else if p.flags & corpus::F_SHORT != 0 {
        DEFAULT_DURATION_SHORT
    } else {
        0
    }
}

/// The two secrets/paths a config carries that are the same for every row of
/// one run.
struct RunPaths<'a> {
    bind: bool,
    self_copy: &'a [u8],
    nonce: &'a [u8],
}

#[allow(clippy::too_many_arguments)]
fn make_config(
    row: usize,
    rows: &[Proc],
    children: &[Vec<usize>],
    fd_of: &[i32],
    args: &Args,
    temp: &[u8],
    run: &RunPaths,
) -> stub::Config {
    let bind = run.bind;
    let p = &rows[row];
    let mut keep = Vec::new();
    descendants(row, children, &mut keep);
    let child_fds: Vec<i32> = children[row].iter().map(|c| fd_of[*c]).collect();
    let keep_fds: Vec<i32> = keep.iter().map(|d| fd_of[*d]).collect();
    let mut max_fd = 5;
    if row < fd_of.len() {
        max_fd = max_fd.max(fd_of[row]);
    }
    for fd in &child_fds {
        max_fd = max_fd.max(*fd);
    }
    for fd in &keep_fds {
        max_fd = max_fd.max(*fd);
    }
    let disk_kb = args
        .disk_mb
        .unwrap_or(0)
        .saturating_mul(1024)
        .min(u32::MAX as u64) as u32;
    stub::Config {
        flags: p.flags as u32
            | if p.parent.is_none() { stub::F_ROOT } else { 0 }
            | if bind && sys::geteuid() != 0 {
                stub::F_USERNS
            } else {
                0
            },
        vsz_kb: p.vsz.min(u32::MAX as u64) as u32,
        rss_kb: p.rss.min(u32::MAX as u64) as u32,
        uid: p.uid,
        gid: p.gid,
        duration: duration_for(p, args),
        cpu: p.cpu,
        stage: 0,
        comm: gen::stub_name(&p.cmd).to_vec(),
        exe: if bind {
            gen::template_exe(&corpus::CORPUS[p.tmpl])
        } else {
            Vec::new()
        },
        cmd: p.cmd.clone(),
        user: p.user.clone(),
        temp: temp.to_vec(),
        disk_kb,
        self_copy: run.self_copy.to_vec(),
        nonce: run.nonce.to_vec(),
        child_fds,
        keep_fds,
        max_fd,
        arena_fd: if p.rss > 0 { 4 } else { -1 },
        status_fd: 5,
        id: row as u32,
    }
}

fn write_config_fd(fd: i32, cfg: &stub::Config) -> bool {
    let data = stub::encode_config(cfg);
    if !sys::ftruncate(fd, data.len() as u64) {
        return false;
    }
    sys::pwrite_fd(fd, &data, 0) == data.len() as isize
}

fn read_status_records(fd: i32, want: usize, timeout_ms: u64) -> Vec<(i32, i32, u32, u32)> {
    const REC: usize = 16;
    let mut buf: Vec<u8> = Vec::with_capacity(want * REC);
    let start = sys::monotonic_ns();
    let deadline = start.saturating_add(timeout_ms.saturating_mul(1_000_000));
    while buf.len() < want * REC {
        let now = sys::monotonic_ns();
        if now >= deadline {
            break;
        }
        if !sys::poll_read(fd, 100) {
            continue;
        }
        let mut tmp = [0u8; 4096];
        let n = sys::read_fd(fd, &mut tmp);
        if n <= 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n as usize]);
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + REC <= buf.len() {
        let pid = i32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let status = i32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
        let id = u32::from_le_bytes([buf[i + 8], buf[i + 9], buf[i + 10], buf[i + 11]]);
        let dev = u32::from_le_bytes([buf[i + 12], buf[i + 13], buf[i + 14], buf[i + 15]]);
        out.push((pid, status, id, dev));
        i += REC;
    }
    out
}

/// Fill `raw` with entropy, falling back to a mix of the pid and the clock.
///
/// A `getrandom` denial must not turn into a failure anywhere: at the injector
/// it would abort a run whose stubs already exist, and at `load --disk-util`
/// it made a disk error look like the cause. The value only has to be unique
/// inside one directory, and the caller's retry loop already handles a
/// collision.
pub fn fill_entropy(raw: &mut [u8]) {
    if sys::getrandom(raw) {
        return;
    }
    let mut x =
        (sys::getpid() as u64).rotate_left(17) ^ sys::monotonic_ns() ^ (sys::now_secs() << 20);
    for chunk in raw.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let b = x.to_le_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(&b[..n]);
    }
}

/// Hex characters for a temporary name.
fn random_hex(bytes: usize) -> Vec<u8> {
    let mut raw = vec![0u8; bytes];
    fill_entropy(&mut raw);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes * 2);
    for b in &raw {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    out
}

/// Build the pidfile contents: header, `# temp` lines, then one identity line
/// per PID.
///
/// The header carries the boot id and the run nonce, and `stop` refuses a
/// header without a boot id, so the writer refuses to produce such a header at
/// all. `None` means the boot id could not be read and no pidfile can be
/// written.
///
/// The nonce is what lets a line identify *this run* rather than a process that
/// merely looks like one of its stubs: it travels in every stub's environment,
/// so a live row can be checked against it. A header from an older release has
/// none, and `stop` then refuses that file's one-field lines rather than
/// falling back to the executable test, which would match any psgen process.
fn pidfile_body(pids: &[i32], temps: &[std::path::PathBuf], nonce: &[u8]) -> Option<Buf> {
    let boot = util::boot_id();
    if boot.is_empty() {
        return None;
    }
    let mut buf = Buf::new();
    buf.push_bytes(crate::version::PIDFILE_PREFIX);
    buf.push_str(crate::version::VERSION);
    buf.push_str(" boot ");
    buf.push_bytes(&boot);
    if !nonce.is_empty() {
        buf.push_bytes(crate::version::PIDFILE_NONCE);
        buf.push_bytes(nonce);
    }
    buf.push(b'\n');
    for t in temps {
        buf.push_str("# temp ");
        buf.push_bytes(t.as_os_str().as_bytes());
        buf.push(b'\n');
    }
    let mut sorted = pids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    for pid in &sorted {
        let st = live::read_starttime(*pid).unwrap_or(0);
        let comm = live::read_comm(*pid).unwrap_or_default();
        buf.push_u64(*pid as u64);
        buf.push(b'\t');
        buf.push_u64(st);
        buf.push(b'\t');
        buf.push_bytes(&comm);
        buf.push(b'\n');
    }
    Some(buf)
}

/// Write a header-only pidfile before anything is spawned.
///
/// `spawn()` cannot write the PIDs until it has them, and a write that fails
/// after the fork leaves live stubs with no record. Proving the write works
/// first, and leaving a valid psgen pidfile behind, makes the later rewrite an
/// overwrite of a file the caller already has.
/// The header carries a nonce of its own. A run that dies between this write
/// and the rewrite leaves a file `stop` can identify as psgen's rather than a
/// bare header, and the same length is what the preflight proves can be
/// written.
fn pending_nonce() -> Vec<u8> {
    format!(
        "{:016x}",
        sys::monotonic_ns() ^ ((sys::getpid() as u64) << 32)
    )
    .into_bytes()
}

/// The exact size of the pending pidfile, for the preflight probe.
pub fn pending_pidfile_len() -> usize {
    pidfile_body(&[], &[], &pending_nonce())
        .map(|b| b.v.len())
        .unwrap_or(0)
}

pub fn write_pending_pidfile(path: &[u8]) -> bool {
    write_pidfile(path, &[], &[], &pending_nonce()).0
}

/// Write the pidfile, falling back to shorter temporary names when the target
/// basename is close to `NAME_MAX`. Returns whether it landed, and the errno
/// that stopped it so the caller can name the real cause.
fn write_pidfile(
    path: &[u8],
    pids: &[i32],
    temps: &[std::path::PathBuf],
    nonce: &[u8],
) -> (bool, i32) {
    if !probe::pidfile_target_ok(path) {
        let e = match probe::pidfile_target(path) {
            Err(probe::TargetProblem::Unreadable(e)) => e,
            _ => libc::EEXIST,
        };
        return (false, e);
    }
    let buf = match pidfile_body(pids, temps, nonce) {
        Some(b) => b,
        None => return (false, libc::EIO),
    };
    let flags = sys::O_WRONLY | sys::O_CREAT | sys::O_EXCL | sys::O_NOFOLLOW;
    for level in 0..probe::pidfile_temp_levels() {
        let mut too_long = false;
        for retry in 0..probe::PIDFILE_RETRIES {
            let nonce = sys::monotonic_ns()
                ^ ((sys::getpid() as u64) << 32)
                ^ retry.wrapping_mul(0x9e3779b97f4a7c15);
            let tmp = probe::pidfile_temp_name(path, level, nonce);
            let fd = sys::open(&tmp, flags, 0o600);
            if fd < 0 {
                match sys::last_error().raw_os_error() {
                    Some(libc::EEXIST) => continue,
                    Some(libc::ENAMETOOLONG) => {
                        too_long = true;
                        break;
                    }
                    Some(e) => return (false, e.abs()),
                    None => return (false, libc::EIO),
                }
            }
            let wrote = sys::write_fd(fd, buf.as_bytes()) && sys::fsync_fd(fd);
            let write_errno = sys::last_error().raw_os_error().unwrap_or(libc::EIO).abs();
            sys::close(fd);
            if !wrote {
                let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(&tmp)));
                return (false, write_errno);
            }
            let renamed = std::fs::rename(
                Path::new(std::ffi::OsStr::from_bytes(&tmp)),
                Path::new(std::ffi::OsStr::from_bytes(path)),
            );
            match renamed {
                Ok(()) => return (true, 0),
                Err(e) => {
                    let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(&tmp)));
                    return (false, e.raw_os_error().unwrap_or(libc::EIO).abs());
                }
            }
        }
        if !too_long {
            return (false, libc::EEXIST);
        }
    }
    (false, libc::ENAMETOOLONG)
}

/// Lock held while this run may rewrite `path`.
///
/// Two injections into one pidfile both passed the live check, then both
/// renamed their own pending file into place: the second erased the first's
/// rows and left stubs with no record. `flock` is released by the kernel when
/// the run dies, so a crash cannot leave a lock that blocks every later run.
pub struct PidfileLock {
    _file: std::fs::File,
}

/// Lock `path` for this run, or fail with `WouldBlock` when another run holds
/// it. The lock lives beside the pidfile, so two runs that name the same path
/// coordinate whatever their `TMPDIR`.
pub fn lock_pidfile(path: &[u8]) -> std::io::Result<PidfileLock> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut lock_path = path.to_vec();
    lock_path.extend_from_slice(b".lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(Path::new(std::ffi::OsStr::from_bytes(&lock_path)))?;
    let fd = {
        use std::os::unix::io::AsRawFd;
        file.as_raw_fd()
    };
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(PidfileLock { _file: file })
}

/// Write the spawned rows beside an unwritable pidfile, so a run whose final
/// write failed still leaves something `stop` can use.
pub fn write_pid_sidecar(path: &[u8], pids: &[i32]) -> bool {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let buf = match pidfile_body(pids, &[], &pending_nonce()) {
        Some(b) => b,
        None => return false,
    };
    let mut side = path.to_vec();
    side.extend_from_slice(b".spawned");
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(Path::new(std::ffi::OsStr::from_bytes(&side)));
    match f {
        Ok(mut f) => f
            .write_all(buf.as_bytes())
            .and_then(|()| f.sync_all())
            .is_ok(),
        Err(_) => false,
    }
}

const OWNER_FILE: &[u8] = b".psgen-owner";
const LIVE_FILE: &[u8] = b".psgen-live";

/// The identity of the PID namespace this process is in: the inode of
/// `/proc/self/ns/pid`, or 0 when it cannot be read.
///
/// A marker records PIDs, and a PID means nothing outside the namespace that
/// produced it. The inode is the only stable name a namespace has.
pub fn pid_ns_inode() -> u64 {
    let path = match sys::cstr(b"/proc/self/ns/pid") {
        Some(p) => p,
        None => return 0,
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(path.as_ptr(), &mut st) } != 0 {
        return 0;
    }
    st.st_ino as u64
}

/// One `pid start ns boot nonce` marker line.
///
/// The namespace is what makes the line meaningful across a PID namespace: a
/// PID and a starttime identify a process only inside the namespace that
/// produced them. The boot id survives a reboot, after which every recorded
/// PID is meaningless whatever its starttime says. The nonce ties the line to
/// the run that wrote it, so a marker from an older run in the same namespace
/// is not mistaken for the current one.
pub fn marker_line(pid: i32, start: u64, boot: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut line = Vec::new();
    line.extend_from_slice(pid.to_string().as_bytes());
    line.push(b' ');
    line.extend_from_slice(start.to_string().as_bytes());
    line.push(b' ');
    line.extend_from_slice(pid_ns_inode().to_string().as_bytes());
    line.push(b' ');
    if boot.is_empty() {
        line.push(b'-');
    } else {
        line.extend_from_slice(boot);
    }
    line.push(b' ');
    if nonce.is_empty() {
        line.push(b'-');
    } else {
        line.extend_from_slice(nonce);
    }
    line.push(b'\n');
    line
}

/// Append marker lines to `dir`'s file, never truncating it.
///
/// The stubs append their own identity before they exec, and the injector
/// learns only about the rows that reported a status record. A truncating
/// rewrite would erase a stub that is alive but has not reported yet, and the
/// prune pass would then delete the directory it is still using. Duplicate
/// lines are harmless: every reader asks `any(live)`.
fn append_marker(dir: &Path, file: &[u8], lines: &[u8]) -> bool {
    if lines.is_empty() {
        return true;
    }
    let path = dir.join(std::ffi::OsStr::from_bytes(file));
    let fd = sys::open(
        path.as_os_str().as_bytes(),
        sys::O_WRONLY | sys::O_CREAT | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    );
    if fd < 0 {
        return false;
    }
    // O_NOFOLLOW refuses a symlink; a hardlink is still a regular file, so the
    // opened descriptor's link count is the remaining signal. The injector
    // creates this file, so a second link means someone else made one.
    let ok = match sys::fd_stat(fd) {
        Some(st) if st.is_reg() && st.nlink == 1 && st.uid == sys::geteuid() => {
            sys::write_fd(fd, lines)
        }
        _ => false,
    };
    sys::close(fd);
    ok
}

/// Record the stubs that are still alive in a staging directory.
///
/// The injector exits before a `--duration` run ends, so the owner marker goes
/// stale while the stubs are still using their `--disk` data and shadow copy.
/// The prune pass must keep those directories until the last stub is gone.
fn write_live_marker(temps: &[std::path::PathBuf], pids: &[(i32, u64)], nonce: &[u8]) {
    // The roots the injector records are its own children, so they live in
    // the injector's namespace; a stub that records itself writes its own.
    let boot = util::boot_id();
    let mut body = Vec::new();
    for (pid, start) in pids {
        body.extend_from_slice(&marker_line(*pid, *start, &boot, nonce));
    }
    for dir in temps {
        let _ = append_marker(dir, LIVE_FILE, &body);
    }
}

/// One marker entry.
struct Marker {
    pid: i32,
    start: u64,
    ns: u64,
    boot: Vec<u8>,
}

/// The entries in a marker file.
///
/// A line written by an older build has two or three fields; the missing boot
/// id is "unknown", which keeps today's behaviour for it.
///
/// A malformed line is skipped, not fatal. Several processes append to this
/// file, so a reader can catch a partial line; returning `None` for the whole
/// file would discard every identity in it, and the caller that matters -- "is
/// anyone still using this directory" -- would then answer "nobody" and delete
/// a directory a live stub is holding. `None` is reserved for a file that
/// cannot be read at all.
fn read_marker(dir: &Path, file: &[u8]) -> Option<Vec<Marker>> {
    let text = std::fs::read(dir.join(std::ffi::OsStr::from_bytes(file))).ok()?;
    let mut out = Vec::new();
    for line in text.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut it = line.split(|b| *b == b' ');
        let Some(pid) = it.next().and_then(str::parse_u64) else {
            continue;
        };
        let Some(start) = it.next().and_then(str::parse_u64) else {
            continue;
        };
        let ns = it.next().and_then(str::parse_u64).unwrap_or(0);
        let boot = match it.next().unwrap_or(b"") {
            b"-" | b"" => Vec::new(),
            b => b.to_vec(),
        };
        let Ok(pid) = i32::try_from(pid) else {
            continue;
        };
        out.push(Marker {
            pid,
            start,
            ns,
            boot,
        });
    }
    Some(out)
}

fn read_live_marker(dir: &Path) -> Option<Vec<Marker>> {
    read_marker(dir, LIVE_FILE)
}

fn read_owner_marker(dir: &Path) -> Option<Marker> {
    read_marker(dir, OWNER_FILE)?.into_iter().next()
}

fn make_temp_dir(idx: usize, nonce: &[u8]) -> Option<std::path::PathBuf> {
    make_temp_dir_in(&std::env::temp_dir(), idx, nonce)
}

fn make_temp_dir_in(base: &Path, idx: usize, nonce: &[u8]) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let _ = std::fs::create_dir_all(base);
    for i in 0..100 {
        let p = base.join(format!(".psgen-{}-{}-{}", sys::getpid(), idx, i));
        let made = std::fs::DirBuilder::new().mode(0o700).create(&p).is_ok();
        if !made {
            continue;
        }
        if std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).is_err() {
            let _ = std::fs::remove_dir(&p);
            continue;
        }
        // Record who owns this directory, with the owner's starttime, PID
        // namespace and run tag, so a later prune can tell a live run from a
        // recycled PID and from a run in another namespace, whose PIDs it
        // cannot read.
        let start = live::read_starttime(sys::getpid()).unwrap_or(0);
        let owner = marker_line(sys::getpid(), start, &util::boot_id(), nonce);
        let _ = append_marker(&p, OWNER_FILE, &owner);
        return Some(std::fs::canonicalize(&p).unwrap_or(p));
    }
    None
}

/// The injector PID encoded in a staging directory name, if the name matches
/// `.psgen-<pid>-<idx>-<n>`.
fn staging_pid(name: &[u8]) -> Option<i32> {
    let rest = name.strip_prefix(b".psgen-")?;
    let parts: Vec<&[u8]> = rest.split(|b| *b == b'-').collect();
    if parts.len() != 3 {
        return None;
    }
    if !parts
        .iter()
        .all(|p| !p.is_empty() && p.iter().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    str::parse_u64(parts[0]).and_then(|v| i32::try_from(v).ok())
}

/// Whether a staging directory still has a live process recorded in it.
///
/// The live marker is written by the injector and by each stub before it
/// execs, so it is the authoritative list of who is using the directory. A
/// zombie does not count: it holds no files and runs no code, and a parent that
/// has signalled its children but not yet reaped them would otherwise keep
/// every directory alive. `stop` already treats a zombie as stopped; this is
/// the same test, so the two cannot disagree about whether a directory is in
/// use. An entry from another PID namespace names a process this one cannot
/// judge, so it counts as live; an entry from another boot is provably dead.
///
/// A directory whose owner marker names *this* process is one this process is
/// still holding open. `SIGKILL` returns before the target has exited, so the
/// one caller in that position — a run that has just killed its own stubs —
/// would otherwise sample the marker inside the window and keep a directory it
/// is entitled to remove. That case waits, bounded, the way `stop` does; a
/// directory owned by anyone else is answered at once, so a prune never blocks.
pub fn staging_busy(dir: &std::path::Path) -> bool {
    let mine = read_owner_marker(dir)
        .map(|o| o.pid == sys::getpid())
        .unwrap_or(false);
    let deadline = if mine {
        Some(sys::monotonic_ns().saturating_add(2_000_000_000))
    } else {
        None
    };
    loop {
        if !marker_busy(dir) {
            return false;
        }
        match deadline {
            Some(d) if sys::monotonic_ns() < d => sys::nanosleep(0, 10_000_000),
            _ => return true,
        }
    }
}

fn marker_busy(dir: &std::path::Path) -> bool {
    let my_ns = pid_ns_inode();
    let my_boot = util::boot_id();
    read_live_marker(dir)
        .map(|entries| {
            entries.iter().any(|m| {
                if !ns_matches(m, my_ns) {
                    // Unknown is not dead.
                    return true;
                }
                if boot_differs(m, &my_boot) {
                    return false;
                }
                marker_alive(m)
            })
        })
        .unwrap_or(false)
}

/// Whether a marker entry names a process that is still running.
fn marker_alive(m: &Marker) -> bool {
    match live::read_stat(m.pid) {
        Some(s) => s.starttime == m.start && s.state != b'Z',
        None => false,
    }
}

/// Whether a marker entry names a namespace this process can read.
///
/// A marker from another PID namespace names PIDs that answer about unrelated
/// processes here, so nothing can be concluded about it: unknown, and unknown
/// must never be read as dead. A marker without a namespace (written by an
/// older build) is read with today's namespace-blind behaviour.
fn ns_matches(m: &Marker, my_ns: u64) -> bool {
    m.ns == 0 || m.ns == my_ns
}

/// Whether a marker entry was written in an earlier boot.
///
/// A process cannot outlive a reboot, so an entry from another boot names
/// nothing that is running now. This is the one mismatch that is proof of
/// death rather than doubt, and it is why a reboot does not leak every
/// staging directory for ever.
fn boot_differs(m: &Marker, my_boot: &[u8]) -> bool {
    !m.boot.is_empty() && !my_boot.is_empty() && m.boot != my_boot
}

/// The default shadow roots a run of this caller can reach.
///
/// There is one default root, and it does not depend on the working directory:
/// a run's cwd is whatever the caller had, and a cage or container gives each
/// run a different one. A default derived from cwd therefore produced a root
/// that no later run could name, so every run left its copy behind where
/// nothing would ever look. The temporary directory is the one location every
/// run of this caller shares, and it is what the prune already scans.
fn shadow_roots() -> Vec<std::path::PathBuf> {
    let mut roots: Vec<std::path::PathBuf> = Vec::with_capacity(2);
    roots.push(std::env::temp_dir().join(".psgen-stubs"));
    // A pidfile written by an older build can name a cwd-relative root, so the
    // current directory is still scanned for leftovers. It is never where a
    // new run writes.
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join(".psgen-stubs");
        if !roots.contains(&p) {
            roots.push(p);
        }
    }
    roots
}

/// Remove the staging directories of runs whose injector and stubs are gone.
///
/// A `--duration` run that nobody stops leaves its shadow copy and `--disk`
/// data behind: the injector exits, the stub dies on its alarm, and nothing
/// else knows the directory exists. The directory name already carries the
/// injector PID, and the owner marker carries its starttime and namespace, so a
/// recycled PID cannot keep a dead run's directory alive and a run in another
/// PID namespace is never mistaken for dead.
///
/// A directory is removed only when it has a live marker and none of the PIDs
/// in that marker still exists. An unmarked directory may belong to another
/// tool, or to a run that crashed before it could write the marker, so it is
/// left alone.
pub fn prune_staging(prep: &Prep) -> usize {
    let mut roots: Vec<std::path::PathBuf> = vec![std::env::temp_dir()];
    for r in shadow_roots() {
        if !roots.contains(&r) {
            roots.push(r);
        }
    }
    if let Some(d) = &prep.shadow_root {
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(d));
        if !roots.contains(&p) {
            roots.push(p);
        }
    }
    let mut removed = 0usize;
    for root in roots {
        removed += prune_root(&root);
    }
    removed
}

/// Warn once that a staging directory belongs to another uid.
///
/// Refusing another caller's data is right, and deleting it would be worse:
/// the directory still names processes, and its owner may yet stop them. A root
/// run's leftovers are therefore reported rather than kept silently, so the
/// caller who asked for `--elevate` knows why they are never reclaimed.
fn report_foreign(path: &Path, uid: u32) {
    let mut out = Buf::new();
    out.push_str("psgen: leaving ");
    out.push_bytes(path.as_os_str().as_bytes());
    out.push_str(" alone: it is owned by uid ");
    out.push_u64(uid as u64);
    out.push_str(", not ");
    out.push_u64(sys::geteuid() as u64);
    out.push_str("; the run that made it must stop it\n");
    sys::err(out.as_bytes());
}

fn prune_root(root: &Path) -> usize {
    use std::os::unix::fs::MetadataExt;
    let me = sys::geteuid();
    let my_ns = pid_ns_inode();
    let my_boot = util::boot_id();
    let rd = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(_) => return 0,
    };
    let mut removed = 0usize;
    for e in rd.flatten() {
        let name = e.file_name();
        let nameb = name.as_os_str().as_bytes();
        if staging_pid(nameb).is_none() {
            continue;
        }
        let path = e.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Only a real directory (not a symlink) owned by the caller. A
        // directory owned by another uid belongs to that uid's run: this
        // process cannot see those PIDs either, so it is refused and reported
        // rather than judged or deleted.
        if !meta.file_type().is_dir() {
            continue;
        }
        if meta.uid() != me {
            report_foreign(&path, meta.uid());
            continue;
        }
        if let Some(owner) = read_owner_marker(&path) {
            // The marker names the injector, its starttime, its namespace and
            // its boot, so a recycled PID cannot keep a dead run's directory
            // alive. A run in another namespace is not this process's to
            // judge; a run from an earlier boot is provably over.
            if !ns_matches(&owner, my_ns) {
                continue;
            }
            if !boot_differs(&owner, &my_boot) && live::same_process(owner.pid, owner.start) {
                continue;
            }
        }
        match read_live_marker(&path) {
            Some(entries) => {
                // A stub is still using this directory while it is alive. A
                // zombie is not: it holds no files and runs no code, and a
                // container whose PID 1 does not reap would otherwise keep
                // every dead run's staging for ever. An entry from another
                // boot is provably dead; an entry from another namespace is
                // not judgeable, so it keeps the directory.
                let busy = entries.iter().any(|m| {
                    if !ns_matches(m, my_ns) {
                        return true;
                    }
                    if boot_differs(m, &my_boot) {
                        return false;
                    }
                    marker_alive(m)
                });
                if busy {
                    continue;
                }
            }
            None => {
                // No live marker. A stub writes one before it execs, so a
                // directory with no marker has no stub using it. If the owner
                // marker names a dead injector, the run died before any stub
                // started and the directory is safe to remove. Without an
                // owner marker it may belong to another tool, so it is left
                // alone.
                if read_owner_marker(&path).is_none() {
                    continue;
                }
            }
        }
        if sys::remove_staging_dir(&path) {
            removed += 1;
        }
    }
    removed
}

fn redirect_stdio() {
    let devnull = sys::open(b"/dev/null", sys::O_RDWR, 0);
    if devnull >= 0 {
        sys::dup2(devnull, 0);
        sys::dup2(devnull, 1);
        sys::dup2(devnull, 2);
        if devnull > 2 {
            sys::close(devnull);
        }
    } else {
        sys::close(0);
        sys::close(1);
        sys::close(2);
    }
}

pub fn spawn(rows: &[Proc], args: &Args, prep: &Prep) -> Result<SpawnResult, String> {
    let children = children_of(rows);
    let roots: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, p)| p.parent.is_none())
        .map(|(i, _)| i)
        .collect();
    let total_nodes = rows.len();
    let self_exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .as_os_str()
        .as_bytes()
        .to_vec();
    let mut tier = prep.tier;
    // The run tag, allocated before any staging directory exists so the owner
    // marker can record it. It is a run identifier, not a secret: it travels
    // in the stub's environment because argv is what `ps aux` renders.
    let nonce = random_hex(8);

    // An optional copy of this binary, used when the exe tier is shadow. It
    // must live somewhere `stop` can remove, so it sits in its own temp dir
    // listed in the pidfile next to the others.
    let mut shadow_dir: Option<std::path::PathBuf> = None;
    let mut self_copy: Vec<u8> = Vec::new();
    if tier == ExeTier::Shadow {
        let dir = prep
            .shadow_root
            .as_ref()
            .expect("an exe tier of shadow needs a shadow root");
        let made = make_temp_dir_in(Path::new(std::ffi::OsStr::from_bytes(dir)), 9_000, &nonce)
            .ok_or_else(|| {
                format!(
                    "cannot create a directory in {} for --shadow-dir",
                    String::from_utf8_lossy(dir)
                )
            });
        let copied = made.and_then(|d| {
            let dst = d.join("psgen-stub");
            match std::fs::copy(Path::new(std::ffi::OsStr::from_bytes(&self_exe)), &dst) {
                Ok(_) => {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
                    Ok((d, dst))
                }
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&d);
                    Err(format!(
                        "cannot copy the stub into {}: {}",
                        String::from_utf8_lossy(dir),
                        e
                    ))
                }
            }
        });
        match copied {
            Ok((d, dst)) => {
                self_copy = std::fs::canonicalize(&dst)
                    .unwrap_or(dst)
                    .as_os_str()
                    .as_bytes()
                    .to_vec();
                shadow_dir = Some(d);
            }
            Err(e) => {
                if args.shadow_dir.is_some() {
                    return Err(e);
                }
                let mut out = Buf::new();
                out.push_str("psgen: ");
                out.push_str(&e);
                out.push_str("; /proc/PID/exe will point at psgen\n");
                sys::err(out.as_bytes());
                tier = ExeTier::ProcSelf;
            }
        }
    }
    let bind = tier == ExeTier::Bind;

    let max_rss = rows.iter().map(|p| p.rss).max().unwrap_or(0);
    let mut arena_fd: i32 = -1;
    if args.mem && max_rss > 0 {
        let fd = sys::anon_file(b"cache", max_rss * 1024);
        if fd < 0 {
            if let Some(d) = &shadow_dir {
                let _ = std::fs::remove_dir_all(d);
            }
            let e = sys::errno();
            return Err(format!(
                "cannot create the RSS arena ({} KiB): {}",
                max_rss,
                std::io::Error::from_raw_os_error(e)
            ));
        }
        let target = sys::dup2(fd, 4);
        if target != 4 {
            sys::close(fd);
            if let Some(d) = &shadow_dir {
                let _ = std::fs::remove_dir_all(d);
            }
            return Err(format!("dup2(arena,4): {}", sys::last_error()));
        }
        if fd != 4 {
            sys::close(fd);
        }
        arena_fd = 4;
    }

    let mut pfd = [0i32; 2];
    if let Err(e) = sys::pipe2_checked(&mut pfd, sys::O_CLOEXEC) {
        if arena_fd >= 0 {
            sys::close(arena_fd);
        }
        if let Some(d) = &shadow_dir {
            let _ = std::fs::remove_dir_all(d);
        }
        return Err(format!("pipe2: {}", std::io::Error::from_raw_os_error(e)));
    }
    if pfd[0] == 5 {
        let n = sys::fcntl_dup(pfd[0], 6);
        if n < 0 {
            sys::close(pfd[0]);
            sys::close(pfd[1]);
            if arena_fd >= 0 {
                sys::close(arena_fd);
            }
            if let Some(d) = &shadow_dir {
                let _ = std::fs::remove_dir_all(d);
            }
            let e = sys::errno();
            return Err(format!(
                "fcntl(F_DUPFD,6): {}",
                std::io::Error::from_raw_os_error(e)
            ));
        }
        sys::close(pfd[0]);
        pfd[0] = n;
    }
    // dup2 onto the same descriptor is a no-op and leaves O_CLOEXEC set, so
    // move the write end off 5 before it is installed for the stub.
    if pfd[1] == 5 {
        let n = sys::fcntl_dup(pfd[1], 6);
        if n < 0 {
            sys::close(pfd[0]);
            sys::close(pfd[1]);
            if arena_fd >= 0 {
                sys::close(arena_fd);
            }
            if let Some(d) = &shadow_dir {
                let _ = std::fs::remove_dir_all(d);
            }
            let e = sys::errno();
            return Err(format!(
                "fcntl(F_DUPFD,6): {}",
                std::io::Error::from_raw_os_error(e)
            ));
        }
        sys::close(pfd[1]);
        pfd[1] = n;
    }
    if sys::dup2(pfd[1], 5) != 5 {
        let e = sys::errno();
        return Err(format!(
            "dup2(status,5): {}",
            std::io::Error::from_raw_os_error(e)
        ));
    }
    if pfd[1] != 5 {
        sys::close(pfd[1]);
    }
    let status_read = pfd[0];

    // Orphaned stub children reparent to this process, so --wait can reap
    // them instead of leaving zombies under PID 1.
    sys::set_child_subreaper();
    // Detach this injector into a new session before any root is forked, so a
    // row without a session flag still leaves the caller's session and terminal:
    // it inherits this one instead. A row that *is* a session leader (`F_SESSION`,
    // which `table` renders as `s`) makes itself one in the stub; every other
    // root joins this session as a process-group leader, so its STAT still has
    // no `s` and the table's prediction stays true. The call fails harmlessly
    // when this process is already a session leader, which is the one case
    // where it is already detached from the caller.
    sys::setsid();
    let mut root_pids: Vec<(i32, u64)> = Vec::new();
    let mut all_temps: Vec<std::path::PathBuf> = Vec::new();
    for root in roots {
        let mut nodes = Vec::new();
        subtree(root, &children, &mut nodes);
        let mut fd_of = vec![0i32; rows.len()];
        let mut cfg_fds: Vec<i32> = Vec::with_capacity(nodes.len());
        let mut refusal: Option<String> = None;
        for node in &nodes {
            // The config is a sealed memfd, and only a sealed memfd is acted
            // on. There is no unlinked fallback: a temporary file cannot be
            // sealed, so its holder could rewrite it between the stub's check
            // and its use, and a descriptor an unprivileged caller opened is
            // the shape a forged config has. A kernel that refuses
            // `memfd_create` cannot feed a stub, so the run refuses rather than
            // handing one a config nothing may act on.
            let fd = sys::anon_sealable_file(b"cfg", 0);
            if fd < 0 {
                let e = sys::errno();
                refusal = Some(format!(
                    "cannot create the config memfd ({}); a stub only acts on a sealed memfd",
                    std::io::Error::from_raw_os_error(e)
                ));
                break;
            }
            let fd = if fd < 6 {
                let n = sys::fcntl_dup(fd, 6);
                sys::close(fd);
                n
            } else {
                fd
            };
            if fd < 0 {
                let e = sys::errno();
                refusal = Some(format!(
                    "cannot move the config memfd to a holding descriptor ({})",
                    std::io::Error::from_raw_os_error(e)
                ));
                break;
            }
            fd_of[*node] = fd;
            cfg_fds.push(fd);
        }
        if refusal.is_some() {
            for fd in &cfg_fds {
                sys::close(*fd);
            }
            for t in &all_temps {
                let _ = std::fs::remove_dir_all(t);
            }
            return Err(refusal.unwrap_or_default());
        }
        let mut failed = false;
        let mut root_temps: Vec<std::path::PathBuf> = Vec::new();
        for node in &nodes {
            let fd = fd_of[*node];
            let exe = if bind {
                gen::template_exe(&corpus::CORPUS[rows[*node].tmpl])
            } else {
                Vec::new()
            };
            let need_exe_dir =
                !exe.is_empty() && !Path::new(std::ffi::OsStr::from_bytes(&exe)).exists();
            let need_disk_dir = args.disk_mb.unwrap_or(0) > 0;
            let temp = if need_exe_dir || need_disk_dir {
                match make_temp_dir(*node, &nonce) {
                    Some(p) => {
                        root_temps.push(p.clone());
                        p.as_os_str().as_bytes().to_vec()
                    }
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            };
            let cfg = make_config(
                *node,
                rows,
                &children,
                &fd_of,
                args,
                &temp,
                &RunPaths {
                    bind,
                    self_copy: &self_copy,
                    nonce: &nonce,
                },
            );
            // The seal is part of the descriptor's identity, not a nicety: the
            // stub requires a memfd to be sealed, so an unsealed one would be
            // refused by the stub it was written for.
            if !write_config_fd(fd, &cfg) || !sys::fd_add_seals(fd) {
                failed = true;
                break;
            }
        }
        if failed {
            for fd in &cfg_fds {
                sys::close(*fd);
            }
            for t in &root_temps {
                let _ = std::fs::remove_dir_all(t);
            }
            continue;
        }
        all_temps.extend(root_temps.iter().cloned());
        let root_cfg_fd = fd_of[root];
        let pid = sys::fork();
        if pid == 0 {
            sys::close(status_read);
            if sys::dup2(root_cfg_fd, 3) != 3 {
                sys::exit(127);
            }
            if root_cfg_fd != 3 {
                sys::close(root_cfg_fd);
            }
            redirect_stdio();
            // The nonce goes in the environment, not argv: argv is what
            // `ps aux` renders and the template command line has to stay
            // byte-exact.
            let nonce_line = stub::nonce_env_line(&nonce);
            let env = stub::envp_with(&nonce_line);
            let (buf, argv) = stub::build_argv(&rows[root].cmd);
            // /proc/self/exe still resolves after the binary is replaced or
            // deleted; the stored path is only the fallback.
            if sys::execve(b"/proc/self/exe", &argv, &env) < 0 {
                sys::execve(&self_exe, &argv, &env);
            }
            let _ = &buf;
            sys::exit(127);
        }
        if pid > 0 {
            // The stub sets its own comm only after exec, so the comm read
            // here is still the parent's. The starttime is stable across exec
            // and is the identity `--wait` checks.
            root_pids.push((pid, live::read_starttime(pid).unwrap_or(0)));
        }
        for fd in &cfg_fds {
            sys::close(*fd);
        }
    }

    sys::close(5);
    if arena_fd >= 0 {
        sys::close(arena_fd);
    }
    // The roots exist now, so a later prune can see that their staging
    // directories are still in use even after this injector exits.
    write_live_marker(&all_temps, &root_pids, &nonce);

    let disk_ms = args.disk_mb.unwrap_or(0).saturating_mul(30);
    let timeout = 2_000u64
        .saturating_add((total_nodes as u64).saturating_mul(30))
        .saturating_add(disk_ms)
        .min(60_000);
    let records = read_status_records(status_read, total_nodes, timeout);
    sys::close(status_read);

    let mut pids: Vec<i32> = Vec::new();
    let mut failed = 0usize;
    let mut warned = 0usize;
    let mut mismatches: Vec<(i32, u32, u64, u64, u64, u64)> = Vec::new();
    let mut failed_ids: Vec<(u32, i32)> = Vec::new();
    let mut tty_wanted = 0usize;
    let mut tty_real = 0usize;
    let mut tty_degraded = 0usize;
    let mut dev_exe = 0usize;
    let mut dev_user = 0usize;
    let mut dev_disk = 0usize;
    let mut dev_mem = 0usize;
    for p in rows.iter() {
        if p.flags & corpus::F_TTY != 0 {
            tty_wanted += 1;
        }
    }
    let tol = 128;
    for (pid, status, id, dev) in &records {
        if *status == 0 {
            pids.push(*pid);
        } else if *status == 2 {
            pids.push(*pid);
            warned += 1;
        } else {
            failed += 1;
            failed_ids.push((*id, *status));
        }
        if *dev & stub::DEV_TTY != 0 {
            tty_degraded += 1;
        } else if (*id as usize) < rows.len() && rows[*id as usize].flags & corpus::F_TTY != 0 {
            tty_real += 1;
        }
        if *dev & stub::DEV_EXE != 0 {
            dev_exe += 1;
        }
        if *dev & stub::DEV_USER != 0 {
            dev_user += 1;
        }
        if *dev & stub::DEV_DISK != 0 {
            dev_disk += 1;
        }
        if *dev & (stub::DEV_RSS | stub::DEV_VSZ) != 0 {
            dev_mem += 1;
        }
        // Status 2 is a deviation, not a failure: the row is running with one
        // part of its setup missing. Only a negative status excludes a row.
        if args.verify && args.mem && *status >= 0 && (*id as usize) < rows.len() {
            if let Some((vsz, rss)) = live::read_sizes(*pid) {
                let want_vsz = rows[*id as usize].vsz;
                let want_rss = rows[*id as usize].rss;
                if vsz.abs_diff(want_vsz) > tol || rss.abs_diff(want_rss) > tol {
                    mismatches.push((*pid, *id, want_vsz, vsz, want_rss, rss));
                }
            }
        }
    }
    let missing = total_nodes.saturating_sub(records.len());
    if pids.is_empty() && !root_pids.is_empty() {
        // No stub reported, but the roots were forked. Record them so the
        // pidfile and --wait can still stop the tree, and keep the temps.
        pids.extend(root_pids.iter().map(|(p, _)| *p));
    }
    if let Some(d) = &shadow_dir {
        all_temps.push(d.clone());
    }
    if pids.is_empty() {
        for t in &all_temps {
            let _ = std::fs::remove_dir_all(t);
        }
        all_temps.clear();
    }
    let mut pidfile_ok = true;
    if let Some(path) = &args.pidfile {
        let (ok, errno) = write_pidfile(path, &pids, &all_temps, &nonce);
        pidfile_ok = ok;
        if !ok {
            let mut out = Buf::new();
            out.push_str("psgen: cannot write pidfile: ");
            out.push_str(&std::io::Error::from_raw_os_error(errno).to_string());
            out.push(b'\n');
            sys::err(out.as_bytes());
        }
    }
    // Every identity in the markers this run wrote, deduplicated. `pids` only
    // holds rows that reported; a stub frozen or detached before its status
    // record is in the marker and nowhere else, so a cleanup keyed on `ident`
    // alone could not name it.
    let mut ident: Vec<(i32, u64, Vec<u8>)> = pids
        .iter()
        .map(|pid| {
            (
                *pid,
                live::read_starttime(*pid).unwrap_or(0),
                live::read_comm(*pid).unwrap_or_default(),
            )
        })
        .collect();
    for dir in &all_temps {
        for m in read_live_marker(dir).unwrap_or_default() {
            if m.pid <= 1 || ident.iter().any(|(p, _, _)| *p == m.pid) {
                continue;
            }
            if ns_matches(&m, pid_ns_inode()) && !boot_differs(&m, &util::boot_id()) {
                ident.push((m.pid, m.start, Vec::new()));
            }
        }
    }
    let live_ids: Vec<(i32, u64)> = ident.iter().map(|(pid, start, _)| (*pid, *start)).collect();
    // The stubs already appended their own lines before they exec'd. This adds
    // the rows that reported, and never removes a stub that has not reported
    // yet: a truncating rewrite here erased live stubs from the marker and made
    // their staging directories prunable.
    write_live_marker(&all_temps, &live_ids, &nonce);
    Ok(SpawnResult {
        pids,
        roots: root_pids,
        failed,
        warned,
        missing,
        mismatches,
        failed_ids,
        pidfile_ok,
        tty_wanted,
        tty_real,
        tty_degraded,
        dev_exe,
        dev_user,
        dev_disk,
        dev_mem,
        tier,
        temps: all_temps,
        ident,
    })
}

fn current_exe_bytes() -> Vec<u8> {
    std::env::current_exe()
        .map(|p| p.as_os_str().as_bytes().to_vec())
        .unwrap_or_default()
}

pub fn safe_temp_dir(t: &[u8]) -> bool {
    let p = Path::new(std::ffi::OsStr::from_bytes(t));
    if !p.is_absolute() {
        return false;
    }
    // A FUSE daemon or user-controlled overlay can report any owner and file
    // type. A root run must not write into or execute from a directory whose
    // metadata it cannot trust.
    if sys::geteuid() == 0
        && matches!(
            sys::path_fs_type(t),
            Some(sys::FUSE_SUPER_MAGIC) | Some(sys::OVERLAYFS_SUPER_MAGIC)
        )
    {
        return false;
    }
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.file_type().is_dir() {
        return false;
    }
    // A bind mount over the name reports the mounted filesystem's root
    // metadata, so every arm below can pass on a directory this run never made.
    // The recursions that follow (removing it, writing a `data.bin` into it)
    // then act on the mount's contents.
    let bytes = p.as_os_str().as_bytes();
    if sys::is_mount_point(bytes) {
        return false;
    }
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != sys::geteuid() {
        return false;
    }
    // A staging directory must not be group-writable or world-writable, or
    // another user could swap a symlink or hardlink inside it.
    if meta.mode() & 0o022 != 0 {
        return false;
    }
    let name = match p.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    let rest = match name.strip_prefix(".psgen-") {
        Some(r) => r,
        None => return false,
    };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

/// How `/proc/PID/exe` identifies a stub.
enum ExeKind {
    /// The psgen binary itself, i.e. a proc-self row.
    Psgen,
    /// A shadow copy inside a staging directory owned by the caller.
    Shadow,
    /// Something else. Bind-tier rows land here with the template path.
    Other(Vec<u8>),
}

fn exe_identity(pid: i32, me: &[u8]) -> ExeKind {
    let mut path = b"/proc/".to_vec();
    let mut b = Buf::new();
    b.push_u64(pid as u64);
    path.extend_from_slice(b.as_bytes());
    path.extend_from_slice(b"/exe");
    let got = match sys::read_link(&path) {
        Some(g) => g,
        None => return ExeKind::Other(Vec::new()),
    };
    // A deleted executable is still the same file, which is what the link
    // would have said before the unlink.
    let deleted = b" (deleted)";
    let real = if got.len() > deleted.len() && got.ends_with(deleted) {
        got[..got.len() - deleted.len()].to_vec()
    } else {
        got.clone()
    };
    if real == me {
        return ExeKind::Psgen;
    }
    // A shadow copy is `<staging dir>/psgen-stub`, and the staging directory
    // name is checked by the same predicate `stop` uses before removing one.
    if str::basename(&real) == b"psgen-stub" {
        if let Some(parent) = Path::new(std::ffi::OsStr::from_bytes(&real)).parent() {
            if safe_temp_dir(parent.as_os_str().as_bytes()) {
                return ExeKind::Shadow;
            }
        }
    }
    ExeKind::Other(real)
}

/// What a line without a starttime can prove about a PID.
enum LineIdentity {
    /// The process belongs to the run that wrote the pidfile.
    Same,
    /// Nothing proves which run the process belongs to, so signalling it could
    /// hit an unrelated process. The message says what is missing.
    Unidentifiable(Buf),
}

/// Identify the process behind a one-field line.
///
/// A line with no starttime has no per-process field to compare, so the only
/// positive identification left is the run nonce the injector puts in every
/// stub's environment and records in the pidfile header. The executable test
/// is not enough on its own: every psgen process shares the `psgen` executable,
/// so a recycled PID with nothing but an exe match would kill whatever process
/// now holds it.
fn line_identity(pid: i32, header_nonce: &[u8], me: &[u8]) -> LineIdentity {
    if header_nonce.is_empty() {
        // A pidfile written before the header recorded a run nonce. Nothing in
        // this line can prove the process is one of its rows, so the safe
        // answer is to refuse: the caller has the three-field form.
        let mut why = Buf::new();
        why.push_str(
            "the pidfile records no run nonce, so a one-field line cannot be told \
             from an unrelated process holding the same PID; use the three-field form",
        );
        return LineIdentity::Unidentifiable(why);
    }
    if read_nonce_env(pid) == header_nonce {
        return LineIdentity::Same;
    }
    // Nothing else can. Report the closest thing to an explanation: a bind-tier
    // row under a template path is the case this form was written for.
    let mut why = Buf::new();
    if let ExeKind::Other(exe) = exe_identity(pid, me) {
        let cmd = read_cmdline_text(pid);
        if corpus_command(&cmd, &exe) {
            why.push_str("a one-field line cannot identify a bind-tier row whose exe is ");
            why.push_bytes(&exe);
            why.push_str("; use the three-field form");
            return LineIdentity::Unidentifiable(why);
        }
    }
    why.push_str(
        "this process does not carry the run nonce in the pidfile header; use the three-field form",
    );
    LineIdentity::Unidentifiable(why)
}

/// Whether a command line looks like one the corpus would produce.
///
/// Used only to recognise a bind-tier row that a pidfile line cannot otherwise
/// identify, so `stop` can say so instead of reporting success.
fn corpus_command(cmdline: &[u8], exe: &[u8]) -> bool {
    if cmdline.is_empty() {
        return false;
    }
    for t in corpus::CORPUS.iter() {
        let tmpl = t.cmd.as_bytes();
        let prefix = match tmpl.iter().position(|b| *b == b'{') {
            Some(p) => &tmpl[..p],
            None => tmpl,
        };
        if !str::starts_with(cmdline, prefix) {
            continue;
        }
        if prefix.len() == tmpl.len() && cmdline != tmpl {
            continue;
        }
        let want = gen::template_exe(t);
        if exe.is_empty() || want.is_empty() || want == exe {
            return true;
        }
        // Compare against where the bind actually pointed. `canonicalize` on
        // the whole path fails when the leaf does not exist, which is the
        // normal case for a spoofed template, so the parent is resolved
        // separately. This is the same rule `stub::resolve_target` applies;
        // resolving only the whole path made every `/usr/sbin/x` row on a host
        // whose `/usr/sbin` is a symlink look like an unrelated process.
        if resolve_exe(&want) == exe {
            return true;
        }
    }
    false
}

/// The path `/proc/PID/exe` reports for `want`, resolving the parent when the
/// leaf itself does not exist.
fn resolve_exe(want: &[u8]) -> Vec<u8> {
    let p = Path::new(std::ffi::OsStr::from_bytes(want));
    if let Ok(canon) = std::fs::canonicalize(p) {
        return canon.as_os_str().as_bytes().to_vec();
    }
    if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
        if let Ok(c) = std::fs::canonicalize(parent) {
            return c.join(name).as_os_str().as_bytes().to_vec();
        }
    }
    want.to_vec()
}

fn read_cmdline_text(pid: i32) -> Vec<u8> {
    let mut path = b"/proc/".to_vec();
    path.extend_from_slice(pid.to_string().as_bytes());
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
        } else if *b < 0x20 || *b == 0x7f {
            out.push(b'?');
        } else {
            out.push(*b);
        }
    }
    str::trim(&out).to_vec()
}

struct StopLine {
    pid: i32,
    start: Option<u64>,
    comm: Vec<u8>,
}

fn parse_stop_line(line: &[u8]) -> Option<StopLine> {
    let fields: Vec<&[u8]> = line.splitn(3, |b| *b == b'\t').collect();
    let pid = str::parse_i64(fields[0])?;
    if pid <= 0 || pid > i32::MAX as i64 {
        return None;
    }
    let start = if fields.len() >= 2 {
        // A second field that is present but unparseable is a malformed line,
        // not a one-field line. Treating it as one-field used to downgrade the
        // identity check to the executable name and kill an unrelated process.
        Some(str::parse_u64(fields[1])?)
    } else {
        None
    };
    let comm = if fields.len() == 3 {
        fields[2].to_vec()
    } else {
        Vec::new()
    };
    Some(StopLine {
        pid: pid as i32,
        start,
        comm,
    })
}

/// The 1-based number of the first CRLF line ending, if the file has one.
///
/// A lone `\r` inside a line is a legal byte in a path or a comm, so only the
/// `\r\n` pair is a line ending here. One such line is enough to make every
/// later field carry a stray `\r`, which is why the whole file is refused
/// rather than the affected lines being skipped.
fn crlf_line(text: &[u8]) -> Option<usize> {
    let mut line = 1usize;
    for (i, b) in text.iter().enumerate() {
        if *b == b'\n' {
            if i > 0 && text[i - 1] == b'\r' {
                return Some(line);
            }
            line += 1;
        }
    }
    None
}

/// The value of `PSGEN_NONCE` in a process's environment.
///
/// The injector puts the run nonce there rather than in argv, so a row can be
/// tied to the run that made it without changing what `ps aux` renders. An
/// empty result means the variable is absent, which is the case for every
/// process psgen did not start.
fn read_nonce_env(pid: i32) -> Vec<u8> {
    let mut path = b"/proc/".to_vec();
    path.extend_from_slice(pid.to_string().as_bytes());
    path.extend_from_slice(b"/environ");
    let mut buf = [0u8; 65536];
    let n = match sys::read_file(&path, &mut buf) {
        Some(n) => n,
        None => return Vec::new(),
    };
    let key = stub::NONCE_ENV.as_bytes();
    for var in buf[..n].split(|b| *b == 0) {
        if !str::starts_with(var, key) || var.len() <= key.len() {
            continue;
        }
        if var[key.len()] != b'=' {
            continue;
        }
        return var[key.len() + 1..].to_vec();
    }
    Vec::new()
}

/// Count pidfile rows that still name a live process.
///
/// A pidfile can only be overwritten safely when none of its recorded rows
/// still exists. Re-injecting over a live pidfile used to orphan the first
/// run's stubs: the second run rewrote the file and pruned the first run's
/// staging directories, and `stop` then had no record of the old PIDs.
/// `None` means the file exists but could not be read, so the caller must not
/// assume it is safe to overwrite.
pub fn live_pidfile_rows(path: &[u8]) -> Option<usize> {
    let text = match sys::read_file_nofollow(path, 1 << 20) {
        Some(t) => t,
        None => {
            // A file that exists but cannot be read or is too large must not
            // be treated as empty: that would let a second run overwrite the
            // only record of the first. Report the uncertainty to the caller.
            return if Path::new(std::ffi::OsStr::from_bytes(path)).exists() {
                None
            } else {
                Some(0)
            };
        }
    };
    let mut live_rows = 0usize;
    for raw in text.split(|b| *b == b'\n') {
        if raw.is_empty() || raw[0] == b'#' {
            continue;
        }
        let line = match parse_stop_line(raw) {
            Some(l) => l,
            None => continue,
        };
        let alive = match line.start {
            Some(start) => live::read_starttime(line.pid) == Some(start) && live::alive(line.pid),
            None => live::alive(line.pid),
        };
        if alive {
            live_rows += 1;
        }
    }
    Some(live_rows)
}

/// How many pidfile rows lie between a row and the top of its tree.
///
/// The pidfile does not store a parent, so the depth is read from `/proc`. A
/// row whose parent is not in the pidfile is a root. The walk is bounded so a
/// corrupted `/proc` cannot loop.
fn stop_depths(lines: &[StopLine]) -> std::collections::BTreeMap<i32, usize> {
    let mut depths = std::collections::BTreeMap::new();
    for line in lines {
        let mut depth = 0usize;
        let mut cur = line.pid;
        for _ in 0..64 {
            let ppid = match live::read_stat(cur) {
                Some(s) => s.ppid as i32,
                None => break,
            };
            if ppid <= 1 || !lines.iter().any(|l| l.pid == ppid) {
                break;
            }
            depth += 1;
            cur = ppid;
        }
        depths.insert(line.pid, depth);
    }
    depths
}

/// Stop (or, with `plan`, describe) every process a pidfile names.
///
/// A row is identified before it is signalled: a line with a starttime checks
/// that, a line with comm checks both, and a line with only a PID checks the run
/// nonce from the header, because that is the only field it carries that ties a
/// process to this run. A row that cannot be identified is an error, never a
/// skip, so a file whose rows all survive cannot report success.
///
/// A line counts as stopped only once the process is gone or a zombie. A zombie
/// is already dead and a signal to it succeeds and does nothing, so counting
/// signals would report a second stop as having stopped the same processes
/// again; a zombie leader's process group is still signalled, because it can
/// hold live members. The count is of distinct PIDs, not of lines.
pub fn stop(path: &[u8], force: bool, plan: bool, quiet: bool) -> i32 {
    let text = match sys::read_file_nofollow_res(path, 1 << 20) {
        Ok(t) => t,
        Err(e) => {
            // A missing file, a mode-000 file and a directory all used to
            // print the same bytes, so a caller could not tell a stale
            // pidfile from a permissions problem. Name both the path and the
            // errno; the exit status stays 1 for every read failure.
            let msg = format!(
                "psgen: cannot read pidfile {}: {}\n",
                String::from_utf8_lossy(path),
                e
            );
            sys::err(msg.as_bytes());
            return 1;
        }
    };
    // A CRLF pidfile is what a Windows editor or a pipeline without `dos2unix`
    // leaves. Every line's last field then ends with `\r`, so no row matches
    // and the boot id does not either; the run used to report a clean success
    // with every row still alive. Refusing names the cause instead.
    if let Some(line) = crlf_line(&text) {
        let mut out = Buf::new();
        out.push_str("psgen: the pidfile has CRLF line endings (line ");
        out.push_u64(line as u64);
        out.push_str("); convert it to LF (for example with dos2unix) and run stop again\n");
        sys::err(out.as_bytes());
        return 1;
    }
    let mut header_boot: Option<Vec<u8>> = None;
    let mut header_nonce: Vec<u8> = Vec::new();
    let mut temp_dirs: Vec<Vec<u8>> = Vec::new();
    let mut lines: Vec<StopLine> = Vec::new();
    let mut malformed = 0usize;
    // A psgen header may follow leading comment lines, but not content: a
    // first line that is any other comment is not a header. Taking every
    // leading `#` as the header turned a `# note` prepended to a valid file
    // into an empty boot id, which then read as "from another boot".
    let mut header_seen = false;
    let mut content_seen = false;
    for raw in text.split(|b| *b == b'\n') {
        if raw.is_empty() {
            continue;
        }
        if raw[0] == b'#' {
            if !header_seen && !content_seen && raw.starts_with(b"# psgen") {
                header_boot = Some(crate::version::pidfile_boot_id(raw).unwrap_or_default());
                header_nonce = crate::version::pidfile_nonce(raw);
                header_seen = true;
            }
            if let Some(rest) = raw.strip_prefix(b"# temp ") {
                temp_dirs.push(str::trim(rest).to_vec());
            }
            continue;
        }
        content_seen = true;
        match parse_stop_line(raw) {
            Some(l) => lines.push(l),
            None => malformed += 1,
        }
    }
    // A file with no psgen header is not a psgen pidfile. Failing open here
    // signalled whatever a made-up file named, and removed whatever a `# temp`
    // line named, which is the one check that exists to prevent exactly that.
    // `--force` stays as the documented escape hatch.
    if header_boot.is_none() && !force {
        sys::err(b"psgen: not a psgen pidfile (no '# psgen' header); use --force to stop anyway\n");
        return 1;
    }
    if let Some(hb) = &header_boot {
        let cur = util::boot_id();
        if !force && (hb.is_empty() || cur.is_empty() || *hb != cur) {
            sys::err(b"psgen: pidfile is from another boot; use --force to ignore\n");
            return 1;
        }
    }
    let me = current_exe_bytes();
    // Children before roots: a root's process-group kill reaches every child
    // that stayed in the group, and those children are then already gone when
    // their own lines are reached. Sorting by depth gives every line its own
    // signal even when a PID wrap makes a child's number lower than its
    // parent's.
    let depths = stop_depths(&lines);
    lines.sort_unstable_by_key(|l| {
        (
            std::cmp::Reverse(depths.get(&l.pid).copied().unwrap_or(0)),
            std::cmp::Reverse(l.pid),
        )
    });

    let mut signalled: Vec<(i32, u64)> = Vec::new();
    // The distinct PIDs a line named, so `plan` counts processes rather than
    // lines: one process named five times is still one process.
    let mut named: Vec<i32> = Vec::new();
    let mut planned = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let note = |quiet: bool, what: &[u8], pid: i32, why: Option<&[u8]>| {
        if quiet {
            return;
        }
        let mut out = Buf::new();
        out.push_str("psgen: ");
        out.push_bytes(what);
        out.push(b' ');
        out.push_u64(pid as u64);
        if let Some(w) = why {
            out.push_str(" (");
            out.push_bytes(w);
            out.push(b')');
        }
        out.push(b'\n');
        sys::err(out.as_bytes());
    };

    for line in &lines {
        let pid = line.pid;
        if pid == 1 {
            skipped += 1;
            note(quiet, b"skip", pid, Some(b"PID 1 is never a psgen stub"));
            continue;
        }
        if pid == sys::getpid() {
            skipped += 1;
            continue;
        }
        let info = live::read_stat(pid);
        let cur_start = info.as_ref().map(|s| s.starttime);
        let cur_state = info.as_ref().map(|s| s.state).unwrap_or(0);
        if info.is_none() {
            // Gone, or unreadable. A PID that still has a /proc entry but
            // cannot be inspected is a failure, not a successful stop.
            let mut procpath = b"/proc/".to_vec();
            procpath.extend_from_slice(pid.to_string().as_bytes());
            if Path::new(std::ffi::OsStr::from_bytes(&procpath)).exists() {
                failed += 1;
                note(quiet, b"cannot read", pid, Some(b"/proc entry unreadable"));
            } else {
                skipped += 1;
                note(quiet, b"skip", pid, Some(b"already gone"));
            }
            continue;
        }
        // Identity: three fields check starttime and comm, two check
        // starttime, and one needs the run nonce from the header, because the
        // only per-process field it carries is the PID.
        if line.start.is_some() {
            let identical = cur_start == line.start
                && (line.comm.is_empty() || live::read_comm(pid).as_deref() == Some(&line.comm));
            if !identical {
                skipped += 1;
                note(quiet, b"skip", pid, Some(b"identity does not match"));
                continue;
            }
        } else {
            match line_identity(pid, &header_nonce, &me) {
                LineIdentity::Same => {}
                LineIdentity::Unidentifiable(why) => {
                    // Refusing is the only safe answer: every psgen process
                    // matches its own executable, so signalling on that alone
                    // would hit whatever now holds a recycled PID.
                    failed += 1;
                    note(quiet, b"cannot identify", pid, Some(why.as_bytes()));
                    continue;
                }
            }
        }
        // A zombie is already dead, but its process group is not: an init that
        // does not reap holds the leader's /proc entry while its children keep
        // running. The group is signalled below for a leader whether it is a
        // zombie or not, and only the signal to the body is skipped.
        let zombie = cur_state == b'Z';
        let leader = info.as_ref().map(|s| s.pgrp == pid as i64).unwrap_or(false);
        if plan {
            // A plan is a prediction of the real stop. Check that the real
            // signal would be permitted; otherwise `--plan` reports success
            // for a process the caller cannot stop.
            if !zombie && !sys::kill(pid, 0) {
                let err = sys::last_error().raw_os_error();
                if err == Some(libc::ESRCH) {
                    skipped += 1;
                    note(quiet, b"skip", pid, Some(b"already gone"));
                    continue;
                }
                if err == Some(libc::EPERM) {
                    failed += 1;
                    note(quiet, b"cannot signal", pid, Some(b"permission denied"));
                    continue;
                }
                failed += 1;
                note(quiet, b"cannot signal", pid, None);
                continue;
            }
            if zombie {
                // The real run signals a zombie leader's group before it
                // decides the row is dead, so the plan must say the same rather
                // than predict a no-op the real run does not perform.
                if leader && !sys::kill(-pid, 0) {
                    let err = sys::last_error().raw_os_error();
                    if err == Some(libc::EPERM) {
                        failed += 1;
                        note(quiet, b"cannot signal", pid, Some(b"process group"));
                        continue;
                    }
                }
                if !quiet {
                    let mut out = Buf::new();
                    out.push_str("would skip ");
                    out.push_u64(pid as u64);
                    out.push_str(" (already a zombie; its process group is signalled first)\n");
                    sys::out(out.as_bytes());
                }
                skipped += 1;
                continue;
            }
            if !quiet {
                let comm = live::read_comm(pid).unwrap_or_default();
                let mut out = Buf::new();
                out.push_str("would signal ");
                out.push_u64(pid as u64);
                out.push_str(" (");
                out.push_bytes(&comm);
                out.push_str(")\n");
                sys::out(out.as_bytes());
            }
            if !named.contains(&pid) {
                named.push(pid);
                planned += 1;
            }
            continue;
        }
        let pfd = sys::pidfd_open(pid);
        // Re-verify identity after opening the pidfd (or right before kill if
        // pidfd_open is unavailable) so a PID recycled between the first
        // `/proc` read and the signal is not hit.
        let post = live::read_stat(pid);
        if post.as_ref().map(|s| s.starttime) != cur_start {
            if pfd >= 0 {
                sys::close(pfd);
            }
            skipped += 1;
            note(quiet, b"skip", pid, Some(b"already gone"));
            continue;
        }
        // A leader's PID is its PGID, so its group kill reaches children that
        // never wrote a status record. For a non-leader the group signal would
        // address a stale group, so signal the process itself.
        let leader = post.as_ref().map(|s| s.pgrp == pid as i64).unwrap_or(false);
        let mut delivered = false;
        if leader {
            // The group signal comes before the zombie check on purpose: a
            // zombie leader whose init does not reap it still heads a group
            // with live members, and `kill(-pid)` is the only signal that
            // reaches them.
            if sys::kill(-pid, sys::SIGKILL) {
                delivered = true;
            } else if sys::last_error().raw_os_error() != Some(libc::ESRCH) {
                if pfd >= 0 {
                    sys::close(pfd);
                }
                failed += 1;
                note(quiet, b"cannot signal", pid, Some(b"process group"));
                continue;
            }
        }
        if zombie {
            // Already dead. Its /proc entry outlives it while an init that does
            // not reap holds it, and a signal to the body is a no-op; a group
            // signal above has already been delivered. The row is not counted
            // as stopped: its own death is not this call's doing.
            if pfd >= 0 {
                sys::close(pfd);
            }
            skipped += 1;
            note(quiet, b"skip", pid, Some(b"already a zombie"));
            continue;
        }
        if !delivered {
            if pfd >= 0 {
                // The pidfd pins the process, so the signal cannot land on a
                // reused PID.
                delivered = sys::pidfd_send_signal(pfd, sys::SIGKILL);
                if !delivered && sys::last_error().raw_os_error() == Some(libc::ESRCH) {
                    sys::close(pfd);
                    skipped += 1;
                    note(quiet, b"skip", pid, Some(b"already gone"));
                    continue;
                }
            }
            if !delivered {
                delivered = sys::kill(pid, sys::SIGKILL);
            }
        }
        if pfd >= 0 {
            sys::close(pfd);
        }
        if delivered {
            signalled.push((pid, cur_start.unwrap_or(0)));
        } else if sys::last_error().raw_os_error() == Some(libc::ESRCH) {
            skipped += 1;
            note(quiet, b"skip", pid, Some(b"already gone"));
        } else {
            failed += 1;
            note(quiet, b"cannot signal", pid, None);
        }
    }

    // A file can name one PID on several lines, and a group leader's line can
    // reach children whose own lines follow. Counting signals therefore counts
    // the same process more than once; dedupe by PID so the summary is a count
    // of processes.
    signalled.sort_unstable();
    signalled.dedup();
    let mut stopped = 0usize;
    if !plan && !signalled.is_empty() {
        // A `SIGKILL` returns before the process has exited, and a zombie is
        // dead but still visible. Wait, bounded, until every signalled PID is
        // gone or a zombie, so "stopped N" is true when it is printed.
        let deadline = sys::monotonic_ns().saturating_add(2_000_000_000);
        loop {
            let mut left = 0usize;
            for (pid, start) in &signalled {
                if live::read_starttime(*pid) == Some(*start) && live::alive(*pid) {
                    left += 1;
                }
            }
            if left == 0 || sys::monotonic_ns() >= deadline {
                break;
            }
            sys::nanosleep(0, 10_000_000);
        }
        for (pid, start) in &signalled {
            if live::read_starttime(*pid) == Some(*start) && live::alive(*pid) {
                failed += 1;
                note(
                    quiet,
                    b"still running",
                    *pid,
                    Some(b"the signal did not land in 2 s"),
                );
            } else {
                stopped += 1;
            }
        }
    }

    if failed == 0 && !plan {
        for t in &temp_dirs {
            let p = Path::new(std::ffi::OsStr::from_bytes(t));
            if !staging_busy(p) && safe_temp_dir(t) {
                let _ = sys::remove_staging_dir(p);
            }
        }
    }
    // The noun matters: an older message said "processes" while counting
    // pidfile lines, so one process named five times read as five.
    let mut out = Buf::new();
    if plan {
        out.push_str("would stop ");
        out.push_u64(planned as u64);
    } else {
        out.push_str("stopped ");
        out.push_u64(stopped as u64);
    }
    out.push_str(if (if plan { planned } else { stopped }) == 1 {
        " process"
    } else {
        " processes"
    });
    let missed = skipped + malformed;
    if missed > 0 {
        out.push_str(", skipped ");
        out.push_u64(missed as u64);
        out.push_str(if missed == 1 { " line" } else { " lines" });
    }
    if failed > 0 {
        out.push_str(", failed ");
        out.push_u64(failed as u64);
    }
    out.push(b'\n');
    sys::out(out.as_bytes());
    if failed > 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(ns: u64, boot: &[u8]) -> Marker {
        Marker {
            pid: 1,
            start: 1,
            ns,
            boot: boot.to_vec(),
        }
    }

    /// A PID means nothing outside the namespace that produced it, so a
    /// mismatch there is doubt, and doubt must keep the directory.
    #[test]
    fn another_namespace_is_not_judgeable() {
        let here = marker(7, b"boot-a");
        assert!(ns_matches(&here, 7));
        // A marker with no namespace is one an older build wrote.
        assert!(ns_matches(&marker(0, b"boot-a"), 7));
        assert!(!ns_matches(&here, 8));
    }

    /// A process cannot outlive a reboot, so a boot mismatch is the one
    /// mismatch that proves death rather than leaving it in doubt.
    #[test]
    fn another_boot_is_provably_dead() {
        assert!(!boot_differs(&marker(7, b"boot-a"), b"boot-a"));
        assert!(boot_differs(&marker(7, b"boot-a"), b"boot-b"));
        // An older line names no boot; it keeps today's behaviour.
        assert!(!boot_differs(&marker(7, b""), b"boot-b"));
    }

    /// The marker line is the whole record a prune has, so its shape is the
    /// contract between the injector, the stub and both readers.
    #[test]
    fn a_marker_line_round_trips_through_the_reader() {
        let line = marker_line(4242, 999, b"boot-xyz", b"abcd");
        let dir = std::env::temp_dir().join(format!(".psgen-marker-{}", sys::getpid()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("m"), &line).unwrap();
        let read = read_marker(&dir, b"m").expect("a marker file");
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].pid, 4242);
        assert_eq!(read[0].start, 999);
        assert_eq!(read[0].boot, b"boot-xyz".to_vec());
        assert_eq!(read[0].ns, pid_ns_inode());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
