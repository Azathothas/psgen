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
    /// so a later signal can prove the PID was not reused.
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
    let sum: u64 = rows.iter().map(|p| p.rss as u64).sum();
    let max = rows.iter().map(|p| p.rss as u64).max().unwrap_or(0);
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
        p.rss = crate::table::round_up(v, page_kb).min(u32::MAX as u64) as u32;
    }
    factor
}

pub fn prepare(rows: &mut [Proc], args: &Args, create_users: bool) -> Prep {
    let me = util::current_user();
    let root = sys::geteuid() == 0;
    let mut warnings: Vec<String> = Vec::new();
    let mut created: Vec<Vec<u8>> = Vec::new();
    let mut warned_names: Vec<Vec<u8>> = Vec::new();
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
        if !switch_users || !root {
            p.user = me.name.clone();
            p.uid = me.uid;
            p.gid = me.gid;
            continue;
        }
        if p.uid == me.uid && p.user == me.name {
            continue;
        }
        let (found, was_created, err) = users::ensure(&p.user, create_users);
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
                    if !create_users {
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
            p.vsz = crate::table::round_up(p.vsz as u64, page).min(u32::MAX as u64) as u32;
            p.rss = crate::table::round_up(p.rss as u64, page).min(u32::MAX as u64) as u32;
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
                let cap = (p.vsz as u64).saturating_sub(gen::BASE_RESERVE_KB as u64);
                let v = target.min(cap.max(page));
                p.rss = crate::table::round_up(v, page).min(u32::MAX as u64) as u32;
            }
        }
    }

    if args.mem_cap_mb > 0 && args.mem {
        let cap = args.mem_cap_mb.saturating_mul(1024);
        let sum: u64 = rows.iter().map(|p| p.rss as u64).sum();
        if sum > cap && !rows.is_empty() {
            // The 4 MiB per-stub reserve is taken off the cap first; what is
            // left is shared in proportion to each row's RSS above it.
            let floor = 4096u64;
            let base = floor.saturating_mul(rows.len() as u64);
            if base >= cap {
                warnings.push(format!(
                    "--mem-cap {} MiB is at or below the {} MiB floor of {} stubs; the reported RSS will be at least {} MiB",
                    args.mem_cap_mb,
                    base / 1024,
                    rows.len(),
                    base / 1024
                ));
                for p in rows.iter_mut() {
                    p.rss = floor.min(u32::MAX as u64) as u32;
                }
            } else {
                let extra = cap - base;
                let weight: u64 = rows
                    .iter()
                    .map(|p| (p.rss as u64).saturating_sub(floor))
                    .sum();
                for p in rows.iter_mut() {
                    let v = floor + (p.rss as u64).saturating_sub(floor) * extra / weight;
                    p.rss = crate::table::round_up(v, page).min(u32::MAX as u64) as u32;
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
            let max = rows.iter().map(|p| p.rss as u64).max().unwrap_or(0);
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
                    if p.rss as u64 > v {
                        p.rss = v as u32;
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
        let sum: u64 = rows.iter().map(|p| p.rss as u64).sum();
        let max = rows.iter().map(|p| p.rss as u64).max().unwrap_or(0);
        let ptes = sum / 512;
        let est = max.saturating_add(ptes).saturating_add(base_kb);
        phys_estimate_kb = est;
        if budget > 0 && est > budget && max > 0 {
            phys_scale = scale_rss(rows, budget, base_kb, page);
            let sum2: u64 = rows.iter().map(|p| p.rss as u64).sum();
            let max2 = rows.iter().map(|p| p.rss as u64).max().unwrap_or(0);
            phys_estimate_kb = max2.saturating_add(sum2 / 512).saturating_add(base_kb);
        }
        if budget > 0 && phys_estimate_kb > budget {
            warnings.push(format!(
                "the estimated physical cost is about {} MiB, above the {} MiB budget",
                phys_estimate_kb / 1024,
                budget / 1024
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
        let tenths = (pct.saturating_mul(10)).min(u16::MAX as u32) as u16;
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
        // plausible `/proc/PID/exe`. The path is absolute so a child can exec
        // the copy regardless of the working directory it inherits; the stub
        // changes its own working directory to / after the fork, not the
        // parent.
        shadow_root = std::env::current_dir().ok().map(|d| {
            let mut v = d.as_os_str().as_bytes().to_vec();
            if !v.ends_with(b"/") {
                v.push(b'/');
            }
            v.extend_from_slice(b".psgen-stubs");
            v
        });
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
        vsz_kb: p.vsz,
        rss_kb: p.rss,
        uid: p.uid,
        gid: p.gid,
        duration: duration_for(p, args),
        cpu: p.cpu as u32,
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

/// Hex characters for a temporary name. A `getrandom` denial must not be able
/// to panic after the stubs are already running, so every fallback path is
/// total and the whole buffer is filled.
fn random_hex(bytes: usize) -> Vec<u8> {
    let mut raw = vec![0u8; bytes];
    if !sys::getrandom(&mut raw) {
        // Mix the pid and the clock, which is all this needs to be unique
        // inside one directory.
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
fn pidfile_body(pids: &[i32], temps: &[std::path::PathBuf]) -> Buf {
    let boot = util::boot_id();
    let mut buf = Buf::new();
    buf.push_bytes(crate::version::PIDFILE_PREFIX);
    buf.push_str(crate::version::VERSION);
    buf.push_str(" boot ");
    buf.push_bytes(&boot);
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
    buf
}

/// Write a header-only pidfile before anything is spawned.
///
/// `spawn()` cannot write the PIDs until it has them, and a write that fails
/// after the fork leaves live stubs with no record. Proving the write works
/// first, and leaving a valid psgen pidfile behind, makes the later rewrite an
/// overwrite of a file the caller already has.
pub fn write_pending_pidfile(path: &[u8]) -> bool {
    write_pidfile(path, &[], &[])
}

/// Write the pidfile, falling back to shorter temporary names when the target
/// basename is close to `NAME_MAX`.
fn write_pidfile(path: &[u8], pids: &[i32], temps: &[std::path::PathBuf]) -> bool {
    if !probe::pidfile_target_ok(path) {
        return false;
    }
    let buf = pidfile_body(pids, temps);
    let flags = sys::O_WRONLY | sys::O_CREAT | sys::O_EXCL | sys::O_NOFOLLOW;
    for level in 0..probe::pidfile_temp_levels() {
        for retry in 0..16u64 {
            let nonce = sys::monotonic_ns()
                ^ ((sys::getpid() as u64) << 32)
                ^ retry.wrapping_mul(0x9e3779b97f4a7c15);
            let tmp = probe::pidfile_temp_name(path, level, nonce);
            let fd = sys::open(&tmp, flags, 0o600);
            if fd < 0 {
                match sys::last_error().raw_os_error() {
                    Some(libc::EEXIST) => continue,
                    Some(libc::ENAMETOOLONG) => break,
                    _ => return false,
                }
            }
            let ok = sys::write_fd(fd, buf.as_bytes()) && sys::fsync_fd(fd);
            sys::close(fd);
            if !ok {
                let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(&tmp)));
                return false;
            }
            let renamed = std::fs::rename(
                Path::new(std::ffi::OsStr::from_bytes(&tmp)),
                Path::new(std::ffi::OsStr::from_bytes(path)),
            )
            .is_ok();
            if !renamed {
                let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(&tmp)));
                return false;
            }
            return true;
        }
    }
    false
}

const OWNER_FILE: &[u8] = b".psgen-owner";
const LIVE_FILE: &[u8] = b".psgen-live";

/// Record the stubs that are still alive in a staging directory.
///
/// The injector exits before a `--duration` run ends, so the owner marker goes
/// stale while the stubs are still using their `--disk` data and shadow copy.
/// The prune pass must keep those directories until the last stub is gone.
fn write_live_marker(temps: &[std::path::PathBuf], pids: &[(i32, u64)]) {
    let mut body = Vec::new();
    for (pid, start) in pids {
        body.extend_from_slice(pid.to_string().as_bytes());
        body.push(b' ');
        body.extend_from_slice(start.to_string().as_bytes());
        body.push(b'\n');
    }
    for dir in temps {
        let _ = std::fs::write(dir.join(std::ffi::OsStr::from_bytes(LIVE_FILE)), &body);
    }
}

fn read_live_marker(dir: &Path) -> Option<Vec<(i32, u64)>> {
    let text = std::fs::read(dir.join(std::ffi::OsStr::from_bytes(LIVE_FILE))).ok()?;
    let mut pids = Vec::new();
    for line in text.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut it = line.split(|b| *b == b' ');
        let pid = str::parse_u64(it.next()?)?;
        let start = str::parse_u64(it.next().unwrap_or(b""))?;
        pids.push((i32::try_from(pid).ok()?, start));
    }
    Some(pids)
}

fn make_temp_dir(idx: usize) -> Option<std::path::PathBuf> {
    make_temp_dir_in(&std::env::temp_dir(), idx)
}

fn make_temp_dir_in(base: &Path, idx: usize) -> Option<std::path::PathBuf> {
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
        // Record who owns this directory, with the owner's starttime, so a
        // later prune can tell a live run from a recycled PID.
        let start = live::read_starttime(sys::getpid()).unwrap_or(0);
        let owner = format!("{} {}\n", sys::getpid(), start);
        let _ = std::fs::write(
            p.join(std::ffi::OsStr::from_bytes(OWNER_FILE)),
            owner.as_bytes(),
        );
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

fn read_owner_marker(dir: &Path) -> Option<(i32, u64)> {
    let text = std::fs::read(dir.join(std::ffi::OsStr::from_bytes(OWNER_FILE))).ok()?;
    let mut it = text.split(|b| *b == b' ' || *b == b'\n');
    let pid = str::parse_u64(it.next()?)?;
    let start = str::parse_u64(it.next().unwrap_or(b""))?;
    Some((i32::try_from(pid).ok()?, start))
}

/// Whether a staging directory still has a live process recorded in it.
///
/// The live marker is written by the injector and by each stub before it
/// execs, so it is the authoritative list of who is using the directory. A
/// zombie does not count: it holds no files and runs no code.
pub fn staging_busy(dir: &std::path::Path) -> bool {
    read_live_marker(dir)
        .map(|pids| {
            pids.iter()
                .any(|(pid, start)| live::same_process(*pid, *start))
        })
        .unwrap_or(false)
}

/// Remove the staging directories of runs whose injector and stubs are gone.
///
/// A `--duration` run that nobody stops leaves its shadow copy and `--disk`
/// data behind: the injector exits, the stub dies on its alarm, and nothing
/// else knows the directory exists. The directory name already carries the
/// injector PID, and the owner marker carries its starttime, so a recycled PID
/// cannot keep a dead run's directory alive.
///
/// A directory is removed only when it has a live marker and none of the PIDs
/// in that marker still exists. An unmarked directory may belong to another
/// tool, or to a run that crashed before it could write the marker, so it is
/// left alone.
pub fn prune_staging(prep: &Prep) -> usize {
    let mut roots: Vec<std::path::PathBuf> = vec![std::env::temp_dir()];
    if let Some(d) = &prep.shadow_root {
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(d));
        if p != std::env::temp_dir() {
            roots.push(p);
        }
    }
    let mut removed = 0usize;
    for root in roots {
        removed += prune_root(&root);
    }
    removed
}

fn prune_root(root: &Path) -> usize {
    use std::os::unix::fs::MetadataExt;
    let me = sys::geteuid();
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
        // Only a real directory (not a symlink) owned by the caller.
        if !meta.file_type().is_dir() || meta.uid() != me {
            continue;
        }
        if let Some((owner, start)) = read_owner_marker(&path) {
            // The marker names the injector and its starttime, so a recycled
            // PID cannot keep a dead run's directory alive. A live injector of
            // another user is skipped here too: its starttime matches.
            if live::same_process(owner, start) {
                continue;
            }
        }
        match read_live_marker(&path) {
            Some(pids) => {
                // A stub is still using this directory while it is alive. A
                // zombie is not: it holds no files and runs no code, and a
                // container whose PID 1 does not reap would otherwise keep
                // every dead run's staging for ever.
                if pids
                    .iter()
                    .any(|(pid, start)| live::same_process(*pid, *start))
                {
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
        if std::fs::remove_dir_all(&path).is_ok() {
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
        let made =
            make_temp_dir_in(Path::new(std::ffi::OsStr::from_bytes(dir)), 9_000).ok_or_else(|| {
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

    let max_rss = rows.iter().map(|p| p.rss as u64).max().unwrap_or(0);
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
    let mut root_pids: Vec<(i32, u64)> = Vec::new();
    let mut all_temps: Vec<std::path::PathBuf> = Vec::new();
    // The secret that ties a config descriptor to this run. It goes in the
    // environment, not argv: argv is what `ps aux` renders, and the template
    // command line has to stay byte-exact.
    let nonce = random_hex(8);

    for root in roots {
        let mut nodes = Vec::new();
        subtree(root, &children, &mut nodes);
        let mut fd_of = vec![0i32; rows.len()];
        let mut cfg_fds: Vec<(usize, i32)> = Vec::with_capacity(nodes.len());
        let mut failed = false;
        for node in &nodes {
            // The config is a memfd that is sealed after it is written, so the
            // stub can prove nothing rewrote it after its check; the unlinked
            // temp file is the fallback, and has no name to reopen either.
            let fd = sys::anon_sealable_file(b"cfg", 0);
            let fd = if fd >= 0 {
                fd
            } else {
                sys::anon_file(b"cfg", 0)
            };
            if fd < 0 {
                failed = true;
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
                failed = true;
                break;
            }
            cfg_fds.push((*node, fd));
        }
        if failed {
            for (_, fd) in &cfg_fds {
                sys::close(*fd);
            }
            continue;
        }
        for (node, fd) in &cfg_fds {
            fd_of[*node] = *fd;
        }
        if let Some((_, rfd)) = cfg_fds.iter().find(|(n, _)| *n == root) {
            fd_of[root] = *rfd;
        }
        let mut root_temps: Vec<std::path::PathBuf> = Vec::new();
        for (node, fd) in &cfg_fds {
            let exe = if bind {
                gen::template_exe(&corpus::CORPUS[rows[*node].tmpl])
            } else {
                Vec::new()
            };
            let need_exe_dir =
                !exe.is_empty() && !Path::new(std::ffi::OsStr::from_bytes(&exe)).exists();
            let need_disk_dir = args.disk_mb.unwrap_or(0) > 0;
            let temp = if need_exe_dir || need_disk_dir {
                match make_temp_dir(*node) {
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
            if !write_config_fd(*fd, &cfg) {
                failed = true;
                break;
            }
            // Best effort: a kernel that refuses the seals still leaves a
            // memfd, which has no name for anyone else to open.
            sys::fd_add_seals(*fd);
        }
        if failed {
            for (_, fd) in &cfg_fds {
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
        for (_, fd) in &cfg_fds {
            sys::close(*fd);
        }
    }

    sys::close(5);
    if arena_fd >= 0 {
        sys::close(arena_fd);
    }
    // The roots exist now, so a later prune can see that their staging
    // directories are still in use even after this injector exits.
    write_live_marker(&all_temps, &root_pids);

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
                let want_vsz = rows[*id as usize].vsz as u64;
                let want_rss = rows[*id as usize].rss as u64;
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
        pidfile_ok = write_pidfile(path, &pids, &all_temps);
        if !pidfile_ok {
            sys::err(b"psgen: cannot write pidfile\n");
        }
    }
    let ident: Vec<(i32, u64, Vec<u8>)> = pids
        .iter()
        .map(|pid| {
            (
                *pid,
                live::read_starttime(*pid).unwrap_or(0),
                live::read_comm(*pid).unwrap_or_default(),
            )
        })
        .collect();
    let live_ids: Vec<(i32, u64)> = ident.iter().map(|(pid, start, _)| (*pid, *start)).collect();
    write_live_marker(&all_temps, &live_ids);
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

/// Whether a command line looks like one the corpus would produce.
///
/// Used only to recognise a bind-tier row that a one-field pidfile line cannot
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
        if let Ok(canon) = std::fs::canonicalize(Path::new(std::ffi::OsStr::from_bytes(&want))) {
            if canon.as_os_str().as_bytes() == exe {
                return true;
            }
        }
    }
    false
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
/// A line counts as stopped only once the process is gone or a zombie. A
/// zombie is already dead and a signal to it succeeds and does nothing, so
/// counting signals would report a second stop as having stopped the same
/// processes again.
pub fn stop(path: &[u8], force: bool, plan: bool, quiet: bool) -> i32 {
    let text = match sys::read_file_nofollow(path, 1 << 20) {
        Some(t) => t,
        None => {
            sys::err(b"psgen: cannot read pidfile\n");
            return 1;
        }
    };
    let mut header_boot: Option<Vec<u8>> = None;
    let mut temp_dirs: Vec<Vec<u8>> = Vec::new();
    let mut lines: Vec<StopLine> = Vec::new();
    let mut malformed = 0usize;
    for raw in text.split(|b| *b == b'\n') {
        if raw.is_empty() {
            continue;
        }
        if raw[0] == b'#' {
            if let Some(boot) = crate::version::pidfile_boot_id(raw) {
                if let Some(prev) = &header_boot {
                    if *prev != boot {
                        sys::err(b"psgen: pidfile has conflicting boot ids\n");
                        return 1;
                    }
                } else {
                    header_boot = Some(boot);
                }
            }
            if let Some(rest) = raw.strip_prefix(b"# temp ") {
                temp_dirs.push(str::trim(rest).to_vec());
            }
            continue;
        }
        match parse_stop_line(raw) {
            Some(l) => lines.push(l),
            None => malformed += 1,
        }
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
        if cur_state == b'Z' {
            // Already dead. Its /proc entry outlives it while an init that does
            // not reap holds it, and a signal to a zombie is a no-op.
            skipped += 1;
            note(quiet, b"skip", pid, Some(b"already a zombie"));
            continue;
        }
        // Identity: three fields check starttime and comm, two check
        // starttime, one can only check the executable.
        let identical = if line.start.is_some() {
            cur_start == line.start
                && (line.comm.is_empty() || live::read_comm(pid).as_deref() == Some(&line.comm))
        } else {
            match exe_identity(pid, &me) {
                ExeKind::Psgen | ExeKind::Shadow => true,
                ExeKind::Other(exe) => {
                    let cmd = read_cmdline_text(pid);
                    if corpus_command(&cmd, &exe) {
                        // This is a bind-tier row under a template path. A
                        // one-field line cannot prove the identity without
                        // also accepting the host's real daemon, so this is an
                        // error, not a silent skip.
                        failed += 1;
                        let mut why = Buf::new();
                        why.push_str(
                            "a one-field line cannot identify a bind-tier row whose exe is ",
                        );
                        why.push_bytes(&exe);
                        why.push_str("; use the three-field form");
                        note(quiet, b"cannot identify", pid, Some(why.as_bytes()));
                        continue;
                    }
                    false
                }
            }
        };
        if !identical {
            skipped += 1;
            note(quiet, b"skip", pid, Some(b"identity does not match"));
            continue;
        }
        if plan {
            // A plan is a prediction of the real stop. Check that the real
            // signal would be permitted; otherwise `--plan` reports success
            // for a process the caller cannot stop.
            if !sys::kill(pid, 0) {
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
            planned += 1;
            continue;
        }
        let pfd = sys::pidfd_open(pid);
        // Re-verify identity after opening the pidfd (or right before kill if
        // pidfd_open is unavailable) so a PID recycled between the first
        // `/proc` read and the signal is not hit.
        let post = live::read_stat(pid);
        if post.as_ref().map(|s| s.starttime) != cur_start
            || post.as_ref().map(|s| s.state) == Some(b'Z')
        {
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
                let _ = std::fs::remove_dir_all(p);
            }
        }
    }
    let mut out = Buf::new();
    if plan {
        out.push_str("would stop ");
        out.push_u64(planned as u64);
        out.push_str(" processes");
    } else {
        out.push_str("stopped ");
        out.push_u64(stopped as u64);
        out.push_str(" processes");
    }
    if skipped > 0 || malformed > 0 {
        out.push_str(", skipped ");
        out.push_u64((skipped + malformed) as u64);
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
