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
            phys_estimate_kb = max2
                .saturating_add(sum2 / 512)
                .saturating_add(base_kb);
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

fn make_config(
    row: usize,
    rows: &[Proc],
    children: &[Vec<usize>],
    fd_of: &[i32],
    args: &Args,
    temp: &[u8],
    bind: bool,
    self_copy: &[u8],
) -> stub::Config {
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
        self_copy: self_copy.to_vec(),
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

fn random_hex16() -> [u8; 16] {
    let mut raw = [0u8; 8];
    if !sys::getrandom(&mut raw) {
        raw[..4].copy_from_slice(&sys::getpid().to_le_bytes());
        raw[4..].copy_from_slice(&sys::monotonic_ns().to_le_bytes());
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for (i, b) in raw.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

fn write_pidfile(path: &[u8], pids: &[i32], temps: &[std::path::PathBuf]) -> bool {
    if !probe::pidfile_target_ok(path) {
        return false;
    }
    let boot = util::boot_id();
    let mut buf = Buf::new();
    buf.push_str("# psgen 0.0.1 boot ");
    buf.push_bytes(&boot);
    buf.push(b'\n');
    for t in temps {
        buf.push_str("# temp ");
        buf.push_bytes(t.as_os_str().as_bytes());
        buf.push(b'\n');
    }
    let mut sorted = pids.to_vec();
    sorted.sort_unstable();
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
    let flags = sys::O_WRONLY | sys::O_CREAT | sys::O_EXCL | sys::O_NOFOLLOW;
    let mut tmp = Vec::new();
    let mut fd = -1;
    for _ in 0..100u64 {
        let suffix = random_hex16();
        let mut cand = path.to_vec();
        let mut b = Buf::new();
        b.push_str(".tmp.");
        b.push_u64(sys::getpid() as u64);
        b.push(b'.');
        b.push_bytes(&suffix);
        cand.extend_from_slice(b.as_bytes());
        let f = sys::open(&cand, flags, 0o600);
        if f >= 0 {
            fd = f;
            tmp = cand;
            break;
        }
        if sys::last_error().raw_os_error() != Some(libc::EEXIST) {
            return false;
        }
    }
    if fd < 0 {
        return false;
    }
    let ok = sys::write_fd(fd, buf.as_bytes());
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
    }
    renamed
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
        return Some(std::fs::canonicalize(&p).unwrap_or(p));
    }
    None
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
        let made = make_temp_dir_in(Path::new(std::ffi::OsStr::from_bytes(dir)), 9_000)
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

    let max_rss = rows.iter().map(|p| p.rss as u64).max().unwrap_or(0);
    let mut arena_fd: i32 = -1;
    if args.mem && max_rss > 0 {
        let fd = sys::anon_file(b"cache", max_rss * 1024);
        if fd < 0 {
            if let Some(d) = &shadow_dir {
                let _ = std::fs::remove_dir_all(d);
            }
            return Err(format!(
                "cannot create the RSS arena ({} KiB): {}",
                max_rss,
                sys::last_error()
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
    if !sys::pipe2(&mut pfd, sys::O_CLOEXEC) {
        if arena_fd >= 0 {
            sys::close(arena_fd);
        }
        if let Some(d) = &shadow_dir {
            let _ = std::fs::remove_dir_all(d);
        }
        return Err(format!("pipe2: {}", sys::last_error()));
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
            return Err(format!("fcntl(F_DUPFD,6): {}", sys::last_error()));
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
            return Err(format!("fcntl(F_DUPFD,6): {}", sys::last_error()));
        }
        sys::close(pfd[1]);
        pfd[1] = n;
    }
    if sys::dup2(pfd[1], 5) != 5 {
        sys::close(pfd[0]);
        sys::close(pfd[1]);
        if arena_fd >= 0 {
            sys::close(arena_fd);
        }
        if let Some(d) = &shadow_dir {
            let _ = std::fs::remove_dir_all(d);
        }
        return Err(format!("dup2(status,5): {}", sys::last_error()));
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

    for root in roots {
        let mut nodes = Vec::new();
        subtree(root, &children, &mut nodes);
        let mut fd_of = vec![0i32; rows.len()];
        let mut cfg_fds: Vec<(usize, i32)> = Vec::with_capacity(nodes.len());
        let mut failed = false;
        for node in &nodes {
            // write_config_fd ftruncates and pwrites, so the file starts empty.
            let fd = sys::anon_file(b"cfg", 0);
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
                bind,
                &self_copy,
            );
            if !write_config_fd(*fd, &cfg) {
                failed = true;
                break;
            }
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
            let (buf, argv) = stub::build_argv(&rows[root].cmd);
            let env = stub::envp();
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

fn exe_matches(pid: i32, me: &[u8]) -> bool {
    let mut path = b"/proc/".to_vec();
    let mut b = Buf::new();
    b.push_u64(pid as u64);
    path.extend_from_slice(b.as_bytes());
    path.extend_from_slice(b"/exe");
    let got = match sys::read_link(&path) {
        Some(g) => g,
        None => return false,
    };
    if got == me {
        return true;
    }
    let deleted = b" (deleted)";
    got.len() > deleted.len()
        && &got[got.len() - deleted.len()..] == deleted
        && &got[..got.len() - deleted.len()] == me
}

fn safe_temp_dir(t: &[u8]) -> bool {
    let p = Path::new(std::ffi::OsStr::from_bytes(t));
    if !p.is_absolute() {
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

pub fn stop(path: &[u8], force: bool) -> i32 {
    let text = match sys::read_file_nofollow(path, 1 << 20) {
        Some(t) => t,
        None => {
            sys::err(b"psgen: cannot read pidfile\n");
            return 1;
        }
    };
    let mut header_boot: Option<Vec<u8>> = None;
    let mut temp_dirs: Vec<Vec<u8>> = Vec::new();
    let mut lines: Vec<&[u8]> = text.split(|b| *b == b'\n').collect();
    for line in &lines {
        if let Some(rest) = line.strip_prefix(b"# psgen 0.0.1 boot ") {
            let boot = str::trim(rest).to_vec();
            if let Some(prev) = &header_boot {
                if *prev != boot {
                    sys::err(b"psgen: pidfile has conflicting boot ids\n");
                    return 1;
                }
            } else {
                header_boot = Some(boot);
            }
        }
        if let Some(rest) = line.strip_prefix(b"# temp ") {
            temp_dirs.push(str::trim(rest).to_vec());
        }
    }
    if let Some(hb) = &header_boot {
        let cur = util::boot_id();
        if !force && !hb.is_empty() && !cur.is_empty() && *hb != cur {
            sys::err(b"psgen: pidfile is from another boot; use --force to ignore\n");
            return 1;
        }
    }
    let me = current_exe_bytes();
    let identity_matches = |pid: i32, fields: &[&[u8]]| -> bool {
        if fields.len() >= 2 {
            let want_start = str::parse_u64(fields[1]).unwrap_or(0);
            let want_comm = if fields.len() == 3 { fields[2] } else { b"" };
            let cur_start = live::read_starttime(pid);
            let cur_comm = live::read_comm(pid);
            cur_start == Some(want_start)
                && (want_comm.is_empty() || cur_comm.as_deref() == Some(want_comm))
        } else {
            // A one-field line carries no starttime, so the exe check
            // is the only identity guard. --force covers the boot id only.
            exe_matches(pid, &me)
        }
    };
    let mut count = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    for line in &mut lines {
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let fields: Vec<&[u8]> = line.splitn(3, |b| *b == b'\t').collect();
        let pid = match str::parse_i64(fields[0]) {
            Some(p) if p > 0 && p <= i32::MAX as i64 => p as i32,
            _ => {
                skipped += 1;
                continue;
            }
        };
        // PID 1 is never a psgen stub, whatever the pidfile says.
        if pid == 1 {
            skipped += 1;
            continue;
        }
        if pid == sys::getpid() {
            continue;
        }
        let pfd = sys::pidfd_open(pid);
        if pfd < 0 {
            if sys::last_error().raw_os_error() == Some(libc::ESRCH) {
                skipped += 1;
                continue;
            }
            // No pidfd: check the identity and kill by PID. A leader's PID is
            // its PGID, so try the group first; a non-leader returns ESRCH.
            if !identity_matches(pid, &fields) {
                skipped += 1;
                continue;
            }
            if sys::kill(-pid, sys::SIGKILL) {
                count += 1;
            } else if sys::last_error().raw_os_error() == Some(libc::ESRCH) {
                if sys::kill(pid, sys::SIGKILL) {
                    count += 1;
                } else if sys::last_error().raw_os_error() == Some(libc::ESRCH) {
                    skipped += 1;
                } else {
                    failed += 1;
                }
            } else {
                failed += 1;
            }
            continue;
        }
        // The pidfd pins the process, so the identity read below and the
        // signal that follows cannot land on a reused PID.
        if !identity_matches(pid, &fields) {
            skipped += 1;
            sys::close(pfd);
            continue;
        }
        // A leader's PID is its PGID. Kill the group so children that never
        // wrote a status record are reached; a non-leader returns ESRCH and
        // the pidfd path below handles the process itself.
        if sys::kill(-pid, sys::SIGKILL) {
            count += 1;
            sys::close(pfd);
            continue;
        }
        if sys::pidfd_send_signal(pfd, sys::SIGKILL) {
            count += 1;
        } else if sys::last_error().raw_os_error() == Some(libc::ESRCH) {
            skipped += 1;
        } else {
            // The pidfd could not signal; re-check the identity and kill by
            // PID, which is no longer pinned now that the pidfd is closed.
            sys::close(pfd);
            if !identity_matches(pid, &fields) {
                skipped += 1;
            } else if sys::kill(pid, sys::SIGKILL) {
                count += 1;
            } else if sys::last_error().raw_os_error() == Some(libc::ESRCH) {
                skipped += 1;
            } else {
                failed += 1;
            }
            continue;
        }
        sys::close(pfd);
    }
    if failed == 0 {
        for t in &temp_dirs {
            if safe_temp_dir(t) {
                let _ = std::fs::remove_dir_all(Path::new(std::ffi::OsStr::from_bytes(t)));
            }
        }
    }
    let mut out = Buf::new();
    out.push_str("stopped ");
    out.push_u64(count as u64);
    out.push_str(" processes");
    if skipped > 0 {
        out.push_str(", skipped ");
        out.push_u64(skipped as u64);
    }
    if failed > 0 {
        out.push_str(", failed ");
        out.push_u64(failed as u64);
    }
    out.push(b'\n');
    sys::out(out.as_bytes());
    if failed > 0 { 1 } else { 0 }
}
