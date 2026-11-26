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

fn buf_to_string(b: Buf) -> String {
    String::from_utf8(b.v).unwrap_or_default()
}

#[inline(never)]
fn warn_parts(w: &mut Vec<String>, parts: &[&[u8]]) {
    let mut b = Buf::new();
    for p in parts {
        sys::buf_push_b(&mut b, p);
    }
    w.push(String::from_utf8_lossy(b.as_bytes()).into_owned());
}

#[inline(never)]
fn push_cnt(b: &mut Buf, pre: &str, n: u64, suf: &str) {
    sys::buf_push_s(b, pre);
    sys::buf_push_u(b, n);
    sys::buf_push_s(b, suf);
}

#[inline(never)]
fn remove_opt_dir(d: &Option<std::path::PathBuf>) {
    if let Some(p) = d {
        let _ = std::fs::remove_dir_all(p);
    }
}

#[inline(never)]
fn err_with_errno(prefix: &str, errno: i32) -> String {
    let mut b = Buf::new();
    sys::buf_push_s(&mut b, prefix);
    sys::push_errno(&mut b, errno);
    buf_to_string(b)
}

#[inline(never)]
fn close_fds(fds: &[i32]) {
    for &fd in fds {
        if fd >= 0 {
            sys::close(fd);
        }
    }
}

#[inline(never)]
fn remove_dirs(dirs: &[std::path::PathBuf]) {
    for d in dirs {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[inline(never)]
fn sort_dedup_i32(v: &mut Vec<i32>) {
    crate::json::shell_sort_by(v, |a, b| a > b);
    v.dedup();
}

#[inline(never)]
fn sort_dedup_pid_start(v: &mut Vec<(i32, u64)>) {
    crate::json::shell_sort_by(v, |a, b| a > b);
    v.dedup();
}

struct CloseFd(i32);
impl Drop for CloseFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            sys::close(self.0);
        }
    }
}

#[inline(never)]
fn make_memfd_name(nonce: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + nonce.len());
    v.extend_from_slice(b"pg:");
    v.extend_from_slice(nonce);
    v
}

#[inline(never)]
fn maybe_node_temp(
    need: bool,
    idx: usize,
    nonce: &[u8],
    temps: &mut Vec<std::path::PathBuf>,
) -> Vec<u8> {
    if !need {
        return Vec::new();
    }
    match make_temp_dir(idx, nonce) {
        Some(p) => {
            temps.push(p.clone());
            p.as_os_str().as_bytes().to_vec()
        }
        None => Vec::new(),
    }
}

#[inline(never)]
pub(crate) fn cleanup_unbusy_temps(temps: &[std::path::PathBuf]) {
    for t in temps {
        if !staging_busy(t) && safe_temp_dir(t.as_os_str().as_bytes()) {
            let _ = sys::remove_staging_dir(t);
        }
    }
}

#[inline(never)]
fn open_status_pipe(install_fd5: bool) -> Result<(i32, i32), String> {
    let mut pfd = [0i32; 2];
    if let Err(e) = sys::pipe2_checked(&mut pfd, sys::O_CLOEXEC) {
        return Err(err_with_errno("pipe2: ", e));
    }
    for slot in &mut pfd {
        let need_move = if install_fd5 { *slot == 5 } else { *slot < 6 };
        if need_move {
            let n = if install_fd5 {
                sys::fcntl_dup(*slot, 6)
            } else {
                unsafe { libc::fcntl(*slot, libc::F_DUPFD_CLOEXEC, 6) }
            };
            if n < 0 {
                let e = sys::errno();
                close_fds(&pfd);
                return Err(err_with_errno("fcntl(F_DUPFD,6): ", e));
            }
            sys::close(*slot);
            *slot = n;
        }
    }
    if install_fd5 {
        if sys::dup2(pfd[1], 5) != 5 {
            let e = sys::errno();
            close_fds(&pfd);
            return Err(err_with_errno("dup2(status,5): ", e));
        }
        if pfd[1] != 5 {
            sys::close(pfd[1]);
        }
        Ok((pfd[0], 5))
    } else {
        Ok((pfd[0], pfd[1]))
    }
}

#[inline(never)]
fn alloc_sealed_cfg_fds(count: usize, name: &[u8], named: bool) -> Result<Vec<i32>, String> {
    let mut fds = Vec::with_capacity(count);
    for _ in 0..count {
        let raw = if named {
            sys::anon_sealable_file_named(name, 0)
        } else {
            sys::anon_sealable_file(name, 0)
        };
        if raw < 0 {
            let e = sys::errno();
            close_fds(&fds);
            let mut b = Buf::new();
            sys::buf_push_s(&mut b, "cannot create the config memfd (");
            sys::push_errno(&mut b, e);
            sys::buf_push_s(&mut b, "); a stub only acts on a sealed memfd");
            return Err(buf_to_string(b));
        }
        let fd = if raw < 6 {
            let n = sys::fcntl_dup(raw, 6);
            sys::close(raw);
            n
        } else {
            raw
        };
        if fd < 0 {
            let e = sys::errno();
            close_fds(&fds);
            let mut b = Buf::new();
            sys::buf_push_s(
                &mut b,
                "cannot move the config memfd to a holding descriptor (",
            );
            sys::push_errno(&mut b, e);
            b.push(b')');
            return Err(buf_to_string(b));
        }
        fds.push(fd);
    }
    Ok(fds)
}

#[inline(never)]
fn collect_node_fds(
    idx: usize,
    children: &[Vec<usize>],
    fd_of: &[i32],
) -> (Vec<i32>, Vec<i32>, i32) {
    let mut keep = Vec::new();
    descendants(idx, children, &mut keep);
    let child_fds: Vec<i32> = children[idx].iter().map(|c| fd_of[*c]).collect();
    let keep_fds: Vec<i32> = keep.iter().map(|d| fd_of[*d]).collect();
    let mut max_fd = 5;
    if idx < fd_of.len() {
        max_fd = max_fd.max(fd_of[idx]);
    }
    for &fd in child_fds.iter().chain(keep_fds.iter()) {
        max_fd = max_fd.max(fd);
    }
    (child_fds, keep_fds, max_fd)
}

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
    /// otherwise `<TMPDIR>/.psgen-stubs` when a bind is denied.
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
    /// Run nonce carried in every stub's environment and in the pidfile header.
    pub nonce: Vec<u8>,
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

fn rss_stats(rows: &[Proc]) -> (u64, u64) {
    let mut sum = 0u64;
    let mut max = 0u64;
    for p in rows {
        sum += p.rss;
        max = max.max(p.rss);
    }
    (sum, max)
}

fn assign_me(p: &mut Proc, me: &users::User) {
    p.user = me.name.clone();
    p.uid = me.uid;
    p.gid = me.gid;
}

fn scale_rss(rows: &mut [Proc], budget_kb: u64, base_kb: u64, page_kb: u64) -> f64 {
    let (sum, max) = rss_stats(rows);
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
        let v = ((p.rss as f64 * factor) as u64).max(floor);
        p.rss = crate::table::round_up(v, page_kb);
    }
    factor
}

#[inline(never)]
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
        warn_parts(
            &mut warnings,
            &[
                b"user switching needs root; running as ",
                &me.name,
                b" (use sudo, --elevate, or --no-root)",
            ],
        );
    }
    const FLAG_WARNS: &str = "\
--no-root disables user switching and the bind tier; --shadow-dir still selects a shadow copy|\
--create-users has no effect with --no-root|\
--create-users has no effect with --no-user|\
--create-users needs root; no accounts were created|\
--mem-cap has no effect with --no-mem|\
--phys-cap has no effect with --no-mem|\
--verify has no effect with --no-mem";
    let flag_conds = [
        args.no_root && args.user,
        args.create_users && args.no_root,
        args.create_users && !args.no_root && !args.user,
        args.create_users && !args.no_root && args.user && !root,
        !args.mem && args.mem_cap_mb > 0,
        !args.mem && args.phys_cap.is_some(),
        args.verify && !args.mem,
    ];
    for (cond, msg) in flag_conds.into_iter().zip(FLAG_WARNS.split('|')) {
        if cond {
            warnings.push(String::from(msg));
        }
    }

    for p in rows.iter_mut() {
        if !switch_users {
            assign_me(p, &me);
            continue;
        }
        if args.dry_run && args.create_users {
            if users::lookup_name(&p.user).is_none() {
                p.uid = u32::MAX;
                p.gid = u32::MAX;
                if !warned_names.contains(&p.user) {
                    warned_names.push(p.user.clone());
                    warn_parts(
                        &mut warnings,
                        &[b"would create ", &p.user, b" (--dry-run creates nothing)"],
                    );
                }
            }
            continue;
        }
        if !root {
            assign_me(p, &me);
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
                    warn_parts(
                        &mut warnings,
                        &[
                            b"no such user ",
                            &p.user,
                            b"; running as ",
                            &me.name,
                            if !args.create_users {
                                b" (pass --create-users to create it)"
                            } else {
                                b""
                            },
                            if err.is_some() { b": " } else { b"" },
                            err.as_deref().map(str::as_bytes).unwrap_or(b""),
                        ],
                    );
                }
                assign_me(p, &me);
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
            warnings.push(String::from("--mem-target has no effect with --no-mem"));
        } else {
            let target = target as u64;
            for p in rows.iter_mut() {
                let cap = p.vsz.saturating_sub(gen::BASE_RESERVE_KB as u64);
                let v = target.min(cap.max(page));
                p.rss = crate::table::round_up(v, page);
            }
        }
    }

    if args.mem_cap_mb > 0 && args.mem {
        let cap = args.mem_cap_mb.saturating_mul(1024);
        let (sum, _) = rss_stats(rows);
        if sum > cap && !rows.is_empty() {
            let floor = 4096u64;
            let base = floor.saturating_mul(rows.len() as u64);
            if base >= cap {
                let mut b = Buf::new();
                push_cnt(
                    &mut b,
                    "--mem-cap ",
                    args.mem_cap_mb,
                    " MiB is at or below the ",
                );
                push_cnt(&mut b, "", base / 1024, " MiB floor of ");
                push_cnt(
                    &mut b,
                    "",
                    rows.len() as u64,
                    if rows.len() == 1 {
                        " stub; the reported RSS will be at least "
                    } else {
                        " stubs; the reported RSS will be at least "
                    },
                );
                push_cnt(&mut b, "", base / 1024, " MiB");
                warnings.push(buf_to_string(b));
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
            let cap_kb = (limit / 1024).saturating_sub(16 * 1024);
            let (_, max) = rss_stats(rows);
            if cap_kb < page {
                warnings.push(String::from(
                    "RLIMIT_FSIZE is too small for an RSS arena; memory padding disabled",
                ));
                for p in rows.iter_mut() {
                    p.rss = 0;
                }
            } else if max > cap_kb {
                let mut b = Buf::new();
                push_cnt(
                    &mut b,
                    "RLIMIT_FSIZE is ",
                    limit / 1024 / 1024,
                    " MiB; RSS targets capped at ",
                );
                push_cnt(&mut b, "", cap_kb / 1024, " MiB");
                warnings.push(buf_to_string(b));
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
        let (sum, max) = rss_stats(rows);
        let est = max.saturating_add(sum / 512).saturating_add(base_kb);
        phys_estimate_kb = est;
        if budget > 0 && est > budget && max > 0 {
            phys_scale = scale_rss(rows, budget, base_kb, page);
            let (sum2, max2) = rss_stats(rows);
            phys_estimate_kb = max2.saturating_add(sum2 / 512).saturating_add(base_kb);
        }
        if budget > 0 && phys_estimate_kb > budget {
            let mut b = Buf::new();
            push_cnt(
                &mut b,
                "the estimated physical cost is about ",
                phys_estimate_kb,
                " KiB, above the ",
            );
            push_cnt(&mut b, "", budget, " KiB budget");
            warnings.push(buf_to_string(b));
        }
    }

    for p in rows.iter_mut() {
        if !args.tty {
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
        } else if p.cpu > 0 {
            p.flags |= corpus::F_BUSY;
        }
        if let Some(pct) = args.cpu_pct {
            p.cpu = pct.saturating_mul(10);
            if pct == 0 {
                p.flags &= !corpus::F_BUSY;
            } else {
                p.flags |= corpus::F_BUSY;
            }
        }
    }

    if args.disk_mb.unwrap_or(0) > 0 && rows.is_empty() {
        warnings.push(String::from("--disk has no rows to write for"));
    }

    let caps = probe::caps();
    let mut shadow_root = args.shadow_dir.clone();
    if shadow_root.is_none() && !args.no_root && !args.no_exe && !caps.can_spoof_exe() {
        let dir = std::env::temp_dir().join(".psgen-stubs");
        let mut v = dir.as_os_str().as_bytes().to_vec();
        if !v.ends_with(b"/") {
            v.push(b'/');
        }
        shadow_root = Some(v);
    }
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
        warn_parts(
            &mut warnings,
            &[
                b"cannot bind the template path here (",
                if !caps.mount_ns {
                    b"mount namespaces denied"
                } else {
                    b"the bind was denied"
                },
                b"); /proc/PID/exe will point at psgen",
            ],
        );
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
    let (child_fds, keep_fds, max_fd) = collect_node_fds(row, children, fd_of);
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
        ..stub::Config::default()
    }
}

#[inline(never)]
fn write_config_fd(fd: i32, cfg: &stub::Config) -> bool {
    let data = stub::encode_config(cfg);
    sys::ftruncate(fd, data.len() as u64)
        && sys::pwrite_fd(fd, &data, 0) == data.len() as isize
        && sys::fd_add_seals(fd)
}

#[inline(never)]
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
    let mut out = Vec::with_capacity(buf.len() / REC);
    for chunk in buf.chunks_exact(REC) {
        let Ok(a) = <[u8; REC]>::try_from(chunk) else {
            continue;
        };
        let pid = i32::from_le_bytes([a[0], a[1], a[2], a[3]]);
        let status = i32::from_le_bytes([a[4], a[5], a[6], a[7]]);
        let id = u32::from_le_bytes([a[8], a[9], a[10], a[11]]);
        let dev = u32::from_le_bytes([a[12], a[13], a[14], a[15]]);
        out.push((pid, status, id, dev));
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
#[inline(never)]
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
#[inline(never)]
fn pidfile_body(pids: &[i32], temps: &[std::path::PathBuf], nonce: &[u8]) -> Option<Buf> {
    let boot = util::boot_id();
    if boot.is_empty() {
        return None;
    }
    let mut buf = Buf::new();
    sys::buf_push_b(&mut buf, crate::version::PIDFILE_PREFIX);
    sys::buf_push_s(&mut buf, crate::version::VERSION);
    sys::buf_push_s(&mut buf, " boot ");
    sys::buf_push_b(&mut buf, &boot);
    if !nonce.is_empty() {
        sys::buf_push_b(&mut buf, crate::version::PIDFILE_NONCE);
        sys::buf_push_b(&mut buf, nonce);
    }
    buf.push(b'\n');
    for t in temps {
        sys::buf_push_s(&mut buf, "# temp ");
        sys::buf_push_b(&mut buf, t.as_os_str().as_bytes());
        buf.push(b'\n');
    }
    let mut sorted = pids.to_vec();
    sort_dedup_i32(&mut sorted);
    for pid in &sorted {
        let st = live::read_starttime(*pid).unwrap_or(0);
        let comm = live::read_comm_exact(*pid).unwrap_or_default();
        sys::buf_push_u(&mut buf, *pid as u64);
        buf.push(b'\t');
        sys::buf_push_u(&mut buf, st);
        buf.push(b'\t');
        sys::buf_push_b(&mut buf, &comm);
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
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let v = sys::monotonic_ns() ^ ((sys::getpid() as u64) << 32);
    let mut out = Vec::with_capacity(16);
    for shift in (0..64).step_by(4).rev() {
        out.push(HEX[((v >> shift) & 0x0f) as usize]);
    }
    out
}

/// The exact size of the pending pidfile, for the preflight probe.
pub fn pending_pidfile_len() -> usize {
    pidfile_body(&[], &[], &pending_nonce())
        .map(|b| b.v.len())
        .unwrap_or(0)
}

/// Conservative upper bound on the final pidfile body size in bytes, so the
/// pre-spawn preflight proves `RLIMIT_FSIZE` and filesystem space can hold the
/// real body rather than only the pending header.
pub fn estimated_pidfile_bytes(row_count: usize, temp_count: usize, tmpdir_len: usize) -> usize {
    pending_pidfile_len()
        .saturating_add(temp_count.saturating_mul(tmpdir_len.saturating_add(48)))
        .saturating_add(row_count.saturating_mul(48))
}

pub fn write_pending_pidfile(path: &[u8]) -> bool {
    write_pidfile(path, &[], &[], &pending_nonce()).0
}

/// Write a standard 3-field pidfile (`pid\tstarttime\tcomm`) for externally
/// spawned decoy PIDs so `psgen stop --pidfile` can clean them up cleanly.
pub fn write_external_pidfile(path: &[u8], pids: &[i32]) -> bool {
    let nonce = random_hex(8);
    write_pidfile(path, pids, &[], &nonce).0
}

/// Write the pidfile, falling back to shorter temporary names when the target
/// basename is close to `NAME_MAX`. Returns whether it landed, and the errno
/// that stopped it so the caller can name the real cause.
#[inline(never)]
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
        .custom_flags(libc::O_NOFOLLOW)
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

/// Whether another process currently holds `<path>.lock`, without creating the
/// lock file or modifying the filesystem. Used by `--dry-run` previews.
pub fn pidfile_lock_held(path: &[u8]) -> bool {
    let mut lock_path = path.to_vec();
    lock_path.extend_from_slice(b".lock");
    let fd = sys::open(
        &lock_path,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    );
    if fd < 0 {
        return false;
    }
    let held = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0
        && sys::last_error().kind() == std::io::ErrorKind::WouldBlock;
    sys::close(fd);
    held
}

/// Write the spawned rows to a recovery sidecar when the main pidfile write
/// failed after spawning, returning the sidecar path on success.
///
/// Tries `<path>.spawned` beside the pidfile first. If the parent directory
/// became unwritable (for example `chmod 555` mid-run), falls back to
/// `<TMPDIR>/psgen-spawned-<pid>-<nonce>.pid` so the caller still gets a valid
/// pidfile carrying the real nonce and `# temp` paths that `stop` can use.
#[inline(never)]
fn write_sidecar_file(path: &Path, data: &[u8], create_new: bool) -> bool {
    let pb = path.as_os_str().as_bytes();
    let mut flags = sys::O_WRONLY | sys::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    flags |= if create_new {
        sys::O_EXCL
    } else {
        libc::O_TRUNC
    };
    let fd = sys::open(pb, flags, 0o600);
    if fd < 0 {
        return false;
    }
    let ok = sys::write_fd(fd, data) && sys::fsync_fd(fd);
    sys::close(fd);
    if !ok {
        let _ = std::fs::remove_file(path);
    }
    ok
}

#[inline(never)]
pub fn write_pid_sidecar(
    path: &[u8],
    pids: &[i32],
    temps: &[std::path::PathBuf],
    nonce: &[u8],
) -> Option<Vec<u8>> {
    let buf = pidfile_body(pids, temps, nonce)?;
    let mut side = path.to_vec();
    side.extend_from_slice(b".spawned");
    if write_sidecar_file(
        Path::new(std::ffi::OsStr::from_bytes(&side)),
        buf.as_bytes(),
        false,
    ) {
        return Some(side);
    }
    let tag = if nonce.is_empty() {
        random_hex(8)
    } else {
        nonce.to_vec()
    };
    let mut fb_name = Buf::new();
    push_cnt(&mut fb_name, "psgen-spawned-", sys::getpid() as u64, "-");
    sys::buf_push_b(&mut fb_name, &tag);
    sys::buf_push_s(&mut fb_name, ".pid");
    let fallback = std::env::temp_dir().join(std::ffi::OsStr::from_bytes(fb_name.as_bytes()));
    if write_sidecar_file(&fallback, buf.as_bytes(), true) {
        Some(fallback.as_os_str().as_bytes().to_vec())
    } else {
        None
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
#[inline(never)]
pub fn marker_line(pid: i32, start: u64, boot: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut line = Buf::new();
    sys::buf_push_u(&mut line, pid as u64);
    line.push(b' ');
    sys::buf_push_u(&mut line, start);
    line.push(b' ');
    sys::buf_push_u(&mut line, pid_ns_inode());
    line.push(b' ');
    sys::buf_push_b(&mut line, if boot.is_empty() { b"-" } else { boot });
    line.push(b' ');
    sys::buf_push_b(&mut line, if nonce.is_empty() { b"-" } else { nonce });
    line.push(b'\n');
    line.v
}

/// Append marker lines to `dir`'s file, never truncating it.
///
/// The stubs append their own identity before they exec, and the injector
/// learns only about the rows that reported a status record. A truncating
/// rewrite would erase a stub that is alive but has not reported yet, and the
/// prune pass would then delete the directory it is still using. Duplicate
/// lines are harmless: every reader asks `any(live)`.
#[inline(never)]
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
#[inline(never)]
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
#[inline(never)]
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

#[inline(never)]
fn make_temp_dir_in(base: &Path, idx: usize, nonce: &[u8]) -> Option<std::path::PathBuf> {
    let _ = std::fs::create_dir_all(base);
    let mut name = Buf::new();
    for i in 0..100 {
        name.v.clear();
        sys::buf_push_s(&mut name, ".psgen-");
        sys::buf_push_u(&mut name, sys::getpid() as u64);
        name.push(b'-');
        sys::buf_push_u(&mut name, idx as u64);
        name.push(b'-');
        sys::buf_push_u(&mut name, i);
        let p = base.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        let Some(cp) = sys::cstr(p.as_os_str().as_bytes()) else {
            continue;
        };
        if unsafe { libc::mkdir(cp.as_ptr(), 0o700) } != 0 {
            continue;
        }
        if unsafe { libc::chmod(cp.as_ptr(), 0o700) } != 0 {
            let _ = std::fs::remove_dir(&p);
            continue;
        }
        let start = live::read_starttime(sys::getpid()).unwrap_or(0);
        let owner = marker_line(sys::getpid(), start, &util::boot_id(), nonce);
        let _ = append_marker(&p, OWNER_FILE, &owner);
        return Some(std::fs::canonicalize(&p).unwrap_or(p));
    }
    None
}

/// The injector PID encoded in a staging directory name, if the name matches
/// `.psgen-<pid>-<idx>-<n>`.
#[inline(never)]
fn staging_pid(name: &[u8]) -> Option<i32> {
    let rest = name.strip_prefix(b".psgen-")?;
    let mut it = rest.split(|b| *b == b'-');
    let (p0, p1, p2) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some()
        || [p0, p1, p2]
            .iter()
            .any(|p| p.is_empty() || !p.iter().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    str::parse_u64(p0).and_then(|v| i32::try_from(v).ok())
}

#[inline(never)]
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

#[inline(never)]
fn markers_any_live(entries: &[Marker], my_ns: u64, my_boot: &[u8]) -> bool {
    entries.iter().any(|m| {
        if !ns_matches(m, my_ns) {
            return true;
        }
        if boot_differs(m, my_boot) {
            return false;
        }
        marker_alive(m)
    })
}

fn marker_busy(dir: &std::path::Path) -> bool {
    let my_ns = pid_ns_inode();
    let my_boot = util::boot_id();
    read_live_marker(dir).is_some_and(|entries| markers_any_live(&entries, my_ns, &my_boot))
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
#[inline(never)]
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
    sys::buf_push_s(&mut out, "psgen: leaving ");
    sys::buf_push_b(&mut out, path.as_os_str().as_bytes());
    sys::buf_push_s(&mut out, " alone: it is owned by uid ");
    sys::buf_push_u(&mut out, uid as u64);
    sys::buf_push_s(&mut out, ", not ");
    sys::buf_push_u(&mut out, sys::geteuid() as u64);
    sys::buf_push_s(&mut out, "; the run that made it must stop it\n");
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
                if markers_any_live(&entries, my_ns, &my_boot) {
                    continue;
                }
            }
            None => {
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

#[inline(never)]
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

#[inline(never)]
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
        .map_err(|e| {
            let mut b = Buf::new();
            sys::push_io_err(&mut b, &e);
            buf_to_string(b)
        })?
        .as_os_str()
        .as_bytes()
        .to_vec();
    let mut tier = prep.tier;
    let nonce = random_hex(8);

    let mut shadow_dir: Option<std::path::PathBuf> = None;
    let mut self_copy: Vec<u8> = Vec::new();
    if tier == ExeTier::Shadow {
        let dir = prep
            .shadow_root
            .as_ref()
            .expect("an exe tier of shadow needs a shadow root");
        let made = make_temp_dir_in(Path::new(std::ffi::OsStr::from_bytes(dir)), 9_000, &nonce)
            .ok_or_else(|| {
                let mut b = Buf::new();
                sys::buf_push_s(&mut b, "cannot create a directory in ");
                sys::buf_push_b(&mut b, dir);
                sys::buf_push_s(&mut b, " for --shadow-dir");
                buf_to_string(b)
            });
        let copied = made.and_then(|d| {
            let dst = d.join("psgen-stub");
            match copy_shadow_exe_res(&self_exe, dst.as_os_str().as_bytes()) {
                Ok(()) => Ok((d, dst)),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&d);
                    let mut b = Buf::new();
                    sys::buf_push_s(&mut b, "cannot copy the stub into ");
                    sys::buf_push_b(&mut b, dir);
                    sys::buf_push_s(&mut b, ": ");
                    sys::push_io_err(&mut b, &e);
                    Err(buf_to_string(b))
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
                sys::err_parts(&[e.as_bytes(), b"; /proc/PID/exe will point at psgen"]);
                tier = ExeTier::ProcSelf;
            }
        }
    }
    let bind = tier == ExeTier::Bind;

    let max_rss = rows.iter().map(|p| p.rss).max().unwrap_or(0);
    let arena_fd = CloseFd(if args.mem && max_rss > 0 {
        let fd = sys::anon_file(b"cache", max_rss * 1024);
        if fd < 0 {
            remove_opt_dir(&shadow_dir);
            let e = sys::errno();
            let mut b = Buf::new();
            push_cnt(&mut b, "cannot create the RSS arena (", max_rss, " KiB): ");
            sys::push_errno(&mut b, e);
            return Err(buf_to_string(b));
        }
        let target = sys::dup2(fd, 4);
        if target != 4 {
            let e = sys::errno();
            sys::close(fd);
            remove_opt_dir(&shadow_dir);
            return Err(err_with_errno("dup2(arena,4): ", e));
        }
        if fd != 4 {
            sys::close(fd);
        }
        4
    } else {
        -1
    });

    let (status_read, _) = match open_status_pipe(true) {
        Ok(pair) => pair,
        Err(e) => {
            remove_opt_dir(&shadow_dir);
            return Err(e);
        }
    };

    sys::set_child_subreaper();
    sys::setsid();
    let memfd_name = make_memfd_name(&nonce);
    let mut root_pids: Vec<(i32, u64)> = Vec::new();
    let mut all_temps: Vec<std::path::PathBuf> = Vec::new();
    for root in roots {
        let mut nodes = Vec::new();
        subtree(root, &children, &mut nodes);
        let cfg_fds = match alloc_sealed_cfg_fds(nodes.len(), &memfd_name, true) {
            Ok(fds) => fds,
            Err(e) => {
                remove_dirs(&all_temps);
                return Err(e);
            }
        };
        let mut fd_of = vec![0i32; rows.len()];
        for (&node, &fd) in nodes.iter().zip(cfg_fds.iter()) {
            if let Some(slot) = fd_of.get_mut(node) {
                *slot = fd;
            }
        }
        let mut failed = false;
        let mut root_temps: Vec<std::path::PathBuf> = Vec::new();
        for &node in &nodes {
            let Some(&fd) = fd_of.get(node) else {
                continue;
            };
            let exe = if bind {
                rows.get(node)
                    .and_then(|r| corpus::CORPUS.get(r.tmpl))
                    .map(gen::template_exe)
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let need_dir = (!exe.is_empty()
                && !Path::new(std::ffi::OsStr::from_bytes(&exe)).exists())
                || args.disk_mb.unwrap_or(0) > 0;
            let temp = maybe_node_temp(need_dir, node, &nonce, &mut root_temps);
            let cfg = make_config(
                node,
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
            if !write_config_fd(fd, &cfg) {
                failed = true;
                break;
            }
        }
        if failed {
            close_fds(&cfg_fds);
            remove_dirs(&root_temps);
            continue;
        }
        all_temps.extend(root_temps);
        let Some(&root_cfg_fd) = fd_of.get(root) else {
            close_fds(&cfg_fds);
            continue;
        };
        let root_cmd = rows.get(root).map(|r| r.cmd.as_slice()).unwrap_or(b"");
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
            let nonce_line = stub::nonce_env_line(&nonce);
            let env = stub::envp_with(&nonce_line);
            let (buf, argv) = stub::build_argv(root_cmd);
            if sys::execve(b"/proc/self/exe", &argv, &env) < 0 {
                sys::execve(&self_exe, &argv, &env);
            }
            let _ = &buf;
            sys::exit(127);
        }
        if pid > 0 {
            root_pids.push((pid, live::read_starttime(pid).unwrap_or(0)));
        }
        close_fds(&cfg_fds);
    }

    sys::close(5);
    drop(arena_fd);
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
    let tty_wanted = rows.iter().filter(|p| p.flags & corpus::F_TTY != 0).count();
    let mut tty_real = 0usize;
    let mut tty_degraded = 0usize;
    let mut dev_exe = 0usize;
    let mut dev_user = 0usize;
    let mut dev_disk = 0usize;
    let mut dev_mem = 0usize;
    let tol = 128;
    for &(pid, status, id, dev) in &records {
        if status == 0 {
            pids.push(pid);
        } else if status == 2 {
            pids.push(pid);
            warned += 1;
        } else {
            failed += 1;
            failed_ids.push((id, status));
        }
        let row_opt = rows.get(id as usize);
        if dev & stub::DEV_TTY != 0 {
            tty_degraded += 1;
        } else if row_opt.is_some_and(|r| r.flags & corpus::F_TTY != 0) {
            tty_real += 1;
        }
        dev_exe += usize::from(dev & stub::DEV_EXE != 0);
        dev_user += usize::from(dev & stub::DEV_USER != 0);
        dev_disk += usize::from(dev & stub::DEV_DISK != 0);
        dev_mem += usize::from(dev & (stub::DEV_RSS | stub::DEV_VSZ) != 0);
        if args.verify && args.mem && status >= 0 {
            if let (Some(row), Some((vsz, rss))) = (row_opt, live::read_sizes(pid)) {
                if vsz.abs_diff(row.vsz) > tol || rss.abs_diff(row.rss) > tol {
                    mismatches.push((pid, id, row.vsz, vsz, row.rss, rss));
                }
            }
        }
    }
    let missing = total_nodes.saturating_sub(records.len());
    if pids.is_empty() && !root_pids.is_empty() {
        pids.extend(root_pids.iter().map(|(p, _)| *p));
    }
    if let Some(d) = &shadow_dir {
        all_temps.push(d.clone());
    }
    if pids.is_empty() {
        remove_dirs(&all_temps);
        all_temps.clear();
    }
    let mut pidfile_ok = true;
    if let Some(path) = &args.pidfile {
        let (ok, errno) = write_pidfile(path, &pids, &all_temps, &nonce);
        pidfile_ok = ok;
        if !ok {
            let mut out = Buf::new();
            sys::buf_push_s(&mut out, "psgen: cannot write pidfile: ");
            sys::push_errno(&mut out, errno);
            out.push(b'\n');
            sys::err(out.as_bytes());
        }
    }
    let mut ident: Vec<(i32, u64, Vec<u8>)> = pids
        .iter()
        .map(|pid| {
            (
                *pid,
                live::read_starttime(*pid).unwrap_or(0),
                live::read_comm_exact(*pid).unwrap_or_default(),
            )
        })
        .collect();
    let my_ns = pid_ns_inode();
    let my_boot = util::boot_id();
    for dir in &all_temps {
        for m in read_live_marker(dir).unwrap_or_default() {
            if m.pid <= 1 || ident.iter().any(|(p, _, _)| *p == m.pid) {
                continue;
            }
            if ns_matches(&m, my_ns) && !boot_differs(&m, &my_boot) {
                ident.push((m.pid, m.start, Vec::new()));
            }
        }
    }
    let live_ids: Vec<(i32, u64)> = ident.iter().map(|(pid, start, _)| (*pid, *start)).collect();
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
        nonce,
        ident,
    })
}

fn current_exe_bytes() -> Vec<u8> {
    std::env::current_exe()
        .map(|p| p.as_os_str().as_bytes().to_vec())
        .unwrap_or_default()
}

#[inline(never)]
pub fn safe_temp_dir(t: &[u8]) -> bool {
    let p = Path::new(std::ffi::OsStr::from_bytes(t));
    if !p.is_absolute() {
        return false;
    }
    // A FUSE daemon or user-controlled overlay can report any owner and file
    // type. A root run must not write into or execute from a directory whose
    // metadata it cannot trust.
    if sys::geteuid() == 0 && sys::is_untrusted_fs(sys::path_fs_type(t)) {
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
    p.file_name()
        .is_some_and(|n| staging_pid(n.as_bytes()).is_some())
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
    let path = sys::proc_path(pid, "/exe");
    let got = match sys::read_link(path.as_bytes()) {
        Some(g) => g,
        None => return ExeKind::Other(Vec::new()),
    };
    // A deleted executable is still the same file, which is what the link
    // would have said before the unlink.
    let real = got.strip_suffix(b" (deleted)").unwrap_or(&got).to_vec();
    if real == me {
        return ExeKind::Psgen;
    }
    // A shadow copy lives inside a staging directory owned by the caller.
    if let Some(parent) = Path::new(std::ffi::OsStr::from_bytes(&real)).parent() {
        if safe_temp_dir(parent.as_os_str().as_bytes()) {
            return ExeKind::Shadow;
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
#[inline(never)]
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
    let path = sys::proc_path(pid, "/cmdline");
    let mut buf = [0u8; 8192];
    let n = match sys::read_file(path.as_bytes(), &mut buf) {
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
    let mut it = line.splitn(3, |&b| b == b'\t');
    let pid = str::parse_i64(it.next()?)?;
    if pid <= 0 || pid > i32::MAX as i64 {
        return None;
    }
    let start = match it.next() {
        Some(f) => Some(str::parse_u64(f)?),
        None => None,
    };
    let comm = it.next().map(|f| f.to_vec()).unwrap_or_default();
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
            if i > 0 && text.get(i - 1) == Some(&b'\r') {
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
    let path = sys::proc_path(pid, "/environ");
    let mut buf = [0u8; 65536];
    let n = match sys::read_file(path.as_bytes(), &mut buf) {
        Some(n) => n,
        None => return Vec::new(),
    };
    let key = stub::NONCE_ENV.as_bytes();
    for var in buf.get(..n).unwrap_or(&[]).split(|b| *b == 0) {
        if let Some(val) = var.strip_prefix(key).and_then(|r| r.strip_prefix(b"=")) {
            return val.to_vec();
        }
    }
    Vec::new()
}

/// Whether `raw` is a `# psgen <version>...` pidfile header line rather than
/// an ordinary comment such as `# psgen-wrapper` or `# psgen: note`.
///
/// A real header starts with `# psgen ` (including the trailing space) and
/// either begins its version token with an ASCII digit (covering legacy
/// headers like `# psgen 0.0.1` without a ` boot ` marker) or carries the
/// ` boot ` marker.
fn is_pidfile_header(raw: &[u8]) -> bool {
    let Some(rest) = raw.strip_prefix(crate::version::PIDFILE_PREFIX) else {
        return false;
    };
    let first_digit = rest.first().is_some_and(|b| b.is_ascii_digit());
    let has_boot = str::find(rest, crate::version::PIDFILE_BOOT).is_some();
    first_digit || has_boot
}

struct ParsedPidfile {
    header_boot: Option<Vec<u8>>,
    header_nonce: Vec<u8>,
    temp_dirs: Vec<Vec<u8>>,
    lines: Vec<StopLine>,
    malformed: usize,
}

/// Parse a pidfile's header, `# temp` lines, and process rows.
///
/// Shared by `stop()` and `live_pidfile_rows()` so both agree on leading
/// comments, blank lines, and header recognition.
#[inline(never)]
fn parse_pidfile(text: &[u8]) -> ParsedPidfile {
    let mut header_boot: Option<Vec<u8>> = None;
    let mut header_nonce: Vec<u8> = Vec::new();
    let mut temp_dirs: Vec<Vec<u8>> = Vec::new();
    let mut lines: Vec<StopLine> = Vec::new();
    let mut malformed = 0usize;
    // A psgen header may follow leading blank or comment lines, but not
    // content: a comment that is not a psgen header is ignored.
    let mut header_seen = false;
    let mut content_seen = false;
    for raw in text.split(|b| *b == b'\n') {
        if raw.is_empty() {
            continue;
        }
        if raw.first() == Some(&b'#') {
            if !header_seen && !content_seen && is_pidfile_header(raw) {
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
    ParsedPidfile {
        header_boot,
        header_nonce,
        temp_dirs,
        lines,
        malformed,
    }
}

fn count_live_lines(lines: &[StopLine]) -> usize {
    let mut live_rows = 0usize;
    for line in lines {
        let alive = match line.start {
            Some(start) => live::read_starttime(line.pid) == Some(start) && live::alive(line.pid),
            None => live::alive(line.pid),
        };
        if alive {
            live_rows += 1;
        }
    }
    live_rows
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
    let parsed = parse_pidfile(&text);
    let mut live_rows = count_live_lines(&parsed.lines);
    if parsed.lines.is_empty() {
        let mut side = path.to_vec();
        side.extend_from_slice(b".spawned");
        if let Some(side_text) = sys::read_file_nofollow(&side, 1 << 20) {
            let side_parsed = parse_pidfile(&side_text);
            live_rows += count_live_lines(&side_parsed.lines);
        }
    }
    Some(live_rows)
}

/// How many pidfile rows lie between a row and the top of its tree.
///
/// The pidfile does not store a parent, so the depth is read from `/proc`. A
/// row whose parent is not in the pidfile is a root. The walk is bounded so a
/// corrupted `/proc` cannot loop.
fn stop_depth_of(pid: i32, lines: &[StopLine]) -> usize {
    let mut depth = 0usize;
    let mut cur = pid;
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
    depth
}

#[inline(never)]
fn stop_note(quiet: bool, what: &[u8], pid: i32, why: Option<&[u8]>) {
    if quiet {
        return;
    }
    let mut out = Buf::new();
    sys::buf_push_s(&mut out, "psgen: ");
    sys::buf_push_b(&mut out, what);
    out.push(b' ');
    sys::buf_push_u(&mut out, pid as u64);
    if let Some(w) = why {
        sys::buf_push_s(&mut out, " (");
        sys::buf_push_b(&mut out, w);
        out.push(b')');
    }
    out.push(b'\n');
    sys::err(out.as_bytes());
}

#[inline(never)]
fn validate_pidfile_text(text: &[u8], is_sidecar: bool, force: bool) -> Result<ParsedPidfile, ()> {
    if let Some(line) = crlf_line(text) {
        let mut out = Buf::new();
        sys::buf_push_s(
            &mut out,
            if is_sidecar {
                "psgen: the recovery sidecar has CRLF line endings (line "
            } else {
                "psgen: the pidfile has CRLF line endings (line "
            },
        );
        sys::buf_push_u(&mut out, line as u64);
        sys::buf_push_s(
            &mut out,
            "); convert it to LF (for example with dos2unix) and run stop again\n",
        );
        sys::err(out.as_bytes());
        return Err(());
    }
    let parsed = parse_pidfile(text);
    if parsed.header_boot.is_none() && !force {
        sys::err(if is_sidecar {
            b"psgen: recovery sidecar is not a psgen pidfile (no '# psgen' header); use --force to stop anyway\n"
        } else {
            b"psgen: not a psgen pidfile (no '# psgen' header); use --force to stop anyway\n"
        });
        return Err(());
    }
    if let Some(hb) = &parsed.header_boot {
        let cur = util::boot_id();
        if !force && (hb.is_empty() || cur.is_empty() || *hb != cur) {
            sys::err(if is_sidecar {
                b"psgen: recovery sidecar is from another boot; use --force to ignore\n"
            } else {
                b"psgen: pidfile is from another boot; use --force to ignore\n"
            });
            return Err(());
        }
    }
    Ok(parsed)
}

fn sort_stop_lines(lines: &mut [StopLine]) {
    let mut keyed: Vec<(usize, StopLine)> = Vec::with_capacity(lines.len());
    for l in lines.iter() {
        keyed.push((
            stop_depth_of(l.pid, lines),
            StopLine {
                pid: l.pid,
                start: l.start,
                comm: l.comm.clone(),
            },
        ));
    }
    crate::json::shell_sort_by(&mut keyed, |a, b| (a.0, a.1.pid) < (b.0, b.1.pid));
    for (slot, (_, l)) in lines.iter_mut().zip(keyed) {
        *slot = l;
    }
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
#[inline(never)]
fn stop_skip(skipped: &mut usize, quiet: bool, pid: i32, why: &[u8]) {
    *skipped += 1;
    stop_note(quiet, b"skip", pid, Some(why));
}

#[inline(never)]
fn stop_fail(failed: &mut usize, quiet: bool, what: &[u8], pid: i32, why: Option<&[u8]>) {
    *failed += 1;
    stop_note(quiet, what, pid, why);
}

#[inline(never)]
fn stop_out_line(quiet: bool, pre: &str, pid: i32, detail: &[u8]) {
    if quiet {
        return;
    }
    let mut out = Buf::new();
    push_cnt(&mut out, pre, pid as u64, " (");
    sys::buf_push_b(&mut out, detail);
    sys::buf_push_s(&mut out, ")\n");
    sys::out(out.as_bytes());
}

#[inline(never)]
pub fn stop(path: &[u8], force: bool, plan: bool, quiet: bool) -> i32 {
    let text = match sys::read_file_nofollow_res(path, 1 << 20) {
        Ok(t) => t,
        Err(e) => {
            // A missing file, a mode-000 file and a directory all used to
            // print the same bytes, so a caller could not tell a stale
            // pidfile from a permissions problem. Name both the path and the
            // errno; the exit status stays 1 for every read failure.
            let mut out = Buf::new();
            sys::buf_push_s(&mut out, "psgen: cannot read pidfile ");
            sys::buf_push_b(&mut out, path);
            sys::buf_push_s(&mut out, ": ");
            sys::push_io_err(&mut out, &e);
            out.push(b'\n');
            sys::err(out.as_bytes());
            return 1;
        }
    };
    let Ok(parsed) = validate_pidfile_text(&text, false, force) else {
        return 1;
    };
    let mut header_nonce = parsed.header_nonce;
    let mut temp_dirs = parsed.temp_dirs;
    let mut lines = parsed.lines;
    let mut malformed = parsed.malformed;
    // If the main pidfile has no rows (for example a leftover pending header
    // after a post-spawn write failure) and `<path>.spawned` exists beside it,
    // stop the rows from that recovery sidecar too and remove it once every
    // row stops cleanly.
    let mut used_sidecar: Option<Vec<u8>> = None;
    if lines.is_empty() && malformed == 0 {
        let mut side_path = path.to_vec();
        side_path.extend_from_slice(b".spawned");
        if let Ok(side_text) = sys::read_file_nofollow_res(&side_path, 1 << 20) {
            let Ok(side) = validate_pidfile_text(&side_text, true, force) else {
                return 1;
            };
            if !quiet {
                sys::err_parts(&[b"reading recovery sidecar ", &side_path]);
            }
            header_nonce = side.header_nonce;
            temp_dirs.extend(side.temp_dirs);
            lines = side.lines;
            malformed = side.malformed;
            used_sidecar = Some(side_path);
        }
    }
    let me = current_exe_bytes();
    // Children before roots: a root's process-group kill reaches every child
    // that stayed in the group, and those children are then already gone when
    // their own lines are reached. Sorting by depth gives every line its own
    // signal even when a PID wrap makes a child's number lower than its
    // parent's.
    sort_stop_lines(&mut lines);

    let mut signalled: Vec<(i32, u64)> = Vec::new();
    // The distinct PIDs a line named, so `plan` counts processes rather than
    // lines: one process named five times is still one process.
    let mut named: Vec<i32> = Vec::new();
    let mut planned = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for line in &lines {
        let pid = line.pid;
        if pid == 1 {
            stop_skip(&mut skipped, quiet, pid, b"PID 1 is never a psgen stub");
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
            let procpath = sys::proc_path(pid, "");
            if Path::new(std::ffi::OsStr::from_bytes(procpath.as_bytes())).exists() {
                stop_fail(
                    &mut failed,
                    quiet,
                    b"cannot read",
                    pid,
                    Some(b"/proc entry unreadable"),
                );
            } else {
                stop_skip(&mut skipped, quiet, pid, b"already gone");
            }
            continue;
        }
        if line.start.is_some() {
            let identical = cur_start == line.start
                && (line.comm.is_empty()
                    || live::read_comm_exact(pid).as_deref() == Some(&line.comm)
                    || live::read_comm(pid).as_deref() == Some(&line.comm));
            if !identical {
                stop_skip(&mut skipped, quiet, pid, b"identity does not match");
                continue;
            }
        } else {
            match line_identity(pid, &header_nonce, &me) {
                LineIdentity::Same => {}
                LineIdentity::Unidentifiable(why) => {
                    stop_fail(
                        &mut failed,
                        quiet,
                        b"cannot identify",
                        pid,
                        Some(why.as_bytes()),
                    );
                    continue;
                }
            }
        }
        let zombie = cur_state == b'Z';
        let leader = info.as_ref().map(|s| s.pgrp == pid as i64).unwrap_or(false);
        if plan {
            if !zombie && !sys::kill(pid, 0) {
                let err = sys::errno();
                if err == libc::ESRCH {
                    stop_skip(&mut skipped, quiet, pid, b"already gone");
                } else {
                    stop_fail(
                        &mut failed,
                        quiet,
                        b"cannot signal",
                        pid,
                        (err == libc::EPERM).then_some(b"permission denied".as_slice()),
                    );
                }
                continue;
            }
            if zombie {
                if leader && !sys::kill(-pid, 0) && sys::errno() == libc::EPERM {
                    stop_fail(
                        &mut failed,
                        quiet,
                        b"cannot signal",
                        pid,
                        Some(b"process group"),
                    );
                    continue;
                }
                stop_out_line(
                    quiet,
                    "would skip ",
                    pid,
                    b"already a zombie; its process group is signalled first",
                );
                skipped += 1;
                continue;
            }
            if !quiet {
                let comm = live::read_comm(pid).unwrap_or_default();
                stop_out_line(false, "would signal ", pid, &comm);
            }
            if !named.contains(&pid) {
                named.push(pid);
                planned += 1;
            }
            continue;
        }
        let pfd = CloseFd(sys::pidfd_open(pid));
        let post = live::read_stat(pid);
        if post.as_ref().map(|s| s.starttime) != cur_start {
            stop_skip(&mut skipped, quiet, pid, b"already gone");
            continue;
        }
        let leader = post.as_ref().map(|s| s.pgrp == pid as i64).unwrap_or(false);
        let mut delivered = false;
        if leader {
            if sys::kill(-pid, sys::SIGKILL) {
                delivered = true;
            } else if sys::errno() != libc::ESRCH {
                stop_fail(
                    &mut failed,
                    quiet,
                    b"cannot signal",
                    pid,
                    Some(b"process group"),
                );
                continue;
            }
        }
        if zombie {
            stop_skip(&mut skipped, quiet, pid, b"already a zombie");
            continue;
        }
        if !delivered {
            if pfd.0 >= 0 {
                delivered = sys::pidfd_send_signal(pfd.0, sys::SIGKILL);
                if !delivered && sys::errno() == libc::ESRCH {
                    stop_skip(&mut skipped, quiet, pid, b"already gone");
                    continue;
                }
            }
            if !delivered {
                delivered = sys::kill(pid, sys::SIGKILL);
            }
        }
        if delivered {
            signalled.push((pid, cur_start.unwrap_or(0)));
        } else if sys::errno() == libc::ESRCH {
            stop_skip(&mut skipped, quiet, pid, b"already gone");
        } else {
            stop_fail(&mut failed, quiet, b"cannot signal", pid, None);
        }
    }

    // A file can name one PID on several lines, and a group leader's line can
    // reach children whose own lines follow. Counting signals therefore counts
    // the same process more than once; dedupe by PID so the summary is a count
    // of processes.
    sort_dedup_pid_start(&mut signalled);
    let mut stopped = 0usize;
    if !plan && !signalled.is_empty() {
        // A `SIGKILL` returns before the process has exited, and a zombie is
        // dead but still visible. Wait, bounded, until every signalled PID is
        // gone or a zombie, so "stopped N" is true when it is printed.
        let deadline = sys::monotonic_ns().saturating_add(2_000_000_000);
        loop {
            let left = signalled
                .iter()
                .filter(|(pid, start)| {
                    live::read_starttime(*pid) == Some(*start) && live::alive(*pid)
                })
                .count();
            if left == 0 || sys::monotonic_ns() >= deadline {
                break;
            }
            sys::nanosleep(0, 10_000_000);
        }
        for (pid, start) in &signalled {
            if live::read_starttime(*pid) == Some(*start) && live::alive(*pid) {
                failed += 1;
                stop_note(
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
        let paths: Vec<std::path::PathBuf> = temp_dirs
            .iter()
            .map(|t| std::path::PathBuf::from(std::ffi::OsStr::from_bytes(t)))
            .collect();
        cleanup_unbusy_temps(&paths);
        if let Some(side) = &used_sidecar {
            let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(side)));
        }
    }
    // The noun matters: an older message said "processes" while counting
    // pidfile lines, so one process named five times read as five.
    let mut out = Buf::new();
    let count = if plan { planned } else { stopped };
    push_cnt(
        &mut out,
        if plan { "would stop " } else { "stopped " },
        count as u64,
        if count == 1 { " process" } else { " processes" },
    );
    let missed = skipped + malformed;
    if missed > 0 {
        push_cnt(
            &mut out,
            ", skipped ",
            missed as u64,
            if missed == 1 { " line" } else { " lines" },
        );
    }
    if failed > 0 {
        push_cnt(&mut out, ", failed ", failed as u64, "");
    }
    out.push(b'\n');
    sys::out(out.as_bytes());
    i32::from(failed > 0)
}

/// Tree node specification for spawning matched decoy processes.
#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct DecoyNodeSpec {
    pub comm: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
    pub cmdline_raw_nuls: Option<usize>,
    pub exe: Vec<u8>,
    pub exe_memfd: bool,
    pub memfd_label: Vec<u8>,
    pub cwd: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
    pub user: Vec<u8>,
    pub rss_kb: u32,
    pub vsz_kb: u32,
    pub vm_lck_kb: u32,
    pub rss_shmem_kb: u32,
    pub rss_file_kb: u32,
    pub environ: Vec<Vec<u8>>,
    pub env_nul_len: u32,
    pub thread_comms: Vec<Vec<u8>>,
    pub thread_wchans: Vec<u8>,
    pub fd_specs: Vec<(i32, Vec<u8>)>,
    pub map_files: Vec<Vec<u8>>,
    pub wchan_mode: u8,
    pub non_dumpable: bool,
    pub no_new_privs: bool,
    pub seccomp_filters: u8,
    pub ptrace_children: bool,
    pub session_leader: bool,
    pub has_tty: bool,
    pub decoy_token: Vec<u8>,
    pub token_placements_mask: u8,
    pub execfn_mode: u8,
    pub execfn_fd: i32,
    pub jitter_ms: u32,
    pub children: Vec<DecoyNodeSpec>,
}

/// Spawn options for `spawn_decoy_trees` and `spawn_interleaved_target`.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct DecoySpawnOpts {
    pub duration: u32,
    pub pidfile: Option<Vec<u8>>,
    pub clean_env: bool,
    pub jitter_ms: u32,
    pub churn: u32,
    pub seed: u64,
    pub quiet: bool,
    pub wait: bool,
    pub bind_exe: bool,
    pub same_session: bool,
    pub label_decoys: usize,
    pub interleave_cmd: Option<String>,
}

impl Default for DecoySpawnOpts {
    fn default() -> Self {
        Self {
            duration: 0,
            pidfile: None,
            clean_env: true,
            jitter_ms: 0,
            churn: 0,
            seed: 1234,
            quiet: true,
            wait: false,
            bind_exe: false,
            same_session: false,
            label_decoys: 0,
            interleave_cmd: None,
        }
    }
}

/// Parse a symbolic `--wchan` mode name into the numeric `stub::Config::wchan_mode`.
pub fn parse_wchan_mode(name: &str) -> Option<u8> {
    const TABLE: &str =
        "pause|epoll,epoll_wait|poll|nanosleep,sleep|futex|read,pipe_read|wait4,wait,do_wait";
    for (mode, group) in TABLE.split('|').enumerate() {
        if group.split(',').any(|k| name.eq_ignore_ascii_case(k)) {
            return Some(mode as u8);
        }
    }
    None
}

fn contains_ascii_ci(hay: &str, needle: &str) -> bool {
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return n.is_empty();
    }
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

fn any_ci(hay: &str, csv: &str) -> bool {
    !csv.is_empty() && csv.split(',').any(|p| contains_ascii_ci(hay, p))
}

#[inline(never)]
fn wchan_mode_from_profile(wchan: &str, syscall: &str) -> u8 {
    const RULES: &str = "\
6|do_wait|wait4,waitid|\n\
1|ep_poll,epoll|epoll|\n\
2|poll|select|poll,ppoll\n\
3|nanosleep,hrtimer|nanosleep|\n\
4|futex|futex|\n\
5|pipe_read||read";
    for line in RULES.lines() {
        let mut p = line.split('|');
        let (Some(m), Some(wc_sub), Some(sc_sub), Some(sc_eq)) =
            (p.next(), p.next(), p.next(), p.next())
        else {
            continue;
        };
        if any_ci(wchan, wc_sub)
            || any_ci(syscall, sc_sub)
            || (!sc_eq.is_empty() && sc_eq.split(',').any(|k| syscall.eq_ignore_ascii_case(k)))
        {
            return m.as_bytes().first().map_or(0, |b| b - b'0');
        }
    }
    0
}

#[inline(never)]
fn clamp_no_nul(src: &[u8], cap: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len().min(cap));
    for &b in src {
        if b == 0 {
            continue;
        }
        if out.len() >= cap {
            break;
        }
        out.push(b);
    }
    out
}

#[inline(never)]
fn push_nul_bounded(buf: &mut Vec<u8>, entry: &[u8], cap: usize) -> bool {
    let clean_len = entry.iter().filter(|&&b| b != 0).count();
    if buf.len().saturating_add(clean_len).saturating_add(1) > cap {
        return false;
    }
    for &b in entry {
        if b != 0 {
            buf.push(b);
        }
    }
    buf.push(0);
    true
}

fn serialize_cmd(argv: &[Vec<u8>], comm: &[u8], raw_nuls: Option<usize>) -> Vec<u8> {
    const CAP: usize = 4096;
    let mut out = Vec::new();
    if argv.is_empty() {
        let fallback = if comm.is_empty() { b"worker" } else { comm };
        let _ = push_nul_bounded(&mut out, fallback, CAP);
    } else {
        for arg in argv {
            if !push_nul_bounded(&mut out, arg, CAP) {
                break;
            }
        }
        if out.is_empty() {
            let fallback = if comm.is_empty() { b"worker" } else { comm };
            let _ = push_nul_bounded(&mut out, fallback, CAP);
        }
    }
    if let Some(want_nuls) = raw_nuls {
        let cur_nuls = out.iter().rev().take_while(|&&b| b == 0).count();
        let extra = want_nuls.saturating_sub(cur_nuls);
        for _ in 0..extra {
            if out.len() >= CAP {
                break;
            }
            out.push(0);
        }
    }
    out
}

#[inline(never)]
fn serialize_nul_items(items: &[Vec<u8>], limit: usize, cap: usize, mode: u8) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items.iter().take(limit) {
        let owned;
        let slice: &[u8] = match mode {
            0 => {
                if item.is_empty() || item.starts_with(b"PSGEN_NONCE=") {
                    continue;
                }
                item
            }
            1 => {
                owned = clamp_no_nul(item, 15);
                if owned.is_empty() {
                    continue;
                }
                &owned
            }
            _ => {
                if item.first() != Some(&b'/') {
                    continue;
                }
                item
            }
        };
        if !push_nul_bounded(&mut out, slice, cap) {
            break;
        }
    }
    out
}

fn serialize_env_block(env: &[Vec<u8>]) -> Vec<u8> {
    serialize_nul_items(env, usize::MAX, 65536, 0)
}

fn serialize_thread_comms(comms: &[Vec<u8>]) -> Vec<u8> {
    serialize_nul_items(comms, 64, 4096, 1)
}

fn serialize_map_files(files: &[Vec<u8>]) -> Vec<u8> {
    serialize_nul_items(files, 32, 16384, 2)
}

fn serialize_fd_specs(specs: &[(i32, Vec<u8>)]) -> Vec<u8> {
    const CAP: usize = 16384;
    let mut out = Vec::new();
    let mut line = Buf::new();
    for (fd, kind) in specs {
        if *fd < 0 || *fd > 1024 || kind.is_empty() {
            continue;
        }
        line.v.clear();
        sys::buf_push_u(&mut line, *fd as u64);
        line.push(b':');
        sys::buf_push_b(&mut line, kind);
        if !push_nul_bounded(&mut out, line.as_bytes(), CAP) {
            break;
        }
    }
    out
}

#[inline(never)]
fn map_profile_fd_kind(
    fd: i32,
    target: &str,
    shared_groups: &mut Vec<(String, usize)>,
) -> Option<(Vec<u8>, bool)> {
    if !(0..=1024).contains(&fd) {
        return None;
    }
    if target.starts_with("/dev/pts/") {
        return Some((Vec::new(), true));
    }
    if target == "/dev/null" {
        return Some((b"null".to_vec(), false));
    }
    for prefix in "pipe:|socket:".split('|') {
        if target.starts_with(prefix) {
            let grp = intern_shared_group(shared_groups, target);
            let mut b = Buf::new();
            sys::buf_push_s(&mut b, prefix);
            sys::buf_push_u(&mut b, grp as u64);
            return Some((b.v, false));
        }
    }
    for pair in "eventpoll:epoll|timerfd:timerfd|signalfd:signalfd|eventfd:eventfd".split('|') {
        if let Some((needle, kind)) = pair.split_once(':') {
            if target.contains(needle) {
                return Some((kind.as_bytes().to_vec(), false));
            }
        }
    }
    if let Some(rest) = target.strip_prefix("/memfd:") {
        let lbl = rest.strip_suffix(" (deleted)").unwrap_or(rest);
        let clean = clamp_no_nul(lbl.as_bytes(), 64);
        let mut kind = b"memfd:".to_vec();
        kind.extend_from_slice(if clean.is_empty() { b"anon" } else { &clean });
        return Some((kind, false));
    }
    if target.starts_with('/')
        && !"/dev/|/proc/|/sys/"
            .split('|')
            .any(|p| target.starts_with(p))
        && !target.ends_with(" (deleted)")
    {
        let grp = intern_shared_group(shared_groups, target);
        let mut b = Buf::new();
        sys::buf_push_s(&mut b, "file:");
        sys::buf_push_u(&mut b, grp as u64);
        b.push(b':');
        sys::buf_push_b(&mut b, &clamp_no_nul(target.as_bytes(), 256));
        return Some((b.v, false));
    }
    (fd <= 2).then(|| (b"null".to_vec(), false))
}

fn intern_shared_group(groups: &mut Vec<(String, usize)>, key: &str) -> usize {
    if let Some((_, id)) = groups.iter().find(|(k, _)| k == key) {
        return *id;
    }
    let id = groups.len();
    groups.push((String::from(key), id));
    id
}

fn extract_profile_map_files(maps: &[String], exe: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for line in maps {
        let Some(slash) = line.find('/') else {
            continue;
        };
        let path = line[slash..].trim_end();
        if path.is_empty()
            || path == exe
            || "/dev/|/proc/|/sys/|/memfd:"
                .split('|')
                .any(|p| path.starts_with(p))
            || path.ends_with(" (deleted)")
        {
            continue;
        }
        let pb = clamp_no_nul(path.as_bytes(), 512);
        if pb.is_empty() || out.iter().any(|x| x == &pb) {
            continue;
        }
        out.push(pb);
        if out.len() >= 32 {
            break;
        }
    }
    out
}

fn parse_execfn_mode(at_execfn: Option<&str>) -> (u8, i32) {
    let Some(v) = at_execfn else {
        return (stub::EXECFN_PATH, -1);
    };
    if v.is_empty() {
        return (stub::EXECFN_EMPTY, -1);
    }
    let rest = v
        .strip_prefix("/dev/fd/")
        .or_else(|| v.strip_prefix("/proc/self/fd/"));
    if let Some(num) = rest {
        if let Some(fd) = str::parse_u64(num.as_bytes()) {
            if fd <= 1024 {
                return (stub::EXECFN_DEVFD, fd as i32);
            }
        }
    }
    (stub::EXECFN_PATH, -1)
}

fn token_placements_to_mask(placements: &[String]) -> u8 {
    let mut mask = 0u8;
    for p in placements {
        if p == "anon" {
            mask |= stub::TOK_PLACE_ANON;
        } else if p == "heap" {
            mask |= stub::TOK_PLACE_HEAP;
        } else if p == "stack" {
            mask |= stub::TOK_PLACE_STACK;
        }
    }
    mask
}

/// Generate a deterministic decoy token matching optional target length and
/// `ProfileMemory::token_charset`, honoring an optional `--decoy-token` prefix
/// when length allows, and guaranteed never to hash to `avoid_sha256`.
#[inline(never)]
pub fn make_shaped_decoy_token(
    prefix_override: Option<&str>,
    len: Option<u32>,
    charset: Option<&str>,
    avoid_sha256: Option<&str>,
    rng: &mut crate::rng::Rng,
) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    const ALNUM: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (charset_pfx, kind) = match charset {
        Some(cs) if cs.starts_with("prefix:") => {
            let rest = &cs["prefix:".len()..];
            match rest.rfind(':') {
                Some(idx) => (Some(&rest[..idx]), &rest[idx + 1..]),
                None => (None, "hex"),
            }
        }
        Some(cs) => (None, cs),
        None => (None, "hex"),
    };
    let target_len = match len {
        Some(l) if l > 0 => (l as usize).min(4096),
        _ => {
            let base = prefix_override.map(|s| s.len()).unwrap_or(0);
            if base < 32 {
                32
            } else {
                base + 16
            }
        }
    };
    let ov_ok = prefix_override.filter(|ov| !ov.is_empty() && ov.len() + 4 <= target_len);
    let effective_pfx: &[u8] = match (charset_pfx, ov_ok) {
        (Some(_), Some(ov)) => ov.as_bytes(),
        (Some(cp), None) if cp.len() < target_len => cp.as_bytes(),
        (None, Some(ov)) if charset.is_none() => ov.as_bytes(),
        _ => b"",
    };
    let alpha: &[u8] = match kind {
        "alnum" | "ascii" => ALNUM,
        "base64" => B64,
        _ => HEX,
    };
    let mut out = vec![0u8; target_len];
    let pfx_len = effective_pfx.len().min(target_len);
    for _ in 0..8 {
        if let (Some(dst), Some(src)) = (out.get_mut(..pfx_len), effective_pfx.get(..pfx_len)) {
            dst.copy_from_slice(src);
        }
        if let Some(tail) = out.get_mut(pfx_len..) {
            for slot in tail {
                let idx = rng.below(alpha.len() as u64) as usize;
                *slot = alpha.get(idx).copied().unwrap_or(b'0');
            }
        }
        if let Some(avoid) = avoid_sha256 {
            if crate::sha256::hash_hex(&out) == avoid {
                continue;
            }
        }
        break;
    }
    out
}

#[inline(never)]
fn fill_redacted_string(
    raw: &str,
    default_tok: &str,
    charset: Option<&str>,
    avoid_sha256: Option<&str>,
    rng: &mut crate::rng::Rng,
) -> Vec<u8> {
    if !raw.contains("<REDACTED") {
        return raw.as_bytes().to_vec();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(pos) = rest.find("<REDACTED") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + "<REDACTED".len()..];
        if let Some(after_len) = after.strip_prefix(":len=") {
            if let Some(close) = after_len.find('>') {
                let num_s = &after_len[..close];
                if let Some(want) = str::parse_u64(num_s.as_bytes()) {
                    let n = (want as usize).min(4096);
                    let tok = if n == default_tok.len() {
                        String::from(default_tok)
                    } else {
                        let bytes = make_shaped_decoy_token(
                            None,
                            Some(n as u32),
                            charset,
                            avoid_sha256,
                            rng,
                        );
                        String::from_utf8_lossy(&bytes).into_owned()
                    };
                    out.push_str(&tok);
                    rest = &after_len[close + 1..];
                    continue;
                }
            }
        }
        if let Some(after_close) = after.strip_prefix('>') {
            out.push_str(default_tok);
            rest = after_close;
            continue;
        }
        out.push_str("<REDACTED");
        rest = after;
    }
    out.push_str(rest);
    out.into_bytes()
}

/// Convert a captured or parsed `Profile` tree into a `DecoyNodeSpec` tree at
/// the requested fidelity `level` (1..=6). Walks upward through captured
/// `parent`/`tracer` ancestors so the decoy tree preserves real parent-child
/// and supervisor-tracer topology instead of flattening to `PPid=1`.
pub fn profile_to_decoy_tree(
    p: &crate::profile::Profile,
    level: u8,
    decoy_token: Option<&[u8]>,
    jitter_ms: u32,
) -> DecoyNodeSpec {
    let mut chain: Vec<(&crate::profile::Profile, bool)> = Vec::new();
    let mut cur = p;
    let mut is_tracer_link = false;
    for _ in 0..16 {
        chain.push((cur, is_tracer_link));
        if let Some(parent) = cur.parent.as_deref() {
            is_tracer_link = cur.status.tracer_pid != 0
                && (cur.status.tracer_pid == parent.identity.pid || cur.tracer.is_none());
            cur = parent;
        } else if let Some(tracer) = cur.tracer.as_deref() {
            is_tracer_link = true;
            cur = tracer;
        } else {
            break;
        }
    }
    if chain.len() == 1 {
        return profile_to_decoy_inner(p, level, decoy_token, jitter_ms, true);
    }
    let self_spec = profile_to_decoy_inner(p, level, decoy_token, 0, false);
    let mut wrapped = self_spec;
    let mut child_pid = p.identity.pid;
    let mut child_tracer = p.status.tracer_pid;
    let mut prev_was_tracer_link = chain.first().is_some_and(|c| c.1);
    for (idx, &(anc, next_tracer_link)) in chain.iter().enumerate().skip(1) {
        let is_top = idx + 1 == chain.len();
        let mut anc_spec =
            profile_to_decoy_inner(anc, level, None, if is_top { jitter_ms } else { 0 }, is_top);
        let traced_by_anc =
            prev_was_tracer_link || (child_tracer != 0 && child_tracer == anc.identity.pid);
        if traced_by_anc {
            anc_spec.ptrace_children = true;
        }
        if anc_spec.wchan_mode == 0 || contains_ascii_ci(&anc.syscall.wchan, "wait") {
            anc_spec.wchan_mode = stub::WCHAN_WAIT4;
        }
        // Avoid duplicating child if ancestor.children already contained it.
        if let Some(pos) = anc
            .children
            .iter()
            .position(|c| c.identity.pid == child_pid)
        {
            if let Some(slot) = anc_spec.children.get_mut(pos) {
                *slot = wrapped;
            } else {
                anc_spec.children.push(wrapped);
            }
        } else {
            anc_spec.children.push(wrapped);
        }
        wrapped = anc_spec;
        child_pid = anc.identity.pid;
        child_tracer = anc.status.tracer_pid;
        prev_was_tracer_link = next_tracer_link;
    }
    wrapped
}

fn profile_to_decoy_inner(
    p: &crate::profile::Profile,
    level: u8,
    decoy_token: Option<&[u8]>,
    jitter_ms: u32,
    is_root: bool,
) -> DecoyNodeSpec {
    let raw_comm = if !p.identity.comm.is_empty() {
        p.identity.comm.as_bytes()
    } else if !p.status.name.is_empty() {
        p.status.name.as_bytes()
    } else {
        b"worker"
    };
    let comm = clamp_no_nul(raw_comm, 15);
    let tok_seed = (p.identity.pid as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (p.identity.starttime.rotate_left(13))
        ^ decoy_token
            .map(|t| t.iter().fold(0u64, |a, &b| a.wrapping_mul(31) ^ b as u64))
            .unwrap_or(0x55aa);
    let mut tok_rng = crate::rng::Rng::new(tok_seed);
    let effective_tok_bytes: Vec<u8> = match decoy_token {
        Some(t) if !t.is_empty() => match p.memory.token_len {
            Some(want_len) if t.len() != want_len as usize => make_shaped_decoy_token(
                core::str::from_utf8(t).ok(),
                Some(want_len),
                p.memory.token_charset.as_deref(),
                p.memory.token_sha256.as_deref(),
                &mut tok_rng,
            ),
            _ => t[..t.len().min(4096)].to_vec(),
        },
        None if p.memory.token_present
            || p.identity.argv.iter().any(|a| a.contains("<REDACTED"))
            || p.environ.iter().any(|e| e.contains("<REDACTED")) =>
        {
            make_shaped_decoy_token(
                None,
                p.memory.token_len,
                p.memory.token_charset.as_deref(),
                p.memory.token_sha256.as_deref(),
                &mut tok_rng,
            )
        }
        _ => Vec::new(),
    };
    let tok_str = String::from_utf8_lossy(&effective_tok_bytes).into_owned();
    let cs = p.memory.token_charset.as_deref();
    let avoid = p.memory.token_sha256.as_deref();

    let mut argv: Vec<Vec<u8>> = Vec::with_capacity(p.identity.argv.len().max(1));
    for a in &p.identity.argv {
        argv.push(fill_redacted_string(a, &tok_str, cs, avoid, &mut tok_rng));
    }
    if argv.is_empty() {
        argv.push(comm.clone());
    }
    let user = users::lookup_uid(p.identity.uid)
        .map(|(n, _)| n)
        .unwrap_or_else(|| {
            if p.identity.uid == sys::geteuid() {
                util::current_user().name
            } else {
                Vec::new()
            }
        });
    let self_sid = sys::getsid(0);
    let session_leader = p.identity.sid > 0
        && (p.identity.sid == p.identity.pid
            || (is_root && self_sid > 0 && p.identity.sid != self_sid));

    let mut spec = DecoyNodeSpec {
        comm: comm.clone(),
        argv,
        cmdline_raw_nuls: p.identity.cmdline_raw_nuls,
        uid: p.identity.uid,
        gid: p.identity.gid,
        user,
        rss_kb: 0,
        vsz_kb: 0,
        session_leader,
        jitter_ms: if is_root { jitter_ms } else { 0 },
        ..DecoyNodeSpec::default()
    };

    let default_wc = if level >= 3 {
        wchan_mode_from_profile(&p.syscall.wchan, &p.syscall.syscall)
    } else {
        0
    };
    let worker_wc = if default_wc == stub::WCHAN_WAIT4 {
        4
    } else {
        default_wc
    };

    if level >= 3 {
        let mut extras: Vec<Vec<u8>> = Vec::new();
        let has_main = p.task.iter().any(|t| t.tid == p.identity.pid);
        for (i, t) in p.task.iter().enumerate() {
            if (has_main && t.tid == p.identity.pid) || (!has_main && i == 0) {
                continue;
            }
            extras.push(if t.comm.is_empty() {
                comm.clone()
            } else {
                clamp_no_nul(t.comm.as_bytes(), 15)
            });
        }
        if extras.is_empty() {
            let total_threads = p.status.threads.max(p.stat.num_threads);
            if total_threads > 1 {
                extras.resize((total_threads - 1).min(64) as usize, comm.clone());
            }
        }
        spec.thread_wchans = vec![worker_wc; extras.len()];
        spec.thread_comms = extras;

        spec.children.reserve(p.children.len());
        for c in &p.children {
            spec.children
                .push(profile_to_decoy_inner(c, level, decoy_token, 0, false));
        }
    }

    if level >= 4 {
        let memfd_src = p
            .identity
            .exe_memfd
            .as_deref()
            .or_else(|| p.identity.exe.strip_prefix("/memfd:"));
        if let Some(raw) = memfd_src {
            let s = raw.strip_prefix("/memfd:").unwrap_or(raw);
            let s = s.strip_suffix(" (deleted)").unwrap_or(s);
            spec.exe_memfd = true;
            spec.memfd_label = clamp_no_nul(s.as_bytes(), 240);
        } else if p.identity.exe.starts_with('/') && p.identity.exe != "<redacted>" {
            spec.exe = clamp_no_nul(p.identity.exe.as_bytes(), 4096);
        }
        let (ef_mode, ef_fd) = parse_execfn_mode(p.auxv.at_execfn.as_deref());
        spec.execfn_mode = ef_mode;
        spec.execfn_fd = ef_fd;

        if p.identity.cwd.starts_with('/') && p.identity.cwd != "<redacted>" {
            spec.cwd = clamp_no_nul(p.identity.cwd.as_bytes(), 4096);
        }

        for e in &p.environ {
            if !e.starts_with("PSGEN_NONCE=") {
                spec.environ
                    .push(fill_redacted_string(e, &tok_str, cs, avoid, &mut tok_rng));
            }
        }
        if spec.environ.is_empty()
            && (p.environ_all_nul || p.environ_raw_len > 0 || p.stat.env_end > p.stat.env_start)
        {
            let span = if p.environ_raw_len > 0 {
                p.environ_raw_len
            } else {
                p.stat.env_end.saturating_sub(p.stat.env_start)
            };
            spec.env_nul_len = span.clamp(1, 65_536) as u32;
        }

        let mut shared_groups: Vec<(String, usize)> = Vec::new();
        for fd_entry in &p.fds {
            if let Some((kind, is_tty)) =
                map_profile_fd_kind(fd_entry.fd, &fd_entry.target, &mut shared_groups)
            {
                if is_tty {
                    spec.has_tty = true;
                } else if !kind.is_empty() {
                    spec.fd_specs.push((fd_entry.fd, kind));
                }
            }
        }

        spec.map_files = extract_profile_map_files(&p.memory.maps, &p.identity.exe);
        spec.wchan_mode = if !spec.children.is_empty() && default_wc == 0 {
            stub::WCHAN_WAIT4
        } else {
            default_wc
        };
        // Strictly match target dumpable, NoNewPrivs, and Seccomp_filters delta
        // instead of forcing opacity inversion at higher decoy levels.
        spec.non_dumpable = p.dumpable == Some(false);
        let target_sf = if p.status.seccomp_filters > 0 {
            p.status.seccomp_filters
        } else if p.status.seccomp == 2 {
            1
        } else {
            0
        };
        let delta_sf = target_sf.saturating_sub(sys::self_seccomp_filters()).min(8) as u8;
        spec.seccomp_filters = delta_sf;
        spec.no_new_privs = p.status.no_new_privs != 0 || delta_sf > 0;
        spec.ptrace_children = p.children.iter().any(|c| c.status.tracer_pid != 0);
        let target_rss_kb = (p.stat.rss.saturating_mul(sys::page_kb())).min(8192) as u32;
        spec.rss_kb = target_rss_kb;
        spec.rss_file_kb = if !spec.map_files.is_empty() {
            target_rss_kb
        } else {
            0
        };
        spec.vsz_kb = (p.stat.vsize / 1024).min(65536) as u32;
        spec.vm_lck_kb = p.status.vm_lck.unwrap_or(0).min(64) as u32;
        spec.rss_shmem_kb = p.status.rss_shmem.unwrap_or(0).min(512) as u32;
    }

    if level >= 5 && p.memory.token_present && !effective_tok_bytes.is_empty() {
        let mask = token_placements_to_mask(&p.memory.token_placements);
        if p.memory.token_placements.is_empty() || mask != 0 {
            spec.decoy_token = effective_tok_bytes[..effective_tok_bytes.len().min(4096)].to_vec();
            spec.token_placements_mask = mask;
        }
    }

    spec
}

/// Apply deterministic seeded memory jitter (`+- 64 KiB` RSS, `+- 128 KiB` VSZ)
/// recursively across a decoy tree so level >= 6 decoys vary naturally.
pub fn apply_decoy_mem_jitter(spec: &mut DecoyNodeSpec, rng: &mut crate::rng::Rng) {
    if spec.rss_kb > 0 {
        let delta = (rng.below(33) as i64 - 16) * 4;
        spec.rss_kb = ((spec.rss_kb as i64) + delta).clamp(4, 8192) as u32;
    }
    if spec.vsz_kb > 0 {
        let delta = (rng.below(65) as i64 - 32) * 4;
        spec.vsz_kb = ((spec.vsz_kb as i64) + delta).clamp(4, 65536) as u32;
    }
    for c in &mut spec.children {
        apply_decoy_mem_jitter(c, rng);
    }
}

fn decoy_rng_next(state: &mut u64) -> u64 {
    let mut x = *state;
    if x == 0 {
        x = 0x9e37_79b9_7f4a_7c15;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[inline(never)]
fn sleep_jitter_ms(jitter_ms: u32, rng: &mut u64) {
    if jitter_ms == 0 {
        return;
    }
    let ms = decoy_rng_next(rng) % (jitter_ms as u64 + 1);
    if ms > 0 {
        sys::nanosleep(ms / 1000, (ms % 1000) * 1_000_000);
    }
}

#[inline(never)]
fn run_churn_batch(count: u32, rng: &mut u64) {
    if count == 0 {
        return;
    }
    let mut pids = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let pid = sys::fork();
        if pid == 0 {
            sys::prctl_set_name(b"sh");
            let ns = (decoy_rng_next(rng) % 3 + 1) * 1_000_000;
            sys::nanosleep(0, ns);
            sys::exit(0);
        } else if pid > 0 {
            pids.push(pid);
        }
        let _ = sys::reap_children_nonblock();
    }
    for cpid in pids {
        let mut st: i32 = 0;
        unsafe {
            libc::waitpid(cpid, &mut st, 0);
        }
    }
    let _ = sys::reap_children_nonblock();
}

fn count_decoy_nodes(node: &DecoyNodeSpec) -> usize {
    1 + node.children.iter().map(count_decoy_nodes).sum::<usize>()
}

fn max_decoy_rss(node: &DecoyNodeSpec) -> u64 {
    let mut m = node.rss_kb as u64;
    for c in &node.children {
        m = m.max(max_decoy_rss(c));
    }
    m
}

fn flatten_decoy_tree<'a>(
    node: &'a DecoyNodeSpec,
    nodes: &mut Vec<&'a DecoyNodeSpec>,
    children: &mut Vec<Vec<usize>>,
) -> usize {
    let idx = nodes.len();
    nodes.push(node);
    children.push(Vec::new());
    let mut child_idxs = Vec::with_capacity(node.children.len());
    for c in &node.children {
        let cidx = flatten_decoy_tree(c, nodes, children);
        child_idxs.push(cidx);
    }
    children[idx] = child_idxs;
    idx
}

fn decoy_stub_exe_paths() -> Result<(Vec<u8>, Vec<u8>), String> {
    let self_exe =
        std::env::current_exe().map_err(|_| String::from("cannot resolve current_exe"))?;
    let fallback = self_exe.as_os_str().as_bytes().to_vec();
    #[cfg(test)]
    {
        if let Some(target_bin) = self_exe
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("psgen"))
        {
            let b = target_bin.as_os_str().as_bytes().to_vec();
            if sys::access(&b, libc::X_OK) {
                return Ok((b.clone(), b));
            }
        }
    }
    Ok((b"/proc/self/exe".to_vec(), fallback))
}

#[inline(never)]
fn copy_shadow_exe_res(src: &[u8], dst: &[u8]) -> Result<(), std::io::Error> {
    let bytes = std::fs::read(Path::new(std::ffi::OsStr::from_bytes(src)))?;
    let fd = sys::open(
        dst,
        sys::O_WRONLY | sys::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o755,
    );
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ok = sys::write_fd(fd, &bytes);
    let err = std::io::Error::last_os_error();
    let _ = unsafe { libc::fchmod(fd, 0o755) };
    sys::close(fd);
    if ok {
        Ok(())
    } else {
        Err(err)
    }
}

fn copy_shadow_exe(src: &[u8], dst: &[u8]) -> bool {
    copy_shadow_exe_res(src, dst).is_ok()
}

fn ensure_shadow_copy(
    exe: &[u8],
    fallback_exe: &[u8],
    nonce: &[u8],
    idx: usize,
    cache: &mut Vec<(Vec<u8>, Vec<u8>)>,
    temps: &mut Vec<std::path::PathBuf>,
) -> Vec<u8> {
    let base = str::basename(exe);
    if base.is_empty()
        || base == b"."
        || base == b".."
        || base.iter().any(|&b| b < 0x20 || b == 0x7f || b == b'/')
    {
        return Vec::new();
    }
    if let Some((_, existing)) = cache.iter().find(|(b, _)| b.as_slice() == base) {
        return existing.clone();
    }
    let Some(dir) = make_temp_dir(idx, nonce) else {
        return Vec::new();
    };
    let mut dst = dir.as_os_str().as_bytes().to_vec();
    dst.push(b'/');
    dst.extend_from_slice(base);
    if !copy_shadow_exe(fallback_exe, &dst) {
        let _ = sys::remove_staging_dir(&dir);
        return Vec::new();
    }
    temps.push(dir);
    cache.push((base.to_vec(), dst.clone()));
    dst
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn make_decoy_config(
    idx: usize,
    nodes: &[&DecoyNodeSpec],
    children: &[Vec<usize>],
    fd_of: &[i32],
    opts: &DecoySpawnOpts,
    arena_fd: i32,
    nonce: &[u8],
    temp: &[u8],
    self_copy: &[u8],
    can_bind_exe: bool,
    global_id: u32,
) -> stub::Config {
    let n = nodes[idx];
    let (child_fds, keep_fds, max_fd) = collect_node_fds(idx, children, fd_of);
    let comm = {
        let c = clamp_no_nul(&n.comm, 15);
        if c.is_empty() {
            b"worker".to_vec()
        } else {
            c
        }
    };
    let use_exe = opts.bind_exe && !n.exe_memfd && !n.exe.is_empty();
    let use_bind = use_exe && can_bind_exe;
    let wait_tracer = nodes
        .iter()
        .zip(children.iter())
        .any(|(p, ch)| p.ptrace_children && ch.contains(&idx));
    let mut flags: u32 = 0;
    for &(cond, bit) in &[
        (idx == 0, stub::F_ROOT),
        (opts.clean_env, stub::F_CLEAN_ENV),
        (
            !opts.same_session && n.session_leader,
            corpus::F_SESSION as u32,
        ),
        (n.has_tty, corpus::F_TTY as u32),
        (n.exe_memfd, stub::F_EXE_MEMFD),
        (n.non_dumpable, stub::F_NON_DUMPABLE),
        (n.no_new_privs, stub::F_NO_NEW_PRIVS),
        (n.ptrace_children, stub::F_PTRACE_CHILDREN),
        (wait_tracer, stub::F_WAIT_TRACER),
        (use_bind && sys::geteuid() != 0, stub::F_USERNS),
    ] {
        if cond {
            flags |= bit;
        }
    }
    stub::Config {
        flags,
        vsz_kb: n.vsz_kb,
        rss_kb: n.rss_kb,
        uid: n.uid,
        gid: n.gid,
        duration: opts.duration,
        cpu: 0,
        stage: 0,
        comm: comm.clone(),
        exe: if use_bind {
            clamp_no_nul(&n.exe, 4096)
        } else {
            Vec::new()
        },
        cmd: serialize_cmd(&n.argv, &comm, n.cmdline_raw_nuls),
        user: clamp_no_nul(&n.user, 64),
        temp: temp.to_vec(),
        disk_kb: 0,
        self_copy: if use_exe {
            self_copy.to_vec()
        } else {
            Vec::new()
        },
        nonce: nonce.to_vec(),
        child_fds,
        keep_fds,
        max_fd,
        arena_fd: if !opts.clean_env && n.rss_kb > 0 && arena_fd >= 0 {
            4
        } else {
            -1
        },
        status_fd: 5,
        id: global_id,
        cwd: clamp_no_nul(&n.cwd, 4096),
        env_block: serialize_env_block(&n.environ),
        env_nul_len: n.env_nul_len,
        memfd_label: clamp_no_nul(&n.memfd_label, 240),
        decoy_token: n
            .decoy_token
            .get(..n.decoy_token.len().min(4096))
            .unwrap_or(&[])
            .to_vec(),
        token_placements_mask: n.token_placements_mask,
        thread_comms: serialize_thread_comms(&n.thread_comms),
        thread_wchans: n
            .thread_wchans
            .get(..n.thread_wchans.len().min(64))
            .unwrap_or(&[])
            .to_vec(),
        fd_specs: serialize_fd_specs(&n.fd_specs),
        map_files: serialize_map_files(&n.map_files),
        wchan_mode: n.wchan_mode,
        seccomp_filters: n.seccomp_filters.min(8),
        execfn_mode: n.execfn_mode,
        execfn_fd: n.execfn_fd,
        jitter_ms: n.jitter_ms.max(opts.jitter_ms).min(50),
        vm_lck_kb: n.vm_lck_kb.min(64),
        rss_shmem_kb: n.rss_shmem_kb.min(512),
        rss_file_kb: n.rss_file_kb.min(8192),
    }
}

fn close_unneeded_fds_above(first: i32, keep: &[i32]) {
    let max_keep = keep.iter().copied().max().unwrap_or(first - 1);
    for fd in first..=max_keep {
        if !keep.contains(&fd) {
            sys::close(fd);
        }
    }
    sys::close_range_from((max_keep + 1).max(first));
}

/// Spawn one or more arbitrary-depth decoy process trees with clean-env
/// authentication, seeded startup jitter, optional churn workers, and 3-field
/// pidfile recording compatible with `psgen stop`.
#[inline(never)]
pub fn spawn_decoy_trees(
    trees: &[DecoyNodeSpec],
    opts: &DecoySpawnOpts,
) -> Result<Vec<i32>, String> {
    let _ = sys::prctl_set_subreaper();
    let mut rng = opts.seed ^ 0xa076_1d64_78bd_642f;
    let nonce = random_hex(8);

    if trees.is_empty() {
        run_churn_batch(opts.churn, &mut rng);
        if let Some(path) = &opts.pidfile {
            if !write_pidfile(path, &[], &[], &nonce).0 {
                return Err(String::from("cannot write pidfile"));
            }
        }
        return Ok(Vec::new());
    }

    let (primary_exe, fallback_exe) = decoy_stub_exe_paths()?;
    let can_bind_exe = opts.bind_exe && probe::caps().can_spoof_exe();
    let mut total_nodes = 0usize;
    let mut max_rss = 0u64;
    for t in trees {
        total_nodes += count_decoy_nodes(t);
        max_rss = max_rss.max(max_decoy_rss(t));
    }

    let arena_fd = CloseFd(if !opts.clean_env && max_rss > 0 {
        let fd = sys::anon_file(b"cache", max_rss * 1024);
        if fd < 0 {
            return Err(String::from("cannot create RSS arena"));
        }
        let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 6) };
        sys::close(fd);
        if duped < 0 {
            return Err(String::from("cannot duplicate RSS arena fd"));
        }
        duped
    } else {
        -1
    });

    let memfd_name = make_memfd_name(&nonce);

    let mut pids: Vec<i32> = Vec::with_capacity(total_nodes);
    let mut root_pids: Vec<(i32, u64)> = Vec::with_capacity(trees.len());
    let mut all_temps: Vec<std::path::PathBuf> = Vec::new();
    let mut shadow_cache: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut next_id: u32 = 0;

    let churn_per_tree = opts.churn / (trees.len() as u32);
    let mut churn_rem = opts.churn % (trees.len() as u32);

    for (tree_idx, tree) in trees.iter().enumerate() {
        let mut nodes: Vec<&DecoyNodeSpec> = Vec::new();
        let mut children: Vec<Vec<usize>> = Vec::new();
        flatten_decoy_tree(tree, &mut nodes, &mut children);

        let fd_of = match alloc_sealed_cfg_fds(nodes.len(), &memfd_name, true) {
            Ok(fds) => fds,
            Err(err) => {
                remove_dirs(&all_temps);
                return Err(err);
            }
        };

        let mut root_temps: Vec<std::path::PathBuf> = Vec::new();
        let mut root_cmd = Vec::new();
        let mut root_env_block = Vec::new();
        let mut root_env_nul_len = 0u32;
        let mut write_ok = true;

        for (i, &n) in nodes.iter().enumerate() {
            let need_dir = can_bind_exe
                && !n.exe_memfd
                && !n.exe.is_empty()
                && !Path::new(std::ffi::OsStr::from_bytes(&n.exe)).exists();
            let temp = maybe_node_temp(need_dir, next_id as usize, &nonce, &mut root_temps);
            let shadow_copy = if opts.bind_exe && !n.exe_memfd && !n.exe.is_empty() {
                ensure_shadow_copy(
                    &n.exe,
                    &fallback_exe,
                    &nonce,
                    (next_id as usize).wrapping_add(100_000),
                    &mut shadow_cache,
                    &mut all_temps,
                )
            } else {
                Vec::new()
            };
            let cfg = make_decoy_config(
                i,
                &nodes,
                &children,
                &fd_of,
                opts,
                arena_fd.0,
                &nonce,
                &temp,
                &shadow_copy,
                can_bind_exe,
                next_id,
            );
            if i == 0 {
                root_cmd = cfg.cmd.clone();
                root_env_block = cfg.env_block.clone();
                root_env_nul_len = cfg.env_nul_len;
            }
            next_id = next_id.wrapping_add(1);
            if !fd_of.get(i).is_some_and(|&fd| write_config_fd(fd, &cfg)) {
                write_ok = false;
                break;
            }
        }

        if !write_ok {
            close_fds(&fd_of);
            remove_dirs(&root_temps);
            continue;
        }
        all_temps.extend(root_temps);

        let (sr, sw) = match open_status_pipe(false) {
            Ok(p) => p,
            Err(err) => {
                close_fds(&fd_of);
                remove_dirs(&all_temps);
                return Err(err);
            }
        };
        let status_read = CloseFd(sr);
        let status_write = CloseFd(sw);

        let root_cfg_fd = fd_of[0];
        let pid = sys::fork();
        if pid == 0 {
            sys::close(status_read.0);
            if sys::dup2(root_cfg_fd, 3) != 3 {
                sys::exit(127);
            }
            sys::close(root_cfg_fd);
            if arena_fd.0 >= 0 {
                if sys::dup2(arena_fd.0, 4) != 4 {
                    sys::exit(127);
                }
                sys::close(arena_fd.0);
            } else {
                sys::close(4);
            }
            if sys::dup2(status_write.0, 5) != 5 {
                sys::exit(127);
            }
            sys::close(status_write.0);
            redirect_stdio();
            // Close any stray inherited pipe fds (e.g. caller `| tee`) while
            // keeping child config fds (`fd_of[1..]`).
            close_unneeded_fds_above(6, &fd_of[1..]);
            let (argv_buf, argv) = stub::build_argv(&root_cmd);
            let (_env_keep, env) = if opts.clean_env {
                stub::build_envp_for_decoy(&root_env_block, root_env_nul_len)
            } else {
                let nonce_line = stub::nonce_env_line(&nonce);
                let env = stub::envp_with(&nonce_line);
                (nonce_line, env)
            };
            if sys::execve(&primary_exe, &argv, &env) < 0 {
                sys::execve(&fallback_exe, &argv, &env);
            }
            let _ = &argv_buf;
            sys::exit(127);
        }
        close_fds(&fd_of);
        drop(status_write);

        if pid > 0 {
            root_pids.push((pid, live::read_starttime(pid).unwrap_or(0)));
            let timeout = 3_000u64
                .saturating_add((nodes.len() as u64).saturating_mul(50))
                .min(10_000);
            let records = read_status_records(status_read.0, nodes.len(), timeout);
            let before = pids.len();
            for (rpid, status, _, _) in &records {
                if *status >= 0 {
                    pids.push(*rpid);
                }
            }
            if pids.len() == before {
                pids.push(pid);
            }
        }
        drop(status_read);

        let batch = churn_per_tree
            + if churn_rem > 0 {
                churn_rem -= 1;
                1
            } else {
                0
            };
        run_churn_batch(batch, &mut rng);

        if tree_idx + 1 < trees.len() {
            sleep_jitter_ms(opts.jitter_ms.max(tree.jitter_ms), &mut rng);
        }
    }

    drop(arena_fd);
    write_live_marker(&all_temps, &root_pids, &nonce);
    sort_dedup_i32(&mut pids);

    if pids.is_empty() {
        remove_dirs(&all_temps);
        all_temps.clear();
    } else if !all_temps.is_empty() {
        let mut live_ids = Vec::with_capacity(pids.len());
        for &pid in &pids {
            live_ids.push((pid, live::read_starttime(pid).unwrap_or(0)));
        }
        write_live_marker(&all_temps, &live_ids, &nonce);
    }

    if let Some(path) = &opts.pidfile {
        if !write_pidfile(path, &pids, &all_temps, &nonce).0 && !opts.quiet {
            sys::err(b"psgen: cannot write pidfile\n");
        }
    }

    if opts.wait && opts.duration > 0 && !root_pids.is_empty() {
        let deadline = sys::monotonic_ns()
            .saturating_add((opts.duration as u64 + 2).saturating_mul(1_000_000_000));
        loop {
            let _ = sys::reap_children_nonblock();
            let any_live = root_pids
                .iter()
                .any(|(pid, st)| live::read_starttime(*pid) == Some(*st) && live::alive(*pid));
            if !any_live || sys::monotonic_ns() >= deadline {
                break;
            }
            sys::nanosleep(0, 20_000_000);
        }
        let _ = sys::reap_children_nonblock();
        cleanup_unbusy_temps(&all_temps);
    }

    let _ = sys::reap_children_nonblock();
    Ok(pids)
}

/// Spawn `count` clean label-only decoys (exact `comm`, clean env, closed pipe
/// fds, no leaked secrets) replacing ad-hoc `sleep 1800` loops.
pub fn spawn_label_decoys(
    label: &str,
    comm: &str,
    count: usize,
    opts: &DecoySpawnOpts,
) -> Result<Vec<i32>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let comm_bytes = if comm.is_empty() {
        clamp_no_nul(label.as_bytes(), 15)
    } else {
        clamp_no_nul(comm.as_bytes(), 15)
    };
    let arg0 = if label.is_empty() {
        comm_bytes.clone()
    } else {
        label.as_bytes().to_vec()
    };
    let mut specs = Vec::with_capacity(count);
    for _ in 0..count {
        specs.push(DecoyNodeSpec {
            comm: comm_bytes.clone(),
            argv: vec![arg0.clone()],
            wchan_mode: 0,
            session_leader: !opts.same_session,
            ..DecoyNodeSpec::default()
        });
    }
    let sub = DecoySpawnOpts {
        clean_env: true,
        bind_exe: false,
        pidfile: None,
        wait: false,
        churn: 0,
        label_decoys: 0,
        interleave_cmd: None,
        ..opts.clone()
    };
    spawn_decoy_trees(&specs, &sub)
}

pub fn make_decoy_token(prefix: &str, rng: &mut crate::rng::Rng) -> Vec<u8> {
    let target_len = if prefix.len() < 32 {
        32
    } else {
        prefix.len() + 16
    };
    let mut out = vec![0u8; target_len];
    out[..prefix.len()].copy_from_slice(prefix.as_bytes());
    let hex_len = target_len - prefix.len();
    rng.hex(hex_len, &mut out[prefix.len()..]);
    out
}

#[inline(never)]
fn maybe_prepend_exec(cmd: &str) -> String {
    let t = cmd.trim();
    if t.is_empty()
        || t.starts_with("exec ")
        || t.starts_with("exec\t")
        || t.bytes()
            .any(|b| matches!(b, b';' | b'|' | b'&' | b'\n' | b'(' | b')' | b'`'))
    {
        return String::from(cmd);
    }
    let mut rest = t;
    while !rest.is_empty() {
        let off = t.len() - rest.len();
        let tok_len = rest
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let tok = &rest[..tok_len];
        let is_env = tok.split_once('=').is_some_and(|(k, _)| {
            !k.is_empty()
                && !tok.contains('\'')
                && !tok.contains('"')
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        });
        if !is_env {
            if tok == "exec" {
                return String::from(cmd);
            }
            return crate::json::cat3(&t[..off], "exec ", &t[off..]);
        }
        rest = rest[tok_len..].trim_start();
    }
    String::from(cmd)
}

#[inline(never)]
fn spawn_shell_child(cmd: &str, duration: u32, extra_env: Option<&[u8]>) -> Result<i32, String> {
    let sh = b"/bin/sh\0";
    let dash_c = b"-c\0";
    let effective = maybe_prepend_exec(cmd);
    let mut cmd_c = clamp_no_nul(effective.as_bytes(), 32768);
    cmd_c.push(0);

    let mut env_block = Vec::new();
    let mut entry = Vec::new();
    for (k, v) in std::env::vars_os() {
        let kb = k.as_bytes();
        if kb == stub::NONCE_ENV.as_bytes() {
            continue;
        }
        entry.clear();
        entry.extend_from_slice(kb);
        entry.push(b'=');
        entry.extend_from_slice(v.as_bytes());
        if !push_nul_bounded(&mut env_block, &entry, 65536) {
            break;
        }
    }
    if let Some(extra) = extra_env {
        let _ = push_nul_bounded(&mut env_block, extra, 65536);
    }

    let pid = sys::fork();
    if pid < 0 {
        return Err(String::from("fork failed"));
    }
    if pid == 0 {
        sys::setsid();
        redirect_stdio();
        sys::close_range_from(3);
        if duration > 0 {
            sys::alarm(duration);
        }
        let argv = [
            sh.as_ptr(),
            dash_c.as_ptr(),
            cmd_c.as_ptr(),
            std::ptr::null(),
        ];
        let (env_buf, env) = stub::build_envp_clean(&env_block);
        sys::execve(b"/bin/sh", &argv, &env);
        let _ = &env_buf;
        sys::exit(127);
    }
    Ok(pid)
}

/// Spawn `count` live decoy processes via an external `masker_cmd` shell command
/// template, applying seeded startup jitter and optional deterministic decoy
/// tokens (`{DECOY_TOKEN}` / `PSGEN_DECOY_TOKEN` and `{DURATION}`).
#[inline(never)]
pub fn spawn_masker_decoys(
    masker_cmd: &str,
    count: usize,
    duration: u32,
    jitter_ms: u32,
    seed: u64,
    decoy_token_prefix: Option<&str>,
) -> Result<Vec<i32>, String> {
    if masker_cmd.trim().is_empty() {
        return Err(String::from("masker_cmd is empty"));
    }
    let _ = sys::prctl_set_subreaper();
    let mut rng_state = seed ^ 0x517c_c1b7_2722_0a95;
    let mut tok_rng = crate::rng::Rng::new(rng_state);
    let dur_str = crate::json::u64_str(duration as u64);

    let mut pids = Vec::with_capacity(count);
    for _ in 0..count {
        sleep_jitter_ms(jitter_ms, &mut rng_state);
        let mut cmd = masker_cmd.replace("{DURATION}", &dur_str);
        let extra_env = if let Some(prefix) = decoy_token_prefix {
            let tok = make_decoy_token(prefix, &mut tok_rng);
            let tok_str = String::from_utf8_lossy(&tok);
            cmd = cmd.replace("{DECOY_TOKEN}", &tok_str);
            let mut kv = b"PSGEN_DECOY_TOKEN=".to_vec();
            kv.extend_from_slice(&tok);
            Some(kv)
        } else {
            None
        };
        let pid = spawn_shell_child(&cmd, duration, extra_env.as_deref())?;
        pids.push(pid);
        let _ = sys::reap_children_nonblock();
    }
    let _ = sys::reap_children_nonblock();
    Ok(pids)
}

fn kill_pids_now(pids: &[i32]) {
    for &pid in pids {
        let _ = sys::kill(pid, sys::SIGKILL);
    }
    let _ = sys::reap_children_nonblock();
}

/// Split `trees` at a seeded random rank in `[20%..80%]` and interleave
/// `target_cmd` with jitter and churn on both sides.
#[inline(never)]
pub fn spawn_decoy_trees_interleaved(
    trees: &[DecoyNodeSpec],
    target_cmd: &str,
    opts: &DecoySpawnOpts,
) -> Result<(Vec<i32>, i32, Vec<i32>), String> {
    let mut rng = opts.seed ^ 0x94d0_49bb_1331_11eb;
    let n = trees.len();
    let split = if n <= 1 {
        0
    } else {
        let lo = (n / 5).max(1);
        let hi = ((n * 4) / 5).max(lo).min(n - 1);
        lo + (decoy_rng_next(&mut rng) as usize % (hi - lo + 1))
    };
    spawn_interleaved_target(&trees[..split], target_cmd, &trees[split..], opts)
}

/// Spawn `prefix` decoy trees, then `target_cmd`, then `suffix` decoy trees so
/// the target's `starttime` and PID sit naturally inside the decoy distribution.
pub fn spawn_interleaved_target(
    prefix: &[DecoyNodeSpec],
    target_cmd: &str,
    suffix: &[DecoyNodeSpec],
    opts: &DecoySpawnOpts,
) -> Result<(Vec<i32>, i32, Vec<i32>), String> {
    if target_cmd.trim().is_empty() {
        return Err(String::from("target_cmd is empty"));
    }
    let _ = sys::prctl_set_subreaper();
    let mut rng = opts.seed ^ 0x2545_f491_4f6c_dd1d;

    let total_trees = prefix.len() + suffix.len();
    let pre_churn = (opts.churn as usize * prefix.len())
        .checked_div(total_trees)
        .map(|n| n as u32)
        .unwrap_or(opts.churn / 2);
    let mut sub_opts = DecoySpawnOpts {
        pidfile: None,
        wait: false,
        churn: pre_churn,
        interleave_cmd: None,
        ..opts.clone()
    };
    let prefix_pids = spawn_decoy_trees(prefix, &sub_opts)?;

    sleep_jitter_ms(opts.jitter_ms, &mut rng);
    let target_pid = match spawn_shell_child(target_cmd, opts.duration, None) {
        Ok(pid) => pid,
        Err(e) => {
            kill_pids_now(&prefix_pids);
            return Err(e);
        }
    };
    // Wait briefly for a multi-process target tree (e.g. supervisor -> payload)
    // to fork its child before starting suffix decoys so suffix spawns do not
    // interleave inside the target's own parent->child PID pair.
    if prefix
        .iter()
        .chain(suffix.iter())
        .any(|t| !t.children.is_empty())
    {
        let mut cpath = Buf::new();
        cpath.push_str("/proc/");
        cpath.push_u64(target_pid as u64);
        cpath.push_str("/task/");
        cpath.push_u64(target_pid as u64);
        cpath.push_str("/children");
        let mut buf = [0u8; 64];
        for _ in 0..50 {
            if let Some(n) = sys::read_file(cpath.as_bytes(), &mut buf) {
                if buf
                    .get(..n)
                    .is_some_and(|s| s.iter().any(|b| b.is_ascii_digit()))
                {
                    break;
                }
            }
            sys::nanosleep(0, 5_000_000);
        }
    }
    // Seeded jitter after target launch instead of a fixed 40ms gap.
    sleep_jitter_ms(opts.jitter_ms.max(5), &mut rng);

    sub_opts.churn = opts.churn.saturating_sub(pre_churn);
    sub_opts.seed = opts.seed ^ 0x517c_c1b7_2722_0a95;
    let suffix_pids = match spawn_decoy_trees(suffix, &sub_opts) {
        Ok(pids) => pids,
        Err(e) => {
            let _ = sys::kill(-target_pid, sys::SIGKILL);
            let _ = sys::kill(target_pid, sys::SIGKILL);
            kill_pids_now(&prefix_pids);
            return Err(e);
        }
    };

    if let Some(path) = &opts.pidfile {
        let mut all_decoys = Vec::with_capacity(prefix_pids.len() + suffix_pids.len());
        all_decoys.extend_from_slice(&prefix_pids);
        all_decoys.extend_from_slice(&suffix_pids);
        let nonce = random_hex(8);
        let (ok, _) = write_pidfile(path, &all_decoys, &[], &nonce);
        if !ok && !opts.quiet {
            sys::err(b"psgen: cannot write pidfile\n");
        }
    }

    let _ = sys::reap_children_nonblock();
    Ok((prefix_pids, target_pid, suffix_pids))
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

    #[test]
    fn pidfile_header_parser_distinguishes_comments_from_headers() {
        // `# note` before a valid header must not disarm header recognition.
        let p = parse_pidfile(b"# note\n# psgen 9.9.9 boot abc-123 nonce deadbeef\n42\t99\tfoo\n");
        assert_eq!(p.header_boot, Some(b"abc-123".to_vec()));
        assert_eq!(p.header_nonce, b"deadbeef".to_vec());
        assert_eq!(p.lines.len(), 1);

        // `# psgen-wrapper` and `# psgen: note` are ordinary comments, not
        // headers with empty boot IDs.
        let p = parse_pidfile(
            b"# psgen-wrapper\n# psgen 9.9.9 boot abc-123 nonce 01234567\n42\t99\tfoo\n",
        );
        assert_eq!(p.header_boot, Some(b"abc-123".to_vec()));
        assert_eq!(p.header_nonce, b"01234567".to_vec());

        let p = parse_pidfile(
            b"# psgen: generated by wrapper\n# psgen 9.9.9 boot abc-123 nonce 89abcdef\n42\t99\tfoo\n",
        );
        assert_eq!(p.header_boot, Some(b"abc-123".to_vec()));
        assert_eq!(p.header_nonce, b"89abcdef".to_vec());

        // Without a real header, `# psgen-wrapper` alone is not a header.
        let p = parse_pidfile(b"# psgen-wrapper\n42\t99\tfoo\n");
        assert_eq!(p.header_boot, None);

        // Leading blank lines before a valid header are allowed.
        let p = parse_pidfile(b"\n\n# psgen 9.9.9 boot xyz nonce cafe\n42\t99\tfoo\n");
        assert_eq!(p.header_boot, Some(b"xyz".to_vec()));
        assert_eq!(p.header_nonce, b"cafe".to_vec());

        // Legacy `# psgen 0.0.1` header without ` boot ` is still recognized as
        // a header (with empty boot id so `stop` refuses without `--force`).
        let p = parse_pidfile(b"# psgen 0.0.1\n42\t99\tfoo\n");
        assert_eq!(p.header_boot, Some(Vec::new()));

        // A header appearing after a content line must be ignored.
        let p = parse_pidfile(b"42\t99\tfoo\n# psgen 9.9.9 boot abc-123 nonce deadbeef\n");
        assert_eq!(p.header_boot, None);
        assert_eq!(p.lines.len(), 1);
    }

    #[test]
    fn estimated_pidfile_bytes_scales_with_rows_and_temps() {
        let base = estimated_pidfile_bytes(0, 0, 4);
        assert_eq!(base, pending_pidfile_len());
        let with_rows = estimated_pidfile_bytes(60, 0, 4);
        assert!(with_rows >= base + 60 * 48);
        let with_temps = estimated_pidfile_bytes(10, 5, 20);
        assert!(with_temps >= base + 5 * 68 + 10 * 48);
    }

    #[test]
    fn pidfile_lock_held_is_read_only_and_detects_active_lock() {
        let dir = std::env::temp_dir().join(format!(".psgen-lock-test-{}", sys::getpid()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("test.pid");
        let lockfile = dir.join("test.pid.lock");
        let pbytes = pidfile.as_os_str().as_bytes().to_vec();

        // Preview check must not create `.lock`.
        assert!(!pidfile_lock_held(&pbytes));
        assert!(!lockfile.exists());

        // While locked, `pidfile_lock_held` reports true and a second
        // `lock_pidfile` fails with WouldBlock.
        let lock = lock_pidfile(&pbytes).expect("acquire lock");
        assert!(pidfile_lock_held(&pbytes));
        assert_eq!(
            lock_pidfile(&pbytes).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::WouldBlock)
        );
        drop(lock);
        assert!(!pidfile_lock_held(&pbytes));

        // Symlink at `.lock` must be refused by O_NOFOLLOW.
        let _ = std::fs::remove_file(&lockfile);
        let target = dir.join("target");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &lockfile).unwrap();
        assert!(lock_pidfile(&pbytes).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_pid_sidecar_carries_temps_and_nonce_and_falls_back_to_tmpdir() {
        if util::boot_id().is_empty() {
            return;
        }
        let dir = std::env::temp_dir().join(format!(".psgen-sidecar-test-{}", sys::getpid()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let temp_entry = dir.join(".psgen-1-0-0");
        let nonce = b"deadbeef01234567";

        // 1. Writable parent: writes `<path>.spawned` beside the pidfile with
        // real `# temp` and real `nonce`.
        let pidfile = dir.join("run.pid");
        let pbytes = pidfile.as_os_str().as_bytes().to_vec();
        let side = write_pid_sidecar(
            &pbytes,
            &[sys::getpid()],
            std::slice::from_ref(&temp_entry),
            nonce,
        )
        .expect("sidecar beside writable parent");
        assert!(side.ends_with(b".spawned"));
        let body = std::fs::read(Path::new(std::ffi::OsStr::from_bytes(&side))).unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains(" nonce deadbeef01234567\n"), "{text}");
        assert!(
            text.contains(&format!("# temp {}\n", temp_entry.display())),
            "{text}"
        );

        // 2. Unwritable / absent parent: falls back to `TMPDIR/psgen-spawned-...pid`.
        let missing_parent_pid = dir.join("no-such-dir").join("run.pid");
        let mpbytes = missing_parent_pid.as_os_str().as_bytes().to_vec();
        let fallback = write_pid_sidecar(
            &mpbytes,
            &[sys::getpid()],
            std::slice::from_ref(&temp_entry),
            nonce,
        )
        .expect("fallback sidecar in temp_dir");
        let fb_path = Path::new(std::ffi::OsStr::from_bytes(&fallback));
        assert!(fb_path.exists());
        let fb_name = fb_path.file_name().unwrap().to_string_lossy();
        assert!(
            fb_name.starts_with("psgen-spawned-") && fb_name.ends_with(".pid"),
            "{fb_name}"
        );
        let fb_text = String::from_utf8_lossy(&std::fs::read(fb_path).unwrap()).into_owned();
        assert!(fb_text.contains(" nonce deadbeef01234567\n"), "{fb_text}");
        assert!(
            fb_text.contains(&format!("# temp {}\n", temp_entry.display())),
            "{fb_text}"
        );
        let _ = std::fs::remove_file(fb_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct PidGuard(Vec<i32>);
    impl Drop for PidGuard {
        fn drop(&mut self) {
            for &pid in &self.0 {
                if pid > 1 {
                    let _ = sys::kill(-pid, sys::SIGKILL);
                    let _ = sys::kill(pid, sys::SIGKILL);
                }
            }
            for &pid in &self.0 {
                if pid > 1 {
                    let mut st: i32 = 0;
                    unsafe {
                        libc::waitpid(pid, &mut st, libc::WNOHANG);
                    }
                }
            }
            let _ = sys::reap_children_nonblock();
        }
    }

    fn has_built_psgen_bin() -> bool {
        use std::io::Read;
        let Ok(cur) = std::env::current_exe() else {
            return false;
        };
        let Some(bin) = cur
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("psgen"))
        else {
            return false;
        };
        if !sys::access(bin.as_os_str().as_bytes(), libc::X_OK) {
            return false;
        }
        // Cross-arch release smoke jobs stage a foreign-arch static binary in
        // target/release/psgen and run it under qemu-user, where /proc/<pid>/exe
        // belongs to QEMU and seccomp/ptrace/dumpable are not emulated.
        let mut h_cur = [0u8; 20];
        let mut h_bin = [0u8; 20];
        let ok_cur = std::fs::File::open(&cur)
            .and_then(|mut f| f.read_exact(&mut h_cur))
            .is_ok();
        let ok_bin = std::fs::File::open(&bin)
            .and_then(|mut f| f.read_exact(&mut h_bin))
            .is_ok();
        ok_cur && ok_bin && h_cur[18..20] == h_bin[18..20]
    }

    fn scan_proc_mem_for_token(pid: i32, needle: &[u8]) -> (bool, bool) {
        use std::os::unix::fs::FileExt;
        let maps = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
            Ok(m) => m,
            Err(_) => return (false, false),
        };
        let mem = match std::fs::File::open(format!("/proc/{pid}/mem")) {
            Ok(f) => f,
            Err(_) => return (false, false),
        };
        let mut in_anon = false;
        let mut in_stack = false;
        for line in maps.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let perms = parts[1];
            if !perms.starts_with("rw") {
                continue;
            }
            let path = if parts.len() >= 6 { parts[5] } else { "" };
            let is_stack = path == "[stack]";
            let is_anon = path.is_empty() || path == "[heap]" || path.starts_with("[anon:");
            if !is_stack && !is_anon {
                continue;
            }
            let Some((s_hex, e_hex)) = parts[0].split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                u64::from_str_radix(s_hex, 16),
                u64::from_str_radix(e_hex, 16),
            ) else {
                continue;
            };
            let len = end.saturating_sub(start).min(2 * 1024 * 1024) as usize;
            if len == 0 {
                continue;
            }
            let mut buf = vec![0u8; len];
            if let Ok(n) = mem.read_at(&mut buf, start) {
                if buf[..n].windows(needle.len()).any(|w| w == needle) {
                    if is_stack {
                        in_stack = true;
                    } else {
                        in_anon = true;
                    }
                }
            }
        }
        (in_anon, in_stack)
    }

    #[test]
    fn profile_to_decoy_tree_excludes_main_thread_and_clamps_caps() {
        let mut p = crate::profile::synthetic_default_profile("ci-sup", true);
        p.identity.pid = 500;
        p.identity.exe = "/memfd:ci-runner (deleted)".to_string();
        p.identity.exe_memfd = Some("/memfd:ci-runner".to_string());
        p.dumpable = Some(false);
        p.status.no_new_privs = 1;
        p.status.seccomp = 2;
        p.status.seccomp_filters = 2;
        p.syscall.wchan = "ep_poll".to_string();
        p.task = vec![
            crate::profile::ProfileTask {
                tid: 500,
                comm: "ci-sup".to_string(),
                state: "S".to_string(),
            },
            crate::profile::ProfileTask {
                tid: 501,
                comm: "ci-w1".to_string(),
                state: "S".to_string(),
            },
            crate::profile::ProfileTask {
                tid: 502,
                comm: "ci-w2".to_string(),
                state: "S".to_string(),
            },
        ];
        if let Some(child) = p.children.first_mut() {
            child.status.tracer_pid = 500;
        }
        let huge_tok = vec![b'X'; 8192];
        let spec = profile_to_decoy_tree(&p, 6, Some(&huge_tok), 35);
        assert_eq!(
            spec.thread_comms,
            vec![b"ci-w1".to_vec(), b"ci-w2".to_vec()]
        );
        assert!(spec.exe_memfd);
        assert_eq!(spec.memfd_label, b"ci-runner");
        assert_eq!(spec.wchan_mode, 1);
        assert!(spec.non_dumpable);
        assert!(spec.no_new_privs);
        assert_eq!(spec.seccomp_filters, 2);
        assert!(spec.ptrace_children);
        assert_eq!(spec.jitter_ms, 35);
        assert!(spec.decoy_token.len() <= 4096);
        assert_eq!(spec.children.len(), 1);
        assert_eq!(parse_wchan_mode("epoll"), Some(1));
        assert_eq!(parse_wchan_mode("nanosleep"), Some(3));
        assert_eq!(parse_wchan_mode("futex"), Some(4));
        assert_eq!(parse_wchan_mode("read"), Some(5));
        assert_eq!(parse_wchan_mode("invalid"), None);
    }

    #[test]
    fn live_decoy_clean_env_memfd_seccomp_threads_wchan_token_and_stop() {
        if !has_built_psgen_bin() {
            return;
        }
        let dir = std::env::temp_dir().join(format!(".psgen-decoy-live-{}", sys::getpid()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("decoys.pid");
        let pf_bytes = pidfile.as_os_str().as_bytes().to_vec();

        let token = b"TOK_LIVE_DECOY_0123456789abcdef!";
        let child_spec = DecoyNodeSpec {
            comm: b"ci-pay".to_vec(),
            argv: vec![b"ci-pay".to_vec(), b"--run".to_vec()],
            exe_memfd: true,
            memfd_label: b"ci-payload".to_vec(),
            cwd: b"/tmp".to_vec(),
            environ: vec![b"ROLE=payload".to_vec()],
            wchan_mode: 4, // futex
            no_new_privs: true,
            seccomp_filters: 1,
            decoy_token: b"TOK_CHILD_DECOY_fedcba9876543210".to_vec(),
            ..DecoyNodeSpec::default()
        };
        let root_spec = DecoyNodeSpec {
            comm: b"ci-sup".to_vec(),
            argv: vec![b"ci-sup".to_vec()],
            cmdline_raw_nuls: Some(3),
            exe_memfd: true,
            memfd_label: b"ci-runner".to_vec(),
            cwd: b"/tmp".to_vec(),
            environ: vec![b"APP_ENV=prod".to_vec(), b"WORKER_ID=7".to_vec()],
            thread_comms: vec![b"ci-w1".to_vec(), b"ci-w2".to_vec()],
            fd_specs: vec![(6, b"pipe".to_vec()), (7, b"eventfd".to_vec())],
            wchan_mode: 3, // nanosleep
            no_new_privs: true,
            seccomp_filters: 2,
            non_dumpable: false,
            decoy_token: token.to_vec(),
            children: vec![child_spec],
            ..DecoyNodeSpec::default()
        };

        let opts = DecoySpawnOpts {
            duration: 30,
            pidfile: Some(pf_bytes.clone()),
            clean_env: true,
            jitter_ms: 15,
            churn: 3,
            seed: 42,
            quiet: true,
            wait: false,
            bind_exe: false,
            ..DecoySpawnOpts::default()
        };
        let pids = spawn_decoy_trees(&[root_spec], &opts).expect("spawn decoy tree");
        let _guard = PidGuard(pids.clone());
        assert_eq!(pids.len(), 2, "expected supervisor + child pids: {pids:?}");

        let (root_pid, child_pid) = if live::read_comm(pids[0]).as_deref() == Some(b"ci-sup") {
            (pids[0], pids[1])
        } else {
            (pids[1], pids[0])
        };

        // 1. comm & NUL-padded cmdline
        assert_eq!(live::read_comm(root_pid).as_deref(), Some(&b"ci-sup"[..]));
        let cmdline = std::fs::read(format!("/proc/{root_pid}/cmdline")).unwrap();
        assert_eq!(cmdline, b"ci-sup\0\0\0");

        // 2. F_CLEAN_ENV: zero PSGEN_NONCE, cloned environ present
        let env_raw = std::fs::read(format!("/proc/{root_pid}/environ")).unwrap();
        let env_str = String::from_utf8_lossy(&env_raw);
        assert!(!env_str.contains("PSGEN_NONCE"), "leaked nonce: {env_str}");
        assert!(env_str.contains("APP_ENV=prod"), "missing env: {env_str}");
        assert!(env_str.contains("WORKER_ID=7"), "missing env: {env_str}");

        // 3. F_EXE_MEMFD
        let exe_link = std::fs::read_link(format!("/proc/{root_pid}/exe")).unwrap();
        let exe_s = exe_link.to_string_lossy();
        assert!(
            exe_s.starts_with("/memfd:ci-runner"),
            "unexpected exe: {exe_s}"
        );

        // 4. cwd
        let cwd_link = std::fs::read_link(format!("/proc/{root_pid}/cwd")).unwrap();
        assert_eq!(cwd_link.to_string_lossy(), "/tmp");

        // 5. Seccomp_filters, NoNewPrivs, Threads == 3
        let status = std::fs::read_to_string(format!("/proc/{root_pid}/status")).unwrap();
        assert!(status.contains("Threads:\t3\n"), "{status}");
        assert!(status.contains("NoNewPrivs:\t1\n"), "{status}");
        assert!(status.contains("Seccomp:\t2\n"), "{status}");
        assert!(status.contains("Seccomp_filters:\t2\n"), "{status}");

        // 6. Exact multi-thread comms
        let mut task_comms: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/{root_pid}/task")).unwrap() {
            let entry = entry.unwrap();
            let c = std::fs::read_to_string(entry.path().join("comm")).unwrap();
            task_comms.push(c.trim().to_string());
        }
        task_comms.sort();
        assert_eq!(task_comms, vec!["ci-sup", "ci-w1", "ci-w2"]);

        // 7. wchan (nanosleep)
        if let Ok(wchan) = std::fs::read_to_string(format!("/proc/{root_pid}/wchan")) {
            let w = wchan.trim();
            if !w.is_empty() && w != "0" {
                assert!(
                    w.contains("nanosleep") || w.contains("hrtimer") || w.contains("do_nanosleep"),
                    "unexpected wchan: {w}"
                );
            }
        }

        // 8. Decoy token present in both anon rw-p AND [stack]
        let (in_anon, in_stack) = scan_proc_mem_for_token(root_pid, token);
        assert!(in_anon, "decoy token not found in anonymous rw-p memory");
        assert!(in_stack, "decoy token not found in [stack]");

        // 9. Child ppid and memfd exe
        let child_stat = live::read_stat(child_pid).expect("child stat");
        assert_eq!(child_stat.ppid as i32, root_pid);
        let child_exe = std::fs::read_link(format!("/proc/{child_pid}/exe")).unwrap();
        assert!(
            child_exe.to_string_lossy().starts_with("/memfd:ci-payload"),
            "unexpected child exe: {}",
            child_exe.display()
        );

        // 10. stop via 3-field pidfile and verify zero zombies
        assert_eq!(stop(&pf_bytes, false, false, true), 0);
        for _ in 0..50 {
            let _ = sys::reap_children_nonblock();
            if pids.iter().all(|&pid| live::read_stat(pid).is_none()) {
                break;
            }
            sys::nanosleep(0, 10_000_000);
        }
        for &pid in &pids {
            assert!(
                live::read_stat(pid).is_none(),
                "pid {pid} still exists or is zombie after stop"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_non_dumpable_eacces_and_stop_compatibility() {
        if !has_built_psgen_bin() {
            return;
        }
        let dir = std::env::temp_dir().join(format!(".psgen-nondump-{}", sys::getpid()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("nondump.pid");
        let pf_bytes = pidfile.as_os_str().as_bytes().to_vec();

        let spec = DecoyNodeSpec {
            comm: b"stealth-d".to_vec(),
            argv: vec![b"stealth-d".to_vec()],
            exe_memfd: true,
            memfd_label: b"stealth-bin".to_vec(),
            non_dumpable: true,
            no_new_privs: true,
            seccomp_filters: 2,
            wchan_mode: 1, // epoll
            ..DecoyNodeSpec::default()
        };
        let opts = DecoySpawnOpts {
            duration: 30,
            pidfile: Some(pf_bytes.clone()),
            clean_env: true,
            ..DecoySpawnOpts::default()
        };
        let pids = spawn_decoy_trees(&[spec], &opts).expect("spawn non-dumpable decoy");
        let _guard = PidGuard(pids.clone());
        assert_eq!(pids.len(), 1);
        let pid = pids[0];

        if sys::geteuid() != 0 {
            let mem_err = std::fs::File::open(format!("/proc/{pid}/mem")).unwrap_err();
            assert_eq!(
                mem_err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected EACCES on /proc/{pid}/mem: {mem_err}"
            );
            let env_err = std::fs::read(format!("/proc/{pid}/environ")).unwrap_err();
            assert_eq!(
                env_err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected EACCES on /proc/{pid}/environ: {env_err}"
            );
        }

        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(status.contains("Seccomp:\t2\n"), "{status}");
        assert!(status.contains("Seccomp_filters:\t2\n"), "{status}");

        // 3-field pidfile stop must succeed even for non-dumpable stubs
        assert_eq!(stop(&pf_bytes, false, false, true), 0);
        for _ in 0..50 {
            let _ = sys::reap_children_nonblock();
            if live::read_stat(pid).is_none() {
                break;
            }
            sys::nanosleep(0, 10_000_000);
        }
        assert!(live::read_stat(pid).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_interleaved_target_and_masker_decoys() {
        if !has_built_psgen_bin() {
            return;
        }
        let make_spec = |name: &[u8]| DecoyNodeSpec {
            comm: name.to_vec(),
            argv: vec![name.to_vec()],
            wchan_mode: 0,
            ..DecoyNodeSpec::default()
        };
        let opts = DecoySpawnOpts {
            duration: 20,
            clean_env: true,
            jitter_ms: 10,
            churn: 2,
            seed: 99,
            ..DecoySpawnOpts::default()
        };
        let (pre, tgt, suf) = spawn_interleaved_target(
            &[make_spec(b"pre-d")],
            "exec /bin/sleep 20",
            &[make_spec(b"suf-d")],
            &opts,
        )
        .expect("spawn interleaved target");
        let mut all = Vec::new();
        all.extend_from_slice(&pre);
        all.push(tgt);
        all.extend_from_slice(&suf);
        let _guard = PidGuard(all);
        assert_eq!(pre.len(), 1);
        assert!(tgt > 1);
        assert_eq!(suf.len(), 1);

        let masker_pids =
            spawn_masker_decoys("exec /bin/sleep {DURATION}", 2, 20, 5, 77, Some("TOK-"))
                .expect("spawn masker decoys");
        let _mguard = PidGuard(masker_pids.clone());
        assert_eq!(masker_pids.len(), 2);
        // Wait briefly for /bin/sh -> exec /bin/sleep to settle
        sys::nanosleep(0, 50_000_000);
        let env = std::fs::read(format!("/proc/{}/environ", masker_pids[0])).unwrap();
        let env_s = String::from_utf8_lossy(&env);
        assert!(env_s.contains("PSGEN_DECOY_TOKEN=TOK-"), "{env_s}");
        assert!(!env_s.contains("PSGEN_NONCE="), "{env_s}");
    }

    fn parse_status_kb_field(status: &str, key: &str) -> u64 {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix(key) {
                if let Some(tok) = rest.split_whitespace().next() {
                    if let Ok(v) = tok.parse::<u64>() {
                        return v;
                    }
                }
            }
        }
        0
    }

    #[test]
    fn maybe_prepend_exec_handles_simple_env_and_compound() {
        assert_eq!(maybe_prepend_exec("/bin/sleep 10"), "exec /bin/sleep 10");
        assert_eq!(
            maybe_prepend_exec("exec /bin/sleep 10"),
            "exec /bin/sleep 10"
        );
        assert_eq!(
            maybe_prepend_exec("FOO=1 BAR=baz /bin/sleep 10"),
            "FOO=1 BAR=baz exec /bin/sleep 10"
        );
        assert_eq!(
            maybe_prepend_exec("/bin/true && /bin/sleep 10"),
            "/bin/true && /bin/sleep 10"
        );
        assert_eq!(
            maybe_prepend_exec("echo hi; /bin/sleep 10"),
            "echo hi; /bin/sleep 10"
        );
    }

    #[test]
    fn live_synchronized_ptrace_seize_and_non_dumpable() {
        if !has_built_psgen_bin() {
            return;
        }
        let child_spec = DecoyNodeSpec {
            comm: b"traced-c".to_vec(),
            argv: vec![b"traced-c".to_vec()],
            exe_memfd: true,
            memfd_label: b"traced-c".to_vec(),
            non_dumpable: true,
            wchan_mode: 1,
            ..DecoyNodeSpec::default()
        };
        let root_spec = DecoyNodeSpec {
            comm: b"tracer-p".to_vec(),
            argv: vec![b"tracer-p".to_vec()],
            exe_memfd: true,
            memfd_label: b"tracer-p".to_vec(),
            non_dumpable: true,
            ptrace_children: true,
            wchan_mode: 1,
            children: vec![child_spec],
            ..DecoyNodeSpec::default()
        };
        let opts = DecoySpawnOpts {
            duration: 30,
            clean_env: true,
            ..DecoySpawnOpts::default()
        };
        let pids = spawn_decoy_trees(&[root_spec], &opts).expect("spawn traced non-dumpable tree");
        let _guard = PidGuard(pids.clone());
        assert_eq!(pids.len(), 2, "expected parent + child pids: {pids:?}");

        let (root_pid, child_pid) = if live::read_comm(pids[0]).as_deref() == Some(b"tracer-p") {
            (pids[0], pids[1])
        } else {
            (pids[1], pids[0])
        };

        let child_status = std::fs::read_to_string(format!("/proc/{child_pid}/status")).unwrap();
        let tracer_pid = parse_status_kb_field(&child_status, "TracerPid:") as i32;
        assert_eq!(
            tracer_pid, root_pid,
            "expected child TracerPid == root_pid ({root_pid}), got {tracer_pid}\n{child_status}"
        );
        if sys::geteuid() != 0 {
            let c_env = std::fs::read(format!("/proc/{child_pid}/environ")).unwrap_err();
            assert_eq!(
                c_env.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected EACCES on non-dumpable seized child environ: {c_env}"
            );
            let p_env = std::fs::read(format!("/proc/{root_pid}/environ")).unwrap_err();
            assert_eq!(
                p_env.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected EACCES on non-dumpable parent environ: {p_env}"
            );
        }
    }

    #[test]
    fn live_vm_lck_rss_shmem_and_delta_memory_parity() {
        if !has_built_psgen_bin() {
            return;
        }
        let dir = std::env::temp_dir().join(format!(".psgen-mempar-{}", sys::getpid()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ro_file = dir.join("shared-rss.dat");
        std::fs::write(&ro_file, vec![0x33u8; 2 * 1024 * 1024]).unwrap();

        let spec = DecoyNodeSpec {
            comm: b"mem-par".to_vec(),
            argv: vec![b"mem-par".to_vec()],
            rss_kb: 2048,
            rss_file_kb: 2048,
            vsz_kb: 16384,
            vm_lck_kb: 16,
            rss_shmem_kb: 64,
            map_files: vec![ro_file.as_os_str().as_bytes().to_vec()],
            wchan_mode: 0,
            ..DecoyNodeSpec::default()
        };
        let opts = DecoySpawnOpts {
            duration: 30,
            clean_env: true,
            ..DecoySpawnOpts::default()
        };
        let pids = spawn_decoy_trees(&[spec], &opts).expect("spawn mem parity decoy");
        let _guard = PidGuard(pids.clone());
        assert_eq!(pids.len(), 1);
        let pid = pids[0];

        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let vm_lck = parse_status_kb_field(&status, "VmLck:");
        let rss_shmem = parse_status_kb_field(&status, "RssShmem:");
        let rss_anon = parse_status_kb_field(&status, "RssAnon:");
        let vm_rss = parse_status_kb_field(&status, "VmRSS:");
        let vm_size = parse_status_kb_field(&status, "VmSize:");

        assert!(
            rss_shmem >= 64,
            "expected RssShmem >= 64 kB, got {rss_shmem}\n{status}"
        );
        assert!(
            vm_rss >= 1900,
            "expected VmRSS >= 1900 kB, got {vm_rss}\n{status}"
        );
        assert!(
            rss_anon < 1024,
            "expected zero-burn low RssAnon < 1024 kB, got {rss_anon}\n{status}"
        );
        assert!(
            vm_size >= 16000,
            "expected VmSize >= 16000 kB, got {vm_size}\n{status}"
        );

        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) } == 0
            && (rl.rlim_cur == libc::RLIM_INFINITY || rl.rlim_cur >= 16 * 1024)
        {
            assert!(
                vm_lck >= 16,
                "expected VmLck >= 16 kB under RLIMIT_MEMLOCK={}, got {vm_lck}\n{status}",
                rl.rlim_cur
            );
        }

        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
        assert!(
            !maps.contains("memfd:cache"),
            "clean_env decoy leaked memfd:cache into maps:\n{maps}"
        );
        assert!(
            maps.contains("shared-rss.dat"),
            "expected shared-rss.dat in maps:\n{maps}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_sequential_per_tree_adjacent_pids_and_target_ppid() {
        if !has_built_psgen_bin() {
            return;
        }
        let make_tree = |p_name: &[u8], c_name: &[u8]| DecoyNodeSpec {
            comm: p_name.to_vec(),
            argv: vec![p_name.to_vec()],
            children: vec![DecoyNodeSpec {
                comm: c_name.to_vec(),
                argv: vec![c_name.to_vec()],
                ..DecoyNodeSpec::default()
            }],
            ..DecoyNodeSpec::default()
        };
        let trees = vec![
            make_tree(b"seq-p0", b"seq-c0"),
            make_tree(b"seq-p1", b"seq-c1"),
            make_tree(b"seq-p2", b"seq-c2"),
        ];
        let opts = DecoySpawnOpts {
            duration: 30,
            clean_env: true,
            ..DecoySpawnOpts::default()
        };
        let pids = spawn_decoy_trees(&trees, &opts).expect("spawn sequential trees");
        let _guard = PidGuard(pids.clone());
        assert_eq!(pids.len(), 6, "expected 3 parent+child pairs: {pids:?}");

        let mut pairs: Vec<(i32, i32)> = Vec::new();
        for &pid in &pids {
            let st = live::read_stat(pid).expect("stat");
            let ppid = st.ppid as i32;
            if pids.contains(&ppid) {
                pairs.push((ppid, pid));
            }
        }
        assert_eq!(pairs.len(), 3, "expected 3 parent->child pairs: {pairs:?}");
        pairs.sort_by_key(|&(p, _)| p);
        for i in 0..pairs.len() {
            let (ppid, cpid) = pairs[i];
            assert!(
                cpid > ppid,
                "expected child PID > parent PID: ({ppid}, {cpid})"
            );
            if i + 1 < pairs.len() {
                let (next_ppid, _) = pairs[i + 1];
                assert!(
                    cpid < next_ppid,
                    "expected sequential tree PIDs (child {cpid} < next root {next_ppid}): {pairs:?}"
                );
            }
        }

        // Also verify interleaved target_cmd without explicit "exec " replaces /bin/sh
        // so its PPid matches our PID (same PPid as decoy roots).
        let (pre, tgt, suf) = spawn_interleaved_target(
            &[make_tree(b"pre-p", b"pre-c")],
            "/bin/sleep 20",
            &[make_tree(b"suf-p", b"suf-c")],
            &opts,
        )
        .expect("spawn interleaved target without exec");
        let mut all = Vec::new();
        all.extend_from_slice(&pre);
        all.push(tgt);
        all.extend_from_slice(&suf);
        let _guard2 = PidGuard(all);
        let tgt_st = live::read_stat(tgt).expect("target stat");
        assert_eq!(
            tgt_st.ppid as i32,
            sys::getpid(),
            "target PPid must match psgen PID"
        );
        let mut seen_comm = None;
        for _ in 0..40 {
            seen_comm = live::read_comm(tgt);
            if seen_comm.as_deref() == Some(&b"sleep"[..]) {
                break;
            }
            sys::nanosleep(0, 5_000_000);
        }
        assert_eq!(
            seen_comm.as_deref(),
            Some(&b"sleep"[..]),
            "expected /bin/sh to exec sleep directly"
        );
    }

    #[test]
    fn live_track_c_fidelity_comm_spaces_nul_env_redacted_dumpable_maps_and_parent_tree() {
        if !has_built_psgen_bin() {
            return;
        }
        let dir = std::env::temp_dir().join(format!(".psgen-trackc-{}", sys::getpid()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("trackc.pid");
        let pf_bytes = pidfile.as_os_str().as_bytes().to_vec();
        let map_file = dir.join("shared-lib.dat");
        std::fs::write(&map_file, vec![0x42u8; 16384]).unwrap();

        // Build a dumpable profile with trailing-space comm, all-NUL environ,
        // <REDACTED:len=16> in argv, anon-only token placement, a captured
        // parent supervisor, and a readable regular map file.
        let mut parent_p = crate::profile::synthetic_default_profile("sup-parent", false);
        parent_p.identity.pid = 700;
        parent_p.identity.comm = "sup-parent".to_string();
        parent_p.dumpable = Some(true);
        parent_p.status.no_new_privs = 0;
        parent_p.status.seccomp = 0;
        parent_p.status.seccomp_filters = sys::self_seccomp_filters();
        parent_p.syscall.wchan = "do_wait".to_string();
        parent_p.memory.token_present = false;

        let mut leaf_p = crate::profile::synthetic_default_profile("ci-runner", false);
        leaf_p.identity.pid = 701;
        leaf_p.identity.ppid = 700;
        leaf_p.identity.comm = "ci-runner      ".to_string(); // exact 15B space-padded
        leaf_p.identity.argv = vec!["ci-runner".to_string(), "<REDACTED:len=16>".to_string()];
        leaf_p.dumpable = Some(true);
        leaf_p.status.no_new_privs = 0;
        leaf_p.status.seccomp = 0;
        leaf_p.status.seccomp_filters = sys::self_seccomp_filters();
        leaf_p.environ.clear();
        leaf_p.environ_raw_len = 64;
        leaf_p.environ_all_nul = true;
        leaf_p.memory.token_present = true;
        leaf_p.memory.token_len = Some(16);
        leaf_p.memory.token_charset = Some("hex".to_string());
        leaf_p.memory.token_placements = vec!["anon".to_string()];
        leaf_p.memory.maps = vec![format!(
            "7f0000000000-7f0000004000 r--p 00000000 00:00 1 {}",
            map_file.display()
        )];
        leaf_p.parent = Some(Box::new(parent_p));

        let spec = profile_to_decoy_tree(&leaf_p, 6, None, 0);
        assert_eq!(spec.comm, b"sup-parent");
        assert_eq!(spec.wchan_mode, stub::WCHAN_WAIT4);
        assert_eq!(spec.children.len(), 1);
        let cspec = &spec.children[0];
        assert_eq!(cspec.comm, b"ci-runner      ");
        assert!(!cspec.non_dumpable, "dumpable target must not invert");
        assert!(!cspec.no_new_privs, "nnp=0 target with delta=0 must stay 0");
        assert_eq!(cspec.seccomp_filters, 0);
        assert_eq!(cspec.env_nul_len, 64);
        assert_eq!(cspec.token_placements_mask, stub::TOK_PLACE_ANON);
        assert_eq!(cspec.decoy_token.len(), 16);
        let arg1 = String::from_utf8_lossy(&cspec.argv[1]);
        assert!(
            !arg1.contains("<REDACTED"),
            "redacted marker leaked: {arg1}"
        );
        assert_eq!(arg1.len(), 16);
        let tok_copy = cspec.decoy_token.clone();

        let opts = DecoySpawnOpts {
            duration: 30,
            pidfile: Some(pf_bytes.clone()),
            clean_env: true,
            bind_exe: false,
            ..DecoySpawnOpts::default()
        };
        let pids = spawn_decoy_trees(&[spec], &opts).expect("spawn track c tree");
        let _guard = PidGuard(pids.clone());
        assert_eq!(pids.len(), 2, "expected parent + child pids: {pids:?}");

        let (sup_pid, leaf_pid) =
            if live::read_comm_exact(pids[0]).as_deref() == Some(b"sup-parent") {
                (pids[0], pids[1])
            } else {
                (pids[1], pids[0])
            };

        // 1. Exact 15B trailing-space comm preserved.
        assert_eq!(
            live::read_comm_exact(leaf_pid).as_deref(),
            Some(&b"ci-runner      "[..])
        );
        // 2. Parent->child PPid preserved (NOT reparented to PPid=1).
        let leaf_stat = live::read_stat(leaf_pid).expect("leaf stat");
        assert_eq!(leaf_stat.ppid as i32, sup_pid);
        // 3. Dumpable preserved (readable /proc/<pid>/environ and NoNewPrivs: 0).
        let env_raw = std::fs::read(format!("/proc/{leaf_pid}/environ")).unwrap();
        assert_eq!(env_raw.len(), 64, "expected 64B all-NUL environ");
        assert!(
            env_raw.iter().all(|&b| b == 0),
            "expected all-NUL environ, got {env_raw:?}"
        );
        let status = std::fs::read_to_string(format!("/proc/{leaf_pid}/status")).unwrap();
        assert!(status.contains("NoNewPrivs:\t0\n"), "{status}");
        // 3b. Redacted argv marker was substituted with exact 16-byte token (never literal <REDACTED>).
        let cmd_raw = std::fs::read(format!("/proc/{leaf_pid}/cmdline")).unwrap();
        let cmd_s = String::from_utf8_lossy(&cmd_raw);
        assert!(
            !cmd_s.contains("<REDACTED"),
            "literal <REDACTED> leaked into cmdline: {cmd_s}"
        );
        // 4. Token present in anon rw-p ONLY (not as a stack local outside argv/env).
        let (in_anon, _) = scan_proc_mem_for_token(leaf_pid, &tok_copy);
        assert!(in_anon, "expected anon-only token in anon rw-p");
        // Verify a pure anon-only token (absent from argv) is NOT placed in [stack].
        let mut anon_only_p = crate::profile::synthetic_default_profile("anon-tok", false);
        anon_only_p.dumpable = Some(true);
        anon_only_p.status.seccomp_filters = sys::self_seccomp_filters();
        anon_only_p.memory.token_present = true;
        anon_only_p.memory.token_len = Some(20);
        anon_only_p.memory.token_charset = Some("hex".to_string());
        anon_only_p.memory.token_placements = vec!["anon".to_string()];
        let anon_spec = profile_to_decoy_tree(&anon_only_p, 6, None, 0);
        let anon_tok = anon_spec.decoy_token.clone();
        assert_eq!(anon_tok.len(), 20);
        let anon_pids = spawn_decoy_trees(
            &[anon_spec],
            &DecoySpawnOpts {
                duration: 30,
                clean_env: true,
                bind_exe: false,
                ..DecoySpawnOpts::default()
            },
        )
        .expect("spawn anon-only decoy");
        let _anon_guard = PidGuard(anon_pids.clone());
        let (a_anon, a_stack) = scan_proc_mem_for_token(anon_pids[0], &anon_tok);
        assert!(a_anon, "expected pure anon-only token in anon rw-p");
        assert!(
            !a_stack,
            "pure anon-only token must not be placed in [stack]"
        );
        // 5. Zero-burn read-only file mapping present in /proc/<pid>/maps.
        let maps = std::fs::read_to_string(format!("/proc/{leaf_pid}/maps")).unwrap();
        assert!(
            maps.contains("shared-lib.dat"),
            "expected shared-lib.dat in maps:\n{maps}"
        );
        // 6. stop via 3-field pidfile cleans up both parent & trailing-space child.
        assert_eq!(stop(&pf_bytes, false, false, true), 0);
        for _ in 0..50 {
            let _ = sys::reap_children_nonblock();
            if pids.iter().all(|&pid| live::read_stat(pid).is_none()) {
                break;
            }
            sys::nanosleep(0, 10_000_000);
        }
        for &pid in &pids {
            assert!(live::read_stat(pid).is_none(), "pid {pid} still alive");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
