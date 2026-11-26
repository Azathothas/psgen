//! The injected-process stub.
//!
//! `psgen inject` forks and re-executes this same binary with the fake
//! command line as argv. The child finds a configuration file descriptor on
//! fd 3 and turns itself into a sleeping process with the requested name,
//! user, virtual size, resident size, tty, thread count and executable path.
//!
//! The executable path is the one part the kernel does not let a process
//! change after exec. When a bind is available, the stub creates a private
//! mount namespace, binds its own binary at the template path, and
//! re-executes through that path. The bind is made private before it is
//! created, so it never reaches the host.

use crate::corpus;
use crate::str::Buf;
use crate::sys;
use crate::util;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const CFG_MAGIC: &[u8; 8] = b"PGCFG023";
/// Single unified wire format carrying all stub and decoy fidelity fields.
const CFG_VERSION: u32 = 5;
const CFG_HEADER: usize = 160;
const CFG_STAGE_OFF: u64 = 40;
const MAX_FDS: usize = 512;

/// Marks the root of a spawned subtree in `Config::flags`.
pub const F_ROOT: u32 = 1 << 8;
/// Decoy clean-env mode: never place `PSGEN_NONCE` in `environ` and use
/// zero-burn file-backed maps / untouched VmSize padding.
pub const F_CLEAN_ENV: u32 = 1 << 9;
/// Copy `/proc/self/exe` into a labeled memfd and re-exec via `execveat` or `/dev/fd/N`.
pub const F_EXE_MEMFD: u32 = 1 << 10;
/// Set `PR_SET_DUMPABLE(0)` after setup so same-UID `/proc/<pid>/mem` reads fail.
pub const F_NON_DUMPABLE: u32 = 1 << 11;
/// Set `PR_SET_NO_NEW_PRIVS(1)` after setup.
pub const F_NO_NEW_PRIVS: u32 = 1 << 12;
/// Best-effort `PTRACE_SEIZE` on direct child stubs after they settle.
pub const F_PTRACE_CHILDREN: u32 = 1 << 13;
/// Child waits for parent `PTRACE_SEIZE` (`TracerPid != 0`) before `PR_SET_DUMPABLE(0)`.
pub const F_WAIT_TRACER: u32 = 1 << 14;
/// Set by the injector when the stub runs in a user namespace it creates.
/// The uid switch is skipped there: the namespace already maps ns-uid 0 to
/// the caller, and the target uid is not mapped.
pub const F_USERNS: u32 = 1 << 30;

/// Token placement bitmask for `Config::token_placements_mask`.
pub const TOK_PLACE_ANON: u8 = 1 << 0;
pub const TOK_PLACE_HEAP: u8 = 1 << 1;
pub const TOK_PLACE_STACK: u8 = 1 << 2;

/// `AT_EXECFN` replication modes for `Config::execfn_mode`.
pub const EXECFN_PATH: u8 = 0;
pub const EXECFN_EMPTY: u8 = 1;
pub const EXECFN_DEVFD: u8 = 2;

/// Wait channel mode for blocking `wait4(-1, ...)` (`do_wait`).
pub const WCHAN_WAIT4: u8 = 6;

/// Deviation bits the stub reports back when a setup step did not take.
/// A row that deviates keeps running; the bit says which part is a lie.
pub const DEV_TTY: u32 = 1;
pub const DEV_RSS: u32 = 2;
pub const DEV_VSZ: u32 = 4;
pub const DEV_USER: u32 = 8;
pub const DEV_EXE: u32 = 16;
pub const DEV_DISK: u32 = 32;

pub const SYS_OPEN_TREE: libc::c_long = 428;
pub const SYS_MOVE_MOUNT: libc::c_long = 429;
pub const AT_FDCWD: libc::c_long = -100;
pub const OPEN_TREE_CLONE: libc::c_long = 1;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_long = 4;

#[derive(Default)]
pub struct Config {
    pub flags: u32,
    pub vsz_kb: u32,
    pub rss_kb: u32,
    pub uid: u32,
    pub gid: u32,
    pub duration: u32,
    pub cpu: u32,
    pub stage: u32,
    pub comm: Vec<u8>,
    pub exe: Vec<u8>,
    pub cmd: Vec<u8>,
    pub user: Vec<u8>,
    pub temp: Vec<u8>,
    pub disk_kb: u32,
    pub self_copy: Vec<u8>,
    /// Per-run tag matched against the sealed config memfd name `pg:<nonce>`.
    pub nonce: Vec<u8>,
    pub child_fds: Vec<i32>,
    pub keep_fds: Vec<i32>,
    pub max_fd: i32,
    pub arena_fd: i32,
    pub status_fd: i32,
    pub id: u32,
    pub cwd: Vec<u8>,
    pub env_block: Vec<u8>,
    pub env_nul_len: u32,
    pub memfd_label: Vec<u8>,
    pub decoy_token: Vec<u8>,
    pub token_placements_mask: u8,
    pub thread_comms: Vec<u8>,
    pub thread_wchans: Vec<u8>,
    pub fd_specs: Vec<u8>,
    pub map_files: Vec<u8>,
    pub wchan_mode: u8,
    pub seccomp_filters: u8,
    pub execfn_mode: u8,
    pub execfn_fd: i32,
    pub jitter_ms: u32,
    pub vm_lck_kb: u32,
    pub rss_shmem_kb: u32,
    pub rss_file_kb: u32,
}

#[cfg(test)]
fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn read_bytes(fd: i32, off: u64, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    let mut v = vec![0u8; len];
    let n = sys::pread_fd(fd, &mut v, off);
    if n < len as isize {
        return None;
    }
    Some(v)
}

struct CfgReader {
    fd: i32,
    off: u64,
}

impl CfgReader {
    fn read_capped(&mut self, len: usize, cap: usize) -> Option<Vec<u8>> {
        if len > cap {
            return None;
        }
        let v = read_bytes(self.fd, self.off, len)?;
        self.off += len as u64;
        Some(v)
    }

    fn read_fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut buf = [0u8; N];
        if sys::pread_fd(self.fd, &mut buf, self.off) < N as isize {
            return None;
        }
        self.off += N as u64;
        Some(buf)
    }
}

fn read_i32_vec(buf: &[u8]) -> Vec<i32> {
    buf.chunks_exact(4)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

#[inline(never)]
fn read_capped_fd(r: &mut CfgReader, len: usize, cap: usize) -> Option<Vec<u8>> {
    r.read_capped(len, cap)
}

#[inline(never)]
fn next_vec(it: &mut std::vec::IntoIter<Vec<u8>>) -> Vec<u8> {
    it.next().unwrap_or_default()
}

#[inline(never)]
pub fn read_config(fd: i32) -> Option<Config> {
    const CAPS: [u32; 15] = [
        64, 4096, 4096, 64, 4096, 4096, 64, 4096, 65536, 256, 4096, 4096, 64, 32768, 32768,
    ];
    let mut r = CfgReader { fd, off: 0 };
    let hdr = r.read_fixed::<CFG_HEADER>()?;
    if &hdr[..8] != CFG_MAGIC {
        return None;
    }
    let mut w = [0u32; 38];
    for (slot, c) in w.iter_mut().zip(hdr[8..].chunks_exact(4)) {
        *slot = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    if w[0] != CFG_VERSION {
        return None;
    }
    let max_fd = w[9] as i32;
    let packed = w[14];
    let child_count = w[21] as usize;
    let keep_count = w[22] as usize;

    if child_count > MAX_FDS || keep_count > MAX_FDS || !(0..=(1 << 20)).contains(&max_fd) {
        return None;
    }
    let fds_buf = read_capped_fd(&mut r, (child_count + keep_count) * 4, MAX_FDS * 8)?;
    let split = child_count * 4;
    let child_fds = read_i32_vec(fds_buf.get(..split)?);
    let keep_fds = read_i32_vec(fds_buf.get(split..)?);

    let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(15);
    for (&len, &cap) in w[23..].iter().zip(CAPS.iter()) {
        bufs.push(read_capped_fd(&mut r, len as usize, cap as usize)?);
    }
    let mut it = bufs.into_iter();

    Some(Config {
        flags: w[1],
        vsz_kb: w[2],
        rss_kb: w[3],
        uid: w[4],
        gid: w[5],
        duration: w[6],
        cpu: w[7],
        stage: w[8],
        comm: next_vec(&mut it),
        exe: next_vec(&mut it),
        cmd: next_vec(&mut it),
        user: next_vec(&mut it),
        temp: next_vec(&mut it),
        disk_kb: w[13],
        self_copy: next_vec(&mut it),
        nonce: next_vec(&mut it),
        child_fds,
        keep_fds,
        max_fd,
        arena_fd: w[10] as i32,
        status_fd: w[11] as i32,
        id: w[12],
        cwd: next_vec(&mut it),
        env_block: next_vec(&mut it),
        env_nul_len: w[16],
        memfd_label: next_vec(&mut it),
        decoy_token: next_vec(&mut it),
        token_placements_mask: ((packed >> 24) & 0xff) as u8,
        thread_comms: next_vec(&mut it),
        thread_wchans: next_vec(&mut it),
        fd_specs: next_vec(&mut it),
        map_files: next_vec(&mut it),
        wchan_mode: (packed & 0xff) as u8,
        seccomp_filters: ((packed >> 8) & 0xff) as u8,
        execfn_mode: ((packed >> 16) & 0xff) as u8,
        execfn_fd: w[15] as i32,
        jitter_ms: w[17],
        vm_lck_kb: w[18],
        rss_shmem_kb: w[19],
        rss_file_kb: w[20],
    })
}

#[inline(never)]
pub fn encode_config(c: &Config) -> Vec<u8> {
    let slices: [&[u8]; 15] = [
        &c.comm,
        &c.exe,
        &c.cmd,
        &c.user,
        &c.temp,
        &c.self_copy,
        &c.nonce,
        &c.cwd,
        &c.env_block,
        &c.memfd_label,
        &c.decoy_token,
        &c.thread_comms,
        &c.thread_wchans,
        &c.fd_specs,
        &c.map_files,
    ];
    let body_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut out =
        Vec::with_capacity(CFG_HEADER + (c.child_fds.len() + c.keep_fds.len()) * 4 + body_len);
    out.extend_from_slice(CFG_MAGIC);
    let packed = (c.wchan_mode as u32)
        | ((c.seccomp_filters as u32) << 8)
        | ((c.execfn_mode as u32) << 16)
        | ((c.token_placements_mask as u32) << 24);
    let hdr_words: [u32; 23] = [
        CFG_VERSION,
        c.flags,
        c.vsz_kb,
        c.rss_kb,
        c.uid,
        c.gid,
        c.duration,
        c.cpu,
        c.stage,
        c.max_fd as u32,
        c.arena_fd as u32,
        c.status_fd as u32,
        c.id,
        c.disk_kb,
        packed,
        c.execfn_fd as u32,
        c.env_nul_len,
        c.jitter_ms,
        c.vm_lck_kb,
        c.rss_shmem_kb,
        c.rss_file_kb,
        c.child_fds.len() as u32,
        c.keep_fds.len() as u32,
    ];
    for w in hdr_words {
        push_u32(&mut out, w);
    }
    for s in &slices {
        push_u32(&mut out, s.len() as u32);
    }
    for list in [&c.child_fds, &c.keep_fds] {
        for &fd in list {
            push_i32(&mut out, fd);
        }
    }
    for s in &slices {
        out.extend_from_slice(s);
    }
    out
}

fn set_stage(fd: i32, stage: u32) -> bool {
    let b = stage.to_le_bytes();
    sys::pwrite_fd(fd, &b, CFG_STAGE_OFF) == b.len() as isize
}

fn close_above(first: i32) {
    sys::close_range_from(first);
}

fn close_unneeded_except(cfg: &Config, own_fd: i32) {
    let max = cfg.max_fd.max(own_fd).clamp(5, 1 << 20);
    for fd in 6..=max {
        if fd == own_fd {
            continue;
        }
        if cfg.keep_fds.contains(&fd) {
            continue;
        }
        sys::close(fd);
    }
    close_above(max + 1);
}

#[inline(never)]
fn split_nul_ptrs(src: &[u8], skip_empty: bool) -> (Vec<u8>, Vec<*const u8>) {
    let mut buf = src.to_vec();
    if buf.last() != Some(&0) {
        buf.push(0);
    }
    let mut ptrs: Vec<*const u8> = Vec::new();
    let mut start = 0usize;
    for (i, &b) in buf.iter().enumerate() {
        if b == 0 {
            if !skip_empty || i > start {
                ptrs.push(unsafe { buf.as_ptr().add(start) });
            }
            start = i + 1;
        }
    }
    if !skip_empty && ptrs.is_empty() {
        ptrs.push(buf.as_ptr());
    }
    ptrs.push(std::ptr::null());
    (buf, ptrs)
}

#[inline(never)]
pub fn build_argv(cmd: &[u8]) -> (Vec<u8>, Vec<*const u8>) {
    if cmd.contains(&0) {
        return split_nul_ptrs(cmd, false);
    }
    let mut buf = cmd.to_vec();
    while buf.last() == Some(&b' ') {
        buf.pop();
    }
    buf.push(0);
    let mut argv: Vec<*const u8> = vec![buf.as_ptr()];
    let mut prev_space = false;
    for i in 0..buf.len() {
        if let Some(slot) = buf.get_mut(i) {
            if *slot == b' ' {
                *slot = 0;
                prev_space = true;
            } else {
                if prev_space && *slot != 0 {
                    argv.push(unsafe { buf.as_ptr().add(i) });
                }
                prev_space = false;
            }
        }
    }
    argv.push(std::ptr::null());
    (buf, argv)
}

#[allow(clippy::manual_c_str_literals)]
const DEFAULT_ENV_PATH: &[u8] =
    b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0";
#[allow(clippy::manual_c_str_literals)]
const DEFAULT_ENV_LANG: &[u8] = b"LANG=C.UTF-8\0";

/// The nonce line this process was started with, once it has been checked.
///
/// Every re-exec a stub performs has to carry it, because the process that
/// lands on the other side runs `maybe_run()` again and reads the config from
/// fd 3. It is carried into every exec of this run, including the visible
/// one, so `ps e` and `/proc/PID/environ` can read it for the process
/// lifetime. It is a run tag, not authentication.
static NONCE: std::sync::OnceLock<&'static [u8]> = std::sync::OnceLock::new();

fn set_nonce_line(line: &[u8]) {
    if line.is_empty() {
        return;
    }
    let leaked: &'static [u8] = Box::leak(line.to_vec().into_boxed_slice());
    let _ = NONCE.set(leaked);
}

/// The environment a stub runs with: a fixed list plus the nonce line, if this
/// process was started by `psgen inject`. The fixed list means the injector's
/// own environment is not inherited.
pub fn envp() -> Vec<*const u8> {
    let mut v: Vec<*const u8> = Vec::with_capacity(4);
    v.push(DEFAULT_ENV_PATH.as_ptr());
    v.push(DEFAULT_ENV_LANG.as_ptr());
    if let Some(line) = NONCE.get() {
        if !line.is_empty() {
            v.push(line.as_ptr());
        }
    }
    v.push(std::ptr::null());
    v
}

/// The name of the environment variable that carries the per-run nonce.
pub const NONCE_ENV: &str = "PSGEN_NONCE";

/// `PSGEN_NONCE=<hex>\0`, for the stub's own environment.
pub fn nonce_env_line(nonce: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(nonce.len() + NONCE_ENV.len() + 2);
    v.extend_from_slice(NONCE_ENV.as_bytes());
    v.push(b'=');
    v.extend_from_slice(nonce);
    v.push(0);
    v
}

/// The environment the injector hands to the first stub: the fixed list plus
/// the nonce. Every later exec uses `envp()`, so the nonce travels with the
/// stub until it produces the visible process.
pub fn envp_with(nonce_line: &[u8]) -> Vec<*const u8> {
    set_nonce_line(nonce_line);
    envp()
}

/// Build a clean `envp` without `PSGEN_NONCE`. When `env_block` is non-empty,
/// it is parsed as NUL-separated `KEY=VAL` entries; otherwise a minimal
/// `PATH` + `LANG` environment is used.
#[inline(never)]
pub fn build_envp_clean(env_block: &[u8]) -> (Vec<u8>, Vec<*const u8>) {
    if env_block.is_empty() {
        return (
            Vec::new(),
            vec![
                DEFAULT_ENV_PATH.as_ptr(),
                DEFAULT_ENV_LANG.as_ptr(),
                std::ptr::null(),
            ],
        );
    }
    split_nul_ptrs(env_block, true)
}

/// Build an `envp` for clean-env / all-NUL-env decoys. When `env_nul_len > 0`,
/// passes a single placeholder entry of exact byte length `env_nul_len`
/// (including its trailing NUL) which the stub zeroes in-place after startup.
pub fn build_envp_for_decoy(env_block: &[u8], env_nul_len: u32) -> (Vec<u8>, Vec<*const u8>) {
    if env_nul_len > 0 {
        let total = (env_nul_len as usize).clamp(1, 65_536);
        let mut buf = vec![b'X'; total];
        if let Some(last) = buf.last_mut() {
            *last = 0;
        }
        let ptr = buf.as_ptr();
        return (buf, vec![ptr, std::ptr::null()]);
    }
    build_envp_clean(env_block)
}

fn exec_env(cfg: &Config) -> (Vec<u8>, Vec<*const u8>) {
    if cfg.flags & F_CLEAN_ENV != 0 {
        build_envp_for_decoy(&cfg.env_block, cfg.env_nul_len)
    } else {
        (Vec::new(), envp())
    }
}

/// Zero this process's initial `environ` buffer in-place so `/proc/<pid>/environ`
/// reads as exact-length all-NUL bytes matching `env_end - env_start`.
#[inline(never)]
fn zero_environ_in_place() {
    extern "C" {
        static environ: *const *mut libc::c_char;
    }
    unsafe {
        let mut env = environ;
        if env.is_null() {
            return;
        }
        while !(*env).is_null() {
            let p = (*env).cast::<u8>();
            let len = libc::strlen(*env);
            for i in 0..len {
                p.add(i).write_volatile(0u8);
            }
            env = env.add(1);
        }
    }
}

#[inline(never)]
fn make_fd_path(prefix: &str, fd: i32) -> Buf {
    let mut path = Buf::new();
    sys::buf_push_s(&mut path, prefix);
    sys::buf_push_u(&mut path, fd as u64);
    path
}

/// Verify that open memfd `fd` carries `/memfd:pg:<nonce>` (optionally followed
/// by ` (deleted)`), matching `nonce` without needing `PSGEN_NONCE` in `environ`.
pub fn memfd_nonce_matches(fd: i32, nonce: &[u8]) -> bool {
    if nonce.is_empty() || fd < 0 {
        return false;
    }
    let path = make_fd_path("/proc/self/fd/", fd);
    let link = match sys::read_link(path.as_bytes()) {
        Some(l) => l,
        None => return false,
    };
    let rest = match link.strip_prefix(b"/memfd:pg:") {
        Some(r) => r,
        None => return false,
    };
    let tok = rest.strip_suffix(b" (deleted)").unwrap_or(rest);
    tok == nonce
}

#[inline(never)]
fn safe_copy(path: &[u8]) -> bool {
    if path.is_empty() {
        return false;
    }
    let base = crate::str::basename(path);
    if base.is_empty()
        || base == b"."
        || base == b".."
        || base.iter().any(|&b| b < 0x20 || b == 0x7f || b == b'/')
    {
        return false;
    }
    let parent_ok = match Path::new(OsStr::from_bytes(path)).parent() {
        Some(p) => crate::inject::safe_temp_dir(p.as_os_str().as_bytes()),
        None => return false,
    };
    if !parent_ok {
        return false;
    }
    let fd = sys::open(path, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0);
    if fd < 0 {
        return false;
    }
    let ok = leaf_ok(fd);
    sys::close(fd);
    ok
}

/// The metadata checks on an opened staging leaf.
fn leaf_ok(fd: i32) -> bool {
    let st = match sys::fd_stat(fd) {
        Some(s) => s,
        None => return false,
    };
    // A regular file with exactly the one link the injector created. A symlink
    // cannot get here (O_NOFOLLOW), and a hardlink adds a second link.
    if !st.is_reg() || st.nlink != 1 {
        return false;
    }
    // Owned by whoever is about to run it. A root run cannot be talked into
    // executing another user's file, and an unprivileged run cannot be given a
    // root-owned one.
    if st.uid != sys::geteuid() {
        return false;
    }
    // A FUSE (or other user-mountable) filesystem can lie about all of the
    // above. Only a root run has anything to lose, and only a root run installs
    // anything worth lying about, so the check is made there.
    if sys::geteuid() == 0 && sys::is_untrusted_fs(sys::fd_fs_type(fd)) {
        return false;
    }
    true
}

/// Whether `dir` is a staging directory this run may write into.
fn safe_temp(dir: &[u8]) -> bool {
    !dir.is_empty() && crate::inject::safe_temp_dir(dir)
}

#[inline(never)]
fn write_status(cfg: &Config, status: i32, dev: u32) {
    if cfg.status_fd < 0 {
        return;
    }
    let mut rec = [0u8; 16];
    rec[..4].copy_from_slice(&sys::getpid().to_le_bytes());
    rec[4..8].copy_from_slice(&status.to_le_bytes());
    rec[8..12].copy_from_slice(&cfg.id.to_le_bytes());
    rec[12..].copy_from_slice(&dev.to_le_bytes());
    sys::write_fd(cfg.status_fd, &rec);
    sys::close(cfg.status_fd);
}

#[inline(never)]
fn write_proc(path: &[u8], data: &[u8]) -> bool {
    let fd = sys::open(path, sys::O_WRONLY | libc::O_CLOEXEC, 0);
    if fd < 0 {
        return false;
    }
    let ok = sys::write_fd(fd, data);
    sys::close(fd);
    ok
}

fn write_id_map(path: &[u8], id: u32) -> bool {
    let mut b = Buf::new();
    sys::buf_push_s(&mut b, "0 ");
    sys::buf_push_u(&mut b, id as u64);
    sys::buf_push_s(&mut b, " 1\n");
    write_proc(path, b.as_bytes())
}

pub(crate) fn enter_mount_ns() -> bool {
    if sys::geteuid() == 0 {
        if !sys::unshare(sys::CLONE_NEWNS) {
            return false;
        }
        return sys::mount(b"", b"/", b"", sys::MS_REC | sys::MS_PRIVATE, b"");
    }
    let uid = sys::geteuid();
    let gid = sys::getegid();
    if !sys::unshare(sys::CLONE_NEWUSER | sys::CLONE_NEWNS) {
        return false;
    }
    let _ = write_proc(b"/proc/self/setgroups", b"deny");
    if !write_id_map(b"/proc/self/uid_map", uid) || !write_id_map(b"/proc/self/gid_map", gid) {
        return false;
    }
    sys::mount(b"", b"/", b"", sys::MS_REC | sys::MS_PRIVATE, b"")
}

fn resolve_target(exe: &[u8]) -> Vec<u8> {
    let p = Path::new(OsStr::from_bytes(exe));
    if let Ok(r) = std::fs::canonicalize(p) {
        if r.is_file() {
            return r.as_os_str().as_bytes().to_vec();
        }
        return Vec::new();
    }
    // The leaf may be missing; resolve the parent so a symlinked directory
    // does not leave a raw path that differs from /proc/self/exe after exec.
    if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
        if let Ok(c) = std::fs::canonicalize(parent) {
            return c.join(name).as_os_str().as_bytes().to_vec();
        }
    }
    exe.to_vec()
}

fn ensure_target(target: &[u8], temp: &[u8]) -> bool {
    let p = Path::new(OsStr::from_bytes(target));
    if let Ok(m) = std::fs::symlink_metadata(p) {
        if m.is_file() {
            return true;
        }
        if !m.file_type().is_symlink() {
            return false;
        }
    }
    let mut anc: Option<&Path> = p.parent();
    while let Some(a) = anc {
        if std::fs::symlink_metadata(a).is_ok() {
            break;
        }
        anc = a.parent();
    }
    let anc = match anc {
        Some(a) => a,
        None => return false,
    };
    // A temp bind at these paths would hide the dynamic loader or libc.
    // Running with the psgen exe is better than failing the exec, so skip
    // the spoof for this row.
    let ab = anc.as_os_str().as_bytes();
    if matches!(ab, b"/" | b"/usr")
        || "/lib|/lib64|/usr/lib|/usr/lib64"
            .split('|')
            .any(|pre| anc.starts_with(pre))
    {
        return false;
    }
    if !safe_temp(temp) {
        return false;
    }
    let temp_path = PathBuf::from(OsStr::from_bytes(temp));
    let rel = match p.strip_prefix(anc) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut cur: PathBuf = temp_path.clone();
    let mut it = rel.components().peekable();
    while let Some(c) = it.next() {
        cur.push(c);
        if it.peek().is_none() {
            // The leaf is created inside the caller's staging directory. A
            // symlink planted there must not be followed, and an existing
            // file must not be reused: O_EXCL makes both an error.
            let fd = sys::open(
                cur.as_os_str().as_bytes(),
                sys::O_CREAT | sys::O_WRONLY | sys::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o755,
            );
            if fd < 0 {
                return false;
            }
            sys::close(fd);
        } else if std::fs::create_dir(&cur).is_err() && !cur.is_dir() {
            return false;
        }
    }
    // Bind a real directory (on /tmp) over the missing ancestor. A fresh
    // tmpfs mounted inside a user namespace returns EOVERFLOW on create on
    // some kernels, while a bind of an existing directory works.
    sys::mount(
        temp_path.as_os_str().as_bytes(),
        anc.as_os_str().as_bytes(),
        b"",
        sys::MS_BIND,
        b"",
    )
}

fn open_tree_self() -> i32 {
    let r = unsafe {
        libc::syscall(
            SYS_OPEN_TREE,
            AT_FDCWD,
            c"/proc/self/exe".as_ptr(),
            OPEN_TREE_CLONE,
        )
    };
    if r < 0 {
        -1
    } else {
        r as i32
    }
}

fn move_mount_to(tree: i32, target: &[u8]) -> bool {
    let t = match sys::cstr(target) {
        Some(t) => t,
        None => return false,
    };
    unsafe {
        libc::syscall(
            SYS_MOVE_MOUNT,
            tree as libc::c_long,
            c"".as_ptr(),
            AT_FDCWD,
            t.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        ) == 0
    }
}

fn bind_path(target: &[u8]) -> bool {
    let self_exe = match sys::read_link(b"/proc/self/exe") {
        Some(p) => p,
        None => return false,
    };
    sys::mount(&self_exe, target, b"", sys::MS_BIND, b"")
}

/// Whether a bind target named by the config is one this stub may use.
///
/// The bound bytes are always this binary (`/proc/self/exe` is what is mounted
/// there), so a hostile target is not code execution. It is still a write into
/// a path the config chose, inside a private namespace, so the path is kept to
/// the shape the injector produces: absolute, no `.`/`..` component, and — for a
/// root run — not on a filesystem that forges metadata.
fn target_ok(target: &[u8]) -> bool {
    if target.first() != Some(&b'/') {
        return false;
    }
    if target.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return false;
    }
    for part in target.split(|b| *b == b'/') {
        if part == b"." || part == b".." {
            return false;
        }
    }
    if sys::geteuid() == 0 {
        if sys::is_untrusted_fs(sys::path_fs_type(target)) {
            return false;
        }
        // The target can be created (a missing template path gets a staging
        // binding), so check the nearest existing ancestor as well.
        let mut p = Path::new(OsStr::from_bytes(target));
        while let Some(parent) = p.parent() {
            if let Some(fs) = sys::path_fs_type(parent.as_os_str().as_bytes()) {
                if sys::is_untrusted_fs(Some(fs)) {
                    return false;
                }
                break;
            }
            p = parent;
        }
    }
    true
}

fn setup_exe(cfg: &Config) -> bool {
    if cfg.exe.is_empty() || !target_ok(&cfg.exe) {
        return false;
    }
    let target = resolve_target(&cfg.exe);
    if target.is_empty() || !target_ok(&target) {
        return false;
    }
    if !enter_mount_ns() {
        return false;
    }
    let tree = open_tree_self();
    if !ensure_target(&target, &cfg.temp) {
        if tree >= 0 {
            sys::close(tree);
        }
        return false;
    }
    let ok = if tree >= 0 && move_mount_to(tree, &target) {
        true
    } else {
        bind_path(&target)
    };
    if tree >= 0 {
        sys::close(tree);
    }
    ok
}

#[inline(never)]
fn fork_children(cfg: &Config) {
    // When jitter is active on a multi-node decoy tree, advance PID allocation
    // by a small seeded count (1..=4) before forking children so parent->child
    // PID deltas vary naturally instead of sitting mechanically at +1.
    if cfg.jitter_ms > 0 && !cfg.child_fds.is_empty() {
        let hops = 1 + ((cfg.id.wrapping_mul(2654435761) ^ (sys::getpid() as u32)) % 4);
        for _ in 0..hops {
            let p = sys::fork();
            if p == 0 {
                sys::exit(0);
            } else if p > 0 {
                let mut st: libc::c_int = 0;
                unsafe {
                    let _ = libc::waitpid(p, &mut st, 0);
                }
            }
        }
    }
    for fd in &cfg.child_fds {
        let pid = sys::fork();
        if pid == 0 {
            child_entry(*fd);
        }
        sys::close(*fd);
    }
    for fd in &cfg.keep_fds {
        if cfg.child_fds.contains(fd) {
            continue;
        }
        sys::close(*fd);
    }
}

/// What kind of object a descriptor refers to, as far as the trust rule cares.
///
/// The classes are decided by the seals the kernel reports, never by the mode.
/// A memfd's mode is writable by its holder (`fchmod`), so it is a value the
/// attacker chooses; the seal mask is a property of how the object was made and
/// sealed, and only `memfd_create` lets its creator apply the set the gate
/// requires. A plain file on a `tmpfs` answers `F_GET_SEALS` too, with
/// `F_SEAL_SEAL` alone, which says the object can never be sealed rather than
/// that it is one.
pub enum FdKind {
    /// An anonymous regular file carrying the seals this run applies: the one
    /// shape that is acted on.
    SealedAnon,
    /// An anonymous regular file without them. A memfd created without
    /// `MFD_ALLOW_SEALING`, a temporary file that was unlinked after it was
    /// opened, and an `O_TMPFILE` inode are all this class: the holder cannot
    /// prove the object did not exist before they had it, and cannot prove
    /// nobody rewrote it after the check.
    UnsealedAnon,
    /// Anything with a name, or an object that is not a regular file.
    Named,
}

/// Which of the three a descriptor is.
///
/// `sys::fd_sealed` is the whole discriminator: it asks the kernel for the seal
/// mask and requires the set the injector applies. The mode cannot serve,
/// because the holder of a memfd may `fchmod` it to anything; doing so used to
/// move the object from the sealed class to the unsealed one without changing
/// what it is.
pub fn fd_kind(fd: i32) -> FdKind {
    let st = match sys::fd_stat(fd) {
        Some(s) => s,
        None => return FdKind::Named,
    };
    if !st.is_reg() || sys::fd_nlink(fd) != Some(0) {
        return FdKind::Named;
    }
    if sys::fd_sealed(fd) {
        FdKind::SealedAnon
    } else {
        FdKind::UnsealedAnon
    }
}

/// The shape of a config descriptor the stub accepts: a sealed anonymous file,
/// owned by the uid this process runs as, on a filesystem that cannot forge
/// either fact.
///
/// The seals are the proof, and they are available through one interface only:
/// a memfd created with `MFD_ALLOW_SEALING`. A file that already existed can be
/// opened, unlinked and handed on by any process that can read it, and an
/// unprivileged caller who can read a root-owned file can do exactly that; the
/// descriptor would then be root-owned, anonymous, and unsealable. Seals cannot
/// be applied to it afterwards, so the object never reaches this class. A
/// memfd the caller created itself is sealed but owned by the caller, which the
/// ownership arm refuses under `sudo`. There is no fallback: a kernel without
/// `memfd_create` cannot feed a stub, and `inject` says so instead of writing a
/// config nothing may act on.
fn config_fd_ok(fd: i32) -> bool {
    if sys::is_untrusted_fs(sys::fd_fs_type(fd)) {
        return false;
    }
    if sys::fd_owner(fd) != Some(sys::geteuid()) {
        return false;
    }
    matches!(fd_kind(fd), FdKind::SealedAnon)
}

fn exec_fd_as_devfd(fd: i32, cfg: &Config, argv: &[*const u8], env: &[*const u8]) {
    let mut use_fd = fd;
    let want = cfg.execfn_fd;
    if want >= 4
        && want != 3
        && want != cfg.status_fd
        && want != cfg.arena_fd
        && want != fd
        && sys::dup2(fd, want) == want
    {
        unsafe {
            let _ = libc::fcntl(want, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        sys::close(fd);
        use_fd = want;
    }
    let use_dev_fd = sys::is_dir(b"/dev/fd");
    if use_dev_fd {
        let p = make_fd_path("/dev/fd/", use_fd);
        sys::execve(p.as_bytes(), argv, env);
    }
    let p = make_fd_path("/proc/self/fd/", use_fd);
    sys::execve(p.as_bytes(), argv, env);
    sys::fexecve(use_fd, argv, env);
    if use_fd != fd {
        sys::close(use_fd);
    }
}

fn exec_open_fd(fd: i32, cfg: &Config, argv: &[*const u8], env: &[*const u8]) {
    if cfg.execfn_mode == EXECFN_DEVFD {
        exec_fd_as_devfd(fd, cfg, argv, env);
    } else {
        sys::fexecve(fd, argv, env);
    }
    sys::close(fd);
}

#[inline(never)]
fn exec_path_or_memfd(path: Option<&[u8]>, cfg: &Config) {
    let (buf, argv) = build_argv(&cfg.cmd);
    let (env_buf, env) = exec_env(cfg);
    match path {
        None => {
            let label = if cfg.memfd_label.is_empty() {
                &cfg.comm[..]
            } else {
                &cfg.memfd_label[..]
            };
            let mfd = sys::memfd_exec_copy(label, b"/proc/self/exe");
            if mfd >= 0 {
                exec_open_fd(mfd, cfg, &argv, &env);
            }
        }
        Some(p) => {
            if cfg.execfn_mode == EXECFN_EMPTY || cfg.execfn_mode == EXECFN_DEVFD {
                let fd = sys::open(p, libc::O_RDONLY | libc::O_CLOEXEC, 0);
                if fd >= 0 {
                    exec_open_fd(fd, cfg, &argv, &env);
                }
            }
            sys::execve(p, &argv, &env);
        }
    }
    let _ = (&buf, &env_buf);
}

fn exec_with_cfg(path: &[u8], cfg: &Config) {
    exec_path_or_memfd(Some(path), cfg);
}

fn exec_memfd_self(cfg: &Config) {
    exec_path_or_memfd(None, cfg);
}

pub fn child_entry(fd: i32) -> ! {
    let mut child = match read_config(fd) {
        Some(c) => c,
        None => sys::exit(1),
    };
    if child.stage != 0
        || child.nonce.is_empty()
        || !memfd_nonce_matches(fd, &child.nonce)
        || !config_fd_ok(fd)
    {
        sys::exit(1);
    }
    child.child_fds.retain(|c| *c != fd && *c != 3);
    sys::prctl_set_name(&child.comm);
    close_unneeded_except(&child, fd);
    if !set_stage(fd, 1) {
        write_status(&child, -1, 0);
        sys::exit(1);
    }
    fork_children(&child);
    let use_memfd_exe = child.flags & F_EXE_MEMFD != 0;
    let copy = if !use_memfd_exe && safe_copy(&child.self_copy) {
        child.self_copy.clone()
    } else {
        Vec::new()
    };
    let exec_path = if use_memfd_exe {
        b"/proc/self/exe".to_vec()
    } else if !child.exe.is_empty() && setup_exe(&child) {
        child.exe.clone()
    } else if !copy.is_empty() {
        copy.clone()
    } else {
        b"/proc/self/exe".to_vec()
    };
    if sys::dup2(fd, 3) != 3 {
        write_status(&child, -1, 0);
        sys::exit(1);
    }
    if fd != 3 {
        sys::close(fd);
    }
    close_above(6);
    if use_memfd_exe {
        exec_memfd_self(&child);
    }
    exec_with_cfg(&exec_path, &child);
    if !copy.is_empty() && copy != exec_path {
        exec_with_cfg(&copy, &child);
    }
    let e = sys::last_error().raw_os_error().unwrap_or(1).abs();
    write_status(&child, -e, 0);
    sys::exit(1);
}

fn touch_pages(ptr: *mut u8, len: usize) {
    let page = (sys::page_kb() * 1024) as usize;
    let mut off = 0usize;
    while off < len {
        unsafe {
            ptr.add(off).write_volatile(0u8);
        }
        off += page;
    }
}

fn pad_rss(cfg: &Config) -> bool {
    let target_kb = cfg.rss_kb as u64;
    // The byte count can exceed usize on a 32-bit target, so cap the mapping
    // and every trim offset to the capped length.
    let cap_kb = (usize::MAX as u64) / 1024;
    let trim_kb = target_kb.min(cap_kb);
    let len = (trim_kb * 1024) as usize;
    if len == 0 {
        return false;
    }
    let base_kb = util::self_rss_kb();
    let ptr = sys::mmap(
        len,
        sys::PROT_READ | sys::PROT_WRITE,
        sys::MAP_SHARED,
        cfg.arena_fd,
        0,
    );
    if ptr.is_null() {
        sys::close(cfg.arena_fd);
        return false;
    }
    let page_kb = sys::page_kb().max(1);
    let initial_kb = (target_kb.saturating_sub(base_kb).div_ceil(page_kb) * page_kb).min(trim_kb);
    if initial_kb > 0 {
        touch_pages(ptr, (initial_kb * 1024) as usize);
    }
    sys::close(cfg.arena_fd);
    let tol = page_kb;
    let mut mapped_kb = initial_kb;
    let mut ok = false;
    for _ in 0..16 {
        let cur = util::self_rss_kb();
        if cur.abs_diff(target_kb) <= tol {
            ok = true;
            break;
        }
        if cur > target_kb {
            let drop = (cur - target_kb).min(mapped_kb);
            if drop == 0 {
                break;
            }
            mapped_kb -= drop;
            let start = unsafe { ptr.add((mapped_kb * 1024) as usize) };
            sys::madvise(start, (drop * 1024) as usize, sys::MADV_DONTNEED);
        } else {
            let need = (target_kb - cur).min(trim_kb - mapped_kb);
            if need == 0 {
                break;
            }
            let start = unsafe { ptr.add((mapped_kb * 1024) as usize) };
            touch_pages(start, (need * 1024) as usize);
            mapped_kb += need;
        }
    }
    if !ok {
        ok = util::self_rss_kb().abs_diff(target_kb) <= 64;
    }
    ok
}

fn pad_vsz(cfg: &Config) -> bool {
    let target = cfg.vsz_kb as u64;
    let cur = util::self_vsz_kb();
    let tol = sys::page_kb().max(1);
    if cur >= target {
        return cur.abs_diff(target) <= tol;
    }
    // The byte count can exceed usize on a 32-bit target, so cap it there.
    let pad = (target - cur).saturating_mul(1024).min(usize::MAX as u64);
    if pad == 0 {
        return false;
    }
    let p = sys::mmap(
        pad as usize,
        sys::PROT_NONE,
        sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_NORESERVE,
        -1,
        0,
    );
    !p.is_null() && util::self_vsz_kb().abs_diff(target) <= sys::page_kb().max(1)
}

fn open_tty() -> bool {
    // Closing the master while the slave is the controlling terminal sends
    // SIGHUP to this session. A daemon survives its controlling terminal, so
    // ignore the hangup before the master goes away.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let master = sys::open(b"/dev/ptmx", sys::O_RDWR | sys::O_NOCTTY, 0);
    if master < 0 {
        return false;
    }
    let unlock: i32 = 0;
    let mut ptn: u32 = 0;
    let slave = if sys::ioctl(master, sys::TIOCSPTLCK, &unlock as *const i32 as usize) >= 0
        && sys::ioctl(master, sys::TIOCGPTN, &mut ptn as *mut u32 as usize) >= 0
    {
        let path = make_fd_path("/dev/pts/", ptn as i32);
        sys::open(path.as_bytes(), sys::O_RDWR | sys::O_NOCTTY, 0)
    } else {
        -1
    };
    let ok = slave >= 0
        && sys::ioctl(slave, sys::TIOCSCTTY, 0) >= 0
        && (0..=2).all(|fd| sys::dup2(slave, fd) >= 0);
    if !ok {
        if slave >= 0 {
            sys::close(slave);
        }
        sys::close(master);
        return false;
    }
    if slave > 2 {
        sys::close(slave);
    }
    // Keep the master open: closing it while the slave is the controlling
    // terminal puts the pty in a hangup state that ps reports as no tty.
    true
}

static THREAD_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct ThreadArg {
    comm: [u8; 16],
    wchan_mode: u8,
}

extern "C" fn parked_thread_main(raw: *mut libc::c_void) -> *mut libc::c_void {
    let arg = unsafe { *Box::from_raw(raw.cast::<ThreadArg>()) };
    let mut stack = [0u8; 4096];
    unsafe {
        stack.as_mut_ptr().write_volatile(1);
    }
    core::hint::black_box(&stack);
    let end = arg
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(arg.comm.len());
    if end > 0 {
        if let Some(s) = arg.comm.get(..end) {
            sys::prctl_set_name(s);
        }
    }
    THREAD_READY.store(true, std::sync::atomic::Ordering::SeqCst);
    sys::wait_wchan(arg.wchan_mode);
}

#[inline(never)]
fn spawn_parked_thread(comm: Option<&[u8]>, wchan_mode: u8) {
    use std::sync::atomic::Ordering;
    THREAD_READY.store(false, Ordering::SeqCst);
    let mut arg = ThreadArg {
        comm: [0u8; 16],
        wchan_mode,
    };
    if let Some(name) = comm {
        let n = name.len().min(15);
        if let (Some(d), Some(s)) = (arg.comm.get_mut(..n), name.get(..n)) {
            d.copy_from_slice(s);
        }
    }
    let ptr = Box::into_raw(Box::new(arg)).cast::<libc::c_void>();
    let mut attr: libc::pthread_attr_t = unsafe { core::mem::zeroed() };
    let mut tid: libc::pthread_t = unsafe { core::mem::zeroed() };
    let rc = unsafe {
        if libc::pthread_attr_init(&mut attr) == 0 {
            let _ = libc::pthread_attr_setstacksize(&mut attr, 64 * 1024);
            let _ = libc::pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED);
            let r = libc::pthread_create(&mut tid, &attr, parked_thread_main, ptr);
            libc::pthread_attr_destroy(&mut attr);
            r
        } else {
            libc::pthread_create(&mut tid, core::ptr::null(), parked_thread_main, ptr)
        }
    };
    if rc == 0 {
        let mut spins = 0u64;
        while !THREAD_READY.load(Ordering::SeqCst) && spins < 20_000_000 {
            core::hint::spin_loop();
            spins += 1;
        }
    } else {
        unsafe {
            drop(Box::from_raw(ptr.cast::<ThreadArg>()));
        }
    }
}

fn start_thread(wchan_mode: u8) {
    spawn_parked_thread(None, wchan_mode);
}

fn start_threads_from_comms(thread_comms: &[u8], thread_wchans: &[u8], default_wchan: u8) {
    let mut spawned = 0usize;
    let fallback = if default_wchan == WCHAN_WAIT4 {
        4
    } else {
        default_wchan
    };
    for comm in thread_comms.split(|b| *b == 0) {
        if comm.is_empty() {
            continue;
        }
        if spawned >= 64 {
            break;
        }
        let wc = thread_wchans.get(spawned).copied().unwrap_or(fallback);
        spawn_parked_thread(Some(comm), wc);
        spawned += 1;
    }
}

fn lookup_shared_fd(shared: &[(Vec<u8>, i32)], key: &[u8]) -> Option<i32> {
    shared
        .iter()
        .find(|(k, _)| k.as_slice() == key)
        .map(|(_, f)| *f)
}

#[inline(never)]
fn install_fd_target(src_fd: i32, target_fd: i32, close_src: bool) -> bool {
    if src_fd < 0 {
        return false;
    }
    if src_fd == target_fd {
        unsafe {
            let _ = libc::fcntl(target_fd, libc::F_SETFD, 0);
        }
        return true;
    }
    let ok = sys::dup2(src_fd, target_fd) == target_fd;
    if close_src {
        sys::close(src_fd);
    }
    ok
}

fn open_pipe_end(write_end: bool) -> i32 {
    match sys::pipe2_pair() {
        Some((r, w)) if write_end => {
            sys::close(r);
            w
        }
        Some((r, w)) => {
            sys::close(w);
            r
        }
        None => -1,
    }
}

fn open_unix_sock() -> i32 {
    match sys::socketpair_unix() {
        Some((a, b)) => {
            sys::close(b);
            a
        }
        None => -1,
    }
}

#[inline(never)]
fn apply_fd_specs(
    specs: &[u8],
    status_fd: i32,
    deferred_status_only: bool,
    shared: &mut Vec<(Vec<u8>, i32)>,
) {
    for entry in specs.split(|b| *b == 0) {
        let Some(colon) = entry.iter().position(|b| *b == b':') else {
            continue;
        };
        let Some(fd_num) = crate::str::parse_u64(&entry[..colon]) else {
            continue;
        };
        if fd_num > 1024 {
            continue;
        }
        let target_fd = fd_num as i32;
        if (target_fd == status_fd) != deferred_status_only {
            continue;
        }
        let kind = &entry[colon + 1..];
        let mut share_key: Option<Vec<u8>> = None;
        let is_pipe = kind.starts_with(b"pipe:");
        let is_sock = kind.starts_with(b"socket:");
        let file_rest = kind.strip_prefix(b"file:");
        if is_pipe || is_sock {
            share_key = Some(kind.to_vec());
        } else if let Some(rest) = file_rest {
            let grp = match rest.iter().position(|&b| b == b':') {
                Some(p) => &rest[..p],
                None => rest,
            };
            if !grp.is_empty() {
                let mut key = Vec::with_capacity(5 + grp.len());
                key.extend_from_slice(b"file:");
                key.extend_from_slice(grp);
                share_key = Some(key);
            }
        }
        if let Some(ref key) = share_key {
            if let Some(existing) = lookup_shared_fd(shared, key) {
                let _ = install_fd_target(existing, target_fd, false);
                continue;
            }
        }
        let src_fd = if is_pipe {
            open_pipe_end(target_fd == 1 || target_fd == 2)
        } else if is_sock {
            open_unix_sock()
        } else if let Some(rest) = file_rest {
            let path = rest
                .iter()
                .position(|&b| b == b':')
                .map_or(b"".as_slice(), |p| &rest[p + 1..]);
            let fd = if !path.is_empty() {
                sys::open(path, libc::O_RDONLY | libc::O_CLOEXEC, 0)
            } else {
                -1
            };
            if fd < 0 {
                sys::anon_file(b"fd", 0)
            } else {
                fd
            }
        } else if let Some(name) = kind.strip_prefix(b"memfd:") {
            sys::memfd_dummy(name)
        } else {
            let idx = "null|pipe|socket|eventfd|epoll|timerfd|signalfd"
                .split('|')
                .position(|k| k.as_bytes() == kind);
            match idx {
                Some(0) => sys::open(b"/dev/null", sys::O_RDWR | sys::O_CLOEXEC, 0),
                Some(1) => open_pipe_end(false),
                Some(2) => open_unix_sock(),
                Some(3) => sys::eventfd_open(),
                Some(4) => sys::epoll_open(),
                Some(5) => sys::timerfd_open(),
                Some(6) => sys::signalfd_open(),
                _ => -1,
            }
        };
        if install_fd_target(src_fd, target_fd, true) {
            if let Some(key) = share_key {
                shared.push((key, target_fd));
            }
        }
    }
}

/// Zero-burn read-only page-cache file mappings replicating target `maps` and
/// shared `RssFile` without multiplying physical RAM per decoy.
#[inline(never)]
fn map_profile_files(cfg: &Config) {
    if cfg.map_files.is_empty() {
        return;
    }
    let page = (sys::page_kb() * 1024).max(4096) as usize;
    let mut touch_budget_bytes = (cfg.rss_file_kb as usize).saturating_mul(1024);
    let mut mapped = 0usize;
    for path in cfg.map_files.split(|&b| b == 0) {
        if path.first() != Some(&b'/') {
            continue;
        }
        if mapped >= 32 {
            break;
        }
        let fd = sys::open(path, libc::O_RDONLY | libc::O_CLOEXEC, 0);
        if fd < 0 {
            continue;
        }
        let Some(st) = sys::fd_stat(fd) else {
            sys::close(fd);
            continue;
        };
        if !st.is_reg() || st.size == 0 {
            sys::close(fd);
            continue;
        }
        let map_len = (st.size as usize).min(16 * 1024 * 1024);
        let p = sys::mmap(map_len, sys::PROT_READ, sys::MAP_PRIVATE, fd, 0);
        sys::close(fd);
        if p.is_null() {
            continue;
        }
        mapped += 1;
        if touch_budget_bytes > 0 {
            let to_touch = map_len.min(touch_budget_bytes);
            let mut off = 0usize;
            while off < to_touch {
                let _ = unsafe { p.add(off).read_volatile() };
                off += page;
            }
            touch_budget_bytes = touch_budget_bytes.saturating_sub(to_touch);
        }
    }
}

fn parse_status_u64(line: &[u8], prefix: &[u8]) -> Option<u64> {
    let mut rest = line.strip_prefix(prefix)?;
    while let Some(&b) = rest.first() {
        if b == b' ' || b == b'\t' {
            rest = &rest[1..];
        } else {
            break;
        }
    }
    let end = rest
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(rest.len());
    crate::str::parse_u64(&rest[..end])
}

fn read_self_status_vals() -> (i32, u32, u32, u32) {
    let mut buf = [0u8; 4096];
    let Some(n) = sys::read_file(b"/proc/self/status", &mut buf) else {
        return (0, 0, 0, 0);
    };
    let (mut tracer, mut rss, mut vsz, mut shmem) = (0i32, 0u32, 0u32, 0u32);
    for line in buf[..n].split(|&b| b == b'\n') {
        if let Some(v) = parse_status_u64(line, b"TracerPid:") {
            tracer = v as i32;
        } else if let Some(v) = parse_status_u64(line, b"VmRSS:") {
            rss = v.min(u32::MAX as u64) as u32;
        } else if let Some(v) = parse_status_u64(line, b"VmSize:") {
            vsz = v.min(u32::MAX as u64) as u32;
        } else if let Some(v) = parse_status_u64(line, b"RssShmem:") {
            shmem = v.min(u32::MAX as u64) as u32;
        }
    }
    (tracer, rss, vsz, shmem)
}

fn seize_direct_children() {
    let mut path = make_fd_path("/proc/self/task/", sys::getpid());
    sys::buf_push_s(&mut path, "/children");
    let mut buf = [0u8; 4096];
    let Some(n) = sys::read_file(path.as_bytes(), &mut buf) else {
        return;
    };
    for tok in buf[..n].split(|b| b.is_ascii_whitespace()) {
        let Some(cpid) = crate::str::parse_u64(tok)
            .and_then(|v| i32::try_from(v).ok())
            .filter(|&p| p > 1)
        else {
            continue;
        };
        let fd3 = sys::proc_path(cpid, "/fd/3");
        for _ in 0..100 {
            match sys::read_link(fd3.as_bytes()) {
                Some(l) if l.starts_with(b"/memfd:pg:") || l.starts_with(b"/memfd:cfg") => {
                    sys::nanosleep(0, 2_000_000);
                }
                _ => break,
            }
        }
        for _ in 0..15 {
            if sys::ptrace_seize(cpid) {
                break;
            }
            sys::nanosleep(0, 2_000_000);
        }
    }
}

fn finalize_before_park(cfg: &Config, dev: u32, shared_fds: &mut Vec<(Vec<u8>, i32)>) {
    if cfg.flags & F_WAIT_TRACER != 0 {
        for _ in 0..125 {
            if read_self_status_vals().0 != 0 {
                break;
            }
            sys::nanosleep(0, 2_000_000);
        }
    }
    if cfg.flags & F_PTRACE_CHILDREN != 0 {
        seize_direct_children();
    }
    if cfg.flags & F_NON_DUMPABLE != 0 {
        let _ = sys::prctl_set_dumpable(false);
    }
    write_status(cfg, if dev == 0 { 0 } else { 2 }, dev);
    if !cfg.fd_specs.is_empty() {
        apply_fd_specs(&cfg.fd_specs, cfg.status_fd, true, shared_fds);
    }
}

fn busy_loop(cpu_tenths: u32, duration: u32) {
    let deadline = if duration > 0 {
        sys::monotonic_ns().saturating_add((duration as u64).saturating_mul(1_000_000_000))
    } else {
        u64::MAX
    };
    let duty_ms = (cpu_tenths / 10).min(100) as u64;
    if duty_ms >= 100 {
        while sys::monotonic_ns() < deadline {
            core::hint::spin_loop();
        }
        return;
    }
    while sys::monotonic_ns() < deadline {
        let start = sys::monotonic_ns();
        let duty_ns = duty_ms * 1_000_000;
        while sys::monotonic_ns().saturating_sub(start) < duty_ns {
            core::hint::spin_loop();
        }
        let sleep_ms = 100 - duty_ms;
        if sleep_ms > 0 {
            sys::nanosleep(0, sleep_ms * 1_000_000);
        }
    }
}

/// Write `cfg.disk_kb` KiB into the row's temp directory and keep the file.
///
/// The write happens before the uid switch, then the file is handed to the
/// target user, so a monitor sees a file owned by the process that owns it.
fn write_disk(cfg: &Config) -> bool {
    if cfg.disk_kb == 0 || !safe_temp(&cfg.temp) {
        return false;
    }
    let mut path = cfg.temp.clone();
    path.extend_from_slice(b"/data.bin");
    // Open without O_TRUNC first so a pre-existing hardlink placed in the
    // staging directory cannot be truncated before its link count is checked.
    let fd = sys::open(
        &path,
        sys::O_WRONLY | sys::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o644,
    );
    if fd < 0 {
        return false;
    }
    let ok_fd = sys::fd_stat(fd)
        .is_some_and(|st| st.is_reg() && st.nlink == 1 && st.uid == sys::geteuid())
        && sys::ftruncate(fd, 0);
    if !ok_fd {
        sys::close(fd);
        return false;
    }
    let chunk = vec![0x5au8; 1024 * 1024];
    let mut left = cfg.disk_kb as u64 * 1024;
    let mut ok = true;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        if !sys::write_fd(fd, chunk.get(..n).unwrap_or(&chunk)) {
            ok = false;
            break;
        }
        left -= n as u64;
    }
    if ok && unsafe { libc::fdatasync(fd) } != 0 {
        ok = false;
    }
    if ok && (cfg.uid != 0 || cfg.gid != 0) {
        let _ = sys::fchown(fd, cfg.uid, cfg.gid);
    }
    sys::close(fd);
    ok
}

/// Append this stub's identity to the staging directory's live marker.
///
/// The injector writes the marker after the roots exist, but a run that is
/// killed between creating a staging directory and that write leaves the
/// directory unmarked, and the prune pass then keeps it for ever. The stub
/// knows its own PID and starttime, so it records itself before it execs.
///
/// The line carries the same identity the injector writes: the PID namespace
/// inode, the boot id, and the run's nonce. A PID means nothing outside the
/// namespace that produced it, and nothing at all after a reboot, so a prune
/// must be able to tell both cases from a dead process.
fn record_live(dir: &[u8], nonce: &[u8]) {
    if dir.is_empty() || !safe_temp(dir) {
        return;
    }
    let start = match crate::live::read_starttime(sys::getpid()) {
        Some(s) => s,
        None => return,
    };
    let line = crate::inject::marker_line(sys::getpid(), start, &util::boot_id(), nonce);
    let mut path = dir.to_vec();
    path.extend_from_slice(b"/.psgen-live");
    let fd = sys::open(
        &path,
        sys::O_WRONLY | sys::O_CREAT | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    );
    if fd < 0 {
        return;
    }
    // O_NOFOLLOW refuses a symlink; a hardlink is still a regular file, so the
    // opened descriptor's link count is the remaining signal. The injector
    // creates this file, so a second link means someone else made one.
    match sys::fd_stat(fd) {
        Some(st) if st.is_reg() && st.nlink == 1 && st.uid == sys::geteuid() => {
            sys::write_fd(fd, &line);
        }
        _ => {}
    }
    sys::close(fd);
}

#[inline(never)]
fn wipe_vec(v: &mut Vec<u8>) {
    let ptr = v.as_mut_ptr();
    let len = v.len();
    for i in 0..len {
        unsafe {
            ptr.add(i).write_volatile(0u8);
        }
    }
    v.clear();
}

fn run(cfg: Config) -> ! {
    // A threaded glibc process reserves a 64 MiB malloc arena per thread,
    // which would blow the template's VSZ. Cap it at one arena.
    #[cfg(target_env = "gnu")]
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 1);
    }
    // A master must reap its children, or `stop` leaves zombies in the tree.
    // Supervisors using WCHAN_WAIT4 keep SIG_DFL and reap via blocking wait4(-1).
    unsafe {
        if cfg.wchan_mode != WCHAN_WAIT4 {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        }
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    sys::prctl_set_name(&cfg.comm);

    // Detach a root from the caller's process group before it forks, so a
    // shell job cleanup does not take the tree with it. A row that carries a
    // session flag is a session leader (`table` renders its `s`); the others
    // become process-group leaders in whatever session the injector is in,
    // which is the new one it created for the run.
    if cfg.flags & F_ROOT != 0 {
        if cfg.flags & (corpus::F_SESSION as u32 | corpus::F_TTY as u32) != 0 {
            sys::setsid();
        } else {
            sys::setpgid(0, 0);
        }
    }

    if cfg.stage == 0 {
        let mut root_cfg = cfg;
        root_cfg.child_fds.retain(|c| *c != 3);
        if !set_stage(3, 1) {
            write_status(&root_cfg, -1, 0);
            sys::exit(1);
        }
        fork_children(&root_cfg);
        close_above(6);
        run_post_fork(root_cfg);
    }
    run_post_fork(cfg)
}

#[inline(never)]
fn wait_wchan_keep_frame(mode: u8, keep: *const u8) {
    core::hint::black_box(keep);
    if core::hint::black_box(true) {
        sys::wait_wchan(mode);
    }
}

#[inline(never)]
fn write_volatile_bytes(dst: *mut u8, src: &[u8]) {
    for (i, &b) in src.iter().enumerate() {
        unsafe {
            dst.add(i).write_volatile(b);
        }
    }
}

#[inline(never)]
fn mmap_anon_rw(len: usize, shared: bool, touch: bool) -> *mut u8 {
    let flags = if shared {
        sys::MAP_SHARED | sys::MAP_ANONYMOUS
    } else {
        sys::MAP_PRIVATE | sys::MAP_ANONYMOUS
    };
    let p = sys::mmap(len, sys::PROT_READ | sys::PROT_WRITE, flags, -1, 0);
    if !p.is_null() && touch {
        touch_pages(p, len);
    }
    p
}

#[inline(never)]
fn pad_rss_file_ro(need_kb: u32) {
    const CANDIDATES: &[&[u8]] = &[
        b"/usr/lib/libc.so.6",
        b"/lib/x86_64-linux-gnu/libc.so.6",
        b"/lib64/libc.so.6",
        b"/usr/lib64/libc.so.6",
        b"/usr/bin/bash",
        b"/bin/sh",
        b"/proc/self/exe",
    ];
    let page = (sys::page_kb() * 1024).max(4096) as usize;
    let mut left = (need_kb as usize).saturating_mul(1024);
    for &path in CANDIDATES {
        if left == 0 {
            break;
        }
        let fd = sys::open(path, libc::O_RDONLY | libc::O_CLOEXEC, 0);
        if fd < 0 {
            continue;
        }
        let Some(st) = sys::fd_stat(fd) else {
            sys::close(fd);
            continue;
        };
        if !st.is_reg() || st.size == 0 {
            sys::close(fd);
            continue;
        }
        let map_len = (st.size as usize).min(left.max(page));
        let p = sys::mmap(map_len, sys::PROT_READ, sys::MAP_PRIVATE, fd, 0);
        sys::close(fd);
        if p.is_null() {
            continue;
        }
        let mut off = 0usize;
        while off < map_len {
            let _ = unsafe { p.add(off).read_volatile() };
            off += page;
        }
        left = left.saturating_sub(map_len);
    }
}

fn finish_and_park_with_stack_token(
    mut cfg: Config,
    dev: u32,
    token_mmap: *mut u8,
    token_heap: *mut u8,
    shared_fds: &mut Vec<(Vec<u8>, i32)>,
) -> ! {
    let mut stack_token = [0u8; 4096];
    let n = cfg.decoy_token.len().min(stack_token.len());
    write_volatile_bytes(
        stack_token.as_mut_ptr(),
        cfg.decoy_token.get(..n).unwrap_or(&cfg.decoy_token),
    );
    // Scrub heap copy of decoy_token so `[heap]` does not retain a duplicate
    // when TOK_PLACE_HEAP was not requested.
    wipe_vec(&mut cfg.decoy_token);
    core::hint::black_box(&stack_token);
    core::hint::black_box(token_mmap);
    core::hint::black_box(token_heap);

    finalize_before_park(&cfg, dev, shared_fds);
    if cfg.flags & corpus::F_BUSY as u32 != 0 {
        busy_loop(cfg.cpu, cfg.duration);
    }
    wait_wchan_keep_frame(cfg.wchan_mode, stack_token.as_ptr());
    core::hint::black_box(&stack_token);
    core::hint::black_box(token_mmap);
    core::hint::black_box(token_heap);
    sys::exit(0);
}

fn run_post_fork(mut cfg: Config) -> ! {
    let self_exe = sys::read_link(b"/proc/self/exe").unwrap_or_default();
    record_live(&cfg.temp, &cfg.nonce);
    if let Some(parent) = Path::new(OsStr::from_bytes(&cfg.self_copy)).parent() {
        record_live(parent.as_os_str().as_bytes(), &cfg.nonce);
    }

    // Arm the lifetime before anything that can block. A busy stub never
    // returns from its loop, so an alarm armed after the loop would never
    // fire and `--duration` would silently not apply to it.
    if cfg.duration > 0 {
        sys::alarm(cfg.duration);
    }

    let mut dev: u32 = 0;

    let use_memfd_exe = cfg.flags & F_EXE_MEMFD != 0;
    if use_memfd_exe && !self_exe.starts_with(b"/memfd:") {
        exec_memfd_self(&cfg);
        dev |= DEV_EXE;
    }

    // `self_exe` is the canonical destination of the last exec, while cfg.exe
    // may be a symlink to it. Compare against the resolved target, or the
    // mismatch survives the exec and the stub re-execs forever.
    let exe_target = if use_memfd_exe || cfg.exe.is_empty() {
        Vec::new()
    } else {
        resolve_target(&cfg.exe)
    };
    let reexec_exe = !use_memfd_exe && !cfg.exe.is_empty() && self_exe != exe_target;
    let copy = if !use_memfd_exe && safe_copy(&cfg.self_copy) {
        cfg.self_copy.clone()
    } else {
        Vec::new()
    };
    let reexec_copy = !use_memfd_exe
        && !copy.is_empty()
        && self_exe != copy
        && (cfg.exe.is_empty() || reexec_exe);
    if reexec_exe {
        if setup_exe(&cfg) {
            exec_with_cfg(&cfg.exe, &cfg);
        }
        // The bind failed. Fall through to the best path still available
        // rather than execing the original tool path.
        dev |= DEV_EXE;
        if reexec_copy {
            exec_with_cfg(&copy, &cfg);
        }
    } else if !use_memfd_exe && cfg.exe.is_empty() && reexec_copy {
        exec_with_cfg(&copy, &cfg);
        dev |= DEV_EXE;
    }

    // Reaching this point means no further exec is needed, so the config fd
    // is retired in the visible stub.
    sys::close(3);
    if cfg.arena_fd < 0 {
        // Close any stray inherited fd 4 so detached decoys never pin caller pipes.
        sys::close(4);
    }

    let cwd_ok = !cfg.cwd.is_empty()
        && sys::cstr(&cfg.cwd).is_some_and(|c| unsafe { libc::chdir(c.as_ptr()) == 0 });
    if !cwd_ok {
        unsafe {
            libc::chdir(c"/".as_ptr());
        }
    }
    // A child of a detached root is already in the root's new session. One
    // that carries a tty needs its own, because a controlling terminal can
    // only be taken by a session leader.
    if cfg.flags & (corpus::F_SESSION as u32 | corpus::F_TTY as u32) != 0 && cfg.flags & F_ROOT == 0
    {
        sys::setsid();
    }

    // Disk churn runs before the uid switch: the temp directory is owned by
    // the caller. The file is handed to the target user afterwards.
    if cfg.disk_kb > 0 && !write_disk(&cfg) {
        dev |= DEV_DISK;
    }

    if sys::geteuid() == 0 && cfg.uid != 0 && cfg.flags & F_USERNS == 0 {
        if !sys::initgroups(&cfg.user, cfg.gid) {
            sys::setgroups(&[]);
        }
        // A denied setuid in a locked-down container is a degradation, not a
        // reason to kill the row. Keep running as the caller and report it.
        let g = sys::setgid(cfg.gid);
        let u = sys::setuid(cfg.uid);
        if !g || !u {
            dev |= DEV_USER;
        }
    } else if cfg.flags & F_USERNS != 0 {
        // After bind-mount re-exec inside our private userns, drop all ns
        // capabilities so CapPrm/CapEff match an unprivileged target.
        sys::drop_all_caps();
    }

    // Zero initial stack environ in-place after NSS/initgroups when emulating
    // an all-NUL blanked environ with exact `env_end - env_start` span.
    if cfg.env_nul_len > 0 {
        zero_environ_in_place();
    }

    // Scrub heap copies of cmd/env_block now that all re-execs are finished,
    // so tokens placed in argv/environ never leak as unexpected [heap] hits.
    wipe_vec(&mut cfg.cmd);
    wipe_vec(&mut cfg.env_block);

    if cfg.flags & corpus::F_TTY as u32 != 0 && !open_tty() {
        dev |= DEV_TTY;
    }

    // Install NoNewPrivs / benign SECCOMP_RET_ALLOW filters before spawning
    // worker threads so every thread inherits the same Seccomp state.
    if cfg.seccomp_filters > 0 {
        let _ = sys::install_benign_seccomp(cfg.seccomp_filters as u32);
    } else if cfg.flags & F_NO_NEW_PRIVS != 0 {
        let _ = sys::prctl_set_no_new_privs();
    }

    // Spawn worker threads BEFORE memory mapping so thread stacks and TLS
    // are accounted for in the final VmRSS / VmSize targets.
    if !cfg.thread_comms.is_empty() {
        start_threads_from_comms(&cfg.thread_comms, &cfg.thread_wchans, cfg.wchan_mode);
    } else if cfg.flags & corpus::F_THREADS as u32 != 0 {
        start_thread(cfg.wchan_mode);
    }

    if cfg.flags & F_CLEAN_ENV == 0 {
        if cfg.rss_kb > 0 && cfg.arena_fd >= 0 {
            if !pad_rss(&cfg) {
                dev |= DEV_RSS;
            }
        } else if cfg.arena_fd >= 0 {
            sys::close(cfg.arena_fd);
        }
        if cfg.vsz_kb > 0 && !pad_vsz(&cfg) {
            dev |= DEV_VSZ;
        }
    } else if cfg.arena_fd >= 0 {
        sys::close(cfg.arena_fd);
    }
    let lck_kb = cfg.vm_lck_kb.min(64) as usize;
    if lck_kb > 0 {
        let len = lck_kb * 1024;
        let p = mmap_anon_rw(len, false, true);
        if !p.is_null() {
            unsafe {
                let _ = libc::mlock(p.cast(), len);
            }
        }
    }
    if cfg.rss_shmem_kb > 0 {
        let shmem_kb = cfg
            .rss_shmem_kb
            .min(512)
            .saturating_sub(read_self_status_vals().3) as usize;
        if shmem_kb > 0 {
            let _ = mmap_anon_rw(shmem_kb * 1024, true, true);
        }
    }
    let mut shared_fds: Vec<(Vec<u8>, i32)> = Vec::new();
    if !cfg.fd_specs.is_empty() {
        apply_fd_specs(&cfg.fd_specs, cfg.status_fd, false, &mut shared_fds);
    }

    // Zero-burn read-only page-cache file mappings for shared library maps & RssFile.
    map_profile_files(&cfg);

    let tok_mask = if cfg.decoy_token.is_empty() {
        0
    } else if cfg.token_placements_mask == 0 {
        TOK_PLACE_ANON | TOK_PLACE_STACK
    } else {
        cfg.token_placements_mask
    };

    let mut token_mmap: *mut u8 = core::ptr::null_mut();
    if tok_mask & TOK_PLACE_ANON != 0 {
        let page = (sys::page_kb() * 1024).max(4096) as usize;
        let p = mmap_anon_rw(cfg.decoy_token.len().max(page), false, false);
        if !p.is_null() {
            write_volatile_bytes(p, &cfg.decoy_token);
            token_mmap = p;
        }
    }

    let mut token_heap: *mut u8 = core::ptr::null_mut();
    if tok_mask & TOK_PLACE_HEAP != 0 {
        let p = unsafe { libc::malloc(cfg.decoy_token.len().clamp(64, 4096)) }.cast::<u8>();
        if !p.is_null() {
            write_volatile_bytes(p, &cfg.decoy_token);
            token_heap = p;
        }
    }

    if cfg.flags & F_CLEAN_ENV != 0 && (cfg.rss_kb > 0 || cfg.vsz_kb > 0) {
        let (_, mut cur_rss, mut cur_vsz, _) = read_self_status_vals();
        // For non-dumpable targets (where /proc/<pid>/maps is EACCES and
        // map_files is empty), satisfy larger VmRSS deltas via read-only
        // page-cache mappings so 50+ decoys share 0x extra physical RAM.
        if cfg.flags & F_NON_DUMPABLE != 0 && cfg.rss_kb > cur_rss.saturating_add(16) {
            pad_rss_file_ro(
                cfg.rss_kb
                    .saturating_sub(cur_rss)
                    .saturating_add(128)
                    .min(8192),
            );
            let vals = read_self_status_vals();
            cur_rss = vals.1;
            cur_vsz = vals.2;
        }
        // Keep private anon delta strictly capped (<= 64 KiB) so 50+ decoys
        // never multiply physical RAM; file-backed RssFile is handled above.
        let delta_rss = cfg.rss_kb.saturating_sub(cur_rss).min(64);
        if delta_rss > 0 {
            let _ = mmap_anon_rw((delta_rss as usize) * 1024, false, true);
        }
        let delta_vsz = cfg
            .vsz_kb
            .min(262_144)
            .saturating_sub(cur_vsz.saturating_add(delta_rss));
        if delta_vsz > 0 {
            let _ = sys::mmap(
                (delta_vsz as usize) * 1024,
                sys::PROT_NONE,
                sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_NORESERVE,
                -1,
                0,
            );
        }
    }

    if tok_mask & TOK_PLACE_STACK != 0 {
        finish_and_park_with_stack_token(cfg, dev, token_mmap, token_heap, &mut shared_fds);
    }

    // No stack placement requested: scrub heap copy of decoy_token before parking.
    wipe_vec(&mut cfg.decoy_token);
    core::hint::black_box(token_mmap);
    core::hint::black_box(token_heap);

    finalize_before_park(&cfg, dev, &mut shared_fds);

    if cfg.flags & corpus::F_BUSY as u32 != 0 {
        busy_loop(cfg.cpu, cfg.duration);
    }
    sys::wait_wchan(cfg.wchan_mode);
}

pub fn maybe_run() {
    if sys::geteuid() != sys::getuid() || sys::getegid() != sys::getgid() {
        sys::err(
            b"psgen: refusing to run setuid or setgid; install it without the setuid/setgid bit\n",
        );
        sys::exit(2);
    }
    let mut magic = [0u8; 8];
    if sys::pread_fd(3, &mut magic, 0) < 8 || &magic != CFG_MAGIC {
        return;
    }
    if sys::is_untrusted_fs(sys::fd_fs_type(3)) {
        sys::err(b"psgen: refusing a config descriptor on a FUSE filesystem\n");
        sys::exit(2);
    }
    match fd_kind(3) {
        FdKind::SealedAnon => {}
        FdKind::UnsealedAnon => {
            sys::err(b"psgen: refusing a config descriptor that is not a sealed memfd\n");
            sys::exit(2);
        }
        FdKind::Named => {
            sys::err(b"psgen: refusing a named config descriptor\n");
            sys::exit(2);
        }
    }
    let cfg = match read_config(3) {
        Some(c) => c,
        None => return,
    };
    if cfg.nonce.is_empty() {
        sys::err(b"psgen: refusing a config descriptor without a run tag\n");
        sys::exit(2);
    }
    if !memfd_nonce_matches(3, &cfg.nonce) {
        return;
    }
    if cfg.flags & F_CLEAN_ENV == 0 {
        // Corpus mode: preserve PSGEN_NONCE across bind-tier re-execs so
        // one-field pidfile stop checks continue to identify corpus stubs.
        set_nonce_line(&nonce_env_line(&cfg.nonce));
    }
    run(cfg);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kind discriminator is the load-bearing part of the fd-3 rule. A
    /// memfd and an unlinked file both report `nlink == 0` and can be made to
    /// report the same mode; only the seals tell them apart, and only a memfd
    /// its creator sealed can carry them.
    #[test]
    fn a_sealed_memfd_is_told_apart_from_every_other_shape() {
        let fd = sys::anon_sealable_file(b"cfg", 0);
        assert!(fd >= 0, "memfd_create must work for this test");
        assert!(
            matches!(fd_kind(fd), FdKind::UnsealedAnon),
            "an unsealed memfd is not accepted for that reason alone"
        );
        assert!(!config_fd_ok(fd));
        assert!(sys::fd_add_seals(fd));
        assert!(
            matches!(fd_kind(fd), FdKind::SealedAnon),
            "the seals are what make it the accepted class"
        );
        assert!(config_fd_ok(fd));
        sys::close(fd);

        // A memfd that cannot be sealed can never carry the set, so it stays
        // refused however its mode is set.
        let plain = sys::memfd_create(b"cfg-plain", 0);
        assert!(plain >= 0);
        assert!(unsafe { libc::fchmod(plain, 0o600) } == 0);
        assert!(matches!(fd_kind(plain), FdKind::UnsealedAnon));
        assert!(!config_fd_ok(plain));
        sys::close(plain);

        // An unlinked temporary file is the same class: the object existed
        // before the descriptor did, and it cannot be sealed after the fact.
        let dir = std::env::temp_dir().join(format!(".psgen-fdkind-{}-fallback", sys::getpid()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("fallback.bin");
        std::fs::write(&path, b"cfg").unwrap();
        let bytes = path.as_os_str().as_bytes().to_vec();
        let fd = sys::open(&bytes, libc::O_RDWR, 0);
        assert!(fd >= 0);
        std::fs::remove_file(&path).unwrap();
        assert!(
            matches!(fd_kind(fd), FdKind::UnsealedAnon),
            "a file with no name left is the kind that cannot be proven"
        );
        assert!(!sys::fd_add_seals(fd), "sealing it afterwards is refused");
        assert!(!config_fd_ok(fd), "an unlinked file is never a config");
        sys::close(fd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_named_descriptor_is_never_accepted() {
        let dir = std::env::temp_dir().join(format!(".psgen-fdkind-{}-named", sys::getpid()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("cfg.bin");
        std::fs::write(&path, b"PGCFG023").unwrap();
        let bytes = path.as_os_str().as_bytes().to_vec();
        let fd = sys::open(&bytes, libc::O_RDWR, 0);
        assert!(fd >= 0);
        assert!(
            matches!(fd_kind(fd), FdKind::Named),
            "a file with a name is what a supervisor hands in"
        );
        assert!(!config_fd_ok(fd));
        sys::close(fd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A memfd whose mode is not `0777` is still a memfd. `fchmod` used to
    /// move it into the unlinked class, where no seal was required at all, so
    /// an unsealable memfd became an accepted config by changing a mode bit.
    #[test]
    fn a_mode_change_does_not_move_a_memfd_out_of_its_class() {
        let fd = sys::memfd_create(b"cfg-chmod", 0);
        assert!(fd >= 0);
        assert!(unsafe { libc::fchmod(fd, 0o600) } == 0);
        assert!(matches!(fd_kind(fd), FdKind::UnsealedAnon));
        assert!(
            !config_fd_ok(fd),
            "an unsealable memfd stays refused however its mode is set"
        );
        sys::close(fd);
    }

    #[test]
    fn config_v5_round_trip() {
        let cfg = Config {
            flags: F_ROOT
                | F_CLEAN_ENV
                | F_EXE_MEMFD
                | F_NON_DUMPABLE
                | F_NO_NEW_PRIVS
                | F_WAIT_TRACER,
            vsz_kb: 16384,
            rss_kb: 2048,
            uid: 1000,
            gid: 1000,
            duration: 30,
            cpu: 0,
            stage: 0,
            comm: b"ci-runner      ".to_vec(),
            exe: b"/usr/local/bin/holdsecret".to_vec(),
            cmd: b"ci-runner\0\0\0".to_vec(),
            user: b"nobody".to_vec(),
            temp: Vec::new(),
            disk_kb: 0,
            self_copy: Vec::new(),
            nonce: b"0123456789abcdef".to_vec(),
            child_fds: vec![6],
            keep_fds: vec![6, 7],
            max_fd: 7,
            arena_fd: -1,
            status_fd: 5,
            id: 3,
            cwd: b"/tmp".to_vec(),
            env_block: b"PATH=/usr/bin\0APP=demo\0".to_vec(),
            env_nul_len: 64,
            memfd_label: b"ci-runner".to_vec(),
            decoy_token: b"TOK_ROUNDTRIP_1234567890abcdef".to_vec(),
            token_placements_mask: TOK_PLACE_ANON | TOK_PLACE_HEAP,
            thread_comms: b"wrk-1\0wrk-2\0".to_vec(),
            thread_wchans: vec![1, 4],
            fd_specs: b"1:pipe:0\x002:pipe:0\x006:epoll\x007:timerfd\x008:signalfd\0".to_vec(),
            map_files: b"/usr/lib/libc.so.6\0/bin/sh\0".to_vec(),
            wchan_mode: WCHAN_WAIT4,
            seccomp_filters: 2,
            execfn_mode: EXECFN_DEVFD,
            execfn_fd: 4,
            jitter_ms: 25,
            vm_lck_kb: 16,
            rss_shmem_kb: 128,
            rss_file_kb: 1024,
        };
        let bytes = encode_config(&cfg);
        assert_eq!(u32_at(&bytes, 8), CFG_VERSION);
        let fd = sys::anon_sealable_file_named(b"pg:0123456789abcdef", 0);
        assert!(fd >= 0);
        assert!(sys::ftruncate(fd, bytes.len() as u64));
        assert_eq!(sys::pwrite_fd(fd, &bytes, 0), bytes.len() as isize);
        assert!(sys::fd_add_seals(fd));
        assert!(memfd_nonce_matches(fd, b"0123456789abcdef"));
        assert!(!memfd_nonce_matches(fd, b"wrong"));
        let got = read_config(fd).expect("read v5 config");
        assert_eq!(got.comm, b"ci-runner      ");
        assert_eq!(got.nonce, b"0123456789abcdef");
        assert_eq!(got.child_fds, vec![6]);
        assert_eq!(got.keep_fds, vec![6, 7]);
        assert_eq!(got.cwd, b"/tmp");
        assert_eq!(got.env_block, b"PATH=/usr/bin\0APP=demo\0");
        assert_eq!(got.env_nul_len, 64);
        assert_eq!(got.memfd_label, b"ci-runner");
        assert_eq!(got.decoy_token, b"TOK_ROUNDTRIP_1234567890abcdef");
        assert_eq!(got.token_placements_mask, TOK_PLACE_ANON | TOK_PLACE_HEAP);
        assert_eq!(got.thread_comms, b"wrk-1\0wrk-2\0");
        assert_eq!(got.thread_wchans, vec![1, 4]);
        assert_eq!(got.map_files, b"/usr/lib/libc.so.6\0/bin/sh\0");
        assert_eq!(got.wchan_mode, WCHAN_WAIT4);
        assert_eq!(got.seccomp_filters, 2);
        assert_eq!(got.execfn_mode, EXECFN_DEVFD);
        assert_eq!(got.execfn_fd, 4);
        assert_eq!(got.jitter_ms, 25);
        assert_eq!(got.vm_lck_kb, 16);
        assert_eq!(got.rss_shmem_kb, 128);
        assert_eq!(got.rss_file_kb, 1024);
        assert_ne!(got.flags & F_WAIT_TRACER, 0);
        sys::close(fd);
    }

    #[test]
    fn build_envp_for_decoy_nul_span_exact_length() {
        let (buf, env) = build_envp_for_decoy(b"", 64);
        assert_eq!(buf.len(), 64);
        assert_eq!(buf[63], 0);
        assert_eq!(env.len(), 2);
        let s = unsafe { std::ffi::CStr::from_ptr(env[0].cast()) }.to_bytes();
        assert_eq!(s.len(), 63);
    }

    #[test]
    fn build_argv_preserves_trailing_nul_padding() {
        let (_buf1, argv1) = build_argv(b"ci-runner\0--worker\0");
        assert_eq!(argv1.len(), 3); // 2 args + NULL
        let a0 = unsafe { std::ffi::CStr::from_ptr(argv1[0].cast()) }.to_bytes();
        let a1 = unsafe { std::ffi::CStr::from_ptr(argv1[1].cast()) }.to_bytes();
        assert_eq!(a0, b"ci-runner");
        assert_eq!(a1, b"--worker");

        let (_buf2, argv2) = build_argv(b"ci-runner\0\0\0");
        assert_eq!(argv2.len(), 4); // "ci-runner", "", "", NULL
        let b0 = unsafe { std::ffi::CStr::from_ptr(argv2[0].cast()) }.to_bytes();
        let b1 = unsafe { std::ffi::CStr::from_ptr(argv2[1].cast()) }.to_bytes();
        let b2 = unsafe { std::ffi::CStr::from_ptr(argv2[2].cast()) }.to_bytes();
        assert_eq!(b0, b"ci-runner");
        assert_eq!(b1, b"");
        assert_eq!(b2, b"");
    }

    #[test]
    fn clean_env_omits_psgen_nonce() {
        let (_buf, env) = build_envp_clean(b"FOO=1\0BAR=2\0");
        assert_eq!(env.len(), 3); // 2 entries + NULL
        for ptr in &env[..2] {
            let s = unsafe { std::ffi::CStr::from_ptr((*ptr).cast()) }.to_bytes();
            assert!(!s.starts_with(b"PSGEN_NONCE="));
        }
    }
}
