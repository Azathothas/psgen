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
/// Version 3 adds the per-run nonce. A config without one is not honoured:
/// an inherited fd 3 could otherwise name an arbitrary binary to exec and an
/// arbitrary directory to create as root.
const CFG_VERSION_V3: u32 = 3;
/// Version 4 extends version 3 with decoy fidelity fields (clean env, memfd
/// exec, cwd, multi-thread comms, cloned fds, decoy token, seccomp/dumpable,
/// wchan mode, jitter).
const CFG_VERSION_V4: u32 = 4;
const CFG_HEADER: usize = 104;
const CFG_V4_EXT: usize = 40;
const CFG_STAGE_OFF: u64 = 40;
const MAX_FDS: usize = 512;

/// Marks the root of a spawned subtree in `Config::flags`.
pub const F_ROOT: u32 = 1 << 8;
/// Verify nonce via `/proc/self/fd/<fd>` memfd name (`pg:<nonce>`) and never
/// place `PSGEN_NONCE` in `environ`.
pub const F_CLEAN_ENV: u32 = 1 << 9;
/// Copy `/proc/self/exe` into a labeled memfd and re-exec via `execveat`.
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
    /// Per-run secret, also present in `PSGEN_NONCE` (v3) or the sealed config
    /// memfd name `pg:<nonce>` (`F_CLEAN_ENV`).
    pub nonce: Vec<u8>,
    pub child_fds: Vec<i32>,
    pub keep_fds: Vec<i32>,
    pub max_fd: i32,
    pub arena_fd: i32,
    pub status_fd: i32,
    pub id: u32,
    pub cwd: Vec<u8>,
    pub env_block: Vec<u8>,
    pub memfd_label: Vec<u8>,
    pub decoy_token: Vec<u8>,
    pub thread_comms: Vec<u8>,
    pub fd_specs: Vec<u8>,
    pub wchan_mode: u8,
    pub seccomp_filters: u8,
    pub jitter_ms: u32,
    pub vm_lck_kb: u32,
    pub rss_shmem_kb: u32,
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn i32_at(buf: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
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

pub fn read_config(fd: i32) -> Option<Config> {
    let mut r = CfgReader { fd, off: 0 };
    let hdr = r.read_fixed::<CFG_HEADER>()?;
    if &hdr[..8] != CFG_MAGIC {
        return None;
    }
    let ver = u32_at(&hdr, 8);
    if ver != CFG_VERSION_V3 && ver != CFG_VERSION_V4 {
        return None;
    }
    let flags = u32_at(&hdr, 12);
    let vsz_kb = u32_at(&hdr, 16);
    let rss_kb = u32_at(&hdr, 20);
    let uid = u32_at(&hdr, 24);
    let gid = u32_at(&hdr, 28);
    let duration = u32_at(&hdr, 32);
    let cpu = u32_at(&hdr, 36);
    let stage = u32_at(&hdr, 40);
    let comm_len = u32_at(&hdr, 44) as usize;
    let exe_len = u32_at(&hdr, 48) as usize;
    let cmd_len = u32_at(&hdr, 52) as usize;
    let user_len = u32_at(&hdr, 56) as usize;
    let temp_len = u32_at(&hdr, 60) as usize;
    let child_count = u32_at(&hdr, 64) as usize;
    let keep_count = u32_at(&hdr, 68) as usize;
    let max_fd = i32_at(&hdr, 72);
    let arena_fd = i32_at(&hdr, 76);
    let status_fd = i32_at(&hdr, 80);
    let id = u32_at(&hdr, 84);
    let disk_kb = u32_at(&hdr, 88);
    let self_len = u32_at(&hdr, 92) as usize;
    let nonce_len = u32_at(&hdr, 96) as usize;
    if child_count > MAX_FDS || keep_count > MAX_FDS || !(0..=(1 << 20)).contains(&max_fd) {
        return None;
    }
    let fds_buf = r.read_capped((child_count + keep_count) * 4, MAX_FDS * 8)?;
    let mut child_fds = Vec::with_capacity(child_count);
    let mut keep_fds = Vec::with_capacity(keep_count);
    for i in 0..child_count {
        child_fds.push(i32_at(&fds_buf, i * 4));
    }
    for i in 0..keep_count {
        keep_fds.push(i32_at(&fds_buf, (child_count + i) * 4));
    }
    let comm = r.read_capped(comm_len, 64)?;
    let exe = r.read_capped(exe_len, 4096)?;
    let cmd = r.read_capped(cmd_len, 4096)?;
    let user = r.read_capped(user_len, 64)?;
    let temp = r.read_capped(temp_len, 4096)?;
    let self_copy = r.read_capped(self_len, 4096)?;
    let nonce = r.read_capped(nonce_len, 64)?;

    let (
        cwd,
        env_block,
        memfd_label,
        decoy_token,
        thread_comms,
        fd_specs,
        wchan_mode,
        seccomp_filters,
        jitter_ms,
        vm_lck_kb,
        rss_shmem_kb,
    ) = if ver == CFG_VERSION_V4 {
        let ext = r.read_fixed::<CFG_V4_EXT>()?;
        let packed = u32_at(&ext, 24);
        let jitter_ms = u32_at(&ext, 28);
        let vm_lck_kb = u32_at(&ext, 32);
        let rss_shmem_kb = u32_at(&ext, 36);
        let cwd = r.read_capped(u32_at(&ext, 0) as usize, 4096)?;
        let env_block = r.read_capped(u32_at(&ext, 4) as usize, 65536)?;
        let memfd_label = r.read_capped(u32_at(&ext, 8) as usize, 256)?;
        let decoy_token = r.read_capped(u32_at(&ext, 12) as usize, 4096)?;
        let thread_comms = r.read_capped(u32_at(&ext, 16) as usize, 4096)?;
        let fd_specs = r.read_capped(u32_at(&ext, 20) as usize, 16384)?;
        (
            cwd,
            env_block,
            memfd_label,
            decoy_token,
            thread_comms,
            fd_specs,
            (packed & 0xff) as u8,
            ((packed >> 8) & 0xff) as u8,
            jitter_ms,
            vm_lck_kb,
            rss_shmem_kb,
        )
    } else {
        (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            0,
            0,
            0,
            0,
        )
    };

    Some(Config {
        flags,
        vsz_kb,
        rss_kb,
        uid,
        gid,
        duration,
        cpu,
        stage,
        comm,
        exe,
        cmd,
        user,
        temp,
        disk_kb,
        self_copy,
        nonce,
        child_fds,
        keep_fds,
        max_fd,
        arena_fd,
        status_fd,
        id,
        cwd,
        env_block,
        memfd_label,
        decoy_token,
        thread_comms,
        fd_specs,
        wchan_mode,
        seccomp_filters,
        jitter_ms,
        vm_lck_kb,
        rss_shmem_kb,
    })
}

pub fn encode_config(c: &Config) -> Vec<u8> {
    let v4_flags = F_CLEAN_ENV
        | F_EXE_MEMFD
        | F_NON_DUMPABLE
        | F_NO_NEW_PRIVS
        | F_PTRACE_CHILDREN
        | F_WAIT_TRACER;
    let is_v4 = (c.flags & v4_flags) != 0
        || !c.cwd.is_empty()
        || !c.env_block.is_empty()
        || !c.memfd_label.is_empty()
        || !c.decoy_token.is_empty()
        || !c.thread_comms.is_empty()
        || !c.fd_specs.is_empty()
        || c.wchan_mode != 0
        || c.seccomp_filters != 0
        || c.jitter_ms != 0
        || c.vm_lck_kb != 0
        || c.rss_shmem_kb != 0;
    let extra_cap = if is_v4 {
        CFG_V4_EXT
            + c.cwd.len()
            + c.env_block.len()
            + c.memfd_label.len()
            + c.decoy_token.len()
            + c.thread_comms.len()
            + c.fd_specs.len()
    } else {
        0
    };
    let mut out = Vec::with_capacity(
        CFG_HEADER
            + (c.child_fds.len() + c.keep_fds.len()) * 4
            + c.comm.len()
            + c.exe.len()
            + c.cmd.len()
            + c.user.len()
            + c.temp.len()
            + c.self_copy.len()
            + c.nonce.len()
            + extra_cap,
    );
    out.extend_from_slice(CFG_MAGIC);
    push_u32(
        &mut out,
        if is_v4 {
            CFG_VERSION_V4
        } else {
            CFG_VERSION_V3
        },
    );
    push_u32(&mut out, c.flags);
    push_u32(&mut out, c.vsz_kb);
    push_u32(&mut out, c.rss_kb);
    push_u32(&mut out, c.uid);
    push_u32(&mut out, c.gid);
    push_u32(&mut out, c.duration);
    push_u32(&mut out, c.cpu);
    push_u32(&mut out, c.stage);
    push_u32(&mut out, c.comm.len() as u32);
    push_u32(&mut out, c.exe.len() as u32);
    push_u32(&mut out, c.cmd.len() as u32);
    push_u32(&mut out, c.user.len() as u32);
    push_u32(&mut out, c.temp.len() as u32);
    push_u32(&mut out, c.child_fds.len() as u32);
    push_u32(&mut out, c.keep_fds.len() as u32);
    push_i32(&mut out, c.max_fd);
    push_i32(&mut out, c.arena_fd);
    push_i32(&mut out, c.status_fd);
    push_u32(&mut out, c.id);
    push_u32(&mut out, c.disk_kb);
    push_u32(&mut out, c.self_copy.len() as u32);
    push_u32(&mut out, c.nonce.len() as u32);
    push_u32(&mut out, 0);
    for fd in &c.child_fds {
        push_i32(&mut out, *fd);
    }
    for fd in &c.keep_fds {
        push_i32(&mut out, *fd);
    }
    out.extend_from_slice(&c.comm);
    out.extend_from_slice(&c.exe);
    out.extend_from_slice(&c.cmd);
    out.extend_from_slice(&c.user);
    out.extend_from_slice(&c.temp);
    out.extend_from_slice(&c.self_copy);
    out.extend_from_slice(&c.nonce);
    if is_v4 {
        push_u32(&mut out, c.cwd.len() as u32);
        push_u32(&mut out, c.env_block.len() as u32);
        push_u32(&mut out, c.memfd_label.len() as u32);
        push_u32(&mut out, c.decoy_token.len() as u32);
        push_u32(&mut out, c.thread_comms.len() as u32);
        push_u32(&mut out, c.fd_specs.len() as u32);
        push_u32(
            &mut out,
            (c.wchan_mode as u32) | ((c.seccomp_filters as u32) << 8),
        );
        push_u32(&mut out, c.jitter_ms);
        push_u32(&mut out, c.vm_lck_kb);
        push_u32(&mut out, c.rss_shmem_kb);
        out.extend_from_slice(&c.cwd);
        out.extend_from_slice(&c.env_block);
        out.extend_from_slice(&c.memfd_label);
        out.extend_from_slice(&c.decoy_token);
        out.extend_from_slice(&c.thread_comms);
        out.extend_from_slice(&c.fd_specs);
    }
    out
}

fn set_stage(fd: i32, stage: u32) -> bool {
    let b = stage.to_le_bytes();
    sys::pwrite_fd(fd, &b, CFG_STAGE_OFF) == b.len() as isize
}

fn close_above(first: i32) {
    unsafe {
        let _ = libc::syscall(
            libc::SYS_close_range,
            first as libc::c_long,
            u32::MAX as libc::c_long,
            0 as libc::c_long,
        );
    }
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

pub fn build_argv(cmd: &[u8]) -> (Vec<u8>, Vec<*const u8>) {
    if cmd.contains(&0) {
        let mut buf = cmd.to_vec();
        if buf.last() != Some(&0) {
            buf.push(0);
        }
        let mut argv: Vec<*const u8> = Vec::new();
        let mut start = 0usize;
        for i in 0..buf.len() {
            if buf[i] == 0 {
                argv.push(unsafe { buf.as_ptr().add(start) });
                start = i + 1;
            }
        }
        if argv.is_empty() {
            argv.push(buf.as_ptr());
        }
        argv.push(std::ptr::null());
        return (buf, argv);
    }
    let mut buf = cmd.to_vec();
    while buf.last() == Some(&b' ') {
        buf.pop();
    }
    buf.push(0);
    let mut argv: Vec<*const u8> = Vec::new();
    argv.push(buf.as_ptr());
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b' ' {
            buf[i] = 0;
            while i + 1 < buf.len() && buf[i + 1] == b' ' {
                i += 1;
                buf[i] = 0;
            }
            if i + 1 < buf.len() && buf[i + 1] != 0 {
                argv.push(unsafe { buf.as_ptr().add(i + 1) });
            }
        }
        i += 1;
    }
    argv.push(std::ptr::null());
    (buf, argv)
}

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
    #[allow(clippy::manual_c_str_literals)]
    let path = b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0";
    #[allow(clippy::manual_c_str_literals)]
    let lang = b"LANG=C.UTF-8\0";
    let mut v: Vec<*const u8> = Vec::with_capacity(4);
    v.push(path.as_ptr());
    v.push(lang.as_ptr());
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

/// The nonce the injector placed in this process's environment.
fn env_nonce() -> Vec<u8> {
    for (k, v) in std::env::vars_os() {
        if k.as_bytes() == NONCE_ENV.as_bytes() {
            return v.as_bytes().to_vec();
        }
    }
    Vec::new()
}

/// Build a clean `envp` without `PSGEN_NONCE`. When `env_block` is non-empty,
/// it is parsed as NUL-separated `KEY=VAL` entries; otherwise a minimal
/// `PATH` + `LANG` environment is used.
pub fn build_envp_clean(env_block: &[u8]) -> (Vec<u8>, Vec<*const u8>) {
    if env_block.is_empty() {
        #[allow(clippy::manual_c_str_literals)]
        let path = b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0";
        #[allow(clippy::manual_c_str_literals)]
        let lang = b"LANG=C.UTF-8\0";
        return (
            Vec::new(),
            vec![path.as_ptr(), lang.as_ptr(), std::ptr::null()],
        );
    }
    let mut buf = env_block.to_vec();
    if buf.last() != Some(&0) {
        buf.push(0);
    }
    let mut env: Vec<*const u8> = Vec::new();
    let mut start = 0usize;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            if i > start {
                env.push(unsafe { buf.as_ptr().add(start) });
            }
            start = i + 1;
        }
    }
    env.push(std::ptr::null());
    (buf, env)
}

fn exec_env(cfg: &Config) -> (Vec<u8>, Vec<*const u8>) {
    if cfg.flags & F_CLEAN_ENV != 0 {
        build_envp_clean(&cfg.env_block)
    } else {
        (Vec::new(), envp())
    }
}

/// Verify that open memfd `fd` carries `/memfd:pg:<nonce>` (optionally followed
/// by ` (deleted)`), matching `nonce` without needing `PSGEN_NONCE` in `environ`.
pub fn memfd_nonce_matches(fd: i32, nonce: &[u8]) -> bool {
    if nonce.is_empty() || fd < 0 {
        return false;
    }
    let mut path = Buf::new();
    path.push_str("/proc/self/fd/");
    path.push_u64(fd as u64);
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

/// `PSGEN_NONCE=<hex>\0` for this process's own nonce, or empty.
fn env_nonce_line() -> Vec<u8> {
    let n = env_nonce();
    if n.is_empty() {
        Vec::new()
    } else {
        nonce_env_line(&n)
    }
}

/// Whether `path` is a shadow copy this run created: a `psgen-stub` inside a
/// staging directory owned by the caller. Anything else must not be executed
/// on the strength of a config file descriptor.
/// Whether `path` is a shadow copy this run may execute.
///
/// The name and the parent directory are checked first, then the leaf itself.
/// Metadata is not enough on its own: a filesystem can report a leaf as a
/// regular file with any bytes behind it, and a hardlink is a regular file by
/// every metadata measure. What is checked is the *opened* descriptor, so the
/// object that is executed is the object that was checked:
///
/// 1. `O_NOFOLLOW` refuses a symlink at the leaf, including one swapped in
///    between the check and the open.
/// 2. `fstat` on that descriptor must say regular file, owned by this uid, with
///    a link count of one: a hardlink adds a link, so it is refused, and the
///    single link the injector made is what remains.
/// 3. For a root run the descriptor's filesystem must not be FUSE or any other
///    filesystem that forges ownership or link counts.
fn safe_copy(path: &[u8]) -> bool {
    if path.is_empty() || crate::str::basename(path) != b"psgen-stub" {
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
    if sys::geteuid() == 0 {
        if let Some(fs) = sys::fd_fs_type(fd) {
            if fs == sys::FUSE_SUPER_MAGIC || fs == sys::OVERLAYFS_SUPER_MAGIC {
                return false;
            }
        }
    }
    true
}

/// Whether `dir` is a staging directory this run may write into.
fn safe_temp(dir: &[u8]) -> bool {
    !dir.is_empty() && crate::inject::safe_temp_dir(dir)
}

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

fn write_id_map(path: &str, id: u32) -> bool {
    let mut b = Buf::new();
    b.push_str("0 ");
    b.push_u64(id as u64);
    b.push_str(" 1\n");
    std::fs::write(path, b.as_bytes()).is_ok()
}

pub(crate) fn enter_mount_ns() -> bool {
    if sys::geteuid() == 0 {
        if !sys::unshare(sys::CLONE_NEWNS) {
            return false;
        }
        // The root path must be private before any bind, or the bind leaks
        // into the host mount table.
        return sys::mount(b"", b"/", b"", sys::MS_REC | sys::MS_PRIVATE, b"");
    }
    let uid = sys::geteuid();
    let gid = sys::getegid();
    if !sys::unshare(sys::CLONE_NEWUSER | sys::CLONE_NEWNS) {
        return false;
    }
    let _ = std::fs::write("/proc/self/setgroups", b"deny");
    if !write_id_map("/proc/self/uid_map", uid) || !write_id_map("/proc/self/gid_map", gid) {
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
    if anc == Path::new("/")
        || anc == Path::new("/usr")
        || anc == Path::new("/lib")
        || anc == Path::new("/lib64")
        || anc == Path::new("/usr/lib")
        || anc == Path::new("/usr/lib64")
        || anc.starts_with("/usr/lib")
        || anc.starts_with("/usr/lib64")
        || anc.starts_with("/lib")
        || anc.starts_with("/lib64")
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
    let comps: Vec<_> = rel.components().collect();
    let mut cur: PathBuf = temp_path.clone();
    for (i, c) in comps.iter().enumerate() {
        cur.push(c);
        if i + 1 == comps.len() {
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
    let p = match sys::cstr(b"/proc/self/exe") {
        Some(p) => p,
        None => return -1,
    };
    let r = unsafe { libc::syscall(SYS_OPEN_TREE, AT_FDCWD, p.as_ptr(), OPEN_TREE_CLONE) };
    if r < 0 {
        -1
    } else {
        r as i32
    }
}

fn move_mount_to(tree: i32, target: &[u8]) -> bool {
    let empty = match sys::cstr(b"") {
        Some(e) => e,
        None => return false,
    };
    let t = match sys::cstr(target) {
        Some(t) => t,
        None => return false,
    };
    let r = unsafe {
        libc::syscall(
            SYS_MOVE_MOUNT,
            tree as libc::c_long,
            empty.as_ptr(),
            AT_FDCWD,
            t.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    r == 0
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
    if target.is_empty() || target[0] != b'/' {
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
        if let Some(fs) = sys::path_fs_type(target) {
            if fs == sys::FUSE_SUPER_MAGIC || fs == sys::OVERLAYFS_SUPER_MAGIC {
                return false;
            }
        }
        // The target can be created (a missing template path gets a staging
        // binding), so check the nearest existing ancestor as well.
        let mut p = Path::new(OsStr::from_bytes(target));
        while let Some(parent) = p.parent() {
            if let Some(fs) = sys::path_fs_type(parent.as_os_str().as_bytes()) {
                if fs == sys::FUSE_SUPER_MAGIC || fs == sys::OVERLAYFS_SUPER_MAGIC {
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

fn fork_children(cfg: &Config) {
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
    if matches!(
        sys::fd_fs_type(fd),
        Some(sys::FUSE_SUPER_MAGIC) | Some(sys::OVERLAYFS_SUPER_MAGIC)
    ) {
        return false;
    }
    if sys::fd_owner(fd) != Some(sys::geteuid()) {
        return false;
    }
    matches!(fd_kind(fd), FdKind::SealedAnon)
}

fn exec_with_cfg(path: &[u8], cfg: &Config) {
    let (buf, argv) = build_argv(&cfg.cmd);
    let (env_buf, env) = exec_env(cfg);
    sys::execve(path, &argv, &env);
    let _ = (&buf, &env_buf);
}

fn exec_memfd_self(cfg: &Config) {
    let label = if cfg.memfd_label.is_empty() {
        &cfg.comm[..]
    } else {
        &cfg.memfd_label[..]
    };
    let mfd = sys::memfd_exec_copy(label, b"/proc/self/exe");
    if mfd >= 0 {
        let (buf, argv) = build_argv(&cfg.cmd);
        let (env_buf, env) = exec_env(cfg);
        sys::fexecve(mfd, &argv, &env);
        let _ = (&buf, &env_buf);
        sys::close(mfd);
    }
}

pub fn child_entry(fd: i32) -> ! {
    let mut child = match read_config(fd) {
        Some(c) => c,
        None => sys::exit(1),
    };
    let nonce_ok = if child.flags & F_CLEAN_ENV != 0 {
        memfd_nonce_matches(fd, &child.nonce)
    } else {
        child.nonce == env_nonce()
    };
    if child.stage != 0 || child.nonce.is_empty() || !nonce_ok || !config_fd_ok(fd) {
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
    if sys::ioctl(master, sys::TIOCSPTLCK, &unlock as *const i32 as usize) < 0 {
        sys::close(master);
        return false;
    }
    let mut ptn: u32 = 0;
    if sys::ioctl(master, sys::TIOCGPTN, &mut ptn as *mut u32 as usize) < 0 {
        sys::close(master);
        return false;
    }
    let mut path = b"/dev/pts/".to_vec();
    let mut b = Buf::new();
    b.push_u64(ptn as u64);
    path.extend_from_slice(b.as_bytes());
    let slave = sys::open(&path, sys::O_RDWR | sys::O_NOCTTY, 0);
    if slave < 0 {
        sys::close(master);
        return false;
    }
    if sys::ioctl(slave, sys::TIOCSCTTY, 0) < 0 {
        sys::close(slave);
        sys::close(master);
        return false;
    }
    if sys::dup2(slave, 0) < 0 || sys::dup2(slave, 1) < 0 || sys::dup2(slave, 2) < 0 {
        sys::close(slave);
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
        core::ptr::write_volatile(&mut stack[0], 1);
    }
    core::hint::black_box(&stack);
    let end = arg
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(arg.comm.len());
    if end > 0 {
        sys::prctl_set_name(&arg.comm[..end]);
    }
    THREAD_READY.store(true, std::sync::atomic::Ordering::SeqCst);
    sys::wait_wchan(arg.wchan_mode);
}

fn spawn_parked_thread(comm: Option<&[u8]>, wchan_mode: u8) {
    use std::sync::atomic::Ordering;
    THREAD_READY.store(false, Ordering::SeqCst);
    let mut arg = ThreadArg {
        comm: [0u8; 16],
        wchan_mode,
    };
    if let Some(name) = comm {
        let n = name.len().min(15);
        arg.comm[..n].copy_from_slice(&name[..n]);
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

fn start_threads_from_comms(thread_comms: &[u8], wchan_mode: u8) {
    let mut spawned = 0usize;
    for comm in thread_comms.split(|b| *b == 0) {
        if comm.is_empty() {
            continue;
        }
        if spawned >= 64 {
            break;
        }
        spawn_parked_thread(Some(comm), wchan_mode);
        spawned += 1;
    }
}

fn apply_fd_specs(specs: &[u8], status_fd: i32, deferred_status_only: bool) {
    for entry in specs.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
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
        if deferred_status_only {
            if target_fd != status_fd {
                continue;
            }
        } else if target_fd == status_fd {
            continue;
        }
        let kind = &entry[colon + 1..];
        let src_fd = if kind == b"null" {
            sys::open(b"/dev/null", sys::O_RDWR, 0)
        } else if kind == b"pipe" {
            match sys::pipe2_pair() {
                Some((r, w)) => {
                    sys::close(w);
                    r
                }
                None => -1,
            }
        } else if kind == b"socket" {
            match sys::socketpair_unix() {
                Some((a, b)) => {
                    sys::close(b);
                    a
                }
                None => -1,
            }
        } else if kind == b"eventfd" {
            sys::eventfd_open()
        } else if let Some(name) = kind.strip_prefix(b"memfd:") {
            sys::memfd_dummy(name)
        } else {
            -1
        };
        if src_fd >= 0 && src_fd != target_fd {
            let _ = sys::dup2(src_fd, target_fd);
            sys::close(src_fd);
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
    let pid = sys::getpid();
    let mut path = Buf::new();
    path.push_str("/proc/self/task/");
    path.push_u64(pid as u64);
    path.push_str("/children");
    let mut buf = [0u8; 4096];
    let Some(n) = sys::read_file(path.as_bytes(), &mut buf) else {
        return;
    };
    let mut child_pids: Vec<i32> = Vec::new();
    for tok in buf[..n].split(|b| b.is_ascii_whitespace()) {
        if tok.is_empty() {
            continue;
        }
        if let Some(v) = crate::str::parse_u64(tok) {
            if let Ok(cpid) = i32::try_from(v) {
                if cpid > 1 {
                    child_pids.push(cpid);
                }
            }
        }
    }
    for cpid in child_pids {
        // Wait briefly for the child to close its config fd 3 (signaling all
        // execve/fexecve calls are complete) so PTRACE_SEIZE does not catch an
        // execve SIGTRAP stop. Checking the link target also handles fd 3 being
        // reused by apply_fd_specs.
        let mut fd3 = Buf::new();
        fd3.push_str("/proc/");
        fd3.push_u64(cpid as u64);
        fd3.push_str("/fd/3");
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

fn finalize_before_park(cfg: &Config, dev: u32) {
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
        apply_fd_specs(&cfg.fd_specs, cfg.status_fd, true);
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
    use std::io::Write;
    let dir = PathBuf::from(OsStr::from_bytes(&cfg.temp));
    let path = dir.join("data.bin");
    // Open without O_TRUNC first so a pre-existing hardlink placed in the
    // staging directory cannot be truncated before its link count is checked.
    let fd = sys::open(
        path.as_os_str().as_bytes(),
        sys::O_WRONLY | sys::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o644,
    );
    if fd < 0 {
        return false;
    }
    let st = match sys::fd_stat(fd) {
        Some(s) => s,
        None => {
            sys::close(fd);
            return false;
        }
    };
    if !st.is_reg() || st.nlink != 1 || st.uid != sys::geteuid() {
        sys::close(fd);
        return false;
    }
    if !sys::ftruncate(fd, 0) {
        sys::close(fd);
        return false;
    }
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd) };
    let chunk = vec![0x5au8; 1024 * 1024];
    let mut left = cfg.disk_kb as u64 * 1024;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        if f.write_all(&chunk[..n]).is_err() {
            return false;
        }
        left -= n as u64;
    }
    if f.sync_data().is_err() {
        return false;
    }
    if cfg.uid != 0 || cfg.gid != 0 {
        use std::os::unix::io::AsRawFd;
        let _ = sys::fchown(f.as_raw_fd(), cfg.uid, cfg.gid);
    }
    true
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

fn run(cfg: Config) -> ! {
    // A threaded glibc process reserves a 64 MiB malloc arena per thread,
    // which would blow the template's VSZ. Cap it at one arena.
    #[cfg(target_env = "gnu")]
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 1);
    }
    // A master must reap its children, or `stop` leaves zombies in the tree.
    // A status reader that exits early must not kill the stub with SIGPIPE.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
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
fn finish_and_park_with_token(cfg: &Config, dev: u32, token_mmap: *mut u8) -> ! {
    let mut stack_token = [0u8; 4096];
    let n = cfg.decoy_token.len().min(stack_token.len());
    for i in 0..n {
        unsafe {
            stack_token
                .as_mut_ptr()
                .add(i)
                .write_volatile(cfg.decoy_token[i]);
        }
    }
    core::hint::black_box(&stack_token);
    core::hint::black_box(token_mmap);

    finalize_before_park(cfg, dev);
    if cfg.flags & corpus::F_BUSY as u32 != 0 {
        busy_loop(cfg.cpu, cfg.duration);
    }
    wait_wchan_keep_frame(cfg.wchan_mode, stack_token.as_ptr());
    core::hint::black_box(&stack_token);
    core::hint::black_box(token_mmap);
    sys::exit(0);
}

fn run_post_fork(cfg: Config) -> ! {
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
    // is retired in the visible stub. The nonce stays in the environment it
    // was exec'd with; `/proc/PID/environ` reads the initial stack, so an
    // `unsetenv` here would not hide it.
    sys::close(3);

    let cwd_ok = !cfg.cwd.is_empty()
        && std::env::set_current_dir(Path::new(OsStr::from_bytes(&cfg.cwd))).is_ok();
    if !cwd_ok {
        let _ = std::env::set_current_dir("/");
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
    }

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

    // Spawn worker threads BEFORE pad_rss / pad_vsz so thread stacks and TLS
    // are accounted for in the final VmRSS / VmSize targets.
    if !cfg.thread_comms.is_empty() {
        start_threads_from_comms(&cfg.thread_comms, cfg.wchan_mode);
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
        let p = sys::mmap(
            len,
            sys::PROT_READ | sys::PROT_WRITE,
            sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
            -1,
            0,
        );
        if !p.is_null() {
            touch_pages(p, len);
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
            let len = shmem_kb * 1024;
            let p = sys::mmap(
                len,
                sys::PROT_READ | sys::PROT_WRITE,
                sys::MAP_SHARED | sys::MAP_ANONYMOUS,
                -1,
                0,
            );
            if !p.is_null() {
                touch_pages(p, len);
            }
        }
    }
    if !cfg.fd_specs.is_empty() {
        apply_fd_specs(&cfg.fd_specs, cfg.status_fd, false);
    }

    let mut token_mmap: *mut u8 = core::ptr::null_mut();
    if !cfg.decoy_token.is_empty() {
        let page = (sys::page_kb() * 1024).max(4096) as usize;
        let map_len = cfg.decoy_token.len().max(page);
        let p = sys::mmap(
            map_len,
            sys::PROT_READ | sys::PROT_WRITE,
            sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
            -1,
            0,
        );
        if !p.is_null() {
            for (i, b) in cfg.decoy_token.iter().enumerate() {
                unsafe {
                    p.add(i).write_volatile(*b);
                }
            }
            token_mmap = p;
        }
    }

    if cfg.flags & F_CLEAN_ENV != 0 && (cfg.rss_kb > 0 || cfg.vsz_kb > 0) {
        let (_, cur_rss, cur_vsz, _) = read_self_status_vals();
        let delta_rss = cfg.rss_kb.min(8192).saturating_sub(cur_rss);
        if delta_rss > 0 {
            let len = (delta_rss as usize) * 1024;
            let p = sys::mmap(
                len,
                sys::PROT_READ | sys::PROT_WRITE,
                sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
                -1,
                0,
            );
            if !p.is_null() {
                touch_pages(p, len);
            }
        }
        let delta_vsz = cfg
            .vsz_kb
            .min(65536)
            .saturating_sub(cur_vsz.saturating_add(delta_rss));
        if delta_vsz > 0 {
            let len = (delta_vsz as usize) * 1024;
            let _ = sys::mmap(
                len,
                sys::PROT_NONE,
                sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_NORESERVE,
                -1,
                0,
            );
        }
    }

    if !cfg.decoy_token.is_empty() {
        finish_and_park_with_token(&cfg, dev, token_mmap);
    }

    finalize_before_park(&cfg, dev);

    if cfg.flags & corpus::F_BUSY as u32 != 0 {
        busy_loop(cfg.cpu, cfg.duration);
    }
    sys::wait_wchan(cfg.wchan_mode);
}

/// Returns when this process was not started by `psgen inject`. When it was,
/// `run` never returns.
///
/// What makes a config trustworthy is the descriptor, not the nonce. Three
/// things are checked before the config is acted on:
///
/// 1. Any setuid or setgid install is refused outright. A forged config on
///    fd 3 would otherwise be a way to run code as root or with a privileged
///    group (such as `disk` or `shadow`).
/// 2. The descriptor must be the object the injector made: a `memfd` created by
///    `memfd_create` and sealed with the size seals. No process can obtain a
///    memfd from an inode that already existed, so holding the descriptor is
///    evidence of having created it. Ownership is *not* part of the proof: a
///    file root owns can still be opened by an unprivileged caller, unlinked,
///    and passed through `sudo`, and the descriptor would then be root-owned
///    and anonymous without being the injector's. Unlinked files and
///    `O_TMPFILE` descriptors are that shape and are refused.
/// 3. The config must carry the nonce this process was started with, which
///    the injector passes on `PSGEN_NONCE`. The nonce is a run tag, not a
///    secret: it travels in the environment, which is the same trust plane as
///    the descriptor, so a caller who controls fd 3 can set it too. It is
///    checked so a stray descriptor from an unrelated run of the same user is
///    ignored rather than half-applied, and so a supervisor that inherits fd 3
///    without choosing the environment does not get a stub.
pub fn maybe_run() {
    if sys::geteuid() != sys::getuid() || sys::getegid() != sys::getgid() {
        sys::err(
            b"psgen: refusing to run setuid or setgid; install it without the setuid/setgid bit\n",
        );
        sys::exit(2);
    }
    let cfg = match read_config(3) {
        Some(c) => c,
        None => return,
    };
    if matches!(
        sys::fd_fs_type(3),
        Some(sys::FUSE_SUPER_MAGIC) | Some(sys::OVERLAYFS_SUPER_MAGIC)
    ) {
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
    if cfg.nonce.is_empty() {
        sys::err(b"psgen: refusing a config descriptor without a run tag\n");
        sys::exit(2);
    }
    if cfg.flags & F_CLEAN_ENV != 0 {
        if !memfd_nonce_matches(3, &cfg.nonce) {
            // Not a config this process was started with. Fall through to the
            // normal command line, which will reject the stray argument.
            return;
        }
    } else {
        if cfg.nonce != env_nonce() {
            // Not a config this process was started with. Fall through to the
            // normal command line, which will reject the stray argument.
            return;
        }
        // Carry the nonce through any further exec this process performs: the
        // bind tier re-executes itself through the template path, and that process
        // reads the same fd 3.
        set_nonce_line(&env_nonce_line());
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
    fn config_v3_and_v4_round_trip() {
        let v3 = Config {
            flags: F_ROOT | corpus::F_THREADS as u32,
            vsz_kb: 4096,
            rss_kb: 1024,
            uid: 1000,
            gid: 1000,
            duration: 30,
            cpu: 0,
            stage: 0,
            comm: b"worker".to_vec(),
            exe: b"/usr/bin/worker".to_vec(),
            cmd: b"/usr/bin/worker --serve".to_vec(),
            user: b"nobody".to_vec(),
            temp: Vec::new(),
            disk_kb: 0,
            self_copy: Vec::new(),
            nonce: b"0123456789abcdef".to_vec(),
            child_fds: vec![6],
            keep_fds: vec![6, 7],
            max_fd: 7,
            arena_fd: 4,
            status_fd: 5,
            id: 3,
            cwd: Vec::new(),
            env_block: Vec::new(),
            memfd_label: Vec::new(),
            decoy_token: Vec::new(),
            thread_comms: Vec::new(),
            fd_specs: Vec::new(),
            wchan_mode: 0,
            seccomp_filters: 0,
            jitter_ms: 0,
            vm_lck_kb: 0,
            rss_shmem_kb: 0,
        };
        let bytes3 = encode_config(&v3);
        assert_eq!(u32_at(&bytes3, 8), CFG_VERSION_V3);
        let fd3 = sys::anon_sealable_file(b"cfg", 0);
        assert!(fd3 >= 0);
        assert!(sys::ftruncate(fd3, bytes3.len() as u64));
        assert_eq!(sys::pwrite_fd(fd3, &bytes3, 0), bytes3.len() as isize);
        assert!(sys::fd_add_seals(fd3));
        let got3 = read_config(fd3).expect("read v3 config");
        assert_eq!(got3.comm, b"worker");
        assert_eq!(got3.nonce, b"0123456789abcdef");
        assert_eq!(got3.child_fds, vec![6]);
        assert_eq!(got3.keep_fds, vec![6, 7]);
        assert_eq!(got3.wchan_mode, 0);
        assert_eq!(got3.vm_lck_kb, 0);
        assert_eq!(got3.rss_shmem_kb, 0);
        assert!(got3.decoy_token.is_empty());
        sys::close(fd3);

        let v4 = Config {
            flags: F_ROOT
                | F_CLEAN_ENV
                | F_EXE_MEMFD
                | F_NON_DUMPABLE
                | F_NO_NEW_PRIVS
                | F_WAIT_TRACER,
            cwd: b"/tmp".to_vec(),
            env_block: b"PATH=/usr/bin\0APP=demo\0".to_vec(),
            memfd_label: b"ci-runner".to_vec(),
            decoy_token: b"TOK_ROUNDTRIP_1234567890abcdef".to_vec(),
            thread_comms: b"wrk-1\0wrk-2\0".to_vec(),
            fd_specs: b"6:pipe\x007:eventfd\0".to_vec(),
            wchan_mode: 3,
            seccomp_filters: 2,
            jitter_ms: 25,
            vm_lck_kb: 16,
            rss_shmem_kb: 128,
            ..v3
        };
        let bytes4 = encode_config(&v4);
        assert_eq!(u32_at(&bytes4, 8), CFG_VERSION_V4);
        let fd4 = sys::anon_sealable_file_named(b"pg:0123456789abcdef", 0);
        assert!(fd4 >= 0);
        assert!(sys::ftruncate(fd4, bytes4.len() as u64));
        assert_eq!(sys::pwrite_fd(fd4, &bytes4, 0), bytes4.len() as isize);
        assert!(sys::fd_add_seals(fd4));
        assert!(memfd_nonce_matches(fd4, b"0123456789abcdef"));
        assert!(!memfd_nonce_matches(fd4, b"wrong"));
        let got4 = read_config(fd4).expect("read v4 config");
        assert_eq!(got4.cwd, b"/tmp");
        assert_eq!(got4.env_block, b"PATH=/usr/bin\0APP=demo\0");
        assert_eq!(got4.memfd_label, b"ci-runner");
        assert_eq!(got4.decoy_token, b"TOK_ROUNDTRIP_1234567890abcdef");
        assert_eq!(got4.thread_comms, b"wrk-1\0wrk-2\0");
        assert_eq!(got4.fd_specs, b"6:pipe\x007:eventfd\0");
        assert_eq!(got4.wchan_mode, 3);
        assert_eq!(got4.seccomp_filters, 2);
        assert_eq!(got4.jitter_ms, 25);
        assert_eq!(got4.vm_lck_kb, 16);
        assert_eq!(got4.rss_shmem_kb, 128);
        assert_ne!(got4.flags & F_WAIT_TRACER, 0);
        sys::close(fd4);
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
