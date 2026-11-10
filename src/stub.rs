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
const CFG_VERSION: u32 = 3;
const CFG_HEADER: usize = 104;
const CFG_STAGE_OFF: u64 = 40;
const MAX_FDS: usize = 512;

/// Marks the root of a spawned subtree in `Config::flags`.
pub const F_ROOT: u32 = 1 << 8;
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
    /// Per-run secret, also present in this process's argv[1]. The injector
    /// generates it; a config handed to the stub by anything else cannot know
    /// it without also choosing argv.
    pub nonce: Vec<u8>,
    pub child_fds: Vec<i32>,
    pub keep_fds: Vec<i32>,
    pub max_fd: i32,
    pub arena_fd: i32,
    pub status_fd: i32,
    pub id: u32,
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

pub fn read_config(fd: i32) -> Option<Config> {
    let mut hdr = [0u8; CFG_HEADER];
    let n = sys::pread_fd(fd, &mut hdr, 0);
    if n < CFG_HEADER as isize || &hdr[..8] != CFG_MAGIC {
        return None;
    }
    if u32_at(&hdr, 8) != CFG_VERSION {
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
    if nonce_len > 64 {
        return None;
    }
    if child_count > MAX_FDS || keep_count > MAX_FDS {
        return None;
    }
    if comm_len > 64 || exe_len > 4096 || cmd_len > 4096 || user_len > 64 || temp_len > 4096 {
        return None;
    }
    if self_len > 4096 {
        return None;
    }
    if !(0..=(1 << 20)).contains(&max_fd) {
        return None;
    }
    let fds_len = (child_count + keep_count) * 4;
    let mut fds_buf = vec![0u8; fds_len];
    if fds_len > 0 {
        let n = sys::pread_fd(fd, &mut fds_buf, CFG_HEADER as u64);
        if n < fds_len as isize {
            return None;
        }
    }
    let mut child_fds = Vec::with_capacity(child_count);
    let mut keep_fds = Vec::with_capacity(keep_count);
    for i in 0..child_count {
        child_fds.push(i32_at(&fds_buf, i * 4));
    }
    for i in 0..keep_count {
        keep_fds.push(i32_at(&fds_buf, (child_count + i) * 4));
    }
    let mut off = (CFG_HEADER + fds_len) as u64;
    let comm = read_bytes(fd, off, comm_len)?;
    off += comm_len as u64;
    let exe = read_bytes(fd, off, exe_len)?;
    off += exe_len as u64;
    let cmd = read_bytes(fd, off, cmd_len)?;
    off += cmd_len as u64;
    let user = read_bytes(fd, off, user_len)?;
    off += user_len as u64;
    let temp = read_bytes(fd, off, temp_len)?;
    off += temp_len as u64;
    let self_copy = read_bytes(fd, off, self_len)?;
    off += self_len as u64;
    let nonce = read_bytes(fd, off, nonce_len)?;
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
    })
}

pub fn encode_config(c: &Config) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CFG_HEADER
            + (c.child_fds.len() + c.keep_fds.len()) * 4
            + c.comm.len()
            + c.exe.len()
            + c.cmd.len()
            + c.user.len()
            + c.temp.len()
            + c.self_copy.len()
            + c.nonce.len(),
    );
    out.extend_from_slice(CFG_MAGIC);
    push_u32(&mut out, CFG_VERSION);
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
    if std::fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid).as_bytes()).is_err() {
        return false;
    }
    if std::fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid).as_bytes()).is_err() {
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

/// Whether a config descriptor has the shape this run creates: owned by the
/// current euid, sealed or unlinked, and not on a FUSE or overlay filesystem
/// where those fields can be forged.
fn config_fd_ok(fd: i32) -> bool {
    if matches!(
        sys::fd_fs_type(fd),
        Some(sys::FUSE_SUPER_MAGIC) | Some(sys::OVERLAYFS_SUPER_MAGIC)
    ) {
        return false;
    }
    let sealed = sys::fd_sealed(fd);
    let unlinked = sys::fd_nlink(fd) == Some(0);
    let owned = sys::fd_owner(fd) == Some(sys::geteuid());
    owned && (sealed || unlinked)
}

pub fn child_entry(fd: i32) -> ! {
    let mut child = match read_config(fd) {
        Some(c) => c,
        None => sys::exit(1),
    };
    if child.stage != 0 || child.nonce.is_empty() || child.nonce != env_nonce() || !config_fd_ok(fd)
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
    let copy = if safe_copy(&child.self_copy) {
        child.self_copy.clone()
    } else {
        Vec::new()
    };
    let exec_path = if !child.exe.is_empty() && setup_exe(&child) {
        child.exe.clone()
    } else if !copy.is_empty() {
        copy.clone()
    } else {
        // Exec the magic link, not the text readlink returns. When the stub
        // has already entered a private mount namespace and the binary lives
        // on another mount, the text path renders relative to that mount and
        // does not exist outside the namespace. The magic link resolves to
        // the file the process is already running, whose path stays visible
        // to the caller.
        b"/proc/self/exe".to_vec()
    };
    let (buf, argv) = build_argv(&child.cmd);
    if sys::dup2(fd, 3) != 3 {
        write_status(&child, -1, 0);
        sys::exit(1);
    }
    if fd != 3 {
        sys::close(fd);
    }
    close_above(6);
    let env = envp();
    sys::execve(&exec_path, &argv, &env);
    if !copy.is_empty() && copy != exec_path {
        let (buf2, argv2) = build_argv(&child.cmd);
        sys::execve(&copy, &argv2, &env);
        let _ = &buf2;
    }
    let _ = &buf;
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
    touch_pages(ptr, len);
    sys::close(cfg.arena_fd);
    let tol = sys::page_kb().max(1);
    let mut ok = false;
    for _ in 0..8 {
        let cur = util::self_rss_kb();
        if cur.abs_diff(target_kb) <= tol {
            ok = true;
            break;
        }
        if cur > trim_kb {
            let drop = cur - trim_kb;
            if drop > trim_kb {
                sys::madvise(ptr, len, sys::MADV_DONTNEED);
                break;
            }
            let start = unsafe { ptr.add(((trim_kb - drop) * 1024) as usize) };
            sys::madvise(start, (drop * 1024) as usize, sys::MADV_DONTNEED);
        } else {
            touch_pages(ptr, len);
        }
    }
    if !ok {
        ok = util::self_rss_kb().abs_diff(target_kb) <= tol;
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

fn start_thread() {
    use std::sync::atomic::Ordering;
    THREAD_READY.store(false, Ordering::SeqCst);
    let h = std::thread::Builder::new().stack_size(64 * 1024).spawn(|| {
        // Touch the new stack before announcing readiness, so the RSS
        // trim that follows sees these pages and does not drift.
        let mut stack = [0u8; 4096];
        unsafe {
            core::ptr::write_volatile(&mut stack[0], 1);
        }
        core::hint::black_box(&stack);
        THREAD_READY.store(true, Ordering::SeqCst);
        loop {
            sys::pause();
        }
    });
    if let Ok(h) = h {
        std::mem::forget(h);
        let mut spins = 0u64;
        while !THREAD_READY.load(Ordering::SeqCst) && spins < 20_000_000 {
            core::hint::spin_loop();
            spins += 1;
        }
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
fn record_live(dir: &[u8]) {
    if dir.is_empty() || !safe_temp(dir) {
        return;
    }
    let start = match crate::live::read_starttime(sys::getpid()) {
        Some(s) => s,
        None => return,
    };
    let mut line = Vec::new();
    line.extend_from_slice(sys::getpid().to_string().as_bytes());
    line.push(b' ');
    line.extend_from_slice(start.to_string().as_bytes());
    line.push(b'\n');
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
    // shell job cleanup does not take the tree with it. Session leaders use
    // setsid; the others use setpgid and keep the caller's session.
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

fn run_post_fork(cfg: Config) -> ! {
    let self_exe = sys::read_link(b"/proc/self/exe").unwrap_or_default();
    record_live(&cfg.temp);
    if let Some(parent) = Path::new(OsStr::from_bytes(&cfg.self_copy)).parent() {
        record_live(parent.as_os_str().as_bytes());
    }

    // Arm the lifetime before anything that can block. A busy stub never
    // returns from its loop, so an alarm armed after the loop would never
    // fire and `--duration` would silently not apply to it.
    if cfg.duration > 0 {
        sys::alarm(cfg.duration);
    }

    let mut dev: u32 = 0;

    // `self_exe` is the canonical destination of the last exec, while cfg.exe
    // may be a symlink to it. Compare against the resolved target, or the
    // mismatch survives the exec and the stub re-execs forever.
    let exe_target = if cfg.exe.is_empty() {
        Vec::new()
    } else {
        resolve_target(&cfg.exe)
    };
    let reexec_exe = !cfg.exe.is_empty() && self_exe != exe_target;
    let copy = if safe_copy(&cfg.self_copy) {
        cfg.self_copy.clone()
    } else {
        Vec::new()
    };
    let reexec_copy = !copy.is_empty() && self_exe != copy && (cfg.exe.is_empty() || reexec_exe);
    if reexec_exe {
        if setup_exe(&cfg) {
            let (buf, argv) = build_argv(&cfg.cmd);
            let env = envp();
            sys::execve(&cfg.exe, &argv, &env);
            let _ = &buf;
        }
        // The bind failed. Fall through to the best path still available
        // rather than execing the original tool path.
        dev |= DEV_EXE;
        if reexec_copy {
            let (buf, argv) = build_argv(&cfg.cmd);
            let env = envp();
            sys::execve(&copy, &argv, &env);
            let _ = &buf;
        }
    } else if cfg.exe.is_empty() && reexec_copy {
        let (buf, argv) = build_argv(&cfg.cmd);
        let env = envp();
        sys::execve(&copy, &argv, &env);
        let _ = &buf;
        dev |= DEV_EXE;
    }

    // Reaching this point means no further exec is needed, so the config fd
    // is retired in the visible stub. The nonce stays in the environment it
    // was exec'd with; `/proc/PID/environ` reads the initial stack, so an
    // `unsetenv` here would not hide it.
    sys::close(3);

    let _ = std::env::set_current_dir("/");
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
    if cfg.flags & corpus::F_THREADS as u32 != 0 {
        start_thread();
    }
    if cfg.rss_kb > 0 && cfg.arena_fd >= 0 && !pad_rss(&cfg) {
        dev |= DEV_RSS;
    }
    if cfg.vsz_kb > 0 && !pad_vsz(&cfg) {
        dev |= DEV_VSZ;
    }

    write_status(&cfg, if dev == 0 { 0 } else { 2 }, dev);

    if cfg.flags & corpus::F_BUSY as u32 != 0 {
        busy_loop(cfg.cpu, cfg.duration);
    }
    loop {
        sys::pause();
    }
}

/// Returns when this process was not started by `psgen inject`. When it was,
/// `run` never returns.
///
/// Three things are checked before the config is acted on:
///
/// 1. Any setuid or setgid install is refused outright. A forged config on
///    fd 3 would otherwise be a way to run code as root or with a privileged
///    group (such as `disk` or `shadow`).
/// 2. The config must carry the nonce this process was started with, which
///    the injector passes on `PSGEN_NONCE`. An inherited fd 3 from a supervisor
///    or a permissive sudo rule does not know it, so the config is ignored and
///    the process behaves like a normal command line.
/// 3. The config descriptor must be one this run could have made: it has no
///    name left (a memfd or an unlinked temporary file), it is sealed when the
///    kernel allows sealing, and it is owned by the uid this process runs as.
///    An fd opened by an unprivileged caller does not survive `sudo`, so a
///    descriptor inherited into a privileged psgen fails the ownership check.
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
    if cfg.nonce.is_empty() || cfg.nonce != env_nonce() {
        // Not a config this process was started with. Fall through to the
        // normal command line, which will reject the stray argument.
        return;
    }
    let sealed = sys::fd_sealed(3);
    let unlinked = sys::fd_nlink(3) == Some(0);
    let owned = sys::fd_owner(3) == Some(sys::geteuid());
    if matches!(
        sys::fd_fs_type(3),
        Some(sys::FUSE_SUPER_MAGIC) | Some(sys::OVERLAYFS_SUPER_MAGIC)
    ) {
        sys::err(b"psgen: refusing a config descriptor on a FUSE filesystem\n");
        sys::exit(2);
    }
    if !owned {
        sys::err(b"psgen: refusing a config descriptor this process does not own\n");
        sys::exit(2);
    }
    if !sealed && !unlinked {
        sys::err(b"psgen: refusing an unsealed, named config descriptor\n");
        sys::exit(2);
    }
    // Carry the nonce through any further exec this process performs: the
    // bind tier re-executes itself through the template path, and that process
    // reads the same fd 3.
    set_nonce_line(&env_nonce_line());
    run(cfg);
}
