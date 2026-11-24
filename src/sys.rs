//! Thin wrappers over the Linux interfaces the tool needs.
//!
//! Everything goes through `libc`, so the same source builds for every Linux
//! architecture Rust supports. Paths are byte strings, matching the corpus and
//! the `/proc` files this tool reads.

use std::ffi::{CString, OsStr};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const O_WRONLY: i32 = libc::O_WRONLY;
pub const O_RDWR: i32 = libc::O_RDWR;
pub const O_CREAT: i32 = libc::O_CREAT;
pub const O_EXCL: i32 = libc::O_EXCL;
pub const O_NOCTTY: i32 = libc::O_NOCTTY;
pub const O_NOFOLLOW: i32 = libc::O_NOFOLLOW;
pub const O_CLOEXEC: i32 = libc::O_CLOEXEC;

pub const W_OK: i32 = libc::W_OK;
pub const X_OK: i32 = libc::X_OK;

pub const PROT_NONE: i32 = libc::PROT_NONE;
pub const PROT_READ: i32 = libc::PROT_READ;
pub const PROT_WRITE: i32 = libc::PROT_WRITE;

pub const MAP_SHARED: i32 = libc::MAP_SHARED;
pub const MAP_PRIVATE: i32 = libc::MAP_PRIVATE;
pub const MAP_ANONYMOUS: i32 = libc::MAP_ANONYMOUS;
pub const MAP_NORESERVE: i32 = libc::MAP_NORESERVE;

pub const MADV_DONTNEED: i32 = libc::MADV_DONTNEED;

pub const SIGKILL: i32 = libc::SIGKILL;

pub const CLONE_NEWNS: i32 = libc::CLONE_NEWNS;
pub const CLONE_NEWUSER: i32 = libc::CLONE_NEWUSER;

// These constants are `c_ulong` on some targets and already `u64` on others,
// so the cast is required on the first kind and redundant on the second.
#[allow(clippy::unnecessary_cast)]
mod consts {
    pub const MS_BIND: u64 = libc::MS_BIND as u64;
    pub const MS_REC: u64 = libc::MS_REC as u64;
    pub const MS_PRIVATE: u64 = libc::MS_PRIVATE as u64;
    pub const TIOCSPTLCK: u64 = libc::TIOCSPTLCK as u64;
    pub const TIOCGPTN: u64 = libc::TIOCGPTN as u64;
    pub const TIOCSCTTY: u64 = libc::TIOCSCTTY as u64;
}

pub use consts::{MS_BIND, MS_PRIVATE, MS_REC, TIOCGPTN, TIOCSCTTY, TIOCSPTLCK};

pub fn cstr(path: &[u8]) -> Option<CString> {
    let body = path.strip_suffix(&[0]).unwrap_or(path);
    CString::new(body).ok()
}

fn path_of(path: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(path.strip_suffix(&[0]).unwrap_or(path)))
}

/// Write to stdout and exit non-zero when the write fails for any reason other
/// than a closed pipe.
///
/// A dropped `ENOSPC` or `EIO` made a truncated table look like a complete one:
/// the caller saw exit 0 and short output. `EPIPE` is not an error — a
/// `| head` exits before the writer does — so it is the one case that stays
/// silent, and the generator that cares stops through `out_checked`.
pub fn out(buf: &[u8]) {
    match io::stdout()
        .write_all(buf)
        .and_then(|()| io::stdout().flush())
    {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {}
        Err(e) => out_failed(e),
    }
}

fn out_message(e: &io::Error) -> Vec<u8> {
    let mut msg = b"psgen: cannot write to stdout: ".to_vec();
    msg.extend_from_slice(e.to_string().as_bytes());
    msg.push(b'\n');
    msg
}

fn out_failed(e: io::Error) -> ! {
    let _ = io::stderr().write_all(&out_message(&e));
    std::process::exit(1)
}

/// What a stdout write means to a generator that may write again.
///
/// The old boolean conflated two questions: whether to keep generating, and
/// whether the write succeeded. Only `EPIPE` answers the first; every other
/// error answers the second with a failure the caller must report. A full
/// filesystem (`ENOSPC`) used to return `true` and exit 0 with the output
/// silently lost.
pub enum OutResult {
    /// The bytes were accepted.
    Ok,
    /// The reader closed the pipe. Not an error, but there is no reader left
    /// to generate for.
    ReaderGone,
    /// The write failed for a reason the caller has to report.
    Failed(io::Error),
}

/// Write to stdout and say which of the three outcomes happened.
pub fn out_checked(buf: &[u8]) -> OutResult {
    match io::stdout()
        .write_all(buf)
        .and_then(|()| io::stdout().flush())
    {
        Ok(()) => OutResult::Ok,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => OutResult::ReaderGone,
        Err(e) => OutResult::Failed(e),
    }
}

/// Report a stdout failure the way `out()` does and return the exit code.
pub fn out_failure(e: io::Error) -> i32 {
    let _ = io::stderr().write_all(&out_message(&e));
    1
}

pub fn err(buf: &[u8]) {
    let _ = io::stderr().write_all(buf);
}

pub fn exit(code: i32) -> ! {
    std::process::exit(code)
}

pub fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// The errno of the failure that just happened, captured immediately.
///
/// `last_error()` reads the thread's errno at the moment it is called, so any
/// intervening call — a `close`, a `remove_dir_all`, a `format!` that allocates,
/// or the `eprintln` cleanup in a caller — can replace it. A syscall wrapper
/// that fails should return this, or nothing at all.
pub fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn read_file(path: &[u8], buf: &mut [u8]) -> Option<usize> {
    let mut f = std::fs::File::open(path_of(path)).ok()?;
    let mut total = 0usize;
    while total < buf.len() {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(total)
}

/// Read at most `max` bytes from `path`, without following a symlink and
/// without blocking on a FIFO, keeping the error for the caller.
pub fn read_file_nofollow_res(path: &[u8], max: usize) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path_of(path))?;
    let mut out = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is larger than the read limit",
        ));
    }
    Ok(out)
}

/// Read at most `max` bytes from `path`, without following a symlink and
/// without blocking on a FIFO.
pub fn read_file_nofollow(path: &[u8], max: usize) -> Option<Vec<u8>> {
    read_file_nofollow_res(path, max).ok()
}

pub fn read_link(path: &[u8]) -> Option<Vec<u8>> {
    std::fs::read_link(path_of(path))
        .ok()
        .map(|p| p.as_os_str().as_bytes().to_vec())
}

/// Whether `bpf(BPF_MAP_CREATE)` is permitted for this caller.
///
/// The command is a well-formed `BPF_MAP_CREATE` of an empty array map, because
/// the permission check (`unprivileged_bpf_disabled`, `CAP_BPF`) runs *after*
/// the kernel has copied and validated the attribute. The previous probe passed
/// `BPF_MAP_LOOKUP_ELEM` with a null attribute and size 0; the kernel rejected
/// that with `EINVAL` before reaching any permission check, so every uid saw
/// `allowed`, including one that `unprivileged_bpf_disabled=2` forbids from
/// creating a map at all.
///
/// `EPERM`, `EACCES` and `ENOSYS` mean a policy, the sysctl, or the kernel
/// refuses the call; anything else — `EINVAL` for an attribute the kernel would
/// not accept, `E2BIG` for too small a buffer — is a verdict about the
/// attribute, which can only be reached once the permission check has passed.
pub fn bpf_allowed() -> bool {
    // struct bpf_attr for BPF_MAP_CREATE: map_type (u32), key_size, value_size,
    // max_entries, map_flags, ... The kernel copies the caller's byte count, so
    // a padded buffer is accepted as long as the named fields are valid.
    let mut attr = [0u8; 48];
    attr[0..4].copy_from_slice(&2u32.to_ne_bytes()); // BPF_MAP_TYPE_ARRAY
    attr[4..8].copy_from_slice(&4u32.to_ne_bytes()); // key_size
    attr[8..12].copy_from_slice(&4u32.to_ne_bytes()); // value_size
    attr[12..16].copy_from_slice(&1u32.to_ne_bytes()); // max_entries
    let r = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            0 as libc::c_int,
            attr.as_ptr(),
            attr.len() as libc::c_uint,
        )
    };
    if r >= 0 {
        // Success returns a descriptor this probe has no use for.
        close(r as i32);
        return true;
    }
    !matches!(errno(), libc::EPERM | libc::EACCES | libc::ENOSYS)
}

/// Whether `SECCOMP_SET_MODE_FILTER` with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
/// is reachable.
///
/// A null program is refused with `EFAULT` or `EINVAL` after the kernel has
/// inspected the arguments, which means the operation is reachable. `EPERM`,
/// `EACCES` and `ENOSYS` mean a policy or the kernel blocks it before that.
pub fn seccomp_user_notif() -> bool {
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1 as libc::c_int,
            0x8 as libc::c_int,
            core::ptr::null::<libc::c_void>(),
        )
    };
    if r != -1 {
        return true;
    }
    !matches!(
        last_error().raw_os_error(),
        Some(libc::EPERM) | Some(libc::EACCES) | Some(libc::ENOSYS)
    )
}

pub fn read_fd(fd: i32, buf: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
}

pub fn pread_fd(fd: i32, buf: &mut [u8], off: u64) -> isize {
    unsafe {
        libc::pread(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            off as libc::off_t,
        )
    }
}

pub fn pwrite_fd(fd: i32, buf: &[u8], off: u64) -> isize {
    unsafe {
        libc::pwrite(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            off as libc::off_t,
        )
    }
}

pub fn write_fd(fd: i32, buf: &[u8]) -> bool {
    let mut rest = buf;
    while !rest.is_empty() {
        let n = unsafe { libc::write(fd, rest.as_ptr() as *const libc::c_void, rest.len()) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if n == 0 {
            return false;
        }
        rest = &rest[n as usize..];
    }
    true
}

pub fn open(path: &[u8], flags: i32, mode: u32) -> i32 {
    let p = match cstr(path) {
        Some(p) => p,
        None => return -1,
    };
    unsafe { libc::open(p.as_ptr(), flags, mode as libc::c_uint) }
}

/// `st_nlink` of the object a descriptor refers to, or None when fstat fails.
///
/// A memfd and an unlinked temporary file both report 0, which is how the stub
/// tells "this file has no name anyone else can open" from a named file handed
/// in by a supervisor.
pub fn fd_nlink(fd: i32) -> Option<u64> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    Some(st.st_nlink as u64)
}

/// The seals the stub requires: the size cannot change and no further seals
/// can be added or removed.
///
/// `F_SEAL_WRITE` is deliberately not used: the stub writes its progress
/// marker into the config after it starts, and a write seal would make that
/// fail on every row.
fn seal_mask() -> i32 {
    libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL
}

/// Everything about one inode that the stub has to trust or not.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub size: u64,
}

impl Stat {
    pub fn is_reg(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }
}

// The field types are `dev_t`, `ino_t`, `nlink_t` and `uid_t`, whose widths
// differ per target; the cast makes them one type for the comparison.
#[allow(clippy::unnecessary_cast)]
fn stat_to(st: &libc::stat) -> Stat {
    Stat {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        mode: st.st_mode,
        nlink: st.st_nlink as u64,
        uid: st.st_uid as u32,
        size: st.st_size as u64,
    }
}

/// `fstat` of an open descriptor.
pub fn fd_stat(fd: i32) -> Option<Stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    Some(stat_to(&st))
}

/// The filesystem type of the object a descriptor refers to, or None when
/// fstatfs fails.
pub fn fd_fs_type(fd: i32) -> Option<i64> {
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut st) } != 0 {
        return None;
    }
    Some(st.f_type as i64)
}

/// The filesystem type of a path, or None when statfs fails.
pub fn path_fs_type(path: &[u8]) -> Option<i64> {
    let p = cstr(path)?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(p.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(st.f_type as i64)
}

/// `FUSE_SUPER_MAGIC`: a FUSE filesystem can report a forged owner and link
/// count, so a config descriptor or staging path on one is never trusted by a
/// root run.
pub const FUSE_SUPER_MAGIC: i64 = 0x6573_5546;

/// `OVERLAYFS_SUPER_MAGIC`: an overlay can present a merged view whose upper
/// layer an unprivileged user controls, so it is treated like FUSE for a root
/// staging leaf.
pub const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c_7630;

/// The owner uid of the object a descriptor refers to, or None when fstat
/// fails.
pub fn fd_owner(fd: i32) -> Option<u32> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    Some(st.st_uid as u32)
}

/// Whether a descriptor carries the seals the stub requires.
pub fn fd_sealed(fd: i32) -> bool {
    let r = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if r < 0 {
        return false;
    }
    r & seal_mask() == seal_mask()
}

/// Apply the size seals to a memfd created with `MFD_ALLOW_SEALING`.
pub fn fd_add_seals(fd: i32) -> bool {
    unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seal_mask()) == 0 }
}

/// Flush a file descriptor to stable storage, reporting failure.
pub fn fsync_fd(fd: i32) -> bool {
    unsafe { libc::fsync(fd) == 0 }
}

pub fn close(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

pub fn dup2(old: i32, new: i32) -> i32 {
    unsafe { libc::dup2(old, new) }
}

pub fn fcntl_dup(fd: i32, min: i32) -> i32 {
    unsafe { libc::fcntl(fd, libc::F_DUPFD, min) }
}

pub fn pipe2(fds: &mut [i32; 2], flags: i32) -> bool {
    unsafe { libc::pipe2(fds.as_mut_ptr(), flags) == 0 }
}

/// Like `pipe2`, but returns the errno of the failure instead of a bool.
pub fn pipe2_checked(fds: &mut [i32; 2], flags: i32) -> Result<(), i32> {
    if unsafe { libc::pipe2(fds.as_mut_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

pub fn fork() -> i32 {
    unsafe { libc::fork() }
}

pub fn execve(path: &[u8], argv: &[*const u8], envp: &[*const u8]) -> isize {
    let p = match cstr(path) {
        Some(p) => p,
        None => return -1,
    };
    unsafe {
        libc::execve(
            p.as_ptr(),
            // `libc::c_char` is `i8` on x86 and `u8` on aarch64, so a cast is
            // needed on one and redundant on the other; `cast` is the form
            // that is correct on both and that clippy accepts either way.
            argv.as_ptr().cast::<*const libc::c_char>(),
            envp.as_ptr().cast::<*const libc::c_char>(),
        ) as isize
    }
}

pub fn waitpid(pid: i32, status: &mut i32) -> i32 {
    loop {
        let r = unsafe { libc::waitpid(pid, status, 0) };
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return r;
    }
}

pub fn waitpid_nohang(pid: i32, status: &mut i32) -> i32 {
    unsafe { libc::waitpid(pid, status, libc::WNOHANG) }
}

pub fn pidfd_open(pid: i32) -> i32 {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_open,
            pid as libc::c_long,
            0 as libc::c_ulong,
        ) as i32
    }
}

pub fn pidfd_send_signal(fd: i32, sig: i32) -> bool {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd as libc::c_long,
            sig as libc::c_long,
            core::ptr::null::<libc::c_void>(),
            0 as libc::c_ulong,
        ) == 0
    }
}

pub fn kill(pid: i32, sig: i32) -> bool {
    unsafe { libc::kill(pid, sig) == 0 }
}

pub fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

pub fn getuid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn getgid() -> u32 {
    unsafe { libc::getgid() }
}

pub fn getegid() -> u32 {
    unsafe { libc::getegid() }
}

pub fn setuid(uid: u32) -> bool {
    unsafe { libc::setuid(uid) == 0 }
}

pub fn setgid(gid: u32) -> bool {
    unsafe { libc::setgid(gid) == 0 }
}

pub fn setgroups(groups: &[u32]) -> bool {
    unsafe { libc::setgroups(groups.len(), groups.as_ptr() as *const libc::gid_t) == 0 }
}

pub fn initgroups(name: &[u8], gid: u32) -> bool {
    let n = match cstr(name) {
        Some(n) => n,
        None => return false,
    };
    unsafe { libc::initgroups(n.as_ptr(), gid as libc::gid_t) == 0 }
}

pub fn setsid() -> i32 {
    unsafe { libc::setsid() }
}

pub fn setpgid(pid: i32, pgid: i32) -> bool {
    unsafe { libc::setpgid(pid, pgid) == 0 }
}

pub fn fchown(fd: i32, uid: u32, gid: u32) -> bool {
    unsafe { libc::fchown(fd, uid as libc::uid_t, gid as libc::gid_t) == 0 }
}

pub fn prctl_set_name(name: &[u8]) -> bool {
    let mut buf = [0u8; 16];
    let n = name.len().min(15);
    buf[..n].copy_from_slice(&name[..n]);
    unsafe { libc::prctl(libc::PR_SET_NAME, buf.as_ptr() as libc::c_ulong, 0, 0, 0) == 0 }
}

pub fn alarm(secs: u32) {
    unsafe {
        libc::alarm(secs);
    }
}

pub fn pause() {
    unsafe {
        libc::pause();
    }
}

pub fn nanosleep(secs: u64, nanos: u64) {
    let ts = libc::timespec {
        tv_sec: secs as _,
        tv_nsec: nanos as libc::c_long,
    };
    unsafe {
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
}

/// Ignore `SIGXFSZ`, so a write past `RLIMIT_FSIZE` returns `EFBIG` to the
/// caller instead of killing the process. psgen has to report the pidfile
/// problem and exit, not die mid-run with live stubs and no record.
pub fn ignore_sigxfsz() {
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
    }
}

pub fn now_secs() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    ts.tv_sec as u64
}

pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// `CLOCK_BOOTTIME` in nanoseconds, or `None` when the syscall fails.
///
/// `/proc/PID/stat`'s `starttime` counts ticks since the host boot, and this
/// is the clock that advances over suspend, so it is the denominator a `%CPU`
/// needs. `/proc/uptime` is normally the same clock, but a container whose
/// procfs is virtualized (lxcfs) makes it disagree.
pub fn boottime_ns() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if r != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return None;
    }
    Some(
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64),
    )
}

pub fn hz() -> u64 {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 {
        v as u64
    } else {
        100
    }
}

pub fn page_kb() -> u64 {
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let bytes = if v > 0 { v as u64 } else { 4096 };
    (bytes / 1024).max(1)
}

pub fn mmap(len: usize, prot: i32, flags: i32, fd: i32, off: u64) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            prot,
            flags,
            fd,
            off as libc::off_t,
        )
    };
    if p == libc::MAP_FAILED {
        std::ptr::null_mut()
    } else {
        p as *mut u8
    }
}

pub fn madvise(ptr: *mut u8, len: usize, advice: i32) -> bool {
    unsafe { libc::madvise(ptr as *mut libc::c_void, len, advice) == 0 }
}

/// An anonymous file of `size` bytes that can still be sealed later, or -1.
///
/// Only a memfd can be sealed; the caller falls back to an unlinked temporary
/// file, which has no name to reopen but cannot be sealed either. The seals
/// are added after the contents are written, because `F_SEAL_WRITE` makes the
/// file unwritable from that point on.
pub fn anon_sealable_file(name: &[u8], size: u64) -> i32 {
    let fd = memfd_create(name, libc::MFD_ALLOW_SEALING);
    if fd < 0 {
        return -1;
    }
    if !ftruncate(fd, size) {
        close(fd);
        return -1;
    }
    fd
}

pub fn memfd_create(name: &[u8], flags: u32) -> i32 {
    let n = match cstr(name) {
        Some(n) => n,
        None => return -1,
    };
    unsafe { libc::memfd_create(n.as_ptr(), flags) }
}

pub fn ftruncate(fd: i32, len: u64) -> bool {
    // off_t is 32-bit on some 32-bit targets; ftruncate64 keeps the arena and
    // config sizes intact there.
    unsafe { libc::ftruncate64(fd, len as libc::off64_t) == 0 }
}

/// An anonymous file of `size` bytes.
///
/// Uses `memfd_create` when the kernel allows it. Otherwise the file is
/// created with `mkstemp` under the first usable directory and unlinked at
/// once, so the fd survives fork and exec with nothing left on disk.
/// Returns -1 when neither route works.
pub fn anon_file(name: &[u8], size: u64) -> i32 {
    let fd = memfd_create(name, 0);
    if fd >= 0 {
        if ftruncate(fd, size) {
            return fd;
        }
        close(fd);
    }
    let bases: Vec<PathBuf> = vec![
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/dev/shm"),
        PathBuf::from("."),
    ];
    for base in bases {
        if let Some(fd) = temp_anon_fd(&base, size) {
            return fd;
        }
    }
    -1
}

fn temp_anon_fd(base: &Path, size: u64) -> Option<i32> {
    let mut tmpl = base.join(".psgen-XXXXXX").as_os_str().as_bytes().to_vec();
    tmpl.push(0);
    let fd = unsafe { libc::mkstemp(tmpl.as_mut_ptr() as *mut libc::c_char) };
    if fd < 0 {
        return None;
    }
    if unsafe { libc::unlink(tmpl.as_ptr() as *const libc::c_char) } != 0 {
        close(fd);
        return None;
    }
    if !ftruncate(fd, size) {
        close(fd);
        return None;
    }
    Some(fd)
}

pub fn set_child_subreaper() -> bool {
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0 }
}

pub fn unshare(flags: i32) -> bool {
    unsafe { libc::unshare(flags) == 0 }
}

pub fn mount(source: &[u8], target: &[u8], fstype: &[u8], flags: u64, data: &[u8]) -> bool {
    let s = if source.is_empty() {
        None
    } else {
        cstr(source)
    };
    let t = match cstr(target) {
        Some(t) => t,
        None => return false,
    };
    let f = if fstype.is_empty() {
        None
    } else {
        cstr(fstype)
    };
    let d = if data.is_empty() { None } else { cstr(data) };
    let sp = s.as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null());
    let fp = f.as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null());
    let dp = d.as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null());
    unsafe {
        libc::mount(
            sp,
            t.as_ptr(),
            fp,
            flags as libc::c_ulong,
            dp as *const libc::c_void,
        ) == 0
    }
}

pub fn umount2(target: &[u8], flags: i32) -> bool {
    let t = match cstr(target) {
        Some(t) => t,
        None => return false,
    };
    unsafe { libc::umount2(t.as_ptr(), flags) == 0 }
}

pub fn ioctl(fd: i32, req: u64, arg: usize) -> isize {
    // Go through syscall(2): glibc and musl declare ioctl(2) with different
    // request types, and the syscall ABI is the same on every Linux target.
    unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            fd as libc::c_long,
            req as libc::c_long,
            arg as libc::c_long,
        ) as isize
    }
}

pub fn access(path: &[u8], mode: i32) -> bool {
    let p = match cstr(path) {
        Some(p) => p,
        None => return false,
    };
    unsafe { libc::access(p.as_ptr(), mode) == 0 }
}

pub fn getrandom(buf: &mut [u8]) -> bool {
    let n = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    n == buf.len() as isize
}

pub fn poll_read(fd: i32, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd, 1, timeout_ms) > 0 }
}

pub fn getcwd(buf: &mut [u8]) -> Option<usize> {
    let r = unsafe { libc::getcwd(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r.is_null() {
        return None;
    }
    // getcwd returns the buffer pointer, not a length.
    let n = unsafe { libc::strlen(r) };
    if n >= buf.len() {
        None
    } else {
        Some(n)
    }
}

/// Free and total bytes on the filesystem holding `path`.
pub fn statvfs(path: &[u8]) -> Option<(u64, u64)> {
    let p = cstr(path)?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statvfs(p.as_ptr(), &mut st) };
    if r != 0 {
        return None;
    }
    // The statvfs fields are u64 on 64-bit targets and u32 on 32-bit ones.
    let unit = if st.f_frsize > 0 {
        st.f_frsize
    } else {
        st.f_bsize
    } as u64;
    let free = (st.f_bavail as u64).saturating_mul(unit);
    let total = (st.f_blocks as u64).saturating_mul(unit);
    Some((free, total))
}

/// Soft RLIMIT_FSIZE in bytes, or None when the limit is unlimited.
pub fn rlimit_fsize() -> Option<u64> {
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut rl) } != 0 {
        return None;
    }
    if rl.rlim_cur == libc::RLIM_INFINITY {
        None
    } else {
        Some(rl.rlim_cur as u64)
    }
}

/// True when `path` exists and is a directory.
pub fn is_dir(path: &[u8]) -> bool {
    let p = match cstr(path) {
        Some(p) => p,
        None => return false,
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(p.as_ptr(), &mut st) } != 0 {
        return false;
    }
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// The device a path's inode lives on, or None when `lstat` fails.
pub fn path_dev(path: &[u8]) -> Option<u64> {
    let p = cstr(path)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(p.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(st.st_dev as u64)
}

/// The device `path`'s parent directory's inode lives on.
///
/// A bind mount reports the mounted filesystem's `st_dev`, so a directory whose
/// device differs from the directory containing it is a mount point or has had
/// something mounted over it. `remove_dir_all` recurses *through* such a
/// mount and deletes the files behind it.
pub fn parent_dev(path: &[u8]) -> Option<u64> {
    let p = Path::new(OsStr::from_bytes(path.strip_suffix(&[0]).unwrap_or(path)));
    let parent = p.parent()?;
    path_dev(parent.as_os_str().as_bytes())
}

/// Whether `path` is a mount point, a bind mount, or on a different filesystem
/// from its parent.
///
/// Both halves matter: a bind mount of a directory on the same filesystem has
/// the same `st_dev` as its parent, so the device comparison alone misses it,
/// and a directory on a different filesystem is not necessarily mounted.
pub fn is_mount_point(path: &[u8]) -> bool {
    if let (Some(a), Some(b)) = (path_dev(path), parent_dev(path)) {
        if a != b {
            return true;
        }
    }
    let t = match cstr(path) {
        Some(t) => t,
        None => return true,
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(t.as_ptr(), &mut st) } != 0 {
        return true;
    }
    let want = (st.st_dev as u64, st.st_ino as u64);
    let mounts = match std::fs::read("/proc/self/mountinfo") {
        Ok(s) => s,
        Err(_) => return true,
    };
    for line in mounts.split(|&b| b == b'\n') {
        let mut it = line.split(|&b| b == b' ');
        let (Some(_id), Some(_parent), Some(dev)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let Some(_root) = it.next() else { continue };
        let Some(mp) = it.next() else { continue };
        let Some(colon) = dev.iter().position(|&b| b == b':') else {
            continue;
        };
        let (Some(maj), Some(min)) = (
            crate::str::parse_u64(&dev[..colon]),
            crate::str::parse_u64(&dev[colon + 1..]),
        ) else {
            continue;
        };
        if libc::makedev(maj as u32, min as u32) as u64 != want.0 {
            continue;
        }
        if unescape_mount_bytes(mp) == t.as_bytes() {
            return true;
        }
    }
    false
}

fn unescape_mount_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let oct = &b[i + 1..i + 4];
            if oct.iter().all(|c| (b'0'..=b'7').contains(c)) {
                let v = (oct[0] - b'0') * 64 + (oct[1] - b'0') * 8 + (oct[2] - b'0');
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Delete a staging directory, refusing anything that is not an ordinary
/// directory on the filesystem its parent is on.
///
/// `remove_dir_all` follows a bind mount: a directory the caller mounted over a
/// `.psgen-N-N-N` name reports the mounted filesystem's root metadata, which can
/// be root-owned `0700` and pass every other arm, and the recursion then deletes
/// files the caller never owned. A staging directory this tool made is never a
/// mount point, so refusing one costs nothing legitimate.
pub fn remove_staging_dir(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    if is_mount_point(bytes) {
        return false;
    }
    std::fs::remove_dir_all(path).is_ok()
}

/// Decode a raw `waitpid` status into success, and the child's exit code.
pub fn wait_exit_code(status: i32) -> Option<i32> {
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}

pub fn prctl_set_dumpable(dumpable: bool) -> bool {
    let v: libc::c_ulong = if dumpable { 1 } else { 0 };
    unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            v,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) == 0
    }
}

pub fn prctl_set_no_new_privs() -> bool {
    unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) == 0
    }
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Install `count.min(8)` minimal 1-instruction `SECCOMP_RET_ALLOW` classic BPF
/// filters after enabling `PR_SET_NO_NEW_PRIVS`.
#[allow(clippy::unnecessary_cast)]
pub fn install_benign_seccomp(count: u32) -> bool {
    let n = count.min(8);
    if n == 0 {
        return true;
    }
    if !prctl_set_no_new_privs() {
        return false;
    }
    let filter = SockFilter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff_0000,
    };
    let prog = SockFprog {
        len: 1,
        filter: &filter,
    };
    for _ in 0..n {
        let r = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &prog as *const SockFprog as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if r != 0 {
            return false;
        }
    }
    true
}

pub fn prctl_set_subreaper() -> bool {
    set_child_subreaper()
}

pub fn reap_children_nonblock() -> usize {
    let mut reaped = 0usize;
    let mut st: i32 = 0;
    loop {
        let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if r > 0 {
            reaped += 1;
        } else {
            break;
        }
    }
    reaped
}

pub fn anon_sealable_file_named(name: &[u8], flags: u32) -> i32 {
    memfd_create(name, flags | libc::MFD_ALLOW_SEALING)
}

pub fn memfd_exec_copy(label: &[u8], src_path: &[u8]) -> i32 {
    let raw = if label.is_empty() { b"exec" } else { label };
    let name = &raw[..raw.len().min(240)];
    let mfd = memfd_create(name, libc::MFD_CLOEXEC);
    if mfd < 0 {
        return -1;
    }
    let sfd = open(src_path, libc::O_RDONLY | libc::O_CLOEXEC, 0);
    if sfd < 0 {
        close(mfd);
        return -1;
    }
    let mut buf = [0u8; 16384];
    let mut ok = true;
    loop {
        let n = read_fd(sfd, &mut buf);
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            ok = false;
            break;
        }
        if n == 0 {
            break;
        }
        if !write_fd(mfd, &buf[..n as usize]) {
            ok = false;
            break;
        }
    }
    close(sfd);
    if !ok {
        close(mfd);
        return -1;
    }
    let _ = unsafe { libc::fchmod(mfd, 0o700) };
    mfd
}

pub fn fexecve(fd: i32, argv: &[*const u8], envp: &[*const u8]) -> i32 {
    let r = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd as libc::c_long,
            c"".as_ptr(),
            argv.as_ptr().cast::<*const libc::c_char>(),
            envp.as_ptr().cast::<*const libc::c_char>(),
            0x1000 as libc::c_long,
        )
    };
    if r < 0 && errno() == libc::ENOSYS {
        let mut path = crate::str::Buf::new();
        path.push_str("/proc/self/fd/");
        path.push_u64(fd as u64);
        return execve(path.as_bytes(), argv, envp) as i32;
    }
    r as i32
}

#[allow(clippy::unnecessary_cast)]
pub fn wait_wchan(mode: u8) -> ! {
    match mode {
        1 => {
            let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if ep >= 0 {
                let mut ev = libc::epoll_event { events: 0, u64: 0 };
                loop {
                    unsafe {
                        libc::epoll_wait(ep, &mut ev, 1, -1);
                    }
                }
            }
        }
        2 => loop {
            unsafe {
                libc::poll(core::ptr::null_mut(), 0, -1);
            }
        },
        3 => loop {
            nanosleep(3600, 0);
        },
        4 => {
            const FUTEX_WAIT_PRIVATE: libc::c_long = 128;
            static V: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
            loop {
                unsafe {
                    libc::syscall(
                        libc::SYS_futex,
                        &V as *const core::sync::atomic::AtomicU32,
                        FUTEX_WAIT_PRIVATE,
                        0 as libc::c_long,
                        core::ptr::null::<libc::timespec>(),
                        core::ptr::null::<u32>(),
                        0 as libc::c_long,
                    );
                }
            }
        }
        5 => {
            if let Some((r, _w)) = pipe2_pair() {
                let mut b = [0u8; 1];
                loop {
                    let n = read_fd(r, &mut b);
                    if n == 0 {
                        pause();
                    }
                }
            }
        }
        _ => {}
    }
    loop {
        pause();
    }
}

pub fn pipe2_pair() -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    if pipe2(&mut fds, O_CLOEXEC) {
        Some((fds[0], fds[1]))
    } else {
        None
    }
}

pub fn socketpair_unix() -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } == 0
    {
        Some((fds[0], fds[1]))
    } else {
        None
    }
}

pub fn eventfd_open() -> i32 {
    unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) }
}

pub fn memfd_dummy(name: &[u8]) -> i32 {
    let raw = if name.is_empty() { b"anon" } else { name };
    let n = &raw[..raw.len().min(240)];
    memfd_create(n, libc::MFD_CLOEXEC)
}

pub fn ptrace_seize(pid: i32) -> bool {
    const PTRACE_SEIZE: libc::c_long = 0x4206;
    unsafe {
        libc::syscall(
            libc::SYS_ptrace,
            PTRACE_SEIZE,
            pid as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        ) == 0
    }
}

/// Run an external program via `fork` + `execvp`/`execve` + `waitpid` without
/// pulling in `std::process::Command` / `CommandEnv` / `BTreeMap<OsString, OsString>`.
///
/// When `env` is `Some`, uses `execve` with the given `KEY=VAL` entries; otherwise
/// uses `execvp` inheriting the parent environment. When `capture_stderr` is true,
/// redirects stdout to `/dev/null` and captures up to 64 KiB of stderr.
/// Returns `Ok((exit_code, stderr))` on exec success, or `Err(errno)` if fork/exec fails.
pub fn run_cmd(
    prog: &[u8],
    argv: &[&[u8]],
    env: Option<&[&[u8]]>,
    capture_stderr: bool,
) -> Result<(i32, Vec<u8>), i32> {
    let c_prog = cstr(prog).ok_or(libc::EINVAL)?;
    let mut c_args: Vec<CString> = Vec::with_capacity(argv.len());
    for &a in argv {
        c_args.push(cstr(a).ok_or(libc::EINVAL)?);
    }
    let mut arg_ptrs: Vec<*const libc::c_char> = Vec::with_capacity(c_args.len() + 1);
    for a in &c_args {
        arg_ptrs.push(a.as_ptr());
    }
    arg_ptrs.push(core::ptr::null());

    let mut c_env: Vec<CString> = Vec::new();
    let mut env_ptrs: Vec<*const libc::c_char> = Vec::new();
    if let Some(es) = env {
        c_env.reserve(es.len());
        for &e in es {
            c_env.push(cstr(e).ok_or(libc::EINVAL)?);
        }
        env_ptrs.reserve(c_env.len() + 1);
        for e in &c_env {
            env_ptrs.push(e.as_ptr());
        }
        env_ptrs.push(core::ptr::null());
    }

    let (err_r, err_w) = pipe2_pair().ok_or_else(errno)?;
    let serr_pipe = if capture_stderr {
        match pipe2_pair() {
            Some(p) => Some(p),
            None => {
                let e = errno();
                close(err_r);
                close(err_w);
                return Err(e);
            }
        }
    } else {
        None
    };

    let pid = fork();
    if pid < 0 {
        let e = errno();
        close(err_r);
        close(err_w);
        if let Some((sr, sw)) = serr_pipe {
            close(sr);
            close(sw);
        }
        return Err(e);
    }
    if pid == 0 {
        close(err_r);
        if let Some((sr, sw)) = serr_pipe {
            close(sr);
            let dn = open(b"/dev/null", O_RDWR, 0);
            if dn >= 0 {
                dup2(dn, 1);
                if dn > 2 {
                    close(dn);
                }
            }
            dup2(sw, 2);
            if sw > 2 {
                close(sw);
            }
        }
        unsafe {
            if env.is_some() {
                libc::execve(c_prog.as_ptr(), arg_ptrs.as_ptr(), env_ptrs.as_ptr());
            } else {
                libc::execvp(c_prog.as_ptr(), arg_ptrs.as_ptr());
            }
        }
        let e = errno().to_ne_bytes();
        let _ = write_fd(err_w, &e);
        unsafe { libc::_exit(127) }
    }

    close(err_w);
    let mut stderr_out = Vec::new();
    if let Some((sr, sw)) = serr_pipe {
        close(sw);
        let mut buf = [0u8; 4096];
        while stderr_out.len() < 65_536 {
            let n = read_fd(sr, &mut buf);
            if n <= 0 {
                break;
            }
            stderr_out.extend_from_slice(&buf[..n as usize]);
        }
        close(sr);
    }

    let mut err_buf = [0u8; 4];
    let mut err_got = 0usize;
    while err_got < 4 {
        let n = read_fd(err_r, &mut err_buf[err_got..]);
        if n <= 0 {
            break;
        }
        err_got += n as usize;
    }
    close(err_r);

    let mut status: libc::c_int = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 && errno() == libc::EINTR {
            continue;
        }
        break;
    }

    if err_got == 4 {
        return Err(i32::from_ne_bytes(err_buf));
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    };
    Ok((code, stderr_out))
}
