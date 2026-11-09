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

pub const MS_BIND: u64 = libc::MS_BIND as u64;
pub const MS_REC: u64 = libc::MS_REC as u64;
pub const MS_PRIVATE: u64 = libc::MS_PRIVATE as u64;

pub const TIOCSPTLCK: u64 = libc::TIOCSPTLCK as u64;
pub const TIOCGPTN: u64 = libc::TIOCGPTN as u64;
pub const TIOCSCTTY: u64 = libc::TIOCSCTTY as u64;

pub fn cstr(path: &[u8]) -> Option<CString> {
    let body = path.strip_suffix(&[0]).unwrap_or(path);
    CString::new(body).ok()
}

fn path_of(path: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(path.strip_suffix(&[0]).unwrap_or(path)))
}

pub fn out(buf: &[u8]) {
    let _ = io::stdout().write_all(buf);
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
/// without blocking on a FIFO.
pub fn read_file_nofollow(path: &[u8], max: usize) -> Option<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path_of(path))
        .ok()?;
    let mut out = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut out).ok()?;
    if out.len() > max {
        return None;
    }
    Some(out)
}

pub fn read_link(path: &[u8]) -> Option<Vec<u8>> {
    std::fs::read_link(path_of(path))
        .ok()
        .map(|p| p.as_os_str().as_bytes().to_vec())
}

/// Whether the `bpf` syscall is reachable at all.
///
/// Calls command 1 (`BPF_MAP_LOOKUP_ELEM`) with a null attribute. The probe
/// treats any result other than `EPERM` as reachable; `EPERM` means a seccomp
/// filter or the kernel policy blocks the syscall. Nothing is looked up either
/// way.
pub fn bpf_allowed() -> bool {
    let r = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            1 as libc::c_int,
            core::ptr::null::<libc::c_void>(),
            0 as libc::c_int,
        )
    };
    r != -1 || last_error().raw_os_error() != Some(libc::EPERM)
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
            argv.as_ptr() as *const *const libc::c_char,
            envp.as_ptr() as *const *const libc::c_char,
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

pub fn chdir(path: &[u8]) -> bool {
    let p = match cstr(path) {
        Some(p) => p,
        None => return false,
    };
    unsafe { libc::chdir(p.as_ptr()) == 0 }
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
    let mut bases: Vec<PathBuf> = Vec::with_capacity(4);
    bases.push(std::env::temp_dir());
    bases.push(PathBuf::from("/tmp"));
    bases.push(PathBuf::from("/dev/shm"));
    bases.push(PathBuf::from("."));
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
    let s = if source.is_empty() { None } else { cstr(source) };
    let t = match cstr(target) {
        Some(t) => t,
        None => return false,
    };
    let f = if fstype.is_empty() { None } else { cstr(fstype) };
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

pub fn chown(path: &[u8], uid: u32, gid: u32) -> bool {
    let p = match cstr(path) {
        Some(p) => p,
        None => return false,
    };
    unsafe { libc::chown(p.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) == 0 }
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
    let unit = if st.f_frsize > 0 { st.f_frsize } else { st.f_bsize } as u64;
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

/// Decode a raw `waitpid` status into success, and the child's exit code.
pub fn wait_exit_code(status: i32) -> Option<i32> {
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}
