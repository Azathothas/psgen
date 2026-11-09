//! Capability probe.
//!
//! `inject` asks this module what the current deployment actually permits
//! before it promises anything. Every check that would change process state
//! runs in a forked child, so probing never modifies the caller.

use crate::str::Buf;
use crate::sys;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::vec::Vec;

/// One probed capability: whether it worked, and the errno when it did not.
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub errno: i32,
    pub detail: Vec<u8>,
}

impl Check {
    fn new(name: &'static str, ok: bool, errno: i32, detail: &[u8]) -> Check {
        Check {
            name,
            ok,
            errno,
            detail: detail.to_vec(),
        }
    }
}

fn errno() -> i32 {
    sys::last_error().raw_os_error().unwrap_or(1).abs()
}

/// Run `f` in a forked child and report whether it returned Ok, plus errno.
///
/// The child never touches the parent's memory, so a probe that calls
/// `unshare` or `setuid` cannot leave the caller in a modified state.
fn in_child<F>(f: F) -> (bool, i32)
where
    F: FnOnce() -> Result<(), i32>,
{
    let mut fds = [0i32; 2];
    if !sys::pipe2(&mut fds, 0) {
        return (false, errno());
    }
    let pid = sys::fork();
    if pid == 0 {
        sys::close(fds[0]);
        let (ok, e) = match f() {
            Ok(()) => (true, 0i32),
            Err(e) => (false, e),
        };
        let raw = (e.max(0) as u32).to_le_bytes();
        sys::write_fd(fds[1], &raw);
        sys::exit(if ok { 0 } else { 1 });
    }
    sys::close(fds[1]);
    if pid < 0 {
        sys::close(fds[0]);
        return (false, errno());
    }
    let mut raw = [0u8; 4];
    let n = sys::read_fd(fds[0], &mut raw);
    sys::close(fds[0]);
    let mut status = 0;
    let r = sys::waitpid(pid, &mut status);
    let ok = r == pid && sys::wait_exit_code(status) == Some(0);
    let e = if n == 4 {
        u32::from_le_bytes(raw) as i32
    } else {
        0
    };
    (ok, e)
}

fn check_pty() -> Check {
    // A seccomp policy that returns KILL for an unexpected syscall must kill
    // the probe child, not psgen. The parent then reports DENY.
    let (ok, e) = in_child(|| {
        let fd = sys::open(b"/dev/ptmx", sys::O_RDWR | sys::O_NOCTTY | sys::O_CLOEXEC, 0);
        if fd < 0 {
            return Err(errno());
        }
        sys::close(fd);
        if sys::access(b"/dev/pts", sys::X_OK) {
            Ok(())
        } else {
            Err(errno())
        }
    });
    Check::new(
        "pty",
        ok,
        e,
        if ok {
            b"/dev/ptmx and /dev/pts"
        } else {
            b"/dev/ptmx or /dev/pts unavailable"
        },
    )
}

fn check_memfd() -> Check {
    let (ok, e) = in_child(|| {
        let fd = sys::memfd_create(b"psgen-probe", 0);
        if fd < 0 {
            return Err(errno());
        }
        let sz = sys::ftruncate(fd, 4096);
        let e = if sz { 0 } else { errno() };
        sys::close(fd);
        if sz {
            Ok(())
        } else {
            Err(e)
        }
    });
    Check::new(
        "memfd",
        ok,
        e,
        if ok {
            b"memfd_create and ftruncate"
        } else {
            b"memfd_create or ftruncate unavailable"
        },
    )
}

fn check_proc_exe() -> Check {
    match sys::read_link(b"/proc/self/exe") {
        Some(p) if !p.is_empty() => Check::new("proc_exe", true, 0, &p),
        Some(_) => Check::new("proc_exe", false, 0, b"empty link"),
        None => Check::new("proc_exe", false, errno(), b"readlink failed"),
    }
}

fn check_mount_ns() -> Check {
    let (ok, e) = in_child(|| {
        // Test the exact function the stub uses, so the verdict cannot drift
        // from the behaviour it predicts.
        if crate::stub::enter_mount_ns() {
            Ok(())
        } else {
            Err(errno())
        }
    });
    let root = sys::geteuid() == 0;
    Check::new(
        "mount_ns",
        ok,
        e,
        if ok {
            if root {
                b"unshare and MS_PRIVATE"
            } else {
                b"unshare, uid map and MS_PRIVATE"
            }
        } else if root {
            b"unshare or MS_PRIVATE failed"
        } else {
            b"unshare, uid map or MS_PRIVATE failed"
        },
    )
}

fn check_bind_mount() -> Check {
    let (ok, e) = in_child(|| {
        // Test the exact function the stub uses, so the verdict cannot drift
        // from the behaviour it predicts.
        if !crate::stub::enter_mount_ns() {
            return Err(errno());
        }
        let dir = std::env::temp_dir();
        let a = dir.join(format!(".psgen-probe-a-{}", sys::getpid()));
        let b = dir.join(format!(".psgen-probe-b-{}", sys::getpid()));
        let ab = a.as_os_str().as_bytes().to_vec();
        let bb = b.as_os_str().as_bytes().to_vec();
        let fa = sys::open(&ab, sys::O_CREAT | sys::O_WRONLY, 0o600);
        if fa < 0 {
            return Err(errno());
        }
        sys::close(fa);
        let fb = sys::open(&bb, sys::O_CREAT | sys::O_WRONLY, 0o600);
        if fb < 0 {
            let _ = std::fs::remove_file(&a);
            return Err(errno());
        }
        sys::close(fb);
        let ok = sys::mount(&ab, &bb, b"", sys::MS_BIND, b"");
        let e = if ok { 0 } else { errno() };
        if ok {
            // The bind target stays busy until the mount goes away, so detach
            // it before unlinking or the probe leaves a file in /tmp.
            sys::umount2(&bb, libc::MNT_DETACH);
        }
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
        if !ok {
            return Err(e);
        }
        Ok(())
    });
    Check::new(
        "bind_mount",
        ok,
        e,
        if ok {
            b"bind inside a private mount namespace"
        } else {
            b"bind inside a namespace failed"
        },
    )
}

fn check_user_switch() -> Check {
    if sys::geteuid() != 0 {
        return Check::new("user_switch", false, 1, b"not root");
    }
    let (ok, e) = in_child(|| {
        sys::setgroups(&[]);
        if !sys::setgid(65534) {
            return Err(errno());
        }
        if !sys::setuid(65534) {
            return Err(errno());
        }
        if sys::geteuid() != 65534 {
            return Err(1);
        }
        Ok(())
    });
    Check::new(
        "user_switch",
        ok,
        e,
        if ok {
            b"setuid to 65534"
        } else {
            b"setuid to 65534 failed"
        },
    )
}

fn check_fork() -> Check {
    let (ok, e) = in_child(|| Ok(()));
    Check::new("fork", ok, e, if ok { b"child exited 0" } else { b"fork failed" })
}

fn check_prctl() -> Check {
    let (ok, e) = in_child(|| {
        if sys::prctl_set_name(b"psgen-probe") {
            Ok(())
        } else {
            Err(errno())
        }
    });
    Check::new(
        "prctl_name",
        ok,
        e,
        if ok { b"PR_SET_NAME" } else { b"PR_SET_NAME denied" },
    )
}

fn check_passwd() -> Check {
    let mut buf = [0u8; 4096];
    match sys::read_file(b"/etc/passwd", &mut buf) {
        Some(n) if n > 0 => Check::new("passwd", true, 0, b"/etc/passwd readable"),
        _ => Check::new("passwd", false, errno(), b"/etc/passwd unreadable"),
    }
}

fn check_cwd() -> Check {
    let mut buf = [0u8; 4096];
    match sys::getcwd(&mut buf) {
        Some(n) => {
            let cwd = buf[..n].to_vec();
            let ok = sys::access(&cwd, sys::W_OK);
            Check::new(
                "cwd",
                ok,
                if ok { 0 } else { errno() },
                if ok { b"cwd writable" } else { b"cwd not writable" },
            )
        }
        None => Check::new("cwd", false, errno(), b"getcwd failed"),
    }
}

fn check_proc_stat() -> Check {
    let ok = sys::read_file(b"/proc/self/stat", &mut [0u8; 1024]).is_some();
    Check::new(
        "proc_stat",
        ok,
        if ok { 0 } else { errno() },
        if ok { b"/proc/PID/stat readable" } else { b"/proc/PID/stat unreadable" },
    )
}

/// Probe everything `doctor` reports.
pub fn checks() -> Vec<Check> {
    let mut v = Vec::with_capacity(12);
    v.push(check_pty());
    v.push(check_memfd());
    v.push(check_proc_exe());
    v.push(check_mount_ns());
    v.push(check_bind_mount());
    v.push(check_user_switch());
    v.push(check_fork());
    v.push(check_prctl());
    v.push(check_passwd());
    v.push(check_cwd());
    v.push(check_proc_stat());
    v
}

/// Whether the `bpf` syscall is reachable, probed in a child so a seccomp
/// KILL policy cannot take down the caller.
pub fn bpf_allowed() -> bool {
    in_child(|| if sys::bpf_allowed() { Ok(()) } else { Err(errno()) }).0
}

/// Whether `SECCOMP_SET_MODE_FILTER` is reachable, probed in a child for the
/// same reason.
pub fn seccomp_user_notif() -> bool {
    in_child(|| {
        if sys::seccomp_user_notif() {
            Ok(())
        } else {
            Err(errno())
        }
    })
    .0
}

/// The facts `inject` needs to choose its strategy, from one probe pass.
pub struct Caps {
    pub root: bool,
    pub pty: bool,
    pub memfd: bool,
    pub mount_ns: bool,
    pub bind_mount: bool,
    pub user_switch: bool,
}

pub fn caps() -> Caps {
    let checks = checks();
    let get = |name: &str| checks.iter().find(|c| c.name == name).map(|c| c.ok);
    Caps {
        root: sys::geteuid() == 0,
        pty: get("pty").unwrap_or(false),
        memfd: get("memfd").unwrap_or(false),
        mount_ns: get("mount_ns").unwrap_or(false),
        bind_mount: get("bind_mount").unwrap_or(false),
        user_switch: get("user_switch").unwrap_or(false),
    }
}

impl Caps {
    /// Whether the template executable path can be spoofed.
    pub fn can_spoof_exe(&self) -> bool {
        self.mount_ns && self.bind_mount
    }
}

fn pidfile_parent(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(0) => b"/",
        Some(i) => &path[..i],
        None => b".",
    }
}

/// Whether a pidfile may replace the object at `path`.
///
/// `write_pidfile` renames a temporary file over the target, so a device, a
/// FIFO, a socket or a symlink would be replaced by a regular file. An absent
/// path and an empty regular file are fine; a non-empty regular file must
/// already start with the psgen header.
pub fn pidfile_target_ok(path: &[u8]) -> bool {
    let path = path.strip_suffix(&[0]).unwrap_or(path);
    let p = Path::new(OsStr::from_bytes(path));
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if !meta.file_type().is_file() {
        return false;
    }
    if meta.len() == 0 {
        return true;
    }
    let mut buf = [0u8; 16];
    match sys::read_file(path, &mut buf) {
        Some(n) => n >= 8 && &buf[..8] == b"# psgen ",
        None => false,
    }
}

/// Whether a pidfile at `path` could be written.
///
/// `inject` writes a temporary file beside `path` and renames it into place,
/// so the parent directory must exist and be writable. An existing file's own
/// mode does not matter, but its type and content do: `pidfile_target_ok`
/// refuses anything that is not an absent path, an empty regular file, or an
/// existing psgen pidfile. This only inspects the tree, which is what
/// `doctor` needs; `pidfile_creatable` proves a write works.
pub fn pidfile_writable(path: &[u8]) -> bool {
    let path = path.strip_suffix(&[0]).unwrap_or(path);
    if path.is_empty() {
        return false;
    }
    if !pidfile_target_ok(path) {
        return false;
    }
    let parent = pidfile_parent(path);
    sys::is_dir(parent) && sys::access(parent, sys::W_OK)
}

/// Whether `inject` can create and replace a pidfile at `path`.
///
/// `access(W_OK)` succeeds for root on a read-only filesystem and on /proc, so
/// this creates a uniquely named file in the parent and removes it again. The
/// write itself creates a unique temporary file beside the path with `O_EXCL`
/// and renames it into place.
pub fn pidfile_creatable(path: &[u8]) -> bool {
    if !pidfile_writable(path) {
        return false;
    }
    let path = path.strip_suffix(&[0]).unwrap_or(path);
    let flags = sys::O_WRONLY | sys::O_CREAT | sys::O_EXCL | sys::O_NOFOLLOW;
    // Test the name `write_pidfile` will actually create, not a short probe
    // name in the parent. A basename close to NAME_MAX passes a short probe
    // and then fails after the stubs are spawned.
    for _ in 0..8u64 {
        let mut cand = path.to_vec();
        let mut b = Buf::new();
        b.push_str(".tmp.");
        b.push_u64(sys::getpid() as u64);
        b.push(b'.');
        b.push_str(&format!("{:016x}", sys::monotonic_ns()));
        cand.extend_from_slice(b.as_bytes());
        let fd = sys::open(&cand, flags, 0o600);
        if fd >= 0 {
            sys::close(fd);
            let _ = std::fs::remove_file(Path::new(OsStr::from_bytes(&cand)));
            return true;
        }
        if sys::last_error().raw_os_error() != Some(libc::EEXIST) {
            return false;
        }
    }
    false
}

/// Total and free bytes on the filesystem that holds `dir`.
pub fn space(dir: &[u8]) -> Option<(u64, u64)> {
    sys::statvfs(dir)
}
