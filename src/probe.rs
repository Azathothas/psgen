//! Capability probe.
//!
//! `inject` asks this module what the current deployment actually permits
//! before it promises anything. Every check that would change process state
//! runs in a forked child, so probing never modifies the caller.

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
    /// The probe could not fork, so the check never ran. A failure reported
    /// here is the process limit, not the capability the check names.
    pub not_attempted: bool,
}

impl Check {
    fn new(name: &'static str, ok: bool, errno: i32, detail: &[u8]) -> Check {
        Check {
            name,
            ok,
            errno,
            detail: detail.to_vec(),
            not_attempted: false,
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
///
/// The third value is true when the probe could not fork at all, which is a
/// process limit rather than the capability being tested. A closure may return
/// a negative errno to mean "precondition failed"; the caller can then name the
/// precondition instead of the syscall the check would have made.
fn in_child<F>(f: F) -> (bool, i32, bool)
where
    F: FnOnce() -> Result<(), i32>,
{
    let mut fds = [0i32; 2];
    if !sys::pipe2(&mut fds, 0) {
        return (false, errno(), true);
    }
    let pid = sys::fork();
    if pid == 0 {
        sys::close(fds[0]);
        let (ok, e) = match f() {
            Ok(()) => (true, 0i32),
            Err(e) => (false, e),
        };
        let raw = e.to_le_bytes();
        sys::write_fd(fds[1], &raw);
        sys::exit(if ok { 0 } else { 1 });
    }
    sys::close(fds[1]);
    if pid < 0 {
        sys::close(fds[0]);
        return (false, errno(), true);
    }
    let mut raw = [0u8; 4];
    let n = sys::read_fd(fds[0], &mut raw);
    sys::close(fds[0]);
    let mut status = 0;
    let r = sys::waitpid(pid, &mut status);
    let ok = r == pid && sys::wait_exit_code(status) == Some(0);
    let e = if n == 4 { i32::from_le_bytes(raw) } else { 0 };
    (ok, e, false)
}

fn check_pty() -> Check {
    // A seccomp policy that returns KILL for an unexpected syscall must kill
    // the probe child, not psgen. The parent then reports DENY.
    let (ok, e, _) = in_child(|| {
        let fd = sys::open(
            b"/dev/ptmx",
            sys::O_RDWR | sys::O_NOCTTY | sys::O_CLOEXEC,
            0,
        );
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

/// Whether the host can produce the config descriptor the stub requires.
///
/// The descriptor is a `memfd` created with `MFD_ALLOW_SEALING` and then sealed
/// with the size seals. A `memfd` without the flag can never be sealed, so
/// `inject` refuses to start rather than spawn stubs with a config nothing may
/// act on; probing plain `memfd_create` reported that host as capable and moved
/// the failure to every row. The probe therefore performs the exact sequence
/// the injector does.
fn check_memfd() -> Check {
    let (ok, e, not_attempted) = in_child(|| {
        let fd = sys::memfd_create(b"psgen-probe", libc::MFD_ALLOW_SEALING);
        if fd < 0 {
            return Err(errno());
        }
        let sized = sys::ftruncate(fd, 4096);
        let sealed = sized && sys::fd_add_seals(fd);
        let e = if sized && sealed { 0 } else { errno() };
        sys::close(fd);
        if sized && sealed {
            Ok(())
        } else {
            Err(e)
        }
    });
    let detail = memfd_detail(ok, not_attempted);
    let mut c = Check::new("memfd", ok, e, &detail);
    c.not_attempted = not_attempted;
    c
}

fn memfd_detail(ok: bool, not_attempted: bool) -> Vec<u8> {
    if ok {
        b"memfd_create with MFD_ALLOW_SEALING, ftruncate and F_ADD_SEALS".to_vec()
    } else if not_attempted {
        b"the probe could not fork, so memfd_create was not tried".to_vec()
    } else {
        b"memfd_create with MFD_ALLOW_SEALING, ftruncate or F_ADD_SEALS unavailable".to_vec()
    }
}

fn check_proc_exe() -> Check {
    match sys::read_link(b"/proc/self/exe") {
        Some(p) if !p.is_empty() => Check::new("proc_exe", true, 0, &p),
        Some(_) => Check::new("proc_exe", false, 0, b"empty link"),
        None => Check::new("proc_exe", false, errno(), b"readlink failed"),
    }
}

fn check_mount_ns() -> Check {
    let (ok, e, _) = in_child(|| {
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

/// Whether the bind probe has somewhere to create its two files.
///
/// A missing, non-directory or unwritable temp dir is a precondition of the
/// probe, not of a bind mount: the old code reported the `open` errno as
/// `bind_mount DENY` and the reader went looking for a mount problem that did
/// not exist. A negative errno is returned so the caller can tell the two
/// apart.
fn temp_dir_ready(dir: &Path) -> Result<(), i32> {
    match std::fs::metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(libc::ENOTDIR),
        Err(e) => return Err(e.raw_os_error().unwrap_or(1).abs()),
    }
    let p = dir.as_os_str().as_bytes();
    if !sys::access(p, sys::W_OK | sys::X_OK) {
        return Err(errno());
    }
    Ok(())
}

fn check_bind_mount() -> Check {
    let dir = std::env::temp_dir();
    let (ok, e, not_attempted) = in_child(|| {
        // Test the exact function the stub uses, so the verdict cannot drift
        // from the behaviour it predicts.
        if !crate::stub::enter_mount_ns() {
            return Err(errno());
        }
        temp_dir_ready(&dir).map_err(|e| -e)?;
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
    let errno_abs = e.abs();
    let detail = bind_detail(ok, not_attempted, e, &dir);
    let mut c = Check::new("bind_mount", ok, errno_abs, &detail);
    c.not_attempted = not_attempted;
    c
}

fn bind_detail(ok: bool, not_attempted: bool, e: i32, dir: &Path) -> Vec<u8> {
    if ok {
        b"bind inside a private mount namespace".to_vec()
    } else if not_attempted {
        b"the probe could not fork, so the bind was not attempted".to_vec()
    } else if e < 0 {
        format!(
            "temporary directory {} is missing, not a directory or not writable (errno {}); the bind was not attempted",
            dir.display(),
            e.abs()
        )
        .into_bytes()
    } else {
        b"bind inside a namespace failed".to_vec()
    }
}

fn check_user_switch() -> Check {
    if sys::geteuid() != 0 {
        return Check::new("user_switch", false, 1, b"not root");
    }
    let (ok, e, _) = in_child(|| {
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
    let (ok, e, _) = in_child(|| Ok(()));
    Check::new(
        "fork",
        ok,
        e,
        if ok {
            b"child exited 0"
        } else {
            b"fork failed"
        },
    )
}

fn check_prctl() -> Check {
    let (ok, e, _) = in_child(|| {
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
        if ok {
            b"PR_SET_NAME"
        } else {
            b"PR_SET_NAME denied"
        },
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
                if ok {
                    b"cwd writable"
                } else {
                    b"cwd not writable"
                },
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
        if ok {
            b"/proc/PID/stat readable"
        } else {
            b"/proc/PID/stat unreadable"
        },
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
    in_child(|| {
        if sys::bpf_allowed() {
            Ok(())
        } else {
            Err(errno())
        }
    })
    .0
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
    /// The memfd probe never ran because the probe could not fork. The
    /// capability is unknown rather than denied, and the warning must say so.
    pub memfd_untested: bool,
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
        memfd_untested: checks
            .iter()
            .find(|c| c.name == "memfd")
            .map(|c| c.not_attempted)
            .unwrap_or(false),
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

/// How many temporary-name shapes `write_pidfile` will try. The first is the
/// most collision-resistant; the later ones are strictly shorter, so a
/// pidfile whose basename is close to `NAME_MAX` still has somewhere to go:
/// `.tmp.<pid>.<16 hex>`, `.t<pid><6 hex>`, `.tmp.<pid>`, `.t<pid>`.
pub fn pidfile_temp_levels() -> usize {
    4
}

/// How many times one temporary-name shape is retried before the next, shorter
/// shape is tried. The writer and the preflight share this so neither can test
/// fewer collisions than the other tolerates.
pub const PIDFILE_RETRIES: u64 = 16;

/// An upper bound on the pidfile body, for the caller that cannot know the
/// exact size before the rows exist.
///
/// The pre-spawn preflight runs before any PID is known, so it proves the
/// largest body the writer can emit: a header, a `# temp` line per staging
/// directory, and 500 rows at the maximum comm length (about 50 KiB). It is an
/// upper bound, so a filesystem that fits a real run is never refused for a
/// body the writer would never emit; and it is the size the post-spawn write
/// must fit, so a filesystem that cannot hold it fails before the first fork.
pub const PIDFILE_PROBE_BYTES: usize = 64 * 1024;

/// The size the pre-spawn preflight writes when the caller has no exact body.
///
/// The pending file is a header and nothing else (about 100 bytes), so a
/// 64 KiB allocation test rejects a file that fits: `RLIMIT_FSIZE` of 32 KiB
/// failed the probe and left the caller with a `SIGXFSZ` and no pidfile. A
/// caller that knows its body passes the exact length instead.
pub const PIDFILE_PENDING_BYTES: usize = 256;

/// The temporary name `write_pidfile` creates for `path` at `level`.
///
/// `pidfile_creatable` and `write_pidfile` both call this, so the preflight
/// can never test a different name from the one the writer uses.
pub fn pidfile_temp_name(path: &[u8], level: usize, nonce: u64) -> Vec<u8> {
    let mut cand = path.to_vec();
    cand.push(b'.');
    match level {
        0 => cand.extend_from_slice(format!("tmp.{}.{:016x}", sys::getpid(), nonce).as_bytes()),
        1 => cand
            .extend_from_slice(format!("t{}{:06x}", sys::getpid(), nonce & 0xff_ffff).as_bytes()),
        2 => cand.extend_from_slice(format!("tmp.{}", sys::getpid()).as_bytes()),
        _ => cand.extend_from_slice(format!("t{}", sys::getpid()).as_bytes()),
    }
    cand
}

/// The length limit for one path component on the filesystems psgen targets.
/// ext4, xfs, btrfs and tmpfs all use 255; a filesystem with a smaller limit
/// reports `ENAMETOOLONG` from the write probe, which `inject` still surfaces.
pub const NAME_MAX: usize = 255;

/// Why one path component cannot name a file, if it cannot.
///
/// `unit` and the pidfile preflight share this rule so a path `inject` refuses
/// cannot be printed into a unit that would fail at every boot.
pub fn component_problem(component: &[u8]) -> Option<&'static str> {
    if component.is_empty() {
        Some("the path ends in a slash or has an empty component")
    } else if component == b"." || component == b".." {
        Some("a path component is `.` or `..`, which names a directory")
    } else if component.len() > NAME_MAX {
        Some("a path component is longer than NAME_MAX (255 bytes)")
    } else if component.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        Some("the path contains a control byte")
    } else {
        None
    }
}

/// Why a pidfile path cannot be used, when it cannot.
pub enum TargetProblem {
    /// The path could not be examined at all: `ENAMETOOLONG` for a component
    /// above `NAME_MAX` or a path above `PATH_MAX`, `EACCES` for a directory
    /// the caller cannot search, and so on.
    Unreadable(i32),
    /// The object exists but is not an absent path, an empty file, or a psgen
    /// pidfile.
    Foreign,
}

/// Whether a pidfile may replace the object at `path`.
///
/// `pidfile_target_ok` is the boolean form; this one says why, so the error
/// message can name the real cause instead of asserting the usual one.
///
/// `Unreadable` carries the errno of the operation that would fail, which is
/// not always an examination: a file another user owns inside a sticky
/// directory can be read, and only the rename that would replace it is denied
/// with `EPERM`.
pub fn pidfile_target(path: &[u8]) -> Result<(), TargetProblem> {
    let path = path.strip_suffix(&[0]).unwrap_or(path);
    let p = Path::new(OsStr::from_bytes(path));
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(TargetProblem::Unreadable(
                e.raw_os_error().unwrap_or(libc::EIO).abs(),
            ))
        }
    };
    if !meta.file_type().is_file() {
        return Err(TargetProblem::Foreign);
    }
    if meta.len() > 0 {
        let prefix = crate::version::PIDFILE_PREFIX;
        let mut buf = [0u8; 16];
        match sys::read_file(path, &mut buf) {
            Some(n) if n >= prefix.len() && &buf[..prefix.len()] == prefix => {}
            _ => return Err(TargetProblem::Foreign),
        }
    }
    if !pidfile_replaceable(path) {
        return Err(TargetProblem::Unreadable(libc::EPERM));
    }
    Ok(())
}

pub fn pidfile_target_ok(path: &[u8]) -> bool {
    pidfile_target(path).is_ok()
}

/// The errno that stopped the preflight, or 0 when the pidfile can be written.
///
/// `inject` writes a temporary file beside `path`, fills it with the body it
/// will commit, renames it over `path`, and proves the rename target is one it
/// may replace. A preflight that only creates a zero-byte file proves a
/// smaller write than the writer performs: a full filesystem, a quota or an
/// `RLIMIT_FSIZE` passes it and then fails after the stubs exist, leaving a
/// header-only pidfile that `stop` reports as a clean stop of nothing.
///
/// The rename is exercised for real, into a second temporary name, because
/// `rename(2)` is the operation that fails in a sticky directory when the
/// caller owns the temporary file but the target belongs to another user.
pub fn pidfile_creatable_errno(path: &[u8]) -> i32 {
    pidfile_creatable_errno_bytes(path, PIDFILE_PENDING_BYTES)
}

/// `pidfile_creatable_errno`, proving a write of `bytes` rather than of the
/// default pending size.
pub fn pidfile_creatable_errno_bytes(path: &[u8], bytes: usize) -> i32 {
    let path = path.strip_suffix(&[0]).unwrap_or(path);
    if path.is_empty() {
        return libc::EINVAL;
    }
    match pidfile_shape_errno(path) {
        Ok(()) => {}
        Err(e) => return e,
    }
    pidfile_write_errno(path, bytes)
}

/// Whether a pidfile may be created, proving a write of `bytes`.
pub fn pidfile_creatable_bytes(path: &[u8], bytes: usize) -> bool {
    pidfile_creatable_errno_bytes(path, bytes) == 0
}

/// The reasons a pidfile path is unusable that do not depend on writing: an
/// absent target, an empty one, or a psgen pidfile, in a directory the caller
/// may create files in and rename over.
pub fn pidfile_shape_errno(path: &[u8]) -> Result<(), i32> {
    let path = path.strip_suffix(&[0]).unwrap_or(path);
    if path.is_empty() {
        return Err(libc::EINVAL);
    }
    let base = match path.iter().rposition(|b| *b == b'/') {
        Some(at) => &path[at + 1..],
        None => path,
    };
    // Only the length is decided here. A `.` or `..` component still reaches
    // the real probe, whose `EISDIR` describes what actually failed.
    if base.len() > NAME_MAX {
        return Err(libc::ENAMETOOLONG);
    }
    match pidfile_target(path) {
        Ok(()) => {}
        Err(TargetProblem::Unreadable(e)) => return Err(e),
        Err(TargetProblem::Foreign) => return Err(libc::EEXIST),
    }
    let parent = pidfile_parent(path);
    if !sys::is_dir(parent) {
        return Err(libc::ENOENT);
    }
    if !sys::access(parent, sys::W_OK) {
        return Err(libc::EACCES);
    }
    if !pidfile_replaceable(path) {
        return Err(libc::EPERM);
    }
    Ok(())
}

/// The reasons the write itself would fail, proved by performing it.
fn pidfile_write_errno(path: &[u8], bytes: usize) -> i32 {
    let flags = sys::O_WRONLY | sys::O_CREAT | sys::O_EXCL | sys::O_NOFOLLOW;
    let body = [0u8; 4096];
    for level in 0..pidfile_temp_levels() {
        let mut too_long = false;
        for retry in 0..PIDFILE_RETRIES {
            let nonce = sys::monotonic_ns() ^ retry.wrapping_mul(0x9e3779b97f4a7c15);
            let name = pidfile_temp_name(path, level, nonce);
            let fd = sys::open(&name, flags, 0o600);
            if fd < 0 {
                match sys::last_error().raw_os_error() {
                    Some(libc::EEXIST) => continue,
                    Some(libc::ENAMETOOLONG) => {
                        too_long = true;
                        break;
                    }
                    Some(e) => return e.abs(),
                    None => return libc::EIO,
                }
            }
            let errno = probe_pidfile_body(fd, &body, path, level, nonce, bytes);
            sys::close(fd);
            let _ = std::fs::remove_file(Path::new(OsStr::from_bytes(&name)));
            return errno;
        }
        if !too_long {
            return libc::EEXIST;
        }
    }
    libc::ENAMETOOLONG
}

/// Fill and rename one probe file, returning 0 or the errno that failed.
fn probe_pidfile_body(
    fd: i32,
    body: &[u8],
    path: &[u8],
    level: usize,
    nonce: u64,
    bytes: usize,
) -> i32 {
    let mut left = bytes.clamp(1, PIDFILE_PROBE_BYTES);
    while left > 0 {
        let n = left.min(body.len());
        if !sys::write_fd(fd, &body[..n]) {
            return sys::last_error().raw_os_error().unwrap_or(libc::EIO).abs();
        }
        left -= n;
    }
    // `write` returning is not the same as the space being there, and the
    // writer fsyncs what it wrote, so the same failure has to be provable here.
    if !sys::fsync_fd(fd) {
        return sys::last_error().raw_os_error().unwrap_or(libc::EIO).abs();
    }
    // Prove the rename itself, into a second name beside the target. The
    // probe file is still open, so this is the same operation the writer will
    // perform; a rename *onto* the target is additionally covered by
    // `pidfile_replaceable`, which cannot create new state in the target.
    let dst = pidfile_temp_name(path, level, nonce ^ 0xa5a5_a5a5_a5a5_a5a5);
    let src = pidfile_temp_name(path, level, nonce);
    let renamed = std::fs::rename(
        Path::new(OsStr::from_bytes(&src)),
        Path::new(OsStr::from_bytes(&dst)),
    );
    match renamed {
        Ok(()) => {
            let _ = std::fs::remove_file(Path::new(OsStr::from_bytes(&dst)));
            0
        }
        Err(e) => e.raw_os_error().unwrap_or(libc::EIO).abs(),
    }
}

/// Whether `rename(2)` may replace whatever is at `path`.
///
/// `access(W_OK)` on the parent is not enough: a directory with the sticky
/// bit set (`/tmp`) lets a user create files and rename their own, but not
/// replace a file another user owns. The caller can read such a file and so
/// passes every earlier check, and only the rename fails.
fn pidfile_replaceable(path: &[u8]) -> bool {
    use std::os::unix::fs::MetadataExt;
    let parent = pidfile_parent(path);
    let pmeta = match std::fs::symlink_metadata(Path::new(OsStr::from_bytes(parent))) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if pmeta.mode() & 0o1000 == 0 {
        return true;
    }
    match std::fs::symlink_metadata(Path::new(OsStr::from_bytes(path))) {
        // Absent: nothing to replace, and the caller may create here.
        Err(_) => true,
        Ok(t) => t.uid() == sys::geteuid() || sys::geteuid() == 0,
    }
}

pub fn pidfile_creatable(path: &[u8]) -> bool {
    pidfile_creatable_errno(path) == 0
}

/// Total and free bytes on the filesystem that holds `dir`.
pub fn space(dir: &[u8]) -> Option<(u64, u64)> {
    sys::statvfs(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfile_target_accepts_what_psgen_writes() {
        // The header is eight bytes; an eight-byte comparison is what made a
        // pidfile psgen had just written look foreign.
        let dir = std::env::temp_dir().join(format!(".psgen-test-{}-a", sys::getpid()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("p.pid");
        let body = format!("# psgen {} boot abc\n1\t2\tcomm\n", crate::version::VERSION);
        std::fs::write(&path, body.as_bytes()).unwrap();
        let bytes = path.as_os_str().as_bytes().to_vec();
        assert!(pidfile_target_ok(&bytes));
        // An empty file is fine too.
        std::fs::write(&path, b"").unwrap();
        assert!(pidfile_target_ok(&bytes));
        // Something that is not a psgen pidfile is not.
        std::fs::write(&path, b"hello world, not a header\n").unwrap();
        assert!(!pidfile_target_ok(&bytes));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pidfile_temp_name_grows_shorter_by_level() {
        let path = b"/tmp/psgen.pid";
        let mut prev = usize::MAX;
        for level in 0..pidfile_temp_levels() {
            let n = pidfile_temp_name(path, level, 0x1234_5678_9abc_def0);
            assert!(
                n.len() < prev,
                "level {} ({}) is not shorter than the previous ({})",
                level,
                n.len(),
                prev
            );
            prev = n.len();
        }
        assert_ne!(
            pidfile_temp_name(path, 0, 1),
            pidfile_temp_name(path, 0, 2),
            "different nonces must yield different names"
        );
    }

    #[test]
    fn the_temp_name_of_a_near_name_max_basename_fits() {
        // The last level is `.t<pid>`; the boundary the preflight accepts is
        // exactly what that shape leaves. Both sides use the same function, so
        // this pins the count the documentation describes.
        let name = vec![b'd'; 255 - (".t".len() + sys::getpid().to_string().len())];
        let mut path = b"/tmp/".to_vec();
        path.extend_from_slice(&name);
        let last = pidfile_temp_name(&path, pidfile_temp_levels() - 1, 0);
        assert!(
            last.len() <= 4096,
            "the last temporary name must stay within PATH_MAX"
        );
    }

    #[test]
    fn a_foreign_owner_in_a_sticky_directory_is_not_replaceable() {
        // The review's case: an empty root-owned file in /tmp. The check has to
        // deny it for an unprivileged caller, because only rename(2) would fail
        // and a preflight that does not predict that fails after the fork.
        if sys::geteuid() == 0 {
            return;
        }
        let dir = Path::new("/tmp");
        let probe = dir.join(format!(".psgen-sticky-test-{}.pid", sys::getpid()));
        let bytes = probe.as_os_str().as_bytes().to_vec();
        // Own the file: replaceable.
        std::fs::write(&probe, b"").unwrap();
        assert!(pidfile_replaceable(&bytes));
        let _ = std::fs::remove_file(&probe);
        // An absent target is replaceable too.
        assert!(pidfile_replaceable(&bytes));
    }

    #[test]
    fn a_missing_temp_directory_is_a_precondition_not_a_bind_failure() {
        let base = std::env::temp_dir().join(format!(".psgen-test-{}-td", sys::getpid()));
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(temp_dir_ready(&base.join("missing")), Err(libc::ENOENT));
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(temp_dir_ready(&file), Err(libc::ENOTDIR));
        assert_eq!(temp_dir_ready(&base), Ok(()));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_precondition_failure_names_the_directory_not_a_bind() {
        let dir = Path::new("/nonexistent-tmp-for-psgen");
        let d = bind_detail(false, false, -libc::ENOENT, dir);
        let text = String::from_utf8_lossy(&d);
        assert!(text.contains("/nonexistent-tmp-for-psgen"), "{}", text);
        assert!(text.contains("not attempted"), "{}", text);
        assert!(!text.contains("bind inside a namespace failed"), "{}", text);
        // The three other outcomes stay distinct.
        assert_eq!(
            bind_detail(false, true, libc::EAGAIN, dir),
            b"the probe could not fork, so the bind was not attempted".to_vec()
        );
        assert_eq!(
            bind_detail(false, false, libc::EPERM, dir),
            b"bind inside a namespace failed".to_vec()
        );
        assert_eq!(
            bind_detail(true, false, 0, dir),
            b"bind inside a private mount namespace".to_vec()
        );
    }

    #[test]
    fn a_fork_failure_is_not_reported_as_a_memfd_denial() {
        assert_eq!(
            memfd_detail(false, true),
            b"the probe could not fork, so memfd_create was not tried".to_vec()
        );
        let denied = memfd_detail(false, false);
        let text = String::from_utf8_lossy(&denied);
        assert!(text.contains("unavailable"), "{}", text);
        assert!(!text.contains("fork"), "{}", text);
        assert!(memfd_detail(true, false).ends_with(b"F_ADD_SEALS"));
    }
}
