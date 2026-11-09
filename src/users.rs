//! User and group lookup and creation.
//!
//! `getpwnam_r` and `getpwuid_r` honour NSS on glibc and read `/etc/passwd`
//! on musl. Missing system users are created with `useradd` only when the
//! caller asks for it; the names are validated first so a bad template name
//! cannot reach `/etc/passwd`.

use crate::sys;
use std::ffi::CStr;

pub struct User {
    pub name: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
}

pub fn lookup_name(name: &[u8]) -> Option<(u32, u32)> {
    let c = sys::cstr(name)?;
    let mut size = 16 * 1024usize;
    loop {
        let mut buf = vec![0u8; size];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                c.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                size,
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return None;
            }
            return Some((pwd.pw_uid, pwd.pw_gid));
        }
        if rc == libc::ERANGE && size < 1024 * 1024 {
            size *= 2;
            continue;
        }
        return None;
    }
}

pub fn lookup_uid(uid: u32) -> Option<(Vec<u8>, u32)> {
    let mut size = 16 * 1024usize;
    loop {
        let mut buf = vec![0u8; size];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                size,
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return None;
            }
            let name = unsafe { CStr::from_ptr(pwd.pw_name) };
            return Some((name.to_bytes().to_vec(), pwd.pw_gid));
        }
        if rc == libc::ERANGE && size < 1024 * 1024 {
            size *= 2;
            continue;
        }
        return None;
    }
}

pub fn current() -> User {
    let uid = sys::getuid();
    if let Some((name, gid)) = lookup_uid(uid) {
        return User { name, uid, gid };
    }
    User {
        name: b"user".to_vec(),
        uid,
        gid: sys::getgid(),
    }
}

pub fn valid_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 32 {
        return false;
    }
    let first = name[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    name[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

/// Look up a user, optionally creating it with `useradd` when it is missing.
/// Returns the uid and gid, whether this call created the account, and the
/// error text when creation failed.
pub fn ensure(name: &[u8], create: bool) -> (Option<(u32, u32)>, bool, Option<String>) {
    if let Some((uid, gid)) = lookup_name(name) {
        return (Some((uid, gid)), false, None);
    }
    if !create {
        return (None, false, None);
    }
    if !valid_name(name) {
        return (None, false, Some("invalid user name".to_string()));
    }
    let name_str = match std::str::from_utf8(name) {
        Ok(s) => s,
        Err(_) => return (None, false, Some("invalid user name".to_string())),
    };
    let attempts: [&[&str]; 3] = [
        &[
            "--system",
            "--badname",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            "--user-group",
        ],
        &[
            "--system",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            "--user-group",
        ],
        // A host can have the group without the user, for example after a
        // package was removed but its group survived. --user-group fails
        // there, so use the existing group by name.
        &[
            "--system",
            "--badname",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            "--gid",
            name_str,
        ],
    ];
    let mut last_error = String::new();
    for opts in attempts.iter() {
        let mut cmd = std::process::Command::new("useradd");
        for o in opts.iter() {
            cmd.arg(o);
        }
        cmd.arg("--").arg(name_str);
        match cmd.output() {
            Ok(out) => {
                if out.status.success() {
                    if let Some((uid, gid)) = lookup_name(name) {
                        return (Some((uid, gid)), true, None);
                    }
                    last_error = "useradd succeeded but the user is not visible".to_string();
                } else {
                    last_error = String::from_utf8_lossy(&out.stderr).trim().to_string();
                }
            }
            Err(e) => {
                last_error = e.to_string();
            }
        }
    }
    (
        None,
        false,
        Some(if last_error.is_empty() {
            "useradd failed".to_string()
        } else {
            last_error
        }),
    )
}
