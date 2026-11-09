//! A systemd unit that starts the synthetic daemons at boot.
//!
//! A process started at boot has a START close to the boot time, which is what
//! the synthetic table shows for long-running rows. The unit is printed, not
//! installed; the operator decides whether to write it.

use crate::str::Buf;

/// Quote one systemd command argument.
///
/// systemd splits ExecStart on whitespace and expands `%` specifiers, so a
/// path that contains either must be escaped or the unit names a different
/// executable. Double quotes with backslash escapes cover both cases.
fn arg(value: &[u8]) -> Vec<u8> {
    let quote = value.is_empty()
        || value
            .iter()
            .any(|b| matches!(b, b' ' | b'\t' | b'"' | b'\\' | b'%'));
    let mut out = Vec::new();
    if quote {
        out.push(b'"');
    }
    for &b in value {
        match b {
            b'%' => out.extend_from_slice(b"%%"),
            b'"' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            _ => out.push(b),
        }
    }
    if quote {
        out.push(b'"');
    }
    out
}

pub fn render(count: usize, seed: u64, pidfile: &[u8], create_users: bool) -> Buf {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/usr/local/bin/psgen".to_string());
    let mut out = Buf::new();
    out.push_str("[Unit]\n");
    out.push_str("Description=psgen synthetic process table\n");
    out.push_str("After=local-fs.target sysinit.target\n");
    out.push_str("ConditionPathExists=/proc/self/stat\n\n");
    out.push_str("[Service]\n");
    out.push_str("Type=oneshot\n");
    out.push_str("RemainAfterExit=yes\n");
    out.push_str("ExecStart=");
    out.push_bytes(&arg(exe.as_bytes()));
    out.push_str(" inject --quiet --pidfile ");
    out.push_bytes(&arg(pidfile));
    out.push_str(" -n ");
    out.push_u64(count as u64);
    out.push_str(" -s ");
    out.push_u64(seed);
    if create_users {
        out.push_str(" --create-users");
    }
    out.push_str("\nExecStop=");
    out.push_bytes(&arg(exe.as_bytes()));
    out.push_str(" stop --pidfile ");
    out.push_bytes(&arg(pidfile));
    out.push_str("\n\n[Install]\nWantedBy=multi-user.target\n");
    out
}
