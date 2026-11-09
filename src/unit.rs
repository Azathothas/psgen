//! A systemd unit that starts the synthetic daemons at boot.
//!
//! A process started at boot has a START close to the boot time, which is what
//! the synthetic table shows for long-running rows. The unit is printed, not
//! installed; the operator decides whether to write it.

use crate::cli::Args;
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

pub fn render(count: usize, seed: u64, pidfile: &[u8], args: &Args) -> Buf {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/usr/local/bin/psgen".to_string());
    let mut out = Buf::new();
    out.push_str("[Unit]\n");
    out.push_str("Description=psgen synthetic process table\n");
    // systemd has no proc-fs-nets.target; naming it made every boot log a
    // failed dependency. `/proc` is a kernel mount, so local-fs and sysinit
    // are the ones that matter.
    out.push_str("After=local-fs.target sysinit.target\n");
    // A condition evaluated by the manager says nothing about the service's
    // own procfs; /proc/1/stat is the init process the service will sit next
    // to.
    out.push_str("ConditionPathExists=/proc/1/stat\n\n");
    out.push_str("[Service]\n");
    out.push_str("Type=oneshot\n");
    out.push_str("RemainAfterExit=yes\n");
    // The manager removes this directory when the unit stops, so the pidfile
    // is gone by the time ExecStart runs again and the service can restart.
    // Without it a second start found a pidfile from the previous run.
    out.push_str("RuntimeDirectory=psgen\n");
    out.push_str("RuntimeDirectoryMode=0700\n");
    out.push_str("ExecStart=");
    out.push_bytes(&arg(exe.as_bytes()));
    out.push_str(" inject --quiet --pidfile ");
    out.push_bytes(&arg(pidfile));
    out.push_str(" -n ");
    out.push_u64(count as u64);
    out.push_str(" -s ");
    out.push_u64(seed);
    // Every inject option the caller gave is forwarded, so a unit written
    // from `psgen unit -p desktop -n 40` injects desktop rows at boot. Before,
    // only -n, -s, --pidfile and --create-users reached the unit and the rest
    // were dropped without a word.
    for item in args.forwarded() {
        out.push(b' ');
        out.push_bytes(&arg(&item));
    }
    if args.create_users {
        out.push_str(" --create-users");
    }
    // A pidfile that is already gone (every injected row exited on --duration,
    // the inject failed, or this is the second stop) must not mark the service
    // stop as failed. `ExecStop=-` is the documented way to say that, and
    // `psgen stop` already exits 0 for a pidfile that names nothing live.
    out.push_str("\nExecStop=-");
    out.push_bytes(&arg(exe.as_bytes()));
    out.push_str(" stop --pidfile ");
    out.push_bytes(&arg(pidfile));
    out.push_str("\n\n[Install]\nWantedBy=multi-user.target\n");
    out
}
