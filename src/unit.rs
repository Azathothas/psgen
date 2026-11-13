//! A systemd unit that starts the synthetic daemons at boot.
//!
//! A process started at boot has a START close to the boot time, which is what
//! the synthetic table shows for long-running rows. The unit is printed, not
//! installed; the operator decides whether to write it.
//!
//! The pidfile and the unit's `RuntimeDirectory=` are one decision: systemd
//! creates the directory, the pidfile is written inside it, and the stop
//! command removes the pidfile so the service can start again. A pidfile the
//! unit cannot place there is refused, because a unit whose `ExecStart` fails
//! at every boot is worse than no unit.

use crate::cli::Args;
use crate::probe;
use crate::str::Buf;
use crate::sys;

/// Quote one systemd command argument.
///
/// systemd splits an `Exec*` line on whitespace, expands `%` specifiers and `$`
/// variables, and reads a raw newline as the end of the directive, so all four
/// must be escaped or the unit names a different path from the one it was
/// given. A single quote opens a single-quoted section when it is not already
/// inside double quotes, so a value carrying one is quoted as well. `%%` and
/// `$$` are systemd's literal forms; inside double quotes the C escapes are
/// what systemd unescapes back to the byte.
fn arg(value: &[u8]) -> Vec<u8> {
    let quote = value.is_empty()
        || value.iter().any(|b| {
            matches!(
                b,
                b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'\\' | b'%'
            )
        });
    let mut out = Vec::new();
    if quote {
        out.push(b'"');
    }
    for &b in value {
        match b {
            b'%' => out.extend_from_slice(b"%%"),
            b'$' => out.extend_from_slice(b"$$"),
            b'"' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\r' => out.extend_from_slice(b"\\r"),
            _ => out.push(b),
        }
    }
    if quote {
        out.push(b'"');
    }
    out
}

/// Where the unit's pidfile lives, as far as the manager is concerned.
enum Runtime {
    /// A pidfile directly in `/run`, which always exists.
    RunRoot,
    /// `/run/<name>/…`: the directory this unit's `RuntimeDirectory=` creates.
    Named(Vec<u8>),
}

fn parent_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(0) => b"/",
        Some(i) => &path[..i],
        None => b".",
    }
}

/// The runtime directory a pidfile implies, or why it implies none.
///
/// `RuntimeDirectory=` creates one directory under `/run` and owns it for the
/// life of the unit, so the directory has to be the pidfile's own parent. A
/// pidfile anywhere else would either need a directory nothing creates (the
/// unit fails at every boot) or a directory that belongs to the system
/// (`/run`, `/run/user/1234`), which the manager must not take over.
fn runtime_of(pidfile: &[u8]) -> Result<Runtime, &'static str> {
    const OUTSIDE: &str = "a pidfile must live under /run, in a directory \
systemd creates for the unit (for example /run/psgen/psgen.pid)";
    if pidfile.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return Err("the path contains a control byte, which a unit file cannot name");
    }
    let rest = match pidfile.strip_prefix(b"/run/") {
        Some(r) => r,
        None => return Err(OUTSIDE),
    };
    if rest.is_empty() || rest.ends_with(b"/") {
        return Err(OUTSIDE);
    }
    match rest.iter().rposition(|b| *b == b'/') {
        None => Ok(Runtime::RunRoot),
        Some(at) => {
            let dir = &rest[..at];
            if dir.is_empty() || dir.contains(&b'/') {
                // `/run/user/1000` belongs to a login session: a unit that
                // named it would have it removed, or re-owned, when it stops.
                return Err(OUTSIDE);
            }
            if dir == b"." || dir == b".." || dir.iter().any(|b| *b <= b' ') {
                return Err("the runtime directory name is not one systemd can create");
            }
            Ok(Runtime::Named(dir.to_vec()))
        }
    }
}

fn refuse(pidfile: &[u8], why: &[u8]) -> ! {
    let mut out = Buf::new();
    out.push_str("psgen: cannot print a unit for the pidfile ");
    out.push_bytes(pidfile);
    out.push_str(": ");
    out.push_bytes(why);
    out.push(b'\n');
    sys::err(out.as_bytes());
    sys::exit(2)
}

fn refuse_errno(pidfile: &[u8], e: i32) -> ! {
    let mut why = Buf::new();
    if e == libc::EEXIST {
        why.push_str("the path is not an empty file or a psgen pidfile");
    } else {
        why.push_bytes(
            &std::io::Error::from_raw_os_error(e)
                .to_string()
                .into_bytes(),
        );
    }
    why.push_str(" (the unit would fail at every boot)");
    refuse(pidfile, why.as_bytes())
}

fn warn_pidfile(pidfile: &[u8], what: &str) {
    let mut out = Buf::new();
    out.push_str("psgen: the pidfile ");
    out.push_bytes(pidfile);
    out.push_str(": ");
    out.push_str(what);
    out.push(b'\n');
    sys::err(out.as_bytes());
}

/// Prove the pidfile the unit will name can be written before printing it.
///
/// `inject` runs the same preflight before it spawns anything; a unit that
/// names a pidfile `inject` would refuse is a service that fails at every
/// boot. The parent directory is the one exception: when it is the runtime
/// directory the unit declares, the manager creates it at start time, so an
/// absent parent is the normal state at the moment the unit is generated.
fn preflight(pidfile: &[u8]) {
    let parent = parent_of(pidfile);
    if !sys::is_dir(parent) {
        match probe::pidfile_target(pidfile) {
            Ok(()) => {}
            Err(probe::TargetProblem::Unreadable(e)) => refuse_errno(pidfile, e),
            Err(probe::TargetProblem::Foreign) => refuse_errno(pidfile, libc::EEXIST),
        }
    } else {
        let e = probe::pidfile_creatable_errno(pidfile);
        if e != 0 {
            // The service runs as root, so a path this caller alone cannot
            // write is not a reason to refuse a unit root can start.
            if sys::geteuid() != 0 && matches!(e, libc::EACCES | libc::EPERM) {
                warn_pidfile(
                    pidfile,
                    "is not writable by this caller; the unit runs as root",
                );
            } else {
                refuse_errno(pidfile, e);
            }
        }
    }
    // A pidfile that still names live rows makes the first start fail. That is
    // a state, not a defect in the path, so it is reported rather than refused.
    if let Some(n) = crate::inject::live_pidfile_rows(pidfile) {
        if n > 0 {
            let mut what = Buf::new();
            what.push_str("records ");
            what.push_u64(n as u64);
            what.push_str(" live processes; the unit cannot start until they are stopped");
            warn_pidfile(pidfile, &what_string(&what));
        }
    }
}

fn what_string(b: &Buf) -> std::string::String {
    std::string::String::from_utf8_lossy(b.as_bytes()).into_owned()
}

pub fn render(count: usize, seed: u64, pidfile: &[u8], args: &Args) -> Buf {
    let runtime = match runtime_of(pidfile) {
        Ok(r) => r,
        Err(why) => refuse(pidfile, why.as_bytes()),
    };
    preflight(pidfile);
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
    if let Runtime::Named(dir) = &runtime {
        // The directory is the pidfile's own parent, so the manager creates
        // exactly the directory the pidfile needs. `%` is a specifier even in
        // this setting, so a literal one is doubled.
        out.push_str("RuntimeDirectory=");
        for &b in dir {
            if b == b'%' {
                out.push_str("%%");
            } else {
                out.push(b);
            }
        }
        out.push(b'\n');
        out.push_str("RuntimeDirectoryMode=0700\n");
        // The directory outlives a stop. Removing it would delete every
        // pidfile in it, including one a second unit of the same deployment is
        // still using; the stop command removes this unit's pidfile instead.
        out.push_str("RuntimeDirectoryPreserve=yes\n");
    }
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
    // A pidfile that is already gone is the one failure that is provably
    // benign: every row may have exited on --duration, or the manager already
    // cleaned up. Every other failure — a foreign boot id, a malformed
    // pidfile, a signal that was refused — must reach systemd, so the `stop`
    // directive has no `-` prefix, which would report all of them as success.
    //
    // The absence test lives in the shell rather than in `-` because `-` cannot
    // tell "no pidfile" from "the pidfile is from another boot". The argument
    // order is `psgen-stop <exe> <pidfile>`: `$0` is the script name, `$1` the
    // executable and `$2` the pidfile. Only positional parameters are used,
    // because systemd expands `$name` as a variable of its own while leaving
    // `$1` and `$?` to the shell. A quote in the exe or the path is escaped by
    // `arg`, and the single quotes around the body keep systemd from splitting
    // it.
    //
    // `stop` does not unlink the pidfile, and a second start against a pidfile
    // from the previous run is refused, so a successful stop removes it: that
    // is what makes the unit restartable. The removal has the `-` prefix
    // because a pidfile that vanished between the check and the `rm` is the
    // same benign absence, and because it runs only after `stop` succeeded.
    out.push_str(
        "\nExecStop=/bin/sh -c 'if [ -e \"$2\" ]; then \"$1\" stop --pidfile \"$2\" \
|| exit $?; fi' psgen-stop ",
    );
    out.push_bytes(&arg(exe.as_bytes()));
    out.push(b' ');
    out.push_bytes(&arg(pidfile));
    out.push_str("\nExecStop=-/bin/rm -f -- ");
    out.push_bytes(&arg(pidfile));
    out.push_str("\n\n[Install]\nWantedBy=multi-user.target\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(pidfile: &[u8]) -> Vec<u8> {
        // Parse a plain `unit` invocation, so the test goes through the same
        // `Args` the real command builds.
        let args = match crate::cli::parse(&[b"psgen".to_vec(), b"unit".to_vec()]) {
            Ok(a) => a,
            Err(_) => panic!("`psgen unit` must parse"),
        };
        render(2, 7, pidfile, &args).v
    }

    #[test]
    fn the_runtime_directory_is_the_pidfile_directory() {
        let unit = rendered(b"/run/psgen-alt/psgen.pid");
        let text = std::string::String::from_utf8(unit).unwrap();
        assert!(text.contains("RuntimeDirectory=psgen-alt\n"), "{text}");
        assert!(
            text.contains("--pidfile /run/psgen-alt/psgen.pid "),
            "{text}"
        );
        // Two pidfile directories are two runtime directories, so stopping one
        // unit cannot remove the other's directory.
        let other = std::string::String::from_utf8(rendered(b"/run/psgen-b/psgen.pid")).unwrap();
        assert!(!other.contains("RuntimeDirectory=psgen-alt"), "{other}");
    }

    #[test]
    fn a_pidfile_outside_run_is_refused_not_printed() {
        for path in [
            &b"/var/lib/psgen/psgen.pid"[..],
            &b"/tmp/psgen.pid"[..],
            &b"/run/user/1000/psgen.pid"[..],
            &b"/run"[..],
        ] {
            assert!(
                runtime_of(path).is_err(),
                "{} must not name a runtime directory",
                std::string::String::from_utf8_lossy(path)
            );
        }
        assert!(matches!(
            runtime_of(b"/run/psgen/psgen.pid"),
            Ok(Runtime::Named(_))
        ));
        assert!(matches!(
            runtime_of(b"/run/psgen.pid"),
            Ok(Runtime::RunRoot)
        ));
    }

    #[test]
    fn a_dollar_and_a_newline_cannot_change_the_argument() {
        // `$` is a variable reference in an Exec line and a newline ends the
        // directive, so both have to be escaped or the unit names a different
        // path than the caller asked for.
        let dollars = std::string::String::from_utf8(rendered(b"/run/psgen/a$b.pid")).unwrap();
        assert!(dollars.contains("a$$b.pid"), "{dollars}");
        assert_eq!(arg(b"a%p"), b"\"a%%p\"".to_vec());
        assert_eq!(arg(b"a\nb"), b"\"a\\nb\"".to_vec());
        assert_eq!(arg(b"a'b"), b"\"a'b\"".to_vec());
        assert_eq!(arg(b"plain"), b"plain".to_vec());
        // A control byte cannot be named in a unit file at all, so the pidfile
        // is refused rather than written into the directive.
        assert!(
            runtime_of(b"/run/psg\nen/psgen.pid").is_err(),
            "a control byte must be refused rather than written into a unit"
        );
    }

    #[test]
    fn the_stop_command_tolerates_only_an_absent_pidfile() {
        let text = std::string::String::from_utf8(rendered(b"/run/psgen/psgen.pid")).unwrap();
        assert!(
            text.contains("\nExecStop=/bin/sh -c '"),
            "the stop command must carry the absence test: {text}"
        );
        // Only the removal may carry `-`: the stop itself must report a foreign
        // boot id or a refused signal as a failure.
        let stops: std::vec::Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("ExecStop="))
            .collect();
        assert_eq!(stops.len(), 2, "expected a stop and a removal: {text}");
        assert!(
            stops[0].starts_with("ExecStop=/bin/sh"),
            "the stop itself must not be prefixed with `-`: {}",
            stops[0]
        );
        assert!(
            stops[1].starts_with("ExecStop=-/bin/rm -f -- "),
            "the removal is the only benign failure: {}",
            stops[1]
        );
        // `$1` is the executable and `$2` the pidfile; swapped, the command
        // ran the pidfile path as a program.
        assert!(stops[0].contains("stop --pidfile \"$2\""), "{text}");
        assert!(stops[0].contains("\"$1\" stop"), "{text}");
        // A successful stop must remove the pidfile, or the next start is
        // refused as "records live processes" / "not an empty file".
        assert!(stops[1].contains("/run/psgen/psgen.pid"), "{text}");
    }
}
