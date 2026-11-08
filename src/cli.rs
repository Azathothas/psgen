//! Argument parsing and command dispatch.

use crate::check;
use crate::corpus;
use crate::doctor;
use crate::activity;
use crate::gen::{self, Opts};
use crate::inject;
use crate::live;
use crate::loggen;
use crate::probe;
use crate::rng::Rng;
use crate::str::{self, Buf};
use crate::sys;
use crate::table;
use crate::unit;
use crate::users;
use crate::util;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::vec::Vec;

#[derive(Clone, Copy, PartialEq)]
pub enum Sub {
    List,
    Table,
    Inject,
    Stop,
    Corpus,
    Check,
    Unit,
    Doctor,
    Log,
    Load,
    Help,
    Version,
}

pub struct Args {
    pub sub: Sub,
    pub count: usize,
    pub seed: Option<u64>,
    pub profile: Vec<u8>,
    pub family: Option<u8>,
    pub sort: bool,
    pub uniq: bool,
    pub offset_min: i64,
    pub local: bool,
    pub pidfile: Option<Vec<u8>>,
    pub duration: u32,
    pub mem: bool,
    pub mem_cap_mb: u64,
    pub phys_cap: Option<u64>,
    pub tty: bool,
    pub threads: bool,
    pub user: bool,
    pub create_users: bool,
    pub busy: bool,
    pub dry_run: bool,
    pub wait: bool,
    pub binaries: bool,
    pub quiet: bool,
    pub want_help: bool,
    pub want_version: bool,
    pub elevate: bool,
    pub table: bool,
    pub live: bool,
    pub force: bool,
    pub no_exe: bool,
    pub verify: bool,
    pub cpu_pct: Option<u32>,
    pub mem_target_kb: Option<u32>,
    pub disk_mb: Option<u64>,
    pub no_root: bool,
    pub shadow_dir: Option<Vec<u8>>,
    pub json: bool,
    pub log_module: Vec<u8>,
    pub log_lines: usize,
    pub log_delay_ms: u64,
    pub log_fmt: Option<loggen::Format>,
    pub speed: u64,
    pub load_cpu: Option<u32>,
    pub load_mem: Option<u32>,
    pub load_disk: Option<u64>,
}

impl Args {
    fn new() -> Args {
        Args {
            sub: Sub::List,
            count: 0,
            seed: None,
            profile: b"server".to_vec(),
            family: None,
            sort: true,
            uniq: true,
            offset_min: 0,
            local: false,
            pidfile: None,
            duration: 0,
            mem: true,
            mem_cap_mb: 0,
            phys_cap: None,
            tty: true,
            threads: true,
            user: true,
            create_users: false,
            busy: false,
            dry_run: false,
            wait: false,
            binaries: false,
            quiet: false,
            want_help: false,
            want_version: false,
            elevate: false,
            table: false,
            live: false,
            force: false,
            no_exe: false,
            verify: false,
            cpu_pct: None,
            mem_target_kb: None,
            disk_mb: None,
            no_root: false,
            shadow_dir: None,
            json: false,
            log_module: b"weblog".to_vec(),
            log_lines: 20,
            log_delay_ms: 0,
            log_fmt: None,
            speed: 1,
            load_cpu: None,
            load_mem: None,
            load_disk: None,
        }
    }
}

fn usage() -> &'static str {
    "psgen 0.0.1 - realistic Linux process lists, on stdout or in the real process table

USAGE
  psgen [list] [options]        print command lines, one per line
  psgen table [options]         print a ps aux style table
  psgen table --live            print the real process table in the same format
  psgen inject [options]        start dummy processes visible in real ps
  psgen stop --pidfile FILE     stop processes started by inject
  psgen corpus                  dump the embedded corpus
  psgen check [--binaries]      validate the corpus and expanded output
  psgen doctor [--json]         probe what this environment permits
  psgen log [options]           write activity logs to stdout
  psgen load [options]          create real cpu, memory and disk pressure
  psgen unit [options]          print a systemd unit that injects at boot

COMMON
  -n, --count N       rows or commands (list: all templates, table: 30, inject: 12)
  -s, --seed N        deterministic output
  -p, --profile NAME  server (default), dev, desktop
  -f, --family NAME   sys, web, db, ctr, dev, mon, sto, mail, desk, net
      --utc-offset M  minutes east of UTC for the START column (default 0)
      --local         use the system timezone for the START column
      --sort / --no-sort   list only
      --uniq / --no-uniq   list only
  -h, --help
  -V, --version

INJECT
  -d, --duration S      lifetime in seconds (0 = until stopped; rows marked
                        short use the 120 s default)
      --pidfile FILE    write the spawned PIDs here; an existing file must be
                        empty or a psgen pidfile
      --mem / --no-mem  pad VSZ and RSS (default on)
      --mem-cap MiB     cap the planned RSS sum; the reported RSS can exceed
                        it by up to a page per stub (0 = no cap, default)
      --mem-target KiB  per-stub RSS target in KiB
      --phys-cap MiB    physical budget for the arena, page tables and base
                        RSS (0 = unlimited, omitted = a quarter of RAM or
                        half the cgroup limit)
      --disk MiB        write this many MiB of temp data per stub
      --exe / --no-exe  bind the template executable path (default on)
      --allow-proc-exe  alias of --no-exe: exec /proc/self/exe, no spoof
      --shadow-dir DIR  directory for the shadow copy when the bind is
                        unavailable or with --no-root; the copy goes in a
                        per-run subdirectory; ignored with --no-exe
      --no-root         portable mode: no user switch, no mount namespace,
                        no bind tier; the stub uses /proc/self/exe or --shadow-dir
      --tty / --no-tty  give tty processes a real pty (default on);
                        --no-tty also detaches every row from the caller's
                        controlling terminal
      --threads / --no-threads  give threaded processes a second thread (default on)
      --user / --no-user  switch to the template user when running as root
      --create-users    create missing template users with useradd
      --busy            burn CPU for processes that are normally CPU bound
      --cpu PCT         target cpu percent for every row; forces the busy path
                        when non-zero, 0 clears it (0..100)
      --dry-run         print what would be spawned
      --table           after spawning, print the real ps aux table for the stubs
      --verify          compare each stub's real VSZ/RSS with the planned
                        value; requires --mem
      --wait            block for a non-zero --duration, then stop the stubs
      --elevate         re-exec through sudo -n when not already root
  -q, --quiet           suppress the inject summary

DOCTOR
      --json            machine readable output

LOG
  -m, --module NAME   weblog (default), bootlog, cargo, cc, download,
                      docker_build, docker_rmi, terraform, ansible,
                      kernel_compile, mkinitcpio, uv, composer, julia, list
      --lines N       events to write (default 20); a weblog burst can produce multiple rows per event
      --delay MS      pause between events
      --speed N       divide the delay by N (default 1)
      --log-fmt NAME  apache (weblog family: access, apache, nginx, web,
                      flog), json, syslog

LOAD
      --cpu-util PCT  burn this percent of one core
      --mem-util PCT  touch and hold this percent of MemTotal, or of the cgroup limit when lower
      --disk-util MiB write and hold MiB of temp data
  -d, --duration S    stop after S seconds (0 = until killed)

STOP
      --force           ignore the boot id; a three-field line still checks
                        starttime and comm, a two-field line still checks
                        starttime, and a one-field line still requires
                        an exe match
"
}

fn set_sub(a: &mut Args, name: &[u8]) -> bool {
    a.sub = match name {
        b"list" | b"ps" => Sub::List,
        b"table" => Sub::Table,
        b"inject" | b"spawn" => Sub::Inject,
        b"stop" | b"kill" => Sub::Stop,
        b"corpus" => Sub::Corpus,
        b"check" => Sub::Check,
        b"unit" => Sub::Unit,
        b"doctor" | b"probe" | b"env" => Sub::Doctor,
        b"log" | b"activity" => Sub::Log,
        b"load" | b"lookbusy" => Sub::Load,
        b"help" => Sub::Help,
        b"version" => Sub::Version,
        _ => return false,
    };
    true
}

fn take_value<'a>(
    args: &'a [Vec<u8>],
    i: &mut usize,
    inline: Option<&'a [u8]>,
) -> Option<&'a [u8]> {
    if let Some(v) = inline {
        return Some(v);
    }
    if *i + 1 < args.len() && !args[*i + 1].starts_with(b"--") {
        *i += 1;
        Some(&args[*i])
    } else {
        None
    }
}

fn is_boolean_flag(name: &[u8]) -> bool {
    matches!(
        name,
        b"-h" | b"--help"
            | b"-V"
            | b"--version"
            | b"--local"
            | b"--sort"
            | b"--no-sort"
            | b"--uniq"
            | b"--no-uniq"
            | b"--mem"
            | b"--no-mem"
            | b"--tty"
            | b"--no-tty"
            | b"--threads"
            | b"--no-threads"
            | b"--user"
            | b"--no-user"
            | b"--create-users"
            | b"--busy"
            | b"--dry-run"
            | b"--wait"
            | b"--binaries"
            | b"--elevate"
            | b"--table"
            | b"--live"
            | b"--force"
            | b"--verify"
            | b"--exe"
            | b"--no-exe"
            | b"--allow-proc-exe"
            | b"--no-root"
            | b"--json"
            | b"-q"
            | b"--quiet"
    )
}

fn abs_path(p: &[u8]) -> Vec<u8> {
    let path = Path::new(OsStr::from_bytes(p));
    if path.is_absolute() {
        return p.to_vec();
    }
    match std::path::absolute(path) {
        Ok(a) => a.as_os_str().as_bytes().to_vec(),
        Err(_) => p.to_vec(),
    }
}

pub fn parse(args: &[Vec<u8>]) -> Result<Args, &'static str> {
    let mut a = Args::new();
    let mut i = 1usize;
    let mut saw_sub = false;
    let mut stop_options = false;
    while i < args.len() {
        let arg = &args[i];
        if !stop_options && arg == b"--" {
            stop_options = true;
            i += 1;
            continue;
        }
        if !stop_options && !arg.is_empty() && arg[0] == b'-' && arg.len() > 1 {
            let (name, inline) = match str::find(arg, b"=") {
                Some(pos) => (&arg[..pos], Some(&arg[pos + 1..])),
                None => (&arg[..], None),
            };
            if inline.is_some() && is_boolean_flag(name) {
                return Err("this option does not take a value");
            }
            match name {
                b"-h" | b"--help" => a.want_help = true,
                b"-V" | b"--version" => a.want_version = true,
                b"-n" | b"--count" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --count")?;
                    a.count =
                        usize::try_from(str::parse_u64(v).ok_or("invalid --count")?)
                            .map_err(|_| "invalid --count")?;
                }
                b"-s" | b"--seed" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --seed")?;
                    a.seed = Some(str::parse_u64(v).ok_or("invalid --seed")?);
                }
                b"-p" | b"--profile" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --profile")?;
                    if v != b"server" && v != b"dev" && v != b"desktop" {
                        return Err("unknown profile");
                    }
                    a.profile = v.to_vec();
                }
                b"-f" | b"--family" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --family")?;
                    a.family = Some(corpus::family_id(v).ok_or("unknown family")?);
                }
                b"--utc-offset" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --utc-offset")?;
                    a.offset_min = str::parse_i64(v).ok_or("invalid --utc-offset")?;
                }
                b"--local" => a.local = true,
                b"--pidfile" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --pidfile")?;
                    a.pidfile = Some(abs_path(v));
                }
                b"-d" | b"--duration" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --duration")?;
                    let n = str::parse_u64(v).ok_or("invalid --duration")?;
                    a.duration = u32::try_from(n).map_err(|_| "invalid --duration")?;
                }
                b"--mem-cap" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --mem-cap")?;
                    a.mem_cap_mb = str::parse_u64(v).ok_or("invalid --mem-cap")?;
                }
                b"--phys-cap" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --phys-cap")?;
                    a.phys_cap = Some(str::parse_u64(v).ok_or("invalid --phys-cap")?);
                }
                b"--sort" => a.sort = true,
                b"--no-sort" => a.sort = false,
                b"--uniq" => a.uniq = true,
                b"--no-uniq" => a.uniq = false,
                b"--mem" => a.mem = true,
                b"--no-mem" => a.mem = false,
                b"--tty" => a.tty = true,
                b"--no-tty" => a.tty = false,
                b"--threads" => a.threads = true,
                b"--no-threads" => a.threads = false,
                b"--user" => a.user = true,
                b"--no-user" => a.user = false,
                b"--create-users" => a.create_users = true,
                b"--busy" => a.busy = true,
                b"--dry-run" => a.dry_run = true,
                b"--wait" => a.wait = true,
                b"--binaries" => a.binaries = true,
                b"--elevate" => a.elevate = true,
                b"--table" => a.table = true,
                b"--live" => a.live = true,
                b"--force" => a.force = true,
                b"--verify" => a.verify = true,
                b"--exe" => a.no_exe = false,
                b"--no-exe" | b"--allow-proc-exe" => a.no_exe = true,
                b"--shadow-dir" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --shadow-dir")?;
                    a.shadow_dir = Some(abs_path(v));
                }
                b"--no-root" => a.no_root = true,
                b"--cpu" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --cpu")?;
                    let n = str::parse_u64(v).ok_or("invalid --cpu")?;
                    if n > 100 {
                        return Err("--cpu must be 0..100");
                    }
                    a.cpu_pct = Some(n as u32);
                }
                b"--mem-target" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --mem-target")?;
                    let n = str::parse_u64(v).ok_or("invalid --mem-target")?;
                    a.mem_target_kb =
                        Some(u32::try_from(n).map_err(|_| "invalid --mem-target")?);
                }
                b"--disk" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --disk")?;
                    let n = str::parse_u64(v).ok_or("invalid --disk")?;
                    if n > u32::MAX as u64 / 1024 {
                        return Err("invalid --disk");
                    }
                    a.disk_mb = Some(n);
                }
                b"--json" => a.json = true,
                b"--log-fmt" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --log-fmt")?;
                    a.log_fmt = Some(loggen::Format::parse(v).ok_or("unknown --log-fmt")?);
                }
                b"-m" | b"--module" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --module")?;
                    a.log_module = v.to_vec();
                }
                b"--lines" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --lines")?;
                    a.log_lines =
                        usize::try_from(str::parse_u64(v).ok_or("invalid --lines")?)
                            .map_err(|_| "invalid --lines")?;
                }
                b"--delay" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --delay")?;
                    a.log_delay_ms = str::parse_u64(v).ok_or("invalid --delay")?;
                }
                b"--speed" => {
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --speed")?;
                    a.speed = str::parse_u64(v).ok_or("invalid --speed")?;
                }
                b"--cpu-util" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --cpu-util")?;
                    let n = str::parse_u64(v).ok_or("invalid --cpu-util")?;
                    if n > 100 {
                        return Err("--cpu-util must be 0..100");
                    }
                    a.load_cpu = Some(n as u32);
                }
                b"--mem-util" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --mem-util")?;
                    let n = str::parse_u64(v).ok_or("invalid --mem-util")?;
                    if n > 95 {
                        return Err("--mem-util must be 0..95");
                    }
                    a.load_mem = Some(n as u32);
                }
                b"--disk-util" => {
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --disk-util")?;
                    a.load_disk = Some(str::parse_u64(v).ok_or("invalid --disk-util")?);
                }
                b"--flame" => {
                    return Err("--flame is not supported; use `psgen load --cpu-util`")
                }
                b"-q" | b"--quiet" => a.quiet = true,
                _ => return Err("unknown option"),
            }
        } else if !saw_sub {
            if !set_sub(&mut a, arg) {
                return Err("unknown subcommand");
            }
            saw_sub = true;
        } else {
            return Err("unexpected argument");
        }
        i += 1;
    }
    if a.force
        && a.sub != Sub::Stop
        && a.sub != Sub::Help
        && a.sub != Sub::Version
        && !a.want_help
        && !a.want_version
    {
        return Err("--force only applies to stop");
    }
    Ok(a)
}

fn elevate(argv: &[Vec<u8>], args: &Args) -> Option<i32> {
    if !args.elevate || args.dry_run || sys::geteuid() == 0 {
        return None;
    }
    let self_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return None,
    };
    let probe = std::process::Command::new("sudo")
        .arg("-n")
        .arg("true")
        .status();
    if !probe.map(|s| s.success()).unwrap_or(false) {
        sys::err(b"psgen: sudo -n is not available; continuing unprivileged\n");
        return None;
    }
    let mut cmd = std::process::Command::new("sudo");
    cmd.arg("-n").arg(&self_exe);
    for a in argv.iter().skip(1) {
        if a == b"--elevate" {
            continue;
        }
        cmd.arg(OsStr::from_bytes(a));
    }
    match cmd.status() {
        Ok(s) => Some(s.code().unwrap_or(1)),
        Err(e) => {
            let mut out = Buf::new();
            out.push_str("psgen: cannot run sudo: ");
            out.push_str(&e.to_string());
            out.push(b'\n');
            sys::err(out.as_bytes());
            Some(1)
        }
    }
}

fn print_notes(prep: &inject::Prep) {
    for w in &prep.warnings {
        let mut out = Buf::new();
        out.push_str("psgen: ");
        out.push_str(w);
        out.push(b'\n');
        sys::err(out.as_bytes());
    }
    let c = &prep.caps;
    let reduced = !c.pty || (c.root && !c.user_switch);
    if reduced {
        let mut out = Buf::new();
        out.push_str("psgen: reduced capability:");
        if !c.pty {
            out.push_str(" pty=no");
        }
        if c.root && !c.user_switch {
            out.push_str(" user_switch=no");
        }
        out.push_str(" (run `psgen doctor` for the errno)\n");
        sys::err(out.as_bytes());
    }
    if !c.memfd {
        sys::err(b"psgen: memfd_create denied; using an unlinked temp file for the arena and config\n");
    }
    if !prep.created.is_empty() {
        let mut out = Buf::new();
        out.push_str("psgen: created users:");
        for u in &prep.created {
            out.push(b' ');
            out.push_bytes(u);
        }
        out.push_str(" (remove with userdel when done)\n");
        sys::err(out.as_bytes());
    }
}

fn print_failures(result: &inject::SpawnResult) {
    for (id, status) in &result.failed_ids {
        let mut m = Buf::new();
        m.push_str("psgen: row ");
        m.push_u64(*id as u64);
        m.push_str(" failed");
        if *status < 0 {
            m.push_str(": ");
            m.push_str(&std::io::Error::from_raw_os_error(-*status).to_string());
        }
        m.push(b'\n');
        sys::err(m.as_bytes());
    }
    for (pid, id, wv, gv, wr, gr) in &result.mismatches {
        let mut m = Buf::new();
        m.push_str("psgen: pid ");
        m.push_u64(*pid as u64);
        m.push_str(" row ");
        m.push_u64(*id as u64);
        m.push_str(" VSZ ");
        m.push_u64(*gv);
        m.push(b'/');
        m.push_u64(*wv);
        m.push_str(" RSS ");
        m.push_u64(*gr);
        m.push(b'/');
        m.push_u64(*wr);
        m.push(b'\n');
        sys::err(m.as_bytes());
    }
}

fn print_summary(prep: &inject::Prep, result: &inject::SpawnResult, args: &Args) {
    print_failures(result);
    if args.quiet {
        return;
    }
    let mut out = Buf::new();
    out.push_str("spawned ");
    out.push_u64(result.pids.len() as u64);
    out.push_str(" processes");
    if let Some(path) = &args.pidfile {
        if result.pidfile_ok {
            out.push_str(", pids in ");
            out.push_bytes(path);
        } else {
            out.push_str("; the pidfile was not written");
        }
    } else {
        out.push_str(" (pass --pidfile FILE to be able to stop them)");
    }
    if result.failed > 0 {
        out.push_str(", ");
        out.push_u64(result.failed as u64);
        out.push_str(" failed");
    }
    if result.missing > 0 {
        out.push_str(", ");
        out.push_u64(result.missing as u64);
        out.push_str(" did not report");
    }
    if result.warned > 0 {
        out.push_str(", ");
        out.push_u64(result.warned as u64);
        out.push_str(" reported a setup deviation");
    }
    if !result.mismatches.is_empty() {
        out.push_str(", ");
        out.push_u64(result.mismatches.len() as u64);
        out.push_str(" outside 128 kB");
    }
    out.push(b'\n');
    out.push_str("exe tier ");
    out.push_str(result.tier.name());
    if result.tty_wanted > 0 {
        out.push_str(", tty ");
        out.push_u64(result.tty_real as u64);
        out.push_str(" real, ");
        out.push_u64(result.tty_degraded as u64);
        out.push_str(" degraded");
    }
    out.push(b'\n');
    if result.dev_exe + result.dev_user + result.dev_disk + result.dev_mem > 0 {
        out.push_str("deviations: user ");
        out.push_u64(result.dev_user as u64);
        out.push_str(", exe ");
        out.push_u64(result.dev_exe as u64);
        out.push_str(", mem ");
        out.push_u64(result.dev_mem as u64);
        out.push_str(", disk ");
        out.push_u64(result.dev_disk as u64);
        out.push(b'\n');
    }
    if args.mem && prep.phys_estimate_kb > 0 {
        out.push_str("reported RSS is shared; estimated physical cost ");
        out.push_u64(prep.phys_estimate_kb / 1024);
        out.push_str(" MiB");
        if prep.phys_scale < 1.0 {
            out.push_str(", scaled to fit the physical budget");
            if prep.phys_budget_kb > 0 {
                out.push_str(" of ");
                out.push_u64(prep.phys_budget_kb / 1024);
                out.push_str(" MiB");
            }
        }
        out.push(b'\n');
    }
    if args.table {
        sys::err(out.as_bytes());
    } else {
        sys::out(out.as_bytes());
    }
}

fn pidfile_parent(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(0) => b"/",
        Some(i) => &path[..i],
        None => b".",
    }
}

/// Name the object that makes `path` unusable as a pidfile.
fn pidfile_error(path: &[u8]) -> Buf {
    let mut out = Buf::new();
    out.push_str("psgen: cannot write the pidfile ");
    out.push_bytes(path);
    if path.is_empty() {
        out.push_str(": the path is empty");
    } else if sys::is_dir(path) {
        out.push_str(": the path is a directory");
    } else if !probe::pidfile_target_ok(path) {
        out.push_str(": the path is not an empty file or a psgen pidfile");
    } else {
        let parent = pidfile_parent(path);
        out.push_str(": the parent ");
        out.push_bytes(parent);
        if !std::path::Path::new(std::ffi::OsStr::from_bytes(parent)).exists() {
            out.push_str(" does not exist");
        } else if !sys::is_dir(parent) {
            out.push_str(" is not a directory");
        } else {
            out.push_str(" is not writable");
        }
    }
    out
}

pub fn run() -> i32 {
    let argv: Vec<Vec<u8>> = std::env::args_os()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    if argv.is_empty() {
        sys::err(b"psgen: cannot read argv\n");
        return 2;
    }
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(msg) => {
            let mut out = Buf::new();
            out.push_str("psgen: ");
            out.push_str(msg);
            out.push(b'\n');
            out.push_str(usage());
            sys::err(out.as_bytes());
            return 2;
        }
    };

    if args.want_help {
        sys::out(usage().as_bytes());
        return 0;
    }
    if args.want_version {
        sys::out(b"psgen 0.0.1\n");
        return 0;
    }

    if args.elevate && (args.sub == Sub::Inject || args.sub == Sub::Stop) {
        if let Some(code) = elevate(&argv, &args) {
            return code;
        }
    }

    match args.sub {
        Sub::Help => {
            sys::out(usage().as_bytes());
            0
        }
        Sub::Version => {
            sys::out(b"psgen 0.0.1\n");
            0
        }
        Sub::Doctor => doctor::run(args.json, args.pidfile.as_deref()),
        Sub::Log => activity::run_log(&args),
        Sub::Load => activity::run_load(&args),
        Sub::Corpus => {
            let mut out = Buf::new();
            for t in corpus::CORPUS.iter() {
                out.push_bytes(corpus::family_name(t.fam).as_bytes());
                out.push(b'\t');
                out.push_bytes(t.user.as_bytes());
                out.push(b'\t');
                out.push_u64(t.vsz as u64);
                out.push(b'\t');
                out.push_u64(t.rss as u64);
                out.push(b'\t');
                out.push_bytes(t.cmd.as_bytes());
                out.push(b'\n');
            }
            sys::out(out.as_bytes());
            0
        }
        Sub::Check => {
            let mut rng = Rng::new(args.seed.unwrap_or(1));
            let opts = Opts {
                count: 0,
                profile: args.profile.clone(),
                family: args.family,
                self_user: b"deploy".to_vec(),
                uniq: args.uniq,
            };
            check::run(&mut rng, &opts, args.binaries)
        }
        Sub::Unit => {
            let count = if args.count == 0 { 24 } else { args.count };
            let pidfile = args
                .pidfile
                .clone()
                .unwrap_or_else(|| b"/run/psgen.pid".to_vec());
            let out = unit::render(count, args.seed.unwrap_or(7), &pidfile, args.create_users);
            sys::out(out.as_bytes());
            0
        }
        Sub::Stop => {
            let path = match &args.pidfile {
                Some(p) => p,
                None => {
                    sys::err(b"psgen: stop needs --pidfile\n");
                    return 2;
                }
            };
            inject::stop(path, args.force)
        }
        Sub::List => {
            if args.count > 2000 {
                sys::err(b"psgen: list count capped at 2000\n");
            }
            let mut rng = match args.seed {
                Some(s) => Rng::new(s),
                None => Rng::from_entropy(),
            };
            let opts = Opts {
                count: args.count,
                profile: args.profile.clone(),
                family: args.family,
                self_user: util::current_user().name,
                uniq: args.uniq,
            };
            let mut cmds = gen::gen_list(&mut rng, &opts);
            if args.sort {
                cmds.sort_unstable();
            }
            let mut out = Buf::with_capacity(cmds.len() * 96);
            for c in &cmds {
                out.push_bytes(c);
                out.push(b'\n');
            }
            sys::out(out.as_bytes());
            0
        }
        Sub::Table => {
            if args.count > 5000 {
                sys::err(b"psgen: table count capped at 5000\n");
            }
            if args.live {
                let mut rows = live::read_all();
                let limit = args.count.min(5000);
                if limit > 0 && rows.len() > limit {
                    rows.truncate(limit);
                }
                let out = table::render(
                    &rows,
                    util::mem_total_kb(),
                    args.offset_min,
                    args.local,
                    sys::page_kb(),
                );
                sys::out(out.as_bytes());
                return 0;
            }
            let mut rng = match args.seed {
                Some(s) => Rng::new(s),
                None => Rng::from_entropy(),
            };
            let opts = Opts {
                count: if args.count == 0 {
                    30
                } else {
                    args.count.min(5000)
                },
                profile: args.profile.clone(),
                family: args.family,
                self_user: util::current_user().name,
                uniq: args.uniq,
            };
            let rows = gen::gen_table(&mut rng, &opts);
            let out = table::render(
                &rows,
                util::mem_total_kb(),
                args.offset_min,
                args.local,
                sys::page_kb(),
            );
            sys::out(out.as_bytes());
            0
        }
        Sub::Inject => {
            if args.wait && args.duration == 0 && !args.dry_run {
                sys::err(b"psgen: --wait needs --duration\n");
                return 2;
            }
            if args.count > 500 {
                sys::err(b"psgen: inject count capped at 500\n");
            }
            // Preflight the pidfile before spawning. Writing it after the
            // fact leaves live stubs with no record of how to stop them.
            if !args.dry_run {
                if let Some(p) = &args.pidfile {
                    if !probe::pidfile_creatable(p) {
                        let mut out = pidfile_error(p);
                        // Suggest a writable path without writing to the
                        // candidate path.
                        for cand in [
                            std::env::temp_dir().join("psgen-pids.txt"),
                            std::path::PathBuf::from("psgen-pids.txt"),
                        ] {
                            use std::os::unix::ffi::OsStrExt;
                            let b = cand.as_os_str().as_bytes();
                            if probe::pidfile_creatable(b) {
                                out.push_str("; use ");
                                out.push_bytes(b);
                                out.push_str(" instead");
                                break;
                            }
                        }
                        out.push(b'\n');
                        sys::err(out.as_bytes());
                        return 2;
                    }
                }
            }
            let me = users::current();
            let mut rng = match args.seed {
                Some(s) => Rng::new(s),
                None => Rng::from_entropy(),
            };
            let opts = Opts {
                count: if args.count == 0 {
                    12
                } else {
                    args.count.min(500)
                },
                profile: args.profile.clone(),
                family: args.family,
                self_user: me.name,
                uniq: args.uniq,
            };
            let mut rows = gen::gen_inject(&mut rng, &opts);

            // A disk target that would fill the filesystem is refused here,
            // before anything is spawned.
            if let Some(mb) = args.disk_mb {
                if mb > 0 && !args.dry_run {
                    if let Some(limit) = sys::rlimit_fsize() {
                        if mb.saturating_mul(1024 * 1024) > limit {
                            let mut out = Buf::new();
                            out.push_str("psgen: --disk ");
                            out.push_u64(mb);
                            out.push_str(" MiB exceeds RLIMIT_FSIZE (");
                            out.push_u64(limit / 1024 / 1024);
                            out.push_str(" MiB)\n");
                            sys::err(out.as_bytes());
                            return 2;
                        }
                    }
                    let total_mb = mb.saturating_mul(rows.len() as u64);
                    let dir = std::env::temp_dir();
                    let dirb = dir.as_os_str().as_bytes().to_vec();
                    if let Some((free, _)) = probe::space(&dirb) {
                        if total_mb.saturating_mul(1024 * 1024) > free.saturating_sub(free / 10)
                        {
                            let mut out = Buf::new();
                            out.push_str("psgen: --disk ");
                            out.push_u64(mb);
                            out.push_str(" MiB x ");
                            out.push_u64(rows.len() as u64);
                            out.push_str(" rows needs ");
                            out.push_u64(total_mb);
                            out.push_str(" MiB, more than the free space in ");
                            out.push_bytes(&dirb);
                            out.push_str(" (");
                            out.push_u64(free / 1024 / 1024);
                            out.push_str(" MiB)\n");
                            sys::err(out.as_bytes());
                            return 2;
                        }
                    }
                }
            }

            let prep = inject::prepare(&mut rows, &args, args.create_users && !args.dry_run);

            if args.dry_run {
                let mut out = Buf::new();
                for p in &rows {
                    out.push_bytes(&p.user);
                    out.push(b'\t');
                    out.push_bytes(&p.cmd);
                    out.push(b'\n');
                }
                sys::out(out.as_bytes());
                print_notes(&prep);
                return 0;
            }

            print_notes(&prep);
            let result = match inject::spawn(&rows, &args, &prep) {
                Ok(r) => r,
                Err(e) => {
                    let mut out = Buf::new();
                    out.push_str("psgen: ");
                    out.push_str(&e);
                    out.push(b'\n');
                    sys::err(out.as_bytes());
                    return 1;
                }
            };
            print_summary(&prep, &result, &args);

            if result.pids.is_empty() {
                sys::err(b"psgen: no processes were spawned\n");
                return 1;
            }
            let pidfile_failed = !result.pidfile_ok;
            if pidfile_failed {
                // The list goes to stderr even under --quiet: without it the
                // caller cannot stop the stubs, which stay alive. The temp
                // dirs are printed too, because the pidfile that would have
                // listed them was not written.
                let mut out = Buf::new();
                out.push_str("psgen: the pidfile was not written; spawned PIDs:");
                for pid in &result.pids {
                    out.push(b' ');
                    out.push_u64(*pid as u64);
                }
                out.push(b'\n');
                for t in &result.temps {
                    out.push_str("psgen: temp dir ");
                    out.push_bytes(t.as_os_str().as_bytes());
                    out.push(b'\n');
                }
                sys::err(out.as_bytes());
            }
            let mut code = 0;
            if result.failed > 0 || result.missing > 0 || !result.mismatches.is_empty() {
                code = 1;
            }

            if args.table {
                let live_rows = live::read_pids(&result.pids);
                let out = table::render(
                    &live_rows,
                    util::mem_total_kb(),
                    args.offset_min,
                    args.local,
                    sys::page_kb(),
                );
                sys::out(out.as_bytes());
            }

            if args.wait && args.duration > 0 {
                sys::nanosleep(args.duration as u64, 0);
                let same = |pid: i32, start: u64, comm: &[u8]| {
                    live::read_starttime(pid) == Some(start)
                        && (comm.is_empty() || live::read_comm(pid).as_deref() == Some(comm))
                };
                // Kill the root's process group first. The starttime check
                // proves the root is alive, so its PGID cannot be a reused
                // PID. This also reaches rows that stayed in the root's
                // process group and therefore have no entry in `ident`.
                for (pid, start) in &result.roots {
                    if live::read_starttime(*pid) == Some(*start) {
                        sys::kill(-*pid, sys::SIGKILL);
                    }
                }
                for (pid, start, comm) in &result.ident {
                    let pfd = sys::pidfd_open(*pid);
                    if pfd >= 0 {
                        if same(*pid, *start, comm)
                            && !sys::pidfd_send_signal(pfd, sys::SIGKILL)
                            && same(*pid, *start, comm)
                        {
                            sys::kill(*pid, sys::SIGKILL);
                        }
                        sys::close(pfd);
                    } else if same(*pid, *start, comm) {
                        sys::kill(*pid, sys::SIGKILL);
                    }
                }
                // The injector is a child subreaper, so orphaned stub
                // children reparent here and can be reaped.
                for _ in 0..200 {
                    loop {
                        let mut status = 0;
                        let r = sys::waitpid_nohang(-1, &mut status);
                        if r <= 0 {
                            break;
                        }
                    }
                    let alive = result.pids.iter().any(|pid| {
                        std::path::Path::new(&format!("/proc/{}", pid)).exists()
                    });
                    if !alive {
                        break;
                    }
                    sys::nanosleep(0, 10_000_000);
                }
                for t in &result.temps {
                    let _ = std::fs::remove_dir_all(t);
                }
            }
            if pidfile_failed {
                1
            } else {
                code
            }
        }
    }
}
