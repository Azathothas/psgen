//! Argument parsing and command dispatch.

use crate::activity;
use crate::check;
use crate::corpus;
use crate::doctor;
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
    /// `inject --dry-run --plan` / `stop --plan`: print the resolved plan.
    pub plan: bool,
    /// `check --require-binaries`: a missing executable is a failure.
    pub require_binaries: bool,
    /// Every option name seen on the command line, in canonical long form.
    /// Used to reject an option that the chosen subcommand does not consume.
    pub seen: Vec<&'static str>,
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
            plan: false,
            require_binaries: false,
            seen: Vec::new(),
        }
    }

    /// Options that change what `unit` prints, in a stable order. Only the
    /// non-default values are forwarded, so a plain `psgen unit` stays short.
    pub fn forwarded(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut push = |name: &str, value: Option<&[u8]>| {
            out.push(name.as_bytes().to_vec());
            if let Some(v) = value {
                out.push(v.to_vec());
            }
        };
        if self.profile != b"server" {
            push("-p", Some(&self.profile));
        }
        if let Some(f) = self.family {
            push("-f", Some(crate::corpus::family_name(f).as_bytes()));
        }
        if self.duration > 0 {
            push("-d", Some(self.duration.to_string().as_bytes()));
        }
        if !self.mem {
            push("--no-mem", None);
        }
        if self.mem_cap_mb > 0 {
            push("--mem-cap", Some(self.mem_cap_mb.to_string().as_bytes()));
        }
        if let Some(kb) = self.mem_target_kb {
            push("--mem-target", Some(kb.to_string().as_bytes()));
        }
        if let Some(mb) = self.phys_cap {
            push("--phys-cap", Some(mb.to_string().as_bytes()));
        }
        if let Some(mb) = self.disk_mb {
            push("--disk", Some(mb.to_string().as_bytes()));
        }
        if self.no_exe {
            push("--no-exe", None);
        }
        if let Some(d) = &self.shadow_dir {
            push("--shadow-dir", Some(d));
        }
        if self.no_root {
            push("--no-root", None);
        }
        if !self.tty {
            push("--no-tty", None);
        }
        if !self.threads {
            push("--no-threads", None);
        }
        if !self.user {
            push("--no-user", None);
        }
        if self.busy {
            push("--busy", None);
        }
        if let Some(pct) = self.cpu_pct {
            push("--cpu", Some(pct.to_string().as_bytes()));
        }
        if self.verify {
            push("--verify", None);
        }
        out
    }
}

/// Everything after the `psgen <version> - ` prefix on the first line, then
/// the rest of the help text. The version comes from `Cargo.toml`.
const USAGE_BODY: &str = "realistic Linux process lists, on stdout or in the real process table

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
  -n, --count N       rows or commands (list: all templates, table: 30,
                      table --live: all, inject: 12). A count is met by
                      repeating rows a real host runs more than once; a
                      request that cannot be met at all prints a warning.
  -s, --seed N        fix the selection and jitter; START and TIME still
                      follow the wall clock
  -p, --profile NAME  server (default), dev, desktop; honoured by list, table
                      and inject
  -f, --family NAME   sys, web, db, ctr, dev, mon, sto, mail, desk, net
      --utc-offset M  minutes east of UTC for the START column, -1440..1440
                      (default 0)
      --local         use the system timezone for the START column; overrides
                      --utc-offset
      --sort / --no-sort   list only
      --uniq / --no-uniq   list only
  -h, --help
  -V, --version

An option that a subcommand does not use is a usage error (exit 2), not a
silent no-op.

INJECT
  -d, --duration S      lifetime in seconds (0 = until stopped; rows marked
                        short use the 120 s default)
      --pidfile FILE    write the spawned PIDs here; an existing file must be
                        empty or a psgen pidfile. A header-only pidfile is
                        written before the first stub is forked, so a later
                        failure never leaves stubs with no record.
      --mem / --no-mem  pad VSZ and RSS (default on)
      --mem-cap MiB     cap the planned RSS sum; each stub keeps a 4 MiB
                        floor, so a cap at or below 4 MiB per stub is raised
                        to it and warned about (0 = no cap, default)
      --mem-target KiB  per-stub RSS target in KiB, clamped to the template's
                        VSZ minus 4 MiB
      --phys-cap MiB    physical budget for the arena, page tables and base
                        RSS (0 = unlimited, omitted = the smaller of a quarter
                        of RAM and half the cgroup limit)
      --disk MiB        write this many MiB of temp data per stub
      --exe / --no-exe  bind the template executable path (default on)
      --allow-proc-exe  alias of --no-exe: exec /proc/self/exe, no spoof
      --shadow-dir DIR  directory for the shadow copy when the bind is
                        unavailable or with --no-root; the copy goes in a
                        per-run subdirectory. With --no-root it forces the
                        shadow tier; ignored with --no-exe and when the bind
                        tier is in use
      --no-root         portable mode: no user switch, no mount namespace,
                        no bind tier; the stub uses /proc/self/exe or --shadow-dir
      --tty / --no-tty  give tty processes a real pty (default on);
                        --no-tty also detaches every row from the caller's
                        controlling terminal
      --threads / --no-threads  give threaded processes a second thread (default on)
      --user / --no-user  switch to the template user when running as root
      --create-users    create missing template users with useradd; needs root
                        and is ignored with --no-root or --no-user
      --busy            burn CPU for every row whose corpus CPU is non-zero
      --cpu PCT         target cpu percent for every row; forces the busy path
                        when non-zero, 0 clears it (0..100)
      --dry-run         print user and command for what would be spawned; the
                        exact two-column format is kept for existing callers
      --plan            with --dry-run, print the resolved plan instead: exe
                        tier, per-row user/VSZ/RSS/CPU/tty/threads/exe, parent
                        links and the physical cost estimate
      --json            with --dry-run, print the plan as one JSON object
      --table           after spawning, print the real ps aux table for the stubs
      --verify          compare each stub's real VSZ/RSS with the planned
                        value within 128 kB; has no effect with --no-mem
      --wait            block for a non-zero --duration, then stop the stubs
      --elevate         re-exec through sudo -n when not already root
  -q, --quiet           suppress the inject summary

CORPUS AND CHECK
      --binaries        report which template executables exist on this host
      --require-binaries  like --binaries, but exit 1 when any is missing
  The corpus dump prints the sentinel @self for a template that runs as the
  invoking user; list, table and inject replace it with the user's name (or
  the decimal uid when the uid has no passwd entry).

UNIT
  The unit forwards the inject options it was given (-p, -f, -d, --no-mem,
  --mem-cap, --mem-target, --phys-cap, --disk, --no-root, --no-user,
  --no-tty, --no-threads, --no-exe, --shadow-dir, --cpu, --busy, --verify),
  caps -n at the inject cap of 500, and uses a RuntimeDirectory the manager
  removes on stop so the service can be restarted. --count, --seed and
  --pidfile select the injected rows and the pidfile path.

DOCTOR
      --json            machine readable output; checks are objects with a
                        name field, and core_ok says whether injection can work
                        at all (the checks named proc_exe, fork, prctl_name)
      --pidfile FILE    also report whether this pidfile can be written

LOG
  -m, --module NAME   weblog (default), bootlog, cargo, cc, download,
                      docker_build, docker_rmi, terraform, ansible,
                      kernel_compile, mkinitcpio, uv, composer, julia, list.
                      Each module accepts aliases; `-m list` prints them.
      --lines N       events to write (default 20, capped at 200000); a weblog
                      burst can produce multiple rows per event
      --delay MS      pause between events
      --speed N       divide the delay by N (default 1, must be at least 1)
      --log-fmt NAME  apache (weblog family only), json, syslog

LOAD
      --cpu-util PCT  burn this percent of one core
      --mem-util PCT  touch and hold this percent of MemTotal, or of the cgroup
                      limit when lower (0..95); refused above MemAvailable
                      unless --force is given
      --disk-util MiB write and hold MiB of temp data
  -d, --duration S    stop after S seconds (0 = until killed)
      --force         allow --mem-util above what is available

STOP
      --force           ignore the boot id; a three-field line still checks
                        starttime and comm, a two-field line still checks
                        starttime, and a one-field line still requires an exe
                        match (proc-self rows, or a shadow copy in a staging
                        directory owned by the caller)
      --plan            print what would be signalled and stop nothing
      --elevate         re-exec through sudo -n when not already root
  -q, --quiet           only print the summary line
  A pidfile from a live run is left in place, so the same path can be used
  again; stop the run twice and the second call is a no-op.
";

fn usage() -> Vec<u8> {
    let mut out = Buf::with_capacity(USAGE_BODY.len() + 64);
    out.push_bytes(crate::version::BARE);
    out.push_str(" - ");
    out.push_str(USAGE_BODY);
    out.v
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
        b"-h"
            | b"--help"
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
            | b"--plan"
            | b"--wait"
            | b"--binaries"
            | b"--require-binaries"
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

/// A usage error. Static for the common cases, owned when the message has to
/// name the option and the subcommand.
pub enum ParseError {
    Static(&'static str),
    Owned(String),
}

impl From<&'static str> for ParseError {
    fn from(s: &'static str) -> ParseError {
        ParseError::Static(s)
    }
}

impl From<String> for ParseError {
    fn from(s: String) -> ParseError {
        ParseError::Owned(s)
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Static(s) => f.write_str(s),
            ParseError::Owned(s) => f.write_str(s),
        }
    }
}

fn sub_name(sub: Sub) -> &'static str {
    match sub {
        Sub::List => "list",
        Sub::Table => "table",
        Sub::Inject => "inject",
        Sub::Stop => "stop",
        Sub::Corpus => "corpus",
        Sub::Check => "check",
        Sub::Unit => "unit",
        Sub::Doctor => "doctor",
        Sub::Log => "log",
        Sub::Load => "load",
        Sub::Help => "help",
        Sub::Version => "version",
    }
}

/// Whether `sub` consumes the option `name` (canonical long form).
///
/// An option that is parsed but never read used to be a silent no-op; the
/// worst case was `unit -p desktop`, which printed a unit that injected server
/// rows. Rejecting it is the same shape as `--force` and catches typos such as
/// `--famly`.
fn applies(sub: Sub, name: &str) -> bool {
    use Sub::*;
    let common = matches!(name, "-h" | "--help" | "-V" | "--version");
    if common {
        return true;
    }
    let inject_flags = matches!(
        name,
        "-n" | "--count"
            | "-s"
            | "--seed"
            | "-p"
            | "--profile"
            | "-f"
            | "--family"
            | "--utc-offset"
            | "--local"
            | "-d"
            | "--duration"
            | "--pidfile"
            | "--mem"
            | "--no-mem"
            | "--mem-cap"
            | "--mem-target"
            | "--phys-cap"
            | "--disk"
            | "--exe"
            | "--no-exe"
            | "--allow-proc-exe"
            | "--shadow-dir"
            | "--no-root"
            | "--tty"
            | "--no-tty"
            | "--threads"
            | "--no-threads"
            | "--user"
            | "--no-user"
            | "--create-users"
            | "--busy"
            | "--cpu"
            | "--dry-run"
            | "--plan"
            | "--json"
            | "--table"
            | "--verify"
            | "--wait"
            | "--elevate"
            | "-q"
            | "--quiet"
    );
    match sub {
        List => matches!(
            name,
            "-n" | "--count"
                | "-s"
                | "--seed"
                | "-p"
                | "--profile"
                | "-f"
                | "--family"
                | "--sort"
                | "--no-sort"
                | "--uniq"
                | "--no-uniq"
        ),
        Table => matches!(
            name,
            "-n" | "--count"
                | "-s"
                | "--seed"
                | "-p"
                | "--profile"
                | "-f"
                | "--family"
                | "--utc-offset"
                | "--local"
                | "--live"
        ),
        Inject => inject_flags,
        Stop => matches!(
            name,
            "--pidfile" | "--force" | "--elevate" | "--plan" | "-q" | "--quiet"
        ),
        Corpus => false,
        // `check` validates the corpus itself: no profile, and a family only
        // narrows which templates it looks at. `--seed` is accepted because
        // check expands commands with the generator, and the seed changes
        // which expansion is checked.
        Check => matches!(
            name,
            "-f" | "--family" | "-s" | "--seed" | "--binaries" | "--require-binaries"
        ),
        Unit => matches!(
            name,
            "-n" | "--count"
                | "-s"
                | "--seed"
                | "-p"
                | "--profile"
                | "-f"
                | "--family"
                | "--pidfile"
                | "-d"
                | "--duration"
                | "--mem"
                | "--no-mem"
                | "--mem-cap"
                | "--mem-target"
                | "--phys-cap"
                | "--disk"
                | "--exe"
                | "--no-exe"
                | "--allow-proc-exe"
                | "--shadow-dir"
                | "--no-root"
                | "--tty"
                | "--no-tty"
                | "--threads"
                | "--no-threads"
                | "--user"
                | "--no-user"
                | "--create-users"
                | "--busy"
                | "--cpu"
                | "--verify"
                | "-q"
                | "--quiet"
        ),
        Doctor => matches!(name, "--json" | "--pidfile"),
        Log => matches!(
            name,
            "-m" | "--module" | "--lines" | "--delay" | "--speed" | "--log-fmt" | "-s" | "--seed"
        ),
        Load => matches!(
            name,
            "--cpu-util"
                | "--mem-util"
                | "--disk-util"
                | "-d"
                | "--duration"
                | "--force"
                | "-q"
                | "--quiet"
        ),
        Help | Version => false,
    }
}

pub fn parse(args: &[Vec<u8>]) -> Result<Args, ParseError> {
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
                return Err("this option does not take a value".into());
            }
            match name {
                b"-h" | b"--help" => {
                    a.want_help = true;
                    a.seen.push("--help");
                }
                b"-V" | b"--version" => {
                    a.want_version = true;
                    a.seen.push("--version");
                }
                b"-n" | b"--count" => {
                    a.seen.push("--count");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --count")?;
                    a.count =
                        usize::try_from(str::parse_u64(v).ok_or("invalid --count")?)
                            .map_err(|_| "invalid --count")?;
                }
                b"-s" | b"--seed" => {
                    a.seen.push("--seed");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --seed")?;
                    a.seed = Some(str::parse_u64(v).ok_or("invalid --seed")?);
                }
                b"-p" | b"--profile" => {
                    a.seen.push("--profile");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --profile")?;
                    if v != b"server" && v != b"dev" && v != b"desktop" {
                        return Err("unknown profile".into());
                    }
                    a.profile = v.to_vec();
                }
                b"-f" | b"--family" => {
                    a.seen.push("--family");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --family")?;
                    a.family = Some(corpus::family_id(v).ok_or("unknown family")?);
                }
                b"--utc-offset" => {
                    a.seen.push("--utc-offset");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --utc-offset")?;
                    let m = str::parse_i64(v).ok_or("invalid --utc-offset")?;
                    // The START column is a clock field. An offset beyond a day
                    // can only produce a year with more digits than the column
                    // has room for, which shifts every field after it.
                    if !(-1440..=1440).contains(&m) {
                        return Err("--utc-offset must be -1440..1440".into());
                    }
                    a.offset_min = m;
                }
                b"--local" => {
                    a.seen.push("--local");
                    a.local = true;
                }
                b"--pidfile" => {
                    a.seen.push("--pidfile");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --pidfile")?;
                    a.pidfile = Some(abs_path(v));
                }
                b"-d" | b"--duration" => {
                    a.seen.push("--duration");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --duration")?;
                    let n = str::parse_u64(v).ok_or("invalid --duration")?;
                    a.duration = u32::try_from(n).map_err(|_| "invalid --duration")?;
                }
                b"--mem-cap" => {
                    a.seen.push("--mem-cap");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --mem-cap")?;
                    a.mem_cap_mb = str::parse_u64(v).ok_or("invalid --mem-cap")?;
                }
                b"--phys-cap" => {
                    a.seen.push("--phys-cap");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --phys-cap")?;
                    a.phys_cap = Some(str::parse_u64(v).ok_or("invalid --phys-cap")?);
                }
                b"--sort" => {
                    a.seen.push("--sort");
                    a.sort = true;
                }
                b"--no-sort" => {
                    a.seen.push("--no-sort");
                    a.sort = false;
                }
                b"--uniq" => {
                    a.seen.push("--uniq");
                    a.uniq = true;
                }
                b"--no-uniq" => {
                    a.seen.push("--no-uniq");
                    a.uniq = false;
                }
                b"--mem" => {
                    a.seen.push("--mem");
                    a.mem = true;
                }
                b"--no-mem" => {
                    a.seen.push("--no-mem");
                    a.mem = false;
                }
                b"--tty" => {
                    a.seen.push("--tty");
                    a.tty = true;
                }
                b"--no-tty" => {
                    a.seen.push("--no-tty");
                    a.tty = false;
                }
                b"--threads" => {
                    a.seen.push("--threads");
                    a.threads = true;
                }
                b"--no-threads" => {
                    a.seen.push("--no-threads");
                    a.threads = false;
                }
                b"--user" => {
                    a.seen.push("--user");
                    a.user = true;
                }
                b"--no-user" => {
                    a.seen.push("--no-user");
                    a.user = false;
                }
                b"--create-users" => {
                    a.seen.push("--create-users");
                    a.create_users = true;
                }
                b"--busy" => {
                    a.seen.push("--busy");
                    a.busy = true;
                }
                b"--dry-run" => {
                    a.seen.push("--dry-run");
                    a.dry_run = true;
                }
                b"--plan" => {
                    a.seen.push("--plan");
                    a.plan = true;
                }
                b"--wait" => {
                    a.seen.push("--wait");
                    a.wait = true;
                }
                b"--binaries" => {
                    a.seen.push("--binaries");
                    a.binaries = true;
                }
                b"--require-binaries" => {
                    a.seen.push("--require-binaries");
                    a.binaries = true;
                    a.require_binaries = true;
                }
                b"--elevate" => {
                    a.seen.push("--elevate");
                    a.elevate = true;
                }
                b"--table" => {
                    a.seen.push("--table");
                    a.table = true;
                }
                b"--live" => {
                    a.seen.push("--live");
                    a.live = true;
                }
                b"--force" => {
                    a.seen.push("--force");
                    a.force = true;
                }
                b"--verify" => {
                    a.seen.push("--verify");
                    a.verify = true;
                }
                b"--exe" => {
                    a.seen.push("--exe");
                    a.no_exe = false;
                }
                b"--no-exe" | b"--allow-proc-exe" => {
                    a.seen.push("--no-exe");
                    a.no_exe = true;
                }
                b"--shadow-dir" => {
                    a.seen.push("--shadow-dir");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --shadow-dir")?;
                    a.shadow_dir = Some(abs_path(v));
                }
                b"--no-root" => {
                    a.seen.push("--no-root");
                    a.no_root = true;
                }
                b"--cpu" => {
                    a.seen.push("--cpu");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --cpu")?;
                    let n = str::parse_u64(v).ok_or("invalid --cpu")?;
                    if n > 100 {
                        return Err("--cpu must be 0..100".into());
                    }
                    a.cpu_pct = Some(n as u32);
                }
                b"--mem-target" => {
                    a.seen.push("--mem-target");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --mem-target")?;
                    let n = str::parse_u64(v).ok_or("invalid --mem-target")?;
                    a.mem_target_kb =
                        Some(u32::try_from(n).map_err(|_| "invalid --mem-target")?);
                }
                b"--disk" => {
                    a.seen.push("--disk");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --disk")?;
                    let n = str::parse_u64(v).ok_or("invalid --disk")?;
                    if n > u32::MAX as u64 / 1024 {
                        return Err("invalid --disk".into());
                    }
                    a.disk_mb = Some(n);
                }
                b"--json" => {
                    a.seen.push("--json");
                    a.json = true;
                }
                b"--log-fmt" => {
                    a.seen.push("--log-fmt");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --log-fmt")?;
                    a.log_fmt = Some(loggen::Format::parse(v).ok_or("unknown --log-fmt")?);
                }
                b"-m" | b"--module" => {
                    a.seen.push("--module");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --module")?;
                    a.log_module = v.to_vec();
                }
                b"--lines" => {
                    a.seen.push("--lines");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --lines")?;
                    let n = usize::try_from(str::parse_u64(v).ok_or("invalid --lines")?)
                        .map_err(|_| "invalid --lines")?;
                    a.log_lines = n;
                }
                b"--delay" => {
                    a.seen.push("--delay");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --delay")?;
                    a.log_delay_ms = str::parse_u64(v).ok_or("invalid --delay")?;
                }
                b"--speed" => {
                    a.seen.push("--speed");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --speed")?;
                    let n = str::parse_u64(v).ok_or("invalid --speed")?;
                    if n == 0 {
                        return Err("--speed must be at least 1".into());
                    }
                    a.speed = n;
                }
                b"--cpu-util" => {
                    a.seen.push("--cpu-util");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --cpu-util")?;
                    let n = str::parse_u64(v).ok_or("invalid --cpu-util")?;
                    if n > 100 {
                        return Err("--cpu-util must be 0..100".into());
                    }
                    a.load_cpu = Some(n as u32);
                }
                b"--mem-util" => {
                    a.seen.push("--mem-util");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --mem-util")?;
                    let n = str::parse_u64(v).ok_or("invalid --mem-util")?;
                    if n > 95 {
                        return Err("--mem-util must be 0..95".into());
                    }
                    a.load_mem = Some(n as u32);
                }
                b"--disk-util" => {
                    a.seen.push("--disk-util");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --disk-util")?;
                    a.load_disk = Some(str::parse_u64(v).ok_or("invalid --disk-util")?);
                }
                b"--flame" => {
                    return Err(
                        "--flame is not supported (it was an alias in an older draft); use `psgen load --cpu-util`"
                            .into(),
                    )
                }
                b"-q" | b"--quiet" => {
                    a.seen.push("--quiet");
                    a.quiet = true;
                }
                _ => return Err("unknown option".into()),
            }
        } else if !saw_sub {
            if !set_sub(&mut a, arg) {
                return Err("unknown subcommand".into());
            }
            saw_sub = true;
        } else {
            return Err("unexpected argument".into());
        }
        i += 1;
    }
    if a.want_help || a.want_version {
        return Ok(a);
    }
    // An option that the chosen subcommand does not consume is an error, not
    // a silent no-op. The first offending option is named.
    for name in &a.seen {
        if !applies(a.sub, name) {
            return Err(format!("{} does not apply to {}", name, sub_name(a.sub)).into());
        }
    }
    // --dry-run is an inject preview. Accepting it for stop made a command
    // that looked like a preview kill the run. `stop --plan` is the honest
    // preview.
    if a.dry_run && a.sub != Sub::Inject {
        return Err("--dry-run only applies to inject".into());
    }
    if a.plan && a.sub != Sub::Inject && a.sub != Sub::Stop {
        return Err("--plan only applies to inject and stop".into());
    }
    if a.json && a.sub == Sub::Inject && !a.dry_run {
        return Err("--json on inject needs --dry-run".into());
    }
    if a.plan && a.sub == Sub::Inject && !a.dry_run {
        return Err("--plan on inject needs --dry-run".into());
    }
    if a.require_binaries && a.sub != Sub::Check {
        return Err("--require-binaries only applies to check".into());
    }
    // The live table is read from /proc, so the synthetic-table options have
    // nothing to filter or seed.
    if a.live && a.sub == Sub::Table {
        for name in &a.seen {
            if matches!(*name, "--family" | "--profile" | "--seed") {
                return Err(format!("{} does not apply to table --live", name).into());
            }
        }
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

fn print_notes(prep: &inject::Prep, args: &Args) {
    for w in &prep.warnings {
        let mut out = Buf::new();
        out.push_str("psgen: ");
        out.push_str(w);
        out.push(b'\n');
        sys::err(out.as_bytes());
    }
    let c = &prep.caps;
    let reduced = (!c.pty && args.tty) || (c.root && !c.user_switch && args.user);
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
        sys::err(
            b"psgen: memfd_create denied; using an unlinked temp file for the arena and config\n",
        );
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
        if !result.temps.is_empty() {
            out.push_str("; temp dirs:");
            for t in &result.temps {
                out.push(b' ');
                out.push_bytes(t.as_os_str().as_bytes());
            }
            out.push_str(" (remove them with rm -rf when the run ends)");
        }
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

/// The START offset to hand to the table. `--local` selects the system
/// timezone, so a UTC offset would shift a second time; local wins.
fn start_offset(args: &Args) -> i64 {
    if args.local {
        0
    } else {
        args.offset_min
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
        } else if !sys::access(parent, sys::W_OK) {
            out.push_str(" is not writable");
        } else {
            // The parent is writable, so the failure was the target name
            // itself. NAME_MAX is one cause, not the only one: PATH_MAX, a
            // filesystem quota, or an unreadable target can fail here too.
            out.push_str(" is writable but the file could not be created");
            out.push_str(" (the name may exceed NAME_MAX once the temporary");
            out.push_str(" suffix is added, or the filesystem refused it)");
        }
    }
    out
}

/// Say so when a request cannot be met at all.
///
/// A table that repeats a row a real host runs several times is not a
/// shortfall: the count is honoured, and `F_REPEAT` marks the templates that may
/// contribute more than one row. What a caller does need to hear is the case
/// where even that cannot reach the number, which happens for a family whose
/// templates all run once and cannot vary (`list -f mail -n 50`).
fn shortfall(family: Option<u8>, got: usize, want: usize, list: bool) {
    if want == 0 || got >= want {
        return;
    }
    let mut out = Buf::new();
    out.push_str("psgen: ");
    match family {
        Some(f) => {
            out.push_str("family ");
            out.push_str(corpus::family_name(f));
        }
        None => out.push_str("the corpus"),
    }
    out.push_str(" can supply ");
    out.push_u64(got as u64);
    out.push_str(" of the ");
    out.push_u64(want as u64);
    out.push_str(" rows requested");
    if list {
        out.push_str("; a list never repeats a command (use --no-uniq to pad)");
    } else {
        out.push_str(" without putting one command in more than a small share of the rows");
    }
    out.push(b'\n');
    sys::err(out.as_bytes());
}

fn json_escape(out: &mut Buf, s: &[u8]) {
    out.push(b'"');
    for b in s {
        match *b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*b),
            _ => out.push(b'?'),
        }
    }
    out.push(b'"');
}

fn bool_str(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}

/// `--dry-run --plan`: everything `prepare()` decided, per row.
fn print_plan(rows: &[gen::Proc], prep: &inject::Prep, args: &Args) {
    let mut out = Buf::new();
    out.push_str("tier ");
    out.push_str(prep.tier.name());
    if let Some(d) = &prep.shadow_root {
        out.push_str(" from ");
        out.push_bytes(d);
    }
    out.push_str("   mem ");
    out.push_str(if args.mem { "on" } else { "off" });
    out.push_str(", tty ");
    out.push_str(if args.tty { "on" } else { "off" });
    out.push_str(", threads ");
    out.push_str(if args.threads { "on" } else { "off" });
    out.push_str(", busy ");
    out.push_str(if args.busy || args.cpu_pct.unwrap_or(0) > 0 {
        "on"
    } else {
        "off"
    });
    out.push(b'\n');
    let roots = rows.iter().filter(|p| p.parent.is_none()).count();
    let rss: u64 = rows.iter().map(|p| p.rss as u64).sum();
    out.push_str("plan: ");
    out.push_u64(rows.len() as u64);
    out.push_str(if rows.len() == 1 {
        " stub, "
    } else {
        " stubs, "
    });
    out.push_u64(roots as u64);
    out.push_str(if roots == 1 {
        " root; rss "
    } else {
        " roots; rss "
    });
    out.push_u64(rss / 1024);
    out.push_str(" MiB shared");
    if args.mem && prep.phys_estimate_kb > 0 {
        out.push_str(", ~");
        out.push_u64(prep.phys_estimate_kb / 1024);
        out.push_str(" MiB physical");
        if prep.phys_budget_kb > 0 {
            out.push_str(" (budget ");
            out.push_u64(prep.phys_budget_kb / 1024);
            out.push_str(" MiB)");
        }
        if prep.phys_scale < 1.0 {
            out.push_str(", scaled");
        }
    }
    if let Some(mb) = args.disk_mb {
        out.push_str("; disk ");
        out.push_u64(mb.saturating_mul(rows.len() as u64));
        out.push_str(" MiB total");
    }
    out.push(b'\n');
    for (i, p) in rows.iter().enumerate() {
        out.push_str("row ");
        out.push_u64(i as u64);
        out.push_str(if p.parent.is_none() {
            " root "
        } else {
            " child "
        });
        out.push_str("user=");
        out.push_bytes(&p.user);
        out.push_str(" vsz=");
        out.push_u64(p.vsz as u64);
        out.push_str(" rss=");
        out.push_u64(p.rss as u64);
        out.push_str(" cpu=");
        out.push_tenths_plain(p.cpu as u32);
        out.push_str(" tty=");
        out.push_str(if p.flags & corpus::F_TTY != 0 {
            "yes"
        } else {
            "no"
        });
        out.push_str(" threads=");
        out.push_str(if p.flags & corpus::F_THREADS != 0 {
            "yes"
        } else {
            "no"
        });
        out.push_str(" exe=");
        let exe = gen::template_exe(&corpus::CORPUS[p.tmpl]);
        out.push_bytes(&exe);
        if let Some(par) = p.parent {
            out.push_str(" parent=");
            out.push_u64(par as u64);
        }
        out.push(b'\n');
    }
    sys::out(out.as_bytes());
}

/// `--dry-run --json`: the same plan as one JSON object.
fn print_json_plan(rows: &[gen::Proc], prep: &inject::Prep, args: &Args) {
    let mut out = Buf::new();
    out.push_str("{\"version\":");
    json_escape(&mut out, crate::version::VERSION.as_bytes());
    out.push_str(",\"tier\":");
    json_escape(&mut out, prep.tier.name().as_bytes());
    out.push_str(",\"shadow_root\":");
    match &prep.shadow_root {
        Some(d) => json_escape(&mut out, d),
        None => out.push_str("null"),
    }
    out.push_str(",\"stubs\":");
    out.push_u64(rows.len() as u64);
    out.push_str(",\"roots\":");
    out.push_u64(rows.iter().filter(|p| p.parent.is_none()).count() as u64);
    out.push_str(",\"mem\":");
    out.push_str(bool_str(args.mem));
    out.push_str(",\"tty\":");
    out.push_str(bool_str(args.tty));
    out.push_str(",\"threads\":");
    out.push_str(bool_str(args.threads));
    out.push_str(",\"busy\":");
    out.push_str(bool_str(args.busy || args.cpu_pct.unwrap_or(0) > 0));
    out.push_str(",\"rss_kb\":");
    out.push_u64(rows.iter().map(|p| p.rss as u64).sum());
    out.push_str(",\"phys_kb\":");
    out.push_u64(prep.phys_estimate_kb);
    out.push_str(",\"budget_kb\":");
    out.push_u64(prep.phys_budget_kb);
    out.push_str(",\"phys_scale\":");
    out.push_u64((prep.phys_scale * 1000.0) as u64);
    out.push_str(",\"disk_mb\":");
    out.push_u64(args.disk_mb.unwrap_or(0));
    out.push_str(",\"rows\":[");
    for (i, p) in rows.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.push_str("{\"row\":");
        out.push_u64(i as u64);
        out.push_str(",\"role\":");
        out.push_str(if p.parent.is_none() {
            "\"root\""
        } else {
            "\"child\""
        });
        out.push_str(",\"user\":");
        json_escape(&mut out, &p.user);
        out.push_str(",\"uid\":");
        out.push_u64(p.uid as u64);
        out.push_str(",\"gid\":");
        out.push_u64(p.gid as u64);
        out.push_str(",\"vsz_kb\":");
        out.push_u64(p.vsz as u64);
        out.push_str(",\"rss_kb\":");
        out.push_u64(p.rss as u64);
        out.push_str(",\"cpu_tenths\":");
        out.push_u64(p.cpu as u64);
        out.push_str(",\"tty\":");
        out.push_str(bool_str(p.flags & corpus::F_TTY != 0));
        out.push_str(",\"threads\":");
        out.push_str(bool_str(p.flags & corpus::F_THREADS != 0));
        out.push_str(",\"busy\":");
        out.push_str(bool_str(p.flags & corpus::F_BUSY != 0));
        out.push_str(",\"exe\":");
        json_escape(&mut out, &gen::template_exe(&corpus::CORPUS[p.tmpl]));
        out.push_str(",\"cmd\":");
        json_escape(&mut out, &p.cmd);
        out.push_str(",\"parent\":");
        match p.parent {
            Some(par) => out.push_u64(par as u64),
            None => out.push_str("null"),
        }
        out.push(b'}');
    }
    out.push_str("]}\n");
    sys::out(out.as_bytes());
}

pub fn run() -> i32 {
    let argv: Vec<Vec<u8>> = std::env::args_os().map(|s| s.as_bytes().to_vec()).collect();
    if argv.is_empty() {
        sys::err(b"psgen: cannot read argv\n");
        return 2;
    }
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(msg) => {
            let mut out = Buf::new();
            out.push_str("psgen: ");
            out.push_str(&msg.to_string());
            out.push_str("\n(psgen --help for the full option list)\n");
            sys::err(out.as_bytes());
            return 2;
        }
    };

    if args.want_help {
        sys::out(&usage());
        return 0;
    }
    if args.want_version {
        sys::out(crate::version::LINE);
        return 0;
    }

    if args.elevate && (args.sub == Sub::Inject || args.sub == Sub::Stop) {
        if let Some(code) = elevate(&argv, &args) {
            return code;
        }
    }

    match args.sub {
        Sub::Help => {
            sys::out(&usage());
            0
        }
        Sub::Version => {
            sys::out(crate::version::LINE);
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
            check::run(&mut rng, &opts, args.binaries, args.require_binaries)
        }
        Sub::Unit => {
            let count = if args.count == 0 {
                24
            } else {
                args.count.min(500)
            };
            if args.count > 500 {
                sys::err(b"psgen: unit count capped at 500\n");
            }
            let pidfile = args
                .pidfile
                .clone()
                .unwrap_or_else(|| b"/run/psgen/psgen.pid".to_vec());
            let out = unit::render(count, args.seed.unwrap_or(7), &pidfile, &args);
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
            inject::stop(path, args.force, args.plan, args.quiet)
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
            shortfall(
                args.family,
                cmds.len(),
                if args.count == 0 {
                    0
                } else {
                    args.count.min(2000)
                },
                true,
            );
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
                    table::mem_budget_kb(),
                    start_offset(&args),
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
            let fit = gen::Fit::host();
            let rows = gen::gen_table(&mut rng, &opts, &fit);
            let want = if args.count == 0 {
                30
            } else {
                args.count.min(5000)
            };
            shortfall(args.family, rows.len(), want, false);
            let out = table::render(
                &rows,
                table::mem_budget_kb(),
                start_offset(&args),
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
            // The stub's own sizes are planned by prepare(); only the corpus
            // sizes need to be lowered to what this host can hold.
            let mut rows = gen::gen_inject(&mut rng, &opts, &gen::Fit::none());
            let want = if args.count == 0 {
                12
            } else {
                args.count.min(500)
            };
            shortfall(args.family, rows.len(), want, false);

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
                        if total_mb.saturating_mul(1024 * 1024) > free.saturating_sub(free / 10) {
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
                if args.json {
                    print_json_plan(&rows, &prep, &args);
                } else if args.plan {
                    print_plan(&rows, &prep, &args);
                } else {
                    let mut out = Buf::new();
                    for p in &rows {
                        out.push_bytes(&p.user);
                        out.push(b'\t');
                        out.push_bytes(&p.cmd);
                        out.push(b'\n');
                    }
                    sys::out(out.as_bytes());
                }
                print_notes(&prep, &args);
                return 0;
            }

            // A pidfile that still records live stubs cannot be reused: the
            // pending rewrite would erase the only record of the old run, and
            // the old stubs would outlive `stop`.
            if let Some(p) = &args.pidfile {
                match inject::live_pidfile_rows(p) {
                    Some(0) => {}
                    Some(_) => {
                        let mut out = Buf::new();
                        out.push_str("psgen: the pidfile ");
                        out.push_bytes(p);
                        out.push_str(
                            " records live processes; stop them first or choose another --pidfile",
                        );
                        out.push(b'\n');
                        sys::err(out.as_bytes());
                        return 2;
                    }
                    None => {
                        let mut out = Buf::new();
                        out.push_str("psgen: cannot read the existing pidfile ");
                        out.push_bytes(p);
                        out.push_str("; remove it or choose another --pidfile");
                        out.push(b'\n');
                        sys::err(out.as_bytes());
                        return 2;
                    }
                }
            }

            // Forget the staging directories of runs whose injector is gone.
            // A `--duration` run that nobody stops leaves its shadow copy and
            // --disk data behind; the next run reclaims them.
            let pruned = inject::prune_staging(&prep);
            if pruned > 0 {
                let mut out = Buf::new();
                out.push_str("psgen: pruned ");
                out.push_u64(pruned as u64);
                out.push_str(" staging directories from earlier runs\n");
                sys::err(out.as_bytes());
            }

            // Prove the pidfile can be written before the first stub exists,
            // and leave a valid header-only pidfile behind. A failure after
            // the fork would otherwise leave live stubs with no record.
            let mut pending_written = false;
            if let Some(p) = &args.pidfile {
                pending_written = inject::write_pending_pidfile(p);
                if !pending_written {
                    // The preflight proved a write works, so a failure here is
                    // a race (the directory went away); refuse rather than
                    // spawn what cannot be stopped.
                    let mut out = pidfile_error(p);
                    out.push_str(" (the pidfile could not be written before spawning)");
                    out.push(b'\n');
                    sys::err(out.as_bytes());
                    return 2;
                }
            }

            print_notes(&prep, &args);
            let result = match inject::spawn(&rows, &args, &prep) {
                Ok(r) => r,
                Err(e) => {
                    // Every `spawn` error is raised before the first fork, so
                    // no stub exists to record. Remove the header-only file
                    // rather than leave a pidfile that claims a run happened.
                    if pending_written {
                        if let Some(p) = &args.pidfile {
                            let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(p)));
                        }
                    }
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
                if pending_written {
                    if let Some(p) = &args.pidfile {
                        let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(p)));
                    }
                }
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
                let mut live_rows = live::read_pids(&result.pids);
                live_rows.sort_unstable_by_key(|p| p.pid);
                let out = table::render(
                    &live_rows,
                    table::mem_budget_kb(),
                    start_offset(&args),
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
                    let alive = result.pids.iter().any(|pid| live::alive(*pid));
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
