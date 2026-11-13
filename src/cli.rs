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

impl Sub {
    /// One bit per subcommand, so an option's set is a single `u16`.
    const fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

const ALL_SUBS: u16 = Sub::List.bit()
    | Sub::Table.bit()
    | Sub::Inject.bit()
    | Sub::Stop.bit()
    | Sub::Corpus.bit()
    | Sub::Check.bit()
    | Sub::Unit.bit()
    | Sub::Doctor.bit()
    | Sub::Log.bit()
    | Sub::Load.bit()
    | Sub::Help.bit()
    | Sub::Version.bit();

// Named groups of subcommands that consume the same generator options, so a
// set is written once instead of repeated in a `matches!` per subcommand.

/// The three commands that draw rows from the corpus with a profile.
const GEN: u16 = Sub::List.bit() | Sub::Table.bit() | Sub::Inject.bit();
/// `GEN` plus `unit`, which forwards the inject options into `ExecStart`.
const GEN_UNIT: u16 = GEN | Sub::Unit.bit();
/// Everything that expands corpus commands and so reads a seed or a family.
const EXPAND: u16 = GEN | Sub::Check.bit() | Sub::Unit.bit();
/// The two `inject`-shaped commands: one spawns, one renders a unit that does.
const INJECT_UNIT: u16 = Sub::Inject.bit() | Sub::Unit.bit();
/// `--help` and `--version` are accepted everywhere, including as the `help`
/// and `version` subcommands' own arguments.
const ANY: u16 = ALL_SUBS;

/// One option the parser understands, and the subcommands that consume it.
///
/// This table is the single place that decides whether an option applies.
/// `parse` rejects anything outside the chosen subcommand's set, so an option
/// cannot be accepted and silently ignored, and the two unit tests below fail
/// when the table and the help text disagree: adding a documented option
/// without deciding its subcommands is a test failure, not a silent no-op.
struct Opt {
    /// The canonical long form, which is what `Args::seen` records and what an
    /// error message names.
    name: &'static str,
    /// Other spellings that select the same option.
    aliases: &'static [&'static str],
    /// Takes no value, so `--flag=value` is a usage error rather than a value
    /// of the next option.
    boolean: bool,
    /// Bitmask of `Sub::bit()`.
    subs: u16,
}

const OPTS: &[Opt] = &[
    Opt {
        name: "--help",
        aliases: &["-h"],
        boolean: true,
        subs: ANY,
    },
    Opt {
        name: "--version",
        aliases: &["-V"],
        boolean: true,
        subs: ANY,
    },
    Opt {
        name: "--count",
        aliases: &["-n"],
        boolean: false,
        subs: GEN_UNIT,
    },
    Opt {
        name: "--seed",
        aliases: &["-s"],
        boolean: false,
        subs: EXPAND | Sub::Log.bit(),
    },
    Opt {
        name: "--profile",
        aliases: &["-p"],
        boolean: false,
        subs: GEN_UNIT,
    },
    Opt {
        name: "--family",
        aliases: &["-f"],
        boolean: false,
        subs: EXPAND,
    },
    // `--local` and `--utc-offset` are synthetic-table knobs. A live table is
    // always the host's own zone, so they are rejected for `table --live` and
    // for every `inject` mode; there is no second place that could shift it.
    Opt {
        name: "--utc-offset",
        aliases: &[],
        boolean: false,
        subs: Sub::Table.bit() | Sub::Inject.bit(),
    },
    Opt {
        name: "--local",
        aliases: &[],
        boolean: true,
        subs: Sub::Table.bit() | Sub::Inject.bit(),
    },
    Opt {
        name: "--sort",
        aliases: &[],
        boolean: true,
        subs: Sub::List.bit(),
    },
    Opt {
        name: "--no-sort",
        aliases: &[],
        boolean: true,
        subs: Sub::List.bit(),
    },
    Opt {
        name: "--uniq",
        aliases: &[],
        boolean: true,
        subs: Sub::List.bit(),
    },
    Opt {
        name: "--no-uniq",
        aliases: &[],
        boolean: true,
        subs: Sub::List.bit(),
    },
    Opt {
        name: "--duration",
        aliases: &["-d"],
        boolean: false,
        subs: Sub::Inject.bit() | Sub::Unit.bit() | Sub::Load.bit(),
    },
    Opt {
        name: "--pidfile",
        aliases: &[],
        boolean: false,
        subs: Sub::Inject.bit() | Sub::Stop.bit() | Sub::Unit.bit() | Sub::Doctor.bit(),
    },
    Opt {
        name: "--mem",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--no-mem",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--mem-cap",
        aliases: &[],
        boolean: false,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--mem-target",
        aliases: &[],
        boolean: false,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--phys-cap",
        aliases: &[],
        boolean: false,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--disk",
        aliases: &[],
        boolean: false,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--exe",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--no-exe",
        aliases: &["--allow-proc-exe"],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--shadow-dir",
        aliases: &[],
        boolean: false,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--no-root",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--tty",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--no-tty",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--threads",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--no-threads",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--user",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--no-user",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--create-users",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--busy",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--cpu",
        aliases: &[],
        boolean: false,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--dry-run",
        aliases: &[],
        boolean: true,
        subs: Sub::Inject.bit(),
    },
    Opt {
        name: "--plan",
        aliases: &[],
        boolean: true,
        subs: Sub::Inject.bit() | Sub::Stop.bit(),
    },
    Opt {
        name: "--json",
        aliases: &[],
        boolean: true,
        subs: Sub::Inject.bit() | Sub::Doctor.bit(),
    },
    Opt {
        name: "--table",
        aliases: &[],
        boolean: true,
        subs: Sub::Inject.bit(),
    },
    Opt {
        name: "--verify",
        aliases: &[],
        boolean: true,
        subs: INJECT_UNIT,
    },
    Opt {
        name: "--wait",
        aliases: &[],
        boolean: true,
        subs: Sub::Inject.bit(),
    },
    Opt {
        name: "--elevate",
        aliases: &[],
        boolean: true,
        subs: Sub::Inject.bit() | Sub::Stop.bit(),
    },
    Opt {
        name: "--quiet",
        aliases: &["-q"],
        boolean: true,
        subs: Sub::Inject.bit() | Sub::Stop.bit() | Sub::Load.bit(),
    },
    Opt {
        name: "--binaries",
        aliases: &[],
        boolean: true,
        subs: Sub::Check.bit(),
    },
    Opt {
        name: "--require-binaries",
        aliases: &[],
        boolean: true,
        subs: Sub::Check.bit(),
    },
    Opt {
        name: "--host-mem",
        aliases: &[],
        boolean: false,
        subs: Sub::Table.bit(),
    },
    Opt {
        name: "--host-pid-max",
        aliases: &[],
        boolean: false,
        subs: Sub::Table.bit(),
    },
    Opt {
        name: "--host-uptime",
        aliases: &[],
        boolean: false,
        subs: Sub::Table.bit(),
    },
    Opt {
        name: "--live",
        aliases: &[],
        boolean: true,
        subs: Sub::Table.bit(),
    },
    Opt {
        name: "--repeat-max",
        aliases: &[],
        boolean: false,
        subs: Sub::Table.bit() | Sub::Inject.bit(),
    },
    Opt {
        name: "--cpu-util",
        aliases: &[],
        boolean: false,
        subs: Sub::Load.bit(),
    },
    Opt {
        name: "--mem-util",
        aliases: &[],
        boolean: false,
        subs: Sub::Load.bit(),
    },
    Opt {
        name: "--disk-util",
        aliases: &[],
        boolean: false,
        subs: Sub::Load.bit(),
    },
    Opt {
        name: "--force",
        aliases: &[],
        boolean: true,
        subs: Sub::Stop.bit() | Sub::Load.bit(),
    },
    Opt {
        name: "--module",
        aliases: &["-m"],
        boolean: false,
        subs: Sub::Log.bit(),
    },
    Opt {
        name: "--lines",
        aliases: &[],
        boolean: false,
        subs: Sub::Log.bit(),
    },
    Opt {
        name: "--delay",
        aliases: &[],
        boolean: false,
        subs: Sub::Log.bit(),
    },
    Opt {
        name: "--speed",
        aliases: &[],
        boolean: false,
        subs: Sub::Log.bit(),
    },
    Opt {
        name: "--log-fmt",
        aliases: &[],
        boolean: false,
        subs: Sub::Log.bit(),
    },
];

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
    /// `--repeat-max N`: cap on how often one command may be repeated. `None`
    /// keeps the realistic default; `Some(0)` means no cap.
    pub repeat_max: Option<usize>,
    /// `--host-mem MiB`: generate for a host with this much memory instead of
    /// this one.
    pub host_mem_mb: Option<u64>,
    /// `--host-pid-max N`: generate for a host whose pid_max is this.
    pub host_pid_max: Option<u64>,
    /// `--host-uptime S`: generate for a host that has been up this long.
    pub host_uptime: Option<u64>,
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
            repeat_max: None,
            host_mem_mb: None,
            host_pid_max: None,
            host_uptime: None,
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
  -p, --profile NAME  server (default), dev, desktop; weights the rows list,
                      table and inject draw. Given explicitly, `list` orders
                      the templates by profile weight; without it, the corpus
                      order is kept.
  -f, --family NAME   sys, web, db, ctr, dev, mon, sto, mail, desk, net
      --utc-offset M  minutes east of UTC for the START column, -1440..1440
                      (default 0); synthetic table only
      --local         use the system timezone for the START column; overrides
                      --utc-offset; synthetic table only
      --sort / --no-sort   list only
      --uniq / --no-uniq   list only
  -h, --help
  -V, --version

An option that a subcommand does not use is a usage error (exit 2), not a
silent no-op. That includes the mode-selected cases: a live table takes no
clock or generator flags, and an `inject` preview takes no flag that needs a
fork.

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
                        and is ignored with --no-root or --no-user. With
                        --dry-run no account is created, but the plan keeps the
                        template's user name and reports it as one the run
                        would create; the plan and the JSON mark such a row and
                        name the accounts, and its uid is null because the
                        account does not exist yet.
      --busy            burn CPU for every row whose corpus CPU is non-zero
      --cpu PCT         target cpu percent for every row; forces the busy path
                        when non-zero, 0 clears it (0..100)
      --dry-run         print user and command for what would be spawned; the
                        exact two-column format is kept for existing callers.
                        Nothing is spawned, so --table, --verify, --wait,
                        --elevate and -q are usage errors here.
      --plan            with --dry-run, print the resolved plan instead: exe
                        tier, per-row user/VSZ/RSS/CPU/tty/threads/exe, parent
                        links, the physical cost estimate, and the staging
                        directories the run would create. It exits non-zero for
                        every preflight the real run would refuse.
      --json            with --dry-run, print the plan as one JSON object; an
                        alternative to --plan, not a companion
      --table           after spawning, print the real ps aux table for the stubs
      --verify          compare each stub's real VSZ/RSS with the planned
                        value within 128 kB; has no effect with --no-mem
      --wait            block for a non-zero --duration, then stop the stubs
      --elevate         re-exec through sudo -n when not already root
  -q, --quiet           suppress the inject summary

CORPUS AND CHECK
      --binaries        report which template executables exist on this host
      --require-binaries  like --binaries, but exit 1 when any is missing
  --host-mem MiB      generate for a host with this much memory instead of this
                      one (table)
  --host-pid-max N    generate for a host whose pid_max is N (table); a host
                      with pid_max below 3 has no PID to show, which is reported
  --host-uptime S     generate as if the host had been up S seconds (table)
  --repeat-max N      how often one command may be repeated; 0 means no cap,
                      omitted means the realistic bound. Raising it is what
                      makes a count the corpus cannot supply reachable.
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
  -q, --quiet         suppress the load summary

STOP
      --force           ignore the boot id; a three-field line still checks
                        starttime and comm, a two-field line still checks
                        starttime, and a one-field line still requires the run
                        nonce recorded in the pidfile header, so a line that
                        cannot be identified is refused rather than signalled
      --plan            print what would be signalled and stop nothing; never
                        elevates, so it reports the caller's own privileges
      --elevate         re-exec through sudo -n when not already root; a usage
                        error with --plan
  -q, --quiet           only print the summary line
  The pidfile header carries the boot id and the run nonce; a header without a
  boot id is refused, and a file with no `# psgen` header is refused unless
  --force is given. A pidfile with CRLF line endings is refused by name, not
  read as unidentifiable rows.
  A pidfile from a live run is left in place, so the same path can be used
  again; stop the run twice and the second call is a no-op. The summary counts
  processes, not lines, and `skipped` counts lines.
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

/// The option a spelling selects, if the table knows it.
fn opt_of(name: &[u8]) -> Option<&'static Opt> {
    OPTS.iter()
        .find(|o| o.name.as_bytes() == name || o.aliases.iter().any(|a| a.as_bytes() == name))
}

fn is_boolean_flag(name: &[u8]) -> bool {
    opt_of(name).map(|o| o.boolean).unwrap_or(false)
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
/// One table decides, so an option that a subcommand does not read cannot be
/// accepted and silently dropped. The worst case before this was `unit -p
/// desktop`, which printed a unit that injected server rows; rejecting it also
/// catches typos such as `--famly`.
fn applies(sub: Sub, name: &str) -> bool {
    match opt_of(name.as_bytes()) {
        Some(o) => o.subs & sub.bit() != 0,
        None => false,
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
                b"--host-mem" => {
                    a.seen.push("--host-mem");
                    let v = take_value(args, &mut i, inline).ok_or("missing value for --host-mem")?;
                    let n = str::parse_u64(v).ok_or("invalid --host-mem")?;
                    // 0 means "unknown" inside Fit, so accepting it here would
                    // silently fall back to this host instead of the one asked
                    // for. A host with no memory is not a host.
                    if n == 0 {
                        return Err("--host-mem must be at least 1 MiB".into());
                    }
                    a.host_mem_mb = Some(n);
                }
                b"--host-pid-max" => {
                    a.seen.push("--host-pid-max");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --host-pid-max")?;
                    let n = str::parse_u64(v).ok_or("invalid --host-pid-max")?;
                    // 0 means "unknown" inside Fit; a host with pid_max 0 has
                    // no PID at all, which is a different statement.
                    if n == 0 {
                        return Err("--host-pid-max must be at least 1".into());
                    }
                    a.host_pid_max = Some(n);
                }
                b"--host-uptime" => {
                    a.seen.push("--host-uptime");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --host-uptime")?;
                    let n = str::parse_u64(v).ok_or("invalid --host-uptime")?;
                    // 0 means "unknown" inside Fit, so accepting it here would
                    // silently generate for this host instead of a host that
                    // has just booted — the case the flag exists to exercise.
                    if n == 0 {
                        return Err("--host-uptime must be at least 1".into());
                    }
                    a.host_uptime = Some(n);
                }
                b"--repeat-max" => {
                    a.seen.push("--repeat-max");
                    let v =
                        take_value(args, &mut i, inline).ok_or("missing value for --repeat-max")?;
                    let n = str::parse_u64(v).ok_or("invalid --repeat-max")?;
                    a.repeat_max = Some(usize::try_from(n).map_err(|_| "invalid --repeat-max")?);
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
    // `--help` and `--version` are answered whatever else is on the line, in
    // both spellings: `psgen help -n 5` must not be an error where `psgen
    // --help -n 5` is not.
    if a.want_help || a.want_version || a.sub == Sub::Help || a.sub == Sub::Version {
        a.sub = if a.want_version || a.sub == Sub::Version {
            Sub::Version
        } else {
            Sub::Help
        };
        return Ok(a);
    }
    // An option that the chosen subcommand does not consume is an error, not
    // a silent no-op. The first offending option is named.
    for name in &a.seen {
        if !applies(a.sub, name) {
            return Err(format!("{} does not apply to {}", name, sub_name(a.sub)).into());
        }
    }
    // The table decides whether a subcommand reads an option at all; the mode
    // the other flags select decides whether it can change anything. Both
    // rejections name the flag and the reason, because an accepted no-op is
    // indistinguishable from a bug.
    forbid(&a)?;
    Ok(a)
}

/// Whether an `inject` run spawns, or only previews.
#[derive(Clone, Copy, PartialEq)]
enum Run {
    Spawn,
    Dry,
}

fn run_mode(a: &Args) -> Run {
    if a.dry_run {
        Run::Dry
    } else {
        Run::Spawn
    }
}

/// Reject an option the chosen mode cannot act on.
fn forbid(a: &Args) -> Result<(), ParseError> {
    let seen = |name: &str| a.seen.contains(&name);
    let reject = |name: &str, why: &str| -> Result<(), ParseError> {
        if seen(name) {
            Err(format!("{} {}", name, why).into())
        } else {
            Ok(())
        }
    };
    // A live table *is* the host's table: %MEM divides by MemTotal and START
    // is the host's own zone, because that is what the `ps` beside it prints.
    // Only the synthetic table has a clock to choose.
    if a.sub == Sub::Table && a.live {
        for name in [
            "--local",
            "--utc-offset",
            "--profile",
            "--family",
            "--seed",
            "--repeat-max",
            "--host-mem",
            "--host-pid-max",
            "--host-uptime",
        ] {
            reject(
                name,
                "does not apply to table --live: the table is this host's own, not a generated one",
            )?;
        }
    }
    if a.sub == Sub::Inject {
        // `inject --table` renders a live table, and a live table is always
        // the host's own zone. There is no mode of `inject` where the clock
        // options could change anything, so they are rejected for all of them
        // (design §11; the class issue #17 belonged to).
        reject(
            "--local",
            "does not apply to inject: the only table it renders is a live one",
        )?;
        reject(
            "--utc-offset",
            "does not apply to inject: the only table it renders is a live one",
        )?;
        match run_mode(a) {
            Run::Dry => {
                // A dry run forks nothing, so a flag that only takes effect
                // after the fork has nothing to act on.
                reject(
                    "--table",
                    "needs a real spawn; use --plan to see the rows a run would create",
                )?;
                reject(
                    "--verify",
                    "compares each stub's /proc with the plan; nothing is spawned with --dry-run",
                )?;
                reject(
                    "--wait",
                    "waits for a spawned run; nothing is spawned with --dry-run",
                )?;
                reject(
                    "--elevate",
                    "does not apply with --dry-run: a preview never elevates",
                )?;
                reject(
                    "--quiet",
                    "suppresses the spawn summary, which a preview does not print",
                )?;
                if a.json && a.plan {
                    return Err("--plan and --json encode the same preview; use one of them".into());
                }
            }
            Run::Spawn => {
                if a.json {
                    return Err("--json on inject needs --dry-run: it encodes the plan".into());
                }
                if a.plan {
                    return Err("--plan on inject needs --dry-run: it is the preview".into());
                }
                if a.wait && a.duration == 0 {
                    return Err(
                        "--wait needs --duration: without one the run is stopped by `psgen stop`"
                            .into(),
                    );
                }
            }
        }
    }
    if a.sub == Sub::Stop && a.plan && a.elevate {
        return Err(
            "--elevate does not apply with --plan: a plan never elevates, so it would report \
             a verdict the real run cannot reach"
                .into(),
        );
    }
    Ok(())
}

fn elevate(argv: &[Vec<u8>], args: &Args) -> Option<i32> {
    // A preview never elevates: `--plan` describes what the caller's own
    // privileges would reach, and re-execing through sudo would answer a
    // different question (and make a read-only command privileged).
    let preview = args.dry_run || (args.plan && args.sub == Sub::Stop);
    if !args.elevate || preview || sys::geteuid() == 0 {
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
        let mut msg = w.clone();
        // `prepare()` runs with `create = false` under --dry-run, so it adds
        // the "pass --create-users" hint even when the flag is already on the
        // command line. The hint exists for a caller who did *not* ask; here
        // the account is already reported as one the run would create.
        if args.dry_run && args.create_users {
            msg = msg.replace(" (pass --create-users to create it)", "");
        }
        let mut out = Buf::new();
        out.push_str("psgen: ");
        out.push_str(&msg);
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

/// The clock the *synthetic* table renders with.
///
/// A live table never calls this: `table::Clock::live` is the only clock a
/// live table gets, which is what stops `--local` and `--utc-offset` from
/// being applied a second time (issue #17). `--local` selects the system
/// timezone, so a UTC offset would shift a second time; local wins.
fn synthetic_clock(args: &Args, now: u64) -> table::Clock {
    if args.local {
        table::Clock::synthetic(now, 0, true)
    } else {
        table::Clock::synthetic(now, args.offset_min, false)
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
    } else if let Err(probe::TargetProblem::Unreadable(e)) = probe::pidfile_target(path) {
        // "Not an empty file or a psgen pidfile" would be a lie here: the path
        // could not be examined, which is a different problem with a different
        // fix (a shorter name, or a directory the caller can search).
        out.push_str(": the path cannot be examined (");
        out.push_str(&std::io::Error::from_raw_os_error(e).to_string());
        out.push(b')');
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

/// How many command lines a `list` run asks `gen_list` for.
///
/// `gen_list` treats 0 as "one line per template, in corpus order" and never
/// reads the profile on that arm, so a bare `list -p desktop` printed exactly
/// what `list -p server` printed (issue #9a). The order is a documented
/// contract, so the default invocation keeps it; an explicit `-p` names a
/// weighting and therefore selects the counted path, where the profile is
/// consulted and the first row stays the first in-scope corpus row.
fn list_target(args: &Args) -> usize {
    let weighted = args.seen.contains(&"--profile");
    if args.count == 0 && !weighted {
        return 0;
    }
    let n = if args.count == 0 {
        corpus::CORPUS
            .iter()
            .filter(|t| args.family.map(|f| t.fam == f).unwrap_or(true))
            .count()
    } else {
        args.count.min(2000)
    };
    n.min(2000)
}

/// Whether a `list` run asked for a number of lines, as opposed to the bare
/// one-per-template dump. Only a count can fall short.
fn lists_count(args: &Args) -> bool {
    list_target(args) != 0
}

/// Whether any in-scope template can produce more than one distinct line.
///
/// This is the only honest test for "`--no-uniq` can pad a short list": a
/// fixed command line re-expands to itself, so repeating it is not padding.
fn can_vary(family: Option<u8>) -> bool {
    corpus::CORPUS
        .iter()
        .filter(|t| family.map(|f| t.fam == f).unwrap_or(true))
        .any(gen::has_variants)
}

/// Say so when a request cannot be met at all.
///
/// A table that repeats a row a real host runs several times is not a
/// shortfall: the count is honoured, and `F_REPEAT` marks the templates that may
/// contribute more than one row. What a caller does need to hear is the case
/// where even that cannot reach the number, which happens for a family whose
/// templates all run once and cannot vary (`list -f mail -n 50`).
fn shortfall(family: Option<u8>, got: usize, want: usize, list: bool, reason: Option<&str>) {
    if want == 0 || got >= want {
        return;
    }
    let mut out = Buf::new();
    out.push_str("psgen: ");
    out.push_u64(got as u64);
    out.push_str(if got == 1 { " row" } else { " rows" });
    out.push_str(" of ");
    out.push_u64(want as u64);
    out.push_str(" could be produced");
    match family {
        Some(f) => {
            out.push_str(" for family ");
            out.push_str(corpus::family_name(f));
        }
        None => out.push_str(" for this host"),
    }
    if let Some(r) = reason {
        out.push_str(": ");
        out.push_str(r);
    }
    // `list` rejects `--repeat-max`, so recommending it there names an option
    // the same run refuses (issue #9b). `--no-uniq` is a remedy only when an
    // in-scope template has a placeholder that can produce a second distinct
    // line; a fixed command line re-expands to itself, so repeating it is not
    // padding.
    if list {
        out.push_str("; a list never repeats a command");
        if can_vary(family) {
            out.push_str(" (use --no-uniq to pad with new command lines)");
        } else {
            out.push_str(", and none of these templates has a variable placeholder");
        }
        out.push_str(". Ask for fewer lines.");
    } else {
        out.push_str(". Use --repeat-max N to allow more repeats, or ask for fewer rows.");
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

/// The identity a `--create-users --dry-run` run would use, with the rows
/// rewritten to it.
///
/// `prepare()` is handed `create = false` under `--dry-run`, so a template
/// user that does not exist yet keeps the template's name but no uid: the real
/// run creates the account and injects as the template's user. This walks the
/// corpus identity rather than the row's current user, because the row already
/// carries the template's name by this point and a test against the caller's
/// name can never match.
fn would_create(rows: &mut [gen::Proc], args: &Args) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    if !args.create_users || args.no_root || !args.user || sys::geteuid() != 0 {
        // The same conditions `prepare()` checks before it would run useradd.
        return out;
    }
    let me = users::current();
    for p in rows.iter_mut() {
        let tmpl = &corpus::CORPUS[p.tmpl];
        if tmpl.user == corpus::SELF_USER {
            continue;
        }
        let want = tmpl.user.as_bytes().to_vec();
        if want == me.name || users::lookup_name(&want).is_some() || !users::valid_name(&want) {
            continue;
        }
        p.user = want.clone();
        // The uid is not known until useradd runs; 0 would claim root.
        p.uid = UNKNOWN_ID;
        p.gid = UNKNOWN_ID;
        if !out.contains(&want) {
            out.push(want);
        }
    }
    out
}

/// The uid/gid a preview prints for an account the real run has not created
/// yet. It is never a real id; the plan says the account does not exist.
pub const UNKNOWN_ID: u32 = u32::MAX;

/// The staging directories a run would create, in the order `spawn()` makes
/// them: one per row that needs its own directory, plus one for the shadow
/// copy when the tier is shadow.
///
/// `spawn()` builds each leaf from the injector's own PID, which does not
/// exist yet, so the plan names the parent and the count rather than inventing
/// a path the run will not use.
fn staging_dirs(rows: &[gen::Proc], prep: &inject::Prep, args: &Args) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    if prep.tier == inject::ExeTier::Shadow {
        if let Some(root) = &prep.shadow_root {
            let mut p = root.clone();
            if !p.ends_with(b"/") {
                p.push(b'/');
            }
            p.extend_from_slice(b".psgen-<pid>-9000");
            out.push(p);
        }
    }
    if args.disk_mb.unwrap_or(0) == 0 {
        return out;
    }
    let dir = std::env::temp_dir();
    let mut base = dir.as_os_str().as_bytes().to_vec();
    if base.ends_with(b"/") {
        base.pop();
    }
    for i in 0..rows.len() {
        let mut p = base.clone();
        p.extend_from_slice(b"/.psgen-<pid>-");
        let mut b = Buf::new();
        b.push_u64(i as u64);
        p.extend_from_slice(b.as_bytes());
        out.push(p);
    }
    out
}

/// The parent directory of each staging path, without repeats.
fn staging_parents(dirs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for d in dirs {
        let p = match d.iter().rposition(|b| *b == b'/') {
            Some(0) => b"/".to_vec(),
            Some(i) => d[..i].to_vec(),
            None => b".".to_vec(),
        };
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// `--dry-run --plan`: everything `prepare()` decided, per row.
fn print_plan(rows: &[gen::Proc], prep: &inject::Prep, create: &[Vec<u8>], args: &Args) {
    let mut out = Buf::new();
    out.push_str("tier ");
    out.push_str(prep.tier.name());
    // `--shadow-dir` is used only by the shadow tier; naming it otherwise
    // advertised a directory the run never touches.
    if prep.tier == inject::ExeTier::Shadow {
        if let Some(d) = &prep.shadow_root {
            out.push_str(" from ");
            out.push_bytes(d);
        }
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
    let disk = args.disk_mb.unwrap_or(0).saturating_mul(rows.len() as u64);
    if disk > 0 {
        out.push_str("; disk ");
        out.push_u64(disk);
        out.push_str(" MiB total over ");
        out.push_u64(rows.len() as u64);
        out.push_str(" stubs");
    }
    let dirs = staging_dirs(rows, prep, args);
    out.push_str("; staging ");
    out.push_u64(dirs.len() as u64);
    out.push_str(if dirs.len() == 1 {
        " directory"
    } else {
        " directories"
    });
    let parents = staging_parents(&dirs);
    if !parents.is_empty() {
        out.push_str(" under ");
        for (i, p) in parents.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_bytes(p);
        }
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
        if create.contains(&p.user) {
            // The identity the real run would use, reported without making an
            // account to prove it. The uid is unknown until then.
            out.push_str(" (would create)");
        }
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
    for d in &dirs {
        out.push_str("staging ");
        out.push_bytes(d);
        out.push(b'\n');
    }
    sys::out(out.as_bytes());
}

/// `--dry-run --json`: the same plan as one JSON object.
fn print_json_plan(rows: &[gen::Proc], prep: &inject::Prep, create: &[Vec<u8>], args: &Args) {
    let mut out = Buf::new();
    out.push_str("{\"version\":");
    json_escape(&mut out, crate::version::VERSION.as_bytes());
    out.push_str(",\"tier\":");
    json_escape(&mut out, prep.tier.name().as_bytes());
    out.push_str(",\"shadow_root\":");
    match &prep.shadow_root {
        Some(d) if prep.tier == inject::ExeTier::Shadow => json_escape(&mut out, d),
        _ => out.push_str("null"),
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
    // Two names, because the per-stub and total figures differ by the stub
    // count and one name cannot say which it is.
    out.push_str(",\"disk_mb_per_stub\":");
    out.push_u64(args.disk_mb.unwrap_or(0));
    out.push_str(",\"disk_mb_total\":");
    out.push_u64(args.disk_mb.unwrap_or(0).saturating_mul(rows.len() as u64));
    let dirs = staging_dirs(rows, prep, args);
    out.push_str(",\"staging_dirs\":[");
    for (i, d) in dirs.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json_escape(&mut out, d);
    }
    out.push_str("],\"would_create\":[");
    for (i, name) in create.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json_escape(&mut out, name);
    }
    out.push_str("],\"rows\":[");
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
        // An account the run would create has no uid yet. `null` says so;
        // printing 0 claimed the row would run as root.
        if p.uid == UNKNOWN_ID {
            out.push_str("null");
        } else {
            out.push_u64(p.uid as u64);
        }
        out.push_str(",\"gid\":");
        if p.gid == UNKNOWN_ID {
            out.push_str("null");
        } else {
            out.push_u64(p.gid as u64);
        }
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
                seed: args.seed.unwrap_or(1),
                profile: args.profile.clone(),
                family: args.family,
                self_user: b"deploy".to_vec(),
                uniq: args.uniq,
                repeat_max: None,
                uptime: None,
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
                // A bare `list` means one line per template, and the profile
                // says which order the templates are drawn in. Passing 0 takes
                // gen_list's corpus-order arm, where the profile is never
                // consulted, so `list -p desktop` printed exactly what
                // `list -p server` printed (issue #9a).
                count: list_target(&args),
                seed: args.seed.unwrap_or(0),
                profile: args.profile.clone(),
                family: args.family,
                self_user: util::current_user().name,
                uniq: args.uniq,
                repeat_max: args.repeat_max,
                uptime: args.host_uptime,
            };
            let mut cmds = gen::gen_list(&mut rng, &opts);
            if lists_count(&args) {
                let want = if args.count == 0 {
                    list_target(&args)
                } else {
                    args.count.min(2000)
                };
                shortfall(args.family, cmds.len(), want, true, None);
            }
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
                // The live table is `ps aux` for this host, so it uses the
                // host's own zone and `ps`'s own denominator. Both are supplied
                // by one function each, so no caller can pick a different one.
                let out = table::render(
                    &rows,
                    live::mem_total_kb(),
                    &table::Clock::live(sys::now_secs()),
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
                seed: args.seed.unwrap_or(0),
                profile: args.profile.clone(),
                family: args.family,
                self_user: util::current_user().name,
                uniq: args.uniq,
                repeat_max: args.repeat_max,
                uptime: args.host_uptime,
            };
            let fit = gen::Fit::target(args.host_mem_mb, args.host_pid_max);
            let rows = gen::gen_table(&mut rng, &opts, &fit);
            let want = if args.count == 0 {
                30
            } else {
                args.count.min(5000)
            };
            shortfall(
                args.family,
                rows.len(),
                want,
                false,
                fit.shortfall_reason(want).as_deref(),
            );
            // `%MEM` divides by the memory of the host the table describes.
            // `table::mem_budget_kb()` is this host's budget; an explicit
            // `--host-mem` names a different host, and the table it produces
            // has to be a percentage of *that* machine or the column is not a
            // property of the table at all.
            let mem_kb = match args.host_mem_mb {
                Some(mb) => mb.saturating_mul(1024),
                None => table::mem_budget_kb(),
            };
            let out = table::render(
                &rows,
                mem_kb,
                &synthetic_clock(&args, sys::now_secs()),
                sys::page_kb(),
            );
            sys::out(out.as_bytes());
            0
        }
        Sub::Inject => {
            if args.count > 500 {
                sys::err(b"psgen: inject count capped at 500\n");
            }
            // Preflight the pidfile before spawning. Writing it after the
            // fact leaves live stubs with no record of how to stop them. The
            // same check runs under --dry-run, which is read-only, so a plan
            // fails for a command line the real run would refuse.
            let mut blockers = 0usize;
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
                    blockers += 1;
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
                seed: args.seed.unwrap_or(0),
                profile: args.profile.clone(),
                family: args.family,
                self_user: me.name,
                uniq: args.uniq,
                repeat_max: args.repeat_max,
                uptime: args.host_uptime,
            };
            // The stub's own sizes are planned by prepare(); only the corpus
            // sizes need to be lowered to what this host can hold.
            let mut rows = gen::gen_inject(&mut rng, &opts, &gen::Fit::none());
            let want = if args.count == 0 {
                12
            } else {
                args.count.min(500)
            };
            shortfall(
                args.family,
                rows.len(),
                want,
                false,
                gen::Fit::none().shortfall_reason(want).as_deref(),
            );

            // A disk target that would fill the filesystem is refused here,
            // before anything is spawned. Every check in this block reads the
            // host, so a preview runs it too: a plan that says "fine" for a
            // command line the run refuses cannot gate a CI step.
            if let Some(mb) = args.disk_mb {
                if mb > 0 {
                    if let Some(limit) = sys::rlimit_fsize() {
                        if mb.saturating_mul(1024 * 1024) > limit {
                            let mut out = Buf::new();
                            out.push_str("psgen: --disk ");
                            out.push_u64(mb);
                            out.push_str(" MiB exceeds RLIMIT_FSIZE (");
                            out.push_u64(limit / 1024 / 1024);
                            out.push_str(" MiB)\n");
                            sys::err(out.as_bytes());
                            blockers += 1;
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
                            blockers += 1;
                        }
                    }
                }
            }
            if blockers > 0 {
                return 2;
            }

            let prep = inject::prepare(&mut rows, &args, args.create_users && !args.dry_run);

            if args.dry_run {
                // A preview cannot create an account, but it must not fall
                // back to the caller's identity either: the run it describes
                // would inject as the template's user.
                let create = would_create(&mut rows, &args);
                for name in &create {
                    let mut out = Buf::new();
                    out.push_str("psgen: would create ");
                    out.push_bytes(name);
                    out.push(b'\n');
                    sys::err(out.as_bytes());
                }
                if args.json {
                    print_json_plan(&rows, &prep, &create, &args);
                } else if args.plan {
                    print_plan(&rows, &prep, &create, &args);
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
                // `inject --table` is a live table: the same renderer inputs as
                // `table --live`, so the two cannot disagree about %MEM or
                // START for the same stub (issue #3's cgroup divergence and
                // issue #17's double shift).
                let out = table::render(
                    &live_rows,
                    live::mem_total_kb(),
                    &table::Clock::live(sys::now_secs()),
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
                // `result.pids` only holds the rows that reported. A stub that
                // never reported (a `setsid` child, a row killed before its
                // status record) is not in it, so "no pid is alive" is not the
                // same as "nothing is using the directory". The live marker is
                // the same test `stop` uses.
                for t in &result.temps {
                    let busy = inject::staging_busy(t);
                    if !busy {
                        let _ = std::fs::remove_dir_all(t);
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every option spelling the help text uses.
    ///
    /// Derived from `USAGE_BODY`, not from `OPTS`, so an option can only be
    /// documented if it has a row in the table: there is no way to describe a
    /// flag without deciding which subcommands consume it.
    fn documented() -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for raw in USAGE_BODY.split(|c: char| c.is_whitespace() || c == ',' || c == ')') {
            let tok = raw.trim_matches(|c: char| "([].;:".contains(c));
            let short =
                tok.len() == 2 && tok.starts_with('-') && tok.as_bytes()[1].is_ascii_alphabetic();
            if !(tok.starts_with("--") || short) || out.contains(&tok) {
                continue;
            }
            out.push(tok);
        }
        out
    }

    #[test]
    fn every_help_spelling_has_a_row_in_the_table() {
        let missing: Vec<&str> = documented()
            .into_iter()
            .filter(|n| opt_of(n.as_bytes()).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "the help documents options with no row in OPTS: {missing:?}"
        );
    }

    /// The other direction of the same property.
    ///
    /// `documented()` derives its list from the help text, so an `OPTS` row
    /// with no help spelling was never examined by either test: the option
    /// parsed, applied and did nothing visible in `--help`. Adding an option
    /// now requires describing it.
    #[test]
    fn every_row_in_the_table_has_a_help_spelling() {
        let help = documented();
        let missing: Vec<&str> = OPTS
            .iter()
            .map(|o| o.name)
            .filter(|n| !help.contains(n))
            .collect();
        assert!(
            missing.is_empty(),
            "OPTS has options the help text never mentions: {missing:?}"
        );
    }

    /// Every row names the subcommands that consume it.
    ///
    /// A zero set means the parser accepts the option nowhere, so the row is
    /// dead; `ANY` means every subcommand takes it, which is almost always a
    /// mistake for a subcommand-specific flag and must be written out in the
    /// help if it is intended.
    #[test]
    fn every_option_declares_its_subcommands() {
        for o in OPTS {
            assert_ne!(o.subs, 0, "{} is accepted by no subcommand", o.name);
            assert!(
                o.subs & !ALL_SUBS == 0,
                "{} names a subcommand bit that does not exist",
                o.name
            );
            if o.subs == ANY {
                assert!(
                    matches!(o.name, "--help" | "--version"),
                    "{} is accepted everywhere; a subcommand-specific option \
                     must name its subcommands",
                    o.name
                );
            }
        }
    }

    /// A row's aliases are spellings too, and each must be reachable.
    #[test]
    fn every_alias_selects_its_own_row() {
        for o in OPTS {
            for a in o.aliases {
                let got = opt_of(a.as_bytes()).expect("an alias is in the table");
                assert_eq!(got.name, o.name, "{a} does not select {}", o.name);
            }
        }
    }

    #[test]
    fn a_documented_option_is_consumed_by_at_least_one_subcommand() {
        for name in documented() {
            let o = opt_of(name.as_bytes()).expect("documented options are in the table");
            assert_ne!(o.subs, 0, "{name} is documented but applies to nothing");
        }
    }

    #[test]
    fn the_table_has_no_duplicate_spelling() {
        let mut names: Vec<&str> = Vec::new();
        for o in OPTS {
            for n in core::iter::once(o.name).chain(o.aliases.iter().copied()) {
                assert!(!names.contains(&n), "{n} appears twice in OPTS");
                names.push(n);
            }
        }
    }

    /// Whether `parse` accepts `argv` for a subcommand it names.
    fn ok(argv: &[&str]) -> bool {
        let argv: Vec<Vec<u8>> = core::iter::once("psgen")
            .chain(argv.iter().copied())
            .map(|s| s.as_bytes().to_vec())
            .collect();
        parse(&argv).is_ok()
    }

    #[test]
    fn help_and_version_take_the_same_arguments_in_both_spellings() {
        assert_eq!(ok(&["--help", "-n", "5"]), ok(&["help", "-n", "5"]));
        assert_eq!(ok(&["--version", "-q"]), ok(&["version", "-q"]));
    }

    #[test]
    fn an_inject_preview_rejects_a_flag_that_needs_a_fork() {
        for flag in ["--table", "--verify", "--wait", "--elevate"] {
            assert!(
                !ok(&["inject", "--dry-run", flag, "-n", "1"]),
                "inject --dry-run {flag} was accepted and can do nothing"
            );
        }
    }

    #[test]
    fn a_live_table_takes_no_clock_and_no_generator() {
        for flag in [
            "--local",
            "--utc-offset",
            "--profile",
            "--family",
            "--seed",
            "--repeat-max",
            "--host-mem",
            "--host-pid-max",
            "--host-uptime",
        ] {
            assert!(
                !ok(&["table", "--live", flag, "1"]),
                "table --live {flag} was accepted and can do nothing"
            );
        }
    }

    #[test]
    fn a_synthetic_table_keeps_its_clock() {
        assert!(ok(&["table", "--local", "-n", "2"]));
        assert!(ok(&["table", "--utc-offset", "60", "-n", "2"]));
    }

    #[test]
    fn a_plan_and_a_json_preview_are_alternatives() {
        assert!(!ok(&["inject", "--dry-run", "--plan", "--json", "-n", "1"]));
    }
}
