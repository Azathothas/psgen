//! Argument parsing and command dispatch.

use crate::activity;
use crate::check;
use crate::corpus;
use crate::doctor;
use crate::gen::{self, Opts};
use crate::harness;
use crate::inject;
use crate::json;
use crate::live;
use crate::loggen;
use crate::probe;
use crate::profile;
use crate::rng::Rng;
use crate::score;
use crate::selftest;
use crate::str::{self, Buf};
use crate::sys;
use crate::table;
use crate::unit;
use crate::users;
use crate::util;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
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
    Profile,
    Run,
    Score,
    Replay,
    Verify,
    Selftest,
    Help,
    Version,
}

impl Sub {
    /// One bit per subcommand, so an option's set is a single `u32`.
    const fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

const ALL_SUBS: u32 = Sub::List.bit()
    | Sub::Table.bit()
    | Sub::Inject.bit()
    | Sub::Stop.bit()
    | Sub::Corpus.bit()
    | Sub::Check.bit()
    | Sub::Unit.bit()
    | Sub::Doctor.bit()
    | Sub::Log.bit()
    | Sub::Load.bit()
    | Sub::Profile.bit()
    | Sub::Run.bit()
    | Sub::Score.bit()
    | Sub::Replay.bit()
    | Sub::Verify.bit()
    | Sub::Selftest.bit()
    | Sub::Help.bit()
    | Sub::Version.bit();

// Named groups of subcommands that consume the same generator options, so a
// set is written once instead of repeated in a `matches!` per subcommand.

/// The three commands that draw rows from the corpus with a profile.
const GEN: u32 = Sub::List.bit() | Sub::Table.bit() | Sub::Inject.bit();
/// `GEN` plus `unit`, which forwards the inject options into `ExecStart`.
const GEN_UNIT: u32 = GEN | Sub::Unit.bit();
/// Everything that expands corpus commands and so reads a seed or a family.
const EXPAND: u32 = GEN | Sub::Check.bit() | Sub::Unit.bit();
/// The two `inject`-shaped commands: one spawns, one renders a unit that does.
const INJECT_UNIT: u32 = Sub::Inject.bit() | Sub::Unit.bit();
/// `--help` and `--version` are accepted everywhere, including as the `help`
/// and `version` subcommands' own arguments.
const ANY: u32 = ALL_SUBS;

/// One option the parser understands, and the subcommands that consume it.
///
/// This table is the single place that decides whether an option applies.
/// `parse` rejects anything outside the chosen subcommand's set, so an option
/// cannot be accepted and silently ignored, and the two unit tests below fail
/// when the table and the help text disagree: adding a documented option
/// without deciding its subcommands is a test failure, not a silent no-op.
#[derive(Clone, Copy)]
enum OptId {
    Help,
    Version,
    Count,
    Seed,
    Profile,
    Family,
    UtcOffset,
    Local,
    Sort,
    NoSort,
    Uniq,
    NoUniq,
    Duration,
    Pidfile,
    Mem,
    NoMem,
    MemCap,
    MemTarget,
    PhysCap,
    Disk,
    Exe,
    NoExe,
    ShadowDir,
    NoRoot,
    Tty,
    NoTty,
    Threads,
    NoThreads,
    User,
    NoUser,
    CreateUsers,
    Busy,
    Cpu,
    DryRun,
    Plan,
    Json,
    Table,
    Verify,
    Wait,
    Elevate,
    Quiet,
    Binaries,
    RequireBinaries,
    HostMem,
    HostPidMax,
    HostUptime,
    Live,
    RepeatMax,
    CpuUtil,
    MemUtil,
    DiskUtil,
    Force,
    Module,
    Lines,
    Delay,
    Speed,
    LogFmt,
    Pid,
    Validate,
    Out,
    Tree,
    Label,
    Masker,
    ProfileName,
    RedactToken,
    RedactEnv,
    FromProfile,
    DecoyLevel,
    CleanEnv,
    ExeMemfd,
    DecoyToken,
    Dumpable,
    Seccomp,
    Wchan,
    JitterMs,
    Churn,
    MaskerCmd,
    Decoys,
    Mode,
    Level,
    Control,
    HardNegatives,
    ObserverUid,
    BlindDir,
    RunId,
    TargetPid,
    TargetCmd,
    Runs,
    Pick,
}

struct OptRow {
    id: OptId,
    name: &'static str,
    #[cfg(test)]
    alias: &'static str,
    boolean: bool,
    subs: u32,
}

#[cfg(test)]
#[allow(dead_code)]
struct Opt {
    name: &'static str,
    aliases: &'static [&'static str],
    boolean: bool,
    subs: u32,
}

#[cfg(test)]
const OPTS_ANCHOR: &[Opt] = &[
    Opt {
        name: "--help",
        aliases: &["-h"],
        boolean: true,
        subs: ANY,
    },
    Opt {
        name: "--force",
        aliases: &[],
        boolean: true,
        subs: Sub::Stop.bit() | Sub::Load.bit(),
    },
];

const OPT_NAMES: &str = concat!(
    "--help,-h|--version,-V|--count,-n|--seed,-s|--profile,-p|--family,-f|",
    "--utc-offset|--local|--sort|--no-sort|--uniq|--no-uniq|--duration,-d|--pidfile|",
    "--mem|--no-mem|--mem-cap|--mem-target|--phys-cap|--disk|--exe|--no-exe,--allow-proc-exe|",
    "--shadow-dir|--no-root|--tty|--no-tty|--threads|--no-threads|--user|--no-user|",
    "--create-users|--busy|--cpu|--dry-run|--plan|--json|--table|--verify|--wait|--elevate|",
    "--quiet,-q|--binaries|--require-binaries|--host-mem|--host-pid-max|--host-uptime|",
    "--live|--repeat-max|--cpu-util|--mem-util|--disk-util|--force|--module,-m|--lines|",
    "--delay|--speed|--log-fmt|--pid|--validate|--out|--tree|--label|--masker|--profile-name|",
    "--redact-token|--redact-env|--from-profile|--decoy-level|--clean-env|--exe-memfd|",
    "--decoy-token|--dumpable|--seccomp|--wchan|--jitter-ms|--churn|--masker-cmd|--decoys|",
    "--mode|--level|--control|--hard-negatives|--observer-uid|--blind-dir|--run-id|",
    "--target-pid|--target-cmd|--runs|--pick",
);

const OPT_META: &[(OptId, bool, u32)] = &[
    (OptId::Help, true, ANY),
    (OptId::Version, true, ANY),
    (OptId::Count, false, GEN_UNIT),
    (OptId::Seed, false, EXPAND | Sub::Log.bit() | Sub::Run.bit()),
    (OptId::Profile, false, GEN_UNIT | Sub::Run.bit()),
    (OptId::Family, false, EXPAND),
    (
        OptId::UtcOffset,
        false,
        Sub::Table.bit() | Sub::Inject.bit(),
    ),
    (OptId::Local, true, Sub::Table.bit() | Sub::Inject.bit()),
    (OptId::Sort, true, Sub::List.bit()),
    (OptId::NoSort, true, Sub::List.bit()),
    (OptId::Uniq, true, Sub::List.bit()),
    (OptId::NoUniq, true, Sub::List.bit()),
    (
        OptId::Duration,
        false,
        Sub::Inject.bit() | Sub::Unit.bit() | Sub::Load.bit(),
    ),
    (
        OptId::Pidfile,
        false,
        Sub::Inject.bit() | Sub::Stop.bit() | Sub::Unit.bit() | Sub::Doctor.bit(),
    ),
    (OptId::Mem, true, INJECT_UNIT),
    (OptId::NoMem, true, INJECT_UNIT),
    (OptId::MemCap, false, INJECT_UNIT),
    (OptId::MemTarget, false, INJECT_UNIT),
    (OptId::PhysCap, false, INJECT_UNIT),
    (OptId::Disk, false, INJECT_UNIT),
    (OptId::Exe, true, INJECT_UNIT),
    (OptId::NoExe, true, INJECT_UNIT),
    (OptId::ShadowDir, false, INJECT_UNIT),
    (OptId::NoRoot, true, INJECT_UNIT),
    (OptId::Tty, true, INJECT_UNIT),
    (OptId::NoTty, true, INJECT_UNIT),
    (OptId::Threads, true, INJECT_UNIT),
    (OptId::NoThreads, true, INJECT_UNIT),
    (OptId::User, true, INJECT_UNIT),
    (OptId::NoUser, true, INJECT_UNIT),
    (OptId::CreateUsers, true, INJECT_UNIT),
    (OptId::Busy, true, INJECT_UNIT),
    (OptId::Cpu, false, INJECT_UNIT),
    (OptId::DryRun, true, Sub::Inject.bit()),
    (OptId::Plan, true, Sub::Inject.bit() | Sub::Stop.bit()),
    (OptId::Json, true, Sub::Inject.bit() | Sub::Doctor.bit()),
    (OptId::Table, true, Sub::Inject.bit()),
    (OptId::Verify, true, INJECT_UNIT),
    (OptId::Wait, true, Sub::Inject.bit()),
    (OptId::Elevate, true, Sub::Inject.bit() | Sub::Stop.bit()),
    (
        OptId::Quiet,
        true,
        Sub::Inject.bit() | Sub::Stop.bit() | Sub::Load.bit(),
    ),
    (OptId::Binaries, true, Sub::Check.bit()),
    (OptId::RequireBinaries, true, Sub::Check.bit()),
    (OptId::HostMem, false, Sub::Table.bit()),
    (OptId::HostPidMax, false, Sub::Table.bit()),
    (OptId::HostUptime, false, Sub::Table.bit()),
    (OptId::Live, true, Sub::Table.bit() | Sub::Run.bit()),
    (
        OptId::RepeatMax,
        false,
        Sub::Table.bit() | Sub::Inject.bit(),
    ),
    (OptId::CpuUtil, false, Sub::Load.bit()),
    (OptId::MemUtil, false, Sub::Load.bit()),
    (OptId::DiskUtil, false, Sub::Load.bit()),
    (OptId::Force, true, Sub::Stop.bit() | Sub::Load.bit()),
    (OptId::Module, false, Sub::Log.bit()),
    (OptId::Lines, false, Sub::Log.bit()),
    (OptId::Delay, false, Sub::Log.bit()),
    (OptId::Speed, false, Sub::Log.bit()),
    (OptId::LogFmt, false, Sub::Log.bit()),
    (OptId::Pid, false, Sub::Profile.bit()),
    (OptId::Validate, false, Sub::Profile.bit()),
    (
        OptId::Out,
        false,
        Sub::Profile.bit()
            | Sub::Run.bit()
            | Sub::Score.bit()
            | Sub::Replay.bit()
            | Sub::Selftest.bit(),
    ),
    (OptId::Tree, true, Sub::Profile.bit()),
    (OptId::Label, false, Sub::Profile.bit()),
    (OptId::Masker, false, Sub::Profile.bit()),
    (OptId::ProfileName, false, Sub::Profile.bit()),
    (
        OptId::RedactToken,
        false,
        Sub::Profile.bit() | Sub::Verify.bit(),
    ),
    (OptId::RedactEnv, false, Sub::Profile.bit()),
    (OptId::FromProfile, false, Sub::Inject.bit()),
    (OptId::DecoyLevel, false, Sub::Inject.bit()),
    (OptId::CleanEnv, true, Sub::Inject.bit()),
    (OptId::ExeMemfd, true, Sub::Inject.bit()),
    (OptId::DecoyToken, false, Sub::Inject.bit() | Sub::Run.bit()),
    (OptId::Dumpable, false, Sub::Inject.bit()),
    (OptId::Seccomp, false, Sub::Inject.bit()),
    (OptId::Wchan, false, Sub::Inject.bit()),
    (OptId::JitterMs, false, Sub::Inject.bit() | Sub::Run.bit()),
    (OptId::Churn, false, Sub::Inject.bit() | Sub::Run.bit()),
    (OptId::MaskerCmd, false, Sub::Inject.bit() | Sub::Run.bit()),
    (OptId::Decoys, false, Sub::Run.bit()),
    (OptId::Mode, false, Sub::Run.bit()),
    (OptId::Level, false, Sub::Run.bit()),
    (OptId::Control, false, Sub::Run.bit()),
    (OptId::HardNegatives, false, Sub::Run.bit()),
    (OptId::ObserverUid, false, Sub::Run.bit()),
    (OptId::BlindDir, false, Sub::Run.bit()),
    (OptId::RunId, false, Sub::Run.bit()),
    (OptId::TargetPid, false, Sub::Run.bit()),
    (OptId::TargetCmd, false, Sub::Run.bit()),
    (OptId::Runs, false, Sub::Score.bit()),
    (
        OptId::Pick,
        false,
        Sub::Score.bit() | Sub::Replay.bit() | Sub::Verify.bit(),
    ),
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
    /// Positional `<run-dir>` for `score`, `replay`, and `verify`.
    pub run_dir: Option<Vec<u8>>,
    /// `profile` options.
    pub target_pid: Option<i32>,
    pub validate_file: Option<Vec<u8>>,
    pub out_path: Option<Vec<u8>>,
    pub tree: bool,
    pub label: Option<String>,
    pub masker: Option<String>,
    pub profile_name: Option<String>,
    pub redact_tokens: Vec<String>,
    pub redact_envs: Vec<String>,
    /// `inject` decoy options (and shared `run` live options).
    pub from_profile: Option<Vec<u8>>,
    pub decoy_level: Option<u8>,
    pub clean_env: bool,
    pub exe_memfd: bool,
    pub decoy_token: Option<String>,
    pub dumpable: Option<u8>,
    pub seccomp: Option<u8>,
    pub wchan: Option<u8>,
    pub jitter_ms: u32,
    pub churn: u32,
    pub masker_cmd: Option<String>,
    /// `run` options.
    pub decoys: usize,
    pub run_mode: harness::Mode,
    pub run_level: u8,
    pub run_control: harness::Control,
    pub hard_negatives: Option<Vec<harness::HardNeg>>,
    pub observer_uid: Option<u32>,
    pub blind_dir: Option<Vec<u8>>,
    pub run_id: Option<String>,
    pub target_cmd: Option<String>,
    /// `score` / `replay` / `verify` options.
    pub runs: Option<String>,
    pub pick: Option<String>,
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
            run_dir: None,
            target_pid: None,
            validate_file: None,
            out_path: None,
            tree: false,
            label: None,
            masker: None,
            profile_name: None,
            redact_tokens: Vec::new(),
            redact_envs: Vec::new(),
            from_profile: None,
            decoy_level: None,
            clean_env: false,
            exe_memfd: false,
            decoy_token: None,
            dumpable: None,
            seccomp: None,
            wchan: None,
            jitter_ms: 0,
            churn: 0,
            masker_cmd: None,
            decoys: 50,
            run_mode: harness::Mode::Both,
            run_level: 5,
            run_control: harness::Control::C06Main,
            hard_negatives: None,
            observer_uid: None,
            blind_dir: None,
            run_id: None,
            target_cmd: None,
            runs: None,
            pick: None,
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
            push("-d", Some(json::u64_str(self.duration as u64).as_bytes()));
        }
        if !self.mem {
            push("--no-mem", None);
        }
        if self.mem_cap_mb > 0 {
            push("--mem-cap", Some(json::u64_str(self.mem_cap_mb).as_bytes()));
        }
        if let Some(kb) = self.mem_target_kb {
            push("--mem-target", Some(json::u64_str(kb as u64).as_bytes()));
        }
        if let Some(mb) = self.phys_cap {
            push("--phys-cap", Some(json::u64_str(mb).as_bytes()));
        }
        if let Some(mb) = self.disk_mb {
            push("--disk", Some(json::u64_str(mb).as_bytes()));
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
            push("--cpu", Some(json::u64_str(pct as u64).as_bytes()));
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
  psgen profile [options]       capture a live process profile or validate JSON
  psgen run [options]           build a reproducible blind evaluation bundle
  psgen score <run-dir> [opts]  score one or more blind evaluation picks
  psgen replay <run-dir> [opts] deterministically rescore an archived run
  psgen verify <run-dir> [opts] verify manifest, schema, hygiene and replay
  psgen selftest [--out DIR]    run planted-defect and discrimination guards

COMMON
  -n, --count N       rows or commands (list: all templates, table: 30,
                      table --live: all, inject: 12). A count is met by
                      repeating rows a real host runs more than once; a
                      request that cannot be met at all prints a warning.
  -s, --seed N        fix the selection and jitter; START and TIME still
                      follow the wall clock
  -p, --profile NAME  server (default), dev, desktop; weights which templates
                      `list`, `table` and `inject` draw. `list` sorts its lines
                      by default and `--no-sort` keeps draw order.
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
                        directory patterns the run would create (`<pid>` and
                        `<i>` are filled at spawn). It exits non-zero for
                        every preflight the real run would refuse.
      --json            with --dry-run, print the plan as one JSON object; an
                        alternative to --plan, not a companion
      --table           after spawning, print the real ps aux table for the stubs
      --verify          compare each stub's real VSZ/RSS with the planned
                        value within 128 kB; has no effect with --no-mem
      --wait            block for a non-zero --duration, then stop the stubs
      --elevate         re-exec through sudo -n when not already root
  -q, --quiet           suppress the inject summary
      --from-profile FILE  spawn matched live decoy trees from profile JSON
      --decoy-level N      decoy fidelity level 1..6 (default 5)
      --clean-env          memfd-name auth, no PSGEN_NONCE
      --exe-memfd          re-exec via memfd_create + execveat
      --decoy-token PREFIX decoy token prefix for memory scans
      --dumpable N         PR_SET_DUMPABLE override (0 or 1)
      --seccomp N          install N benign seccomp filters (0..8)
      --wchan MODE         pause, epoll, poll, nanosleep, futex or read
      --jitter-ms MS       startup jitter ceiling in ms
      --churn N            short-lived churn workers
      --masker-cmd CMD     spawn decoys via external masker command

CORPUS AND CHECK
      --binaries        report which template executables exist on this host
      --require-binaries  like --binaries, but exit 1 when any is missing
  --host-mem MiB      generate for a host with this much memory instead of this
                      one (table)
  --host-pid-max N    generate for a host whose pid_max is N (table); PID 1
                      is still shown, and the capacity below 3 is zero rows
                      beside it
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
  --no-tty, --no-threads, --no-exe, --shadow-dir, --cpu, --busy, --verify,
  --create-users), caps -n at the inject cap of 500, and keeps its
  RuntimeDirectory across a stop (RuntimeDirectoryPreserve=yes) so another
  unit in the same directory is unaffected; the stop command removes this
  unit's pidfile so the service can start again. --count, --seed and
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
      --lines N       events to write (default 20, must be at least 1, capped
                      at 200000); a weblog burst can produce multiple rows per
                      event
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

PROFILE
      --pid PID / --validate FILE / --out FILE / --tree
      --label STR / --masker STR / --profile-name STR
      --redact-token STR / --redact-env VAR

RUN
      --profile FILE / --out DIR / --decoys N / --seed N
      --mode MODE / --level N / --control ID / --hard-negatives SET
      --observer-uid UID / --blind-dir DIR / --run-id STR / --decoy-token PREFIX
      --live / --target-pid PID / --target-cmd CMD / --masker-cmd CMD
      --jitter-ms MS / --churn N

SCORE, REPLAY, VERIFY AND SELFTEST
      --runs DIRS / --pick FILE / --out FILE / --redact-token STR
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
        b"profile" => Sub::Profile,
        b"run" => Sub::Run,
        b"score" => Sub::Score,
        b"replay" => Sub::Replay,
        b"verify" => Sub::Verify,
        b"selftest" => Sub::Selftest,
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

#[inline(never)]
fn opt_of(needle: &[u8]) -> Option<OptRow> {
    for (spec, &(id, boolean, subs)) in OPT_NAMES.split('|').zip(OPT_META.iter()) {
        let (name, alias) = spec.split_once(',').unwrap_or((spec, ""));
        if name.as_bytes() == needle || (!alias.is_empty() && alias.as_bytes() == needle) {
            return Some(OptRow {
                id,
                name,
                #[cfg(test)]
                alias,
                boolean,
                subs,
            });
        }
    }
    None
}

#[cfg(test)]
fn all_opts() -> Vec<OptRow> {
    let specs: Vec<&str> = OPT_NAMES.split('|').collect();
    assert_eq!(specs.len(), OPT_META.len());
    specs
        .into_iter()
        .zip(OPT_META.iter())
        .map(|(spec, &(id, boolean, subs))| {
            let (name, alias) = spec.split_once(',').unwrap_or((spec, ""));
            OptRow {
                id,
                name,
                alias,
                boolean,
                subs,
            }
        })
        .collect()
}

#[inline(never)]
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
#[cfg_attr(test, derive(Debug))]
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

impl ParseError {
    pub fn as_str(&self) -> &str {
        match self {
            ParseError::Static(s) => s,
            ParseError::Owned(s) => s.as_str(),
        }
    }
}

#[cfg(test)]
impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
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
        Sub::Profile => "profile",
        Sub::Run => "run",
        Sub::Score => "score",
        Sub::Replay => "replay",
        Sub::Verify => "verify",
        Sub::Selftest => "selftest",
        Sub::Help => "help",
        Sub::Version => "version",
    }
}

fn req_utf8(v: &[u8], name: &str) -> Result<String, ParseError> {
    core::str::from_utf8(v)
        .map(String::from)
        .map_err(|_| json::cat2("invalid ", name).into())
}

fn req_num(
    v: &[u8],
    name: &str,
    lo: u64,
    hi: u64,
    range_err: &'static str,
) -> Result<u64, ParseError> {
    let n = str::parse_u64(v).ok_or_else(|| json::cat2("invalid ", name))?;
    if n < lo || n > hi {
        return Err(if range_err.is_empty() {
            json::cat2("invalid ", name).into()
        } else {
            range_err.into()
        });
    }
    Ok(n)
}

fn err_unknown_val(flag: &str, v: &[u8], suffix: &str) -> ParseError {
    let mut s = String::with_capacity(64);
    s.push_str("unknown ");
    s.push_str(flag);
    s.push(' ');
    json::push_escaped_str(&String::from_utf8_lossy(v), &mut s);
    s.push_str(suffix);
    ParseError::Owned(s)
}

/// Whether `sub` consumes the option `name` (canonical long form).
fn applies(sub: Sub, name: &str) -> bool {
    match opt_of(name.as_bytes()) {
        Some(o) => o.subs & sub.bit() != 0,
        None => false,
    }
}

#[inline(never)]
fn set_opt_str(slot: &mut Option<String>, v: &[u8], name: &str) -> Result<(), ParseError> {
    *slot = Some(req_utf8(v, name)?);
    Ok(())
}

#[inline(never)]
fn apply_opt(a: &mut Args, opt: &OptRow, v: &[u8]) -> Result<(), ParseError> {
    const UMAX: u64 = usize::MAX as u64;
    const U32M: u64 = u32::MAX as u64;
    let name = opt.name;
    match opt.id {
        OptId::Help => a.want_help = true,
        OptId::Version => a.want_version = true,
        OptId::Local => a.local = true,
        OptId::Sort => a.sort = true,
        OptId::NoSort => a.sort = false,
        OptId::Uniq => a.uniq = true,
        OptId::NoUniq => a.uniq = false,
        OptId::Mem => a.mem = true,
        OptId::NoMem => a.mem = false,
        OptId::Tty => a.tty = true,
        OptId::NoTty => a.tty = false,
        OptId::Threads => a.threads = true,
        OptId::NoThreads => a.threads = false,
        OptId::User => a.user = true,
        OptId::NoUser => a.user = false,
        OptId::CreateUsers => a.create_users = true,
        OptId::Busy => a.busy = true,
        OptId::DryRun => a.dry_run = true,
        OptId::Plan => a.plan = true,
        OptId::Wait => a.wait = true,
        OptId::Binaries => a.binaries = true,
        OptId::RequireBinaries => {
            a.binaries = true;
            a.require_binaries = true;
        }
        OptId::Elevate => a.elevate = true,
        OptId::Table => a.table = true,
        OptId::Live => a.live = true,
        OptId::Force => a.force = true,
        OptId::Verify => a.verify = true,
        OptId::Exe => a.no_exe = false,
        OptId::NoExe => a.no_exe = true,
        OptId::NoRoot => a.no_root = true,
        OptId::Json => a.json = true,
        OptId::Quiet => a.quiet = true,
        OptId::Tree => a.tree = true,
        OptId::CleanEnv => a.clean_env = true,
        OptId::ExeMemfd => a.exe_memfd = true,
        OptId::Label => set_opt_str(&mut a.label, v, name)?,
        OptId::Masker => set_opt_str(&mut a.masker, v, name)?,
        OptId::ProfileName => set_opt_str(&mut a.profile_name, v, name)?,
        OptId::DecoyToken => set_opt_str(&mut a.decoy_token, v, name)?,
        OptId::MaskerCmd => set_opt_str(&mut a.masker_cmd, v, name)?,
        OptId::RunId => set_opt_str(&mut a.run_id, v, name)?,
        OptId::TargetCmd => set_opt_str(&mut a.target_cmd, v, name)?,
        OptId::Runs => set_opt_str(&mut a.runs, v, name)?,
        OptId::Pick => set_opt_str(&mut a.pick, v, name)?,
        OptId::Validate => a.validate_file = Some(v.to_vec()),
        OptId::Out => a.out_path = Some(v.to_vec()),
        OptId::FromProfile => a.from_profile = Some(v.to_vec()),
        OptId::BlindDir => a.blind_dir = Some(v.to_vec()),
        OptId::Pidfile => a.pidfile = Some(abs_path(v)),
        OptId::ShadowDir => a.shadow_dir = Some(abs_path(v)),
        OptId::Profile => a.profile = v.to_vec(),
        OptId::Module => a.log_module = v.to_vec(),
        OptId::RedactToken => a.redact_tokens.push(req_utf8(v, name)?),
        OptId::RedactEnv => a.redact_envs.push(req_utf8(v, name)?),
        OptId::Family => {
            a.family = Some(corpus::family_id(v).ok_or_else(|| {
                err_unknown_val("--family", v, "; see `--help` for the accepted set")
            })?);
        }
        OptId::LogFmt => {
            a.log_fmt = Some(loggen::Format::parse(v).ok_or_else(|| {
                err_unknown_val("--log-fmt", v, "; expected apache, json or syslog")
            })?);
        }
        OptId::UtcOffset => {
            let m = str::parse_i64(v).ok_or("invalid --utc-offset")?;
            if !(-1440..=1440).contains(&m) {
                return Err("--utc-offset must be -1440..1440".into());
            }
            a.offset_min = m;
        }
        OptId::Wchan => {
            let s = req_utf8(v, name)?;
            a.wchan =
                Some(inject::parse_wchan_mode(&s).ok_or(
                    "invalid --wchan; expected pause, epoll, poll, nanosleep, futex or read",
                )?);
        }
        OptId::Mode => a.run_mode = harness::Mode::parse(&req_utf8(v, name)?)?,
        OptId::Control => a.run_control = harness::Control::parse(&req_utf8(v, name)?)?,
        OptId::HardNegatives => {
            a.hard_negatives = Some(harness::HardNeg::parse_list(&req_utf8(v, name)?)?);
        }
        OptId::Count => a.count = req_num(v, name, 0, UMAX, "")? as usize,
        OptId::Decoys => a.decoys = req_num(v, name, 0, UMAX, "")? as usize,
        OptId::RepeatMax => a.repeat_max = Some(req_num(v, name, 0, UMAX, "")? as usize),
        OptId::Lines => {
            a.log_lines = req_num(v, name, 1, UMAX, "--lines must be at least 1")? as usize
        }
        OptId::Duration => a.duration = req_num(v, name, 0, U32M, "")? as u32,
        OptId::JitterMs => a.jitter_ms = req_num(v, name, 0, U32M, "")? as u32,
        OptId::Churn => a.churn = req_num(v, name, 0, U32M, "")? as u32,
        OptId::MemTarget => a.mem_target_kb = Some(req_num(v, name, 0, U32M, "")? as u32),
        OptId::ObserverUid => a.observer_uid = Some(req_num(v, name, 0, U32M, "")? as u32),
        OptId::Seed => a.seed = Some(req_num(v, name, 0, u64::MAX, "")?),
        OptId::MemCap => a.mem_cap_mb = req_num(v, name, 0, u64::MAX, "")?,
        OptId::PhysCap => a.phys_cap = Some(req_num(v, name, 0, u64::MAX, "")?),
        OptId::Delay => a.log_delay_ms = req_num(v, name, 0, u64::MAX, "")?,
        OptId::DiskUtil => a.load_disk = Some(req_num(v, name, 0, u64::MAX, "")?),
        OptId::Disk => a.disk_mb = Some(req_num(v, name, 0, U32M / 1024, "")?),
        OptId::Pid | OptId::TargetPid => {
            a.target_pid = Some(req_num(v, name, 1, i32::MAX as u64, "")? as i32)
        }
        OptId::Cpu => a.cpu_pct = Some(req_num(v, name, 0, 100, "--cpu must be 0..100")? as u32),
        OptId::Speed => a.speed = req_num(v, name, 1, u64::MAX, "--speed must be at least 1")?,
        OptId::CpuUtil => {
            a.load_cpu = Some(req_num(v, name, 0, 100, "--cpu-util must be 0..100")? as u32)
        }
        OptId::MemUtil => {
            a.load_mem = Some(req_num(v, name, 0, 95, "--mem-util must be 0..95")? as u32)
        }
        OptId::HostMem => {
            a.host_mem_mb = Some(req_num(
                v,
                name,
                1,
                u64::MAX,
                "--host-mem must be at least 1 MiB",
            )?)
        }
        OptId::HostPidMax => {
            a.host_pid_max = Some(req_num(
                v,
                name,
                1,
                u64::MAX,
                "--host-pid-max must be at least 1",
            )?)
        }
        OptId::HostUptime => {
            a.host_uptime = Some(req_num(
                v,
                name,
                1,
                u64::MAX,
                "--host-uptime must be at least 1",
            )?)
        }
        OptId::DecoyLevel => {
            a.decoy_level = Some(req_num(v, name, 1, 6, "--decoy-level must be 1..6")? as u8)
        }
        OptId::Dumpable => {
            a.dumpable = Some(req_num(v, name, 0, 1, "--dumpable must be 0 or 1")? as u8)
        }
        OptId::Seccomp => a.seccomp = Some(req_num(v, name, 0, 8, "--seccomp must be 0..8")? as u8),
        OptId::Level => a.run_level = req_num(v, name, 1, 6, "--level must be 1..6")? as u8,
    }
    Ok(())
}

#[inline(never)]
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
            if inline.is_some() && matches!(name, b"-V" | b"--version") {
                return Err("this option does not take a value".into());
            }
            match name {
                b"--flame" => {
                    return Err(
                        "--flame is not supported (it was an alias in an older draft); use `psgen load --cpu-util`"
                            .into(),
                    );
                }
                b"-V" | b"--version" => {
                    a.want_version = true;
                    a.seen.push("--version");
                }
                _ => {
                    let opt = opt_of(name).ok_or("unknown option")?;
                    if inline.is_some() && opt.boolean {
                        return Err("this option does not take a value".into());
                    }
                    a.seen.push(opt.name);
                    let val: &[u8] = if opt.boolean {
                        b""
                    } else {
                        take_value(args, &mut i, inline)
                            .ok_or_else(|| json::cat2("missing value for ", opt.name))?
                    };
                    apply_opt(&mut a, &opt, val)?;
                }
            }
        } else if !saw_sub {
            if !set_sub(&mut a, arg) {
                return Err("unknown subcommand".into());
            }
            saw_sub = true;
        } else if matches!(a.sub, Sub::Score | Sub::Replay | Sub::Verify) && a.run_dir.is_none() {
            a.run_dir = Some(arg.clone());
        } else {
            return Err("unexpected argument".into());
        }
        i += 1;
    }
    if a.want_help || a.want_version || a.sub == Sub::Help || a.sub == Sub::Version {
        a.sub = if a.want_version || a.sub == Sub::Version {
            Sub::Version
        } else {
            Sub::Help
        };
        return Ok(a);
    }
    for name in &a.seen {
        if !applies(a.sub, name) {
            return Err(json::cat3(name, " does not apply to ", sub_name(a.sub)).into());
        }
    }
    if a.sub != Sub::Run
        && a.seen.contains(&"--profile")
        && a.profile != b"server"
        && a.profile != b"dev"
        && a.profile != b"desktop"
    {
        return Err(err_unknown_val(
            "--profile",
            &a.profile,
            "; expected server, dev or desktop",
        ));
    }
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

fn reject_if_seen(a: &Args, name: &str, why: &str) -> Result<(), ParseError> {
    if a.seen.contains(&name) {
        Err(json::cat3(name, " ", why).into())
    } else {
        Ok(())
    }
}

fn reject_csv(a: &Args, names_csv: &str, why: &str) -> Result<(), ParseError> {
    for name in names_csv.split(',') {
        reject_if_seen(a, name, why)?;
    }
    Ok(())
}

/// Reject an option the chosen mode cannot act on.
#[inline(never)]
fn forbid(a: &Args) -> Result<(), ParseError> {
    if a.sub == Sub::Table && a.live {
        reject_csv(
            a,
            "--local,--utc-offset,--profile,--family,--seed,--repeat-max,--host-mem,--host-pid-max,--host-uptime",
            "does not apply to table --live: the table is this host's own, not a generated one",
        )?;
    }
    if a.sub == Sub::Inject {
        reject_csv(
            a,
            "--local,--utc-offset",
            "does not apply to inject: the only table it renders is a live one",
        )?;
        match run_mode(a) {
            Run::Dry => {
                const DRY_REJECT: &str = "\
--table|needs a real spawn; use --plan to see the rows a run would create\n\
--verify|compares each stub's /proc with the plan; nothing is spawned with --dry-run\n\
--wait|waits for a spawned run; nothing is spawned with --dry-run\n\
--elevate|does not apply with --dry-run: a preview never elevates\n\
--quiet|suppresses the spawn summary, which a preview does not print";
                for line in DRY_REJECT.lines() {
                    if let Some((flag, why)) = line.split_once('|') {
                        reject_if_seen(a, flag, why)?;
                    }
                }
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
        if a.from_profile.is_some() && a.masker_cmd.is_some() {
            return Err("--from-profile and --masker-cmd are mutually exclusive".into());
        }
        if a.from_profile.is_none() {
            reject_csv(
                a,
                "--decoy-level,--clean-env,--exe-memfd,--dumpable,--seccomp,--wchan",
                "requires --from-profile",
            )?;
            if a.masker_cmd.is_none() {
                reject_csv(
                    a,
                    "--decoy-token,--jitter-ms,--churn",
                    "requires --from-profile or --masker-cmd",
                )?;
            }
        }
        if (a.from_profile.is_some() || a.masker_cmd.is_some()) && a.dry_run {
            return Err("--dry-run does not apply with --from-profile or --masker-cmd".into());
        }
    }
    if a.sub == Sub::Stop && a.plan && a.elevate {
        return Err(
            "--elevate does not apply with --plan: a plan never elevates, so it would report \
             a verdict the real run cannot reach"
                .into(),
        );
    }
    if a.sub == Sub::Profile {
        if a.target_pid.is_some() && a.validate_file.is_some() {
            return Err("--pid and --validate are mutually exclusive".into());
        }
        if a.target_pid.is_none() && a.validate_file.is_none() {
            return Err("profile requires --pid or --validate".into());
        }
        if a.validate_file.is_some() {
            reject_csv(
                a,
                "--tree,--label,--masker,--profile-name,--redact-env,--out",
                "does not apply with --validate",
            )?;
        }
    }
    if a.sub == Sub::Run {
        if !a.seen.contains(&"--profile") {
            return Err("run requires --profile".into());
        }
        if a.out_path.is_none() {
            return Err("run requires --out".into());
        }
        if a.target_pid.is_some() && a.target_cmd.is_some() {
            return Err("--target-pid and --target-cmd are mutually exclusive".into());
        }
    }
    if a.sub == Sub::Score {
        if a.run_dir.is_some() && a.runs.is_some() {
            return Err("use either <run-dir> or --runs, not both".into());
        }
        if a.run_dir.is_none() && a.runs.is_none() {
            return Err("score requires <run-dir> or --runs".into());
        }
        let _ = parse_score_pairs(a)?;
    }
    if a.sub == Sub::Replay {
        if a.run_dir.is_none() {
            return Err("replay requires <run-dir>".into());
        }
        if a.pick.is_none() {
            return Err("replay requires --pick".into());
        }
    }
    if a.sub == Sub::Verify && a.run_dir.is_none() {
        return Err("verify requires <run-dir>".into());
    }
    Ok(())
}

#[inline(never)]
fn split_csv_paths(raw: &str) -> Vec<PathBuf> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn parse_score_pairs(a: &Args) -> Result<Vec<(PathBuf, PathBuf)>, ParseError> {
    if let Some(ref rd) = a.run_dir {
        let dir = PathBuf::from(OsStr::from_bytes(rd));
        let pick = match &a.pick {
            Some(p) => PathBuf::from(p),
            None => dir.join("pick.json"),
        };
        return Ok(vec![(dir, pick)]);
    }
    let runs_raw = a
        .runs
        .as_deref()
        .ok_or("score requires <run-dir> or --runs")?;
    let dirs = split_csv_paths(runs_raw);
    if dirs.is_empty() {
        return Err("--runs must list at least one run directory".into());
    }
    let picks: Vec<PathBuf> = match &a.pick {
        None => dirs.iter().map(|d| d.join("pick.json")).collect(),
        Some(raw) => {
            let list = split_csv_paths(raw);
            if list.len() != dirs.len() {
                return Err("--pick count must match --runs count".into());
            }
            list
        }
    };
    Ok(dirs.into_iter().zip(picks).collect())
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
    let probe = sys::run_cmd(b"sudo", &[b"sudo", b"-n", b"true"], None, false);
    if !matches!(probe, Ok((0, _))) {
        sys::err(b"psgen: sudo -n is not available; continuing unprivileged\n");
        return None;
    }
    let self_b = self_exe.as_os_str().as_bytes();
    let mut cmd_argv: Vec<&[u8]> = Vec::with_capacity(argv.len() + 2);
    cmd_argv.push(b"sudo");
    cmd_argv.push(b"-n");
    cmd_argv.push(self_b);
    for a in argv.iter().skip(1) {
        if a == b"--elevate" {
            continue;
        }
        cmd_argv.push(a.as_slice());
    }
    match sys::run_cmd(b"sudo", &cmd_argv, None, false) {
        Ok((code, _)) => Some(code),
        Err(e) => {
            let mut out = Buf::new();
            out.push_str("psgen: cannot run sudo: ");
            out.push_str(&std::io::Error::from_raw_os_error(e).to_string());
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
        if c.memfd_untested {
            sys::err(
                b"psgen: the capability probe could not fork, so memfd_create is untested; the arena may fall back to an unlinked temp file and the run will refuse if a stub config needs a memfd\n",
            );
        } else {
            sys::err(
                b"psgen: memfd_create denied; the arena falls back to an unlinked temp file, but a stub config cannot, so the run will refuse when it reaches the config\n",
            );
        }
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

/// Whether physical cost and budget should be printed in KiB instead of MiB so
/// an over-budget summary does not truncate both numbers to the same MiB.
fn phys_uses_kib(est_kb: u64, budget_kb: u64) -> bool {
    budget_kb > 0 && est_kb > budget_kb && est_kb / 1024 == budget_kb / 1024
}

#[inline(never)]
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
        let show_kib = phys_uses_kib(prep.phys_estimate_kb, prep.phys_budget_kb);
        out.push_str("reported RSS is shared; estimated physical cost ");
        if show_kib {
            out.push_u64(prep.phys_estimate_kb);
            out.push_str(" KiB");
        } else {
            out.push_u64(prep.phys_estimate_kb / 1024);
            out.push_str(" MiB");
        }
        if prep.phys_scale < 1.0 {
            out.push_str(", scaled to fit the physical budget");
            if prep.phys_budget_kb > 0 {
                out.push_str(" of ");
                if show_kib {
                    out.push_u64(prep.phys_budget_kb);
                    out.push_str(" KiB");
                } else {
                    out.push_u64(prep.phys_budget_kb / 1024);
                    out.push_str(" MiB");
                }
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
    pidfile_error_bytes(path, probe::PIDFILE_PENDING_BYTES)
}

fn pidfile_error_bytes(path: &[u8], bytes: usize) -> Buf {
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
        } else if probe::pidfile_creatable_errno_bytes(path, bytes) == libc::EFBIG {
            // The one failure a writable parent does not explain. Naming the
            // limit is the difference between a fixable setting and a mystery.
            out.push_str(" is writable but RLIMIT_FSIZE is too small for the pidfile");
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

/// Refuse to overwrite a pidfile that still records live stubs or cannot be
/// read. Returns `true` when the pidfile is absent or has zero live rows.
fn check_pidfile_inactive(p: &[u8]) -> bool {
    match inject::live_pidfile_rows(p) {
        Some(0) => true,
        Some(_) => {
            let mut out = Buf::new();
            out.push_str("psgen: the pidfile ");
            out.push_bytes(p);
            out.push_str(" records live processes; stop them first or choose another --pidfile\n");
            sys::err(out.as_bytes());
            false
        }
        None => {
            let mut out = Buf::new();
            out.push_str("psgen: cannot read the existing pidfile ");
            out.push_bytes(p);
            out.push_str("; remove it or choose another --pidfile\n");
            sys::err(out.as_bytes());
            false
        }
    }
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
        // One line per template in scope. An explicit `-p` makes the zero
        // weight of a family a statement about the host, and a template in
        // that family is not in scope; an explicit `-f` stays an override.
        let weights = corpus::profile_weights(&args.profile);
        corpus::CORPUS
            .iter()
            .filter(|t| match args.family {
                Some(f) => t.fam == f,
                None => weights[t.fam as usize] != 0,
            })
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

/// Say so when a request cannot be met at all.
///
/// A table that repeats a row a real host runs several times is not a
/// shortfall: the count is honoured, and `F_REPEAT` marks the templates that may
/// contribute more than one row. What a caller does need to hear is the case
/// where even that cannot reach the number, which happens for a family whose
/// templates all run once and cannot vary (`list -f mail -n 50`).
fn shortfall(
    family: Option<u8>,
    got: usize,
    want: usize,
    list: bool,
    reason: Option<&str>,
    distinct: u64,
) {
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
    // the same run refuses (issue #9b). `--no-uniq` does not invent new
    // command lines: it repeats the lines the templates already produced, so
    // the warning quotes the distinct supply instead of promising padding
    // that does not exist.
    if list {
        out.push_str("; a list never repeats a command (");
        out.push_u64(distinct);
        out.push_str(if distinct == 1 {
            " distinct line"
        } else {
            " distinct lines"
        });
        out.push_str(" can be produced; --no-uniq pads by repeating them). Ask for fewer lines.");
    } else {
        out.push_str(". Use --repeat-max N to allow more repeats, or ask for fewer rows.");
    }
    out.push(b'\n');
    sys::err(out.as_bytes());
}

fn json_escape(out: &mut Buf, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'"' => {
                out.push_str("\\\"");
                i += 1;
            }
            b'\\' => {
                out.push_str("\\\\");
                i += 1;
            }
            b'\n' => {
                out.push_str("\\n");
                i += 1;
            }
            b'\r' => {
                out.push_str("\\r");
                i += 1;
            }
            b'\t' => {
                out.push_str("\\t");
                i += 1;
            }
            b if b < 0x20 || b == 0x7f => {
                out.push_str("\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0xf) as usize]);
                i += 1;
            }
            b if b < 0x7f => {
                out.push(b);
                i += 1;
            }
            b => {
                let n = match b {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => 1,
                };
                if n > 1 && i + n <= s.len() && core::str::from_utf8(&s[i..i + n]).is_ok() {
                    out.push_bytes(&s[i..i + n]);
                    i += n;
                } else {
                    out.push_str("\\u00");
                    out.push(HEX[(b >> 4) as usize]);
                    out.push(HEX[(b & 0xf) as usize]);
                    i += 1;
                }
            }
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

/// The staging directory patterns a run would create, in the order `spawn()`
/// creates them on disk: the shadow copy directory first when the tier is
/// shadow, then one per row that needs its own directory.
///
/// `spawn()` builds each leaf from the injector's own PID and a retry index,
/// neither of which exists yet, so the plan prints a pattern with every
/// placeholder named. The parent is real; the leaf is not, and a caller that
/// read the leaf as a path would look for a directory the run never makes.
///
/// The predicate mirrors `spawn()` exactly: a bind-tier row whose template
/// executable is missing needs a directory even without `--disk`, because the
/// stub's exe is written there.
fn staging_patterns(rows: &[gen::Proc], prep: &inject::Prep, args: &Args) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    if prep.tier == inject::ExeTier::Shadow {
        if let Some(root) = &prep.shadow_root {
            let mut p = root.clone();
            if !p.ends_with(b"/") {
                p.push(b'/');
            }
            p.extend_from_slice(b".psgen-<pid>-9000-<i>");
            out.push(p);
        }
    }
    let disk = args.disk_mb.unwrap_or(0) > 0;
    let dir = std::env::temp_dir();
    let mut base = dir.as_os_str().as_bytes().to_vec();
    if base.ends_with(b"/") {
        base.pop();
    }
    for (i, row) in rows.iter().enumerate() {
        let exe = gen::template_exe(&corpus::CORPUS[row.tmpl]);
        let need_exe_dir = prep.tier == inject::ExeTier::Bind
            && !exe.is_empty()
            && !std::path::Path::new(std::ffi::OsStr::from_bytes(&exe)).exists();
        if !disk && !need_exe_dir {
            continue;
        }
        let mut p = base.clone();
        p.extend_from_slice(b"/.psgen-<pid>-");
        let mut b = Buf::new();
        b.push_u64(i as u64);
        p.extend_from_slice(b.as_bytes());
        p.extend_from_slice(b"-<i>");
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
#[inline(never)]
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
    // The plan describes the run that would start, so a host without a pty
    // master says the rows will be detached rather than promising a terminal
    // the run cannot give them.
    out.push_str(if !args.tty {
        "off"
    } else if prep.caps.pty {
        "on"
    } else {
        "unavailable on this host"
    });
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
    let rss: u64 = rows.iter().map(|p| p.rss).sum();
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
        let show_kib = phys_uses_kib(prep.phys_estimate_kb, prep.phys_budget_kb);
        out.push_str(", ~");
        if show_kib {
            out.push_u64(prep.phys_estimate_kb);
            out.push_str(" KiB physical");
        } else {
            out.push_u64(prep.phys_estimate_kb / 1024);
            out.push_str(" MiB physical");
        }
        if prep.phys_budget_kb > 0 {
            out.push_str(" (budget ");
            if show_kib {
                out.push_u64(prep.phys_budget_kb);
                out.push_str(" KiB)");
            } else {
                out.push_u64(prep.phys_budget_kb / 1024);
                out.push_str(" MiB)");
            }
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
    let dirs = staging_patterns(rows, prep, args);
    out.push_str("; staging ");
    out.push_u64(dirs.len() as u64);
    out.push_str(if dirs.len() == 1 {
        " directory pattern"
    } else {
        " directory patterns"
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
        out.push_u64(p.vsz);
        out.push_str(" rss=");
        out.push_u64(p.rss);
        out.push_str(" cpu=");
        out.push_tenths_plain(p.cpu);
        out.push_str(" tty=");
        out.push_str(
            if p.flags & corpus::F_TTY != 0 && args.tty && prep.caps.pty {
                "yes"
            } else {
                "no"
            },
        );
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
        out.push_str("staging pattern ");
        out.push_bytes(d);
        out.push(b'\n');
    }
    sys::out(out.as_bytes());
}

/// `--dry-run --json`: the same plan as one JSON object.
#[inline(never)]
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
    out.push_str(bool_str(args.tty && prep.caps.pty));
    out.push_str(",\"threads\":");
    out.push_str(bool_str(args.threads));
    out.push_str(",\"busy\":");
    out.push_str(bool_str(args.busy || args.cpu_pct.unwrap_or(0) > 0));
    out.push_str(",\"rss_kb\":");
    out.push_u64(rows.iter().map(|p| p.rss).sum());
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
    let dirs = staging_patterns(rows, prep, args);
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
        out.push_u64(p.vsz);
        out.push_str(",\"rss_kb\":");
        out.push_u64(p.rss);
        out.push_str(",\"cpu_tenths\":");
        out.push_u64(p.cpu as u64);
        out.push_str(",\"tty\":");
        out.push_str(bool_str(
            p.flags & corpus::F_TTY != 0 && args.tty && prep.caps.pty,
        ));
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

fn err_line(msg: &str) -> i32 {
    let mut out = Buf::new();
    out.push_str("psgen: ");
    out.push_str(msg);
    out.push(b'\n');
    sys::err(out.as_bytes());
    1
}

fn write_text_output(out_path: Option<&[u8]>, text: &str) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    match out_path {
        Some(p) => {
            let path = Path::new(OsStr::from_bytes(p));
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    json::mkdir_all(parent)?;
                }
            }
            json::write_file(path, &bytes)
        }
        None => {
            sys::out(&bytes);
            Ok(())
        }
    }
}

fn load_profile_file(path: &[u8], forbidden: &[&str]) -> Result<profile::Profile, String> {
    let p = Path::new(OsStr::from_bytes(path));
    let text = json::read_str(p)?;
    let prof = profile::Profile::parse_str(&text)?;
    prof.validate(forbidden)?;
    Ok(prof)
}

fn apply_decoy_overrides(node: &mut inject::DecoyNodeSpec, args: &Args) {
    if args.exe_memfd {
        node.exe_memfd = true;
        if node.memfd_label.is_empty() {
            node.memfd_label = if node.comm.is_empty() {
                b"worker".to_vec()
            } else {
                node.comm.clone()
            };
        }
    }
    if let Some(d) = args.dumpable {
        node.non_dumpable = d == 0;
    }
    if let Some(sc) = args.seccomp {
        node.seccomp_filters = sc;
        if sc > 0 {
            node.no_new_privs = true;
        }
    }
    if let Some(wc) = args.wchan {
        node.wchan_mode = wc;
    }
    for child in &mut node.children {
        apply_decoy_overrides(child, args);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_decoy_trees(
    prof: &profile::Profile,
    count: usize,
    level: u8,
    token_prefix: Option<&str>,
    force_token: bool,
    jitter_ms: u32,
    seed: u64,
    overrides: Option<&Args>,
) -> Vec<inject::DecoyNodeSpec> {
    let mut rng = Rng::new(seed ^ 0x9e37_79b9_7f4a_7c15);
    let mut trees = Vec::with_capacity(count);
    for _ in 0..count {
        let tok = token_prefix.map(|pfx| inject::make_decoy_token(pfx, &mut rng));
        let mut spec = inject::profile_to_decoy_tree(prof, level, tok.as_deref(), jitter_ms);
        if level >= 6 {
            inject::apply_decoy_mem_jitter(&mut spec, &mut rng);
        }
        if force_token && spec.decoy_token.is_empty() {
            if let Some(ref t) = tok {
                spec.decoy_token = t[..t.len().min(4096)].to_vec();
            }
        }
        if let Some(a) = overrides {
            apply_decoy_overrides(&mut spec, a);
        }
        trees.push(spec);
    }
    trees
}

fn filter_root_pids(pids: &[i32]) -> Vec<i32> {
    let mut roots = Vec::with_capacity(pids.len());
    for &pid in pids {
        let ppid = live::read_stat(pid).map(|s| s.ppid as i32).unwrap_or(0);
        if !pids.contains(&ppid) && !roots.contains(&pid) {
            roots.push(pid);
        }
    }
    roots
}

fn collect_pid_tree(roots: &[i32]) -> Vec<i32> {
    let mut all: Vec<i32> = Vec::with_capacity(roots.len() * 2);
    for &r in roots {
        if r > 1 && !all.contains(&r) {
            all.push(r);
        }
    }
    let mut pairs: Vec<(i32, i32)> = Vec::new();
    if let Ok(pids) = profile::read_numeric_dir("/proc") {
        for pid in pids {
            if let Some(st) = live::read_stat(pid) {
                pairs.push((pid, st.ppid as i32));
            }
        }
    }
    let mut idx = 0;
    while idx < all.len() {
        let cur = all[idx];
        idx += 1;
        for &(pid, ppid) in &pairs {
            if ppid == cur && pid > 1 && !all.contains(&pid) {
                all.push(pid);
            }
        }
    }
    all
}

struct LiveCleanup {
    pids: Vec<i32>,
}

impl LiveCleanup {
    fn new() -> Self {
        Self { pids: Vec::new() }
    }

    fn extend(&mut self, pids: &[i32]) {
        for &p in pids {
            if p > 1 && !self.pids.contains(&p) {
                self.pids.push(p);
            }
        }
    }
}

impl Drop for LiveCleanup {
    fn drop(&mut self) {
        if self.pids.is_empty() {
            return;
        }
        let targets = collect_pid_tree(&self.pids);
        for &pid in &targets {
            sys::kill(-pid, sys::SIGKILL);
            sys::kill(pid, sys::SIGKILL);
        }
        for _ in 0..50 {
            let _ = sys::reap_children_nonblock();
            if !targets.iter().any(|&p| live::alive(p)) {
                break;
            }
            sys::nanosleep(0, 10_000_000);
        }
        let _ = sys::reap_children_nonblock();
    }
}

#[inline(never)]
fn make_gen_opts(
    args: &Args,
    count: usize,
    seed: u64,
    self_user: Vec<u8>,
    repeat_max: Option<usize>,
    uptime: Option<u64>,
) -> Opts {
    Opts {
        count,
        seed,
        profile: args.profile.clone(),
        profile_set: args.seen.contains(&"--profile"),
        family: args.family,
        self_user,
        uniq: args.uniq,
        repeat_max,
        uptime,
    }
}

#[inline(never)]
fn render_live_table(pids: &[i32]) {
    let mut live_rows = live::read_pids(pids);
    json::shell_sort_by(&mut live_rows, |a, b| a.pid > b.pid);
    let out = table::render(
        &live_rows,
        live::mem_total_kb(),
        &table::Clock::live(sys::now_secs()),
        sys::page_kb(),
    );
    sys::out(out.as_bytes());
}

#[inline(never)]
fn acquire_pidfile_lock(p: &[u8]) -> Result<inject::PidfileLock, i32> {
    match inject::lock_pidfile(p) {
        Ok(lock) => Ok(lock),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let mut out = Buf::new();
            out.push_str("psgen: another psgen run holds the pidfile ");
            out.push_bytes(p);
            out.push_str("; wait for it to finish or choose another --pidfile\n");
            sys::err(out.as_bytes());
            Err(2)
        }
        Err(e) => {
            let mut out = Buf::new();
            out.push_str("psgen: cannot lock the pidfile ");
            out.push_bytes(p);
            out.push_str(": ");
            out.push_str(&e.to_string());
            out.push(b'\n');
            sys::err(out.as_bytes());
            Err(2)
        }
    }
}

#[inline(never)]
fn run_profile(args: &Args) -> i32 {
    let forbidden: Vec<&str> = args.redact_tokens.iter().map(String::as_str).collect();
    if let Some(ref file) = args.validate_file {
        let prof = match load_profile_file(file, &forbidden) {
            Ok(p) => p,
            Err(e) => return err_line(&e),
        };
        let mut w = json::Jw::new(false);
        w.obj_open();
        w.k_bool("ok", true);
        w.k_i64("schema", prof.schema as i64);
        w.k_str("comm", &prof.identity.comm);
        w.k_i64("children", prof.children.len() as i64);
        w.obj_close();
        if let Err(e) = write_text_output(None, &w.finish()) {
            return err_line(&e);
        }
        return 0;
    }
    let pid = match args.target_pid {
        Some(p) => p,
        None => return err_line("profile requires --pid or --validate"),
    };
    let mut eopts = profile::ExtractOpts::for_pid(pid);
    eopts.tree = args.tree;
    eopts.label = args.label.clone();
    eopts.masker = args
        .masker
        .clone()
        .unwrap_or_else(|| String::from("unknown"));
    eopts.profile_name = args.profile_name.clone().unwrap_or_else(|| {
        if args.tree {
            String::from("tree")
        } else {
            String::from("single")
        }
    });
    eopts.redact_tokens = args.redact_tokens.clone();
    eopts.redact_envs = args.redact_envs.clone();
    let prof = match profile::extract_live(&eopts) {
        Ok(p) => p,
        Err(e) => return err_line(&e),
    };
    if let Err(e) = prof.validate(&forbidden) {
        return err_line(&e);
    }
    if let Err(e) = write_text_output(args.out_path.as_deref(), &prof.to_json_str(true)) {
        return err_line(&e);
    }
    0
}

fn spawn_masker_tracked(
    cmd: &str,
    count: usize,
    jitter_ms: u32,
    seed: u64,
    tok: Option<&str>,
    cleanup: &mut LiveCleanup,
) -> Result<Vec<i32>, String> {
    let v = inject::spawn_masker_decoys(cmd, count, 300, jitter_ms, seed, tok)?;
    cleanup.extend(&v);
    Ok(v)
}

#[inline(never)]
fn run_harness_inner(args: &Args) -> Result<String, String> {
    let mut prof = load_profile_file(&args.profile, &[])?;
    let out_dir = match &args.out_path {
        Some(p) => PathBuf::from(OsStr::from_bytes(p)),
        None => return Err("run requires --out".to_string()),
    };
    let blind_dir = args
        .blind_dir
        .as_deref()
        .map(|p| PathBuf::from(OsStr::from_bytes(p)));
    let seed = args.seed.unwrap_or(1234);
    let tok_prefix = args.decoy_token.as_deref().unwrap_or("TOK-");
    let hard_negatives = match &args.hard_negatives {
        Some(v) => v.clone(),
        None if args.run_mode == harness::Mode::Table => Vec::new(),
        None => harness::HardNeg::all().to_vec(),
    };

    let wants_target = !matches!(
        args.run_control,
        harness::Control::C02Hidden | harness::Control::C04NoTarget
    );
    let uses_decoys = matches!(
        args.run_control,
        harness::Control::C02Hidden
            | harness::Control::C04NoTarget
            | harness::Control::C06Main
            | harness::Control::C07HiddenByMask
    );

    let mut cleanup = LiveCleanup::new();
    let mut live_target_pids: Vec<i32> = Vec::new();
    let mut live_decoy_pids: Vec<i32> = Vec::new();
    let mut synthetic_decoys = args.decoys;
    let decoy_n = if uses_decoys { args.decoys } else { 0 };
    let eff_jitter =
        if args.jitter_ms == 0 && args.run_level >= 6 && (args.live || args.target_cmd.is_some()) {
            20
        } else {
            args.jitter_ms
        };

    if let Some(ref mcmd) = args.masker_cmd {
        let mut spawn_m =
            |cmd: &str, n: usize, s: u64, tok: Option<&str>| -> Result<Vec<i32>, String> {
                if n == 0 {
                    return Ok(Vec::new());
                }
                spawn_masker_tracked(cmd, n, eff_jitter, s, tok, &mut cleanup)
            };
        let mut all_d = Vec::new();
        if let Some(tcmd) = args.target_cmd.as_deref().filter(|_| wants_target) {
            let pre_n = decoy_n / 2;
            all_d.extend(spawn_m(mcmd, pre_n, seed, Some(tok_prefix))?);
            live_target_pids = spawn_m(tcmd, 1, seed ^ 1, None)?;
            all_d.extend(spawn_m(
                mcmd,
                decoy_n.saturating_sub(pre_n),
                seed ^ 2,
                Some(tok_prefix),
            )?);
        } else {
            if args.target_cmd.is_none() {
                if let Some(tpid) = args.target_pid {
                    live_target_pids.push(tpid);
                }
            }
            all_d = spawn_m(mcmd, decoy_n, seed, Some(tok_prefix))?;
        }
        if !all_d.is_empty() || !live_target_pids.is_empty() {
            sys::nanosleep(0, 150_000_000);
        }
        live_decoy_pids = filter_root_pids(&all_d);
        synthetic_decoys = 0;
    } else {
        let trees = if args.live && decoy_n > 0 {
            let tp = (args.run_level >= 5).then_some(tok_prefix);
            build_decoy_trees(
                &prof,
                decoy_n,
                args.run_level,
                tp,
                false,
                eff_jitter,
                seed,
                None,
            )
        } else {
            Vec::new()
        };
        let spawn_opts = inject::DecoySpawnOpts {
            duration: 300,
            pidfile: None,
            clean_env: true,
            jitter_ms: eff_jitter,
            churn: args.churn,
            seed,
            quiet: true,
            wait: false,
            bind_exe: false,
        };
        if let Some(tcmd) = args.target_cmd.as_ref().filter(|_| wants_target) {
            let mid = trees.len() / 2;
            let (mut pre, tgt, suf) =
                inject::spawn_interleaved_target(&trees[..mid], tcmd, &trees[mid..], &spawn_opts)?;
            cleanup.extend(&pre);
            cleanup.extend(&[tgt]);
            cleanup.extend(&suf);
            sys::nanosleep(0, 150_000_000);
            live_target_pids.push(tgt);
            pre.extend_from_slice(&suf);
            live_decoy_pids = filter_root_pids(&pre);
        } else {
            if args.target_cmd.is_none() {
                if let Some(tpid) = args.target_pid {
                    live_target_pids.push(tpid);
                }
            }
            if !trees.is_empty() {
                let decs = inject::spawn_decoy_trees(&trees, &spawn_opts)?;
                cleanup.extend(&decs);
                live_decoy_pids = filter_root_pids(&decs);
            }
        }
        if args.live {
            synthetic_decoys = 0;
        }
    }

    harness::sanitize_live_profile(&mut prof);
    let run_opts = harness::RunOpts {
        profile: prof,
        decoys: synthetic_decoys,
        seed,
        mode: args.run_mode,
        level: args.run_level,
        control: args.run_control,
        hard_negatives,
        observer_uid: args.observer_uid,
        out_dir,
        blind_dir,
        run_id: args.run_id.clone(),
        live_target_pids,
        live_decoy_pids,
        decoy_token_prefix: tok_prefix.to_string(),
    };

    let res = harness::build_run(&run_opts);
    drop(cleanup);
    let res = res?;

    let mut w = json::Jw::new(false);
    w.obj_open();
    w.k_str("run_id", &res.run_id);
    w.k_str("out_dir", &res.out_dir.to_string_lossy());
    match res.blind_dir {
        Some(ref b) => w.k_str("blind_dir", &b.to_string_lossy()),
        None => w.k_null("blind_dir"),
    }
    w.k_i32_arr("target_pids", &res.target_pids);
    w.k_i64("decoy_count", res.decoy_count as i64);
    w.k_i64("hn_count", res.hn_count as i64);
    w.k_i64("total_rows", res.total_rows as i64);
    w.k_i64("manifest_files", res.manifest_files as i64);
    w.obj_close();
    Ok(w.finish())
}

fn run_harness(args: &Args) -> i32 {
    match run_harness_inner(args).and_then(|s| write_text_output(None, &s)) {
        Ok(()) => 0,
        Err(e) => err_line(&e),
    }
}

#[inline(never)]
fn run_score_or_replay(args: &Args, replay: bool) -> i32 {
    let res = if replay {
        let Some(ref rd) = args.run_dir else {
            return err_line("replay requires <run-dir>");
        };
        let Some(ref pk) = args.pick else {
            return err_line("replay requires --pick");
        };
        score::replay_run(Path::new(OsStr::from_bytes(rd)), Path::new(pk))
    } else {
        match parse_score_pairs(args) {
            Ok(pairs) => score::score_runs(&pairs),
            Err(e) => Err(e.as_str().to_string()),
        }
    };
    match res.and_then(|s| write_text_output(args.out_path.as_deref(), &s)) {
        Ok(()) => 0,
        Err(e) => err_line(&e),
    }
}

#[inline(never)]
fn run_verify(args: &Args) -> i32 {
    let Some(ref rd) = args.run_dir else {
        return err_line("verify requires <run-dir>");
    };
    let pick_path = args.pick.as_deref().map(Path::new);
    let forbidden: Vec<&str> = args.redact_tokens.iter().map(String::as_str).collect();
    let ver = match score::verify_run(Path::new(OsStr::from_bytes(rd)), pick_path, &forbidden) {
        Ok(v) => v,
        Err(e) => return err_line(&e),
    };
    if let Err(e) = write_text_output(None, &ver.json) {
        return err_line(&e);
    }
    i32::from(!ver.ok)
}

#[inline(never)]
fn run_selftest(args: &Args) -> i32 {
    let out_dir = args
        .out_path
        .as_deref()
        .map(|p| Path::new(OsStr::from_bytes(p)));
    let (ok, report) = match selftest::run_selftest(out_dir) {
        Ok(v) => v,
        Err(e) => return err_line(&e),
    };
    if let Err(e) = write_text_output(None, &report) {
        return err_line(&e);
    }
    i32::from(!ok)
}

#[inline(never)]
fn run_inject_decoy(args: &Args) -> i32 {
    if args.count > 500 {
        sys::err(b"psgen: inject count capped at 500\n");
    }
    let count = if args.count == 0 {
        1
    } else {
        args.count.min(500)
    };
    let seed = args.seed.unwrap_or(1234);

    if let Some(ref p) = args.pidfile {
        if !check_pidfile_inactive(p) {
            return 2;
        }
    }
    let _pidfile_lock = match &args.pidfile {
        Some(p) => match acquire_pidfile_lock(p) {
            Ok(lock) => Some(lock),
            Err(code) => return code,
        },
        None => None,
    };
    if let Some(ref p) = args.pidfile {
        if !check_pidfile_inactive(p) {
            return 2;
        }
    }

    let pids = if let Some(ref prof_path) = args.from_profile {
        let prof = match load_profile_file(prof_path, &[]) {
            Ok(p) => p,
            Err(e) => return err_line(&e),
        };
        let level = args.decoy_level.unwrap_or(5);
        let tok_prefix = if args.decoy_token.is_some() || level >= 5 {
            Some(args.decoy_token.as_deref().unwrap_or("TOK-"))
        } else {
            None
        };
        let trees = build_decoy_trees(
            &prof,
            count,
            level,
            tok_prefix,
            args.decoy_token.is_some(),
            args.jitter_ms,
            seed,
            Some(args),
        );
        let opts = inject::DecoySpawnOpts {
            duration: args.duration,
            pidfile: args.pidfile.clone(),
            clean_env: args.clean_env,
            jitter_ms: args.jitter_ms,
            churn: args.churn,
            seed,
            quiet: args.quiet,
            wait: args.wait,
            bind_exe: args.seen.contains(&"--exe") && !args.no_exe && !args.no_root,
        };
        match inject::spawn_decoy_trees(&trees, &opts) {
            Ok(v) => v,
            Err(e) => return err_line(&e),
        }
    } else if let Some(ref mcmd) = args.masker_cmd {
        let spawned = match inject::spawn_masker_decoys(
            mcmd,
            count,
            args.duration,
            args.jitter_ms,
            seed,
            args.decoy_token.as_deref(),
        ) {
            Ok(v) => v,
            Err(e) => return err_line(&e),
        };
        if let Some(ref pf) = args.pidfile {
            sys::nanosleep(0, 50_000_000);
            let all_pids = collect_pid_tree(&spawned);
            if !inject::write_external_pidfile(pf, &all_pids) {
                return err_line("cannot write pidfile");
            }
        }
        if args.wait && args.duration > 0 && !spawned.is_empty() {
            let mut guard = LiveCleanup::new();
            guard.extend(&spawned);
            sys::nanosleep(args.duration as u64, 0);
            drop(guard);
        }
        spawned
    } else {
        return err_line("internal error: missing decoy source");
    };

    if pids.is_empty() {
        return err_line("no processes were spawned");
    }

    if !args.quiet {
        let mut out = Buf::new();
        out.push_str("spawned ");
        out.push_u64(pids.len() as u64);
        out.push_str(" processes");
        if let Some(ref path) = args.pidfile {
            out.push_str(", pids in ");
            out.push_bytes(path);
        }
        out.push(b'\n');
        if args.table {
            sys::err(out.as_bytes());
        } else {
            sys::out(out.as_bytes());
        }
    }

    if args.table {
        render_live_table(&pids);
    }
    0
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
            out.push_str(msg.as_str());
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
        Sub::Profile => run_profile(&args),
        Sub::Run => run_harness(&args),
        Sub::Score => run_score_or_replay(&args, false),
        Sub::Replay => run_score_or_replay(&args, true),
        Sub::Verify => run_verify(&args),
        Sub::Selftest => run_selftest(&args),
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
            let opts = make_gen_opts(
                &args,
                0,
                args.seed.unwrap_or(1),
                b"deploy".to_vec(),
                None,
                None,
            );
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
            let opts = make_gen_opts(
                &args,
                list_target(&args),
                args.seed.unwrap_or(0),
                util::current_user().name,
                args.repeat_max,
                args.host_uptime,
            );
            let mut cmds = gen::gen_list(&mut rng, &opts);
            if lists_count(&args) {
                let want = if args.count == 0 {
                    list_target(&args)
                } else {
                    args.count.min(2000)
                };
                shortfall(
                    args.family,
                    cmds.len(),
                    want,
                    true,
                    None,
                    gen::distinct_supply(
                        args.family,
                        &corpus::profile_weights(&args.profile),
                        args.seen.contains(&"--profile"),
                    ),
                );
            }
            if args.sort {
                json::shell_sort_by(&mut cmds, |a, b| a > b);
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
            let want = if args.count == 0 {
                30
            } else {
                args.count.min(5000)
            };
            let opts = make_gen_opts(
                &args,
                want,
                args.seed.unwrap_or(0),
                util::current_user().name,
                args.repeat_max,
                args.host_uptime,
            );
            let fit = gen::Fit::target(args.host_mem_mb, args.host_pid_max);
            let rows = gen::gen_table(&mut rng, &opts, &fit);
            let has_init = rows.iter().any(|r| r.pid == 1);
            shortfall(
                args.family,
                rows.len(),
                want,
                false,
                fit.shortfall_reason_for(rows.len(), want, has_init)
                    .as_deref(),
                gen::distinct_supply(
                    args.family,
                    &corpus::profile_weights(&args.profile),
                    args.seen.contains(&"--profile"),
                ),
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
            if args.from_profile.is_some() || args.masker_cmd.is_some() {
                return run_inject_decoy(&args);
            }
            if args.count > 500 {
                sys::err(b"psgen: inject count capped at 500\n");
            }
            let me = users::current();
            let mut rng = match args.seed {
                Some(s) => Rng::new(s),
                None => Rng::from_entropy(),
            };
            let want = if args.count == 0 {
                12
            } else {
                args.count.min(500)
            };
            let opts = make_gen_opts(
                &args,
                want,
                args.seed.unwrap_or(0),
                me.name,
                args.repeat_max,
                args.host_uptime,
            );
            let mut rows = gen::gen_inject(&mut rng, &opts, &gen::Fit::none());

            // A preview never creates `<pidfile>.lock`, but if another run
            // already holds it, refuse with exit 2 just like a real run would.
            if args.dry_run {
                if let Some(p) = &args.pidfile {
                    if inject::pidfile_lock_held(p) {
                        let mut out = Buf::new();
                        out.push_str("psgen: another psgen run holds the pidfile ");
                        out.push_bytes(p);
                        out.push_str("; wait for it to finish or choose another --pidfile\n");
                        sys::err(out.as_bytes());
                        return 2;
                    }
                }
            }

            // Preflight the pidfile before spawning, proving space and
            // RLIMIT_FSIZE for the estimated real body rather than only the
            // pending header. The same check runs under --dry-run so a plan
            // fails for a command line the real run would refuse.
            let mut blockers = 0usize;
            let tmpdir_len = std::env::temp_dir().as_os_str().as_bytes().len();
            let mut probed_bytes = 0usize;
            if let Some(p) = &args.pidfile {
                let init_temps = if args.disk_mb.unwrap_or(0) > 0 {
                    rows.len()
                } else {
                    0
                };
                let need_bytes =
                    inject::estimated_pidfile_bytes(rows.len(), init_temps, tmpdir_len);
                probed_bytes = need_bytes;
                if !probe::pidfile_creatable_bytes(p, need_bytes) {
                    let mut out = pidfile_error_bytes(p, need_bytes);
                    // Suggest a writable path without writing to the
                    // candidate path.
                    for cand in [
                        std::env::temp_dir().join("psgen-pids.txt"),
                        std::path::PathBuf::from("psgen-pids.txt"),
                    ] {
                        let b = cand.as_os_str().as_bytes();
                        if probe::pidfile_creatable_bytes(b, need_bytes) {
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
            shortfall(
                args.family,
                rows.len(),
                want,
                false,
                gen::Fit::none()
                    .shortfall_reason_for(rows.len(), want, false)
                    .as_deref(),
                gen::distinct_supply(
                    args.family,
                    &corpus::profile_weights(&args.profile),
                    args.seen.contains(&"--profile"),
                ),
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

            // A pidfile that still records live stubs cannot be reused: the
            // pending rewrite would erase the only record of the old run, and
            // the old stubs would outlive `stop`. A preview runs the same
            // check, because it describes what a real run would do, and a run
            // against this pidfile would be refused.
            if let Some(p) = &args.pidfile {
                if !check_pidfile_inactive(p) {
                    return 2;
                }
            }

            let prep = inject::prepare(&mut rows, &args, args.create_users && !args.dry_run);

            // Re-check the pidfile size once `prepare()` has resolved the exe
            // tier and staging directory count, in case bind/shadow staging
            // adds `# temp` lines beyond the initial estimate.
            if let Some(p) = &args.pidfile {
                let temps_est = staging_patterns(&rows, &prep, &args).len();
                let dir_len = prep
                    .shadow_root
                    .as_deref()
                    .map_or(tmpdir_len, |s| tmpdir_len.max(s.len()));
                let need_bytes = inject::estimated_pidfile_bytes(rows.len(), temps_est, dir_len);
                if need_bytes > probed_bytes && !probe::pidfile_creatable_bytes(p, need_bytes) {
                    let mut out = pidfile_error_bytes(p, need_bytes);
                    out.push(b'\n');
                    sys::err(out.as_bytes());
                    return 2;
                }
            }

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

            // Serialize the pending write and the final rewrite. The live
            // check above is a read, and two runs that pass it together both
            // rename a file into place; the second erases the first's rows.
            let _pidfile_lock = match &args.pidfile {
                Some(p) => match acquire_pidfile_lock(p) {
                    Ok(lock) => Some(lock),
                    Err(code) => return code,
                },
                None => None,
            };

            // Re-check liveness while holding the lock: another injector could
            // have finished and released the lock between the unlocked preflight
            // check above and `lock_pidfile` here.
            if let Some(p) = &args.pidfile {
                if !check_pidfile_inactive(p) {
                    return 2;
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
                // The file still on disk is the pending header, not a record
                // of this run. Remove it if possible, and always write a
                // recovery sidecar (beside the pidfile, or in TMPDIR if the
                // parent directory is unwritable) carrying the real nonce and
                // `# temp` paths so `psgen stop --pidfile <sidecar>` can stop
                // the run cleanly.
                if let Some(p) = &args.pidfile {
                    let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(p)));
                    if !result.pids.is_empty() {
                        if let Some(sidecar) =
                            inject::write_pid_sidecar(p, &result.pids, &result.temps, &result.nonce)
                        {
                            out.push_str("psgen: the spawned rows are in ");
                            out.push_bytes(&sidecar);
                            out.push_str("; stop them with: psgen stop --pidfile ");
                            out.push_bytes(&sidecar);
                            out.push(b'\n');
                        }
                    }
                }
                sys::err(out.as_bytes());
            }
            let mut code = 0;
            if result.failed > 0
                || result.missing > 0
                || !result.mismatches.is_empty()
                || pidfile_failed
            {
                // A run whose pidfile was not written is not a success even
                // when every stub started: the caller cannot stop them.
                code = 1;
            }

            if args.table {
                render_live_table(&result.pids);
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
        let missing: Vec<&str> = all_opts()
            .into_iter()
            .map(|o| o.name)
            .chain(OPTS_ANCHOR.iter().map(|o| o.name))
            .filter(|n| !help.contains(n))
            .collect();
        assert!(
            missing.is_empty(),
            "OPTS has options the help text never mentions: {missing:?}"
        );
    }

    #[test]
    fn every_option_declares_its_subcommands() {
        for o in all_opts() {
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
        for o in all_opts() {
            if !o.alias.is_empty() {
                let got = opt_of(o.alias.as_bytes()).expect("an alias is in the table");
                assert_eq!(got.name, o.name, "{} does not select {}", o.alias, o.name);
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
        for o in all_opts() {
            assert!(!names.contains(&o.name), "{} appears twice in OPTS", o.name);
            names.push(o.name);
            if !o.alias.is_empty() {
                assert!(
                    !names.contains(&o.alias),
                    "{} appears twice in OPTS",
                    o.alias
                );
                names.push(o.alias);
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

    #[test]
    fn json_escape_preserves_utf8_and_escapes_control_and_invalid_bytes() {
        let mut out = Buf::new();
        json_escape(&mut out, "café 日本語".as_bytes());
        assert_eq!(out.as_bytes(), "\"café 日本語\"".as_bytes());

        let mut out = Buf::new();
        json_escape(&mut out, b"a\"b\\c\nd\re\tf\x01\x7f");
        assert_eq!(out.as_bytes(), br#""a\"b\\c\nd\re\tf\u0001\u007f""#);

        let mut out = Buf::new();
        json_escape(&mut out, b"x\xffy");
        assert_eq!(out.as_bytes(), br#""x\u00ffy""#);
    }

    #[test]
    fn unknown_log_fmt_names_the_value_and_expected_set() {
        let argv = vec![
            b"psgen".to_vec(),
            b"log".to_vec(),
            b"--log-fmt".to_vec(),
            b"bogus".to_vec(),
        ];
        match parse(&argv) {
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("bogus"), "{msg}");
                assert!(msg.contains("apache, json or syslog"), "{msg}");
            }
            Ok(_) => panic!("unknown --log-fmt must be refused"),
        }
    }

    #[test]
    fn phys_uses_kib_only_when_over_budget_in_same_mib() {
        assert!(phys_uses_kib(30 * 1024 + 80, 30 * 1024));
        assert!(!phys_uses_kib(30 * 1024, 30 * 1024));
        assert!(!phys_uses_kib(31 * 1024, 30 * 1024));
        assert!(!phys_uses_kib(29 * 1024, 30 * 1024));
        assert!(!phys_uses_kib(100, 0));
    }

    fn parse_strs(argv: &[&str]) -> Result<Args, ParseError> {
        let argv: Vec<Vec<u8>> = core::iter::once("psgen")
            .chain(argv.iter().copied())
            .map(|s| s.as_bytes().to_vec())
            .collect();
        parse(&argv)
    }

    #[test]
    fn profile_subcommand_flags_and_conflicts() {
        let a = parse_strs(&[
            "profile",
            "--pid",
            "42",
            "--tree",
            "--label",
            "ci-runner",
            "--masker",
            "pmask",
            "--profile-name",
            "tree",
            "--redact-token",
            "SEC1",
            "--redact-token",
            "SEC2",
            "--redact-env",
            "API_KEY",
            "--out",
            "/tmp/p.json",
        ])
        .unwrap();
        assert!(a.sub == Sub::Profile);
        assert_eq!(a.target_pid, Some(42));
        assert!(a.tree);
        assert_eq!(a.label.as_deref(), Some("ci-runner"));
        assert_eq!(a.masker.as_deref(), Some("pmask"));
        assert_eq!(a.profile_name.as_deref(), Some("tree"));
        assert_eq!(a.redact_tokens, vec!["SEC1", "SEC2"]);
        assert_eq!(a.redact_envs, vec!["API_KEY"]);
        assert_eq!(a.out_path.as_deref(), Some(&b"/tmp/p.json"[..]));

        let v = parse_strs(&[
            "profile",
            "--validate",
            "/tmp/p.json",
            "--redact-token",
            "FORBID",
        ])
        .unwrap();
        assert!(v.sub == Sub::Profile);
        assert_eq!(v.validate_file.as_deref(), Some(&b"/tmp/p.json"[..]));
        assert_eq!(v.redact_tokens, vec!["FORBID"]);

        assert!(!ok(&["profile"]));
        assert!(!ok(&["profile", "--pid", "1", "--validate", "/tmp/p.json"]));
        assert!(!ok(&["profile", "--pid", "0"]));
        assert!(!ok(&["profile", "--validate", "/tmp/p.json", "--tree"]));
        assert!(!ok(&["profile", "--pid", "1", "extra-pos"]));
    }

    #[test]
    fn run_subcommand_flags_defaults_and_conflicts() {
        let a = parse_strs(&["run", "--profile", "/tmp/p.json", "--out", "/tmp/run"]).unwrap();
        assert!(a.sub == Sub::Run);
        assert_eq!(a.profile, b"/tmp/p.json");
        assert_eq!(a.out_path.as_deref(), Some(&b"/tmp/run"[..]));
        assert_eq!(a.decoys, 50);
        assert_eq!(a.run_mode, harness::Mode::Both);
        assert_eq!(a.run_level, 5);
        assert_eq!(a.run_control, harness::Control::C06Main);
        assert!(a.hard_negatives.is_none());

        let b = parse_strs(&[
            "run",
            "--profile",
            "/tmp/p.json",
            "--out",
            "/tmp/run",
            "--decoys",
            "12",
            "--seed",
            "999",
            "--mode",
            "deep",
            "--level",
            "6",
            "--control",
            "C-04",
            "--hard-negatives",
            "HN-01,HN-05",
            "--observer-uid",
            "2000",
            "--blind-dir",
            "/tmp/blind",
            "--run-id",
            "r01",
            "--decoy-token",
            "DT-",
            "--live",
            "--target-cmd",
            "exec /bin/sleep 5",
            "--jitter-ms",
            "25",
            "--churn",
            "3",
        ])
        .unwrap();
        assert_eq!(b.decoys, 12);
        assert_eq!(b.seed, Some(999));
        assert_eq!(b.run_mode, harness::Mode::Deep);
        assert_eq!(b.run_level, 6);
        assert_eq!(b.run_control, harness::Control::C04NoTarget);
        assert_eq!(
            b.hard_negatives,
            Some(vec![harness::HardNeg::Hn01Exe, harness::HardNeg::Hn05Maps])
        );
        assert_eq!(b.observer_uid, Some(2000));
        assert_eq!(b.blind_dir.as_deref(), Some(&b"/tmp/blind"[..]));
        assert_eq!(b.run_id.as_deref(), Some("r01"));
        assert_eq!(b.decoy_token.as_deref(), Some("DT-"));
        assert!(b.live);
        assert_eq!(b.target_cmd.as_deref(), Some("exec /bin/sleep 5"));
        assert_eq!(b.jitter_ms, 25);
        assert_eq!(b.churn, 3);

        assert!(!ok(&["run", "--out", "/tmp/run"]));
        assert!(!ok(&["run", "--profile", "/tmp/p.json"]));
        assert!(!ok(&[
            "run",
            "--profile",
            "/tmp/p.json",
            "--out",
            "/tmp/run",
            "--level",
            "7"
        ]));
        assert!(!ok(&[
            "run",
            "--profile",
            "/tmp/p.json",
            "--out",
            "/tmp/run",
            "--target-pid",
            "10",
            "--target-cmd",
            "sleep 5"
        ]));
        assert!(!ok(&[
            "run",
            "--profile",
            "/tmp/p.json",
            "--out",
            "/tmp/run",
            "unexpected-pos"
        ]));
    }

    #[test]
    fn score_replay_verify_selftest_positional_and_flags() {
        let s1 = parse_strs(&["score", "/tmp/r1", "--pick", "/tmp/p1.json"]).unwrap();
        assert!(s1.sub == Sub::Score);
        assert_eq!(s1.run_dir.as_deref(), Some(&b"/tmp/r1"[..]));
        assert_eq!(s1.pick.as_deref(), Some("/tmp/p1.json"));

        let s2 = parse_strs(&[
            "score",
            "--runs",
            "/tmp/r1,/tmp/r2",
            "--pick",
            "/tmp/p1.json,/tmp/p2.json",
            "--out",
            "/tmp/s.json",
        ])
        .unwrap();
        assert_eq!(parse_score_pairs(&s2).unwrap().len(), 2);

        assert!(!ok(&["score"]));
        assert!(!ok(&["score", "/tmp/r1", "--runs", "/tmp/r2"]));
        assert!(!ok(&["score", "/tmp/r1", "/tmp/r2"]));
        assert!(!ok(&[
            "score",
            "--runs",
            "/tmp/r1,/tmp/r2",
            "--pick",
            "/tmp/p1.json"
        ]));

        let rep = parse_strs(&[
            "replay",
            "/tmp/r1",
            "--pick",
            "/tmp/p1.json",
            "--out",
            "/tmp/o.json",
        ])
        .unwrap();
        assert!(rep.sub == Sub::Replay);
        assert_eq!(rep.run_dir.as_deref(), Some(&b"/tmp/r1"[..]));
        assert!(!ok(&["replay", "/tmp/r1"]));
        assert!(!ok(&["replay", "--pick", "/tmp/p1.json"]));

        let ver = parse_strs(&[
            "verify",
            "/tmp/r1",
            "--pick",
            "/tmp/p1.json",
            "--redact-token",
            "SECRET_A",
            "--redact-token",
            "SECRET_B",
        ])
        .unwrap();
        assert!(ver.sub == Sub::Verify);
        assert_eq!(ver.redact_tokens, vec!["SECRET_A", "SECRET_B"]);
        assert!(!ok(&["verify"]));
        assert!(!ok(&["verify", "/tmp/r1", "/tmp/extra"]));

        let st = parse_strs(&["selftest", "--out", "/tmp/st"]).unwrap();
        assert!(st.sub == Sub::Selftest);
        assert_eq!(st.out_path.as_deref(), Some(&b"/tmp/st"[..]));
        assert!(ok(&["selftest"]));
        assert!(!ok(&["selftest", "extra-pos"]));
    }

    #[test]
    fn inject_new_decoy_flags_and_legacy_preservation() {
        let a = parse_strs(&[
            "inject",
            "--from-profile",
            "/tmp/p.json",
            "-n",
            "10",
            "-d",
            "30",
            "--decoy-level",
            "6",
            "--clean-env",
            "--exe-memfd",
            "--decoy-token",
            "DT-",
            "--dumpable",
            "0",
            "--seccomp",
            "2",
            "--wchan",
            "epoll",
            "--jitter-ms",
            "40",
            "--churn",
            "2",
            "--pidfile",
            "/tmp/d.pid",
        ])
        .unwrap();
        assert!(a.sub == Sub::Inject);
        assert_eq!(a.from_profile.as_deref(), Some(&b"/tmp/p.json"[..]));
        assert_eq!(a.decoy_level, Some(6));
        assert!(a.clean_env);
        assert!(a.exe_memfd);
        assert_eq!(a.decoy_token.as_deref(), Some("DT-"));
        assert_eq!(a.dumpable, Some(0));
        assert_eq!(a.seccomp, Some(2));
        assert_eq!(a.wchan, Some(1));
        assert_eq!(a.jitter_ms, 40);
        assert_eq!(a.churn, 2);

        let m = parse_strs(&[
            "inject",
            "--masker-cmd",
            "exec /bin/sleep 5",
            "-n",
            "3",
            "--jitter-ms",
            "10",
            "--decoy-token",
            "TOK-",
        ])
        .unwrap();
        assert_eq!(m.masker_cmd.as_deref(), Some("exec /bin/sleep 5"));

        // Conflicts & validation
        assert!(!ok(&[
            "inject",
            "--from-profile",
            "/tmp/p.json",
            "--masker-cmd",
            "sleep 5"
        ]));
        assert!(!ok(&["inject", "--clean-env"]));
        assert!(!ok(&[
            "inject",
            "--from-profile",
            "/tmp/p.json",
            "--dry-run"
        ]));
        assert!(!ok(&[
            "inject",
            "--from-profile",
            "/tmp/p.json",
            "--dumpable",
            "2"
        ]));
        assert!(!ok(&[
            "inject",
            "--from-profile",
            "/tmp/p.json",
            "--seccomp",
            "9"
        ]));
        assert!(!ok(&[
            "inject",
            "--from-profile",
            "/tmp/p.json",
            "--wchan",
            "bogus"
        ]));
        assert!(!ok(&[
            "inject",
            "--from-profile",
            "/tmp/p.json",
            "--decoy-level",
            "0"
        ]));
        // Legacy profile validation still rejects non-corpus names on table/inject
        assert!(!ok(&["table", "--profile", "/tmp/p.json"]));
        assert!(!ok(&["inject", "--profile", "/tmp/p.json"]));
    }
}
