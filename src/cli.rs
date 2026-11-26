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

#[derive(Clone, Copy, Default, PartialEq)]
pub enum Sub {
    #[default]
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
#[derive(Clone, Copy, PartialEq, Eq)]
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
    NoAncestors,
    Label,
    Masker,
    ProfileName,
    RedactToken,
    RedactTokenFile,
    RedactEnv,
    FromProfile,
    DecoyLevel,
    CleanEnv,
    NoCleanEnv,
    SameSession,
    LabelDecoys,
    InterleaveCmd,
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
    "--delay|--speed|--log-fmt|--pid|--validate|--out|--tree|--no-ancestors|--label|--masker|--profile-name|",
    "--redact-token|--redact-token-file|--redact-env|--from-profile|--decoy-level|--clean-env|--no-clean-env|",
    "--same-session|--label-decoys|--interleave-cmd|--exe-memfd|",
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
    (OptId::NoAncestors, true, Sub::Profile.bit()),
    (OptId::Label, false, Sub::Profile.bit()),
    (OptId::Masker, false, Sub::Profile.bit()),
    (OptId::ProfileName, false, Sub::Profile.bit()),
    (
        OptId::RedactToken,
        false,
        Sub::Profile.bit() | Sub::Run.bit() | Sub::Verify.bit(),
    ),
    (
        OptId::RedactTokenFile,
        false,
        Sub::Profile.bit() | Sub::Run.bit() | Sub::Verify.bit(),
    ),
    (OptId::RedactEnv, false, Sub::Profile.bit() | Sub::Run.bit()),
    (OptId::FromProfile, false, Sub::Inject.bit()),
    (OptId::DecoyLevel, false, Sub::Inject.bit()),
    (OptId::CleanEnv, true, Sub::Inject.bit()),
    (OptId::NoCleanEnv, true, Sub::Inject.bit()),
    (OptId::SameSession, true, Sub::Inject.bit()),
    (OptId::LabelDecoys, false, Sub::Inject.bit()),
    (OptId::InterleaveCmd, false, Sub::Inject.bit()),
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
    (OptId::BlindDir, false, Sub::Run.bit() | Sub::Verify.bit()),
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

#[derive(Default)]
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
    pub no_ancestors: bool,
    pub label: Option<String>,
    pub masker: Option<String>,
    pub profile_name: Option<String>,
    pub redact_tokens: Vec<String>,
    pub redact_token_files: Vec<String>,
    pub redact_envs: Vec<String>,
    /// `inject` decoy options (and shared `run` live options).
    pub from_profile: Option<Vec<u8>>,
    pub decoy_level: Option<u8>,
    pub clean_env: bool,
    pub no_clean_env: bool,
    pub same_session: bool,
    pub label_decoys: usize,
    pub interleave_cmd: Option<String>,
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
            profile: b"server".to_vec(),
            sort: true,
            uniq: true,
            mem: true,
            tty: true,
            threads: true,
            user: true,
            log_module: b"weblog".to_vec(),
            log_lines: 20,
            speed: 1,
            decoys: 50,
            run_level: 5,
            ..Args::default()
        }
    }

    /// Options that change what `unit` prints, in a stable order. Only the
    /// non-default values are forwarded, so a plain `psgen unit` stays short.
    #[inline(never)]
    pub fn forwarded(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        fn push(out: &mut Vec<Vec<u8>>, name: &str, value: Option<&[u8]>) {
            out.push(name.as_bytes().to_vec());
            if let Some(v) = value {
                out.push(v.to_vec());
            }
        }
        fn push_u(out: &mut Vec<Vec<u8>>, name: &str, val: Option<u64>) {
            if let Some(n) = val {
                push(out, name, Some(json::u64_str(n).as_bytes()));
            }
        }
        fn push_b(out: &mut Vec<Vec<u8>>, cond: bool, name: &str) {
            if cond {
                push(out, name, None);
            }
        }
        if self.profile != b"server" {
            push(&mut out, "-p", Some(&self.profile));
        }
        if let Some(f) = self.family {
            push(
                &mut out,
                "-f",
                Some(crate::corpus::family_name(f).as_bytes()),
            );
        }
        push_u(
            &mut out,
            "-d",
            (self.duration > 0).then_some(self.duration as u64),
        );
        push_b(&mut out, !self.mem, "--no-mem");
        push_u(
            &mut out,
            "--mem-cap",
            (self.mem_cap_mb > 0).then_some(self.mem_cap_mb),
        );
        push_u(&mut out, "--mem-target", self.mem_target_kb.map(u64::from));
        push_u(&mut out, "--phys-cap", self.phys_cap);
        push_u(&mut out, "--disk", self.disk_mb);
        push_b(&mut out, self.no_exe, "--no-exe");
        if let Some(d) = &self.shadow_dir {
            push(&mut out, "--shadow-dir", Some(d));
        }
        push_b(&mut out, self.no_root, "--no-root");
        push_b(&mut out, !self.tty, "--no-tty");
        push_b(&mut out, !self.threads, "--no-threads");
        push_b(&mut out, !self.user, "--no-user");
        push_b(&mut out, self.busy, "--busy");
        push_u(&mut out, "--cpu", self.cpu_pct.map(u64::from));
        push_b(&mut out, self.verify, "--verify");
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
  -n, --count N       rows/commands (list: all, table: 30, --live: all, inject: 12)
  -s, --seed N        fix selection and jitter; START/TIME follow wall clock
  -p, --profile NAME  server (default), dev, desktop; weights templates for
                      list, table and inject
  -f, --family NAME   sys, web, db, ctr, dev, mon, sto, mail, desk, net
      --utc-offset M  minutes east of UTC for START, -1440..1440 (default 0)
      --local         use system timezone for START (overrides --utc-offset)
      --sort / --no-sort   list only
      --uniq / --no-uniq   list only
  -h, --help
  -V, --version

Unused or mode-incompatible options exit 2.

INJECT
  -d, --duration S      lifetime in seconds (0 = until stopped; short rows: 120 s)
      --pidfile FILE    write spawned PIDs (must be empty or a psgen pidfile)
      --mem / --no-mem  pad VSZ and RSS (default on)
      --mem-cap MiB     cap planned RSS sum; 4 MiB per-stub floor (0 = no cap)
      --mem-target KiB  per-stub RSS target in KiB (clamped to VSZ - 4 MiB)
      --phys-cap MiB    physical memory budget (0 = unlimited)
      --disk MiB        write MiB of temp data per stub
      --exe / --no-exe  bind template executable path (default on)
      --allow-proc-exe  alias of --no-exe: exec /proc/self/exe, no spoof
      --shadow-dir DIR  shadow copy root when bind is unavailable or --no-root
      --no-root         portable mode: no user switch, mount ns, or bind tier
      --tty / --no-tty  give tty rows a real pty (default on)
      --threads / --no-threads  give threaded rows a second thread (default on)
      --user / --no-user  switch to template user when root (default on)
      --create-users    create missing template users via useradd (needs root)
      --busy            burn CPU for rows whose corpus CPU is non-zero
      --cpu PCT         target CPU percent for every row (0..100)
      --dry-run         print user and command without spawning
      --plan            with --dry-run, print resolved plan and staging patterns
      --json            with --dry-run, print plan as JSON (alternative to --plan)
      --table           after spawning, print real ps aux table for the stubs
      --verify          compare real VSZ/RSS with plan (has no effect with --no-mem)
      --wait            block for non-zero --duration, then stop stubs
      --elevate         re-exec through sudo -n when not root
  -q, --quiet           suppress inject summary
      --from-profile FILE  spawn matched live decoy trees from profile JSON
      --decoy-level N      decoy fidelity level 1..6 (default 5)
      --clean-env          memfd-name auth, no PSGEN_NONCE (default on)
      --no-clean-env       opt out of clean-env auth under --from-profile
      --same-session       opt out of per-tree setsid session isolation
      --label-decoys N     also spawn N clean label-only decoys
      --interleave-cmd CMD launch CMD interleaved among decoy spawns
      --exe-memfd          re-exec via memfd_create + execveat
      --decoy-token PREFIX decoy token prefix for memory scans
      --dumpable N         PR_SET_DUMPABLE override (0 or 1)
      --seccomp N          install N benign seccomp filters (0..8)
      --wchan MODE         pause, epoll, poll, nanosleep, futex, read or wait4
      --jitter-ms MS       startup jitter ceiling in ms
      --churn N            short-lived churn workers
      --masker-cmd CMD     spawn decoys via external masker command

CORPUS AND CHECK
      --binaries          report which template executables exist on this host
      --require-binaries  like --binaries, but exit 1 when any is missing
      --host-mem MiB      generate table for host memory MiB
      --host-pid-max N    generate table for pid_max N; PID 1 is still shown
      --host-uptime S     generate table as if host uptime is S seconds
      --repeat-max N      max repeats per command (0 = no cap)
  `corpus` prints @self for invoking-user templates; list/table/inject expand it.

UNIT
  Forwards inject flags, caps -n at 500, sets RuntimeDirectoryPreserve=yes.

DOCTOR
      --json            JSON output with checks[] and core_ok (proc_exe, fork, prctl_name)
      --pidfile FILE    also check whether FILE can be written

LOG
  -m, --module NAME   weblog (default), bootlog, cargo, cc, download, docker_build,
                      docker_rmi, terraform, ansible, kernel_compile, mkinitcpio,
                      uv, composer, julia, list (prints aliases)
      --lines N       events to write (default 20, 1..200000)
      --delay MS      pause between events
      --speed N       divide delay by N (default 1, >= 1)
      --log-fmt NAME  apache (weblog only), json, syslog

LOAD
      --cpu-util PCT  burn PCT% of one core (0..100)
      --mem-util PCT  hold PCT% of MemTotal/cgroup (0..95; --force overrides available)
      --disk-util MiB write and hold MiB of temp data
  -d, --duration S    stop after S seconds (0 = until killed)
      --force         allow --mem-util above MemAvailable
  -q, --quiet         suppress load summary

STOP
      --force         ignore boot id / missing '# psgen' header
      --plan          print what would be signalled without stopping
      --elevate       re-exec through sudo -n when not root (error with --plan)
  -q, --quiet         only print the summary line
  Leaves pidfile in place; rejects CRLF line endings.

PROFILE
      --pid PID / --validate FILE / --out FILE / --tree / --no-ancestors
      --label STR / --masker STR / --profile-name STR
      --redact-token STR / --redact-token-file FILE / --redact-env VAR

RUN
      --profile FILE / --out DIR / --decoys N / --seed N
      --mode MODE / --level N / --control ID / --hard-negatives SET
      --observer-uid UID / --blind-dir DIR / --run-id STR / --decoy-token PREFIX
      --redact-token STR / --redact-token-file FILE / --redact-env VAR
      --live / --target-pid PID / --target-cmd CMD / --masker-cmd CMD
      --jitter-ms MS / --churn N

SCORE, REPLAY, VERIFY AND SELFTEST
      --runs DIRS / --pick FILE / --out FILE
      --redact-token STR / --redact-token-file FILE / --blind-dir DIR
";

fn usage() -> Vec<u8> {
    let mut out = Buf::with_capacity(USAGE_BODY.len() + 64);
    out.push_bytes(crate::version::BARE);
    out.push_str(" - ");
    out.push_str(USAGE_BODY);
    out.v
}

const SUB_SPECS: &str = "list,ps|table|inject,spawn|stop,kill|corpus|check|unit|\
doctor,probe,env|log,activity|load,lookbusy|profile|run|score|replay|verify|\
selftest|help|version";

const SUB_LIST: &[Sub] = &[
    Sub::List,
    Sub::Table,
    Sub::Inject,
    Sub::Stop,
    Sub::Corpus,
    Sub::Check,
    Sub::Unit,
    Sub::Doctor,
    Sub::Log,
    Sub::Load,
    Sub::Profile,
    Sub::Run,
    Sub::Score,
    Sub::Replay,
    Sub::Verify,
    Sub::Selftest,
    Sub::Help,
    Sub::Version,
];

fn set_sub(a: &mut Args, name: &[u8]) -> bool {
    for (spec, &sub) in SUB_SPECS.split('|').zip(SUB_LIST.iter()) {
        if spec.split(',').any(|k| k.as_bytes() == name) {
            a.sub = sub;
            return true;
        }
    }
    false
}

fn take_value<'a>(
    args: &'a [Vec<u8>],
    i: &mut usize,
    inline: Option<&'a [u8]>,
) -> Option<&'a [u8]> {
    if let Some(v) = inline {
        return Some(v);
    }
    if let Some(next) = args.get(*i + 1) {
        if !next.starts_with(b"--") {
            *i += 1;
            return Some(next);
        }
    }
    None
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
    if p.first() == Some(&b'/') {
        return p.to_vec();
    }
    let rel = p.strip_prefix(b"./").unwrap_or(p);
    match std::env::current_dir() {
        Ok(d) => d
            .join(OsStr::from_bytes(rel))
            .as_os_str()
            .as_bytes()
            .to_vec(),
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
    SUB_SPECS
        .split('|')
        .nth(sub as usize)
        .and_then(|s| s.split(',').next())
        .unwrap_or("")
}

#[inline(never)]
fn req_utf8(v: &[u8], name: &str) -> Result<String, ParseError> {
    core::str::from_utf8(v)
        .map(String::from)
        .map_err(|_| json::cat2("invalid ", name).into())
}

const HI_U64: u16 = 1000;
const HI_USIZE: u16 = 1001;
const HI_U32: u16 = 1002;
const HI_I32: u16 = 1003;
const HI_DISK: u16 = 1004;

#[inline(never)]
fn req_num(v: &[u8], name: &str, lo: u8, hi_code: u16, has_msg: bool) -> Result<u64, ParseError> {
    let hi: u64 = match hi_code {
        HI_U64 => u64::MAX,
        HI_USIZE => usize::MAX as u64,
        HI_U32 => u32::MAX as u64,
        HI_I32 => i32::MAX as u64,
        HI_DISK => (u32::MAX as u64) / 1024,
        x => x as u64,
    };
    let n = str::parse_u64(v).ok_or_else(|| json::cat2("invalid ", name))?;
    if n < lo as u64 || n > hi {
        if !has_msg {
            return Err(json::cat2("invalid ", name).into());
        }
        let msg = if hi_code >= 1000 {
            json::cat3(
                name,
                " must be at least 1",
                if name == "--host-mem" { " MiB" } else { "" },
            )
        } else if lo == 0 && hi_code == 1 {
            json::cat2(name, " must be 0 or 1")
        } else {
            json::concat(&[
                name,
                " must be ",
                &json::u64_str(lo as u64),
                "..",
                &json::u64_str(hi_code as u64),
            ])
        };
        return Err(msg.into());
    }
    Ok(n)
}

#[inline(never)]
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

fn opt_str_slot(a: &mut Args, id: OptId) -> Option<&mut Option<String>> {
    Some(match id {
        OptId::Label => &mut a.label,
        OptId::Masker => &mut a.masker,
        OptId::ProfileName => &mut a.profile_name,
        OptId::DecoyToken => &mut a.decoy_token,
        OptId::MaskerCmd => &mut a.masker_cmd,
        OptId::InterleaveCmd => &mut a.interleave_cmd,
        OptId::RunId => &mut a.run_id,
        OptId::TargetCmd => &mut a.target_cmd,
        OptId::Runs => &mut a.runs,
        OptId::Pick => &mut a.pick,
        _ => return None,
    })
}

fn vec_str_slot(a: &mut Args, id: OptId) -> Option<&mut Vec<String>> {
    Some(match id {
        OptId::RedactToken => &mut a.redact_tokens,
        OptId::RedactTokenFile => &mut a.redact_token_files,
        OptId::RedactEnv => &mut a.redact_envs,
        _ => return None,
    })
}

fn opt_bytes_slot(a: &mut Args, id: OptId) -> Option<(&mut Option<Vec<u8>>, bool)> {
    Some(match id {
        OptId::Validate => (&mut a.validate_file, false),
        OptId::Out => (&mut a.out_path, false),
        OptId::FromProfile => (&mut a.from_profile, false),
        OptId::BlindDir => (&mut a.blind_dir, false),
        OptId::Pidfile => (&mut a.pidfile, true),
        OptId::ShadowDir => (&mut a.shadow_dir, true),
        _ => return None,
    })
}

fn bool_slot(a: &mut Args, id: OptId) -> Option<(&mut bool, bool)> {
    Some(match id {
        OptId::Help => (&mut a.want_help, true),
        OptId::Version => (&mut a.want_version, true),
        OptId::Local => (&mut a.local, true),
        OptId::Sort => (&mut a.sort, true),
        OptId::NoSort => (&mut a.sort, false),
        OptId::Uniq => (&mut a.uniq, true),
        OptId::NoUniq => (&mut a.uniq, false),
        OptId::Mem => (&mut a.mem, true),
        OptId::NoMem => (&mut a.mem, false),
        OptId::Tty => (&mut a.tty, true),
        OptId::NoTty => (&mut a.tty, false),
        OptId::Threads => (&mut a.threads, true),
        OptId::NoThreads => (&mut a.threads, false),
        OptId::User => (&mut a.user, true),
        OptId::NoUser => (&mut a.user, false),
        OptId::CreateUsers => (&mut a.create_users, true),
        OptId::Busy => (&mut a.busy, true),
        OptId::DryRun => (&mut a.dry_run, true),
        OptId::Plan => (&mut a.plan, true),
        OptId::Wait => (&mut a.wait, true),
        OptId::Binaries => (&mut a.binaries, true),
        OptId::Elevate => (&mut a.elevate, true),
        OptId::Table => (&mut a.table, true),
        OptId::Live => (&mut a.live, true),
        OptId::Force => (&mut a.force, true),
        OptId::Verify => (&mut a.verify, true),
        OptId::Exe => (&mut a.no_exe, false),
        OptId::NoExe => (&mut a.no_exe, true),
        OptId::NoRoot => (&mut a.no_root, true),
        OptId::Json => (&mut a.json, true),
        OptId::Quiet => (&mut a.quiet, true),
        OptId::Tree => (&mut a.tree, true),
        OptId::NoAncestors => (&mut a.no_ancestors, true),
        OptId::NoCleanEnv => (&mut a.no_clean_env, true),
        OptId::SameSession => (&mut a.same_session, true),
        OptId::ExeMemfd => (&mut a.exe_memfd, true),
        _ => return None,
    })
}

#[inline(never)]
fn apply_opt(a: &mut Args, opt: &OptRow, v: &[u8]) -> Result<(), ParseError> {
    const NUM_SPECS: &[(OptId, u8, u16, bool)] = &[
        (OptId::Count, 0, HI_USIZE, false),
        (OptId::Decoys, 0, HI_USIZE, false),
        (OptId::LabelDecoys, 0, 500, true),
        (OptId::RepeatMax, 0, HI_USIZE, false),
        (OptId::Lines, 1, HI_USIZE, true),
        (OptId::Duration, 0, HI_U32, false),
        (OptId::JitterMs, 0, HI_U32, false),
        (OptId::Churn, 0, HI_U32, false),
        (OptId::MemTarget, 0, HI_U32, false),
        (OptId::ObserverUid, 0, HI_U32, false),
        (OptId::Seed, 0, HI_U64, false),
        (OptId::MemCap, 0, HI_U64, false),
        (OptId::PhysCap, 0, HI_U64, false),
        (OptId::Delay, 0, HI_U64, false),
        (OptId::DiskUtil, 0, HI_U64, false),
        (OptId::Disk, 0, HI_DISK, false),
        (OptId::Pid, 1, HI_I32, false),
        (OptId::TargetPid, 1, HI_I32, false),
        (OptId::Cpu, 0, 100, true),
        (OptId::Speed, 1, HI_U64, true),
        (OptId::CpuUtil, 0, 100, true),
        (OptId::MemUtil, 0, 95, true),
        (OptId::HostMem, 1, HI_U64, true),
        (OptId::HostPidMax, 1, HI_U64, true),
        (OptId::HostUptime, 1, HI_U64, true),
        (OptId::DecoyLevel, 1, 6, true),
        (OptId::Dumpable, 0, 1, true),
        (OptId::Seccomp, 0, 8, true),
        (OptId::Level, 1, 6, true),
    ];

    let name = opt.name;
    let id = opt.id;
    if let Some((slot, val)) = bool_slot(a, id) {
        *slot = val;
        return Ok(());
    }
    if let Some(slot) = opt_str_slot(a, id) {
        *slot = Some(req_utf8(v, name)?);
        return Ok(());
    }
    if let Some(slot) = vec_str_slot(a, id) {
        slot.push(req_utf8(v, name)?);
        return Ok(());
    }
    if let Some((slot, abs)) = opt_bytes_slot(a, id) {
        *slot = Some(if abs { abs_path(v) } else { v.to_vec() });
        return Ok(());
    }
    if let Some(&(_, lo, hi, has_msg)) = NUM_SPECS.iter().find(|s| s.0 == id) {
        let n = req_num(v, name, lo, hi, has_msg)?;
        match id {
            OptId::Count => a.count = n as usize,
            OptId::Decoys => a.decoys = n as usize,
            OptId::LabelDecoys => a.label_decoys = n as usize,
            OptId::RepeatMax => a.repeat_max = Some(n as usize),
            OptId::Lines => a.log_lines = n as usize,
            OptId::Duration => a.duration = n as u32,
            OptId::JitterMs => a.jitter_ms = n as u32,
            OptId::Churn => a.churn = n as u32,
            OptId::MemTarget => a.mem_target_kb = Some(n as u32),
            OptId::ObserverUid => a.observer_uid = Some(n as u32),
            OptId::Seed => a.seed = Some(n),
            OptId::MemCap => a.mem_cap_mb = n,
            OptId::PhysCap => a.phys_cap = Some(n),
            OptId::Delay => a.log_delay_ms = n,
            OptId::DiskUtil => a.load_disk = Some(n),
            OptId::Disk => a.disk_mb = Some(n),
            OptId::Pid | OptId::TargetPid => a.target_pid = Some(n as i32),
            OptId::Cpu => a.cpu_pct = Some(n as u32),
            OptId::Speed => a.speed = n,
            OptId::CpuUtil => a.load_cpu = Some(n as u32),
            OptId::MemUtil => a.load_mem = Some(n as u32),
            OptId::HostMem => a.host_mem_mb = Some(n),
            OptId::HostPidMax => a.host_pid_max = Some(n),
            OptId::HostUptime => a.host_uptime = Some(n),
            OptId::DecoyLevel => a.decoy_level = Some(n as u8),
            OptId::Dumpable => a.dumpable = Some(n as u8),
            OptId::Seccomp => a.seccomp = Some(n as u8),
            OptId::Level => a.run_level = n as u8,
            _ => {}
        }
        return Ok(());
    }

    match id {
        OptId::RequireBinaries => {
            a.binaries = true;
            a.require_binaries = true;
        }
        OptId::CleanEnv => {
            a.clean_env = true;
            a.no_clean_env = false;
        }
        OptId::Profile => a.profile = v.to_vec(),
        OptId::Module => a.log_module = v.to_vec(),
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
        OptId::Wchan | OptId::Mode | OptId::Control | OptId::HardNegatives => {
            let s = req_utf8(v, name)?;
            match id {
                OptId::Wchan => {
                    a.wchan = Some(inject::parse_wchan_mode(&s).ok_or(
                        "invalid --wchan; expected pause, epoll, poll, nanosleep, futex, read or wait4",
                    )?);
                }
                OptId::Mode => a.run_mode = harness::Mode::parse(&s)?,
                OptId::Control => a.run_control = harness::Control::parse(&s)?,
                OptId::HardNegatives => a.hard_negatives = Some(harness::HardNeg::parse_list(&s)?),
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

#[inline(never)]
pub fn parse(args: &[Vec<u8>]) -> Result<Args, ParseError> {
    let mut a = Args::new();
    let mut i = 1usize;
    let mut saw_sub = false;
    let mut stop_options = false;
    while let Some(arg) = args.get(i) {
        if !stop_options && arg == b"--" {
            stop_options = true;
            i += 1;
            continue;
        }
        if !stop_options && arg.len() > 1 && arg.first() == Some(&b'-') {
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

#[inline(never)]
fn reject_if_seen(a: &Args, name: &str, why: &str) -> Result<(), ParseError> {
    if a.seen.contains(&name) {
        Err(json::cat3(name, " ", why).into())
    } else {
        Ok(())
    }
}

#[inline(never)]
fn reject_csv(a: &Args, names_csv: &str, why: &str) -> Result<(), ParseError> {
    for name in names_csv.split(',') {
        reject_if_seen(a, name, why)?;
    }
    Ok(())
}

#[inline(never)]
fn check_forbid(cond: bool, msg: &'static str) -> Result<(), ParseError> {
    if cond {
        Err(ParseError::Static(msg))
    } else {
        Ok(())
    }
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
                check_forbid(
                    a.json && a.plan,
                    "--plan and --json encode the same preview; use one of them",
                )?;
            }
            Run::Spawn => {
                check_forbid(
                    a.json,
                    "--json on inject needs --dry-run: it encodes the plan",
                )?;
                check_forbid(
                    a.plan,
                    "--plan on inject needs --dry-run: it is the preview",
                )?;
                check_forbid(
                    a.wait && a.duration == 0,
                    "--wait needs --duration: without one the run is stopped by `psgen stop`",
                )?;
            }
        }
        check_forbid(
            a.from_profile.is_some() && a.masker_cmd.is_some(),
            "--from-profile and --masker-cmd are mutually exclusive",
        )?;
        if a.from_profile.is_none() {
            reject_csv(
                a,
                "--decoy-level,--clean-env,--no-clean-env,--same-session,--label-decoys,--interleave-cmd,--exe-memfd,--dumpable,--seccomp,--wchan",
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
        check_forbid(
            (a.from_profile.is_some() || a.masker_cmd.is_some()) && a.dry_run,
            "--dry-run does not apply with --from-profile or --masker-cmd",
        )?;
    }
    check_forbid(
        a.sub == Sub::Stop && a.plan && a.elevate,
        "--elevate does not apply with --plan: a plan never elevates, so it would report a verdict the real run cannot reach",
    )?;
    if a.sub == Sub::Profile {
        check_forbid(
            a.target_pid.is_some() && a.validate_file.is_some(),
            "--pid and --validate are mutually exclusive",
        )?;
        check_forbid(
            a.target_pid.is_none() && a.validate_file.is_none(),
            "profile requires --pid or --validate",
        )?;
        if a.validate_file.is_some() {
            reject_csv(
                a,
                "--tree,--no-ancestors,--label,--masker,--profile-name,--redact-env,--out",
                "does not apply with --validate",
            )?;
        }
    }
    if a.sub == Sub::Run {
        check_forbid(
            !a.seen.contains(&"--profile")
                && !(a.live && (a.target_cmd.is_some() || a.target_pid.is_some())),
            "run requires --profile (or --live with --target-cmd/--target-pid)",
        )?;
        check_forbid(a.out_path.is_none(), "run requires --out")?;
        check_forbid(
            a.target_pid.is_some() && a.target_cmd.is_some(),
            "--target-pid and --target-cmd are mutually exclusive",
        )?;
    }
    if a.sub == Sub::Score {
        check_forbid(
            a.run_dir.is_some() && a.runs.is_some(),
            "use either <run-dir> or --runs, not both",
        )?;
        check_forbid(
            a.run_dir.is_none() && a.runs.is_none(),
            "score requires <run-dir> or --runs",
        )?;
        let _ = parse_score_pairs(a)?;
    }
    if a.sub == Sub::Replay {
        check_forbid(a.run_dir.is_none(), "replay requires <run-dir>")?;
        check_forbid(a.pick.is_none(), "replay requires --pick")?;
    }
    check_forbid(
        a.sub == Sub::Verify && a.run_dir.is_none(),
        "verify requires <run-dir>",
    )?;
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

#[inline(never)]
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

#[inline(never)]
fn elevate(argv: &[Vec<u8>], args: &Args) -> Option<i32> {
    // A preview never elevates: `--plan` describes what the caller's own
    // privileges would reach, and re-execing through sudo would answer a
    // different question (and make a read-only command privileged).
    let preview = args.dry_run || (args.plan && args.sub == Sub::Stop);
    if !args.elevate || preview || sys::geteuid() == 0 {
        return None;
    }
    let self_exe = std::env::current_exe().ok()?;
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
        if a != b"--elevate" {
            cmd_argv.push(a.as_slice());
        }
    }
    match sys::run_cmd(b"sudo", &cmd_argv, None, false) {
        Ok((code, _)) => Some(code),
        Err(e) => {
            let mut out = Buf::new();
            sys::buf_push_s(&mut out, "psgen: cannot run sudo: ");
            sys::push_errno(&mut out, e);
            out.push(b'\n');
            sys::err(out.as_bytes());
            Some(1)
        }
    }
}

#[inline(never)]
fn print_notes(prep: &inject::Prep, args: &Args) {
    for w in &prep.warnings {
        let msg = if args.dry_run && args.create_users {
            w.replace(" (pass --create-users to create it)", "")
        } else {
            w.clone()
        };
        sys::err_parts(&[msg.as_bytes()]);
    }
    let c = &prep.caps;
    let reduced = (!c.pty && args.tty) || (c.root && !c.user_switch && args.user);
    if reduced {
        let mut out = Buf::new();
        sys::buf_push_s(&mut out, "psgen: reduced capability:");
        if !c.pty {
            sys::buf_push_s(&mut out, " pty=no");
        }
        if c.root && !c.user_switch {
            sys::buf_push_s(&mut out, " user_switch=no");
        }
        sys::buf_push_s(&mut out, " (run `psgen doctor` for the errno)\n");
        sys::err(out.as_bytes());
    }
    if !c.memfd {
        sys::err(if c.memfd_untested {
            b"psgen: the capability probe could not fork, so memfd_create is untested; the arena may fall back to an unlinked temp file and the run will refuse if a stub config needs a memfd\n"
        } else {
            b"psgen: memfd_create denied; the arena falls back to an unlinked temp file, but a stub config cannot, so the run will refuse when it reaches the config\n"
        });
    }
    if !prep.created.is_empty() {
        let mut out = Buf::new();
        sys::buf_push_s(&mut out, "psgen: created users:");
        for u in &prep.created {
            out.push(b' ');
            sys::buf_push_b(&mut out, u);
        }
        sys::buf_push_s(&mut out, " (remove with userdel when done)\n");
        sys::err(out.as_bytes());
    }
}

fn print_failures(result: &inject::SpawnResult) {
    for (id, status) in &result.failed_ids {
        let mut m = Buf::new();
        sys::buf_push_s(&mut m, "psgen: row ");
        sys::buf_push_u(&mut m, *id as u64);
        sys::buf_push_s(&mut m, " failed");
        if *status < 0 {
            sys::buf_push_s(&mut m, ": ");
            sys::push_errno(&mut m, -*status);
        }
        m.push(b'\n');
        sys::err(m.as_bytes());
    }
    for (pid, id, wv, gv, wr, gr) in &result.mismatches {
        let mut m = Buf::new();
        bp_kvs_u(
            &mut m,
            "psgen: pid | row | VSZ |/| RSS |/",
            &[*pid as u64, *id as u64, *gv, *wv, *gr, *wr],
        );
        bp_c(&mut m, b'\n');
        sys::err(m.as_bytes());
    }
}

/// Whether physical cost and budget should be printed in KiB instead of MiB so
/// an over-budget summary does not truncate both numbers to the same MiB.
fn phys_uses_kib(est_kb: u64, budget_kb: u64) -> bool {
    budget_kb > 0 && est_kb > budget_kb && est_kb / 1024 == budget_kb / 1024
}

#[inline(never)]
fn bp_c(b: &mut Buf, c: u8) {
    b.push(c);
}

#[inline(never)]
fn bp_kv_s(b: &mut Buf, k: &str, v: &str) {
    sys::buf_push_s(b, k);
    sys::buf_push_s(b, v);
}

#[inline(never)]
fn bp_kv_b(b: &mut Buf, k: &str, v: &[u8]) {
    sys::buf_push_s(b, k);
    sys::buf_push_b(b, v);
}

#[inline(never)]
fn bp_kv_u(b: &mut Buf, k: &str, v: u64) {
    sys::buf_push_s(b, k);
    sys::buf_push_u(b, v);
}

#[inline(never)]
fn bp_cnt(b: &mut Buf, pre: &str, n: u64, suf: &str) {
    sys::buf_push_s(b, pre);
    sys::buf_push_u(b, n);
    sys::buf_push_s(b, suf);
}

#[inline(never)]
fn bp_plural(b: &mut Buf, n: u64, sg: &str, pl: &str) {
    sys::buf_push_u(b, n);
    sys::buf_push_s(b, if n == 1 { sg } else { pl });
}

#[inline(never)]
fn bp_mem_unit(b: &mut Buf, kb: u64, kib: bool, suf: &str) {
    sys::buf_push_u(b, if kib { kb } else { kb / 1024 });
    sys::buf_push_s(b, if kib { " KiB" } else { " MiB" });
    sys::buf_push_s(b, suf);
}

#[inline(never)]
fn jp_k(b: &mut Buf, k: &str) {
    bp_kv_s(b, ",\"", k);
    sys::buf_push_s(b, "\":");
}

#[inline(never)]
fn jp_s(b: &mut Buf, k: &str, v: &[u8]) {
    jp_k(b, k);
    json_escape(b, v);
}

#[inline(never)]
fn jp_u(b: &mut Buf, k: &str, v: u64) {
    jp_k(b, k);
    sys::buf_push_u(b, v);
}

#[inline(never)]
fn jp_b(b: &mut Buf, k: &str, v: bool) {
    jp_k(b, k);
    sys::buf_push_s(b, bool_str(v));
}

#[inline(never)]
fn jp_opt_u(b: &mut Buf, k: &str, v: Option<u64>) {
    jp_k(b, k);
    match v {
        Some(n) => sys::buf_push_u(b, n),
        None => sys::buf_push_s(b, "null"),
    }
}

#[inline(never)]
fn jp_arr(b: &mut Buf, k: &str, items: &[Vec<u8>]) {
    jp_k(b, k);
    bp_c(b, b'[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            bp_c(b, b',');
        }
        json_escape(b, item);
    }
    bp_c(b, b']');
}

#[inline(never)]
fn jp_bools(b: &mut Buf, keys_csv: &str, vals: &[bool]) {
    for (k, &v) in keys_csv.split(',').zip(vals.iter()) {
        jp_b(b, k, v);
    }
}

#[inline(never)]
fn jp_u64s(b: &mut Buf, keys_csv: &str, vals: &[u64]) {
    for (k, &v) in keys_csv.split(',').zip(vals.iter()) {
        jp_u(b, k, v);
    }
}

#[inline(never)]
fn bp_kvs_s(b: &mut Buf, keys_pipe: &str, vals: &[&str]) {
    for (k, &v) in keys_pipe.split('|').zip(vals.iter()) {
        bp_kv_s(b, k, v);
    }
}

#[inline(never)]
fn bp_kvs_u(b: &mut Buf, keys_pipe: &str, vals: &[u64]) {
    for (k, &v) in keys_pipe.split('|').zip(vals.iter()) {
        bp_kv_u(b, k, v);
    }
}

#[inline(never)]
fn rm_bytes(p: &[u8]) {
    let _ = std::fs::remove_file(Path::new(OsStr::from_bytes(p)));
}

#[inline(never)]
fn print_summary(prep: &inject::Prep, result: &inject::SpawnResult, args: &Args) {
    print_failures(result);
    if args.quiet {
        return;
    }
    let mut out = Buf::new();
    bp_cnt(&mut out, "spawned ", result.pids.len() as u64, " processes");
    if let Some(path) = &args.pidfile {
        if result.pidfile_ok {
            bp_kv_b(&mut out, ", pids in ", path);
        } else {
            sys::buf_push_s(&mut out, "; the pidfile was not written");
        }
    } else {
        sys::buf_push_s(&mut out, " (pass --pidfile FILE to be able to stop them)");
        if !result.temps.is_empty() {
            sys::buf_push_s(&mut out, "; temp dirs:");
            for t in &result.temps {
                bp_kv_b(&mut out, " ", t.as_os_str().as_bytes());
            }
            sys::buf_push_s(&mut out, " (remove them with rm -rf when the run ends)");
        }
    }
    for (n, label) in [
        result.failed,
        result.missing,
        result.warned,
        result.mismatches.len(),
    ]
    .into_iter()
    .zip(" failed| did not report| reported a setup deviation| outside 128 kB".split('|'))
    {
        if n > 0 {
            bp_cnt(&mut out, ", ", n as u64, label);
        }
    }
    bp_kv_s(&mut out, "\nexe tier ", result.tier.name());
    if result.tty_wanted > 0 {
        bp_cnt(&mut out, ", tty ", result.tty_real as u64, " real");
        bp_cnt(&mut out, ", ", result.tty_degraded as u64, " degraded");
    }
    bp_c(&mut out, b'\n');
    if result.dev_exe + result.dev_user + result.dev_disk + result.dev_mem > 0 {
        bp_kvs_u(
            &mut out,
            "deviations: user |, exe |, mem |, disk ",
            &[
                result.dev_user as u64,
                result.dev_exe as u64,
                result.dev_mem as u64,
                result.dev_disk as u64,
            ],
        );
        bp_c(&mut out, b'\n');
    }
    if args.mem && prep.phys_estimate_kb > 0 {
        let show_kib = phys_uses_kib(prep.phys_estimate_kb, prep.phys_budget_kb);
        sys::buf_push_s(&mut out, "reported RSS is shared; estimated physical cost ");
        bp_mem_unit(&mut out, prep.phys_estimate_kb, show_kib, "");
        if prep.phys_scale < 1.0 {
            sys::buf_push_s(&mut out, ", scaled to fit the physical budget");
            if prep.phys_budget_kb > 0 {
                sys::buf_push_s(&mut out, " of ");
                bp_mem_unit(&mut out, prep.phys_budget_kb, show_kib, "");
            }
        }
        bp_c(&mut out, b'\n');
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

#[inline(never)]
fn pidfile_error_bytes(path: &[u8], bytes: usize) -> Buf {
    let mut out = Buf::new();
    bp_kv_b(&mut out, "psgen: cannot write the pidfile ", path);
    let tail: &str = if path.is_empty() {
        ": the path is empty"
    } else if sys::is_dir(path) {
        ": the path is a directory"
    } else if let Err(probe::TargetProblem::Unreadable(e)) = probe::pidfile_target(path) {
        // "Not an empty file or a psgen pidfile" would be a lie here: the path
        // could not be examined, which is a different problem with a different
        // fix (a shorter name, or a directory the caller can search).
        sys::buf_push_s(&mut out, ": the path cannot be examined (");
        sys::push_errno(&mut out, e);
        ")"
    } else if !probe::pidfile_target_ok(path) {
        ": the path is not an empty file or a psgen pidfile"
    } else {
        let parent = pidfile_parent(path);
        bp_kv_b(&mut out, ": the parent ", parent);
        if !Path::new(OsStr::from_bytes(parent)).exists() {
            " does not exist"
        } else if !sys::is_dir(parent) {
            " is not a directory"
        } else if !sys::access(parent, sys::W_OK) {
            " is not writable"
        } else if probe::pidfile_creatable_errno_bytes(path, bytes) == libc::EFBIG {
            // The one failure a writable parent does not explain. Naming the
            // limit is the difference between a fixable setting and a mystery.
            " is writable but RLIMIT_FSIZE is too small for the pidfile"
        } else {
            // The parent is writable, so the failure was the target name
            // itself. NAME_MAX is one cause, not the only one: PATH_MAX, a
            // filesystem quota, or an unreadable target can fail here too.
            " is writable but the file could not be created (the name may exceed NAME_MAX once the temporary suffix is added, or the filesystem refused it)"
        }
    };
    sys::buf_push_s(&mut out, tail);
    out
}

/// Refuse to overwrite a pidfile that still records live stubs or cannot be
/// read. Returns `true` when the pidfile is absent or has zero live rows.
#[inline(never)]
fn check_pidfile_inactive(p: &[u8]) -> bool {
    match inject::live_pidfile_rows(p) {
        Some(0) => true,
        Some(_) => {
            sys::err_parts(&[
                b"the pidfile ",
                p,
                b" records live processes; stop them first or choose another --pidfile",
            ]);
            false
        }
        None => {
            sys::err_parts(&[
                b"cannot read the existing pidfile ",
                p,
                b"; remove it or choose another --pidfile",
            ]);
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
#[inline(never)]
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
#[inline(never)]
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
    sys::buf_push_s(&mut out, "psgen: ");
    bp_plural(&mut out, got as u64, " row", " rows");
    bp_cnt(&mut out, " of ", want as u64, " could be produced");
    match family {
        Some(f) => bp_kv_s(&mut out, " for family ", corpus::family_name(f)),
        None => sys::buf_push_s(&mut out, " for this host"),
    }
    if let Some(r) = reason {
        bp_kv_s(&mut out, ": ", r);
    }
    if list {
        sys::buf_push_s(&mut out, "; a list never repeats a command (");
        bp_plural(&mut out, distinct, " distinct line", " distinct lines");
        sys::buf_push_s(
            &mut out,
            " can be produced; --no-uniq pads by repeating them). Ask for fewer lines.\n",
        );
    } else {
        sys::buf_push_s(
            &mut out,
            ". Use --repeat-max N to allow more repeats, or ask for fewer rows.\n",
        );
    }
    sys::err(out.as_bytes());
}

#[inline(never)]
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
#[inline(never)]
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
    let on_off = |b: bool| if b { "on" } else { "off" };
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    let mut out = Buf::new();
    bp_kv_s(&mut out, "tier ", prep.tier.name());
    if prep.tier == inject::ExeTier::Shadow {
        if let Some(d) = &prep.shadow_root {
            bp_kv_b(&mut out, " from ", d);
        }
    }
    let tty_s = if !args.tty {
        "off"
    } else if prep.caps.pty {
        "on"
    } else {
        "unavailable on this host"
    };
    bp_kvs_s(
        &mut out,
        "   mem |, tty |, threads |, busy ",
        &[
            on_off(args.mem),
            tty_s,
            on_off(args.threads),
            on_off(args.busy || args.cpu_pct.unwrap_or(0) > 0),
        ],
    );
    let roots = rows.iter().filter(|p| p.parent.is_none()).count();
    let rss: u64 = rows.iter().map(|p| p.rss).sum();
    sys::buf_push_s(&mut out, "\nplan: ");
    bp_plural(&mut out, rows.len() as u64, " stub, ", " stubs, ");
    bp_plural(&mut out, roots as u64, " root; rss ", " roots; rss ");
    bp_cnt(&mut out, "", rss / 1024, " MiB shared");
    if args.mem && prep.phys_estimate_kb > 0 {
        let show_kib = phys_uses_kib(prep.phys_estimate_kb, prep.phys_budget_kb);
        sys::buf_push_s(&mut out, ", ~");
        bp_mem_unit(&mut out, prep.phys_estimate_kb, show_kib, " physical");
        if prep.phys_budget_kb > 0 {
            sys::buf_push_s(&mut out, " (budget ");
            bp_mem_unit(&mut out, prep.phys_budget_kb, show_kib, ")");
        }
        if prep.phys_scale < 1.0 {
            sys::buf_push_s(&mut out, ", scaled");
        }
    }
    let disk = args.disk_mb.unwrap_or(0).saturating_mul(rows.len() as u64);
    if disk > 0 {
        bp_cnt(&mut out, "; disk ", disk, " MiB total over ");
        bp_cnt(&mut out, "", rows.len() as u64, " stubs");
    }
    let dirs = staging_patterns(rows, prep, args);
    sys::buf_push_s(&mut out, "; staging ");
    bp_plural(
        &mut out,
        dirs.len() as u64,
        " directory pattern",
        " directory patterns",
    );
    let parents = staging_parents(&dirs);
    if !parents.is_empty() {
        sys::buf_push_s(&mut out, " under ");
        for (i, p) in parents.iter().enumerate() {
            if i > 0 {
                sys::buf_push_s(&mut out, ", ");
            }
            sys::buf_push_b(&mut out, p);
        }
    }
    bp_c(&mut out, b'\n');
    for (i, p) in rows.iter().enumerate() {
        bp_kv_u(&mut out, "row ", i as u64);
        bp_kv_b(
            &mut out,
            if p.parent.is_none() {
                " root user="
            } else {
                " child user="
            },
            &p.user,
        );
        if create.contains(&p.user) {
            sys::buf_push_s(&mut out, " (would create)");
        }
        bp_kvs_u(&mut out, " vsz=| rss=", &[p.vsz, p.rss]);
        sys::buf_push_s(&mut out, " cpu=");
        out.push_tenths_plain(p.cpu);
        bp_kvs_s(
            &mut out,
            " tty=| threads=",
            &[
                yes_no(p.flags & corpus::F_TTY != 0 && args.tty && prep.caps.pty),
                yes_no(p.flags & corpus::F_THREADS != 0),
            ],
        );
        bp_kv_b(
            &mut out,
            " exe=",
            &gen::template_exe(&corpus::CORPUS[p.tmpl]),
        );
        if let Some(par) = p.parent {
            bp_kv_u(&mut out, " parent=", par as u64);
        }
        bp_c(&mut out, b'\n');
    }
    for d in &dirs {
        bp_kv_b(&mut out, "staging pattern ", d);
        bp_c(&mut out, b'\n');
    }
    sys::out(out.as_bytes());
}

/// `--dry-run --json`: the same plan as one JSON object.
#[inline(never)]
fn print_json_plan(rows: &[gen::Proc], prep: &inject::Prep, create: &[Vec<u8>], args: &Args) {
    let mut out = Buf::new();
    sys::buf_push_s(&mut out, "{\"version\":");
    json_escape(&mut out, crate::version::VERSION.as_bytes());
    jp_s(&mut out, "tier", prep.tier.name().as_bytes());
    jp_k(&mut out, "shadow_root");
    match &prep.shadow_root {
        Some(d) if prep.tier == inject::ExeTier::Shadow => json_escape(&mut out, d),
        _ => sys::buf_push_s(&mut out, "null"),
    }
    jp_u64s(
        &mut out,
        "stubs,roots",
        &[
            rows.len() as u64,
            rows.iter().filter(|p| p.parent.is_none()).count() as u64,
        ],
    );
    jp_bools(
        &mut out,
        "mem,tty,threads,busy",
        &[
            args.mem,
            args.tty && prep.caps.pty,
            args.threads,
            args.busy || args.cpu_pct.unwrap_or(0) > 0,
        ],
    );
    let disk_per = args.disk_mb.unwrap_or(0);
    jp_u64s(
        &mut out,
        "rss_kb,phys_kb,budget_kb,phys_scale,disk_mb_per_stub,disk_mb_total",
        &[
            rows.iter().map(|p| p.rss).sum(),
            prep.phys_estimate_kb,
            prep.phys_budget_kb,
            (prep.phys_scale * 1000.0) as u64,
            disk_per,
            disk_per.saturating_mul(rows.len() as u64),
        ],
    );
    let dirs = staging_patterns(rows, prep, args);
    jp_arr(&mut out, "staging_dirs", &dirs);
    jp_arr(&mut out, "would_create", create);
    sys::buf_push_s(&mut out, ",\"rows\":[");
    for (i, p) in rows.iter().enumerate() {
        if i > 0 {
            bp_c(&mut out, b',');
        }
        bp_kv_u(&mut out, "{\"row\":", i as u64);
        jp_s(
            &mut out,
            "role",
            if p.parent.is_none() {
                b"root"
            } else {
                b"child"
            },
        );
        jp_s(&mut out, "user", &p.user);
        jp_opt_u(
            &mut out,
            "uid",
            (p.uid != UNKNOWN_ID).then_some(p.uid as u64),
        );
        jp_opt_u(
            &mut out,
            "gid",
            (p.gid != UNKNOWN_ID).then_some(p.gid as u64),
        );
        jp_u64s(
            &mut out,
            "vsz_kb,rss_kb,cpu_tenths",
            &[p.vsz, p.rss, p.cpu as u64],
        );
        jp_bools(
            &mut out,
            "tty,threads,busy",
            &[
                p.flags & corpus::F_TTY != 0 && args.tty && prep.caps.pty,
                p.flags & corpus::F_THREADS != 0,
                p.flags & corpus::F_BUSY != 0,
            ],
        );
        jp_s(&mut out, "exe", &gen::template_exe(&corpus::CORPUS[p.tmpl]));
        jp_s(&mut out, "cmd", &p.cmd);
        jp_opt_u(&mut out, "parent", p.parent.map(|par| par as u64));
        bp_c(&mut out, b'}');
    }
    sys::buf_push_s(&mut out, "]}\n");
    sys::out(out.as_bytes());
}

#[inline(never)]
fn err_line(msg: &str) -> i32 {
    sys::err_parts(&[msg.as_bytes()]);
    1
}

#[inline(never)]
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

#[inline(never)]
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

#[inline(never)]
fn resolve_redact_tokens(args: &Args) -> Result<Vec<String>, String> {
    let mut out = args.redact_tokens.clone();
    for f in &args.redact_token_files {
        for tok in profile::read_redact_tokens_file(f)? {
            if !out.contains(&tok) {
                out.push(tok);
            }
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn build_decoy_trees(
    prof: &profile::Profile,
    count: usize,
    level: u8,
    token_prefix: Option<&str>,
    use_tokens: bool,
    force_token: bool,
    jitter_ms: u32,
    seed: u64,
    overrides: Option<&Args>,
) -> Vec<inject::DecoyNodeSpec> {
    let mut rng = Rng::new(seed ^ 0x9e37_79b9_7f4a_7c15);
    let mut trees = Vec::with_capacity(count);
    for _ in 0..count {
        let tok = if use_tokens {
            Some(inject::make_shaped_decoy_token(
                token_prefix,
                prof.memory.token_len,
                prof.memory.token_charset.as_deref(),
                prof.memory.token_sha256.as_deref(),
                &mut rng,
            ))
        } else {
            None
        };
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

#[inline(never)]
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

    #[inline(never)]
    fn extend(&mut self, pids: &[i32]) {
        for &p in pids {
            if p > 1 && !self.pids.contains(&p) {
                self.pids.push(p);
            }
        }
    }
}

impl Drop for LiveCleanup {
    #[inline(never)]
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
            sys::err_parts(&[
                b"another psgen run holds the pidfile ",
                p,
                b"; wait for it to finish or choose another --pidfile",
            ]);
            Err(2)
        }
        Err(e) => {
            let mut out = Buf::new();
            bp_kv_b(&mut out, "psgen: cannot lock the pidfile ", p);
            sys::buf_push_s(&mut out, ": ");
            sys::push_io_err(&mut out, &e);
            bp_c(&mut out, b'\n');
            sys::err(out.as_bytes());
            Err(2)
        }
    }
}

#[inline(never)]
fn lock_and_check_pidfile(pidfile: Option<&[u8]>) -> Result<Option<inject::PidfileLock>, i32> {
    let Some(p) = pidfile else {
        return Ok(None);
    };
    let lock = acquire_pidfile_lock(p)?;
    if !check_pidfile_inactive(p) {
        return Err(2);
    }
    Ok(Some(lock))
}

#[inline(never)]
fn wait_and_cleanup(pids: &[i32], duration: u32) {
    let mut guard = LiveCleanup::new();
    guard.extend(pids);
    sys::nanosleep(duration as u64, 0);
    drop(guard);
}

#[inline(never)]
fn run_profile(args: &Args) -> i32 {
    let redact_tokens = match resolve_redact_tokens(args) {
        Ok(v) => v,
        Err(e) => return err_line(&e),
    };
    let forbidden: Vec<&str> = redact_tokens.iter().map(String::as_str).collect();
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
    eopts.ancestors = !args.no_ancestors;
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
    eopts.redact_tokens = redact_tokens.clone();
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

#[inline(never)]
fn capture_auto_profile(
    pid: i32,
    redact_tokens: &[String],
    redact_envs: &[String],
) -> Result<profile::Profile, String> {
    let mut eopts = profile::ExtractOpts::for_pid(pid);
    eopts.tree = true;
    eopts.ancestors = true;
    eopts.redact_tokens = redact_tokens.to_vec();
    eopts.redact_envs = redact_envs.to_vec();
    let mut prof = profile::extract_live(&eopts)?;
    harness::strip_self_ancestors(&mut prof);
    let forbidden: Vec<&str> = redact_tokens.iter().map(String::as_str).collect();
    prof.validate(&forbidden)?;
    Ok(prof)
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
    let redact_tokens = resolve_redact_tokens(args)?;
    let forbidden: Vec<&str> = redact_tokens.iter().map(String::as_str).collect();
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
        None if args.run_mode == harness::Mode::Table || args.live => Vec::new(),
        None => harness::HardNeg::all().to_vec(),
    };

    let wants_target = !matches!(
        args.run_control,
        harness::Control::C02Hidden | harness::Control::C04NoTarget
    );
    let uses_decoys = matches!(
        args.run_control,
        harness::Control::C01Obvious
            | harness::Control::C02Hidden
            | harness::Control::C04NoTarget
            | harness::Control::C06Main
            | harness::Control::C07HiddenByMask
    );

    if args.live && wants_target && args.target_cmd.is_none() && args.target_pid.is_none() {
        return Err(
            "run --live requires --target-cmd or --target-pid for controls with a target"
                .to_string(),
        );
    }

    let mut prof = if args.seen.contains(&"--profile") {
        load_profile_file(&args.profile, &forbidden)?
    } else if let Some(tpid) = args.target_pid {
        capture_auto_profile(tpid, &redact_tokens, &args.redact_envs)?
    } else if let Some(ref tcmd) = args.target_cmd {
        // Brief probe launch to capture the live target's profile before the blind interleaved run.
        let probe_opts = inject::DecoySpawnOpts {
            duration: 30,
            seed: seed ^ 0x7072_6f62_6500_0001,
            ..inject::DecoySpawnOpts::default()
        };
        let mut probe_guard = LiveCleanup::new();
        let (_, probe_pid, _) = inject::spawn_decoy_trees_interleaved(&[], tcmd, &probe_opts)?;
        probe_guard.extend(&[probe_pid]);
        sys::nanosleep(0, 150_000_000);
        let captured = capture_auto_profile(probe_pid, &redact_tokens, &args.redact_envs);
        drop(probe_guard);
        captured?
    } else {
        return Err(
            "run requires --profile (or --live with --target-cmd/--target-pid)".to_string(),
        );
    };

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

    if args.target_cmd.is_none() {
        if let Some(tpid) = args.target_pid {
            live_target_pids.push(tpid);
        }
    }

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
            let pre_n = if decoy_n <= 1 {
                0
            } else {
                let mut r = Rng::new(seed ^ 0x94d0_49bb_1331_11eb);
                let lo = (decoy_n / 5).max(1) as u64;
                let hi = ((decoy_n * 4) / 5).max(lo as usize).min(decoy_n - 1) as u64;
                r.range(lo, hi) as usize
            };
            all_d.extend(spawn_m(mcmd, pre_n, seed, Some(tok_prefix))?);
            live_target_pids = spawn_m(tcmd, 1, seed ^ 1, None)?;
            all_d.extend(spawn_m(
                mcmd,
                decoy_n.saturating_sub(pre_n),
                seed ^ 2,
                Some(tok_prefix),
            )?);
        } else {
            all_d = spawn_m(mcmd, decoy_n, seed, Some(tok_prefix))?;
        }
        if !all_d.is_empty() || !live_target_pids.is_empty() {
            sys::nanosleep(0, 150_000_000);
        }
        live_decoy_pids = filter_root_pids(&all_d);
        synthetic_decoys = 0;
    } else {
        let trees = if args.live && decoy_n > 0 {
            let use_tokens = args.run_level >= 5 || args.decoy_token.is_some();
            build_decoy_trees(
                &prof,
                decoy_n,
                args.run_level,
                args.decoy_token.as_deref(),
                use_tokens,
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
            jitter_ms: eff_jitter,
            churn: args.churn,
            seed,
            bind_exe: !args.no_exe && !args.no_root,
            ..inject::DecoySpawnOpts::default()
        };
        if let Some(tcmd) = args.target_cmd.as_ref().filter(|_| wants_target) {
            let (mut pre, tgt, suf) =
                inject::spawn_decoy_trees_interleaved(&trees, tcmd, &spawn_opts)?;
            cleanup.extend(&pre);
            cleanup.extend(&[tgt]);
            cleanup.extend(&suf);
            sys::nanosleep(0, 150_000_000);
            live_target_pids.push(tgt);
            pre.extend_from_slice(&suf);
            live_decoy_pids = filter_root_pids(&pre);
        } else if !trees.is_empty() {
            let decs = inject::spawn_decoy_trees(&trees, &spawn_opts)?;
            cleanup.extend(&decs);
            live_decoy_pids = filter_root_pids(&decs);
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
        redact_tokens,
        redact_envs: args.redact_envs.clone(),
        live_mode: args.live,
    };

    let res = harness::build_run(&run_opts);
    drop(cleanup);
    let res = res?;

    let mut w = json::Jw::new(false);
    w.obj_open();
    w.k_strs(
        "run_id,out_dir",
        &[&res.run_id, &res.out_dir.to_string_lossy()],
    );
    w.k_opt_str(
        "blind_dir",
        &res.blind_dir
            .as_ref()
            .map(|b| b.to_string_lossy().into_owned()),
    );
    w.k_i32_arr("target_pids", &res.target_pids);
    w.k_i64s(
        "decoy_count,hn_count,total_rows,manifest_files",
        &[
            res.decoy_count as i64,
            res.hn_count as i64,
            res.total_rows as i64,
            res.manifest_files as i64,
        ],
    );
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
    let redact_tokens = match resolve_redact_tokens(args) {
        Ok(v) => v,
        Err(e) => return err_line(&e),
    };
    let pick_path = args.pick.as_deref().map(Path::new);
    let blind_dir = args
        .blind_dir
        .as_deref()
        .map(|p| Path::new(OsStr::from_bytes(p)));
    let forbidden: Vec<&str> = redact_tokens.iter().map(String::as_str).collect();
    let ver = match score::verify_run_with_blind(
        Path::new(OsStr::from_bytes(rd)),
        pick_path,
        blind_dir,
        &forbidden,
    ) {
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
fn append_pidfile_rows(path: &[u8], pids: &[i32]) -> bool {
    if pids.is_empty() {
        return true;
    }
    let p = Path::new(OsStr::from_bytes(path));
    if !p.exists() {
        return inject::write_external_pidfile(path, pids);
    }
    let Ok(mut body) = std::fs::read(p) else {
        return false;
    };
    if !body.is_empty() && !body.ends_with(b"\n") {
        body.push(b'\n');
    }
    let mut line = Buf::new();
    for &pid in pids {
        line.v.clear();
        sys::buf_push_u(&mut line, pid as u64);
        if let Some(st) = live::read_starttime(pid) {
            bp_kv_u(&mut line, "\t", st);
            if let Some(comm) = live::read_comm(pid) {
                bp_kv_b(&mut line, "\t", &comm);
            }
        }
        bp_c(&mut line, b'\n');
        body.extend_from_slice(line.as_bytes());
    }
    std::fs::write(p, &body).is_ok()
}

#[inline(never)]
fn rng_for(seed: Option<u64>) -> Rng {
    match seed {
        Some(s) => Rng::new(s),
        None => Rng::from_entropy(),
    }
}

#[inline(never)]
fn check_cap(count: usize, cap: usize, def: usize, label: &str) -> usize {
    if count > cap {
        let mut out = Buf::new();
        bp_kv_s(&mut out, "psgen: ", label);
        bp_cnt(&mut out, " count capped at ", cap as u64, "\n");
        sys::err(out.as_bytes());
    }
    if count == 0 {
        def
    } else {
        count.min(cap)
    }
}

#[inline(never)]
fn check_shortfall(args: &Args, got: usize, want: usize, list: bool, reason: Option<&str>) {
    shortfall(
        args.family,
        got,
        want,
        list,
        reason,
        gen::distinct_supply(
            args.family,
            &corpus::profile_weights(&args.profile),
            args.seen.contains(&"--profile"),
        ),
    );
}

fn cleanup_pending(pending: bool, pidfile: Option<&[u8]>) {
    if pending {
        if let Some(p) = pidfile {
            rm_bytes(p);
        }
    }
}

#[inline(never)]
fn run_inject_decoy(args: &Args) -> i32 {
    let count = check_cap(args.count, 500, 1, "inject");
    let seed = args.seed.unwrap_or(1234);

    if let Some(ref p) = args.pidfile {
        if !check_pidfile_inactive(p) {
            return 2;
        }
    }
    let _pidfile_lock = match lock_and_check_pidfile(args.pidfile.as_deref()) {
        Ok(lock) => lock,
        Err(code) => return code,
    };

    let pids = if let Some(ref prof_path) = args.from_profile {
        let prof = match load_profile_file(prof_path, &[]) {
            Ok(p) => p,
            Err(e) => return err_line(&e),
        };
        let level = args.decoy_level.unwrap_or(5);
        let use_tokens = args.decoy_token.is_some() || level >= 5;
        let trees = build_decoy_trees(
            &prof,
            count,
            level,
            args.decoy_token.as_deref(),
            use_tokens,
            args.decoy_token.is_some(),
            args.jitter_ms,
            seed,
            Some(args),
        );
        let opts = inject::DecoySpawnOpts {
            duration: args.duration,
            pidfile: args.pidfile.clone(),
            clean_env: !args.no_clean_env,
            jitter_ms: args.jitter_ms,
            churn: args.churn,
            seed,
            quiet: args.quiet,
            wait: args.wait && args.label_decoys == 0 && args.interleave_cmd.is_none(),
            bind_exe: !args.no_exe && !args.no_root,
            same_session: args.same_session,
            label_decoys: args.label_decoys,
            interleave_cmd: args.interleave_cmd.clone(),
        };
        let mut spawned = if let Some(ref icmd) = opts.interleave_cmd {
            match inject::spawn_decoy_trees_interleaved(&trees, icmd, &opts) {
                Ok((mut pre, _tgt, suf)) => {
                    pre.extend_from_slice(&suf);
                    pre
                }
                Err(e) => return err_line(&e),
            }
        } else {
            match inject::spawn_decoy_trees(&trees, &opts) {
                Ok(v) => v,
                Err(e) => return err_line(&e),
            }
        };
        if opts.label_decoys > 0 {
            let lbl_pids = match inject::spawn_label_decoys(
                &prof.identity.label,
                &prof.identity.comm,
                opts.label_decoys,
                &opts,
            ) {
                Ok(v) => v,
                Err(e) => return err_line(&e),
            };
            if let Some(ref pf) = args.pidfile {
                if !append_pidfile_rows(pf, &lbl_pids) && !args.quiet {
                    sys::err(b"psgen: cannot append label decoys to pidfile\n");
                }
            }
            spawned.extend_from_slice(&lbl_pids);
        }
        if args.wait
            && args.duration > 0
            && (args.label_decoys > 0 || args.interleave_cmd.is_some())
        {
            wait_and_cleanup(&spawned, args.duration);
        }
        spawned
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
            wait_and_cleanup(&spawned, args.duration);
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
        bp_cnt(&mut out, "spawned ", pids.len() as u64, " processes");
        if let Some(ref path) = args.pidfile {
            bp_kv_b(&mut out, ", pids in ", path);
        }
        bp_c(&mut out, b'\n');
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

#[inline(never)]
fn run_corpus() -> i32 {
    let mut out = Buf::new();
    for t in corpus::CORPUS.iter() {
        sys::buf_push_s(&mut out, corpus::family_name(t.fam));
        bp_kv_s(&mut out, "\t", t.user);
        bp_kv_u(&mut out, "\t", t.vsz as u64);
        bp_kv_u(&mut out, "\t", t.rss as u64);
        bp_kv_s(&mut out, "\t", t.cmd);
        bp_c(&mut out, b'\n');
    }
    sys::out(out.as_bytes());
    0
}

#[inline(never)]
fn run_check(args: &Args) -> i32 {
    let mut rng = Rng::new(args.seed.unwrap_or(1));
    let opts = make_gen_opts(
        args,
        0,
        args.seed.unwrap_or(1),
        b"deploy".to_vec(),
        None,
        None,
    );
    check::run(&mut rng, &opts, args.binaries, args.require_binaries)
}

#[inline(never)]
fn run_unit(args: &Args) -> i32 {
    let count = check_cap(args.count, 500, 24, "unit");
    let pidfile = args
        .pidfile
        .clone()
        .unwrap_or_else(|| b"/run/psgen/psgen.pid".to_vec());
    let out = unit::render(count, args.seed.unwrap_or(7), &pidfile, args);
    sys::out(out.as_bytes());
    0
}

#[inline(never)]
fn run_stop(args: &Args) -> i32 {
    let path = match &args.pidfile {
        Some(p) => p,
        None => {
            sys::err(b"psgen: stop needs --pidfile\n");
            return 2;
        }
    };
    inject::stop(path, args.force, args.plan, args.quiet)
}

#[inline(never)]
fn run_list(args: &Args) -> i32 {
    let _ = check_cap(args.count, 2000, 0, "list");
    let mut rng = rng_for(args.seed);
    let opts = make_gen_opts(
        args,
        list_target(args),
        args.seed.unwrap_or(0),
        util::current_user().name,
        args.repeat_max,
        args.host_uptime,
    );
    let mut cmds = gen::gen_list(&mut rng, &opts);
    if lists_count(args) {
        let want = if args.count == 0 {
            list_target(args)
        } else {
            args.count.min(2000)
        };
        check_shortfall(args, cmds.len(), want, true, None);
    }
    if args.sort {
        json::shell_sort_by(&mut cmds, |a, b| a > b);
    }
    let mut out = Buf::with_capacity(cmds.len() * 96);
    for c in &cmds {
        sys::buf_push_b(&mut out, c);
        bp_c(&mut out, b'\n');
    }
    sys::out(out.as_bytes());
    0
}

#[inline(never)]
fn run_table(args: &Args) -> i32 {
    let want = check_cap(args.count, 5000, if args.live { 0 } else { 30 }, "table");
    if args.live {
        let mut rows = live::read_all();
        if want > 0 && rows.len() > want {
            rows.truncate(want);
        }
        let out = table::render(
            &rows,
            live::mem_total_kb(),
            &table::Clock::live(sys::now_secs()),
            sys::page_kb(),
        );
        sys::out(out.as_bytes());
        return 0;
    }
    let mut rng = rng_for(args.seed);
    let opts = make_gen_opts(
        args,
        want,
        args.seed.unwrap_or(0),
        util::current_user().name,
        args.repeat_max,
        args.host_uptime,
    );
    let fit = gen::Fit::target(args.host_mem_mb, args.host_pid_max);
    let rows = gen::gen_table(&mut rng, &opts, &fit);
    let has_init = rows.iter().any(|r| r.pid == 1);
    check_shortfall(
        args,
        rows.len(),
        want,
        false,
        fit.shortfall_reason_for(rows.len(), want, has_init)
            .as_deref(),
    );
    let mem_kb = match args.host_mem_mb {
        Some(mb) => mb.saturating_mul(1024),
        None => table::mem_budget_kb(),
    };
    let out = table::render(
        &rows,
        mem_kb,
        &synthetic_clock(args, sys::now_secs()),
        sys::page_kb(),
    );
    sys::out(out.as_bytes());
    0
}

#[inline(never)]
fn run_inject_corpus(args: &Args) -> i32 {
    if args.from_profile.is_some() || args.masker_cmd.is_some() {
        return run_inject_decoy(args);
    }
    let want = check_cap(args.count, 500, 12, "inject");
    let me = users::current();
    let mut rng = rng_for(args.seed);
    let opts = make_gen_opts(
        args,
        want,
        args.seed.unwrap_or(0),
        me.name,
        args.repeat_max,
        args.host_uptime,
    );
    let mut rows = gen::gen_inject(&mut rng, &opts, &gen::Fit::none());

    if args.dry_run {
        if let Some(p) = &args.pidfile {
            if inject::pidfile_lock_held(p) {
                sys::err_parts(&[
                    b"another psgen run holds the pidfile ",
                    p,
                    b"; wait for it to finish or choose another --pidfile",
                ]);
                return 2;
            }
        }
    }

    let mut blockers = 0usize;
    let tmpdir = std::env::temp_dir();
    let tmpdir_b = tmpdir.as_os_str().as_bytes();
    let tmpdir_len = tmpdir_b.len();
    let mut probed_bytes = 0usize;
    if let Some(p) = &args.pidfile {
        let init_temps = if args.disk_mb.unwrap_or(0) > 0 {
            rows.len()
        } else {
            0
        };
        let need_bytes = inject::estimated_pidfile_bytes(rows.len(), init_temps, tmpdir_len);
        probed_bytes = need_bytes;
        if !probe::pidfile_creatable_bytes(p, need_bytes) {
            let mut out = pidfile_error_bytes(p, need_bytes);
            for cand in [
                tmpdir.join("psgen-pids.txt"),
                PathBuf::from("psgen-pids.txt"),
            ] {
                let b = cand.as_os_str().as_bytes();
                if probe::pidfile_creatable_bytes(b, need_bytes) {
                    bp_kv_b(&mut out, "; use ", b);
                    sys::buf_push_s(&mut out, " instead");
                    break;
                }
            }
            bp_c(&mut out, b'\n');
            sys::err(out.as_bytes());
            blockers += 1;
        }
    }
    check_shortfall(
        args,
        rows.len(),
        want,
        false,
        gen::Fit::none()
            .shortfall_reason_for(rows.len(), want, false)
            .as_deref(),
    );

    if let Some(mb) = args.disk_mb {
        if mb > 0 {
            if let Some(limit) = sys::rlimit_fsize() {
                if mb.saturating_mul(1024 * 1024) > limit {
                    let mut out = Buf::new();
                    bp_cnt(
                        &mut out,
                        "psgen: --disk ",
                        mb,
                        " MiB exceeds RLIMIT_FSIZE (",
                    );
                    bp_cnt(&mut out, "", limit / 1024 / 1024, " MiB)\n");
                    sys::err(out.as_bytes());
                    blockers += 1;
                }
            }
            let total_mb = mb.saturating_mul(rows.len() as u64);
            if let Some((free, _)) = probe::space(tmpdir_b) {
                if total_mb.saturating_mul(1024 * 1024) > free.saturating_sub(free / 10) {
                    let mut out = Buf::new();
                    bp_cnt(&mut out, "psgen: --disk ", mb, " MiB x ");
                    bp_cnt(&mut out, "", rows.len() as u64, " rows needs ");
                    bp_cnt(&mut out, "", total_mb, " MiB, more than the free space in ");
                    sys::buf_push_b(&mut out, tmpdir_b);
                    bp_cnt(&mut out, " (", free / 1024 / 1024, " MiB)\n");
                    sys::err(out.as_bytes());
                    blockers += 1;
                }
            }
        }
    }
    if blockers > 0 {
        return 2;
    }

    if let Some(p) = &args.pidfile {
        if !check_pidfile_inactive(p) {
            return 2;
        }
    }

    let prep = inject::prepare(&mut rows, args, args.create_users && !args.dry_run);

    if let Some(p) = &args.pidfile {
        let temps_est = staging_patterns(&rows, &prep, args).len();
        let dir_len = prep
            .shadow_root
            .as_deref()
            .map_or(tmpdir_len, |s| tmpdir_len.max(s.len()));
        let need_bytes = inject::estimated_pidfile_bytes(rows.len(), temps_est, dir_len);
        if need_bytes > probed_bytes && !probe::pidfile_creatable_bytes(p, need_bytes) {
            let mut out = pidfile_error_bytes(p, need_bytes);
            bp_c(&mut out, b'\n');
            sys::err(out.as_bytes());
            return 2;
        }
    }

    if args.dry_run {
        let create = would_create(&mut rows, args);
        for name in &create {
            sys::err_parts(&[b"would create ", name]);
        }
        if args.json {
            print_json_plan(&rows, &prep, &create, args);
        } else if args.plan {
            print_plan(&rows, &prep, &create, args);
        } else {
            let mut out = Buf::new();
            for p in &rows {
                sys::buf_push_b(&mut out, &p.user);
                bp_kv_b(&mut out, "\t", &p.cmd);
                bp_c(&mut out, b'\n');
            }
            sys::out(out.as_bytes());
        }
        print_notes(&prep, args);
        return 0;
    }

    let _pidfile_lock = match lock_and_check_pidfile(args.pidfile.as_deref()) {
        Ok(lock) => lock,
        Err(code) => return code,
    };

    let pruned = inject::prune_staging(&prep);
    if pruned > 0 {
        let mut out = Buf::new();
        bp_cnt(
            &mut out,
            "psgen: pruned ",
            pruned as u64,
            " staging directories from earlier runs\n",
        );
        sys::err(out.as_bytes());
    }

    let mut pending_written = false;
    if let Some(p) = &args.pidfile {
        pending_written = inject::write_pending_pidfile(p);
        if !pending_written {
            let mut out = pidfile_error(p);
            sys::buf_push_s(
                &mut out,
                " (the pidfile could not be written before spawning)\n",
            );
            sys::err(out.as_bytes());
            return 2;
        }
    }

    print_notes(&prep, args);
    let result = match inject::spawn(&rows, args, &prep) {
        Ok(r) => r,
        Err(e) => {
            cleanup_pending(pending_written, args.pidfile.as_deref());
            return err_line(&e);
        }
    };
    print_summary(&prep, &result, args);

    if result.pids.is_empty() {
        cleanup_pending(pending_written, args.pidfile.as_deref());
        return err_line("no processes were spawned");
    }
    let pidfile_failed = !result.pidfile_ok;
    if pidfile_failed {
        let mut out = Buf::new();
        sys::buf_push_s(
            &mut out,
            "psgen: the pidfile was not written; spawned PIDs:",
        );
        for pid in &result.pids {
            bp_kv_u(&mut out, " ", *pid as u64);
        }
        bp_c(&mut out, b'\n');
        for t in &result.temps {
            bp_kv_b(&mut out, "psgen: temp dir ", t.as_os_str().as_bytes());
            bp_c(&mut out, b'\n');
        }
        if let Some(p) = &args.pidfile {
            rm_bytes(p);
            if !result.pids.is_empty() {
                if let Some(sidecar) =
                    inject::write_pid_sidecar(p, &result.pids, &result.temps, &result.nonce)
                {
                    bp_kv_b(&mut out, "psgen: the spawned rows are in ", &sidecar);
                    bp_kv_b(
                        &mut out,
                        "; stop them with: psgen stop --pidfile ",
                        &sidecar,
                    );
                    bp_c(&mut out, b'\n');
                }
            }
        }
        sys::err(out.as_bytes());
    }
    let mut code = 0;
    if result.failed > 0 || result.missing > 0 || !result.mismatches.is_empty() || pidfile_failed {
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
        for _ in 0..200 {
            let mut status = 0;
            while sys::waitpid_nohang(-1, &mut status) > 0 {}
            if !result.pids.iter().any(|pid| live::alive(*pid)) {
                break;
            }
            sys::nanosleep(0, 10_000_000);
        }
        for t in &result.temps {
            if !inject::staging_busy(t) {
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

pub fn run() -> i32 {
    let argv: Vec<Vec<u8>> = std::env::args_os().map(|s| s.as_bytes().to_vec()).collect();
    if argv.is_empty() {
        sys::err(b"psgen: cannot read argv\n");
        return 2;
    }
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(msg) => {
            sys::err_parts(&[
                msg.as_str().as_bytes(),
                b"\n(psgen --help for the full option list)",
            ]);
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
        Sub::Corpus => run_corpus(),
        Sub::Check => run_check(&args),
        Sub::Unit => run_unit(&args),
        Sub::Stop => run_stop(&args),
        Sub::List => run_list(&args),
        Sub::Table => run_table(&args),
        Sub::Inject => run_inject_corpus(&args),
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

    #[test]
    fn track_d_new_cli_flags_and_optional_live_profile() {
        let p = parse_strs(&[
            "profile",
            "--pid",
            "99",
            "--tree",
            "--no-ancestors",
            "--redact-token-file",
            "/tmp/toks.txt",
        ])
        .unwrap();
        assert!(p.no_ancestors);
        assert_eq!(p.redact_token_files, vec!["/tmp/toks.txt"]);
        assert!(!ok(&[
            "profile",
            "--validate",
            "/tmp/p.json",
            "--no-ancestors"
        ]));

        let inj = parse_strs(&[
            "inject",
            "--from-profile",
            "/tmp/p.json",
            "--no-clean-env",
            "--same-session",
            "--label-decoys",
            "5",
            "--interleave-cmd",
            "exec /bin/sleep 5",
        ])
        .unwrap();
        assert!(inj.no_clean_env);
        assert!(inj.same_session);
        assert_eq!(inj.label_decoys, 5);
        assert_eq!(inj.interleave_cmd.as_deref(), Some("exec /bin/sleep 5"));
        assert!(!ok(&["inject", "--no-clean-env"]));
        assert!(!ok(&["inject", "--same-session"]));
        assert!(!ok(&["inject", "--label-decoys", "5"]));
        assert!(!ok(&["inject", "--interleave-cmd", "sleep 1"]));

        // `run --live` with `--target-cmd` or `--target-pid` no longer requires `--profile`.
        let r1 = parse_strs(&[
            "run",
            "--live",
            "--target-cmd",
            "exec /bin/sleep 5",
            "--out",
            "/tmp/run",
            "--redact-token",
            "SEC",
            "--redact-token-file",
            "/tmp/t.txt",
            "--redact-env",
            "API_KEY",
        ])
        .unwrap();
        assert!(r1.live);
        assert_eq!(r1.redact_tokens, vec!["SEC"]);
        assert_eq!(r1.redact_token_files, vec!["/tmp/t.txt"]);
        assert_eq!(r1.redact_envs, vec!["API_KEY"]);
        assert!(ok(&[
            "run",
            "--live",
            "--target-pid",
            "42",
            "--out",
            "/tmp/run"
        ]));
        assert!(!ok(&["run", "--live", "--out", "/tmp/run"]));

        let v = parse_strs(&[
            "verify",
            "/tmp/r1",
            "--blind-dir",
            "/tmp/b1",
            "--redact-token-file",
            "/tmp/t.txt",
        ])
        .unwrap();
        assert_eq!(v.blind_dir.as_deref(), Some(&b"/tmp/b1"[..]));
        assert_eq!(v.redact_token_files, vec!["/tmp/t.txt"]);
    }
}
