# Changelog

## Unreleased

### Fixed

- `log --lines 0` is a usage error instead of a successful run with no output,
  and the cap warning names events rather than lines.
- A `load` run with no utilization option, or with every option at zero, is
  refused with a message that names the missing or useless values.
- `load --disk-util` measures the temporary directory before it compares the
  request with `RLIMIT_FSIZE`, so a missing `TMPDIR` is reported as the cause
  instead of a second limit hiding it.
- `inject --plan` prints the staging directories as patterns with the fields
  filled at spawn, and lists a directory a run would create even when `--disk`
  is absent but a bind-tier executable is missing.
- A preview (`--dry-run`, `--plan`, `--json`) refuses a pidfile that records
  live rows exactly when a real run would.
- `unit` refuses a pidfile whose final component is `.`, `..`, over `NAME_MAX`
  or a control byte, and a runtime directory name that is non-UTF-8 or carries
  a quote or backslash. It also refuses a pidfile more than one directory below
  `/run` instead of printing a unit that fails at boot.
- `doctor --json` refuses a pidfile path that is not valid UTF-8, because the
  JSON string encoder cannot represent it without a collision; the text report
  escapes a control or invalid byte as `\xNN`.
- `stop` reports an unreadable pidfile with the path and the OS error, and
  exits 1. A header may follow leading comment lines but must precede every
  content line.
- `--host-pid-max` and `--host-uptime` cover the whole PID range: `3` yields one
  row beside PID 1, and an uptime of `0` is refused instead of printing a table
  whose START is before the boot.
- A VSZ or RSS above 4 GiB is printed at full width instead of clamped to
  `u32::MAX`, a `/proc/PID/status` larger than 8 KiB is read whole, and a tty
  name is printed only when the device node exists, so a stale `tty_nr` shows
  `?`.
- `%CPU` divides by `CLOCK_BOOTTIME`, which is the clock `/proc` start times are
  relative to, and warns once when `/proc/uptime` disagrees.
- `load --mem-util` reads the cgroup limit as the denominator when one applies,
  and refuses when the current usage under that limit cannot be read.
- A pidfile is written under an exclusive lock beside it, a second injector is
  refused while the lock is held, and a run past `RLIMIT_FSIZE` fails with
  `EFBIG` rather than dying with live stubs and no record. A body that cannot be
  written after spawning removes the pending file, or leaves a `.spawned`
  sidecar naming the rows, and exits 1.
- A profile that gives a family weight zero no longer contributes rows to
  `table`, `inject` or `list`; a fixed template is a fill candidate with room
  one, and `--repeat-max 1` reaches the in-scope template count instead of
  losing slots to collisions.
- The `list` shortfall warning reports the distinct lines the writer can
  produce, from the same ranges the writer draws, instead of an estimate that
  could promise new lines.
- The capability probe reports a missing temporary directory or a failed fork
  as "not attempted" instead of as a denial of the capability it names, and
  `--create-users` resolves `useradd` by absolute path rather than through the
  caller's `PATH`.
- A stdout write error other than `EPIPE` exits 1 with the errno instead of
  reporting a successful run; a closed reader still ends the run quietly.
- The release workflow fails a final tag when `CARGO_REGISTRY_TOKEN` is unset
  and verifies with `cargo info` that the registry serves the version before it
  reports success. The README now says `v0.0.2` is not on crates.io.

### Changed

- An explicit `-p` excludes a family its profile weights at zero; the bare
  default profile still lists the whole corpus.
- `--repeat-max` bounds distinct command lines, not templates: a template with
  a placeholder may supply one line per distinct value, while a fixed command
  supplies one.

## 0.0.2

### Fixed

- `table --live` renders START in the host's own zone, matching the `ps aux`
  beside it, and `inject --table` uses the same renderer. `--local` and
  `--utc-offset` apply to the synthetic table only and are usage errors on a
  live one.
- `%MEM` divides by `MemTotal` from `/proc/meminfo` in every table, including
  `inject --table` and a container with a cgroup limit; the value truncates to
  one decimal and is capped at 999.
- A live row carries its real `utime + stime` as TIME, and its start time from
  `/proc`, so START and TIME do not drift from `ps`.
- `%CPU` uses the sub-second part of `CLOCK_BOOTTIME` as the elapsed time, and
  prints an integer at or above 100.0 so the field keeps its four columns.
- STAT carries the full `pr_stat` flag set: state, `<`/`N` for nice, `L` for
  locked pages, `s`, `l` and `+`.
- TTY resolves the device name for serial, virtual and pty majors, so a
  container console shows `hvc0` rather than `?`.
- COMMAND writes no raw line break, so a `\n` in argv cannot split a row;
  control bytes become `?`, a zombie gets ` <defunct>`, and a command line is
  read up to 512 KiB and printed up to the 128 KiB `ps` buffer.
- A numeric field wider than its slot eats the padding after it instead of
  pushing STAT, START, TIME and COMMAND to the right, and `inject --table`
  prints in PID order.
- A seed is reproducible across seconds: every age is drawn from a fixed-size
  modulus and every row derives from one snapshot instant.
- A synthetic row never starts before the boot of the host it describes and
  never in the future, and a row on another calendar day prints `%b%d` rather
  than a clock time.
- PostgreSQL background workers and client backends are children of the
  postmaster in one session, with STAT `S` rather than `Ss`.
- `--local` overrides `--utc-offset` instead of shifting START twice, and
  `--utc-offset` is bounded to ±1440 minutes.
- `-n` is met whenever an in-scope template can repeat. A template that stands
  for `inst` processes keeps that instance count, the rest of the rows are split
  evenly over the templates that can repeat, and the busiest command line stays
  at `max(inst, ceil(rows / k))` for `k` repeatable templates. A family that
  cannot supply the count says so on stderr with the number it can supply.
- A synthetic table holds at most `pid_max - 1` rows beside PID 1, never
  repeats a PID, and reports the gap with the numbers.
- A synthetic row never claims more RSS than the host it describes has, so
  `%MEM` stays below 100 on a small host.
- The pidfile header is written with the version from `Cargo.toml` and parsed
  without interpreting it, so a pidfile from another release still gets the
  boot-id check.
- A pidfile psgen wrote is accepted by the next `inject`, by `stop` and by
  `doctor`.
- `stop` refuses a file with no psgen header, and a header with an empty or
  missing boot id, instead of signalling whatever the file names. `--force`
  remains the escape hatch.
- `stop` skips a zombie rather than counting it as stopped, and waits, bounded
  at two seconds, until every signalled PID is gone or a zombie before it
  prints `stopped N`. A second `stop` reports `stopped 0 processes`.
- `stop` signals the deepest PIDs first, so a root's group kill cannot make the
  per-line count depend on scheduling.
- `stop` identifies a one-field line by the run nonce the header records,
  read from the process environment. That covers proc-self, shadow and
  bind-tier rows; a header with no nonce refuses one-field lines, and a
  process without the nonce is skipped. The executable is only named in the
  skip message, never treated as a match.
- The pidfile preflight proves the whole write — the body size the writer will
  emit, the mode, the rename and the link count of an existing target — and
  builds exactly the temporary name the writer creates. A basename near
  `NAME_MAX` now fails before anything is spawned, with a message that names
  the real cause.
- A header-only pidfile is written before the first stub is forked, so a later
  failure never leaves live stubs with no record of how to stop them.
- `--duration` runs that nobody stops leave their staging directories behind;
  `stop` on the run's pidfile removes them, and the next `inject` prunes any that
  remain in the temporary directory or the default shadow roots. The prune keeps
  a directory whose live marker records a live process or another PID namespace,
  and removes one whose owner and every marked process are gone.
- `--wait` keeps a staging directory that a non-reporting stub still uses, by
  asking the live marker.
- `--mem-util` is refused above `MemAvailable` unless `--force` is given.
- `log --lines` is capped at 200000, the buffer is flushed in bounded chunks,
  and a closed reader stops the generator.
- `load` writes its summary to stdout, and `-q` suppresses it.
- `check --binaries` keeps the absolute path a command names, searches `PATH`
  for a bare name, and resolves a symlinked executable, so an installed daemon
  is no longer reported missing.
- `--create-users` repairs a host that has the group but not the user, keeps
  the first `useradd` error rather than the last, and stops retrying when the
  account exists but NSS cannot see it.
- A uid with no passwd entry renders as its decimal value, which is what `ps`
  prints for the same process.

### Unit, doctor and output

- The unit's `RuntimeDirectory=` is the pidfile's own directory instead of a
  fixed `psgen`, so `unit --pidfile /run/x/y.pid` names a directory the manager
  creates. A pidfile directly in `/run` declares no runtime directory, and a
  path outside `/run` is refused with exit 2 rather than printed into a service
  that fails at every boot.
- Two units no longer share one managed directory: the directory is per
  pidfile, and `RuntimeDirectoryPreserve=yes` keeps it across a stop, so
  stopping one unit cannot delete a pidfile another unit still uses.
- `unit` runs the same pidfile preflight as `inject`, so a path `inject` would
  refuse is never printed. A path only root can write is printed with a warning
  that the unit runs as root.
- `unit::arg` escapes `$` as `$$` and quotes a path containing `'`; a byte
  below `0x20`, which a unit file cannot name, is refused with exit 2.
- `ExecStop` no longer carries the `-` prefix, which reported a foreign boot id,
  a malformed pidfile and a refused signal as a successful stop. The absence
  test is a `/bin/sh -c` condition on the pidfile, and a second
  `ExecStop=-/bin/rm` removes the pidfile so the service restarts.
- `doctor --pidfile` answers the question `inject` asks: a pidfile that records
  live rows is `DENY`, not `ALLOW`, and the report carries the reason.
- `doctor --json` escapes every non-ASCII byte as `\u00XX` instead of mapping it
  to `?`, so `/tmp/aéb.pid` and `/tmp/aèb.pid` are two values. The pidfile report
  is an object with `path`, `allowed`, `writable`, `live_rows` and `detail`.
- A write error on stdout other than `EPIPE` is an error: `sys::out` exits 1
  with the errno instead of reporting success.
- `bpf_allowed()` probes `BPF_MAP_CREATE` with a well-formed attribute instead
  of `BPF_MAP_LOOKUP_ELEM` with a null one, so a kernel that forbids map
  creation for this uid reports `blocked` rather than `allowed`.

### Added

- `--repeat-max N` bounds how often one command line may appear in a `table` or
  `inject` run: `1` never repeats a command, `0` removes the bound.
- `--host-mem MiB`, `--host-pid-max N` and `--host-uptime S` generate a table
  for a named host instead of this one; `--host-mem 0` and `--host-pid-max 0`
  are usage errors.
- `--plan` and `--json` with `--dry-run` print the resolved plan — exe tier,
  per-row user, sizes, CPU, tty, threads, exe and parent, the physical estimate
  and the staging directories — instead of the two-column preview. The
  two-column format is unchanged.
- `stop --plan` prints what would be signalled and signals nothing.
- `check --require-binaries` exits 1 when any template executable is missing;
  `--binaries` reports the same list and exits 0.
- `doctor --json` checks are objects with a `name` field, `core` and `core_ok`
  say what "ok" covers, and the pidfile report is an object with `path` and
  `writable`.
- `log -m list` prints the fourteen module names on one line, then one line per
  module that accepts aliases with the aliases in parentheses.
- The printed unit uses a `RuntimeDirectory` derived from the pidfile and
  preserved across a stop, an `ExecStop` guarded by a `/bin/sh` absence test
  plus an `ExecStop=-/bin/rm` for the pidfile, `After=local-fs.target
  sysinit.target` and `ConditionPathExists=/proc/1/stat`, and forwards every
  inject option it was given.
- `tests/proof_cases/report.sh` demonstrates the report and utility issues
  (#8, #13, #19, #20, #21, #23, #24, #27) one case at a time, against systemd,
  `ps`, the kernel and the filesystem rather than psgen's own output. It runs
  from `tests/smoke.sh`. Each case fails on the commit before its fix; a case
  that needs a host capability this machine lacks prints `SKIP` with the
  reason, and `PSGEN_REQUIRE_ALL=1` turns that skip into a failure.

### Changed

- An option a subcommand does not consume is a usage error with exit 2, not a
  silent no-op. That includes a flag that only applies to another mode:
  `table --live --local`, `stop --dry-run` and `inject --dry-run --table` all
  exit 2.
- `list` sorts its lines by default; `--no-sort` keeps corpus order. `-p`
  weights which templates a list, table or inject run draws.
- `inject --dry-run` prints the identity the run would use under
  `--create-users` and reports the accounts it would create, instead of
  creating nothing and falling back to the caller.
- A preview runs the same preflights as the real run — pidfile writability,
  free space, `RLIMIT_FSIZE` — and exits non-zero for a command line the real
  run would refuse.
- `gen_list`'s duplicate check is a `BTreeSet`, so `list -n 2000` is not
  quadratic.

### Security

- The stub refuses to run from a setuid or setgid installation.
- The stub acts on a config descriptor only when the descriptor is a sealed
  memfd or an unlinked file, is owned by the uid the stub runs as, is not on
  FUSE or overlayfs, and carries the run's nonce in `PSGEN_NONCE`.
- The stub only writes into, and only executes from, a staging directory that
  passes the ownership and name rule `stop` uses, and identifies the leaf it
  executes by the opened descriptor: regular file, one link, the right owner,
  and for a root run not on FUSE or overlayfs.
- `inject --pidfile` never aborts after the stubs are spawned when entropy is
  unavailable: the nonce falls back to a pid and clock mix, so the pidfile is
  written and the run stays stoppable.

## 0.0.1

Initial release.

- `list`, `table` and `table --live` generate process lists and `ps aux` style
  tables.
- `inject` starts a synthetic process tree in the real process table with bind,
  shadow and proc-self exe tiers, user switching, ptys, threads and VSZ/RSS
  padding.
- `stop` terminates a run from its pidfile; `--wait` stops it after a duration.
- `doctor` probes the environment; `log` and `load` generate activity and
  pressure.
- `corpus`, `check` and `unit` inspect the corpus and print a boot-time systemd
  unit.
- Static musl release binaries for seven targets, with `SHA256SUMS`.
