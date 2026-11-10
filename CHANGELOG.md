# Changelog

## Unreleased

### Review round 5

Independent review of the second-round branch. Each item was reproduced on the
branch head before the change.

- `%MEM` truncates to one decimal like procps; the old renderer rounded.
- Every generated age is capped at the host uptime, not only the boot-relative
  one, so `--host-uptime 0` no longer shows rows that started weeks before boot.
- `table --live` keeps a final argv space and maps `\r`, `\v` and `\f` to
  `?`, and reads 512 KiB of cmdline instead of 8 KiB.
- `--repeat-max` is enforced per command line in the main table and inject
  loops, so `--repeat-max 1` on `web` and `sys` emits no duplicate command.
- `table --live` rejects `--repeat-max` and the `--host-*` flags, `list`
  rejects `--repeat-max`, `unit` rejects `-q`, and `inject` rejects
  `--utc-offset` and `--local` without `--table`, instead of ignoring them.
- A bind-tier row with a symlinked template exe is named as unidentifiable
  instead of being silently skipped by a one-field pidfile line.
- The stub refuses any setuid or setgid install, treats overlayfs like FUSE
  for the config descriptor and staging directory, checks a hardlinked leaf and
  `data.bin` by descriptor before truncating. A crashed run's staging is
  pruned once its stubs are gone.
- `stop` rechecks starttime and state after `pidfd_open`, and keeps a staging
  directory whose live marker still names a live process.
- The release test job runs fmt, clippy, `cargo package` and the unit
  assertions; every cross matrix entry runs smoke; publish dry-runs first; and
  a tag with no CHANGELOG section fails the notes script.
- New regressions in `tests/invariants.py` fail on the unreviewed head for the
  START, `%MEM`, COMMAND, repeat, one-field and prune defects.
  `tests/workflow.sh` checks the matrix, the test job and the dry-run order.

Known residual limits are documented in README and SECURITY: the nonce is
visible in `/proc/PID/environ` for the process lifetime, the config memfd is size-sealed but
not write-sealed, the staging leaf is validated by descriptor and exec'd by
path, a crafted `child_fds` can still fork more than planned, and a failed
privilege drop does not abort the stub. The list and table path caches user
lookups and the variable-template pool, but large tables are still slower than
the base commit; there is no timing regression for that.

### Second review round

- `-n` is a guarantee for `table` and `inject`: the count is met whenever any
  in-scope template can repeat, split evenly over the templates a host runs many
  of, so the busiest command is at the pigeonhole minimum instead of taking the
  remainder. `--repeat-max N` is the explicit opt-out (`1` = never repeat,
  `0` = no bound) and the shortfall message names it.
- A table is capped at the host's PID space, never repeats a PID, never exceeds
  `pid_max`, and reports the gap with the numbers. A host with `pid_max` below 3
  yields the init row and says why.
- `--host-mem`, `--host-pid-max` and `--host-uptime` generate for a named host,
  which is how the fit rules are tested end to end.
- The stub identifies the shadow leaf by its *opened descriptor* (regular file,
  one link, the right owner, and for root not on FUSE or overlayfs), so a
  hardlink or a FUSE type spoof is refused; `data.bin` gets the same treatment.
  `cfg.exe` is held to the shape the injector produces.
- The staging prune uses the same start-time-and-alive test as `stop`, so a
  zombie no longer keeps a dead run's directory (which every container hit).
- A failed `pipe2` reported "os error 0"; the spawn error paths capture errno at
  the failing call.
- `tests/helpers/deny_syscall.c` gives the suite a real seccomp denial, and
  `tests/workflow.sh` runs the release pipeline's shell, with a fake `gh`,
  outside GitHub.
- `tests/invariants.py` gains a regression for every residual the review named.

Fixes for the whole third and fourth beta-test rounds. Each area is a chain
fix: the symptom and everything that shares its root cause.

### Correctness

- The pidfile header is written with the version from `Cargo.toml`, and parsed
  without interpreting it, so a pidfile from another release still gets the
  boot-id check instead of silently passing it.
- A psgen header with an empty or missing boot id is refused unless `--force`
  is given, instead of skipping the boot check.
- `pidfile_target_ok` compares eight header bytes, not nine, so a pidfile psgen
  wrote is accepted again on the next run, by `inject` and by `doctor`.
- The pidfile preflight tests the temporary name the writer actually creates
  (`.tmp.<pid>.<nonce>`), and the writer shortens that name in steps when the
  target basename is near `NAME_MAX`.
- A header-only pidfile is written before the first stub is forked, so a
  failure later never leaves live stubs with no record of how to stop them.
- `stop` waits, bounded, for each signalled PID to exit or become a zombie
  before it reports. A zombie is skipped rather than counted as stopped, so a
  second `stop` reports `stopped 0`.
- `stop` signals the deepest PIDs first, so a root's group kill cannot make the
  per-line count depend on scheduling.
- `stop` refuses a one-field line for a bind-tier row it can recognise, instead
  of reporting success without signalling anything; a one-field line is
  honoured for proc-self rows and for a shadow copy in a staging directory the
  caller owns. `stop --plan` prints what would be signalled.
- A seed is reproducible across seconds: the child-row age and the boot-relative
  age are drawn from fixed-size moduli, so only the wall-clock columns move.
- PostgreSQL background workers and client backends are children of the
  postmaster, in one session, with STAT `S` rather than `Ss`.
- `table --live` never writes a raw line break into COMMAND, marks zombies with
  `<defunct>`, sorts `inject --table` by PID, and keeps STAT/START/TIME/COMMAND
  at the header offsets when a numeric field is wider than its slot.
- `%MEM` is rounded the way procps rounds it and capped at 999.
- A synthetic table never claims more RSS than this host has, keeps PIDs below
  `pid_max`, and never puts one command in more than a small share of the rows.
- `--count` is honoured by repeating templates that can run more than once
  (`F_REPEAT`, or a placeholder that changes the command line), spread evenly;
  a family with fewer distinct rows says so on stderr.
- `list` shares the profile weights with `table` and `inject`, so `-p` changes a
  short list too; the first line is still the first in-scope corpus row.
- `gen_list`'s duplicate check is a `BTreeSet`, so `list -n 2000` is not
  quadratic.
- `check --binaries` keeps the absolute path the command names, searches `PATH`,
  and `--require-binaries` exits 1 when anything is missing.
- `--create-users` repairs a host that has the group but not the user, keeps the
  first error rather than the last, and stops retrying when the account was
  created but NSS cannot see it.
- A uid without a passwd entry renders as the decimal uid, which is what `ps`
  prints for the same stub.
- `--local` overrides `--utc-offset` instead of shifting twice, and
  `--utc-offset` is bounded to ±1440 minutes.
- `--mem-util` is refused above `MemAvailable` unless `--force` is given.
- `log --lines` is capped at 200000, the buffer is flushed in bounded chunks,
  and a closed reader stops the generator instead of being ignored.
- `load`'s summary goes to stdout and `-q` suppresses it.

### Security

- The stub refuses to run from a setuid installation, requires a per-run nonce
  in its environment, and requires the config descriptor to be a sealed memfd
  or an unlinked file, so an inherited fd 3 cannot name a binary to exec or a
  directory to create as root.
- The stub only writes into a staging directory that matches the ownership and
  name rule `stop` already used, and only execs a `psgen-stub` inside one.

### Features

- `inject --dry-run --plan` prints the resolved plan (tier, per-row user, sizes,
  CPU, tty, threads, exe and parent) and `--dry-run --json` prints it as JSON.
  The existing two-column `--dry-run` output is unchanged.
- `inject` prunes the staging directories of runs whose injector is gone, so a
  `--duration` run that nobody stops no longer leaks its shadow copy or `--disk`
  data.
- `doctor --json` checks are objects with a `name` field, `core_ok` and `core`
  say what "ok" covers, and the pidfile report is an object with `path` and
  `writable`.
- `stop --plan`, `stop --quiet`, `check --require-binaries`, `--require-binaries`
  and `unit` forwarding every inject option it accepts.
- An option that a subcommand does not consume is a usage error, not a silent
  no-op.
- `log -m list` prints the aliases each module accepts.
- The printed unit uses a `RuntimeDirectory` the manager removes on stop, an
  `ExecStop=-`, `After=local-fs.target sysinit.target` and
  `ConditionPathExists=/proc/1/stat`, so the service can be restarted.
- CI runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo package` and a
  `systemd-analyze verify` of the printed unit; the release job smokes the cross
  binaries under binfmt and publishes the crate when a token is present.

## 0.0.1

Initial release.

- `list`, `table` and `table --live` generate process lists and `ps aux` style tables.
- `inject` starts a synthetic process tree in the real process table with bind, shadow and proc-self exe tiers, user switching, ptys, threads and VSZ/RSS padding.
- `stop` terminates a run from its pidfile; `--wait` stops it after a duration.
- `doctor` probes the environment; `log` and `load` generate activity and pressure.
- `corpus`, `check` and `unit` inspect the corpus and print a boot-time systemd unit.
- Static musl release binaries for seven targets, with `SHA256SUMS`.
