# Changelog

## Unreleased

Fixes for the whole third and fourth beta-test rounds. Each area is a chain
fix: the symptom and everything that shares its root cause.

### Correctness

- The pidfile header is parsed and written without the version string, so a
  pidfile from another release still disarms the boot-id check correctly
  instead of silently passing it. `0.0.1` now comes from `Cargo.toml` in one
  place.
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
