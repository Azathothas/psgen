# psgen

`psgen` generates realistic Linux process lists on stdout and can inject them
into the real process table. After injection, `ps aux`, `ps -ef` and `/proc`
show the synthetic processes as ordinary running processes.

It is a single Rust binary with one dependency, `libc`. It is Linux-only. The
release binaries are statically linked against musl. It uses no ptrace, kernel
module or `LD_PRELOAD`; each stub is the same binary re-executed with the
template argv.

## Build

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The binary is `target/x86_64-unknown-linux-musl/release/psgen`.
`.cargo/config.toml` selects `rust-lld`; dependencies come from crates.io and
there is no `vendor/` directory. `scripts/build-all.sh` builds the same target
and checks for `NEEDED` and `INTERP`.

The release workflow builds `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`,
`i686-unknown-linux-musl`, `riscv64gc-unknown-linux-musl`,
`loongarch64-unknown-linux-musl` and `powerpc64le-unknown-linux-musl`.
Non-native targets use `cargo-zigbuild`; every binary is checked for dynamic
dependencies and an interpreter. The workflow publishes the binaries and
`SHA256SUMS` as a GitHub release.

## Install

Download a tarball or a raw `psgen-<target>` binary from GitHub Releases.
Assets are `psgen-<version>-<target>.tar.gz`, `psgen-<target>` and
`SHA256SUMS`.

```sh
# Both come from the tag and Cargo.toml; the example uses the current release.
TAG=v0.0.1-beta.1
VERSION=0.0.1
TARGET=x86_64-unknown-linux-musl
BASE=https://github.com/Azathothas/psgen/releases/download/$TAG
curl -LO "$BASE/psgen-$VERSION-$TARGET.tar.gz"
curl -LO "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf "psgen-$VERSION-$TARGET.tar.gz"
install -m 0755 "psgen-$VERSION-$TARGET/psgen" /usr/local/bin/psgen
```

`--ignore-missing` checks the assets you downloaded. The raw binary is
installed the same way; the tarball also contains `LICENSE` and `README.md`.

## Commands

`psgen list` prints command lines, `psgen table` prints a `ps aux` style table,
`psgen table --live` prints the real table, and `psgen inject` starts synthetic
processes. The other commands are `stop`, `doctor`, `log`, `load`, `corpus`,
`check`, `unit`, `help` and `version`.

```sh
psgen list -n 40 -s 7
psgen table -n 40 -s 7
psgen table --live -n 50
psgen inject -n 12 -d 300 --pidfile /tmp/psgen.pid
psgen inject --table --pidfile /tmp/psgen.pid
psgen stop --pidfile /tmp/psgen.pid
psgen doctor
psgen log -m weblog --lines 10
psgen load --cpu-util 50 -d 10
```

`list` prints one line per template when `-n` is omitted; `table` defaults to
30 rows and `inject` to 12. `list` caps at 2000 rows, `table` at 5000 and
`inject` at 500. A count includes the synthetic PID 1 row when `sys` is in
scope, and `table --live` defaults to every process on the host.

`table --live` renders the same columns as `ps aux`. `%MEM` is `rss * 1000 /
MemTotal` truncated to one decimal, which is what procps prints, not a rounded
percentage, and the denominator is `MemTotal` from `/proc/meminfo` — not the
cgroup limit, which is what a container's `ps` also uses. `START` is the
process's own start time and `TIME` is its real `utime+stime`, so neither drifts
from the `ps` beside it. COMMAND is read up to 512 KiB of `/proc/PID/cmdline`; a final argv
element that ends in a space keeps it, a newline becomes a space, and other
control bytes (including `\r`, `\v` and `\f`) become `?`, matching `ps`. The
live table rejects `--repeat-max` and `--host-mem`, `--host-pid-max` and
`--host-uptime`: those describe a generated table, not this host.

`-n` is a guarantee for `table` and `inject`: the count is met whenever any
in-scope template can repeat. The rows after the distinct ones come from the
templates a real host runs many of — login sessions, build jobs, per-connection
shims, workers, one `tail -f` per watched file — and they are split *evenly*
over those templates, so the busiest command is at the pigeonhole minimum
`ceil(rows / templates)` rather than taking the remainder. A template with a
placeholder that changes the command line (`{hex64}`, `{cport}`, `{ip}`, …) can
also supply another row.

`--repeat-max N` changes that bound: `--repeat-max 1` never shows a command
twice and is the way to prefer fewer rows to a repeated one, and
`--repeat-max 0` removes the bound. `list` never repeats a command at all;
`list --no-uniq` pads a list if that is what you want.

Two hard limits still cap a table, and both are reported with the reason and
the numbers:

- the host's PID space. A `ps` snapshot cannot show two rows with the same PID,
  and a PID at or above `pid_max` does not exist, so at most `pid_max - 2` rows
  can appear beside PID 1. `--host-pid-max N` generates for such a host
  (including `pid_max` below 3, which leaves only the init row).
- the corpus, for a family whose every row is a one-off command that cannot
  vary. `--repeat-max` is the explicit override there.

`--host-mem MiB`, `--host-pid-max N` and `--host-uptime S` generate a table for
a named host instead of this one. A value of 0 is a usage error: zero means
"unknown" internally, so accepting it would silently fall back to this host. They exist so the fit rules can be exercised
end to end — including the ones only a tiny container or a freshly booted host
would hit — and so a table can be produced for a machine that is not the one
running the tool.

The options a command honours are the options it accepts: an option that does
not apply to the chosen subcommand is a usage error (exit 2), not a silent
no-op. The generator options are `-n/--count`, `-s/--seed`, `-p/--profile`
(`server`, `dev`, `desktop`) and `-f/--family` (`sys`, `web`, `db`, `ctr`,
`dev`, `mon`, `sto`, `mail`, `desk`, `net`). `list` adds `--sort/--no-sort`
and `--uniq/--no-uniq`; `table` and `inject` add `--utc-offset` and `--local`.

`stop` takes `--force`, `--plan` and `-q`; `doctor` takes `--json` and
`--pidfile`; `log` takes `-m/--module`, `--lines` (at most 200000), `--delay`,
`--speed` and `--log-fmt`; `load` takes `--cpu-util`, `--mem-util`,
`--disk-util`, `-d` and `--force`; `check` takes `--binaries` and
`--require-binaries`; `unit` takes the inject options listed below and forwards
them. The corpus contains 181 templates across ten families; `psgen corpus`
dumps it (with `@self` for a template that runs as the invoking user, which
`list`, `table` and `inject` replace with the user's name or decimal uid) and
`psgen check` rejects placeholders, control bytes and a denylist of crypto,
botnet and attack terms.

## Injection model

`inject` builds a process tree from corpus rows. A root stub forks its children
after reading its configuration, so `ps -ef` and `pstree` show a parent chain.
Each stub keeps the template argv set at `execve`, so `ps aux` and
`/proc/PID/cmdline` show the template command line.

### Exe tiers

`/proc/PID/exe` is selected from three tiers, best first:

- **bind**: a private mount namespace, `/` made private, the template path
  bound over the stub binary, then a re-exec through that path.
  `/proc/PID/exe` and `/proc/PID/maps` show the template path. A missing path
  gets a temporary `.psgen-<pid>-<row>-<n>` directory; `stop` removes it.
- **shadow**: a copy of the binary in a per-run directory under
  `./.psgen-stubs` (or `--shadow-dir`), executed by the stub.
  `/proc/PID/exe` shows the shadow path. The directory is
  `.psgen-<pid>-9000-<n>`; the copy is `psgen-stub`.
- **proc-self**: the stub executes `/proc/self/exe`; `/proc/PID/exe` points at
  psgen.

The bind tier is used when `--no-root` and `--no-exe` are not set and a mount
namespace and bind mount are permitted. The shadow tier is used when the bind
is unavailable, or with `--no-root --shadow-dir`. `--no-exe` and
`--allow-proc-exe` always select proc-self; `--no-root` alone also selects it.

### Users, tty and threads

As root, and unless `--no-root` or `--no-user` is set, each stub calls
`initgroups`, `setgid` and `setuid` for the template user. A missing user falls
back to the invoking user with a warning; `--create-users` creates it with
`useradd`. Without root, the run warns once; `--elevate` re-executes `inject`
or `stop` through `sudo -n`.

`--tty` (default) opens a real pty for tty rows; `ps` shows `pts/N`.
`--no-tty` clears the tty and session flags and detaches every row from the
caller's controlling terminal; `--threads` gives threaded rows a second thread.

### Memory and disk

`--mem` (default) pads VSZ and RSS from one anonymous arena sized to the
largest target, using `memfd_create` or an unlinked temp file. Each stub maps
a prefix, touches its pages, trims RSS with `MADV_DONTNEED`, and pads VSZ with
a `PROT_NONE` mapping. Reported RSS is shared, so the physical cost is smaller
than the sum.

`--mem-target KiB` sets a per-stub RSS target. `--mem-cap MiB` caps the planned
RSS sum with a 4 MiB floor per stub. `--phys-cap MiB` bounds the estimated
physical cost (largest RSS, page tables and base RSS); the default is a quarter
of RAM or half the cgroup limit. `--disk MiB` writes that much temp data per
stub. `RLIMIT_FSIZE` is checked before the arena is sized; targets above it are
lowered, and padding is disabled with a warning if the limit is too small.
`--verify` compares real VSZ and RSS with the plan within 128 kB and has no
effect with `--no-mem` (it warns). `--dry-run` prints the two columns it always
printed; `--dry-run --plan` prints the resolved plan instead (tier, per-row
user, VSZ, RSS, CPU, tty, threads, exe, parent and the physical estimate) and
`--dry-run --json` prints the same plan as one JSON object.

### Pidfile and stop

`--pidfile FILE` records the run:

```text
# psgen <version> boot <boot-id>
# temp <absolute-temp-dir>
<pid>\t<starttime>\t<comm>
```

The header is parsed without interpreting the version, so a pidfile written by
another release is still recognised. A header-only file is written before the
first stub is forked: if that write fails, nothing is spawned, and if it
succeeds, a later failure still leaves a valid pidfile behind. The write goes
through `<path>.tmp.<pid>.<nonce>` with `O_EXCL` and is renamed into place; the
temporary suffix shrinks in three steps so a target basename near `NAME_MAX`
still works, and the preflight tests exactly the name the writer will use. An
existing target must be absent, empty or a psgen pidfile; a device, FIFO,
socket or symlink is refused. A preflight failure exits 2.

`stop --pidfile FILE` checks the boot id, then each line's identity before
signalling. A three-field line checks starttime and comm, a two-field line
checks starttime, and a one-field line checks the exe: that form only
identifies a proc-self row, or a shadow copy inside a staging directory the
caller owns. A one-field line naming a bind-tier row is an error rather than a
silent skip, because accepting the template path would also accept the host's
real daemon. PID 1 is never signalled. Lines are processed deepest PID first,
a leader's process group is killed so children that never reported are
reached, and the PID itself is signalled through a pidfd when available, or
after a check-then-kill.

A zombie is skipped, not counted: it is already dead, and a signal to one
succeeds and does nothing. After signalling, `stop` waits (bounded at two
seconds) until every signalled PID is gone or a zombie, so `stopped N` is true
when it is printed. A second `stop` on the same pidfile therefore reports
`stopped 0 processes, skipped N`. `--plan` prints what would be signalled and
signals nothing. `--force` ignores only the boot id. The `# temp` directories
are removed only when the path is absolute, is a real directory, is owned by
the caller, has a basename matching `.psgen-<digits>-<digits>-<digits>`, and
every signal succeeded.

A run that ends by `--duration` alone leaves its staging directories, because
the injector is gone by then. The next `inject` reclaims them. A stub writes a
live marker, a `pid starttime` line per root, before it execs, so a directory
is kept while any process in that marker is still alive (a zombie does not
count). A directory with no live marker is removed only when its owner marker
names an injector that is already gone; with neither marker it may belong to
another tool, so it is left alone. The owner marker also carries the
injector's starttime, so a recycled PID cannot keep a dead run's directory
alive.

`--wait` requires a non-zero `--duration` (exit 2 otherwise, except with
`--dry-run`). It blocks for the duration, then kills each root's process group
after a starttime check, signals each identified PID through a pidfd or a
check-then-kill, and removes the temp directories.

## Requirements

Linux with a mounted `procfs`. Root is required for user switching; without
it, stubs run as the invoking user and `inject` warns once. The bind tier
needs a private mount namespace and a bind mount, which root can create
directly or an unprivileged process can create inside an unprivileged user
namespace when the kernel allows it. The release binaries are static musl.

## Tests

`tests/smoke.sh` builds nothing. It expects `target/release/psgen`, runs the
version, help, corpus, list and seed checks, then `tests/invariants.py`. Stage
the musl binary at `target/release/psgen` (copy it from
`target/x86_64-unknown-linux-musl/release/psgen`), then run `sh tests/smoke.sh`.

`tests/workflow.sh` checks the parts of the release pipeline that can run
outside GitHub: the tag-to-notes decisions (through the same
`scripts/release-notes.sh` the workflow calls), the arguments
`gh release create` would receive (with a fake `gh`), that every `run:` block in
both workflows parses as shell, and that the assertions which used to be
no-ops now fail on a bad unit. It cannot exercise GitHub's own expression
evaluation or the network calls; those are noted in `tests/workflow.sh`.

The root section of `tests/invariants.py` runs only with passwordless `sudo`;
it is skipped otherwise. So are the checks that depend on a capability the host
lacks: a pty (doctor says so), a reaping PID 1, and a hard `RLIMIT_FSIZE` large
enough to exercise the free-space guard. A host that cannot run a check prints
why and continues; a check that does run and fails exits non-zero. `python3` is
required.

Besides the behavioural checks, `tests/invariants.py` carries a regression for
every defect the beta-test rounds filed, each of which failed before the fix:
the pidfile reuse rule, a second `stop`, `stop --plan`, the seed across one
second, the family shortfall and the repeat spread, the host-fitted sizes, the
`pid_max` bound, the live table's column offsets and `<defunct>` marker, the
`doctor --json` shape, the pidfile header with a foreign version, the
`--utc-offset` bound, `--local` with `--utc-offset`, the name-length preflight,
an inherited fd 3, the staging prune, a closed log reader, `--mem-util` above
`MemAvailable`, `check --binaries` on an installed path, and the `NAME_MAX`
boundary.

## Benchmarks

`python3 bench/measure.py` measures the corpus, the table and injection round
trips, and writes `bench/RESULTS.md`. It expects `target/release/psgen`.

`bench/sand.sh` runs `bench/guest.sh` in a sand-net container cage or microVM
and checks the transcript. Copy the static binary to
`dist/psgen-x86_64-unknown-linux-musl` first, then run:

```sh
SANDNET=/path/to/sand-net sh bench/sand.sh container
SANDNET=/path/to/sand-net sh bench/sand.sh microvm
```

It writes `bench/sand-<cage>.log` and requires the `sand-net` checkout and the
cage image from `tests/sand/Containerfile`.

## Limitations

- Linux only.
- The pidfile is trusted input: the boot id, starttime and comm are visible in
  `/proc`, so a forged pidfile can name a process the caller may signal, and
  can point the `# temp` cleanup at a matching directory owned by the caller.
  Run `stop` only on a pidfile you control. `stop` does not unlink the pidfile,
  which is why re-running `inject` against the same path works.
- The stub refuses to run from a setuid or setgid installation, and only
  honours a config descriptor that carries the per-run nonce in its
  environment, is a sealed memfd or an unlinked file, and is owned by the uid
  the stub runs as (a descriptor inherited through `sudo` was opened by the
  caller, so it fails that check). It only writes into, and only execs from, a
  staging directory that passes the same ownership and name rule `stop` uses
  before removing one, and it identifies the leaf it executes by the *opened
  descriptor*: regular file, one link, the right owner, and for a root run not
  on FUSE or overlayfs. A hardlink or a FUSE type spoof is refused. Do not
  install it setuid.
- A real FUSE mount was not available in the development cage, so the FUSE
  branch is exercised through its predicates and through the hardlink and
  symlink cases rather than a mounted daemon.
- The nonce is a run tag, not authentication: it binds a config descriptor to
  the environment the injector set, and a caller who controls both can match it.
  It stays visible in `/proc/PID/environ` for the process lifetime, so a
  process that can read that file can replay it. What a descriptor cannot forge
  is its ownership and (for a root run) its filesystem type.
- The config memfd carries the size seals (`F_SEAL_SHRINK`, `F_SEAL_GROW`,
  `F_SEAL_SEAL`) but not `F_SEAL_WRITE`, so the injector can still write the
  status record through the same mapping. A descriptor holder that can write
  the mapping can change the config after it was validated.
- The staging leaf is validated through its opened descriptor and then executed
  by path. A caller who can replace that leaf between the two steps has a
  time-of-check/time-of-use window. The injector keeps the directory mode at
  `0700`, which bounds who can do that.
- `child_fds` may not name the stub's own config descriptor or fd 3, and a
  child stub must be at stage 0, so a self-referential config cannot recurse
  through the same descriptor. A config that names other descriptors can still
  fork more processes than the injector planned.
- A failed privilege drop is reported as a deviation and the stub continues
  under the uid it already has; it does not abort the run.
- Release artifacts are static musl only; no GNU/glibc artifacts are published.
  A `cargo install` builds whatever target your host defaults to, which is
  normally glibc; use `cargo install psgen --target x86_64-unknown-linux-musl`
  if you want the static binary the releases ship.
- The crate is published from the release workflow for a final (non-prerelease)
  tag, so `cargo install psgen` installs the real tool rather than the `0.0.0`
  placeholders the `psgen` and `psinject` names were reserved with.
- Cross targets are built in CI; `make build` and `scripts/build-all.sh` build
  only `x86_64-unknown-linux-musl`.
- A non-root `--tty` row that calls `setsid` and never reports is outside the
  per-PID and root-group kill paths: it has no status record, so it is not in
  the pidfile, and it has left the root's process group.

## Security

This tool deliberately spoofs process state. Read `SECURITY.md` before handing a
pidfile from someone else to `stop`, or installing it anywhere a supervisor can
pass it file descriptors. It must not be installed setuid; the stub refuses to
run in that case.

## License

0BSD. See `LICENSE`.
