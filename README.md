# psgen

`psgen` generates realistic Linux process lists on stdout, and can inject them
into the real process table. After injection, `ps aux`, `ps -ef` and `/proc`
show the synthetic processes as ordinary running processes.

It is a single Rust binary with one dependency, `libc`. It is Linux-only. The
release binaries are statically linked against musl. It uses no ptrace, no
kernel module and no `LD_PRELOAD`; each stub is the same binary re-executed
with the template argv.

## Requirements

- Linux with `procfs` mounted at `/proc`.
- Root for user switching (`setuid`, `initgroups`) and for the bind exe tier.
  Without root, `inject` warns once and every stub runs as the invoking user.
- The bind tier needs a private mount namespace and a bind mount. Root can
  create both directly; an unprivileged process can create them inside an
  unprivileged user namespace when the kernel allows it. Without either, the
  shadow tier is used, or proc-self.
- `python3` for `tests/invariants.py`. `cargo` and a Rust toolchain for the
  unit tests and for building from source.
- No runtime dependencies: the release binaries are static musl.

## Build

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The binary is `target/x86_64-unknown-linux-musl/release/psgen`.
`.cargo/config.toml` selects `rust-lld`; dependencies come from crates.io and
there is no `vendor/` directory. `scripts/build-all.sh` builds that target and
checks the result for `NEEDED` and `INTERP`.

`cargo build --release` without `--target` builds for the host's default
target, which is normally glibc. That binary works, but it is not the static
artifact the releases ship.

The release workflow builds seven targets: `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`,
`i686-unknown-linux-musl`, `riscv64gc-unknown-linux-musl`,
`loongarch64-unknown-linux-musl` and `powerpc64le-unknown-linux-musl`.
Non-native targets are linked with `cargo-zigbuild`; each binary is checked
for dynamic dependencies and an interpreter before it is packaged.

## Install

A release carries three kinds of asset:

- `psgen-<version>-<target>.tar.gz` — the directory
  `psgen-<version>-<target>/` holding `psgen`, `LICENSE` and `README.md`;
- `psgen-<target>` — the same binary, uncompressed;
- `SHA256SUMS` — one `sha256sum` line for each tarball and each raw binary;
  it does not list itself.

```sh
# TAG and VERSION come from the release: TAG is the git tag, VERSION is the
# [package] version in Cargo.toml at that tag.
TAG=v0.0.2
VERSION=0.0.2
TARGET=x86_64-unknown-linux-musl
BASE=https://github.com/Azathothas/psgen/releases/download/$TAG
curl -LO "$BASE/psgen-$VERSION-$TARGET.tar.gz"
curl -LO "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf "psgen-$VERSION-$TARGET.tar.gz"
install -m 0755 "psgen-$VERSION-$TARGET/psgen" /usr/local/bin/psgen
```

`SHA256SUMS` lists every tarball and every raw binary — fourteen lines for the
fifteen assets of a seven-target release, because the file cannot list itself —
and a plain `sha256sum -c SHA256SUMS` fails on each one you did not download.
`--ignore-missing` skips
the absent files and verifies the ones that are present; it exits non-zero if
none was verified, and it does not report a missing file as a failure, so it
proves the assets you have are the published ones and says nothing about the
rest. The raw binary is installed the same way, with `psgen-<target>` in place
of the tarball.

The crate is published from the release workflow for a final tag only. The
workflow fails when the registry token is unset and, after uploading, checks
that the registry actually serves the tag's version, so a green release can no
longer skip the publish. `v0.0.2` was released before that check existed and
was not published: the registry still holds the `0.0.0` name reservation, so
`cargo install psgen` installs the reservation rather than the tool. Install
from the release assets until a release publishes a version.

## Commands

`psgen list` prints command lines, `psgen table` prints a `ps aux` style table,
`psgen table --live` prints the real process table in the same format, and
`psgen inject` starts synthetic processes. The other commands are `stop`,
`doctor`, `log`, `load`, `corpus`, `check`, `unit`, `help` and `version`.

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

Defaults and caps:

| command | default | cap |
| --- | --- | --- |
| `list` | one line per in-scope template (181 in the full corpus) | 2000 |
| `table` | 30 rows | 5000 |
| `table --live` | every process in `/proc` | 5000 rows |
| `inject` | 12 rows | 500 |
| `unit` | 24 rows in `ExecStart` | 500 |
| `log` | 20 events | 200000 |
| `corpus` | every template | — |

A cap above the limit prints it on stderr and uses it. `-n 0` means the
default for every command; for `list` the default is one line per in-scope
template, so `list` and `list -n 0` print 181 lines, and `list -s N` and
`list -n 0 -s N` are byte-identical. An explicit `-p` excludes a family its
profile weights at zero: `list -n 0 -p server` prints 163 lines and `-p dev`
173, and the template order follows the profile weights. At a finite count `-p`
changes which templates are drawn as well:
`list -n 40 -s 7 -p server` and `-p desktop` name 10 of the same templates.
`list` sorts its lines by default; `--no-sort` keeps draw order, which starts
with `/sbin/init`.

### Counts, repeats and host limits

`-n` is a guarantee for `table` and `inject`: the count is met whenever any
in-scope template can appear more than once. A template that stands for several
rows at once (six nginx workers) keeps its instance count, so one draw can add
`inst` rows at a time.

The split is per template, not per row, and the bound on one command line is
`max(inst, ceil(rows / k))`, where `k` is the number of in-scope templates that
can repeat. `inst` is the largest instance count among them. Both terms are
needed: the pigeonhole term `ceil(rows / k)` is what an even split over `k`
templates can achieve at the top, and `inst` is the floor a template that
represents several processes contributes however small the count is. For
`-f web -n 200` that is `max(6, ceil(200 / 7)) = 29` rows for the busiest
command; `-f mail -n 200` gives `max(1, ceil(200 / 5)) = 40`; and `-f sys -n 200`
gives `max(2, ceil(200 / 6)) = 34`. A template whose command line contains a
variable placeholder (`{hex64}`, `{cport}`, `{ip}`, …) can always supply another
distinct row.

`--repeat-max N` bounds how often one command line may appear:

- `--repeat-max 1` — no command line twice. The count is then whatever the
  corpus can supply; `table -f web -n 40 --repeat-max 1` prints 17 rows and
  says so on stderr.
- `--repeat-max 0` — no bound on repeats.
- omitted — the realistic bound described above.

`list` never repeats a command line, so `--repeat-max` does not apply to it;
`list --no-uniq` pads a list when that is what you want.

Two host properties cap a table, and both are reported with the reason and the
numbers:

- the PID space. A snapshot cannot show two rows with the same PID, and a PID at
  or above `pid_max` does not exist, so at most `pid_max - 1` rows can appear in
  total, including PID 1. `--host-pid-max N` generates for such a host; a host
  with `pid_max` below 3 leaves the init row alone.
- the corpus, for a family whose every row is a fixed command line.
  `--repeat-max` is the explicit override there.

`--host-mem MiB`, `--host-pid-max N` and `--host-uptime S` generate a table for
a named host instead of this one. All three reject 0 with exit 2, because 0
means "unknown" inside the fit rules and would silently describe this machine
instead. They exist so the fit rules can be exercised end to end, and so a
table can be produced for a machine that is not the one running the tool.

### Options by command

The options a command honours are the options it accepts: an option that does
not apply to the chosen subcommand exits 2 with a message naming it, rather
than being silently ignored. A mode-selected case is rejected the same way —
`table --live --local` and `inject --dry-run --table` are usage errors.

- `list`: `-n/--count`, `-s/--seed`, `-p/--profile`, `-f/--family`,
  `--sort`/`--no-sort`, `--uniq`/`--no-uniq`.
- `table`: the generator options, `--utc-offset`, `--local`, `--live`,
  `--repeat-max`, `--host-mem`, `--host-pid-max`, `--host-uptime`.
- `inject`: the generator options, `--repeat-max`, `-d/--duration`,
  `--pidfile`, `--mem`/`--no-mem`, `--mem-cap`, `--mem-target`, `--phys-cap`,
  `--disk`, `--exe`/`--no-exe` (`--allow-proc-exe` is an alias of `--no-exe`),
  `--shadow-dir`, `--no-root`, `--tty`/`--no-tty`, `--threads`/`--no-threads`,
  `--user`/`--no-user`, `--create-users`, `--busy`, `--cpu`, `--dry-run`,
  `--plan`, `--json`, `--table`, `--verify`, `--wait`, `--elevate`,
  `-q/--quiet`.
- `stop`: `--pidfile`, `--force`, `--plan`, `--elevate`, `-q/--quiet`.
- `check`: `-s/--seed`, `-f/--family`, `--binaries`, `--require-binaries`.
- `unit`: `-n/--count`, `-s/--seed`, `-p/--profile`, `-f/--family`,
  `--pidfile`, `--create-users`, and the inject options minus `--table`,
  `--wait`, `--dry-run`, `--plan`, `--json`, `--repeat-max`, `--elevate` and
  `-q`. `-n` is capped at 500.
- `doctor`: `--json`, `--pidfile`.
- `log`: `-s/--seed`, `-m/--module`, `--lines`, `--delay`, `--speed`,
  `--log-fmt`.
- `load`: `--cpu-util`, `--mem-util`, `--disk-util`, `-d/--duration`,
  `--force`, `-q/--quiet`.
- `corpus`: no options.

The generator options are `-n/--count`, `-s/--seed`, `-p/--profile` (`server`,
`dev`, `desktop`) and `-f/--family` (`sys`, `web`, `db`, `ctr`, `dev`, `mon`,
`sto`, `mail`, `desk`, `net`). `-p` weights which templates `list`, `table` and
`inject` draw, and excludes a family the profile gives weight zero; the defaults table above says what it does to a set and to an
order.

## The table

`table`, `table --live` and `inject --table` print one header and one line per
row:

```text
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
```

The column rules are the ones `ps aux` uses with `procps-ng`:

- **USER** is the effective uid, resolved through the passwd database; a uid
  with no entry prints as its decimal value. A name longer than eight
  characters is cut to seven and a `+`.
- **%CPU** is `tics * 1000 / elapsed`, where `elapsed` comes from
  `CLOCK_BOOTTIME` with its sub-second part, so a young process is not
  reported several times low. Below 100.0 it prints one decimal; at or above
  it prints an integer, which keeps the field four columns wide.
- **%MEM** is `rss * 1000 / MemTotal` in integer arithmetic, which truncates
  rather than rounds, and is capped at 999. A live table divides by
  `/proc/meminfo`'s `MemTotal`, which is what `ps` uses even inside a
  container. A synthetic table divides by this host's budget ( `MemTotal`
  lowered to the cgroup limit when that is smaller) or by `--host-mem`.
- **START** is `HH:MM` when the row started on the current calendar day in the
  rendering zone, `%b%d` with a zero-padded day (`Nov05`) when it started on
  another day of the same year, and `%Y` when it started in another year. The
  day, not the age, decides. A synthetic row never starts before the boot of
  the host it describes and never in the future.
- **TIME** is total minutes and seconds of CPU time, `75:00`, never
  `HH:MM:SS` and never a day prefix. A live row carries its real
  `utime + stime`; a synthetic row models it from its age and the `%CPU` it
  claims.
- **STAT** is the state character followed by `<` for a negative nice, `N` for
  a positive one, `L` when pages are locked, `s` for a session leader, `l` for
  more than one thread and `+` for a foreground process group.
- **TTY** is the device name resolved from the tty number, else `?`.
- **COMMAND** is `/proc/PID/cmdline` up to 512 KiB, joined on spaces. A NUL or
  a line break separates arguments, other control bytes become `?`, and a
  zombie gets a trailing ` <defunct>`. A process with no argv prints `[comm]`.
  A row is cut at the 128 KiB `ps` writes through one buffer.

`table --live` renders the host's own zone and the host's own `MemTotal`, and
rejects `--local`, `--utc-offset`, `--repeat-max` and the `--host-*` flags:
they describe a generated table, not this host. `inject --table` uses the same
renderer and the same inputs, and prints in PID order.

`table` (synthetic) keeps `--utc-offset` (minutes east of UTC, `-1440..1440`,
default 0) and `--local` as its knobs, with the same column formats, because a
synthetic table claims to look like `ps aux`. `--local` selects the system
timezone and overrides `--utc-offset` rather than shifting the timestamp a
second time.

## Injection model

`inject` builds a process tree from corpus rows. A root stub forks its children
after reading its configuration, so `ps -ef` and `pstree` show a parent chain.
Each stub keeps the template argv set at `execve`, so `ps aux` and
`/proc/PID/cmdline` show the template command line.

### Exe tiers

`/proc/PID/exe` is selected from three tiers:

- **bind**: a private mount namespace, `/` made private, the template path
  bound over the stub binary, then a re-exec through that path.
  `/proc/PID/exe` and `/proc/PID/maps` show the template path. A missing path
  gets a temporary `.psgen-<pid>-<row>-<n>` directory; `stop` removes it.
- **shadow**: a copy of the binary in a per-run directory under
  `<TMPDIR>/.psgen-stubs` (or `--shadow-dir`), executed by the stub.
  `/proc/PID/exe` shows the shadow path. The directory is
  `.psgen-<pid>-9000-<n>`; the copy is `psgen-stub`.
- **proc-self**: the stub executes `/proc/self/exe`; `/proc/PID/exe` points at
  psgen.

The tier is chosen once per run, in this order:

| condition | tier |
| --- | --- |
| `--no-exe` (or `--allow-proc-exe`) | proc-self, whatever else is set |
| `--no-root` with `--shadow-dir` | shadow |
| `--no-root` without `--shadow-dir` | proc-self |
| root (or a usable user namespace) with mount and bind allowed | bind |
| otherwise, with a shadow root available | shadow |
| otherwise | proc-self, with a warning naming what was denied |

A bind denied in a cage that allows mount namespaces leaves the default
`<TMPDIR>/.psgen-stubs` in place, so `/proc/PID/exe` still names a plausible
path.

### Users, tty and threads

As root, and unless `--no-root` or `--no-user` is set, each stub calls
`initgroups`, `setgid` and `setuid` for the template user. A missing user falls
back to the invoking user with a warning; `--create-users` creates it with
`useradd`, using the existing group when the group is present but the user is
not. Without root, the run warns once and `--create-users` cannot create
anything; `--elevate` re-executes `inject` or `stop` through `sudo -n` when
passwordless `sudo` is available.

`--tty` (default) gives a tty row a real pty and makes it the row's
controlling terminal, so `ps` shows `pts/N` for it. `--no-tty` clears the tty
and session flags and detaches every row from the caller's controlling
terminal. `--threads` (default) gives a threaded row a second thread.

A failed privilege drop is reported as a deviation, and the stub keeps running
under the uid it already has.

### Memory and disk

`--mem` (default) pads VSZ and RSS from one anonymous arena sized to the
largest target, using `memfd_create` or an unlinked temp file. Each stub maps a
prefix, touches its pages, trims RSS with `MADV_DONTNEED`, and pads VSZ with a
`PROT_NONE` mapping. Reported RSS is shared, so the physical cost is smaller
than the sum of the rows.

- `--mem-target KiB` sets a per-stub RSS target, clamped to the template's VSZ
  minus 4 MiB.
- `--mem-cap MiB` caps the planned RSS sum, with a 4 MiB floor per stub.
- `--phys-cap MiB` bounds the estimated physical cost: the largest RSS, its
  page tables and the base RSS. The default is the smaller of a quarter of RAM
  and half the cgroup limit.
- `--disk MiB` writes that much temp data per stub.

`RLIMIT_FSIZE` is checked before the arena is sized: targets above it are
lowered with a warning, and padding is disabled with a warning when the limit
cannot hold the arena at all. `--verify` compares each stub's real VSZ and RSS
with the plan within 128 kB, and has no effect with `--no-mem` (it warns).

### Previewing a run

`--dry-run` prints the `user<TAB>command` pairs that would be spawned and
nothing else, which is the format existing callers parse.

`--dry-run --plan` prints the resolved plan instead:

```text
tier bind   mem on, tty on, threads on, busy off
plan: 4 stubs, 2 roots; rss 67 MiB shared, ~42 MiB physical (budget 3994 MiB); staging 0 directories
row 0 root user=root vsz=13160 rss=8156 cpu=0.0 tty=no threads=no exe=/usr/sbin/nginx
row 1 child user=www-data vsz=15444 rss=4824 cpu=0.0 tty=no threads=no exe=/usr/sbin/nginx parent=0
row 2 root user=root vsz=60676 rss=20596 cpu=0.1 tty=no threads=no exe=/usr/sbin/php-fpm
row 3 child user=www-data vsz=73208 rss=35680 cpu=0.1 tty=no threads=no exe=/usr/sbin/php-fpm parent=2
```

The plan reports the tier and its shadow root, the physical estimate and
whether it was scaled, the staging directories the run would create, and the
users it would create. `--dry-run --json` prints the same plan as one JSON
object, with `rows`, `staging_dirs` and `would_create` arrays. The two are
alternatives; passing both exits 2.

A preview runs the same preflights as the real run — pidfile writability, disk
space, `RLIMIT_FSIZE` — and exits non-zero for a command line the real run
would refuse. It never elevates and never creates an account. `--plan` with
`--create-users` keeps the template's user name and reports the accounts the
run would create, instead of falling back to the caller's identity.

## Pidfile and stop

`--pidfile FILE` records the run:

```text
# psgen <version> boot <boot-id> nonce <nonce>
# temp <absolute-temp-dir>
<pid>\t<starttime>\t<comm>
```

The `nonce` field is part of the header `stop` reads: it is the run nonce, and
a one-field line is identified by carrying it in the process environment. A
pidfile written before the header recorded a nonce has no `nonce` field, and
`stop` then refuses its one-field lines rather than guessing. The `# temp` line
is conditional: `inject` writes one per staging directory the
run creates, and creates none when nothing in the run needs a directory. A
proc-self run therefore has a header and its PID lines only, while a bind run
whose template executables exist has the same, and a shadow run, a bind run
with `--disk`, or a bind run whose template path is missing adds one `# temp`
line per directory. The header is parsed without interpreting the version, so a
pidfile written by another release still gets the boot-id check. A header with
no boot id is refused by `stop` and never written by `inject`: if the boot id
cannot be read, `inject` refuses to start.

A header-only pidfile is written before the first stub is forked. If that write
fails, nothing is spawned; if it succeeds, a later failure still leaves a valid
pidfile behind. The write goes through a temporary name with `O_EXCL` and is
renamed into place. The temporary suffix shrinks through four shapes, appended
to the target path and tried in order: `.tmp.<pid>.<16 hex>`, `.t<pid><6 hex>`,
`.tmp.<pid>`, `.t<pid>`. On a filesystem with `NAME_MAX` 255 and a five-digit
PID, a 247-byte basename is written and a 248-byte one exits 2 before anything
is spawned. The bound moves with the PID's width and with `NAME_MAX`, so it is
decided by trying the real name rather than by a constant. The preflight builds
exactly the name the writer will use, and proves the body size, the mode and
the rename, not just a zero-byte create.

An existing target must be absent, empty or a psgen pidfile. A device, FIFO,
socket or symlink is refused with exit 2. `stop` reads through `O_NOFOLLOW`,
so a symlinked pidfile is not followed.

`stop --pidfile FILE` checks the boot id, then each line's identity before
signalling:

- a three-field line checks starttime and comm;
- a two-field line checks starttime;
- a one-field line matches the run nonce from the header against the process
  environment. That is the identity; it holds for proc-self, shadow and
  bind-tier rows alike. A header with no nonce refuses every one-field line,
  and a process whose environment does not carry the nonce is skipped. The
  executable is only a diagnostic fallback: a bind-tier exe is named in that
  skip message, and never makes the line match.

PID 1 is never signalled. Lines are processed deepest PID first, a leader's
process group is killed so children that never reported are reached, and the
PID itself is signalled through a pidfd when available, or after a
check-then-kill. A zombie is skipped, not counted: it is already dead, and a
signal to one succeeds and does nothing.

After signalling, `stop` waits, bounded at two seconds, until every signalled
PID is gone or a zombie, so `stopped N` is true when it is printed. A line that
needed no signal — already gone, a zombie, PID 1, an identity mismatch — counts
as skipped, and a line it could not signal counts as failed and makes the exit
code 1. A second `stop` on the same pidfile therefore reports
`stopped 0 processes, skipped N`.

`--plan` prints what would be signalled and signals nothing; it also refuses
the signal it could not send, and it never elevates. `--force` ignores only the
boot id, and is also the escape hatch for a file with no psgen header at all. A
`# psgen` line after the first line is a comment, not a header.

`stop` does not unlink the pidfile, so the same path can be reused once its
processes are gone. `stop` removes a `# temp` directory when all of these hold:
the path is absolute; it is a real directory, not a symlink; it is owned by the
caller and is not group- or world-writable; its basename matches
`.psgen-<digits>-<digits>-<digits>`; its live marker names no live process; and
no line failed. A skipped line — already gone, a zombie, PID 1, an identity
mismatch, a malformed line — does not block the removal; a line whose signal did
not land does. `--plan` never removes anything.

A run that ends by `--duration` alone leaves its staging directories, because
the injector is gone by then and no `stop` ran. Two paths reclaim them:

- `stop` on the run's pidfile removes them, the same as for a stopped run: the
  PID lines are already gone, so `stop` reports `stopped 0 processes, skipped N`
  and then removes each `# temp` directory whose marker names nothing alive.
- The next `inject` prunes before it spawns. It scans the temporary directory,
  `<TMPDIR>/.psgen-stubs`, the old default `<cwd>/.psgen-stubs`, plus this
  run's `--shadow-dir`. A stub appends its own identity to the directory's live marker
  before it execs, and the prune keeps a directory while any process in that
  marker is alive or while the owner marker names a live injector. A marker
  records the PID namespace inode, the boot id and a run tag, so a PID from
  another namespace is never read as dead, a marker from an earlier boot is
  provably over, and a directory whose owner is gone and whose marker is empty
  is removed. A directory owned by a different uid is reported and left alone.

The default shadow root is `<TMPDIR>/.psgen-stubs`, so a later run finds it
whatever its working directory. The `<cwd>/.psgen-stubs` scan is only for
leftovers written by an older build. A custom `--shadow-dir` outside the
temporary directory and this run's own value is the one place a later prune
will not look; give it a fixed path that every run shares.

`--wait` requires a non-zero `--duration` (exit 2 otherwise). It blocks for the
duration, then kills each root's process group after a starttime check, signals
each identified PID through a pidfd or a check-then-kill, and removes the temp
directories after asking the live marker.

## unit

`psgen unit` prints, without installing, a systemd unit that injects at boot.
For a build installed at `/usr/local/bin/psgen`, `psgen unit` prints exactly
this:

```text
[Unit]
Description=psgen synthetic process table
After=local-fs.target sysinit.target
ConditionPathExists=/proc/1/stat

[Service]
Type=oneshot
RemainAfterExit=yes
RuntimeDirectory=psgen
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ExecStart=/usr/local/bin/psgen inject --quiet --pidfile /run/psgen/psgen.pid -n 24 -s 7
ExecStop=/bin/sh -c 'if [ -e "$2" ]; then "$1" stop --pidfile "$2" || exit $?; fi' psgen-stop /usr/local/bin/psgen /run/psgen/psgen.pid
ExecStop=-/bin/rm -f -- /run/psgen/psgen.pid

[Install]
WantedBy=multi-user.target
```

`ExecStart` and both `ExecStop` lines name the running binary, so a unit written
from a staged build names that build. The `RuntimeDirectory` is derived from the
pidfile path: a pidfile directly in `/run` gets no `RuntimeDirectory` line,
`/run/<dir>/...` declares `<dir>`, and a path outside `/run` is refused with
exit 2 because nothing would create its parent at boot. `RuntimeDirectoryMode`
is `0700`.

`RuntimeDirectoryPreserve=yes` keeps the directory across a stop, so stopping
one unit cannot delete a pidfile a second unit under `/run` still uses. The
pidfile itself is what makes the service restartable: the first `ExecStop` runs
`psgen stop`, and the second removes the file with a leading `-`, so a pidfile
that vanished between the check and the `rm` is not reported as a failure. The
first `ExecStop` deliberately carries no `-`: a foreign boot id, a malformed
pidfile or a refused signal must reach systemd instead of being reported as a
successful stop. The absence test lives in `/bin/sh` rather than in `-`, because
`-` cannot tell "no pidfile" from "a pidfile from another boot"; `$1` is the
executable and `$2` the pidfile, and only positional parameters are used because
systemd expands `$name` as its own variable.

Every inject option the caller gave is forwarded into `ExecStart` (`-p`, `-f`,
`-d`, `--no-mem`, `--mem-cap`, `--mem-target`, `--phys-cap`, `--disk`,
`--no-exe`, `--shadow-dir`, `--no-root`, `--no-tty`, `--no-threads`,
`--no-user`, `--busy`, `--cpu`, `--verify`, `--create-users`), so
`psgen unit -p desktop -f desk -n 40` writes a unit that injects desktop rows
at boot. `-n` is capped at the inject cap of 500.

## corpus, check, doctor, log and load

`psgen corpus` dumps the embedded corpus as `family<TAB>user<TAB>vsz<TAB>rss<TAB>command`,
181 templates across ten families. The user column prints the sentinel `@self`
for a template that runs as the invoking user; `list`, `table` and `inject`
replace it with the user's name, or with the decimal uid when the uid has no
passwd entry.

`psgen check` expands every template and rejects placeholders, control bytes,
empty commands and a denylist of cryptocurrency, botnet, brute-force and
credential-dumping terms. `check -f FAMILY` narrows the run and prints the
expanded count beside the total. `check --binaries` reports which template
executables exist on this host: an absolute path is checked as written, a bare
name is looked up in `PATH` and then the standard directories, and a template
whose executable resolves through a symlink is not reported missing.
`--binaries` always exits 0 for a host fact and `--require-binaries` exits 1
when anything is missing, which is the form to use in CI.

`psgen doctor` probes the environment and prints one line per capability with
its verdict and detail; `--json` emits the same as one object with a `checks`
array of objects carrying `name` and `ok`, plus `core` and `core_ok` saying
whether injection can work at all (probed through `proc_exe`, `fork` and
`prctl_name`). `doctor --pidfile FILE` also reports whether that pidfile can be
written.

`psgen log` writes activity logs for 14 modules. `-m list` prints the module
names on one line, then one line per module that accepts aliases, in the form
`  <module> (<alias>, …)`; twelve of the fourteen modules have aliases, and
`mkinitcpio` and `julia` have none, so their names appear in the first line
only. `--log-fmt apache` is defined for `weblog` only;
`json` and `syslog` work for every module. A closed reader stops the generator
instead of leaving it to finish a long run.

`psgen load` creates real CPU, memory or disk pressure. `--mem-util PCT` is a
percentage of `MemTotal` and is refused above `MemAvailable` unless `--force`
is given, because a load generator that exhausts memory invokes the OOM killer
against its own host. `--disk-util MiB` is refused above the free space of
`TMPDIR`. The summary goes to stdout, and `-q` suppresses it.

## Tests

`tests/smoke.sh` expects `target/release/psgen` and runs the version, help,
corpus, list and seed checks, `cargo test --release`, `tests/workflow.sh`,
`tests/invariants.py`, `tests/proof_cases/report.sh` and a binary-size check.
Stage the musl binary at `target/release/psgen` first:

```sh
cargo build --release --target x86_64-unknown-linux-musl
mkdir -p target/release
cp target/x86_64-unknown-linux-musl/release/psgen target/release/psgen
sh tests/smoke.sh
```

`PSGEN_BIN=path/to/psgen python3 tests/invariants.py` runs the invariant suite
alone against any binary.

`sh tests/proof_cases/report.sh path/to/psgen [issue ...]` runs the per-issue
proof for the report and utility surface — issues #8, #13, #19, #20, #21, #23,
#24 and #27 — one line per case. A case is kept only if it fails on the commit
before its fix, so the script doubles as the record of what each fix changed.
The tree the documentation cases read is inferred from the binary's own path
(`<tree>/target/<profile>/psgen`), so the same script can be pointed at a
pre-fix build; `PSGEN_SRC=<tree>` overrides that.

`PSGEN_REQUIRE_ALL=1` makes every skip a failure that names the capability it
needed. Without it, a check that cannot run on this host prints `SKIP:` and its
reason and the suite continues; with it, the same check fails. Use it on a host
that is supposed to have the capability (a pty, a reaping PID 1, passwordless
`sudo`, a finite `RLIMIT_FSIZE` large enough for the free-space guard) so a
missing capability cannot pass as a pass. The variable is read by
`tests/smoke.sh`, `tests/invariants.py`, `tests/workflow.sh`, `tests/cross.sh`,
`tests/proof_cases/report.sh` and `tests/vm.sh`. Both workflows set it for the
job that runs the suite:
`ci.yml`'s `test` job and `release.yml`'s `test` job, so a skip on a runner that
has the capability fails the run instead of passing.

`tests/invariants.py` compares `table --live` against `ps aux` field by field
for every stable row, checks every option against every subcommand, and carries
a regression for each defect class the corpus and injection rules cover: the
pidfile reuse rule, a second `stop`, `stop --plan`, a seed across one second,
the family shortfall and the repeat spread, the host-fitted sizes, the
`pid_max` bound, the live table's column offsets and `<defunct>` marker, the
`doctor --json` shape, a pidfile header with a foreign version, the
`--utc-offset` bound, `--local` with `--utc-offset`, the name-length preflight,
an inherited fd 3, the staging prune, a closed log reader, `--mem-util` above
`MemAvailable`, `check --binaries` on an installed path, and the `NAME_MAX`
boundary.

`tests/workflow.sh` checks the parts of the release pipeline that can run
outside GitHub: the tag-to-notes decisions through the same
`scripts/release-notes.sh` the workflow calls, the arguments `gh release
create` receives (with a fake `gh`), that every `run:` block in both workflows
parses as shell, and a sabotage case for each gate. It cannot exercise GitHub's
own expression evaluation or the network calls.

### CI gates

`.github/workflows/ci.yml` runs two jobs:

- `lint`: `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets --
  -D warnings`, `cargo test --locked --release`, `cargo package --locked
  --no-verify`, `tests/workflow.sh`, and a unit check that runs
  `systemd-analyze verify` when the tool exists, rejects a unit naming the
  nonexistent `proc-fs-nets.target`, requires
  `RuntimeDirectory=psgen` and `ConditionPathExists=/proc/1/stat`, and requires
  an `ExecStop=` line that runs `psgen stop --pidfile` with every such line
  guarded (the
  `-` prefix or the `/bin/sh -c` pidfile test). It does not grep for
  `ExecStop=-`: the cleanup `/bin/rm` line satisfies that whatever the psgen
  stop looks like.
- `test`: builds `x86_64-unknown-linux-musl`, stages the binary at
  `target/release/psgen` and runs `tests/smoke.sh`.

`.github/workflows/release.yml` runs the same lint and test gates, then builds
each of the seven targets (native or through `cargo-zigbuild`), checks the
result for `NEEDED` and `INTERP`, registers binfmt and runs `tests/smoke.sh`
for every target, packages a reproducible tarball and the raw binary, and
publishes `SHA256SUMS`, build provenance, the crate (a final tag only, with
`CARGO_REGISTRY_TOKEN`) and the GitHub release.

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

## Limits

- Linux only, with `/proc`.
- The pidfile is trusted input: the boot id, starttime and comm are visible in
  `/proc`, so a forged pidfile can name a process the caller may signal, and
  can point the `# temp` cleanup at a matching directory owned by the caller.
  Run `stop` only on a pidfile you control.
- `stop` does not unlink the pidfile. Re-running `inject` against the same path
  works once the processes it names are gone; the printed unit removes the
  pidfile in `ExecStop` and keeps the `RuntimeDirectory`, so a restart finds the
  directory and no pidfile.
- A one-field pidfile line is identified by the run nonce from the header,
  carried in the process environment. A pidfile from before the nonce existed
  has no one-field form, and a process without the nonce is skipped; neither is
  guessed at. Bind-tier rows need no special case: the nonce identifies them
  too.
- An injected row's terminal is not guaranteed to be `?`. `--tty` (default) gives
  a template the corpus marks as a tty row a real pty and makes it that row's
  controlling terminal, so `ps` shows `pts/N`; `--no-tty` clears the tty and
  session flags on every row and detaches each one from the caller's terminal,
  so a later `ps` shows `?` throughout. A harness that needs a stable `?` in a
  later `ps` should pass `--no-tty`.
- A failed privilege drop is reported as a deviation and the stub continues
  under the uid it already has; it does not abort the run.
- The config memfd carries the size seals (`F_SEAL_SHRINK`, `F_SEAL_GROW`,
  `F_SEAL_SEAL`) but not `F_SEAL_WRITE`, so the injector can still write the
  status record through the same mapping. A descriptor holder that can write
  the mapping can change the config after it was validated.
- The staging leaf is validated through its opened descriptor and then
  executed by path, so a caller who can replace it between the two steps has a
  time-of-check/time-of-use window. The injector keeps the directory mode at
  `0700`, which bounds who can do that.
- `child_fds` may not name the stub's own config descriptor or fd 3, and a
  child stub must be at stage 0, so a self-referential config cannot recurse
  through the same descriptor. A config that names other descriptors can still
  fork more processes than the injector planned.
- A real FUSE mount was not available in the development cage, so the FUSE
  branch is exercised through its predicates and through the hardlink and
  symlink cases rather than a mounted daemon.
- Release artifacts are static musl only; no GNU/glibc artifact is published.
  A `cargo install` builds whatever target the host defaults to, normally
  glibc; use `--target x86_64-unknown-linux-musl` for the artifact the releases
  ship.
- Cross targets are built in CI; `make build` and `scripts/build-all.sh` build
  only `x86_64-unknown-linux-musl`.
- A non-root `--tty` row that calls `setsid` and never reports is outside the
  per-PID and root-group kill paths: it has no status record, so it is not in
  the pidfile, and it has left the root's process group.

## Security

This tool deliberately spoofs process state. Read `SECURITY.md` before handing
a pidfile from someone else to `stop`, or installing it anywhere a supervisor
can pass it file descriptors. It must not be installed setuid; the stub refuses
to run in that case.

## License

0BSD. See `LICENSE`.
