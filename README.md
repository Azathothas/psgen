# psgen

`psgen` generates realistic Linux process lists on stdout and can inject synthetic processes into the live process table.
After injection, `ps aux`, `ps -ef`, and `/proc` display the synthetic processes as normal running processes.

`psgen` is a single Linux-only Rust binary with one dependency (`libc`).
Release binaries are statically linked against musl.
`psgen` uses no `ptrace`, no kernel module, and no `LD_PRELOAD`.
Each injected stub re-executes the `psgen` binary with the template argv.

## Requirements

- Run on Linux with `procfs` mounted at `/proc`.
- Run as root to switch users (`setuid`, `initgroups`) or to use the `bind` executable tier directly.
  Without root, `inject` prints one warning and runs every stub as the invoking user.
- Provide a private mount namespace and bind-mount permission for the `bind` tier.
  Root creates mount namespaces and bind mounts directly.
  Unprivileged processes can create mount namespaces and bind mounts inside an unprivileged user namespace when the kernel permits user namespaces.
  When the kernel denies bind mounts, `inject` selects the `shadow` tier or the `proc-self` tier.
- Install `python3` to run `tests/invariants.py`.
- Install `cargo` and a Rust toolchain to run unit tests or build from source.
- Release binaries require no runtime dependencies because release binaries are statically linked against musl.

## Build

Add the musl target and build the static release binary:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Cargo writes the static binary to `target/x86_64-unknown-linux-musl/release/psgen`.
`.cargo/config.toml` selects `rust-lld`, downloads dependencies from crates.io, and uses no `vendor/` directory.
Run `scripts/build-all.sh` to build the `x86_64-unknown-linux-musl` target and verify that the ELF binary has no `NEEDED` or `INTERP` entries.

Running `cargo build --release` without `--target` builds for the host default target, which is normally glibc.
The glibc build works on the host, but GitHub Releases ship only static musl artifacts.

The release workflow builds seven static musl targets:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `armv7-unknown-linux-musleabihf`
- `i686-unknown-linux-musl`
- `riscv64gc-unknown-linux-musl`
- `loongarch64-unknown-linux-musl`
- `powerpc64le-unknown-linux-musl`

The workflow links cross-compiled targets with `cargo-zigbuild` and verifies that every binary has no dynamic dependencies and no ELF interpreter before packaging.

## Install

Each GitHub release publishes three asset types:

- `psgen-<version>-<target>.tar.gz`: archive containing `psgen-<version>-<target>/` with `psgen`, `LICENSE`, and `README.md`.
- `psgen-<target>`: uncompressed static binary.
- `SHA256SUMS`: one `sha256sum` line for each tarball and each raw binary. `SHA256SUMS` does not list itself.

Download, verify, and install a release tarball:

```sh
# Set TAG to the git tag and VERSION to [package].version in Cargo.toml at that tag.
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

`SHA256SUMS` contains 14 lines for the 15 assets of a seven-target release because `SHA256SUMS` cannot list its own checksum.
A plain `sha256sum -c SHA256SUMS` command fails on every asset that you did not download.
Pass `--ignore-missing` to verify the downloaded files and skip absent files.
`sha256sum -c --ignore-missing` exits non-zero if zero files match, proving that each downloaded file matches the release manifest.
Install the raw `psgen-<target>` binary using the same verification steps.

The release workflow publishes to crates.io for final tags only.
Final tags require `CARGO_REGISTRY_TOKEN` and verify `cargo info psgen@<version>` after upload so a release cannot succeed without publishing.
Because `v0.0.2` shipped before the `publish-crate` gate existed, crates.io currently holds only the `0.0.0` name reservation.
Install `psgen` from GitHub release assets until a new final release publishes to crates.io.

## Commands

`psgen list` prints command lines.
`psgen table` prints a synthetic `ps aux` table.
`psgen table --live` prints the live process table in `ps aux` format.
`psgen inject` starts synthetic processes in the live process table.
The remaining subcommands are `stop`, `doctor`, `log`, `load`, `corpus`, `check`, `unit`, `profile`, `run`, `score`, `replay`, `verify`, `selftest`, `help`, and `version`.

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

When a requested count exceeds the command cap, `psgen` prints the cap on stderr and clamps the count to the cap.
`-n 0` selects the default count for every command.
For `list`, the default is one line per in-scope template, so `list` and `list -n 0` both print 181 lines, and `list -s N` matches `list -n 0 -s N` byte for byte.

Passing an explicit `-p` excludes every family that the profile weights at zero:

- `list -n 0 -p server` prints 163 lines.
- `list -n 0 -p dev` prints 173 lines.

`list` sorts output lexicographically by default (`--sort`).
Pass `--no-sort` to preserve weighted draw order, which starts with `/sbin/init`.
At a finite count, `-p` also changes which templates are drawn: `list -n 40 -s 7 -p server` and `list -n 40 -s 7 -p desktop` share 10 templates.

### Counts, repeats and host limits

`table` and `inject` meet `-n` whenever any in-scope template can repeat.
A multi-instance template (such as six `nginx` workers) preserves its instance count (`inst`), so one draw adds `inst` rows.

The repeat limit applies per template, with a per-command-line bound of `max(inst, ceil(rows / k))`.
In that formula, `k` is the count of repeatable in-scope templates and `inst` is the template's instance count.
`ceil(rows / k)` distributes large counts evenly across repeatable templates, while `inst` sets the floor for multi-instance services:

- `-f web -n 200`: `max(6, ceil(200 / 7)) = 29` rows for the busiest command.
- `-f mail -n 200`: `max(1, ceil(200 / 5)) = 40` rows.
- `-f sys -n 200`: `max(2, ceil(200 / 6)) = 34` rows.

Any template with a variable placeholder (`{hex64}`, `{cport}`, `{ip}`, `{n}`, and similar tokens) produces a new command line on each distinct expansion.

`--repeat-max N` limits how many times one expanded command line may appear:

- `--repeat-max 1`: allows each distinct command line at most once.
  In `FAM_WEB`, 17 templates (16 fixed command lines plus 1 `envoy` `{n}` template with 9 values) produce 25 distinct command lines.
  `table -f web -n 40 --repeat-max 1` therefore prints 25 rows and reports the shortfall on stderr.
- `--repeat-max 0`: removes the repeat cap.
- omitted: applies the default `max(inst, ceil(rows / k))` bound.

`list` never repeats a command line and rejects `--repeat-max` with exit 2.
Pass `list --no-uniq` to pad a list by repeating existing command lines.

Two limits can cap a synthetic table, and `table` prints the cause and counts on stderr:

- **PID space**: A snapshot cannot repeat a PID, and valid PIDs are strictly below `pid_max`.
  A synthetic table holds at most `pid_max - 1` rows in total, including PID 1 (`pid_max - 2` rows beside PID 1).
  When `pid_max < 3`, `table` still shows PID 1 if `/sbin/init` is in scope, with zero rows beside PID 1.
- **Corpus supply**: A family with only fixed command lines can supply at most its distinct templates unless `--repeat-max` allows repeats.

`--host-mem MiB`, `--host-pid-max N`, and `--host-uptime S` generate a synthetic table for a target host instead of the local host.
All three options reject `0` with exit 2 because `0` means unknown inside the host-fit rules.

### Options by command

Each subcommand accepts only the options that the subcommand consumes.
Passing an unsupported option or an invalid mode combination (such as `table --live --local` or `inject --dry-run --table`) exits 2 with a message naming the option.

- `list`: `-n/--count`, `-s/--seed`, `-p/--profile`, `-f/--family`, `--sort`/`--no-sort`, `--uniq`/`--no-uniq`.
- `table`: generator options, `--utc-offset`, `--local`, `--live`, `--repeat-max`, `--host-mem`, `--host-pid-max`, `--host-uptime`.
- `inject`: generator options, `--repeat-max`, `-d/--duration`, `--pidfile`, `--mem`/`--no-mem`, `--mem-cap`, `--mem-target`, `--phys-cap`, `--disk`, `--exe`/`--no-exe` (`--allow-proc-exe` aliases `--no-exe`), `--shadow-dir`, `--no-root`, `--tty`/`--no-tty`, `--threads`/`--no-threads`, `--user`/`--no-user`, `--create-users`, `--busy`, `--cpu`, `--dry-run`, `--plan`, `--json`, `--table`, `--verify`, `--wait`, `--elevate`, `-q/--quiet`.
- `stop`: `--pidfile`, `--force`, `--plan`, `--elevate`, `-q/--quiet`.
- `check`: `-s/--seed`, `-f/--family`, `--binaries`, `--require-binaries`.
- `unit`: `-n/--count`, `-s/--seed`, `-p/--profile`, `-f/--family`, `--pidfile`, `--create-users`, and all `inject` options except `--table`, `--wait`, `--dry-run`, `--plan`, `--json`, `--repeat-max`, `--elevate`, and `-q`.
  `unit` caps `-n` at 500.
- `doctor`: `--json`, `--pidfile`.
- `log`: `-s/--seed`, `-m/--module`, `--lines`, `--delay`, `--speed`, `--log-fmt`.
- `load`: `--cpu-util`, `--mem-util`, `--disk-util`, `-d/--duration`, `--force`, `-q/--quiet`.
- `corpus`: no options.

Generator options are `-n/--count`, `-s/--seed`, `-p/--profile` (`server`, `dev`, `desktop`), and `-f/--family` (`sys`, `web`, `db`, `ctr`, `dev`, `mon`, `sto`, `mail`, `desk`, `net`).
`-p` weights template draws for `list`, `table`, and `inject` and excludes families weighted at zero when `-p` is explicit.

## The table

`table`, `table --live`, and `inject --table` print one header line followed by one line per process:

```text
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
```

The column rules match `procps-ng` `ps aux`:

- **USER**: Resolves the effective UID through the passwd database, or prints the decimal UID if unresolved.
  Names longer than 8 characters truncate to 7 characters plus `+`.
- **%CPU**: Computes `ticks * 1000 / elapsed`, where `elapsed` uses sub-second `CLOCK_BOOTTIME`.
  Values below 100.0 print one decimal place; values at or above 100.0 print an integer to keep four columns.
- **%MEM**: Computes `rss * 1000 / MemTotal` using truncating integer division, capped at 999.
  Live tables divide by `/proc/meminfo` `MemTotal`, matching `ps` inside containers.
  Synthetic tables divide by the local memory budget (`MemTotal`, lowered to the cgroup limit if smaller) or by `--host-mem`.
- **START**: Prints `HH:MM` for the current calendar day in the active timezone, `%b%d` (`Nov05`) for another day in the same year, and `%Y` for another year.
  Synthetic rows never start before host boot and never start in the future.
- **TIME**: Prints total CPU minutes and seconds (`75:00`), never `HH:MM:SS` and never a day prefix.
  Live rows use real `utime + stime`; synthetic rows model CPU time from process age and `%CPU`.
- **STAT**: Prints the process state character plus `<` (negative nice), `N` (positive nice), `L` (locked pages), `s` (session leader), `l` (multithreaded), and `+` (foreground process group).
- **TTY**: Resolves the TTY device name when the device node exists, or prints `?`.
- **COMMAND**: Reads `/proc/PID/cmdline` up to 512 KiB and joins arguments with spaces.
  NUL bytes and line breaks separate arguments, and other control bytes become `?`.
  Zombies receive a trailing ` <defunct>`, processes without argv print `[comm]`, and printed rows truncate at 128 KiB.

`table --live` uses the host timezone and host `MemTotal`, and rejects `--local`, `--utc-offset`, `--repeat-max`, and all `--host-*` flags with exit 2.
`inject --table` uses the same live renderer and sorts rows by PID.

Synthetic `table` accepts `--utc-offset` (minutes east of UTC, `-1440..1440`, default 0) and `--local`.
`--local` selects the system timezone and overrides `--utc-offset` instead of applying both offsets.

## Injection model

`inject` spawns a process tree from corpus rows.
Each root stub forks its child stubs after reading its configuration so `ps -ef` and `pstree` display realistic parent chains.
Each stub keeps the template argv across `execve` so `ps aux` and `/proc/PID/cmdline` display the template command line.

### Exe tiers

`inject` chooses `/proc/PID/exe` from three tiers:

- **bind**: Creates a private mount namespace, marks `/` private, bind-mounts the stub binary over the template executable path, and re-executes through the template path.
  `/proc/PID/exe` and `/proc/PID/maps` show the template path.
  When the template path does not exist on disk, `inject` creates a `.psgen-<pid>-<row>-<n>` staging directory that `stop` later removes.
- **shadow**: Copies the `psgen` binary to `psgen-stub` inside `.psgen-<pid>-9000-<n>` under the shadow root (`<TMPDIR>/.psgen-stubs` by default, or `--shadow-dir`) and executes that copy.
  `/proc/PID/exe` shows the shadow path.
- **proc-self**: Executes `/proc/self/exe`.
  `/proc/PID/exe` points to the `psgen` binary.

`inject` selects the tier once per run in this priority order:

| condition | tier |
| --- | --- |
| `--no-exe` (or `--allow-proc-exe`) | `proc-self` regardless of other flags |
| `--no-root` with `--shadow-dir` | `shadow` |
| `--no-root` without `--shadow-dir` | `proc-self` |
| root (or usable user namespace) with mount namespace and bind mount allowed | `bind` |
| otherwise, with a shadow root available | `shadow` |
| otherwise | `proc-self`, with a warning naming the denied capability |

The default shadow root is `<TMPDIR>/.psgen-stubs`.
When a container denies bind mounts, `inject` falls back to `<TMPDIR>/.psgen-stubs` so `/proc/PID/exe` still displays a plausible path.
`inject` scans `<cwd>/.psgen-stubs` only to clean up leftovers from earlier versions.

### Users, tty and threads

When running as root without `--no-root` or `--no-user`, each stub calls `initgroups`, `setgid`, and `setuid` for its template user.
If a template user does not exist, the stub warns and runs as the invoking user.

Passing `--create-users` as root creates missing system accounts with `useradd`, reusing an existing group when the group exists without the user.
`psgen` looks up `useradd` only at four fixed absolute paths without consulting `PATH`:

- `/usr/sbin/useradd`
- `/usr/bin/useradd`
- `/sbin/useradd`
- `/run/current-system/sw/bin/useradd`

Before running `useradd`, `psgen` clears the child environment with `env_clear()` and sets only `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LC_ALL=C`.

Without root, `inject` warns once and `--create-users` creates no accounts.
`--elevate` re-executes `inject` or `stop` through `sudo -n` when passwordless `sudo` is available.

`--tty` (default) allocates a real PTY for each TTY template and sets that PTY as the controlling terminal so `ps` shows `pts/N`.
`--no-tty` clears TTY and session flags and detaches every row from the caller's controlling terminal.
`--threads` (default) starts a second thread for threaded templates.

If a privilege drop fails, the stub reports a deviation and continues running under its current UID.

### Memory and disk

`--mem` (default) pads VSZ and RSS from one shared anonymous arena sized to the largest RSS target, backed by `memfd_create` or an unlinked temporary file.
Each stub maps a prefix, touches its pages, trims RSS with `MADV_DONTNEED`, and pads VSZ with a `PROT_NONE` mapping.
Because stubs share the arena pages, actual physical memory usage stays smaller than the sum of reported RSS values.

- `--mem-target KiB`: sets the per-stub RSS target, clamped to template VSZ minus 4 MiB.
- `--mem-cap MiB`: caps the sum of planned RSS targets while keeping a 4 MiB floor per stub.
- `--phys-cap MiB`: caps estimated physical memory (largest RSS plus page tables plus base RSS).
  When omitted, the default budget is the smaller of one quarter of host RAM and half of the cgroup memory limit.
- `--disk MiB`: writes the requested MiB of temporary data per stub.

`inject` checks `RLIMIT_FSIZE` before sizing the arena.
Targets above `RLIMIT_FSIZE` drop with a warning, and memory padding disables with a warning if the limit cannot hold the arena.
`--verify` checks that each stub's real VSZ and RSS match the plan within 128 KiB, and warns with no effect under `--no-mem`.

### Previewing a run

`--dry-run` prints `user<TAB>command` lines for the rows that `inject` would spawn.

`--dry-run --plan` prints the resolved execution plan instead:

```text
tier bind   mem on, tty on, threads on, busy off
plan: 4 stubs, 2 roots; rss 67 MiB shared, ~42 MiB physical (budget 3994 MiB); staging 0 directory patterns
row 0 root user=root vsz=13160 rss=8156 cpu=0.0 tty=no threads=no exe=/usr/sbin/nginx
row 1 child user=www-data vsz=15444 rss=4824 cpu=0.0 tty=no threads=no exe=/usr/sbin/nginx parent=0
row 2 root user=root vsz=60676 rss=20596 cpu=0.1 tty=no threads=no exe=/usr/sbin/php-fpm
row 3 child user=www-data vsz=73208 rss=35680 cpu=0.1 tty=no threads=no exe=/usr/sbin/php-fpm parent=2
```

The plan line prints `from <shadow_root>` only when the resolved tier is `shadow`.
When a run requires staging directories (`shadow`, `--disk`, or missing `bind` executables), the plan prints `staging pattern <dir>` lines.
Those patterns include `<pid>` and `<i>` placeholders that `inject` fills at spawn time.

`--dry-run --json` prints the same plan as one JSON object with `rows`, `staging_dirs`, and `would_create` arrays.
`--plan` and `--json` are mutually exclusive; passing both exits 2.

Previews execute the same preflight checks as real runs: pidfile writability, live-pidfile detection, lock-file contention, disk space, and `RLIMIT_FSIZE`.
A preview refuses a live pidfile or an externally held `<pidfile>.lock` with exit 2 without creating or modifying files.
Previews never elevate and never create user accounts.
With `--create-users`, `--dry-run --plan` and `--dry-run --json` keep missing template usernames and list the accounts in `would_create` (with `null` UID/GID in JSON).

## Pidfile and stop

`--pidfile FILE` writes the run record in this format:

```text
# psgen <version> boot <boot-id> nonce <nonce>
# temp <absolute-temp-dir>
<pid>\t<starttime>\t<comm>
```

The header carries the boot ID and the run `nonce`.
`inject` writes one `# temp` line for each staging directory created during the run and writes no `# temp` lines when the run creates no staging directories.
`stop` parses the header without rejecting other version strings, so pidfiles from other releases still receive the boot-ID check.
If `inject` cannot read `/proc/sys/kernel/random/boot_id`, `inject` refuses to start.

### Pidfile Locking, Preflight, and Recovery Sidecars

Before spawning stubs, `inject` performs these steps:

1. Preflights the estimated final pidfile body size against directory permissions, target type, and `RLIMIT_FSIZE`.
   `psgen` ignores `SIGXFSZ` at startup so oversize writes fail cleanly with `EFBIG` instead of terminating the process.
2. Acquires an exclusive non-blocking `flock` on `<pidfile>.lock` (opened with `O_NOFOLLOW`) to serialize concurrent `inject` runs on the same pidfile.
3. Re-checks that the pidfile records zero live rows while holding `<pidfile>.lock`.
4. Writes a header-only pending pidfile through an `O_EXCL | O_NOFOLLOW` temporary file and renames the temporary file atomically into place.

`inject` tries four temporary filename suffixes in order: `.tmp.<pid>.<16 hex>`, `.t<pid><6 hex>`, `.tmp.<pid>`, and `.t<pid>`.
With `NAME_MAX` = 255 and a 5-digit PID, `.t<pid>` is 7 bytes.
A 248-byte basename therefore fits, and a 249-byte basename fails preflight with exit 2.
The lock suffix `.lock` is 5 bytes.
Because Linux PIDs can reach 7 digits, `unit` reserves 9 bytes of suffix headroom and accepts basenames up to 246 bytes.

An existing pidfile target must be absent, empty, or an existing `psgen` pidfile.
`inject` refuses directories, symlinks, FIFOs, sockets, and devices with exit 2.
`stop` opens the pidfile with `O_NOFOLLOW` so symlinks are never followed.

If the post-spawn pidfile write fails after stubs exist, `inject` removes the pending header file if possible.
`inject` then writes a recovery sidecar carrying the real `# temp` paths and run `nonce`.
`inject` tries `<pidfile>.spawned` first (opened with `O_NOFOLLOW`) and falls back to `<TMPDIR>/psgen-spawned-<pid>-<nonce>.pid` if the pidfile directory is unwritable.
`inject` then prints the exact `psgen stop --pidfile <sidecar>` command on stderr and exits 1.

### Stopping a Run

`stop --pidfile FILE` validates the pidfile and checks each row's identity before sending signals:

- **Format and header**: `stop` prints the path and OS error on unreadable files and exits 1.
  `stop` refuses CRLF pidfiles.
  `stop` accepts a `# psgen <version>...` header after leading blank or comment lines before the first content line, and ignores unrelated comments such as `# psgen-wrapper` or `# psgen: ...`.
  When `<pidfile>` has zero process rows, `stop` automatically reads `<pidfile>.spawned` beside `<pidfile>` if that sidecar exists.
- **Three-field lines (`pid\tstarttime\tcomm`)**: `stop` verifies both `starttime` and `comm`.
- **Two-field lines (`pid\tstarttime`)**: `stop` verifies `starttime`.
- **One-field lines (`pid`)**: `stop` verifies that `PSGEN_NONCE` in `/proc/PID/environ` matches the header's `nonce` across `proc-self`, `shadow`, and `bind` tiers.
  If the header carries no nonce or the process lacks the matching `PSGEN_NONCE`, `stop` counts the row as a failure (`cannot identify`) and exits 1, never as a skip.
  For bind-tier rows, the diagnostic message names the executable path only as a hint and never treats the executable path as a match.

`stop` never signals PID 1.
`stop` processes deepest PIDs first, signals each leader's process group to catch unreported children, and signals each target PID via `pidfd_send_signal` (or check-then-kill when `pidfd_open` is unavailable).
`stop` skips zombies because zombies are already dead, while still signalling a zombie leader's process group.

After signalling, `stop` waits up to 2 seconds until every signalled PID exits or becomes a zombie so `stopped N` is accurate when printed.
Rows that needed no signal (already gone, zombie, PID 1, or starttime/comm mismatch) count as skipped.
Rows that `stop` could not identify or could not signal count as failed and make `stop` exit 1.
Running `stop` a second time on the same pidfile prints `stopped 0 processes, skipped N lines`.

`stop --plan` prints what `stop` would signal without sending signals, verifies signal permissions, and never elevates.
`stop --force` ignores boot-ID mismatches and allows stopping files that lack a `# psgen` header.

`stop` does not unlink the pidfile so callers can reuse the same pidfile path once its processes exit.
`stop` removes a `# temp` staging directory only when all of these conditions hold:

- Zero rows failed during `stop` and `--plan` is not set.
- `safe_temp_dir` approves the directory: absolute path, real directory (not a symlink), and not a mount point or bind mount (`is_mount_point`).
  The directory must not sit on FUSE or overlayfs on root runs.
  The caller must own the directory, mode bits must clear group and world write, and the basename must match `.psgen-<digits>-<digits>-<digits>`.
- The directory's live marker names zero live processes.
- `remove_staging_dir` confirms `is_mount_point` is false before deletion.

Skipped lines (already gone, zombie, PID 1, identity mismatch, or malformed line) do not block staging directory removal.

### Reclaiming Staging Directories After `--duration`

A run that exits via `--duration` without `stop` leaves its staging directories on disk.
Two mechanisms reclaim those directories:

- Run `psgen stop --pidfile FILE` on the run's pidfile.
  `stop` reports `stopped 0 processes, skipped N lines` and removes every unreferenced `# temp` directory.
- Start a later `psgen inject` run.
  Before spawning, `inject` prunes unreferenced staging directories in the temporary directory, `<TMPDIR>/.psgen-stubs`, `<cwd>/.psgen-stubs` (for older-version leftovers), and the current run's `--shadow-dir`.
  Stubs append their PID, start time, PID namespace inode, boot ID, and nonce to the live marker before `execve`.
  Pruning keeps any directory with a live marked process, an active owner marker, or a marker from another PID namespace.
  Pruning removes directories whose boot ID is from an earlier boot or whose marked processes have all exited.
  Directories owned by another UID are reported and left untouched.

If you use a custom `--shadow-dir` outside the temporary directory, pass the same path on later runs so pruning can reach it.

`--wait` requires a non-zero `--duration` (exit 2 otherwise).
`--wait` sleeps for the duration, verifies root start times, and kills each root's process group.
`--wait` then signals remaining identified PIDs and removes staging directories once their live markers are clear.

## unit

`psgen unit` prints a boot-time systemd unit to stdout without installing the unit file.
For a binary installed at `/usr/local/bin/psgen`, `psgen unit` prints:

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

`ExecStart` and `ExecStop` reference the running binary path.
`unit` derives `RuntimeDirectory=` from the pidfile path: a pidfile directly inside `/run` emits no `RuntimeDirectory=`, and `/run/<dir>/<file>` emits `RuntimeDirectory=<dir>` with `RuntimeDirectoryMode=0700`.

`unit` validates the pidfile path and exits 2 for any of these defects:

- A path outside `/run`.
- A nested path more than one directory below `/run` (such as `/run/a/b/c`).
- A `.` or `..` component.
- An empty path component (`//`).
- A pidfile basename longer than 246 bytes (reserving 9 bytes for temporary and lock suffixes within `NAME_MAX`).
- Any control byte (`< 0x20` or `0x7f`).
- Any non-UTF-8 byte anywhere in the path.
- Any `'`, `"`, or `\` character in the runtime directory name.

`RuntimeDirectoryPreserve=yes` keeps the runtime directory across stops so stopping one unit cannot remove another unit's pidfile.
The first `ExecStop` uses `/bin/sh -c` without a `-` prefix so an absent pidfile succeeds.
Real stop failures (foreign boot ID, malformed pidfile, or refused signal) still fail the unit stop.
The second `ExecStop=-/bin/rm -f -- <pidfile>` removes the pidfile so the service can restart cleanly.

`unit` forwards all supplied `inject` options into `ExecStart`: `-p`, `-f`, `-d`, `--no-mem`, `--mem-cap`, `--mem-target`, `--phys-cap`, `--disk`, `--no-exe`, `--shadow-dir`, `--no-root`, `--no-tty`, `--no-threads`, `--no-user`, `--busy`, `--cpu`, `--verify`, and `--create-users`.
`unit` caps `-n` at 500.

## corpus, check, doctor, log and load

### corpus

`psgen corpus` prints all 181 embedded templates across 10 families as `family<TAB>user<TAB>vsz<TAB>rss<TAB>command`.
Templates that run as the invoking user print the `@self` sentinel in the user column.
`list`, `table`, and `inject` replace `@self` with the invoking user's name, or with the decimal UID when `/etc/passwd` has no entry for that UID.

### check

`psgen check` expands every template and rejects unexpanded placeholders, control bytes, empty commands, and denylisted cryptocurrency, botnet, brute-force, or credential-dumping terms.
`check -f FAMILY` checks one family and prints both the expanded count and the total.
`check --binaries` reports which template executables exist on the host (checking absolute paths directly, searching `PATH` and standard directories for bare names, and resolving symlinks) and always exits 0.
`check --require-binaries` performs the same check and exits 1 if any executable is missing.

### doctor

`psgen doctor` probes host capabilities and prints `env`, capability verdicts (`ALLOW`/`DENY` with `errno`), `probe` (sandbox posture), and `summary` sections.
When a probe cannot fork or `TMPDIR` is missing, `doctor` reports `[not attempted]` in text mode and `"not_attempted":true` in JSON mode.
This avoids misreporting a fork or directory failure as a kernel denial.
The `pty` check (`check_pty`) tests full PTY allocation (`/dev/ptmx`, `TIOCSPTLCK`, `TIOCGPTN`, and `/dev/pts/<n>`).

`doctor --json` prints one JSON object containing `env`, `checks` (objects with `name`, `ok`, `detail`, and optional `errno` and `not_attempted`), `probe`, `core`, and `core_ok` (`proc_exe`, `fork`, `prctl_name`).
`doctor --json` preserves literal printable ASCII and valid UTF-8 strings, and refuses non-UTF-8 paths or environment values with exit 1 so raw bytes cannot collide with UTF-8.
Text mode escapes control bytes, `0x7f`, `\`, and invalid UTF-8 bytes as `\xNN` (and `\\` for literal backslashes).

`doctor --pidfile FILE` verifies that `FILE` is both writable and records zero live rows (`allowed` in JSON, `ALLOW`/`DENY` in text).

### log

`psgen log` writes activity logs for 14 modules.
Run `psgen log -m list` to print all 14 module names on one line followed by `  <module> (<alias>, ...)` lines for the 12 modules that have aliases (`mkinitcpio` and `julia` have no aliases).
`--log-fmt apache` applies to `weblog` only; `json` and `syslog` work for every module.
`--lines 0` exits 2 as a usage error.
Counts above 200000 print `log events capped at 200000` on stderr and clamp to 200000.
On `EPIPE` (closed reader), `log` exits 0 silently; on any other stdout write error, `log` prints the errno and exits 1.

### load

`psgen load` generates real CPU, memory, and disk pressure and prints a summary to stdout (`-q` suppresses the summary).
`load` exits 2 if no utilization flag is provided or if every provided utilization value is zero.
On `EPIPE`, `load` exits 0 silently; on any other stdout write error, `load` prints the errno and exits 1.

- `--mem-util PCT`: maps and touches `PCT` percent (0..95) of the tighter of `MemTotal` and the cgroup memory limit.
  `load` walks cgroup v2 and v1 ancestors to find the tightest limit and minimum remaining headroom.
  `load` exits 1 if current cgroup usage is unreadable.
  Without `--force`, `load` exits 2 if the request exceeds `MemAvailable` or remaining cgroup headroom (including zero headroom).
- `--disk-util MiB`: measures usable space in `TMPDIR` (90% budget with 10% reserved) before checking `RLIMIT_FSIZE`, so a missing `TMPDIR` reports the real cause first.

## Profile-driven decoys and blind evaluation harness

`psgen` can capture a live target's observable `/proc` shape (`schema: 1`, never storing real secrets), spawn matched low-overhead live decoy populations, and run reproducible two-phase blind evaluations (Phase A process table + Phase B deep `/proc`) with controls (`C-01`..`C-07`), single-surface hard negatives (`HN-01`..`HN-10`), SHA-256 manifests, and planted-defect self-tests.

### profile

Capture a live process or tree into a schema v1 JSON profile, or validate an existing profile:

```sh
psgen profile --pid 4210 --tree --label ci-runner --masker pmask \
  --redact-token FAKE_SECRET --out profile.json
psgen profile --validate profile.json
```

### inject fidelity flags

Bare `psgen inject` preserves its existing corpus behavior and `PSGEN_NONCE` / v3 stub config contract.
Opt-in flags enable profile-matched high-fidelity decoy populations:

- `--from-profile FILE`: build live decoy trees from a schema v1 `profile.json` (`--decoy-level 1..6`, default `5`).
- `--clean-env`: authenticate config fd 3 via sealed memfd link name (`/memfd:pg:<nonce>`) with zero `PSGEN_NONCE` in `/proc/<pid>/environ`, and clone target `environ`, `cwd`, `fds`, `task/*` thread names, `VmLck`, `RssShmem`, and delta `VmRSS`/`VmSize` without `memfd:cache`.
- `--exe-memfd`: re-execute stubs from an anonymous memfd (`/memfd:<label> (deleted)`).
- `--decoy-token PREFIX`: place deterministic shape-matched decoy tokens in anonymous `rw-p` memory and `[stack]` (Level 5+).
- `--dumpable 0|1`, `--seccomp 0..8`, `--wchan pause|epoll|poll|nanosleep|futex|read`: override hardening and wait-channel surfaces.
- `--jitter-ms N`, `--churn N`: spread spawn start times with seeded jitter and reap short-lived background churn with zero zombies (`PR_SET_CHILD_SUBREAPER`).
- `--masker-cmd CMD`: spawn decoys by running an external masker command directly.

### run, score, replay, verify, and selftest

```sh
# Build a reproducible bundle with a physically isolated evaluator view (no answer.json in blind-dir)
psgen run --profile profile.json --out run-1234 --blind-dir blind-1234 \
  --decoys 50 --seed 1234 --mode both --level 6 --control C-06

# Live interleaved run (spawns target among matched live decoys and snapshots /proc)
psgen run --live --profile profile.json --target-cmd "pmask --stealth --label ci-runner -- /bin/sleep 60" \
  --out run-live --blind-dir blind-live --decoys 20 --seed 4004 --mode both --level 6

# Verify manifest hashes, schema validity, target presence, and zero secret/host-path leaks
psgen verify run-1234 --pick pick.json --redact-token FAKE_SECRET

# Score or deterministically replay offline without touching /proc
psgen score run-1234 --pick pick.json --out score.json
psgen replay run-1234 --pick pick.json

# Run all 6 planted-defect passing+refusal guards and the 36-run 9/10 vs 7/10 discrimination matrix
psgen selftest --out selftest-out
```

## Tests

Build and stage the static musl binary at `target/release/psgen`, then run `tests/smoke.sh`:

```sh
cargo build --release --target x86_64-unknown-linux-musl
mkdir -p target/release
cp target/x86_64-unknown-linux-musl/release/psgen target/release/psgen
sh tests/smoke.sh
```

`tests/smoke.sh` runs every CI gate in one script:

- `PSGEN_REQUIRE_ALL` contract verification (`tests/helpers/require_all_check.sh`)
- CLI smoke checks (version, help, corpus check, corpus count, list count, deterministic seed)
- `fmt` (`cargo fmt --all -- --check`)
- `clippy` (`cargo clippy --locked --all-targets -- -D warnings`)
- `unit tests` (`cargo test --quiet --locked --release`)
- `package` (`cargo package --locked --no-verify`)
- `unit` (`systemd-analyze verify` and unit assertions)
- `workflow` (`tests/workflow.sh`)
- `invariants` (`tests/invariants.py`)
- all 7 per-issue proof scripts under `tests/proof_cases/`: `report.sh`, `pidfile.sh`, `generator.sh`, `table.sh`, `stop.sh`, `inject.sh`, and `surface.sh`
- binary size check (under 1 MiB)

`tests/smoke.sh` unsets `PSGEN_REQUIRE_ALL` before running `tests/proof_cases/*` so cases requiring optional host capabilities (root, PTY, PID namespaces, or live systemd) skip cleanly while regressions still fail.

Run `tests/invariants.py` alone against any binary with:

```sh
PSGEN_BIN=path/to/psgen python3 tests/invariants.py
```

Run one per-issue proof script against any binary with:

```sh
sh tests/proof_cases/report.sh path/to/psgen [issue ...]
```

Set `PSGEN_SRC=<tree>` to override the source tree inferred from `<tree>/target/<profile>/psgen`.

Set `PSGEN_REQUIRE_ALL=1` on capable hosts so any skipped check becomes a failure naming the missing capability.
`tests/smoke.sh`, `tests/invariants.py`, `tests/workflow.sh`, `tests/cross.sh`, `tests/proof_cases/report.sh`, and `tests/vm.sh` all read `PSGEN_REQUIRE_ALL`.
Both `ci.yml`'s `test` job and `release.yml`'s `test` job set `PSGEN_REQUIRE_ALL=1`.

`tests/invariants.py` compares `table --live` against `ps aux` field by field and validates option acceptance across every subcommand.
The suite also runs regressions for pidfile reuse, repeated `stop`, `stop --plan`, seed stability, repeat bounds, host-fitted sizes, and `pid_max` limits.
Additional checks cover live table formatting, `doctor --json` structure, foreign-version headers, timezone flags, `NAME_MAX` preflight, inherited fd 3 handling, staging cleanup, closed log pipes, `--mem-util` bounds, and `check --binaries`.

`tests/workflow.sh` verifies release-note selection via `scripts/release-notes.sh`, `gh release create` arguments, shell syntax for every `run:` block in both workflows, and sabotage tests for each CI gate.

### CI gates

`.github/workflows/ci.yml` runs two jobs:

- `lint`: runs `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --release`, `cargo package --locked --no-verify`, `tests/workflow.sh`, and a `unit` check.
  The `unit` check runs `systemd-analyze verify` when installed and rejects any unit naming `proc-fs-nets.target`.
  The `unit` check requires `RuntimeDirectory=psgen`, `ConditionPathExists=/proc/1/stat`, and an `ExecStop=` line running `psgen stop --pidfile` guarded by `-` or `/bin/sh -c`.
  The `unit` check does not grep for `ExecStop=-` because the `/bin/rm` cleanup line would satisfy that grep regardless of the `psgen stop` line.
- `test`: builds `x86_64-unknown-linux-musl`, stages the binary at `target/release/psgen`, and runs `tests/smoke.sh` with `PSGEN_REQUIRE_ALL=1`.

`.github/workflows/release.yml` runs all of those checks in its `test` job, then builds all seven targets natively or via `cargo-zigbuild`.
The workflow verifies that every binary has no `NEEDED` or `INTERP` entries and runs `tests/smoke.sh` per target under binfmt.
Finally, the workflow packages reproducible tarballs and raw binaries and publishes `SHA256SUMS`, build provenance, the GitHub release, and the crates.io crate.
Crate publishing runs for final tags only, requires `CARGO_REGISTRY_TOKEN`, and verifies `cargo info psgen@<version>`.

## Benchmarks

Run `python3 bench/measure.py` (expecting `target/release/psgen`) to measure corpus, table, and injection timings and write `bench/RESULTS.md`.

Copy the static binary to `dist/psgen-x86_64-unknown-linux-musl`, then run `bench/sand.sh` inside a `sand-net` container cage or microVM:

```sh
SANDNET=/path/to/sand-net sh bench/sand.sh container
SANDNET=/path/to/sand-net sh bench/sand.sh microvm
```

`bench/sand.sh` writes `bench/sand-<cage>.log` and requires a `sand-net` checkout plus the image built from `tests/sand/Containerfile`.

## Limits

- `psgen` runs on Linux only and requires `/proc`.
- The pidfile is trusted input.
  Boot IDs, start times, and `comm` values are readable from `/proc`.
  A forged pidfile can therefore name processes that the caller can signal or staging directories that the caller owns.
  Run `stop` only on pidfiles that you control.
- `stop` does not unlink the pidfile.
  Re-running `inject` with the same pidfile path works once all recorded processes exit.
  The systemd unit removes the pidfile in `ExecStop` and preserves `RuntimeDirectory` so restarts start cleanly.
- One-field pidfile lines require the header's run `nonce` to match `PSGEN_NONCE` in `/proc/PID/environ` across all executable tiers.
  A header without a nonce or a process without a matching `PSGEN_NONCE` fails the row (`cannot identify`, exit 1) instead of guessing.
- Injected rows do not guarantee `TTY` is `?` under default `--tty`.
  Pass `--no-tty` when a harness requires `?` on every row in `ps`.
- A failed privilege drop reports a deviation and leaves the stub running under its current UID instead of aborting the run.
- The configuration `memfd` carries `F_SEAL_SHRINK`, `F_SEAL_GROW`, and `F_SEAL_SEAL`, but omits `F_SEAL_WRITE`.
  Status records travel over pipe fd 5 (`status_fd`), not over fd 3.
  `inject` omits `F_SEAL_WRITE` only so the stub can write `stage = 1` at `CFG_STAGE_OFF` on fd 3 before re-exec.
  A process that holds a writable descriptor to that `memfd` can modify configuration bytes after validation.
- The stub validates the shadow leaf (`psgen-stub`) through an opened descriptor and then executes the leaf by path.
  The `0700` staging directory mode limits access to that time-of-check/time-of-use window to the owning UID and root.
- `child_fds` cannot reference the stub's own configuration descriptor or fd 3, and child stubs must start at stage 0.
  This blocks single-descriptor recursion, though a crafted configuration with multiple sealed descriptors can fork extra processes.
- Development cages lacked a live FUSE daemon, so tests verify the FUSE guards through predicate unit tests, hardlinks, and symlinks.
- Release artifacts ship static musl binaries only; no glibc release artifacts are published.
  `cargo install` defaults to the host target (normally glibc); pass `--target x86_64-unknown-linux-musl` to build a static binary.
- `make build` and `scripts/build-all.sh` build only `x86_64-unknown-linux-musl`; CI builds all seven targets.
- A non-root `--tty` row that calls `setsid` and exits or stalls before reporting a status record leaves the root process group and does not appear in the pidfile.

## Security

`psgen` intentionally spoofs process state.
Read `SECURITY.md` before passing an untrusted pidfile to `stop` or allowing a supervisor to pass file descriptors to `psgen`.
Never install `psgen` setuid or setgid; the stub refuses to run in that configuration.

## License

0BSD. See `LICENSE`.
