# Changelog

## 0.2.0

### Added

- Upgraded `psgen profile` to **schema v2** with upward + downward `--tree` capture (`parent` and `tracer` ancestors bounded away from init and caller harness shells; opt out via `--no-ancestors`), exact trailing-space `comm` preservation (up to 15 bytes), `sid`/`pgid`/`groups`, `environ_raw_len`/`environ_all_nul`, and token shape/length/charset/placement/SHA-256 metadata (`token_len`, `token_charset`, `token_placements`, `token_sha256`) across `argv`, `environ`, `heap`, `stack`, and `anon`.
- Added `--redact-token-file <FILE>` (supporting `-` for stdin) to `profile`, `run`, and `verify` so callers never have to export secrets into child environments.
- Added `--no-clean-env`, `--same-session`, `--label-decoys <N>`, and `--interleave-cmd <CMD>` to `psgen inject`, plus `wait4` (`do_wait`) wait-channel mode and per-thread `wchan` cloning.
- Added `--redact-token`, `--redact-token-file`, and `--redact-env` to `psgen run`, and made `--profile` optional when `--live` is paired with `--target-cmd` or `--target-pid` (auto-capturing the target tree).
- Added fail-closed `psgen verify --blind-dir <DIR>` verifying `BLIND_MANIFEST.sha256` and refusing any contaminated blind directory (`answer.json`, `population.json`, `profile.json`, `MANIFEST.sha256`, `*.pid`, target PID labels, secret leaks, or host path leaks).
- Added 15-surface `surface_fidelity` reporting (`ps_indistinguishable_decoys`, `proc_indistinguishable_decoys`, `per_surface`, `separating_surfaces`, `discrimination_gate`) in `psgen score`.
- Added planted-defect guards `PD-07` (blind-dir contamination fail-closed check) and `PD-08` (opacity/seccomp inversion and flat-`PPid=1` decoy defect detection + survival-gated scoring) to `psgen selftest`.

### Fixed

- Fixed opacity & seccomp/NNP inversion in `inject --from-profile`: decoys now match target `dumpable`, `NoNewPrivs`, and exact `Seccomp_filters` delta (`target - inherited`) instead of forcing `dumpable=0` / extra filters at Level 6, and Yama `ptrace_scope=1` `/proc/<pid>/mem` denials no longer misclassify dumpable targets as non-dumpable.
- Fixed flat `PPid=1` decoy trees and session leaks: decoy supervisors now stay alive blocking in `wait4` (`do_wait`) with seeded intra-tree PID dispersion, exact child session inheritance, and full-tree 3-field pidfile cleanup via `psgen stop`.
- Fixed `<REDACTED:len=N>` verbatim copy, all-NUL `environ` span mismatch (in-place stack `environ` zeroing), `AT_EXECFN` matching, capability leakage (`capset` zeroing after private-userns bind-mount exe spoofing), detached stdout pipe hangs under `| tee`, and `run --live` synthetic churn/decoy mixing.
- Replaced high-RAM private `F_CLEAN_ENV` page dirtying with zero-burn shared read-only page-cache `maps`/`RssFile` mappings and untouched `PROT_NONE` `VmSize` padding.
- Fixed `compute_population_score` to strictly gate the 0–10 score on `C-06` survival, control pass rate, `C-04` false-positive rate, `wrong_reason_picks`, and `differing_target_surfaces`.

### Changed

- Unified the stub configuration wire format to `PGCFG023` v5 authenticated via sealed memfd link name (`/memfd:pg:<nonce>`), defaulted `--clean-env` and `bind_exe` (with basename-matched shadow copy fallback) ON under `inject --from-profile`, and slimmed binary size + enabled static non-PIE musl relocation so all seven static musl release binaries stay comfortably under 1 MiB.

## 0.1.0

### Added

- Added `psgen profile` (`--pid`, `--tree`, `--validate`, `--redact-token`, `--redact-env`) to capture and validate schema v1 observable process profiles from live processes or trees without ever writing real secrets.
- Added high-fidelity decoy injection options to `psgen inject`: `--from-profile`, `--decoy-level 1..6`, `--clean-env` (sealed memfd link-name run-tag authentication with zero `PSGEN_NONCE` in `/proc/<pid>/environ`), `--exe-memfd` (`/memfd:<label> (deleted)` via `memfd_create` + `execveat`), `--decoy-token`, `--dumpable 0|1`, `--seccomp 0..8`, `--wchan` (`pause|epoll|poll|nanosleep|futex|read`), `--jitter-ms`, `--churn`, and `--masker-cmd`.
- Added synchronized live stealth parity for profile-driven decoys: sequential per-tree spawning with adjacent parent-child PIDs, interleaved target spawning (`PPid` and `starttime` parity), synchronized `PTRACE_SEIZE` before `PR_SET_DUMPABLE(0)` (matching both `TracerPid` and same-UID `EACCES`), `VmLck` (`mlock`), `RssShmem`, delta `VmRSS`/`VmSize` without `memfd:cache` fingerprints, per-thread `comm` cloning, `fd` cloning, and `PR_SET_CHILD_SUBREAPER` zombie reaping.
- Added the reproducible blind evaluation harness subcommands:
  - `psgen run` (`--profile`, `--out`, `--blind-dir`, `--decoys`, `--seed`, `--mode table|deep|both`, `--level 1..6`, `--control C-01..C-07`, `--hard-negatives HN-01..HN-10`, `--live`, `--target-pid`, `--target-cmd`, `--masker-cmd`) generating hash-verified, relocatable bundles with physically isolated `--blind-dir` evaluator views (never containing `answer.json`).
  - `psgen score` and `psgen replay` computing target survival, decoy pick rate, false-positive/false-negative rates, ambiguity rate, Wilson 95% confidence intervals, per-surface confusion matrix, reason distribution, and hard-negative survival with mandatory pre-scoring target-presence verification.
  - `psgen verify` checking `MANIFEST.sha256`, schema v1 validity, secret and host-path redaction across all bundle artifacts, and target-presence consistency.
  - `psgen selftest` running 6 planted-defect passing + refusal guards and a 36-run 9/10 vs 7/10 discrimination matrix.

### Changed

- Kept `libc = "0.2"` as the sole crate dependency and slimmed binary size across all modules so all seven static musl targets remain under 1 MiB.
- Preserved all 12 existing subcommands, flags, and legacy `psgen inject` (`PSGEN_NONCE` / v3 config) behavior unchanged.

## 0.0.3

### Security

- `stub` now enforces a sealed-`memfd`-only gate on file descriptor 3 via `sys::fd_sealed(fd)`.
  `stub` refuses all unsealed, anonymous, unlinked, and `O_TMPFILE` descriptors regardless of file mode or `fchmod`.
  `inject` no longer falls back to an unlinked temporary file for stub configurations.
- `safe_temp_dir()` and `sys::remove_staging_dir()` now call `sys::is_mount_point()` to refuse mount points and bind mounts.
  Both functions also refuse FUSE and overlayfs paths on root runs.
- `--create-users` now resolves `useradd` only from fixed absolute paths (`/usr/sbin/useradd`, `/usr/bin/useradd`, `/sbin/useradd`, `/run/current-system/sw/bin/useradd`) without consulting `PATH`.
  `psgen` clears the child environment before invoking `useradd` and sets only `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LC_ALL=C`.
- `inject` now opens `<pidfile>.lock`, `<pidfile>.spawned`, and fallback recovery sidecars with `O_NOFOLLOW`.

### Fixed

- `log --lines 0` now exits 2 as a usage error instead of succeeding with empty output.
  The event cap warning now prints `log events capped at 200000`.
- `load` now exits 2 when no utilization flag is given or when every supplied utilization value is zero.
- `load --mem-util` now walks cgroup v2 and v1 ancestors (including co-mounted v1 memory hierarchies) for the tightest limit and minimum remaining headroom.
  `load --mem-util` fails closed when current cgroup usage is unreadable or remaining headroom is zero.
- `load --disk-util` now checks usable space in `TMPDIR` (90% budget with 10% reserved) before checking `RLIMIT_FSIZE`, so a missing `TMPDIR` reports the real cause.
- `inject --dry-run --plan` now prints `staging N directory patterns` and `staging pattern <dir>` lines with `<pid>` and `<i>` placeholders.
  The plan lists staging patterns needed for missing bind-tier executables even without `--disk`, and prints `from <shadow_root>` only for the `shadow` tier.
- Previews (`--dry-run`, `--plan`, `--json`) now refuse a live pidfile or an externally held `<pidfile>.lock` with exit 2.
- `unit` now refuses paths outside `/run`, nested paths below `/run/<dir>`, empty path components (`//`), `.`, `..`, and basenames longer than 246 bytes.
  `unit` also refuses control bytes, non-UTF-8 bytes anywhere in the path, and `'`, `"`, or `\` in the runtime directory name.
- `doctor --json` now preserves printable ASCII and valid UTF-8 literals and exits 1 on non-UTF-8 paths or environment values.
  Text mode escapes control bytes, `0x7f`, `\`, and invalid UTF-8 bytes as `\xNN`.
- `stop` now prints the path and OS error on unreadable pidfiles and exits 1.
  `stop` accepts a `# psgen <version>...` header after leading blank or comment lines before the first content line and ignores `# psgen-wrapper` or `# psgen: ...` comments.
  `stop` refuses CRLF pidfiles and reads `<pidfile>.spawned` when `<pidfile>` has zero rows.
- `--host-pid-max` and `--host-uptime` now reject `0` with exit 2 and cover the full PID range (`pid_max - 1` rows in total including PID 1, or `pid_max - 2` rows beside PID 1).
- Live table rendering now prints VSZ and RSS above 4 GiB at full width and reads `/proc/PID/status` and `/proc/stat` beyond 8 KiB.
  Live table rendering prints a TTY name only when the device node exists.
- `%CPU` now divides by `CLOCK_BOOTTIME` to match `/proc` start times and warns once when `/proc/uptime` disagrees.
- `inject` now serializes concurrent runs with an exclusive `flock` on `<pidfile>.lock` and re-checks live rows after locking.
  `inject` preflights the estimated pidfile body size against `RLIMIT_FSIZE` and ignores `SIGXFSZ` so oversize writes report `EFBIG`.
- When a post-spawn pidfile write fails, `inject` removes the pending file if possible and writes a recovery sidecar carrying the real `# temp` paths and run `nonce`.
  `inject` writes `<pidfile>.spawned` (or fallback `<TMPDIR>/psgen-spawned-<pid>-<nonce>.pid`), prints `psgen stop --pidfile <sidecar>`, and exits 1.
- Capability probes now test full PTY allocation (`/dev/ptmx`, `TIOCSPTLCK`, `TIOCGPTN`, `/dev/pts/<n>`) and report `not_attempted` / `[not attempted]` when `fork` fails or `TMPDIR` is missing.
- Profiles that assign weight zero to a family no longer contribute rows to `list`, `table`, or `inject`.
  Fixed templates act as fill candidates with room 1, so `--repeat-max 1` reaches all distinct in-scope command lines.
- The `list` shortfall warning now computes distinct available lines from the same placeholder ranges that the generator uses.
- `log` and `load` now exit 1 with the errno on non-`EPIPE` stdout write errors and exit 0 silently on `EPIPE`.
- The release workflow now requires `CARGO_REGISTRY_TOKEN` for final tags and verifies `cargo info psgen@<version>` after publishing.
  `README.md` documents that `v0.0.2` was not published to crates.io.

### Changed

- Passing an explicit `-p` excludes families weighted at zero; omitting `-p` still includes the full corpus.
- `--repeat-max` bounds distinct expanded command lines instead of templates.
  A template with a variable placeholder supplies up to one row per distinct expansion under `--repeat-max 1`.
- The default shadow root is now `<TMPDIR>/.psgen-stubs`.
  `inject` scans `<cwd>/.psgen-stubs` only to prune leftovers from earlier versions.

## 0.0.2

### Fixed

- `table --live` now renders `START` in the host timezone to match `ps aux`, and `inject --table` uses the same renderer.
  `--local` and `--utc-offset` apply only to synthetic tables and exit 2 on live tables.
- `%MEM` now divides by `MemTotal` from `/proc/meminfo` in live tables, truncates to one decimal place, and caps at 999.
- Live rows now report real `utime + stime` in `TIME` and `/proc` start times in `START`.
- `%CPU` now uses sub-second `CLOCK_BOOTTIME` elapsed time and prints an integer at or above 100.0 to keep four columns.
- `STAT` now includes the full `pr_stat` flag set: state, `<` or `N` for nice, `L` for locked pages, `s`, `l`, and `+`.
- `TTY` now resolves serial, virtual, and PTY device names so container consoles show `hvc0` instead of `?`.
- `COMMAND` now strips raw line breaks, replaces control bytes with `?`, and appends ` <defunct>` to zombies.
  `COMMAND` reads up to 512 KiB and truncates printed rows at the 128 KiB `ps` buffer limit.
- Wide numeric fields now absorb adjacent spacing instead of shifting `STAT`, `START`, `TIME`, and `COMMAND` to the right.
  `inject --table` now prints rows in PID order.
- Seeds now remain reproducible across seconds because every age uses a fixed modulus and one snapshot timestamp.
- Synthetic rows never start before host boot or in the future, and rows from earlier calendar days print `%b%d`.
- PostgreSQL background workers and client backends now appear as children of the postmaster with `STAT` `S` instead of `Ss`.
- `--local` now overrides `--utc-offset` instead of applying two timezone shifts, and `--utc-offset` validates `-1440..1440`.
- `table` and `inject` now meet `-n` whenever any in-scope template can repeat.
  Multi-instance templates keep their instance count, remaining rows split evenly across repeatable templates up to `max(inst, ceil(rows / k))`, and shortfalls print the maximum reachable count on stderr.
- Synthetic tables now hold at most `pid_max - 1` rows in total including PID 1 (`pid_max - 2` rows beside PID 1), never repeat PIDs, and report PID-space shortfalls.
- Synthetic rows now fit within the target host memory so `%MEM` stays below 100.
- `inject` now writes the `Cargo.toml` version into the pidfile header, and `stop` parses the header without rejecting other version strings.
- `inject`, `stop`, and `doctor` now agree on valid `psgen` pidfiles.
- `stop` now refuses files with no `# psgen` header and headers with an empty or missing boot ID unless `--force` is given.
- `stop` now skips zombies instead of counting zombies as stopped and waits up to 2 seconds until signalled PIDs exit or become zombies.
  A second `stop` on the same pidfile reports `stopped 0 processes`.
- `stop` now signals deepest PIDs first so parent group kills do not skew per-line counts.
- `stop` now identifies one-field lines by matching the header's run nonce against `PSGEN_NONCE` in `/proc/PID/environ` across proc-self, shadow, and bind tiers.
  A header with no nonce or a process without the matching `PSGEN_NONCE` fails the row (`cannot identify`, exit 1).
  Executable paths appear only as diagnostic hints and never authorize a signal.
- The pidfile preflight now tests body size, file mode, atomic rename, and link count using the exact temporary filename shapes that `write_pidfile()` creates.
- `inject` now writes a header-only pending pidfile before forking the first stub.
- `stop` removes staging directories from `--duration` runs.
  The next `inject` prunes unreferenced staging directories in the temporary directory and default shadow roots while checking live markers, owner markers, PID namespaces, and boot IDs.
- `--wait` now checks live markers before removing staging directories so active non-reporting stubs retain their directories.
- `load --mem-util` now refuses allocations above `MemAvailable` unless `--force` is given.
- `log --lines` now caps at 200000 events, flushes in 64 KiB chunks, and stops immediately when the reader closes the pipe.
- `load` now writes its summary to stdout and suppresses the summary under `-q`.
- `check --binaries` now checks absolute paths directly, searches `PATH` and standard directories for bare names, and follows symlinks.
- `--create-users` now reuses an existing group when the user is absent, reports the first `useradd` error, and stops retrying when NSS cannot see a created account.
- Unresolved UIDs now render as decimal values to match `ps`.

### Unit, doctor and output

- `unit` now derives `RuntimeDirectory=` from the pidfile's parent directory, omits `RuntimeDirectory=` for paths directly under `/run`, and refuses paths outside `/run` with exit 2.
- `unit` now sets `RuntimeDirectoryPreserve=yes` so stopping one unit does not remove another unit's pidfile.
- `unit` now runs the pidfile preflight and warns when a path requires root privileges.
- `unit::arg()` now escapes `$` as `$$`, quotes arguments containing `'`, and refuses bytes below `0x20` with exit 2.
- `unit` now guards `psgen stop` with `/bin/sh -c` instead of `-` so real stop errors reach systemd, and adds `ExecStop=-/bin/rm -f -- <pidfile>` so restarts succeed.
- `doctor --pidfile` now reports `DENY` with a detail string when a pidfile records live rows.
- `doctor --json` in 0.0.2 escaped non-ASCII bytes as `\u00XX` instead of replacing non-ASCII bytes with `?`.
  `Unreleased` supersedes that behavior by keeping valid UTF-8 literal and refusing non-UTF-8 with exit 1.
  The `pidfile` field is an object containing `path`, `allowed`, `writable`, `live_rows`, and `detail`.
- `sys::out()` now exits 1 with the errno on non-`EPIPE` stdout write errors.
- `bpf_allowed()` now probes `BPF_MAP_CREATE` with a valid attribute structure instead of a null `BPF_MAP_LOOKUP_ELEM` call.

### Added

- Added `--repeat-max N` for `table` and `inject` (`1` forbids repeats; `0` removes the cap).
- Added `--host-mem MiB`, `--host-pid-max N`, and `--host-uptime S` for `table`.
- Added `--dry-run --plan` and `--dry-run --json` for `inject` to preview tier selection, rows, physical memory estimates, and staging directories.
- Added `stop --plan` to preview which processes `stop` would signal without sending signals.
- Added `check --require-binaries` (exit 1 on missing binaries) alongside `check --binaries` (exit 0).
- Added `name` fields to `doctor --json` check objects, plus `core`, `core_ok`, and the `pidfile` object.
- Added `log -m list` to print all 14 module names and their aliases.
- Updated `unit` output to emit `After=local-fs.target sysinit.target`, `ConditionPathExists=/proc/1/stat`, derived `RuntimeDirectory`, `RuntimeDirectoryPreserve=yes`, guarded `ExecStop`, and all forwarded `inject` options.
- Added `tests/proof_cases/report.sh` covering issues #8, #13, #19, #20, #21, #23, #24, and #27, invoked by `tests/smoke.sh` with `PSGEN_REQUIRE_ALL=1` support.

### Changed

- Unsupported subcommand options and invalid mode combinations (such as `table --live --local`, `stop --dry-run`, and `inject --dry-run --table`) now exit 2 with an error message.
- `list` now sorts output lexicographically by default (`--sort`); `--no-sort` keeps draw order.
  `-p` now weights template draws for `list`, `table`, and `inject`.
- `inject --dry-run --create-users` now preserves missing template usernames and lists accounts in `would_create` instead of falling back to the caller.
- `inject` previews now run the same pidfile, disk-space, and `RLIMIT_FSIZE` preflights as live runs.
- `gen_list()` now uses a `BTreeSet` for deduplication to avoid quadratic runtime on large lists.

### Security

- `stub` refuses to run when installed setuid or setgid.
- `stub` validated fd 3 ownership, non-FUSE/overlayfs filesystem, and `PSGEN_NONCE` (hardened further in `Unreleased` to accept only sealed `memfd` descriptors).
- `stub` validates staging directories and opened shadow-copy descriptors (regular file, `nlink == 1`, owning UID, non-FUSE/overlayfs on root runs).
- `inject` falls back from `getrandom` to a PID and clock mix for run nonces so missing entropy never aborts pidfile creation after spawning stubs.

## 0.0.1

Initial release.

- Added `list`, `table`, and `table --live` for synthetic and live `ps aux` output.
- Added `inject` with bind, shadow, and proc-self executable tiers, user switching, PTYs, threads, and VSZ/RSS padding.
- Added `stop` for pidfile-based cleanup and `--wait` for timed runs.
- Added `doctor` capability probing plus `log` and `load` activity generators.
- Added `corpus`, `check`, and `unit` subcommands.
- Shipped static musl Linux binaries for seven targets with `SHA256SUMS`.
