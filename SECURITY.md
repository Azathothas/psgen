# Security Policy

`psgen` intentionally spoofs Linux process state.
Deployment boundaries matter more for `psgen` than for an ordinary command-line tool.

## Deployment Requirements

- Never install `psgen` with setuid or setgid bits set.
  Before reading any configuration, `stub::maybe_run()` compares effective and real UIDs and GIDs.
  If the real and effective IDs differ, `psgen` exits with status 2.
- Never allow a supervisor, wrapper, or `sudoers` rule to pass an arbitrary file descriptor 3 to a privileged `psgen` process.
  File descriptor 3 is a trust boundary.
- Run `psgen stop` only on a pidfile that you control or trust completely.

## Threat Model and Enforcement

### Pidfile Trust Boundary

`psgen` treats the pidfile as trusted input.
`/proc` exposes boot IDs, process start times, and command names (`comm`) to local readers.
A forged pidfile can name any process that the caller has permission to signal.
A forged pidfile can also point `# temp` cleanup at a matching staging directory that the caller owns.

`stop` enforces these protections on pidfiles and sidecars:

- `stop` opens the pidfile and `<pidfile>.spawned` sidecar with `O_NOFOLLOW`, so `stop` never follows symlinks.
- `stop` refuses any file that has no `# psgen` header unless the caller passes `--force`.
- `stop` refuses any header with an empty boot ID or a boot ID from another boot unless the caller passes `--force`.
- `stop` refuses pidfiles with CRLF line endings.
- `inject` opens `<pidfile>.lock`, `<pidfile>.spawned`, and fallback sidecar files with `O_NOFOLLOW` to prevent symlink replacement.

### File Descriptor 3 Gate

The stub inspects file descriptor 3 and the process environment before entering stub mode.
The stub acts on a configuration descriptor only when all five conditions hold:

1. The process is not setuid or setgid.
2. The descriptor's filesystem is neither FUSE nor overlayfs.
   FUSE and overlayfs can forge file ownership and link counts.
3. `fstat` shows that the descriptor is owned by the stub's effective UID.
4. `fd_kind()` confirms a regular file with zero links (`nlink == 0`) where `sys::fd_sealed(fd)` returns true.
   `sys::fd_sealed(fd)` requires a sealed `memfd` carrying `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`.
5. The configuration nonce equals `PSGEN_NONCE` in the process environment.

`sys::fd_sealed(fd)` is the sole discriminator for descriptor type.
The stub ignores file mode bits, so `fchmod` cannot reclassify an unsealed `memfd`.
The stub refuses every unsealed, anonymous, unlinked, and `O_TMPFILE` descriptor regardless of its file mode.
`inject` has no unlinked-file configuration fallback.
If the kernel denies `memfd_create` with `MFD_ALLOW_SEALING`, `inject` refuses to start instead of spawning stubs.

This gate blocks named files, hardlinks, symlinks, unlinked temporary files, and `O_TMPFILE` inodes.
This gate also blocks unsealed `memfd` descriptors, `fchmod`-modified `memfd` descriptors, foreign-UID descriptors, FUSE or overlayfs descriptors, and missing or mismatched `PSGEN_NONCE` values.
Non-seekable objects such as FIFOs, sockets, and devices fail `pread` in `read_config()` and do not trigger stub mode.

### Run Nonce Scope

`PSGEN_NONCE` is a run tag, not cryptographic authentication.
The injector writes `PSGEN_NONCE` into the stub's environment, which shares the same trust plane as file descriptor 3.
A caller who controls both file descriptor 3 and the process environment can supply a matching `PSGEN_NONCE`.

`PSGEN_NONCE` rejects stray descriptors from unrelated runs of the same user and from supervisors that inherit file descriptor 3 without setting `PSGEN_NONCE`.
The injector generates `PSGEN_NONCE` from 8 random bytes via `getrandom`, or from a PID and clock mix if `getrandom` fails, encoded as hexadecimal.
Because each re-exec reads `PSGEN_NONCE`, the variable remains in `/proc/PID/environ` for the stub's lifetime.
Do not treat `PSGEN_NONCE` as a secret or a message authentication code.

### Staging Directories and Mount-Point Refusal

The stub writes into and executes from a staging directory only if `safe_temp_dir()` approves the directory.
`stop` applies the same `safe_temp_dir()` check before calling `sys::remove_staging_dir()`.

`safe_temp_dir()` requires all of the following conditions:

- The path is absolute.
- On root runs, the path is not on FUSE or overlayfs.
- `symlink_metadata` confirms a real directory, not a symlink.
- `sys::is_mount_point()` confirms the path is not a mount point or bind mount.
  `sys::is_mount_point()` compares the directory's device ID (`st_dev`) with its parent's device ID and checks `/proc/self/mountinfo`.
- The directory is owned by the effective UID and is neither group-writable nor world-writable (`mode & 0o022 == 0`).
- The directory basename matches `.psgen-<digits>-<digits>-<digits>`.

`sys::remove_staging_dir()` calls `sys::is_mount_point()` again before removing any directory.
These checks block bind-mount attacks that mount an arbitrary directory over a `.psgen-<d>-<d>-<d>` path.

Because `safe_temp_dir()` checks ownership and naming rather than per-run provenance, two runs under the same UID share the namespace of valid staging directories.
An attacker who controls the stub's UID, a sealed `memfd` on fd 3, and `PSGEN_NONCE` can target another staging directory owned by that UID with `--disk` writes.
Even in that scenario, the stub binds only `/proc/self/exe` and never executes an arbitrary path from the configuration.

### Staging Leaf Validation

Before executing a shadow copy (`psgen-stub`), the stub validates the opened file descriptor with `O_NOFOLLOW`:

- `fstat` confirms a regular file with link count 1 (`nlink == 1`).
- The file is owned by the stub's effective UID.
- On root runs, the descriptor's filesystem is neither FUSE nor overlayfs.

Hardlinks, symlinks, foreign-owned files, and root-run FUSE or overlayfs files fail this check.

### User Creation (`--create-users`)

When running as root with `--create-users`, `psgen` searches only four fixed absolute paths for `useradd`:

- `/usr/sbin/useradd`
- `/usr/bin/useradd`
- `/sbin/useradd`
- `/run/current-system/sw/bin/useradd`

`psgen` never looks up `useradd` through the caller's `PATH`.
Before executing `useradd`, `psgen` clears the child environment with `env_clear()` and sets only `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LC_ALL=C`.

### Privilege Elevation (`--elevate`)

`--elevate` runs `sudo -n` with the current arguments minus `--elevate`.
Previews (`--dry-run` and `stop --plan`) never elevate.
`--elevate` is a convenience for callers who already hold passwordless `sudo` access for `psgen`.

## What Counts as a Vulnerability

Report any of the following defects as security vulnerabilities:

- A method that makes `psgen` signal a process not named in the pidfile or execute an unintended binary.
- A method that makes the stub accept a configuration descriptor without already controlling the stub's effective UID.
- A write outside a validated staging directory, or any traversal into a mount point or bind mount.
- A crash or write failure that leaves live stubs with no pidfile or recovery sidecar to stop the stubs.
- Replacement of a symlink, FIFO, socket, or device by a pidfile, lock file, or sidecar file.

## Residual Limits

The following limits are known design trade-offs, not unreported defects:

- `PSGEN_NONCE` remains visible in `/proc/PID/environ` for the process lifetime.
  Any process allowed to read `/proc/PID/environ` can read the run nonce.
- The configuration `memfd` carries `F_SEAL_SHRINK`, `F_SEAL_GROW`, and `F_SEAL_SEAL`, but omits `F_SEAL_WRITE`.
  Status records travel over pipe fd 5 (`status_fd`), not over the `memfd`.
  `inject` omits `F_SEAL_WRITE` only so `set_stage()` can write `stage = 1` at `CFG_STAGE_OFF` on fd 3 before re-exec.
  A process that already holds a writable descriptor to that `memfd` can modify configuration bytes after validation.
- The stub validates the shadow leaf (`psgen-stub`) through an opened descriptor and then executes the leaf by path.
  A caller who can modify files inside the `0700` staging directory between validation and `execve` has a time-of-check/time-of-use window.
  The `0700` directory mode limits access to the owning UID and root.
- `child_fds` cannot reference the stub's own configuration descriptor or fd 3, and child stubs must start at stage 0.
  This prevents recursion through one descriptor, but a crafted configuration with distinct sealed descriptors can fork more processes than the injector planned.
- A failed privilege drop logs a deviation and lets the stub continue under its current UID rather than aborting the run.
- `psgen` does not hide its staging directories and does not try to defeat monitors that compare `/proc` against trusted out-of-band records.
- Development cages lacked a live FUSE daemon, so tests exercise the FUSE checks through predicate unit tests, hardlinks, and symlinks.

## Reporting a Vulnerability

Open a private GitHub Security Advisory on the repository, or send email to Azathothas <AjamX101@gmail.com>.
Do not open a public GitHub issue for an exploitable security defect.

Include the following details in your report:

- The exact command line.
- The `psgen` version.
- The Linux kernel version.
- The output of `psgen doctor`.
