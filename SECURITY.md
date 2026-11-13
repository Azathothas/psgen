# Security policy

`psgen` deliberately spoofs process state. That is the feature, and it is also
why a deployment decision matters more here than for an ordinary tool.

## Requirements

- Never install `psgen` setuid or setgid. The stub refuses to run in that case:
  `maybe_run()` compares the effective uid and gid with the real ones and exits
  2 when they differ, before it reads any configuration.
- Do not let a supervisor, wrapper or `sudoers` rule hand an arbitrary
  descriptor 3 to a privileged `psgen`. The descriptor is the trust boundary;
  see below for what the stub checks and what it cannot know.
- Run `stop` only on a pidfile you wrote, or on one from a caller you trust as
  much as yourself.

## What the threat model assumes

- The pidfile is trusted input. `/proc` makes the boot id, starttime and comm
  visible, so a forged pidfile can name a process the caller may signal
  anyway, and can point the `# temp` cleanup at a directory with the right
  name that the caller owns. `stop` refuses a file with no psgen header at all
  and refuses a header whose boot id is empty or from another boot, but a
  header with today's boot id and a real process's fields is accepted.

- The fd-3 gate checks the descriptor and the environment, and trusts neither
  to prove who created the descriptor. The stub acts on a config only when all
  of these hold:

  1. the process is not setuid or setgid;
  2. the descriptor's filesystem is not FUSE or overlayfs, where ownership and
     link counts can be forged;
  3. `fstat` says the descriptor is owned by the uid the stub runs as;
  4. the descriptor is a regular file with no links left, and either a memfd
     carrying `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL` or an unlinked
     temporary file;
  5. the config's nonce equals `PSGEN_NONCE` in the process environment.

  Conditions 3 and 4 ask about the inode, not about the process that opened it.
  Under `sudo` the uid is 0, so any root-owned inode the caller can open and
  then unlink satisfies them, including one root wrote into a directory the
  caller owns. A memfd is told from an unlinked file by its mode: `0777` is the
  mode `memfd_create` gives, anything else is treated as the unlinked case and
  skips the seal check, so `fchmod(0600)` on a memfd created without
  `MFD_ALLOW_SEALING` also satisfies them. What the gate does enforce is that a
  *named* descriptor is refused, that a memfd left at `0777` must carry the
  seals, that ownership must match the uid the stub runs as, and that a FUSE or
  overlayfs path is refused. It does not prove who created the descriptor.

- The nonce is a run tag, not authentication. It is written into the stub's
  environment, which is the same trust plane as the descriptor, so a caller
  who controls fd 3 can also set `PSGEN_NONCE` and match it. What the nonce
  does is reject a stray descriptor from an unrelated run of the same user, and
  refuse a supervisor that inherits fd 3 without choosing the environment. It
  is 8 random bytes from `getrandom`, or a pid/clock mix when `getrandom`
  fails, printed as hex. It must stay in the environment for the process
  lifetime so every re-exec can read it, so it is visible in
  `/proc/PID/environ` and to `ps e` for whoever may read that process. Do not
  treat it as a secret. It is not a password, not a MAC, and not evidence that
  a config came from psgen.

- The stub only writes into, and only executes from, a staging directory that
  passes the ownership and name rule `stop` uses to decide whether it may
  remove one: absolute, a real directory, owned by the uid the stub runs as,
  not group- or world-writable, basename matching
  `.psgen-<digits>-<digits>-<digits>`. The rule describes the directory, not
  which run created it, so two runs of the same uid share one namespace of
  acceptable directories.

- The staging leaf it executes is identified by the *opened descriptor*: a
  regular file, one link, owned by the caller, and for a root run not on FUSE
  or overlayfs. A hardlink or a FUSE type spoof is refused.

- `--elevate` runs `sudo -n` with the same argv as the unprivileged call, minus
  `--elevate` itself. A preview never elevates: `--plan` and `--dry-run`
  describe what the caller's own privileges reach. `--elevate` is a
  convenience for a caller who already has passwordless `sudo` for `psgen`,
  not a way to obtain privileges.

### What an attacker who controls fd 3 and the environment can still do

The gate decides on the inode's metadata and on the environment, and both are
under the caller's control. Three shapes pass that should not:

- **A root-owned unlinked file opened by an unprivileged caller.** `fstat` says
  `uid 0`, so under `sudo` the ownership condition holds, and `nlink 0` selects
  the unlinked case, which needs no seals. Ownership of an inode says nothing
  about who opened it: root writing any file into a directory the caller owns
  is enough. Measured on this tree: a root-owned `0644` file, opened and then
  unlinked by uid 1000, with a matching `PSGEN_NONCE`, was acted on by a root
  stub, which took the config's `comm` and kept running.
- **A memfd reclassified by `fchmod`.** `memfd_create(name, 0)` cannot be
  sealed, but `fchmod(0600)` moves it out of the `0777` memfd arm and into the
  unlinked arm, which skips the seal check. Measured: accepted, and a `pwrite`
  after acceptance still succeeded, so the config can change after it was
  validated.
- **A root-owned staging directory of another run.** `safe_temp_dir` checks the
  directory's own metadata, so a root run accepts any root-owned
  `.psgen-<d>-<d>-<d>` that is not group- or world-writable. With `--disk` in
  the config, the stub truncated an 8 KiB root-owned `data.bin` inside another
  root run's `0700` staging directory and rewrote it as 512 KiB.

With those shapes the attacker chooses the stub's `comm`, flags (threads, tty,
busy CPU), duration, children and disk size, and gets a process that keeps
running as the uid the target `psgen` runs as. What was **not** demonstrated:
execution of the config's `exe` or `cmd` — the bind source is always
`/proc/self/exe`, and a proc-self stub never rewrites its argv — and any write
to a path that is not a staging directory passing the ownership and name rule.

What the gate does refuse, measured on the same tree: a named regular file, a
hardlinked file, a symlink to one, a memfd left at `0777` without the seals, a
memfd sealed with `SEAL` only, a descriptor owned by another uid, a descriptor
on FUSE or overlayfs, a mismatched nonce, and a missing nonce. A FIFO, socket or
device is not acted on either, because `read_config` reads with `pread` and
fails on a non-seekable object, so the process falls through to the normal
command line. The setuid and setgid refusal also holds: a root-owned `4755`
install on a filesystem without `nosuid` exits 2 before reading any config.

The conditions above are what the tree implements today. The branch that owns
the fd-3 rules is re-checking them; when its gate lands, re-measure this
section against the new conditions.

## What counts as a vulnerability

- A way to make `psgen` signal a process the pidfile does not name, or to
  execute a binary it was not told to execute.
- A way to make the stub act on a config descriptor it did not create, without
  already controlling the uid the stub runs as.
- A write outside a staging directory that passes the ownership and name rule,
  or through a path whose metadata does not describe what is under it, such as
  a bind mount over a staging name.
- A crash or an abort that leaves live stubs with no record of how to stop
  them.
- A symlink, FIFO, socket or device being replaced by a pidfile.

## Residual limits

These are known and accepted, not unreported defects.

- The nonce is visible in `/proc/PID/environ` for the process lifetime, so a
  process that can read that file can replay it. It binds a descriptor to the
  environment the injector set; it is not a secret.
- The config memfd carries the size seals but not `F_SEAL_WRITE`, because the
  stub writes its status record through the same mapping. A descriptor holder
  that can write the mapping can change the config after it was validated.
- The staging leaf is validated through its opened descriptor and then executed
  by path, so a caller who can replace that leaf between the two steps has a
  time-of-check/time-of-use window. The injector keeps the directory mode at
  `0700`, which bounds who can do that.
- `safe_temp_dir` validates the path with `symlink_metadata`, so a symlink is
  refused, but a bind mount over a `.psgen-<d>-<d>-<d>` name reports the
  *mounted* filesystem's root as its metadata and passes every arm when that
  root has the caller's uid, mode `0700` and the right basename. `stop` then
  calls `remove_dir_all`, which recurses through the mount and deletes what is
  under it. See the paragraph above.
- `child_fds` may not name the stub's own config descriptor or fd 3, and a
  child stub must be at stage 0, so a self-referential config cannot recurse
  through the same descriptor. A config that names other descriptors can still
  fork more processes than the injector planned.
- A failed privilege drop is reported as a deviation, and the stub continues
  under the uid it already has rather than aborting the run.
- `psgen` is designed to be spoofed. It does not try to defeat a monitor that
  compares `/proc` with a source it trusts, and it does not hide its own
  staging directories.
- A real FUSE mount was not available in the development environment, so the
  FUSE branch is exercised through its predicates and through the hardlink and
  symlink cases rather than a mounted daemon.

## Reporting

Open a private security advisory on the repository, or mail the maintainer
address in `Cargo.toml`. Do not open a public issue for an exploitable report.
Please include the exact command line, the psgen version, the kernel, and the
capabilities of the environment (`psgen doctor` is a good summary).
