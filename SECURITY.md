# Security policy

`psgen` deliberately spoofs process state. That is the feature, and it is also
why a deployment decision matters more here than for an ordinary tool.

## What the threat model assumes

- The pidfile is trusted input. `/proc` makes the boot id, starttime and comm
  visible, so a forged pidfile can name a process the caller may signal
  anyway, and can point the `# temp` cleanup at a directory with the right
  name that the caller owns. Run `stop` only on a pidfile you wrote, or on one
  from someone you trust as much as yourself.
- The stub refuses to run from a setuid or setgid install, and only acts on a
  config descriptor that carries the per-run nonce in its environment and is a
  sealed memfd or an unlinked file. It only writes into, and only execs from, a
  staging directory that passes the ownership and name rule `stop` uses. A
  supervisor that can set the environment of a privileged `psgen` is outside
  that boundary.
- The nonce is not authentication. It stays in `/proc/PID/environ` for the
  process lifetime, so a process that can read our environment can replay it. The config memfd is size-sealed but writable by its owner while
  the injector maps it, and the staging leaf is checked through its descriptor
  and then executed by path. None of those is a boundary against the caller
  who started the run.
- `--elevate` runs `sudo -n` with the same argv as the unprivileged call. It is
  a convenience for a caller who already has passwordless `sudo` for `psgen`,
  not a way to obtain privileges.

## What counts as a vulnerability

- A way to make `psgen` signal a process the pidfile does not name, or to
  write outside a staging directory, or to execute a binary it was not told to
  execute.
- A crash or an abort that leaves live stubs with no record of how to stop
  them.
- A symlink, FIFO, socket or device being replaced by a pidfile.

## Reporting

Open a private security advisory on the repository, or mail the maintainer
address in `Cargo.toml`. Do not open a public issue for an exploitable report.
Please include the exact command line, the psgen version, the kernel and the
capabilities of the environment (`psgen doctor` is a good summary).
