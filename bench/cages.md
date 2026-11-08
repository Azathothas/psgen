# Cage checks

`bench/sand.sh` runs `bench/guest.sh` inside a sand-net cage, writes the whole
run to a transcript, and checks what the guest saw. The guest injects a fixed
number of processes and reads them back through `ps`, `top`,
`/proc/PID/comm`, `htop` and `btop`.

## Prerequisites

- podman with netavark, and a sand-net checkout. `SANDNET` points at the
  checkout that provides `./sand`.
- The cage image `localhost/psgen-test:1`, built from `tests/sand/Containerfile`
  on top of `localhost/sand-net/base:1`:

  ```sh
  podman build -t localhost/psgen-test:1 tests/sand
  ```

- qemu for the `microvm` recipe.
- `dist/psgen-x86_64-unknown-linux-musl`, the static musl build copied there
  before the run.

## Run

```sh
SANDNET=/path/to/sand-net sh bench/sand.sh container
SANDNET=/path/to/sand-net sh bench/sand.sh microvm
```

The `container` recipe is sand-net's `docker-none`; `microvm` is
`microvm-none` with 4 GiB. The microVM run adds a 1 MiB file to the project
directory to shift qemu's initrd out of the size range that hangs in ACPI
setup.

## What it checks

The guest injects 40 processes with seed 7, then the host-side checker reads
the transcript:

- `ps aux` lists every injected PID, and not every row is still named `psgen`.
- `top -b -n1 -w 200` lists at least half of the injected PIDs.
- `/proc/PID/comm` is readable for every PID, non-empty, and not `psgen`.
- `htop` and `btop` each render at least five distinct injected command names.
  Both are captured through tmux, so a name is a row on a real screen.
- `stop` reports the injected count, and no stub is alive one second later.

The checker also requires every transcript section (`ENV`, `DOCTOR`, `INJECT`,
`PIDS`, `PS`, `TOP`, `COMM`, `EXE`, `HTOP`, `BTOP`, `STOP`, `AFTER`), a doctor
summary, and a spawn count of 40.

## Transcript

The cage's stdout and stderr go to `bench/sand-<cage>.log`. The checker reads
that file, so a failed run can be inspected after the fact. A passing run
prints `sand <cage>: ok (<count> processes, ps/top/comm/htop/btop checked)`.
