#!/bin/sh
# Run the measurement guest in a sandbox cage and check the result.
#
#   SANDNET=/path/to/sand-net sh bench/sand.sh container
#   SANDNET=/path/to/sand-net sh bench/sand.sh microvm
#
# The cage image is localhost/psgen-test:1 (tests/sand/Containerfile): the
# sand-net base plus htop, btop and tmux. The guest script is bench/guest.sh;
# the static musl binary and that script are copied into the cage, and the
# microVM also gets a 1 MiB pad.
#
# The full transcript is kept at bench/sand-<cage>.log. The checks below read
# that transcript, so a failure can be inspected after the fact.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CAGE=${1:-container}
N=${N:-40}
SANDNET=${SANDNET:?set SANDNET to the sand-net checkout}
BIN="$ROOT/dist/psgen-x86_64-unknown-linux-musl"
LOG="$ROOT/bench/sand-$CAGE.log"

[ -x "$BIN" ] || { echo "missing $BIN, run scripts/build-all.sh" >&2; exit 1; }
[ -x "$SANDNET/sand" ] || { echo "$SANDNET/sand is not executable" >&2; exit 1; }

case "$CAGE" in
container) RECIPE=docker-none; EXTRA="" ;;
microvm)   RECIPE=microvm-none; EXTRA="-s limits.memory=4096m" ;;
*) echo "usage: sand.sh container|microvm" >&2; exit 2 ;;
esac

PROJ=$(mktemp -d /tmp/psgen-sand-XXXXXX)
trap 'rm -rf "$PROJ"' EXIT
cp "$BIN" "$PROJ/psgen"
cp "$ROOT/bench/guest.sh" "$PROJ/guest.sh"
# qemu's microvm machine places the initrd just below the ACPI tables. With
# an initrd in a narrow size range the kernel hangs in ACPI setup before
# /init runs. A 1 MiB pad in the project shifts the initrd out of that range.
# It costs nothing in the guest and is not read by guest.sh.
if [ "$CAGE" = microvm ]; then
    dd if=/dev/zero of="$PROJ/pad" bs=1M count=1 status=none
fi

echo "== $CAGE: $RECIPE"
(
    cd "$SANDNET"
    # shellcheck disable=SC2086
    ./sand run "$RECIPE" -s fs.image=localhost/psgen-test:1 $EXTRA \
        --project "$PROJ" -- sh /workspace/guest.sh
) > "$LOG" 2>&1 || true

python3 - "$LOG" "$N" "$CAGE" <<'PY'
import re
import sys

log, want, cage = sys.argv[1], int(sys.argv[2]), sys.argv[3]
text = open(log, encoding="utf-8", errors="replace").read()


def fail(msg):
    print(f"FAIL ({cage}): {msg}", file=sys.stderr)
    sys.exit(1)


def section(name):
    m = re.search(rf"^=== {name}$(.*?)(?=^=== |\Z)", text, re.S | re.M)
    return m.group(1) if m else None


for name in ("ENV", "DOCTOR", "INJECT", "PS", "TOP", "COMM", "EXE",
             "HTOP", "BTOP", "STOP", "AFTER"):
    if section(name) is None:
        fail(f"missing section {name}")

if "summary" not in section("DOCTOR"):
    fail("doctor printed no summary")
if re.search(rf"spawned {want} processes", section("INJECT")) is None:
    fail(f"inject did not spawn {want}")

pids = [int(p) for p in section("PIDS").split()]
if len(pids) != want:
    fail(f"pidfile lists {len(pids)} pids, wanted {want}")

# ps aux: every injected pid must be there, with the planned command line.
ps_rows = {}
for line in section("PS").splitlines():
    parts = line.split(None, 10)
    if len(parts) == 11 and parts[1].isdigit():
        ps_rows[int(parts[1])] = parts
missing = [p for p in pids if p not in ps_rows]
if missing:
    fail(f"ps aux lacks {len(missing)} injected pids: {missing[:5]}")
names = {ps_rows[p][10].split()[0].rsplit("/", 1)[-1] for p in pids}
if names == {"psgen"}:
    fail("every ps row still shows psgen")

# top -b: the same pids, read from the PID column.
top = section("TOP")
top_pids = {int(m) for m in re.findall(r"^\s*(\d+)\s+\S+\s+\d+\s+\d+", top, re.M)}
if not top_pids:
    fail("top printed no process rows")
if len([p for p in pids if p in top_pids]) < want // 2:
    fail(f"top shows only {len([p for p in pids if p in top_pids])} of {want} pids")

# comm: the kernel's own view of each process name, set with prctl.
comm = {}
for line in section("COMM").splitlines():
    parts = line.split(None, 1)
    if len(parts) == 2 and parts[0].isdigit():
        comm[int(parts[0])] = parts[1].strip()
if len(comm) != want:
    fail(f"/proc/PID/comm readable for {len(comm)} of {want} pids")
if any(not c or c == "psgen" for c in comm.values()):
    fail("a comm value is empty or still psgen")

# htop and btop: both screens must show several injected command names. tmux
# capture-pane gives the text of the visible pane, so a name here is a rendered
# row, not a substring of a stray escape sequence.
def shown(names, body):
    return {n for n in names if len(n) >= 3 and n in body}

if "Error" in section("HTOP"):
    fail("htop printed an error instead of a screen")
least = 5
for tool in ("HTOP", "BTOP"):
    seen = shown(names, section(tool))
    if len(seen) < least:
        fail(f"{tool.lower()} showed {len(seen)} injected names, wanted at least {least}")

if re.search(rf"stopped {want} processes", section("STOP")) is None:
    fail("stop did not report the injected count")
if "alive" in section("AFTER"):
    fail("an injected process survived stop")
if "after-check-done" not in section("AFTER"):
    fail("the after-check did not run")

print(f"sand {cage}: ok ({want} processes, ps/top/comm/htop/btop checked)")
PY
