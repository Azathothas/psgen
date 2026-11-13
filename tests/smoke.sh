#!/bin/sh
# The one entry point: every gate CI runs, in one command.
#
# CI's `lint` job and `test` job both bottom out here (see
# .github/workflows/ci.yml), so a defect that only a CI runner would catch has
# to be catchable here too. `tests/helpers/check_workflows.py` holds the gate
# that each of these steps is present, so this file cannot quietly lose one.
#
# Every check that needs a host capability goes through `skip`
# (tests/helpers/gate.sh, the one place the rule lives), and with
# PSGEN_REQUIRE_ALL=1 (which CI sets) an absent capability is a failure that
# names it instead of a silent pass. The `require-all behaviour` gate below
# proves both branches, because a skip that CI cannot see is a check that never
# runs.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/tests/helpers/gate.sh"
BIN=$ROOT/target/release/psgen
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
[ -n "$VERSION" ] || { echo "smoke: no version in Cargo.toml" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fatal() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "== require-all behaviour"
# A skip must print SKIP and exit 0 without PSGEN_REQUIRE_ALL, and must FAIL
# naming the reason with it. The helper drives `skip` from gate.sh, so this
# holds the real rule to its contract rather than a copy of it.
sh "$ROOT/tests/helpers/require_all_check.sh" "$ROOT/tests/helpers/gate.sh" ||
    fatal "the PSGEN_REQUIRE_ALL rule is broken"

echo "== version"
[ -x "$BIN" ] || fatal "$BIN is missing; run cargo build --release"
"$BIN" --version | grep -q "^psgen $VERSION$"

echo "== help"
"$BIN" --help | grep -q 'psgen inject'

echo "== corpus denylist and expanded output"
"$BIN" check >/dev/null

echo "== corpus dump"
n=$("$BIN" corpus | wc -l)
[ "$n" -ge 180 ] || fatal "corpus has only $n templates"

echo "== list"
n=$("$BIN" list -n 0 -s 1 | wc -l)
[ "$n" -ge 180 ] || fatal "list has only $n lines"

echo "== deterministic seed"
# The second run is a second later on purpose: a modulus that grows with uptime
# made the same seed produce a different table, and only a gap catches that.
# START and TIME follow the wall clock by design, so the comparison drops them.
mask() {
    "$BIN" table -n 12 -s 42 | awk 'NR>1 {printf "%s %s %s %s %s %s\n", $1,$2,$3,$4,$5,$6}'
}
a=$(mask)
sleep 1.2
b=$(mask)
[ "$a" = "$b" ] || fatal "seed is not deterministic"

echo "== toolchain"
# One probe for "cargo can run here", reused by the five cargo gates. A finite
# RLIMIT_FSIZE kills the compiler with SIGXFSZ, which is the limit's doing and
# not a test failure, so the reason names the limit.
tool_state=ok
tool_reason=""
limit=$(ulimit -f)
if ! command -v cargo >/dev/null 2>&1 || [ ! -f "$ROOT/Cargo.toml" ]; then
    tool_state=missing
    tool_reason="cargo is not installed"
elif [ "$limit" != "unlimited" ] && [ "$limit" -lt 16384 ]; then
    # `ulimit -f` is in 512-byte blocks on some shells and kiB on others;
    # anything under 8 MiB is too small for a compiler's object files.
    tool_state=small
    tool_reason="cargo needs more than RLIMIT_FSIZE ($limit blocks)"
fi

# `gate <label> <dir> <command...>`: run one cargo gate, or skip it with the
# same reason the probe found.
gate() {
    label=$1
    dir=$2
    shift 2
    if [ "$tool_state" != ok ]; then
        skip "$tool_reason"
        return 0
    fi
    if ! (cd "$dir" && "$@") >"$TMP/$label.out" 2>&1; then
        cat "$TMP/$label.out" >&2
        fatal "$label is not clean"
    fi
}

echo "== fmt"
gate fmt "$ROOT" cargo fmt --all -- --check

echo "== clippy"
gate clippy "$ROOT" cargo clippy --locked --all-targets -- -D warnings

echo "== unit tests"
gate unit-tests "$ROOT" cargo test --quiet --locked --release

echo "== package"
# `cargo package` is the gate that a published crate is complete: a file the
# workflows read but the package omits fails here, before a tag exists.
gate package "$ROOT" cargo package --locked --no-verify

echo "== unit file"
# The same assertions CI's unit step makes, so `sh tests/smoke.sh` is the whole
# gate and not a subset of it. systemd-analyze is advisory when it is missing
# (a runner's systemd is not the unit's target systemd) and fatal when it
# rejects the unit; the greps below are the assertions in every case.
"$BIN" unit > "$TMP/psgen.service"
if command -v systemd-analyze >/dev/null 2>&1; then
    if ! systemd-analyze verify "$TMP/psgen.service" >"$TMP/analyze.out" 2>&1; then
        cat "$TMP/analyze.out" >&2
        fatal "systemd-analyze rejected the printed unit"
    fi
else
    skip "systemd-analyze is not installed, so the unit cannot be verified"
fi
# Each assertion is written as a test that fails on the defect, so `set -e`
# cannot turn a missing line into a passing one.
if grep -q 'proc-fs-nets.target' "$TMP/psgen.service"; then
    fatal "the unit names proc-fs-nets.target, which systemd does not ship"
fi
grep -q '^RuntimeDirectory=psgen$' "$TMP/psgen.service" ||
    fatal "the unit has no RuntimeDirectory=psgen"
# `grep -q '^ExecStop=-'` is satisfied by the `/bin/rm` cleanup line whatever the
# psgen stop looks like, so the assertion names the psgen stop directive: it
# must be present, and every `ExecStop=` line that runs it must carry a guard —
# the `-` prefix, or the `/bin/sh -c` test for the pidfile that the shipped unit
# uses because `-` cannot tell an absent pidfile from a foreign boot id. An
# unguarded stop reports every such failure as a failed service stop.
grep -q '^ExecStop=.* stop --pidfile' "$TMP/psgen.service" ||
    fatal "the unit has no psgen stop --pidfile ExecStop line"
if grep '^ExecStop=.* stop --pidfile' "$TMP/psgen.service" |
        grep -v -E '^ExecStop=(-|/bin/sh -c )' | grep -q .; then
    fatal "the unit's psgen stop is unguarded, so an absent pidfile fails the stop"
fi
grep -q '^ConditionPathExists=/proc/1/stat$' "$TMP/psgen.service" ||
    fatal "the unit's ConditionPathExists does not name /proc/1/stat"

echo "== workflow shell"
sh "$ROOT/tests/workflow.sh"

echo "== invariants and injection"
python3 "$ROOT/tests/invariants.py"

# The per-issue proof harness. Its cases are written against systemd, ps, the
# kernel and the filesystem rather than against psgen's own formula, so they
# belong in the same gate: a fix that regresses one of these issues has to fail
# here. The harness exits non-zero on any FAIL and turns a SKIP into a failure
# under PSGEN_REQUIRE_ALL=1, which this suite already runs with in CI.
echo "== per-issue proof"
sh "$ROOT/tests/proof_cases/report.sh" "$BIN"
sh "$ROOT/tests/proof_cases/pidfile.sh" "$BIN"
sh "$ROOT/tests/proof_cases/generator.sh" "$BIN"
sh "$ROOT/tests/proof_cases/table.sh" "$BIN"
sh "$ROOT/tests/proof_cases/stop.sh" "$BIN"
sh "$ROOT/tests/proof_cases/inject.sh" "$BIN"
sh "$ROOT/tests/proof_cases/surface.sh" "$BIN"

echo "== size"
if command -v size >/dev/null 2>&1; then
    size "$BIN"
fi
bytes=$(stat -c %s "$BIN")
[ "$bytes" -lt 1048576 ] || fatal "binary is $bytes bytes, over 1 MiB"

echo "smoke: ok"
