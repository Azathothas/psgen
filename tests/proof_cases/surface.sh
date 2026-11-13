#!/bin/sh
# Per-issue proof harness: the option surface, the suite on a constrained host,
# and the release gates.
#
#   sh tests/proof_cases/surface.sh <binary> [issue ...]
#
# Covers issues #6, #9 and #11. Each case prints one line — `PASS <n> <what>`,
# `FAIL <n> <what>: <why>` or `SKIP <n> <what>: <why>` — and the script exits
# non-zero when any case failed.
#
# #6 and #11 are about the harness that ships with the binary, not about a
# subcommand, so those cases read `$SRC`, the tree the binary was built from:
# `tests/invariants.py`, `tests/smoke.sh`, `scripts/release-notes.sh` and
# `.github/workflows/`. The path is inferred from the binary's own location
# (`<tree>/target/<profile>/psgen`), so running this file against a pre-fix
# binary checks the pre-fix harness too. That is the only way a case about CI
# configuration can fail on the commit that lacked the configuration.
#
# The rule the suite already enforces (DESIGN.md §4) applies here: a check that
# cannot fail is worse than no check. Every case is written against a reference
# the tool does not own — the kernel's RLIMIT_FSIZE, a pty allocation, the state
# `/proc` reports for a child nobody reaped, the real process table, rustfmt,
# clippy, cargo, real `systemd-analyze`, and the text of the unit the tool
# prints. Each one fails on `bf80156`, the commit the fixes branch from.
#
# A case that needs a host capability this machine lacks prints SKIP with the
# reason; with PSGEN_REQUIRE_ALL=1 that same absence is a failure, so a release
# gate cannot pass on a host where the case never ran.
set -u

LC_ALL=C
export LC_ALL

if [ $# -lt 1 ]; then
	echo "usage: sh tests/proof_cases/surface.sh <binary> [issue ...]" >&2
	exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BIN_ARG=$1
shift
SELECTED=$*

[ -x "$BIN_ARG" ] || {
	echo "surface.sh: $BIN_ARG is not an executable" >&2
	exit 2
}
case $BIN_ARG in
	/*) BIN=$BIN_ARG ;;
	*) BIN=$(CDPATH= cd -- "$(dirname -- "$BIN_ARG")" && pwd)/$(basename -- "$BIN_ARG") ;;
esac

TMP=$(mktemp -d) || {
	echo "surface.sh: cannot create a temp directory" >&2
	exit 2
}

# The tree the binary came from. `$ROOT` is where the harness runs, which is a
# different checkout when the proof is run against the pre-fix binary.
SRC=${PSGEN_SRC:-}
if [ -z "$SRC" ]; then
	_bin_dir=$(dirname -- "$BIN")
	case $_bin_dir in
		*/target/*) SRC=$(CDPATH= cd -- "$_bin_dir/../.." && pwd) ;;
		*) SRC=$ROOT ;;
	esac
fi
[ -d "$SRC" ] || {
	echo "surface.sh: $SRC (the tree the binary came from) is not a directory" >&2
	exit 2
}

SUITE=$SRC/tests/invariants.py
SMOKE=$SRC/tests/smoke.sh
CI=$SRC/.github/workflows/ci.yml
REL=$SRC/.github/workflows/release.yml

FAILS=0
RAN=0
CUR_ID=
CUR_WHAT=

mkdir -p "$TMP/suite" || exit 2

# The two drivers the #6 cases run inside the constrained host. `one.py` calls
# one check from the tree's own suite, exactly as `main()` would, so the case is
# about the suite's code and not about a re-implementation of it. `noreap.py`
# is a PID 1 that never calls `wait()` on an orphan: the kernel reparents
# everything whose parent died to it, and it stays visible in `/proc` as a
# zombie. It first proves that property with a real child, so a host where the
# namespace reaps reports itself instead of passing the case for the wrong
# reason.
cat >"$TMP/one.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
getattr(m, sys.argv[2])()
PY
cat >"$TMP/noreap.py" <<'PY'
import os, subprocess, sys, time
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    g = os.fork()
    if g == 0:
        os._exit(0)
    os.write(w, str(g).encode())
    os._exit(0)
os.close(w)
raw = os.read(r, 32).decode().strip()
os.close(r)
time.sleep(0.5)
state = None
try:
    with open("/proc/%s/stat" % raw) as f:
        line = f.read()
    state = line[line.rindex(")") + 2]
except OSError:
    pass
if state != "Z":
    print("NOT-NONREAPING %r" % (state,), file=sys.stderr)
    sys.exit(3)
sys.exit(subprocess.run(sys.argv[1:]).returncode)
PY

# ---------------------------------------------------------------- plumbing

require_all() {
	case ${PSGEN_REQUIRE_ALL:-} in
		"" | 0) return 1 ;;
		*) return 0 ;;
	esac
}

asroot() {
	if [ "$(id -u)" = 0 ]; then
		"$@"
	else
		sudo -n "$@"
	fi
}

# Whether this caller can elevate without a password. The answer does not
# change during a run, so it is computed once.
ELEVATE=
can_elevate() {
	if [ -z "$ELEVATE" ]; then
		if [ "$(id -u)" = 0 ]; then
			ELEVATE=yes
		elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
			ELEVATE=yes
		else
			ELEVATE=no
		fi
	fi
	[ "$ELEVATE" = yes ]
}

have() { command -v "$1" >/dev/null 2>&1; }

have_sudo() { can_elevate; }

say() { printf '%s\n' "$*" >&2; }

pass_c() {
	printf 'PASS %s %s\n' "$CUR_ID" "$CUR_WHAT"
}

fail_c() {
	printf 'FAIL %s %s: %s\n' "$CUR_ID" "$CUR_WHAT" "$1"
	FAILS=$((FAILS + 1))
}

skip_c() {
	if require_all; then
		printf 'FAIL %s %s: required capability missing: %s\n' \
			"$CUR_ID" "$CUR_WHAT" "$1"
		FAILS=$((FAILS + 1))
	else
		printf 'SKIP %s %s: %s\n' "$CUR_ID" "$CUR_WHAT" "$1"
	fi
}

# tmo <seconds> <command...> — timeout(1) when the host has it.
tmo() {
	_t=$1
	shift
	timeout "$_t" "$@"
}

# stop_pidfile <path> — stop a run without masking its exit status.
stop_pidfile() {
	[ -f "$1" ] || return 0
	"$BIN" stop --pidfile "$1" >/dev/null 2>&1
}

# alive_pid <pid> — the kernel's answer, not the tool's: a zombie is dead.
alive_pid() {
	[ -r "/proc/$1/stat" ] || return 1
	_state=$(sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -c1)
	[ -n "$_state" ] && [ "$_state" != Z ]
}

# record_pids <pidfile> — bank every stub a case spawns, so the exit trap can
# kill it even when the case fails before its own stop.
record_pids() {
	[ -f "$1" ] || return 0
	grep -v '^#' "$1" 2>/dev/null | awk 'NF >= 1 { print $1 }' >>"$TMP/stub-pids"
}

cleanup() {
	trap - EXIT INT TERM HUP
	# `check_load` mounts a tmpfs under the TMPDIR it is given, which is ours;
	# an interrupted run can leave the mount behind and then the removal below
	# would fail.
	for _m in "$TMP"/suite/psgen-loadfs-*; do
		[ -d "$_m" ] || continue
		if can_elevate; then
			asroot umount "$_m" 2>/dev/null
		fi
	done
	if [ -f "$TMP/stub-pids" ]; then
		while read -r p; do
			[ -n "$p" ] && kill "$p" 2>/dev/null
		done <"$TMP/stub-pids"
	fi
	rm -rf "$TMP" 2>/dev/null || {
		if can_elevate; then asroot rm -rf "$TMP"; fi
	}
}
trap cleanup EXIT INT TERM HUP

run_case() {
	_id=$1
	_issue=$2
	_what=$3
	_fn=$4
	if [ -n "$SELECTED" ]; then
		_want=0
		for _s in $SELECTED; do
			[ "$_s" = "$_issue" ] && _want=1
		done
		[ "$_want" = 1 ] || return 0
	fi
	CUR_ID=$_id
	CUR_WHAT=$_what
	RAN=$((RAN + 1))
	"$_fn"
}

# ---------------------------------------------------------------- issue #6
# The suite must skip what this host cannot do and keep running. The three host
# properties are the ones the issue reported: a finite RLIMIT_FSIZE, no pty
# master, and a PID 1 that never reaps. Each is built for real — the kernel
# enforces the limit, the kernel refuses the pty, and `/proc` shows the zombie —
# so the case cannot pass by asking the tool what it thinks about itself.

# The suite's own `skip()` reads PSGEN_REQUIRE_ALL. This harness is testing the
# skip path itself, so the child always sees 0; `check_skip_needs` in the suite
# is the check that the same absence fails under the requirement.
run_suite() {
	PSGEN_BIN="$BIN" PSGEN_REQUIRE_ALL=0 TMPDIR="$TMP/suite" \
		python3 "$TMP/one.py" "$SUITE" "$1"
}

need_suite() {
	have python3 || {
		skip_c "no python3 to run the suite"
		return 1
	}
	have timeout || {
		skip_c "no timeout(1) to bound the suite"
		return 1
	}
	[ -f "$SUITE" ] || {
		fail_c "no tests/invariants.py under $SRC"
		return 1
	}
	return 0
}

# 6.1 — a soft limit far below one copy of the binary. `check_unit` stages a
# copy under a path that contains a space; the write hits the kernel's EFBIG
# and the suite must skip that one assertion, not die with a traceback.
case_6_1() {
	need_suite || return
	_err=$( (ulimit -Sf 100 && run_suite check_unit) 2>&1 >/dev/null )
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "the suite exited $_rc under a 100 KiB RLIMIT_FSIZE: $(printf '%s' "$_err" | tail -1)"
		return
	fi
	case $_err in
		*"SKIP: "*RLIMIT_FSIZE*) ;;
		*)
			fail_c "the suite did not print a skip reason naming RLIMIT_FSIZE: $(printf '%s' "$_err" | tail -1)"
			return
			;;
	esac
	pass_c
}

# 6.2 — the issue's own case: a hard RLIMIT_FSIZE of 953 MiB while the guard
# asks for a 1 GiB soft limit. `setrlimit` cannot raise the soft limit above the
# hard one, so the suite must clamp instead of raising in `preexec_fn`.
case_6_2() {
	need_suite || return
	_hard=$(ulimit -Hf)
	case $_hard in
		unlimited) ;;
		*)
			case $_hard in
				"" | *[!0-9]*)
					skip_c "cannot read the hard RLIMIT_FSIZE ('$_hard')"
					return
					;;
			esac
			if [ "$_hard" -lt 976562 ]; then
				skip_c "the hard RLIMIT_FSIZE is already $_hard KiB, below the issue's 953 MiB"
				return
			fi
			;;
	esac
	_err=$( (ulimit -Sf 976562 && ulimit -Hf 976562 && run_suite check_load) 2>&1 >/dev/null )
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "the suite exited $_rc with a 953 MiB hard RLIMIT_FSIZE: $(printf '%s' "$_err" | tail -1)"
		return
	fi
	case $_err in
		*preexec* | *SubprocessError*)
			fail_c "a limit it could not install surfaced as an exception: $(printf '%s' "$_err" | tail -1)"
			return
			;;
	esac
	pass_c
}

# 6.3 — a /dev with no pty master. The pty assertion must skip and name the
# capability; asserting it fails on every hardened container. A PID namespace
# is used as well so a failed case cannot leave stubs behind: they die with the
# namespace's PID 1.
case_6_3() {
	need_suite || return
	[ "$(id -u)" = 0 ] && {
		skip_c "needs an unprivileged caller, so the suite's root branch does not mask the result"
		return
	}
	have_sudo || {
		skip_c "needs passwordless sudo to build a /dev without a pty"
		return
	}
	have setpriv || {
		skip_c "no setpriv to drop back to the caller's uid"
		return
	}
	asroot unshare --pid --fork --mount-proc --mount true >/dev/null 2>&1 || {
		skip_c "this host cannot create a PID and mount namespace"
		return
	}
	_uid=$(id -u)
	_gid=$(id -g)
	_ns="mount -t tmpfs tmpfs /dev || exit 111
mknod /dev/null c 1 3 && chmod 666 /dev/null || exit 111
mknod /dev/zero c 1 5 && chmod 666 /dev/zero || exit 111
mknod /dev/urandom c 1 9 && chmod 666 /dev/urandom || exit 111
exec setpriv --reuid=$_uid --regid=$_gid --clear-groups env PSGEN_BIN='$BIN' PSGEN_REQUIRE_ALL=0 TMPDIR='$TMP/suite' python3 '$TMP/one.py' '$SUITE' check_injection"
	_err=$(asroot timeout 600 unshare --pid --fork --mount-proc --mount sh -c "$_ns" 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" = 111 ]; then
		skip_c "cannot build a /dev without a pty here"
		return
	fi
	if [ "$_rc" -ne 0 ]; then
		fail_c "the suite exited $_rc without a pty master: $(printf '%s' "$_err" | tail -1)"
		return
	fi
	case $_err in
		*"SKIP: "*pty*) ;;
		*)
			fail_c "the suite did not print a pty skip reason: $(printf '%s' "$_err" | tail -1)"
			return
			;;
	esac
	pass_c
}

# 6.4 — a PID 1 that never reaps. Every stub that dies on its `--duration`
# alarm is a zombie there; `kill(pid, 0)` succeeds on a zombie, so the old
# liveness test always said "survived". The probe inside the namespace proves
# the host really leaves the child unreaped before the suite is trusted.
case_6_4() {
	need_suite || return
	[ "$(id -u)" = 0 ] && {
		skip_c "needs an unprivileged caller, so the suite's root branch does not mask the result"
		return
	}
	have_sudo || {
		skip_c "needs passwordless sudo to create a PID namespace"
		return
	}
	have setpriv || {
		skip_c "no setpriv to drop back to the caller's uid"
		return
	}
	asroot unshare --pid --fork --mount-proc true >/dev/null 2>&1 || {
		skip_c "this host cannot create a PID namespace"
		return
	}
	_uid=$(id -u)
	_gid=$(id -g)
	_err=$(asroot timeout 600 unshare --pid --fork --mount-proc python3 "$TMP/noreap.py" \
		setpriv --reuid="$_uid" --regid="$_gid" --clear-groups \
		env PSGEN_BIN="$BIN" PSGEN_REQUIRE_ALL=0 TMPDIR="$TMP/suite" \
		python3 "$TMP/one.py" "$SUITE" check_injection 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" = 3 ]; then
		skip_c "this host reaps an orphaned child, so no zombie can be produced ($(printf '%s' "$_err" | tail -1))"
		return
	fi
	if [ "$_rc" -ne 0 ]; then
		fail_c "the suite exited $_rc with a non-reaping PID 1: $(printf '%s' "$_err" | tail -1)"
		return
	fi
	pass_c
}

# ---------------------------------------------------------------- issue #9
# Every option is either consumed by the subcommand it was given to, or refused
# with its own name. "Consumed" is decided by two runs with different values of
# the knob; "refused" is exit 2 (the status `--force` already uses) with the
# long spelling of the flag on stderr.

# refused <long-option> <rc> <errfile> — a usage error that names the flag.
refused() {
	[ "$2" = 2 ] && grep -q -- "$1" "$3"
}

case_9_1() {
	"$BIN" corpus >"$TMP/9_1.base" 2>/dev/null
	"$BIN" corpus -n 5 >"$TMP/9_1.out" 2>"$TMP/9_1.err"
	_rc=$?
	if refused --count "$_rc" "$TMP/9_1.err"; then
		pass_c
		return
	fi
	if [ "$_rc" = 0 ] && ! cmp -s "$TMP/9_1.base" "$TMP/9_1.out"; then
		pass_c
		return
	fi
	fail_c "corpus -n 5 exited $_rc and printed the same $(wc -l <"$TMP/9_1.base" | tr -d ' ') lines as corpus"
}

case_9_2() {
	"$BIN" list -s 1 -n 1 >"$TMP/9_2.base" 2>/dev/null
	"$BIN" list --json -n 1 >"$TMP/9_2.out" 2>"$TMP/9_2.err"
	_rc=$?
	if refused --json "$_rc" "$TMP/9_2.err"; then
		pass_c
		return
	fi
	if [ "$_rc" = 0 ] && ! cmp -s "$TMP/9_2.base" "$TMP/9_2.out"; then
		pass_c
		return
	fi
	fail_c "list --json -n 1 exited $_rc and printed a command line: $(head -1 "$TMP/9_2.out")"
}

# `-n` on stop has no meaning a caller could rely on, so the only correct
# outcome is the refusal. The stubs are real, and `/proc` says whether the
# accepted-but-ignored run signalled them.
case_9_3() {
	_pf=$TMP/9_3.pid
	"$BIN" inject -n 2 -s 7 --no-user --no-mem --no-tty --no-threads \
		--duration 300 --pidfile "$_pf" -q >/dev/null 2>&1 || {
		fail_c "could not stage an inject run"
		return
	}
	record_pids "$_pf"
	_dead=
	for _p in $(grep -v '^#' "$_pf" 2>/dev/null | awk 'NF >= 1 { print $1 }'); do
		alive_pid "$_p" || _dead="$_dead $_p"
	done
	[ -z "$_dead" ] || {
		fail_c "the staged stubs$_dead were already gone before stop"
		stop_pidfile "$_pf"
		return
	}
	"$BIN" stop -n 40 --pidfile "$_pf" >"$TMP/9_3.out" 2>"$TMP/9_3.err"
	_rc=$?
	if ! refused --count "$_rc" "$TMP/9_3.err"; then
		fail_c "stop -n 40 exited $_rc without naming --count: $(head -1 "$TMP/9_3.out")$(head -1 "$TMP/9_3.err")"
		stop_pidfile "$_pf"
		return
	fi
	_dead=
	for _p in $(grep -v '^#' "$_pf" 2>/dev/null | awk 'NF >= 1 { print $1 }'); do
		alive_pid "$_p" || _dead="$_dead $_p"
	done
	if [ -n "$_dead" ]; then
		fail_c "the refused stop still signalled$_dead"
		stop_pidfile "$_pf"
		return
	fi
	stop_pidfile "$_pf"
	pass_c
}

# The live table is this host's own, so a family filter cannot be consumed —
# refusing it is the only honest answer. Pre-fix it was accepted and ignored.
case_9_4() {
	"$BIN" table --live -f web >"$TMP/9_4.out" 2>"$TMP/9_4.err"
	_rc=$?
	if ! refused --family "$_rc" "$TMP/9_4.err"; then
		fail_c "table --live -f web exited $_rc and printed $(wc -l <"$TMP/9_4.out" | tr -d ' ') live rows"
		return
	fi
	pass_c
}

case_9_5() {
	"$BIN" doctor --json >"$TMP/9_5.base" 2>/dev/null
	"$BIN" doctor --json --lines 5 >"$TMP/9_5.out" 2>"$TMP/9_5.err"
	_rc=$?
	if refused --lines "$_rc" "$TMP/9_5.err"; then
		pass_c
		return
	fi
	if [ "$_rc" = 0 ] && ! cmp -s "$TMP/9_5.base" "$TMP/9_5.out"; then
		pass_c
		return
	fi
	fail_c "doctor --json --lines 5 exited $_rc and printed the same document"
}

case_9_6() {
	"$BIN" check >"$TMP/9_6.base" 2>/dev/null
	"$BIN" check --utc-offset 300 >"$TMP/9_6.out" 2>"$TMP/9_6.err"
	_rc=$?
	if refused --utc-offset "$_rc" "$TMP/9_6.err"; then
		pass_c
		return
	fi
	if [ "$_rc" = 0 ] && ! cmp -s "$TMP/9_6.base" "$TMP/9_6.out"; then
		pass_c
		return
	fi
	fail_c "check --utc-offset 300 exited $_rc and printed the same report"
}

case_9_7() {
	"$BIN" list -s 1 -n 1 >"$TMP/9_7.base" 2>/dev/null
	"$BIN" list -d 5 -n 1 >"$TMP/9_7.out" 2>"$TMP/9_7.err"
	_rc=$?
	if refused --duration "$_rc" "$TMP/9_7.err"; then
		pass_c
		return
	fi
	if [ "$_rc" = 0 ] && ! cmp -s "$TMP/9_7.base" "$TMP/9_7.out"; then
		pass_c
		return
	fi
	fail_c "list -d 5 exited $_rc and printed the same line as list"
}

# 9a: `-p` was listed under COMMON and did nothing for `list` at any count up to
# the corpus size — the first pass is in corpus order and the profile weights
# only the rows beyond it. The default count is the case the issue names, and
# the help must say which commands honour the flag.
case_9_8() {
	"$BIN" list -s 2 -p server >"$TMP/9_8.server" 2>/dev/null
	"$BIN" list -s 2 -p desktop >"$TMP/9_8.desktop" 2>/dev/null
	if cmp -s "$TMP/9_8.server" "$TMP/9_8.desktop"; then
		fail_c "list -p server and list -p desktop are byte-identical at the default count"
		return
	fi
	_p=$("$BIN" --help 2>/dev/null | grep -A3 -- '--profile')
	_missing=
	for _w in list table inject; do
		case $_p in
			*"$_w"*) ;;
			*) _missing="$_missing $_w" ;;
		esac
	done
	if [ -n "$_missing" ]; then
		fail_c "the -p help does not say that$_missing honour the profile"
		return
	fi
	pass_c
}

# The issue's headline example: `psgen unit -p desktop` accepts the profile and
# prints a unit that injects server rows. An accepted flag must reach ExecStart;
# refusing it with its name is the other honest answer. (The other generation
# flags are proved in report.sh's 13.2; this case is the option surface.)
case_9_9() {
	"$BIN" unit -n 2 -p desktop >"$TMP/9_9.out" 2>"$TMP/9_9.err"
	_rc=$?
	if [ "$_rc" = 2 ] && grep -q -- '--profile' "$TMP/9_9.err"; then
		pass_c
		return
	fi
	_start=$(sed -n 's/^ExecStart=//p' "$TMP/9_9.out")
	[ -n "$_start" ] || {
		fail_c "psgen unit printed no ExecStart line"
		return
	}
	case $_start in
		*"-p desktop"* | *"--profile desktop"*)
			pass_c
			return
			;;
	esac
	fail_c "unit accepts -p desktop but ExecStart drops it: $_start"
}

# --------------------------------------------------------------- issue #11
# The workflows must gate style, lints, packaging, the unit and the cross
# binary's smoke. The gate's text is read from the workflows; where this host
# has the tool, the same command is run against the tree, and the unit gate is
# shown to reject the defect it exists for.

# run_value <workflow> <exact command> — true when a single-line `run:` is it.
run_value() {
	sed -n 's/^[[:space:]]*run:[[:space:]]*//p' "$1" | grep -Fxq -- "$2"
}

# gate_tools — whether this host can run a gate's command as written. The
# workflow is checked either way; a toolchain component that is not installed
# is reported, not treated as a pass or as a capability the case cannot do
# without.
gate_tools() { have cargo && have timeout; }

case_11_1() {
	_bad=
	for _w in "$CI" "$REL"; do
		if [ ! -f "$_w" ]; then
			_bad="$_bad $(basename "$_w")(absent)"
			continue
		fi
		run_value "$_w" 'cargo fmt --all -- --check' || _bad="$_bad $(basename "$_w")"
	done
	if [ -n "$_bad" ]; then
		fail_c "no fmt gate in:$_bad"
		return
	fi
	if ! gate_tools || ! ( cd "$SRC" && cargo fmt --version ) >/dev/null 2>&1; then
		say "  #11.1: this toolchain has no rustfmt; the gate text was checked, the command was not run"
		pass_c
		return
	fi
	if ! ( cd "$SRC" && tmo 300 cargo fmt --all -- --check ) 2>"$TMP/11_1.err" >/dev/null; then
		fail_c "cargo fmt --all -- --check rejects the tree: $(head -1 "$TMP/11_1.err")"
		return
	fi
	pass_c
}

case_11_2() {
	_bad=
	for _w in "$CI" "$REL"; do
		if [ ! -f "$_w" ]; then
			_bad="$_bad $(basename "$_w")(absent)"
			continue
		fi
		run_value "$_w" 'cargo clippy --locked --all-targets -- -D warnings' ||
			_bad="$_bad $(basename "$_w")"
	done
	if [ -n "$_bad" ]; then
		fail_c "no clippy gate that denies warnings in:$_bad"
		return
	fi
	if ! gate_tools || ! ( cd "$SRC" && cargo clippy --version ) >/dev/null 2>&1; then
		say "  #11.2: this toolchain has no clippy; the gate text was checked, the command was not run"
		pass_c
		return
	fi
	if ! ( cd "$SRC" && tmo 900 cargo clippy --locked --all-targets -- -D warnings ) \
		2>"$TMP/11_2.err" >/dev/null; then
		fail_c "cargo clippy -D warnings rejects the tree: $(grep '^error' "$TMP/11_2.err" | head -1)"
		return
	fi
	pass_c
}

case_11_3() {
	_bad=
	for _w in "$CI" "$REL"; do
		if [ ! -f "$_w" ]; then
			_bad="$_bad $(basename "$_w")(absent)"
			continue
		fi
		run_value "$_w" 'cargo package --locked --no-verify' || _bad="$_bad $(basename "$_w")"
	done
	if [ -n "$_bad" ]; then
		fail_c "no crate-package gate in:$_bad"
		return
	fi
	if ! gate_tools; then
		say "  #11.3: this host has no cargo; the gate text was checked, the command was not run"
		pass_c
		return
	fi
	# `--offline` is added here, not in the gate: the proof must not need the
	# network, and a tree that was built already has the index this reads.
	if ! ( cd "$SRC" && tmo 300 cargo package --locked --no-verify --offline ) \
		2>"$TMP/11_3.err" >/dev/null; then
		fail_c "cargo package --locked --no-verify rejects the tree: $(head -1 "$TMP/11_3.err")"
		return
	fi
	pass_c
}

# unit_gate <file> — the assertions CI's unit step makes, applied to a unit
# file. Kept in one function so the same code has to accept the shipped unit
# and reject the sabotaged one below.
unit_gate() {
	_f=$1
	grep -q 'proc-fs-nets.target' "$_f" && return 1
	grep -q '^RuntimeDirectory=psgen$' "$_f" || return 1
	grep -q '^ConditionPathExists=/proc/1/stat$' "$_f" || return 1
	grep -q '^ExecStop=.* stop --pidfile' "$_f" || return 1
	if grep '^ExecStop=.* stop --pidfile' "$_f" |
		grep -v -E '^ExecStop=(-|/bin/sh -c )' | grep -q .; then
		return 1
	fi
	return 0
}

case_11_4() {
	[ -f "$CI" ] || {
		fail_c "no $CI"
		return
	}
	_bad=
	for _frag in \
		"systemd-analyze verify /tmp/psgen.service" \
		"grep -q 'proc-fs-nets.target' /tmp/psgen.service" \
		"grep -q '^RuntimeDirectory=psgen\$' /tmp/psgen.service" \
		"grep -q '^ConditionPathExists=/proc/1/stat\$' /tmp/psgen.service" \
		"grep -q '^ExecStop=.* stop --pidfile' /tmp/psgen.service" \
		"grep -v -E '^ExecStop=(-|/bin/sh -c )'"
	do
		grep -Fq -- "$_frag" "$CI" || _bad="$_bad '$_frag'"
	done
	if [ -n "$_bad" ]; then
		fail_c "the CI unit step does not check:$_bad"
		return
	fi
	if ! "$BIN" unit >"$TMP/11_4.service" 2>"$TMP/11_4.err"; then
		fail_c "psgen unit exited non-zero: $(head -1 "$TMP/11_4.err")"
		return
	fi
	if ! unit_gate "$TMP/11_4.service"; then
		fail_c "the printed unit fails the gate CI applies to it"
		return
	fi
	if have systemd-analyze; then
		if ! systemd-analyze verify "$TMP/11_4.service" >/dev/null 2>"$TMP/11_4.verify"; then
			fail_c "systemd-analyze rejects the printed unit: $(head -1 "$TMP/11_4.verify")"
			return
		fi
	else
		say "  #11.4: no systemd-analyze here; the greps were applied, the analyzer was not run"
	fi
	# The defect the gate exists for: the psgen stop loses its guard, while the
	# unrelated `rm` line keeps its `-`. `grep -q '^ExecStop=-'` (the old gate)
	# still passes; the line has to be checked, not the file. The first line that
	# runs the stop is replaced, whatever guard it carried.
	awk -v bin="$BIN" '
		!done && /^ExecStop=.* stop --pidfile/ {
			print "ExecStop=" bin " stop --pidfile /run/psgen/psgen.pid"
			done = 1
			next
		}
		{ print }
	' "$TMP/11_4.service" >"$TMP/11_4.bad"
	if unit_gate "$TMP/11_4.bad"; then
		fail_c "the unit gate accepts an unguarded psgen stop"
		return
	fi
	pass_c
}

# matrix_qemu_smoke <release.yml> — true when one build-matrix entry both needs
# an emulator and sets `smoke: true`. Without the coupling a cross target could
# be smeared with `--version` and the `smoke` step skipped for it.
matrix_qemu_smoke() {
	awk '
	/^[[:space:]]*include:[[:space:]]*$/ { ininc = 1; next }
	ininc && /^[[:space:]]*runs-on:/ { ininc = 0 }
	!ininc { next }
	{
		line = $0
		sub(/^[[:space:]]*/, "", line)
		if (line ~ /^- /) {
			if (n && qemu && smoke) found = 1
			n++
			qemu = 0
			smoke = 0
			sub(/^- /, "", line)
		}
		if (line ~ /^qemu:/) {
			v = line
			sub(/^qemu:[[:space:]]*/, "", v)
			gsub(/"/, "", v)
			sub(/[[:space:]]*$/, "", v)
			qemu = (v != "")
		}
		if (line ~ /^smoke:/) {
			v = line
			sub(/^smoke:[[:space:]]*/, "", v)
			sub(/[[:space:]]*$/, "", v)
			smoke = (v == "true")
		}
	}
	END {
		if (n && qemu && smoke) found = 1
		exit(found ? 0 : 1)
	}' "$1"
}

case_11_5() {
	[ -f "$REL" ] || {
		fail_c "no $REL"
		return
	}
	_bad=
	grep -Fq 'if: matrix.smoke' "$REL" || _bad="$_bad 'if: matrix.smoke'"
	grep -Fq 'cp "$1" target/release/psgen' "$REL" || _bad="$_bad 'stage into target/release'"
	grep -Fq 'sh tests/smoke.sh' "$REL" || _bad="$_bad 'sh tests/smoke.sh'"
	grep -Fq 'sha256sum target/release/psgen' "$REL" || _bad="$_bad 'the staged-binary checksum'"
	matrix_qemu_smoke "$REL" || _bad="$_bad 'a qemu target with smoke: true'"
	if [ -n "$_bad" ]; then
		fail_c "the cross smoke gate is missing:$_bad"
		return
	fi
	# The staging is only load-bearing if the suite reads that path.
	if ! grep -Fq 'BIN=$ROOT/target/release/psgen' "$SMOKE"; then
		fail_c "tests/smoke.sh does not read target/release/psgen, so staging proves nothing"
		return
	fi
	pass_c
}

case_11_6() {
	[ -f "$REL" ] || {
		fail_c "no $REL"
		return
	}
	grep -Fq 'sh scripts/release-notes.sh publish "$TAG"' "$REL" || {
		fail_c "the publish decision is not made through scripts/release-notes.sh"
		return
	}
	_dry=$(grep -n 'cargo publish --locked --dry-run' "$REL" | cut -d: -f1 | head -1)
	_real=$(grep -n '^[[:space:]]*cargo publish --locked$' "$REL" | cut -d: -f1 | head -1)
	_rel=$(grep -n 'gh release create' "$REL" | cut -d: -f1 | head -1)
	if [ -z "$_dry" ] || [ -z "$_real" ]; then
		fail_c "the release job never publishes the crate (dry run: ${_dry:-none}, real: ${_real:-none})"
		return
	fi
	if [ -z "$_rel" ] || [ "$_dry" -lt "$_rel" ] || [ "$_real" -lt "$_dry" ]; then
		fail_c "the crate publish is not ordered after the release assets and its dry run"
		return
	fi
	grep -Fq 'CARGO_REGISTRY_TOKEN is not set; skipping' "$REL" || {
		fail_c "a missing registry token fails the release instead of skipping the crate"
		return
	}
	pass_c
}

case_11_7() {
	[ -f "$REL" ] || {
		fail_c "no $REL"
		return
	}
	_notes=$SRC/scripts/release-notes.sh
	[ -f "$_notes" ] || {
		fail_c "no scripts/release-notes.sh under $SRC"
		return
	}
	grep -Fq 'sh scripts/release-notes.sh notes "$TAG" /tmp/notes.md' "$REL" || {
		fail_c "the release job does not generate the notes from the tag"
		return
	}
	grep -Fq -- '--notes-file /tmp/notes.md' "$REL" || {
		fail_c "the release job does not publish the generated notes"
		return
	}
	if grep -Fq -- '--notes-file .github/release-notes.md' "$REL"; then
		fail_c "the release job still publishes the fixed release-notes.md"
		return
	fi
	# The fixed file is a header, not the release body: a synthetic CHANGELOG
	# makes the body observable, and a body from another release may not appear.
	cat >"$TMP/CHANGELOG" <<'EOF'
## Unreleased

- unreleased marker

## 0.0.9

- marker for nine

## 0.0.1

- marker for one

EOF
	if ! ( cd "$SRC" && CHANGELOG="$TMP/CHANGELOG" \
		sh "$_notes" notes v0.0.9 "$TMP/11_7.md" ) 2>"$TMP/11_7.err"; then
		fail_c "release-notes.sh notes v0.0.9 failed: $(head -1 "$TMP/11_7.err")"
		return
	fi
	grep -q 'marker for nine' "$TMP/11_7.md" || {
		fail_c "the notes for v0.0.9 do not carry that release's CHANGELOG section"
		return
	}
	if grep -q 'marker for one' "$TMP/11_7.md"; then
		fail_c "the notes for v0.0.9 carry another release's section"
		return
	fi
	# The fixed file's title was "Static Linux binaries for psgen 0.0.1". The
	# header may explain versions further down, but the title of a release's
	# notes may not name one release.
	_head=$(head -1 "$TMP/11_7.md")
	case $_head in
		*"psgen "[0-9]*)
			fail_c "the release title names a version ('$_head'), as the fixed file did"
			return
			;;
	esac
	pass_c
}

# ------------------------------------------------------------------ driver

run_case 6.1 6 "a finite RLIMIT_FSIZE skips the copy, not the suite" case_6_1
run_case 6.2 6 "the RLIMIT guard runs under a finite hard limit" case_6_2
run_case 6.3 6 "a host without a pty master skips the pty assertion" case_6_3
run_case 6.4 6 "a non-reaping PID 1 does not fail the duration checks" case_6_4
run_case 9.1 9 "corpus -n is consumed or refused with its name" case_9_1
run_case 9.2 9 "list --json is consumed or refused with its name" case_9_2
run_case 9.3 9 "stop -n is refused and signals nothing" case_9_3
run_case 9.4 9 "table --live -f is refused with its name" case_9_4
run_case 9.5 9 "doctor --lines is consumed or refused with its name" case_9_5
run_case 9.6 9 "check --utc-offset is consumed or refused with its name" case_9_6
run_case 9.7 9 "list -d is consumed or refused with its name" case_9_7
run_case 9.8 9 "list -p changes the default list and is documented" case_9_8
run_case 9.9 9 "unit consumes the profile it accepts" case_9_9
run_case 11.1 11 "the workflows gate fmt, and the tree is formatted" case_11_1
run_case 11.2 11 "the workflows gate clippy -D warnings" case_11_2
run_case 11.3 11 "the workflows gate cargo package" case_11_3
run_case 11.4 11 "the unit gate passes the unit and rejects an unguarded stop" case_11_4
run_case 11.5 11 "the cross binaries are smoked, not only versioned" case_11_5
run_case 11.6 11 "the release publishes the crate, after the assets" case_11_6
run_case 11.7 11 "the release notes are the tag's, not a fixed file" case_11_7

if [ "$RAN" = 0 ]; then
	echo "surface.sh: no case matched '$SELECTED'" >&2
	exit 2
fi

if [ "$FAILS" -gt 0 ]; then
	exit 1
fi
exit 0
