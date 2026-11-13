#!/bin/sh
# Per-issue proof harness: pidfile acceptance, version-independent parsing and
# the name-length preflight.
#
#   sh tests/proof_cases/pidfile.sh <binary> [issue ...]
#
# Covers issues #1, #7 and #26. Each case prints one line — `PASS <n> <what>`,
# `FAIL <n> <what>: <why>` or `SKIP <n> <what>: <why>` — and the script exits
# non-zero when any case failed.
#
# The rule the suite already enforces (DESIGN.md §4) applies to this file: a
# check that cannot fail is worse than no check. The behavioural cases are
# written against a reference the tool does not own — `/proc`, the filesystem's
# `NAME_MAX` — and each one fails on `bf80156`, the commit the fixes branch
# from. Case 7.2 is a source check, because its defect is a duplicated literal;
# it reads the tree the binary was built from. A case that needs a host
# capability this machine lacks prints SKIP with the reason; with
# PSGEN_REQUIRE_ALL=1 that same absence is a failure, so a release gate cannot
# pass on a host where the case never ran.
#
# Nothing here writes outside a private temp directory. Stubs, staging
# directories and pidfiles all live under `$TMP`, which is exported as
# `TMPDIR`; `cleanup` kills any stub a case recorded and removes the tree.
set -u

LC_ALL=C
export LC_ALL

if [ $# -lt 1 ]; then
	echo "usage: sh tests/proof_cases/pidfile.sh <binary> [issue ...]" >&2
	exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BIN_ARG=$1
shift
SELECTED=$*

[ -x "$BIN_ARG" ] || {
	echo "pidfile.sh: $BIN_ARG is not an executable" >&2
	exit 2
}
case $BIN_ARG in
	/*) BIN=$BIN_ARG ;;
	*) BIN=$(CDPATH= cd -- "$(dirname -- "$BIN_ARG")" && pwd)/$(basename -- "$BIN_ARG") ;;
esac

TMP=$(mktemp -d) || {
	echo "pidfile.sh: cannot create a temp directory" >&2
	exit 2
}
# The tool stages its stubs under the system temp directory. Point that at the
# tree this script already owns, so a failed run leaves nothing in /tmp.
TMPDIR=$TMP
export TMPDIR

FAILS=0
RAN=0
CUR_ID=
CUR_WHAT=

# The checkpoint tree, not this file's tree: case 7.2 is about the source the
# binary was built from, so it must read that tree, not the one running the
# harness. It is inferred from the binary's own path (`<tree>/target/<profile>`
# `/psgen`) so a caller cannot forget it; PSGEN_SRC overrides the inference.
SRC=${PSGEN_SRC:-}
SRC_GIVEN=
if [ -z "$SRC" ]; then
	_bin_dir=$(dirname -- "$BIN")
	case $_bin_dir in
		*/target/*) SRC=$(CDPATH= cd -- "$_bin_dir/../.." && pwd) ;;
		*) SRC=$ROOT ;;
	esac
else
	SRC_GIVEN=1
fi
[ -d "$SRC" ] || {
	echo "pidfile.sh: $SRC (the tree the binary came from) is not a directory" >&2
	exit 2
}

# ---------------------------------------------------------------- plumbing

require_all() {
	case ${PSGEN_REQUIRE_ALL:-} in
		"" | 0) return 1 ;;
		*) return 0 ;;
	esac
}

have() { command -v "$1" >/dev/null 2>&1; }

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

# proc_state <pid> — the state letter from /proc/PID/stat, empty when gone.
proc_state() {
	[ -r "/proc/$1/stat" ] || return 0
	sed -n 's/^[0-9][0-9]* (.*) \([^ ]*\).*/\1/p' "/proc/$1/stat" 2>/dev/null
}

# running <pid> — a process that is neither gone nor a zombie.
running() {
	_s=$(proc_state "$1")
	[ -n "$_s" ] && [ "$_s" != Z ]
}

# gone <pid> — no /proc entry, or a zombie whose parent has not reaped it. A
# zombie has already exited; `stop` counts it as stopped (issue #4).
gone() {
	_s=$(proc_state "$1")
	[ -z "$_s" ] || [ "$_s" = Z ]
}

# bank_pidfile <path> — record every PID a pidfile names, for the exit trap.
bank_pidfile() {
	[ -f "$1" ] || return 0
	grep -v '^#' "$1" 2>/dev/null | awk 'NF >= 1 { print $1 }' >>"$TMP/stub-pids"
}

# bank_spawned <stderr-file> — record the PIDs a failed run admitted to
# spawning, so a post-spawn failure leaves nothing behind.
bank_spawned() {
	[ -f "$1" ] || return 0
	for _p in $(sed -n 's/.*spawned PIDs: //p' "$1" 2>/dev/null); do
		printf '%s\n' "$_p" >>"$TMP/stub-pids"
	done
}

cleanup() {
	trap - EXIT INT TERM HUP
	if [ -f "$TMP/stub-pids" ]; then
		while read -r p; do
			[ -n "$p" ] || continue
			# A stub may ignore SIGTERM; the trap must still remove it.
			kill "$p" 2>/dev/null
			kill -9 "$p" 2>/dev/null
		done <"$TMP/stub-pids"
	fi
	rm -rf "$TMP" 2>/dev/null
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

# ---------------------------------------------------------------- issue #1
# A pidfile psgen wrote is a psgen pidfile. The header comparison tested nine
# bytes of the buffer against the eight-byte prefix `# psgen `, which is false
# for every input, so only an absent or empty target was ever accepted. A run
# that ended (and left its file behind, as `stop` does) refused the next run,
# and `doctor` called the file foreign.
#
# The flags keep the cases away from user switching and the bind tier: this
# case is about the pidfile, and it must behave the same for any caller.

# One run, then `stop`, then the same path again. `stop` deliberately leaves
# the pidfile, which is exactly the file the next run must accept.
case_1_1() {
	_pf=$TMP/1_1.pid
	: >"$_pf"
	"$BIN" inject -n 1 -s 3 --no-user --no-root --no-mem --no-tty --no-threads \
		--pidfile "$_pf" -q >"$TMP/1_1a.out" 2>"$TMP/1_1a.err"
	_rc=$?
	bank_spawned "$TMP/1_1a.err"
	if [ "$_rc" -ne 0 ]; then
		fail_c "the first run exited $_rc: $(head -1 "$TMP/1_1a.err")"
		return
	fi
	_head=$(head -1 "$_pf" 2>/dev/null)
	case $_head in
		"# psgen "*) ;;
		*)
			fail_c "the first run wrote no psgen header ('$_head')"
			stop_pidfile "$_pf"
			return
			;;
	esac
	bank_pidfile "$_pf"
	stop_pidfile "$_pf"
	if [ ! -f "$_pf" ]; then
		fail_c "stop removed the pidfile, so there is nothing to reuse"
		return
	fi
	"$BIN" inject -n 1 -s 3 --no-user --no-root --no-mem --no-tty --no-threads \
		--pidfile "$_pf" -q >"$TMP/1_1b.out" 2>"$TMP/1_1b.err"
	_rc=$?
	bank_spawned "$TMP/1_1b.err"
	stop_pidfile "$_pf"
	if [ "$_rc" -ne 0 ]; then
		fail_c "the second run refused the pidfile the first one wrote: $(head -1 "$TMP/1_1b.err")"
		return
	fi
	_head=$(head -1 "$_pf" 2>/dev/null)
	case $_head in
		"# psgen "*) ;;
		*)
			fail_c "the second run succeeded without leaving a psgen header"
			return
			;;
	esac
	pass_c
}

# `doctor` promises to say whether `inject` would accept a path. For a pidfile
# psgen wrote, whose rows are all gone, the verdict is ALLOW.
case_1_2() {
	_pf=$TMP/1_2.pid
	: >"$_pf"
	"$BIN" inject -n 1 -s 3 --no-user --no-root --no-mem --no-tty --no-threads \
		--pidfile "$_pf" -q >"$TMP/1_2.out" 2>"$TMP/1_2.err"
	_rc=$?
	bank_spawned "$TMP/1_2.err"
	if [ "$_rc" -ne 0 ]; then
		fail_c "could not write a pidfile to probe: exit $_rc ($(head -1 "$TMP/1_2.err"))"
		return
	fi
	bank_pidfile "$_pf"
	stop_pidfile "$_pf"
	_verdict=$(tmo 60 "$BIN" doctor --pidfile "$_pf" 2>/dev/null |
		awk -F '	' '$1 == "pidfile" { print $2; exit }')
	if [ "$_verdict" != ALLOW ]; then
		fail_c "doctor reports '${_verdict:-no pidfile line}' for a pidfile psgen wrote"
		return
	fi
	pass_c
}

# ---------------------------------------------------------------- issue #7
# The header is `# psgen <version> boot <boot-id>`. The boot-id guard must not
# depend on the version: the pre-fix parser matched the literal
# `# psgen 0.0.1 boot `, so a version bump silently disarmed the one check that
# stops a pidfile from a previous boot from signalling whatever now owns those
# PIDs. A file written by another release is still judged by its boot id.

# start_victim — a real process with a three-field pidfile row.
#
# The inner shell starts the victim and exits, so this script has no background
# job to report when `stop` kills it; the output stays one line per case.
start_victim() {
	_victim=$(sh -c 'sleep 300 >/dev/null 2>&1 </dev/null & echo $!')
	printf '%s\n' "$_victim" >>"$TMP/stub-pids"
	# `sleep`'s comm has no space, so the 22nd field is the starttime.
	_starttime=$(awk '{ print $22 }' "/proc/$_victim/stat" 2>/dev/null)
	_comm=$(cat "/proc/$_victim/comm" 2>/dev/null)
	[ -n "$_starttime" ] && [ -n "$_comm" ]
}

case_7() {
	_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
	if [ -z "$_boot" ]; then
		skip_c "no /proc/sys/kernel/random/boot_id to build a header with"
		return
	fi
	_other=00000000-0000-0000-0000-000000000000
	[ "$_boot" != "$_other" ] || _other=11111111-1111-1111-1111-111111111111

	# (a) Another release's pidfile, from this boot: it must still stop. A
	# build that only knows its own version parses this as "no header" and
	# stops the row by accident, so this half alone would pass on bf80156;
	# it is here to prove the version is not part of the identity rule.
	if ! start_victim; then
		fail_c "could not start a process to name in a pidfile"
		return
	fi
	printf '# psgen 9.9.9 boot %s\n%s\t%s\t%s\n' \
		"$_boot" "$_victim" "$_starttime" "$_comm" >"$TMP/7-same.pid"
	_out=$(tmo 30 "$BIN" stop --pidfile "$TMP/7-same.pid" 2>&1)
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "a pidfile from another release did not stop: $(printf '%s' "$_out" | head -1)"
		kill "$_victim" 2>/dev/null
		return
	fi
	if ! gone "$_victim"; then
		fail_c "stop reported success but the named process is still running"
		return
	fi

	# (b) Another release's pidfile, from another boot: the guard must arm.
	# bf80156 does not match the header, so the guard never runs and the
	# process is signalled — a fail-open across a version bump.
	if ! start_victim; then
		fail_c "could not start a second process to name in a pidfile"
		return
	fi
	printf '# psgen 9.9.9 boot %s\n%s\t%s\t%s\n' \
		"$_other" "$_victim" "$_starttime" "$_comm" >"$TMP/7-other.pid"
	_out=$(tmo 30 "$BIN" stop --pidfile "$TMP/7-other.pid" 2>&1)
	_rc=$?
	if [ "$_rc" -eq 0 ]; then
		fail_c "stop reported success for a foreign-version pidfile from another boot"
		kill "$_victim" 2>/dev/null
		return
	fi
	if ! running "$_victim"; then
		fail_c "stop refused the foreign boot but signalled the process anyway"
		return
	fi
	case $_out in
		*"another boot"*) ;;
		*)
			fail_c "stop refused for a reason other than the boot id: $(printf '%s' "$_out" | head -1)"
			kill "$_victim" 2>/dev/null
			return
			;;
	esac
	kill "$_victim" 2>/dev/null
	pass_c
}

# The version has one owner: Cargo.toml, read at build time. A literal of it
# anywhere but `version.rs` is how the parser and the runtime strings drift
# apart on a bump. This half is a source check because the defect is
# duplication in the source; the behaviour it protects is case 7.
case_7_2() {
	_ver=$("$BIN" --version 2>/dev/null | sed -n 's/^psgen //p')
	if [ -z "$_ver" ]; then
		fail_c "the binary printed no version"
		return
	fi
	if [ ! -d "$SRC/src" ]; then
		skip_c "the source tree $SRC has no src/ to read"
		return
	fi
	# A binary copied out of its tree has no discoverable source. Reading this
	# checkout instead would pass for a build that was not made from it, which
	# is the vacuous case this file exists to avoid.
	if [ -z "$SRC_GIVEN" ]; then
		case $BIN in
			"$SRC"/target/*) ;;
			*)
				skip_c "$BIN is not under $SRC/target, so its source tree is unknown"
				return
				;;
		esac
	fi
	# The version is a token, not a substring: `127.0.0.1` in the corpus must
	# not count as a hardcoded 0.0.1.
	_re=$(printf '%s' "$_ver" | sed 's/[^A-Za-z0-9]/\\&/g')
	_hits=$(grep -nE "(^|[^0-9.])${_re}([^0-9.]|$)" "$SRC"/src/*.rs 2>/dev/null |
		grep -vF "$SRC/src/version.rs:")
	if [ -n "$_hits" ]; then
		say "  #7.2 diagnostics:"
		printf '%s\n' "$_hits" | sed 's/^/    /' >&2
		fail_c "a source file outside version.rs hardcodes the version (first: $(printf '%s\n' "$_hits" | head -1))"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #26
# The preflight must test the name the writer creates. A basename that fits in
# NAME_MAX but not in NAME_MAX once the temporary suffix is appended used to
# pass a short probe file created in the parent, spawn its stubs, and only then
# fail the write: live processes and no pidfile. The boundary is derived from
# the filesystem's NAME_MAX and the shortest suffix the writer can use
# (`.t<pid>`), and both sides of it are asserted, so the check is not simply
# stricter than before.
case_26() {
	have getconf || {
		skip_c "no getconf to read NAME_MAX"
		return
	}
	have timeout || {
		skip_c "no timeout to bound the inject run"
		return
	}
	_name_max=$(getconf NAME_MAX "$TMP" 2>/dev/null)
	case $_name_max in
		"" | *[!0-9]*)
			skip_c "getconf did not report a numeric NAME_MAX"
			return
			;;
	esac
	_ok_len=$((_name_max - 15))
	_too_long=$((_name_max - 3))
	if [ "$_ok_len" -lt 1 ] || [ "$_too_long" -le "$_ok_len" ]; then
		skip_c "NAME_MAX $_name_max leaves no room for both sides of the boundary"
		return
	fi
	_ok=$(printf '%*s' "$_ok_len" '' | tr ' ' d)
	_bad=$(printf '%*s' "$_too_long" '' | tr ' ' d)

	# (a) A long basename the writer can still serve is accepted, written at
	# the name it was given, and stoppable.
	_pf=$TMP/$_ok
	"$BIN" inject -n 1 -s 3 --no-user --no-root --no-mem --no-tty --no-threads \
		--pidfile "$_pf" -q >"$TMP/26_ok.out" 2>"$TMP/26_ok.err"
	_rc=$?
	_spawned=$(sed -n 's/.*spawned PIDs: //p' "$TMP/26_ok.err")
	bank_spawned "$TMP/26_ok.err"
	if [ "$_rc" -ne 0 ]; then
		_why=$(head -1 "$TMP/26_ok.err")
		[ -n "$_spawned" ] && _why="spawned $_spawned, then: $_why"
		fail_c "a ${_ok_len}-byte basename was refused (exit $_rc): $_why"
		return
	fi
	if [ ! -f "$_pf" ]; then
		fail_c "the run reported success but wrote no pidfile at the name it was given"
		stop_pidfile "$_pf"
		return
	fi
	_pid=$(grep -v '^#' "$_pf" | awk 'NF >= 1 { print $1; exit }')
	if [ -z "$_pid" ] || [ ! -d "/proc/$_pid" ]; then
		fail_c "the pidfile at a ${_ok_len}-byte basename does not name the live stub"
		stop_pidfile "$_pf"
		return
	fi
	bank_pidfile "$_pf"
	stop_pidfile "$_pf"
	if ! gone "$_pid"; then
		fail_c "the run at a ${_ok_len}-byte basename could not be stopped"
		return
	fi

	# (b) A basename that fits NAME_MAX but not NAME_MAX minus the writer's
	# temporary suffix is refused before anything is spawned.
	_pf=$TMP/$_bad
	: >"$TMP/26_bad.err"
	tmo 60 "$BIN" inject -n 1 -s 3 --no-user --no-root --no-mem --no-tty --no-threads \
		--pidfile "$_pf" -q >"$TMP/26_bad.out" 2>"$TMP/26_bad.err"
	_rc=$?
	# Whatever it admits to spawning is a real process; the trap must know it.
	_spawned=$(sed -n 's/.*spawned PIDs: //p' "$TMP/26_bad.err")
	for _p in $_spawned; do
		printf '%s\n' "$_p" >>"$TMP/stub-pids"
	done
	if [ "$_rc" -eq 0 ]; then
		fail_c "accepted a ${_too_long}-byte basename that cannot hold the temporary name"
		stop_pidfile "$_pf"
		return
	fi
	if [ -f "$_pf" ]; then
		fail_c "refused a ${_too_long}-byte basename but left the pidfile behind"
		return
	fi
	if [ -n "$_spawned" ]; then
		fail_c "refused after spawning stubs: $_spawned"
		return
	fi
	if grep -q 'spawned PIDs:' "$TMP/26_bad.err" 2>/dev/null; then
		fail_c "refused only after spawning: $(head -1 "$TMP/26_bad.err")"
		return
	fi
	pass_c
}

# ------------------------------------------------------------------ driver

run_case 1.1 1 "a pidfile stop left behind is accepted by the next run" case_1_1
run_case 1.2 1 "doctor --pidfile accepts a psgen pidfile" case_1_2
run_case 7 7 "a foreign-version pidfile still stops and its boot guard arms" case_7
run_case 7.2 7 "the version has one owner in the source" case_7_2
run_case 26 26 "a basename near NAME_MAX is accepted and one past it refused pre-spawn" case_26

if [ "$RAN" = 0 ]; then
	echo "pidfile.sh: no case matched '$SELECTED'" >&2
	exit 2
fi

if [ "$FAILS" -gt 0 ]; then
	exit 1
fi
exit 0
