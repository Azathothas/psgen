#!/bin/sh
# Per-issue proof harness: `stop`'s accounting, its preview flags and its
# one-field identity rule.
#
#   sh tests/proof_cases/stop.sh <binary> [issue ...]
#
# Covers issues #4, #15 and #22. Each case prints one line — `PASS <n> <what>`,
# `FAIL <n> <what>: <why>` or `SKIP <n> <what>: <why>` — and the script exits
# non-zero when any case failed.
#
# The rule the suite already enforces (DESIGN.md §4) applies to this file: a
# check that cannot fail is worse than no check. Every case here is written
# against a reference the tool does not own — `/proc` and the state the kernel
# shows, a process `psgen` did not start, a real injected run — and each one
# fails on `bf80156`, the commit the fixes branch from. A case that needs a
# host capability this machine lacks prints SKIP with the reason; with
# PSGEN_REQUIRE_ALL=1 that same absence is a failure, so a release gate cannot
# pass on a host where the case never ran.
#
# Everything the cases start lives under `$TMP`: `TMPDIR` is pointed at it, so
# the staging directories `inject` creates are inside it too, and `cleanup`
# kills every banked PID and removes the tree from the exit trap.
set -u

LC_ALL=C
export LC_ALL

if [ $# -lt 1 ]; then
	echo "usage: sh tests/proof_cases/stop.sh <binary> [issue ...]" >&2
	exit 2
fi

BIN_ARG=$1
shift
SELECTED=$*

[ -x "$BIN_ARG" ] || {
	echo "stop.sh: $BIN_ARG is not an executable" >&2
	exit 2
}
case $BIN_ARG in
	/*) BIN=$BIN_ARG ;;
	*) BIN=$(CDPATH= cd -- "$(dirname -- "$BIN_ARG")" && pwd)/$(basename -- "$BIN_ARG") ;;
esac
# A caller can pass a symlink; the victim's `/proc/PID/exe` reports the target.
BIN_REAL=$(readlink -f -- "$BIN" 2>/dev/null) || BIN_REAL=$BIN
[ -n "$BIN_REAL" ] || BIN_REAL=$BIN

TMP=$(mktemp -d) || {
	echo "stop.sh: cannot create a temp directory" >&2
	exit 2
}
# `inject` stages under the system temp directory. Pointing it here keeps every
# staging directory inside the tree `cleanup` removes, and keeps `stop`'s own
# "is this a directory this caller owns" check looking at the same place.
TMPDIR=$TMP
export TMPDIR

FAILS=0
RAN=0
CUR_ID=
CUR_WHAT=

# ---------------------------------------------------------------- plumbing

require_all() {
	case ${PSGEN_REQUIRE_ALL:-} in
		"" | 0) return 1 ;;
		*) return 0 ;;
	esac
}

have() { command -v "$1" >/dev/null 2>&1; }

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

# tmo <seconds> <command...> — timeout(1) when the host has it. A stop that
# hangs is a failed stop, not a harness that never ends.
tmo() {
	_t=$1
	shift
	if have timeout; then
		timeout "$_t" "$@"
	else
		"$@"
	fi
}

# ---------------------------------------------------------------- references

is_pid() {
	case ${1:-} in
		"" | *[!0-9]*) return 1 ;;
		*) return 0 ;;
	esac
}

# The fields of /proc/PID/stat after the parenthesised comm, so a comm with a
# space in it does not shift them. `state` is 1, `pgrp` is 3, `starttime` 20.
proc_fields() {
	sed -n 's/^[0-9]* (.*) //p' "/proc/$1/stat" 2>/dev/null
}

proc_state() { proc_fields "$1" | cut -d' ' -f1; }

proc_pgrp() { proc_fields "$1" | cut -d' ' -f3; }

proc_start() { proc_fields "$1" | cut -d' ' -f20; }

# The tool's own definition of alive: a zombie is already dead.
alive() {
	_s=$(proc_state "$1")
	[ -n "$_s" ] && [ "$_s" != Z ]
}

row_pids() {
	awk '!/^#/ && NF { print $1 }' "$1" 2>/dev/null
}

# alive_named <pidfile> — how many of the PIDs the file names are still alive.
alive_named() {
	_n=0
	for _p in $(row_pids "$1"); do
		is_pid "$_p" || continue
		alive "$_p" && _n=$((_n + 1))
	done
	printf '%s' "$_n"
}

# --------------------------------------------------------------- lifecycle

# bank <pid...> — remember a process this run started, for the exit trap. A
# case that fails before its stop must not leave the process behind.
bank() {
	for _b in "$@"; do
		is_pid "$_b" || continue
		printf '%s\n' "$_b" >>"$TMP/stub-pids"
	done
}

# kill_tree <pid> — the process and, when it leads one, its process group. The
# group is only signalled when `/proc` says this PID is its leader, so a number
# that is not a PGID cannot address somebody else's group.
kill_tree() {
	_pg=$(proc_pgrp "$1")
	if [ -n "$_pg" ] && [ "$_pg" = "$1" ]; then
		kill -9 "-$1" 2>/dev/null
	fi
	kill -9 "$1" 2>/dev/null
}

cleanup() {
	trap - EXIT INT TERM HUP
	if [ -f "$TMP/stub-pids" ]; then
		while read -r _p; do
			[ -n "$_p" ] || continue
			kill_tree "$_p"
			# Reap the ones this script started itself, so the shell does not
			# print a job-control line over the case output.
			wait "$_p" 2>/dev/null
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

# stage_run <dir> <name> <count> <seed> [inject flags...] — one small run with
# a pidfile of its own, banked for the exit trap. Returns 1 when the binary
# refused to start it; the reason is in <dir>/<name>.err.
stage_run() {
	_sd=$1
	_sn=$2
	_sc=$3
	_ss=$4
	shift 4
	if ! tmo 120 "$BIN" inject -n "$_sc" -s "$_ss" --pidfile "$_sd/$_sn.pid" \
		-q --no-user --no-mem --no-tty --no-threads "$@" \
		>"$_sd/$_sn.out" 2>"$_sd/$_sn.err"; then
		return 1
	fi
	for _sp in $(row_pids "$_sd/$_sn.pid"); do
		bank "$_sp"
	done
	[ -s "$_sd/$_sn.pid" ]
}

# ---------------------------------------------------------------- issue #4
# A zombie is already dead. Its /proc entry still answers starttime and comm,
# and a signal to it succeeds and does nothing, so a stop that counts signals
# reports the same processes stopped twice.

case_4_1() {
	have python3 || {
		skip_c "no python3 to leave a child unreaped in zombie state"
		return
	}
	_d=$TMP/4_1
	mkdir -p "$_d" || {
		skip_c "cannot create a work directory"
		return
	}
	# A session leader that exits while a child stays in its group, and a
	# parent that never waits: the leader is a zombie whose group still holds
	# a live process, the shape an init that does not reap leaves behind.
	cat >"$_d/zombie.py" <<'PY'
import os, time
pid = os.fork()
if pid == 0:
    os.setsid()
    child = os.fork()
    if child:
        print(os.getpid(), child, flush=True)
        os._exit(0)
    time.sleep(600)
    os._exit(0)
time.sleep(600)
PY
	python3 "$_d/zombie.py" >"$_d/pids" 2>"$_d/zombie.err" &
	_holder=$!
	bank "$_holder"
	_i=0
	while [ ! -s "$_d/pids" ] && [ "$_i" -lt 50 ]; do
		sleep 0.1
		_i=$((_i + 1))
	done
	_leader=$(cut -d' ' -f1 "$_d/pids" 2>/dev/null)
	_child=$(cut -d' ' -f2 "$_d/pids" 2>/dev/null)
	if ! is_pid "$_leader" || ! is_pid "$_child"; then
		fail_c "could not stage a zombie leader: $(head -1 "$_d/zombie.err")"
		return
	fi
	bank "$_leader" "$_child"
	# The child has to be in the leader's group, or the group-reach half of
	# the case is not being exercised at all.
	_pg=$(proc_pgrp "$_child")
	if [ "$_pg" != "$_leader" ]; then
		fail_c "the staged child is in group ${_pg:-none}, not the leader's ($_leader)"
		return
	fi
	_state=$(proc_state "$_leader")
	if [ "$_state" != Z ]; then
		fail_c "the staged leader is '${_state:-gone}', not a zombie"
		return
	fi
	_start=$(proc_start "$_leader")
	_comm=$(tr -d '\n' <"/proc/$_leader/comm" 2>/dev/null)
	_pf=$_d/zombie.pid
	printf '# psgen 0.0.1 boot %s\n%s\t%s\t%s\n' \
		"$(cat /proc/sys/kernel/random/boot_id)" "$_leader" "$_start" "$_comm" >"$_pf"
	_out=$(tmo 60 "$BIN" stop --pidfile "$_pf" 2>"$_d/stop.err")
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "stop exited $_rc on a zombie: $(head -1 "$_d/stop.err")"
		return
	fi
	# The child is the live member of the zombie's group. Reaching it is why
	# the group signal stays even though the leader itself is dead.
	if alive "$_child"; then
		fail_c "stop did not reach the live child $_child in the zombie's group"
		return
	fi
	case $_out in
		"stopped 0 "*)
			;;
		*)
			fail_c "a zombie was counted as stopped: '$(printf '%s' "$_out" | head -1)'"
			return
			;;
	esac
	# And it has to say why, so `stopped 0` is not the same output as a file
	# that named nothing at all.
	grep -q "already a zombie" "$_d/stop.err" || {
		fail_c "the skip was not explained: $(head -1 "$_d/stop.err")"
		return
	}
	pass_c
}

# One process named on five lines is still one process. `stopped N` is a count
# of processes, and a second stop on the same file must say zero.
case_4_2() {
	_d=$TMP/4_2
	mkdir -p "$_d" || {
		skip_c "cannot create a work directory"
		return
	}
	stage_run "$_d" run 1 5 || {
		fail_c "inject did not start a run: $(head -1 "$_d/run.err")"
		return
	}
	_line=$(awk '!/^#/ && NF { print; exit }' "$_d/run.pid")
	_pid=$(printf '%s\n' "$_line" | cut -f1)
	if ! is_pid "$_pid"; then
		fail_c "the run's pidfile has no usable row"
		return
	fi
	if ! alive "$_pid"; then
		fail_c "the staged row $_pid was not running when stop was asked"
		return
	fi
	{
		grep '^#' "$_d/run.pid"
		_i=0
		while [ "$_i" -lt 5 ]; do
			printf '%s\n' "$_line"
			_i=$((_i + 1))
		done
	} >"$_d/dup.pid"
	_out=$(tmo 60 "$BIN" stop --pidfile "$_d/dup.pid" 2>"$_d/stop.err")
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "stop exited $_rc: $(head -1 "$_d/stop.err")"
		return
	fi
	_stopped=$(printf '%s\n' "$_out" | sed -n 's/^stopped \([0-9][0-9]*\).*/\1/p')
	if [ -z "$_stopped" ]; then
		fail_c "stop printed no count: '$(printf '%s' "$_out" | head -1)'"
		return
	fi
	if [ "$_stopped" -ne 1 ]; then
		fail_c "one process named on five lines was counted as $_stopped"
		return
	fi
	if alive "$_pid"; then
		fail_c "the row $_pid was counted as stopped and is still running"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #15
# A preview must not be destructive. `--dry-run` is inject's flag and `stop`
# never read it, so a command that reads as a preview killed the run.

case_15_1() {
	_d=$TMP/15_1
	mkdir -p "$_d" || {
		skip_c "cannot create a work directory"
		return
	}
	stage_run "$_d" run 2 5 || {
		fail_c "inject did not start a run: $(head -1 "$_d/run.err")"
		return
	}
	_pf=$_d/run.pid
	_before=$(alive_named "$_pf")
	_out=$(tmo 60 "$BIN" stop --pidfile "$_pf" --dry-run 2>"$_d/stop.err")
	_rc=$?
	_after=$(alive_named "$_pf")
	if [ "$_after" -ne "$_before" ]; then
		fail_c "stop --dry-run signalled: $_before rows were alive, $_after still are"
		return
	fi
	if [ "$_rc" -ne 2 ]; then
		fail_c "stop --dry-run exited $_rc, not 2 (said '$(printf '%s' "$_out" | head -1)')"
		return
	fi
	grep -q -- '--dry-run' "$_d/stop.err" || {
		fail_c "the refusal does not name --dry-run: $(head -1 "$_d/stop.err")"
		return
	}
	pass_c
}

# `--plan` is the real preview: it prints what it would do, signals nothing, and
# predicts the stop that follows.
case_15_2() {
	_d=$TMP/15_2
	mkdir -p "$_d" || {
		skip_c "cannot create a work directory"
		return
	}
	stage_run "$_d" run 2 5 || {
		fail_c "inject did not start a run: $(head -1 "$_d/run.err")"
		return
	}
	_pf=$_d/run.pid
	_before=$(alive_named "$_pf")
	_out=$(tmo 60 "$BIN" stop --pidfile "$_pf" --plan 2>"$_d/plan.err")
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "stop --plan exited $_rc: $(head -1 "$_d/plan.err")"
		return
	fi
	_after=$(alive_named "$_pf")
	if [ "$_after" -ne "$_before" ]; then
		fail_c "stop --plan signalled: $_before rows were alive, $_after still are"
		return
	fi
	_planned=$(printf '%s\n' "$_out" | sed -n 's/^would stop \([0-9][0-9]*\).*/\1/p')
	if [ -z "$_planned" ]; then
		fail_c "stop --plan printed no plan: '$(printf '%s' "$_out" | head -1)'"
		return
	fi
	if [ "$_planned" -ne "$_before" ]; then
		fail_c "the plan says $_planned processes where $_before rows are alive"
		return
	fi
	if printf '%s\n' "$_out" | grep -q '^stopped '; then
		fail_c "the preview printed a completion as well as a plan"
		return
	fi
	# The plan has to describe the stop it predicts, so run it and compare.
	_out=$(tmo 60 "$BIN" stop --pidfile "$_pf" 2>"$_d/stop.err")
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "the real stop after --plan exited $_rc: $(head -1 "$_d/stop.err")"
		return
	fi
	_stopped=$(printf '%s\n' "$_out" | sed -n 's/^stopped \([0-9][0-9]*\).*/\1/p')
	if [ "$_stopped" != "$_planned" ]; then
		fail_c "the plan said $_planned and the real stop said ${_stopped:-nothing}"
		return
	fi
	if [ "$(alive_named "$_pf")" -ne 0 ]; then
		fail_c "rows the real stop counted as stopped are still running"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #22
# A one-field line has no starttime, so the executable is not an identity:
# every psgen process shares it. Signalling on that alone hits whatever now
# holds a recycled PID.

case_22_1() {
	_d=$TMP/22_1
	mkdir -p "$_d" || {
		skip_c "cannot create a work directory"
		return
	}
	# Started through a shell that exits at once: the victim's parent is then
	# init, so killing it cannot print a job-control line over the case
	# output, and the stopping is done by psgen rather than this script.
	sh -c '"$1" load --cpu-util 5 -d 120 -q >/dev/null 2>"$2" & printf "%s\n" "$!" >"$3"' \
		sh "$BIN" "$_d/load.err" "$_d/victim.pid"
	_i=0
	while [ ! -s "$_d/victim.pid" ] && [ "$_i" -lt 50 ]; do
		sleep 0.1
		_i=$((_i + 1))
	done
	_victim=$(cat "$_d/victim.pid" 2>/dev/null)
	if ! is_pid "$_victim"; then
		fail_c "could not start a victim process: $(head -1 "$_d/load.err")"
		return
	fi
	bank "$_victim"
	_i=0
	while [ -z "$(proc_state "$_victim")" ] && [ "$_i" -lt 50 ]; do
		sleep 0.1
		_i=$((_i + 1))
	done
	case $(proc_state "$_victim") in
		"" | Z)
			fail_c "load did not start a victim process: $(head -1 "$_d/load.err")"
			return
			;;
	esac
	_exe=$(readlink "/proc/$_victim/exe" 2>/dev/null)
	if [ "$_exe" != "$BIN" ] && [ "$_exe" != "$BIN_REAL" ]; then
		skip_c "the victim runs '${_exe:-no exe}', not the binary under test"
		return
	fi
	_pf=$_d/victim-line.pid
	# No nonce: nothing in this file can tie the PID to the process it now
	# holds, which is exactly the recycled-PID shape a pidfile outlives.
	printf '# psgen 0.0.1 boot %s\n%s\n' \
		"$(cat /proc/sys/kernel/random/boot_id)" "$_victim" >"$_pf"
	_out=$(tmo 60 "$BIN" stop --pidfile "$_pf" 2>"$_d/stop.err")
	_rc=$?
	if ! alive "$_victim"; then
		fail_c "a one-field line killed an unrelated psgen process ($_victim)"
		return
	fi
	if [ "$_rc" -eq 0 ]; then
		fail_c "a one-field line reported success for a PID it could not identify: '$(printf '%s' "$_out" | head -1)'"
		return
	fi
	grep -q "cannot identify $_victim" "$_d/stop.err" || {
		fail_c "the refusal does not name $_victim: $(head -1 "$_d/stop.err")"
		return
	}
	pass_c
}

# The one-field rows of a run that is not proc-self: either the line identifies
# them positively, or stop refuses and names every row it leaves running. What
# it must never do is skip them and report success.
case_22_2() {
	_d=$TMP/22_2
	mkdir -p "$_d/sh" || {
		skip_c "cannot create a work directory"
		return
	}
	if ! stage_run "$_d" run 2 9 --no-root --shadow-dir "$_d/sh"; then
		fail_c "inject did not start a shadow-tier run: $(head -1 "$_d/run.err")"
		return
	fi
	_pf=$_d/run.pid
	_not_proc_self=0
	for _p in $(row_pids "$_pf"); do
		_exe=$(readlink "/proc/$_p/exe" 2>/dev/null)
		if [ "$_exe" != "$BIN" ] && [ "$_exe" != "$BIN_REAL" ]; then
			_not_proc_self=$((_not_proc_self + 1))
		fi
	done
	if [ "$_not_proc_self" -eq 0 ]; then
		skip_c "the run chose proc-self, whose rows a one-field line already identified"
		return
	fi
	# The one-field form a caller gets by cutting the pid column out of the
	# pidfile the run wrote, header included.
	{
		grep '^#' "$_pf"
		row_pids "$_pf"
	} >"$_d/one.pid"
	_before=$(alive_named "$_d/one.pid")
	if [ "$_before" -eq 0 ]; then
		fail_c "the staged rows were not running when stop was asked"
		return
	fi
	_out=$(tmo 60 "$BIN" stop --pidfile "$_d/one.pid" 2>"$_d/stop.err")
	_rc=$?
	_after=$(alive_named "$_d/one.pid")
	if [ "$_after" -eq 0 ]; then
		# Positively identified: the report has to say so, and be true.
		if [ "$_rc" -ne 0 ]; then
			fail_c "every row was stopped but stop exited $_rc: $(head -1 "$_d/stop.err")"
			return
		fi
		_stopped=$(printf '%s\n' "$_out" | sed -n 's/^stopped \([0-9][0-9]*\).*/\1/p')
		if [ "$_stopped" != "$_before" ]; then
			fail_c "stop stopped $_before rows and reported ${_stopped:-nothing}"
			return
		fi
		pass_c
		return
	fi
	# Refused: an error that names every row it left running.
	if [ "$_rc" -eq 0 ]; then
		fail_c "silently skipped $_after live row(s) and exited 0: '$(printf '%s' "$_out" | head -1)'"
		return
	fi
	for _p in $(row_pids "$_d/one.pid"); do
		alive "$_p" || continue
		grep -q "cannot identify $_p" "$_d/stop.err" || {
			fail_c "live row $_p was neither stopped nor named: $(head -1 "$_d/stop.err")"
			return
		}
	done
	pass_c
}

# ------------------------------------------------------------------ driver

run_case 4.1 4 "a zombie is skipped, not counted as stopped" case_4_1
run_case 4.2 4 "stopped N counts processes, not lines" case_4_2
run_case 15.1 15 "stop --dry-run is refused and signals nothing" case_15_1
run_case 15.2 15 "stop --plan prints and signals nothing" case_15_2
run_case 22.1 22 "a one-field line does not kill an unrelated psgen" case_22_1
run_case 22.2 22 "a one-field line stops or names every live row" case_22_2

if [ "$RAN" = 0 ]; then
	echo "stop.sh: no case matched '$SELECTED'" >&2
	exit 2
fi

if [ "$FAILS" -gt 0 ]; then
	exit 1
fi
exit 0
