#!/bin/sh
# Per-issue proof harness: injection, its staging directories, and the stub's
# config channel.
#
#   sh tests/proof_cases/inject.sh <binary> [issue ...]
#
# Covers issues #5, #14, #18 and #25. Each case prints one line — `PASS <n>
# <what>`, `FAIL <n> <what>: <why>` or `SKIP <n> <what>: <why>` — and the
# script exits non-zero when any case failed.
#
# The rule the suite already enforces (DESIGN.md §4) applies to this file: a
# check that cannot fail is worse than no check. Every case here is written
# against a reference the tool does not own — `/proc` and the state the kernel
# shows, the filesystem after the run has exited, a process `psgen` did not
# start — and each one fails on `bf80156`, the commit the fixes branch from. A
# case that needs a host capability this machine lacks prints SKIP with the
# reason; with PSGEN_REQUIRE_ALL=1 that same absence is a failure, so a release
# gate cannot pass on a host where the case never ran.
#
# Everything the cases start lives under `$TMP`: `TMPDIR` is pointed at it, so
# the staging directories `inject` creates are inside it too, and `cleanup`
# kills every banked PID and removes the tree from the exit trap.
set -u

LC_ALL=C
export LC_ALL

if [ $# -lt 1 ]; then
	echo "usage: sh tests/proof_cases/inject.sh <binary> [issue ...]" >&2
	exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BIN_ARG=$1
shift
SELECTED=$*

[ -x "$BIN_ARG" ] || {
	echo "inject.sh: $BIN_ARG is not an executable" >&2
	exit 2
}
case $BIN_ARG in
	/*) BIN=$BIN_ARG ;;
	*) BIN=$(CDPATH= cd -- "$(dirname -- "$BIN_ARG")" && pwd)/$(basename -- "$BIN_ARG") ;;
esac

TMP=$(mktemp -d) || {
	echo "inject.sh: cannot create a temp directory" >&2
	exit 2
}
# `inject` stages under the system temp directory. Pointing it here keeps every
# staging directory inside the tree `cleanup` removes, and lets issue #5's
# prune find the leftovers of the case's own runs.
TMPDIR=$TMP
export TMPDIR

# The tree the binary came from, which is a different tree when the proof is
# run against the pre-fix binary. The seccomp helper is read from there first,
# so a checkout proves itself against its own tests.
SRC=${PSGEN_SRC:-}
if [ -z "$SRC" ]; then
	_bin_dir=$(dirname -- "$BIN")
	case $_bin_dir in
		*/target/*) SRC=$(CDPATH= cd -- "$_bin_dir/../.." && pwd) ;;
		*) SRC=$ROOT ;;
	esac
fi

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

# tmo <seconds> <command...> — timeout(1) when the host has it. A run that
# hangs is a failed case, not a harness that never ends.
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
# space in it does not shift them. `state` is 1, `ppid` is 2, `pgrp` is 3,
# `session` is 4.
proc_fields() {
	sed -n 's/^[0-9]* (.*) //p' "/proc/$1/stat" 2>/dev/null
}

proc_state() { proc_fields "$1" | cut -d' ' -f1; }

proc_ppid() { proc_fields "$1" | cut -d' ' -f2; }

proc_sid() { proc_fields "$1" | cut -d' ' -f4; }

# The tool's own definition of alive: a zombie is already dead. The local is
# named for the helper: `_s` belongs to the callers that hold a staging root.
alive() {
	_alive_state=$(proc_state "$1")
	[ -n "$_alive_state" ] && [ "$_alive_state" != Z ]
}

row_pids() {
	awk '!/^#/ && NF { print $1 }' "$1" 2>/dev/null
}

# wait_dead <pid> — a signalled process needs a moment to stop being alive.
wait_dead() {
	_i=0
	while alive "$1" && [ "$_i" -lt 30 ]; do
		sleep 0.1
		_i=$((_i + 1))
	done
	! alive "$1"
}

# stop_pidfile <path> — stop a run without masking its exit status.
stop_pidfile() {
	[ -f "$1" ] || return 0
	tmo 30 "$BIN" stop --pidfile "$1" >/dev/null 2>&1
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
	_pg=$(proc_fields "$1" | cut -d' ' -f3)
	if [ -n "$_pg" ] && [ "$_pg" = "$1" ]; then
		kill -9 "-$1" 2>/dev/null
	fi
	kill -9 "$1" 2>/dev/null
}

cleanup() {
	trap - EXIT INT TERM HUP
	# A pidfile this run wrote names the processes it started, even when the
	# case failed between the spawn and its own stop.
	for _f in "$TMP"/*.pid; do
		[ -f "$_f" ] || continue
		_pids=$(row_pids "$_f")
		[ -n "$_pids" ] || continue
		stop_pidfile "$_f"
		# stop may have refused a line; the bank below still kills it.
		for _p in $_pids; do bank "$_p"; done
	done
	if [ -f "$TMP/stub-pids" ]; then
		while read -r _p; do
			[ -n "$_p" ] || continue
			alive "$_p" || continue
			kill_tree "$_p"
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

# ---------------------------------------------------------------- issue #5
# A `--duration` run that nobody stops leaks its staging directories: the
# shadow copy in the run's shadow root and the `--disk` data in TMPDIR. The
# next `inject` has to reclaim them — and has to keep a run whose stubs are
# still alive, which is the half a destructive prune would get wrong.
#
# The reference is the filesystem: a directory exists or it does not, after the
# run that was supposed to remove it has exited. `inject`'s own "pruned N"
# line is only diagnostics.
# The processes a staged run left behind: the PIDs its pidfile names and the
# ones its stubs recorded in `.psgen-live` before they exec'd. The marker is
# what the prune itself consults, so waiting for those PIDs to leave `/proc`
# is waiting for the exact fact the next run will read — a stub that is still
# a zombie is still an entry, and a prune that runs in that window keeps the
# directory.
expired_pids() {
	{
		row_pids "$_exp"
		while IFS= read -r _d; do
			[ -f "$_d/.psgen-live" ] || continue
			awk '{ print $1 }' "$_d/.psgen-live"
		done <"$TMP/5-expired.dirs"
	} | sort -u
}

case_5() {
	_s=$TMP/5-shadow
	_live=$TMP/5-live.pid
	_exp=$TMP/5-expired.pid
	mkdir -p "$_s" || {
		fail_c "cannot create the staging root $_s"
		return
	}
	# A: still running, 60 s out. Its staging must survive the prune below.
	_err=$(tmo 60 "$BIN" inject -n 2 -s 3 -d 60 --no-root --shadow-dir "$_s" \
		--disk 1 --pidfile "$_live" -q 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "the live run exited $_rc: $(printf '%s' "$_err" | head -1)"
		return
	fi
	bank $(row_pids "$_live")
	ls -d "$_s"/.psgen-* 2>/dev/null >"$TMP/5-live.dirs"
	_live_n=$(awk 'END { print NR }' "$TMP/5-live.dirs")
	if [ "$_live_n" -eq 0 ]; then
		stop_pidfile "$_live"
		fail_c "the live run created no shadow staging directory to keep"
		return
	fi

	# C: a timed run nobody stops. The stubs arm their own alarm on start.
	_err=$(tmo 60 "$BIN" inject -n 3 -s 7 -d 1 --no-root --shadow-dir "$_s" \
		--disk 1 --pidfile "$_exp" -q 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		stop_pidfile "$_live"
		fail_c "the timed run exited $_rc: $(printf '%s' "$_err" | head -1)"
		return
	fi
	{
		grep '^# temp ' "$_exp" | sed 's/^# temp //'
		# The shadow root is not in the pidfile: whatever appeared under it
		# after A started is C's.
		ls -d "$_s"/.psgen-* 2>/dev/null
	} | sort -u >"$TMP/5-expired.all"
	: >"$TMP/5-expired.dirs"
	while IFS= read -r _d; do
		[ -n "$_d" ] || continue
		grep -qxF "$_d" "$TMP/5-live.dirs" 2>/dev/null ||
			printf '%s\n' "$_d" >>"$TMP/5-expired.dirs"
	done <"$TMP/5-expired.all"
	_exp_n=$(awk 'END { print NR }' "$TMP/5-expired.dirs")
	if [ "$_exp_n" -eq 0 ]; then
		stop_pidfile "$_live"
		fail_c "the timed run created no staging directory to reclaim"
		return
	fi

	# Wait for the alarm rather than guess at it: a prune that runs while a
	# stub is still in `/proc` keeps that stub's directory, and that is not the
	# defect. The wait covers the children the marker names as well as the
	# roots the pidfile names.
	_i=0
	_c_left=0
	while [ "$_i" -lt 100 ]; do
		_c_left=0
		for _p in $(expired_pids); do
			# A zombie is already dead: the timed run is reclaimed when no
			# non-zombie is left, and PID 1 may not reap on this host.
			alive "$_p" && _c_left=$((_c_left + 1))
		done
		[ "$_c_left" -eq 0 ] && break
		sleep 0.1
		_i=$((_i + 1))
	done
	if [ "$_c_left" -ne 0 ]; then
		stop_pidfile "$_live"
		fail_c "$_c_left stub(s) of the timed run were still in /proc 10 s after a 1 s lifetime"
		return
	fi
	_err=$(tmo 60 "$BIN" inject -n 1 -s 1 -d 1 --no-root --shadow-dir "$_s" \
		--pidfile "$TMP/5-next.pid" -q 2>&1 >/dev/null)
	_rc=$?
	stop_pidfile "$TMP/5-next.pid"
	if [ "$_rc" -ne 0 ]; then
		stop_pidfile "$_live"
		fail_c "the next inject exited $_rc: $(printf '%s' "$_err" | head -1)"
		return
	fi

	_left=0
	while IFS= read -r _d; do
		[ -n "$_d" ] || continue
		[ -e "$_d" ] && _left=$((_left + 1))
	done <"$TMP/5-expired.dirs"
	_gone=0
	while IFS= read -r _d; do
		[ -n "$_d" ] || continue
		[ -e "$_d" ] || _gone=$((_gone + 1))
	done <"$TMP/5-live.dirs"
	_dead=0
	for _p in $(row_pids "$_live"); do
		alive "$_p" || _dead=$((_dead + 1))
	done
	stop_pidfile "$_live"

	if [ "$_left" -ne 0 ]; then
		fail_c "the next inject left $_left of $_exp_n staging directories of a run that ended: $(sed -n '1p' "$TMP/5-expired.dirs")"
		return
	fi
	if [ "$_gone" -ne 0 ]; then
		fail_c "the prune removed $_gone of $_live_n staging directories of a run whose stubs were alive"
		return
	fi
	if [ "$_dead" -ne 0 ]; then
		fail_c "the live run lost $_dead stub(s) while the next inject ran"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #14
# `inject --pidfile` used to abort in `random_hex16` after every stub had been
# spawned: `getrandom` fails, the 8-byte fallback is copied into a 4-byte
# slice, and `panic = "abort"` ends the process with no pidfile, no summary and
# no way to stop what it started. A seccomp filter that answers EPERM for
# `getrandom` is the same failure a locked-down container produces.
#
# The reference is what a caller can still do afterwards: the pidfile exists,
# the PIDs in it match live processes, `stop` exits 0 and those PIDs die.
case_14() {
	have cc || {
		skip_c "no cc to build the seccomp helper"
		return
	}
	_helper=$SRC/tests/helpers/deny_syscall.c
	[ -f "$_helper" ] || _helper=$ROOT/tests/helpers/deny_syscall.c
	[ -f "$_helper" ] || {
		skip_c "tests/helpers/deny_syscall.c is not in this tree"
		return
	}
	_deny=$TMP/14-deny
	if ! cc -O2 -o "$_deny" "$_helper" 2>"$TMP/14-cc.err"; then
		skip_c "cannot build the seccomp helper: $(head -1 "$TMP/14-cc.err")"
		return
	fi
	_pf=$TMP/14.pid
	_err=$(tmo 60 "$_deny" getrandom "$BIN" inject -n 2 -s 7 -d 3 \
		--no-root --shadow-dir "$TMP/14-shadow" --pidfile "$_pf" \
		--no-user --no-mem --no-tty --no-threads -q 2>&1 >/dev/null)
	_rc=$?
	case $_rc in
		126 | 127)
			skip_c "cannot execute the seccomp helper from $TMP"
			return
			;;
	esac
	case $_err in
		*prctl*)
			skip_c "cannot install a seccomp filter here: $(printf '%s' "$_err" | head -1)"
			return
			;;
	esac
	if [ "$_rc" -ne 0 ]; then
		# The abort lands after the spawn, so the stubs are running and no
		# pidfile names them. They carry -d 3; wait them out rather than
		# return with processes this case started still alive.
		sleep 4
		fail_c "a denied getrandom aborted the run (exit $_rc): $(printf '%s\n' "$_err" | grep -m1 .)"
		return
	fi
	if [ ! -f "$_pf" ]; then
		stop_pidfile "$_pf"
		sleep 4
		fail_c "a denied getrandom spawned stubs and wrote no pidfile"
		return
	fi
	head -1 "$_pf" | grep -q '^# psgen' || {
		stop_pidfile "$_pf"
		fail_c "the pidfile has no psgen header: $(head -1 "$_pf")"
		return
	}
	_pids=$(row_pids "$_pf")
	bank $_pids
	if [ -z "$_pids" ]; then
		stop_pidfile "$_pf"
		fail_c "the pidfile records no PID"
		return
	fi
	for _p in $_pids; do
		if ! alive "$_p"; then
			stop_pidfile "$_pf"
			fail_c "the pidfile names $_p, which is not running"
			return
		fi
	done
	_out=$(tmo 30 "$BIN" stop --pidfile "$_pf" 2>&1)
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "stop --pidfile exited $_rc: $(printf '%s' "$_out" | head -1)"
		return
	fi
	for _p in $_pids; do
		if ! wait_dead "$_p"; then
			fail_c "stop reported success and left $_p running"
			return
		fi
	done
	pass_c
}

# --------------------------------------------------------------- issue #18
# The postmaster forks every backend and background worker, so they share its
# session and process group and are never session leaders. `F_SESSION` used to
# mean three different things, and the db rows all carried it: every backend
# was rendered `Ss` and spawned with `setsid`.
#
# The reference is `/proc/PID/stat` (sid == pid is a session leader) and `ps`,
# which derives the `s` in STAT from the same fact.

# The commands `-f db` draws are the postmaster and the `postgres: 17/main:`
# workers. A draw that contains no worker cannot demonstrate anything.
# A cross binary runs under qemu-user in the release smoke, where /proc reports
# the emulator's argv rather than the command psgen set. The cases that match a
# planned row with a live one cannot do that there, so they say so instead of
# failing on the emulator's shape.
emulated() {
	[ "$(uname -m)" = "unknown" ] && return 1
	have readelf || return 1
	_m=$(readelf -h "$BIN" 2>/dev/null | sed -n 's/^ *Machine: *//p' | head -1)
	case "$(uname -m):$_m" in
	x86_64:Advanced*Micro*Devices*X86-64) return 1 ;;
	aarch64:AArch64) return 1 ;;
	i686:Intel*80386|i386:Intel*80386) return 1 ;;
	*) return 0 ;;
	esac
}

case_18_1() {
	if emulated; then
		skip_c "the emulator rewrites argv, so a planned row cannot be matched"
		return
	fi
	_tbl=$(tmo 60 "$BIN" table -f db -n 20 -s 1 2>"$TMP/18t.err")
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "table -f db exited $_rc: $(head -1 "$TMP/18t.err")"
		return
	fi
	_workers=$(printf '%s\n' "$_tbl" | grep -c 'postgres: 17/main:')
	if [ "$_workers" -eq 0 ]; then
		skip_c "the draw contained no postgres backend"
		return
	fi
	# STAT is the eighth column; COMMAND starts at the eleventh and carries
	# spaces, so it is rebuilt rather than matched field by field.
	_bad=$(printf '%s\n' "$_tbl" | awk '
		NR > 1 {
			stat = $8
			cmd = ""
			for (i = 11; i <= NF; i++) cmd = cmd " " $i
			if (cmd ~ /^ postgres: 17\/main:/ && index(stat, "s") != 0)
				printf "%s(%s) ", $2, stat
		}')
	if [ -n "$_bad" ]; then
		fail_c "table -f db renders $_workers postgres backends as session leaders: $_bad"
		return
	fi
	# ...and the postmaster itself is one, so the fix did not drop the flag
	# everywhere and call it done. A draw without the postmaster row cannot
	# show that, so the check is asked only when the row is there.
	_master=$(printf '%s\n' "$_tbl" | awk '
		NR > 1 {
			cmd = ""
			for (i = 11; i <= NF; i++) cmd = cmd " " $i
			if (cmd ~ /bin\/postgres -D/) {
				rows++
				if (index($8, "s") != 0) with_s++
			}
		}
		END { printf "%d %d", rows, with_s }')
	_m_rows=${_master% *}
	_m_with=${_master#* }
	if [ "$_m_rows" -gt 0 ] && [ "$_m_with" -eq 0 ]; then
		fail_c "the postmaster row is not a session leader either, so the flag was removed rather than split"
		return
	fi
	pass_c
}

case_18_2() {
	if emulated; then
		skip_c "the emulator rewrites argv, so a planned row cannot be matched"
		return
	fi
	_pf=$TMP/18.pid
	_err=$(tmo 60 "$BIN" inject -f db -n 12 -s 1 --no-root --no-user --no-mem \
		--no-tty --no-threads --pidfile "$_pf" -q 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "inject -f db exited $_rc: $(printf '%s' "$_err" | head -1)"
		return
	fi
	_pids=$(row_pids "$_pf")
	bank $_pids
	if [ -z "$_pids" ]; then
		stop_pidfile "$_pf"
		fail_c "the run recorded no stub"
		return
	fi
	_master=
	_workers=0
	for _p in $_pids; do
		if ! alive "$_p"; then
			stop_pidfile "$_pf"
			fail_c "stub $_p exited during the case"
			return
		fi
		_cmd=$(tr '\0' ' ' <"/proc/$_p/cmdline" 2>/dev/null)
		case $_cmd in
			*"bin/postgres -D"*) _master=$_p ;;
			"postgres: 17/main:"*) _workers=$((_workers + 1)) ;;
		esac
	done
	if [ "$_workers" -eq 0 ]; then
		stop_pidfile "$_pf"
		skip_c "the draw contained no postgres backend"
		return
	fi
	_bad=
	for _p in $_pids; do
		_cmd=$(tr '\0' ' ' <"/proc/$_p/cmdline" 2>/dev/null)
		case $_cmd in
			"postgres: 17/main:"*) ;;
			*) continue ;;
		esac
		_sid=$(proc_sid "$_p")
		_ppid=$(proc_ppid "$_p")
		_pstat=$(ps -o stat= -p "$_p" 2>/dev/null | tr -d ' ')
		if [ "$_sid" = "$_p" ]; then
			_bad="$_bad $_p(session leader: sid=$_sid)"
		fi
		case $_pstat in
			*s*) _bad="$_bad $_p(STAT=$_pstat)" ;;
		esac
		if [ -n "$_master" ] && [ "$_ppid" != "$_master" ]; then
			_bad="$_bad $_p(ppid=$_ppid, not $_master)"
		fi
	done
	stop_pidfile "$_pf"
	if [ -n "$_bad" ]; then
		fail_c "postgres backends are not the postmaster's children in its session:$_bad"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #25
# The stub's entry point used to accept any inherited fd 3 whose first eight
# bytes were the config magic, and the config names a `self_copy` to exec and a
# `temp` directory to create. That is a code-execution primitive for whatever
# can hand the process a descriptor.
#
# The reference is the effect: a config that was honoured leaves a process
# running with the config's lifetime and a file the config's `self_copy`
# wrote. A config that was refused leaves neither.
#
# The wire format changed with the fix (`PGCFG021`/2 -> `PGCFG023`/3), so a
# probe that speaks only the current format would pass on the pre-fix binary
# for the wrong reason: it would be rejected at the version check, not at the
# descriptor. Each case therefore probes the format the binary under test is
# most likely to speak, and 25.1 probes both.

# stray_config <effect|refused> — print one line per problem, nothing when the
# probes found none.
stray_config() {
	_mode=$1
	python3 - "$BIN" "$TMP/25" "$_mode" <<'PY'
import os, shlex, shutil, struct, subprocess, sys

bin_, d, mode = sys.argv[1:4]
nonce = "deadbeefdeadbeef"
sentinel = os.path.join(d, "sentinel")
selfcopy = os.path.join(d, "self.sh")

os.makedirs(d, exist_ok=True)
with open(selfcopy, "w") as f:
    f.write("#!/bin/sh\n: >%s\nexec sleep 30\n" % shlex.quote(sentinel))
os.chmod(selfcopy, 0o755)

# The header is the u32 fields `read_config` reads, in its order. Version 2
# ends at `self_len`; version 3 appends `nonce_len` and a reserved word.
def encode(ver, temp):
    comm = b"psgenproof25"
    exe = b""
    cmd = b"psgenproof25"
    user = b""
    hdr = b"PGCFG02" + (b"1" if ver == 2 else b"3")
    hdr += struct.pack("<I", ver)
    for v in (0, 0, 0, 0, 0, 0, 0, 0,
              len(comm), len(exe), len(cmd), len(user), len(temp.encode()),
              0, 0):
        hdr += struct.pack("<I", v)
    hdr += struct.pack("<iii", 5, -1, -1)
    hdr += struct.pack("<I", 1)          # id
    hdr += struct.pack("<I", 1)          # disk_kb: the write primitive
    hdr += struct.pack("<I", len(selfcopy.encode()))
    if ver == 3:
        hdr += struct.pack("<I", len(nonce.encode()))
        hdr += struct.pack("<I", 0)
    assert len(hdr) == (96 if ver == 2 else 104), len(hdr)
    body = comm + exe + cmd + user + temp.encode() + selfcopy.encode()
    if ver == 3:
        body += nonce.encode()
    return hdr + body

def first_line(text):
    for line in text.splitlines():
        if line.strip():
            return line
    return ""

def probe(label, ver, unlink):
    temp = os.path.join(d, "attack-" + label)
    path = os.path.join(d, "cfg-" + label)
    with open(path, "wb") as f:
        f.write(encode(ver, temp))
    fd = os.open(path, os.O_RDWR)
    if fd != 3:
        os.dup2(fd, 3)
        os.close(fd)
    if unlink:
        os.unlink(path)
    env = dict(os.environ)
    env["PSGEN_NONCE"] = nonce
    timed_out = False
    try:
        p = subprocess.run([bin_], pass_fds=(3,), env=env, timeout=6,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        rc = p.returncode
        err = p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        timed_out = True
        rc = None
        err = (e.stderr or b"").decode("utf-8", "replace")
    finally:
        os.close(3)

    acted = []
    if timed_out:
        acted.append("it was still running after 6 s, as a stub is")
    if os.path.exists(sentinel):
        acted.append("it executed the config's self_copy")
    if os.path.isdir(temp):
        acted.append("it created the config's temp directory")
    detail = ("%s: rc=%s timed_out=%s sentinel=%s temp=%s stderr=%r" %
              (label, rc, timed_out, os.path.exists(sentinel), os.path.isdir(temp),
               first_line(err)))
    if os.path.exists(sentinel):
        os.unlink(sentinel)
    if os.path.isdir(temp):
        shutil.rmtree(temp)
    return acted, rc, err, detail

if mode == "effect":
    specs = [("parent-format", 2, False), ("current-format", 3, True)]
else:
    specs = [("current-format", 3, True)]

problems = []
details = []
for label, ver, unlink in specs:
    acted, rc, err, detail = probe(label, ver, unlink)
    details.append(detail)
    if acted:
        problems.append("%s: %s" % (label, "; ".join(acted)))
        continue
    if mode == "refused":
        if rc != 2:
            problems.append("%s: the config was not refused (exit %s)" % (label, rc))
        elif "config descriptor" not in err or "sealed memfd" not in err:
            problems.append("%s: the refusal does not name the descriptor: %r"
                            % (label, first_line(err)))

# A passing run stays quiet; a failing one carries the state of every probe.
if problems:
    print("\n".join(details), file=sys.stderr)
print("\n".join(problems))
sys.exit(1 if problems else 0)
PY
}

case_25_1() {
	have python3 || {
		skip_c "no python3 to build a config and hand it in on fd 3"
		return
	}
	_errs=$(stray_config effect)
	_rc=$?
	if [ "$_rc" -ne 0 ] && [ -z "$_errs" ]; then
		fail_c "the fd-3 probe did not run (exit $_rc)"
		return
	fi
	if [ -n "$_errs" ]; then
		say "  #25.1 diagnostics:"
		printf '%s\n' "$_errs" | sed 's/^/    /' >&2
		fail_c "$(printf '%s' "$_errs" | head -1)"
		return
	fi
	pass_c
}

case_25_2() {
	have python3 || {
		skip_c "no python3 to build a config and hand it in on fd 3"
		return
	}
	_errs=$(stray_config refused)
	_rc=$?
	if [ "$_rc" -ne 0 ] && [ -z "$_errs" ]; then
		fail_c "the fd-3 probe did not run (exit $_rc)"
		return
	fi
	if [ -n "$_errs" ]; then
		say "  #25.2 diagnostics:"
		printf '%s\n' "$_errs" | sed 's/^/    /' >&2
		fail_c "$(printf '%s' "$_errs" | head -1)"
		return
	fi
	pass_c
}

# ------------------------------------------------------------------ driver

run_case 5 5 "a timed run nobody stops is reclaimed by the next inject" case_5
run_case 14 14 "a denied getrandom leaves a pidfile and a stoppable run" case_14
run_case 18.1 18 "table -f db does not make postgres backends session leaders" case_18_1
run_case 18.2 18 "injected postgres backends stay in the postmaster's session" case_18_2
run_case 25.1 25 "a config on fd 3 is not honoured" case_25_1
run_case 25.2 25 "a config descriptor outside the injector is refused" case_25_2

if [ "$RAN" = 0 ]; then
	echo "inject.sh: no case matched '$SELECTED'" >&2
	exit 2
fi

if [ "$FAILS" -gt 0 ]; then
	exit 1
fi
exit 0
