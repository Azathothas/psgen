#!/bin/sh
# Per-issue proof harness: the rendered-table surface.
#
#   sh tests/proof_cases/table.sh <binary> [issue ...]
#
# Covers issues #3, #12 and #17. Each case prints one line — `PASS <n> <what>`,
# `FAIL <n> <what>: <why>` or `SKIP <n> <what>: <why>` — and the script exits
# non-zero when any case failed.
#
# The rule the suite already enforces (DESIGN.md §4) applies to this file: a
# check that cannot fail is worse than no check. Every case here is written
# against a reference the tool does not own — `ps`, the kernel's own
# `/proc/<pid>/exe`, the filesystem, the host's clock — and each one fails on
# `bf80156`, the commit the fixes branch from. A case that needs a host
# capability this machine lacks prints SKIP with the reason; with
# PSGEN_REQUIRE_ALL=1 that same absence is a failure, so a release gate cannot
# pass on a host where the case never ran.
#
# The fixtures are a python process per case (a line break in argv, a zombie, a
# wide VSZ), and every one is banked for the exit trap. Every inject run records
# its pidfile under $TMP, which the trap stops even when the case failed before
# reaching its own `stop`; `stop` is also what removes the bind-tier temp
# directory a run creates under the caller's TMPDIR, which is the only thing
# here that lands outside $TMP.
set -u

LC_ALL=C
export LC_ALL

if [ $# -lt 1 ]; then
	echo "usage: sh tests/proof_cases/table.sh <binary> [issue ...]" >&2
	exit 2
fi

BIN_ARG=$1
shift
SELECTED=$*

[ -x "$BIN_ARG" ] || {
	echo "table.sh: $BIN_ARG is not an executable" >&2
	exit 2
}
case $BIN_ARG in
	/*) BIN=$BIN_ARG ;;
	*) BIN=$(CDPATH= cd -- "$(dirname -- "$BIN_ARG")" && pwd)/$(basename -- "$BIN_ARG") ;;
esac

TMP=$(mktemp -d) || {
	echo "table.sh: cannot create a temp directory" >&2
	exit 2
}

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

# tmo <seconds> <command...> — timeout(1) when the host has it.
tmo() {
	_t=$1
	shift
	if have timeout; then
		timeout "$_t" "$@"
	else
		"$@"
	fi
}

# stop_pidfile <path> — stop a run without masking its exit status.
stop_pidfile() {
	[ -f "$1" ] || return 0
	"$BIN" stop --pidfile "$1" >/dev/null 2>&1
}

cleanup() {
	trap - EXIT INT TERM HUP
	# Every inject run in this file writes its pidfile under $TMP, so a case
	# that failed before its own stop is still reaped here. `stop` also removes
	# the bind-tier temp directory the run created outside $TMP.
	for _pf in "$TMP"/*.pid "$TMP"/*/*.pid; do
		[ -f "$_pf" ] || continue
		stop_pidfile "$_pf"
		sed -n 's/^# temp //p' "$_pf" 2>/dev/null | while read -r _d; do
			case $_d in
				*/.psgen-*) rm -rf "$_d" ;;
			esac
		done
	done
	if [ -f "$TMP/fixture-pids" ]; then
		while read -r _p; do
			[ -n "$_p" ] && kill "$_p" 2>/dev/null
		done <"$TMP/fixture-pids"
	fi
	rm -rf "$TMP"
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

# --------------------------------------------------------------- fixtures

# bank_pid <pid> — remember a process this script started, so the exit trap can
# kill it even when the case exited early.
bank_pid() {
	[ -n "$1" ] || return 0
	printf '%s\n' "$1" >>"$TMP/fixture-pids"
}

# wait_ready <path> — poll for a file a fixture writes, up to 5 s.
wait_ready() {
	_i=0
	while [ ! -s "$1" ] && [ "$_i" -lt 50 ]; do
		sleep 0.1
		_i=$((_i + 1))
	done
	[ -s "$1" ]
}

# pids_of <pidfile> — the stub pids a run recorded, in file order.
pids_of() {
	awk '!/^#/ && NF { print $1 }' "$1"
}

# wait_pids <pidfile> <count> — poll until the run has recorded <count> pids.
wait_pids() {
	_i=0
	while [ "$_i" -lt 100 ]; do
		_n=$(pids_of "$1" | grep -c .)
		[ "$_n" -ge "$2" ] && return 0
		sleep 0.1
		_i=$((_i + 1))
	done
	return 1
}

# ------------------------------------------------------- table inspection

# aux_shape <file> — the first line that is not a `ps aux` row, or nothing.
#
# Ten fixed columns is what a consumer of this table parses, and the failure
# #3a describes is that a raw line break in COMMAND splits one row into two:
# the remainder has no PID in field 2 and no numbers in fields 3..6. That is
# visible here without a reference implementation.
aux_shape() {
	awk '
	NR == 1 { next }
	$2 !~ /^[0-9]+$/ ||
	$3 !~ /^[0-9]+(\.[0-9])?$/ ||
	$4 !~ /^[0-9]+\.[0-9]$/ ||
	$5 !~ /^[0-9]+$/ ||
	$6 !~ /^[0-9]+$/ {
		printf "line %d is not a table row (%s)\n", NR, substr($0, 1, 48)
		exit
	}' "$1"
}

# aux_cmd <file> <pid> — the COMMAND field of one pid's row, taken at the
# header's own COMMAND offset so a row shifted right cannot pass by luck.
aux_cmd() {
	awk -v want="$2" '
	NR == 1 { off = index($0, "COMMAND"); next }
	off < 1 { next }
	$2 == want { print substr($0, off) }
	' "$1"
}

# aux_cols <file> <pid> — the byte offsets of the STAT, START, TIME and COMMAND
# tokens of one pid's row, in that order.
aux_cols() {
	awk -v want="$2" '
	{
		n = 0; pos = 1; len = length($0); pid = ""
		while (n < 11 && pos <= len) {
			while (pos <= len && substr($0, pos, 1) == " ") pos++
			start = pos
			while (pos <= len && substr($0, pos, 1) != " ") pos++
			n++
			if (n == 2) pid = substr($0, start, pos - start)
			if (n >= 8) col[n] = start
		}
		if (pid == want) printf "%d %d %d %d\n", col[8], col[9], col[10], col[11]
	}' "$1"
}

# aux_pids <file> — the pids of every row, in the order the table printed them.
aux_pids() {
	awk 'NR > 1 && $2 ~ /^[0-9]+$/ { print $2 }' "$1"
}

# plan_tsv <plan|json> <out> — one line per planned row:
#
#   vsz rss cpu tty threads user parent
#
# `tty`/`threads` stay the plan's own yes/no words and `parent` is the row index
# the plan links to or `-`. Both encoders describe the same facts, so the
# comparison below reads one shape whichever one the case asked for.
plan_tsv() {
	case $1 in
		plan)
			awk '$1 == "row" {
				par = "-"
				vsz = rss = cpu = tty = thr = user = ""
				for (i = 3; i <= NF; i++) {
					eq = index($i, "=")
					if (!eq) continue
					k = substr($i, 1, eq - 1)
					v = substr($i, eq + 1)
					if (k == "vsz") vsz = v
					else if (k == "rss") rss = v
					else if (k == "cpu") cpu = v
					else if (k == "tty") tty = v
					else if (k == "threads") thr = v
					else if (k == "user") user = v
					else if (k == "parent") par = v
				}
				print vsz, rss, cpu, tty, thr, user, par
			}' "$2" >"$3"
			;;
		json)
			python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception as e:
    print("ERR the document is not one JSON object: %s" % e)
    raise SystemExit(0)
print("TIER", d.get("tier"))
print("STUBS", d.get("stubs"))
print("ROOTS", d.get("roots"))
print("ROWS", len(d.get("rows") or []))
for r in d.get("rows") or []:
    cpu = "%d.%d" % (int(r["cpu_tenths"]) // 10, int(r["cpu_tenths"]) % 10)
    print("%s %s %s %s %s %s %s" % (
        r["vsz_kb"], r["rss_kb"], cpu,
        "yes" if r["tty"] else "no",
        "yes" if r["threads"] else "no",
        r["user"],
        "-" if r["parent"] is None else r["parent"]))
' <"$2" >"$3"
			;;
	esac
}

# real_tsv <pidfile> <out> — one line per recorded stub, from /proc:
#
#   pid ppid vsz rss pcpu tty nlwp user
#
# The values come from the kernel, never from psgen: `ps` reads the same
# `/proc` entries, and PPid is the link the plan claims for a child row.
real_tsv() {
	: >"$2"
	for _p in $(pids_of "$1"); do
		ps -o pid=,ppid=,vsz=,rss=,pcpu=,tty=,nlwp=,user= -p "$_p" 2>/dev/null |
			awk '{ printf "%d %d %d %d %s %s %d %s\n", $1, $2, $3, $4, $5, $6, $7, $8 }' >>"$2"
	done
}

# plan_vs_proc <plan.tsv> <real.tsv> — every planned row must name one real
# process and nothing else: same VSZ, RSS, CPU, user, tty and thread count, and
# the real parent of a child row must be the stub the plan linked it to.
#
# A row is identified by the VSZ/RSS pair it says it will have, taking the
# nearest stub rather than the first inside a window: RSS moves while the run
# settles (a stub touches one more page on the busy path, and the kernel can
# reclaim a page under load), and two rows of one family differ by less than
# that. The tolerance is the project's own `--verify` bound, so a plan value
# that is wrong by anything a caller would notice is still rejected. Prints one
# line per disagreement and exits non-zero.
plan_vs_proc() {
	awk -v tol=128 -v cputol=15 '
	FNR == NR {
		n++
		pv[n] = $1; pr[n] = $2; pc[n] = $3; pt[n] = $4
		ph[n] = $5; pu[n] = $6; pp[n] = $7
		next
	}
	{
		r++
		rp[r] = $1; rpar[r] = $2; rv[r] = $3; rr[r] = $4
		rc[r] = $5; rt[r] = $6; rn[r] = $7; ru[r] = $8
	}
	END {
		bad = 0
		if (n == 0) {
			print "the plan named no rows"
			exit 1
		}
		if (r == 0) {
			print "the run recorded no stubs"
			exit 1
		}
		for (i = 1; i <= n; i++) {
			best = 0; bestd = -1; bdv = 0; bdr = 0
			for (j = 1; j <= r; j++) {
				dv = pv[i] - rv[j]; if (dv < 0) dv = -dv
				dr = pr[i] - rr[j]; if (dr < 0) dr = -dr
				if (bestd < 0 || dv + dr < bestd) {
					best = j; bestd = dv + dr; bdv = dv; bdr = dr
				}
			}
			if (best == 0) {
				printf "plan row %d has no running stub to describe\n", i - 1
				bad = 1
				continue
			}
			if (best in claimed) {
				printf "plan rows %d and %d both describe pid %s\n",
					claimed[best] - 1, i - 1, rp[best]
				bad = 1
				continue
			}
			claimed[best] = i
			hit[i] = best
			seen[best] = 1
			if (bdv > tol || bdr > tol) {
				printf "plan row %d says vsz %s rss %s, the nearest stub (pid %s) is vsz %s rss %s\n",
					i - 1, pv[i], pr[i], rp[best], rv[best], rr[best]
				bad = 1
				continue
			}
			m = best
			want = (rt[m] == "?") ? "no" : "yes"
			if (pt[i] != want) {
				printf "plan row %d says tty=%s, ps shows %s\n", i - 1, pt[i], rt[m]
				bad = 1
			}
			want = (rn[m] + 0 > 1) ? "yes" : "no"
			if (ph[i] != want) {
				printf "plan row %d says threads=%s, ps shows %d\n", i - 1, ph[i], rn[m]
				bad = 1
			}
			if (pu[i] != ru[m]) {
				printf "plan row %d says user=%s, ps shows %s\n", i - 1, pu[i], ru[m]
				bad = 1
			}
			# The plan states the share the stub will ask for. A busy host
			# delivers less than that -- eight stubs each asking 40% cannot
			# all get it from two cores -- so only an *excess* is a defect.
			dc = rc[m] - pc[i]
			if (dc > cputol) {
				printf "plan row %d says cpu=%s, ps measures %s\n", i - 1, pc[i], rc[m]
				bad = 1
			}
		}
		for (i = 1; i <= n; i++) {
			if (pp[i] == "-" || !(i in hit)) continue
			prow = pp[i] + 1
			if (!(prow in hit)) {
				printf "plan row %d names parent %s, which is not a matched row\n", i - 1, pp[i]
				bad = 1
				continue
			}
			m = hit[i]
			if (rpar[m] != rp[hit[prow]]) {
				printf "plan row %d says its parent is row %s, ps says ppid %s\n",
					i - 1, pp[i], rpar[m]
				bad = 1
			}
		}
		for (i = 1; i <= n; i++) {
			# A row the plan calls a root must not turn out to be a child of
			# another stub: that is the one link the kernel can refute without
			# knowing anything about the scheduler.
			if (pp[i] != "-" || !(i in hit)) continue
			for (k = 1; k <= n; k++) {
				if (k == i || !(k in hit)) continue
				if (rpar[hit[i]] == rp[hit[k]]) {
					printf "plan row %d says it is a root, ps says its parent is row %d\n", i - 1, k - 1
					bad = 1
				}
			}
		}
		for (j = 1; j <= r; j++) {
			if (!(j in seen)) {
				printf "pid %s was spawned but no plan row describes it\n", rp[j]
				bad = 1
			}
		}
		exit bad
	}' "$1" "$2"
}

# ------------------------------------------------------------------ issue #3
# `table --live` and `inject --table` must render the rows `ps aux` renders, on
# the same columns. Each case builds the live process the defect needs and
# compares the two renderers; the reference is `ps`, never psgen itself.

# 3a: a line break or a control byte in argv. `ps` blanks a line break and
# writes `?` for every other non-printable byte, so COMMAND stays one field.
case_3_1() {
	have python3 || {
		skip_c "no python3 to start a process whose argv has a line break"
		return
	}
	_w=$TMP/3_1
	mkdir -p "$_w"
	python3 -c '
import subprocess, sys, time
p = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)",
                      "line1\nline2", "line3"])
print(p.pid, flush=True)
time.sleep(25)
' >"$_w/child.pid" 2>"$_w/start.err" &
	_bg=$!
	bank_pid "$_bg"
	if ! wait_ready "$_w/child.pid"; then
		kill "$_bg" 2>/dev/null
		skip_c "the fixture did not start: $(head -1 "$_w/start.err")"
		return
	fi
	_child=$(head -1 "$_w/child.pid")
	bank_pid "$_child"

	tmo 60 "$BIN" table --live >"$_w/live" 2>"$_w/live.err"
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "table --live exited $_rc: $(head -1 "$_w/live.err")"
		return
	}
	ps -o args= -p "$_child" >"$_w/ps" 2>/dev/null
	_ref=$(head -1 "$_w/ps" | sed 's/ *$//')
	[ -n "$_ref" ] || {
		skip_c "ps printed no COMMAND for pid $_child"
		return
	}
	_mine=$(aux_cmd "$_w/live" "$_child" | sed 's/ *$//')
	_n=$(printf '%s\n' "$_mine" | grep -c .)
	if [ "$_n" -ne 1 ]; then
		fail_c "pid $_child has $_n rows, so the row was split"
		return
	fi
	if [ "$_mine" != "$_ref" ]; then
		say "  ps:   $_ref"
		say "  psgen: $_mine"
		fail_c "COMMAND is not the line ps renders"
		return
	fi
	# No control byte may reach the table: `ps` maps each to `?`, and a raw one
	# is what a column parser drops silently. This is checked as a property
	# rather than against `ps`, because procps renders a tab differently across
	# versions and the reference here is the host's `ps`, not one release.
	_ctl=$(LC_ALL=C grep -n '[[:cntrl:]]' "$_w/live" | head -3)
	if [ -n "$_ctl" ]; then
		fail_c "a control byte reached the table: $(printf '%s' "$_ctl" | head -1)"
		return
	fi
	# ...and no other row may break the table either: a line that is not a row
	# is what a column parser drops silently.
	_junk=$(aux_shape "$_w/live")
	if [ -n "$_junk" ]; then
		fail_c "$_junk"
		return
	fi
	pass_c
}

# 3b: a zombie keeps its /proc entry when its parent does not reap, and `ps`
# marks it in COMMAND. Without the marker a container whose PID 1 does not reap
# is full of rows that do not match.
case_3_2() {
	have python3 || {
		skip_c "no python3 to leave a zombie behind"
		return
	}
	_w=$TMP/3_2
	mkdir -p "$_w"
	python3 -c '
import subprocess, time
p = subprocess.Popen(["sleep", "0.01"])
time.sleep(0.6)
print(p.pid, flush=True)
time.sleep(25)
' >"$_w/zombie.pid" 2>"$_w/start.err" &
	_bg=$!
	bank_pid "$_bg"
	if ! wait_ready "$_w/zombie.pid"; then
		kill "$_bg" 2>/dev/null
		skip_c "the fixture did not start: $(head -1 "$_w/start.err")"
		return
	fi
	_z=$(head -1 "$_w/zombie.pid")

	_state=$(ps -o stat= -p "$_z" 2>/dev/null | tr -d ' ')
	case $_state in
		Z*)
			bank_pid "$_z"
			;;
		*)
			kill "$_bg" 2>/dev/null
			skip_c "the child was reaped (state '${_state:-gone}'), so no zombie exists"
			return
			;;
	esac
	ps -o args= -p "$_z" >"$_w/ps" 2>/dev/null
	_ref=$(head -1 "$_w/ps" | sed 's/ *$//')
	case $_ref in
		*defunct*)
			;;
		*)
			skip_c "this ps does not mark a zombie ('$_ref'), so the reference is unavailable"
			return
			;;
	esac

	tmo 60 "$BIN" table --live >"$_w/live" 2>"$_w/live.err"
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "table --live exited $_rc: $(head -1 "$_w/live.err")"
		return
	}
	_mine=$(aux_cmd "$_w/live" "$_z" | sed 's/ *$//')
	[ -n "$_mine" ] || {
		fail_c "the zombie (pid $_z) has no row"
		return
	}
	if [ "$_mine" != "$_ref" ]; then
		fail_c "the zombie row renders '$_mine', ps renders '$_ref'"
		return
	fi
	pass_c
}

# 3c: `inject --table` renders the rows in the order `ps aux` renders them,
# which is the order `ps` itself lists the pids in, not the order the run
# happened to build its rows.
case_3_3() {
	_w=$TMP/3_3
	mkdir -p "$_w"
	_pf=$_w/stubs.pid
	tmo 90 "$BIN" inject -f web -n 6 -s 5 --duration 30 --pidfile "$_pf" \
		--table >"$_w/table" 2>"$_w/err"
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		stop_pidfile "$_pf"
		fail_c "inject --table exited $_rc: $(head -1 "$_w/err")"
		return
	fi
	_got=$(aux_pids "$_w/table")
	_want=$(pids_of "$_pf" | sort -n)
	# The reference is ps's own listing order, read while the stubs are still
	# running: a stopped pid is not in it, and an empty reference would compare
	# equal to nothing at all.
	_ref=$(ps -eo pid= | awk -v list="$(printf '%s ' $_want)" '
		BEGIN { n = split(list, w, " "); for (i = 1; i <= n; i++) want[w[i]] = 1 }
		want[$1] { print $1 }')
	stop_pidfile "$_pf"
	[ -n "$_got" ] || {
		fail_c "inject --table printed no rows"
		return
	}
	_have=$(printf '%s\n' "$_got" | sort -n)
	if [ "$_want" != "$_have" ]; then
		fail_c "the table lists '$(printf '%s' "$_got" | tr '\n' ' ')' but the run recorded '$(printf '%s' "$_want" | tr '\n' ' ')'"
		return
	fi
	_seq=$(printf '%s\n' "$_got")
	if [ "$_ref" != "$_seq" ]; then
		fail_c "the table prints '$(printf '%s' "$_seq" | tr '\n' ' ')', ps lists '$(printf '%s' "$_ref" | tr '\n' ' ')'"
		return
	fi
	pass_c
}

# 3d: a VSZ wider than its six-column slot. `ps` keeps STAT, START, TIME and
# COMMAND at the header offsets by letting the overflow eat the TTY padding;
# a fixed eight-wide TTY field pushes every column after it to the right. The
# fixture reserves 12 GiB of address space, which costs no memory, and is
# started in its own session so its TTY is `?` — the shape the issue verified.
case_3_4() {
	have python3 || {
		skip_c "no python3 to reserve a wide address space"
		return
	}
	have setsid || {
		skip_c "no setsid to give the fixture a `?` TTY"
		return
	}
	_w=$TMP/3_4
	mkdir -p "$_w"
	setsid python3 -c '
import mmap, os, sys, time
m = mmap.mmap(-1, 12 << 30, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
with open(sys.argv[1], "w") as f:
    f.write(str(os.getpid()))
time.sleep(30)
' "$_w/pid" </dev/null >/dev/null 2>"$_w/start.err" &
	_bg=$!
	bank_pid "$_bg"
	if ! wait_ready "$_w/pid"; then
		kill "$_bg" 2>/dev/null
		skip_c "the wide-VSZ fixture did not start: $(head -1 "$_w/start.err")"
		return
	fi
	_p=$(head -1 "$_w/pid")
	bank_pid "$_p"
	_v=$(sed -n 's/^VmSize:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$_p/status" 2>/dev/null)
	if [ ${#_v} -lt 8 ]; then
		skip_c "the fixture's VSZ is '${_v:-unreadable}' kB, not an eight-digit field"
		return
	fi
	_tty=$(ps -o tty= -p "$_p" 2>/dev/null | tr -d ' ')
	if [ "$_tty" != "?" ]; then
		skip_c "the fixture has tty '$_tty', so the wide row is not the shape the issue names"
		return
	fi

	ps aux >"$_w/ps" 2>"$_w/ps.err"
	tmo 60 "$BIN" table --live >"$_w/live" 2>"$_w/live.err"
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "table --live exited $_rc: $(head -1 "$_w/live.err")"
		return
	}
	_ref=$(aux_cols "$_w/ps" "$_p")
	_mine=$(aux_cols "$_w/live" "$_p")
	if [ -z "$_ref" ] || [ -z "$_mine" ]; then
		skip_c "no row for pid $_p in one of the two tables"
		return
	fi
	if [ "$_mine" != "$_ref" ]; then
		fail_c "STAT/START/TIME/COMMAND start at '$_mine', ps puts them at '$_ref' (a wide VSZ shifted the row)"
		return
	fi
	pass_c
}

# ----------------------------------------------------------------- issue #12
# `inject --dry-run --plan` and `--json` must describe the run the same flags
# would start: the tier, and per row the user, VSZ, RSS, CPU, tty, thread count
# and parent links. The reference is the process table the run actually creates.

# The planned rows and the running stubs have to be joined, and neither the
# pidfile nor the row index is an ordering the run promises (children are
# forked by their parents). A row is therefore identified by the VSZ/RSS pair
# it says it will have, which is unique per row in the fixtures below.
compare_run() { # compare_run <plan.tsv> <real.tsv> <label>
	_diag=$(plan_vs_proc "$1" "$2")
	_rc=$?
	if [ "$_rc" -ne 0 ] || [ -n "$_diag" ]; then
		printf '%s\n' "$_diag" | sed 's/^/  /' >&2
		_why=$(printf '%s\n' "$_diag" | head -1)
		fail_c "$3${_why:+: $_why}"
		return 1
	fi
	return 0
}

# 12.1: the text plan. `-f sys -n 8 -s 4` draws rows with a pty, three of them,
# and a busy CPU target so the per-row CPU is a value the kernel can confirm.
# The default two-column preview has to keep the exact format bench/measure.py
# splits on a tab, which is why the plan is a separate switch.
case_12_1() {
	_w=$TMP/12_1
	mkdir -p "$_w"
	_flags='-f sys -n 8 -s 4 --cpu 40'

	tmo 90 "$BIN" inject $_flags --dry-run >"$_w/plain" 2>"$_w/plain.err"
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "the dry run exited $_rc: $(head -1 "$_w/plain.err")"
		return
	}
	_n=$(grep -c . "$_w/plain")
	if [ "$_n" -ne 8 ]; then
		fail_c "the two-column preview printed $_n rows for -n 8"
		return
	fi
	_bad=$(awk -F'\t' 'NF != 2 { print "line " NR " has " NF " fields: " $0 }' "$_w/plain" | head -1)
	if [ -n "$_bad" ]; then
		fail_c "the preview is no longer two tab-separated columns: $_bad"
		return
	fi

	tmo 90 "$BIN" inject $_flags --dry-run --plan >"$_w/plan" 2>"$_w/plan.err"
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "inject --dry-run --plan exited $_rc: $(head -1 "$_w/plan.err")"
		return
	}
	_nrows=$(awk '$1 == "row"' "$_w/plan" | wc -l)
	if [ "$_nrows" -ne 8 ]; then
		fail_c "the plan named $_nrows rows for -n 8"
		return
	fi
	# The plan states the share the run was asked for, whatever the host can
	# deliver of it, so this is deterministic where the measured value is not.
	_badcpu=$(awk '$1 == "row" { for (i = 1; i <= NF; i++) if ($i ~ /^cpu=/) print $i }' \
		"$_w/plan" | grep -v '^cpu=40\.0$' | head -2)
	if [ -n "$_badcpu" ]; then
		fail_c "the plan does not state the requested --cpu 40: $(printf '%s' "$_badcpu" | tr '\n' ' ')"
		return
	fi
	plan_tsv plan "$_w/plan" "$_w/plan.tsv"

	_pf=$_w/stubs.pid
	tmo 90 "$BIN" inject $_flags --duration 30 --pidfile "$_pf" >"$_w/run.out" 2>"$_w/run.err"
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		stop_pidfile "$_pf"
		fail_c "the real run exited $_rc: $(head -1 "$_w/run.err")"
		return
	fi
	if ! wait_pids "$_pf" 8; then
		stop_pidfile "$_pf"
		fail_c "the real run recorded $(pids_of "$_pf" | grep -c .) of 8 pids"
		return
	fi
	sleep 2
	real_tsv "$_pf" "$_w/real.tsv"
	stop_pidfile "$_pf"
	compare_run "$_w/plan.tsv" "$_w/real.tsv" "the plan does not describe the run" || return
	pass_c
}

# 12.2: the JSON plan. One object, the same rows, and the parent links checked
# against the kernel's PPid rather than against the plan itself.
case_12_2() {
	have python3 || {
		skip_c "no python3 to parse the JSON plan"
		return
	}
	_w=$TMP/12_2
	mkdir -p "$_w"
	_flags='-f web -n 6 -s 5 --cpu 40'

	tmo 90 "$BIN" inject $_flags --dry-run --json >"$_w/json" 2>"$_w/json.err"
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "inject --dry-run --json exited $_rc: $(head -1 "$_w/json.err")"
		return
	}
	plan_tsv json "$_w/json" "$_w/plan.tsv"
	_bad=$(grep -m1 '^ERR ' "$_w/plan.tsv")
	if [ -n "$_bad" ]; then
		fail_c "${_bad#ERR }"
		return
	fi
	_stubs=$(sed -n 's/^STUBS //p' "$_w/plan.tsv")
	_roots=$(sed -n 's/^ROOTS //p' "$_w/plan.tsv")
	_rows=$(sed -n 's/^ROWS //p' "$_w/plan.tsv")
	if [ "$_stubs" != 6 ] || [ "$_rows" != 6 ]; then
		fail_c "the document says stubs=$_stubs rows=$_rows for -n 6"
		return
	fi
	_toplevel=$(awk '$7 == "-"' "$_w/plan.tsv" | wc -l)
	if [ "$_roots" != "$_toplevel" ]; then
		fail_c "the document says $_roots roots but $_toplevel rows have no parent"
		return
	fi
	grep -v '^[A-Z]* ' "$_w/plan.tsv" >"$_w/rows.tsv"

	_pf=$_w/stubs.pid
	tmo 90 "$BIN" inject $_flags --duration 30 --pidfile "$_pf" >"$_w/run.out" 2>"$_w/run.err"
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		stop_pidfile "$_pf"
		fail_c "the real run exited $_rc: $(head -1 "$_w/run.err")"
		return
	fi
	if ! wait_pids "$_pf" 6; then
		stop_pidfile "$_pf"
		fail_c "the real run recorded $(pids_of "$_pf" | grep -c .) of 6 pids"
		return
	fi
	sleep 2
	real_tsv "$_pf" "$_w/real.tsv"
	stop_pidfile "$_pf"
	compare_run "$_w/rows.tsv" "$_w/real.tsv" "the JSON plan does not describe the run" || return
	pass_c
}

# 12.3: the tier the plan names is the executable the kernel reports. With
# `--no-root` the run cannot bind or shadow, so every stub must exec psgen
# itself; a plan that said `bind` there would send a caller looking for a
# spoofed exe that never appears.
case_12_3() {
	_w=$TMP/12_3
	mkdir -p "$_w"
	_binexe=$(readlink -f "$BIN" 2>/dev/null)
	[ -n "$_binexe" ] || _binexe=$BIN

	tmo 90 "$BIN" inject -f web -n 4 -s 5 --no-root --dry-run --plan \
		>"$_w/plan" 2>"$_w/plan.err"
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "inject --dry-run --plan --no-root exited $_rc: $(head -1 "$_w/plan.err")"
		return
	}
	_tier=$(awk '$1 == "tier" { print $2 }' "$_w/plan")
	if [ "$_tier" != "proc-self" ]; then
		fail_c "the plan names tier '${_tier:-none}', but --no-root can only exec /proc/self/exe"
		return
	fi

	_pf=$_w/stubs.pid
	tmo 90 "$BIN" inject -f web -n 4 -s 5 --no-root --duration 30 --pidfile "$_pf" \
		>"$_w/run.out" 2>"$_w/run.err"
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		stop_pidfile "$_pf"
		fail_c "the real run exited $_rc: $(head -1 "$_w/run.err")"
		return
	fi
	if ! wait_pids "$_pf" 4; then
		stop_pidfile "$_pf"
		fail_c "the real run recorded $(pids_of "$_pf" | grep -c .) of 4 pids"
		return
	fi
	_bad=
	for _p in $(pids_of "$_pf"); do
		_exe=$(readlink "/proc/$_p/exe" 2>/dev/null)
		if [ "$_exe" != "$_binexe" ]; then
			_bad="$_bad pid $_p runs '${_exe:-gone}'"
		fi
	done
	stop_pidfile "$_pf"
	if [ -n "$_bad" ]; then
		fail_c "the plan said proc-self but:$_bad (psgen is $_binexe)"
		return
	fi
	pass_c
}

# 12.4: `--disk` and the staging directories. The plan promises a total and a
# count before anything is written; the filesystem is what says whether the
# run wrote that much in that many places.
case_12_4() {
	_w=$TMP/12_4
	mkdir -p "$_w/tmp"
	_d=$_w/tmp

	TMPDIR="$_d" tmo 90 "$BIN" inject -f web -n 2 -s 5 --disk 1 --no-root \
		--dry-run --plan >"$_w/plan" 2>"$_w/plan.err"
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "inject --dry-run --plan --disk 1 exited $_rc: $(head -1 "$_w/plan.err")"
		return
	}
	_total=$(awk '$1 == "plan:" { for (i = 1; i <= NF; i++) if ($i == "disk") print $(i + 1) }' "$_w/plan")
	_dirs=$(awk '$1 == "plan:" { for (i = 1; i <= NF; i++) if ($i == "staging") print $(i + 1) }' "$_w/plan")
	_under=$(awk '$1 == "plan:" { for (i = 1; i <= NF; i++) if ($i == "under") print $(i + 1) }' "$_w/plan")
	if [ "$_total" != 2 ] || [ "$_dirs" != 2 ] || [ "$_under" != "$_d" ]; then
		fail_c "the plan says disk '${_total:-none}' MiB over '${_dirs:-none}' staging directories under '${_under:-none}'"
		return
	fi
	_stage=$(awk '$1 == "staging" { print $2 }' "$_w/plan" | grep -cF "$_d/.psgen-<pid>-")
	if [ "$_stage" -ne 2 ]; then
		fail_c "the plan named $_stage staging paths under $_d"
		return
	fi

	_pf=$_w/stubs.pid
	TMPDIR="$_d" tmo 90 "$BIN" inject -f web -n 2 -s 5 --disk 1 --no-root \
		--duration 30 --pidfile "$_pf" >"$_w/run.out" 2>"$_w/run.err"
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		stop_pidfile "$_pf"
		fail_c "the real run exited $_rc: $(head -1 "$_w/run.err")"
		return
	fi
	if ! wait_pids "$_pf" 2; then
		stop_pidfile "$_pf"
		fail_c "the real run recorded $(pids_of "$_pf" | grep -c .) of 2 pids"
		return
	fi
	_made=$(find "$_d" -maxdepth 1 -type d -name '.psgen-*' | wc -l)
	if [ "$_made" -ne 2 ]; then
		stop_pidfile "$_pf"
		fail_c "the run created $_made staging directories, the plan said 2"
		return
	fi
	_bytes=$(find "$_d" -name data.bin -type f -printf '%s\n' | awk '{ s += $1 } END { print s + 0 }')
	stop_pidfile "$_pf"
	if [ "$_bytes" -ne 2097152 ]; then
		fail_c "the run wrote $_bytes bytes of --disk data, the plan said 2 MiB"
		return
	fi
	pass_c
}

# ----------------------------------------------------------------- issue #17
# `--local` selects the system timezone, so a UTC offset must not be applied on
# top of it, and the offset itself has to stay inside the range the help names.

# 17.1: the START column shifted once. The zone is chosen, not inherited: a UTC
# host cannot tell a localtime renderer from a UTC one, so the case would be
# comparing two identical truncations.
case_17_1() {
	_zone=
	# The row ages decide whether a second shift is visible at all: a start on
	# the previous calendar day renders as `Nov12` in both zones, where the
	# shift cannot show. The zone is therefore picked for a local hour in the
	# middle of the day, which leaves every row started within the last hours on
	# the current day and keeps the clock visible.
	_fallback=
	for _z in Asia/Kolkata Asia/Kathmandu Europe/Berlin America/New_York; do
		[ -f "/usr/share/zoneinfo/$_z" ] || continue
		_off=$(TZ=$_z date +%z 2>/dev/null)
		case $_off in
			"" | +0000 | -0000) continue ;;
		esac
		[ -n "$_fallback" ] || _fallback=$_z
		_h=$(TZ=$_z date +%H 2>/dev/null)
		case $_h in
			0[5-9] | 1[0-9]) ;;
			*) continue ;;
		esac
		_zone=$_z
		break
	done
	[ -n "$_zone" ] || _zone=$_fallback
	[ -n "$_zone" ] || {
		skip_c "no zone under /usr/share/zoneinfo with a non-zero offset"
		return
	}
	_off=$(TZ=$_zone date +%z 2>/dev/null)
	_w=$TMP/17_1
	mkdir -p "$_w"
	for _m in utc off loc both; do
		case $_m in
			utc) _f= ;;
			off) _f='--utc-offset 120' ;;
			loc) _f='--local' ;;
			both) _f='--local --utc-offset 120' ;;
		esac
			TZ=$_zone tmo 60 "$BIN" table -f dev -n 40 -s 1 $_f \
			>"$_w/$_m" 2>"$_w/$_m.err" || {
			fail_c "table $_f exited non-zero: $(head -1 "$_w/$_m.err")"
			return
		}
	done

	# The same rows, in the same order, or the comparison would be of different
	# tables: START and TIME follow the wall clock, the row set does not.
	for _m in off loc both; do
		_a=$(awk 'NR > 1 { print $2 }' "$_w/utc")
		_b=$(awk 'NR > 1 { print $2 }' "$_w/$_m")
		if [ "$_a" != "$_b" ]; then
			fail_c "$_m selected a different set of rows from the default run"
			return
		fi
	done

	# `--local --utc-offset 120` must be `--local`, row for row. This is the
	# defect itself, and it needs no clock arithmetic: a row rendered as `Nov12`
	# in both runs is as good as one rendered `09:47`.
	_diff=$(awk '
		FNR == NR { if (FNR > 1) a[FNR - 1] = $9; next }
		FNR > 1 { if ($9 != a[FNR - 1]) printf "row %d: --local is %s, --local --utc-offset 120 is %s\n", FNR - 1, a[FNR - 1], $9 }
	' "$_w/loc" "$_w/both")
	if [ -n "$_diff" ]; then
		fail_c "--local and --utc-offset were both applied: $(printf '%s\n' "$_diff" | head -1)"
		return
	fi

	# A row that has already started cannot print a clock time later than now.
	# This is the check the double shift fails on its own: local plus two hours
	# puts every row of the last two hours in the future.
	_now=$(TZ=$_zone date +%H:%M)
	_future=$(awk -v now="$_now" '
		NR > 1 && $9 ~ /^[0-9][0-9]:[0-9][0-9]$/ {
			clock = substr($9, 1, 2) * 60 + substr($9, 4, 2)
			nowm = substr(now, 1, 2) * 60 + substr(now, 4, 2)
			seen++
			if (clock > nowm + 1) printf "row %d starts at %s, it is %s\n", NR - 1, $9, now
		}
		END { if (!seen) print "no row renders as a clock time right now" }
	' "$_w/both")
	case $_future in
		"no row renders as a clock time right now")
			skip_c "every row is a calendar day in $_zone right now, so a second shift cannot be seen"
			return
			;;
		?*)
			fail_c "--local --utc-offset 120 prints a start in the future: $(printf '%s\n' "$_future" | head -1)"
			return
			;;
	esac

	# The offset is applied on top of the default UTC rendering, and the shift
	# is exact.
	_shift=$(awk '
		FNR == NR { if (FNR > 1) a[FNR - 1] = $9; next }
		FNR > 1 {
			b = $9
			if (a[FNR - 1] !~ /^[0-9][0-9]:[0-9][0-9]$/ || b !~ /^[0-9][0-9]:[0-9][0-9]$/)
				next
			am = substr(a[FNR - 1], 1, 2) * 60 + substr(a[FNR - 1], 4, 2)
			bm = substr(b, 1, 2) * 60 + substr(b, 4, 2)
			d = (bm - am) % 1440
			if (d < 0) d += 1440
			n++
			if (d != 120) { printf "row %d moved %d minutes: %s -> %s\n", FNR - 1, d, a[FNR - 1], b; bad = 1 }
		}
		END { if (!n) exit 3; exit bad }
	' "$_w/utc" "$_w/off")
	_rc=$?
	if [ "$_rc" -eq 3 ]; then
		skip_c "no row is a clock time in both the UTC and the offset render right now"
		return
	fi
	if [ -n "$_shift" ] || [ "$_rc" -ne 0 ]; then
		fail_c "--utc-offset 120 did not shift START by 120 minutes: $(printf '%s\n' "$_shift" | head -1)"
		return
	fi

	# ...and the local rendering is the host's own offset from UTC, so the two
	# checks above are not two ways of agreeing with the same mistake.
	_min=$(printf '%s' "$_off" | awk '{
		s = substr($0, 1, 1); h = substr($0, 2, 2) + 0; m = substr($0, 4, 2) + 0
		t = h * 60 + m
		if (s == "-") t = -t
		print t
	}')
	_hostoff=$(awk -v want="$_min" '
		FNR == NR { if (FNR > 1) a[FNR - 1] = $9; next }
		FNR > 1 {
			b = $9
			if (a[FNR - 1] !~ /^[0-9][0-9]:[0-9][0-9]$/ || b !~ /^[0-9][0-9]:[0-9][0-9]$/)
				next
			am = substr(a[FNR - 1], 1, 2) * 60 + substr(a[FNR - 1], 4, 2)
			bm = substr(b, 1, 2) * 60 + substr(b, 4, 2)
			d = (bm - am) % 1440
			if (d < 0) d += 1440
			n++
			if (d != want) { printf "row %d moved %d minutes, the zone is %d: %s -> %s\n", FNR - 1, d, want, a[FNR - 1], b; bad = 1 }
		}
		END { if (!n) exit 3; exit bad }
	' "$_w/utc" "$_w/loc")
	_rc=$?
	if [ "$_rc" -eq 3 ]; then
		skip_c "no row is a clock time in both the UTC and the local render right now"
		return
	fi
	if [ -n "$_hostoff" ] || [ "$_rc" -ne 0 ]; then
		fail_c "--local is not the zone's offset from UTC ($_off): $(printf '%s\n' "$_hostoff" | head -1)"
		return
	fi
	pass_c
}

# 17.2: an offset outside the documented range has to be refused, not folded
# into a START column that no longer fits the five columns ps uses.
case_17_2() {
	_w=$TMP/17_2
	mkdir -p "$_w"
	_bad=
	for _o in 1441 -1441 9223372036854775807; do
		_err=$(tmo 30 "$BIN" table -n 4 --utc-offset "$_o" 2>&1 >"$_w/out")
		_rc=$?
		if [ "$_rc" -ne 2 ]; then
			_bad="$_bad $_o(exit $_rc)"
			continue
		fi
		case $_err in
			*--utc-offset*) ;;
			*) _bad="$_bad $_o(no diagnostic naming the flag)" ;;
		esac
	done
	if [ -n "$_bad" ]; then
		fail_c "--utc-offset outside -1440..1440 was not refused:$_bad"
		return
	fi

	# The bound itself must still be usable, and the START column it produces
	# must stay where ps puts it: five cells at the header offset.
	for _o in 1440 -1440; do
		tmo 30 "$BIN" table -f dev -n 20 -s 1 --utc-offset "$_o" >"$_w/out.$_o" 2>"$_w/err.$_o"
		_rc=$?
		if [ "$_rc" -ne 0 ]; then
			fail_c "--utc-offset $_o was refused (exit $_rc): $(head -1 "$_w/err.$_o")"
			return
		fi
		_bad=$(awk '
			NR == 1 { next }
			{
				col = 0; pos = 1; len = length($0)
				while (col < 9 && pos <= len) {
					while (pos <= len && substr($0, pos, 1) == " ") pos++
					col++
					if (col == 9) start = pos
					while (pos <= len && substr($0, pos, 1) != " ") pos++
				}
				if (start != 55 || length($9) != 5)
					printf "line %d: START %s starts at %d\n", NR, $9, start
			}' "$_w/out.$_o" | head -1)
		if [ -n "$_bad" ]; then
			fail_c "--utc-offset $_o moved the START column: $_bad"
			return
		fi
	done
	pass_c
}

# ------------------------------------------------------------------ driver

run_case 3.1 3 "a line break in argv stays inside one COMMAND field" case_3_1
run_case 3.2 3 "a zombie carries <defunct> like ps" case_3_2
run_case 3.3 3 "inject --table prints the rows in ps's PID order" case_3_3
run_case 3.4 3 "a wide VSZ keeps STAT/START/TIME/COMMAND at ps's columns" case_3_4
run_case 12.1 12 "--plan describes the run it would start" case_12_1
run_case 12.2 12 "--json is the same plan as one object" case_12_2
run_case 12.3 12 "the plan's exe tier is the exe the kernel reports" case_12_3
run_case 12.4 12 "--disk totals and staging directories match the filesystem" case_12_4
run_case 17.1 17 "--local overrides --utc-offset instead of shifting twice" case_17_1
run_case 17.2 17 "--utc-offset outside -1440..1440 is refused" case_17_2

if [ "$RAN" = 0 ]; then
	echo "table.sh: no case matched '$SELECTED'" >&2
	exit 2
fi

if [ "$FAILS" -gt 0 ]; then
	exit 1
fi
exit 0
