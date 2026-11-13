#!/bin/sh
# Per-issue proof harness: the generator's determinism, count and plausibility.
#
#   sh tests/proof_cases/generator.sh <binary> [issue ...]
#
# Covers issues #2, #16 and #28. Each case prints one line — `PASS <n>
# <what>`, `FAIL <n> <what>: <why>` or `SKIP <n> <what>: <why>` — and the
# script exits non-zero when any case failed.
#
# The rule the suite already enforces (DESIGN.md §4) applies to this file: a
# check that cannot fail is worse than no check. Every case here is written
# against a reference the tool does not own — the count it was asked for, CPU
# time measured by the parent, `/proc/meminfo`, `/proc/stat`,
# `/proc/sys/kernel/pid_max`, the host's own uptime — and each one fails on
# `bf80156`, the commit the fixes branch from. A case that needs a host
# capability this machine lacks prints SKIP with the reason; with
# PSGEN_REQUIRE_ALL=1 that same absence is a failure, so a release gate cannot
# pass on a host where the case never ran.
#
# Nothing here starts a process or writes outside a private temp directory: the
# injection cases are dry runs, and the `/proc` files a case replaces are bound
# inside a private mount namespace that dies with the case. `cleanup` removes
# the temp directory from the exit trap.
set -u

LC_ALL=C
export LC_ALL

if [ $# -lt 1 ]; then
	echo "usage: sh tests/proof_cases/generator.sh <binary> [issue ...]" >&2
	exit 2
fi

BIN_ARG=$1
shift
SELECTED=$*

[ -x "$BIN_ARG" ] || {
	echo "generator.sh: $BIN_ARG is not an executable" >&2
	exit 2
}
case $BIN_ARG in
	/*) BIN=$BIN_ARG ;;
	*) BIN=$(CDPATH= cd -- "$(dirname -- "$BIN_ARG")" && pwd)/$(basename -- "$BIN_ARG") ;;
esac

TMP=$(mktemp -d) || {
	echo "generator.sh: cannot create a temp directory" >&2
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

# Cleanup removes only the private temp directory: no case here starts a
# process, creates a user or mounts a path that outlives its namespace.
cleanup() {
	trap - EXIT INT TERM HUP
	rm -rf "$TMP" 2>/dev/null || asroot rm -rf "$TMP"
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

# ------------------------------------------------------- a host of one's own
# The `--host-*` options that name a foreign host are new in this branch, so a
# case cannot use them and still run against `bf80156`. These helpers describe
# the same foreign host through `/proc` instead, which both trees read: the
# files are bound over their real counterparts inside a private mount
# namespace, so the substitution is invisible outside the case.

fake_meminfo() { # fake_meminfo <total_kb> <available_kb>
	{
		printf 'MemTotal:       %s kB\n' "$1"
		printf 'MemFree:        %s kB\n' "$2"
		printf 'MemAvailable:   %s kB\n' "$2"
	} >"$TMP/meminfo"
}

fake_stat() { printf 'btime %s\n' "$1" >"$TMP/stat"; }

fake_uptime() { printf '%s.00 1000.00\n' "$1" >"$TMP/uptime"; }

fake_pid_max() { printf '%s\n' "$1" >"$TMP/pid_max"; }

clear_fakes() { rm -f "$TMP/meminfo" "$TMP/stat" "$TMP/uptime" "$TMP/pid_max"; }

# The bind mounts for whichever fake files this case staged, in one prefix a
# `sh -c` can run before `exec`.
fake_mounts() {
	_pre=
	for _spec in meminfo:/proc/meminfo stat:/proc/stat uptime:/proc/uptime \
		pid_max:/proc/sys/kernel/pid_max; do
		_src=${_spec%%:*}
		_dst=${_spec#*:}
		if [ -f "$TMP/$_src" ]; then
			_pre="$_pre mount --bind '$TMP/$_src' '$_dst' &&"
		fi
	done
	printf '%s' "$_pre"
}

in_fake_host() { # in_fake_host <seconds> <command...>
	_t=$1
	shift
	_pre=$(fake_mounts)
	asroot unshare -m sh -c "$_pre exec timeout $_t \"\$@\"" sh "$@"
}

need_fake_proc() { # need_fake_proc <what is being replaced>
	have_sudo || {
		skip_c "needs sudo to mount a private /proc/$1"
		return 1
	}
	have unshare || {
		skip_c "no unshare to mount a private /proc/$1"
		return 1
	}
	return 0
}

# ------------------------------------------------------------------ issue #2
# The same seed is documented as deterministic, and the pre-fix child-row age
# is `next_u64() % uptime`: the draw is fixed by the seed, the modulus grows by
# one every second, so the same seed produced different START values a second
# later. The reference here is the other process's output; the pair is taken
# inside one wall-clock minute because the fixed generator pins the instant to
# the start of the minute, and a pair that straddles the boundary is not the
# defect under test.
case_2() {
	while :; do
		_s=$(date +%S)
		_s=${_s#0}
		[ -n "$_s" ] || _s=0
		[ "$_s" -le 45 ] && break
		sleep 1
	done
	_sec_a=$(date +%S)
	tmo 60 "$BIN" table -n 12 -s 42 >"$TMP/2a" 2>"$TMP/2.err"
	_rc=$?
	sleep 2
	_sec_b=$(date +%S)
	tmo 60 "$BIN" table -n 12 -s 42 >"$TMP/2b" 2>>"$TMP/2.err"
	_rc_b=$?
	if [ "$_rc" -ne 0 ] || [ "$_rc_b" -ne 0 ]; then
		fail_c "table -n 12 -s 42 exited $_rc and $_rc_b: $(head -1 "$TMP/2.err")"
		return
	fi
	if [ "$_sec_a" = "$_sec_b" ]; then
		fail_c "the two runs did not start in different seconds"
		return
	fi
	if [ ! -s "$TMP/2a" ]; then
		fail_c "table -n 12 -s 42 printed nothing"
		return
	fi
	if ! cmp -s "$TMP/2a" "$TMP/2b"; then
		say "  #2 diagnostics:"
		diff "$TMP/2a" "$TMP/2b" | sed -n '1,8p' | sed 's/^/    /' >&2
		fail_c "the same seed printed different rows 2 s apart"
		return
	fi
	pass_c
}

# ----------------------------------------------------------------- issue #10
# `gen_list`'s duplicate check was a linear scan over every line kept, so the
# cost grew with the square of the count. The reference is the row count: eight
# times the rows may cost at most five times the CPU, where a quadratic scan
# costs it sixty-four times. The CPU time comes from the parent's own
# accounting (`RUSAGE_CHILDREN`), not from the child. Under a linear generator
# the ratio measured here is around 2 (process start dominates 250 rows); the
# quadratic tree lands between 5 and 18.
# ----------------------------------------------------------------- issue #16
# `-n` was silently under-delivered for the families whose templates all carry
# `inst <= 1`, and the families that did reach the count were padded with
# unlimited repeats of one template. Four cases: the count is met where it was
# short, the shortfall is named where it cannot be met, the remedy the message
# offers works, and no family pads one command past half the table.

case_16_1() {
	for _f in mail mon sto net; do
		tmo 60 "$BIN" table -f "$_f" -n 50 >"$TMP/16.out" 2>"$TMP/16.err"
		_rc=$?
		_err=$(cat "$TMP/16.err")
		if [ "$_rc" -ne 0 ]; then
			fail_c "table -f $_f -n 50 exited $_rc: $_err"
			return
		fi
		_rows=$(tail -n +2 "$TMP/16.out" | wc -l)
		if [ "$_rows" -ne 50 ]; then
			fail_c "table -f $_f -n 50 printed $_rows rows, not 50${_err:+ ($_err)}"
			return
		fi
		if [ -n "$_err" ]; then
			fail_c "table -f $_f -n 50 met the count but still named a shortfall: $_err"
			return
		fi
	done
	pass_c
}

case_16_2() {
	for _f in mail mon sto net; do
		tmo 120 "$BIN" inject -f "$_f" -n 50 --dry-run >"$TMP/16.out" 2>"$TMP/16.err"
		_rc=$?
		if [ "$_rc" -ne 0 ]; then
			fail_c "inject -f $_f -n 50 --dry-run exited $_rc: $(head -1 "$TMP/16.err")"
			return
		fi
		_rows=$(grep -c . "$TMP/16.out")
		if [ "$_rows" -ne 50 ]; then
			fail_c "inject -f $_f -n 50 planned $_rows stubs, not 50"
			return
		fi
	done
	pass_c
}

# A family that cannot supply the count must say so, with the number it did
# produce, and the remedy it names must work: `--no-uniq` must actually pad,
# and "ask for fewer lines" must be silent at the smaller count. The pre-fix
# `list` printed no shortfall at all, and offered a `--no-uniq` that could not
# pad a family whose templates are all fixed.
case_16_3() {
	tmo 60 "$BIN" list -f mail -n 50 >"$TMP/16.out" 2>"$TMP/16.err"
	_rc=$?
	_rows=$(wc -l <"$TMP/16.out")
	_err=$(cat "$TMP/16.err")
	if [ "$_rc" -ne 0 ]; then
		fail_c "list -f mail -n 50 exited $_rc"
		return
	fi
	if [ "$_rows" -ge 50 ]; then
		fail_c "list -f mail -n 50 claims to have produced 50 rows"
		return
	fi
	if [ -z "$_err" ]; then
		fail_c "list -f mail -n 50 printed $_rows of 50 rows and said nothing"
		return
	fi
	case $_err in
		*"$_rows"*) ;;
		*)
			fail_c "the shortfall does not carry the $_rows rows it did produce: $_err"
			return
			;;
	esac
	case $_err in
		*50*) ;;
		*)
			fail_c "the shortfall does not carry the 50 rows requested: $_err"
			return
			;;
	esac
	# Asking for what the family can supply is the remedy the message names.
	tmo 60 "$BIN" list -f mail -n "$_rows" >"$TMP/16b.out" 2>"$TMP/16b.err"
	_rc=$?
	_n=$(wc -l <"$TMP/16b.out")
	if [ "$_rc" -ne 0 ] || [ "$_n" -ne "$_rows" ]; then
		fail_c "asking for the $_rows lines it offered gave $_n (exit $_rc)"
		return
	fi
	if [ -s "$TMP/16b.err" ]; then
		fail_c "asking for the $_rows lines it offered still named a shortfall"
		return
	fi
	# `sys` can supply the count with repeated command lines, so its message
	# offers `--no-uniq` and that flag has to reach the count.
	tmo 60 "$BIN" list -f sys -n 50 >"$TMP/16c.out" 2>"$TMP/16c.err"
	_rc=$?
	_rows=$(wc -l <"$TMP/16c.out")
	_err=$(cat "$TMP/16c.err")
	if [ "$_rc" -ne 0 ]; then
		fail_c "list -f sys -n 50 exited $_rc"
		return
	fi
	case $_err in
		*--no-uniq*)
			tmo 60 "$BIN" list -f sys -n 50 --no-uniq >"$TMP/16d.out" 2>"$TMP/16d.err"
			_rc=$?
			_n=$(wc -l <"$TMP/16d.out")
			if [ "$_rc" -ne 0 ] || [ "$_n" -ne 50 ]; then
				fail_c "the shortfall offered --no-uniq but it produced $_n of 50 lines (exit $_rc)"
				return
			fi
			;;
		*)
			if [ "$_rows" -lt 50 ]; then
				fail_c "list -f sys -n 50 printed $_rows rows and offered no way to pad"
				return
			fi
			;;
	esac
	pass_c
}

# The padding half: with `inst > 1` doing double duty as a repeat licence,
# `sys -n 200` was 120 rows of one `sshd ... [priv]` pair, and one command may
# not fill more than half of any table (tests/invariants.py asserts the same
# bound on the default table).
case_16_4() {
	for _f in sys dev web mon; do
		tmo 60 "$BIN" table -f "$_f" -n 200 -s 2 >"$TMP/16.out" 2>"$TMP/16.err"
		_rc=$?
		if [ "$_rc" -ne 0 ]; then
			fail_c "table -f $_f -n 200 -s 2 exited $_rc: $(head -1 "$TMP/16.err")"
			return
		fi
		_rows=$(tail -n +2 "$TMP/16.out" | wc -l)
		if [ "$_rows" -ne 200 ]; then
			fail_c "table -f $_f -n 200 -s 2 printed $_rows rows"
			return
		fi
		_top=$(tail -n +2 "$TMP/16.out" |
			awk '{ c = ""; for (i = 11; i <= NF; i++) c = c " " $i; print c }' |
			sort | uniq -c | sort -rn | head -1 | awk '{ print $1 }')
		if [ "$_top" -gt $((_rows / 2)) ]; then
			fail_c "table -f $_f -n 200 -s 2 prints $_top copies of one command in $_rows rows"
			return
		fi
	done
	pass_c
}

# ----------------------------------------------------------------- issue #28
# A row is a claim about a real process. The corpus carries absolute sizes and
# synthetic PIDs, so on a 512 MiB host the pre-fix table printed an RSS of 880
# MiB, a `%MEM` of 172 and PIDs above a small `pid_max`. The host is described
# through `/proc` for both trees: MemTotal 512 MiB with a two-minute uptime,
# then a 32768 `pid_max`.

case_28_1() {
	need_fake_proc meminfo || return
	clear_fakes
	fake_meminfo 524288 262144
	fake_stat "$(($(date +%s) - 120))"
	fake_uptime 120
	in_fake_host 90 "$BIN" table -n 400 -s 3 --utc-offset 0 \
		>"$TMP/28.out" 2>"$TMP/28.err"
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "table -n 400 on a 512 MiB host exited $_rc: $(head -1 "$TMP/28.err")"
		return
	fi
	_rows=$(tail -n +2 "$TMP/28.out" | wc -l)
	if [ "$_rows" -ne 400 ]; then
		fail_c "table -n 400 on a 512 MiB host printed $_rows rows"
		return
	fi
	_bad=$(tail -n +2 "$TMP/28.out" | awk '
		$6 + 0 > $5 + 0 { printf "PID %s RSS %s > VSZ %s; ", $2, $6, $5 }
		$6 + 0 > 524288  { printf "PID %s RSS %s > MemTotal 524288; ", $2, $6 }
		$4 + 0 > 100     { printf "PID %s %%MEM %s; ", $2, $4 }
	' | cut -c1-400)
	if [ -n "$_bad" ]; then
		fail_c "a 512 MiB host shows an impossible row: $_bad"
		return
	fi
	# The same host booted two minutes before the run, so every START is either
	# a clock time inside that window or, when the window straddles midnight,
	# the boot's own calendar day. Anything older is before the boot; a clock
	# time past the run's is in the future.
	_now_h=$(date -u +%H)
	_now_h=${_now_h#0}
	[ -n "$_now_h" ] || _now_h=0
	_now_m=$(date -u +%M)
	_now_m=${_now_m#0}
	[ -n "$_now_m" ] || _now_m=0
	_now_min=$((_now_h * 60 + _now_m))
	_boot_md=$(date -u -d "@$(($(date +%s) - 120))" +%m-%d 2>/dev/null) || _boot_md=
	_bad=$(tail -n +2 "$TMP/28.out" | awk -v nowm="$_now_min" -v bootmd="$_boot_md" '
		BEGIN {
			split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", n, " ")
			for (i = 1; i <= 12; i++) mon[n[i]] = i
		}
		{
			s = $9
			if (s ~ /^[0-9][0-9]:[0-9][0-9]$/) {
				split(s, a, ":")
				d = (a[1] * 60 + a[2] - nowm + 1440) % 1440
				if (d > 720) d -= 1440
				if (d < -3)
					printf "PID %s START %s before the boot; ", $2, s
				else if (d > 1)
					printf "PID %s START %s in the future; ", $2, s
			} else if (s ~ /^[A-Z][a-z][a-z][0-9][0-9]$/ && bootmd != "") {
				md = sprintf("%02d-%s", mon[substr(s, 1, 3)], substr(s, 4, 2))
				if (md != bootmd)
					printf "PID %s START %s before the boot day %s; ", $2, s, bootmd
			} else {
				printf "PID %s START %s on a host up 120 s; ", $2, s
			}
		}
	' | cut -c1-400)
	if [ -n "$_bad" ]; then
		fail_c "a 512 MiB host shows an impossible START: $_bad"
		return
	fi
	clear_fakes
	pass_c
}

case_28_2() {
	need_fake_proc sys/kernel/pid_max || return
	clear_fakes
	fake_pid_max 32768
	in_fake_host 120 "$BIN" table -n 5000 -s 1 --utc-offset 0 \
		>"$TMP/28b.out" 2>"$TMP/28b.err"
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "table -n 5000 on a pid_max 32768 host exited $_rc: $(head -1 "$TMP/28b.err")"
		return
	fi
	_rows=$(tail -n +2 "$TMP/28b.out" | wc -l)
	if [ "$_rows" -ne 5000 ]; then
		fail_c "table -n 5000 on a pid_max 32768 host printed $_rows rows"
		return
	fi
	_bad=$(tail -n +2 "$TMP/28b.out" | awk '
		$2 + 0 < 1     { printf "PID %s; ", $2 }
		$2 + 0 >= 32768 { printf "PID %s >= pid_max 32768; ", $2 }
	' | cut -c1-400)
	if [ -n "$_bad" ]; then
		fail_c "a PID the host cannot have: $_bad"
		return
	fi
	_repeat=$(tail -n +2 "$TMP/28b.out" | awk '{ print $2 }' | sort -n | uniq -d | head -3)
	if [ -n "$_repeat" ]; then
		fail_c "two rows share a PID: $(printf '%s' "$_repeat" | tr '\n' ' ')"
		return
	fi
	clear_fakes
	pass_c
}

# ------------------------------------------------------------------ driver

run_case 2 2 "the same seed is byte-identical in two processes started in different seconds" case_2
run_case 16.1 16 "table meets -n for the four families that used to fall short" case_16_1
run_case 16.2 16 "inject meets -n for the same four families" case_16_2
run_case 16.3 16 "a list shortfall is named and the remedy it offers works" case_16_3
run_case 16.4 16 "no single command is padded past half the table" case_16_4
run_case 28.1 28 "a 512 MiB host shows no impossible row" case_28_1
run_case 28.2 28 "PIDs stay below a small host's pid_max" case_28_2

if [ "$RAN" = 0 ]; then
	echo "generator.sh: no case matched '$SELECTED'" >&2
	exit 2
fi

if [ "$FAILS" -gt 0 ]; then
	exit 1
fi
exit 0
