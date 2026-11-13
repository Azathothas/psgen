#!/bin/sh
# Per-issue proof harness: the report and utility surface.
#
#   sh tests/proof_cases/report.sh <binary> [issue ...]
#
# Covers issues #8, #13, #19, #20, #21, #23, #24 and #27. Each case prints one
# line — `PASS <n> <what>`, `FAIL <n> <what>: <why>` or `SKIP <n> <what>:
# <why>` — and the script exits non-zero when any case failed.
#
# The rule the suite already enforces (DESIGN.md §4) applies to this file: a
# check that cannot fail is worse than no check. Every case here is written
# against a reference the tool does not own — systemd, `ps`, the kernel, the
# filesystem — and each one fails on `bf80156`, the commit the fixes branch
# from. A case that needs a host capability this machine lacks prints SKIP with
# the reason; with PSGEN_REQUIRE_ALL=1 that same absence is a failure, so a
# release gate cannot pass on a host where the case never ran.
#
# Nothing here writes outside a private temp directory except where the case is
# about a fixed system location: a group and its user for #20, a shim at a
# mapped binary path for #21, a systemd unit for #27. Every one of those is
# removed by `cleanup`, which runs from the exit trap.
set -u

LC_ALL=C
export LC_ALL

if [ $# -lt 1 ]; then
	echo "usage: sh tests/proof_cases/report.sh <binary> [issue ...]" >&2
	exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BIN_ARG=$1
shift
SELECTED=$*

[ -x "$BIN_ARG" ] || {
	echo "report.sh: $BIN_ARG is not an executable" >&2
	exit 2
}
case $BIN_ARG in
	/*) BIN=$BIN_ARG ;;
	*) BIN=$(CDPATH= cd -- "$(dirname -- "$BIN_ARG")" && pwd)/$(basename -- "$BIN_ARG") ;;
esac

TMP=$(mktemp -d) || {
	echo "report.sh: cannot create a temp directory" >&2
	exit 2
}

FAILS=0
RAN=0
CUR_ID=
CUR_WHAT=
UNIT_PREFIX=psgen-proof-$$
SHIM_ANVIL=
SHIM_JEST_LOCAL=

# The checkpoint tree, not this file's tree: the documentation cases are about
# the release that ships the binary, so they must read the README, the manifest
# and the test scripts that shipped with it. `$ROOT` is where the harness runs;
# `$SRC` is where the binary was built, which is a different tree when the
# proof is run against the pre-fix binary. It is inferred from the binary's
# own path (`<tree>/target/<profile>/psgen`) so a caller cannot forget it.
SRC=${PSGEN_SRC:-}
if [ -z "$SRC" ]; then
	_bin_dir=$(dirname -- "$BIN")
	case $_bin_dir in
		*/target/*) SRC=$(CDPATH= cd -- "$_bin_dir/../.." && pwd) ;;
		*) SRC=$ROOT ;;
	esac
fi
[ -d "$SRC" ] || {
	echo "report.sh: $SRC (the tree the binary came from) is not a directory" >&2
	exit 2
}

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
	asroot "$BIN" stop --pidfile "$1" >/dev/null 2>&1
}

unit_stop() {
	[ -n "$1" ] || return 0
	asroot systemctl stop "$1" >/dev/null 2>&1
	asroot systemctl reset-failed "$1" >/dev/null 2>&1
}

# Cleanup elevates exactly once, and only when the run itself could: a case
# that ran without sudo never wrote outside the private temp directory, so a
# `sudo` here would only print "a password is required".
clean_asroot() {
	if can_elevate; then
		asroot "$@" 2>/dev/null
	else
		"$@" 2>/dev/null
	fi
}

cleanup() {
	trap - EXIT INT TERM HUP
	# A case can be interrupted between the mount and its umount.
	for m in "$TMP/full" "$TMP/fakeproc"; do
		if [ -d "$m" ]; then
			clean_asroot umount -l "$m"
			clean_asroot umount "$m"
		fi
	done
	# Units first: their ExecStop is what reaps the stubs they started.
	for u in $(ls /etc/systemd/system 2>/dev/null | sed -n "s/^\(${UNIT_PREFIX}.*\.service\)$/\1/p"); do
		unit_stop "$u"
		clean_asroot rm -f "/etc/systemd/system/$u"
	done
	if ls /etc/systemd/system 2>/dev/null | grep -q "^${UNIT_PREFIX}"; then
		clean_asroot systemctl daemon-reload >/dev/null 2>&1
	fi
	clean_asroot rm -rf /etc/systemd/system/${UNIT_PREFIX}*.service
	clean_asroot rm -rf /run/${UNIT_PREFIX}*
	clean_asroot rm -f /run/${UNIT_PREFIX}*.pid
	# The cases that create system accounts and shims at fixed paths.
	clean_asroot userdel "$(cat "$TMP/proof-user" 2>/dev/null)"
	clean_asroot groupdel "$(cat "$TMP/proof-group" 2>/dev/null)"
	[ -n "$SHIM_ANVIL" ] && clean_asroot rm -f "$SHIM_ANVIL"
	[ -n "$SHIM_JEST_LOCAL" ] && clean_asroot rmdir "$SHIM_JEST_LOCAL"
	clean_asroot rmdir /usr/lib/dovecot
	# Any stub a case managed to leave behind.
	if [ -f "$TMP/stub-pids" ]; then
		while read -r p; do
			[ -n "$p" ] && clean_asroot kill "$p"
		done <"$TMP/stub-pids"
	fi
	# A root run leaves root-owned files (a pidfile, a shim log) in here.
	rm -rf "$TMP" 2>/dev/null || clean_asroot rm -rf "$TMP"
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

# ---------------------------------------------------------------- issue #8
# `doctor --json` must describe each capability as a record with a name, not as
# a single-key object whose key is the name: a consumer cannot filter on
# `checks[].errno` otherwise, and a path cannot be a JSON key at all.
case_8() {
	have python3 || {
		skip_c "no python3 to parse the JSON document"
		return
	}
	_pf=$TMP/p8.pid
	_json=$("$BIN" doctor --json --pidfile "$_pf" 2>"$TMP/p8.err")
	_rc=$?
	if [ "$_rc" -ne 0 ] || [ -z "$_json" ]; then
		fail_c "doctor --json exited $_rc: $(head -1 "$TMP/p8.err")"
		return
	fi
	_errs=$(printf '%s' "$_json" | python3 -c '
import json, sys
want = sys.argv[1]
try:
    d = json.load(sys.stdin)
except Exception as e:
    print("the document is not JSON: %s" % e)
    raise SystemExit(0)
add = print
errs = []
checks = d.get("checks")
if not isinstance(checks, list) or not checks:
    errs.append("checks is not a non-empty array")
    checks = []
for i, item in enumerate(checks):
    if not isinstance(item, dict):
        errs.append("checks[%d] is a %s, not an object" % (i, type(item).__name__))
        continue
    if "name" not in item:
        errs.append("checks[%d] has no name field (keys %s)" % (i, sorted(item)))
    for k in ("ok", "detail"):
        if k not in item:
            errs.append("checks[%d] has no %s field" % (i, k))
    extra = set(item) - {"name", "ok", "detail", "errno"}
    if extra:
        errs.append("checks[%d] has unexpected keys %s" % (i, sorted(extra)))
names = [c.get("name") for c in checks if isinstance(c, dict)]
if "core_ok" not in d:
    errs.append("no core_ok field")
elif not isinstance(d["core_ok"], bool):
    errs.append("core_ok is not a boolean")
if "core" not in d:
    errs.append("no core field")
elif not isinstance(d["core"], list) or not d["core"]:
    errs.append("core is not a non-empty array")
else:
    for n in d["core"]:
        if n not in names:
            errs.append("core names %r, which is not one of the checks" % (n,))
    if isinstance(d.get("core_ok"), bool):
        want_ok = all(
            any(c.get("name") == n and c.get("ok") is True for c in checks if isinstance(c, dict))
            for n in d["core"])
        if d["core_ok"] != want_ok:
            errs.append("core_ok=%r but the core checks say %r" % (d["core_ok"], want_ok))
if isinstance(d.get("ok"), bool) and isinstance(d.get("core_ok"), bool):
    if d["ok"] != d["core_ok"]:
        errs.append("ok=%r and core_ok=%r disagree" % (d["ok"], d["core_ok"]))
pf = d.get("pidfile")
if not isinstance(pf, dict):
    errs.append("no pidfile object")
else:
    if "path" not in pf:
        errs.append("pidfile has no path field (keys %s)" % sorted(pf))
    elif pf["path"] != want:
        errs.append("pidfile.path is %r, not the path probed" % (pf["path"],))
    if not isinstance(pf.get("writable"), bool):
        errs.append("pidfile.writable is not a boolean")
for e in errs:
    print(e)
' "$_pf")
	if [ -n "$_errs" ]; then
		say "  #8 diagnostics:"
		printf '%s\n' "$_errs" | sed 's/^/    /' >&2
		fail_c "$(printf '%s' "$_errs" | head -1)"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #13
# Twelve independent defects. One case each, numbered 13.1 .. 13.12 in the
# order the issue lists them.

# The unit refuses a pidfile that no runtime directory can hold, so the cases
# that inspect the text name one under /run that the manager would create.
# `-n 2` keeps the ExecStart line short enough to read in one line.
unit_text() {
	"$BIN" unit -n 2 --pidfile "/run/$UNIT_PREFIX-t/psgen.pid" "$@" 2>>"$TMP/unit.err"
}

case_13_1() {
	have systemctl || {
		skip_c "no systemctl to resolve the unit's After= targets"
		return
	}
	[ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ] || {
		skip_c "PID 1 is not systemd, so the targets cannot be resolved"
		return
	}
	_after=$(unit_text | sed -n 's/^After=//p')
	[ -n "$_after" ] || {
		fail_c "the unit has no After= line"
		return
	}
	_bad=
	for _t in $_after; do
		case $_t in
			*.target) ;;
			*) continue ;;
		esac
		_state=$(systemctl show "$_t" -p LoadState 2>/dev/null | sed -n 's/^LoadState=//p')
		[ "$_state" = loaded ] || _bad="$_bad $_t(${_state:-unknown})"
	done
	if [ -n "$_bad" ]; then
		fail_c "After= names a target systemd does not have:$_bad"
		return
	fi
	pass_c
}

case_13_2() {
	_line=$(unit_text -p desktop -f desk --no-mem -d 300 -n 40 |
		sed -n 's/^ExecStart=//p')
	if [ -z "$_line" ]; then
		fail_c "the unit has no ExecStart line"
		return
	fi
	_missing=
	for _want in "-p desktop" "-f desk" "--no-mem" "-d 300"; do
		case $_line in
			*" $_want "*) ;;
			*" $_want") ;;
			*) _missing="$_missing '$_want'" ;;
		esac
	done
	if [ -n "$_missing" ]; then
		fail_c "ExecStart drops generation flags:$_missing"
		return
	fi
	pass_c
}

# --verify with --no-mem must behave the way the documentation says it does.
# The issue is the disagreement, not one particular choice: a help text that
# promises a refusal and a run that warns and continues is the defect.
case_13_3() {
	_help=$("$BIN" --help 2>/dev/null)
	_says_error=0
	_says_warn=0
	case $_help in
		*"requires --mem"*) _says_error=1 ;;
	esac
	case $_help in
		*"has no effect with --no-mem"*) _says_warn=1 ;;
	esac
	if [ "$_says_error$_says_warn" = "00" ]; then
		fail_c "the help text says nothing about --verify with --no-mem"
		return
	fi
	_pf=$TMP/13_3.pid
	_err=$("$BIN" inject -n 1 -s 1 --verify --no-mem --no-root --no-exe \
		--no-tty --no-threads --duration 1 --pidfile "$_pf" 2>&1 >/dev/null)
	_rc=$?
	stop_pidfile "$_pf"
	if [ "$_says_error" = 1 ]; then
		# The documented refusal must be a refusal.
		if [ "$_rc" -ne 2 ]; then
			fail_c "the help says --verify requires --mem but --no-mem exited $_rc (it only warned)"
			return
		fi
	else
		if [ "$_rc" -eq 2 ]; then
			fail_c "the help says --verify has no effect with --no-mem but the run exited 2"
			return
		fi
		case $_err in
			*--verify*--no-mem*) ;;
			*--no-mem*--verify*) ;;
			*)
				fail_c "the help says --verify has no effect with --no-mem, but nothing said so: $(printf '%s' "$_err" | head -1)"
				return
				;;
		esac
	fi
	pass_c
}

# `check --binaries` reports; `--require-binaries` fails. An exit code that
# ignores the missing count makes the flag useless as a CI step.
case_13_4() {
	_out=$("$BIN" check --binaries 2>/dev/null)
	_missing=$(printf '%s\n' "$_out" | sed -n 's/^binaries missing: //p')
	[ -n "$_missing" ] || {
		fail_c "check --binaries did not report a missing count"
		return
	}
	"$BIN" check --require-binaries >/dev/null 2>&1
	_req=$?
	if [ "$_missing" -gt 0 ]; then
		_want=1
	else
		_want=0
	fi
	if [ "$_req" -ne "$_want" ]; then
		fail_c "--require-binaries exited $_req with $_missing missing (expected $_want)"
		return
	fi
	# The templates line must say how much of the corpus the family kept.
	_fam=$("$BIN" check -f web 2>/dev/null | sed -n 's/^templates: //p')
	case $_fam in
		*"in family web"*) ;;
		*)
			fail_c "check -f web prints 'templates: $_fam', not the family count"
			return
			;;
	esac
	pass_c
}

# Every alias the module reader accepts must be one `-m list` prints, and every
# alias `-m list` prints must be accepted.
case_13_5() {
	_list=$("$BIN" log -m list 2>/dev/null)
	[ -n "$_list" ] || {
		fail_c "log -m list printed nothing"
		return
	}
	_bad=
	for _a in access apache nginx web flog boot dmesg rustc gcc make wget curl \
		docker dockerbuild docker_rm dockerrmi tf playbook kernel pip php; do
		"$BIN" log -m "$_a" --lines 1 >/dev/null 2>&1 || {
			_bad="$_bad $_a(not accepted)"
			continue
		}
		printf '%s\n' "$_list" | grep -q "[( ]$_a[,)]" || _bad="$_bad $_a(undocumented)"
	done
	# ...and the documented names work.
	for _a in $(printf '%s\n' "$_list" | sed -n 's/^  [a-z_]* (\(.*\))$/\1/p' | tr ',' ' '); do
		"$BIN" log -m "$_a" --lines 1 >/dev/null 2>&1 || _bad="$_bad $_a(listed but rejected)"
	done
	if [ -n "$_bad" ]; then
		fail_c "log module aliases:$_bad"
		return
	fi
	pass_c
}

# An informational line belongs on stdout: `psgen load ... | tee` must show it.
case_13_6() {
	_out=$(tmo 60 "$BIN" load --cpu-util 5 -d 1 2>/dev/null)
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "load --cpu-util 5 -d 1 exited $_rc"
		return
	fi
	case $_out in
		*load*) ;;
		*)
			fail_c "load's summary did not reach stdout (got '$(printf '%s' "$_out" | head -1)')"
			return
			;;
	esac
	pass_c
}

# `--create-users` needs root for `useradd` as well; without a word about it,
# the caller reads "use sudo" and still gets no account.
case_13_7() {
	[ "$(id -u)" = 0 ] && {
		skip_c "this case needs an unprivileged caller"
		return
	}
	_err=$("$BIN" inject -n 2 -s 7 --create-users --no-exe --no-mem --no-tty \
		--no-threads --dry-run 2>&1 >/dev/null)
	_rc=$?
	[ "$_rc" -eq 0 ] || {
		fail_c "the dry run exited $_rc: $(printf '%s' "$_err" | head -1)"
		return
	}
	case $_err in
		*--create-users*root*) ;;
		*root*--create-users*) ;;
		*)
			fail_c "--create-users as a non-root caller said nothing about it"
			return
			;;
	esac
	pass_c
}

# An unprivileged uid with no passwd entry must render the way `ps` renders it:
# the decimal uid, not the literal name `user`.
case_13_8() {
	have_sudo || {
		skip_c "needs sudo to run as a uid with no passwd entry"
		return
	}
	have setpriv || {
		skip_c "no setpriv to change uid"
		return
	}
	_uid=
	for _c in 12345 12346 12347 23456 34567; do
		if ! getent passwd "$_c" >/dev/null 2>&1; then
			_uid=$_c
			break
		fi
	done
	[ -n "$_uid" ] || {
		skip_c "every candidate uid resolves through NSS here"
		return
	}
	# The reference is `ps`'s own rendering of a live process owned by that uid,
	# so the case compares two renderers rather than a formula. The pid comes
	# from the child itself: `$!` is the sudo which spawned it, and the private
	# temp directory is not writable by the uid under test, so the pid arrives
	# on stdout that this caller opened.
	_as_user() { # _as_user <cmd...>
		asroot setpriv --reuid="$_uid" --regid="$_uid" --clear-groups "$@"
	}
	_as_user sh -c 'echo $$; exec sleep 30' >"$TMP/13_8.pid" 2>/dev/null &
	_bg=$!
	_i=0
	while [ ! -s "$TMP/13_8.pid" ] && [ "$_i" -lt 50 ]; do
		sleep 0.1
		_i=$((_i + 1))
	done
	_sl=$(head -1 "$TMP/13_8.pid" 2>/dev/null)
	case $_sl in
		"" | *[!0-9]*)
			kill "$_bg" 2>/dev/null
			skip_c "could not start a process as uid $_uid"
			return
			;;
	esac
	_want=$(ps -o user= -p "$_sl" 2>/dev/null | tr -d ' ')
	if [ "$_want" != "$_uid" ]; then
		kill "$_sl" "$_bg" 2>/dev/null
		wait "$_bg" 2>/dev/null
		skip_c "ps resolved uid $_uid to '$_want', so the reference is unavailable"
		return
	fi
	_table=$(_as_user "$BIN" table -n 40 -s 7 2>/dev/null)
	kill "$_sl" 2>/dev/null
	wait "$_bg" 2>/dev/null
	[ -n "$_table" ] || {
		fail_c "table produced nothing as uid $_uid"
		return
	}
	if ! printf '%s\n' "$_table" | awk -v u="$_want" 'NR > 1 && $1 == u { found = 1 } END { exit !found }'; then
		_what_user=$(printf '%s\n' "$_table" | awk 'NR > 1 { print $1 }' | sort -u | tr '\n' ' ')
		fail_c "the table renders uid $_uid as one of '$_what_user', not as ps does ('$_want')"
		return
	fi
	pass_c
}

# The corpus dump's `@self` sentinel has to be documented, and the readers
# have to substitute it.
case_13_9() {
	_corpus=$("$BIN" corpus 2>/dev/null)
	printf '%s\n' "$_corpus" | awk '$2 == "@self" { found = 1 } END { exit !found }' || {
		fail_c "corpus has no @self row, so the sentinel cannot be shown"
		return
	}
	_doc=$("$BIN" --help 2>/dev/null)
	case $_doc in
		*@self*) ;;
		*)
			_doc=$(cat "$SRC/README.md" 2>/dev/null)
			case $_doc in
				*@self*) ;;
				*)
					fail_c "the @self sentinel is documented neither in --help nor in README.md"
					return
					;;
			esac
			;;
	esac
	# The readers replace it, so no rendered row carries it.
	if "$BIN" list -n 200 -s 1 2>/dev/null | awk '{ print $1 }' | grep -qx '@self'; then
		fail_c "list printed the @self sentinel instead of a user"
		return
	fi
	if "$BIN" table -n 60 -s 7 2>/dev/null | awk 'NR > 1 { print $1 }' | grep -qx '@self'; then
		fail_c "table printed the @self sentinel instead of a user"
		return
	fi
	pass_c
}

# `stop` accepts -q and --elevate; the help must say so under STOP, and must
# say that `stop` leaves the pidfile in place.
case_13_10() {
	_help=$("$BIN" --help 2>/dev/null)
	_stop=$(printf '%s\n' "$_help" | awk '/^STOP/{ f = 1; next } /^[A-Z][A-Z ]*$/{ f = 0 } f')
	[ -n "$_stop" ] || {
		fail_c "the help has no STOP section"
		return
	}
	_bad=
	case $_stop in
		*--elevate*) ;;
		*) _bad="$_bad --elevate" ;;
	esac
	printf '%s\n' "$_stop" | grep -q -- '-q, --quiet' || _bad="$_bad -q/--quiet"
	# Both flags must actually be accepted by stop.
	tmo 20 "$BIN" stop -q --pidfile "$TMP/13_10-absent.pid" >/dev/null 2>&1
	[ $? -le 1 ] || _bad="$_bad 'stop -q'(rejected)"
	if [ -n "$_bad" ]; then
		fail_c "the STOP help does not document:$_bad"
		return
	fi
	_readme=$(cat "$SRC/README.md" 2>/dev/null)
	case $_readme in
		*"does not unlink"* | *"not unlink"*) ;;
		*)
			fail_c "README.md does not say that stop leaves the pidfile in place"
			return
			;;
	esac
	pass_c
}

# Repository metadata: the crate's manifest and SECURITY.md.
case_13_11() {
	_toml=$SRC/Cargo.toml
	if [ ! -f "$_toml" ]; then
		fail_c "no Cargo.toml under $SRC"
		return
	fi
	_bad=
	for _k in repository homepage readme keywords categories; do
		grep -q "^$_k[[:space:]]*=" "$_toml" || _bad="$_bad $_k"
	done
	_desc=$(sed -n 's/^description[[:space:]]*=[[:space:]]*"\(.*\)"$/\1/p' "$_toml" | head -1)
	[ ${#_desc} -ge 20 ] || _bad="$_bad description(short)"
	[ -f "$SRC/SECURITY.md" ] || _bad="$_bad SECURITY.md"
	if [ -n "$_bad" ]; then
		fail_c "the crate metadata is missing:$_bad"
		return
	fi
	pass_c
}

# The VM smoke test must read the version from Cargo.toml instead of grepping
# a literal, which turns the next version bump into a phantom VM failure.
case_13_12() {
	_vm=$SRC/tests/vm.sh
	[ -f "$_vm" ] || {
		fail_c "no tests/vm.sh under $SRC"
		return
	}
	_ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/Cargo.toml" | head -1)
	[ -n "$_ver" ] || {
		fail_c "Cargo.toml has no version"
		return
	}
	if grep -q "psgen $_ver" "$_vm"; then
		fail_c "tests/vm.sh still greps the literal 'psgen $_ver'"
		return
	fi
	grep -q 'Cargo.toml' "$_vm" || {
		fail_c "tests/vm.sh does not read the version from Cargo.toml"
		return
	}
	pass_c
}

# --------------------------------------------------------------- issue #19
# The seccomp verdict must be the errno the syscall returns, classified by the
# rule the function documents: EPERM/EACCES/ENOSYS are blocked, anything else
# (EFAULT for a null program, EINVAL for a malformed one) is reachable.
# A cross binary runs under qemu-user in the release smoke. That matters here
# for two reasons: qemu proxies syscalls, so a raw-syscall probe measures the
# emulator rather than the binary; and qemu needs a large address space and JIT
# buffer of its own, so a case that imposes RLIMIT_AS or RLIMIT_DATA cannot run
# the binary at all. Those cases say so instead of failing on qemu's shape.
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

case_19() {
	if emulated; then
		skip_c "the emulator proxies the syscall, so the probe cannot be compared"
		return
	fi
	have python3 || {
		skip_c "no python3 to poke the syscall and read the JSON"
		return
	}
	[ "$(uname -m)" = x86_64 ] || {
		skip_c "the seccomp syscall number used here is the x86_64 one (317)"
		return
	}
	have_sudo || {
		skip_c "needs sudo to install a seccomp filter with systemd-run"
		return
	}
	have systemd-run || {
		skip_c "no systemd-run to install a filter"
		return
	}
	[ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ] || {
		skip_c "PID 1 is not systemd, so no filter can be installed"
		return
	}
	_bad=

	# (a) the unfiltered kernel: whatever the syscall returns decides.
	_errno=$(python3 -c '
import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall(317, 1, 8, None)
print(ctypes.get_errno())
' 2>/dev/null)
	case $_errno in
		"" | *[!0-9]*)
			fail_c "could not poke seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, NULL)"
			return
			;;
	esac
	case $_errno in
		1 | 13 | 38) _want=blocked ;; # EPERM, EACCES, ENOSYS
		*) _want=reachable ;;
	esac
	_got=$("$BIN" doctor --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["probe"]["seccomp_user_notif"])
' 2>/dev/null)
	if [ "$_got" != "$_want" ]; then
		_bad="errno $_errno means $_want, doctor reports '$_got'"
	fi

	# (b) a policy that answers with each errno the rule names.
	for _pair in ENOSYS:blocked EPERM:blocked EACCES:blocked EINVAL:reachable; do
		_e=${_pair%%:*}
		_w=${_pair#*:}
		_g=$(asroot systemd-run --wait --pipe -q \
			-p SystemCallFilter=~seccomp \
			-p SystemCallErrorNumber="$_e" \
			-- "$BIN" doctor --json 2>/dev/null |
			python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("no-json")
    raise SystemExit(0)
print(d["probe"]["seccomp_user_notif"])
' 2>/dev/null)
		if [ "$_g" != "$_w" ]; then
			_bad="$_e from the filter means $_w, doctor reports '$_g'"
		fi
	done
	if [ -n "$_bad" ]; then
		fail_c "$_bad"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #20
# A host with the group but not the user is the case `--create-users` exists
# for: both `--user-group` attempts fail there, so the account is never made.

# Pick a corpus user this host is missing entirely, from the users the run's
# own preview names.
miss_is_missing_user() {
	! getent passwd "$1" >/dev/null 2>&1 && ! getent group "$1" >/dev/null 2>&1
}

case_20_1() {
	have_sudo || {
		skip_c "needs sudo to create a system group and run inject as root"
		return
	}
	have getent || {
		skip_c "no getent to ask NSS"
		return
	}
	have groupadd || {
		skip_c "no groupadd"
		return
	}
	# The name comes from the run itself, so the case does not depend on a
	# particular corpus row being drawn.
	_cands=$(asroot "$BIN" inject -f web -n 60 -s 8 --user --create-users \
		--dry-run --no-exe --no-mem --no-tty --no-threads 2>/dev/null |
		awk 'NF > 1 { print $1 }' | grep -vE '^[0-9]+$|^root$|^www-data$' | sort -u)
	_name=
	for _c in $_cands haproxy nginx apache2 varnishd; do
		if miss_is_missing_user "$_c"; then
			_name=$_c
			break
		fi
	done
	[ -n "$_name" ] || {
		skip_c "every corpus user already exists here, so the repair cannot be shown"
		return
	}
	printf '%s' "$_name" >"$TMP/proof-user"
	printf '%s' "$_name" >"$TMP/proof-group"
	if ! asroot groupadd -r "$_name" 2>"$TMP/g.err"; then
		fail_c "could not create the group-only host state: $(head -1 "$TMP/g.err")"
		return
	fi
	getent passwd "$_name" >/dev/null 2>&1 && {
		fail_c "user $_name exists before the run, so the case proves nothing"
		return
	}
	_pf=$TMP/20_1.pid
	_out=$(asroot "$BIN" inject -f web -n 60 -s 8 --user --create-users --no-exe \
		--no-mem --no-tty --no-threads --duration 2 --pidfile "$_pf" 2>&1)
	_rc=$?
	stop_pidfile "$_pf"
	if [ "$_rc" -ne 0 ]; then
		fail_c "inject --create-users exited $_rc: $(printf '%s' "$_out" | grep '^psgen:' | head -1)"
		return
	fi
	if ! getent passwd "$_name" >/dev/null 2>&1; then
		fail_c "the group-only host was not repaired: no passwd entry for $_name ($(printf '%s' "$_out" | grep '^psgen:' | head -1))"
		return
	fi
	pass_c
}

# A create that succeeds but which NSS cannot see must be one call per name.
# Both trees call `useradd`; only the fixed one stops after the create lands.
_shim_log() { printf '%s/log' "$TMP"; }
install_shim() { # install_shim <script-body>
	_sd=$TMP/shim
	mkdir -p "$_sd"
	printf '#!/bin/sh\n%s\n' "$1" >"$_sd/useradd"
	chmod 755 "$_sd/useradd"
}

count_shim_calls() { # count_shim_calls -> "<count> <name>" lines
	awk '{ print $NF }' "$TMP/log" 2>/dev/null | sort | uniq -c | awk '{ print $1, $2 }'
}

case_20_2() {
	have_sudo || {
		skip_c "needs sudo, because --create-users only runs as root"
		return
	}
	install_shim "echo \"\$*\" >> $(_shim_log)
exit 0"
	: >"$TMP/log"
	mkdir -p "$TMP/shimtmp"
	_pf=$TMP/20_2.pid
	asroot env PATH="$TMP/shim:/usr/bin:/bin" TMPDIR="$TMP/shimtmp" \
		"$BIN" inject -f mail -n 30 -s 8 --create-users --user --no-exe \
		--no-mem --no-tty --no-threads --pidfile "$_pf" >/dev/null 2>&1
	stop_pidfile "$_pf"
	_lines=$(count_shim_calls)
	if [ -z "$_lines" ]; then
		fail_c "the run never invoked useradd, so the count cannot be checked"
		return
	fi
	_retried=$(printf '%s\n' "$_lines" | awk '$1 > 1 { print $2 "(" $1 ")" }' | tr '\n' ' ')
	if [ -n "$_retried" ]; then
		fail_c "a create that succeeded was retried: $_retried"
		return
	fi
	pass_c
}

# The retry used to overwrite the first error, so the caller saw "already
# exists" — the second attempt's complaint — instead of the real one.
case_20_3() {
	have_sudo || {
		skip_c "needs sudo, because --create-users only runs as root"
		return
	}
	mkdir -p "$TMP/shimtmp" "$TMP/seen"
	install_shim "for a; do last=\$a; done
echo \"\$*\" >> $(_shim_log)
if [ -e \"$TMP/seen/\$last\" ]; then
	echo \"useradd: user '\$last' already exists\" >&2
	exit 9
fi
: >\"$TMP/seen/\$last\"
exit 0"
	: >"$TMP/log"
	_pf=$TMP/20_3.pid
	_err=$(asroot env PATH="$TMP/shim:/usr/bin:/bin" TMPDIR="$TMP/shimtmp" \
		"$BIN" inject -f mail -n 30 -s 8 --create-users --user --no-exe \
		--no-mem --no-tty --no-threads --pidfile "$_pf" 2>&1 >/dev/null)
	stop_pidfile "$_pf"
	_lines=$(count_shim_calls)
	[ -n "$_lines" ] || {
		fail_c "the run never invoked useradd, so the message cannot be checked"
		return
	}
	_retried=$(printf '%s\n' "$_lines" | awk '$1 > 1 { print $2 "(" $1 ")" }' | tr '\n' ' ')
	if [ -n "$_retried" ]; then
		fail_c "a successful create was retried: $_retried"
		return
	fi
	case $_err in
		*"already exists"*)
			fail_c "the retry replaced the real error with 'already exists'"
			return
			;;
		*visible*)
			;;
		*)
			fail_c "the create-but-invisible state was not reported: $(printf '%s' "$_err" | grep '^psgen:' | head -1)"
			return
			;;
	esac
	pass_c
}

# A dry run must not create accounts, but must not fall back to the caller's
# identity either: it has to name what the real run would use.
case_20_4() {
	have_sudo || {
		skip_c "needs sudo, because --create-users only runs as root"
		return
	}
	mkdir -p "$TMP/shimtmp"
	install_shim "echo \"\$*\" >> $(_shim_log)
exit 1"
	: >"$TMP/log"
	_err=$(asroot env PATH="$TMP/shim:/usr/bin:/bin" TMPDIR="$TMP/shimtmp" \
		"$BIN" inject -f mail -n 30 -s 8 --user --create-users --dry-run \
		--no-exe --no-mem --no-tty --no-threads 2>&1 >/dev/null)
	_rc=$?
	_calls=$(wc -l <"$TMP/log" 2>/dev/null || echo 0)
	if [ "$_calls" -ne 0 ]; then
		fail_c "the dry run invoked useradd $_calls times"
		return
	fi
	if [ "$_rc" -ne 0 ]; then
		fail_c "the dry run exited $_rc: $(printf '%s' "$_err" | grep '^psgen:' | head -1)"
		return
	fi
	case $_err in
		*would\ create*) ;;
		*)
			fail_c "the dry run named no identity it would create (with --create-users it said: $(printf '%s' "$_err" | grep -i 'create-users' | head -1))"
			return
			;;
	esac
	pass_c
}

# --------------------------------------------------------------- issue #21
# `check --binaries` must judge the path the command names, search PATH for a
# bare name, treat a name-mapped daemon as installed, refuse a directory, and
# account for every expanded row.

missing_lines() {
	"$BIN" check --binaries 2>/dev/null | sed -n 's/^missing: //p'
}

case_21_1() {
	_missing=$(missing_lines)
	printf '%s\n' "$_missing" | sed -n 's/^.*<- //p' >"$TMP/21_1.paths"
	_bad=
	while IFS= read -r _line; do
		[ -n "$_line" ] || continue
		_p=${_line%% *}
		case $_p in
			/*)
				if [ -f "$_p" ] && [ -x "$_p" ]; then
					_bad="$_bad $_p"
				fi
				;;
			*)
				# A bare name is looked up the way a shell would.
				if have "$_p"; then
					_bad="$_bad $_p"
				fi
				;;
		esac
	done <"$TMP/21_1.paths"
	if [ -n "$_bad" ]; then
		fail_c "reported missing although present:$_bad"
		return
	fi
	pass_c
}

# A bare command in the corpus that this host does not have, provided only
# through PATH, must be found.
case_21_2() {
	_sd=$TMP/pathshim
	mkdir -p "$_sd"
	_name=
	for _c in jest vite tsc next webpack eslint julia uv composer terraform; do
		if ! have "$_c"; then
			_name=$_c
			break
		fi
	done
	[ -n "$_name" ] || {
		skip_c "every bare corpus command this case tries is already installed"
		return
	}
	printf '#!/bin/sh\nexit 0\n' >"$_sd/$_name"
	chmod 755 "$_sd/$_name"
	if PATH="$_sd:$PATH" "$BIN" check --binaries 2>/dev/null | grep -q "^missing: $_name\$\|^missing: $_name "; then
		fail_c "a $_name on PATH was reported missing"
		return
	fi
	pass_c
}

# `dovecot/anvil` is a corpus command whose location `gen` maps; `check` has to
# ask the same map or it reports a binary `inject` would run.
case_21_3() {
	have_sudo || {
		skip_c "needs sudo to place the shim where the map says"
		return
	}
	if [ -x /usr/lib/dovecot/anvil ]; then
		skip_c "/usr/lib/dovecot/anvil already exists, so the shim would not prove anything"
		return
	fi
	asroot mkdir -p /usr/lib/dovecot 2>/dev/null || {
		skip_c "cannot create /usr/lib/dovecot"
		return
	}
	printf '#!/bin/sh\nexit 0\n' | asroot tee /usr/lib/dovecot/anvil >/dev/null 2>&1
	asroot chmod 755 /usr/lib/dovecot/anvil 2>/dev/null
	SHIM_ANVIL=/usr/lib/dovecot/anvil
	if missing_lines | grep -q '^anvil \|^anvil$'; then
		fail_c "anvil was reported missing although its mapped path is installed"
		return
	fi
	pass_c
}

# A directory is searchable, so access(X_OK) says yes; it still is not a binary.
case_21_4() {
	have_sudo || {
		skip_c "needs sudo to place a directory in /usr/local/bin"
		return
	}
	have jest && {
		skip_c "jest is installed here, so a directory of that name would not be the first match"
		return
	}
	[ -e /usr/local/bin/jest ] && {
		skip_c "/usr/local/bin/jest already exists"
		return
	}
	asroot mkdir /usr/local/bin/jest 2>/dev/null || {
		skip_c "cannot create /usr/local/bin/jest"
		return
	}
	SHIM_JEST_LOCAL=/usr/local/bin/jest
	if ! missing_lines | grep -q '^jest \|^jest$'; then
		fail_c "a directory at /usr/local/bin/jest was counted as an installed binary"
		return
	fi
	pass_c
}

# Every expanded row is either found, missing, or not a binary; the totals have
# to add up, or a row the resolver dropped goes unreported.
case_21_5() {
	_out=$("$BIN" check --binaries 2>/dev/null)
	_expanded=$(printf '%s\n' "$_out" | sed -n 's/^expanded:  *//p')
	_found=$(printf '%s\n' "$_out" | sed -n 's/^binaries found: //p')
	_missing=$(printf '%s\n' "$_out" | sed -n 's/^binaries missing: //p')
	_other=$(printf '%s\n' "$_out" | sed -n 's/^binaries not a binary: //p')
	for _v in "$_expanded" "$_found" "$_missing" "$_other"; do
		case $_v in
			"" | *[!0-9]*)
				fail_c "check --binaries did not report the four totals it is counted from: $(printf '%s\n' "$_out" | grep '^binaries' | tr '\n' ' ')"
				return
				;;
		esac
	done
	_sum=$((_found + _missing + _other))
	if [ "$_sum" -ne "$_expanded" ]; then
		fail_c "found($_found) + missing($_missing) + not a binary($_other) = $_sum, but expanded is $_expanded"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #23
# `--mem-util` must be checked against the budget it is sized from, and the
# refusal must name that budget.

# fake_meminfo <total_kb> <available_kb>
fake_meminfo() {
	{
		printf 'MemTotal:       %s kB\n' "$1"
		printf 'MemFree:        1000000 kB\n'
		printf 'MemAvailable:   %s kB\n' "$2"
		printf 'MemTotal:       %s kB\n' "$1" # /proc/meminfo has no duplicate; the first wins
	} >"$TMP/meminfo"
}

# in_fake_host <ulimit-kb> <command...>: run with a private /proc/meminfo.
in_fake_host() {
	_v=$1
	shift
	asroot unshare -m sh -c "mount --bind '$TMP/meminfo' /proc/meminfo && ulimit -v $_v && exec \"\$@\"" sh "$@"
}

case_23_1() {
	if emulated; then
		skip_c "qemu needs an address space of its own, so the budget cannot be tested"
		return
	fi
	have_sudo || {
		skip_c "needs sudo to mount a private /proc/meminfo"
		return
	}
	have unshare || {
		skip_c "no unshare to mount a private /proc/meminfo"
		return
	}
	fake_meminfo 67108864 16384
	_out=$(in_fake_host 300000 "$BIN" load --mem-util 95 -d 1 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" -ne 2 ]; then
		fail_c "a request far above MemAvailable exited $_rc, not 2 ('$(printf '%s' "$_out" | head -1)')"
		return
	fi
	case $_out in
		*--force*) ;;
		*)
			fail_c "the refusal did not offer --force"
			return
			;;
	esac
	# ...and --force means the check is skipped, not that the request succeeds.
	_out=$(in_fake_host 300000 "$BIN" load --mem-util 95 -d 1 --force 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" -eq 2 ] || printf '%s' "$_out" | grep -q 'use --force'; then
		fail_c "--force did not lift the refusal (exit $_rc)"
		return
	fi
	pass_c
}

case_23_2() {
	if emulated; then
		skip_c "qemu needs an address space of its own, so the budget cannot be tested"
		return
	fi
	have_sudo || {
		skip_c "needs sudo to mount a private /proc/meminfo"
		return
	}
	have unshare || {
		skip_c "no unshare to mount a private /proc/meminfo"
		return
	}
	fake_meminfo 67108864 16384
	_out=$(in_fake_host 300000 "$BIN" load --mem-util 95 -d 1 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" -ne 2 ]; then
		fail_c "the over-budget request was not refused (exit $_rc)"
		return
	fi
	case $_out in
		*MemAvailable*) ;;
		*)
			fail_c "the refusal does not name the budget it used: $(printf '%s' "$_out" | head -1)"
			return
			;;
	esac
	printf '%s' "$_out" | grep -q '16 MiB' || {
		fail_c "the refusal does not carry the available figure (16 MiB): $(printf '%s' "$_out" | head -1)"
		return
	}
	pass_c
}

# Inside a cgroup the budget is the cgroup's, not the host's: 20% of a 512 MiB
# limit is 102 MiB, and that is the number the refusal must carry.
case_23_3() {
	if emulated; then
		skip_c "qemu needs an address space of its own, so the budget cannot be tested"
		return
	fi
	have_sudo || {
		skip_c "needs sudo for a cgroup scope and a private /proc/meminfo"
		return
	}
	have systemd-run || {
		skip_c "no systemd-run to place the run in a cgroup"
		return
	}
	have unshare || {
		skip_c "no unshare to mount a private /proc/meminfo"
		return
	}
	[ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ] || {
		skip_c "PID 1 is not systemd, so no memory cgroup can be created"
		return
	}
	fake_meminfo 67108864 16384
	_out=$(asroot systemd-run --scope -q -p MemoryMax=536870912 -- \
		unshare -m sh -c "mount --bind '$TMP/meminfo' /proc/meminfo && ulimit -v 400000 && exec \"\$@\"" sh \
		"$BIN" load --mem-util 20 -d 1 2>&1 >/dev/null)
	_rc=$?
	if [ "$_rc" -ne 2 ]; then
		fail_c "20% of a 512 MiB cgroup (102 MiB) over 16 MiB available exited $_rc, not 2 ('$(printf '%s' "$_out" | head -1)')"
		return
	fi
	case $_out in
		*"102 MiB"*) ;;
		*)
			fail_c "the refusal is not sized against the cgroup: $(printf '%s' "$_out" | head -1)"
			return
			;;
	esac
	pass_c
}

# --------------------------------------------------------------- issue #24
# A closed reader must stop the generator, a failed write must be an error, and
# `--lines` must bound the output rather than only the event count.

case_24_1() {
	if emulated; then
		skip_c "qemu cannot run under the address-space limit this case imposes"
		return
	fi
	have timeout || {
		skip_c "no timeout(1) to bound the case"
		return
	}
	# A reader that leaves after one line must take the generator with it. The
	# pids are the pipeline's own subshells, so this tests that the reader's
	# exit ended the writer rather than scraping a process table and matching
	# this script's own command line.
	s="$TMP/24_1.out"
	( "$BIN" log --lines 200000 --delay 10 2>"$TMP/24_1.err" | head -1 >"$s" ) &
	_sub=$!
	sleep 2
	_alive=0
	if kill -0 "$_sub" 2>/dev/null; then
		_alive=1
		kill "$_sub" 2>/dev/null
		pkill -f "$BIN log --lines 200000 --delay 10" 2>/dev/null
	fi
	wait "$_sub" 2>/dev/null
	if [ "$_alive" = 1 ]; then
		fail_c "the generator was still running 2 s after its reader exited"
		return
	fi
	[ -s "$s" ] || {
		fail_c "the reader got no line at all"
		return
	}
	# ...and the whole output must not be buffered before the first write: a
	# 64 MiB address space cannot hold 200000 rows.
	( ulimit -v 65536; "$BIN" log --lines 200000 2>"$TMP/24_1.mem" | head -1 >"$TMP/24_1.one" )
	[ -s "$TMP/24_1.one" ] || {
		fail_c "no line came out under a 64 MiB address space ($(head -1 "$TMP/24_1.mem"))"
		return
	}
	if grep -q 'memory allocation' "$TMP/24_1.mem"; then
		fail_c "the output was buffered until allocation failed: $(head -1 "$TMP/24_1.mem")"
		return
	fi
	pass_c
}

# A write that fails for any reason other than a closed pipe is an error.
case_24_2() {
	have_sudo || {
		skip_c "needs sudo to mount a full filesystem"
		return
	}
	_m=$TMP/full
	mkdir -p "$_m" || {
		skip_c "cannot create a mount point"
		return
	}
	if ! asroot mount -t tmpfs -o size=64k tmpfs "$_m" 2>"$TMP/24_2.mount"; then
		skip_c "cannot mount a tmpfs here ($(head -1 "$TMP/24_2.mount"))"
		return
	fi
	_err=$("$BIN" table -n 4000 -s 1 2>&1 >"$_m/out")
	_rc=$?
	asroot umount "$_m" 2>/dev/null
	if [ "$_rc" -eq 0 ]; then
		fail_c "a write that could not fit on the filesystem exited 0"
		return
	fi
	case $_err in
		*write* | *space* | *ENOSPC*) ;;
		*)
			fail_c "the write failure was not reported: '$(printf '%s' "$_err" | head -1)'"
			return
			;;
	esac
	pass_c
}

# `--lines` bounds what is emitted, not just how many events are formatted: an
# absurd count must be capped and say so, and the output must stay bounded.
case_24_3() {
	if emulated; then
		skip_c "qemu cannot run under the address-space limit this case imposes"
		return
	fi
	have timeout || {
		skip_c "no timeout(1) to bound the case"
		return
	}
	( ulimit -v 524288
	  timeout 120 "$BIN" log --lines 2000000000 >"$TMP/24_3.big" 2>"$TMP/24_3.err" )
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		fail_c "log --lines 2000000000 exited $_rc ($(head -1 "$TMP/24_3.err"))"
		return
	fi
	_bytes=$(wc -c <"$TMP/24_3.big")
	if [ "$_bytes" -gt $((200 * 1024 * 1024)) ]; then
		fail_c "log --lines 2000000000 emitted $_bytes bytes"
		return
	fi
	grep -qi 'cap' "$TMP/24_3.err" || {
		fail_c "the capped line count was not reported"
		return
	}
	# The cap is on events, and one event can be several rows, so the emitted
	# output is what has a bound.
	_bytes=$(tmo 120 "$BIN" log --lines 200000 2>/dev/null | wc -c)
	if [ "$_bytes" -le 0 ] || [ "$_bytes" -gt $((200 * 1024 * 1024)) ]; then
		fail_c "log --lines 200000 emitted $_bytes bytes"
		return
	fi
	pass_c
}

# --------------------------------------------------------------- issue #27
# The printed unit must survive a real systemd start/stop/start, and stop must
# fail only for a real failure.

need_systemd() {
	have systemctl || {
		skip_c "no systemctl"
		return 1
	}
	[ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ] || {
		skip_c "PID 1 is not systemd"
		return 1
	}
	have_sudo || {
		skip_c "needs sudo to install a unit"
		return 1
	}
	return 0
}

# install_unit <name> <pidfile> — print the unit and install it; returns 1 when
# psgen refused to print one.
install_unit() {
	asroot "$BIN" unit -n 2 --pidfile "$2" >"$TMP/$1.service" 2>"$TMP/$1.unit.err" || return 1
	asroot cp "$TMP/$1.service" "/etc/systemd/system/$1.service" || return 1
	asroot systemctl daemon-reload || return 1
}

systemctl_show() { # systemctl_show <unit> <property>
	asroot systemctl show "$1" -p "$2" 2>/dev/null | sed -n "s/^$2=//p"
}

# unit_status <unit> — one line of why a start or stop failed: the result, the
# failing control process's exit code, and the first diagnostic the unit's own
# output carried. A bare `Result=exit-code` does not say what refused.
unit_status() {
	_r=$(systemctl_show "$1" Result)
	_p=$(asroot systemctl show "$1" -p ExecMainStatus 2>/dev/null | sed -n 's/^ExecMainStatus=//p')
	_msg=$(asroot journalctl -q --no-pager -u "$1" -n 20 -o cat 2>/dev/null |
		grep -E '^psgen:|cannot|failed|not ' | head -1)
	printf 'Result=%s status=%s%s' "$_r" "${_p:-?}" "${_msg:+: $_msg}"
}

# unit_pids <pidfile> — the stub pids a unit's run recorded, also banked for the
# exit trap.
unit_pids() {
	asroot sh -c 'test -f "$1" && grep -v "^#" "$1" | awk "NF >= 1 { print \$1 }"' sh "$1" 2>/dev/null |
		while read -r _p; do
			printf '%s\n' "$_p" >>"$TMP/stub-pids"
			printf '%s\n' "$_p"
		done
}

# wait_gone <pid> — a signalled process needs a moment to leave /proc.
wait_gone() {
	_i=0
	while [ -d "/proc/$1" ] && [ "$_i" -lt 30 ]; do
		sleep 0.1
		_i=$((_i + 1))
	done
	[ ! -d "/proc/$1" ]
}

case_27_1() {
	need_systemd || return
	_u="$UNIT_PREFIX-a"
	_run="/run/$_u/psgen.pid"
	if ! install_unit "$_u" "$_run"; then
		fail_c "psgen refused to print the unit: $(head -1 "$TMP/$_u.unit.err")"
		unit_stop "$_u"
		return
	fi
	asroot systemctl start "$_u" >/dev/null 2>&1 || {
		fail_c "the first start failed ($(unit_status "$_u"))"
		unit_stop "$_u"
		return
	}
	_pids=$(unit_pids "$_run")
	if [ -z "$_pids" ]; then
		fail_c "the unit started without recording any stub"
		unit_stop "$_u"
		return
	fi
	asroot systemctl stop "$_u" >/dev/null 2>&1
	for _p in $_pids; do
		if ! wait_gone "$_p"; then
			fail_c "stop left stub $_p running"
			unit_stop "$_u"
			return
		fi
	done
	if ! asroot systemctl start "$_u" >/dev/null 2>"$TMP/27_1.restart"; then
		fail_c "the unit could not be started a second time: $(head -1 "$TMP/27_1.restart")"
		unit_stop "$_u"
		return
	fi
	_again=$(unit_pids "$_run")
	if [ -z "$_again" ]; then
		fail_c "the restarted unit recorded no stub"
		unit_stop "$_u"
		return
	fi
	asroot systemctl stop "$_u" >/dev/null 2>&1
	if [ "$(systemctl_show "$_u" Result)" = failed ]; then
		fail_c "the second stop failed"
		unit_stop "$_u"
		return
	fi
	for _p in $_again; do
		if ! wait_gone "$_p"; then
			fail_c "the second stop left stub $_p running"
			unit_stop "$_u"
			return
		fi
	done
	unit_stop "$_u"
	pass_c
}

# Two units in two RuntimeDirectories: stopping one must not touch the other.
case_27_2() {
	need_systemd || return
	_a="$UNIT_PREFIX-a"
	_b="$UNIT_PREFIX-b"
	_pa="/run/$_a/psgen.pid"
	_pb="/run/$_b/psgen.pid"
	if ! install_unit "$_a" "$_pa"; then
		fail_c "psgen refused to print the first unit: $(head -1 "$TMP/$_a.unit.err")"
		unit_stop "$_a"
		return
	fi
	if ! install_unit "$_b" "$_pb"; then
		fail_c "psgen refused to print the second unit: $(head -1 "$TMP/$_b.unit.err")"
		unit_stop "$_a"
		unit_stop "$_b"
		return
	fi
	asroot systemctl start "$_a" >/dev/null 2>&1 || {
		fail_c "the first unit did not start ($(unit_status "$_a"))"
		unit_stop "$_a"
		unit_stop "$_b"
		return
	}
	asroot systemctl start "$_b" >/dev/null 2>&1 || {
		fail_c "the second unit did not start ($(unit_status "$_b"))"
		unit_stop "$_a"
		unit_stop "$_b"
		return
	}
	_pids=$(unit_pids "$_pa")
	if [ -z "$_pids" ]; then
		fail_c "the first unit recorded no stub"
		unit_stop "$_a"
		unit_stop "$_b"
		return
	fi
	asroot systemctl stop "$_b" >/dev/null 2>&1
	if [ "$(systemctl_show "$_a" ActiveState)" != active ]; then
		fail_c "stopping the second unit left the first one $(systemctl_show "$_a" ActiveState)"
		unit_stop "$_a"
		unit_stop "$_b"
		return
	fi
	for _p in $_pids; do
		if [ ! -d "/proc/$_p" ]; then
			fail_c "stopping the second unit killed the first unit's stub $_p"
			unit_stop "$_a"
			unit_stop "$_b"
			return
		fi
	done
	asroot systemctl stop "$_a" >/dev/null 2>&1
	asroot systemctl start "$_a" >/dev/null 2>&1 || {
		fail_c "the first unit could not be restarted after the second was stopped"
		unit_stop "$_a"
		unit_stop "$_b"
		return
	}
	asroot systemctl stop "$_a" >/dev/null 2>&1
	unit_stop "$_a"
	unit_stop "$_b"
	pass_c
}

# ExecStop reports a real failure and tolerates only an absent pidfile.
#
# This case drives the printed unit's own `ExecStop=` lines with `/bin/sh`
# rather than through `systemctl`: the question is what those two directives do
# with a missing pidfile and with a foreign one, and a start that never
# succeeded must not hide the answer. The unit's `ExecStart` is not under test
# here (27.1 starts it for real).
case_27_3() {
	need_systemd || return
	_u="$UNIT_PREFIX-a"
	_run="/run/$_u/psgen.pid"
	if ! install_unit "$_u" "$_run"; then
		fail_c "psgen refused to print the unit: $(head -1 "$TMP/$_u.unit.err")"
		unit_stop "$_u"
		return
	fi
	asroot mkdir -p "/run/$_u"
	asroot chmod 700 "/run/$_u"
	_stage_pids=
	stage_run() { # stage_run: make a live run and point its pidfile at _run
		asroot "$BIN" inject -n 2 -s 7 --pidfile "$_run" -d 300 >/dev/null 2>&1
		_stage_pids=$(asroot sh -c 'test -f "$1" && grep -v "^#" "$1" | awk "NF >= 1 { print \$1 }"' \
			sh "$_run" 2>/dev/null)
		for _p in $_stage_pids; do printf '%s\n' "$_p" >>"$TMP/stub-pids"; done
		asroot test -f "$_run"
	}
	# Every `ExecStop=` line, in the order systemd runs them. A `-` prefix is
	# the unit's own statement that the failure is benign, so it is honoured
	# rather than stripped: the case is about what the directives report.
	_stops=$(grep '^ExecStop=' "$TMP/$_u.service" | sed 's/^ExecStop=//')
	[ -n "$_stops" ] || {
		fail_c "the unit has no ExecStop= line"
		unit_stop "$_u"
		return
	}
	# run_stops: run every directive; print the number that reported failure.
	run_stops() {
		_failed=0
		_n=0
		while IFS= read -r _body; do
			_n=$((_n + 1))
			_benign=
			case $_body in
				-*) _benign=1; _body=${_body#-} ;;
			esac
			asroot sh -c "exec $_body" >/dev/null 2>&1
			_rc=$?
			[ "$_rc" -ne 0 ] && [ -z "$_benign" ] && _failed=$((_failed + 1))
		done <<EOF
$_stops
EOF
		printf '%s' "$_failed"
	}
	if ! stage_run; then
		fail_c "could not stage a run for the ExecStop case"
		unit_stop "$_u"
		return
	fi
	# (a) An absent pidfile is the only state the directives may call benign.
	# `inject` may have exited on --duration or the manager may have cleaned
	# up, and neither is a failed service stop.
	asroot rm -f "$_run"
	_failed=$(run_stops)
	if [ "$_failed" -ne 0 ]; then
		fail_c "a stop with no pidfile present reported $_failed failed directive(s)"
		unit_stop "$_u"
		return
	fi
	# (b) A pidfile that names another boot is a real failure: the stubs it
	# names are still running, so the stop must not be reported as a success.
	if ! stage_run; then
		fail_c "could not stage a run for the foreign-boot case"
		unit_stop "$_u"
		return
	fi
	asroot sed -i '1s/boot [^ ]*/boot 00000000-0000-0000-0000-000000000000/' "$_run"
	_failed=$(run_stops)
	if [ "$_failed" -eq 0 ]; then
		fail_c "a pidfile from another boot was reported as a successful stop"
		unit_stop "$_u"
		return
	fi
	_alive=0
	for _p in $_stage_pids; do
		[ -d "/proc/$_p" ] && _alive=$((_alive + 1))
	done
	_want=$(printf '%s\n' "$_stage_pids" | grep -c .)
	if [ "$_alive" -ne "$_want" ]; then
		fail_c "a stop that reported failure still signalled its stubs"
		unit_stop "$_u"
		return
	fi
	asroot rm -f "$_run"
	unit_stop "$_u"
	asroot rm -rf "/run/$_u"
	pass_c
}

# ------------------------------------------------------------------ driver

run_case 8 8 "doctor --json checks are objects with a name" case_8
run_case 13.1 13 "unit names a target systemd has" case_13_1
run_case 13.2 13 "unit forwards the generation flags it was given" case_13_2
run_case 13.3 13 "--verify with --no-mem matches its documentation" case_13_3
run_case 13.4 13 "check --require-binaries fails when binaries are missing" case_13_4
run_case 13.5 13 "log module aliases are documented and accepted" case_13_5
run_case 13.6 13 "load writes its summary to stdout" case_13_6
run_case 13.7 13 "--create-users without root says so" case_13_7
run_case 13.8 13 "a uid with no passwd entry renders as ps renders it" case_13_8
run_case 13.9 13 "the corpus @self sentinel is documented and substituted" case_13_9
run_case 13.10 13 "help documents stop's -q and --elevate" case_13_10
run_case 13.11 13 "the crate carries its repository metadata and SECURITY.md" case_13_11
run_case 13.12 13 "tests/vm.sh reads the version from Cargo.toml" case_13_12
run_case 19 19 "doctor's seccomp verdict matches the syscall's errno" case_19
run_case 20.1 20 "--create-users repairs a group-only host" case_20_1
run_case 20.2 20 "one useradd per missing name" case_20_2
run_case 20.3 20 "a create NSS cannot see is not retried" case_20_3
run_case 20.4 20 "--create-users --dry-run names the identity" case_20_4
run_case 21.1 21 "an existing absolute path is reported present" case_21_1
run_case 21.2 21 "a bare name resolves against PATH" case_21_2
run_case 21.3 21 "a name-mapped binary is not reported missing" case_21_3
run_case 21.4 21 "a directory is not a binary" case_21_4
run_case 21.5 21 "the reported totals equal the expanded count" case_21_5
run_case 23.1 23 "--mem-util above the available budget needs --force" case_23_1
run_case 23.2 23 "the refusal names the budget it used" case_23_2
run_case 23.3 23 "a cgroup request is sized against the cgroup" case_23_3
run_case 24.1 24 "a closed reader stops log promptly" case_24_1
run_case 24.2 24 "a failed write is an error, not a truncation" case_24_2
run_case 24.3 24 "--lines bounds the emitted output" case_24_3
run_case 27.1 27 "the printed unit starts, stops and restarts" case_27_1
run_case 27.2 27 "a second unit in another RuntimeDirectory is independent" case_27_2
run_case 27.3 27 "ExecStop reports a real failure only" case_27_3

if [ "$RAN" = 0 ]; then
	echo "report.sh: no case matched '$SELECTED'" >&2
	exit 2
fi

if [ "$FAILS" -gt 0 ]; then
	exit 1
fi
exit 0
