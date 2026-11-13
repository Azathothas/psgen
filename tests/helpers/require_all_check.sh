#!/bin/sh
# Prove the skip rule both ways: SKIP without PSGEN_REQUIRE_ALL, FAIL with it.
#
# tests/helpers/gate.sh is the one place the rule lives, and a suite that
# skipped in CI would let every check behind that skip pass unexercised. This
# script drives the helper through a real skip and asserts both branches, so
# the rule cannot rot into "always skip" or "always fail".
#
# Usage: require_all_check.sh [<gate.sh>]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
GATE=${1:-$ROOT/tests/helpers/gate.sh}
[ -f "$GATE" ] || { echo "FAIL: $GATE is missing" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

REASON="synthetic capability missing"
cat > "$TMP/probe.sh" <<'PROBE'
. "$1"
# skip() prints the reason and returns, so the caller can skip the blocked
# section and carry on with the rest of the suite.
skip "synthetic capability missing"
echo "PROBE-RETURNED"
PROBE

# 1. No PSGEN_REQUIRE_ALL: a printed SKIP with the reason, and a clean return.
env -u PSGEN_REQUIRE_ALL sh "$TMP/probe.sh" "$GATE" \
    >"$TMP/plain.out" 2>"$TMP/plain.err" ||
    { echo "FAIL: skip() exited non-zero without PSGEN_REQUIRE_ALL" >&2; exit 1; }
grep -qx "SKIP: $REASON" "$TMP/plain.err" ||
    { echo "FAIL: skip() did not print 'SKIP: $REASON'" >&2; exit 1; }
grep -qx "PROBE-RETURNED" "$TMP/plain.out" ||
    { echo "FAIL: skip() did not return to its caller without " >&2
      echo "PSGEN_REQUIRE_ALL" >&2; exit 1; }
if grep -q '^FAIL' "$TMP/plain.err"; then
    echo "FAIL: skip() failed without PSGEN_REQUIRE_ALL" >&2
    exit 1
fi

# 2. PSGEN_REQUIRE_ALL=1: a failure that names the same reason, and no SKIP.
if PSGEN_REQUIRE_ALL=1 sh "$TMP/probe.sh" "$GATE" \
        >"$TMP/req.out" 2>"$TMP/req.err"; then
    echo "FAIL: skip() passed under PSGEN_REQUIRE_ALL=1" >&2
    exit 1
fi
grep -q "FAIL: required capability missing: $REASON" "$TMP/req.err" ||
    { echo "FAIL: the PSGEN_REQUIRE_ALL failure did not name the capability" >&2
      exit 1; }
if grep -q '^SKIP' "$TMP/req.err"; then
    echo "FAIL: skip() printed SKIP under PSGEN_REQUIRE_ALL=1" >&2
    exit 1
fi
if grep -q 'PROBE-RETURNED' "$TMP/req.out"; then
    echo "FAIL: skip() returned under PSGEN_REQUIRE_ALL=1 instead of failing" >&2
    exit 1
fi

# 3. PSGEN_REQUIRE_ALL=0 is the same as unset, so a caller can override CI.
if ! PSGEN_REQUIRE_ALL=0 sh "$TMP/probe.sh" "$GATE" \
        >"$TMP/zero.out" 2>"$TMP/zero.err"; then
    echo "FAIL: PSGEN_REQUIRE_ALL=0 still failed a skip" >&2
    exit 1
fi
grep -qx "SKIP: $REASON" "$TMP/zero.err" ||
    { echo "FAIL: PSGEN_REQUIRE_ALL=0 did not print SKIP" >&2; exit 1; }

echo "   the skip rule: SKIP without PSGEN_REQUIRE_ALL, FAIL with it"
