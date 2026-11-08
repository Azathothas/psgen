#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/target/release/psgen"

echo "== version"
"$BIN" --version | grep -q '^psgen 0\.0\.1$'

echo "== help"
"$BIN" --help | grep -q 'psgen inject'

echo "== corpus denylist and expanded output"
"$BIN" check >/dev/null

echo "== corpus dump"
n=$("$BIN" corpus | wc -l)
[ "$n" -ge 180 ] || { echo "corpus has only $n templates" >&2; exit 1; }

echo "== list"
n=$("$BIN" list -n 0 -s 1 | wc -l)
[ "$n" -ge 180 ] || { echo "list has only $n lines" >&2; exit 1; }

echo "== deterministic seed"
a=$("$BIN" table -n 12 -s 42)
b=$("$BIN" table -n 12 -s 42)
[ "$a" = "$b" ] || { echo "seed is not deterministic" >&2; exit 1; }

echo "== invariants and injection"
python3 "$ROOT/tests/invariants.py"

echo "== size"
if command -v size >/dev/null 2>&1; then
    size "$BIN"
fi
bytes=$(stat -c %s "$BIN")
[ "$bytes" -lt 1048576 ] || { echo "binary is $bytes bytes, over 1 MiB" >&2; exit 1; }

echo "smoke: ok"
