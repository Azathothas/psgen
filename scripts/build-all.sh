#!/bin/sh
# Build the local static x86_64 musl binary and verify that it is static.
#
# The full release matrix is built by .github/workflows/release.yml. This
# helper builds only the host target and prints the binary path.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

TARGET=x86_64-unknown-linux-musl
BIN="target/$TARGET/release/psgen"

cargo build --locked --release --target "$TARGET"

[ -f "$BIN" ] || {
    echo "missing $BIN" >&2
    exit 1
}

command -v readelf >/dev/null 2>&1 || {
    echo "readelf not found; cannot verify static linkage" >&2
    exit 1
}

dynamic=$(readelf -d "$BIN") || {
    echo "readelf -d failed for $BIN" >&2
    exit 1
}
case "$dynamic" in
    *NEEDED*)
        echo "dynamic dependencies in $BIN" >&2
        exit 1
        ;;
esac

program=$(readelf -l "$BIN") || {
    echo "readelf -l failed for $BIN" >&2
    exit 1
}
case "$program" in
    *INTERP*)
        echo "dynamic interpreter in $BIN" >&2
        exit 1
        ;;
esac

echo "$ROOT/$BIN"
