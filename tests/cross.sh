#!/bin/sh
# Run the cross-built binaries: x86_64 and i686 directly, the other five under
# qemu-user. The target set matches .github/workflows/release.yml.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST="$ROOT/dist"
[ -d "$DIST" ] || { echo "build the static targets first (see .github/workflows/release.yml)" >&2; exit 1; }

check() {
    name=$1
    qemu=$2
    bin="$DIST/psgen-$name"
    [ -x "$bin" ] || { echo "missing $bin" >&2; exit 1; }
    echo "== $name"
    if [ -n "$qemu" ]; then
        "$qemu" "$bin" --version | grep -q '^psgen 0\.0\.1$'
        "$qemu" "$bin" table -n 3 -s 1 | grep -q '^USER '
    else
        "$bin" --version | grep -q '^psgen 0\.0\.1$'
        "$bin" table -n 3 -s 1 | grep -q '^USER '
    fi
}

check x86_64-unknown-linux-musl ""
check i686-unknown-linux-musl ""
check aarch64-unknown-linux-musl qemu-aarch64-static
check riscv64gc-unknown-linux-musl qemu-riscv64-static
check armv7-unknown-linux-musleabihf qemu-arm-static
check loongarch64-unknown-linux-musl qemu-loongarch64-static
check powerpc64le-unknown-linux-musl qemu-ppc64le-static

echo "cross: ok"
