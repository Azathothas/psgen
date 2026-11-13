#!/bin/sh
# Run the cross-built binaries: x86_64 and i686 directly, the other five under
# qemu-user. The target set matches .github/workflows/release.yml.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/tests/helpers/gate.sh"
DIST="$ROOT/dist"
# The expected version comes from Cargo.toml, so a bump cannot leave the
# assertion pinned to a literal no build produces.
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
[ -n "$VERSION" ] || { echo "cross: no version in Cargo.toml" >&2; exit 1; }
[ -d "$DIST" ] || { echo "build the static targets first (see .github/workflows/release.yml)" >&2; exit 1; }

check() {
    name=$1
    qemu=$2
    bin="$DIST/psgen-$name"
    [ -x "$bin" ] || { echo "missing $bin" >&2; exit 1; }
    echo "== $name"
    if [ -n "$qemu" ]; then
        if ! command -v "$qemu" >/dev/null 2>&1; then
            skip "$name needs $qemu"
            return 0
        fi
        "$qemu" "$bin" --version | grep -q "^psgen $VERSION$"
        "$qemu" "$bin" table -n 3 -s 1 | grep -q '^USER '
    else
        "$bin" --version | grep -q "^psgen $VERSION$"
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
