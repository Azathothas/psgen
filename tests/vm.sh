#!/bin/sh
# Boot a minimal KVM guest with the static x86_64 musl binary and busybox, and
# exercise the injection path as real root in init_user_ns. This is the check
# that matters for mount namespaces, the exe link and the stop path.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/dist/psgen-x86_64-unknown-linux-musl"
KERNEL=$(ls /boot/vmlinuz-* 2>/dev/null | head -1 || true)
BUSYBOX=$(command -v busybox || true)
QEMU=$(command -v qemu-system-x86_64 || true)

if [ ! -x "$BIN" ] || [ -z "$KERNEL" ] || [ -z "$BUSYBOX" ] || [ -z "$QEMU" ]; then
    echo "vm: skipped (need dist binary, /boot/vmlinuz-*, busybox, qemu-system-x86_64)" >&2
    exit 0
fi
if [ ! -e /dev/kvm ]; then
    echo "vm: skipped (no /dev/kvm)" >&2
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/rootfs/bin" "$TMP/rootfs/proc" "$TMP/rootfs/sys" \
    "$TMP/rootfs/dev" "$TMP/rootfs/tmp" "$TMP/rootfs/run" \
    "$TMP/rootfs/usr/sbin" "$TMP/rootfs/usr/bin" "$TMP/rootfs/usr/lib"
cp "$BUSYBOX" "$TMP/rootfs/bin/busybox"
for a in sh mount mkdir cat awk readlink poweroff '['; do
    ln -sf busybox "$TMP/rootfs/bin/$a"
done
cp "$BIN" "$TMP/rootfs/psgen"
cat > "$TMP/rootfs/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmp /tmp
mkdir -p /run
echo "== version"
/psgen --version
echo "== inject"
/psgen inject -n 6 -s 7 --no-user --pidfile /run/pids
cat /run/pids
for p in $(awk -F'\t' '!/^#/{print $1}' /run/pids); do
    printf '%s ' "$p"
    readlink /proc/$p/exe
done
echo "== table"
/psgen inject -n 4 -s 11 --no-user --no-mem --no-tty --no-threads \
    --table --pidfile /run/pids2
/psgen stop --pidfile /run/pids
/psgen stop --pidfile /run/pids2
echo "== stopped"
poweroff -f
EOF
chmod +x "$TMP/rootfs/init"
(cd "$TMP/rootfs" && find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$TMP/initrd.gz")

timeout 120 "$QEMU" -enable-kvm -m 2048 -smp 2 -kernel "$KERNEL" \
    -initrd "$TMP/initrd.gz" \
    -append "console=ttyS0 rdinit=/init panic=-1" \
    -nographic -no-reboot > "$TMP/out" 2>&1 || true

cat "$TMP/out"
grep -q '^psgen 0\.' "$TMP/out" || { echo "vm: version missing" >&2; exit 1; }
grep -q 'spawned 6' "$TMP/out" || { echo "vm: inject did not spawn 6" >&2; exit 1; }
grep -q '/usr/sbin/nginx' "$TMP/out" || { echo "vm: nginx exe missing" >&2; exit 1; }
grep -q '/usr/bin/flanneld' "$TMP/out" || { echo "vm: flanneld exe missing" >&2; exit 1; }
grep -q 'spawned 4' "$TMP/out" || { echo "vm: table inject did not spawn 4" >&2; exit 1; }
grep -q 'stopped' "$TMP/out" || { echo "vm: stop missing" >&2; exit 1; }
echo "vm: ok"
