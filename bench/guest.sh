#!/bin/sh
# Measurement script run inside a sandbox cage.
#
# It injects N processes and then reads them back through the five tools the
# benchmark reports on. Output goes to one stream, so each section starts with
# a marker the host script can split on. The microVM guest has no stdin and
# merges stdout and stderr, so nothing here prompts and nothing depends on a
# terminal of its own.

set -u

BIN=./psgen
N=${N:-40}

echo "=== ENV"
uname -srm
head -1 /etc/os-release
id
echo "cpus: $(nproc)"
awk '/MemTotal/{print "mem_kb: " $2}' /proc/meminfo

# The microVM init does not mount devpts, so /dev/ptmx cannot be opened until
# it is. The container already has it.
if [ ! -e /dev/pts/ptmx ] && [ "$(id -u)" = 0 ]; then
    mkdir -p /dev/pts
    mount -t devpts devpts /dev/pts 2>/dev/null
fi

echo "=== DOCTOR"
$BIN doctor

echo "=== DOCTOR JSON"
$BIN doctor --json

echo "=== INJECT"
$BIN inject -n "$N" -s 7 --pidfile /tmp/pids 2>&1
PIDS=$(awk -F'\t' '!/^#/{print $1}' /tmp/pids)
echo "=== PIDS"
echo "$PIDS" | tr '\n' ' '
echo

echo "=== PS"
ps aux

echo "=== TOP"
top -b -n1 -w 200

echo "=== COMM"
for p in $PIDS; do
    printf '%s %s\n' "$p" "$(cat "/proc/$p/comm" 2>/dev/null)"
done

echo "=== EXE"
for p in $PIDS; do
    printf '%s %s\n' "$p" "$(readlink "/proc/$p/exe" 2>/dev/null)"
done

# htop and btop draw a full screen and need a terminal. tmux owns a real pty,
# so capture-pane returns the exact screen a user would see, at a known size,
# with no escape-sequence stripping involved.
shot() {
    tmux -L "$1" -f /dev/null new-session -d -s "$1" -x 160 -y 48 "$2"
    sleep 2
    tmux -L "$1" capture-pane -p -t "$1"
    tmux -L "$1" kill-server 2>/dev/null
}

# htop's sort key is the column name M_RESIDENT/PERCENT_MEM, not the display
# label MEM. Sort by resident memory so the padded rows reach the screen, and
# keep htop's default of hiding kernel threads.
echo "=== HTOP"
export TERM=xterm-256color
shot htop "htop -s PERCENT_MEM -d 100"

# btop reads XDG_CONFIG_HOME, not BTOP_CONFIG_DIR. Hiding kernel threads keeps
# zero-memory threads off the visible rows, whose order is pid; the padded rows
# carry contiguous pids and fill the top of the list.
mkdir -p /tmp/xdg/btop
printf 'proc_filter_kernel = True\n' > /tmp/xdg/btop/btop.conf
export XDG_CONFIG_HOME=/tmp/xdg
echo "=== BTOP"
shot btop "btop --utf-force"
unset XDG_CONFIG_HOME

echo "=== STOP"
$BIN stop --pidfile /tmp/pids

echo "=== AFTER"
# stop signals and returns; give the kernel a moment to reap. A zombie has
# already exited, so only a live state counts as a survivor.
sleep 1
for p in $PIDS; do
    state=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
    if [ -n "$state" ] && [ "$state" != "Z" ]; then
        echo "alive $p state=$state"
    fi
done
echo "after-check-done"
