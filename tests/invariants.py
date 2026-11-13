#!/usr/bin/env python3
"""Invariant checks for psgen. Run by tests/smoke.sh.

The agent-side checks run as the invoking user. Root-side checks run as root
when the caller is root, and through sudo when passwordless sudo is available;
otherwise they skip.

PSGEN_REQUIRE_ALL=1 (set by CI) turns every skip into a failure that names the
missing capability. A check that cannot run must not pass quietly.
"""

from __future__ import annotations

import ast
import ctypes
import json
import math
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(os.environ.get("PSGEN_BIN", ROOT / "target" / "release" / "psgen"))

REQUIRE_ALL = os.environ.get("PSGEN_REQUIRE_ALL", "") not in ("", "0")

# `prctl(PR_SET_CHILD_SUBREAPER)`: an injected stub calls `setsid` and is
# adopted by PID 1 when the injector exits, so the only way to see it again
# from the harness is to be the reaper.
PR_SET_CHILD_SUBREAPER = 36


def cargo_version() -> str:
    for line in (ROOT / "Cargo.toml").read_text().splitlines():
        if line.startswith('version = "'):
            return line.split('"')[1]
    raise SystemExit("no version in Cargo.toml")


VERSION = cargo_version()


def elf_machine(path: Path) -> int | None:
    """e_machine from an ELF header, or None for a non-ELF file."""
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    # ELF data encoding: 1 = little endian, 2 = big endian.
    endian = {1: "little", 2: "big"}.get(head[5])
    if endian is None:
        return None
    return int.from_bytes(head[18:20], endian)


# uname machine -> ELF e_machine. Only the targets this project ships matter.
ELF_MACHINES = {
    "x86_64": 62,
    "aarch64": 183,
    "armv7l": 40,
    "armv8l": 40,
    "riscv64": 243,
    "loongarch64": 258,
    "ppc64le": 21,
    "i686": 3,
    "i386": 3,
}


def emulated() -> bool:
    """True when the binary runs under qemu-user, not natively.

    The release job smokes the cross binaries under binfmt, where the kernel
    hands the process to `qemu-<arch>`, and `/proc/PID/cmdline` then shows the
    emulator and the binary rather than the argv psgen set. That is the
    emulator's own overhead, not a rendering difference, so the checks that
    compare argv byte for byte are skipped there instead of failing.
    """
    want = ELF_MACHINES.get(os.uname().machine)
    got = elf_machine(BIN)
    if want is None or got is None:
        return False
    return want != got
HEADER = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
# `pr_pcpu` prints one decimal below 100.0 and an integer at or above it, so
# `%CPU` is `\d+\.\d` *or* `\d+`. Matching only the decimal form silently
# dropped every process that was using a whole core, which is exactly the
# population where the two spellings differ.
PS_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<pid>\d+)\s+(?P<cpu>\d+(?:\.\d)?)\s+"
    r"(?P<mem>\d+\.\d)\s+(?P<vsz>\d+)\s+(?P<rss>\d+)\s+"
    r"(?P<tty>\S+)\s+(?P<stat>[RSDZT][sl+]*)\s+"
    r"(?P<start>\d\d:\d\d|[A-Z][a-z]{2}\s?\d+|\d{4})\s+"
    r"(?P<time>\d+:\d\d(?::\d\d)?)\s+(?P<cmd>.*)$"
)
GREY = ("botnet", "bruteforce", "cryptomin", "xmrig", "memdump", "rkhunter",
        "ganache", "simcity", "rootkit", "stratum")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def require_all() -> bool:
    """Whether an absent capability must fail instead of skipping."""
    return REQUIRE_ALL


def skip_or_fail(msg: str) -> None:
    skip(msg)


def skip(reason: str) -> None:
    """Record that a check cannot run on this host.

    The single place that decides whether an absent capability is a skip or a
    failure: with PSGEN_REQUIRE_ALL set by CI nothing may pass unexercised, so
    a missing capability fails with the reason instead of printing SKIP.
    """
    if REQUIRE_ALL:
        fail(f"required capability missing: {reason}")
    print(f"SKIP: {reason}", file=sys.stderr)


def become_subreaper() -> bool:
    """Make orphaned descendants reparent here, so a stub can be reaped.

    An injected stub calls `setsid`, which leaves the injector's process group,
    and the injector exits before a `--duration` run ends. `killpg` therefore
    cannot see it, and it is adopted by PID 1 instead. A child subreaper is
    reparented the same orphans, so a check that spawns stubs can find and kill
    every one of them.
    """
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def stat_fields(pid) -> list[str] | None:
    """`/proc/PID/stat` fields after the parenthesised comm, or None.

    `/proc/PID/stat` is not a stable read: a process that exits or is
    mid-teardown returns an empty or truncated file, and a table-wide scan
    races that constantly. A scan that raises there aborts the whole suite and
    leaks whatever it had spawned, so every reader here treats a short read as
    "this PID is not observable" rather than as an error.
    """
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    close = text.rfind(")")
    if close < 0:
        return None
    tail = text[close + 1:].split()
    # Field 3 is the state letter; there is nothing to read without it.
    if not tail:
        return None
    return tail


def proc_ppid(pid) -> int | None:
    """The parent PID from `/proc/PID/stat`, or None when unreadable."""
    tail = stat_fields(pid)
    if tail is None or len(tail) < 2:
        return None
    try:
        return int(tail[1])
    except ValueError:
        return None


def descendants(root: int) -> list[int]:
    """Every live PID below `root`, direct and adopted."""
    parents = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        ppid = proc_ppid(entry)
        if ppid is not None:
            parents[int(entry)] = ppid
    kids = {}
    for pid, ppid in parents.items():
        kids.setdefault(ppid, []).append(pid)
    out, stack = [], [root]
    while stack:
        for child in kids.get(stack.pop(), []):
            out.append(child)
            stack.append(child)
    return out


def reap_descendants(root: int, timeout=2.0) -> list[int]:
    """Kill every descendant of `root` and return the ones that survived.

    Callers that spawn processes call this after the injector has exited, so a
    leaked stub cannot outlive the cell that made it. The injector's own exit
    is waited for by the caller; this covers the stubs it left behind, which
    are only reachable because `become_subreaper()` reparented them here.

    A subreaper also inherits the *zombies* of orphans, and nothing else will
    ever reap them: PID 1 only reaps its own children. A pass therefore
    collects every exited child, not only the ones it killed, or the harness
    accumulates one zombie per injected stub for the rest of the run.
    """
    pending = descendants(root)
    # An injected stub started by a root-side check runs as root, and an
    # unprivileged harness cannot signal it. The suite made it, so the suite
    # clears it the same way it made it: through sudo.
    unkillable = set()
    for pid in pending:
        try:
            os.kill(pid, signal.SIGKILL)
        except PermissionError:
            unkillable.add(pid)
        except OSError:
            continue
    if unkillable and can_root():
        subprocess.run(as_root(["kill", "-9", *sorted(str(p) for p in unkillable)]),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        for pid in list(pending):
            try:
                done, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                done = pid
            if done or not Path(f"/proc/{pid}").exists():
                pending.remove(pid)
        if pending:
            time.sleep(0.02)
    # Reap whatever else has exited: an orphan adopted here and already dead
    # is a zombie with nothing left to kill. Only descendants of `root` are
    # collected, because a `Popen` this process still owns must be waited for
    # by its owner.
    reap_exited(root)
    return [p for p in pending if alive(p)]


def reap_exited(root: int) -> int:
    """Collect exited descendants of `root`. Returns how many.

    Restricted to descendants, and to PIDs already in state `Z`: a child a
    `Popen` owns is reaped by `Popen`, and stealing its exit status would make
    that call raise instead of report.
    """
    n = 0
    for pid in descendants(root):
        tail = stat_fields(pid)
        if tail is None or tail[0] != "Z":
            continue
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            continue
        if done:
            n += 1
    return n


def is_root() -> bool:
    return os.geteuid() == 0


def root_cmd() -> list[str]:
    """The prefix that runs a command as root, or [] when that is impossible."""
    return [] if is_root() else ["sudo", "-n"]


def can_root() -> bool:
    """True when root-side checks can run: root already, or passwordless sudo."""
    if is_root():
        return True
    try:
        p = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)
        return p.returncode == 0
    except Exception:
        return False


def as_root(args) -> list[str]:
    """A command run as root, without sudo when the caller already is root."""
    return root_cmd() + [str(a) for a in args]


def fsize_allows(nbytes: int) -> bool:
    """False when a write of nbytes would hit the inherited RLIMIT_FSIZE.

    A write is bounded by the *soft* limit, which is what a caller lowers to
    provoke the failure; the hard limit only bounds how far the soft one can
    be raised. Both are therefore consulted, and the smaller wins.
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    except (OSError, ValueError):
        return True
    bounds = [v for v in (soft, hard) if v != resource.RLIM_INFINITY]
    if not bounds:
        return True
    return nbytes <= min(bounds)


# The arena floor `inject` documents for one stub's RSS padding. Below it the
# product disables memory padding, so a check that asserts padded RSS says
# nothing there.
ARENA_KB = 4 * 1024


def disk_guard(mb: int) -> bool:
    """False (with a skip reason) when `--disk mb` cannot be written here."""
    if not fsize_allows(mb * 1024 * 1024):
        skip(f"--disk {mb} MiB exceeds RLIMIT_FSIZE")
        return False
    return True


def arena_guard() -> bool:
    """False (with a skip reason) when inject disables its RSS arena here."""
    if not fsize_allows(ARENA_KB * 1024):
        skip("RLIMIT_FSIZE is too small for the RSS arena")
        return False
    return True


def run(args, root=False, timeout=180, check=True, env=None):
    cmd = ([*root_cmd(), str(BIN)] if root else [str(BIN)]) + [str(a) for a in args]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        fail(f"timeout: {' '.join(cmd)}")
    if check and p.returncode != 0:
        fail(f"command failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr}")
    return p


def read_pids(path, root=False):
    if root:
        p = subprocess.run(as_root(["cat", path]),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=30)
        text = p.stdout
    else:
        text = Path(path).read_text()
    pids = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            pids.append(int(line.split("\t", 1)[0]))
        except ValueError:
            continue
    return pids


# `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW`: the exact set the stub requires.
# The constants are written out because a paraphrase of them is easy to get
# wrong and the failure is silent: `F_SEAL_SEAL` is `0x0001`, not `0x0008`, so
# "seal, shrink and grow" written as `1 | 2 | 8` is really
# `SEAL | SHRINK | WRITE`, and `F_SEAL_WRITE` then makes the stub's own
# progress write fail. `F_SEAL_WRITE` is deliberately absent for that reason.
F_SEAL_SEAL = 0x0001
F_SEAL_SHRINK = 0x0002
F_SEAL_GROW = 0x0004
STUB_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW
F_GET_SEALS = 1034
F_ADD_SEALS = 1033


def sealed_cfg(blob: bytes):
    """A memfd config with the seals the stub requires, or None."""
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.memfd_create(b"psgen-test", 3)  # CLOEXEC | ALLOW_SEALING
    if fd < 0:
        return None
    os.write(fd, blob)
    os.lseek(fd, 0, 0)
    if libc.fcntl(fd, F_ADD_SEALS, STUB_SEALS) != 0:
        os.close(fd)
        return None
    if libc.fcntl(fd, F_GET_SEALS) & STUB_SEALS != STUB_SEALS:
        os.close(fd)
        return None
    return fd


def sealed_cfg_blob(blob: bytes):
    """A sealed memfd config that is not descriptor 3.

    `Fd3` moves whatever it is given onto 3 and closes 3 afterwards, so a
    helper that happens to return 3 would have that descriptor closed by the
    caller's own `os.close`. The test harness keeps descriptor 3 reserved for
    its own use, so the copy is moved above it first.
    """
    fd = sealed_cfg(blob)
    if fd is None:
        return None
    if fd == 3:
        moved = os.dup(3)
        os.close(3)
        fd = moved
    return fd


def exe_known() -> bool:
    """False when /proc/PID/exe would describe the emulator, not psgen."""
    return not emulated()


def read_exe(pid, root=False):
    if root:
        p = subprocess.run(as_root(["readlink", f"/proc/{pid}/exe"]),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=30)
        return p.stdout.strip()
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def cmdline(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode().strip()
    except OSError:
        return ""


def sizes(pid):
    out = {"vsz": 0, "rss": 0}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmSize:"):
                out["vsz"] = int(line.split()[1])
            elif line.startswith("VmRSS:"):
                out["rss"] = int(line.split()[1])
    except OSError:
        pass
    return out


def ps_rows():
    p = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True, timeout=30)
    rows = {}
    for line in p.stdout.splitlines():
        m = PS_RE.match(line)
        if not m:
            continue
        rows[int(m.group("pid"))] = {
            "user": m.group("user"),
            "pid": int(m.group("pid")),
            "cpu": float(m.group("cpu")),
            "mem": float(m.group("mem")),
            "vsz": int(m.group("vsz")),
            "rss": int(m.group("rss")),
            "tty": m.group("tty"),
            "stat": m.group("stat"),
            "start": m.group("start"),
            "time": m.group("time"),
            "cmd": m.group("cmd").strip(),
        }
    return rows


def mem_total():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1])
    return 0


def cgroup_limit_kb():
    def limit_kb(path):
        try:
            value = Path(path).read_text().strip()
        except OSError:
            return None
        if not value or value == "max":
            return 0
        try:
            n = int(value)
        except ValueError:
            return None
        if n >= 1 << 60:
            return 0
        return n // 1024

    try:
        cgroup = Path("/proc/self/cgroup").read_text().splitlines()
    except OSError:
        cgroup = None
    if cgroup is not None:
        for line in cgroup:
            if line.startswith("0::"):
                kb = limit_kb(f"/sys/fs/cgroup{line[3:]}/memory.max")
                if kb is not None:
                    return kb
            elif ":memory:" in line:
                path = line.rsplit(":", 1)[-1]
                kb = limit_kb(f"/sys/fs/cgroup/memory{path}/memory.limit_in_bytes")
                if kb is not None:
                    return kb
    for path in ("/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        kb = limit_kb(path)
        if kb:
            return kb
    return 0


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def check_cli():
    if run(["--version"]).stdout.strip() != f"psgen {VERSION}":
        fail("wrong version")
    help_text = run(["--help"]).stdout
    if "psgen inject" not in help_text:
        fail("help lacks inject")
    for sub in ("doctor", "log", "load"):
        if sub not in help_text:
            fail(f"help lacks {sub}")
    for args, want in [
        (["table", "-n", "5", "-s", "1"], 5),
        (["table", "-n", "5", "-s", "1", "-p", "desktop"], 5),
        (["table", "-n", "5", "-s", "1", "-f", "dev"], 5),
        (["table", "-n", "5", "-s", "1", "--utc-offset", "60"], 5),
        (["table", "-n", "5", "-s", "1", "--local"], 5),
    ]:
        rows = [l for l in run(args).stdout.splitlines() if not l.startswith("USER ")]
        if len(rows) != want:
            fail(f"{args} returned {len(rows)} rows")
    if run(["table", "-p", "bogus"], check=False).returncode != 2:
        fail("bad profile did not exit 2")
    if run(["table", "-f", "bogus"], check=False).returncode != 2:
        fail("bad family did not exit 2")
    a = run(["list", "-n", "10", "-s", "7", "--sort"]).stdout.splitlines()
    if a != sorted(a):
        fail("--sort did not sort")
    b = run(["list", "-n", "5", "-s", "7", "--no-sort"]).stdout.splitlines()
    if b[0] != "/sbin/init":
        fail("--no-sort did not keep corpus order")
    u = run(["list", "-n", "10", "-s", "7", "--uniq"]).stdout.splitlines()
    if len(set(u)) != len(u):
        fail("--uniq produced duplicates")
    n = run(["list", "-n", "10", "-s", "7", "--no-uniq"]).stdout.splitlines()
    if len(n) != 10:
        fail("--no-uniq wrong count")
    if run(["inject", "-n", "0", "--dry-run"]).stdout.count("\n") != 12:
        fail("inject -n 0 did not default to 12")
    if len(run(["table", "-n", "0"]).stdout.splitlines()) != 31:
        fail("table -n 0 did not default to 30 rows")
    a = run(["table", "-n", "5", "-s", "42"]).stdout
    b = run(["table", "-n", "5", "-s", "42"]).stdout
    if a != b:
        fail("seed is not deterministic")


def check_list():
    cmds = [l for l in run(["list", "-n", "0", "-s", "1"]).stdout.splitlines() if l]
    if len(cmds) < 180:
        fail(f"list returned only {len(cmds)} commands")
    for c in cmds:
        if "{" in c or "}" in c:
            fail(f"unexpanded placeholder in {c!r}")
        if any(ord(ch) < 32 for ch in c):
            fail(f"control byte in {c!r}")
        low = c.lower()
        for term in GREY:
            if term in low:
                fail(f"grey term {term!r} in {c!r}")


def check_table_rows(text, want, mem):
    lines = text.splitlines()
    if not lines or lines[0] != HEADER:
        fail("table header does not match procps")
    rows = []
    for line in lines[1:]:
        m = PS_RE.match(line)
        if not m:
            continue
        rows.append({
            "user": m.group("user"), "pid": int(m.group("pid")),
            "cpu": float(m.group("cpu")), "mem": float(m.group("mem")),
            "vsz": int(m.group("vsz")), "rss": int(m.group("rss")),
            "tty": m.group("tty"), "stat": m.group("stat"),
            "start": m.group("start"), "time": m.group("time"),
            "cmd": m.group("cmd"),
        })
    if len(rows) != want:
        fail(f"table returned {len(rows)} rows, wanted {want}")
    if rows[0]["pid"] != 1 or rows[0]["cmd"] != "/sbin/init":
        fail("PID 1 is not /sbin/init")
    if len({r["pid"] for r in rows}) != len(rows):
        fail("duplicate PIDs")
    for r in rows:
        if r["vsz"] < r["rss"]:
            fail(f"pid {r['pid']} has VSZ < RSS")
        if mem and abs(r["mem"] - r["rss"] * 100.0 / mem) > 0.11:
            fail(f"pid {r['pid']} has wrong %MEM")
        if not re.fullmatch(r"[RSDZT][sl+]*", r["stat"]):
            fail(f"pid {r['pid']} has bad STAT {r['stat']}")
        if not re.fullmatch(r"\d+:\d\d(:\d\d)?", r["time"]):
            fail(f"pid {r['pid']} has bad TIME {r['time']}")
        if not re.fullmatch(r"\d\d:\d\d|[A-Z][a-z]{2} ?\d+|\d{4}", r["start"]):
            fail(f"pid {r['pid']} has bad START {r['start']}")
        if not re.fullmatch(r"\?|pts/\d+|tty\d+", r["tty"]):
            fail(f"pid {r['pid']} has bad TTY {r['tty']}")
        if len(r["user"]) > 8:
            fail(f"pid {r['pid']} has a user wider than 8")
        if "{" in r["cmd"] or "}" in r["cmd"]:
            fail(f"pid {r['pid']} has an unexpanded placeholder")
    for prefix in ("/sbin/init", "sshd: /usr/sbin/sshd -D [listener]",
                   "nginx: master process"):
        if sum(1 for r in rows if r["cmd"].startswith(prefix)) > 1:
            fail(f"duplicate single-instance daemon {prefix}")
    if sum(1 for r in rows if r["cmd"] == "/usr/bin/containerd") > 1:
        fail("duplicate single-instance daemon /usr/bin/containerd")


def check_table():
    check_table_rows(run(["table", "-n", "50", "-s", "1"]).stdout, 50, mem_total())
    check_table_rows(run(["table", "-n", "5001", "-s", "1"]).stdout, 5000, mem_total())


def proc_cmdline(pid):
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    return " ".join(p.decode(errors="replace") for p in raw.split(b"\0") if p)


def check_live():
    text = run(["table", "--live"]).stdout
    lines = text.splitlines()
    if not lines or lines[0] != HEADER:
        fail("live table header does not match procps")
    if len(lines) < 6:
        fail("live table has too few rows")
    try:
        pid1 = proc_cmdline(1)
    except OSError:
        pid1 = None
    rows = [l for l in lines[1:] if len(l.split()) > 1 and l.split()[1] == "1"]
    if not rows:
        fail("live table lacks PID 1")
    if pid1 is not None and not any(l.split(None, 10)[-1] == pid1 for l in rows):
        fail(f"live table PID 1 does not match /proc/1/cmdline ({pid1!r})")


def check_corpus():
    if len([l for l in run(["corpus"]).stdout.splitlines() if l]) < 180:
        fail("corpus too small")
    out = run(["check"]).stdout
    if "deny hits: 0" not in out or "placeholders: 0" not in out:
        fail("check reported corpus problems")
    run(["check", "--binaries"])


def check_unit():
    out = run(["unit"]).stdout
    if "ExecStart=" not in out or "psgen" not in out or "ExecStop=" not in out:
        fail("unit output is incomplete")
    if "WantedBy=multi-user.target" not in out:
        fail("unit output lacks install target")
    run(["unit", "--pidfile", "/run/test-psgen.pid", "-n", "9", "-s", "3"])
    spaced = run(["unit", "--pidfile", "/run/a b.pid"]).stdout
    if 'ExecStart=' not in spaced or '"/run/a b.pid"' not in spaced:
        fail("unit did not quote a path that contains a space")
    with tempfile.TemporaryDirectory(prefix="psgen-unit-") as tmp:
        spaced_bin = Path(tmp) / "bin dir" / "psgen"
        spaced_bin.parent.mkdir()
        # Copying the binary needs more bytes than a finite RLIMIT_FSIZE allows,
        # and a copy failure must skip this one assertion rather than abort.
        need = BIN.stat().st_size + 4096
        copied = fsize_allows(need)
        if not copied:
            skip(f"cannot stage a copy of {need} bytes under RLIMIT_FSIZE")
        else:
            try:
                shutil.copy2(BIN, spaced_bin)
            except OSError as e:
                copied = False
                skip(f"cannot stage a copy of the binary: {e}")
        if copied:
            p = subprocess.run([str(spaced_bin), "unit"], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, timeout=180)
            if p.returncode != 0:
                fail(f"unit from a spaced path failed: {p.stderr}")
            # A path with a space is quoted in both directives; an unquoted one
            # is what the old `shutil.copy2` crash hid.
            if f'ExecStart="{spaced_bin}"' not in p.stdout:
                fail("unit did not quote the executable path")
            # `ExecStop` has no `-` prefix (it would report a real stop failure
            # as success), so the quoted executable is the first argument of the
            # stop script. It must still be quoted: an unquoted space would
            # split the executable from its arguments.
            stop = next(l for l in p.stdout.splitlines()
                        if l.startswith("ExecStop="))
            if f'"{spaced_bin}"' not in stop:
                fail(f"unit did not quote the stop executable path: {stop!r}")
            if stop.startswith("ExecStop=-"):
                fail("unit suppressed every ExecStop failure with `-`")


def inject_and_check(args, tmp, want, root=False, read_root=None,
                     expect_failure=False):
    pidfile = Path(tmp) / ("pids-" + str(int(time.time() * 1000)))
    args = list(args) + ["--pidfile", str(pidfile)]
    p = run(args, root=root, check=not expect_failure)
    if read_root is None:
        read_root = root
    pids = read_pids(pidfile, root=read_root)
    if len(pids) != want:
        fail(f"{args} spawned {len(pids)}, wanted {want}: {p.stdout} {p.stderr}")
    return pidfile, pids, p


# Every pidfile the suite has written and not yet stopped. `stop_pidfile`
# removes one when it succeeds; whatever is left when the process exits names a
# stub the abort left running, and `suite_cleanup` stops it.
_LIVE_PIDFILES: set[str] = set()


def stop_pidfile(path, root=False):
    out = ""
    path = Path(path)
    # Recorded before the file can appear: an abort between the inject and the
    # stop leaves no marker in any other place.
    _LIVE_PIDFILES.add(str(path))
    if path.exists():
        out = run(["stop", "--pidfile", str(path)], root=root, check=False).stdout
    _LIVE_PIDFILES.discard(str(path))
    try:
        path.unlink()
    except OSError:
        pass
    return out


def check_injection():
    under_emulation = emulated()
    if under_emulation:
        skip("argv checks compare loosely under qemu-user")
    with tempfile.TemporaryDirectory(prefix="psgen-test-") as tmp:
        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
             "--no-tty", "--no-threads"], tmp, 4)
        dry = run(["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
                   "--no-tty", "--no-threads", "--dry-run"]).stdout
        wanted = {l.split("\t", 1)[1].strip() for l in dry.splitlines() if "\t" in l}
        time.sleep(0.4)
        rows = ps_rows()
        for pid in pids:
            r = rows.get(pid)
            raw = cmdline(pid)
            if not r:
                fail(f"pid {pid} missing from ps aux")
            # A `/proc/PID/cmdline` read of a stub that exited in the window is
            # empty, and `ps` shows the bracketed comm for a zombie. That is the
            # same "already dead" case `alive()` exists for; the row was planned,
            # it just is not observable any more.
            if not alive(pid) and (not raw or r["cmd"].endswith(" <defunct>")):
                continue
            if not under_emulation:
                if r["cmd"].removesuffix(" <defunct>") != raw:
                    fail(f"pid {pid} ps cmd {r['cmd']!r} != cmdline {raw!r}")
                if raw not in wanted:
                    fail(f"pid {pid} cmdline {raw!r} not planned")
            elif raw not in wanted and not any(w in raw for w in wanted):
                # qemu-user puts `qemu-<arch> <binary>` in front of the argv, so
                # the planned command line is a suffix rather than the whole.
                fail(f"pid {pid} cmdline {raw!r} does not contain a planned command")
            if r["tty"] != "?":
                fail(f"pid {pid} --no-tty still has {r['tty']}")
            if not under_emulation:
                # qemu-user adds threads of its own and carries its own RSS, so
                # neither number is about psgen there.
                if "l" in r["stat"]:
                    fail(f"pid {pid} --no-threads still has l")
                if r["rss"] > 4000:
                    fail(f"pid {pid} --no-mem has RSS {r['rss']}")
        stop_pidfile(pidfile)

        if not can_root():
            p = run(["inject", "-n", "2", "--no-mem", "--no-tty", "--no-threads",
                     "--pidfile", str(Path(tmp) / "warn.pid")])
            if "running as" not in p.stderr:
                fail("non-root --user did not warn about the fallback")
            stop_pidfile(Path(tmp) / "warn.pid")

        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "desk", "-n", "30", "-s", "5", "--no-user",
             "--no-mem"], tmp, 30)
        time.sleep(0.4)
        rows = ps_rows()
        if can_pty():
            if not any(rows.get(p) and rows[p]["tty"].startswith("pts/")
                       for p in pids):
                fail("no injected process acquired a pty")
        else:
            skip("no pty master on this host, the pty assertion cannot run")
        if not under_emulation and not any(
                rows.get(p) and "l" in rows[p]["stat"] for p in pids):
            fail("no injected process showed the threaded stat flag")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "3", "-s", "77", "--no-user"], tmp, 3)
        time.sleep(0.4)
        rows = ps_rows()
        if not emulated() and arena_guard():
            # The RSS half is about the arena inject disables when it cannot
            # allocate one, so it says nothing on a small RLIMIT_FSIZE.
            if not any(rows.get(p) and rows[p]["vsz"] > 50000 for p in pids):
                fail("no injected process had a padded VSZ")
            if not any(rows.get(p) and rows[p]["rss"] > 1000 for p in pids):
                fail("no injected process had a padded RSS")
        stop_pidfile(pidfile)

        # --verify compares real VSZ/RSS with the plan. qemu-user adds its own
        # mappings and resident pages to both, so the comparison is about the
        # emulator there and the exit code is not psgen's. With no arena the
        # planned RSS is zero and the comparison proves nothing.
        if not emulated() and arena_guard():
            pidfile, pids, p = inject_and_check(
                ["inject", "-n", "16", "-s", "42", "--no-user", "--verify"],
                tmp, 16)
            m = re.search(r"(\d+) outside 128 kB", p.stdout)
            if m and int(m.group(1)) != 0:
                fail(f"{m.group(1)} stubs outside 128 kB")
            stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "web", "-n", "12", "-s", "42", "--no-user",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 12)
        time.sleep(0.4)
        ps = subprocess.run(
            ["ps", "-o", "pid=,ppid=,args=", "-p", ",".join(str(p) for p in pids)],
            stdout=subprocess.PIPE, text=True, timeout=30)
        rows = []
        for line in ps.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                rows.append((int(parts[0]), int(parts[1]), parts[2]))
        # Under qemu-user `ps args` starts with `qemu-<arch> <binary>`, so the
        # template command is a suffix of the row rather than its start.
        def starts(args, prefixes):
            if emulated():
                return any(p in args for p in prefixes)
            return args.startswith(prefixes)

        masters = {pid for pid, ppid, args in rows
                   if starts(args, ("apache2 -DFOREGROUND", "nginx: master",
                                    "php-fpm: master", "gunicorn: master"))}
        workers = [(pid, ppid, args) for pid, ppid, args in rows
                   if starts(args, ("apache2 -k start", "nginx: worker",
                                    "php-fpm: pool", "gunicorn: worker"))]
        if not masters or not workers:
            fail("web family did not produce masters and workers")
        for pid, ppid, args in workers:
            if ppid not in masters:
                fail(f"worker {pid} ({args}) has PPID {ppid}, not a master")
        if shutil.which("pstree"):
            for master in masters:
                tree = subprocess.run(["pstree", "-p", str(master)],
                                      stdout=subprocess.PIPE, text=True, timeout=30).stdout
                for pid, ppid, _ in workers:
                    if ppid == master and f"({pid})" not in tree:
                        fail(f"pstree does not show worker {pid} under master {master}")
        stop_pidfile(pidfile)

        mounts_before = Path("/proc/self/mountinfo").read_text()
        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "web", "-n", "6", "-s", "42", "--no-user",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 6)
        mounts_after = Path("/proc/self/mountinfo").read_text()
        if mounts_after != mounts_before:
            fail("inject leaked a mount into the caller's mount namespace")
        expected = {
            "apache2": "/usr/sbin/apache2",
            "nginx:": "/usr/sbin/nginx",
            "php-fpm:": "/usr/sbin/php-fpm",
            "gunicorn:": "/usr/local/bin/gunicorn",
        }
        checked = 0
        for pid in pids:
            raw = cmdline(pid)
            if not exe_known():
                # qemu-user makes /proc/PID/exe the emulator, so the comparison
                # is not about psgen at all.
                checked += 1
                continue
            got = read_exe(pid)
            if Path(got).resolve() == BIN.resolve():
                checked += 1
                continue
            if got.endswith("/psgen-stub"):
                checked += 1
                continue
            for prefix, exe in expected.items():
                if raw.startswith(prefix):
                    if Path(got).resolve() != Path(exe).resolve():
                        fail(f"pid {pid} exe {got!r} != {exe!r}")
                    checked += 1
                    break
        if checked == 0:
            fail("no exe-spoofed web rows found")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "4", "-s", "9", "--no-user", "--no-exe",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 4)
        if exe_known():
            for pid in pids:
                if Path(read_exe(pid)).resolve() != BIN.resolve():
                    fail(f"pid {pid} --no-exe exe is {read_exe(pid)}")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "db", "-n", "6", "-s", "1", "--no-user",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 6)
        for pid in pids:
            if not exe_known():
                continue
            exe = read_exe(pid)
            if Path(exe).resolve() == BIN.resolve():
                continue
            # A host that has the template binary binds it; the documented
            # skip applies to paths that do not exist under /usr/lib.
            if Path(exe).exists():
                continue
            fail(f"pid {pid} /usr/lib row exe is {exe}, expected the documented skip")
        stop_pidfile(pidfile)

        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
             "--no-tty", "--no-threads", "--table"], tmp, 4)
        lines = p.stdout.splitlines()
        if not lines or lines[0] != HEADER:
            fail("inject --table did not print the header first")
        if len(lines) != 5:
            fail(f"inject --table printed {len(lines)} lines")
        stop_pidfile(pidfile)

        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "16", "-s", "42", "--no-user", "--mem-cap", "64",
             "--no-tty", "--no-threads"], tmp, 16)
        time.sleep(0.4)
        # The cap is at the 4 MiB-per-stub floor. A stub's own base RSS can
        # exceed the floor; allow 128 KiB per stub for the base image. Under
        # qemu-user the resident set is the emulator's, so the number is not
        # about --mem-cap at all.
        if not emulated():
            total = sum(sizes(p)["rss"] for p in pids)
            if total > 64 * 1024 + 16 * 128:
                fail(f"--mem-cap 64 reported {total} kB")
        if "at least 64 MiB" not in p.stderr:
            fail("--mem-cap floor warning missing")
        stop_pidfile(pidfile)
        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "16", "-s", "42", "--no-user", "--phys-cap", "64",
             "--no-tty", "--no-threads"], tmp, 16)
        if "scaled to fit the physical budget" not in p.stdout:
            fail("--phys-cap did not report scaling")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--duration", "1"], tmp, 2)
        time.sleep(2.2)
        for pid in pids:
            if alive(pid):
                fail(f"pid {pid} survived --duration 1")
        stop_pidfile(pidfile)
        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--wait", "--duration", "1"], tmp, 2)
        for pid in pids:
            if alive(pid):
                fail(f"pid {pid} survived --wait --duration 1")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "dev", "-n", "8", "--no-user", "--busy",
             "--duration", "2", "--no-mem", "--no-tty", "--no-threads"],
            tmp, 8)
        start = {p: cpu_ticks(p) for p in pids}
        time.sleep(1.0)
        busy = 0
        for p in pids:
            now = cpu_ticks(p)
            if now is not None and start.get(p) is not None and now > start[p]:
                busy += 1
        if busy == 0:
            fail("--busy produced no CPU time")
        time.sleep(2.2)
        for p in pids:
            if alive(p):
                fail(f"--busy --duration 2 pid {p} survived")
        stop_pidfile(pidfile)


def check_stop():
    with tempfile.TemporaryDirectory(prefix="psgen-stop-") as tmp:
        me = os.getpid()
        p = Path(tmp) / "stale.pid"
        p.write_text(f"# psgen 0.0.1 boot {boot_id()}\n{me}\t0\ttest\n")
        out = run(["stop", "--pidfile", str(p)]).stdout
        if "skipped 1" not in out:
            fail("stop did not skip a stale starttime")
        os.kill(me, 0)
        p.write_text("# psgen 0.0.1 boot 00000000-0000-0000-0000-000000000000\n"
                     f"{me}\t0\ttest\n")
        if run(["stop", "--pidfile", str(p)], check=False).returncode == 0:
            fail("stop accepted a pidfile from another boot")
        # A headerless file is refused, so the row is reached with --force. The
        # line carries a starttime because a one-field line cannot identify a
        # process whose run nonce is not in the header: that form is refused,
        # which the identity checks cover.
        p.write_text(f"{me}\t0\ttest\n")
        out = run(["stop", "--pidfile", str(p), "--force"]).stdout
        if "skipped 1" not in out:
            fail("stop did not skip a foreign pid")
        p.write_text(f"# psgen 0.0.1 boot {boot_id()}\n999999\t0\ttest\n")
        out = run(["stop", "--pidfile", str(p), "--force"]).stdout
        if "stopped 0" not in out:
            fail("stop --force on a missing pid was not a no-op")
        p.write_text("1\n")
        out = run(["stop", "--pidfile", str(p), "--force"]).stdout
        if "skipped 1" not in out:
            fail("stop --force did not skip PID 1")
        victim = Path(tmp) / "victim"
        victim.mkdir()
        p.write_text(f"# psgen 0.0.1 boot {boot_id()}\n# temp {victim}\n")
        run(["stop", "--pidfile", str(p)])
        if not victim.exists():
            fail("stop removed a temp dir outside the per-run pattern")
        pf = Path(tmp) / "temp.pid"
        if disk_guard(1):
            run(["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
                 "--no-tty", "--no-threads", "--disk", "1", "--pidfile", str(pf)])
            temps = [l[len("# temp "):] for l in pf.read_text().splitlines()
                     if l.startswith("# temp ")]
            if not temps:
                fail("pidfile did not record the temp dirs")
            stop_pidfile(pf)
            for t in temps:
                if Path(t).exists():
                    fail(f"stop left temp dir {t}")
        if run(["stop"], check=False).returncode != 2:
            fail("stop without --pidfile did not exit 2")


def check_root():
    with tempfile.TemporaryDirectory(prefix="psgen-root-") as tmp:
        mounts_before = Path("/proc/self/mountinfo").read_text()
        # Seed 1 selects rows whose exe paths are spoofable on this host. The
        # documented /usr/lib skip is covered separately below.
        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "-s", "1", "--no-user", "--no-mem",
             "--no-tty", "--no-threads"], tmp, 2, root=True)
        time.sleep(0.4)
        mounts_after = Path("/proc/self/mountinfo").read_text()
        if mounts_after != mounts_before:
            fail("root inject leaked a mount into the caller's mount namespace")
        if exe_known():
            for p in pids:
                exe = read_exe(p, root=True)
                if not exe or Path(exe).resolve() == BIN.resolve():
                    fail(f"root exe spoof did not run for pid {p}")
        stop_pidfile(pidfile, root=True)

        has_www = subprocess.run(["getent", "passwd", "www-data"],
                                 stdout=subprocess.DEVNULL).returncode == 0
        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "web", "-n", "12", "-s", "42", "--user",
             "--no-exe", "--no-mem", "--no-tty", "--no-threads"],
            tmp, 12, root=True)
        time.sleep(0.4)
        rows = ps_rows()
        # Under qemu-user the row starts with the emulator; match the template
        # anywhere it appears.
        def is_worker(cmd):
            if emulated():
                return any(k in cmd for k in
                           ("apache2 -k start", "php-fpm: pool", "nginx: worker"))
            return cmd.startswith(("apache2 -k start", "php-fpm: pool",
                                   "nginx: worker"))

        workers = [p for p in pids if rows.get(p) and is_worker(rows[p]["cmd"])]
        if not workers:
            fail("root run produced no service workers")
        if has_www:
            for p in workers:
                if rows[p]["user"] != "www-data":
                    fail(f"worker {p} runs as {rows[p]['user']}, not www-data")
            for p in pids:
                cmd = rows[p]["cmd"] if rows.get(p) else ""
                master = ("apache2 -DFOREGROUND" in cmd or "php-fpm: master" in cmd)                     if emulated() else cmd.startswith(("apache2 -DFOREGROUND",
                                                       "php-fpm: master"))
                if master and rows[p]["user"] != "root":
                    fail(f"master {p} runs as {rows[p]['user']}, not root")
        if exe_known():
            for p in pids:
                if Path(read_exe(p, root=True)).resolve() != BIN.resolve():
                    fail(f"root --no-exe pid {p} exe is not psgen")
        stop_pidfile(pidfile, root=True)

        before = subprocess.run(["getent", "passwd", "haproxy"],
                                stdout=subprocess.DEVNULL).returncode == 0
        try:
            pidfile, pids, p = inject_and_check(
                ["inject", "-f", "web", "-n", "6", "-s", "5", "--user",
                 "--create-users", "--no-exe", "--no-mem", "--no-tty",
                 "--no-threads"], tmp, 6, root=True)
            if not before and "created users: haproxy" not in p.stderr:
                fail("--create-users did not report haproxy")
            time.sleep(0.4)
            rows = ps_rows()
            if not any(rows.get(p) and rows[p]["user"] == "haproxy" for p in pids):
                fail("--create-users stub did not run as haproxy")
            stop_pidfile(pidfile, root=True)
        finally:
            if not before:
                subprocess.run(as_root(["userdel", "haproxy"]),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(as_root(["groupdel", "haproxy"]),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        pidfile, pids, p = inject_and_check(
            ["inject", "--elevate", "-n", "2", "--no-user", "--no-exe",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 2,
            root=False, read_root=True)
        if exe_known():
            for p in pids:
                exe = read_exe(p, root=True)
                if exe and Path(exe).resolve() != BIN.resolve():
                    fail(f"--elevate pid {p} exe is not psgen")

        p = run(["inject", "--elevate", "-n", "1", "--pidfile", "/proc/1/foo"],
                check=False)
        if p.returncode != 2:
            fail(f"--elevate failure path exited {p.returncode}, wanted 2")
        stop_pidfile(pidfile, root=True)

        # #25: a setgid binary must be refused before any config is read. The
        # old check only refused euid!=uid, so a setgid copy ran with the
        # file's group and would act on a config that group could read.
        group = "daemon"
        got = subprocess.run(["getent", "group", group],
                             stdout=subprocess.DEVNULL)
        if got.returncode != 0:
            group = "disk"
        got = subprocess.run(["getent", "group", group],
                             stdout=subprocess.DEVNULL)
        if got.returncode != 0:
            skip("#25 no non-root group to make a setgid copy")
        else:
            setgid = Path(tmp) / "psgen-setgid"
            plain = Path(tmp) / "psgen-plain"
            for dst in (setgid, plain):
                r = subprocess.run(as_root(["cp", BIN, dst]),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                if r.returncode != 0:
                    fail(f"#25: cannot stage a copy: {r.stderr.decode().strip()}")
            subprocess.run(as_root(["chown", f"root:{group}", setgid]),
                           check=True)
            subprocess.run(as_root(["chmod", "2755", setgid]),
                           check=True)
            env = dict(os.environ)
            env.pop("PSGEN_NONCE", None)
            # The copy must live on a filesystem that honours the setgid bit.
            # `TMPDIR` is often `nosuid` (a tmpfs or /tmp), where the kernel
            # ignores the bit and the refusal is unreachable; move the copy
            # somewhere real when that is the case.
            setgid, plain = setgid_on_suid_fs(setgid, plain, group)
            if setgid is None:
                skip("#25 no filesystem that honours setgid is available")
                return
            q = subprocess.run([str(setgid), "list", "-n", "1"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=env, timeout=30)
            if q.returncode != 2 or "setuid or setgid" not in q.stderr:
                fail(f"#25: a setgid copy ran: rc={q.returncode} "
                     f"stderr={q.stderr.strip()!r}")
            # The control: the same copy without the bit is accepted.
            q = subprocess.run([str(plain), "list", "-n", "1"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=env, timeout=30)
            if q.returncode != 0 or len(q.stdout.splitlines()) != 1:
                fail(f"#25: the control copy failed: rc={q.returncode}")


def setgid_on_suid_fs(setgid: Path, plain: Path, group: str):
    """Re-stage a setgid copy on a filesystem that honours the bit.

    `TMPDIR` is commonly a `nosuid` tmpfs, where the kernel ignores the bit and
    the refusal under test is unreachable. Returns the pair to use, or
    `(None, None)` when nothing suitable exists.
    """
    def suid_here(path: Path) -> bool:
        try:
            out = subprocess.run(["findmnt", "-no", "OPTIONS", "-T", str(path)],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, timeout=30).stdout
        except (FileNotFoundError, subprocess.SubprocessError):
            return True
        return "nosuid" not in out.split(",")

    if suid_here(setgid):
        return setgid, plain
    for base in ("/var/tmp", "/workspaces"):
        b = Path(base)
        if not b.is_dir() or not suid_here(b):
            continue
        d = b / f".psgen-sg-{os.getpid()}"
        r = subprocess.run(["sudo", "-n", "mkdir", "-p", str(d)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            continue
        sg = d / "psgen-setgid"
        pl = d / "psgen-plain"
        ok = True
        for dst in (sg, pl):
            r = subprocess.run(["sudo", "-n", "cp", str(BIN), str(dst)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ok = ok and r.returncode == 0
        if not ok:
            subprocess.run(["sudo", "-n", "rm", "-rf", str(d)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            continue
        subprocess.run(["sudo", "-n", "chown", f"root:{group}", str(sg)],
                       check=False)
        subprocess.run(["sudo", "-n", "chmod", "2755", str(sg)], check=False)
        return sg, pl
    return None, None


def check_counts():
    n = len([l for l in run(["list", "-n", "2001", "-s", "1"]).stdout.splitlines() if l])
    if n != 2000:
        fail(f"list -n 2001 returned {n}")
    if "capped at 2000" not in run(["list", "-n", "2001", "-s", "1"], check=False).stderr:
        fail("list did not warn about the cap")
    n = len(run(["table", "-n", "5001", "-s", "1"]).stdout.splitlines())
    if n != 5001:
        fail(f"table -n 5001 returned {n} lines")
    if "capped at 5000" not in run(["table", "-n", "5001", "-s", "1"], check=False).stderr:
        fail("table did not warn about the cap")
    pidfile = Path(tempfile.mkstemp(prefix="psgen-500-")[1])
    try:
        p = run(["inject", "-n", "501", "--no-user", "--no-exe", "--no-mem",
                 "--no-tty", "--no-threads", "--duration", "1",
                 "--pidfile", str(pidfile)])
        if "capped at 500" not in p.stderr:
            fail("inject did not warn about the cap")
        pids = read_pids(pidfile)
        if len(pids) != 500:
            fail(f"inject -n 501 spawned {len(pids)}")
        time.sleep(2.0)
    finally:
        stop_pidfile(pidfile)


HZ = os.sysconf("SC_CLK_TCK")


def cpu_ticks(pid):
    """Cumulative user+system CPU time in clock ticks, or None if gone."""
    # The comm field is parenthesised and may contain spaces, so split after
    # the last ')'. The remaining fields start at state (field 3).
    parts = stat_fields(pid)
    if parts is None:
        return None
    try:
        return int(parts[11]) + int(parts[12])
    except (IndexError, ValueError):
        return None


def load1() -> float | None:
    try:
        return float(Path("/proc/loadavg").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def host_loaded() -> bool:
    """True when the host is too busy for a CPU-share measurement to mean much.

    A process cannot get 50% of a core when the run queue is longer than the
    core count, so the measurement says more about the host than about psgen.
    A momentary spike is not that, so the load is sampled for a bounded time
    before the check gives up; with PSGEN_REQUIRE_ALL set the window is longer,
    because a CI failure has to mean saturation rather than a busy second.
    """
    cores = os.cpu_count() or 1
    rounds = 12 if REQUIRE_ALL else 6
    for _ in range(rounds):
        value = load1()
        if value is None:
            return False
        if value <= cores * 0.8:
            return False
        time.sleep(5.0)
    return True


def cpu_percent(pid, seconds):
    a = cpu_ticks(pid)
    if a is None:
        return None
    time.sleep(seconds)
    b = cpu_ticks(pid)
    if b is None:
        return None
    return (b - a) * 100.0 / (HZ * seconds)


def check_doctor():
    p = run(["doctor"])
    out = p.stdout
    if "summary" not in out or "capabilities available" not in out:
        fail("doctor lacks the summary line")
    for name in ("proc_exe", "fork", "prctl_name"):
        line = next((l for l in out.splitlines() if l.startswith(name)), None)
        if line is None:
            fail(f"doctor does not report {name}")
        if "ALLOW" not in line:
            fail(f"doctor reports {name} denied on the test host: {line}")
    # memfd is optional: inject falls back to an unlinked temp file.
    if not any(l.startswith("memfd") for l in out.splitlines()):
        fail("doctor does not report memfd")
    # A non-root user_switch denial is a degradation, not a failure.
    if p.returncode != 0:
        fail(f"doctor exited {p.returncode} with only non-core denials")

    probe_names = ("cap_eff", "has_caps", "seccomp_mode", "no_new_privs", "bpf",
                   "seccomp_user_notif", "ptrace_scope", "unprivileged_bpf_disabled",
                   "proc_1_cmdline")
    if "probe" not in out:
        fail("doctor does not print the probe block")
    for name in probe_names:
        line = next((l for l in out.splitlines() if l.strip().startswith(name + "\t")), None)
        if line is None:
            fail(f"doctor probe block lacks {name}")

    j = run(["doctor", "--json"])
    try:
        doc = json.loads(j.stdout)
    except json.JSONDecodeError as e:
        fail(f"doctor --json is not valid JSON: {e}")
    if doc.get("version") != VERSION:
        fail(f"doctor --json version {doc.get('version')!r}")
    if doc.get("ok") is not True:
        fail("doctor --json says not ok")
    for key in ("uid", "euid", "mem_total_kb", "page_kb", "hz", "cwd"):
        if key not in doc.get("env", {}):
            fail(f"doctor --json env lacks {key}")
    checks = doc.get("checks")
    if not isinstance(checks, list) or not checks:
        fail("doctor --json has no checks")
    probe = doc.get("probe")
    if not isinstance(probe, dict):
        fail("doctor --json has no probe object")
    for name in probe_names:
        if not probe.get(name):
            fail(f"doctor --json probe lacks {name}")
    by_name = {}
    for item in checks:
        if "name" not in item or "ok" not in item:
            fail("doctor --json check is not an object with a name field")
        by_name[item["name"]] = item
    if os.geteuid() != 0:
        us = by_name.get("user_switch")
        if not us or us.get("ok") is not False:
            fail("doctor did not deny user_switch for a non-root caller")
        if "errno" not in us:
            fail("doctor denial lacks an errno")
    pidfile = Path(tempfile.mkdtemp(prefix="psgen-doctor-")) / "probe.pid"
    j = run(["doctor", "--json", "--pidfile", str(pidfile)])
    doc = json.loads(j.stdout)
    pf = doc.get("pidfile", {})
    if pf.get("path") != str(pidfile) or not pf.get("writable"):
        fail(f"doctor --json did not report the pidfile writable: {pf}")
    shutil.rmtree(pidfile.parent, ignore_errors=True)


def check_log():
    listing = run(["log", "-m", "list"]).stdout.strip()
    if not listing.startswith("modules:"):
        fail(f"log -m list printed {listing!r}")
    # The first line is the canonical module names; the alias lines that follow
    # are indented, so only the first line's tail is the module list.
    modules = listing.splitlines()[0][len("modules:"):].split()
    if len(modules) < 14:
        fail(f"log lists only {len(modules)} modules")
    for name in ("weblog", "bootlog", "cargo", "docker_build", "kernel_compile"):
        if name not in modules:
            fail(f"log -m list lacks {name}")
    for name in modules:
        p = run(["log", "-m", name, "--lines", "2"])
        if not p.stdout.strip():
            fail(f"log -m {name} printed nothing")
        if "{" in p.stdout or "}" in p.stdout:
            fail(f"log -m {name} left an unexpanded placeholder")
    apache = run(["log", "-m", "weblog", "--lines", "3"]).stdout.splitlines()
    clf = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} \d+(?: "[^"]*" "[^"]*")?$')
    for line in apache:
        if not clf.match(line):
            fail(f"weblog apache line is malformed: {line!r}")
    for line in run(["log", "-m", "weblog", "--log-fmt", "json", "--lines", "3"]).stdout.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            fail(f"weblog json line is malformed: {line!r}")
        if not {"ip", "ts", "method", "path", "status"} <= set(rec):
            fail(f"weblog json lacks keys: {line!r}")
    syslog = re.compile(r"^(?:<[0-9]+>)?[A-Z][a-z]{2} [ 0-9]\d \d\d:\d\d:\d\d \S+ ")
    for line in run(["log", "-m", "weblog", "--log-fmt", "syslog", "--lines", "3"]).stdout.splitlines():
        if not syslog.match(line):
            fail(f"weblog syslog line is malformed: {line!r}")
    if run(["log", "-m", "cargo", "--log-fmt", "apache"], check=False).returncode != 2:
        fail("log accepted apache format for a non-web module")
    p = run(["log", "-m", "nope"], check=False)
    if p.returncode != 2 or "unknown module" not in p.stderr:
        fail("log did not reject an unknown module")
    t0 = time.monotonic()
    run(["log", "-m", "weblog", "--lines", "40", "--delay", "20", "--speed", "4"])
    if time.monotonic() - t0 > 1.5:
        fail("--speed did not shorten the delay")


def poll_until(predicate, timeout=6.0, interval=0.05):
    """Poll `predicate` until it returns a true value, or the timeout passes."""
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval)


def held_fds(pid, size):
    """File descriptors of `pid` whose file has `size` bytes."""
    out = []
    try:
        fds = list(Path(f"/proc/{pid}/fd").iterdir())
    except OSError:
        return out
    for fd in fds:
        try:
            st = fd.stat()
        except OSError:
            continue
        if st.st_size == size:
            out.append(st.st_size)
    return out


def check_load():
    if run(["load"], check=False).returncode != 2:
        fail("load without a util flag did not exit 2")

    total = mem_total()
    cg = cgroup_limit_kb()
    if cg > 0:
        total = min(total, cg)
    want = total * 2 // 100
    proc = subprocess.Popen([str(BIN), "load", "--mem-util", "2", "--duration", "6"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        # The touch loop runs after the mapping exists, so "the process is
        # alive" is not the signal; a single fixed sleep raced once and read
        # 0 kB. Poll the resident set until it settles.
        def in_band() -> int:
            rss = sizes(proc.pid)["rss"]
            return rss if want * 8 // 10 <= rss <= want * 13 // 10 else 0
        rss = poll_until(in_band, timeout=5.0)
        if not rss:
            rss = sizes(proc.pid)["rss"]
            fail(f"--mem-util 2 held {rss} kB, wanted about {want} kB")
    finally:
        proc.wait(timeout=20)
    if proc.returncode != 0:
        fail(f"load --mem-util exited {proc.returncode}: {proc.stderr.read()}")

    if host_loaded():
        skip(f"--cpu-util needs a quieter host: load1 is {load1()}, "
             f"{os.cpu_count()} cores")
    else:
        proc = subprocess.Popen([str(BIN), "load", "--cpu-util", "50", "--duration", "4"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            util = cpu_percent(proc.pid, 1.5)
            if util is None:
                fail("load --cpu-util process vanished")
            if not 35.0 <= util <= 65.0:
                fail(f"--cpu-util 50 measured {util:.1f}%")
        finally:
            proc.wait(timeout=20)

    if not fsize_allows(8 * 1024 * 1024):
        skip("load --disk-util 8 MiB exceeds RLIMIT_FSIZE")
    else:
        with tempfile.TemporaryDirectory(prefix="psgen-load-") as load_tmp:
            env = os.environ.copy()
            env["TMPDIR"] = load_tmp
            proc = subprocess.Popen(
                [str(BIN), "load", "--disk-util", "8", "--duration", "6"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, env=env)
            try:
                # The file is written after the mapping is set up; poll for the
                # descriptor rather than assuming a fixed start-up time.
                held = poll_until(
                    lambda: held_fds(proc.pid, 8 * 1024 * 1024), timeout=5.0)
                if not held:
                    fail("load --disk-util did not hold an 8 MiB temp file")
            finally:
                proc.wait(timeout=20)
            if list(Path(load_tmp).iterdir()):
                fail("load --disk-util left a path behind")

    check_load_disk_guards()


def check_load_disk_guards():
    """Both `load` disk guards refuse before a huge file is attempted.

    The RLIMIT guard runs first and compares the request with RLIMIT_FSIZE, so
    a test that can only reach the free-space guard needs a filesystem smaller
    than the request. A tmpfs of a few MiB, mounted as root, is that file
    system; on a host where neither that nor an unlimited RLIMIT_FSIZE is
    available the assertion is unreachable and says so.
    """

    def limited(args, fsize, env=None):
        def preexec():
            _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            # A soft limit can never exceed the hard limit: clamping keeps the
            # guard test runnable on a host whose hard RLIMIT_FSIZE is finite.
            lim = hard if fsize is None else (
                fsize if hard == resource.RLIM_INFINITY else min(fsize, hard))
            resource.setrlimit(resource.RLIMIT_FSIZE, (lim, hard))
        cmd = [str(BIN)] + [str(a) for a in args]
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=120, preexec_fn=preexec, env=env)

    p = limited(["load", "--disk-util", "2048"], 1024 ** 3)
    if p.returncode != 1 or "exceeds RLIMIT_FSIZE" not in p.stderr:
        fail("load --disk-util ignored the RLIMIT_FSIZE guard")

    small_fs = None
    if can_root():
        small_fs = Path(tempfile.mkdtemp(prefix="psgen-loadfs-"))
        r = subprocess.run(as_root(["mount", "-t", "tmpfs", "-o", "size=16m",
                                    "tmpfs", small_fs]),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if r.returncode != 0:
            small_fs.rmdir()
            small_fs = None
    if small_fs is not None:
        try:
            free = shutil.disk_usage(small_fs).free
            over = (free // (1024 * 1024)) + 8
            env = dict(os.environ, TMPDIR=str(small_fs))
            p = limited(["load", "--disk-util", over], None, env=env)
            if p.returncode != 1 or "exceeds the free space" not in p.stderr:
                fail(f"load --disk-util {over} ignored the free-space guard: "
                     f"rc={p.returncode} {p.stderr.strip()[:120]!r}")
        finally:
            subprocess.run(as_root(["umount", small_fs]), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            try:
                small_fs.rmdir()
            except OSError:
                pass
        return

    # No root, so the free space is the real filesystem's. Pick the smallest
    # request the free-space guard rejects and check that RLIMIT_FSIZE does not
    # reject it first; if it does, the assertion cannot run here.
    free = shutil.disk_usage(tempfile.gettempdir()).free
    over = free // (1024 * 1024) + 4096
    if not fsize_allows(over * 1024 * 1024):
        skip(f"free-space guard needs a {over} MiB request, but RLIMIT_FSIZE "
             f"is {resource.getrlimit(resource.RLIMIT_FSIZE)[1] // (1024 * 1024)} MiB")
        return
    p = limited(["load", "--disk-util", over], None)
    if p.returncode != 1 or "exceeds the free space" not in p.stderr:
        fail(f"load --disk-util {over} ignored the free-space guard")


TIOCGPTN = 0x80045430
TIOCSPTLCK = 0x40045431


def pty_master_works_at(master: str = "/dev/ptmx", slave_dir: str = "/dev/pts") -> bool:
    """Open a pty master and take a slave, the way the stub does.

    `open("/dev/ptmx")` succeeds on a bind-mounted regular file and on a
    hardened container that refuses to allocate a pty, so the probe has to
    issue the same two ioctls `stub::open_tty` needs and open the slave.
    """
    import fcntl
    try:
        fd = os.open(master, os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return False
    try:
        fcntl.ioctl(fd, TIOCSPTLCK, b"\0\0\0\0")
        n = int.from_bytes(fcntl.ioctl(fd, TIOCGPTN, b"\0\0\0\0"), "little")
        slave = os.open(f"{slave_dir}/{n}", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return False
    finally:
        os.close(fd)
    os.close(slave)
    return True


def pty_master_works() -> bool:
    return pty_master_works_at()


def can_pty() -> bool:
    """True when this host lets a process acquire a pty.

    The primary measurement is the syscall pair the stub itself needs, because
    `doctor`'s probe only opens `/dev/ptmx` and reports ALLOW where allocation
    fails. The tool's verdict is required as well: a `doctor` that cannot be
    read at all, or that has no pty entry, is treated as "no", not "yes". The
    safe default for a predicate that decides whether to skip is False.
    """
    if not pty_master_works():
        return False
    j = run(["doctor", "--json"], check=False)
    if j.returncode != 0:
        return False
    try:
        doc = json.loads(j.stdout)
    except json.JSONDecodeError:
        return False
    for c in doc.get("checks", []):
        if c.get("name") == "pty":
            return bool(c.get("ok"))
    return False


def alive(pid: int) -> bool:
    """False when the PID is gone, or when it is a zombie left by a parent
    that never reaped it: either way there is nothing left to signal."""
    tail = stat_fields(pid)
    if tail is None:
        return False
    return tail[0] != "Z"


def check_inject_flags():
    with tempfile.TemporaryDirectory(prefix="psgen-flags-") as tmp:
        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "3", "-s", "3", "--no-user", "--no-mem",
             "--no-tty", "--no-threads", "--cpu", "40"], tmp, 3)
        try:
            for pid in pids:
                if emulated():
                    continue
                if host_loaded():
                    continue
                util = cpu_percent(pid, 1.0)
                if util is None:
                    fail(f"--cpu pid {pid} vanished")
                if not 28.0 <= util <= 55.0:
                    fail(f"--cpu 40 measured {util:.1f}% on pid {pid}")
        finally:
            stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "4", "-s", "3", "--no-user", "--no-tty",
             "--no-threads", "--phys-cap", "0", "--mem-target", "65536"], tmp, 4)
        time.sleep(0.3)
        # --mem-target sets RSS. A row whose template VSZ leaves less room is
        # clamped below the target, never above it.
        if not emulated():
            sizes_now = [sizes(p)["rss"] for p in pids]
            if not any(abs(v - 65536) <= 8 for v in sizes_now):
                fail(f"--mem-target 65536 produced {sizes_now}")
            if any(v > 65536 + 16 for v in sizes_now):
                fail(f"--mem-target 65536 exceeded the target: {sizes_now}")
        stop_pidfile(pidfile)

        if disk_guard(2):
            pidfile, pids, _ = inject_and_check(
                ["inject", "-n", "2", "-s", "3", "--no-user", "--no-tty",
                 "--no-threads", "--disk", "2"], tmp, 2)
            temps = [l[len("# temp "):] for l in Path(pidfile).read_text().splitlines()
                     if l.startswith("# temp ")]
            found = [Path(t) / "data.bin" for t in temps]
            found = [f for f in found if f.exists()]
            if len(found) != 2:
                fail(f"--disk 2 produced {len(found)} data files in {temps}")
            for f in found:
                if f.stat().st_size != 2 * 1024 * 1024:
                    fail(f"--disk 2 wrote {f.stat().st_size} bytes")
            stop_pidfile(pidfile)
            for f in found:
                if f.exists():
                    fail("stop left a --disk file behind")

        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "2", "-s", "3", "--no-root", "--no-mem",
             "--no-tty", "--no-threads"], tmp, 2)
        if "disables user switching" not in p.stderr:
            fail("--no-root did not explain itself")
        if exe_known():
            for pid in pids:
                if Path(read_exe(pid)).resolve() != BIN.resolve():
                    fail(f"--no-root pid {pid} exe is {read_exe(pid)}")
        stop_pidfile(pidfile)

        shadow = Path(tmp) / "shadow"
        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "-s", "3", "--no-root", "--no-mem",
             "--no-tty", "--no-threads", "--shadow-dir", str(shadow)], tmp, 2)
        for pid in pids:
            if not exe_known():
                continue
            exe = read_exe(pid)
            if not exe.startswith(str(shadow) + "/"):
                fail(f"--shadow-dir pid {pid} exe is {exe}")
        stop_pidfile(pidfile)
        if shadow.exists() and any(shadow.iterdir()):
            fail("stop left shadow copies behind")

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "-s", "3", "--allow-proc-exe", "--no-user",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 2)
        if exe_known():
            for pid in pids:
                if Path(read_exe(pid)).resolve() != BIN.resolve():
                    fail(f"--allow-proc-exe pid {pid} exe is {read_exe(pid)}")
        stop_pidfile(pidfile)

        p = run(["inject", "-n", "1", "--flame"], check=False)
        if p.returncode != 2 or "flame" not in p.stderr:
            fail("--flame was not rejected with an explanation")

def check_regressions():
    """Regressions for the QA findings. Each one failed at bf80156."""
    # F-01: the same seed must give the same non-time columns a second apart.
    def masked(text):
        rows = []
        for line in text.splitlines()[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            rows.append((m.group("pid"), m.group("cmd"), m.group("vsz"),
                         m.group("rss"), m.group("stat")))
        return rows
    a = masked(run(["table", "-n", "20", "-s", "42"]).stdout)
    time.sleep(1.2)
    b = masked(run(["table", "-n", "20", "-s", "42"]).stdout)
    if a != b:
        fail("F-01: table is not deterministic across one second with the same seed")

    # F-03: an existing psgen pidfile is accepted as an output path.
    with tempfile.TemporaryDirectory(prefix="psgen-reg-") as tmp:
        pf = Path(tmp) / "existing.pid"
        pf.write_text("# psgen 0.0.1 boot x\n")
        p = run(["inject", "-n", "1", "-s", "3", "--no-user", "--no-mem",
                 "--no-tty", "--no-threads", "--pidfile", str(pf), "--duration", "2"])
        if p.returncode != 0:
            fail(f"F-03: an existing psgen pidfile was refused: {p.stderr}")
        stop_pidfile(pf)

        # F-02: stop --dry-run must be a parse error, not a kill.
        if run(["stop", "--pidfile", str(pf), "--dry-run"], check=False).returncode != 2:
            fail("F-02: stop --dry-run was accepted")

        # F-17: a pidfile naming a live process with the wrong starttime keeps
        # the temp dirs and exits nonzero only when the process is unreadable;
        # a readable but mismatched process is skipped.
        me = os.getpid()
        pf.write_text(f"# psgen 0.0.1 boot {boot_id()}\n{me}\t0\ttest\n")
        out = run(["stop", "--pidfile", str(pf)], check=False).stdout
        if "skipped 1" not in out:
            fail("F-17: a readable mismatched starttime was not skipped")
        os.kill(me, 0)

        # F-31/F-35: 40-row stop must report 40, not a timing-dependent count.
        pf.write_text("")
        run(["inject", "-n", "40", "-s", "7", "--no-user", "--no-mem",
             "--no-tty", "--threads", "--pidfile", str(pf)])
        out = run(["stop", "--pidfile", str(pf)]).stdout
        if "stopped 40 processes" not in out:
            fail(f"F-31/F-35: stop reported {out.strip()!r} for 40 rows")

        # F-13: the probe must agree with the syscall it describes. A null
        # filter program is refused with EFAULT after the kernel has entered
        # the syscall, which means reachable; EPERM, EACCES and ENOSYS mean a
        # policy or the kernel blocks it. Accepting either label let the old
        # inverted verdict pass.
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ctypes.set_errno(0)
        r = libc.syscall(317, 1, 8, None)
        err = ctypes.get_errno()
        if r != -1:
            want = "reachable"
        elif err in (1, 13, 38):  # EPERM, EACCES, ENOSYS
            want = "blocked"
        else:
            want = "reachable"
        j = run(["doctor", "--json"])
        doc = json.loads(j.stdout)
        val = doc.get("probe", {}).get("seccomp_user_notif")
        if val != want:
            fail(f"F-13: seccomp probe said {val!r}, the syscall says {want!r} (errno {err})")

        # F-12: cargo on PATH must not be reported missing.
        out = run(["check", "--binaries"]).stdout
        if "missing: cargo  <-" in out:
            fail("F-12: check --binaries reported cargo missing")

        # F-23: %MEM follows procps. Measured against procps-ng 4.0.4,
        # `ps` prints `rss * 1000 / MemTotal` truncated: an RSS of 1.453%
        # prints as 1.4, and 0.377% prints as 0.3. `table --live` has to
        # agree with the `ps` beside it, so the synthetic table uses the
        # same arithmetic.
        mem = mem_total()
        for line in run(["table", "-n", "40", "-s", "1"]).stdout.splitlines()[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            rss = int(m.group("rss"))
            want = (rss * 1000 // mem) / 10.0
            got = float(m.group("mem"))
            if abs(got - want) > 0.051:
                fail(f"F-23: %MEM {got} for RSS {rss} kB, want {want}")

        # F-15: the help must describe the 4 MiB floor.
        if "4 MiB" not in run(["--help"]).stdout:
            fail("F-15: help does not mention the 4 MiB mem-cap floor")

        # F-16: the unit must not name a nonexistent target.
        if "proc-fs-nets.target" in run(["unit"]).stdout:
            fail("F-16: unit still names proc-fs-nets.target")

        # F-11: a group without a user is repaired.
        if can_root():
            before_group = subprocess.run(
                ["getent", "group", "haproxy"], stdout=subprocess.DEVNULL).returncode == 0
            before_user = subprocess.run(
                ["getent", "passwd", "haproxy"], stdout=subprocess.DEVNULL).returncode == 0
            if not before_group and not before_user:
                subprocess.run(as_root(["groupadd", "-r", "haproxy"]),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    pf.write_text("")
                    run(["inject", "-f", "web", "-n", "60", "-s", "8", "--user",
                         "--create-users", "--no-exe", "--no-mem", "--no-tty",
                         "--no-threads", "--pidfile", str(pf), "--duration", "2"],
                        root=True)
                    if subprocess.run(["getent", "passwd", "haproxy"],
                                      stdout=subprocess.DEVNULL).returncode != 0:
                        fail("F-11: --create-users did not repair a missing user")
                finally:
                    stop_pidfile(pf, root=True)
                    subprocess.run(as_root(["userdel", "haproxy"]),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(as_root(["groupdel", "haproxy"]),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            skip("F-11 needs sudo or a root caller")

        check_regressions2(tmp)


def check_regressions2(tmp):
    """Second batch: the defects the earlier round left open."""

    # #4: a second stop must not count zombies as stopped, and must not fail.
    pf = Path(tmp) / "zombie.pid"
    run(["inject", "-n", "6", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    first = run(["stop", "--pidfile", str(pf)]).stdout
    if "stopped 6 processes" not in first:
        fail(f"#4: first stop reported {first.strip()!r} for 6 rows")
    time.sleep(0.5)
    second = run(["stop", "--pidfile", str(pf)]).stdout
    if "stopped 0 processes" not in second:
        fail(f"#4: a second stop counted zombies as stopped: {second.strip()!r}")
    pf.unlink()

    # #4 (second half): a subtree is counted once per row, not once per signal
    # that happened to land before the process exited.
    pf = Path(tmp) / "subtree.pid"
    run(["inject", "-n", "40", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--threads", "--pidfile", str(pf)])
    out = run(["stop", "--pidfile", str(pf)]).stdout
    if "stopped 40 processes" not in out:
        fail(f"#4: stop reported {out.strip()!r} for a 40-row tree")
    pf.unlink()

    # #22: a one-field pidfile line must not report success without signalling.
    pf = Path(tmp) / "full.pid"
    one = Path(tmp) / "one.pid"
    run(["inject", "-n", "2", "-s", "5", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    pids = read_pids(pf)
    # The header is not optional: without it `stop` refuses the file before any
    # row is examined, so a headerless copy makes this assertion unreachable.
    header = pidfile_header(pf)
    write_rows(one, header, pids)
    p = run(["stop", "--pidfile", str(one)], check=False)
    # A zombie is gone for every purpose `stop` reports, so the liveness test
    # is the same one the tool uses.
    alive_now = [pid for pid in pids if alive(pid)]
    if alive_now:
        fail(f"#22: a one-field pidfile left {len(alive_now)} of {len(pids)} "
             f"rows alive that its run nonce identifies (rc={p.returncode}): "
             f"{p.stdout.strip()!r}")
    stop_pidfile(pf)

    # #15: stop --dry-run must be refused; stop --plan must not signal.
    pf = Path(tmp) / "plan.pid"
    run(["inject", "-n", "2", "-s", "5", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    pids = read_pids(pf)
    if run(["stop", "--pidfile", str(pf), "--dry-run"], check=False).returncode != 2:
        fail("#15: stop --dry-run was accepted")
    plan = run(["stop", "--pidfile", str(pf), "--plan"], check=False)
    if "would stop 2 processes" not in plan.stdout:
        fail(f"#15: stop --plan printed {plan.stdout.strip()!r}")
    for pid in pids:
        if not alive(pid):
            fail(f"#15: stop --plan signalled pid {pid}")
    stop_pidfile(pf)

    # #26: a basename near NAME_MAX is refused before anything is spawned.
    for length in (200, 220, 225, 230, 240, 250):
        name = "d" * length
        p = run(["inject", "-n", "1", "--no-user", "--no-mem", "--no-tty",
                 "--no-threads", "--pidfile", str(Path(tmp) / name)], check=False)
        if p.returncode != 0 and "spawned" in p.stdout:
            fail(f"#26: basename {length} failed after spawning")
        if p.returncode == 0 and not (Path(tmp) / name).exists():
            fail(f"#26: basename {length} reported success without a pidfile")
        if (Path(tmp) / name).exists():
            stop_pidfile(Path(tmp) / name)

    # #25: a config on fd 3 that this process did not create must not be
    # acted on. A file opened by the caller is a named descriptor, which is
    # refused outright rather than silently ignored: silence left the exit
    # status and the command line as the only evidence, and neither is what
    # the stub path changes.
    import struct
    magic = b"PGCFG023"
    hdr = bytearray(104)
    hdr[:8] = magic
    struct.pack_into("<I", hdr, 8, 3)      # version
    struct.pack_into("<I", hdr, 92, 0)     # self_copy len
    struct.pack_into("<I", hdr, 96, 4)     # nonce len
    blob = bytes(hdr) + b"dead"
    cfg = Path(tmp) / "cfg.bin"
    cfg.write_bytes(blob)
    fd = os.open(str(cfg), os.O_RDONLY)
    rc, exes, _, comm, _ = fd3_run_observe(fd, timeout=1.5)
    os.close(fd)
    if comm and comm != "psgen":
        fail(f"#25: an inherited fd 3 config turned the process into {comm!r}")
    foreign = [e for e in exes
               if e and os.path.realpath(e) != os.path.realpath(str(BIN))]
    if foreign:
        fail(f"#25: an inherited fd 3 config executed {foreign[0]}")

    # #25 (stronger): a config with a matching nonce but an attacker-named
    # self_copy must not exec it and must not create the named directory. The
    # nonce is a run tag, not the gate; the descriptor is.
    attack = Path(tmp) / "attack"
    blob = cfg_blob(b"PGCFG023", 3, stage=1, comm=b"nginx", exe=b"",
                    cmd=b"sleep 120", user=b"root",
                    temp=str(attack).encode(), self_copy=b"/bin/sh",
                    nonce=b"deadbeefdeadbeef", disk_kb=1024)
    fd = memfd_blob(blob, 1)          # no MFD_ALLOW_SEALING: unsealable
    if fd is not None and fd >= 0:
        rc, exes, _, comm, _ = fd3_run_observe(
            fd, {"PSGEN_NONCE": "deadbeefdeadbeef"}, timeout=1.5)
        os.close(fd)
        if comm and comm != "psgen":
            fail(f"#25: a forged config with a matching nonce became {comm!r}")
        if attack.exists():
            shutil.rmtree(attack)
            fail("#25: a forged config created the directory it named")
        foreign = [e for e in exes
                   if e and os.path.realpath(e) != os.path.realpath(str(BIN))]
        if foreign:
            fail(f"#25: a forged config executed {foreign[0]}")

    # #14: a denied getrandom must not abort after the stubs are spawned.
    #     (The fallback is total; a run with --pidfile must exit 0 or, at
    #     worst, report the rows without a panic.)
    pf = Path(tmp) / "rand.pid"
    p = run(["inject", "-n", "2", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", str(pf), "--duration", "1"],
            check=False)
    if p.returncode >= 128:
        fail(f"#14: inject died with signal {p.returncode - 128}")
    stop_pidfile(pf)

    # #8: doctor --json checks are objects with a name field.
    doc = json.loads(run(["doctor", "--json"]).stdout)
    if not all(isinstance(c, dict) and "name" in c for c in doc["checks"]):
        fail("#8: doctor --json checks are not named objects")
    if "core_ok" not in doc:
        fail("#8: doctor --json lacks core_ok")
    pf = Path(tmp) / "doctor.pid"
    doc = json.loads(run(["doctor", "--json", "--pidfile", str(pf)]).stdout)
    if doc.get("pidfile", {}).get("path") != str(pf):
        fail("#8: doctor --json pidfile is not an object with a path")

    # #7: a pidfile header with another version is still recognised.
    me = os.getpid()
    pf.write_text(f"# psgen 9.9.9 boot 00000000-0000-0000-0000-000000000000\n{me}\t0\ttest\n")
    p = run(["stop", "--pidfile", str(pf)], check=False)
    if "another boot" not in p.stderr:
        fail("#7: a foreign-version pidfile header was not parsed")

    # #17: --utc-offset is bounded.
    if run(["table", "-n", "1", "--utc-offset", "9223372036854775807"],
           check=False).returncode != 2:
        fail("#17: an absurd --utc-offset was accepted")
    env = dict(os.environ, TZ="Asia/Kolkata")
    loc = run(["table", "-f", "dev", "-n", "4", "-s", "1", "--local"], env=env).stdout
    both = run(["table", "-f", "dev", "-n", "4", "-s", "1", "--local",
                "--utc-offset", "120"], env=env).stdout
    if loc != both:
        fail("#17: --local and --utc-offset were both applied")

    # #16: a count is honoured by spreading the repeats over the templates that
    # can run more than once, and a request that cannot be met at all says so.
    for fam, n in (("mail", 50), ("mon", 50), ("sto", 50), ("net", 50)):
        p = run(["table", "-f", fam, "-n", str(n)])
        cmds = [" ".join(r.split()[10:]) for r in p.stdout.splitlines()[1:]]
        if cmds and max(cmds.count(c) for c in set(cmds)) > n // 2:
            fail(f"#16: {fam} -n {n} is dominated by one command")
        if "can supply" in p.stderr and not cmds:
            fail(f"#16: {fam} warned but produced no rows")
        # `list` never repeats, so it stops short and says so.
        lp = run(["list", "-f", fam, "-n", str(n)])
        lines = lp.stdout.splitlines()
        if len(lines) < n and "a list never repeats" not in lp.stderr:
            fail(f"#16: list -f {fam} shortfall was silent")
        if len(set(lines)) != len(lines):
            fail(f"#16: list -f {fam} repeated a command")
    rows = run(["table", "-f", "sys", "-n", "200"]).stdout.splitlines()[1:]
    cmds = [" ".join(r.split()[10:]) for r in rows]
    # The regression was one command taking 60% of the table (120 of 200 rows
    # were `sshd: user [priv]`).
    top = max(cmds.count(c) for c in set(cmds))
    if top > len(cmds) // 3:
        fail(f"#16: sys -n 200 has one command {top} of {len(cmds)} rows")
    if len(set(cmds)) < 30:
        fail(f"#16: sys -n 200 used only {len(set(cmds))} distinct commands")
    big = [" ".join(r.split()[10:]) for r in
           run(["table", "-n", "5000", "-s", "1"]).stdout.splitlines()[1:]]
    if len(big) < 1000:
        fail(f"#16: table -n 5000 produced only {len(big)} rows")
    top = max(big.count(c) for c in set(big))
    if top > len(big) // 25:
        fail(f"#16: table -n 5000 has one command {top} of {len(big)} rows")

    # #28: RSS cannot exceed MemTotal, %MEM cannot exceed 100, PIDs stay below
    # pid_max.
    mem = mem_total()
    pid_max = int(Path("/proc/sys/kernel/pid_max").read_text())
    for line in run(["table", "-n", "5000", "-s", "1"]).stdout.splitlines()[1:]:
        m = PS_RE.match(line)
        if not m:
            continue
        rss, mempct, pid = int(m.group("rss")), float(m.group("mem")), int(m.group("pid"))
        if rss > mem:
            fail(f"#28: RSS {rss} kB exceeds MemTotal {mem} kB")
        if mempct > 100.0:
            fail(f"#28: %MEM {mempct} is impossible for one process")
        if pid > pid_max:
            fail(f"#28: PID {pid} exceeds pid_max {pid_max}")

    # #3: table --live matches ps aux on the cases a monitor hits.
    live = run(["table", "--live"]).stdout.splitlines()
    ref = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True,
                         timeout=30).stdout.splitlines()
    if live[0] != ref[0]:
        fail("#3: live header differs from ps aux")

    def offsets(lines):
        out = []
        for line in lines[1:]:
            m = PS_RE.match(line)
            if not m:
                out.append(None)
                continue
            try:
                stat = line.index(m.group("stat"), 40)
                start = line.index(m.group("start"), stat)
                tm = line.index(m.group("time"), start)
                cmd = line.index(m.group("cmd"), tm)
            except ValueError:
                out.append(None)
                continue
            out.append((stat, start, tm, cmd))
        return out

    # Only compare rows that both sides parsed: the two reads are not atomic, so
    # a process that exits between them has no pair.
    def by_pid(lines):
        out = {}
        for line in lines[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            try:
                stat = line.index(m.group("stat"), 40)
                start = line.index(m.group("start"), stat)
                tm = line.index(m.group("time"), start)
                cmd = line.index(m.group("cmd"), tm)
            except ValueError:
                continue
            out[int(m.group("pid"))] = (stat, start, tm, cmd)
        return out

    mine, theirs = by_pid(live), by_pid(ref)
    common = set(mine) & set(theirs)
    if len(common) < 5:
        fail(f"#3: only {len(common)} rows are common to the two tables")
    for pid in common:
        if mine[pid] != theirs[pid]:
            fail(f"#3: live column offsets {mine[pid]} differ from ps {theirs[pid]} for {pid}")
    if any("\n" in l for l in live):
        fail("#3: live table emitted a raw newline")
    # A zombie's COMMAND must carry <defunct>, as ps prints it.
    ps_rows_ref = {}
    for line in ref[1:]:
        m = PS_RE.match(line)
        if m:
            ps_rows_ref[int(m.group("pid"))] = m.group("cmd")
    live_rows_now = {}
    for line in live[1:]:
        m = PS_RE.match(line)
        if m:
            live_rows_now[int(m.group("pid"))] = m.group("cmd")
    for pid, want in ps_rows_ref.items():
        if want.endswith("<defunct>") and pid in live_rows_now:
            if live_rows_now[pid] != want:
                fail(f"#3: zombie {pid} cmd {live_rows_now[pid]!r} != ps {want!r}")

    # A newline in argv must not split a row.
    script = ("import subprocess,time,sys;"
              "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)',"
              "'line1\\nline2','tab\\there','','empty-argv']);print(p.pid,flush=True);"
              "time.sleep(30)")
    helper = subprocess.Popen([sys.executable, "-c", script],
                              stdout=subprocess.PIPE, text=True)
    try:
        time.sleep(0.8)
        wide = run(["table", "--live"]).stdout
        for line in wide.splitlines():
            if "line1" in line:
                if "line2" in line.split("line1", 1)[1][:8]:
                    pass
                break
        else:
            pass
        bad = [l for l in wide.splitlines() if l.startswith("line2")]
        if bad:
            fail("#3: a newline in argv split a live table row")
        # The empty argv elements must survive as the extra spaces `ps` shows.
        inner = int(helper.stdout.readline().strip())
        mine = None
        for line in wide.splitlines():
            m = PS_RE.match(line)
            if m and int(m.group("pid")) == inner:
                mine = m.group("cmd")
                break
        ps_args = subprocess.run(["ps", "-o", "args=", "-p", str(inner)],
                                 stdout=subprocess.PIPE, text=True,
                                 timeout=30).stdout.strip()
        if mine is None:
            fail("#3: the empty-argv process is missing from the live table")
        if mine != ps_args:
            fail(f"#3: live cmd {mine!r} != ps {ps_args!r} for an empty argv element")
    finally:
        helper.kill()
        helper.wait()
        try:
            os.kill(inner, 9)
        except (ProcessLookupError, UnboundLocalError, OSError):
            pass

    # #9: an option that does not apply to the subcommand is an error.
    for args in (["stop", "-n", "40", "--pidfile", str(Path(tmp) / "x.pid")],
                 ["corpus", "-n", "5"],
                 ["list", "-d", "5", "-n", "1"],
                 ["list", "--json", "-n", "1"],
                 ["table", "--live", "-f", "web"],
                 ["doctor", "--json", "--lines", "5"],
                 ["check", "--utc-offset", "300"],
                 ["check", "-p", "desktop"],
                 ["inject", "--plan"]):
        if run(args, check=False).returncode != 2:
            fail(f"#9: {args} was accepted")

    # #9/#13.2: unit forwards what it was given and caps -n.
    unit = run(["unit", "-p", "desktop", "-f", "desk", "--no-mem", "-d", "300",
                "-n", "40"]).stdout
    for want in ("-p desktop", "-f desk", "-d 300", "--no-mem", "-n 40"):
        if want not in unit.split("ExecStart=")[1].splitlines()[0]:
            fail(f"#13.2: unit did not forward {want}")
    capped = run(["unit", "-n", "1000"]).stdout
    if "-n 500" not in capped:
        fail("#27: unit -n was not capped at the inject cap")

    # #12: --dry-run keeps its two columns; --plan and --json add the plan.
    dry = run(["inject", "-n", "2", "-s", "3", "--dry-run", "--no-user"]).stdout
    if not all(len(l.split("\t")) == 2 for l in dry.splitlines() if l):
        fail("#12: --dry-run changed its two-column format")
    plan = run(["inject", "-n", "2", "-s", "3", "--dry-run", "--plan",
                "--no-user"]).stdout
    if "tier " not in plan or "row 0 " not in plan:
        fail("#12: --plan printed no plan")
    doc = json.loads(run(["inject", "-n", "2", "-s", "3", "--dry-run", "--json",
                          "--no-user"]).stdout)
    if doc.get("tier") not in ("bind", "shadow", "proc-self") or len(doc["rows"]) != 2:
        fail("#12: --dry-run --json is not a plan")

    # #5: a --duration run that nobody stops leaves nothing for the next run.
    if disk_guard(1):
        check_staging_prune(tmp)

    # #1: a pidfile that still records live stubs cannot be reused. The second
    # inject must refuse, and the first run must remain stoppable.
    pf = Path(tmp) / "reuse.pid"
    run(["inject", "-n", "2", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    p = run(["inject", "-n", "2", "-s", "7", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", str(pf)], check=False)
    if p.returncode != 2 or "records live processes" not in p.stderr:
        fail(f"#1: reusing a live pidfile was not refused: rc {p.returncode}")
    out = stop_pidfile(pf)
    if "stopped 2 processes" not in out:
        fail(f"#1: the first run could not be stopped after the refusal: {out!r}")
    run(["inject", "-n", "2", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    stop_pidfile(pf)

    # #4 (third case): a malformed starttime is skipped, not treated as a
    # one-field line whose executable check can kill a psgen stub.
    pf = Path(tmp) / "malformed.pid"
    run(["inject", "-n", "1", "-s", "7", "--no-exe", "--no-user", "--no-mem",
         "--no-tty", "--no-threads", "--pidfile", str(pf)])
    lines = pf.read_text().splitlines()
    row = next(l for l in lines if l and not l.startswith("#"))
    fields = row.split("\t")
    pid = int(fields[0])
    fields[1] = "notanumber"
    lines = [("\t".join(fields) if l == row else l) for l in lines]
    pf.write_text("\n".join(lines) + "\n")
    try:
        out = run(["stop", "--pidfile", str(pf)]).stdout
        if "skipped 1" not in out:
            fail(f"#4: a malformed starttime was not skipped: {out.strip()!r}")
        if not Path(f"/proc/{pid}").exists():
            fail("#4: a malformed starttime killed the named psgen stub")
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        pf.unlink(missing_ok=True)

    # #24: a closed reader stops the generator, and --lines is bounded.
    proc = subprocess.Popen([str(BIN), "log", "-m", "weblog", "--lines", "100000",
                             "--delay", "10"], stdout=subprocess.PIPE)
    proc.stdout.readline()
    proc.stdout.close()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        fail("#24: log kept generating after its reader exited")
    p = run(["log", "--lines", "1000000000"], check=False, timeout=120)
    if len(p.stdout) > 200 * 1024 * 1024:
        fail("#24: log --lines 1000000000 produced an unbounded amount of output")
    if "capped" not in p.stderr:
        fail("#24: log did not warn about the cap")

    # #23: --mem-util above MemAvailable is refused without --force.
    avail = 0
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            avail = int(line.split()[1])
    if avail and avail * 1000 // mem_total() < 950:
        p = run(["load", "--mem-util", "95", "-d", "1"], check=False, timeout=120)
        if p.returncode != 2 or "MemAvailable" not in p.stderr:
            fail("#23: load --mem-util above MemAvailable was not refused")

    # #21: check --binaries does not report an installed path as missing.
    out = run(["check", "--binaries"]).stdout
    for line in out.splitlines():
        if not line.startswith("missing: "):
            continue
        path = line.split("<- ", 1)[1].strip().split()[0]
        if os.access(path, os.X_OK):
            fail(f"#21: check --binaries reported an existing path missing: {path}")
    if run(["check", "--require-binaries"], check=False).returncode not in (0, 1):
        fail("#21: --require-binaries exited with an unexpected code")


_SECCOMP_HELPER: Path | None = None


def seccomp_helper() -> Path | None:
    """Build the seccomp launcher once, or None when there is no C compiler.

    Cached: two checks need it, and a fresh `mkdtemp` per call left one build
    directory behind per call for a helper that never changes during a run.
    """
    global _SECCOMP_HELPER
    if _SECCOMP_HELPER is not None:
        return _SECCOMP_HELPER
    src = ROOT / "tests" / "helpers" / "deny_syscall.c"
    if not src.is_file():
        return None
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        return None
    out = Path(tempfile.mkdtemp(prefix="psgen-seccomp-")) / "deny_syscall"
    p = subprocess.run([cc, "-O2", "-o", str(out), str(src)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        shutil.rmtree(out.parent, ignore_errors=True)
        skip(f"cannot build the seccomp helper: {p.stderr.strip()[:200]}")
        return None
    _SECCOMP_HELPER = out
    return out


def check_staging_prune(tmp: Path) -> None:
    """#5: a dead run's staging directory is pruned, a live one is not."""
    shadow = Path(tmp) / "staging"
    env = dict(os.environ, TMPDIR=str(Path(tmp) / "tmpdir"))
    (Path(tmp) / "tmpdir").mkdir()
    run(["inject", "-n", "3", "-s", "7", "-d", "1", "--disk", "1",
         "--no-user", "--no-mem", "--no-tty", "--no-threads",
         "--shadow-dir", str(shadow), "--pidfile", str(Path(tmp) / "d.pid")],
        env=env)
    time.sleep(2.2)
    leftovers = list(shadow.rglob("*")) + list((Path(tmp) / "tmpdir").glob(".psgen-*"))
    if not leftovers:
        fail("#5: the --duration run left no staging behind to test the prune")
    for p in leftovers:
        try:
            os.utime(p, (0, 0))
        except OSError:
            pass
    p = run(["inject", "-n", "1", "-s", "7", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--shadow-dir", str(shadow),
             "--pidfile", str(Path(tmp) / "p.pid")], env=env, check=False)
    stop_pidfile(Path(tmp) / "p.pid")
    if "pruned" not in p.stderr:
        fail("#5: the next run did not prune the staging directories")
    if list((Path(tmp) / "tmpdir").glob(".psgen-*")):
        fail("#5: the prune left a dead run's data directory")

    # #5 (second half): a live --duration run must keep its staging until its
    # last stub exits. The injector is already gone, so only the live marker
    # can tell the prune that the data is still in use.
    live_tmp = Path(tmp) / "livetmp"
    live_tmp.mkdir()
    live_shadow = Path(tmp) / "live-staging"
    live_env = dict(os.environ, TMPDIR=str(live_tmp))
    pf1 = Path(tmp) / "live1.pid"
    pf2 = Path(tmp) / "live2.pid"
    run(["inject", "-n", "1", "-s", "7", "-d", "8", "--disk", "1",
         "--no-user", "--no-mem", "--no-tty", "--no-threads",
         "--shadow-dir", str(live_shadow), "--pidfile", str(pf1)], env=live_env)
    dirs = list(live_tmp.glob(".psgen-*"))
    if not dirs:
        fail("#5: the live run created no staging directory")
    try:
        p = run(["inject", "-n", "1", "-s", "7", "-d", "1", "--no-user",
                 "--no-mem", "--no-tty", "--no-threads",
                 "--shadow-dir", str(live_shadow), "--pidfile", str(pf2)],
                env=live_env, check=False)
        if "pruned" in p.stderr:
            fail("#5: the prune removed a live --duration run's staging")
        if not dirs[0].is_dir():
            fail("#5: the live --duration run's staging directory is gone")
        if not (dirs[0] / "data.bin").is_file():
            fail("#5: the live --duration run's disk data is gone")
    finally:
        stop_pidfile(pf2)
        stop_pidfile(pf1)


def check_residuals(tmp):
    """Regressions for the defects a second review found in the first PR."""

    # #16: `-n` is a guarantee, not a target, for one family as well as for the
    # whole corpus. Every family that has a template able to repeat must reach
    # the requested count exactly, and the busiest command must stay under
    # half the table.
    for fam in ("sys", "web", "db", "mon", "net", "mail", "sto", "desk", "dev", "ctr"):
        p = run(["table", "-f", fam, "-n", "200"], check=False)
        rows = p.stdout.splitlines()[1:]
        if len(rows) != 200:
            fail(f"#16: table -f {fam} -n 200 returned {len(rows)} rows")
        cmds = [" ".join(r.split()[10:]) for r in rows]
        top = max(cmds.count(c) for c in set(cmds))
        if top > len(cmds) // 2:
            fail(f"#16: table -f {fam} -n 200 has one command {top} of {len(cmds)} rows")
    # The count is exact for `inject` too.
    rows = run(["inject", "-f", "web", "-n", "120", "--dry-run"]).stdout.splitlines()
    if len(rows) != 120:
        fail(f"#16: inject -f web -n 120 printed {len(rows)} rows")

    # #16 (opt-out): `--repeat-max 1` is how a caller asks for fewer rows rather
    # than a repeated command, and the shortfall names the reason.
    p = run(["table", "-f", "sto", "-n", "200", "--repeat-max", "1"], check=False)
    rows = p.stdout.splitlines()[1:]
    if len(rows) >= 200:
        fail("#16: --repeat-max 1 still reached 200 rows")
    if "row" not in p.stderr or "could be produced" not in p.stderr:
        fail(f"#16: the shortfall message is unhelpful: {p.stderr.strip()!r}")
    cmds = [" ".join(r.split()[10:]) for r in rows]
    if cmds and max(cmds.count(c) for c in set(cmds)) > 1:
        fail("#16: --repeat-max 1 repeated a command")
    # ... and the default reaches the count for the same family.
    rows = run(["table", "-f", "sto", "-n", "200"]).stdout.splitlines()[1:]
    if len(rows) != 200:
        fail(f"#16: table -f sto -n 200 returned {len(rows)} rows by default")

    # #28: a small pid_max caps the table, reports the gap, and never repeats or
    # exceeds a PID.
    for pid_max in (2, 3, 4, 10, 100):
        p = run(["table", "-n", "50", "--host-pid-max", str(pid_max)], check=False)
        rows = p.stdout.splitlines()[1:]
        pids = [int(r.split()[1]) for r in rows]
        if len(set(pids)) != len(pids):
            fail(f"#28: pid_max {pid_max} produced a duplicate PID")
        for pid in pids:
            if pid < 1 or pid >= pid_max:
                fail(f"#28: pid_max {pid_max} produced PID {pid}")
        room = max(pid_max - 1, 1)
        if len(pids) > room:
            fail(f"#28: pid_max {pid_max} produced {len(pids)} rows with room for {room}")
        if pid_max < 50 and "could be produced" not in p.stderr:
            fail(f"#28: pid_max {pid_max} silently under-delivered")
        if pid_max >= 50 and p.stderr:
            fail(f"#28: pid_max {pid_max} printed a shortfall it does not have")

    # #28 (memory half): a small host is fitted, not exceeded.
    rows = run(["table", "-n", "600", "--host-mem", "256"]).stdout.splitlines()[1:]
    total = 0
    for line in rows:
        m = PS_RE.match(line)
        if not m:
            continue
        rss = int(m.group("rss"))
        total += rss
        if rss > 256 * 1024:
            fail(f"#28: a 256 MiB host got a {rss} kB row")
        if float(m.group("mem")) > 100.0:
            fail("#28: %MEM above 100 on a 256 MiB host")
    if total > 256 * 1024:
        fail(f"#28: a 256 MiB host got {total} kB of RSS")

    # #2: the same seed must give the same non-time columns at any uptime, with
    # no private mount and no fake host: the generator takes the uptime.
    def masked(args, uptime):
        out = run(args + ["--host-uptime", str(uptime)]).stdout
        rows = []
        for line in out.splitlines()[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            rows.append((m.group("pid"), m.group("cpu"), m.group("vsz"),
                         m.group("rss"), m.group("stat"), m.group("cmd")))
        return rows

    # The smallest real host is 1 s: 0 names a host that never booted and is a
    # usage error, so it cannot be part of an uptime sweep.
    for uptime in (1, 5, 10, 11, 30, 60, 61, 600):
        a = masked(["table", "-n", "30", "-s", "165"], uptime)
        b = masked(["table", "-n", "30", "-s", "165"], uptime + 1)
        if a != b:
            fail(f"#2: seed 165 differs between uptime {uptime} and {uptime + 1}")

    # #14: a real seccomp denial of getrandom must not abort after the pidfile
    # header is written, and the run must stay stoppable.
    helper = seccomp_helper()
    # The relaunch falls back to an unlinked temp file holding a copy of the
    # binary, so a small RLIMIT_FSIZE kills it with SIGXFSZ. That is the
    # limit's doing, not psgen's, and the check cannot observe the fallback.
    if not fsize_allows(BIN.stat().st_size + 1024 * 1024):
        skip("#14 needs room for an unlinked temp copy under RLIMIT_FSIZE")
    elif helper is None:
        skip("#14 needs a C compiler for the seccomp launcher")
    else:
        pf = Path(tmp) / "getrandom.pid"
        p = subprocess.run([str(helper), "getrandom", str(BIN), "inject", "-n", "2",
                            "--no-user", "--no-mem", "--no-tty", "--no-threads",
                            "--pidfile", str(pf)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=180)
        if p.returncode >= 128:
            fail(f"#14: inject died by signal {p.returncode - 128} under a getrandom denial")
        if p.returncode != 0:
            fail(f"#14: inject failed under a getrandom denial: {p.stderr.strip()[:300]}")
        if not pf.exists():
            fail("#14: no pidfile after a getrandom denial")
        pids = read_pids(pf)
        if len(pids) != 2:
            fail(f"#14: {len(pids)} rows recorded under a getrandom denial")
        out = stop_pidfile(pf)
        if "stopped 2 processes" not in out:
            fail(f"#14: the run was not stoppable after a getrandom denial: {out!r}")

        # The other half: a failure inside spawn, after the header-only pidfile
        # exists. Nothing may be spawned and the header must be removed.
        pf = Path(tmp) / "pipe2.pid"
        p = subprocess.run([str(helper), "pipe2", str(BIN), "inject", "-n", "2",
                            "--no-user", "--no-mem", "--no-tty", "--no-threads",
                            "--pidfile", str(pf)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=180)
        if p.returncode == 0:
            fail("#14: inject succeeded with pipe2 denied")
        if pf.exists():
            fail("#14: a post-header spawn failure left a pidfile behind")
        if "pipe2" not in p.stderr:
            fail(f"#14: the failure does not name the syscall: {p.stderr.strip()[:200]!r}")

    # #25: a hardlink named psgen-stub must not be executed. A hardlink is a
    # regular file with a second link, which is exactly what the leaf check
    # refuses.
    if not (shutil.which("ln") and os.path.isdir("/proc/self/fd")):
        skip("#25 hardlink leaf needs ln")
    else:
        staging = Path(tmp) / "hardlink"
        staging.mkdir()
        run(["inject", "-n", "1", "-s", "5", "--no-root", "--no-user",
             "--no-mem", "--no-tty", "--no-threads", "--shadow-dir", str(staging),
             "--pidfile", str(Path(tmp) / "hl.pid")], check=False)
        dirs = list(staging.glob(".psgen-*"))
        if not dirs:
            skip("#25 no shadow staging was created")
        else:
            d = dirs[0]
            run([str(BIN), "stop", "--pidfile", str(Path(tmp) / "hl.pid")], check=False)
            run([str(BIN), "stop", "--pidfile", str(Path(tmp) / "hl.pid")], check=False)
            leaf = d / "psgen-stub"
            victim = d / "victim"
            if leaf.exists():
                leaf.unlink()
            shutil.copy2("/bin/echo", victim)
            try:
                os.link(victim, leaf)
            except OSError as e:
                skip(f"#25 cannot make a hardlink here: {e}")
            else:
                # Feed the stub a config that names the hardlinked leaf. It must
                # not exec it.
                cfg = Path(tmp) / "hl.cfg"
                nonce = b"deadbeefdeadbeef"
                comm = b"nginx"
                cmd = b"/usr/sbin/nginx"
                self_copy = str(leaf).encode()
                temp = str(d).encode()
                import struct
                hdr = bytearray(104)
                hdr[:8] = b"PGCFG023"

                def w(off, v):
                    struct.pack_into("<I", hdr, off, v)

                w(8, 3)
                w(40, 1)
                w(44, len(comm))
                w(48, len(self_copy))
                w(52, len(cmd))
                w(56, 1)
                w(60, len(temp))
                struct.pack_into("<i", hdr, 72, 5)
                struct.pack_into("<i", hdr, 76, -1)
                struct.pack_into("<i", hdr, 80, -1)
                w(92, len(self_copy))
                w(96, len(nonce))
                blob = bytes(hdr) + comm + self_copy + cmd + b"u" + temp + self_copy + nonce
                # A named file is refused before the leaf is reached: nlink
                # is 1 and it carries no seals. A sealed memfd is the only
                # shape the stub accepts, and it is what reaches the check.
                fd = sealed_cfg(blob)
                env = dict(os.environ, PSGEN_NONCE=nonce.decode())
                proc = None if fd is None else subprocess.Popen(
                    [str(BIN)], env=env, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=lambda: os.dup2(fd, 3),
                    pass_fds=(fd,))
                time.sleep(1.0)
                try:
                    exe = os.readlink(f"/proc/{proc.pid}/exe")
                except OSError:
                    exe = ""
                proc.kill()
                proc.wait()
                if exe == str(victim) or exe == str(leaf):
                    fail("#25: a hardlinked psgen-stub was executed")
                leaf.unlink()
                victim.unlink()

    # #25 (data.bin): a pre-existing hardlink named data.bin must not be
    # truncated by --disk.
    if shutil.which("ln") and fsize_allows(1024 * 1024):
        staging = Path(tmp) / "diskhard"
        staging.mkdir()
        outer = Path(tmp) / "victim-file"
        outer.write_bytes(b"keep me\n")
        pf = Path(tmp) / "disk.pid"
        run(["inject", "-n", "1", "-s", "5", "--disk", "1", "--no-root",
             "--no-user", "--no-mem", "--no-tty", "--no-threads",
             "--shadow-dir", str(staging),
             "--pidfile", str(pf)], check=False,
            # The run stages under `TMPDIR` as well as `--shadow-dir`; pin it
            # to this check's own directory so the pass cannot leave a data
            # directory in the caller's temporary root.
            env=dict(os.environ, TMPDIR=str(Path(tmp) / "disk-tmp")))
        dirs = list(staging.glob(".psgen-*"))
        for d in dirs:
            run([str(BIN), "stop", "--pidfile", str(pf)], check=False)
            data = d / "data.bin"
            if data.exists():
                data.unlink()
            try:
                os.link(outer, data)
            except OSError:
                continue
            # Run the stub for this directory through a config naming it.
            cfg = Path(tmp) / "disk.cfg"
            nonce = b"deadbeefdeadbeef"
            comm = b"nginx"
            cmd = b"/usr/sbin/nginx"
            temp = str(d).encode()
            import struct
            hdr = bytearray(104)
            hdr[:8] = b"PGCFG023"

            def w2(off, v):
                struct.pack_into("<I", hdr, off, v)

            w2(8, 3)
            w2(40, 1)
            w2(44, len(comm))
            w2(48, 0)
            w2(52, len(cmd))
            w2(56, 1)
            w2(60, len(temp))
            struct.pack_into("<i", hdr, 72, 5)
            struct.pack_into("<i", hdr, 76, -1)
            struct.pack_into("<i", hdr, 80, -1)
            w2(88, 1024)  # 1 MiB of --disk data
            w2(92, 0)
            w2(96, len(nonce))
            blob = bytes(hdr) + comm + cmd + b"u" + temp + nonce
            fd = sealed_cfg(blob)
            env = dict(os.environ, PSGEN_NONCE=nonce.decode())
            proc = None if fd is None else subprocess.Popen(
                [str(BIN)], env=env, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=lambda: os.dup2(fd, 3),
                pass_fds=(fd,))
            time.sleep(1.2)
            if proc is not None:
                proc.kill()
                proc.wait()
                os.close(fd)
            if outer.read_bytes() != b"keep me\n":
                fail("#25: a hardlinked data.bin was truncated")
            data.unlink()
            break
        try:
            outer.unlink()
        except OSError:
            pass

    # #26: the error names what actually failed. A path that is too long is not
    # a NAME_MAX problem when the basename is short and the directory is deep.
    deep = Path(tmp)
    while len(str(deep)) < 4090:
        deep = deep / ("d" * 200)
    target = str(deep / "p.pid")
    p = run(["inject", "-n", "1", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", target], check=False)
    if p.returncode != 2:
        fail(f"#26: an over-long path exited {p.returncode}")
    # The message has to name what failed. For a path over PATH_MAX with short
    # components that is not a NAME_MAX problem, and saying "not a psgen
    # pidfile" (the old wording) is a lie about a path that was never opened.
    if len(target) > 4096:
        if "cannot be examined" not in p.stderr:
            fail(f"#26: an over-long path was not reported as unopenable: {p.stderr[:160]!r}")
        if "NAME_MAX" in p.stderr:
            fail("#26: a PATH_MAX failure was reported as NAME_MAX")
    # A basename over NAME_MAX is a different message, and it must be refused
    # before anything is spawned.
    long_name = Path(tmp) / ("n" * 300)
    p = run(["inject", "-n", "2", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", str(long_name)], check=False)
    if p.returncode != 2 or "spawned" in p.stdout:
        fail(f"#26: a NAME_MAX basename was not refused before spawning: {p.returncode}")

    # #6: a psgen header with no boot id is refused, not silently accepted.
    pf = Path(tmp) / "noboot.pid"
    pf.write_text("# psgen 0.0.1\n")
    p = run(["stop", "--pidfile", str(pf)], check=False)
    if p.returncode == 0:
        fail("#6: a header with no boot id was accepted")
    p = run(["stop", "--pidfile", str(pf), "--force"], check=False)
    if p.returncode != 0:
        fail(f"#6: --force did not accept a header with no boot id: {p.stderr.strip()!r}")

    # #15: --plan -q is quiet, and a target the caller cannot signal is reported.
    pf = Path(tmp) / "plan2.pid"
    run(["inject", "-n", "2", "-s", "5", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    p = run(["stop", "--pidfile", str(pf), "--plan", "-q"], check=False)
    if "would signal" in p.stdout:
        fail("#15: --plan -q printed would-signal lines")
    stop_pidfile(pf)

    # #24: --lines 0 is "print nothing and succeed", which is what the base
    # did; the review kept that rather than turning it into an error.
    p = run(["log", "--lines", "0"], check=False)
    if p.returncode != 0 or p.stdout.strip():
        fail(f"#24: log --lines 0 printed {p.stdout[:40]!r} and exited {p.returncode}")

    # #5: an unmarked foreign .psgen-* directory is never removed.
    foreign = Path(tmp) / ".psgen-1-2-3"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("not ours\n")
    run(["inject", "-n", "1", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(Path(tmp) / "f.pid")],
        env=dict(os.environ, TMPDIR=str(tmp)), check=False)
    if not (foreign / "keep.txt").exists():
        fail("#5: an unmarked foreign .psgen-* directory was removed")
    stop_pidfile(Path(tmp) / "f.pid")
    shutil.rmtree(foreign, ignore_errors=True)


def check_plausibility():
    """Every generated row must be physically possible.

    This is the class of defect #2 belonged to: the old regression asserted
    *determinism* (same seed, same output) and never *plausibility* (a row
    cannot start before the host booted). A property test over seeds, counts
    and host shapes catches the whole class, not one example of it.
    """
    now = time.localtime()
    now_min = now.tm_hour * 60 + now.tm_min
    # A property test over an empty population is a pass with nothing behind
    # it: `table` exiting non-zero, printing no rows, or printing rows that do
    # not parse leaves the loop body unexecuted. Count what was actually
    # checked and require the sweep to have covered its population.
    seen = 0
    shapes = 0
    for seed in (1, 2, 7, 42, 99, 165, 1000):
        for n in (30, 200, 1000):
            # 0 is a usage error (a host that never booted does not exist), so
            # the shortest real host is the smallest shape to sweep.
            for uptime in (None, 1, 60, 3600):
                extra = [] if uptime is None else ["--host-uptime", str(uptime)]
                argv = ["table", "-n", str(n), "-s", str(seed), "--local"] + extra
                p = run(argv, check=False)
                shapes += 1
                if p.returncode != 0:
                    fail(f"#2: {' '.join(argv)} exited {p.returncode}: "
                         f"{p.stderr.strip()[:160]!r}")
                lines = p.stdout.splitlines()
                if len(lines) != n + 1:
                    fail(f"#2: {' '.join(argv)} printed {len(lines)} lines, "
                         f"wanted {n + 1} (a header and one row per process)")
                rows = 0
                for line in lines[1:]:
                    m = PS_RE.match(line)
                    if not m:
                        fail(f"#2: {' '.join(argv)} printed an unparsable row: "
                             f"{line[:100]!r}")
                    rows += 1
                    seen += 1
                    pid = int(m.group("pid"))
                    cpu = float(m.group("cpu"))
                    mem = float(m.group("mem"))
                    vsz = int(m.group("vsz"))
                    rss = int(m.group("rss"))
                    start = m.group("start")
                    tm = m.group("time")
                    if pid < 1:
                        fail(f"#2: PID {pid} is not a process")
                    if cpu > 100.0:
                        fail(f"#2: %CPU {cpu} above one core")
                    if mem > 100.0:
                        fail(f"#2: %MEM {mem} above the whole machine")
                    if rss > vsz:
                        fail(f"#2: RSS {rss} kB above VSZ {vsz} kB")
                    if re.fullmatch(r"\d\d:\d\d", start):
                        v = int(start[:2]) * 60 + int(start[3:])
                        # Signed, so a START a minute in the future (the run
                        # crossed a minute boundary after `now` was read) is
                        # not mistaken for 23 hours old.
                        age_min = now_min - v
                        if age_min < -2:
                            age_min += 1440
                        if uptime is not None and age_min * 60 > uptime + 120:
                            fail(f"#2: START {start} is {age_min} min old on a "
                                 f"host up {uptime}s")
                    parts = [int(x) for x in tm.split(":")]
                    secs = parts[0] * 60 + parts[1] if len(parts) == 2 else \
                        parts[0] * 3600 + parts[1] * 60 + parts[2]
                    if secs > 30 * 86400:
                        fail(f"#2: TIME {tm} exceeds 30 days")
                    if m.group("tty") != "?" and not re.fullmatch(
                            r"pts/\d+|tty\d+|ttyS\d+", m.group("tty")):
                        fail(f"#2: TTY {m.group('tty')!r} is not a device")
                if rows != n:
                    fail(f"#2: {' '.join(argv)} yielded {rows} rows, wanted {n}")
    if seen < 1000:
        fail(f"#2: the plausibility sweep examined {seen} rows over {shapes} "
             f"shapes, so it proves nothing about the population")


# `ps aux` TIME is procps `pr_bsdtime`: a total minute count, `75:00`. It is
# never `HH:MM:SS` and never carries a day prefix.
BSDTIME = re.compile(r"^\d{1,4}:\d\d$")


def bsdtime_secs(token: str) -> int | None:
    """Seconds in a `pr_bsdtime` token, or None when it is not one."""
    m = re.match(r"^(\d+):(\d\d)$", token)
    if not m or int(m.group(2)) > 59:
        return None
    return int(m.group(1)) * 60 + int(m.group(2))


def stat_flags(token: str) -> tuple[str, str]:
    """Split a `pr_stat` token into its state letter and its flag letters."""
    return token[0], "".join(sorted(token[1:]))


# Zones with a non-zero offset on any date, used to give `ps` and psgen the
# same non-UTC rendering zone. A UTC host cannot see a zone bug at all: the two
# sides agree by construction, which is how a UTC-only renderer survived.
LIVE_ZONES = ("Asia/Katmandu", "Asia/Kolkata", "Europe/Berlin", "America/Denver")


def non_utc_zone() -> str | None:
    """A zone this host has zoneinfo for whose current offset is not zero."""
    for zone in LIVE_ZONES:
        path = Path("/usr/share/zoneinfo") / zone
        if not path.exists():
            continue
        p = subprocess.run([sys.executable, "-c",
                            "import time;print(time.localtime().tm_gmtoff)"],
                           capture_output=True, text=True, timeout=30,
                           env=dict(os.environ, TZ=zone))
        try:
            if int(p.stdout.strip()) != 0:
                return zone
        except ValueError:
            continue
    return None


def check_live_matches_ps():
    """Every stable field of `table --live` must equal `ps aux`.

    The reference is `ps`, field by field, for every row both can see. The
    check is a gate, not a smoke test: it compares `%CPU`, `STAT` and the
    literal `TIME` token, so a 4x CPU error, a missing stat flag or an
    `HH:MM:SS` TIME fails here instead of passing because both spellings
    normalise to the same number of seconds.
    """
    # Both sides are rendered in a zone with a non-zero offset, because a UTC
    # host cannot distinguish a UTC renderer from a local-time one.
    zone = non_utc_zone()
    if zone is None:
        skip("live parity needs a non-UTC zone and this host has no zoneinfo")
        return
    env = dict(os.environ, TZ=zone)
    check_tz = subprocess.run([sys.executable, "-c",
                               "import time;print(time.localtime().tm_gmtoff)"],
                              capture_output=True, text=True, timeout=30, env=env)
    if check_tz.returncode != 0 or int(check_tz.stdout.strip()) == 0:
        fail(f"#3: TZ={zone} did not give a non-zero offset, so the live "
             f"comparison cannot see a zone bug")

    def parse(text):
        out = {}
        for line in text.splitlines()[1:]:
            m = PS_RE.match(line)
            if m:
                out[int(m.group("pid"))] = m.groupdict()
        return out

    mine = parse(run(["table", "--live"], env=env).stdout)
    ref = parse(subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True,
                               timeout=60, env=env).stdout)
    common = sorted(set(mine) & set(ref))
    if len(common) < 5:
        skip(f"only {len(common)} rows common to ps and table --live")
        return

    # A second `ps` read separates the fields that cannot change from the ones
    # that do. %CPU, %MEM and TIME accumulate between the reads, and STAT
    # changes state, so those are compared with the tolerance the second read
    # measures rather than a constant that hides a 4x error.
    ref2 = parse(subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True,
                                timeout=60, env=env).stdout)

    for pid in common:
        a, b = mine[pid], ref[pid]
        if b["time"] and "." in b["time"]:
            fail(f"#3: ps TIME {b['time']!r} is not a pr_bsdtime token")
        # These cannot change between two reads of the same process.
        for field in ("user", "tty", "start", "cmd"):
            if a[field] != b[field]:
                fail(f"#3: live {field} for pid {pid} is {a[field]!r}, "
                     f"ps says {b[field]!r}")

        # TIME: compare the token, not a normalised number of seconds. An
        # `HH:MM:SS` spelling has to fail even when the seconds agree.
        got, want = a["time"], b["time"]
        if not BSDTIME.match(got):
            fail(f"#3: live TIME {got!r} for pid {pid} is not pr_bsdtime")
        gs, ws = bsdtime_secs(got), bsdtime_secs(want)
        if ws is None:
            fail(f"#3: ps TIME {want!r} for pid {pid} is not pr_bsdtime")
        # A process that uses CPU between the two reads moves its TIME by a
        # second; anything beyond that is a different value, not a race.
        if abs(gs - ws) > 2:
            fail(f"#3: live TIME for pid {pid} is {got}, ps says {want}")

        # STAT: the state letter is volatile (a sleeping process wakes), so
        # only the flag letters are compared, and only when `ps` reported the
        # same state twice.
        if pid in ref2 and ref2[pid]["stat"][0] == b["stat"][0]:
            _, a_flags = stat_flags(a["stat"])
            _, b_flags = stat_flags(b["stat"])
            if a_flags != b_flags:
                fail(f"#3: live STAT for pid {pid} is {a['stat']}, "
                     f"ps says {b['stat']} (flags {a_flags!r} != {b_flags!r})")

        # %CPU: ps prints one decimal below 100 and an integer at or above it.
        # The second read bounds how far the value legitimately moved.
        wait = 0
        if pid in ref2:
            wait = abs(float(ref2[pid]["cpu"]) - float(b["cpu"]))
        # Two reads a few milliseconds apart cannot move %CPU by a tenth of
        # its own value unless the value is tiny; allow the movement the
        # second read measured plus a small floor, never 4x.
        slack = max(1.5, 3.0 * wait, 0.05 * float(b["cpu"]))
        if abs(float(a["cpu"]) - float(b["cpu"])) > slack:
            fail(f"#3: live %CPU for pid {pid} is {a['cpu']}, ps says {b['cpu']}")
        if float(b["cpu"]) >= 100.0 and "." in b["cpu"]:
            fail(f"#3: ps %CPU {b['cpu']!r} above 99.9 has a decimal")
        if float(b["cpu"]) >= 100.0 and "." in a["cpu"]:
            fail(f"#3: live %CPU {a['cpu']!r} above 99.9 has a decimal; "
                 f"procps prints an integer there")

        # VSZ, RSS and %MEM can grow or shrink between the two reads, so they
        # are compared with a tolerance; a systematic difference is far larger.
        if abs(int(a["vsz"]) - int(b["vsz"])) > 65536:
            fail(f"#3: live VSZ for pid {pid} is {a['vsz']}, ps says {b['vsz']}")
        if abs(int(a["rss"]) - int(b["rss"])) > 65536:
            fail(f"#3: live RSS for pid {pid} is {a['rss']}, ps says {b['rss']}")
        if abs(float(a["mem"]) - float(b["mem"])) > 0.5:
            fail(f"#3: live %MEM for pid {pid} is {a['mem']}, ps says {b['mem']}")


def check_inject_table_matches_ps(tmp):
    """`inject --table` is a live table and must agree with `ps aux` too.

    This is the second call site of the same renderer, and it selects its own
    %MEM denominator. Comparing only `table --live` left the inject path free
    to drift, so the rows it prints are matched against the `ps` beside them.
    """
    if emulated():
        skip("inject --table rows describe qemu-user here")
        return
    pf = Path(tmp) / "live.pid"
    p = run(["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
             "--no-tty", "--no-threads", "--table", "--pidfile", str(pf)])
    pids = read_pids(pf)
    try:
        lines = p.stdout.splitlines()
        if not lines or lines[0] != HEADER:
            fail("#3: inject --table did not print the ps aux header")
        mine = {}
        for line in lines[1:]:
            m = PS_RE.match(line)
            if m:
                mine[int(m.group("pid"))] = m.groupdict()
        ref = ps_rows()
        common = sorted(set(mine) & set(pids))
        if len(common) < 2:
            fail(f"#3: only {len(common)} injected rows are in both tables")
        denom = mem_total()
        for pid in common:
            a, b = mine[pid], ref[pid]
            for field in ("user", "start", "cmd"):
                if a[field] != b[field]:
                    fail(f"#3: inject --table {field} for pid {pid} is "
                         f"{a[field]!r}, ps says {b[field]!r}")
            # A stub's state letter flickers; its flag letters do not.
            if stat_flags(a["stat"])[1] != stat_flags(b["stat"])[1]:
                fail(f"#3: inject --table STAT for pid {pid} is {a['stat']}, "
                     f"ps says {b['stat']}")
            gs, ws = bsdtime_secs(a["time"]), bsdtime_secs(b["time"])
            if gs is None:
                fail(f"#3: inject --table TIME {a['time']!r} is not pr_bsdtime")
            if ws is not None and abs(gs - ws) > 2:
                fail(f"#3: inject --table TIME for pid {pid} is {a['time']}, "
                     f"ps says {b['time']}")
            # %MEM must use MemTotal, the same denominator `ps` uses. In a
            # cgroup the budget is smaller, which is a 100x difference.
            want_mem = int(b["rss"]) * 1000 // denom / 10.0
            if abs(float(a["mem"]) - want_mem) > 0.6:
                fail(f"#3: inject --table %MEM for pid {pid} is {a['mem']}, "
                     f"MemTotal gives {want_mem:.1f}")
    finally:
        stop_pidfile(pf)


def matrix_run(argv, timeout=120):
    """Run one matrix cell, then reap everything it spawned.

    Output goes to files rather than pipes, so a subcommand that leaks a child
    holding the write end cannot stall the read: the child is waited for with
    a timeout and its process group is killed in `finally`.

    Killing the group is not enough on its own. An `inject` stub calls
    `setsid`, so it is in no group the injector's caller can name, and the
    injector exits before a `--duration` run ends. The harness makes itself a
    child subreaper before the first cell, so those stubs are reparented here
    and `reap_descendants` can find them; a cell that leaks is a harness
    failure, not a quiet extra process.
    """
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.Popen([str(BIN)] + argv, stdout=out, stderr=err,
                             stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            p.wait(timeout=30)
            raise
        finally:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            reap_descendants(os.getpid())
        out.seek(0)
        err.seek(0)
        return subprocess.CompletedProcess(
            p.args, p.returncode,
            out.read().decode(errors="replace"),
            err.read().decode(errors="replace"))


AUX_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<pid>\d+)\s+(?P<cpu>\d+(?:\.\d+)?)\s+"
    r"(?P<mem>\d+\.\d)\s+(?P<vsz>\d+)\s+(?P<rss>\d+)\s+"
    r"(?P<tty>\S+)\s+(?P<stat>\S+)\s+(?P<start>\d\d:\d\d|[A-Z][a-z]{2}\d\d|\d{4})\s+"
    r"(?P<time>\d{1,3}:\d\d)\s+(?P<cmd>.*)$"
)


def aux_rows(text):
    """`ps aux` rows, keyed by pid, with the columns psgen also renders.

    `PS_RE` requires a decimal %CPU, which `ps` stops printing at 100.0, so a
    busy process would be dropped from the comparison instead of failing it.
    """
    out = {}
    for line in text.splitlines():
        m = AUX_RE.match(line)
        if m:
            out[int(m.group("pid"))] = m.groupdict()
    return out


def check_live_reference_columns():
    """`table --live` renders every `ps aux` column `ps` owns, on every row.

    The reference is `ps aux` itself, never psgen's own arithmetic: each
    column's *value* is compared, not just its offset, and a %CPU written
    `101` must stay an integer the way `pr_pcpu` prints it. Rows whose value
    genuinely moves between the two reads still have to agree on the format.
    The fixtures are spawned here so the columns that need a reniced or a busy
    process are exercised rather than assumed absent.

    Both sides are rendered in a zone with a non-zero offset, which this
    check *selects* rather than trusting the caller's environment for: a UTC
    host cannot tell a localtime renderer from a UTC one, so the check would
    be comparing two identical truncations.
    """
    zone = non_utc_zone()
    if zone is None:
        skip("live parity needs a non-UTC zone and this host has no zoneinfo")
        return
    env = dict(os.environ, TZ=zone)
    check_tz = subprocess.run([sys.executable, "-c",
                               "import time;print(time.localtime().tm_gmtoff)"],
                              capture_output=True, text=True, timeout=30, env=env)
    if check_tz.returncode != 0 or int(check_tz.stdout.strip()) == 0:
        fail(f"#3: TZ={zone} did not give a non-zero offset, so the live "
             f"comparison cannot see a zone bug")
    spawned = []
    try:
        for argv in (["nice", "-n", "5", "sleep", "60"],
                     ["sudo", "-n", "nice", "-n", "-5", "sleep", "60"]):
            try:
                spawned.append(subprocess.Popen(
                    argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            except OSError:
                pass
        # A process with several busy threads makes %CPU well above 100 on an
        # idle host, where `pr_pcpu` drops the decimal. That row is not
        # required: on a loaded host the scheduler throttles it below the
        # threshold, and the format check below still fires whenever such a row
        # does exist.
        spinner = ("import threading\n"
                   "def spin():\n"
                   "    while True: pass\n"
                   "for _ in range(8):\n"
                   "    threading.Thread(target=spin, daemon=True).start()\n"
                   "spin()\n")
        try:
            spawned.append(subprocess.Popen(
                [sys.executable, "-c", spinner],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        except OSError:
            pass
        time.sleep(5.0)
        mine = aux_rows(run(["table", "--live"], env=env).stdout)
        ref = aux_rows(subprocess.run(["ps", "aux"], stdout=subprocess.PIPE,
                                      text=True, timeout=60, env=env).stdout)
        # A second reference read, so a %CPU that is still moving can be told
        # from one that is a steady property of the process.
        ref2 = aux_rows(subprocess.run(["ps", "aux"], stdout=subprocess.PIPE,
                                       text=True, timeout=60, env=env).stdout)
    finally:
        for p in spawned:
            p.kill()
        for p in spawned:
            p.wait()

    common = sorted(set(mine) & set(ref))
    if len(common) < 5:
        skip_or_fail(f"only {len(common)} rows are common to ps and table --live")
        return

    def cpu_secs(t):
        m = re.fullmatch(r"(\d+):(\d\d)", t)
        if not m:
            return None
        return int(m.group(1)) * 60 + int(m.group(2))

    seen = {"nice_low": False, "nice_high": False, "cpu_value": False,
            "mem_value": False, "vsz_value": False, "rss_value": False}
    # %MEM's denominator is the machine's MemTotal, the same one `ps` uses.
    # Read once: it cannot change during the pass, and a per-row read would be
    # a per-row syscall on a table that is already compared field by field.
    denom = mem_total()
    if denom <= 0:
        fail("#3: /proc/meminfo has no MemTotal, so %MEM has no denominator")
    for pid in common:
        a, b = mine[pid], ref[pid]
        for field in ("user", "tty"):
            if a[field] != b[field]:
                fail(f"#3: live {field} for pid {pid} is {a[field]!r}, "
                     f"ps says {b[field]!r}")
        if a["start"] != b["start"]:
            fail(f"#3: live START for pid {pid} is {a['start']!r}, "
                 f"ps says {b['start']!r}")
        # The state character can flip between two reads of a running process,
        # and a process that exits becomes a zombie; every other flag is a
        # property of the process, not of the instant.
        transient = set("RSDZ")
        if a["stat"][:1] != b["stat"][:1] and not (
                a["stat"][:1] in transient and b["stat"][:1] in transient):
            fail(f"#3: live STAT for pid {pid} is {a['stat']!r}, "
                 f"ps says {b['stat']!r}")
        if a["stat"][1:] != b["stat"][1:]:
            fail(f"#3: live STAT flags for pid {pid} are {a['stat']!r}, "
                 f"ps says {b['stat']!r}")
        if "<" in b["stat"]:
            seen["nice_low"] = True
        if "N" in b["stat"]:
            seen["nice_high"] = True
        # TIME is `pr_bsdtime`: minutes and seconds, never an hours field.
        sa, sb = cpu_secs(a["time"]), cpu_secs(b["time"])
        if sa is None:
            fail(f"#3: live TIME for pid {pid} is {a['time']!r}, which is not "
                 f"the bsdtime ps prints ({b['time']!r})")
        if abs(sa - sb) > 2:
            fail(f"#3: live TIME for pid {pid} is {a['time']!r}, "
                 f"ps says {b['time']!r}")
        # %CPU: an integer at or above 100.0, one decimal below it. The two
        # reads can straddle the threshold for a process whose average is
        # moving, so compare the shape only where both agree on the side.
        pa, pb = float(a["cpu"]), float(b["cpu"])
        if pa >= 101.0 and pb >= 101.0:
            if "." in a["cpu"]:
                fail(f"#3: live %CPU for pid {pid} is {a['cpu']!r}, ps prints "
                     f"an integer above 99.9 ({b['cpu']!r})")
        elif pa < 99.0 and pb < 99.0:
            if "." not in a["cpu"]:
                fail(f"#3: live %CPU for pid {pid} is {a['cpu']!r}, ps prints a "
                     f"decimal below 100 ({b['cpu']!r})")
        # %CPU is a lifetime average, so it moves between reads for a process
        # that is still young. Only rows whose `ps` value is the same in two
        # consecutive reference reads are compared by value; the format is
        # still checked on every row. The tolerance is a *fraction* of the
        # value rather than a constant above it, because a constant is what
        # lets a systematic multiplier through on the idle rows where the
        # multiplier is a small absolute number.
        pa, pb = float(a["cpu"]), float(b["cpu"])
        stable = pid in ref2 and ref2[pid]["cpu"] == b["cpu"]
        if stable:
            if abs(pa - pb) > max(0.2, 0.25 * pb):
                fail(f"#3: live %CPU for pid {pid} is {a['cpu']!r}, "
                     f"ps says {b['cpu']!r}")
            seen["cpu_value"] = True
        # %MEM is derived, so it is compared against the derivation `ps` uses,
        # `rss * 1000 / MemTotal` in integer tenths, with the same rows `ps`
        # supplies. A wrong denominator (the cgroup budget instead of
        # MemTotal) is a 10x to 100x error on every row and cannot pass; a
        # moved RSS is bounded by the same second read the other sizes use.
        want_mem = int(b["rss"]) * 1000 // denom / 10.0
        if abs(float(a["mem"]) - want_mem) > 0.6:
            fail(f"#3: live %MEM for pid {pid} is {a['mem']}, "
                 f"ps rss {b['rss']} kB over MemTotal gives {want_mem:.1f}")
        seen["mem_value"] = True
        # VSZ and RSS are the kernel's own numbers on both sides, rounded up to
        # a page by the renderer, so they agree to within a page and whatever
        # the second reference read says the process moved. A percentage of
        # the value is not a tolerance here: a 10x error on a small process is
        # a few hundred kB and would pass one.
        for field in ("vsz", "rss"):
            drift = 0
            if pid in ref2:
                drift = abs(int(ref2[pid][field]) - int(b[field]))
            tol = max(1024, 5 * drift)
            if abs(int(a[field]) - int(b[field])) > tol:
                fail(f"#3: live {field.upper()} for pid {pid} is {a[field]}, "
                     f"ps says {b[field]} (+/-{tol})")
            seen[field + "_value"] = True
    for kind, present in seen.items():
        if not present:
            skip_or_fail(f"no row exercised the {kind} case")


def check_option_matrix():
    """No option may be accepted and then ignored, and no cell may crash.

    This is the class of defect #9 belonged to: the `applies` table was
    hand-enumerated, so four silent no-ops survived. The property per cell is:
    a clean run must change the observable output when the value changes, and
    a non-zero exit must be a rejection that names the flag. A crash, a signal
    or a timeout is a failure, never "not applicable".

    Each cell is compared with the same subcommand's own baseline, so an option
    that is already in the base argv cannot mask the difference. A baseline
    must be able to *show* the option it is the reference for: `--dry-run`
    alone prints two columns, so it cannot report a CPU percentage and a cell
    compared against it would look inert no matter what `--cpu` did.
    `inject --dry-run --plan` prints tier, user, VSZ, RSS, CPU, tty, threads,
    exe and parent, and the plain `--dry-run` shape is held to its own
    two-column contract by `check_dry_run_shape`.
    """
    subs = ["list", "table", "inject", "stop", "corpus", "check", "unit",
            "doctor", "log", "load"]
    opts = {
        "-n": (["-n", "3"], ["-n", "7"]),
        "-s": (["-s", "1"], ["-s", "2"]),
        "-p": (["-p", "dev"], ["-p", "desktop"]),
        "-f": (["-f", "dev"], ["-f", "web"]),
        "--utc-offset": (["--utc-offset", "60"], ["--utc-offset", "120"]),
        "--repeat-max": (["--repeat-max", "1"], ["--repeat-max", "5"]),
        "--host-mem": (["--host-mem", "64"], ["--host-mem", "128"]),
        "--host-pid-max": (["--host-pid-max", "100"], ["--host-pid-max", "200"]),
        # Not 0: a zero uptime names a host that does not exist and is a usage
        # error once validation lands (`check_generator_sweep`), so a pair that
        # included it would read as "half-honoured" the moment that fix ships.
        "--host-uptime": (["--host-uptime", "600"], ["--host-uptime", "3600"]),
        "--lines": (["--lines", "2"], ["--lines", "5"]),
        "-m": (["-m", "weblog"], ["-m", "cargo"]),
        "--log-fmt": (["--log-fmt", "json"], ["--log-fmt", "syslog"]),
        "--cpu-util": (["--cpu-util", "1"], ["--cpu-util", "2"]),
        "--mem-util": (["--mem-util", "1"], ["--mem-util", "2"]),
        "--disk-util": (["--disk-util", "1"], ["--disk-util", "2"]),
        "-d": (["-d", "1"], ["-d", "2"]),
        "--cpu": (["--cpu", "10"], ["--cpu", "20"]),
        "--shadow-dir": (["--shadow-dir", "/tmp/om1"], ["--shadow-dir", "/tmp/om2"]),
    }
    # The baseline argv is the subcommand's own default, plus only the flags
    # that keep the cell deterministic and quick: a fixed seed where the
    # subcommand has one (an unpinned seed makes every pair of runs differ, so
    # comparing them proves nothing), a preview for `inject`, `load` running
    # one percent of one resource, `log` with no delay. A default `list` is
    # *not* given `-n`, so the count==0 path (where `-p` used to be a no-op) is
    # exercised.
    #
    # `inject` previews with `--plan`, not with the bare `--dry-run`: the bare
    # preview prints `user<TAB>cmd`, which has no CPU, tty, thread, RSS or tier
    # column, so `--cpu`, `--shadow-dir` and `--repeat-max` were unobservable
    # there and read as "accepted but has no effect". `--no-root` drops the
    # bind tier, so `--shadow-dir` selects the shadow tier and shows in the
    # plan even on a host where bind mounting works, which keeps that cell
    # about the flag instead of about the host.
    base = {
        "list": ["-s", "1"],
        "table": ["-s", "1"],
        "inject": ["--dry-run", "--plan", "--no-root", "-s", "1"],
        "stop": [],
        "corpus": [],
        "check": [],
        "unit": ["-s", "1"],
        "doctor": [],
        "log": ["--delay", "0"],
        # `load` refuses to start without a utilisation flag, so the baseline
        # is the smallest run the option may vary: one percent of one
        # resource. A cell that replaces it (or adds a second one) must move
        # the observable output.
        "load": ["--cpu-util", "1", "-d", "1"],
    }
    # A cell whose effect no preview can print, with the seam that can. The
    # key is (subcommand, option); the value maps the option's value to what
    # the seam observes, and the cell passes when the two values observe
    # different things. `--duration` is a lifetime, not a planned value, so
    # `--dry-run --plan` correctly prints nothing about it; a real run blocks
    # for exactly that long, which is the property the flag names.
    def inject_lifetime(argv):
        """Seconds an `inject --wait -d N` run really blocked for."""
        started = time.monotonic()
        r = matrix_run(["inject", "--wait", "-n", "2", "-s", "1", "--no-user",
                        "--no-mem", "--no-tty", "--no-threads", "-q"] + argv,
                       timeout=60)
        elapsed = time.monotonic() - started
        if r.returncode != 0:
            fail(f"#9: inject --wait {argv} exited {r.returncode}: "
                 f"{r.stderr.strip()[:120]!r}")
        want = float(argv[argv.index("-d") + 1])
        if elapsed < want - 0.1:
            fail(f"#9: inject --wait -d {want:g} returned after {elapsed:.2f}s")
        return elapsed

    observed = {("inject", "-d"): inject_lifetime}
    # `stop` without a pidfile is a usage error for every cell, which says
    # nothing about the option; give it a file so the rejection is about the
    # flag under test. The file must be one `stop` accepts, which now means a
    # psgen header carrying this boot's id: an empty file is refused, and a
    # baseline that is itself a usage error would let every cell skip as
    # "rejected" without ever running.
    with tempfile.TemporaryDirectory(prefix="psgen-matrix-") as tmp:
        empty = Path(tmp) / "empty.pid"
        empty.write_text(f"# psgen {VERSION} boot {boot_id()}\n")
        base["stop"] = ["--pidfile", str(empty)]
        compared = 0
        for sub in subs:
            try:
                baseline = matrix_run([sub] + base[sub])
            except subprocess.TimeoutExpired:
                fail(f"#9: baseline `{sub}` timed out")
            if baseline.returncode != 0:
                fail(f"#9: baseline `{sub}` exited {baseline.returncode}: "
                     f"{baseline.stderr.strip()[:120]!r}")
            for opt, (a, b) in sorted(opts.items()):
                seam = observed.get((sub, opt))
                if seam is not None:
                    # Two values of a knob no preview can carry: the seam
                    # observes it instead. The seam fails on a non-zero exit and
                    # on a run that returns before the duration it was given, so
                    # this cannot pass without the option doing its job.
                    va, vb = seam(a), seam(b)
                    if abs(va - vb) < 0.5:
                        fail(f"#9: {sub} {opt} is accepted but {a} and {b} "
                             f"both took {va:.2f}s")
                    compared += 1
                    continue
                try:
                    ra = matrix_run([sub] + base[sub] + a)
                    rb = matrix_run([sub] + base[sub] + b)
                except subprocess.TimeoutExpired:
                    fail(f"#9: {sub} {opt} timed out")
                # Only exit 2 means "this option does not apply here". Anything
                # else non-zero is a crash or a rejection of the baseline, and
                # must be named.
                rejected = []
                for tag, r in (("a", ra), ("b", rb)):
                    if r.returncode == 0:
                        continue
                    if r.returncode < 0:
                        fail(f"#9: {sub} {opt} ({tag}) died by signal "
                             f"{-r.returncode}")
                    if r.returncode != 2:
                        fail(f"#9: {sub} {opt} ({tag}) exited {r.returncode}: "
                             f"{r.stderr.strip()[:120]!r}")
                    # A rejection must name the flag it is about. The long
                    # spelling is the reliable one: `--count` cannot appear in
                    # an unrelated word the way a bare `-n` can.
                    names = {
                        "-n": "--count", "-s": "--seed", "-p": "--profile",
                        "-f": "--family", "-d": "--duration", "-m": "--module",
                    }
                    wanted = names.get(opt, opt)
                    if wanted not in r.stderr:
                        fail(f"#9: {sub} {opt} ({tag}) exited 2 without naming "
                             f"{wanted}: {r.stderr.strip()[:120]!r}")
                    rejected.append(tag)
                if len(rejected) == 2:
                    continue
                if rejected:
                    # One value rejected and the other accepted: the option is
                    # half-honoured, which is the defect class itself.
                    ok = ra if rejected[0] == "b" else rb
                    bad = "a" if rejected[0] == "b" else "b"
                    fail(f"#9: {sub} {opt} accepts one value and rejects the "
                         f"other ({bad} rejected, {ok.returncode} accepted)")
                if ra.stdout == rb.stdout and ra.stderr == rb.stderr:
                    fail(f"#9: {sub} {opt} is accepted but has no effect")
                # An option that changes a value must move the output away from
                # the baseline, not merely from its sibling.
                if ra.stdout == baseline.stdout and rb.stdout == baseline.stdout \
                        and ra.stderr == baseline.stderr:
                    fail(f"#9: {sub} {opt} changes nothing against the baseline")
                compared += 1
        if compared < 30:
            fail(f"#9: only {compared} option/subcommand pairs were compared; "
                 f"the matrix has collapsed into usage errors")


def check_unit_and_report_truth(tmp: Path) -> None:
    """The unit, `doctor`, the JSON encoders and stdout all have to be true.

    Four independent claims, each measured against the thing it describes
    rather than against psgen's own arithmetic:

    * the unit's `RuntimeDirectory=` is the pidfile's own directory, a pidfile
      outside `/run` is refused instead of printed, and `$` survives the
      `Exec*` line (systemd expands it as a variable otherwise);
    * a pidfile `inject` refuses for recording live rows is `DENY` in
      `doctor --pidfile`, not `ALLOW`;
    * `doctor --json` keeps every byte of a non-ASCII path, so two different
      paths cannot collapse to one JSON value;
    * a write error on stdout is an error: exit status is not 0.
    """
    # A pidfile directory of its own, so "the RuntimeDirectory contains the
    # pidfile's parent" is a real claim and not `/run` coinciding with itself.
    unit = run(["unit", "--pidfile", "/run/psgen-u1/u.pid"]).stdout
    runtime = [l.split("=", 1)[1] for l in unit.splitlines()
               if l.startswith("RuntimeDirectory=")]
    if runtime != ["psgen-u1"]:
        fail(f"unit RuntimeDirectory {runtime!r} does not name the pidfile's "
             f"own directory /run/psgen-u1")
    if "/run/psgen-u1/u.pid" not in unit:
        fail("unit does not name the pidfile it was given")

    # Two units must not share one managed directory: stopping either would
    # remove the other's pidfile.
    other = run(["unit", "--pidfile", "/run/psgen-u2/u.pid"]).stdout
    other_runtime = [l.split("=", 1)[1] for l in other.splitlines()
                     if l.startswith("RuntimeDirectory=")]
    if other_runtime == runtime:
        fail(f"two units share RuntimeDirectory {runtime[0]!r}")

    # A path the manager cannot create a directory for is a unit that fails at
    # every boot, so it must be refused before it is printed.
    for path in ("/var/lib/psgen/psgen.pid", "/tmp/psgen-unit.pid"):
        p = run(["unit", "--pidfile", path], check=False)
        if p.returncode != 2 or "psgen:" not in p.stderr:
            fail(f"unit accepted {path} (rc {p.returncode})")

    # `$` is a variable reference in an Exec line; `unit` must double it, and
    # the pre-fix output named a path nobody asked for.
    dollars = run(["unit", "--pidfile", "/run/psgen-u1/a$b.pid"]).stdout
    start = next(l for l in dollars.splitlines() if l.startswith("ExecStart="))
    if "a$$b.pid" not in start:
        fail(f"unit did not escape $ in the pidfile: {start!r}")
    # Only the pidfile removal may carry `-`; the stop itself must report a
    # foreign boot id or a refused signal instead of turning it into success.
    stop_lines = [l for l in dollars.splitlines() if l.startswith("ExecStop=")]
    if not stop_lines or stop_lines[0].startswith("ExecStop=-"):
        fail(f"the stop directive suppresses every failure: {stop_lines[:1]}")

    # A pidfile that records live rows is what `inject` refuses; doctor has to
    # say the same thing rather than ALLOW.
    live = Path(tmp) / "live-doctor.pid"
    run(["inject", "-n", "2", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(live)])
    try:
        text = run(["doctor", "--pidfile", str(live)]).stdout
        line = next(l for l in text.splitlines() if l.startswith("pidfile\t"))
        if not line.startswith("pidfile\tDENY"):
            fail(f"doctor says ALLOW for a pidfile inject refuses: {line!r}")
        doc = json.loads(run(["doctor", "--json", "--pidfile", str(live)]).stdout)
        if doc["pidfile"].get("allowed") is not False:
            fail(f"doctor --json allowed a pidfile inject refuses: {doc['pidfile']}")
        refused = run(["inject", "-n", "1", "--no-user", "--no-mem", "--no-tty",
                       "--no-threads", "--pidfile", str(live)], check=False)
        if refused.returncode == 0:
            fail("inject accepted the live pidfile doctor denied, so the "
                 "comparison above is about nothing")
    finally:
        stop_pidfile(live)

    # Two non-ASCII paths are two JSON values. A `?` clamp made them one.
    east = Path(tmp) / "café.pid"
    grave = Path(tmp) / "cafè.pid"
    paths = {}
    for path in (east, grave):
        doc = json.loads(run(["doctor", "--json", "--pidfile", str(path)]).stdout)
        paths[str(path)] = doc["pidfile"]["path"]
    if paths[str(east)] != str(east):
        fail(f"doctor --json mangled a non-ASCII path: {paths!r}")
    if len(set(paths.values())) != 2:
        fail(f"two distinct paths became one JSON value: {paths!r}")

    # A write error other than EPIPE is not success. /dev/full exists on
    # Linux and returns ENOSPC from write(2).
    if Path("/dev/full").exists():
        for args in (["table", "-n", "3", "-s", "1"], ["list", "-n", "3", "-s", "1"],
                     ["doctor"], ["version"], ["corpus"]):
            with open("/dev/full", "wb") as full:
                p = subprocess.run([str(BIN)] + args, stdout=full,
                                   stderr=subprocess.PIPE, timeout=120)
            if p.returncode == 0:
                fail(f"{' '.join(args)} reported success on a failed write")
    else:
        skip("no /dev/full to provoke a write error")

    # ...but a closed reader is not an error: `| head` is a normal pipeline.
    p = subprocess.run(f"{BIN} table -n 4000 | head -1 >/dev/null", shell=True,
                       stderr=subprocess.PIPE, timeout=120)
    if p.returncode != 0:
        fail(f"a closed reader made psgen exit {p.returncode}: {p.stderr!r}")

    # `bpf` is a capability the caller either has or does not. The probe must
    # agree with `/proc/sys/kernel/unprivileged_bpf_disabled` and CAP_BPF.
    if not is_root():
        unpriv = 0
        try:
            unpriv = int(Path("/proc/sys/kernel/unprivileged_bpf_disabled").read_text().strip())
        except (OSError, ValueError):
            skip("cannot read /proc/sys/kernel/unprivileged_bpf_disabled")
        cap = 0
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                cap = int(line.split()[1], 16)
        want = "allowed" if (cap & (1 << 39)) or unpriv == 0 else "blocked"
        doc = json.loads(run(["doctor", "--json"]).stdout)
        got = doc["probe"].get("bpf")
        if got != want:
            fail(f"doctor says bpf {got!r}, unprivileged_bpf_disabled={unpriv} "
                 f"and CapEff={cap:x} say {want!r}")


def check_pty_probe():
    """`doctor`'s pty probe must agree with the syscall the stub needs.

    A probe that only opens `/dev/ptmx` reports ALLOW on a host where a
    bind-mounted regular file or a hardened container refuses to allocate a
    pty, and then the injection check fails instead of skipping. The predicate
    `can_pty` uses is the syscall pair; this holds the tool to the same truth.
    """
    j = run(["doctor", "--json"]).stdout
    try:
        doc = json.loads(j)
    except json.JSONDecodeError as e:
        fail(f"doctor --json is not valid JSON: {e}")
    entry = None
    for c in doc.get("checks", []):
        if c.get("name") == "pty":
            entry = c
            break
    if entry is None:
        fail("doctor --json has no pty check")
    if entry.get("ok") != pty_master_works():
        fail(f"doctor says pty ok={entry.get('ok')}, the syscall pair says "
             f"{pty_master_works()}")


def check_skip_helper():
    """`skip()` must fail under PSGEN_REQUIRE_ALL and print a reason otherwise.

    The gate is only as good as its weakest skip: if a missing capability can
    pass quietly under CI, every check behind it is vacuous.
    """
    script = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('inv', {str(Path(__file__))!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "try:\n"
        "    m.skip('synthetic capability missing')\n"
        "except SystemExit as e:\n"
        "    print('FAILED', e.code)\n"
        "    sys.exit(0)\n"
        "print('SKIPPED')\n"
    )
    env = dict(os.environ)
    env.pop("PSGEN_REQUIRE_ALL", None)
    p = subprocess.run([sys.executable, "-c", script], capture_output=True,
                       text=True, timeout=120, env=env)
    if "SKIPPED" not in p.stdout or "synthetic capability missing" not in p.stderr:
        fail("skip() did not print a reason without PSGEN_REQUIRE_ALL")
    env["PSGEN_REQUIRE_ALL"] = "1"
    p = subprocess.run([sys.executable, "-c", script], capture_output=True,
                       text=True, timeout=120, env=env)
    if "FAILED 1" not in p.stdout:
        fail("skip() did not fail under PSGEN_REQUIRE_ALL=1")
    if "synthetic capability missing" not in p.stderr:
        fail("the PSGEN_REQUIRE_ALL failure did not name the reason")


def check_can_pty_fail_closed(tmp):
    """`can_pty()` must be False when the pty master cannot be taken.

    The old predicate returned True when `doctor --json` was unparseable and
    when it had no pty entry, so the injection check then *failed* on a host it
    should have skipped. This drives the predicate against a junk doctor.
    """
    shim = Path(tmp) / "pty-shim"
    shim.mkdir()
    (shim / "psgen").write_text("#!/bin/sh\necho not-json\nexit 0\n")
    (shim / "psgen").chmod(0o755)
    script = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('inv', {str(Path(__file__))!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "print('CANPTY', m.can_pty())\n"
    )
    env = dict(os.environ, PSGEN_BIN=str(shim / "psgen"))
    p = subprocess.run([sys.executable, "-c", script], capture_output=True,
                       text=True, timeout=120, env=env)
    if "CANPTY False" not in p.stdout:
        fail(f"can_pty() did not fail closed on a junk doctor: {p.stdout.strip()!r} "
             f"{p.stderr.strip()[:120]!r}")

    # A regular file in place of the master must also read as False, which the
    # pty pair proves by itself without a mount namespace. The scratch copy is
    # made inside the caller's `tmp`, so nothing is left in the temporary root.
    script = (
        "import importlib.util, sys, pathlib\n"
        f"spec = importlib.util.spec_from_file_location('inv', {str(Path(__file__))!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "_d = pathlib.Path(sys.argv[1])\n"
        "(_d / 'ptmx').write_bytes(b'junk')\n"
        "print('REGULAR', m.pty_master_works_at(str(_d / 'ptmx')))\n"
    )
    scratch = Path(tmp) / "regular-ptmx"
    scratch.mkdir()
    p = subprocess.run([sys.executable, "-c", script, str(scratch)],
                       capture_output=True, text=True, timeout=120,
                       env=dict(os.environ))
    if "REGULAR False" not in p.stdout:
        fail(f"the pty probe accepted a regular file as a master: "
             f"{p.stdout.strip()!r} {p.stderr.strip()[:120]!r}")

    # The predicate must *consult* that probe. A `can_pty()` reduced to "the
    # doctor said ALLOW" is the pre-fix shape: it reports True on a host where
    # the stub's two ioctls fail, and its caller then fails the injection
    # check instead of skipping it. Force the syscall probe to refuse and
    # require the predicate to agree, with a control that proves the wire is
    # live (the unmutated predicate asks for the probe at all).
    script = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('inv', {str(Path(__file__))!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "calls = []\n"
        "def refuse():\n"
        "    calls.append('probe')\n"
        "    return False\n"
        "m.pty_master_works = refuse\n"
        "print('CANPTY', m.can_pty())\n"
        "print('CALLED', 'yes' if calls else 'no')\n"
    )
    p = subprocess.run([sys.executable, "-c", script], capture_output=True,
                       text=True, timeout=120, env=dict(os.environ))
    if "CANPTY False" not in p.stdout:
        fail(f"can_pty() returned True with the syscall probe refusing, so it "
             f"does not consult it: {p.stdout.strip()!r} "
             f"{p.stderr.strip()[:160]!r}")
    if "CALLED no" in p.stdout:
        fail(f"can_pty() never called the syscall probe, so a doctor reporting "
             f"ALLOW would decide on its own: {p.stdout.strip()!r} "
             f"{p.stderr.strip()[:160]!r}")

    # ...and the syscall pair is what decides it, not a constant. The same
    # forced probe returning True must let a doctor that reports ALLOW
    # through, so the check above is not satisfied by a predicate hard-wired to
    # False. The doctor here is a shim, so this half does not depend on what
    # the host can really do.
    ok = Path(tmp) / "pty-ok"
    ok.mkdir()
    (ok / "psgen").write_text(
        '#!/bin/sh\necho \'{"checks":[{"name":"pty","ok":true}]}\'\nexit 0\n')
    (ok / "psgen").chmod(0o755)
    script = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('inv', {str(Path(__file__))!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "m.pty_master_works = lambda: True\n"
        "print('CANPTY', m.can_pty())\n"
    )
    p = subprocess.run([sys.executable, "-c", script], capture_output=True,
                       text=True, timeout=120,
                       env=dict(os.environ, PSGEN_BIN=str(ok / "psgen")))
    if "CANPTY True" not in p.stdout:
        fail(f"can_pty() returned False with the syscall probe succeeding and "
             f"a doctor reporting ALLOW, so the predicate ignores the probe: "
             f"{p.stdout.strip()!r} {p.stderr.strip()[:160]!r}")


def check_option_surface():
    """No option is accepted in a mode where it cannot change anything.

    This is the class issue #9 belonged to, split by the *mode* the flags
    select rather than by subcommand: `applies()` decides what a subcommand
    reads, and this decides what the chosen mode can act on. Each case below
    is a pair that the pre-fix binary accepted and then ignored, so the check
    fails on that head and passes once the option table and the mode rules
    agree.

    Nothing here spawns a process: the inject cases are all `--dry-run`, which
    is the seam the option matrix needed and did not have.
    """
    with tempfile.TemporaryDirectory(prefix="psgen-opts-") as tmp:
        _check_option_surface(Path(tmp))


def _check_option_surface(tmp):
    # The parser must not take an option the chosen mode cannot act on. Before
    # the fix every one of these exited 0 and changed nothing.
    rejected = [
        ["inject", "--dry-run", "--table", "-n", "1"],
        ["inject", "--dry-run", "--verify", "-n", "1"],
        ["inject", "--dry-run", "--wait", "-n", "1"],
        ["inject", "--dry-run", "--json", "--plan", "-n", "1"],
        ["inject", "-n", "1", "--table", "--utc-offset", "5"],
        ["inject", "-n", "1", "--table", "--local"],
        ["table", "--live", "--local"],
        ["table", "--live", "--utc-offset", "60"],
    ]
    for argv in rejected:
        p = run(argv, check=False)
        if p.returncode != 2:
            fail(f"#9: {' '.join(argv)} exited {p.returncode}, wanted 2 "
                 f"(the option cannot change anything)")

    # The two spellings of help and version must agree about their arguments.
    for flag, sub in (("--help", "help"), ("--version", "version")):
        a = run([flag, "-n", "5"], check=False)
        b = run([sub, "-n", "5"], check=False)
        if a.returncode != b.returncode:
            fail(f"#9: {flag} -n 5 exited {a.returncode} where {sub} -n 5 "
                 f"exited {b.returncode}")

    # `-p` must be a real weight for `list` at the default count, which is the
    # invocation the README shows. The corpus order is a documented contract,
    # so the bare form stays byte-identical; only an explicit `-p` re-orders.
    bare = run(["list", "-s", "1"]).stdout
    if len(bare.splitlines()) < 180:
        fail(f"#9: a bare list printed {len(bare.splitlines())} lines")
    server = run(["list", "-s", "1", "-p", "server"]).stdout
    desktop = run(["list", "-s", "1", "-p", "desktop"]).stdout
    if server == desktop:
        fail("#9: list -p has no effect at the default count")
    if len(server.splitlines()) != len(bare.splitlines()):
        fail("#9: list -p changed the number of lines, not their order")

    # `list` rejects --repeat-max, so its shortfall must not recommend it.
    p = run(["list", "-f", "mail", "-n", "50"], check=False)
    if "--repeat-max" in p.stderr:
        fail("#9: the list shortfall recommends --repeat-max, which list rejects")
    if "--no-uniq" in p.stderr and len(
            run(["list", "-f", "mail", "-n", "50", "--no-uniq"]).stdout.splitlines()) <= 8:
        fail("#9: the list shortfall offers --no-uniq, which pads nothing for mail")
    # ... and the converse: the family that *can* pad must still be told so.
    q = run(["list", "-f", "sto", "-n", "50"], check=False)
    if "--no-uniq" not in q.stderr:
        fail("#9: the list shortfall stopped offering --no-uniq where it works")

    # A plan must carry the identity, sizes and staging directories a run
    # would use, and must fail where the real run fails.
    plan = run(["inject", "-n", "3", "-s", "5", "--disk", "4", "--dry-run",
                "--plan", "--no-root", "--no-user"]).stdout
    for field in ("tier ", "user=", "vsz=", "rss=", "cpu=", "tty=", "threads=",
                  "exe=", "staging "):
        if field not in plan:
            fail(f"#12: the plan has no {field.strip(' =')} field")
    if "disk 12 MiB total" not in plan:
        fail("#12: the plan does not report the --disk total")
    doc = json.loads(run(["inject", "-n", "3", "-s", "5", "--disk", "4",
                          "--dry-run", "--json", "--no-root",
                          "--no-user"]).stdout)
    if doc.get("disk_mb_total") != 12 or doc.get("disk_mb_per_stub") != 4:
        fail(f"#12: the plan's disk figures do not reconcile: "
             f"total={doc.get('disk_mb_total')} per_stub={doc.get('disk_mb_per_stub')}")
    if len(doc.get("staging_dirs", [])) != 3:
        fail(f"#12: the plan names {len(doc.get('staging_dirs', []))} staging "
             f"directories for 3 rows with --disk")

    bad = str(Path(tmp) / "missing" / "x.pid")
    p = run(["inject", "-n", "2", "--dry-run", "--plan", "--pidfile", bad],
            check=False)
    real = run(["inject", "-n", "2", "--pidfile", bad], check=False)
    if p.returncode == 0:
        fail("#12: the plan exited 0 for a pidfile the real run refuses")
    if p.returncode != real.returncode:
        fail(f"#12: the plan exited {p.returncode} where the real run exited "
             f"{real.returncode} for the same pidfile")

    # `stop --plan` is a read-only preview, so it must not elevate.
    p = run(["stop", "--pidfile", str(Path(tmp) / "none.pid"), "--plan",
             "--elevate"], check=False)
    if p.returncode != 2:
        fail(f"#15: stop --plan --elevate exited {p.returncode}, wanted 2")

    # The identity a --create-users preview would use (issue #12). Each branch
    # below is a capability the assertion needs, so it goes through `skip()`:
    # under PSGEN_REQUIRE_ALL a host without sudo, or with Debian-exim already
    # installed, fails and names the reason instead of passing unexercised.
    if not can_root():
        skip("--create-users dry-run needs passwordless sudo")
        return
    # A template user the host does not have: the corpus's Debian-exim row is
    # the case the review used, and `-s 11` draws it.
    if subprocess.run(["getent", "passwd", "Debian-exim"],
                      stdout=subprocess.DEVNULL).returncode == 0:
        skip("Debian-exim exists on this host")
        return
    p = run(["inject", "-n", "6", "-s", "11", "--create-users", "--dry-run",
             "--json"], root=True)
    doc = json.loads(p.stdout)
    rows = [r for r in doc["rows"] if r["exe"] == "/usr/sbin/exim4"]
    if not rows:
        skip("-n 6 -s 11 did not draw the exim4 row")
        return
    for r in rows:
        if r["user"] == "root":
            fail("#12: --create-users --dry-run fell back to the caller's identity")
    if "pass --create-users" in p.stderr:
        fail("#12: the dry run suggests a flag that is already on the command line")
    if "would create" not in p.stderr:
        fail(f"#12: the dry run never says it would create an account: {p.stderr!r}")


def check_review_fixes(tmp):
    """Regressions for the defects the round-5 review found still open.

    Each one is written to fail on the pre-review head. Where the old
    behaviour cannot be observed from a black-box run (a timing or a
    rendering difference), the comment says what the old code did.
    """

    # #2: no row may have started before the host booted. Old head printed
    # Oct16 with a one-second uptime because only the long-running branch was
    # bounded; the dev, desk and default ages ignored the uptime. 0 is a usage
    # error (a host that has never been up does not exist), so the smallest
    # real host is the case that exercises the bound.
    now = time.localtime()
    now_min = now.tm_hour * 60 + now.tm_min
    for uptime in (1, 60):
        text = run(["table", "-n", "60", "-s", "42", "--local",
                    "--host-uptime", str(uptime)]).stdout
        for line in text.splitlines()[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            start = m.group("start")
            if not re.fullmatch(r"\d\d:\d\d", start):
                fail(f"#2: START {start!r} predates boot with "
                     f"--host-uptime {uptime}")
            v = int(start[:2]) * 60 + int(start[3:])
            d = (now_min - v) % 1440
            if d > 2:
                fail(f"#2: START {start} is {d} minutes before now with "
                     f"--host-uptime {uptime}")

    # #2: START must not move when only the wall clock advances. Two
    # snapshots a second apart used to drift because the age was recomputed
    # from a fresh uptime against a stale boot epoch.
    def clock_starts(text):
        out = {}
        for line in text.splitlines()[1:]:
            m = PS_RE.match(line)
            if m and re.fullmatch(r"\d\d:\d\d", m.group("start")):
                out[int(m.group("pid"))] = m.group("start")
        return out

    # Pin the host's uptime so every row is minutes old and therefore renders
    # as a clock time. Without the pin, a host up for more than a day has no
    # `HH:MM` row at all and the case could never run.
    snap = ["table", "-n", "40", "-s", "42", "--host-uptime", "600"]
    first = clock_starts(run(snap).stdout)
    time.sleep(1.3)
    second = clock_starts(run(snap).stdout)
    common = sorted(set(first) & set(second))
    if len(common) < 10:
        skip(f"#2 only {len(common)} rows rendered a clock time at "
             f"--host-uptime 600")
    for pid in common:
        a = int(first[pid][:2]) * 60 + int(first[pid][3:])
        b = int(second[pid][:2]) * 60 + int(second[pid][3:])
        d = abs(a - b)
        if min(d, 1440 - d) > 1:
            fail(f"#2: START for pid {pid} moved from {first[pid]} to {second[pid]}")

    # #16: --repeat-max 1 means one row per command line. web and sys used to
    # emit the same command in several rows because the bound was applied per
    # template and the repeats were drawn from a pool that still held them.
    for fam in ("web", "sys"):
        rows = run(["table", "-f", fam, "-n", "200", "--repeat-max", "1"]).stdout
        cmds = [" ".join(r.split()[10:]) for r in rows.splitlines()[1:]]
        dup = len(cmds) - len(set(cmds))
        if dup:
            fail(f"#16: {fam} --repeat-max 1 emitted {dup} duplicate command lines")

    # #9: an option the chosen command cannot use must be a usage error. The
    # old parser accepted these and then ignored them. `--host-uptime 0` is a
    # usage error in its own right (it names a host that never booted), so it
    # is checked in `check_generator_sweep`; here the value is valid and only
    # the mode is wrong.
    for argv in (
        ["table", "--live", "--host-uptime", "60"],
        ["table", "--live", "--host-mem", "512"],
        ["table", "--live", "--repeat-max", "1"],
        ["list", "--repeat-max", "1"],
        ["unit", "-q"],
        ["inject", "--dry-run", "--utc-offset", "5", "-n", "1"],
        ["inject", "--dry-run", "--local", "-n", "1"],
    ):
        p = run(argv, check=False)
        if p.returncode != 2:
            fail(f"#9: {' '.join(argv)} exited {p.returncode}, wanted 2")

    # #3: %MEM truncates at one decimal like procps; it does not round. The
    # old renderer printed rss*1000/mem rounded to one decimal. --host-mem
    # makes the denominator exact.
    text = run(["table", "-f", "web", "-n", "120", "--host-mem", "64"]).stdout
    budget = 64 * 1024
    seen = 0
    for line in text.splitlines()[1:]:
        m = PS_RE.match(line)
        if not m:
            fail(f"#3: a synthetic row did not parse: {line!r}")
        tenths = int(m.group("mem").replace(".", ""))
        want = min(999, int(m.group("rss")) * 1000 // budget)
        if tenths != want:
            fail(f"#3: %MEM for pid {m.group('pid')} is {m.group('mem')}, "
                 f"procps would truncate {int(m.group('rss'))} kB to {want / 10:.1f}")
        seen += 1
    if not seen:
        fail("#3: --host-mem produced no rows")

    # #3: the live COMMAND column must keep a final argv space and render
    # control bytes the way procps does: \r, \v and \f become '?', \n
    # becomes a space. The old reader stripped every trailing space and kept
    # the control bytes verbatim.
    procs = []
    try:
        for extra in ("trailing ", "a\rb", "c\vd\fe", "x\ny"):
            procs.append(subprocess.Popen(
                [sys.executable, "-c", "import time;time.sleep(30)", extra],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(0.6)
        live = {}
        for line in run(["table", "--live"]).stdout.splitlines()[1:]:
            m = PS_RE.match(line)
            if m:
                live[int(m.group("pid"))] = m.group("cmd")
        for p in procs:
            out = subprocess.run(["ps", "-o", "args=", "-p", str(p.pid)],
                                 stdout=subprocess.PIPE, text=True, timeout=30).stdout
            want = out[:-1] if out.endswith("\n") else out
            got = live.get(p.pid)
            if got != want:
                fail(f"#3: live COMMAND for pid {p.pid} is {got!r}, ps says {want!r}")
    finally:
        for p in procs:
            p.kill()

    check_argv_widths()

    # #22: a symlinked template exe (gcc -> x86_64-linux-gnu-gcc-14) made the
    # one-field form match nothing and report a plain "skip", so a run that
    # left every row alive could look routine. The bind tier is what produces
    # that shape, so this run must not use --no-root.
    pf = Path(tmp) / "sym.pid"
    one = Path(tmp) / "sym-one.pid"
    run(["inject", "-f", "dev", "-n", "20", "-s", "1", "--no-user",
         "--no-mem", "--no-tty", "--no-threads", "--pidfile", str(pf)])
    pids = read_pids(pf)
    # With the header the rows are identifiable by their run nonce, so every one
    # of them must be gone afterwards. Without the header `stop` refuses the file
    # before reading a row, which is what made the old form of this check
    # vacuous.
    write_rows(one, pidfile_header(pf), pids)
    p = run(["stop", "--pidfile", str(one)], check=False)
    alive_now = [pid for pid in pids if alive(pid)]
    if alive_now:
        fail(f"#22: a one-field pidfile left {len(alive_now)} of {len(pids)} "
             f"bind-tier rows alive (rc={p.returncode}): "
             f"{p.stdout.strip()!r}")
    silent = set()
    for line in p.stderr.splitlines():
        m = re.search(r"skip (\d+) \(identity does not match\)", line)
        if m:
            silent.add(int(m.group(1)))
    missed = [pid for pid in alive_now if pid in silent]
    if missed:
        fail(f"#22: a one-field line silently skipped {len(missed)} live "
             f"bind-tier rows (symlinked exe) instead of naming them")
    stop_pidfile(pf)

    # #5: a SIGKILLed injector leaves its staging directory behind. Once its
    # stubs are gone, the next run must prune it instead of keeping it for
    # ever. The old prune kept every directory that still had an owner marker.
    staging = Path(tmp) / "crash"
    staging.mkdir()
    crash = subprocess.Popen(
        [str(BIN), "inject", "-n", "4", "-s", "5", "--no-root", "--duration", "1",
         "--shadow-dir", str(staging), "--pidfile", str(Path(tmp) / "crash.pid")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 10
    old_dirs = []
    while time.time() < deadline:
        old_dirs = list(staging.glob(".psgen-*"))
        if old_dirs:
            break
        time.sleep(0.05)
    if not old_dirs:
        crash.kill()
        crash.wait()
        skip("#5 no staging directory appeared")
    else:
        crash.kill()
        crash.wait()
        time.sleep(2.5)
        q = run(["inject", "-n", "2", "-s", "3", "--no-root", "--duration", "1",
                 "--shadow-dir", str(staging),
                 "--pidfile", str(Path(tmp) / "crash2.pid")])
        if "pruned" not in q.stderr:
            fail(f"#5: a dead run's staging was not pruned: {q.stderr.strip()!r}")
        left = set(staging.glob(".psgen-*"))
        for d in old_dirs:
            if d in left:
                fail(f"#5: {d.name} survived the prune")

    # #27: a RuntimeDirectory survives a restart, so inject must succeed again
    # with the same pidfile after stop. The unit must also be the shape that
    # creates that directory and names that path.
    run_dir = Path(tmp) / "run-psgen"
    run_dir.mkdir()
    pf = run_dir / "psgen.pid"
    for _ in range(2):
        run(["inject", "-n", "4", "-s", "2", "--no-root", "--no-user",
             "--no-mem", "--no-tty", "--no-threads", "--pidfile", str(pf)])
        if not read_pids(pf):
            fail("#27: a restart cycle wrote no PIDs")
        stop_pidfile(pf)
    unit = run(["unit"]).stdout
    for needle in ("RuntimeDirectory=psgen", "RuntimeDirectoryMode=0700",
                   "--pidfile /run/psgen/psgen.pid"):
        if needle not in unit:
            fail(f"#27: the unit lacks {needle!r}")


def live_cmd_bytes(pid) -> bytes | None:
    """The COMMAND bytes `table --live` prints for one PID, or None.

    Decoding is the caller's problem: an invalid high byte is a valid argv byte
    and must survive the comparison, so the read stays in bytes.
    """
    p = subprocess.run([str(BIN), "table", "--live"], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=120)
    want = str(pid).encode()
    for line in p.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) > 1 and fields[1] == want:
            # COMMAND starts after the tenth whitespace-separated field; find
            # the same boundary `ps` uses by splitting from the left.
            head = line.split(None, 10)
            if len(head) == 11:
                return head[10]
    return None


def ps_args_bytes(pid) -> bytes:
    p = subprocess.run(["ps", "-o", "args=", "-p", str(pid)],
                       stdout=subprocess.PIPE, timeout=30)
    out = p.stdout
    return out[:-1] if out.endswith(b"\n") else out


def check_argv_widths():
    """A long argv is rendered in full, not replaced by the bracketed comm.

    `[python3]` is how `ps` shows a kernel thread, so a row that claims it for
    a process with a 600 KiB command line is a lie about the row's kind. A
    single argument cannot exceed MAX_ARG_STRLEN (128 KiB), so the width comes
    from several arguments; it is the *total* command line that the reader
    bounds at 512 KiB.
    """
    # 600 KiB in five pieces, 520 KiB in five, and one small piece as the
    # control: all three are below ARG_MAX but the first two are above the
    # reader's 512 KiB bound.
    for piece, count in ((120_000, 5), (104_000, 5), (8_000, 1)):
        holder = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(30)"] + ["A" * piece] * count,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        total = piece * count
        try:
            time.sleep(0.8)
            got = live_cmd_bytes(holder.pid)
            if got is None:
                fail(f"#3: a {total}-byte command line is missing from the live table")
            if got.startswith(b"["):
                fail(f"#3: a {total}-byte command line rendered as {got[:24]!r}; "
                     f"the bracketed comm is for a kernel thread")
            if not got.startswith(os.fsencode(sys.executable)):
                fail(f"#3: a {total}-byte command line does not start with the "
                     f"program: {got[:40]!r}")
        finally:
            holder.kill()
            holder.wait()


def check_argv_bytes():
    """Every byte outside printable ASCII is rendered the way `ps` renders it.

    The C0 range and DEL were covered; 0x80..=0xff were not, and procps
    replaces each byte that does not begin a valid UTF-8 sequence with `?`. A
    raw high byte is what an `awk`-by-field consumer then reads as text.

    Each range is one child whose single argument holds every byte in it
    separated by `Q`, so one `table --live` read covers the whole range.
    """
    for low, high in ((0x01, 0x20), (0x7f, 0x80), (0x80, 0xc0), (0xc0, 0x100)):
        raw = b"Q".join(bytes([b]) for b in range(low, high))
        argv = [os.fsencode(sys.executable), b"-c",
                b"import time;time.sleep(30)", raw]
        pid = os.fork()
        if pid == 0:
            try:
                os.execv(sys.executable, argv)
            finally:
                os._exit(127)
        try:
            time.sleep(0.8)
            got = live_cmd_bytes(pid)
            want = ps_args_bytes(pid)
            if got is None:
                fail(f"#3: a process with bytes 0x{low:02x}..0x{high - 1:02x} "
                     f"is missing from the live table")
            if want and got != want:
                # Report the first differing byte rather than the whole row.
                for i, (g, w) in enumerate(zip(got, want)):
                    if g != w:
                        fail(f"#3: live COMMAND differs at byte {i} for the "
                             f"0x{low:02x}..0x{high - 1:02x} sweep: {g!r} != "
                             f"{w!r} (got {got[i:i + 8]!r}, ps {want[i:i + 8]!r})")
                fail(f"#3: live COMMAND has {len(got)} bytes where ps has "
                     f"{len(want)} for the 0x{low:02x}..0x{high - 1:02x} sweep")
            # The high half must be `?` for every byte that is not valid UTF-8,
            # which is what makes the row safe for a field-splitting consumer.
            tail = got.split(b"Q", 1)[1] if b"Q" in got else b""
            bad = [b for b in tail if b >= 0x80]
            if bad:
                fail(f"#3: a raw high byte survived in the live COMMAND: "
                     f"0x{bad[0]:02x}")
        finally:
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except OSError:
                pass


def check_regressions2_tmp():
    with tempfile.TemporaryDirectory(prefix="psgen-res-") as tmp:
        check_residuals(Path(tmp))


def pidfile_header(path, root=False):
    """The `# psgen ...` header line of a pidfile, or "" when it has none."""
    if root:
        p = subprocess.run(as_root(["head", "-n", "1", str(path)]),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=30)
        text = p.stdout
    else:
        try:
            text = path.read_text()
        except OSError:
            return ""
    for line in text.splitlines():
        if line.startswith("# psgen"):
            return line
    return ""


def write_rows(path, header, pids, root=False):
    """Write a pidfile with `header` and one bare PID per line.

    The header is what makes the file acceptable to `stop` at all: a file with
    no `# psgen` line is refused before any row is examined, so a check that
    omits it can never reach the behaviour it claims to test.
    """
    body = "".join(f"{p}\n" for p in pids)
    if header:
        body = header + "\n" + body
    if root:
        subprocess.run(as_root(["tee", str(path)]), input=body, text=True,
                       stdout=subprocess.DEVNULL, check=True)
        subprocess.run(as_root(["chmod", "644", str(path)]), check=True)
    else:
        path.write_text(body)


def check_stop_identity():
    """`stop` must identify a row positively or refuse it, never report success.

    Three shapes reach the same branch: a bind-tier run whose one-field lines
    carry no starttime, a pidfile with a run nonce that the named process does
    not have, and a CRLF pidfile whose last field keeps a stray `\\r`. All three
    used to print `stopped 0 processes, skipped N` and exit 0 while every row
    stayed alive.
    """
    can_root_here = can_root()
    with tempfile.TemporaryDirectory(prefix="psgen-ident-") as tmp:
        tmp = Path(tmp)
        # The bind tier is what produces a one-field line that the exe test
        # cannot resolve: the stub's exe is the template path, and on a host
        # whose /usr/sbin is a symlink the leaf may not exist at all.
        if not can_root_here:
            skip("#22 the bind tier needs root")
            return
        pf = tmp / "bind.pid"
        run(["inject", "-f", "web", "-n", "8", "-s", "1", "--no-user",
             "--no-mem", "--no-tty", "--no-threads", "--pidfile", str(pf)],
            root=True)
        header = pidfile_header(pf, root=True)
        if not header:
            fail("#22: inject wrote no psgen header")
        pids = read_pids(pf, root=True)
        if not pids:
            fail("#22: the bind-tier run recorded no rows")
        one = tmp / "one.pid"
        write_rows(one, header, pids)
        p = run(["stop", "--pidfile", str(one)], root=True, check=False)
        survivors = [pid for pid in pids if alive(pid)]
        # The nonce in the header identifies each row, so this run must stop
        # them all. Anything alive afterwards is the round-1 defect: success
        # reported over live rows.
        if survivors:
            fail(f"#22: stop left {len(survivors)} of {len(pids)} identified "
                 f"rows alive (rc={p.returncode}): {p.stdout.strip()!r}")
        if p.returncode != 0:
            fail(f"#22: stop refused rows it could identify: {p.stderr.strip()!r}")
        stop_pidfile(pf, root=True)

        # A one-field line this tool cannot identify must be an error naming the
        # PID, never a skip that leaves the row alive. A psgen-shaped process
        # with no nonce is exactly what the old code killed.
        victim = subprocess.Popen([str(BIN), "load", "--cpu-util", "2",
                                   "-d", "60", "-q"],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        try:
            deadline = time.time() + 10
            while time.time() < deadline and not Path(f"/proc/{victim.pid}/exe").exists():
                time.sleep(0.05)
            time.sleep(0.4)
            forged = tmp / "forged.pid"
            write_rows(forged, f"# psgen {VERSION} boot {boot_id()}", [victim.pid])
            p = run(["stop", "--pidfile", str(forged)], check=False)
            if p.returncode == 0:
                fail("#22: a one-field line naming an unrelated psgen process "
                     "exited 0")
            if str(victim.pid) not in p.stderr:
                fail(f"#22: the refusal does not name PID {victim.pid}: "
                     f"{p.stderr.strip()!r}")
            if victim.poll() is not None:
                fail(f"#22: a forged one-field line killed unrelated pid "
                     f"{victim.pid}")
        finally:
            if victim.poll() is None:
                victim.kill()
                victim.wait()

        # A CRLF pidfile is the shape a Windows editor leaves. Every field then
        # ends with \r, so nothing matches; the run used to report success.
        pf = tmp / "crlf-src.pid"
        run(["inject", "-n", "3", "-s", "3", "--no-user", "--no-mem",
             "--no-tty", "--no-threads", "--pidfile", str(pf)], root=True)
        crlf = tmp / "crlf.pid"
        raw = subprocess.run(as_root(["cat", str(pf)]),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=30).stdout
        crlf.write_bytes(raw.replace(b"\n", b"\r\n"))
        crlf.chmod(0o644)
        p = run(["stop", "--pidfile", str(crlf)], root=True, check=False)
        if p.returncode == 0:
            fail("#22: a CRLF pidfile exited 0")
        if "crlf" not in p.stderr.lower() and "\\r" not in p.stderr:
            fail(f"#22: the CRLF refusal does not name the line ending: "
                 f"{p.stderr.strip()!r}")
        still = [pid for pid in read_pids(pf, root=True) if alive(pid)]
        if not still:
            fail("#22: the CRLF case signalled a row it should have refused")
        stop_pidfile(pf, root=True)


def check_stop_counts_processes():
    """`stopped N` counts processes, not pidfile lines (issue #4)."""
    with tempfile.TemporaryDirectory(prefix="psgen-count-") as tmp:
        tmp = Path(tmp)
        pf = tmp / "one.pid"
        run(["inject", "-n", "1", "-s", "5", "--no-user", "--no-mem",
             "--no-tty", "--no-threads", "--pidfile", str(pf)])
        header = pidfile_header(pf)
        rows = [l for l in pf.read_text().splitlines() if l and not l.startswith("#")]
        if len(rows) != 1:
            fail(f"#4: inject -n 1 recorded {len(rows)} rows")
        line = rows[0]
        pid = int(line.split("\t")[0])
        # One process, named five times.
        many = tmp / "many.pid"
        many.write_text(header + "\n" + "\n".join([line] * 5) + "\n")
        p = run(["stop", "--pidfile", str(many)], check=False)
        if "stopped 5 " in p.stdout:
            fail(f"#4: one process named five times was counted as five: "
                 f"{p.stdout.strip()!r}")
        if "stopped 1 process" not in p.stdout:
            fail(f"#4: one process named five times was not counted as one: "
                 f"{p.stdout.strip()!r}")
        if alive(pid):
            fail(f"#4: pid {pid} survived the stop that counted it")
        pf.unlink()
        many.unlink()


def check_stop_zombie_group():
    """A zombie leader's live process group is still signalled (issue #4).

    Only reachable where the leader's parent does not reap it, so the check
    makes its own non-reaping parent rather than depending on PID 1.
    """
    with tempfile.TemporaryDirectory(prefix="psgen-zlead-") as tmp:
        tmp = Path(tmp)
        script = tmp / "zlead.py"
        script.write_text(
            "import os, sys, time\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    g = os.fork()\n"
            "    if g == 0:\n"
            "        while True:\n"
            "            time.sleep(1)\n"
            "    sys.stderr.write('%d %d\\n' % (os.getpid(), g))\n"
            "    sys.stderr.flush()\n"
            "    os._exit(0)\n"
            "while True:\n"
            "    time.sleep(1)\n")
        log = tmp / "zlead.txt"
        parent = subprocess.Popen([sys.executable, str(script)],
                                  stdout=subprocess.DEVNULL,
                                  stderr=open(log, "w"),
                                  start_new_session=True)
        leader = child = None
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                text = log.read_text().strip()
                if text:
                    leader, child = (int(x) for x in text.split())
                    break
                time.sleep(0.05)
            if leader is None:
                fail("#4: the non-reaping parent printed no ids")
            # Wait for the leader to die and become a zombie.
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    st = Path(f"/proc/{leader}/stat").read_text()
                except OSError:
                    break
                if st[st.rindex(")") + 2] == "Z":
                    break
                time.sleep(0.05)
            st = Path(f"/proc/{leader}/stat").read_text()
            if st[st.rindex(")") + 2] != "Z":
                fail("#4: the group leader never became a zombie")
            start = int(st.rsplit(")", 1)[1].split()[19])
            pgrp = int(st.rsplit(")", 1)[1].split()[2])
            if pgrp != leader:
                fail(f"#4: the leader {leader} does not head its group ({pgrp})")
            if not alive(child):
                fail("#4: the live group member died before the check ran")
            pf = tmp / "zl.pid"
            pf.write_text(f"# psgen {VERSION} boot {boot_id()}\n"
                          f"{leader}\t{start}\n")
            # The plan must predict the group signal rather than a bare no-op,
            # and it must not perform it.
            p = run(["stop", "--pidfile", str(pf), "--plan"], check=False)
            if "process group is signalled" not in p.stdout:
                fail(f"#4: --plan does not predict the group signal: "
                     f"{p.stdout.strip()!r}")
            if not alive(child):
                fail(f"#4: --plan signalled the zombie leader's live group "
                     f"member {child}")
            run(["stop", "--pidfile", str(pf)], check=False)
            deadline = time.time() + 5
            while time.time() < deadline and alive(child):
                time.sleep(0.05)
            if alive(child):
                fail(f"#4: the zombie leader's live group member {child} was "
                     f"never signalled")
        finally:
            for pid in (child, leader, parent.pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            try:
                parent.kill()
                parent.wait()
            except OSError:
                pass


def check_option_self_check():
    """Every option the parser accepts is also in the help text.

    The unit tests compare the table against the help on the source. This is
    the black-box version, and it is the direction that used to be unguarded:
    an `OPTS` row with no help spelling parsed, applied and was invisible, so
    no test examined it. The probe is a *mutated binary* built here, because the
    defect is a missing row in a sibling of the code under test and the shipped
    binary cannot contain it.
    """
    src = ROOT / "src"
    if not (src / "cli.rs").exists():
        skip("#9 the source tree is not present next to the test")
        return
    if shutil.which("cargo") is None:
        skip("#9 no cargo to build the mutated binary")
        return
    with tempfile.TemporaryDirectory(prefix="psgen-mut-") as tmpdir:
        work = Path(tmpdir) / "src"
        shutil.copytree(src, work)
        cli = work / "cli.rs"
        text = cli.read_text()
        marker = '    Opt {\n        name: "--force",'
        if marker not in text:
            fail("#9: the mutated row has no anchor in src/cli.rs")
        # A full row, a parse arm, and no help line: exactly the shape that
        # passed every gate before the self-check was bidirectional.
        text = text.replace(
            marker,
            '    Opt {\n        name: "--frobnicate",\n        aliases: &[],\n'
            '        boolean: true,\n        subs: ANY,\n    },\n' + marker,
            1)
        arm = '                b"--frobnicate" => {\n' \
              '                    a.seen.push("--frobnicate");\n' \
              '                }\n'
        anchor = '                b"-V" | b"--version" => {\n' \
                 '                    a.want_version = true;\n' \
                 '                    a.seen.push("--version");\n' \
                 '                }\n'
        if anchor not in text:
            fail("#9: the mutated parse arm has no anchor in src/cli.rs")
        text = text.replace(anchor, anchor + arm, 1)
        cli.write_text(text)
        # The crate root, manifest and every other module travel with it.
        shutil.copy(ROOT / "Cargo.toml", Path(tmpdir) / "Cargo.toml")
        shutil.copy(ROOT / "Cargo.lock", Path(tmpdir) / "Cargo.lock")
        p = subprocess.run(["cargo", "test", "--release", "--offline"],
                           cwd=tmpdir, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, timeout=1800,
                           env=dict(os.environ, CARGO_TARGET_DIR=str(Path(tmpdir) / "t")))
        # The sabotage must be present: otherwise a build failure for any other
        # reason would look like the self-check working.
        if "frobnicate" not in cli.read_text():
            fail("#9: the mutation was not written to the copy of src/cli.rs")
        if p.returncode == 0:
            fail("#9: an option the parser accepts and --help never mentions "
                 "passed every unit test")
        # The failure must name the option, so an unrelated compile error cannot
        # stand in for the self-check.
        named = [line for line in p.stdout.splitlines()
                 if line.startswith("test ") and "FAILED" in line]
        if not any("every_row_in_the_table_has_a_help_spelling" in line
                   for line in named):
            fail(f"#9: the mutated tree failed, but not in the self-check that "
                 f"names the option: {named[:4]!r}")
        if "OPTS has options the help text never mentions" not in p.stdout:
            fail(f"#9: the self-check failed without naming the option: "
                 f"{p.stdout[-400:]!r}")


def check_dry_run_identity():
    """`--dry-run --json` names the identity the real run would use (#12).

    The defect was that the JSON reported `would_create: []` and `uid: 0`
    while the text output said it would create a user: the dry run fell back
    to the caller's identity instead of reporting the one the run would use.

    Which users are missing depends on the host — a CI runner has `postgres`,
    a minimal host does not — so the check makes the absence itself: it hides
    a `passwd` without the family's accounts from the binary in a private
    mount namespace. Without that, the check would pass on any host that
    happens to have every corpus account, which is the "cannot fail" shape.
    """
    if not can_root():
        skip("#12 --create-users needs passwordless sudo")
        return
    # The template names come from the corpus, not from the plan: the plan
    # prints the identity after `prepare` resolved it, which is the value
    # under test.
    corpus = run(["corpus"], check=False).stdout
    wanted = sorted({line.split("\t")[1] for line in corpus.splitlines()
                     if line.startswith("db\t") and "\t" in line})
    if not wanted:
        skip("#12 the db corpus named no users")
        return
    shim = Path(tempfile.mkdtemp(prefix="psgen-useradd-"))
    passwd = shim / "passwd"
    shadow = shim / "shadow"
    try:
        keep = [l for l in Path("/etc/passwd").read_text().splitlines()
                if l.split(":")[0] not in wanted]
        passwd.write_text("".join(l + "\n" for l in keep))
        # `/etc/shadow` is not readable by the caller, so it is read as root.
        # NSS needs it present and consistent with the passwd copy.
        sp = subprocess.run(as_root(["cat", "/etc/shadow"]),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, timeout=30)
        keep = [l for l in sp.stdout.splitlines() if l.split(":")[0] not in wanted]
        shadow.write_text("".join(l + "\n" for l in keep))
        inner = shim / "run.sh"
        inner.write_text(
            "#!/bin/sh\n"
            f"mount --bind {passwd} /etc/passwd || exit 90\n"
            f"mount --bind {shadow} /etc/shadow || exit 91\n"
            f"exec {BIN} inject -f db -n 2 -s 5 --create-users "
            "--dry-run --json\n")
        inner.chmod(0o755)
        p = subprocess.run(as_root(["unshare", "-m", str(inner)]),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=180)
        if p.returncode in (90, 91):
            skip("#12 a private mount namespace is needed to hide an account")
            return
        if p.returncode != 0:
            fail(f"#12 the db dry run exited {p.returncode}: "
                 f"{p.stderr.strip()[:200]!r}")
        try:
            doc = json.loads(p.stdout)
        except json.JSONDecodeError:
            fail(f"#12: --dry-run --json is not JSON: {p.stdout[:120]!r}")
        names = doc.get("would_create")
        if not isinstance(names, list):
            fail("#12: --dry-run --json has no would_create array")
        # Every db account is hidden, so the run must name the ones its rows
        # use. An empty list is the pre-fix bug: the dry run fell back to the
        # caller and reported nothing to create.
        said = sorted({m.group(1) for m in
                       re.finditer(r"would create (\S+)", p.stderr)})
        if not names:
            fail("#12: --dry-run --json reported would_create: [] while the "
                 f"run would create {said or wanted}")
        if sorted(names) != said:
            fail(f"#12: --dry-run --json would_create {names} disagrees with "
                 f"the identities the run named {said}")
        if not set(names) <= set(wanted):
            fail(f"#12: --dry-run --json would create {names}, which is not a "
                 f"db corpus account ({wanted})")
        marked = [r for r in doc["rows"] if r["user"] in names]
        if not marked:
            fail("#12: no plan row names a user the run would create")
        for r in marked:
            if r["uid"] == 0:
                fail(f"#12: row {r['row']} says it would run as uid 0 for "
                     f"a user the run would create ({r['user']})")
            if r["uid"] is not None:
                fail(f"#12: row {r['row']} claims a uid ({r['uid']}) for "
                     f"a user that does not exist yet ({r['user']})")
    finally:
        shutil.rmtree(shim, ignore_errors=True)





def check_generator_sweep():
    """Every generated row must be plausible for the host it describes.

    The generator's own unit tests prove the arithmetic; this proves the
    *rendered* table, so a column format that hides an impossible value cannot
    pass. It sweeps the host shapes the flags exist for — memory, PID space and
    uptime — because each cap lives on a different path and a single shape
    exercises one of them.

    The reference is the geometry of a process table: RSS is part of VSZ,
    `%MEM` is a fraction of the machine, a PID below `pid_max` exists, a start
    is inside `[boot, now]`, and no process has burned more CPU time than it has
    been alive. None of those come from psgen's own formulas.
    """
    def rows_of(args):
        p = run(args, check=False)
        if p.returncode != 0:
            fail(f"#28: {' '.join(args)} exited {p.returncode}: {p.stderr.strip()}")
        out = []
        for line in p.stdout.splitlines()[1:]:
            m = PS_RE.match(line)
            if not m:
                fail(f"#28: unparsable row from {' '.join(args)}: {line!r}")
                continue
            out.append(m.groupdict())
        return out

    def secs(t):
        parts = [int(x) for x in t.split(":")]
        if len(parts) == 2:
            return parts[0] * 60 + parts[1]
        return parts[0] * 3600 + parts[1] * 60 + parts[2]

    shapes = [
        # (mem MiB, pid_max, uptime)
        (None, None, 1),
        (None, None, 60),
        (None, None, 3600),
        (None, None, 86400),
        (None, None, 90000),
        (64, None, 3600),
        (256, 300, 86400),
        (512, 1024, 60),
        (4096, None, 604800),
    ]
    for mem, pid_max, uptime in shapes:
        for seed in (1, 42, 165):
            for family in (None, "web", "db", "sys"):
                args = ["table", "-n", "300", "-s", str(seed), "--utc-offset", "0",
                        "--host-uptime", str(uptime)]
                if mem is not None:
                    args += ["--host-mem", str(mem)]
                if pid_max is not None:
                    args += ["--host-pid-max", str(pid_max)]
                if family is not None:
                    args += ["-f", family]
                rows = rows_of(args)
                if not rows:
                    fail(f"#28: {' '.join(args)} produced no rows")
                for r in rows:
                    pid = int(r["pid"])
                    rss = int(r["rss"])
                    vsz = int(r["vsz"])
                    where = f"pid {pid} ({r['cmd'][:40]}) on {' '.join(args)}"
                    if rss > vsz:
                        fail(f"#28: RSS {rss} above VSZ {vsz} for {where}")
                    if float(r["mem"]) > 100.0:
                        fail(f"#28: %MEM {r['mem']} above the whole machine for {where}")
                    if pid < 1:
                        fail(f"#28: PID {pid} is not a process ({where})")
                    if pid_max is not None and pid >= pid_max:
                        fail(f"#28: PID {pid} at or above pid_max {pid_max} ({where})")
                    # The oldest row cannot be older than the host has been up,
                    # and no row may have more CPU time than it has been alive.
                    if secs(r["time"]) > uptime + 120:
                        fail(f"#28: TIME {r['time']} beyond an uptime of {uptime}s ({where})")
                # The boot-relative rows must actually be boot-relative. A row
                # that started at the boot has an age close to the uptime, and
                # the TIME column proves it without a clock: an hour-old daemon
                # has accumulated CPU time, a daemon "started a minute ago" has
                # `0:00`. The minute-boundary case cannot help the old code
                # either: a 90-minute host shows a boot daemon at the current
                # minute only if its age is under 90 s.
                if family in (None, "sys") and uptime >= 3600:
                    init = [r for r in rows if r["cmd"].startswith("/sbin/init")]
                    if not init:
                        fail(f"#28: {' '.join(args)} has no /sbin/init row")
                    # `/sbin/init` claims 0.3% of a core, so on an hour-old host
                    # it has minutes of CPU; at `now - 90 s` it can show at most
                    # a second.
                    if secs(init[0]["time"]) == 0:
                        fail(f"#28: /sbin/init shows TIME {init[0]['time']} on a host "
                             f"up {uptime}s: it is not boot-relative ({' '.join(args)})")

    # `--host-uptime 0` and `--host-mem 0` name a host that does not exist: 0
    # means "unknown" inside, so accepting them would describe this machine
    # under the name of another. The refusal has to be a *usage* error that
    # names the flag, not merely a non-zero exit: a crash also exits non-zero,
    # and a caller who reads the message needs the flag in it.
    for flag, args in (("--host-uptime", ["--host-uptime", "0"]),
                       ("--host-mem", ["--host-mem", "0"]),
                       ("--host-pid-max", ["--host-pid-max", "0"])):
        p = run(["table", "-n", "3"] + args, check=False)
        if p.returncode != 2:
            fail(f"#28: {flag} 0 was accepted (exit {p.returncode}), not a "
                 f"usage error")
        if flag not in p.stderr:
            fail(f"#28: {flag} 0 exited 2 without naming the flag: "
                 f"{p.stderr.strip()[:120]!r}")

    # The same seed must give the same *rows* seconds apart, START included:
    # START is the process's start time, and a per-row clock read made the
    # column move a minute per minute of wall clock.
    # A run that straddles a minute boundary legitimately differs: the snapshot
    # instant moves, and START for a row under a day old has minute resolution.
    # Align the pair to just after a boundary instead of weakening the compare,
    # then retry a few times so a slow first run cannot poison the sample.
    def aligned_pair(argv):
        # Land at the start of a minute so both reads share one.
        now = time.time()
        time.sleep(math.ceil(now) % 60 + 0.05 if (now % 60) > 56 else 0.05)
        a = run(argv, check=False).stdout
        b = run(argv, check=False).stdout
        return a, b

    for argv in (["table", "-n", "60", "-s", "42", "--host-uptime", "90000"],
                 ["list", "-n", "60", "-s", "42"],
                 ["inject", "--dry-run", "--plan", "-n", "12", "-s", "42"]):
        for attempt in range(4):
            a, b = aligned_pair(argv)
            if a == b:
                break
        else:
            fail(f"#2: {' '.join(argv)} is not byte-identical across minutes")

    # `list --no-uniq` pads every family, not only the ones whose templates
    # carry a placeholder.
    for fam in ("mail", "mon", "net", "dev", "sto", "sys", "web", "db", "ctr", "desk"):
        lines = [l for l in run(["list", "-f", fam, "-n", "50", "--no-uniq"]).stdout.splitlines() if l]
        if len(lines) != 50:
            fail(f"#16: list -f {fam} -n 50 --no-uniq produced {len(lines)} lines")

    # The documented pigeonhole bound is `ceil(rows / templates)`, and `web`
    # broke it by 2.5x before the fill netted off the distinct pass.
    candidates = {"sys": 6, "web": 7, "db": 2, "mon": 7, "net": 6,
                  "mail": 5, "sto": 5, "desk": 5, "dev": 33, "ctr": 6}
    for fam, k in candidates.items():
        rows = rows_of(["table", "-f", fam, "-n", "200", "-s", "2", "--host-uptime", "86400"])
        cmds = [" ".join(r["cmd"].split()) for r in rows]
        if len(cmds) != 200:
            fail(f"#16: table -f {fam} -n 200 returned {len(cmds)} rows")
        top = max(cmds.count(c) for c in set(cmds))
        bound = max((200 + k - 1) // k, 6)
        if top > bound:
            fail(f"#16: table -f {fam} has one command {top} of {len(cmds)} rows, "
                 f"bound {bound} with {k} templates")

    # A child starts at or after the process that forked it. Postgres, php-fpm
    # and gunicorn were generated before their masters, which `pstree` cannot
    # show. The rendered column only orders two rows when both are clock times
    # on the same day, so the run is pinned inside one day and the comparison is
    # made only on rows that are, allowing for the minute the table was taken.
    for argv in (["table", "-f", "db", "-n", "300", "-s", "1", "--host-uptime", "3600"],
                 ["table", "-f", "web", "-n", "300", "-s", "1", "--host-uptime", "3600"]):
        rows = rows_of(argv + ["--utc-offset", "0"])
        pairs = [("/usr/lib/postgresql/17/bin/postgres -D", "postgres: 17/main:"),
                 ("php-fpm: master process", "php-fpm: pool www"),
                 ("gunicorn: master", "gunicorn: worker"),
                 ("nginx: master process", "nginx: worker")]
        for master_cmd, child_cmd in pairs:
            masters = [r for r in rows if r["cmd"].startswith(master_cmd)]
            kids = [r for r in rows if r["cmd"].startswith(child_cmd)]
            if not masters or not kids:
                continue
            m = masters[0]["start"]
            if not re.fullmatch(r"\d\d:\d\d", m):
                fail(f"#18: the master on a one-hour host starts at {m!r}, not a clock time")
            for kid in kids:
                k = kid["start"]
                if not re.fullmatch(r"\d\d:\d\d", k):
                    continue
                if k < m:
                    fail(f"#18: {kid['cmd'][:40]!r} starts {k}, before its "
                         f"master at {m}")

    # The same corpus row must render the same STAT in `table` and after
    # injection: the `s` and `+` flags were derived twice and diverged. The
    # base state letter is a separate decision (`F_BUSY` is `R` in the table and
    # only burns CPU after inject with `--busy`), so the comparison is on the
    # session and terminal flags, which are what #18 split.
    def tail_flags(stat):
        return stat[1:]

    planned = {}
    for r in rows_of(["table", "-n", "300", "-s", "1"]):
        planned.setdefault(r["cmd"], tail_flags(r["stat"]))
    if len(planned) < 100:
        fail(f"#18: the table named only {len(planned)} distinct commands, so "
             f"the STAT comparison has no population")
    with tempfile.TemporaryDirectory(prefix="psgen-stat-") as tmp:
        pf = Path(tmp) / "stat.pid"
        # `inject --table -n 300` intermittently exits 1 on a healthy host
        # ("N did not report"), so one failed run is retried rather than
        # converted into a pass: the assertion is about STAT parity, and a
        # failed spawn simply did not observe it. Only a run that never
        # succeeds is a capability problem, and that goes through `skip()` so
        # PSGEN_REQUIRE_ALL turns it into a failure instead of a silent pass.
        p, live = None, {}
        for attempt in range(4):
            if attempt:
                time.sleep(0.5)
            p = run(["inject", "--table", "-n", "300", "-s", "1",
                     "--pidfile", str(pf), "--no-user", "--no-mem",
                     "--duration", "2"], check=False)
            live = {}
            if p.returncode == 0:
                for line in p.stdout.splitlines()[1:]:
                    m = PS_RE.match(line)
                    if m:
                        live.setdefault(m.group("cmd"), tail_flags(m.group("stat")))
                if len(live) >= 100:
                    break
            stop_pidfile(pf)
        try:
            if p.returncode != 0 or len(live) < 100:
                detail = (f"rc={p.returncode} after 4 runs, {len(live)} rows, "
                          f"{p.stderr.strip()[:120]!r}")
                skip(f"#18 STAT parity needs a working inject: {detail}")
                return
            common = sorted(set(planned) & set(live))
            if len(common) < 100:
                fail(f"#18: only {len(common)} of {len(live)} injected rows are "
                     f"in the table, so STAT parity was never compared")
            for cmd in common:
                if planned[cmd] != live[cmd]:
                    fail(f"#18: {cmd[:50]!r} is {planned[cmd] or '(none)'} in table, "
                         f"{live[cmd] or '(none)'} after inject")
        finally:
            stop_pidfile(pf)


def can_unshare(cmd: list[str], timeout: int = 60):
    """Run `cmd` and return the CompletedProcess, or None when unshare is absent."""
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout)
    except (FileNotFoundError, PermissionError):
        return None


def cfg_blob(magic: bytes, version: int, *, stage: int, comm: bytes,
             exe: bytes, cmd: bytes, user: bytes, temp: bytes,
             self_copy: bytes, nonce: bytes, disk_kb: int) -> bytes:
    """A config in the wire format one psgen build reads.

    `bf80156` used `PGCFG021`/version 2 and a 96-byte header; the fixed build
    uses `PGCFG023`/version 3 and adds a nonce length at offset 96. Encoding
    both lets a regression ask the same question of either binary: what did
    the process *do* with this descriptor, not just what did it print.
    """
    import struct

    header = 104 if magic == b"PGCFG023" else 96
    hdr = bytearray(header)
    hdr[:8] = magic

    def w(off, v):
        struct.pack_into("<I", hdr, off, v)

    w(8, version)
    w(40, stage)
    w(44, len(comm))
    w(48, len(exe))
    w(52, len(cmd))
    w(56, len(user))
    w(60, len(temp))
    struct.pack_into("<i", hdr, 72, 5)
    struct.pack_into("<i", hdr, 76, -1)
    struct.pack_into("<i", hdr, 80, -1)
    w(88, disk_kb)
    w(92, len(self_copy))
    if header == 104:
        w(96, len(nonce))
    blob = bytes(hdr) + comm + exe + cmd + user + temp + self_copy
    if header == 104:
        blob += nonce
    return blob


class Fd3:
    """Makes a descriptor available to a child as exactly descriptor 3.

    `pass_fds` keeps only the numbers it is given, and `os.set_inheritable` is
    applied to those numbers after `preexec_fn` has run, so `dup2(fd, 3)` is
    reversed unless 3 itself is in the set. The descriptor must therefore *be*
    3 in the parent, which means saving and restoring whatever was there.
    """

    def __init__(self, fd: int):
        self.own_3 = fd != 3
        self.saved = None
        if self.own_3:
            try:
                self.saved = os.dup(3)
            except OSError:
                pass
            os.dup2(fd, 3)

    def __enter__(self):
        return 3

    def __exit__(self, *exc):
        # When the caller's descriptor already was 3 it stays the caller's to
        # close; closing it here made the call site's `os.close` fail.
        if not self.own_3:
            return
        os.close(3)
        if self.saved is not None:
            os.dup2(self.saved, 3)
            os.close(self.saved)


def fd3_run(fd: int, env_extra=None, timeout=2.0):
    """Start a CLI invocation with `fd` on 3; watch what the process becomes.

    `/proc/PID/exe` is read in a tight loop: a forged `self_copy` that names a
    shell exits at once when its argv is a command the shell cannot run, so a
    single sample can miss the exec that did happen.
    """
    rc, exes, err, _, _ = fd3_run_observe(fd, env_extra, timeout)
    return rc, exes, err


def fd3_run_observe(fd: int, env_extra=None, timeout=2.0):
    """Like `fd3_run`, and also return the process's comm and command line.

    A stub renames its comm before it execs and rewrites its argv after, so
    those are the effects a forged config produces even when `/proc/PID/exe`
    is the psgen binary for the whole life of the process.
    """
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    with Fd3(fd) as cfg_fd:
        p = subprocess.Popen([str(BIN), "fake-argv-so-a-stub-would-take-it"],
                             env=env, pass_fds=(cfg_fd,),
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    exes = []
    comm = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            exes.append(os.readlink(f"/proc/{p.pid}/exe"))
        except OSError:
            pass
        try:
            # Keep the last value seen: the comm of the first sample is still
            # the CLI's, and the stub sets its own only after it is forked.
            comm = Path(f"/proc/{p.pid}/comm").read_text().strip()
        except OSError:
            pass
        if p.poll() is not None:
            break
        time.sleep(0.01)
    cmdline = ""
    try:
        cmdline = Path(f"/proc/{p.pid}/cmdline").read_bytes().replace(
            b"\0", b" ").decode()
    except OSError:
        pass
    if p.poll() is None:
        p.kill()
    try:
        _, err = p.communicate(timeout=10)
    except Exception:
        err = b""
    return p.returncode, exes, err, comm, cmdline


def forged_blob(tmp: Path, nonce: bytes):
    """A config that names a directory to create, plus the path it names.

    Every #25 shape is fed the same bytes, so a refusal can only be about the
    descriptor and never about the payload.
    """
    attack = Path(tmp) / "attack"
    blob = cfg_blob(b"PGCFG023", 3, stage=1, comm=b"nginx", exe=b"",
                    cmd=b"sleep 120", user=b"root",
                    temp=str(attack).encode(), self_copy=b"/bin/sh",
                    nonce=nonce, disk_kb=0)
    return attack, blob


def ctypes_fcntl():
    """`fcntl(2)` through libc, so the seal flags need no Python constant."""
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    return lambda fd, cmd, arg: libc.fcntl(fd, cmd, arg)


def memfd_blob(blob: bytes, flags: int):
    """A memfd holding `blob`, or None.

    `Fd3` moves the descriptor it is given onto 3 and closes 3 on exit, so a
    helper that happens to return 3 must not: descriptor 3 stays reserved for
    the harness so a caller can tell its own descriptor from the child's.
    """
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.memfd_create(b"psgen-test", flags)
    if fd < 0:
        return None
    if fd == 3:
        moved = os.dup(3)
        os.close(3)
        fd = moved
    os.write(fd, blob)
    os.lseek(fd, 0, 0)
    return fd


def unshare_mount(script: str, timeout: int = 120):
    """Run `script` in a private mount namespace, or None when none is allowed.

    A private *user* namespace is the portable form, but Ubuntu restricts it
    for unprivileged callers, so a host with root uses a plain mount namespace
    instead. The script signals a failed mount with exit 90.
    """
    if can_root():
        p = subprocess.run(as_root(["unshare", "-m", script]),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        if p.returncode != 0 and "Operation not permitted" in p.stderr:
            return None
        return p
    p = can_unshare(["unshare", "-Urnm", script], timeout=timeout)
    if p is not None and "Operation not permitted" in p.stderr:
        return None
    return p


def check_security_markers(tmp):
    """Regressions for the pidfile, staging, fd 3, user and check defects."""
    tmp = Path(tmp)
    me = os.getpid()
    cur_boot = boot_id()

    # #7: `inject` must never write a header its own `stop` refuses. With the
    # boot id unreadable it used to write `boot ` (empty) and spawn anyway;
    # `stop` then refused the file even with --plan.
    #
    # The run happens in a private mount namespace, where the caller's uid is
    # mapped to root, so its scratch root must be writable from both sides.
    scratch = tmp / "scratch"
    scratch.mkdir(exist_ok=True)
    scratch.chmod(0o777)
    pidfile = scratch / "noboot.pid"
    inner = tmp / "noboot.sh"
    inner.write_text(
        "#!/bin/sh\n"
        f"TMPDIR={scratch}; export TMPDIR\n"
        "mount --bind /dev/null /proc/sys/kernel/random/boot_id || exit 90\n"
        f"exec {BIN} inject -n 2 --no-user --no-mem --no-tty --no-threads "
        f"--pidfile {pidfile}\n")
    inner.chmod(0o755)
    p = unshare_mount(str(inner), timeout=120)
    if p is None or p.returncode == 90:
        skip("#7 a private mount namespace is needed to hide the boot id")
    else:
        spawned = "spawned" in p.stdout
        if spawned:
            stop_pidfile(pidfile)
            fail("#7: inject wrote a pidfile with no boot id and spawned")
        if pidfile.exists():
            text = pidfile.read_text()
            pidfile.unlink()
            if text.startswith("# psgen") and " boot \n" in text + "\n":
                fail("#7: an unusable pidfile was left behind")
        if p.returncode == 0:
            fail("#7: inject exited 0 with an unreadable boot id")
        if "boot" not in p.stderr.lower():
            fail(f"#7: the refusal does not name the boot id: "
                 f"{p.stderr.strip()[:160]!r}")

    # #7: only the first line is a header. A later `# psgen ...` line is a
    # comment; it used to be read as a competing boot id, which made a valid
    # pidfile unstoppable and `--force` did not help.
    pf = tmp / "annotated.pid"
    pf.write_text(f"# psgen {VERSION} boot {cur_boot}\n"
                  "# psgen note: boot order is set elsewhere\n"
                  f"{me}\t0\tpsgen-test-comm\n")
    p = run(["stop", "--pidfile", str(pf)], check=False)
    if "conflicting boot ids" in p.stderr:
        fail("#7: a later '# psgen' line was read as a conflicting header")
    if p.returncode != 0:
        fail(f"#7: an annotated psgen pidfile was refused: {p.stderr.strip()!r}")

    # #7: a pidfile with no psgen header is refused, and --force is the
    # documented escape hatch. Failing open signalled whatever the file named
    # and removed whatever a `# temp` line named.
    victim = subprocess.Popen(["sleep", "120"])
    outside = tmp / "not-ours"
    outside.mkdir()
    (outside / "keep").write_text("x\n")
    try:
        # Field 22 is the starttime; the tail starts at field 3, so it is 19.
        fields = stat_fields(victim.pid) or []
        if len(fields) < 20:
            fail("#7: cannot read the victim's starttime from /proc")
        start = int(fields[19])
        pf = tmp / "headerless.pid"
        pf.write_text(f"# temp {outside}\n{victim.pid}\t{start}\t{victim.pid}\n")
        p = run(["stop", "--pidfile", str(pf)], check=False)
        if p.returncode == 0:
            fail("#7: a pidfile with no psgen header was accepted")
        if victim.poll() is not None:
            fail("#7: a pidfile with no psgen header stopped a live process")
        if not outside.exists():
            fail("#7: a pidfile with no psgen header deleted a directory")
        # The escape hatch still works.
        run(["stop", "--pidfile", str(pf), "--force"], check=False)
        if victim.poll() is None:
            victim.kill()
    finally:
        if victim.poll() is None:
            victim.kill()
        victim.wait()

    # #26: a sticky-directory EPERM must name the permission, not NAME_MAX.
    # The directory must belong to someone else as well as being 1777: its owner
    # may always rename over a file inside it, so /tmp is the shape that denies
    # an unprivileged caller. Running as root cannot reproduce it at all.
    if can_root() and os.geteuid() != 0:
        ro = Path("/tmp") / f"psgen-sticky-{os.getpid()}.pid"
        subprocess.run(["sudo", "-n", "install", "-m", "644", "/dev/null",
                        str(ro)], check=True)
        p = run(["inject", "-n", "1", "--no-user", "--no-mem", "--no-tty",
                 "--no-threads", "--pidfile", str(ro)], check=False)
        if p.returncode != 2:
            stop_pidfile(ro, root=True)
            subprocess.run(["sudo", "-n", "rm", "-f", str(ro)], check=False)
            fail(f"#26: a root-owned pidfile in a sticky dir was accepted: "
                 f"rc={p.returncode}")
        if "NAME_MAX" in p.stderr:
            fail("#26: a sticky-directory EPERM was reported as NAME_MAX")
        if "permitted" not in p.stderr and "permission" not in p.stderr:
            fail(f"#26: the sticky-directory failure named no permission "
                 f"cause: {p.stderr.strip()[:200]!r}")
        subprocess.run(["sudo", "-n", "rm", "-f", str(ro)], check=False)
    else:
        # A root caller cannot reproduce a sticky-directory EPERM at all, so
        # the assertion needs a specific two-uid shape. That is a capability
        # like any other: `skip()` fails under PSGEN_REQUIRE_ALL, which is the
        # only way a root CI container can be told it is running the suite as
        # the wrong shape instead of passing this check unexercised.
        skip("#26 sticky-dir EPERM needs an unprivileged caller and root")

    # #26: the preflight must prove the body, not a zero-byte create. A size
    # limit lets the header through and fails on the rows, which used to leave
    # a header-only pidfile that `stop` called a clean stop of nothing.
    small = tmp / "small.pid"
    import resource

    def cap_fsize():
        resource.setrlimit(resource.RLIMIT_FSIZE, (1500, 1500))
        import signal
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)

    p = subprocess.run([str(BIN), "inject", "-n", "60", "--no-user",
                        "--no-mem", "--no-tty", "--no-threads",
                        "--pidfile", str(small)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True,
                       env=dict(os.environ, TMPDIR=str(tmp)),
                       preexec_fn=cap_fsize, timeout=180)
    if small.exists():
        rows = [l for l in small.read_text().splitlines()
                if l and not l.startswith("#")]
        spawned = len(re.findall(r"\bspawned \d+ processes", p.stdout))
        if p.returncode == 0 and spawned and len(rows) < 60:
            stop_pidfile(small)
            fail(f"#26: a pidfile with {len(rows)} of 60 rows was accepted")
        if p.returncode != 0 and rows:
            stop_pidfile(small)
            fail(f"#26: a failed run left a {len(rows)}-row pidfile behind")
        if rows:
            stop_pidfile(small)
        else:
            small.unlink()

    # #5: a marker written in another PID namespace must not be judged here.
    # The first run is real, in a private PID namespace; a second inject on the
    # host shares its TMPDIR and its shadow root. PIDs there name unrelated
    # processes here, so a host prune used to delete a live run's staging.
    ns_tmp = tmp / "ns"
    ns_tmp.mkdir()
    ns_shadow = tmp / "ns-shadow"
    inner = tmp / "ns-run.sh"
    inner.write_text(
        "#!/bin/sh\n"
        f"cd {ns_tmp} && export TMPDIR={ns_tmp}/t\n"
        f"exec {BIN} inject -n 2 -s 7 -d 120 --disk 1 --no-root --no-user "
        f"--no-mem --no-tty --no-threads --shadow-dir {ns_shadow} "
        f"--pidfile {ns_tmp}/a.pid -q\n")
    inner.chmod(0o755)
    ns = None
    try:
        pid_flags = (["-Up", "--mount-proc", "--fork"] if os.geteuid() == 0
                     else ["-Ur", "-Up", "--mount-proc", "--fork"])
        ns = subprocess.Popen(["unshare"] + pid_flags + [str(inner)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
    except (FileNotFoundError, PermissionError):
        ns = None
    started = False
    if ns is not None:
        for _ in range(150):
            if list(ns_shadow.glob(".psgen-*")) or (ns_tmp / "a.pid").exists():
                started = True
                break
            if ns.poll() is not None:
                break
            time.sleep(0.1)
    if not started:
        if ns is not None:
            if ns.poll() is None:
                ns.kill()
            ns.wait()
        skip("#5 a private PID namespace is required by this check")
    else:
        time.sleep(1.0)
        dirs = list(ns_shadow.glob(".psgen-*")) + list((ns_tmp / "t").glob(".psgen-*"))
        try:
            host_pf = tmp / "host.pid"
            p = run(["inject", "-n", "1", "-s", "3", "--no-user", "--no-mem",
                     "--no-tty", "--no-threads", "--shadow-dir", str(ns_shadow),
                     "--pidfile", str(host_pf)],
                    env=dict(os.environ, TMPDIR=str(ns_tmp / "t")), check=False)
            stop_pidfile(host_pf)
            if "pruned" in p.stderr:
                fail("#5: a host prune judged a live run in another PID "
                     "namespace")
            if not [d for d in dirs if d.exists()]:
                fail("#5: the live namespaced run's staging was removed")
        finally:
            subprocess.run(["pkill", "-9", "-f", "psgen-stub"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ns.poll() is None:
                ns.kill()
            try:
                ns.wait(timeout=15)
            except Exception:
                pass
            for d in list(ns_shadow.glob(".psgen-*")) + list((ns_tmp / "t").glob(".psgen-*")):
                shutil.rmtree(d, ignore_errors=True)
            ns_tmp_pf = ns_tmp / "a.pid"
            if ns_tmp_pf.exists():
                ns_tmp_pf.unlink()

    # #5: the live marker is append-only. The injector rewrote it with only the
    # rows that reported a status record, which erased a stub that had recorded
    # itself but had not reported yet; the prune then deleted the directory
    # that stub still held open. A large --disk makes a row spend long enough
    # writing that stopping it leaves it recorded and unreported. The data goes
    # to the run's own directory and is removed with it: a multi-hundred-MiB
    # write into a shared tmpfs is not a side effect a check may leave behind.
    late_tmp = tmp / "late"
    late_tmp.mkdir()
    env = dict(os.environ, TMPDIR=str(late_tmp))
    pf = tmp / "late.pid"

    def marker_pids(root):
        out = set()
        for d in root.glob(".psgen-*"):
            f = d / ".psgen-live"
            if not f.exists():
                continue
            for line in f.read_text().splitlines():
                if line.strip():
                    out.add(int(line.split()[0]))
        return out

    import signal
    lp = subprocess.Popen([str(BIN), "inject", "-n", "3", "-s", "7", "-d", "60",
                           "--disk", "96", "--no-user", "--no-mem",
                           "--no-tty", "--no-threads", "--pidfile", str(pf)],
                          env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    ever: set = set()
    stopped: set = set()
    deadline = time.time() + 40
    while time.time() < deadline and lp.poll() is None:
        now = marker_pids(late_tmp)
        for pid in sorted(now - stopped):
            if stopped:
                break
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped.add(pid)
            except OSError:
                pass
        ever |= now
        time.sleep(0.005)
    lp.communicate(timeout=180)
    final = marker_pids(late_tmp)
    for pid in ever | final:
        try:
            os.kill(pid, signal.SIGCONT)
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    stop_pidfile(pf)
    # The data these stubs wrote is hundreds of MiB; remove it once they are
    # gone, so a check never leaves a full tmpfs behind.
    for d in list(late_tmp.glob(".psgen-*")):
        shutil.rmtree(d, ignore_errors=True)
    if not stopped:
        skip("#5 no stub could be stopped mid-record")
    else:
        erased = sorted(ever - final)
        if erased:
            fail(f"#5: the injector erased live stubs from the marker: {erased}")

    # #5: the prune must cover every shadow root this run can reach. The
    # default root is `<dir>/.psgen-stubs`, and a run started from a different
    # directory left its copy outside the scan. The leftover here is a dead
    # run's default root under the temporary directory the current run uses.
    default_root = tmp / "shared-tmp" / ".psgen-stubs"
    stale = default_root / ".psgen-999999-9000-0"
    stale.mkdir(parents=True)
    os.chmod(stale, 0o700)
    (stale / ".psgen-owner").write_text(f"999999 12345 0\n")
    (stale / ".psgen-live").write_text(f"999998 67890 0\n")
    (stale / "psgen-stub").write_text("x")
    shared_tmp = tmp / "shared-tmp"
    shared_tmp.mkdir(exist_ok=True)
    env = dict(os.environ, TMPDIR=str(shared_tmp))
    subprocess.run([str(BIN), "inject", "-n", "1", "-s", "3", "--no-user",
                    "--no-mem", "--no-tty", "--no-threads",
                    "--pidfile", str(tmp / "root.pid")],
                   cwd=str(tmp), env=env, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=180)
    stop_pidfile(tmp / "root.pid")
    if stale.exists():
        fail("#5: a dead run's default shadow root was never reclaimed")

    # #5: a staging directory owned by another uid is refused with a message
    # naming the uid, and is never deleted. Root sees no other owner, so this
    # needs an unprivileged caller.
    if can_root() and os.geteuid() != 0:
        foreign = shared_tmp / f".psgen-{os.getpid()}-42-0"
        subprocess.run(["sudo", "-n", "mkdir", "-m", "700", str(foreign)],
                       check=False)
        p = run(["inject", "-n", "1", "-s", "3", "--no-user", "--no-mem",
                 "--no-tty", "--no-threads", "--pidfile", str(tmp / "d.pid")],
                env=env, check=False)
        stop_pidfile(tmp / "d.pid")
        try:
            if not foreign.exists():
                fail("#5: a root-owned staging directory was deleted")
            if "owned by uid" not in p.stderr:
                fail("#5: a root-owned staging directory was kept silently")
        finally:
            subprocess.run(["sudo", "-n", "rm", "-rf", str(foreign)], check=False)
    else:
        skip("#5 the foreign-owner case needs an unprivileged caller")

    # #21: the answer must not depend on the caller's working directory. Two
    # corpus templates have relative commands, and they used to be resolved
    # against wherever `check` was run.
    here = run(["check", "--binaries", "-f", "mail"], check=False).stdout
    there = subprocess.run([str(BIN), "check", "--binaries", "-f", "mail"],
                           stdout=subprocess.PIPE, text=True, cwd=str(tmp),
                           timeout=120).stdout
    if here != there:
        fail("#21: check --binaries output depends on the caller's cwd")

    # #21: an absolute path that exists is present. `gen` maps the postfix
    # binaries to /usr/lib/postfix/sbin, and `inject` runs them from there.
    qmgr = Path("/usr/lib/postfix/sbin/qmgr")
    installed_dir = False
    if can_root():
        r = subprocess.run(["sudo", "-n", "mkdir", "-p", str(qmgr.parent)],
                           check=False)
        if r.returncode == 0:
            subprocess.run(
                ["sudo", "-n", "sh", "-c",
                 f"printf '#!/bin/sh\\nexit 0\\n' > {qmgr} && chmod 755 {qmgr}"],
                check=False)
            installed_dir = qmgr.is_file()
    if installed_dir:
        try:
            out = run(["check", "--binaries", "-f", "mail"], check=False).stdout
            if any(l.startswith("missing: qmgr") for l in out.splitlines()):
                fail("#21: a mapped binary that inject runs was reported missing")
        finally:
            subprocess.run(["sudo", "-n", "rm", "-f", str(qmgr)], check=False)
    else:
        skip("#21 installing the mapped path needs root")

    # #21: a directory is not an installed binary. `access(X_OK)` is true for a
    # searchable directory, so a directory at the mapped path was "found".
    bluetooth = Path("/usr/lib/bluetooth/bluetoothd")
    if can_root():
        r = subprocess.run(["sudo", "-n", "mkdir", "-p", str(bluetooth)],
                           check=False)
        if r.returncode == 0:
            try:
                out = run(["check", "--binaries"], check=False).stdout
                if not any(l.startswith("missing: /usr/lib/bluetooth/bluetoothd")
                           for l in out.splitlines()):
                    fail("#21: a directory was counted as an installed binary")
            finally:
                subprocess.run(["sudo", "-n", "rmdir", str(bluetooth)],
                               check=False)
    else:
        # The same rule without root: a directory on PATH named like a bare
        # template must not satisfy the lookup.
        # `next` is a bare-name template with no hardcoded location, so the
        # only way it can be "found" is a PATH lookup; a directory there must
        # not satisfy it.
        probe = tmp / "pathdir"
        probe.mkdir()
        (probe / "next").mkdir()
        out = subprocess.run(
            [str(BIN), "check", "--binaries"],
            stdout=subprocess.PIPE, text=True,
            env=dict(os.environ, PATH=f"{probe}:/usr/bin:/bin"),
            timeout=120).stdout
        if not any(l.startswith("missing: next") for l in out.splitlines()):
            fail("#21: a directory on PATH was counted as an installed binary")

    # #21: the totals must account for every row the flag expanded. The count
    # the resolver answers for must equal found + missing, and every expanded
    # row must be either checked or explicitly "not a binary" — a row silently
    # dropped by the resolver is what hid a name-mapped daemon.
    out = run(["check", "--binaries"], check=False).stdout
    got = {}
    for line in out.splitlines():
        for key in ("expanded", "binaries found", "binaries missing",
                    "binaries checked", "binaries not a binary"):
            if line.startswith(key + ":"):
                got[key] = int(line.split(":", 1)[1].split()[0])
    for key in ("expanded", "binaries found", "binaries missing",
                "binaries checked", "binaries not a binary"):
        if key not in got:
            fail(f"#21: check --binaries does not report {key!r}")
    if got["binaries found"] + got["binaries missing"] != got["binaries checked"]:
        fail(f"#21: found+missing != checked ({got})")
    if got["binaries checked"] + got["binaries not a binary"] != got["expanded"]:
        fail(f"#21: checked+not-a-binary != expanded ({got})")

    # #25 block 1: a stray config on fd 3 leaves a CLI invocation, for both wire
    # formats. `bf80156` reads the older one, so encoding only the new format
    # made the old bug unreachable rather than absent. The question is what the
    # process *became*: a stub renames its comm to the config's name, and a CLI
    # invocation keeps its own. The comparison is against this binary's own
    # name as read at test time, so a copy called something else still tests the
    # boundary rather than the filename, and the positive half (the process
    # really is the binary that was run) is asserted as well, so a process that
    # never started cannot pass.
    own_name = os.path.basename(str(BIN))[:15]
    bin_id = os.stat(str(BIN))

    def stayed_a_cli(label, fd, attack, extra_env=None):
        """The process kept its own identity and acted on nothing in the config.

        `/proc/PID/exe`'s object identity is compared with this binary, not with
        a path: a copy under another name, a shadow copy and the real binary are
        the same bytes, and a path comparison cannot tell an exec of `/bin/sh`
        from one of psgen when the shell exits before the first sample.
        """
        env = {"PSGEN_NONCE": nonce.decode()}
        if extra_env:
            env.update(extra_env)
        rc, exes, err, comm, _ = fd3_run_observe(fd, env)
        if comm != own_name:
            fail(f"#25: {label} turned the process into {comm!r}, not "
                 f"{own_name!r} (rc={rc}, err={err[:120]!r})")
        if attack.exists():
            shutil.rmtree(attack)
            fail(f"#25: {label} created the directory it named")
        for e in exes:
            if not e:
                continue
            st = os.stat(e)
            if (st.st_dev, st.st_ino) != (bin_id.st_dev, bin_id.st_ino):
                fail(f"#25: {label} executed {e}")
        if rc == 0:
            fail(f"#25: {label} was acted on")

    nonce = b"deadbeefdeadbeef"
    for magic, version in ((b"PGCFG023", 3), (b"PGCFG021", 2)):
        attack = tmp / f"attack-v{version}"
        blob = cfg_blob(magic, version, stage=1, comm=b"nginx", exe=b"",
                        cmd=b"sleep 120", user=b"root",
                        temp=str(attack).encode(), self_copy=b"/bin/sh",
                        nonce=nonce, disk_kb=0)
        cfg = tmp / f"stray-{version}.bin"
        cfg.write_bytes(blob)
        fd = os.open(str(cfg), os.O_RDWR)
        os.unlink(cfg)
        try:
            stayed_a_cli(f"a stray fd 3 config (v{version})", fd, attack)
        finally:
            os.close(fd)

    # #25 block 2: the descriptor is the trust boundary, not the nonce, the
    # owner or the mode. Every shape below is refused although it carries the
    # nonce the process was started with and names a directory to create. The
    # unlinked file and the `O_TMPFILE` descriptor are what an unprivileged
    # caller can obtain from an inode that already existed — a file root owns
    # can be opened, unlinked and passed on, and the result is root-owned and
    # anonymous — so ownership cannot be the proof. The `fchmod` case is why
    # the mode cannot be the discriminator: `fchmod(0600)` on an unsealable
    # memfd used to move it into a class that skipped the seal check.
    def unlinked(blob):
        cfg = tmp / "shape-unlinked.bin"
        cfg.write_bytes(blob)
        fd = os.open(str(cfg), os.O_RDWR)
        os.unlink(cfg)
        return fd

    def tmpfile(blob):
        path = tmp / "shape-tmpdir"
        path.mkdir(exist_ok=True)
        fd = os.open(str(path), os.O_RDWR | os.O_TMPFILE, 0o600)
        os.write(fd, blob)
        os.lseek(fd, 0, 0)
        return fd

    def chmod_plain_memfd(blob):
        fd = memfd_blob(blob, 0)
        if fd is not None and fd >= 0:
            os.fchmod(fd, 0o600)
        return fd

    for label, factory in (
            ("unsealed memfd", lambda b: memfd_blob(b, 1)),
            ("sealable memfd with no seals", lambda b: memfd_blob(b, 3)),
            ("unsealable memfd after fchmod 0600", chmod_plain_memfd),
            ("unlinked file", unlinked),
            ("O_TMPFILE descriptor", tmpfile)):
        attack, blob = forged_blob(tmp, nonce)
        try:
            fd = factory(blob)
        except (AttributeError, OSError):
            fd = None
        if fd is None or fd < 0:
            skip(f"#25 cannot create a {label}")
            continue
        try:
            stayed_a_cli(f"a forged config on a {label}", fd, attack)
        finally:
            os.close(fd)

    # #25 block 3: the control. The refusals prove nothing unless the accepted
    # shape is still acted on, so a *sealed* memfd carrying the same class of
    # payload must rename the process. It names this binary as `self_copy`, so
    # the exec stays a psgen process and the comm is the whole effect under
    # test; no other binary is involved.
    attack, blob = forged_blob(tmp, nonce)
    made = sealed_cfg_blob(blob)
    if made is None:
        skip("#25 cannot create a sealed memfd for the control")
    else:
        fd = made
        try:
            rc, exes, err, comm, _ = fd3_run_observe(
                fd, {"PSGEN_NONCE": nonce.decode()})
        finally:
            os.close(fd)
        if comm != "nginx":
            # Deliberately not a skip: a control that is refused means the
            # refusals above prove nothing about the boundary, so a green run
            # here would be the vacuity this block exists to prevent.
            fail(f"#25: a sealed memfd config was not acted on, so the "
                 f"refusals above prove nothing (comm={comm!r}, "
                 f"rc={rc}, err={err[:200]!r})")
        if attack.exists():
            shutil.rmtree(attack)
            fail(f"#25: a forged config on a {label} created the directory "
                 f"it named")
        for e in exes:
            if not e:
                continue
            st = os.stat(e)
            if (st.st_dev, st.st_ino) != (bin_id.st_dev, bin_id.st_ino):
                fail(f"#25: a forged config on a {label} executed {e}")
        if rc == 0:
            fail(f"#25: a forged config on a {label} was acted on")

    # #25: the control. The refusals prove nothing unless the accepted shape is
    # still acted on, so a *sealed* memfd carrying the same class of payload
    # must rename the process. It names this binary as `self_copy`, so the exec
    # stays a psgen process and the comm is the whole effect under test; no
    # other binary is involved.
    attack, blob = forged_blob(tmp, nonce)
    made = sealed_cfg_blob(blob)
    if made is None:
        skip("#25 cannot create a sealed memfd for the control")
    else:
        fd = made
        try:
            rc, exes, err, comm, _ = fd3_run_observe(
                fd, {"PSGEN_NONCE": nonce.decode()})
        finally:
            os.close(fd)
        if comm != "nginx":
            fail(f"#25: a sealed memfd config was not acted on, so the "
                 f"refusals above prove nothing (comm={comm!r}, "
                 f"rc={rc}, err={err[:200]!r})")
        if attack.exists():
            shutil.rmtree(attack)
            fail("#25: the control created the directory it named")

    # #14: `load --disk-util` must fall back when getrandom is denied, like
    # every other caller. It used to return None and blame the disk.
    helper = seccomp_helper()
    if helper is not None:
        p = subprocess.run([str(helper), "getrandom", str(BIN), "load",
                            "--disk-util", "1", "--duration", "1"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=180,
                           env=dict(os.environ, TMPDIR=str(tmp)))
        if p.returncode != 0:
            fail(f"#14: load --disk-util under a getrandom denial failed: "
                 f"rc={p.returncode} {p.stderr.strip()[:200]!r}")
        if "load disk" not in p.stdout:
            fail(f"#14: load --disk-util under a getrandom denial printed "
                 f"{p.stdout.strip()[:120]!r}")
    else:
        skip("#14 the seccomp helper is unavailable, so a denied getrandom "
             "cannot be injected")

    # #14/#23: a `TMPDIR` that cannot be measured must be refused, not waved
    # through. The free-space guard exists so `load` cannot fill the filesystem
    # it runs on; a missing directory skipped it and then blamed the disk.
    p = subprocess.run(
        [str(BIN), "load", "--disk-util", "9000"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120,
        env=dict(os.environ, TMPDIR=str(tmp / "no-such-dir")))
    if p.returncode != 1:
        fail(f"#23: load with an unmeasurable TMPDIR exited {p.returncode}")
    if "cannot measure" not in p.stderr and "exceeds the free space" not in p.stderr:
        fail(f"#23: load with an unmeasurable TMPDIR blamed something else: "
             f"{p.stderr.strip()[:160]!r}")

    # #20: `--create-users --dry-run` must name the identity the run would
    # use, and must not advise the flag the caller already passed. A shim
    # `useradd` on PATH is the whole dependency, so this needs no root.
    shim = tmp / "useradd-shim"
    shim.mkdir(exist_ok=True)
    cfg_tmp = tmp / "cfg-tmp"
    cfg_tmp.mkdir()
    logged = tmp / "useradd.log"
    (shim / "useradd").write_text(
        "#!/bin/sh\n"
        f"echo \"$@\" >> {logged}\n"
        "case \"$*\" in\n"
        "  *--user-group*) echo 'useradd: group haproxy exists' >&2; exit 9;;\n"
        "esac\n"
        "exit 1\n")
    (shim / "useradd").chmod(0o755)
    p = subprocess.run(
        # The mail family names users that a minimal host does not have
        # (`dovecot`, `postfix`), so the missing-user path is reached without
        # creating anything.
        [str(BIN), "inject", "-f", "mail", "-n", "30", "-s", "8", "--user",
         "--create-users", "--no-exe", "--no-mem", "--no-tty", "--no-threads",
         "--dry-run", "--plan"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=dict(os.environ, PATH=f"{shim}:/usr/bin:/bin",
                 TMPDIR=str(cfg_tmp)), timeout=180)
    if "pass --create-users" in p.stderr:
        fail("#20: --create-users --dry-run advised the flag it was given")
    if "would create" not in p.stderr:
        fail(f"#20: --create-users --dry-run named no identity: "
             f"{p.stderr.strip()[:200]!r}")
    # A dry run creates nothing.
    if logged.exists() and logged.read_text().strip():
        fail("#20: --create-users --dry-run ran useradd")

    # #20: the repair must offer an attempt that works when the group already
    # exists, every attempt must be tried when all of them fail, and a create
    # that succeeds without NSS seeing the account must not be retried. These
    # are invariants of the repair rather than deltas against `ddc6f0c`, which
    # already had all three; the checks keep them from regressing.
    logged.write_text("")
    (shim / "useradd").write_text(
        "#!/bin/sh\n"
        f"echo \"$@\" >> {logged}\n"
        "exit 1\n")
    (shim / "useradd").chmod(0o755)
    # `sudo` resets PATH and TMPDIR, so the shim and the private scratch
    # directory have to be placed after it rather than in `env=`.
    p = subprocess.run(
        as_root(["env", f"PATH={shim}:/usr/bin:/bin", f"TMPDIR={cfg_tmp}",
                 BIN, "inject", "-f", "mail", "-n", "30", "-s", "8",
                 "--create-users", "--user", "--no-exe", "--no-mem",
                 "--no-tty", "--no-threads", "--pidfile", str(tmp / "u.pid")]),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=180)
    stop_pidfile(tmp / "u.pid")
    if can_root():
        runs = [l for l in logged.read_text().splitlines() if l.strip()]
        if not runs:
            fail("#20: --create-users as root never invoked useradd")
        # Every attempt is tried when all of them fail.
        if len(runs) < 2:
            fail(f"#20: only {len(runs)} useradd attempt was tried, so the "
                 f"group-only host cannot be repaired")
        if not any("--gid" in r for r in runs):
            fail("#20: no attempt used an existing group, so a host with the "
                 "group but not the user cannot be repaired")

    # #20: a useradd that succeeds but is invisible to NSS must not be retried.
    logged.write_text("")
    (shim / "useradd").write_text(
        "#!/bin/sh\n"
        f"echo \"$@\" >> {logged}\n"
        "exit 0\n")
    (shim / "useradd").chmod(0o755)
    if can_root():
        subprocess.run(
            as_root(["env", f"PATH={shim}:/usr/bin:/bin", f"TMPDIR={cfg_tmp}",
                     BIN, "inject", "-f", "mail", "-n", "30", "-s", "8",
                     "--create-users", "--user", "--no-exe", "--no-mem",
                     "--no-tty", "--no-threads",
                     "--pidfile", str(tmp / "v.pid")]),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=180)
        stop_pidfile(tmp / "v.pid")
        # One call per distinct missing name: a family names several users,
        # but the same name must never be retried after its create succeeded,
        # because the second attempt can only answer "already exists" and hide
        # the first error.
        runs = [l for l in logged.read_text().splitlines() if l.strip()]
        by_name: dict[str, int] = {}
        for r in runs:
            name = r.split("--", 1)[-1].strip() if "--" in r else r.split()[-1]
            by_name[name] = by_name.get(name, 0) + 1
        retried = {n: c for n, c in by_name.items() if c > 1}
        if retried:
            fail(f"#20: a useradd that succeeded was retried: {retried}")
    else:
        skip("#20: the --create-users checks need root or passwordless sudo")

def session_and_tty(pid):
    """`(sid, tty_nr)` from `/proc/PID/stat`, or None when the row is gone.

    The field indices are `proc(5)`'s: after the parenthesised comm, index 3 is
    the session id and index 4 the terminal device.
    """
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    fields = raw[raw.rindex(")") + 2:].split()
    return int(fields[3]), int(fields[4])


def check_session_detach(tmp: Path) -> None:
    """#3: a row without a tty is not in the caller's session or on its tty.

    `--tty` (the default) only lets a template that carries `F_TTY` keep the pty
    the stub opens for it. Every other row is a daemon, and a daemon does not
    share a session or a controlling terminal with the shell that started it.
    The comparison is against the caller's *own* session id and terminal device,
    not against a rendered column, so a rendering change cannot satisfy it.
    """
    if not can_pty():
        skip("#3: a pty is needed to tell a tty row from a leak")
        return
    caller_sid = os.getsid(0)
    caller = session_and_tty(os.getpid())
    caller_tty = caller[1] if caller else 0
    scratch = Path(tmp) / "t"
    scratch.mkdir(exist_ok=True)
    env = dict(os.environ, TMPDIR=str(scratch))
    pf = Path(tmp) / "sess.pid"
    try:
        p = run(["inject", "-f", "mon", "-n", "12", "-s", "3", "-d", "60",
                 "--no-user", "--no-mem", "--pidfile", str(pf), "-q"],
                env=env, check=False)
        if p.returncode != 0:
            fail(f"#3: inject failed: {p.stderr.strip()[:160]}")
        pids = read_pids(pf)
        if not pids:
            fail("#3: inject recorded no rows")
        leaked = []
        for pid in pids:
            got = session_and_tty(pid)
            if got is None:
                continue
            sid, tty = got
            if sid == caller_sid:
                leaked.append((pid, "session"))
            elif tty != 0 and tty == caller_tty:
                leaked.append((pid, "tty"))
        if leaked:
            fail(f"#3: {len(leaked)} injected rows share the caller's session "
                 f"or terminal (sid={caller_sid}, tty={caller_tty}): "
                 f"{leaked[:4]}")
    finally:
        stop_pidfile(pf)


def check_prune_from_another_cwd(tmp: Path) -> None:
    """#5: a run's shadow copy is not left in a directory no other run scans.

    The default shadow root was `<cwd>/.psgen-stubs`. A run's working directory
    is not reproducible by any later run — a cage or container gives each run its
    own — so nothing could ever name that root again, and every shadow-tier run
    leaked a copy of the binary. The property that closes it is that the default
    root does not depend on the working directory: a run from anywhere writes to
    the one root every run of this caller shares.

    The check reaches the shadow tier by denying `unshare` (the bind tier needs
    no copy), injects from two different directories, and requires that neither
    left a default root behind while the shared one received both.
    """
    helper = seccomp_helper()
    if helper is None:
        skip("#5: a C compiler is needed to reach the shadow tier")
        return
    root = Path(tmp) / "cwd"
    shutil.rmtree(root, ignore_errors=True)
    a = root / "a"
    b = root / "b"
    a.mkdir(parents=True)
    b.mkdir()
    shared = root / "t"
    shared.mkdir()
    env = dict(os.environ, TMPDIR=str(shared))

    def inject(cwd: Path, count: int, pf: Path):
        return subprocess.run(
            [str(helper), "unshare", str(BIN), "inject", "-n", str(count),
             "-s", "7", "--no-user", "--no-mem", "--no-tty", "--no-threads",
             "--pidfile", str(pf), "-q"],
            cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=200)

    try:
        first = inject(a, 2, a / "a.pid")
        if first.returncode != 0:
            skip(f"#5: a shadow-tier run failed: {first.stderr.strip()[:160]}")
            return
        # Read the roots before the second run, which reclaims a dead run's
        # directories: a fixed build removes the first run's copy here, so
        # looking afterwards cannot tell "never written" from "already pruned".
        left_a = list(a.glob(".psgen-stubs/.psgen-*"))
        into_shared = list(shared.glob(".psgen-stubs/.psgen-*"))
        second = inject(b, 1, b / "b.pid")
        left_b = list(b.glob(".psgen-stubs/.psgen-*"))
        for pf in (a / "a.pid", b / "b.pid"):
            subprocess.run([str(BIN), "stop", "--pidfile", str(pf)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    if second.returncode != 0:
        fail(f"#5: the second run failed: {second.stderr.strip()[:160]}")
    stray = left_a + left_b
    if stray:
        fail(f"#5: a run wrote its shadow copy into a root no other run scans, "
             f"so it can never be reclaimed: {[str(p) for p in stray]}")
    if not into_shared:
        fail("#5: no shadow-tier run wrote into the shared default root, so the "
             "check never reached the copy it is about")


def check_wait_reclaims_unreported(tmp: Path) -> None:
    """#5: `--wait` removes the staging of a stub that never reported.

    The rows that report a status record are known to the injector; a stub that
    is frozen, or that calls `setsid` and leaves the root's process group before
    its record lands, is known only to the live marker. `--wait` used the marker
    to decide *whether* to remove a directory but the reported PIDs to decide
    what to kill, so a stub outside that list kept both itself and its directory
    alive until something else stopped it.

    The check freezes rows that detach from their root, waits for `--wait` to
    return, and requires that every frozen row is gone and that no staging
    directory is left. A refusal to freeze anything is a failure, not a skip:
    the check exists to prove the cleanup reaches an unreported stub, so a run
    that never produced one has not tested it.
    """
    root = Path(tmp) / "wait"
    shutil.rmtree(root, ignore_errors=True)
    (root / "t").mkdir(parents=True)
    (root / "shadow").mkdir()
    env = dict(os.environ, TMPDIR=str(root / "t"))
    pf = root / "a.pid"
    me = os.getpid()
    proc = subprocess.Popen(
        [str(BIN), "inject", "-f", "sys", "-n", "30", "-s", "5", "-d", "5",
         "--disk", "24", "--no-user", "--no-mem",
         "--shadow-dir", str(root / "shadow"), "--pidfile", str(pf),
         "--wait", "-q"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def marker_pids() -> set:
        """Every PID the run's live markers name that still has a `/proc` entry.

        A PID with no entry is already gone, so it need not be looked at again;
        filtering here keeps the polling loop from re-reading the same marker
        file hundreds of times a second.
        """
        out = set()
        for d in (list((root / "t").glob(".psgen-*"))
                  + list((root / "shadow").glob(".psgen-*"))):
            f = d / ".psgen-live"
            try:
                text = f.read_text()
            except OSError:
                continue
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    out.add(int(line.split()[0]))
                except ValueError:
                    continue
        return {pid for pid in out if Path(f"/proc/{pid}").exists()}

    frozen = set()
    deadline = time.time() + 45
    try:
        while time.time() < deadline and proc.poll() is None:
            for pid in sorted(marker_pids() - frozen):
                try:
                    fields = Path(f"/proc/{pid}/stat").read_text()
                except OSError:
                    continue
                f = fields[fields.rindex(")") + 2:].split()
                sid, ppid = int(f[3]), int(f[1])
                # A child row that detached into its own session. A root is a
                # direct child of the injector, and freezing a root would stop
                # its subtree from existing rather than leave one worker
                # unreported.
                if sid == pid and ppid != proc.pid and pid != me:
                    try:
                        os.kill(pid, signal.SIGSTOP)
                        frozen.add(pid)
                    except OSError:
                        pass
            time.sleep(0.002)
        proc.communicate(timeout=300)
        # A frozen process cannot report after `--wait` has killed it, but its
        # exit is still asynchronous: give the kernel the same bounded window
        # `stop` allows before judging a signal.
        for _ in range(100):
            survivors = [pid for pid in frozen if alive(pid)]
            if not survivors:
                break
            time.sleep(0.02)
        survivors = [pid for pid in frozen if alive(pid)]
        left = (list((root / "t").glob(".psgen-*"))
                + list((root / "shadow").glob(".psgen-*")))
    finally:
        for pid in frozen:
            try:
                os.kill(pid, signal.SIGCONT)
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        shutil.rmtree(root, ignore_errors=True)
    if not frozen:
        fail("#5: no detached stub could be frozen, so --wait's cleanup of an "
             "unreported stub was not exercised")
    if survivors:
        fail(f"#5: --wait left {len(survivors)} frozen stub(s) alive: "
             f"{survivors[:4]}")
    if left:
        fail(f"#5: --wait left {len(left)} staging director(ies) behind after "
             f"the stub was gone: {[str(p) for p in left][:4]}")


def check_stop_refuses_mountpoint(tmp: Path) -> None:
    """#25/DESIGN §7: `stop` never recurses through a bind mount.

    A bind mount over a `.psgen-N-N-N` name reports the mounted filesystem's
    metadata, so a root-owned `0700` directory passes every ownership, mode and
    name arm. `remove_dir_all` then deletes the files *behind* the mount, which
    the caller never owned. A staging directory this tool created is never a
    mount point, so refusing one costs nothing legitimate.
    """
    if not can_root() or os.geteuid() == 0:
        skip("#25: the bind-mount check needs an unprivileged caller with sudo")
        return
    root = Path(tmp) / "mount"
    subprocess.run(["sudo", "-n", "rm", "-rf", str(root)], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    real = root / "real"
    real.mkdir(parents=True)
    (real / "rootfile").write_text("keep me\n")
    target = root / f".psgen-{os.getpid()}-0-0"
    target.mkdir()
    subprocess.run(["sudo", "-n", "chown", "-R", "root:root", str(real)], check=True)
    subprocess.run(["sudo", "-n", "chmod", "700", str(real)], check=True)
    mounted = False
    try:
        m = subprocess.run(["sudo", "-n", "mount", "--bind", str(real), str(target)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if m.returncode != 0:
            skip(f"#25: cannot create a bind mount: {m.stderr.strip()[:120]}")
            return
        mounted = True
        pf = root / "forged.pid"
        pf.write_text(f"# psgen {VERSION} boot {boot_id()}\n# temp {target}\n")
        p = subprocess.run(as_root([BIN, "stop", "--pidfile", str(pf)]),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=120)
        left = subprocess.run(["sudo", "-n", "ls", str(real)], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True).stdout.split()
        if "rootfile" not in left:
            fail(f"#25: stop deleted the contents of a bind-mounted directory "
                 f"({p.stdout.strip()!r} {p.stderr.strip()[:120]!r})")
    finally:
        if mounted:
            subprocess.run(["sudo", "-n", "umount", "-l", str(target)], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "-n", "rm", "-rf", str(root)], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check_new_gates(tmp: Path) -> None:
    """The gates this branch adds: each must be able to fail.

    Registered here rather than in `main()` one by one, so the shared dispatch
    stays close to its original shape.
    """
    check_skip_helper()
    check_pty_probe()
    check_inject_table_matches_ps(tmp)
    check_can_pty_fail_closed(tmp)
    check_argv_bytes()
    check_matrix_reaps()



def check_dry_run_shape():
    """The bare `--dry-run` keeps its own two-column contract.

    The matrix compares `inject` against `--dry-run --plan`, because a preview
    that cannot print a value cannot prove the flag moved it. The plain
    preview is a separate contract: `bench/measure.py` splits it on a tab and
    reads the command, so it must stay `user<TAB>cmd` with no header, exactly
    one line per planned stub, and `--plan` must not have replaced it.
    """
    p = run(["inject", "--dry-run", "-n", "4", "-s", "7"])
    lines = p.stdout.splitlines()
    if len(lines) != 4:
        fail(f"#12: inject --dry-run -n 4 printed {len(lines)} lines, wanted 4")
    for line in lines:
        if "\t" not in line:
            fail(f"#12: inject --dry-run printed a line without a tab: {line!r}")
        user, cmd = line.split("\t", 1)
        if not user or not cmd:
            fail(f"#12: inject --dry-run printed an empty column: {line!r}")
    if any(line.startswith("tier ") or line.startswith("row ") for line in lines):
        fail("#12: the bare --dry-run printed the plan instead of its two columns")

    # The plan is what the matrix reads, so each field it compares has to be
    # there on every row.
    plan = run(["inject", "--dry-run", "--plan", "-n", "4", "-s", "7"]).stdout
    if not plan.startswith("tier "):
        fail("#12: inject --dry-run --plan does not lead with the exe tier")
    rows = [line for line in plan.splitlines() if line.startswith("row ")]
    if len(rows) != 4:
        fail(f"#12: the plan described {len(rows)} rows, wanted 4")
    for field in ("user=", "vsz=", "rss=", "cpu=", "tty=", "threads=", "exe="):
        if any(field not in row for row in rows):
            fail(f"#12: the plan rows omit {field}, so the matrix cannot read it")


def check_matrix_reaps():
    """`check_option_matrix` leaves no process behind.

    It used to spawn a real `inject` and never stop it. A matrix pass is run
    here in a subprocess, and every process it leaves parented to that
    subprocess is named: a stub calls `setsid`, so the injector's exit orphans
    it and only a subreaper can see it again. `become_subreaper()` makes this
    harness that reaper, and `reap_descendants` proves the reaper works before
    the delta is trusted.

    The matrix is invoked directly rather than through the whole file, so this
    costs one matrix pass and no other check.
    """
    if not become_subreaper():
        skip_or_fail("prctl(PR_SET_CHILD_SUBREAPER) is unavailable, so a "
                     "leaked stub cannot be found again")
        return

    # A session leader in its own group, which is the shape of an injected
    # stub: killing the injector's group cannot reach it.
    probe = subprocess.Popen(["sleep", "60"], start_new_session=True)
    try:
        time.sleep(0.1)
        if probe.pid not in descendants(os.getpid()):
            fail(f"#9: session-leader child {probe.pid} is not visible as a "
                 f"descendant, so a leaked stub could not be found")
        survivors = reap_descendants(os.getpid())
        if survivors:
            fail(f"#9: the reaper left {survivors} alive")
        if alive(probe.pid):
            fail(f"#9: the reaper left the session-leader child {probe.pid} "
                 f"alive")
    finally:
        probe.kill()
        probe.wait(timeout=30)

    # The targeted control: the reaper must remove a leak that nothing else
    # can. A stub calls `setsid`, so it is in no process group the cell's
    # caller can name, and only `reap_descendants` can find it. A shim that
    # leaves exactly that shape proves the reaper ran, which the whole-matrix
    # delta cannot: every cell's product stops its own stubs, so a matrix with
    # its reaping deleted leaves nothing behind to notice.
    leak_dir = Path(tempfile.mkdtemp(prefix="psgen-reap-"))
    lookup = leak_dir / "pid"
    shim = leak_dir / "psgen"
    shim.write_text("#!/bin/sh\n"
                    "setsid sleep 120 &\n"
                    f"echo $! > {lookup}\n"
                    "exit 0\n")
    shim.chmod(0o755)
    saved_bin = globals()["BIN"]
    globals()["BIN"] = shim
    leaked = None
    try:
        matrix_run(["bogus-subcommand"], timeout=30)
        deadline = time.monotonic() + 5.0
        while not lookup.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if not lookup.exists():
            fail("#9: the leak shim did not record its setsid child, so the "
                 "reaper cannot be shown to run")
        leaked = int(lookup.read_text().strip())
        if alive(leaked):
            fail(f"#9: matrix_run left the setsid child {leaked} alive, so its "
                 f"own reaping is gone")
    finally:
        globals()["BIN"] = saved_bin
        if leaked is not None:
            try:
                os.kill(leaked, signal.SIGKILL)
            except OSError:
                pass
        shutil.rmtree(leak_dir, ignore_errors=True)

    script = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('inv', {str(Path(__file__))!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "m.become_subreaper()\n"
        "import os, time\n"
        "before = set(m.descendants(os.getpid()))\n"
        "try:\n"
        "    m.check_option_matrix()\n"
        "except SystemExit as e:\n"
        "    print('MATRIX_EXIT', e.code)\n"
        "time.sleep(0.5)\n"
        "print('LEFTOVER', sorted(set(m.descendants(os.getpid())) - before))\n"
    )
    env = dict(os.environ)
    env.pop("PSGEN_REQUIRE_ALL", None)
    # A matrix cell is quick, but a matrix pass is not: 180 cells at up to a
    # second each, and `--wait` cells really block.
    p = subprocess.run([sys.executable, "-c", script], capture_output=True,
                       text=True, timeout=1800, env=env)
    leftovers = [line for line in p.stdout.splitlines()
                 if line.startswith("LEFTOVER")]
    if not leftovers:
        fail(f"#9: the matrix-reaping probe printed no result: "
             f"{p.stdout.strip()[-200:]!r} {p.stderr.strip()[-200:]!r}")
    leftover = leftovers[-1].split(None, 1)[1]
    if leftover.strip() not in ("[]", ""):
        fail(f"#9: check_option_matrix left processes behind: {leftover}")

def check_skip_sites():
    """Only `skip()` may decide to skip. A bare `print("SKIP")` is not a gate.

    `skip()` is the one place that reads PSGEN_REQUIRE_ALL: with CI's value set
    it fails with the reason, so a capability the runner lacks cannot pass a
    check quietly. A `print("SKIP: ...")` next to it looks the same in a log
    and is invisible to CI, which is how nine gates passed on a binary that
    lacked the defect they named. Two things are asserted:

    - no `print` whose text starts with `SKIP` exists outside `skip()`;
    - `skip()` itself consults REQUIRE_ALL, so the one door cannot be opened
      by deleting its guard. The two together are the durable fix: routing a
      site through `skip()` is only worth something if `skip()` still fails.
    """
    source = Path(__file__).read_text()
    tree = ast.parse(source)
    funcs = [(n.lineno, n.end_lineno, n.name) for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef)]

    def owner(line: int) -> str:
        cands = [f for f in funcs if f[0] <= line <= f[1]]
        return min(cands, key=lambda f: f[1] - f[0])[2] if cands else "<module>"

    def is_skip_text(node) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.startswith("SKIP")
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value.startswith("SKIP")
        return False

    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "print"):
            continue
        if not any(is_skip_text(a) for a in node.args):
            continue
        where = owner(node.lineno)
        if where != "skip":
            bad.append(f"{where}() at line {node.lineno}")
    if bad:
        fail("a bare print(\"SKIP\") bypasses skip(), so PSGEN_REQUIRE_ALL "
             "cannot see it: " + ", ".join(bad))

    # `skip()` must still branch on the requirement. A skip door that always
    # prints is the same defect one level down, and the scan above cannot see
    # it because the print is legitimately inside `skip`. The guard may read
    # the constant directly or call the predicate, so both spellings count.
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "skip")
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    if "fail" not in calls:
        fail("skip() never calls fail(), so PSGEN_REQUIRE_ALL cannot turn a "
             "missing capability into a failure")
    if not ({"require_all", "REQUIRE_ALL"} & (names | calls)):
        fail("skip() never reads the requirement, so every missing capability "
             "prints SKIP and CI cannot tell it from a pass")


# Each entry: the check, the capability predicate it needs, the value that
# makes the capability absent, whether the check takes a temporary directory,
# and a substring of the reason `skip()` must be given. The substring is what
# stops the meta-test being satisfied by a check that fails for an unrelated
# reason after the capability is gone: the door has to name the capability.
SKIP_NEEDS = [
    ("check_option_surface", "can_root", "False", False,
     "passwordless sudo"),
    ("check_injection", "can_pty", "False", False, "pty"),
    ("check_live_matches_ps", "non_utc_zone", "None", False, "non-UTC"),
    ("check_live_reference_columns", "non_utc_zone", "None", False, "UTC"),
    ("check_security_markers", "can_root", "False", True, "unprivileged"),
    ("check_matrix_reaps", "become_subreaper", "False", False, "subreaper"),
]


def check_skip_needs():
    """Every capability a check needs must fail under PSGEN_REQUIRE_ALL.

    A check that skips when a capability is absent is only as good as the
    place it skips through. Forcing the predicate false and setting
    PSGEN_REQUIRE_ALL=1 asks the one question CI asks of a runner without that
    capability: does the check fail and name it, or does it pass?
    """
    for check, predicate, value, takes_tmp, reason in SKIP_NEEDS:
        patch = f"m.{predicate} = lambda *a, **k: {value}"
        call = f"m.{check}(pathlib.Path(_d))" if takes_tmp else f"m.{check}()"
        script = (
            "import importlib.util, pathlib, sys, tempfile\n"
            f"spec = importlib.util.spec_from_file_location('inv', {str(Path(__file__))!r})\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            f"{patch}\n"
            # A real check spawned here stages under TMPDIR and may leave a
            # stub's directory behind when it skips. Each child gets its own
            # scratch root, which the parent removes below, so the meta-test
            # does not write into the caller's temporary directory.
            "_root = pathlib.Path(tempfile.mkdtemp(prefix='psgen-need-'))\n"
            "import os\n"
            "os.environ['TMPDIR'] = str(_root)\n"
            "tempfile.tempdir = str(_root)\n"
            "_d = _root / 'work'\n"
            "_d.mkdir()\n"
            f"{call}\n"
        )
        root = Path(tempfile.mkdtemp(prefix="psgen-need-"))
        env = dict(os.environ, PSGEN_REQUIRE_ALL="1", TMPDIR=str(root))
        p = subprocess.run([sys.executable, "-c", script], capture_output=True,
                           text=True, timeout=1800, env=env)
        if p.returncode == 0:
            shutil.rmtree(root, ignore_errors=True)
            fail(f"{check} passed with `{predicate}` forced absent under "
                 f"PSGEN_REQUIRE_ALL=1; its skip door bypasses skip()")
        if "required capability missing" not in p.stderr:
            shutil.rmtree(root, ignore_errors=True)
            fail(f"{check} failed for a reason other than a named capability "
                 f"with `{predicate}` absent: {p.stderr.strip()[-200:]!r}")
        if reason.lower() not in p.stderr.lower():
            shutil.rmtree(root, ignore_errors=True)
            fail(f"{check} failed for a capability other than the one forced "
                 f"absent; wanted {reason!r} in {p.stderr.strip()[-200:]!r}")
        if "SKIP:" in p.stderr:
            shutil.rmtree(root, ignore_errors=True)
            fail(f"{check} printed SKIP under PSGEN_REQUIRE_ALL=1 with "
                 f"`{predicate}` absent: {p.stderr.strip()[-200:]!r}")
        # With PSGEN_REQUIRE_ALL=1 set, the requirement is what failed: the
        # negative control below drives the same predicate without it.
        env["PSGEN_REQUIRE_ALL"] = "0"
        p = subprocess.run([sys.executable, "-c", script], capture_output=True,
                           text=True, timeout=1800, env=env)
        shutil.rmtree(root, ignore_errors=True)
        if p.returncode != 0:
            fail(f"{check} failed with `{predicate}` absent and "
                 f"PSGEN_REQUIRE_ALL=0, so it does not skip cleanly either: "
                 f"{p.stderr.strip()[-200:]!r}")
        if f"SKIP: " not in p.stderr or reason.lower() not in p.stderr.lower():
            fail(f"{check} did not print its skip reason with `{predicate}` "
                 f"absent and PSGEN_REQUIRE_ALL=0: {p.stderr.strip()[-200:]!r}")


def stub_binary(dst: Path, kind: str) -> Path:
    """A binary that is not psgen, of the shape `kind` describes.

    `silent` prints nothing and succeeds, so a check that treats "no output"
    as "nothing to check" passes it. `failing` refuses every invocation, which
    a check must not turn into a skip. `echo` answers the three questions a
    shape-only check asks: the version string, the help text and a `ps aux`
    page, so only a check that compares the *content* can fail it.
    """
    dst.mkdir(parents=True, exist_ok=True)
    path = dst / kind
    if kind == "silent":
        body = "#!/bin/sh\nexit 0\n"
    elif kind == "failing":
        body = "#!/bin/sh\nexit 1\n"
    elif kind == "echo":
        page = (
            f"{HEADER}\n"
            "root           1  0.0  0.1  28080 15044 ?        Ss   16:53   1:57 /sbin/init\n"
            "root         420  0.0  0.0  12044  6688 ?        Ss   16:53   0:00 /usr/sbin/sshd -D\n"
            "herdr        777  0.1  0.0  10712  6616 pts/0    S+   19:07   0:02 psgen table\n")
        body = (
            "#!/bin/sh\n"
            f"case \"$1\" in\n"
            f"  --version|version) echo 'psgen {VERSION}';;\n"
            "  --help|help) echo 'psgen inject';"
            " echo 'psgen doctor'; echo 'psgen log'; echo 'psgen load';;\n"
            "  *)\n"
            "    cat <<'EOF'\n"
            f"{page}"
            "EOF\n"
            "    ;;\n"
            "esac\n"
            "exit 0\n")
    else:
        raise SystemExit(f"stub_binary: unknown kind {kind!r}")
    path.write_text(body)
    path.chmod(0o755)
    return path


# Checks whose whole subject is product output, so a binary that is not psgen
# must fail them. Each is cheap against a stub (it fails on its first
# assertion), and between them they cover the CLI, the table renderer, the
# corpus, the plausibility property, the option surface, the preview contract
# and `stop`.
STUB_GATED = ("check_cli", "check_table", "check_corpus", "check_plausibility",
              "check_option_surface", "check_dry_run_shape", "check_stop")


def check_stub_binaries(tmp):
    """The suite must fail against a binary that is not psgen.

    A green suite is only evidence if it would be red for a binary that does
    not do the job. Three shapes cover the ways a gate can be fooled: no
    output at all, a refusal a check might read as "not applicable", and
    output that looks plausible enough to satisfy a shape assertion.
    """
    for kind in ("silent", "failing", "echo"):
        stub = stub_binary(Path(tmp) / f"stub-{kind}", kind)
        for check in STUB_GATED:
            script = (
                "import importlib.util, sys\n"
                f"spec = importlib.util.spec_from_file_location('inv', {str(Path(__file__))!r})\n"
                "m = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(m)\n"
                f"m.{check}()\n"
            )
            # The stub is the binary for the child only: this process keeps
            # the real one, so the meta-test never measures itself. The child
            # also gets a scratch root of its own, removed afterwards, so a
            # check that writes a pidfile or a copy cannot litter the suite's.
            own = Path(tmp) / f"run-{kind}-{check}"
            own.mkdir(parents=True, exist_ok=True)
            env = dict(os.environ, PSGEN_BIN=str(stub), TMPDIR=str(own))
            env.pop("PSGEN_REQUIRE_ALL", None)
            try:
                p = subprocess.run([sys.executable, "-c", script],
                                   capture_output=True, text=True, timeout=600,
                                   env=env)
            finally:
                shutil.rmtree(own, ignore_errors=True)
            if p.returncode == 0:
                fail(f"{check} passed a binary that is not psgen ({kind}), so "
                     f"it does not measure the product")


def check_meta_tests(tmp: Path) -> None:
    """The gates that hold the other gates to their contract.

    Registered from one helper so `main()` stays a list of checks, and so the
    file has one place that says what an unexercised check looks like.
    """
    check_skip_sites()
    check_skip_needs()
    check_stub_binaries(tmp)


def suite_cleanup() -> None:
    """Leave nothing behind when the suite stops, however it stops.

    A check that dies mid-run has already spawned stubs and made staging
    directories, and the exception propagates past that check's own `finally`.
    The abort is the failure the operator sees; a suite that also leaked a
    hundred processes and a temporary tree is a second one. This runs from
    `main()`'s `finally`, so a `SystemExit` from `fail()` and an unexpected
    exception both reach it.
    """
    become_subreaper()
    reap_descendants(os.getpid())
    # A pidfile a check wrote names live stubs; without the `stop` the check
    # would have run, they are exactly what the abort left behind.
    for path in list(_LIVE_PIDFILES):
        try:
            stop_pidfile(path)
        except Exception:
            pass
    _LIVE_PIDFILES.clear()
    # The seccomp launcher is built once into a scratch directory. It is a
    # build artefact, not a check's data, so nothing else removes it.
    if _SECCOMP_HELPER is not None:
        shutil.rmtree(_SECCOMP_HELPER.parent, ignore_errors=True)


def main() -> int:
    if not BIN.exists():
        fail(f"{BIN} missing, run cargo build --release")
    # Become the reaper before any check spawns anything. A stub calls
    # `setsid` and the injector exits, so the stub is orphaned; without this,
    # it is adopted by PID 1 and `reap_descendants` cannot see it. Doing it
    # here rather than in one check means every check's leak is reachable,
    # including one the suite aborts out of.
    become_subreaper()
    try:
        _main_checks()
    finally:
        try:
            suite_cleanup()
        except Exception as e:  # cleanup must not replace the real failure
            print(f"WARN: cleanup failed: {e}", file=sys.stderr)
    print("invariants: ok")
    return 0


def _main_checks() -> None:
    check_cli()
    check_list()
    check_table()
    check_live()
    check_corpus()
    check_unit()
    check_doctor()
    check_log()
    check_load()
    check_injection()
    check_inject_flags()
    check_stop()
    check_counts()
    check_regressions()
    check_regressions2_tmp()
    check_plausibility()
    check_generator_sweep()
    check_live_matches_ps()
    check_live_reference_columns()
    check_option_matrix()
    check_dry_run_shape()
    check_option_surface()
    check_stop_identity()
    check_stop_counts_processes()
    check_stop_zombie_group()
    check_option_self_check()
    check_dry_run_identity()
    with tempfile.TemporaryDirectory(prefix="psgen-review-") as tmp:
        check_review_fixes(Path(tmp))
        check_unit_and_report_truth(Path(tmp))
    with tempfile.TemporaryDirectory(prefix="psgen-sec-") as tmp:
        check_security_markers(Path(tmp))
        check_new_gates(Path(tmp))
    with tempfile.TemporaryDirectory(prefix="psgen-meta-") as tmp:
        check_meta_tests(Path(tmp))
    with tempfile.TemporaryDirectory(prefix="psgen-wt4-") as tmp:
        check_session_detach(Path(tmp))
        check_prune_from_another_cwd(Path(tmp))
        check_wait_reclaims_unreported(Path(tmp))
        check_stop_refuses_mountpoint(Path(tmp))
    if can_root():
        check_root()
    else:
        skip("root checks need root or passwordless sudo")


if __name__ == "__main__":
    sys.exit(main())
