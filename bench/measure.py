#!/usr/bin/env python3
"""Measure psgen against the reference process list.

Runs target/release/psgen and writes a fresh report to bench/RESULTS.md.
"""

from __future__ import annotations

import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

PS_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<pid>\d+)\s+(?P<cpu>\d+\.\d)\s+"
    r"(?P<mem>\d+\.\d)\s+(?P<vsz>\d+)\s+(?P<rss>\d+)\s+"
    r"(?P<tty>\S+)\s+(?P<stat>[RSDZT][sl+]*)\s+"
    r"(?P<start>\d\d:\d\d|[A-Z][a-z]{2}\s?\d+|\d{4})\s+"
    r"(?P<time>\d+:\d\d(?::\d\d)?)\s+(?P<cmd>.*)$"
)


ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "target" / "release" / "psgen"
ORIGINAL = ROOT / "bench" / "original-legit_ps_linux.txt"
REFERENCE = ROOT / "bench" / "reference-ps.txt"

GREY = [
    "botnet", "bruteforce", "brute-force", "cryptomin", "cryptominer",
    "cryptomining", "stratum", "xmrig", "memdump", "rkhunter", "ganache",
    "simcity", "rootkit", "hashcat", "hydra", "nmap", "masscan",
    "metasploit", "msfconsole", "mimikatz", "lazagne", "sqlmap", "nikto",
    "gobuster", "ffuf", "nuclei", "reverse shell", "/dev/tcp", "nc -e",
    "ncat -e", "chisel", "ligolo", "ngrok", "ransomware", "lsass",
    "procdump", "kerberoast", "bloodhound", "impacket", "responder",
    "ettercap", "arpspoof", "aircrack", "reaver", "wifite", "kismet",
    "bettercap",
]

PLACEHOLDER = re.compile(r"[{}]")


def run(args: list[str], timeout: int = 30) -> str:
    p = subprocess.run(
        [str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        text=True,
    )
    if p.returncode != 0:
        raise SystemExit(f"psgen {' '.join(args)} failed: {p.returncode}\n{p.stderr}")
    return p.stdout


def parse_ps(text: str) -> list[dict]:
    """Parse ps aux with a regex so large RSS and "Oct 8" do not shift fields."""
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("USER "):
            continue
        m = PS_RE.match(line)
        if not m:
            continue
        rows.append({
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
            "cmd": m.group("cmd"),
        })
    return rows

def word_hit(haystack: str, needle: str) -> bool:
    low = haystack.lower()
    n = needle.lower()
    start = 0
    while True:
        i = low.find(n, start)
        if i < 0:
            return False
        before = low[i - 1] if i else ""
        after = low[i + len(n)] if i + len(n) < len(low) else ""
        if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
            return True
        start = i + 1


def executable(cmd: str) -> str | None:
    first = cmd.split(" ", 1)[0]
    if not first or first.startswith("("):
        return None
    if first.endswith(":"):
        first = first[:-1]
    elif ":" in first:
        first = first.split(":", 1)[0]
    return os.path.basename(first)


def exe_exists(name: str | None) -> bool:
    if not name:
        return False
    if "/" in name:
        return os.path.exists(name)
    return shutil.which(name) is not None


def token_hist(cmds: list[str]) -> Counter:
    return Counter(min(len(c.split()), 16) for c in cmds)


def js_divergence(p: Counter, q: Counter) -> float:
    keys = set(p) | set(q)
    pt = sum(p.values()) or 1
    qt = sum(q.values()) or 1
    m = 0.0
    for k in keys:
        a = p.get(k, 0) / pt
        b = q.get(k, 0) / qt
        mid = (a + b) / 2
        if a:
            m += 0.5 * a * math.log2(a / mid)
        if b:
            m += 0.5 * b * math.log2(b / mid)
    return m


FAMILY_KEYS = {
    "sys": ["systemd", "init", "sshd", "cron", "dbus-daemon", "rsyslogd",
            "agetty", "polkitd", "chronyd", "atd", "smartd", "haveged",
            "accounts-daemon", "upowerd", "ModemManager", "bluetoothd",
            "irqbalance", "sd-pam"],
    "web": ["nginx", "apache2", "php-fpm", "gunicorn", "haproxy", "envoy",
            "caddy", "traefik", "varnishd", "unitd"],
    "db": ["postgres", "mysqld", "mariadbd", "redis-server", "mongod",
           "memcached", "clickhouse-server", "etcd"],
    "ctr": ["containerd", "dockerd", "containerd-shim-runc-v2", "docker-proxy",
            "kubelet", "kube-proxy", "coredns", "flanneld", "calico-node",
            "firecracker", "qemu-system-x86_64", "libvirtd", "virtlogd",
            "lxc-start"],
    "dev": ["gcc", "make", "cargo", "rustc", "node", "npm", "npx", "next",
            "python3", "java", "go", "webpack", "vite", "tsc", "eslint",
            "jest", "docker", "ansible-playbook", "terraform", "pip",
            "composer", "uv", "julia", "cmake", "ninja", "clang", "ld",
            "mkinitcpio"],
    "mon": ["prometheus", "prometheus-node-exporter", "grafana-server",
            "telegraf", "filebeat", "metricbeat", "fluent-bit", "vector",
            "collectd", "snmpd", "zabbix_agentd", "datadog-agent",
            "newrelic-infra", "journalctl", "tail"],
    "sto": ["ceph-osd", "ceph-mon", "glusterd", "smbd", "nmbd", "rpcbind",
            "minio", "rclone", "rsync"],
    "mail": ["master", "qmgr", "pickup", "tlsmgr", "exim4", "dovecot",
             "anvil", "auth"],
    "desk": ["Xorg", "gnome-shell", "gnome-terminal-server", "pipewire",
             "pipewire-pulse", "wireplumber", "tracker-miner-fs-3",
             "evolution-alarm-notify", "code", "firefox", "chromium",
             "gsd-power", "gsd-color", "nautilus", "ibus-daemon",
             "gnome-keyring-daemon", "vim", "bash"],
    "net": ["NetworkManager", "dhclient", "wpa_supplicant", "openvpn",
            "wireguard-go", "keepalived", "dnsmasq", "unbound", "ntpd",
            "ssh", "scp", "curl", "wget"],
}


def families_covered(cmds: list[str]) -> int:
    seen = set()
    for cmd in cmds:
        exe = executable(cmd) or ""
        for fam, keys in FAMILY_KEYS.items():
            if exe in keys:
                seen.add(fam)
                break
    return len(seen)


def validate_table(text: str) -> tuple[list[str], list[dict]]:
    problems = []
    lines = text.splitlines()
    expected = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    if not lines or lines[0] != expected:
        problems.append("header mismatch")
    rows = parse_ps(text)
    if len(rows) < 2:
        problems.append("too few rows")
    pids = [r["pid"] for r in rows]
    if len(pids) != len(set(pids)):
        problems.append("duplicate pids")
    mem_total = 0
    with open("/proc/meminfo") as fh:
        for line in fh:
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1])
    for r in rows:
        if r["vsz"] < r["rss"]:
            problems.append(f"vsz<rss pid {r['pid']}")
        if mem_total:
            want = r["rss"] * 100.0 / mem_total
            if abs(want - r["mem"]) > 0.11:
                problems.append(f"mem mismatch pid {r['pid']}: {r['mem']} vs {want:.2f}")
        if not re.fullmatch(r"[RSDZT][sl+]*", r["stat"]):
            problems.append(f"bad stat pid {r['pid']}: {r['stat']}")
        if not re.fullmatch(r"\d+:\d\d(:\d\d)?", r["time"]):
            problems.append(f"bad time pid {r['pid']}: {r['time']}")
        if not re.fullmatch(r"\d\d:\d\d|[A-Z][a-z]{2} ?\d+|\d{4}", r["start"]):
            problems.append(f"bad start pid {r['pid']}: {r['start']}")
        if not re.fullmatch(r"\?|pts/\d+|tty\d+", r["tty"]):
            problems.append(f"bad tty pid {r['pid']}: {r['tty']}")
        if len(r["user"]) > 8:
            problems.append(f"user too wide pid {r['pid']}: {r['user']}")
        if not r["cmd"] or PLACEHOLDER.search(r["cmd"]):
            problems.append(f"bad command pid {r['pid']}")
    if rows and rows[0]["pid"] != 1:
        problems.append("pid 1 is not first")
    if rows and rows[0]["cmd"] != "/sbin/init":
        problems.append("pid 1 is not init")
    singles = [
        "/sbin/init",
        "sshd: /usr/sbin/sshd -D [listener]",
        "nginx: master process",
        "/usr/lib/postgresql/17/bin/postgres -D",
        "/usr/bin/redis-server",
        "/usr/bin/containerd",
        "/usr/sbin/dockerd",
    ]
    for prefix in singles:
        n = sum(1 for r in rows if r["cmd"].startswith(prefix))
        if n > 1:
            problems.append(f"duplicate single-instance daemon: {prefix} x{n}")
    return problems, rows


def proc_rss(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def read_pids(path: Path) -> list[int]:
    pids: list[int] = []
    if not path.exists():
        return pids
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            pids.append(int(line.split("\t", 1)[0]))
        except ValueError:
            continue
    return pids


def injection_roundtrip() -> dict:
    result = {"spawned": 0, "visible": 0, "cmdline_ok": 0, "tty_seen": 0,
              "pids": [], "verify_spawned": 0, "verify_bad": 0, "verify_phys": 0,
              "verify_rss": 0}
    pidfile = Path(tempfile.mkstemp(prefix="psgen-pids-")[1])
    pidfile2 = Path(tempfile.mkstemp(prefix="psgen-pids-tty-")[1])
    pidfile3 = Path(tempfile.mkstemp(prefix="psgen-pids-verify-")[1])
    try:
        dry = run(["inject", "-n", "8", "-s", "123", "--no-user", "--no-mem",
                   "--no-tty", "--no-threads", "--dry-run"])
        wanted = {line.split("\t", 1)[1].strip() for line in dry.splitlines() if "\t" in line}
        run(["inject", "-n", "8", "-s", "123", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", str(pidfile)])
        pids = read_pids(pidfile)
        result["spawned"] = len(pids)
        result["pids"] = pids
        time.sleep(0.4)
        ps = parse_ps(subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True).stdout)
        by_pid = {r["pid"]: r for r in ps}
        for pid in pids:
            try:
                raw = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
            except OSError:
                raw = ""
            row = by_pid.get(pid)
            if row and raw and row["cmd"].strip() == raw.strip():
                result["visible"] += 1
            if raw.strip() in wanted:
                result["cmdline_ok"] += 1
        # tty pass
        run(["inject", "-f", "desk", "-n", "30", "-s", "5", "--no-user", "--no-mem",
             "--pidfile", str(pidfile2)])
        pids2 = read_pids(pidfile2)
        time.sleep(0.4)
        ps2 = parse_ps(subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True).stdout)
        by2 = {r["pid"]: r for r in ps2}
        result["tty_seen"] = sum(1 for p in pids2 if by2.get(p) and by2[p]["tty"].startswith("pts/"))
        result["pids"] += pids2
        # exactness pass
        verify = run(["inject", "-n", "16", "-s", "42", "--no-user", "--verify",
                      "--pidfile", str(pidfile3)])
        verify_pids = read_pids(pidfile3)
        result["verify_spawned"] = len(verify_pids)
        result["verify_rss"] = sum(proc_rss(p) for p in verify_pids)
        m = re.search(r"(\d+) outside 128 kB", verify)
        result["verify_bad"] = int(m.group(1)) if m else 0
        m = re.search(r"estimated physical cost (\d+) MiB", verify)
        result["verify_phys"] = int(m.group(1)) if m else 0
        result["pids"] += read_pids(pidfile3)
    finally:
        for pf in (pidfile, pidfile2, pidfile3):
            if pf.exists():
                subprocess.run([str(BIN), "stop", "--pidfile", str(pf)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    pf.unlink()
                except OSError:
                    pass
        for p in result["pids"]:
            try:
                os.kill(p, 15)
            except OSError:
                pass
    return result


def os_pretty_name() -> str | None:
    try:
        text = Path("/etc/os-release").read_text(errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def main() -> int:
    if not BIN.exists():
        raise SystemExit(f"build first: {BIN} missing")

    original = [l for l in ORIGINAL.read_text().splitlines() if l.strip()]
    generated = [l for l in run(["list", "-n", "0", "-s", "1"]).splitlines() if l.strip()]
    table_text = run(["table", "-n", "40", "-s", "7"])
    table_problems, table_rows = validate_table(table_text)

    reference = parse_ps(REFERENCE.read_text())
    ref_cmds = [r["cmd"] for r in reference]

    gen_fams = families_covered(generated)
    orig_fams = families_covered(original)

    def stats(cmds: list[str]) -> dict:
        toks = [len(c.split()) for c in cmds]
        chars = [len(c) for c in cmds]
        toks_sorted = sorted(toks)
        return {
            "count": len(cmds),
            "grey": sum(1 for c in cmds if any(word_hit(c, g) for g in GREY)),
            "placeholder": sum(1 for c in cmds if PLACEHOLDER.search(c)),
            "control": sum(1 for c in cmds if any(ord(ch) < 32 or ord(ch) == 127 for ch in c)),
            "exes": len({executable(c) for c in cmds if executable(c)}),
            "exe_found": sum(1 for c in cmds if exe_exists(executable(c))),
            "mean_tokens": sum(toks) / max(len(toks), 1),
            "median_tokens": toks_sorted[len(toks_sorted) // 2] if toks_sorted else 0,
            "p90_tokens": toks_sorted[int(len(toks_sorted) * 0.9)] if toks_sorted else 0,
            "mean_chars": sum(chars) / max(len(chars), 1),
            "families": families_covered(cmds),
        }

    g = stats(generated)
    o = stats(original)
    js_gen = js_divergence(token_hist(generated), token_hist(ref_cmds))
    js_orig = js_divergence(token_hist(original), token_hist(ref_cmds))
    inj = injection_roundtrip()

    date = subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                          stdout=subprocess.PIPE, text=True).stdout.strip()
    report = []
    report.append("# psgen measurements\n")
    distro = os_pretty_name()
    host = f"`{os.uname().sysname} {os.uname().release} {os.uname().machine}`"
    if distro:
        host += f", {distro}"
    report.append(f"Run: {date} on {host}. Reference: `bench/reference-ps.txt` "
                  f"({len(reference)} real processes with nginx, postgresql, redis, sshd, cron "
                  f"and node-exporter installed).\n")
    report.append("## Corpus\n")
    report.append("| metric | original genact/fakeact wordlist | psgen |")
    report.append("| --- | ---: | ---: |")
    report.append(f"| command lines | {o['count']} | {g['count']} |")
    report.append(f"| grey / crypto / nonsense terms | {o['grey']} | {g['grey']} |")
    report.append(f"| unexpanded placeholders | {o['placeholder']} | {g['placeholder']} |")
    report.append(f"| control bytes | {o['control']} | {g['control']} |")
    report.append(f"| distinct executables | {o['exes']} | {g['exes']} |")
    report.append(f"| executables present on this host | {o['exe_found']}/{o['count']} | {g['exe_found']}/{g['count']} |")
    report.append(f"| families covered | {o['families']} | {g['families']} |")
    report.append(f"| mean argv tokens | {o['mean_tokens']:.1f} | {g['mean_tokens']:.1f} |")
    report.append(f"| median argv tokens | {o['median_tokens']} | {g['median_tokens']} |")
    report.append(f"| p90 argv tokens | {o['p90_tokens']} | {g['p90_tokens']} |")
    report.append(f"| mean command chars | {o['mean_chars']:.1f} | {g['mean_chars']:.1f} |")
    report.append(f"| JS divergence vs real ps | {js_orig:.3f} | {js_gen:.3f} |")
    report.append("")
    report.append("## Table\n")
    report.append(f"- rows: {len(table_rows)}")
    report.append(f"- structural problems: {len(table_problems)}")
    for p in table_problems[:10]:
        report.append(f"  - {p}")
    report.append("")
    report.append("## Injection\n")
    report.append(f"- spawned: {inj['spawned']}")
    report.append(f"- visible in real `ps aux` with the exact command: {inj['visible']}/{inj['spawned']}")
    report.append(f"- `/proc/PID/cmdline` exact: {inj['cmdline_ok']}/{inj['spawned']}")
    report.append(f"- tty stubs showing a real pts: {inj['tty_seen']}")
    report.append(f"- exactness pass: {inj['verify_spawned']} spawned, "
                  f"{inj['verify_bad']} outside 128 kB, "
                  f"reported RSS {inj['verify_rss'] // 1024} MiB, "
                  f"physical estimate {inj['verify_phys']} MiB")
    report.append("")
    report.append("## Commands used\n")
    report.append("```")
    report.append("psgen list -n 0 -s 1")
    report.append("psgen table -n 40 -s 7")
    report.append("psgen inject -n 8 -s 123 --no-mem --no-tty --no-threads --pidfile ...")
    report.append("psgen inject -f desk -n 30 -s 5 --no-user --no-mem --pidfile ...")
    report.append("psgen inject -n 16 -s 42 --no-user --verify --pidfile ...")
    report.append("ps aux")
    report.append("```")
    text = "\n".join(report) + "\n"
    (ROOT / "bench" / "RESULTS.md").write_text(text)
    print(text)
    if table_problems or inj["visible"] != inj["spawned"] or inj["cmdline_ok"] != inj["spawned"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
