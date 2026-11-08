//! `psgen log` and `psgen load`.
//!
//! `log` writes plausible activity text, one event at a time, in an access
//! log, JSON or syslog encoding. `load` creates real CPU, memory and disk
//! pressure, so a monitor sees true utilisation rather than a pleasant shape.

use crate::cli::Args;
use crate::loggen::{self, Format, WebRecord};
use crate::rng::Rng;
use crate::str::Buf;
use crate::sys;
use crate::util;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::vec::Vec;

pub const MODULES: &[&str] = &[
    "weblog",
    "bootlog",
    "cargo",
    "cc",
    "download",
    "docker_build",
    "docker_rmi",
    "terraform",
    "ansible",
    "kernel_compile",
    "mkinitcpio",
    "uv",
    "composer",
    "julia",
];

const PATHS: &[&str] = &[
    "/",
    "/api/v1/users",
    "/api/v1/orders",
    "/api/v1/search?q=psgen",
    "/static/js/app.js",
    "/static/css/site.css",
    "/api/v1/health",
    "/api/v1/metrics",
    "/.well-known/security.txt",
    "/favicon.ico",
    "/v2/items/8f2c1a",
    "/login",
];

const UAS: &[&str] = &[
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "curl/8.7.1",
    "Go-http-client/1.1",
    "python-requests/2.32.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
];

const CRATES: &[&str] = &[
    "serde",
    "tokio",
    "libc",
    "syn",
    "quote",
    "clap",
    "anyhow",
    "regex",
    "hyper",
    "tracing",
    "bytes",
    "indexmap",
    "thiserror",
    "parking_lot",
    "hashbrown",
];

const HOSTS: &[&str] = &["web1", "web2", "db1", "cache1", "worker1", "worker2"];

fn hex(rng: &mut Rng, n: usize) -> Vec<u8> {
    let mut h = vec![0u8; n];
    rng.hex(n, &mut h);
    h
}

fn web_record(rng: &mut Rng) -> WebRecord {
    WebRecord {
        ip: loggen::rand_ip(rng),
        method: if rng.below(12) == 0 { "POST" } else { "GET" },
        path: PATHS[rng.below(PATHS.len() as u64) as usize].as_bytes().to_vec(),
        status: loggen::pick_status(rng),
        bytes: if rng.below(5) == 0 {
            rng.range(0, 400)
        } else {
            rng.range(180, 94_000)
        },
        ua: UAS[rng.below(UAS.len() as u64) as usize],
        ms: rng.range(1, 420),
    }
}

fn web_line(rng: &mut Rng, fmt: Format, now: u64) -> Vec<u8> {
    let rec = web_record(rng);
    match fmt {
        Format::Apache => loggen::apache_line(&rec, now),
        Format::Json => loggen::json_web_line(&rec, now),
        Format::Syslog => loggen::syslog_web_line(&rec, now, b"web1"),
    }
}

fn weblog(rng: &mut Rng, fmt: Format, now: u64) -> Vec<u8> {
    // A real access log arrives in bursts. One event in twenty brings 10 to 50
    // requests at once, the rest arrive singly, so `--lines` counts events,
    // not output rows.
    if rng.below(20) == 0 {
        let burst = rng.range(10, 50);
        let mut out = Buf::new();
        for _ in 0..burst {
            out.push_bytes(&web_line(rng, fmt, now));
        }
        return out.v;
    }
    web_line(rng, fmt, now)
}

fn bootlog(rng: &mut Rng, now: u64) -> Vec<u8> {
    let mut b = Buf::new();
    let major = rng.range(6, 12);
    let minor = rng.range(1, 18);
    let patch = rng.range(1, 120);
    let cpu = ["GenuineIntel", "AuthenticAMD"][rng.below(2) as usize];
    let model = ["Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz", "AMD EPYC 7B13 64-Core Processor"]
        [rng.below(2) as usize];
    b.push_str("[    0.000000] Linux version ");
    b.push_u64(major);
    b.push(b'.');
    b.push_u64(minor);
    b.push(b'.');
    b.push_u64(patch);
    b.push_str(" (debian-kernel@buildhost) (gcc (Debian 14.2.0-19) 14.2.0, GNU ld 2.44) #1 SMP PREEMPT_DYNAMIC Debian 6.");
    b.push_u64(major);
    b.push(b'.');
    b.push_u64(minor);
    b.push_str("\n[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-");
    b.push_u64(major);
    b.push(b'.');
    b.push_u64(minor);
    b.push_str(" root=UUID=");
    b.push_bytes(&hex(rng, 8));
    b.push_str("-1234-5678-9abc ro quiet splash\n");
    b.push_str("[    0.000000] BIOS-provided physical RAM map:\n");
    b.push_str("[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable\n");
    b.push_str("[    0.000000] DMI: QEMU Standard PC (Q35 + ICH9, 2009)\n");
    b.push_str("[    0.000000] smpboot: CPU0: ");
    b.push_str(cpu);
    b.push_str(" ");
    b.push_str(model);
    b.push_str("\n[    0.000000] smpboot: Allowed CPUs: ");
    b.push_u64(rng.range(2, 16));
    b.push_str(" (of ");
    b.push_u64(rng.range(16, 128));
    b.push_str(")\n[    0.000000] Memory: ");
    b.push_u64(rng.range(2_000_000, 64_000_000));
    b.push_str("K/");
    b.push_u64(rng.range(64_000_001, 68_000_000));
    b.push_str("K available\n[    0.041203] systemd[1]: Detected virtualisation: none\n");
    let _ = now;
    b.as_bytes().to_vec()
}

fn cargo(rng: &mut Rng) -> Vec<u8> {
    let n = rng.range(1, 4);
    let mut b = Buf::new();
    for _ in 0..n {
        b.push_str("   Compiling ");
        b.push_str(CRATES[rng.below(CRATES.len() as u64) as usize]);
        b.push_str(" v0.");
        b.push_u64(rng.range(1, 19));
        b.push(b'.');
        b.push_u64(rng.range(0, 40));
        b.push_str(" (/build/registry/src/index.crates.io-6f17d22bba15001f/");
        b.push_str(CRATES[rng.below(CRATES.len() as u64) as usize]);
        b.push_str("-");
        b.push_bytes(&hex(rng, 8));
        b.push_str(")\n");
    }
    b.push_str("    Finished `dev` profile [unoptimized + debuginfo] target(s) in ");
    b.push_u64(rng.range(1, 90));
    b.push(b'.');
    b.push_u64(rng.range(0, 9));
    b.push_str("s\n");
    b.as_bytes().to_vec()
}

fn cc(rng: &mut Rng) -> Vec<u8> {
    let files = [
        "drivers/net/e1000.c",
        "net/ipv4/tcp_input.c",
        "fs/ext4/inode.c",
        "kernel/sched/fair.c",
        "arch/x86/mm/pgtable.c",
    ];
    let mut b = Buf::new();
    b.push_str("gcc -Wp,-MMD,obj/");
    b.push_str(files[rng.below(files.len() as u64) as usize]);
    b.push_str(".d -O2 -Wall -Wextra -fno-strict-aliasing -c -o obj/");
    b.push_str(files[rng.below(files.len() as u64) as usize]);
    b.push_str("\n");
    b.as_bytes().to_vec()
}

fn download(rng: &mut Rng) -> Vec<u8> {
    let names = ["pkgforge", "toolchain", "nightly", "vendored-src", "data-dump"];
    let mut b = Buf::new();
    b.push_str("  % Total    % Received % Xferd  Average Speed\n");
    b.push_str("100 ");
    b.push_u64(rng.range(1000, 9999));
    b.push_str("k  100 ");
    b.push_u64(rng.range(1000, 9999));
    b.push_str("k    0     0  ");
    b.push_u64(rng.range(100, 9000));
    b.push_str("k      0      0 --:--:-- --:--:-- --:--:-- ");
    b.push_u64(rng.range(100, 9000));
    b.push_str("k\n");
    b.push_str("Downloading ");
    b.push_str(names[rng.below(names.len() as u64) as usize]);
    b.push_str("-");
    b.push_str("2.1.");
    b.push_u64(rng.range(0, 9));
    b.push_str(".tar.gz\n");
    b.as_bytes().to_vec()
}

fn docker_build(rng: &mut Rng) -> Vec<u8> {
    let steps = [
        ("FROM debian:13-slim", ""),
        ("COPY . /src", ""),
        ("RUN cargo build --release", ""),
        ("RUN useradd -r app", ""),
        ("ENTRYPOINT [\"/src/target/release/app\"]", ""),
    ];
    let mut b = Buf::new();
    for (i, (s, _)) in steps.iter().enumerate() {
        b.push_str("Step ");
        b.push_u64(i as u64 + 1);
        b.push_str("/");
        b.push_u64(steps.len() as u64);
        b.push_str(" : ");
        b.push_str(s);
        b.push_str("\n ---> ");
        b.push_bytes(&hex(rng, 12));
        b.push(b'\n');
        b.push_str(" ---> Running in ");
        b.push_bytes(&hex(rng, 12));
        b.push(b'\n');
    }
    b.push_str("Successfully built ");
    b.push_bytes(&hex(rng, 12));
    b.push(b'\n');
    b.as_bytes().to_vec()
}

fn docker_rmi(rng: &mut Rng) -> Vec<u8> {
    let repo = ["grafana/grafana", "node", "python", "alpine", "traefik"][rng.below(5) as usize];
    let tag = ["0.12.18-alpha", "22-bookworm", "3.13-slim", "3.20", "v3.1"][rng.below(5) as usize];
    let mut b = Buf::new();
    b.push_str("Untagged: ");
    b.push_str(repo);
    b.push(b':');
    b.push_str(tag);
    b.push_str("\nUntagged: ");
    b.push_str(repo);
    b.push_str("@sha256:");
    b.push_bytes(&hex(rng, 64));
    b.push_str("\nDeleted: sha256:");
    b.push_bytes(&hex(rng, 64));
    b.push_str("\nDeleted: sha256:");
    b.push_bytes(&hex(rng, 64));
    b.push(b'\n');
    b.as_bytes().to_vec()
}

fn terraform(rng: &mut Rng) -> Vec<u8> {
    let mut b = Buf::new();
    b.push_str("aws_instance.web: Still creating... [10s elapsed]\n");
    b.push_str("aws_instance.web: Still creating... [20s elapsed]\n");
    b.push_str("aws_instance.web: Creation complete after ");
    b.push_u64(rng.range(21, 90));
    b.push_str("s [id=i-0");
    b.push_bytes(&hex(rng, 16));
    b.push_str("]\naws_security_group.web: Modifying... [id=sg-0");
    b.push_bytes(&hex(rng, 16));
    b.push_str("]\naws_security_group.web: Modifications complete after 2s\n");
    b.push_str("Apply complete! Resources: 3 added, 0 changed, 1 destroyed.\n");
    b.as_bytes().to_vec()
}

fn ansible(rng: &mut Rng) -> Vec<u8> {
    let host = HOSTS[rng.below(HOSTS.len() as u64) as usize];
    let mut b = Buf::new();
    b.push_str("PLAY [webservers] *****************************************************\n");
    b.push_str("TASK [Gathering Facts] *************************************************\n");
    b.push_str("ok: [");
    b.push_str(host);
    b.push_str("]\nTASK [Install nginx] ***************************************************\n");
    b.push_str("changed: [");
    b.push_str(host);
    b.push_str("]\nTASK [Deploy site config] **********************************************\n");
    b.push_str("ok: [");
    b.push_str(host);
    b.push_str("]\nPLAY RECAP *************************************************************\n");
    b.push_str(host);
    b.push_str(" : ok=3 changed=1 unreachable=0 failed=0 skipped=0\n");
    b.as_bytes().to_vec()
}

fn kernel_compile(rng: &mut Rng) -> Vec<u8> {
    let files = [
        "net/wireless/mlme/nway.o",
        "net/wireless/mlme/assoc.o",
        "arch/x86/entry/vsyscall/vsyscall_64.o",
        "fs/ext4/inode.o",
        "mm/page_alloc.o",
        "kernel/sched/core.o",
    ];
    let mut b = Buf::new();
    for _ in 0..rng.range(2, 6) {
        b.push_str("  CC      ");
        b.push_str(files[rng.below(files.len() as u64) as usize]);
        b.push(b'\n');
    }
    b.push_str("  LD      net/wireless/mlme/mlme.o\n  AR      net/wireless/built-in.a\n");
    b.as_bytes().to_vec()
}

fn mkinitcpio(rng: &mut Rng) -> Vec<u8> {
    let mut b = Buf::new();
    b.push_str("==> Building image from preset: /etc/mkinitcpio.d/linux.preset: 'default'\n");
    b.push_str("==> Using default configuration file: /etc/mkinitcpio.conf\n");
    b.push_str("  -> -k /boot/vmlinuz-linux -g /boot/initramfs-linux.img\n");
    b.push_str("==> Starting build: '");
    b.push_u64(rng.range(6, 12));
    b.push(b'.');
    b.push_u64(rng.range(1, 18));
    b.push_str("-arch1-1'\n  -> Running build hook: [base]\n  -> Running build hook: [udev]\n  -> Running build hook: [autodetect]\n");
    b.push_str("==> Generating module dependencies\n==> Creating zstd-compressed initcpio image: /boot/initramfs-linux.img\n");
    b.push_str("==> Image generation successful\n");
    b.as_bytes().to_vec()
}

fn uv(rng: &mut Rng) -> Vec<u8> {
    let mut b = Buf::new();
    let n = rng.range(10, 200);
    b.push_str("Resolved ");
    b.push_u64(n);
    b.push_str(" packages in ");
    b.push_u64(rng.range(20, 900));
    b.push_str("ms\nPrepared ");
    b.push_u64(rng.range(1, n));
    b.push_str(" packages in ");
    b.push_u64(rng.range(10, 400));
    b.push_str("ms\nInstalled ");
    b.push_u64(rng.range(1, n));
    b.push_str(" packages in ");
    b.push_u64(rng.range(10, 700));
    b.push_str("ms\n");
    b.as_bytes().to_vec()
}

fn composer(rng: &mut Rng) -> Vec<u8> {
    let mut b = Buf::new();
    b.push_str("Loading composer repositories with package information\nUpdating dependencies\n");
    b.push_str("  - Installing symfony/console (v6.");
    b.push_u64(rng.range(0, 9));
    b.push_str(".0): Extracting archive\n  - Installing psr/log (3.");
    b.push_u64(rng.range(0, 9));
    b.push_str(".0): Extracting archive\nGenerating optimized autoload files\n");
    b.push_str("Executing script cache:clear [OK]\n");
    b.as_bytes().to_vec()
}

fn julia(rng: &mut Rng) -> Vec<u8> {
    let mut b = Buf::new();
    b.push_str("   Resolving package versions...\n   Installed DataFrames v1.");
    b.push_u64(rng.range(0, 9));
    b.push_str(".0\n   Installed CSV v0.10.");
    b.push_u64(rng.range(0, 9));
    b.push_str("\n    Updating `/project/Project.toml`\n  [a93c6f00] + DataFrames v1.");
    b.push_u64(rng.range(0, 9));
    b.push_str(".0\n");
    b.as_bytes().to_vec()
}

fn page(rng: &mut Rng, fmt: Format, module: &[u8], now: u64) -> Option<Vec<u8>> {
    let out = match module {
        b"weblog" | b"access" | b"apache" | b"nginx" | b"web" | b"flog" => {
            weblog(rng, fmt, now)
        }
        b"bootlog" | b"boot" | b"dmesg" => bootlog(rng, now),
        b"cargo" | b"rustc" => cargo(rng),
        b"cc" | b"gcc" | b"make" => cc(rng),
        b"download" | b"wget" | b"curl" => download(rng),
        b"docker_build" | b"docker" | b"dockerbuild" => docker_build(rng),
        b"docker_rmi" | b"docker_rm" | b"dockerrmi" => docker_rmi(rng),
        b"terraform" | b"tf" => terraform(rng),
        b"ansible" | b"playbook" => ansible(rng),
        b"kernel_compile" | b"kernel" => kernel_compile(rng),
        b"mkinitcpio" => mkinitcpio(rng),
        b"uv" | b"pip" => uv(rng),
        b"composer" | b"php" => composer(rng),
        b"julia" => julia(rng),
        _ => return None,
    };
    Some(out)
}

fn module_service(module: &[u8]) -> &'static str {
    match module {
        b"weblog" | b"access" | b"apache" | b"nginx" | b"web" | b"flog" => "web",
        b"bootlog" | b"boot" | b"dmesg" => "kernel",
        b"cargo" | b"rustc" => "cargo",
        b"cc" | b"gcc" | b"make" | b"kernel_compile" | b"kernel" | b"mkinitcpio" => "make",
        b"download" | b"wget" | b"curl" => "curl",
        b"docker_build" | b"docker" | b"dockerbuild" | b"docker_rmi" | b"docker_rm"
        | b"dockerrmi" => "dockerd",
        b"terraform" | b"tf" => "terraform",
        b"ansible" | b"playbook" => "ansible",
        b"uv" | b"pip" => "uv",
        b"composer" | b"php" => "composer",
        b"julia" => "julia",
        _ => "psgen",
    }
}

fn is_weblog(module: &[u8]) -> bool {
    matches!(
        module,
        b"weblog" | b"access" | b"apache" | b"nginx" | b"web" | b"flog"
    )
}

fn module_known(module: &[u8]) -> bool {
    matches!(
        module,
        b"weblog"
            | b"access"
            | b"apache"
            | b"nginx"
            | b"web"
            | b"flog"
            | b"bootlog"
            | b"boot"
            | b"dmesg"
            | b"cargo"
            | b"rustc"
            | b"cc"
            | b"gcc"
            | b"make"
            | b"download"
            | b"wget"
            | b"curl"
            | b"docker_build"
            | b"docker"
            | b"dockerbuild"
            | b"docker_rmi"
            | b"docker_rm"
            | b"dockerrmi"
            | b"terraform"
            | b"tf"
            | b"ansible"
            | b"playbook"
            | b"kernel_compile"
            | b"kernel"
            | b"mkinitcpio"
            | b"uv"
            | b"pip"
            | b"composer"
            | b"php"
            | b"julia"
    )
}

pub fn run_log(args: &Args) -> i32 {
    let module = args.log_module.as_slice();
    if module == b"list" || module == b"modules" || module == b"help" {
        let mut out = Buf::new();
        out.push_str("modules:");
        for m in MODULES {
            out.push(b' ');
            out.push_str(m);
        }
        out.push(b'\n');
        sys::out(out.as_bytes());
        return 0;
    }
    if !module_known(module) {
        let mut out = Buf::new();
        out.push_str("psgen: unknown module ");
        out.push_bytes(module);
        out.push_str(" (try --module list)\n");
        sys::err(out.as_bytes());
        return 2;
    }
    // The format value defaults to Apache, but it is applied only to the web
    // log. Other modules print their own text unless JSON or syslog is
    // requested, so an explicit --log-fmt apache stays an error for them.
    let fmt = args.log_fmt.unwrap_or(Format::Apache);
    if args.log_fmt == Some(Format::Apache) && !is_weblog(module) {
        let mut out = Buf::new();
        out.push_str("psgen: --log-fmt apache is only defined for weblog; use json or syslog for ");
        out.push_bytes(module);
        out.push(b'\n');
        sys::err(out.as_bytes());
        return 2;
    }
    if args.speed == 0 {
        sys::err(b"psgen: --speed must be at least 1\n");
        return 2;
    }
    let mut rng = match args.seed {
        Some(s) => Rng::new(s),
        None => Rng::from_entropy(),
    };
    let now = sys::now_secs();
    let lines = args.log_lines;
    let mut emitted = Buf::new();
    for i in 0..lines {
        let chunk = match page(&mut rng, fmt, module, now + i as u64) {
            Some(c) => c,
            None => {
                // module_known() already rejected unknown names.
                break;
            }
        };
        if fmt == Format::Json {
            // weblog already emits JSON; other modules need the envelope.
            if is_weblog(module) {
                emitted.push_bytes(&chunk);
            } else {
                for line in chunk.split(|b| *b == b'\n') {
                    if !line.is_empty() {
                        emitted.push_bytes(&loggen::text_line(
                            fmt,
                            now + i as u64,
                            module_service(module),
                            "INFO",
                            line,
                        ));
                    }
                }
            }
        } else if fmt == Format::Syslog && !is_weblog(module) {
            for line in chunk.split(|b| *b == b'\n') {
                if !line.is_empty() {
                    emitted.push_bytes(&loggen::text_line(
                        fmt,
                        now + i as u64,
                        module_service(module),
                        "INFO",
                        line,
                    ));
                }
            }
        } else {
            emitted.push_bytes(&chunk);
        }
        if args.log_delay_ms > 0 && i + 1 < lines {
            sys::out(emitted.as_bytes());
            emitted = Buf::new();
            let ms = args.log_delay_ms / args.speed.max(1);
            sys::nanosleep(ms / 1000, (ms % 1000) * 1_000_000);
        }
    }
    sys::out(emitted.as_bytes());
    0
}

/// Burn `pct` percent of one core until `deadline` (monotonic ns), or forever.
fn burn(cpu_pct: u32, deadline: u64) {
    let pct = cpu_pct.min(100) as u64;
    if pct == 0 {
        if deadline == u64::MAX {
            loop {
                sys::nanosleep(1, 0);
            }
        }
        while sys::monotonic_ns() < deadline {
            sys::nanosleep(0, 50_000_000);
        }
        return;
    }
    let period_ns = 100_000_000u64; // 100 ms accounting window
    let duty_ns = period_ns * pct / 100;
    loop {
        if deadline != u64::MAX && sys::monotonic_ns() >= deadline {
            return;
        }
        let start = sys::monotonic_ns();
        while sys::monotonic_ns().saturating_sub(start) < duty_ns {
            core::hint::spin_loop();
        }
        let spent = sys::monotonic_ns().saturating_sub(start);
        if spent < period_ns {
            let rest = period_ns - spent;
            sys::nanosleep(rest / 1_000_000_000, rest % 1_000_000_000);
        }
    }
}

fn touch(ptr: *mut u8, len: usize) {
    let page = (sys::page_kb() * 1024) as usize;
    let mut off = 0usize;
    while off < len {
        unsafe {
            ptr.add(off).write_volatile(1u8);
        }
        off += page;
    }
}

pub fn run_load(args: &Args) -> i32 {
    let cpu_pct = args.load_cpu.unwrap_or(0).min(100);
    let mem_pct = args.load_mem.unwrap_or(0).min(95);
    let disk_mb = args.load_disk.unwrap_or(0);
    if cpu_pct == 0 && mem_pct == 0 && disk_mb == 0 {
        sys::err(b"psgen: load needs at least one of --cpu-util, --mem-util, --disk-util\n");
        return 2;
    }
    let secs = args.duration as u64;
    let deadline = if secs == 0 {
        u64::MAX
    } else {
        sys::monotonic_ns()
            .saturating_add(secs.saturating_mul(1_000_000_000))
    };

    let mut note = Buf::new();
    note.push_str("psgen: load");

    // Memory: hold a touched mapping for the whole run.
    if mem_pct > 0 {
        let total = util::mem_total_kb();
        let cg = util::cgroup_mem_limit_kb();
        let total = if cg > 0 { total.min(cg) } else { total };
        if total == 0 {
            sys::err(b"psgen: cannot read MemTotal; --mem-util needs /proc/meminfo\n");
            return 1;
        }
        let mem_kb = total * mem_pct as u64 / 100;
        let want = mem_kb.saturating_mul(1024);
        let len = want.min(usize::MAX as u64) as usize;
        if want > len as u64 {
            let mut out = Buf::new();
            out.push_str("psgen: --mem-util ");
            out.push_u64(mem_pct as u64);
            out.push_str("% needs ");
            out.push_u64(want / 1024 / 1024);
            out.push_str(" MiB, more than this address space allows; holding ");
            out.push_u64(len as u64 / 1024 / 1024);
            out.push_str(" MiB\n");
            sys::err(out.as_bytes());
        }
        let p = sys::mmap(
            len,
            sys::PROT_READ | sys::PROT_WRITE,
            sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p.is_null() {
            let mut out = Buf::new();
            out.push_str("psgen: cannot map ");
            out.push_u64(mem_kb);
            out.push_str(" KiB of memory\n");
            sys::err(out.as_bytes());
            return 1;
        }
        touch(p, len);
        note.push_str(" mem ");
        note.push_u64(len as u64 / 1024 / 1024);
        note.push_str(" MiB touched");
    }

    // Disk: write a real file, with a free-space guard so load cannot fill
    // the filesystem it runs on. The file is unlinked as soon as it is open,
    // so the blocks are held by the handle and no path is left behind.
    let mut disk_file: Option<std::fs::File> = None;
    if disk_mb > 0 {
        let dir = std::env::temp_dir();
        let want = disk_mb.saturating_mul(1024 * 1024);
        if let Some(limit) = sys::rlimit_fsize() {
            if want > limit {
                let mut out = Buf::new();
                out.push_str("psgen: --disk-util ");
                out.push_u64(disk_mb);
                out.push_str(" MiB exceeds RLIMIT_FSIZE (");
                out.push_u64(limit / 1024 / 1024);
                out.push_str(" MiB)\n");
                sys::err(out.as_bytes());
                return 1;
            }
        }
        let dirb = dir.as_os_str().as_bytes().to_vec();
        if let Some((free, _)) = crate::probe::space(&dirb) {
            if want > free.saturating_sub(free / 10) {
                let mut out = Buf::new();
                out.push_str("psgen: --disk-util ");
                out.push_u64(disk_mb);
                out.push_str(" MiB exceeds the free space in ");
                out.push_bytes(&dirb);
                out.push_str(" (");
                out.push_u64(free / 1024 / 1024);
                out.push_str(" MiB free)\n");
                sys::err(out.as_bytes());
                return 1;
            }
        }
        let mut f = match make_load_file(&dir) {
            Some(f) => f,
            None => {
                let mut out = Buf::new();
                out.push_str("psgen: cannot write ");
                out.push_u64(disk_mb);
                out.push_str(" MiB of temp data\n");
                sys::err(out.as_bytes());
                return 1;
            }
        };
        let chunk = vec![0x5au8; 1024 * 1024];
        let mut left = want;
        while left > 0 {
            let n = left.min(chunk.len() as u64) as usize;
            if f.write_all(&chunk[..n]).is_err() {
                let mut out = Buf::new();
                out.push_str("psgen: cannot write ");
                out.push_u64(disk_mb);
                out.push_str(" MiB of temp data\n");
                sys::err(out.as_bytes());
                return 1;
            }
            left -= n as u64;
        }
        disk_file = Some(f);
        note.push_str(" disk ");
        note.push_u64(disk_mb);
        note.push_str(" MiB");
    }

    if cpu_pct > 0 {
        note.push_str(" cpu ");
        note.push_u64(cpu_pct as u64);
        note.push_str("%");
    }
    if secs > 0 {
        note.push_str(" for ");
        note.push_u64(secs);
        note.push_str("s");
    }
    note.push(b'\n');
    sys::err(note.as_bytes());

    burn(cpu_pct, deadline);

    drop(disk_file);
    0
}

fn make_load_file(dir: &std::path::Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    for _ in 0..100 {
        let mut r = [0u8; 8];
        if !sys::getrandom(&mut r) {
            return None;
        }
        let path = dir.join(format!(".psgen-load-{:016x}", u64::from_le_bytes(r)));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => {
                if std::fs::remove_file(&path).is_err()
                    && std::fs::remove_file(&path).is_err()
                {
                    drop(f);
                    return None;
                }
                return Some(f);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}
