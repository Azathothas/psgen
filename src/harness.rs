//! Reproducible 9/10+ decoy population engine, single-surface hard-negative
//! generator, controls (`C-01`..`C-07`), and physically isolated blind bundle
//! builder (`psgen run`).

use crate::json::{
    self, cat2, cat3, cat4, err_io, i64_str, mkdir_all, push_i64, push_i64_right, push_str_left,
    push_u64, push_u64_right, sort_strings, u64_str, write_file, write_in, Jw, OutDir,
};
use crate::profile::{self, ExtractOpts, Profile, ProfileFd, ProfileTask};
use crate::rng::Rng;
use crate::sha256;
use std::fs;
use std::path::{Path, PathBuf};

pub const HARNESS_SCHEMA: u32 = 1;
pub const DEFAULT_RESIDUAL: &str = "same-uid local observer; root/kernel out of scope";
const DECOY_TOKEN_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Table,
    Deep,
    Both,
}

fn eq_any_ci(s: &str, opts_csv: &str) -> bool {
    opts_csv.split(',').any(|o| s.eq_ignore_ascii_case(o))
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self, String> {
        let t = s.trim();
        if t.eq_ignore_ascii_case("table") {
            Ok(Mode::Table)
        } else if t.eq_ignore_ascii_case("deep") {
            Ok(Mode::Deep)
        } else if t.eq_ignore_ascii_case("both") {
            Ok(Mode::Both)
        } else {
            Err(cat3(
                "invalid mode '",
                t,
                "' (expected table, deep, or both)",
            ))
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Table => "table",
            Mode::Deep => "deep",
            Mode::Both => "both",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Control {
    C01Obvious,
    C02Hidden,
    C03ExactClone,
    C04NoTarget,
    C05TargetOnly,
    C06Main,
    C07HiddenByMask,
}

impl Control {
    pub fn parse(s: &str) -> Result<Self, String> {
        let t = s.trim();
        if eq_any_ci(t, "c-01,c01,obvious,obvious-target") {
            Ok(Control::C01Obvious)
        } else if eq_any_ci(t, "c-02,c02,hidden,hidden-target") {
            Ok(Control::C02Hidden)
        } else if eq_any_ci(t, "c-03,c03,exact-clone,exact_clone,clone") {
            Ok(Control::C03ExactClone)
        } else if eq_any_ci(t, "c-04,c04,no-target,no_target") {
            Ok(Control::C04NoTarget)
        } else if eq_any_ci(t, "c-05,c05,target-only,target_only") {
            Ok(Control::C05TargetOnly)
        } else if eq_any_ci(t, "c-06,c06,main") {
            Ok(Control::C06Main)
        } else if eq_any_ci(t, "c-07,c07,hidden-by-mask,hidden_by_mask") {
            Ok(Control::C07HiddenByMask)
        } else {
            Err(cat3("invalid control '", t, "' (expected C-01..C-07)"))
        }
    }

    pub fn id(&self) -> &'static str {
        match self {
            Control::C01Obvious => "C-01",
            Control::C02Hidden => "C-02",
            Control::C03ExactClone => "C-03",
            Control::C04NoTarget => "C-04",
            Control::C05TargetOnly => "C-05",
            Control::C06Main => "C-06",
            Control::C07HiddenByMask => "C-07",
        }
    }

    #[cfg(test)]
    pub fn slug(&self) -> &'static str {
        match self {
            Control::C01Obvious => "obvious",
            Control::C02Hidden => "hidden",
            Control::C03ExactClone => "exact-clone",
            Control::C04NoTarget => "no-target",
            Control::C05TargetOnly => "target-only",
            Control::C06Main => "main",
            Control::C07HiddenByMask => "hidden-by-mask",
        }
    }

    #[cfg(test)]
    pub fn all() -> &'static [Control] {
        &[
            Control::C01Obvious,
            Control::C02Hidden,
            Control::C03ExactClone,
            Control::C04NoTarget,
            Control::C05TargetOnly,
            Control::C06Main,
            Control::C07HiddenByMask,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HardNeg {
    Hn01Exe,
    Hn02Ppid,
    Hn03Starttime,
    Hn04MemToken,
    Hn05Maps,
    Hn06Fd,
    Hn07Status,
    Hn08Syscall,
    Hn09Cmdline,
    Hn10Threads,
}

impl HardNeg {
    pub fn id(&self) -> &'static str {
        match self {
            HardNeg::Hn01Exe => "HN-01",
            HardNeg::Hn02Ppid => "HN-02",
            HardNeg::Hn03Starttime => "HN-03",
            HardNeg::Hn04MemToken => "HN-04",
            HardNeg::Hn05Maps => "HN-05",
            HardNeg::Hn06Fd => "HN-06",
            HardNeg::Hn07Status => "HN-07",
            HardNeg::Hn08Syscall => "HN-08",
            HardNeg::Hn09Cmdline => "HN-09",
            HardNeg::Hn10Threads => "HN-10",
        }
    }

    pub fn surface(&self) -> &'static str {
        match self {
            HardNeg::Hn01Exe => "exe",
            HardNeg::Hn02Ppid => "ppid",
            HardNeg::Hn03Starttime => "starttime",
            HardNeg::Hn04MemToken => "memory",
            HardNeg::Hn05Maps => "maps",
            HardNeg::Hn06Fd => "fd",
            HardNeg::Hn07Status => "status",
            HardNeg::Hn08Syscall => "syscall",
            HardNeg::Hn09Cmdline => "cmdline",
            HardNeg::Hn10Threads => "threads",
        }
    }

    pub fn all() -> &'static [HardNeg] {
        &[
            HardNeg::Hn01Exe,
            HardNeg::Hn02Ppid,
            HardNeg::Hn03Starttime,
            HardNeg::Hn04MemToken,
            HardNeg::Hn05Maps,
            HardNeg::Hn06Fd,
            HardNeg::Hn07Status,
            HardNeg::Hn08Syscall,
            HardNeg::Hn09Cmdline,
            HardNeg::Hn10Threads,
        ]
    }

    pub fn parse_one(s: &str) -> Result<Self, String> {
        let t = s.trim();
        let all = Self::all();
        const ALIASES: &str = "hn-01,hn01,exe|hn-02,hn02,ppid|hn-03,hn03,starttime|hn-04,hn04,memory,mem,mem-token|hn-05,hn05,maps|hn-06,hn06,fd,fds|hn-07,hn07,status|hn-08,hn08,syscall,wchan|hn-09,hn09,cmdline,argv|hn-10,hn10,threads,task";
        for (i, group) in ALIASES.split('|').enumerate() {
            if eq_any_ci(t, group) {
                return Ok(all[i]);
            }
        }
        Err(cat3(
            "invalid hard-negative '",
            t,
            "' (expected HN-01..HN-10, all, or none)",
        ))
    }

    pub fn parse_list(s: &str) -> Result<Vec<HardNeg>, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
            return Ok(Vec::new());
        }
        if trimmed.eq_ignore_ascii_case("all") {
            return Ok(Self::all().to_vec());
        }
        let mut out = Vec::new();
        for part in trimmed.split(',') {
            let p = part.trim();
            if p.is_empty() || p.eq_ignore_ascii_case("none") {
                continue;
            }
            if p.eq_ignore_ascii_case("all") {
                return Ok(Self::all().to_vec());
            }
            let hn = Self::parse_one(p)?;
            if !out.contains(&hn) {
                out.push(hn);
            }
        }
        Ok(out)
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct RunOpts {
    pub profile: Profile,
    pub decoys: usize,
    pub seed: u64,
    pub mode: Mode,
    pub level: u8,
    pub control: Control,
    pub hard_negatives: Vec<HardNeg>,
    pub observer_uid: Option<u32>,
    pub out_dir: PathBuf,
    pub blind_dir: Option<PathBuf>,
    pub run_id: Option<String>,
    pub live_target_pids: Vec<i32>,
    pub live_decoy_pids: Vec<i32>,
    pub decoy_token_prefix: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResult {
    pub run_id: String,
    pub out_dir: PathBuf,
    pub blind_dir: Option<PathBuf>,
    pub target_pids: Vec<i32>,
    pub decoy_count: usize,
    pub hn_count: usize,
    pub total_rows: usize,
    pub manifest_files: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableRow {
    pub pid: i32,
    pub ppid: i32,
    pub user: String,
    pub comm: String,
    pub args: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Target,
    Decoy,
    ExactClone,
    HardNeg(HardNeg),
    Churn,
}

impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::Target => "target",
            Role::Decoy => "decoy",
            Role::ExactClone => "exact_clone",
            Role::HardNeg(_) => "hard_negative",
            Role::Churn => "churn",
        }
    }
}

struct ProcEntry {
    role: Role,
    profile: Profile,
    mutation: Option<&'static str>,
    decoy_token_len: Option<usize>,
    visible: bool,
    is_live: bool,
    parent_idx: Option<usize>,
    orig_parent_pid: Option<i32>,
    pgrp: i32,
    session: i32,
    depth: u32,
    tie: u64,
}

/// Compact PID set backed by a 65536-bit bitset (zero BTree monomorphization bloat).
struct PidSet {
    bits: Vec<u64>,
    extra: Vec<i32>,
}

impl PidSet {
    fn new() -> Self {
        Self {
            bits: vec![0u64; 1024],
            extra: Vec::new(),
        }
    }

    fn insert(&mut self, pid: i32) {
        if (0..65_536).contains(&pid) {
            let p = pid as usize;
            self.bits[p >> 6] |= 1u64 << (p & 63);
        } else if pid > 0 && !self.extra.contains(&pid) {
            self.extra.push(pid);
        }
    }

    fn contains(&self, pid: i32) -> bool {
        if (0..65_536).contains(&pid) {
            let p = pid as usize;
            (self.bits[p >> 6] & (1u64 << (p & 63))) != 0
        } else {
            self.extra.contains(&pid)
        }
    }

    fn alloc_monotonic(&mut self, start_cursor: i32, span: u32) -> i32 {
        let need = span.max(1) as i32;
        let mut cand = start_cursor.max(300);
        loop {
            if (0..need).all(|off| !self.contains(cand + off)) {
                for off in 0..need {
                    self.insert(cand + off);
                }
                return cand;
            }
            cand += 1;
        }
    }
}

fn reserve_tree_pids(prof: &Profile, alloc: &mut PidSet) {
    alloc.insert(prof.identity.pid);
    for t in &prof.task {
        alloc.insert(t.tid);
    }
    for child in &prof.children {
        reserve_tree_pids(child, alloc);
    }
}

fn sort_tasks(v: &mut [ProfileTask]) {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && v[j - 1].tid > v[j].tid {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
}

fn validate_run_id(id: &str) -> Result<String, String> {
    let trimmed = id.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('\0')
    {
        return Err(cat3("invalid run_id '", trimmed, "'"));
    }
    Ok(trimmed.to_string())
}

fn default_run_id(seed: u64, control: Control, level: u8) -> String {
    let mut mat = String::with_capacity(48);
    mat.push_str("eval:");
    push_u64(&mut mat, seed);
    mat.push(':');
    mat.push_str(control.id());
    mat.push(':');
    push_u64(&mut mat, level as u64);
    let digest = sha256::hash_hex(mat.as_bytes());
    cat2("run-", &digest[..12])
}

fn uid_display(uid: u32) -> String {
    if uid == 0 {
        "root".to_string()
    } else {
        cat2("u", &u64_str(uid as u64))
    }
}

fn uid_quad(id: u32) -> String {
    let s = u64_str(id as u64);
    let mut out = String::with_capacity(s.len() * 4 + 3);
    for i in 0..4 {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&s);
    }
    out
}

fn sanitize_comm_col(comm: &str) -> String {
    let clean: String = comm
        .chars()
        .map(|c| {
            if c.is_ascii_whitespace() || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .take(15)
        .collect();
    if clean.is_empty() {
        "proc".to_string()
    } else {
        clean
    }
}

fn format_args(prof: &Profile) -> String {
    if prof.identity.argv.is_empty() {
        cat3("[", &prof.identity.comm, "]")
    } else {
        let mut out = String::new();
        for (i, a) in prof.identity.argv.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            for ch in a.chars() {
                out.push(if matches!(ch, '\n' | '\r' | '\0') {
                    ' '
                } else {
                    ch
                });
            }
        }
        out
    }
}

pub fn sanitize_live_profile(prof: &mut Profile) {
    prof.identity.cwd = profile::sanitize_host_home(&prof.identity.cwd);
    prof.identity.exe = profile::sanitize_host_home(&prof.identity.exe);
    for arg in &mut prof.identity.argv {
        *arg = profile::sanitize_host_home(arg);
    }
    if let Some(ref execfn) = prof.auxv.at_execfn {
        prof.auxv.at_execfn = Some(profile::sanitize_host_home(execfn));
    }
    for env in &mut prof.environ {
        *env = profile::sanitize_host_home(env);
    }
    for m in &mut prof.memory.maps {
        *m = profile::sanitize_host_home(m);
    }
    for s in &mut prof.memory.smaps {
        *s = profile::sanitize_host_home(s);
    }
    for fd in &mut prof.fds {
        fd.target = profile::sanitize_host_home(&fd.target);
    }
    for child in &mut prof.children {
        sanitize_live_profile(child);
    }
}

/// Normalize ephemeral kernel pipe/socket inodes so FD shape comparison
/// matches across peers that hold distinct realistic inodes.
pub fn normalize_fd_target(target: &str) -> String {
    for prefix in ["pipe:[", "socket:["] {
        if let Some(rest) = target.strip_prefix(prefix) {
            if let Some(inner) = rest.strip_suffix(']') {
                if !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_digit()) {
                    return cat2(prefix, "<ino>]");
                }
            }
        }
    }
    target.to_string()
}

/// Derive unique realistic per-process inodes for `pipe:[<digits>]` and `socket:[<digits>]`.
/// Identical original inodes within the SAME process (e.g., fd 1 & fd 2 sharing a log pipe)
/// map to the same derived inode, while distinct processes get distinct realistic inodes.
fn remap_synthetic_fd_inodes(fds: &mut [ProfileFd], seed: u64, pid: i32) {
    for fd in fds.iter_mut() {
        for prefix in ["pipe:[", "socket:["] {
            if let Some(rest) = fd.target.strip_prefix(prefix) {
                if let Some(inner) = rest.strip_suffix(']') {
                    if let Some(orig_ino) = json::parse_u64_s(inner) {
                        let mix = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                            ^ (pid as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9)
                            ^ orig_ino.wrapping_mul(0x94D0_49BB_1331_11EB);
                        let mut r = Rng::new(mix);
                        let new_ino = 100_000 + r.below(8_900_000);
                        fd.target = cat3(prefix, &u64_str(new_ino), "]");
                        break;
                    }
                }
            }
        }
    }
}

/// Generate a deterministic 32-byte decoy token matching target token length.
fn generate_decoy_token(rng: &mut Rng, prefix: &str) -> (usize, String) {
    let raw_pfx = if prefix.trim().is_empty() {
        "dtok_"
    } else {
        prefix.trim()
    };
    let pfx_len = raw_pfx.len().min(DECOY_TOKEN_LEN - 8);
    let pfx = &raw_pfx[..pfx_len];
    let hex_len = DECOY_TOKEN_LEN - pfx_len;
    let mut hex_buf = [0u8; DECOY_TOKEN_LEN];
    rng.hex(hex_len, &mut hex_buf[..hex_len]);
    let mut token = String::with_capacity(DECOY_TOKEN_LEN);
    token.push_str(pfx);
    token.push_str(std::str::from_utf8(&hex_buf[..hex_len]).unwrap_or("00000000"));
    (token.len(), sha256::hash_hex(token.as_bytes()))
}

fn sync_node_pid_ppid(node: &mut Profile, pid: i32, ppid: i32, orig_parent_pid: Option<i32>) {
    let old_pid = node.identity.pid;
    node.identity.pid = pid;
    node.identity.ppid = ppid;
    node.status.ppid = ppid;
    node.stat.ppid = ppid;
    if let Some(orig_p) = orig_parent_pid {
        if node.status.tracer_pid == orig_p && orig_p > 0 {
            node.status.tracer_pid = ppid;
        }
    }

    let wanted = node.status.threads.max(node.stat.num_threads).max(1);
    node.status.threads = wanted;
    node.stat.num_threads = wanted;

    let mut new_tasks = Vec::with_capacity(wanted as usize);
    if node.task.is_empty() {
        new_tasks.push(ProfileTask {
            tid: pid,
            comm: node.identity.comm.clone(),
            state: node.status.state.clone(),
        });
    } else {
        let mut next_extra = 1i32;
        let mut main_placed = false;
        for t in &node.task {
            let tid = if !main_placed && t.tid == old_pid {
                main_placed = true;
                pid
            } else {
                let x = pid + next_extra;
                next_extra += 1;
                x
            };
            new_tasks.push(ProfileTask {
                tid,
                comm: t.comm.clone(),
                state: t.state.clone(),
            });
        }
        if !main_placed {
            if let Some(first) = new_tasks.first_mut() {
                first.tid = pid;
            }
        }
    }
    while (new_tasks.len() as u32) < wanted {
        new_tasks.push(ProfileTask {
            tid: pid + new_tasks.len() as i32,
            comm: node.identity.comm.clone(),
            state: node.status.state.clone(),
        });
    }
    sort_tasks(&mut new_tasks);
    node.task = new_tasks;
}

/// Push a synthetic process tree into `out` with parent links and tiebreakers.
/// Actual monotonic PIDs are assigned in `assign_synthetic_pids` once all entries exist.
#[inline(never)]
fn push_synthetic_tree(
    template: &Profile,
    roles: (Role, Role),
    rng: &mut Rng,
    parent_link: Option<(usize, i32, u64)>,
    depth: u32,
    visible: bool,
    out: &mut Vec<ProcEntry>,
) -> usize {
    let (role, child_role) = roles;
    let mut node = template.clone();
    let kids = std::mem::take(&mut node.children);
    let orig_pid = node.identity.pid;
    let (parent_idx, orig_parent_pid) = match parent_link {
        Some((pidx, orig_p, parent_st)) => {
            if node.identity.starttime < parent_st {
                node.identity.starttime = parent_st;
                node.stat.starttime = parent_st;
            }
            (Some(pidx), Some(orig_p))
        }
        None => (None, None),
    };

    let tok_len = if node.memory.token_present {
        Some(DECOY_TOKEN_LEN)
    } else {
        None
    };

    let my_st = node.identity.starttime;
    let my_idx = out.len();
    out.push(ProcEntry {
        role,
        profile: node,
        mutation: None,
        decoy_token_len: tok_len,
        visible,
        is_live: false,
        parent_idx,
        orig_parent_pid,
        pgrp: 0,
        session: 0,
        depth,
        tie: rng.next_u64(),
    });

    for child in &kids {
        push_synthetic_tree(
            child,
            (child_role, child_role),
            rng,
            Some((my_idx, orig_pid, my_st)),
            depth + 1,
            visible,
            out,
        );
    }
    my_idx
}

/// Assign monotonically increasing PIDs correlated with `starttime` across all synthetic entries,
/// guaranteeing `child.pid > parent.pid`, realistic `pgrp`/`session` inheritance, and unique
/// per-process pipe/socket inodes.
fn assign_synthetic_pids(entries: &mut [ProcEntry], alloc: &mut PidSet, rng: &mut Rng, seed: u64) {
    let mut synth: Vec<usize> = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        if !e.is_live {
            synth.push(i);
        }
    }

    // Shellsort by (starttime, depth, random tiebreaker) so parents always precede children
    // and PID order monotonically tracks process creation time (avoids core::slice::sort bloat).
    const GAPS: &[usize] = &[701, 301, 132, 57, 23, 10, 4, 1];
    let key = |idx: usize| {
        let e = &entries[idx];
        (e.profile.identity.starttime, e.depth, e.tie)
    };
    let slen = synth.len();
    for &gap in GAPS {
        if gap >= slen {
            continue;
        }
        for i in gap..slen {
            let mut j = i;
            while j >= gap && key(synth[j - gap]) > key(synth[j]) {
                synth.swap(j - gap, j);
                j -= gap;
            }
        }
    }

    let n = synth.len().max(1);
    let mut cursor = rng.range(1_200, 3_600) as i32;
    let max_step = ((52_000i32 - cursor) / n as i32).clamp(2, 40) as u64;
    let mut prev_st: Option<u64> = None;

    for idx in synth {
        let span = entries[idx]
            .profile
            .status
            .threads
            .max(entries[idx].profile.stat.num_threads)
            .max(entries[idx].profile.task.len() as u32)
            .max(1);
        let st = entries[idx].profile.identity.starttime;
        let step = rng.range(1, max_step) as i32;
        let jump_bonus = match prev_st {
            Some(pst) if st > pst => ((st - pst) / 2_000).min(12) as i32,
            _ => 0,
        };
        cursor = cursor.saturating_add(step + jump_bonus);
        if let Some(pidx) = entries[idx].parent_idx {
            let parent_pid = entries[pidx].profile.identity.pid;
            if cursor <= parent_pid {
                cursor = parent_pid + 1;
            }
        }
        let pid = alloc.alloc_monotonic(cursor, span);
        cursor = pid + span as i32;
        prev_st = Some(st);

        let (ppid, pgrp, session) = match entries[idx].parent_idx {
            Some(pidx) => (
                entries[pidx].profile.identity.pid,
                entries[pidx].pgrp,
                entries[pidx].session,
            ),
            None => (entries[idx].profile.identity.ppid, pid, pid),
        };
        let orig_parent_pid = entries[idx].orig_parent_pid;
        sync_node_pid_ppid(&mut entries[idx].profile, pid, ppid, orig_parent_pid);
        entries[idx].pgrp = pgrp;
        entries[idx].session = session;
        remap_synthetic_fd_inodes(&mut entries[idx].profile.fds, seed, pid);
    }

    // Set pgrp/session for live entries (children inherit parent's pgrp/session).
    for idx in 0..entries.len() {
        if entries[idx].is_live {
            let (pgrp, session) = match entries[idx].parent_idx {
                Some(pidx) => (entries[pidx].pgrp, entries[pidx].session),
                None => {
                    let pid = entries[idx].profile.identity.pid;
                    (pid, pid)
                }
            };
            entries[idx].pgrp = pgrp;
            entries[idx].session = session;
        }
    }
}

fn adjust_smaps_heap_rss(smaps: &mut [String], delta_kb: i64) {
    if delta_kb == 0 {
        return;
    }
    for line in smaps.iter_mut() {
        if !line.contains("[heap]") {
            continue;
        }
        let Some(rss_pos) = line.find("Rss:") else {
            continue;
        };
        let after_rss = &line[rss_pos + 4..];
        let Some(kb_pos) = after_rss.find("kB") else {
            continue;
        };
        let Some(cur_kb) = json::parse_u64_s(&after_rss[..kb_pos]) else {
            continue;
        };
        let new_kb = (cur_kb as i64).saturating_add(delta_kb).max(64) as u64;
        let prefix = &line[..rss_pos];
        let mut rebuilt = String::with_capacity(line.len() + 8);
        rebuilt.push_str(prefix);
        rebuilt.push_str("Rss:");
        push_u64(&mut rebuilt, new_kb);
        rebuilt.push_str("kB Private_Dirty:");
        push_u64(&mut rebuilt, new_kb);
        rebuilt.push_str("kB Anonymous:");
        push_u64(&mut rebuilt, new_kb);
        rebuilt.push_str("kB");
        *line = rebuilt;
        break;
    }
}

/// Apply Level 6 `starttime`, 4K-aligned `vsize`, and `rss` (plus matching `smaps`) jitter.
/// Applied symmetrically to BOTH synthetic Target and Level 6 decoys so Target is statistically
/// indistinguishable from the decoy distribution.
fn apply_level6_jitter(node: &mut Profile, rng: &mut Rng, parent_starttime: Option<u64>) {
    let base_st = match parent_starttime {
        Some(pst) => pst.saturating_add(rng.range(5, 45)),
        None => {
            let offset = rng.range(0, 24_000) as i64 - 12_000;
            (node.identity.starttime as i64)
                .saturating_add(offset)
                .max(100) as u64
        }
    };
    node.identity.starttime = base_st;
    node.stat.starttime = base_st;

    let aligned_vsize = node.stat.vsize & !4095u64;
    let vsize_delta = (rng.range(0, 16) as i64 - 8) * 4096;
    node.stat.vsize = (aligned_vsize as i64).saturating_add(vsize_delta).max(4096) as u64;

    let old_rss = node.stat.rss;
    let rss_delta = rng.range(0, 16) as i64 - 8;
    let new_rss = (old_rss as i64).saturating_add(rss_delta).max(16) as u64;
    node.stat.rss = new_rss;
    let delta_kb = (new_rss as i64 - old_rss as i64) * 4;
    adjust_smaps_heap_rss(&mut node.memory.smaps, delta_kb);

    for child in &mut node.children {
        apply_level6_jitter(child, rng, Some(base_st));
    }
}

fn reset_decoy_deep(
    d: &mut Profile,
    exe: &str,
    ino: &str,
    exe_kb: u64,
    heap_kb: u64,
    sc: &str,
    wchan: &str,
) {
    d.identity.exe = exe.to_string();
    d.identity.exe_memfd = None;
    d.auxv.at_execfn = Some(exe.to_string());
    let (maps, smaps) = profile::basic_maps_smaps(exe, ino, exe_kb, heap_kb);
    d.memory.maps = maps;
    d.memory.smaps = smaps;
    d.memory.token_present = false;
    d.memory.token_sha256 = None;
    d.syscall.syscall = sc.to_string();
    d.syscall.wchan = wchan.to_string();
    d.dumpable = Some(true);
}

fn null_fds(n: i32) -> Vec<ProfileFd> {
    (0..n)
        .map(|fd| ProfileFd {
            fd,
            target: "/dev/null".to_string(),
        })
        .collect()
}

fn build_level1_decoy(target: &Profile, rng: &mut Rng) -> Profile {
    let mut d = target.clone();
    d.children.clear();
    let st = target
        .identity
        .starttime
        .saturating_add(rng.range(50, 5_000));
    d.source.masker = "level1".to_string();
    d.source.profile = "single".to_string();
    d.identity.comm = "sleep".to_string();
    d.identity.argv = vec![target.identity.label.clone(), "1800".to_string()];
    d.identity.cmdline_raw_nuls = Some(1);
    d.identity.pid = 0;
    d.identity.ppid = 1;
    d.identity.starttime = st;
    d.identity.cwd = "/tmp".to_string();
    d.status.name = "sleep".to_string();
    d.status.state = "S".to_string();
    d.status.ppid = 1;
    d.status.threads = 1;
    d.status.tracer_pid = 0;
    d.status.no_new_privs = 0;
    d.status.seccomp = 0;
    d.status.seccomp_filters = 0;
    d.stat.ppid = 1;
    d.stat.num_threads = 1;
    d.stat.starttime = st;
    d.stat.vsize = 5_840_896;
    d.stat.rss = 192;
    d.memory.denied_by.clear();
    d.fds = null_fds(3);
    d.environ = vec!["PATH=/usr/bin:/bin".to_string(), "LANG=C".to_string()];
    d.task = vec![ProfileTask {
        tid: 0,
        comm: "sleep".to_string(),
        state: "S".to_string(),
    }];
    reset_decoy_deep(
        &mut d,
        "/usr/bin/sleep",
        "501",
        256,
        384,
        "clock_nanosleep",
        "hrtimer_nanosleep",
    );
    d
}

fn build_level2_decoy(target: &Profile, rng: &mut Rng) -> Profile {
    let mut d = target.clone();
    d.children.clear();
    let alt_ppid = if target.identity.ppid == 1 { 412 } else { 1 };
    let alt_exe = if target.identity.exe == "/usr/libexec/decoy-stub" {
        "/usr/bin/decoy-stub"
    } else {
        "/usr/libexec/decoy-stub"
    };
    d.identity.ppid = alt_ppid;
    d.status.ppid = alt_ppid;
    d.stat.ppid = alt_ppid;
    d.identity.cwd = "/tmp".to_string();
    d.identity.starttime = target
        .identity
        .starttime
        .saturating_add(rng.range(20, 4_000));
    d.stat.starttime = d.identity.starttime;
    d.environ = vec!["PATH=/usr/bin:/bin".to_string(), "LANG=C".to_string()];
    d.fds = null_fds(2);
    reset_decoy_deep(
        &mut d,
        alt_exe,
        "777",
        1536,
        2432,
        "nanosleep",
        "hrtimer_nanosleep",
    );
    d
}

fn degrade_deep_for_level3(node: &mut Profile, rng: &mut Rng, parent_st: Option<u64>) {
    let alt_exe = if node.identity.exe == "/usr/libexec/decoy-tree-worker" {
        "/usr/bin/decoy-tree-worker"
    } else {
        "/usr/libexec/decoy-tree-worker"
    };
    let sc = node.syscall.syscall.clone();
    let wc = node.syscall.wchan.clone();
    reset_decoy_deep(node, alt_exe, "888", 1536, 2432, &sc, &wc);
    node.environ = vec![
        "PATH=/usr/bin:/bin".to_string(),
        "DECOY_STAGE=tree-only".to_string(),
    ];
    node.fds = vec![
        ProfileFd {
            fd: 0,
            target: "/dev/null".to_string(),
        },
        ProfileFd {
            fd: 1,
            target: "pipe:[99001]".to_string(),
        },
    ];
    let st = match parent_st {
        Some(pst) => pst.saturating_add(rng.range(5, 45)),
        None => node.identity.starttime.saturating_add(rng.range(10, 2_000)),
    };
    node.identity.starttime = st;
    node.stat.starttime = st;
    for child in &mut node.children {
        degrade_deep_for_level3(child, rng, Some(st));
    }
}

fn tree_has_token(p: &Profile) -> bool {
    p.memory.token_present || p.children.iter().any(tree_has_token)
}

fn prepare_level4_to_6_decoy(
    target: &Profile,
    level: u8,
    rng: &mut Rng,
    token_prefix: &str,
    is_root: bool,
    target_tree_has_token: bool,
) -> (Profile, Option<usize>) {
    let mut node = target.clone();
    let mut tok_len = None;

    if level == 4 {
        node.memory.token_present = false;
        node.memory.token_sha256 = None;
    } else {
        let place_token = node.memory.token_present || (!target_tree_has_token && is_root);
        if place_token {
            let (tlen, digest) = generate_decoy_token(rng, token_prefix);
            node.memory.token_present = true;
            node.memory.token_sha256 = Some(digest);
            tok_len = Some(tlen);
        } else {
            node.memory.token_present = false;
            node.memory.token_sha256 = None;
        }
    }

    let orig_children = std::mem::take(&mut node.children);
    let mut new_children = Vec::with_capacity(orig_children.len());
    for child in &orig_children {
        let (c_node, _) = prepare_level4_to_6_decoy(
            child,
            level,
            rng,
            token_prefix,
            false,
            target_tree_has_token,
        );
        new_children.push(c_node);
    }
    node.children = new_children;

    if is_root && level >= 6 {
        apply_level6_jitter(&mut node, rng, None);
    }

    (node, tok_len)
}

fn build_hard_negative(
    target: &Profile,
    hn: HardNeg,
    level: u8,
    rng: &mut Rng,
    token_prefix: &str,
) -> (Profile, &'static str, Option<usize>) {
    let mut node = target.clone();
    if level >= 5 {
        for child in &mut node.children {
            if child.memory.token_present {
                let (_, digest) = generate_decoy_token(rng, token_prefix);
                child.memory.token_sha256 = Some(digest);
            }
        }
    }
    if level >= 6 {
        apply_level6_jitter(&mut node, rng, None);
    }

    let mut tok_len = if node.memory.token_present {
        Some(DECOY_TOKEN_LEN)
    } else {
        None
    };

    let mutation = match hn {
        HardNeg::Hn01Exe => {
            let new_exe = if node.identity.exe == "/usr/bin/hn01-alt-bin" {
                "/usr/local/bin/hn01-alt-bin"
            } else {
                "/usr/bin/hn01-alt-bin"
            };
            node.identity.exe = new_exe.to_string();
            node.identity.exe_memfd = None;
            node.auxv.at_execfn = Some(new_exe.to_string());
            "exe mutated"
        }
        HardNeg::Hn02Ppid => {
            let new_ppid = if node.identity.ppid == 1 { 2048 } else { 1 };
            node.identity.ppid = new_ppid;
            node.status.ppid = new_ppid;
            node.stat.ppid = new_ppid;
            "ppid mutated"
        }
        HardNeg::Hn03Starttime => {
            let new_st = node.identity.starttime.saturating_add(500_000);
            node.identity.starttime = new_st;
            node.stat.starttime = new_st;
            for child in &mut node.children {
                child.identity.starttime = new_st.saturating_add(18);
                child.stat.starttime = child.identity.starttime;
            }
            "starttime mutated"
        }
        HardNeg::Hn04MemToken => {
            let flipped = !node.memory.token_present;
            node.memory.token_present = flipped;
            if flipped {
                let (tlen, digest) = generate_decoy_token(rng, token_prefix);
                node.memory.token_sha256 = Some(digest);
                tok_len = Some(tlen);
            } else {
                node.memory.token_sha256 = None;
                tok_len = None;
            }
            "mem_scan token_present mutated"
        }
        HardNeg::Hn05Maps => {
            node.memory
                .maps
                .push("<addr> rwxp 00000000 00:00 0 /tmp/hn05-injected.so".to_string());
            node.memory.smaps.push(
                "rwxp /tmp/hn05-injected.so Rss:128kB Private_Dirty:128kB Anonymous:128kB"
                    .to_string(),
            );
            "maps mutated"
        }
        HardNeg::Hn06Fd => {
            let next_fd = node.fds.iter().map(|f| f.fd).max().unwrap_or(2) + 1;
            node.fds.push(ProfileFd {
                fd: next_fd,
                target: "socket:[9999006]".to_string(),
            });
            "fd added"
        }
        HardNeg::Hn07Status => {
            node.status.no_new_privs = u32::from(node.status.no_new_privs == 0);
            node.status.seccomp = if node.status.seccomp == 0 { 2 } else { 0 };
            node.status.seccomp_filters = u32::from(node.status.seccomp == 2);
            node.status.tracer_pid = if node.status.tracer_pid == 0 { 9999 } else { 0 };
            "status flags mutated"
        }
        HardNeg::Hn08Syscall => {
            if node.syscall.syscall == "epoll_wait" {
                node.syscall.syscall = "nanosleep".to_string();
                node.syscall.wchan = "hrtimer_nanosleep".to_string();
            } else {
                node.syscall.syscall = "epoll_wait".to_string();
                node.syscall.wchan = "do_epoll_wait".to_string();
            }
            "syscall mutated"
        }
        HardNeg::Hn09Cmdline => {
            if node.identity.argv.is_empty() {
                node.identity.argv.push(node.identity.comm.clone());
            }
            node.identity.argv.push("--hn09-mutated-arg".to_string());
            if node.stat.arg_start != 0 {
                let new_len = render_cmdline_bytes(&node).len() as u64;
                let new_arg_end = node.stat.arg_start.saturating_add(new_len);
                if node.stat.env_start > 0 && new_arg_end > node.stat.env_start {
                    let shift = new_arg_end - node.stat.env_start;
                    node.stat.env_start = node.stat.env_start.saturating_add(shift);
                    node.stat.env_end = node.stat.env_end.saturating_add(shift);
                }
                node.stat.arg_end = new_arg_end;
            }
            "cmdline argv mutated"
        }
        HardNeg::Hn10Threads => {
            let new_threads = node.status.threads.saturating_add(3);
            node.status.threads = new_threads;
            node.stat.num_threads = new_threads;
            let base_tid = node.identity.pid;
            for i in 1..=3 {
                node.task.push(ProfileTask {
                    tid: base_tid + i,
                    comm: cat2("hn10-worker-", &i64_str(i as i64)),
                    state: "S".to_string(),
                });
            }
            "thread count mutated"
        }
    };

    (node, mutation, tok_len)
}

fn build_churn_processes(target: &Profile, count: usize, rng: &mut Rng) -> Vec<ProcEntry> {
    const DAEMONS: &str =
        "systemd-journal|/usr/lib/systemd/systemd-journald|epoll_wait|do_epoll_wait\n\
dbus-daemon|/usr/bin/dbus-daemon|epoll_wait|do_epoll_wait\n\
rsyslogd|/usr/sbin/rsyslogd|ppoll|do_sys_poll\n\
sshd|/usr/sbin/sshd|poll|do_sys_poll\n\
cron|/usr/sbin/cron|nanosleep|hrtimer_nanosleep";
    let churn_uid = if target.identity.uid == 0 { 65534 } else { 0 };
    let uid_str = uid_quad(churn_uid);
    let pairs = (count / 2).clamp(1, 5);
    let mut out = Vec::with_capacity(pairs * 2);

    for line in DAEMONS.lines().take(pairs) {
        let mut p = line.split('|');
        let (Some(comm), Some(exe), Some(sc), Some(wchan)) =
            (p.next(), p.next(), p.next(), p.next())
        else {
            continue;
        };
        for _ in 0..2 {
            let st = target
                .identity
                .starttime
                .saturating_sub(rng.range(1_000, 10_000))
                .max(50);
            let mut prof = build_level1_decoy(target, rng);
            prof.source.masker = "churn".to_string();
            prof.identity.label = comm.to_string();
            prof.identity.comm = comm.to_string();
            prof.identity.argv = vec![exe.to_string()];
            prof.identity.pid = 0;
            prof.identity.uid = churn_uid;
            prof.identity.gid = churn_uid;
            prof.identity.starttime = st;
            prof.identity.cwd = "/".to_string();
            prof.status.name = comm.to_string();
            prof.status.uid = uid_str.clone();
            prof.status.gid = uid_str.clone();
            prof.stat.starttime = st;
            prof.stat.vsize = 18_432_000;
            prof.stat.rss = 1024;
            reset_decoy_deep(&mut prof, exe, "101", 1536, 2432, sc, wchan);
            prof.task = vec![ProfileTask {
                tid: 0,
                comm: comm.to_string(),
                state: "S".to_string(),
            }];
            out.push(ProcEntry {
                role: Role::Churn,
                profile: prof,
                mutation: None,
                decoy_token_len: None,
                visible: true,
                is_live: false,
                parent_idx: None,
                orig_parent_pid: None,
                pgrp: 0,
                session: 0,
                depth: 0,
                tie: rng.next_u64(),
            });
        }
    }
    out
}

fn is_dumpable_denied(entry: &ProcEntry, observer_uid: u32) -> bool {
    entry.profile.dumpable == Some(false) && observer_uid != 0
}

fn state_label(code: &str) -> &'static str {
    match code {
        "R" => "R (running)",
        "S" => "S (sleeping)",
        "D" => "D (disk sleep)",
        "T" => "T (stopped)",
        "t" => "t (tracing stop)",
        "Z" => "Z (zombie)",
        "X" => "X (dead)",
        "I" => "I (idle)",
        _ => "S (sleeping)",
    }
}

#[inline(never)]
fn push_kv_str(out: &mut String, k: &str, v: &str) {
    out.push_str(k);
    out.push_str(":\t");
    out.push_str(v);
    out.push('\n');
}

fn push_kv_tab_str(out: &mut String, k: &str, v: &str) {
    out.push_str(k);
    out.push_str(":\t");
    for ch in v.chars() {
        out.push(if ch == ' ' { '\t' } else { ch });
    }
    out.push('\n');
}

#[inline(never)]
fn push_kv_i64(out: &mut String, k: &str, v: i64) {
    out.push_str(k);
    out.push_str(":\t");
    push_i64(out, v);
    out.push('\n');
}

#[inline(never)]
fn push_kv_kb(out: &mut String, k: &str, kb: u64) {
    out.push_str(k);
    out.push_str(":\t");
    push_u64_right(out, kb, 8);
    out.push_str(" kB\n");
}

fn render_status_file(p: &Profile) -> String {
    let mut out = String::with_capacity(512);
    push_kv_str(&mut out, "Name", &p.status.name);
    push_kv_str(&mut out, "State", state_label(&p.status.state));
    for (k, v) in [
        ("Tgid", p.identity.pid as i64),
        ("Pid", p.identity.pid as i64),
        ("PPid", p.status.ppid as i64),
        ("TracerPid", p.status.tracer_pid as i64),
    ] {
        push_kv_i64(&mut out, k, v);
    }
    push_kv_tab_str(&mut out, "Uid", &p.status.uid);
    push_kv_tab_str(&mut out, "Gid", &p.status.gid);
    push_kv_i64(&mut out, "Threads", p.status.threads as i64);
    for (k, kb) in [
        ("VmSize", p.stat.vsize / 1024),
        ("VmRSS", p.stat.rss.saturating_mul(4)),
        ("VmLck", p.status.vm_lck.unwrap_or(0)),
        ("RssShmem", p.status.rss_shmem.unwrap_or(0)),
    ] {
        push_kv_kb(&mut out, k, kb);
    }
    for (k, v) in [
        ("CapPrm", p.status.cap_prm.as_str()),
        ("CapEff", p.status.cap_eff.as_str()),
        ("CapBnd", p.status.cap_bnd.as_str()),
    ] {
        push_kv_str(&mut out, k, v);
    }
    for (k, v) in [
        ("NoNewPrivs", p.status.no_new_privs as i64),
        ("Seccomp", p.status.seccomp as i64),
        ("Seccomp_filters", p.status.seccomp_filters as i64),
    ] {
        push_kv_i64(&mut out, k, v);
    }
    out
}

fn push_sp_u64s(out: &mut String, vals: &[u64]) {
    for &v in vals {
        out.push(' ');
        push_u64(out, v);
    }
}

fn render_stat_file(p: &Profile, pgrp: i32, session: i32, denied: bool) -> String {
    let flags = p.stat.flags.unwrap_or(4_194_304);
    let (startstack, arg_s, arg_e, env_s, env_e) = if denied {
        (0, 0, 0, 0, 0)
    } else {
        (
            p.stat.startstack,
            p.stat.arg_start,
            p.stat.arg_end,
            p.stat.env_start,
            p.stat.env_end,
        )
    };
    let pg = if pgrp > 0 { pgrp } else { p.identity.pid };
    let sid = if session > 0 { session } else { p.identity.pid };
    let mut out = String::with_capacity(256);
    push_i64(&mut out, p.identity.pid as i64);
    out.push_str(" (");
    out.push_str(&p.identity.comm);
    out.push_str(") ");
    out.push_str(&p.status.state);
    for v in [p.stat.ppid, pg, sid] {
        out.push(' ');
        push_i64(&mut out, v as i64);
    }
    out.push_str(" 0 -1 ");
    push_u64(&mut out, flags);
    out.push_str(" 0 0 0 0 0 0 0 0 ");
    push_i64(&mut out, p.syscall.priority as i64);
    out.push_str(" 0 ");
    push_u64(&mut out, p.stat.num_threads as u64);
    out.push_str(" 0");
    push_sp_u64s(&mut out, &[p.stat.starttime, p.stat.vsize, p.stat.rss]);
    out.push_str(" 18446744073709551615 0 0 ");
    push_u64(&mut out, startstack);
    out.push_str(" 0 0 0 0 0 0 0 0 0 17 0 0 ");
    push_i64(&mut out, p.syscall.policy as i64);
    out.push_str(" 0 0 0 0 0 0");
    push_sp_u64s(&mut out, &[arg_s, arg_e, env_s, env_e]);
    out.push_str(" 0\n");
    out
}

fn render_cmdline_bytes(p: &Profile) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, arg) in p.identity.argv.iter().enumerate() {
        if i > 0 {
            out.push(0);
        }
        out.extend_from_slice(arg.as_bytes());
    }
    let nuls = p.identity.cmdline_raw_nuls.unwrap_or(1);
    out.resize(out.len() + nuls, 0);
    out
}

fn write_deep_entry(deep_root: &Path, entry: &ProcEntry, observer_uid: u32) -> Result<(), String> {
    let p = &entry.profile;
    let pid_dir = deep_root.join(i64_str(p.identity.pid as i64));
    let fd_dir = pid_dir.join("fd");
    let task_dir = pid_dir.join("task");
    mkdir_all(&fd_dir)?;
    mkdir_all(&task_dir)?;

    let denied = is_dumpable_denied(entry, observer_uid);
    let mut o = OutDir::new(&pid_dir);
    o.write("status", render_status_file(p).as_bytes());
    o.write(
        "stat",
        render_stat_file(p, entry.pgrp, entry.session, denied).as_bytes(),
    );
    o.write("cmdline", &render_cmdline_bytes(p));
    o.line("comm", &p.identity.comm);
    o.line("syscall", &p.syscall.syscall);
    o.line("wchan", &p.syscall.wchan);

    let mut w = Jw::new(true);
    w.obj_open();
    w.k_opt_str("pid", &p.identity.ns.pid);
    w.k_opt_str("mnt", &p.identity.ns.mnt);
    w.k_opt_str("user", &p.identity.ns.user);
    w.k_opt_str("net", &p.identity.ns.net);
    w.obj_close();
    o.jw("ns.json", &mut w);

    w.reset(true);
    w.arr_open();
    let mut to = OutDir::new(&task_dir);
    for t in &p.task {
        w.elem_obj();
        w.k_i64("tid", t.tid as i64);
        w.k_str("comm", &t.comm);
        w.k_str("state", &t.state);
        w.obj_close();
        let body = cat4("comm=", &t.comm, "\nstate=", &t.state);
        to.line(&i64_str(t.tid as i64), &body);
    }
    w.arr_close();
    o.jw("task.json", &mut w);

    if denied {
        let eacces = b"EACCES: permission denied\n";
        for name in "exe,cwd,environ,auxv,maps,smaps".split(',') {
            o.write(name, eacces);
        }
        o.write("fd.json", b"{\n  \"error\": \"EACCES\"\n}\n");
    } else {
        o.line("exe", &p.identity.exe);
        o.line("cwd", &p.identity.cwd);
        o.lines("environ", &p.environ);
        w.out.clear();
        w.out.push_str("AT_EXECFN=");
        w.out.push_str(p.auxv.at_execfn.as_deref().unwrap_or(""));
        w.out.push_str("\nAT_PLATFORM=");
        w.out.push_str(p.auxv.at_platform.as_deref().unwrap_or(""));
        w.out.push_str("\nAT_BASE=");
        push_u64(&mut w.out, p.auxv.at_base);
        w.out.push_str("\nAT_ENTRY=");
        push_u64(&mut w.out, p.auxv.at_entry);
        w.out.push('\n');
        o.write("auxv", w.out.as_bytes());
        o.lines("maps", &p.memory.maps);
        o.lines("smaps", &p.memory.smaps);

        w.reset(true);
        w.arr_open();
        let mut fo = OutDir::new(&fd_dir);
        for f in &p.fds {
            w.elem_obj();
            w.k_i64("fd", f.fd as i64);
            w.k_str("target", &f.target);
            w.obj_close();
            fo.line(&i64_str(f.fd as i64), &f.target);
        }
        w.arr_close();
        o.jw("fd.json", &mut w);
        fo.check()?;
    }

    w.reset(true);
    w.obj_open();
    w.k_bool("readable", !denied);
    if denied {
        w.k_str("error", "EACCES");
        w.k_null("token_present");
        w.k_null("token_len");
    } else {
        w.k_bool("token_present", p.memory.token_present);
        match entry.decoy_token_len {
            Some(n) => w.k_u64("token_len", n as u64),
            None if p.memory.token_present => w.k_u64("token_len", DECOY_TOKEN_LEN as u64),
            None => w.k_null("token_len"),
        }
    }
    w.obj_close();
    o.jw("mem_scan.json", &mut w);
    to.check()?;
    o.check()
}

fn render_blind_table(entries: &[ProcEntry], indices: &[usize]) -> String {
    let mut out = String::from("PID     PPID    USER       COMM            ARGS\n");
    for &idx in indices {
        let p = &entries[idx].profile;
        push_i64_right(&mut out, p.identity.pid as i64, 7);
        out.push(' ');
        push_i64_right(&mut out, p.identity.ppid as i64, 7);
        out.push(' ');
        push_str_left(&mut out, &uid_display(p.identity.uid), 10);
        out.push(' ');
        push_str_left(&mut out, &sanitize_comm_col(&p.identity.comm), 15);
        out.push(' ');
        out.push_str(&format_args(p));
        out.push('\n');
    }
    out
}

/// Parse `blind-table.txt` rows into structured `TableRow` records.
pub fn parse_blind_table(text: &str) -> Result<Vec<TableRow>, String> {
    let mut rows = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || (idx == 0 && trimmed.starts_with("PID")) {
            continue;
        }
        let line_no = idx + 1;
        let bad = |msg: &str| cat4("blind-table line ", &u64_str(line_no as u64), ": ", msg);
        let mut parts = trimmed.split_ascii_whitespace();
        let pid = parts
            .next()
            .and_then(json::parse_i32_s)
            .ok_or_else(|| bad("invalid PID"))?;
        let ppid = parts
            .next()
            .and_then(json::parse_i32_s)
            .ok_or_else(|| bad("invalid PPID"))?;
        let user = parts.next().ok_or_else(|| bad("missing USER"))?;
        let comm = parts.next().ok_or_else(|| bad("missing COMM"))?;
        let mut args = String::new();
        for (i, a) in parts.enumerate() {
            if i > 0 {
                args.push(' ');
            }
            args.push_str(a);
        }
        rows.push(TableRow {
            pid,
            ppid,
            user: user.to_string(),
            comm: comm.to_string(),
            args,
        });
    }
    Ok(rows)
}

/// Convenience helper returning all PIDs present in `blind-table.txt`.
pub fn parse_blind_table_pids(text: &str) -> Vec<i32> {
    parse_blind_table(text)
        .map(|rows| rows.into_iter().map(|r| r.pid).collect())
        .unwrap_or_default()
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    mkdir_all(dst)?;
    let entries = fs::read_dir(src).map_err(|e| err_io("cannot read", src, &e))?;
    for entry in entries {
        let entry = entry.map_err(|e| err_io("cannot read", src, &e))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let meta =
            fs::symlink_metadata(&src_path).map_err(|e| err_io("cannot stat", &src_path, &e))?;
        if meta.file_type().is_symlink() {
            return Err("refusing symlink in blind_dir".to_string());
        }
        if meta.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if meta.is_file() {
            let data = json::read_bytes(&src_path)?;
            write_file(&dst_path, &data)?;
        }
    }
    Ok(())
}

/// Format canonical `status` security/capability signature (shared by `harness` and `selftest`).
pub fn format_status_sig(
    nnp: &str,
    sec: &str,
    sf: &str,
    traced: bool,
    cap_eff: &str,
    cap_prm: &str,
    cap_bnd: &str,
) -> String {
    let mut s = String::with_capacity(96);
    s.push_str("nnp=");
    s.push_str(nnp);
    s.push_str("|sec=");
    s.push_str(sec);
    s.push_str("|sf=");
    s.push_str(sf);
    s.push_str("|tr=");
    s.push_str(if traced { "true" } else { "false" });
    s.push_str("|ce=");
    s.push_str(cap_eff);
    s.push_str("|cp=");
    s.push_str(cap_prm);
    s.push_str("|cb=");
    s.push_str(cap_bnd);
    s
}

fn surface_signature(
    entry: &ProcEntry,
    surface_idx: usize,
    observer_uid: u32,
    all_pids: &PidSet,
    parent_set: &PidSet,
) -> String {
    let p = &entry.profile;
    if is_dumpable_denied(entry, observer_uid) && matches!(surface_idx, 2 | 5 | 6 | 7 | 8) {
        return "EACCES".to_string();
    }
    match surface_idx {
        0 => p.identity.comm.clone(),
        1 => format_args(p),
        2 => p.identity.exe.clone(),
        3 => {
            let is_child = all_pids.contains(p.identity.ppid);
            let has_child = parent_set.contains(p.identity.pid);
            let hc = if has_child { "true" } else { "false" };
            if is_child {
                cat2("cluster-parent|has_child=", hc)
            } else {
                cat3(&i64_str(p.identity.ppid as i64), "|has_child=", hc)
            }
        }
        4 => u64_str(p.identity.starttime / 25_000),
        5 => {
            let mut e = p.environ.clone();
            sort_strings(&mut e);
            e.join("\n")
        }
        6 => cat2(
            "readable=true|token=",
            if p.memory.token_present {
                "true"
            } else {
                "false"
            },
        ),
        7 => p.memory.maps.join("\n"),
        8 => {
            let mut fds: Vec<String> = p
                .fds
                .iter()
                .map(|f| cat3(&i64_str(f.fd as i64), ":", &normalize_fd_target(&f.target)))
                .collect();
            sort_strings(&mut fds);
            fds.join("|")
        }
        9 => format_status_sig(
            &u64_str(p.status.no_new_privs as u64),
            &u64_str(p.status.seccomp as u64),
            &u64_str(p.status.seccomp_filters as u64),
            p.status.tracer_pid != 0,
            &p.status.cap_eff,
            &p.status.cap_prm,
            &p.status.cap_bnd,
        ),
        10 => cat3(&p.syscall.syscall, "|", &p.syscall.wchan),
        11 => {
            let mut comms: Vec<String> = p.task.iter().map(|t| t.comm.clone()).collect();
            sort_strings(&mut comms);
            cat3(&u64_str(p.status.threads as u64), "|", &comms.join(","))
        }
        _ => String::new(),
    }
}

fn compute_differing_surfaces(entries: &[ProcEntry], observer_uid: u32) -> Vec<String> {
    const SURFACES: &str =
        "comm,cmdline,exe,ppid,starttime,environ,memory,maps,fd,status,syscall,threads";
    let mut all_pids = PidSet::new();
    let mut targets: Vec<&ProcEntry> = Vec::new();
    let mut decoys: Vec<&ProcEntry> = Vec::new();
    for e in entries {
        if !e.visible {
            continue;
        }
        all_pids.insert(e.profile.identity.pid);
        if e.role == Role::Target {
            targets.push(e);
        } else if matches!(e.role, Role::Decoy | Role::ExactClone) {
            decoys.push(e);
        }
    }
    if targets.is_empty() || decoys.is_empty() {
        return Vec::new();
    }

    let mut parent_set = PidSet::new();
    for e in entries {
        if e.visible && all_pids.contains(e.profile.identity.ppid) {
            parent_set.insert(e.profile.identity.ppid);
        }
    }

    let mut differing = Vec::new();
    for (si, surf) in SURFACES.split(',').enumerate() {
        let mut decoy_sigs: Vec<String> = Vec::new();
        for d in &decoys {
            let sig = surface_signature(d, si, observer_uid, &all_pids, &parent_set);
            if !decoy_sigs.contains(&sig) {
                decoy_sigs.push(sig);
            }
        }
        if targets.iter().any(|t| {
            !decoy_sigs.contains(&surface_signature(
                t,
                si,
                observer_uid,
                &all_pids,
                &parent_set,
            ))
        }) {
            differing.push(surf.to_string());
        }
    }
    differing
}

fn build_neutral_readme(run_id: &str, mode: Mode) -> String {
    let deep_note = match mode {
        Mode::Table => "This bundle contains only the process table (`blind-table.txt`).",
        Mode::Deep | Mode::Both => {
            "This bundle contains the process table (`blind-table.txt`) and per-process snapshots under `deep/<pid>/`."
        }
    };
    cat4(
        "Evaluation Bundle: ",
        run_id,
        "\n\n",
        &cat2(
            deep_note,
            "\n\nInstructions:\n\
             1. Inspect only files in this directory.\n\
             2. Identify the anomalous PID, or \"absent\", or \"ambiguous\".\n\
             3. Output JSON (`schema: 1`) with keys: schema, phase, pick, reason_surface, reason, elapsed_sec, evaluator.\n",
        ),
    )
}

fn push_live_tree(
    prof: &Profile,
    role: Role,
    parent_idx: Option<usize>,
    depth: u32,
    visible: bool,
    out: &mut Vec<ProcEntry>,
) {
    let mut node = prof.clone();
    let kids = std::mem::take(&mut node.children);
    let pid = node.identity.pid;
    let tok_len = if node.memory.token_present {
        Some(DECOY_TOKEN_LEN)
    } else {
        None
    };
    let my_idx = out.len();
    out.push(ProcEntry {
        role,
        profile: node,
        mutation: None,
        decoy_token_len: tok_len,
        visible,
        is_live: true,
        parent_idx,
        orig_parent_pid: None,
        pgrp: pid,
        session: pid,
        depth,
        tie: 0,
    });
    for c in &kids {
        push_live_tree(c, role, Some(my_idx), depth + 1, visible, out);
    }
}

fn capture_live_profiles(pids: &[i32]) -> Result<Vec<Profile>, String> {
    let mut captured = Vec::with_capacity(pids.len());
    for &lpid in pids {
        let mut eopts = ExtractOpts::for_pid(lpid);
        eopts.tree = true;
        let mut p = profile::extract_live(&eopts)?;
        sanitize_live_profile(&mut p);
        captured.push(p);
    }
    Ok(captured)
}

fn add_synthetic_decoys(
    template: &Profile,
    count: usize,
    level: u8,
    token_prefix: &str,
    rng: &mut Rng,
    out: &mut Vec<ProcEntry>,
) {
    let has_tok = tree_has_token(template);
    for _ in 0..count {
        let (d, tok_len) = match level {
            1 => (build_level1_decoy(template, rng), None),
            2 => (build_level2_decoy(template, rng), None),
            3 => {
                let mut d = template.clone();
                degrade_deep_for_level3(&mut d, rng, None);
                (d, None)
            }
            4..=6 => prepare_level4_to_6_decoy(template, level, rng, token_prefix, true, has_tok),
            _ => continue,
        };
        let start_idx =
            push_synthetic_tree(&d, (Role::Decoy, Role::Decoy), rng, None, 0, true, out);
        if level >= 5 {
            if let Some(root_entry) = out.get_mut(start_idx) {
                root_entry.decoy_token_len = tok_len;
            }
            for child_entry in out.iter_mut().skip(start_idx + 1) {
                if child_entry.profile.memory.token_present {
                    child_entry.decoy_token_len = Some(DECOY_TOKEN_LEN);
                }
            }
        }
    }
    if level >= 6 {
        let churn_n = (count / 10).clamp(2, 10);
        out.extend(build_churn_processes(template, churn_n, rng));
    }
}

#[inline(never)]
fn push_common_meta(w: &mut Jw, run_id: &str, opts: &RunOpts, observer_uid: u32) {
    w.obj_open();
    w.k_i64("schema", HARNESS_SCHEMA as i64);
    w.k_str("run_id", run_id);
    w.k_u64("seed", opts.seed);
    w.k_str("control", opts.control.id());
    w.k_i64("level", opts.level as i64);
    w.k_str("mode", opts.mode.as_str());
    w.k_i64("observer_uid", observer_uid as i64);
}

#[inline(never)]
pub fn verify_target_presence(
    blind_table: &str,
    target_visible_in_table: bool,
    target_pids: &[i32],
    require_deep: bool,
    deep_dir: &Path,
) -> Result<(), String> {
    let mut parsed_pids = PidSet::new();
    for pid in parse_blind_table_pids(blind_table) {
        parsed_pids.insert(pid);
    }
    if target_visible_in_table {
        if target_pids.is_empty() {
            return Err("target presence verification failed: empty target_pids".to_string());
        }
        for &tpid in target_pids {
            let tpid_s = i64_str(tpid as i64);
            if !parsed_pids.contains(tpid) {
                return Err(cat3(
                    "target presence verification failed: PID ",
                    &tpid_s,
                    " missing from blind-table.txt",
                ));
            }
            if require_deep && !deep_dir.join(&tpid_s).join("status").is_file() {
                return Err(cat3(
                    "target presence verification failed: deep/",
                    &tpid_s,
                    "/status missing",
                ));
            }
        }
    } else {
        for &tpid in target_pids {
            if parsed_pids.contains(tpid) {
                return Err(cat3(
                    "target presence verification failed: hidden PID ",
                    &i64_str(tpid as i64),
                    " in blind-table.txt",
                ));
            }
        }
    }
    Ok(())
}

fn write_private_artifacts(
    opts: &RunOpts,
    run_id: &str,
    observer_uid: u32,
    entries: &[ProcEntry],
    target_flags: (bool, bool),
    target_pids: &[i32],
    total_rows: usize,
) -> Result<(usize, usize), String> {
    let (target_present, target_visible_in_table) = target_flags;
    let evidence_dir = opts.out_dir.join("evidence");
    mkdir_all(&evidence_dir)?;

    let mut o = OutDir::new(&opts.out_dir);
    let mut w = Jw::new(true);
    opts.profile.write_json(&mut w);
    o.jw("profile.json", &mut w);

    w.reset(true);
    push_common_meta(&mut w, run_id, opts, observer_uid);
    w.k_arr("processes");
    for e in entries {
        w.elem_obj();
        w.k_str("role", e.role.as_str());
        w.k_i64("pid", e.profile.identity.pid as i64);
        w.k_i64("ppid", e.profile.identity.ppid as i64);
        w.k_bool("visible", e.visible);
        if let Role::HardNeg(hn) = e.role {
            w.k_str("hn_id", hn.id());
            w.k_str("surface", hn.surface());
        }
        if let Some(m) = e.mutation {
            w.k_str("mutation", m);
        }
        w.k_some_str("decoy_token_sha256", &e.profile.memory.token_sha256);
        w.key("profile");
        e.profile.write_json(&mut w);
        w.obj_close();
    }
    w.arr_close();
    w.obj_close();
    o.jw("population.json", &mut w);

    let mut decoy_pids = Vec::new();
    let mut exact_clone_pids = Vec::new();
    let mut role_counts = [0usize; 5];
    for e in entries {
        match e.role {
            Role::Target => role_counts[0] += 1,
            Role::Decoy => {
                role_counts[1] += 1;
                decoy_pids.push(e.profile.identity.pid);
            }
            Role::ExactClone => {
                role_counts[2] += 1;
                exact_clone_pids.push(e.profile.identity.pid);
            }
            Role::HardNeg(_) => role_counts[3] += 1,
            Role::Churn => {
                role_counts[4] += 1;
                decoy_pids.push(e.profile.identity.pid);
            }
        }
    }

    let differing = compute_differing_surfaces(entries, observer_uid);
    let hn_count = role_counts[3];
    let decoy_count = decoy_pids.len() + exact_clone_pids.len();

    w.reset(true);
    push_common_meta(&mut w, run_id, opts, observer_uid);
    w.k_bool("target_present", target_present);
    w.k_bool("target_visible_in_table", target_visible_in_table);
    w.k_i32_arr("target_pids", target_pids);
    w.k_arr("hard_negatives");
    for e in entries {
        if let Role::HardNeg(hn) = e.role {
            w.elem_obj();
            w.k_i64("pid", e.profile.identity.pid as i64);
            w.k_str("hn_id", hn.id());
            w.k_str("surface", hn.surface());
            w.k_str("mutation", e.mutation.unwrap_or(""));
            w.obj_close();
        }
    }
    w.arr_close();
    w.k_i32_arr("decoy_pids", &decoy_pids);
    w.k_i32_arr("exact_clone_pids", &exact_clone_pids);
    w.k_obj("differing_surfaces");
    w.k_str_arr("target_vs_decoys", &differing);
    w.obj_close();
    w.k_str("residual", DEFAULT_RESIDUAL);
    w.obj_close();
    o.jw("answer.json", &mut w);

    w.reset(true);
    push_common_meta(&mut w, run_id, opts, observer_uid);
    w.k_i64("total_rows", total_rows as i64);
    w.k_bool("target_visible_in_table", target_visible_in_table);
    w.k_obj("role_counts");
    for (k, &v) in "target,decoy,exact_clone,hard_negative,churn"
        .split(',')
        .zip(role_counts.iter())
    {
        if v > 0 {
            w.k_i64(k, v as i64);
        }
    }
    w.obj_close();
    w.k_str("version", env!("CARGO_PKG_VERSION"));
    w.k_str("residual", DEFAULT_RESIDUAL);
    w.obj_close();
    o.jw("evidence/metadata.json", &mut w);
    o.check()?;

    Ok((decoy_count, hn_count))
}

fn push_root(
    prof: &Profile,
    roles: (Role, Role),
    visible: bool,
    rng: &mut Rng,
    out: &mut Vec<ProcEntry>,
) -> usize {
    push_synthetic_tree(prof, roles, rng, None, 0, visible, out)
}

fn push_targets(
    live_targets: &[Profile],
    synth: &Profile,
    visible: bool,
    also_clone: bool,
    rng: &mut Rng,
    out: &mut Vec<ProcEntry>,
) {
    if !live_targets.is_empty() {
        for lt in live_targets {
            push_live_tree(lt, Role::Target, None, 0, visible, out);
            if also_clone {
                push_root(lt, (Role::ExactClone, Role::ExactClone), true, rng, out);
            }
        }
    } else {
        push_root(synth, (Role::Target, Role::Target), visible, rng, out);
        if also_clone {
            push_root(synth, (Role::ExactClone, Role::ExactClone), true, rng, out);
        }
    }
}

fn populate_entries(
    opts: &RunOpts,
    base_target: &Profile,
    effective_template: &Profile,
    live_targets: &[Profile],
    live_decoys: &[Profile],
    rng: &mut Rng,
) -> Vec<ProcEntry> {
    let mut entries = Vec::new();
    match opts.control {
        Control::C01Obvious => {
            if !live_targets.is_empty() {
                push_targets(live_targets, base_target, true, false, rng, &mut entries);
            } else {
                let mut ob = base_target.clone();
                ob.identity.label = "obvious-target-unique".to_string();
                ob.identity.comm = "obvious-target".to_string();
                ob.status.name = "obvious-target".to_string();
                ob.identity.argv = vec![
                    "obvious-target-unique".to_string(),
                    "--obvious-control".to_string(),
                ];
                ob.identity.exe = "/srv/ci/obvious-target-unique".to_string();
                ob.auxv.at_execfn = Some("/srv/ci/obvious-target-unique".to_string());
                if let Some(t) = ob.task.first_mut() {
                    t.comm = "obvious-target".to_string();
                }
                push_root(&ob, (Role::Target, Role::Target), true, rng, &mut entries);
            }
            add_synthetic_decoys(
                effective_template,
                10,
                1,
                &opts.decoy_token_prefix,
                rng,
                &mut entries,
            );
        }
        Control::C02Hidden | Control::C04NoTarget => {
            for ld in live_decoys {
                push_live_tree(ld, Role::Decoy, None, 0, true, &mut entries);
            }
            add_synthetic_decoys(
                effective_template,
                opts.decoys,
                opts.level,
                &opts.decoy_token_prefix,
                rng,
                &mut entries,
            );
        }
        Control::C03ExactClone | Control::C05TargetOnly => {
            push_targets(
                live_targets,
                base_target,
                true,
                opts.control == Control::C03ExactClone,
                rng,
                &mut entries,
            );
        }
        Control::C06Main | Control::C07HiddenByMask => {
            let vis = opts.control == Control::C06Main;
            if live_targets.is_empty() && opts.level >= 6 {
                let mut t_node = base_target.clone();
                // Apply the EXACT same Level 6 jitter distribution to synthetic Target
                // as to Level 6 decoys so Target is statistically indistinguishable.
                apply_level6_jitter(&mut t_node, rng, None);
                push_root(
                    &t_node,
                    (Role::Target, Role::Target),
                    vis,
                    rng,
                    &mut entries,
                );
            } else {
                push_targets(live_targets, base_target, vis, false, rng, &mut entries);
            }
            for ld in live_decoys {
                push_live_tree(ld, Role::Decoy, None, 0, true, &mut entries);
            }
            add_synthetic_decoys(
                effective_template,
                opts.decoys,
                opts.level,
                &opts.decoy_token_prefix,
                rng,
                &mut entries,
            );
            if vis {
                for &hn in &opts.hard_negatives {
                    let (hn_prof, mutation, tok_len) = build_hard_negative(
                        effective_template,
                        hn,
                        opts.level,
                        rng,
                        &opts.decoy_token_prefix,
                    );
                    let idx = push_root(
                        &hn_prof,
                        (Role::HardNeg(hn), Role::Decoy),
                        true,
                        rng,
                        &mut entries,
                    );
                    if let Some(e) = entries.get_mut(idx) {
                        e.mutation = Some(mutation);
                        e.decoy_token_len = tok_len;
                    }
                }
            }
        }
    }
    entries
}

fn clear_dir_if_exists(dir: &Path) -> Result<(), String> {
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| err_io("cannot clear", dir, &e))?;
    }
    Ok(())
}

/// Build a reproducible evaluation run bundle (`psgen run`).
pub fn build_run(opts: &RunOpts) -> Result<RunResult, String> {
    build_run_with_target_override(opts, None)
}

/// Build a reproducible evaluation run bundle where decoys are generated from
/// `opts.profile` while an optional `target_override` specifies the actual
/// target placed in the population (used for discrimination & planted-defect tests).
pub fn build_run_with_target_override(
    opts: &RunOpts,
    target_override: Option<&Profile>,
) -> Result<RunResult, String> {
    if !(1..=6).contains(&opts.level) {
        return Err("invalid decoy level (expected 1..=6)".to_string());
    }
    opts.profile.validate(&[])?;
    if let Some(ov) = target_override {
        ov.validate(&[])?;
    }
    if opts.blind_dir.as_ref() == Some(&opts.out_dir) {
        return Err("blind_dir must be distinct from out_dir".to_string());
    }

    let run_id = match &opts.run_id {
        Some(id) => validate_run_id(id)?,
        None => default_run_id(opts.seed, opts.control, opts.level),
    };

    let template = &opts.profile;
    let observer_uid = opts
        .observer_uid
        .or(template.source.observer_uid)
        .unwrap_or(template.identity.uid);

    let mut rng = Rng::new(opts.seed);
    let mut alloc = PidSet::new();
    for p in [0, 1, 2, template.identity.ppid] {
        alloc.insert(p);
    }

    let live_targets = capture_live_profiles(&opts.live_target_pids)?;
    let live_decoys = capture_live_profiles(&opts.live_decoy_pids)?;
    for lt in &live_targets {
        reserve_tree_pids(lt, &mut alloc);
    }
    for ld in &live_decoys {
        reserve_tree_pids(ld, &mut alloc);
    }

    let (target_present, target_visible_in_table) = match opts.control {
        Control::C01Obvious
        | Control::C03ExactClone
        | Control::C05TargetOnly
        | Control::C06Main => (true, true),
        Control::C02Hidden | Control::C04NoTarget => (false, false),
        Control::C07HiddenByMask => (true, false),
    };

    let effective_template = if !live_targets.is_empty() {
        &live_targets[0]
    } else {
        template
    };
    let base_target = target_override.unwrap_or(effective_template);

    let mut entries = populate_entries(
        opts,
        base_target,
        effective_template,
        &live_targets,
        &live_decoys,
        &mut rng,
    );
    assign_synthetic_pids(&mut entries, &mut alloc, &mut rng, opts.seed);

    let mut target_pids = Vec::new();
    let mut visible_indices = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if e.role == Role::Target {
            target_pids.push(e.profile.identity.pid);
        }
        if e.visible {
            visible_indices.push(i);
        }
    }
    let mut shuffle_rng = Rng::new(opts.seed ^ 0x517c_c1b7_2722_0a95);
    for i in (1..visible_indices.len()).rev() {
        let j = shuffle_rng.below((i + 1) as u64) as usize;
        visible_indices.swap(i, j);
    }

    mkdir_all(&opts.out_dir)?;
    let deep_dir = opts.out_dir.join("deep");
    clear_dir_if_exists(&deep_dir)?;

    let blind_table = render_blind_table(&entries, &visible_indices);
    write_in(&opts.out_dir, "blind-table.txt", blind_table.as_bytes())?;

    if opts.mode != Mode::Table {
        mkdir_all(&deep_dir)?;
        for &idx in &visible_indices {
            write_deep_entry(&deep_dir, &entries[idx], observer_uid)?;
        }
    }

    verify_target_presence(
        &blind_table,
        target_visible_in_table,
        &target_pids,
        opts.mode != Mode::Table,
        &deep_dir,
    )?;

    let total_rows = visible_indices.len();
    let (decoy_count, hn_count) = write_private_artifacts(
        opts,
        &run_id,
        observer_uid,
        &entries,
        (target_present, target_visible_in_table),
        &target_pids,
        total_rows,
    )?;

    let manifest_files = sha256::write_manifest(&opts.out_dir)?;

    if let Some(ref bdir) = opts.blind_dir {
        mkdir_all(bdir)?;
        let blind_deep = bdir.join("deep");
        clear_dir_if_exists(&blind_deep)?;
        write_in(bdir, "blind-table.txt", blind_table.as_bytes())?;
        if opts.mode != Mode::Table {
            copy_dir_recursive(&deep_dir, &blind_deep)?;
        }
        write_in(
            bdir,
            "README.txt",
            build_neutral_readme(&run_id, opts.mode).as_bytes(),
        )?;
    }

    Ok(RunResult {
        run_id,
        out_dir: opts.out_dir.clone(),
        blind_dir: opts.blind_dir.clone(),
        target_pids,
        decoy_count,
        hn_count,
        total_rows,
        manifest_files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn test_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("psgen-harness-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create test dir");
        p
    }

    fn base_opts(out_dir: PathBuf, blind_dir: Option<PathBuf>, tree: bool) -> RunOpts {
        let mut prof = profile::synthetic_default_profile("ci-runner", tree);
        prof.memory.token_present = true;
        for c in &mut prof.children {
            c.memory.token_present = true;
        }
        RunOpts {
            profile: prof,
            decoys: 12,
            seed: 1234,
            mode: Mode::Both,
            level: 5,
            control: Control::C06Main,
            hard_negatives: HardNeg::all().to_vec(),
            observer_uid: Some(2000),
            out_dir,
            blind_dir,
            run_id: None,
            live_target_pids: Vec::new(),
            live_decoy_pids: Vec::new(),
            decoy_token_prefix: "dtok_".to_string(),
        }
    }

    #[test]
    fn parse_modes_controls_and_hard_negatives() {
        assert_eq!(Mode::parse("table").unwrap(), Mode::Table);
        assert_eq!(Mode::parse("DEEP").unwrap(), Mode::Deep);
        assert_eq!(Mode::parse("both").unwrap(), Mode::Both);
        assert!(Mode::parse("invalid").is_err());

        for &c in Control::all() {
            assert_eq!(Control::parse(c.id()).unwrap(), c);
            assert_eq!(Control::parse(c.slug()).unwrap(), c);
        }
        assert!(Control::parse("C-99").is_err());

        let all = HardNeg::parse_list("all").unwrap();
        assert_eq!(all.len(), 10);
        assert!(HardNeg::parse_list("none").unwrap().is_empty());
        let subset = HardNeg::parse_list("HN-01,HN-05,HN-01,HN-10").unwrap();
        assert_eq!(
            subset,
            vec![HardNeg::Hn01Exe, HardNeg::Hn05Maps, HardNeg::Hn10Threads]
        );
    }

    #[test]
    fn deterministic_reproducibility_and_blind_isolation() {
        let base = test_dir("repro");
        let out1 = base.join("r1");
        let blind1 = base.join("b1");
        let out2 = base.join("r2");
        let blind2 = base.join("b2");

        let res1 = build_run(&base_opts(out1.clone(), Some(blind1.clone()), true)).unwrap();
        let res2 = build_run(&base_opts(out2.clone(), Some(blind2.clone()), true)).unwrap();

        assert_eq!(res1.run_id, res2.run_id);
        assert_eq!(res1.target_pids, res2.target_pids);
        assert_eq!(res1.total_rows, res2.total_rows);
        assert_eq!(res1.hn_count, 10);
        assert_eq!(
            fs::read_to_string(out1.join("blind-table.txt")).unwrap(),
            fs::read_to_string(out2.join("blind-table.txt")).unwrap()
        );
        assert_eq!(
            fs::read_to_string(out1.join("MANIFEST.sha256")).unwrap(),
            fs::read_to_string(out2.join("MANIFEST.sha256")).unwrap()
        );

        assert!(sha256::verify_manifest(&out1).unwrap().is_ok());

        assert!(blind1.join("blind-table.txt").is_file());
        assert!(blind1.join("deep").is_dir());
        assert!(blind1.join("README.txt").is_file());
        assert!(!blind1.join("answer.json").exists());
        assert!(!blind1.join("population.json").exists());
        assert!(!blind1.join("profile.json").exists());
        let readme = fs::read_to_string(blind1.join("README.txt")).unwrap();
        assert!(!readme.to_ascii_lowercase().contains("psgen"));
        assert!(!readme.to_ascii_lowercase().contains("pmask"));

        let rows =
            parse_blind_table(&fs::read_to_string(out1.join("blind-table.txt")).unwrap()).unwrap();
        assert_eq!(res1.target_pids.len(), 2);
        let child_row = rows.iter().find(|r| r.pid == res1.target_pids[1]).unwrap();
        assert_eq!(child_row.ppid, res1.target_pids[0]);
        assert!(
            res1.target_pids[1] > res1.target_pids[0],
            "child PID must exceed parent PID"
        );

        // Child stat inherits parent pgrp/session.
        let child_stat =
            fs::read_to_string(out1.join(format!("deep/{}/stat", res1.target_pids[1]))).unwrap();
        let after_paren = &child_stat[child_stat.rfind(')').unwrap() + 1..];
        let stat_fields: Vec<&str> = after_paren.split_ascii_whitespace().collect();
        assert_eq!(stat_fields[2], res1.target_pids[0].to_string()); // pgrp == parent pid
        assert_eq!(stat_fields[3], res1.target_pids[0].to_string()); // session == parent pid

        let ans_text = fs::read_to_string(out1.join("answer.json")).unwrap();
        assert!(!ans_text.contains(&out1.display().to_string()));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn hard_negatives_exact_single_surface_isolation() {
        let base = test_dir("hn-isolation");
        for tree in [false, true] {
            let out = base.join(if tree { "tree" } else { "single" });
            let mut opts = base_opts(out.clone(), None, tree);
            opts.decoys = 5;
            let res = build_run(&opts).unwrap();
            assert_eq!(res.hn_count, 10);

            let ans = json::parse(&fs::read_to_string(out.join("answer.json")).unwrap()).unwrap();
            let target_pid = ans.req_arr("target_pids").unwrap()[0].as_i64().unwrap() as i32;
            let hns = ans.req_arr("hard_negatives").unwrap();
            assert_eq!(hns.len(), 10);

            let pop =
                json::parse(&fs::read_to_string(out.join("population.json")).unwrap()).unwrap();
            let procs = pop.req_arr("processes").unwrap();

            let mut all_pids = PidSet::new();
            let mut parent_set = PidSet::new();
            for p in procs {
                all_pids.insert(p.req_i64("pid").unwrap() as i32);
            }
            for p in procs {
                let pp = p.req_i64("ppid").unwrap() as i32;
                if all_pids.contains(pp) {
                    parent_set.insert(pp);
                }
            }

            let t_prof = Profile::from_json(
                procs
                    .iter()
                    .find(|p| p.req_i64("pid").unwrap() as i32 == target_pid)
                    .unwrap()
                    .get("profile")
                    .unwrap(),
            )
            .unwrap();

            let t_entry = ProcEntry {
                role: Role::Target,
                profile: t_prof,
                mutation: None,
                decoy_token_len: Some(DECOY_TOKEN_LEN),
                visible: true,
                is_live: false,
                parent_idx: None,
                orig_parent_pid: None,
                pgrp: target_pid,
                session: target_pid,
                depth: 0,
                tie: 0,
            };
            const ALL_SURFACES: &[&str] = &[
                "comm",
                "cmdline",
                "exe",
                "ppid",
                "starttime",
                "environ",
                "memory",
                "maps",
                "fd",
                "status",
                "syscall",
                "threads",
            ];

            for hn_obj in hns {
                let hpid = hn_obj.req_i64("pid").unwrap() as i32;
                let expected_surface = hn_obj.req_str("surface").unwrap();
                let h_prof = Profile::from_json(
                    procs
                        .iter()
                        .find(|p| p.req_i64("pid").unwrap() as i32 == hpid)
                        .unwrap()
                        .get("profile")
                        .unwrap(),
                )
                .unwrap();
                let h_entry = ProcEntry {
                    role: Role::HardNeg(HardNeg::Hn01Exe),
                    profile: h_prof,
                    mutation: None,
                    decoy_token_len: None,
                    visible: true,
                    is_live: false,
                    parent_idx: None,
                    orig_parent_pid: None,
                    pgrp: hpid,
                    session: hpid,
                    depth: 0,
                    tie: 0,
                };
                let mut diffs = Vec::new();
                for (si, &surf) in ALL_SURFACES.iter().enumerate() {
                    let ts = surface_signature(&t_entry, si, 2000, &all_pids, &parent_set);
                    let hs = surface_signature(&h_entry, si, 2000, &all_pids, &parent_set);
                    if ts != hs {
                        diffs.push(surf);
                    }
                }
                assert_eq!(
                    diffs,
                    vec![expected_surface],
                    "tree={tree} HN {} should differ ONLY on {}, got {:?}",
                    hn_obj.req_str("hn_id").unwrap(),
                    expected_surface,
                    diffs
                );
            }
        }

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn all_controls_and_dumpable_eacces_parity() {
        let base = test_dir("controls");

        for &ctrl in Control::all() {
            let out = base.join(ctrl.id());
            let mut opts = base_opts(out.clone(), None, false);
            opts.control = ctrl;
            opts.decoys = 6;
            opts.hard_negatives = Vec::new();
            let res = build_run(&opts).unwrap();
            assert!(sha256::verify_manifest(&out).unwrap().is_ok());

            let ans = json::parse(&fs::read_to_string(out.join("answer.json")).unwrap()).unwrap();
            let table_pids =
                parse_blind_table_pids(&fs::read_to_string(out.join("blind-table.txt")).unwrap());

            match ctrl {
                Control::C01Obvious => {
                    assert!(ans.req_bool("target_present").unwrap());
                    assert!(ans.req_bool("target_visible_in_table").unwrap());
                    assert_eq!(res.total_rows, 11);
                }
                Control::C02Hidden | Control::C04NoTarget => {
                    assert!(!ans.req_bool("target_present").unwrap());
                    assert!(!ans.req_bool("target_visible_in_table").unwrap());
                    assert!(res.target_pids.is_empty());
                }
                Control::C03ExactClone => {
                    assert_eq!(res.total_rows, 2);
                    assert_eq!(ans.req_arr("exact_clone_pids").unwrap().len(), 1);
                }
                Control::C05TargetOnly => {
                    assert_eq!(res.total_rows, 1);
                }
                Control::C06Main => {
                    assert_eq!(res.total_rows, 7);
                }
                Control::C07HiddenByMask => {
                    assert!(ans.req_bool("target_present").unwrap());
                    assert!(!ans.req_bool("target_visible_in_table").unwrap());
                    assert!(!res.target_pids.is_empty());
                    for &tpid in &res.target_pids {
                        assert!(!table_pids.contains(&tpid));
                    }
                }
            }
        }

        let out_nd = base.join("non-dumpable");
        let mut opts_nd = base_opts(out_nd.clone(), None, false);
        opts_nd.profile.dumpable = Some(false);
        opts_nd.decoys = 4;
        opts_nd.level = 4;
        opts_nd.hard_negatives = vec![HardNeg::Hn04MemToken];
        let res_nd = build_run(&opts_nd).unwrap();
        let tpid = res_nd.target_pids[0];
        let t_exe = fs::read_to_string(out_nd.join(format!("deep/{tpid}/exe"))).unwrap();
        assert!(t_exe.contains("EACCES"));
        let ans_nd = json::parse(&fs::read_to_string(out_nd.join("answer.json")).unwrap()).unwrap();
        let dpid = ans_nd.req_arr("decoy_pids").unwrap()[0].as_i64().unwrap() as i32;
        let d_exe = fs::read_to_string(out_nd.join(format!("deep/{dpid}/exe"))).unwrap();
        assert_eq!(t_exe, d_exe);
        let d_mem = fs::read_to_string(out_nd.join(format!("deep/{dpid}/mem_scan.json"))).unwrap();
        assert!(d_mem.contains("EACCES"));
        // HN-04 must stay physically consistent (EACCES) when dumpable == false.
        let hn04_pid = ans_nd.req_arr("hard_negatives").unwrap()[0]
            .req_i64("pid")
            .unwrap() as i32;
        let hn04_mem =
            fs::read_to_string(out_nd.join(format!("deep/{hn04_pid}/mem_scan.json"))).unwrap();
        assert!(hn04_mem.contains("EACCES"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn levels_1_through_6_behave_distinctly() {
        let base = test_dir("levels");
        for lvl in 1..=6u8 {
            let out = base.join(format!("L{lvl}"));
            let mut opts = base_opts(out.clone(), None, true);
            opts.level = lvl;
            opts.decoys = 4;
            opts.hard_negatives = Vec::new();
            let res = build_run(&opts).unwrap();
            assert!(sha256::verify_manifest(&out).unwrap().is_ok());

            let ans = json::parse(&fs::read_to_string(out.join("answer.json")).unwrap()).unwrap();
            let diffs = ans
                .get("differing_surfaces")
                .unwrap()
                .req_arr("target_vs_decoys")
                .unwrap();
            if lvl == 1 {
                assert!(diffs.iter().any(|v| v.as_str() == Some("comm")));
            } else if lvl == 4 {
                assert!(diffs.iter().any(|v| v.as_str() == Some("memory")));
            } else if lvl == 5 {
                assert!(diffs.is_empty(), "got {:?}", diffs);
                // Verify Target and Decoy mem_scan.json are 100% symmetric (Tell #1 closed!).
                let tpid = res.target_pids[0];
                let dpid = ans.req_arr("decoy_pids").unwrap()[0].as_i64().unwrap() as i32;
                let t_mem =
                    fs::read_to_string(out.join(format!("deep/{tpid}/mem_scan.json"))).unwrap();
                let d_mem =
                    fs::read_to_string(out.join(format!("deep/{dpid}/mem_scan.json"))).unwrap();
                assert_eq!(t_mem, d_mem);
                let mem_j = json::parse(&d_mem).unwrap();
                assert!(mem_j.req_bool("token_present").unwrap());
                assert_eq!(mem_j.req_i64("token_len").unwrap(), 32);
                assert!(mem_j.get("token_sha256").is_none());

                // Verify per-process unique pipe inodes (Tell #3 closed!).
                let t_fd = fs::read_to_string(out.join(format!("deep/{tpid}/fd/1"))).unwrap();
                let d_fd = fs::read_to_string(out.join(format!("deep/{dpid}/fd/1"))).unwrap();
                assert_ne!(t_fd, d_fd);
                assert_ne!(t_fd.trim(), "pipe:[12345]");
            } else if lvl == 6 {
                assert!(res.total_rows > 10);
                // Verify Target also received Level 6 jitter and child > parent PID.
                assert!(res.target_pids[1] > res.target_pids[0]);
            }
        }
        let _ = fs::remove_dir_all(&base);
    }
}
