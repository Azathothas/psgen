//! Reproducible 9/10+ decoy population engine, single-surface hard-negative
//! generator, controls (`C-01`..`C-07`), and physically isolated blind bundle
//! builder (`psgen run`).

use crate::inject;
use crate::json::{
    self, cat2, cat3, cat4, err_io, i64_str, mkdir_all, push_i64, push_i64_right, push_str_left,
    push_u64, push_u64_right, sort_strings, u64_str, write_file, write_in, Jw, OutDir,
};
use crate::profile::{self, ExtractOpts, Profile, ProfileFd, ProfileTask};
use crate::rng::Rng;
use crate::score;
use crate::sha256;
use std::fs;
use std::path::{Path, PathBuf};

pub const HARNESS_SCHEMA: u32 = 1;
pub const DEFAULT_RESIDUAL: &str = "same-uid local observer; root/kernel out of scope";
const DECOY_TOKEN_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    Table,
    Deep,
    #[default]
    Both,
}

#[inline(never)]
fn nth_pipe(table: &'static str, idx: usize) -> &'static str {
    table.split('|').nth(idx).unwrap_or("")
}

#[inline(never)]
fn parse_alias_idx(
    s: &str,
    aliases_pipe: &str,
    kind: &str,
    expected: &str,
) -> Result<usize, String> {
    let t = s.trim();
    for (i, group) in aliases_pipe.split('|').enumerate() {
        if group.split(',').any(|o| t.eq_ignore_ascii_case(o)) {
            return Ok(i);
        }
    }
    Err(cat4("invalid ", kind, " '", &cat3(t, "' ", expected)))
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self, String> {
        let idx = parse_alias_idx(
            s,
            "table|deep|both",
            "mode",
            "(expected table, deep, or both)",
        )?;
        Ok([Mode::Table, Mode::Deep, Mode::Both]
            .get(idx)
            .copied()
            .unwrap_or(Mode::Both))
    }

    pub fn as_str(&self) -> &'static str {
        nth_pipe("table|deep|both", *self as usize)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Control {
    C01Obvious,
    C02Hidden,
    C03ExactClone,
    C04NoTarget,
    C05TargetOnly,
    #[default]
    C06Main,
    C07HiddenByMask,
}

impl Control {
    const ALL: &'static [Control] = &[
        Control::C01Obvious,
        Control::C02Hidden,
        Control::C03ExactClone,
        Control::C04NoTarget,
        Control::C05TargetOnly,
        Control::C06Main,
        Control::C07HiddenByMask,
    ];

    pub fn parse(s: &str) -> Result<Self, String> {
        let idx = parse_alias_idx(
            s,
            "c-01,c01,obvious,obvious-target|c-02,c02,hidden,hidden-target|c-03,c03,exact-clone,exact_clone,clone|c-04,c04,no-target,no_target|c-05,c05,target-only,target_only|c-06,c06,main|c-07,c07,hidden-by-mask,hidden_by_mask",
            "control",
            "(expected C-01..C-07)",
        )?;
        Ok(Self::ALL.get(idx).copied().unwrap_or(Control::C06Main))
    }

    pub fn id(&self) -> &'static str {
        nth_pipe("C-01|C-02|C-03|C-04|C-05|C-06|C-07", *self as usize)
    }

    #[cfg(test)]
    pub fn slug(&self) -> &'static str {
        nth_pipe(
            "obvious|hidden|exact-clone|no-target|target-only|main|hidden-by-mask",
            *self as usize,
        )
    }

    #[cfg(test)]
    pub fn all() -> &'static [Control] {
        Self::ALL
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
        nth_pipe(
            "HN-01|HN-02|HN-03|HN-04|HN-05|HN-06|HN-07|HN-08|HN-09|HN-10",
            *self as usize,
        )
    }

    pub fn surface(&self) -> &'static str {
        nth_pipe(
            "exe|ppid|starttime|memory|maps|fd|status|syscall|cmdline|threads",
            *self as usize,
        )
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
        let idx = parse_alias_idx(
            s,
            "hn-01,hn01,exe|hn-02,hn02,ppid|hn-03,hn03,starttime|hn-04,hn04,memory,mem,mem-token|hn-05,hn05,maps|hn-06,hn06,fd,fds|hn-07,hn07,status|hn-08,hn08,syscall,wchan|hn-09,hn09,cmdline,argv|hn-10,hn10,threads,task",
            "hard-negative",
            "(expected HN-01..HN-10, all, or none)",
        )?;
        Ok(Self::all().get(idx).copied().unwrap_or(HardNeg::Hn01Exe))
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
    pub redact_tokens: Vec<String>,
    pub redact_envs: Vec<String>,
    pub live_mode: bool,
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

    #[inline(never)]
    fn insert(&mut self, pid: i32) {
        if (0..65_536).contains(&pid) {
            let p = pid as usize;
            if let Some(w) = self.bits.get_mut(p >> 6) {
                *w |= 1u64 << (p & 63);
            }
        } else if pid > 0 && !self.extra.contains(&pid) {
            self.extra.push(pid);
        }
    }

    #[inline(never)]
    fn contains(&self, pid: i32) -> bool {
        if (0..65_536).contains(&pid) {
            let p = pid as usize;
            self.bits
                .get(p >> 6)
                .is_some_and(|&w| (w & (1u64 << (p & 63))) != 0)
        } else {
            self.extra.contains(&pid)
        }
    }

    #[inline(never)]
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
    cat2("run-", digest.get(..12).unwrap_or(&digest))
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

#[inline(never)]
fn push_args(out: &mut String, prof: &Profile) {
    if prof.identity.argv.is_empty() {
        out.push('[');
        out.push_str(&prof.identity.comm);
        out.push(']');
        return;
    }
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
}

#[inline(never)]
fn sanitize_workspace_paths(s: &str) -> String {
    let mut cur = profile::sanitize_host_home(s);
    while let Some(pos) = cur.find("/workspaces/") {
        let rest = &cur[pos + "/workspaces/".len()..];
        let seg_len = rest
            .bytes()
            .take_while(|&b| {
                !b.is_ascii_whitespace() && !matches!(b, b'/' | b':' | b'"' | b'\'' | b'\0')
            })
            .count();
        let end = pos + "/workspaces/".len() + seg_len;
        let mut next = String::with_capacity(cur.len());
        next.push_str(&cur[..pos]);
        next.push_str("/srv/work");
        next.push_str(&cur[end..]);
        cur = next;
    }
    cur
}

#[inline(never)]
fn set_s(dst: &mut String, val: &str) {
    dst.clear();
    dst.push_str(val);
}

#[inline(never)]
fn set_opt_s(dst: &mut Option<String>, val: Option<&str>) {
    *dst = val.map(json::own);
}

#[inline(never)]
fn set_vec_s(dst: &mut Vec<String>, vals: &[&str]) {
    dst.clear();
    for &v in vals {
        dst.push(json::own(v));
    }
}

#[inline(never)]
fn sp_s(out: &mut String, s: &str) {
    out.push_str(s);
}

#[inline(never)]
fn sp_kv_s(out: &mut String, k: &str, v: &str) {
    out.push_str(k);
    out.push_str(v);
}

#[inline(never)]
fn sp_kv_u(out: &mut String, k: &str, v: u64) {
    out.push_str(k);
    push_u64(out, v);
}

#[inline(never)]
fn push_joined(out: &mut String, items: &[String], sep: &str) {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            sp_s(out, sep);
        }
        sp_s(out, item);
    }
}

#[inline(never)]
fn push_sorted_joined(out: &mut String, items: &[String], sep: &str) {
    let mut tmp = items.to_vec();
    sort_strings(&mut tmp);
    push_joined(out, &tmp, sep);
}

#[inline(never)]
fn clear_mem_token(m: &mut profile::ProfileMemory) {
    m.token_present = false;
    m.token_sha256 = None;
    m.token_len = None;
    m.token_placements.clear();
}

#[inline(never)]
fn apply_decoy_token(m: &mut profile::ProfileMemory, rng: &mut Rng, prefix: &str) -> usize {
    let (tlen, digest) = generate_decoy_token(
        rng,
        prefix,
        m.token_len,
        m.token_charset.as_deref(),
        m.token_sha256.as_deref(),
    );
    m.token_present = true;
    m.token_sha256 = Some(digest);
    if m.token_len.is_none() {
        m.token_len = Some(tlen as u32);
    }
    tlen
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn make_proc_entry(
    role: Role,
    profile: Profile,
    decoy_token_len: Option<usize>,
    visible: bool,
    is_live: bool,
    parent_idx: Option<usize>,
    orig_parent_pid: Option<i32>,
    pgrp: i32,
    session: i32,
    depth: u32,
    tie: u64,
) -> ProcEntry {
    ProcEntry {
        role,
        profile,
        mutation: None,
        decoy_token_len,
        visible,
        is_live,
        parent_idx,
        orig_parent_pid,
        pgrp,
        session,
        depth,
        tie,
    }
}

#[inline(never)]
fn set_ppid(p: &mut Profile, ppid: i32) {
    p.identity.ppid = ppid;
    p.status.ppid = ppid;
    p.stat.ppid = ppid;
}

#[inline(never)]
fn set_starttime(p: &mut Profile, st: u64) {
    p.identity.starttime = st;
    p.stat.starttime = st;
}

fn default_tok_len(p: &Profile) -> Option<usize> {
    p.memory
        .token_present
        .then(|| p.memory.token_len.unwrap_or(DECOY_TOKEN_LEN as u32) as usize)
}

fn sanitize_vec(v: &mut [String]) {
    for s in v.iter_mut() {
        *s = sanitize_workspace_paths(s);
    }
}

#[inline(never)]
pub fn sanitize_live_profile(prof: &mut Profile) {
    prof.identity.cwd = sanitize_workspace_paths(&prof.identity.cwd);
    prof.identity.exe = sanitize_workspace_paths(&prof.identity.exe);
    sanitize_vec(&mut prof.identity.argv);
    if let Some(ref execfn) = prof.auxv.at_execfn {
        prof.auxv.at_execfn = Some(sanitize_workspace_paths(execfn));
    }
    sanitize_vec(&mut prof.environ);
    sanitize_vec(&mut prof.memory.maps);
    sanitize_vec(&mut prof.memory.smaps);
    for fd in &mut prof.fds {
        fd.target = sanitize_workspace_paths(&fd.target);
    }
    for child in &mut prof.children {
        sanitize_live_profile(child);
    }
    if let Some(ref mut par) = prof.parent {
        sanitize_live_profile(par);
    }
    if let Some(ref mut tr) = prof.tracer {
        sanitize_live_profile(tr);
    }
}

/// Prune `self_pid` (the running `psgen` harness process) and its own parent from
/// captured upward ancestor chains so live captures never pull `psgen` itself into
/// the target or decoy trees.
#[inline(never)]
pub fn strip_self_ancestors(prof: &mut Profile) {
    let self_pid = std::process::id() as i32;
    let self_ppid = crate::live::read_stat(self_pid)
        .map(|s| s.ppid as i32)
        .unwrap_or(0);
    strip_ancestors_inner(prof, self_pid, self_ppid);
}

fn strip_ancestors_inner(prof: &mut Profile, self_pid: i32, self_ppid: i32) {
    if let Some(ref mut par) = prof.parent {
        if par.identity.pid == self_pid || (self_ppid > 1 && par.identity.pid == self_ppid) {
            prof.parent = None;
        } else {
            strip_ancestors_inner(par, self_pid, self_ppid);
        }
    }
    if let Some(ref mut tr) = prof.tracer {
        if tr.identity.pid == self_pid || (self_ppid > 1 && tr.identity.pid == self_ppid) {
            prof.tracer = None;
        } else {
            strip_ancestors_inner(tr, self_pid, self_ppid);
        }
    }
}

/// Normalize ephemeral kernel pipe/socket inodes so FD shape comparison
/// matches across peers that hold distinct realistic inodes.
#[inline(never)]
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

/// Generate a deterministic decoy token matching target length/charset and avoiding `avoid_sha256`.
fn generate_decoy_token(
    rng: &mut Rng,
    prefix: &str,
    want_len: Option<u32>,
    charset: Option<&str>,
    avoid_sha256: Option<&str>,
) -> (usize, String) {
    let pfx = prefix.trim();
    let pfx_opt = if pfx.is_empty() { None } else { Some(pfx) };
    let tok = inject::make_shaped_decoy_token(pfx_opt, want_len, charset, avoid_sha256, rng);
    (tok.len(), sha256::hash_hex(&tok))
}

#[inline(never)]
fn make_task(tid: i32, comm: &str, state: &str) -> ProfileTask {
    ProfileTask {
        tid,
        comm: json::own(comm),
        state: json::own(state),
    }
}

#[inline(never)]
fn sync_node_pid_ppid(node: &mut Profile, pid: i32, ppid: i32, orig_parent_pid: Option<i32>) {
    let old_pid = node.identity.pid;
    node.identity.pid = pid;
    set_ppid(node, ppid);
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
        new_tasks.push(make_task(pid, &node.identity.comm, &node.status.state));
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
            new_tasks.push(make_task(tid, &t.comm, &t.state));
        }
        if !main_placed {
            if let Some(first) = new_tasks.first_mut() {
                first.tid = pid;
            }
        }
    }
    while (new_tasks.len() as u32) < wanted {
        new_tasks.push(make_task(
            pid + new_tasks.len() as i32,
            &node.identity.comm,
            &node.status.state,
        ));
    }
    json::shell_sort_by(&mut new_tasks, |a, b| a.tid > b.tid);
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
                set_starttime(&mut node, parent_st);
            }
            (Some(pidx), Some(orig_p))
        }
        None => (None, None),
    };

    let tok_len = default_tok_len(&node);
    let my_st = node.identity.starttime;
    let my_idx = out.len();
    out.push(make_proc_entry(
        role,
        node,
        tok_len,
        visible,
        false,
        parent_idx,
        orig_parent_pid,
        0,
        0,
        depth,
        rng.next_u64(),
    ));

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
#[inline(never)]
fn assign_synthetic_pids(entries: &mut [ProcEntry], alloc: &mut PidSet, rng: &mut Rng, seed: u64) {
    let mut synth: Vec<usize> = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        if !e.is_live {
            synth.push(i);
        }
    }

    // Shellsort by (starttime, depth, random tiebreaker) so parents always precede children
    // and PID order monotonically tracks process creation time.
    json::shell_sort_by(&mut synth, |&a, &b| {
        let (Some(ea), Some(eb)) = (entries.get(a), entries.get(b)) else {
            return false;
        };
        (ea.profile.identity.starttime, ea.depth, ea.tie)
            > (eb.profile.identity.starttime, eb.depth, eb.tie)
    });

    let n = synth.len().max(1);
    let mut cursor = rng.range(1_200, 3_600) as i32;
    let max_step = ((52_000i32 - cursor) / n as i32).clamp(2, 40) as u64;
    let mut prev_st: Option<u64> = None;

    for idx in synth {
        let Some((span, st, parent_idx, orig_parent_pid, cur_ppid)) = entries.get(idx).map(|e| {
            let p = &e.profile;
            (
                p.status
                    .threads
                    .max(p.stat.num_threads)
                    .max(p.task.len() as u32)
                    .max(1),
                p.identity.starttime,
                e.parent_idx,
                e.orig_parent_pid,
                p.identity.ppid,
            )
        }) else {
            continue;
        };
        let step = rng.range(1, max_step) as i32;
        let jump_bonus = match prev_st {
            Some(pst) if st > pst => ((st - pst) / 2_000).min(12) as i32,
            _ => 0,
        };
        cursor = cursor.saturating_add(step + jump_bonus);
        let parent_info = parent_idx.and_then(|pidx| {
            entries
                .get(pidx)
                .map(|pe| (pe.profile.identity.pid, pe.pgrp, pe.session))
        });
        if let Some((parent_pid, _, _)) = parent_info {
            if cursor <= parent_pid {
                cursor = parent_pid + 1;
            }
        }
        let pid = alloc.alloc_monotonic(cursor, span);
        cursor = pid + span as i32;
        prev_st = Some(st);

        let (ppid, pgrp, session) = parent_info.unwrap_or((cur_ppid, pid, pid));
        if let Some(e) = entries.get_mut(idx) {
            sync_node_pid_ppid(&mut e.profile, pid, ppid, orig_parent_pid);
            e.pgrp = pgrp;
            e.session = session;
            remap_synthetic_fd_inodes(&mut e.profile.fds, seed, pid);
        }
    }

    // Set pgrp/session for live entries (children inherit parent's pgrp/session).
    for idx in 0..entries.len() {
        let Some((is_live, parent_idx, pid)) = entries
            .get(idx)
            .map(|e| (e.is_live, e.parent_idx, e.profile.identity.pid))
        else {
            continue;
        };
        if is_live {
            let (pgrp, session) = parent_idx
                .and_then(|pidx| entries.get(pidx).map(|pe| (pe.pgrp, pe.session)))
                .unwrap_or((pid, pid));
            if let Some(e) = entries.get_mut(idx) {
                e.pgrp = pgrp;
                e.session = session;
            }
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
#[inline(never)]
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
    set_starttime(node, base_st);

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

#[inline(never)]
fn reset_decoy_deep(
    d: &mut Profile,
    exe: &str,
    ino: &str,
    exe_kb: u64,
    heap_kb: u64,
    sc: &str,
    wchan: &str,
) {
    set_s(&mut d.identity.exe, exe);
    d.identity.exe_memfd = None;
    set_opt_s(&mut d.auxv.at_execfn, Some(exe));
    let (maps, smaps) = profile::basic_maps_smaps(exe, ino, exe_kb, heap_kb);
    d.memory.maps = maps;
    d.memory.smaps = smaps;
    d.memory.token_present = false;
    d.memory.token_sha256 = None;
    set_s(&mut d.syscall.syscall, sc);
    set_s(&mut d.syscall.wchan, wchan);
    d.dumpable = Some(true);
}

#[inline(never)]
fn null_fds(n: i32) -> Vec<ProfileFd> {
    (0..n)
        .map(|fd| ProfileFd {
            fd,
            target: json::own("/dev/null"),
        })
        .collect()
}

#[inline(never)]
fn default_decoy_env() -> Vec<String> {
    vec![json::own("PATH=/usr/bin:/bin"), json::own("LANG=C")]
}

#[inline(never)]
fn single_sleeping_task(comm: &str) -> Vec<ProfileTask> {
    vec![ProfileTask {
        tid: 0,
        comm: json::own(comm),
        state: json::own("S"),
    }]
}

#[inline(never)]
fn build_level1_decoy(target: &Profile, rng: &mut Rng) -> Profile {
    let mut d = target.clone();
    d.children.clear();
    let st = target
        .identity
        .starttime
        .saturating_add(rng.range(50, 5_000));
    set_s(&mut d.source.masker, "level1");
    set_s(&mut d.source.profile, "single");
    set_s(&mut d.identity.comm, "sleep");
    set_vec_s(&mut d.identity.argv, &[&target.identity.label, "1800"]);
    d.identity.cmdline_raw_nuls = Some(1);
    d.identity.pid = 0;
    set_ppid(&mut d, 1);
    set_starttime(&mut d, st);
    set_s(&mut d.identity.cwd, "/tmp");
    set_s(&mut d.status.name, "sleep");
    set_s(&mut d.status.state, "S");
    d.status.threads = 1;
    d.status.tracer_pid = 0;
    d.status.no_new_privs = 0;
    d.status.seccomp = 0;
    d.status.seccomp_filters = 0;
    d.stat.num_threads = 1;
    d.stat.vsize = 5_840_896;
    d.stat.rss = 192;
    d.memory.denied_by.clear();
    d.fds = null_fds(3);
    d.environ = default_decoy_env();
    d.task = single_sleeping_task("sleep");
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

#[inline(never)]
fn build_level2_decoy(target: &Profile, rng: &mut Rng) -> Profile {
    let mut d = target.clone();
    d.children.clear();
    let alt_ppid = if target.identity.ppid == 1 { 412 } else { 1 };
    let alt_exe = if target.identity.exe == "/usr/libexec/decoy-stub" {
        "/usr/bin/decoy-stub"
    } else {
        "/usr/libexec/decoy-stub"
    };
    set_ppid(&mut d, alt_ppid);
    set_s(&mut d.identity.cwd, "/tmp");
    set_starttime(
        &mut d,
        target
            .identity
            .starttime
            .saturating_add(rng.range(20, 4_000)),
    );
    d.environ = default_decoy_env();
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

#[inline(never)]
fn degrade_deep_for_level3(node: &mut Profile, rng: &mut Rng, parent_st: Option<u64>) {
    let alt_exe = if node.identity.exe == "/usr/libexec/decoy-tree-worker" {
        "/usr/bin/decoy-tree-worker"
    } else {
        "/usr/libexec/decoy-tree-worker"
    };
    let sc = node.syscall.syscall.clone();
    let wc = node.syscall.wchan.clone();
    reset_decoy_deep(node, alt_exe, "888", 1536, 2432, &sc, &wc);
    set_vec_s(
        &mut node.environ,
        &["PATH=/usr/bin:/bin", "DECOY_STAGE=tree-only"],
    );
    node.fds = vec![
        ProfileFd {
            fd: 0,
            target: json::own("/dev/null"),
        },
        ProfileFd {
            fd: 1,
            target: json::own("pipe:[99001]"),
        },
    ];
    let st = match parent_st {
        Some(pst) => pst.saturating_add(rng.range(5, 45)),
        None => node.identity.starttime.saturating_add(rng.range(10, 2_000)),
    };
    set_starttime(node, st);
    for child in &mut node.children {
        degrade_deep_for_level3(child, rng, Some(st));
    }
}

#[inline(never)]
fn prepare_level4_to_6_decoy(
    target: &Profile,
    level: u8,
    rng: &mut Rng,
    token_prefix: &str,
    is_root: bool,
) -> (Profile, Option<usize>) {
    let mut node = target.clone();
    let tok_len = if level >= 5 && node.memory.token_present {
        Some(apply_decoy_token(&mut node.memory, rng, token_prefix))
    } else {
        clear_mem_token(&mut node.memory);
        None
    };

    let orig_children = std::mem::take(&mut node.children);
    let mut new_children = Vec::with_capacity(orig_children.len());
    for child in &orig_children {
        let (c_node, _) = prepare_level4_to_6_decoy(child, level, rng, token_prefix, false);
        new_children.push(c_node);
    }
    node.children = new_children;

    if is_root && level >= 6 {
        apply_level6_jitter(&mut node, rng, None);
    }

    (node, tok_len)
}

#[inline(never)]
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
                let _ = apply_decoy_token(&mut child.memory, rng, token_prefix);
            }
        }
    }
    if level >= 6 {
        apply_level6_jitter(&mut node, rng, None);
    }

    let mut tok_len = default_tok_len(&node);

    match hn {
        HardNeg::Hn01Exe => {
            let new_exe = if node.identity.exe == "/usr/bin/hn01-alt-bin" {
                "/usr/local/bin/hn01-alt-bin"
            } else {
                "/usr/bin/hn01-alt-bin"
            };
            set_s(&mut node.identity.exe, new_exe);
            node.identity.exe_memfd = None;
        }
        HardNeg::Hn02Ppid => {
            let new_ppid = if node.identity.ppid == 1 { 2048 } else { 1 };
            set_ppid(&mut node, new_ppid);
        }
        HardNeg::Hn03Starttime => {
            let new_st = node.identity.starttime.saturating_add(500_000);
            set_starttime(&mut node, new_st);
            for child in &mut node.children {
                set_starttime(child, new_st.saturating_add(18));
            }
        }
        HardNeg::Hn04MemToken => {
            if !node.memory.token_present {
                let tlen = apply_decoy_token(&mut node.memory, rng, token_prefix);
                node.memory.token_len = Some(tlen as u32);
                tok_len = Some(tlen);
            } else {
                clear_mem_token(&mut node.memory);
                tok_len = None;
            }
        }
        HardNeg::Hn05Maps => {
            node.memory.maps.push(json::own(
                "<addr> rwxp 00000000 00:00 0 /tmp/hn05-injected.so",
            ));
            node.memory.smaps.push(json::own(
                "rwxp /tmp/hn05-injected.so Rss:128kB Private_Dirty:128kB Anonymous:128kB",
            ));
        }
        HardNeg::Hn06Fd => {
            let next_fd = node.fds.iter().map(|f| f.fd).max().unwrap_or(2) + 1;
            node.fds.push(ProfileFd {
                fd: next_fd,
                target: json::own("socket:[9999006]"),
            });
        }
        HardNeg::Hn07Status => {
            node.status.no_new_privs = u32::from(node.status.no_new_privs == 0);
            node.status.seccomp = if node.status.seccomp == 0 { 2 } else { 0 };
            node.status.seccomp_filters = u32::from(node.status.seccomp == 2);
            node.status.tracer_pid = if node.status.tracer_pid == 0 { 9999 } else { 0 };
        }
        HardNeg::Hn08Syscall => {
            let (sc, wc) = if node.syscall.syscall == "epoll_wait" {
                ("nanosleep", "hrtimer_nanosleep")
            } else {
                ("epoll_wait", "do_epoll_wait")
            };
            set_s(&mut node.syscall.syscall, sc);
            set_s(&mut node.syscall.wchan, wc);
        }
        HardNeg::Hn09Cmdline => {
            if node.identity.argv.is_empty() {
                node.identity.argv.push(node.identity.comm.clone());
            }
            node.identity.argv.push(json::own("--hn09-mutated-arg"));
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
                    state: json::own("S"),
                });
            }
        }
    }

    let mutation = nth_pipe(
        "exe mutated|ppid mutated|starttime mutated|mem_scan token_present mutated|maps mutated|fd added|status flags mutated|syscall mutated|cmdline argv mutated|thread count mutated",
        hn as usize,
    );
    (node, mutation, tok_len)
}

#[inline(never)]
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
            set_s(&mut prof.source.masker, "churn");
            set_s(&mut prof.identity.label, comm);
            set_s(&mut prof.identity.comm, comm);
            set_vec_s(&mut prof.identity.argv, &[exe]);
            prof.identity.pid = 0;
            prof.identity.uid = churn_uid;
            prof.identity.gid = churn_uid;
            set_starttime(&mut prof, st);
            set_s(&mut prof.identity.cwd, "/");
            set_s(&mut prof.status.name, comm);
            set_s(&mut prof.status.uid, &uid_str);
            set_s(&mut prof.status.gid, &uid_str);
            prof.stat.vsize = 18_432_000;
            prof.stat.rss = 1024;
            reset_decoy_deep(&mut prof, exe, "101", 1536, 2432, sc, wchan);
            prof.task = single_sleeping_task(comm);
            out.push(make_proc_entry(
                Role::Churn,
                prof,
                None,
                true,
                false,
                None,
                None,
                0,
                0,
                0,
                rng.next_u64(),
            ));
        }
    }
    out
}

fn is_dumpable_denied(entry: &ProcEntry, observer_uid: u32) -> bool {
    entry.profile.dumpable == Some(false) && observer_uid != 0
}

fn state_label(code: &str) -> &'static str {
    let idx = if code.len() == 1 {
        "RSDTtZXI".find(code).unwrap_or(1)
    } else {
        1
    };
    nth_pipe(
        "R (running)|S (sleeping)|D (disk sleep)|T (stopped)|t (tracing stop)|Z (zombie)|X (dead)|I (idle)",
        idx,
    )
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

#[inline(never)]
fn push_kv_strs(out: &mut String, keys_csv: &str, vals: &[&str]) {
    for (k, &v) in keys_csv.split(',').zip(vals.iter()) {
        push_kv_str(out, k, v);
    }
}

#[inline(never)]
fn push_kv_i64s(out: &mut String, keys_csv: &str, vals: &[i64]) {
    for (k, &v) in keys_csv.split(',').zip(vals.iter()) {
        push_kv_i64(out, k, v);
    }
}

#[inline(never)]
fn push_kv_kbs(out: &mut String, keys_csv: &str, vals: &[u64]) {
    for (k, &v) in keys_csv.split(',').zip(vals.iter()) {
        push_kv_kb(out, k, v);
    }
}

#[inline(never)]
fn render_status_file(p: &Profile) -> String {
    let mut out = String::with_capacity(512);
    push_kv_strs(
        &mut out,
        "Name,State",
        &[&p.status.name, state_label(&p.status.state)],
    );
    push_kv_i64s(
        &mut out,
        "Tgid,Pid,PPid,TracerPid",
        &[
            p.identity.pid as i64,
            p.identity.pid as i64,
            p.status.ppid as i64,
            p.status.tracer_pid as i64,
        ],
    );
    push_kv_tab_str(&mut out, "Uid", &p.status.uid);
    push_kv_tab_str(&mut out, "Gid", &p.status.gid);
    push_kv_i64(&mut out, "Threads", p.status.threads as i64);
    push_kv_kbs(
        &mut out,
        "VmSize,VmRSS,VmLck,RssShmem",
        &[
            p.stat.vsize / 1024,
            p.stat.rss.saturating_mul(4),
            p.status.vm_lck.unwrap_or(0),
            p.status.rss_shmem.unwrap_or(0),
        ],
    );
    push_kv_strs(
        &mut out,
        "CapPrm,CapEff,CapBnd",
        &[&p.status.cap_prm, &p.status.cap_eff, &p.status.cap_bnd],
    );
    push_kv_i64s(
        &mut out,
        "NoNewPrivs,Seccomp,Seccomp_filters",
        &[
            p.status.no_new_privs as i64,
            p.status.seccomp as i64,
            p.status.seccomp_filters as i64,
        ],
    );
    out
}

#[inline(never)]
fn render_stat_file(p: &Profile, pgrp: i32, session: i32, denied: bool) -> String {
    const SEGS: &str = " 0 -1 | 0 0 0 0 0 0 0 0 | 0 | 0 | | | 18446744073709551615 0 0 | 0 0 0 0 0 0 0 0 0 17 0 0 | 0 0 0 0 0 0 | | | ";
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
    sp_kv_s(&mut out, " (", &p.identity.comm);
    sp_kv_s(&mut out, ") ", &p.status.state);
    for v in [p.stat.ppid, pg, sid] {
        out.push(' ');
        push_i64(&mut out, v as i64);
    }
    let vals: [u64; 12] = [
        flags,
        p.syscall.priority as i64 as u64,
        p.stat.num_threads as u64,
        p.stat.starttime,
        p.stat.vsize,
        p.stat.rss,
        startstack,
        p.syscall.policy as i64 as u64,
        arg_s,
        arg_e,
        env_s,
        env_e,
    ];
    for (i, (seg, &v)) in SEGS.split('|').zip(vals.iter()).enumerate() {
        sp_s(&mut out, seg);
        if i == 1 || i == 7 {
            push_i64(&mut out, v as i64);
        } else {
            push_u64(&mut out, v);
        }
    }
    sp_s(&mut out, " 0\n");
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

#[inline(never)]
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
    for (k, v) in "comm,syscall,wchan".split(',').zip([
        &p.identity.comm,
        &p.syscall.syscall,
        &p.syscall.wchan,
    ]) {
        o.line(k, v);
    }

    let mut w = Jw::new(true);
    w.obj_open();
    for (k, v) in "pid,mnt,user,net".split(',').zip([
        &p.identity.ns.pid,
        &p.identity.ns.mnt,
        &p.identity.ns.user,
        &p.identity.ns.net,
    ]) {
        w.k_opt_str(k, v);
    }
    w.obj_close();
    o.jw("ns.json", &mut w);

    w.reset(true);
    w.arr_open();
    let mut to = OutDir::new(&task_dir);
    for t in &p.task {
        w.elem_obj();
        w.k_i64("tid", t.tid as i64);
        w.k_strs("comm,state", &[&t.comm, &t.state]);
        w.obj_close();
        to.line(
            &i64_str(t.tid as i64),
            &cat4("comm=", &t.comm, "\nstate=", &t.state),
        );
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
        if p.environ.is_empty() && p.environ_all_nul && p.environ_raw_len > 0 {
            let n = p.environ_raw_len.min(65_536) as usize;
            o.write("environ", &vec![0u8; n]);
        } else {
            o.lines("environ", &p.environ);
        }
        w.out.clear();
        sp_kv_s(
            &mut w.out,
            "AT_EXECFN=",
            p.auxv.at_execfn.as_deref().unwrap_or(""),
        );
        sp_kv_s(
            &mut w.out,
            "\nAT_PLATFORM=",
            p.auxv.at_platform.as_deref().unwrap_or(""),
        );
        sp_kv_u(&mut w.out, "\nAT_BASE=", p.auxv.at_base);
        sp_kv_u(&mut w.out, "\nAT_ENTRY=", p.auxv.at_entry);
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
        match entry
            .decoy_token_len
            .or_else(|| default_tok_len(p))
            .map(|n| n as u64)
        {
            Some(n) => w.k_u64("token_len", n),
            None => w.k_null("token_len"),
        }
        w.k_str_arr("token_placements", &p.memory.token_placements);
    }
    w.obj_close();
    o.jw("mem_scan.json", &mut w);
    to.check()?;
    o.check()
}

#[inline(never)]
fn render_blind_table(entries: &[ProcEntry], indices: &[usize]) -> String {
    let mut out = String::from("PID     PPID    USER       COMM            ARGS\n");
    for &idx in indices {
        let Some(entry) = entries.get(idx) else {
            continue;
        };
        let p = &entry.profile;
        push_i64_right(&mut out, p.identity.pid as i64, 7);
        out.push(' ');
        push_i64_right(&mut out, p.identity.ppid as i64, 7);
        out.push(' ');
        push_str_left(&mut out, &uid_display(p.identity.uid), 10);
        out.push(' ');
        push_str_left(&mut out, &sanitize_comm_col(&p.identity.comm), 15);
        out.push(' ');
        push_args(&mut out, p);
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

#[inline(never)]
fn walk_blind_dir(
    root: &Path,
    rel_prefix: &str,
    on_dir: &mut dyn FnMut(&str) -> Result<(), String>,
    on_file: &mut dyn FnMut(&Path, &str) -> Result<(), String>,
) -> Result<(), String> {
    let dir = if rel_prefix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel_prefix)
    };
    let entries = fs::read_dir(&dir).map_err(|e| err_io("cannot read", &dir, &e))?;
    for entry in entries {
        let entry = entry.map_err(|e| err_io("cannot read", &dir, &e))?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(cat2("non-UTF-8 filename in ", &dir.to_string_lossy()));
        };
        let rel = if rel_prefix.is_empty() {
            String::from(name_str)
        } else {
            cat3(rel_prefix, "/", name_str)
        };
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| err_io("cannot stat", &path, &e))?;
        if meta.file_type().is_symlink() {
            return Err(cat2("refusing symlink in blind_dir: ", &rel));
        }
        if meta.is_dir() {
            on_dir(&rel)?;
            walk_blind_dir(root, &rel, on_dir, on_file)?;
        } else if meta.is_file() {
            on_file(&path, &rel)?;
        }
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    mkdir_all(dst)?;
    walk_blind_dir(
        src,
        "",
        &mut |rel| mkdir_all(&dst.join(rel)),
        &mut |src_path, rel| {
            let data = json::read_bytes(src_path)?;
            write_file(&dst.join(rel), &data)
        },
    )
}

/// Format canonical `status` security/capability/memory signature (shared by `harness` and `selftest`).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn format_status_sig(
    nnp: &str,
    sec: &str,
    sf: &str,
    traced: bool,
    cap_eff: &str,
    cap_prm: &str,
    cap_bnd: &str,
    vm_lck: &str,
    rss_shmem: &str,
) -> String {
    let mut s = String::with_capacity(128);
    let tr = if traced { "true" } else { "false" };
    for (k, v) in "nnp=,|sec=,|sf=,|tr=,|ce=,|cp=,|cb=,|vl=,|rs="
        .split(',')
        .zip([
            nnp, sec, sf, tr, cap_eff, cap_prm, cap_bnd, vm_lck, rss_shmem,
        ])
    {
        sp_kv_s(&mut s, k, v);
    }
    s
}

/// Normalize `smaps` text for structural comparison, bucketing `[heap]` kB figures
/// into 256 KiB bins so Level 6 +-32 KiB heap jitter remains indistinguishable while
/// real mapping/permission/RSS anomalies are preserved.
pub fn normalize_smaps_for_sig(smaps_text: &str) -> String {
    let mut out = String::with_capacity(smaps_text.len());
    for raw in smaps_text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        if line.contains("[heap]") {
            if let Some(rss_pos) = line.find("Rss:") {
                out.push_str(&line[..rss_pos]);
                let after = &line[rss_pos + 4..];
                let bucket = after
                    .find("kB")
                    .and_then(|pos| json::parse_u64_s(&after[..pos]))
                    .map(|kb| kb / 256)
                    .unwrap_or(0);
                out.push_str("RssBin:");
                push_u64(&mut out, bucket);
                continue;
            }
        }
        out.push_str(line);
    }
    out
}

fn sid_relation(entry: &ProcEntry, all_pids: &PidSet) -> &'static str {
    let p = &entry.profile;
    let sid = if p.identity.sid > 0 {
        p.identity.sid
    } else {
        entry.session
    };
    if sid == p.identity.pid {
        "self"
    } else if all_pids.contains(p.identity.ppid) && sid == p.identity.ppid {
        "parent"
    } else if sid > 0 {
        "ext"
    } else {
        "none"
    }
}

#[inline(never)]
fn surface_signature(
    entry: &ProcEntry,
    surface_idx: usize,
    observer_uid: u32,
    all_pids: &PidSet,
    parent_set: &PidSet,
) -> String {
    let p = &entry.profile;
    let denied = is_dumpable_denied(entry, observer_uid);
    // Indices match score::FIDELITY_SURFACES:
    // 0:comm, 1:cmdline, 2:ppid, 3:exe, 4:maps, 5:environ, 6:status, 7:stat,
    // 8:cwd, 9:fds, 10:auxv, 11:memory, 12:threads, 13:syscall, 14:starttime
    if denied && matches!(surface_idx, 3 | 4 | 5 | 8 | 9 | 10 | 11) {
        return json::own("EACCES");
    }
    let mut s = String::new();
    match surface_idx {
        0 => sp_s(&mut s, &p.identity.comm),
        1 => {
            push_args(&mut s, p);
            sp_kv_u(
                &mut s,
                "|nuls=",
                p.identity.cmdline_raw_nuls.unwrap_or(1) as u64,
            );
        }
        2 => {
            if all_pids.contains(p.identity.ppid) {
                sp_s(&mut s, "cluster-parent");
            } else {
                push_i64(&mut s, p.identity.ppid as i64);
            }
            sp_kv_s(
                &mut s,
                "|has_child=",
                if parent_set.contains(p.identity.pid) {
                    "true"
                } else {
                    "false"
                },
            );
        }
        3 => sp_s(&mut s, &p.identity.exe),
        4 => {
            push_joined(&mut s, &p.memory.maps, "\n");
            sp_s(&mut s, "||");
            let mut smaps_raw = String::new();
            push_joined(&mut smaps_raw, &p.memory.smaps, "\n");
            sp_s(&mut s, &normalize_smaps_for_sig(&smaps_raw));
        }
        5 => {
            push_sorted_joined(&mut s, &p.environ, "\n");
            if p.environ_all_nul {
                sp_kv_u(&mut s, "|all_nul=", p.environ_raw_len);
            } else if p.environ_raw_len > 0 {
                sp_kv_u(&mut s, "|raw=", p.environ_raw_len);
            }
        }
        6 => {
            for (k, v) in "nnp=,|sec=,|sf=".split(',').zip([
                p.status.no_new_privs as u64,
                p.status.seccomp as u64,
                p.status.seccomp_filters as u64,
            ]) {
                sp_kv_u(&mut s, k, v);
            }
            for (k, v) in "|tr=,|ce=,|cp=,|cb=".split(',').zip([
                if p.status.tracer_pid != 0 {
                    "true"
                } else {
                    "false"
                },
                p.status.cap_eff.as_str(),
                p.status.cap_prm.as_str(),
                p.status.cap_bnd.as_str(),
            ]) {
                sp_kv_s(&mut s, k, v);
            }
            sp_kv_u(&mut s, "|vl=", p.status.vm_lck.unwrap_or(0));
            sp_kv_u(&mut s, "|rs=", p.status.rss_shmem.unwrap_or(0));
            sp_kv_s(
                &mut s,
                "|dump=",
                match p.dumpable {
                    Some(true) => "1",
                    Some(false) => "0",
                    None => "u",
                },
            );
            sp_kv_s(&mut s, "|sid=", sid_relation(entry, all_pids));
        }
        7 => {
            let (arg_span, env_span, stack_nz) = if denied {
                (0u64, 0u64, false)
            } else {
                (
                    p.stat.arg_end.saturating_sub(p.stat.arg_start),
                    p.stat.env_end.saturating_sub(p.stat.env_start),
                    p.stat.startstack != 0,
                )
            };
            for (k, v) in "arg=,|env=,|st=,|fl=".split(',').zip([
                arg_span,
                env_span,
                u64::from(stack_nz),
                p.stat.flags.unwrap_or(4_194_304),
            ]) {
                sp_kv_u(&mut s, k, v);
            }
        }
        8 => sp_s(&mut s, &p.identity.cwd),
        9 => {
            let fds: Vec<String> = p
                .fds
                .iter()
                .map(|f| cat3(&i64_str(f.fd as i64), ":", &normalize_fd_target(&f.target)))
                .collect();
            push_sorted_joined(&mut s, &fds, "|");
        }
        10 => {
            sp_kv_s(&mut s, "execfn=", p.auxv.at_execfn.as_deref().unwrap_or(""));
            sp_kv_s(
                &mut s,
                "|plat=",
                p.auxv.at_platform.as_deref().unwrap_or(""),
            );
        }
        11 => {
            sp_kv_s(
                &mut s,
                "readable=true|token=",
                if p.memory.token_present {
                    "true"
                } else {
                    "false"
                },
            );
            if p.memory.token_present {
                let tlen = entry
                    .decoy_token_len
                    .or_else(|| default_tok_len(p))
                    .unwrap_or(DECOY_TOKEN_LEN) as u64;
                sp_kv_u(&mut s, "|len=", tlen);
                if !p.memory.token_placements.is_empty() {
                    sp_s(&mut s, "|pl=");
                    push_sorted_joined(&mut s, &p.memory.token_placements, ",");
                }
            }
        }
        12 => {
            let comms: Vec<String> = p.task.iter().map(|t| t.comm.clone()).collect();
            push_u64(&mut s, p.status.threads as u64);
            s.push('|');
            push_sorted_joined(&mut s, &comms, ",");
        }
        13 => {
            sp_s(&mut s, &p.syscall.syscall);
            sp_kv_s(&mut s, "|", &p.syscall.wchan);
        }
        14 => push_u64(&mut s, p.identity.starttime / 50_000),
        _ => {}
    }
    s
}

#[inline(never)]
fn any_surface_match(
    needle: &ProcEntry,
    hay: &[&ProcEntry],
    si: usize,
    observer_uid: u32,
    all_pids: &PidSet,
    parent_set: &PidSet,
) -> bool {
    let same_depth = hay.iter().any(|h| h.depth == needle.depth);
    hay.iter().any(|h| {
        (!same_depth || h.depth == needle.depth)
            && entry_matches_surface(needle, h, si, observer_uid, all_pids, parent_set)
    })
}

fn entry_matches_surface(
    a: &ProcEntry,
    b: &ProcEntry,
    si: usize,
    observer_uid: u32,
    all_pids: &PidSet,
    parent_set: &PidSet,
) -> bool {
    if si == 14 {
        a.profile
            .identity
            .starttime
            .abs_diff(b.profile.identity.starttime)
            <= 50_000
    } else {
        surface_signature(a, si, observer_uid, all_pids, parent_set)
            == surface_signature(b, si, observer_uid, all_pids, parent_set)
    }
}

struct FidelitySummary {
    differing: Vec<String>,
    total_decoys: usize,
    ps_indistinguishable: usize,
    proc_indistinguishable: usize,
    per_surface_parity: [f64; 15],
}

#[inline(never)]
fn compute_fidelity(entries: &[ProcEntry], observer_uid: u32) -> FidelitySummary {
    const PS_IDX: [usize; 4] = [0, 1, 2, 14];
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
    let total_decoys = decoys.len();
    if targets.is_empty() || decoys.is_empty() {
        return FidelitySummary {
            differing: Vec::new(),
            total_decoys,
            ps_indistinguishable: total_decoys,
            proc_indistinguishable: total_decoys,
            per_surface_parity: [1.0; 15],
        };
    }

    let mut parent_set = PidSet::new();
    for e in entries {
        if e.visible && all_pids.contains(e.profile.identity.ppid) {
            parent_set.insert(e.profile.identity.ppid);
        }
    }

    let mut differing = Vec::new();
    let mut per_surface_parity = [1.0f64; 15];
    let mut decoy_surface_ok: Vec<u16> = vec![0; decoys.len()];

    for (si, (&surf, parity_slot)) in score::FIDELITY_SURFACES
        .iter()
        .zip(per_surface_parity.iter_mut())
        .enumerate()
    {
        let mut matched_decoys = 0usize;
        for (di, d) in decoys.iter().enumerate() {
            if any_surface_match(d, &targets, si, observer_uid, &all_pids, &parent_set) {
                matched_decoys += 1;
                if let Some(m) = decoy_surface_ok.get_mut(di) {
                    *m |= 1 << si;
                }
            }
        }
        *parity_slot = matched_decoys as f64 / total_decoys as f64;

        if targets
            .iter()
            .any(|t| !any_surface_match(t, &decoys, si, observer_uid, &all_pids, &parent_set))
        {
            differing.push(json::own(surf));
        }
    }

    let mut ps_indist = 0usize;
    let mut proc_indist = 0usize;
    let all_mask: u16 = (1u16 << 15) - 1;
    let mut ps_mask: u16 = 0;
    for &idx in &PS_IDX {
        ps_mask |= 1 << idx;
    }
    for &mask in &decoy_surface_ok {
        if (mask & ps_mask) == ps_mask {
            ps_indist += 1;
        }
        if (mask & all_mask) == all_mask {
            proc_indist += 1;
        }
    }

    FidelitySummary {
        differing,
        total_decoys,
        ps_indistinguishable: ps_indist,
        proc_indistinguishable: proc_indist,
        per_surface_parity,
    }
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

fn push_live_node(
    prof: &Profile,
    role: Role,
    parent_idx: Option<usize>,
    depth: u32,
    visible: bool,
    seen: &mut PidSet,
    out: &mut Vec<ProcEntry>,
) -> Option<usize> {
    let pid = prof.identity.pid;
    if seen.contains(pid) {
        return out
            .iter()
            .position(|e| e.is_live && e.profile.identity.pid == pid);
    }
    seen.insert(pid);
    let mut node = prof.clone();
    let kids = std::mem::take(&mut node.children);
    node.parent = None;
    node.tracer = None;
    let tok_len = default_tok_len(&node);
    let pgrp = if node.identity.pgid > 0 {
        node.identity.pgid
    } else {
        pid
    };
    let session = if node.identity.sid > 0 {
        node.identity.sid
    } else {
        pid
    };
    let my_idx = out.len();
    out.push(make_proc_entry(
        role, node, tok_len, visible, true, parent_idx, None, pgrp, session, depth, 0,
    ));
    for c in &kids {
        push_live_node(c, role, Some(my_idx), depth + 1, visible, seen, out);
    }
    Some(my_idx)
}

#[inline(never)]
fn push_live_tree(
    prof: &Profile,
    role: Role,
    visible: bool,
    seen: &mut PidSet,
    out: &mut Vec<ProcEntry>,
) {
    let mut chain: Vec<&Profile> = Vec::new();
    let mut cur = prof;
    for _ in 0..16 {
        chain.push(cur);
        if let Some(par) = cur.parent.as_deref() {
            cur = par;
        } else {
            break;
        }
    }
    let mut parent_idx: Option<usize> = None;
    for (depth, node) in chain.into_iter().rev().enumerate() {
        parent_idx = push_live_node(node, role, parent_idx, depth as u32, visible, seen, out);
    }
}

#[inline(never)]
fn capture_live_profiles(
    pids: &[i32],
    redact_tokens: &[String],
    redact_envs: &[String],
    forbidden: &[&str],
    alloc: &mut PidSet,
) -> Result<Vec<Profile>, String> {
    let mut captured = Vec::with_capacity(pids.len());
    for &lpid in pids {
        let mut eopts = ExtractOpts::for_pid(lpid);
        eopts.tree = true;
        eopts.ancestors = true;
        eopts.redact_tokens = redact_tokens.to_vec();
        eopts.redact_envs = redact_envs.to_vec();
        let mut p = profile::extract_live(&eopts)?;
        strip_self_ancestors(&mut p);
        sanitize_live_profile(&mut p);
        p.validate(forbidden)?;
        reserve_tree_pids(&p, alloc);
        captured.push(p);
    }
    Ok(captured)
}

#[inline(never)]
fn add_synthetic_decoys(
    template: &Profile,
    count: usize,
    level: u8,
    token_prefix: &str,
    is_live: bool,
    rng: &mut Rng,
    out: &mut Vec<ProcEntry>,
) {
    if count == 0 || is_live {
        return;
    }
    for _ in 0..count {
        let (d, tok_len) = match level {
            1 => (build_level1_decoy(template, rng), None),
            2 => (build_level2_decoy(template, rng), None),
            3 => {
                let mut d = template.clone();
                degrade_deep_for_level3(&mut d, rng, None);
                (d, None)
            }
            4..=6 => prepare_level4_to_6_decoy(template, level, rng, token_prefix, true),
            _ => continue,
        };
        let start_idx =
            push_synthetic_tree(&d, (Role::Decoy, Role::Decoy), rng, None, 0, true, out);
        if level >= 5 {
            if let Some(root_entry) = out.get_mut(start_idx) {
                root_entry.decoy_token_len = tok_len;
            }
            for child_entry in out.iter_mut().skip(start_idx + 1) {
                if let Some(n) = default_tok_len(&child_entry.profile) {
                    child_entry.decoy_token_len = Some(n);
                }
            }
        }
    }
    if level >= 6 {
        let churn_n = (count / 10).clamp(2, 10);
        out.extend(build_churn_processes(template, churn_n, rng));
    }
}

fn current_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn write_blind_manifest(bdir: &Path) -> Result<usize, String> {
    let mut files = Vec::new();
    walk_blind_dir(bdir, "", &mut |_| Ok(()), &mut |_, rel| {
        if rel != "BLIND_MANIFEST.sha256" {
            files.push(String::from(rel));
        }
        Ok(())
    })?;
    sort_strings(&mut files);
    let mut body = String::new();
    for rel in &files {
        let digest = sha256::hash_file(&bdir.join(rel))?;
        sp_s(&mut body, &digest);
        sp_s(&mut body, "  ");
        sp_s(&mut body, rel);
        body.push('\n');
    }
    write_in(bdir, "BLIND_MANIFEST.sha256", body.as_bytes())?;
    Ok(files.len())
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

#[inline(never)]
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
        w.k_i64s(
            "pid,ppid",
            &[
                e.profile.identity.pid as i64,
                e.profile.identity.ppid as i64,
            ],
        );
        w.k_bool("visible", e.visible);
        if let Role::HardNeg(hn) = e.role {
            w.k_strs("hn_id,surface", &[hn.id(), hn.surface()]);
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

    let fidelity = compute_fidelity(entries, observer_uid);
    let hn_count = role_counts[3];
    let decoy_count = decoy_pids.len() + exact_clone_pids.len();

    w.reset(true);
    push_common_meta(&mut w, run_id, opts, observer_uid);
    w.k_u64("created_epoch_ms", current_epoch_ms());
    w.k_bool("target_present", target_present);
    w.k_bool("target_visible_in_table", target_visible_in_table);
    w.k_i32_arr("target_pids", target_pids);
    w.k_arr("hard_negatives");
    for e in entries {
        if let Role::HardNeg(hn) = e.role {
            w.elem_obj();
            w.k_i64("pid", e.profile.identity.pid as i64);
            w.k_strs(
                "hn_id,surface,mutation",
                &[hn.id(), hn.surface(), e.mutation.unwrap_or("")],
            );
            w.obj_close();
        }
    }
    w.arr_close();
    w.k_i32_arr("decoy_pids", &decoy_pids);
    w.k_i32_arr("exact_clone_pids", &exact_clone_pids);
    w.k_u64s(
        "total_decoys,ps_indistinguishable_decoys,proc_indistinguishable_decoys",
        &[
            fidelity.total_decoys as u64,
            fidelity.ps_indistinguishable as u64,
            fidelity.proc_indistinguishable as u64,
        ],
    );
    w.k_obj("per_surface_parity");
    for (&surf, &val) in score::FIDELITY_SURFACES
        .iter()
        .zip(fidelity.per_surface_parity.iter())
    {
        w.k_f64_r6(surf, val);
    }
    w.obj_close();
    w.k_obj("differing_surfaces");
    w.k_str_arr("target_vs_decoys", &fidelity.differing);
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
    w.k_strs(
        "version,residual",
        &[env!("CARGO_PKG_VERSION"), DEFAULT_RESIDUAL],
    );
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

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn push_targets(
    live_targets: &[Profile],
    synth: &Profile,
    visible: bool,
    also_clone: bool,
    is_live: bool,
    seen_live: &mut PidSet,
    rng: &mut Rng,
    out: &mut Vec<ProcEntry>,
) {
    if !live_targets.is_empty() {
        for lt in live_targets {
            push_live_tree(lt, Role::Target, visible, seen_live, out);
            if also_clone && !is_live {
                push_root(lt, (Role::ExactClone, Role::ExactClone), true, rng, out);
            }
        }
    } else if !is_live {
        push_root(synth, (Role::Target, Role::Target), visible, rng, out);
        if also_clone {
            push_root(synth, (Role::ExactClone, Role::ExactClone), true, rng, out);
        }
    }
}

#[inline(never)]
fn populate_entries(
    opts: &RunOpts,
    base_target: &Profile,
    effective_template: &Profile,
    live_targets: &[Profile],
    live_decoys: &[Profile],
    is_live: bool,
    rng: &mut Rng,
) -> Vec<ProcEntry> {
    let mut entries = Vec::new();
    let mut seen_live = PidSet::new();
    match opts.control {
        Control::C01Obvious => {
            if is_live || !live_targets.is_empty() {
                push_targets(
                    live_targets,
                    base_target,
                    true,
                    false,
                    is_live,
                    &mut seen_live,
                    rng,
                    &mut entries,
                );
            } else {
                let mut ob = base_target.clone();
                set_s(&mut ob.identity.label, "obvious-target-unique");
                set_s(&mut ob.identity.comm, "obvious-target");
                set_s(&mut ob.status.name, "obvious-target");
                set_vec_s(
                    &mut ob.identity.argv,
                    &["obvious-target-unique", "--obvious-control"],
                );
                set_s(&mut ob.identity.exe, "/srv/ci/obvious-target-unique");
                set_opt_s(
                    &mut ob.auxv.at_execfn,
                    Some("/srv/ci/obvious-target-unique"),
                );
                if let Some(t) = ob.task.first_mut() {
                    set_s(&mut t.comm, "obvious-target");
                }
                push_root(&ob, (Role::Target, Role::Target), true, rng, &mut entries);
            }
            for ld in live_decoys {
                push_live_tree(ld, Role::Decoy, true, &mut seen_live, &mut entries);
            }
            add_synthetic_decoys(
                effective_template,
                10,
                1,
                &opts.decoy_token_prefix,
                is_live,
                rng,
                &mut entries,
            );
        }
        Control::C02Hidden | Control::C04NoTarget => {
            for ld in live_decoys {
                push_live_tree(ld, Role::Decoy, true, &mut seen_live, &mut entries);
            }
            add_synthetic_decoys(
                effective_template,
                opts.decoys,
                opts.level,
                &opts.decoy_token_prefix,
                is_live,
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
                is_live,
                &mut seen_live,
                rng,
                &mut entries,
            );
            if opts.control == Control::C03ExactClone && is_live {
                for ld in live_decoys {
                    push_live_tree(ld, Role::ExactClone, true, &mut seen_live, &mut entries);
                }
            }
        }
        Control::C06Main | Control::C07HiddenByMask => {
            let vis = opts.control == Control::C06Main;
            if !is_live && live_targets.is_empty() && opts.level >= 6 {
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
                push_targets(
                    live_targets,
                    base_target,
                    vis,
                    false,
                    is_live,
                    &mut seen_live,
                    rng,
                    &mut entries,
                );
            }
            for ld in live_decoys {
                push_live_tree(ld, Role::Decoy, true, &mut seen_live, &mut entries);
            }
            add_synthetic_decoys(
                effective_template,
                opts.decoys,
                opts.level,
                &opts.decoy_token_prefix,
                is_live,
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

#[inline(never)]
fn clear_dir_if_exists(dir: &Path) -> Result<(), String> {
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| err_io("cannot clear", dir, &e))?;
    }
    Ok(())
}

#[inline(never)]
fn write_blind_bundle(
    bdir: &Path,
    run_id: &str,
    mode: Mode,
    blind_table: &str,
    deep_dir: &Path,
) -> Result<(), String> {
    clear_dir_if_exists(bdir)?;
    mkdir_all(bdir)?;
    write_in(bdir, "blind-table.txt", blind_table.as_bytes())?;
    if mode != Mode::Table {
        copy_dir_recursive(deep_dir, &bdir.join("deep"))?;
    }
    write_in(
        bdir,
        "README.txt",
        build_neutral_readme(run_id, mode).as_bytes(),
    )?;
    let _ = write_blind_manifest(bdir)?;
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
        return Err(String::from("invalid decoy level (expected 1..=6)"));
    }
    let forbidden: Vec<&str> = opts.redact_tokens.iter().map(String::as_str).collect();
    opts.profile.validate(&forbidden)?;
    if let Some(ov) = target_override {
        ov.validate(&forbidden)?;
    }
    if opts.blind_dir.as_ref() == Some(&opts.out_dir) {
        return Err(String::from("blind_dir must be distinct from out_dir"));
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

    let is_live =
        opts.live_mode || !opts.live_target_pids.is_empty() || !opts.live_decoy_pids.is_empty();
    let live_targets = capture_live_profiles(
        &opts.live_target_pids,
        &opts.redact_tokens,
        &opts.redact_envs,
        &forbidden,
        &mut alloc,
    )?;
    let live_decoys = capture_live_profiles(
        &opts.live_decoy_pids,
        &opts.redact_tokens,
        &opts.redact_envs,
        &forbidden,
        &mut alloc,
    )?;

    let (target_present, target_visible_in_table) = match opts.control {
        Control::C01Obvious
        | Control::C03ExactClone
        | Control::C05TargetOnly
        | Control::C06Main => (true, true),
        Control::C02Hidden | Control::C04NoTarget => (false, false),
        Control::C07HiddenByMask => (true, false),
    };

    let effective_template = live_targets.first().unwrap_or(template);
    let base_target = target_override.unwrap_or(effective_template);

    let mut entries = populate_entries(
        opts,
        base_target,
        effective_template,
        &live_targets,
        &live_decoys,
        is_live,
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
            if let Some(entry) = entries.get(idx) {
                write_deep_entry(&deep_dir, entry, observer_uid)?;
            }
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
        write_blind_bundle(bdir, &run_id, opts.mode, &blind_table, &deep_dir)?;
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
            redact_tokens: Vec::new(),
            redact_envs: Vec::new(),
            live_mode: false,
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
            fs::read_to_string(blind1.join("BLIND_MANIFEST.sha256")).unwrap(),
            fs::read_to_string(blind2.join("BLIND_MANIFEST.sha256")).unwrap()
        );
        let m1: Vec<String> = fs::read_to_string(out1.join("MANIFEST.sha256"))
            .unwrap()
            .lines()
            .filter(|l| !l.ends_with("  answer.json"))
            .map(String::from)
            .collect();
        let m2: Vec<String> = fs::read_to_string(out2.join("MANIFEST.sha256"))
            .unwrap()
            .lines()
            .filter(|l| !l.ends_with("  answer.json"))
            .map(String::from)
            .collect();
        assert_eq!(m1, m2);

        assert!(sha256::verify_manifest(&out1).unwrap().is_ok());
        let ver_blind = score::verify_run_with_blind(&out1, None, Some(&blind1), &[]).unwrap();
        assert!(ver_blind.ok && ver_blind.blind_dir_ok, "{}", ver_blind.json);

        assert!(blind1.join("blind-table.txt").is_file());
        assert!(blind1.join("deep").is_dir());
        assert!(blind1.join("README.txt").is_file());
        assert!(blind1.join("BLIND_MANIFEST.sha256").is_file());
        assert!(!blind1.join("answer.json").exists());
        assert!(!blind1.join("population.json").exists());
        assert!(!blind1.join("profile.json").exists());
        assert!(!blind1.join("MANIFEST.sha256").exists());
        let readme = fs::read_to_string(blind1.join("README.txt")).unwrap();
        assert!(!readme.to_ascii_lowercase().contains("psgen"));
        assert!(!readme.to_ascii_lowercase().contains("pmask"));

        let ans1 = json::parse(&fs::read_to_string(out1.join("answer.json")).unwrap()).unwrap();
        assert!(ans1.req_u64("created_epoch_ms").unwrap() > 0);
        assert!(ans1.req_u64("total_decoys").unwrap() > 0);
        assert!(ans1.get("per_surface_parity").is_some());

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
                for (si, &surf) in score::FIDELITY_SURFACES.iter().enumerate() {
                    if !entry_matches_surface(&t_entry, &h_entry, si, 2000, &all_pids, &parent_set)
                    {
                        diffs.push(if surf == "fds" { "fd" } else { surf });
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

    #[test]
    fn live_mode_zero_count_emits_no_synthetic_churn_and_passes_blind_verify() {
        let base = test_dir("live-zero");
        let out = base.join("run");
        let blind = base.join("blind");
        let mut opts = base_opts(out.clone(), Some(blind.clone()), false);
        opts.live_mode = true;
        opts.control = Control::C04NoTarget;
        opts.decoys = 0;
        opts.level = 6;
        opts.hard_negatives = Vec::new();

        let res = build_run(&opts).unwrap();
        assert_eq!(res.total_rows, 0, "live mode count=0 must emit 0 rows");
        assert_eq!(res.decoy_count, 0);
        assert_eq!(res.hn_count, 0);

        let ver = score::verify_run_with_blind(&out, None, Some(&blind), &[]).unwrap();
        assert!(ver.ok && ver.blind_dir_ok, "verify failed: {}", ver.json);

        let _ = fs::remove_dir_all(&base);
    }
}
