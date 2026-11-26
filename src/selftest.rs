//! Built-in reference blind observer, 8 planted-defect guards (`PD-01`..`PD-08`
//! with both passing and refusal verification), and the 9/10 vs 7/10
//! discrimination acceptance suite (`psgen selftest`).

use crate::harness::{self, Control, HardNeg, Mode, RunOpts, DEFAULT_RESIDUAL};
use crate::json::{
    self, cat2, cat3, csv_idx, i64_str, join_strs, mkdir_all, next_csv, own, read_opt_in, read_str,
    read_str_in, sort_strings, u64_str, write_file, Json, Jw,
};
use crate::profile::{self, Profile};
use crate::score::{self, Pick, PickChoice, PICK_SCHEMA};
use std::fs;
use std::path::{Path, PathBuf};

pub const SELFTEST_SCHEMA: u32 = 1;

const OBS_SURFACE_COUNT: usize = 14;
const OBS_SURFACES_CSV: &str =
    "comm,cmdline,ppid,exe,memory,maps,environ,fd,status,syscall,threads,cwd,auxv,stat";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObserverDefect {
    None,
    AlwaysAbsent,
    AlwaysPickFirst,
    IgnoreExe,
    IgnoreMaps,
}

struct ObservedProc {
    pid: i32,
    ppid: i32,
    user: String,
    is_child: bool,
    surfaces: Vec<(u8, String)>,
    starttime: Option<u64>,
    leaked_secret_env: bool,
}

impl ObservedProc {
    #[inline(never)]
    fn set_surf(&mut self, i: usize, val: String) {
        let k = i as u8;
        if let Some((_, slot)) = self.surfaces.iter_mut().find(|(idx, _)| *idx == k) {
            *slot = val;
        } else {
            self.surfaces.push((k, val));
        }
    }

    #[inline(never)]
    fn surf(&self, i: usize) -> Option<&str> {
        let k = i as u8;
        self.surfaces
            .iter()
            .find(|(idx, _)| *idx == k)
            .map(|(_, s)| s.as_str())
    }
}

#[inline(never)]
fn parse_stat_fields(stat_text: &str) -> (Option<u64>, Option<String>) {
    let Some(close) = stat_text.rfind(')') else {
        return (None, None);
    };
    let mut st = None;
    let mut f = [0u64; 6]; // flags, startstack, arg_s, arg_e, env_s, env_e
    for (idx, tok) in stat_text
        .get(close + 1..)
        .unwrap_or("")
        .split_ascii_whitespace()
        .enumerate()
    {
        let Some(v) = json::parse_u64_s(tok) else {
            continue;
        };
        match idx {
            6 => f[0] = v,
            19 => st = Some(v),
            25 => f[1] = v,
            45 => f[2] = v,
            46 => f[3] = v,
            47 => f[4] = v,
            48 => f[5] = v,
            _ => {}
        }
    }
    let mut sig = String::with_capacity(48);
    sig.push_str("arg=");
    json::push_u64(&mut sig, f[3].saturating_sub(f[2]));
    sig.push_str("|env=");
    json::push_u64(&mut sig, f[5].saturating_sub(f[4]));
    sig.push_str(if f[1] != 0 { "|st=1|fl=" } else { "|st=0|fl=" });
    json::push_u64(&mut sig, f[0]);
    (st, Some(sig))
}

#[inline(never)]
fn parse_status_sig(status_text: &str) -> String {
    const KEYS: &str =
        "NoNewPrivs,Seccomp,Seccomp_filters,TracerPid,CapEff,CapPrm,CapBnd,VmLck,RssShmem";
    let mut v = ["0", "0", "0", "0", "", "", "", "0", "0"];
    for line in status_text.lines() {
        let Some((k, raw)) = line.split_once(':') else {
            continue;
        };
        if let Some(i) = csv_idx(KEYS, k, false) {
            let t = raw.trim();
            if let Some(slot) = v.get_mut(i) {
                *slot = if i >= 7 {
                    t.strip_suffix("kB").unwrap_or(t).trim()
                } else {
                    t
                };
            }
        }
    }
    harness::format_status_sig(
        v[0],
        v[1],
        v[2],
        v[3] != "0" && !v[3].is_empty(),
        v[4],
        v[5],
        v[6],
        v[7],
        v[8],
    )
}

#[inline(never)]
fn parse_mem_scan_sig(mem_text: &str) -> String {
    let Ok(doc) = json::parse(mem_text) else {
        return own(mem_text.trim());
    };
    if !doc.get_bool("readable").unwrap_or(false) {
        return cat2(
            "readable=false|err=",
            doc.get_str("error").unwrap_or("EACCES"),
        );
    }
    let tp = doc.get_bool("token_present").unwrap_or(false);
    let mut sig = cat2("readable=true|token=", bstr(tp));
    if tp {
        if let Some(len) = doc.get_u64("token_len") {
            sig.push_str("|len=");
            json::push_u64(&mut sig, len);
        }
        if let Some(arr) = doc.get_arr("token_placements") {
            let mut pl = Vec::new();
            for v in arr {
                if let Some(s) = v.as_str() {
                    pl.push(own(s));
                }
            }
            if !pl.is_empty() {
                sort_strings(&mut pl);
                sig.push_str("|pl=");
                sig.push_str(&join_strs(&pl, ","));
            }
        }
    }
    sig
}

#[inline(never)]
fn parse_auxv_sig(auxv_text: &str) -> String {
    let trimmed = auxv_text.trim();
    if trimmed.starts_with("EACCES") {
        return own("EACCES");
    }
    let mut execfn = "";
    let mut plat = "";
    for line in trimmed.lines() {
        if let Some(v) = line.strip_prefix("AT_EXECFN=") {
            execfn = v;
        } else if let Some(v) = line.strip_prefix("AT_PLATFORM=") {
            plat = v;
        }
    }
    json::cat4("execfn=", execfn, "|plat=", plat)
}

#[inline(never)]
fn parse_fd_sig(fd_text: &str) -> String {
    let Ok(doc) = json::parse(fd_text) else {
        return own(fd_text.trim());
    };
    if let Some(err) = doc.get_str("error") {
        return cat2("err=", err);
    }
    let Some(arr) = doc.as_arr() else {
        return own(fd_text.trim());
    };
    let mut items = Vec::with_capacity(arr.len());
    for item in arr {
        if let (Some(fd), Some(t)) = (item.get_i64("fd"), item.get_str("target")) {
            items.push(cat3(&i64_str(fd), ":", &harness::normalize_fd_target(t)));
        }
    }
    sort_strings(&mut items);
    join_strs(&items, "|")
}

#[inline(never)]
fn parse_task_sig(task_text: &str) -> String {
    let Ok(doc) = json::parse(task_text) else {
        return own(task_text.trim());
    };
    let Some(arr) = doc.as_arr() else {
        return own(task_text.trim());
    };
    let mut comms = Vec::with_capacity(arr.len());
    for item in arr {
        if let Some(c) = item.get_str("comm") {
            comms.push(own(c));
        }
    }
    sort_strings(&mut comms);
    cat3(&u64_str(arr.len() as u64), "|", &join_strs(&comms, ","))
}

#[inline(never)]
fn full_fingerprint(p: &ObservedProc, all: &[ObservedProc]) -> String {
    let mut out = cat3("user=", &p.user, "\n");
    let mut csv = OBS_SURFACES_CSV;
    for i in 0..OBS_SURFACE_COUNT {
        let name = next_csv(&mut csv);
        if let Some(v) = p.surf(i) {
            out.push_str(name);
            out.push('=');
            out.push_str(v);
            out.push('\n');
        }
    }
    if let Some(st) = p.starttime {
        out.push_str("st=");
        json::push_u64(&mut out, st / 25_000);
        out.push('\n');
    }
    let mut child_fps = Vec::new();
    for c in all {
        if c.is_child && c.ppid == p.pid {
            child_fps.push(full_fingerprint(c, all));
        }
    }
    sort_strings(&mut child_fps);
    for cfp in child_fps {
        out.push_str("child{\n");
        out.push_str(&cfp);
        out.push_str("}\n");
    }
    out
}

fn median_u64(vals: &mut [u64]) -> u64 {
    json::shell_sort_by(vals, |a, b| a > b);
    vals.get(vals.len() / 2).copied().unwrap_or(0)
}

#[inline(never)]
fn find_cohort_anomaly(
    cohort: &[&ObservedProc],
    deep_enabled: bool,
    defect: ObserverDefect,
) -> Option<(i32, &'static str, String)> {
    if cohort.len() < 3 {
        return None;
    }
    let limit = if deep_enabled { OBS_SURFACE_COUNT } else { 3 };
    let mut csv = OBS_SURFACES_CSV;
    for si in 0..limit {
        let surf = next_csv(&mut csv);
        if (defect == ObserverDefect::IgnoreExe && si == 3)
            || (defect == ObserverDefect::IgnoreMaps && si == 5)
        {
            continue;
        }
        let mut counts: Vec<(&str, usize)> = Vec::new();
        for p in cohort {
            if let Some(val) = p.surf(si) {
                if let Some(slot) = counts.iter_mut().find(|(k, _)| *k == val) {
                    slot.1 += 1;
                } else {
                    counts.push((val, 1));
                }
            }
        }
        if !counts.iter().any(|(_, c)| *c >= 2) {
            continue;
        }
        for p in cohort {
            if let Some(val) = p.surf(si) {
                if counts.iter().any(|(k, c)| *k == val && *c == 1) {
                    return Some((p.pid, surf, cat3("unique '", surf, "' signature")));
                }
            }
        }
    }

    if deep_enabled {
        let mut sts = Vec::new();
        for p in cohort {
            if let Some(st) = p.starttime {
                sts.push(st);
            }
        }
        if sts.len() >= 3 {
            let med = median_u64(&mut sts);
            let mut devs: Vec<u64> = sts.iter().map(|&s| s.abs_diff(med)).collect();
            let mad = median_u64(&mut devs);
            let thresh = 50_000u64.max(mad.saturating_mul(10));
            let mut best: Option<(i32, u64)> = None;
            for p in cohort {
                if let Some(st) = p.starttime {
                    let d = st.abs_diff(med);
                    if d > thresh && !best.is_some_and(|(_, bd)| d <= bd) {
                        best = Some((p.pid, d));
                    }
                }
            }
            if let Some((pid, delta)) = best {
                return Some((pid, "starttime", cat2("starttime delta=", &u64_str(delta))));
            }
        }
    }
    None
}

#[inline(never)]
fn make_pick(
    phase_norm: &str,
    defect: ObserverDefect,
    choice: PickChoice,
    surface: &str,
    reason: &str,
) -> Pick {
    Pick {
        schema: PICK_SCHEMA,
        phase: own(phase_norm),
        pick: choice,
        reason_surface: own(surface),
        reason: own(reason),
        elapsed_sec: Some(0.05),
        evaluator: Some(own(match defect {
            ObserverDefect::None => "reference-blind-v1",
            ObserverDefect::AlwaysAbsent => "defect-always-absent",
            ObserverDefect::AlwaysPickFirst => "defect-always-pick-first",
            ObserverDefect::IgnoreExe => "defect-ignore-exe",
            ObserverDefect::IgnoreMaps => "defect-ignore-maps",
        })),
    }
}

#[inline(never)]
fn parse_environ_sig(env_text: &str) -> String {
    if !env_text.is_empty() && env_text.bytes().all(|b| b == 0) {
        return cat2("all_nul:", &u64_str(env_text.len() as u64));
    }
    let mut lines = Vec::new();
    for part in env_text.split(['\n', '\0']) {
        let t = part.trim();
        if !t.is_empty() {
            lines.push(own(t));
        }
    }
    sort_strings(&mut lines);
    join_strs(&lines, "\n")
}

#[inline(never)]
fn read_deep_surfaces(pdir: &Path, defect: ObserverDefect, op: &mut ObservedProc) {
    if let Some(s) = read_opt_in(pdir, "comm") {
        let exact = s.strip_suffix('\n').unwrap_or(&s);
        if !exact.is_empty() {
            op.set_surf(0, own(exact));
        }
    }
    for (fname, idx, skip) in [
        ("exe", 3, defect == ObserverDefect::IgnoreExe),
        ("cwd", 11, false),
    ] {
        if !skip {
            if let Some(s) = read_opt_in(pdir, fname) {
                op.set_surf(idx, own(s.trim()));
            }
        }
    }
    for &(fname, idx, parse_fn) in &[
        ("mem_scan.json", 4, parse_mem_scan_sig as fn(&str) -> String),
        ("fd.json", 7, parse_fd_sig as fn(&str) -> String),
        ("status", 8, parse_status_sig as fn(&str) -> String),
        ("task.json", 10, parse_task_sig as fn(&str) -> String),
        ("auxv", 12, parse_auxv_sig as fn(&str) -> String),
    ] {
        if let Some(s) = read_opt_in(pdir, fname) {
            op.set_surf(idx, parse_fn(&s));
        }
    }
    if defect != ObserverDefect::IgnoreMaps {
        if let Some(m) = read_opt_in(pdir, "maps") {
            let sm = read_opt_in(pdir, "smaps")
                .map(|t| harness::normalize_smaps_for_sig(&t))
                .unwrap_or_default();
            op.set_surf(5, cat3(m.trim(), "||", &sm));
        }
    }
    if let Some(env_text) = read_opt_in(pdir, "environ") {
        if profile::has_unredacted_secret_in_environ(&env_text) {
            op.leaked_secret_env = true;
        }
        op.set_surf(6, parse_environ_sig(&env_text));
    }
    if let (Some(sc), Some(wc)) = (read_opt_in(pdir, "syscall"), read_opt_in(pdir, "wchan")) {
        op.set_surf(9, cat3(sc.trim(), "|", wc.trim()));
    }
    if let Some(s) = read_opt_in(pdir, "stat") {
        let (st, stat_sig) = parse_stat_fields(&s);
        op.starttime = st;
        if let Some(ss) = stat_sig {
            op.set_surf(13, ss);
        }
    }
}

#[inline(never)]
fn observe_with_defect(
    blind_dir: &Path,
    phase: &str,
    defect: ObserverDefect,
) -> Result<Pick, String> {
    let pt = phase.trim();
    let phase_norm = if pt.eq_ignore_ascii_case("table") {
        "table"
    } else if pt.eq_ignore_ascii_case("deep") {
        "deep"
    } else {
        return Err(cat2("invalid phase ", pt));
    };

    let rows = harness::parse_blind_table(&read_str_in(blind_dir, "blind-table.txt")?)?;
    if defect == ObserverDefect::AlwaysAbsent || rows.is_empty() {
        return Ok(make_pick(
            phase_norm,
            defect,
            PickChoice::Absent,
            "absent",
            "absent",
        ));
    }
    if defect == ObserverDefect::AlwaysPickFirst {
        let pid = rows.first().map_or(0, |r| r.pid);
        return Ok(make_pick(
            phase_norm,
            defect,
            PickChoice::Pid(pid),
            "comm",
            "pick first",
        ));
    }

    let mut pid_list = Vec::with_capacity(rows.len());
    for r in &rows {
        pid_list.push(r.pid);
    }
    let mut parent_list = Vec::new();
    for r in &rows {
        if pid_list.contains(&r.ppid) {
            parent_list.push(r.ppid);
        }
    }

    let deep_root = blind_dir.join("deep");
    let deep_enabled = phase_norm == "deep" && deep_root.is_dir();

    let mut observed: Vec<ObservedProc> = Vec::with_capacity(rows.len());
    for row in rows {
        let is_child = pid_list.contains(&row.ppid);
        let hc = bstr(parent_list.contains(&row.pid));
        let mut op = ObservedProc {
            pid: row.pid,
            ppid: row.ppid,
            user: row.user,
            is_child,
            surfaces: Vec::new(),
            starttime: None,
            leaked_secret_env: false,
        };
        op.set_surf(0, row.comm);
        op.set_surf(1, row.args);
        op.set_surf(
            2,
            if is_child {
                cat2("cluster-parent|has_child=", hc)
            } else {
                cat3(&i64_str(op.ppid as i64), "|has_child=", hc)
            },
        );
        if deep_enabled {
            read_deep_surfaces(&deep_root.join(i64_str(op.pid as i64)), defect, &mut op);
        }
        observed.push(op);
    }

    let mut roots = Vec::new();
    let mut children = Vec::new();
    for p in &observed {
        if p.is_child {
            children.push(p);
        } else {
            roots.push(p);
        }
    }

    let (choice, surf, reason) = if let Some(leaker) = observed.iter().find(|p| p.leaked_secret_env)
    {
        (PickChoice::Pid(leaker.pid), "environ", own("leaked secret"))
    } else if let [only] = roots.as_slice() {
        (PickChoice::Pid(only.pid), "comm", own("sole root"))
    } else if let [a, b] = roots.as_slice() {
        let msg = if full_fingerprint(a, &observed) == full_fingerprint(b, &observed) {
            "exact clone tie"
        } else {
            "two candidates"
        };
        (PickChoice::Ambiguous, "ambiguous", own(msg))
    } else if let Some((pid, surf, reason)) = [roots.as_slice(), children.as_slice()]
        .into_iter()
        .find_map(|c| find_cohort_anomaly(c, deep_enabled, defect))
    {
        (PickChoice::Pid(pid), surf, reason)
    } else {
        (PickChoice::Absent, "absent", own("no anomaly"))
    };
    Ok(make_pick(phase_norm, defect, choice, surf, &reason))
}

/// Strictly blind built-in reference observer. Reads ONLY `blind-table.txt`
/// and `deep/<pid>/*` under `blind_dir` (never `answer.json`).
pub fn reference_observe(blind_dir: &Path, phase: &str) -> Result<Pick, String> {
    observe_with_defect(blind_dir, phase, ObserverDefect::None)
}

fn clean_profile(label: &str, tree: bool) -> Profile {
    let mut prof = profile::synthetic_default_profile(label, tree);
    prof.memory.token_present = true;
    prof.environ = vec![
        own("PATH=/usr/local/bin:/usr/bin:/bin"),
        own("HOME=/srv/ci"),
        own("LANG=C.UTF-8"),
    ];
    for child in &mut prof.children {
        child.memory.token_present = true;
        child.environ = prof.environ.clone();
    }
    prof
}

fn make_7of10_leaking_target(base: &Profile, variant: usize) -> Profile {
    let mut weak = base.clone();
    match variant % 4 {
        0 => {
            let leak_exe = "/opt/weak-masker/real-target-bin";
            json::assign_str(&mut weak.identity.exe, leak_exe);
            weak.auxv.at_execfn = Some(own(leak_exe));
            if let Some(m0) = weak.memory.maps.first_mut() {
                *m0 = cat2("<addr> r-xp 00001000 08:01 1001 ", leak_exe);
            }
            if let Some(s0) = weak.memory.smaps.first_mut() {
                *s0 = cat3(
                    "r-xp ",
                    leak_exe,
                    " Rss:1536kB Private_Dirty:0kB Anonymous:0kB",
                );
            }
        }
        1 => {
            weak.memory.maps.push(own(
                "<addr> r-xp 00000000 08:01 4242 /usr/lib/libweakmask.so",
            ));
            weak.memory.smaps.push(own(
                "r-xp /usr/lib/libweakmask.so Rss:128kB Private_Dirty:0kB Anonymous:0kB",
            ));
        }
        2 => weak.environ.push(own("WEAK_MASKER_ACTIVE=1")),
        _ => {
            json::assign_str(&mut weak.identity.comm, "python3");
            json::assign_str(&mut weak.status.name, "python3");
            if let Some(t) = weak.task.first_mut() {
                json::assign_str(&mut t.comm, "python3");
            }
        }
    }
    weak
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn build_case(
    profile: &Profile,
    control: Control,
    level: u8,
    decoys: usize,
    seed: u64,
    hns: &[HardNeg],
    out_dir: &Path,
    blind_dir: Option<&Path>,
    target_ov: Option<&Profile>,
) -> Result<harness::RunResult, String> {
    let opts = RunOpts {
        profile: profile.clone(),
        decoys,
        seed,
        mode: Mode::Both,
        level,
        control,
        hard_negatives: hns.to_vec(),
        observer_uid: Some(2000),
        out_dir: out_dir.to_path_buf(),
        blind_dir: blind_dir.map(Path::to_path_buf),
        run_id: None,
        live_target_pids: Vec::new(),
        live_decoy_pids: Vec::new(),
        decoy_token_prefix: own("dtok_"),
        redact_tokens: Vec::new(),
        redact_envs: Vec::new(),
        live_mode: false,
    };
    harness::build_run_with_target_override(&opts, target_ov)
}

struct PdRun {
    run: PathBuf,
    blind: PathBuf,
    tpid: i32,
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn run_pd(
    work_root: &Path,
    tag: &str,
    prof: &Profile,
    ctrl: Control,
    level: u8,
    decoys: usize,
    seed: u64,
    hns: &[HardNeg],
    ov: Option<&Profile>,
) -> Result<PdRun, String> {
    let run = work_root.join(cat2(tag, "-run"));
    let blind = work_root.join(cat2(tag, "-blind"));
    let rr = build_case(prof, ctrl, level, decoys, seed, hns, &run, Some(&blind), ov)?;
    Ok(PdRun {
        run,
        blind,
        tpid: rr.target_pids.first().copied().unwrap_or(0),
    })
}

struct PdResult {
    id: &'static str,
    name: &'static str,
    passing_ok: bool,
    refusal_ok: bool,
    passing_detail: String,
    refusal_detail: String,
}

impl PdResult {
    fn ok(&self) -> bool {
        self.passing_ok && self.refusal_ok
    }

    fn write_entry(&self, w: &mut Jw, mode: u8) {
        w.elem_obj();
        w.k_strs("id,name", &[self.id, self.name]);
        match mode {
            0 => {
                w.k_bool("passing_ok", self.passing_ok);
                w.k_str("detail", &self.passing_detail);
            }
            1 => {
                w.k_bool("refusal_ok", self.refusal_ok);
                w.k_str("detail", &self.refusal_detail);
            }
            _ => {
                w.k_bool("ok", self.ok());
                w.k_bool("passing_ok", self.passing_ok);
                w.k_bool("refusal_ok", self.refusal_ok);
                w.k_strs(
                    "passing_detail,refusal_detail",
                    &[&self.passing_detail, &self.refusal_detail],
                );
            }
        }
        w.obj_close();
    }
}

fn bstr(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

#[inline(never)]
fn verify_flags(run: &Path, blind: Option<&Path>, sec: &[&str]) -> Result<u8, String> {
    let v = match blind {
        Some(b) => score::verify_run_with_blind(run, None, Some(b), sec)?,
        None => score::verify_run(run, None, sec)?,
    };
    Ok(u8::from(v.ok)
        | (u8::from(v.target_presence_ok) << 1)
        | (u8::from(v.has_secret_leaks) << 2)
        | (u8::from(v.blind_dir_ok) << 3)
        | (u8::from(v.failures.is_empty()) << 4))
}

#[inline(never)]
fn score_pick_doc(run_dir: &Path, pick: &Pick, name: &str) -> Result<Json, String> {
    let pp = run_dir.join(name);
    write_file(&pp, pick.to_json_str().as_bytes())?;
    json::parse(&score::score_runs(&[(run_dir.to_path_buf(), pp)])?)
}

#[inline(never)]
fn obs_ctrl_ok(
    r: &PdRun,
    phase: &str,
    defect: ObserverDefect,
    ctrl: &str,
    name: &str,
) -> Result<(PickChoice, bool), String> {
    let pick = observe_with_defect(&r.blind, phase, defect)?;
    let sc = score_pick_doc(&r.run, &pick, name)?;
    let ok = sc
        .get("controls")
        .and_then(|c| c.get(ctrl))
        .and_then(|c| c.get_bool("ok"))
        .unwrap_or(false);
    Ok((pick.pick, ok))
}

#[inline(never)]
fn score_pop(run_dir: &Path, pick: &Pick, name: &str, default: i64) -> Result<i64, String> {
    let sc = score_pick_doc(run_dir, pick, name)?;
    Ok(sc.get_i64("psgen_population_score").unwrap_or(default))
}

#[inline(never)]
fn obs_pop(r: &PdRun, name: &str, default: i64) -> Result<(PickChoice, i64), String> {
    let pick = reference_observe(&r.blind, "deep")?;
    let sc = score_pop(&r.run, &pick, name, default)?;
    Ok((pick.pick, sc))
}

#[inline(never)]
fn answer_diff_len(run_dir: &Path) -> Result<Option<usize>, String> {
    let ans = json::parse(&read_str_in(run_dir, "answer.json")?)?;
    Ok(ans
        .get("differing_surfaces")
        .and_then(|d| d.get_arr("target_vs_decoys"))
        .map(<[Json]>::len))
}

fn pd_item(
    id: &'static str,
    name: &'static str,
    passing_ok: bool,
    refusal_ok: bool,
    passing_detail: String,
    refusal_detail: String,
) -> PdResult {
    PdResult {
        id,
        name,
        passing_ok,
        refusal_ok,
        passing_detail,
        refusal_detail,
    }
}

struct PdCtrlSpec {
    tag: &'static str,
    id: &'static str,
    name: &'static str,
    ctrl: Control,
    level: u8,
    decoys: usize,
    seed: u64,
    phase: &'static str,
    bad_defect: ObserverDefect,
    check_isolated: bool,
}

#[inline(never)]
fn pd_ctrl_case(
    work_root: &Path,
    base_prof: &Profile,
    spec: &PdCtrlSpec,
) -> Result<PdResult, String> {
    let r = run_pd(
        work_root,
        spec.tag,
        base_prof,
        spec.ctrl,
        spec.level,
        spec.decoys,
        spec.seed,
        &[],
        None,
    )?;
    let isolated = !spec.check_isolated
        || !["answer.json", "population.json", "profile.json"]
            .iter()
            .any(|f| r.blind.join(f).exists());
    let (good_pick, good_ok) = obs_ctrl_ok(
        &r,
        spec.phase,
        ObserverDefect::None,
        spec.ctrl.id(),
        "pick-good.json",
    )?;
    let (_, bad_ok) = obs_ctrl_ok(
        &r,
        spec.phase,
        spec.bad_defect,
        spec.ctrl.id(),
        "pick-bad.json",
    )?;
    let pick_ok = if r.tpid > 0 {
        good_pick == PickChoice::Pid(r.tpid)
    } else {
        good_pick == PickChoice::Absent
    };
    Ok(pd_item(
        spec.id,
        spec.name,
        isolated && good_ok && pick_ok,
        !bad_ok,
        own(bstr(isolated && good_ok)),
        own(bstr(bad_ok)),
    ))
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn pd_deep_surface_case(
    work_root: &Path,
    base_prof: &Profile,
    tag: &str,
    id: &'static str,
    name: &'static str,
    seed: u64,
    surface: &str,
    bad_defect: ObserverDefect,
    hns: &[HardNeg],
    target_ov: Option<&Profile>,
) -> Result<PdResult, String> {
    let r = run_pd(
        work_root,
        tag,
        base_prof,
        Control::C06Main,
        5,
        12,
        seed,
        hns,
        target_ov,
    )?;
    let expected_pid = if hns.is_empty() {
        r.tpid
    } else {
        let ans = json::parse(&read_str_in(&r.run, "answer.json")?)?;
        ans.req_arr("hard_negatives")?
            .first()
            .and_then(|v| v.get_i64("pid"))
            .ok_or("missing hn pid")? as i32
    };
    let good = reference_observe(&r.blind, "deep")?;
    let bad_pick = observe_with_defect(&r.blind, "deep", bad_defect)?.pick;
    Ok(pd_item(
        id,
        name,
        good.pick == PickChoice::Pid(expected_pid) && good.reason_surface == surface,
        bad_pick != PickChoice::Pid(expected_pid),
        good.reason_surface,
        own(bstr(bad_pick != PickChoice::Pid(expected_pid))),
    ))
}

#[inline(never)]
fn pd05_case(work_root: &Path, base_prof: &Profile) -> Result<PdResult, String> {
    let (c07_pick, c07_ok) = {
        let c07 = run_pd(
            work_root,
            "pd05-c07",
            base_prof,
            Control::C07HiddenByMask,
            5,
            10,
            1005,
            &[],
            None,
        )?;
        let pick = reference_observe(&c07.blind, "deep")?;
        let ok = (verify_flags(&c07.run, None, &[])? & 1) != 0;
        (pick, ok)
    };
    let ref_ok = {
        let bad = run_pd(
            work_root,
            "pd05-tampered",
            base_prof,
            Control::C06Main,
            5,
            10,
            1005,
            &[],
            None,
        )?;
        let tpid_s = i64_str(bad.tpid as i64);
        let tbl_path = bad.run.join("blind-table.txt");
        let orig = read_str(&tbl_path)?;
        let mut stripped = String::with_capacity(orig.len());
        for l in orig.lines() {
            if l.split_ascii_whitespace().next() != Some(tpid_s.as_str()) {
                stripped.push_str(l);
                stripped.push('\n');
            }
        }
        write_file(&tbl_path, stripped.as_bytes())?;
        (verify_flags(&bad.run, None, &[])? & 3) == 0
            && score_pick_doc(&bad.run, &c07_pick, "pick.json").is_err()
    };
    Ok(pd_item(
        "PD-05",
        "Missing target PID guard (LDKit regression)",
        c07_pick.pick == PickChoice::Absent && c07_ok,
        ref_ok,
        own(bstr(c07_ok)),
        own(bstr(ref_ok)),
    ))
}

#[inline(never)]
fn pd06_case(work_root: &Path, base_prof: &Profile) -> Result<PdResult, String> {
    const PLANTED_SECRET: &str = "ghp_PlantedTestSecretToken0123456789abcd";
    let prof_rejected = {
        let mut leaky = base_prof.clone();
        leaky.environ.push(cat2("APP_TOKEN=", PLANTED_SECRET));
        leaky.validate(&[PLANTED_SECRET]).is_err() && leaky.validate(&[]).is_err()
    };

    let r = run_pd(
        work_root,
        "pd06",
        base_prof,
        Control::C06Main,
        5,
        10,
        1006,
        &[],
        None,
    )?;
    let env_path = r
        .run
        .join("deep")
        .join(i64_str(r.tpid as i64))
        .join("environ");
    let body = json::concat(&[&read_str(&env_path)?, "APP_TOKEN=", PLANTED_SECRET, "\n"]);
    write_file(&env_path, body.as_bytes())?;

    let obs = reference_observe(&r.run, "deep")?;
    let vf = verify_flags(&r.run, None, &[PLANTED_SECRET])?;
    let ref_ok = prof_rejected && (vf & 1) == 0 && (vf & 4) != 0;
    Ok(pd_item(
        "PD-06",
        "Planted secret in environ hygiene & scan guard",
        obs.pick == PickChoice::Pid(r.tpid) && obs.reason_surface == "environ",
        ref_ok,
        obs.reason_surface,
        own(bstr(ref_ok)),
    ))
}

#[inline(never)]
fn pd07_case(work_root: &Path, base_prof: &Profile) -> Result<PdResult, String> {
    let r = run_pd(
        work_root,
        "pd07",
        base_prof,
        Control::C06Main,
        6,
        10,
        1007,
        &[],
        None,
    )?;
    let vc = verify_flags(&r.run, Some(&r.blind), &[])?;
    let clean_ok = (vc & 0b11001) == 0b11001;

    write_file(&r.blind.join("answer.json"), b"{\"leaked\":true}\n")?;
    write_file(&r.blind.join("decoys.pid"), b"12345\n")?;
    let vd = verify_flags(&r.run, Some(&r.blind), &[])?;
    let dirty_refused = (vd & 0b11001) == 0;
    Ok(pd_item(
        "PD-07",
        "Blind-dir isolation & contamination fail-closed guard",
        clean_ok,
        dirty_refused,
        own(bstr(clean_ok)),
        own(bstr(dirty_refused)),
    ))
}

fn set_pd08_attrs(p: &mut Profile, dumpable: bool, ppid: i32, sec: u32) {
    p.dumpable = Some(dumpable);
    p.identity.ppid = ppid;
    p.status.ppid = ppid;
    p.stat.ppid = ppid;
    p.status.no_new_privs = u32::from(sec > 0);
    p.status.seccomp = sec;
    p.status.seccomp_filters = sec;
}

#[inline(never)]
fn pd08_case(work_root: &Path, base_prof: &Profile) -> Result<PdResult, String> {
    let mut target_prof = base_prof.clone();
    set_pd08_attrs(&mut target_prof, true, 4242, 0);

    let (passing_ok, ok_score) = {
        let ok_r = run_pd(
            work_root,
            "pd08-clean",
            &target_prof,
            Control::C06Main,
            6,
            10,
            1008,
            &[],
            None,
        )?;
        let (ok_pick, ok_score) = obs_pop(&ok_r, "pick-clean.json", 0)?;
        (
            answer_diff_len(&ok_r.run)? == Some(0)
                && ok_pick == PickChoice::Absent
                && ok_score >= 9,
            ok_score,
        )
    };

    let mut bad_decoy = target_prof.clone();
    set_pd08_attrs(&mut bad_decoy, false, 1, 2);
    let bad_r = run_pd(
        work_root,
        "pd08-defect",
        &bad_decoy,
        Control::C06Main,
        6,
        10,
        1008,
        &[],
        Some(&target_prof),
    )?;
    let (bad_pick, caught_score) = obs_pop(&bad_r, "pick-caught.json", 10)?;
    let abs_pick = make_pick(
        "deep",
        ObserverDefect::None,
        PickChoice::Absent,
        "absent",
        "forced",
    );
    let diff_cap = score_pop(&bad_r.run, &abs_pick, "pick-absent.json", 10)?;
    let refusal_ok = answer_diff_len(&bad_r.run)?.unwrap_or(0) >= 2
        && bad_pick == PickChoice::Pid(bad_r.tpid)
        && caught_score <= 2
        && diff_cap <= 7;
    Ok(pd_item(
        "PD-08",
        "Opacity/seccomp inversion & flat-PPid decoy defect guard",
        passing_ok,
        refusal_ok,
        cat2("score=", &i64_str(ok_score)),
        cat2("caught=", &i64_str(caught_score)),
    ))
}

fn pd03_case(work_root: &Path, base_prof: &Profile) -> Result<PdResult, String> {
    let mut target_exe = base_prof.clone();
    json::assign_str(
        &mut target_exe.identity.exe,
        "/opt/planted/unique-target-exe",
    );
    pd_deep_surface_case(
        work_root,
        base_prof,
        "pd03",
        "PD-03",
        "Unique exe deep-phase detection",
        1003,
        "exe",
        ObserverDefect::IgnoreExe,
        &[],
        Some(&target_exe),
    )
}

fn pd04_case(work_root: &Path, base_prof: &Profile) -> Result<PdResult, String> {
    pd_deep_surface_case(
        work_root,
        base_prof,
        "pd04",
        "PD-04",
        "Unique maps decoy (HN-05) deep-phase detection",
        1004,
        "maps",
        ObserverDefect::IgnoreMaps,
        &[HardNeg::Hn05Maps],
        None,
    )
}

#[inline(never)]
fn run_pd_suite(work_root: &Path) -> Result<Vec<PdResult>, String> {
    const CTRL_SPECS: &[PdCtrlSpec] = &[
        PdCtrlSpec {
            tag: "pd01",
            id: "PD-01",
            name: "C-01 obvious target detection",
            ctrl: Control::C01Obvious,
            level: 1,
            decoys: 10,
            seed: 1001,
            phase: "table",
            bad_defect: ObserverDefect::AlwaysAbsent,
            check_isolated: true,
        },
        PdCtrlSpec {
            tag: "pd02",
            id: "PD-02",
            name: "C-04 no-target false-positive guard",
            ctrl: Control::C04NoTarget,
            level: 5,
            decoys: 15,
            seed: 1002,
            phase: "deep",
            bad_defect: ObserverDefect::AlwaysPickFirst,
            check_isolated: false,
        },
    ];
    type PdFn = fn(&Path, &Profile) -> Result<PdResult, String>;
    const EXTRA_FNS: &[PdFn] = &[
        pd03_case, pd04_case, pd05_case, pd06_case, pd07_case, pd08_case,
    ];
    let base_prof = clean_profile("ci-runner", false);
    let mut out = Vec::with_capacity(8);
    for spec in CTRL_SPECS {
        out.push(pd_ctrl_case(work_root, &base_prof, spec)?);
    }
    for &f in EXTRA_FNS {
        out.push(f(work_root, &base_prof)?);
    }
    Ok(out)
}

struct DiscReport {
    runs_per_tier: usize,
    survived_9of10: usize,
    survived_7of10: usize,
    survival_9of10: f64,
    survival_7of10: f64,
    ci_9of10: (f64, f64),
    ci_7of10: (f64, f64),
    ok: bool,
}

fn disc_dir_name(prefix: &str, tree: bool, decoys: usize, seed: u64) -> String {
    let mut s = String::with_capacity(32);
    s.push_str(prefix);
    s.push(if tree { '1' } else { '0' });
    s.push('-');
    json::push_u64(&mut s, decoys as u64);
    s.push('-');
    json::push_u64(&mut s, seed);
    s
}

fn run_disc_trial(
    work_root: &Path,
    tag: &str,
    base_prof: &Profile,
    decoys: usize,
    seed: u64,
    target_ov: Option<&Profile>,
) -> Result<bool, String> {
    let dir = work_root.join(tag);
    let rr = build_case(
        base_prof,
        Control::C06Main,
        5,
        decoys,
        seed,
        &[],
        &dir,
        None,
        target_ov,
    )?;
    let pick = reference_observe(&dir, "deep")?;
    let survived = !matches!(pick.pick, PickChoice::Pid(p) if rr.target_pids.contains(&p));
    let _ = fs::remove_dir_all(&dir);
    Ok(survived)
}

#[inline(never)]
fn run_discrimination_matrix(work_root: &Path) -> Result<DiscReport, String> {
    const SEEDS: &[u64] = &[101, 202, 303];
    const DECOY_COUNTS: &[usize] = &[10, 50, 200];

    let mut total = 0usize;
    let mut survived_9 = 0usize;
    let mut survived_7 = 0usize;
    let mut variant = 0usize;

    for tree in [false, true] {
        let base_prof = clean_profile("ci-runner", tree);
        for &decoys in DECOY_COUNTS {
            for &seed in SEEDS {
                total += 1;
                if run_disc_trial(
                    work_root,
                    &disc_dir_name("d9-", tree, decoys, seed),
                    &base_prof,
                    decoys,
                    seed,
                    None,
                )? {
                    survived_9 += 1;
                }
                let weak = make_7of10_leaking_target(&base_prof, variant);
                variant += 1;
                if run_disc_trial(
                    work_root,
                    &disc_dir_name("d7-", tree, decoys, seed),
                    &base_prof,
                    decoys,
                    seed,
                    Some(&weak),
                )? {
                    survived_7 += 1;
                }
            }
        }
    }

    let s9 = if total > 0 {
        survived_9 as f64 / total as f64
    } else {
        0.0
    };
    let s7 = if total > 0 {
        survived_7 as f64 / total as f64
    } else {
        0.0
    };
    Ok(DiscReport {
        runs_per_tier: total,
        survived_9of10: survived_9,
        survived_7of10: survived_7,
        survival_9of10: s9,
        survival_7of10: s7,
        ci_9of10: score::wilson_ci_95(survived_9, total),
        ci_7of10: score::wilson_ci_95(survived_7, total),
        ok: s9 >= 0.90 && s7 <= 0.50,
    })
}

#[inline(never)]
fn write_selftest_doc(
    w: &mut Jw,
    ok: bool,
    arr_key: &str,
    pds: &[PdResult],
    mode: u8,
    disc: Option<&DiscReport>,
) {
    w.reset(true);
    w.obj_open();
    w.k_i64("schema", SELFTEST_SCHEMA as i64);
    w.k_bool("ok", ok);
    w.k_arr(arr_key);
    for p in pds {
        p.write_entry(w, mode);
    }
    w.arr_close();
    if let Some(d) = disc {
        w.k_obj("discrimination");
        w.k_bool("ok", d.ok);
        w.k_i64("runs_per_tier", d.runs_per_tier as i64);
        w.k_str(
            "matrix",
            "3 seeds x 3 decoy counts (10,50,200) x 2 profiles (single,tree)",
        );
        w.k_i64s(
            "survived_9of10,survived_7of10",
            &[d.survived_9of10 as i64, d.survived_7of10 as i64],
        );
        w.k_f64s_r6(
            "survival_9of10,survival_7of10",
            &[d.survival_9of10, d.survival_7of10],
        );
        w.k_f64_pair_r6("ci_95_9of10", d.ci_9of10);
        w.k_f64_pair_r6("ci_95_7of10", d.ci_7of10);
        w.k_f64("threshold_9of10_min", 0.90);
        w.k_f64("threshold_7of10_max", 0.50);
        w.obj_close();
        w.k_strs(
            "observer,residual",
            &["reference-blind-v1", DEFAULT_RESIDUAL],
        );
    }
    w.obj_close();
}

/// Run the complete 9/10 planted-defect (`PD-01`..`PD-08`) and discrimination
/// acceptance suite (`psgen selftest`), returning `(ok, pretty_json)`.
#[inline(never)]
pub fn run_selftest(out_dir: Option<&Path>) -> Result<(bool, String), String> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let scratch: PathBuf = std::env::temp_dir().join(json::concat(&[
        "psgen-selftest-",
        &u64_str(std::process::id() as u64),
        "-",
        &u64_str(seq),
    ]));
    let _ = fs::remove_dir_all(&scratch);
    mkdir_all(&scratch)?;

    let pd_res = run_pd_suite(&scratch);
    let disc_res = run_discrimination_matrix(&scratch);
    let _ = fs::remove_dir_all(&scratch);

    let pds = pd_res?;
    let disc = disc_res?;

    let all_pd_ok = pds.iter().all(PdResult::ok);
    let overall_ok = all_pd_ok && disc.ok;

    let mut w = Jw::new(true);
    if let Some(dir) = out_dir {
        mkdir_all(dir)?;
        write_selftest_doc(&mut w, overall_ok, "guards", &pds, 0, Some(&disc));
        w.write_to(&dir.join("passing.json"))?;
        write_selftest_doc(&mut w, all_pd_ok, "planted_defects", &pds, 1, None);
        w.write_to(&dir.join("planted-defects.json"))?;
    }

    write_selftest_doc(&mut w, overall_ok, "planted_defects", &pds, 2, Some(&disc));
    let report = w.finish();

    if !overall_ok {
        return Err(cat2("selftest failed: ", &report));
    }
    Ok((overall_ok, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("psgen-selftest-ut-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create test dir");
        p
    }

    #[test]
    fn reference_observer_handles_c03_exact_clone_and_c05_target_only() {
        let base = test_dir("obs-controls");
        let prof = clean_profile("ci-runner", true);

        let d3 = base.join("c03");
        let b3 = base.join("c03-blind");
        build_case(
            &prof,
            Control::C03ExactClone,
            5,
            0,
            77,
            &[],
            &d3,
            Some(&b3),
            None,
        )
        .unwrap();
        assert_eq!(
            reference_observe(&b3, "deep").unwrap().pick,
            PickChoice::Ambiguous
        );

        let d5 = base.join("c05");
        let b5 = base.join("c05-blind");
        let r5 = build_case(
            &prof,
            Control::C05TargetOnly,
            5,
            0,
            78,
            &[],
            &d5,
            Some(&b5),
            None,
        )
        .unwrap();
        assert_eq!(
            reference_observe(&b5, "table").unwrap().pick,
            PickChoice::Pid(r5.target_pids[0])
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn reference_observer_isolates_every_single_hard_negative() {
        let base = test_dir("obs-hns");
        let prof = clean_profile("ci-runner", false);

        for &hn in HardNeg::all() {
            let d = base.join(hn.id());
            let b = base.join(format!("{}-blind", hn.id()));
            build_case(
                &prof,
                Control::C06Main,
                5,
                10,
                555,
                &[hn],
                &d,
                Some(&b),
                None,
            )
            .unwrap();
            let ans = json::parse(&fs::read_to_string(d.join("answer.json")).unwrap()).unwrap();
            let hn_pid = ans.req_arr("hard_negatives").unwrap()[0]
                .req_i64("pid")
                .unwrap() as i32;
            let pick = reference_observe(&b, "deep").unwrap();
            assert_eq!(
                pick.pick,
                PickChoice::Pid(hn_pid),
                "{} should be isolated, got {:?}",
                hn.id(),
                pick
            );
            assert_eq!(pick.reason_surface, hn.surface());
        }

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn full_selftest_passes_all_guards_and_discrimination_matrix() {
        let out = test_dir("full-suite");
        let (ok, report_s) = run_selftest(Some(&out)).expect("selftest should pass");
        assert!(ok);
        let report = json::parse(&report_s).unwrap();
        assert!(report.req_bool("ok").unwrap());
        assert!(out.join("passing.json").is_file());
        assert!(out.join("planted-defects.json").is_file());

        let disc = report.get("discrimination").unwrap();
        assert!(disc.req_f64("survival_9of10").unwrap() >= 0.90);
        assert!(disc.req_f64("survival_7of10").unwrap() <= 0.50);
        assert_eq!(disc.req_i64("runs_per_tier").unwrap(), 18);

        let pds = report.req_arr("planted_defects").unwrap();
        assert_eq!(pds.len(), 8);
        for pd in pds {
            assert!(pd.req_bool("ok").unwrap(), "guard failed: {pd}");
            assert!(pd.req_bool("passing_ok").unwrap());
            assert!(pd.req_bool("refusal_ok").unwrap());
        }

        let _ = fs::remove_dir_all(&out);
    }
}
