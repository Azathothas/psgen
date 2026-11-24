//! Built-in reference blind observer, 6 planted-defect guards (`PD-01`..`PD-06`
//! with both passing and refusal verification), and the 9/10 vs 7/10
//! discrimination acceptance suite (`psgen selftest`).

use crate::harness::{self, Control, HardNeg, Mode, RunOpts, TableRow, DEFAULT_RESIDUAL};
use crate::json::{
    self, cat2, cat3, i64_str, mkdir_all, read_str, read_str_in, sort_strings, u64_str, write_file,
    Json, Jw,
};
use crate::profile::{self, Profile};
use crate::score::{self, Pick, PickChoice, PICK_SCHEMA};
use std::fs;
use std::path::{Path, PathBuf};

pub const SELFTEST_SCHEMA: u32 = 1;

const OBS_SURFACES_CSV: &str =
    "comm,cmdline,ppid,exe,memory,maps,environ,fd,status,syscall,threads";

fn obs_surface_name(idx: usize) -> &'static str {
    OBS_SURFACES_CSV.split(',').nth(idx).unwrap_or("")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObserverDefect {
    None,
    AlwaysAbsent,
    AlwaysPickFirst,
    IgnoreExe,
    IgnoreMaps,
}

struct ObservedProc {
    row: TableRow,
    is_child: bool,
    surfaces: [String; 11],
    surf_mask: u16,
    starttime: Option<u64>,
    leaked_secret_env: bool,
}

impl ObservedProc {
    fn set_surf(&mut self, i: usize, val: String) {
        self.surfaces[i] = val;
        self.surf_mask |= 1 << i;
    }

    fn surf(&self, i: usize) -> Option<&str> {
        if (self.surf_mask & (1 << i)) != 0 {
            Some(self.surfaces[i].as_str())
        } else {
            None
        }
    }
}

fn parse_stat_starttime(stat_text: &str) -> Option<u64> {
    let close = stat_text.rfind(')')?;
    stat_text[close + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .and_then(json::parse_u64_s)
}

fn parse_status_sig(status_text: &str) -> String {
    let mut nnp = "0";
    let mut sec = "0";
    let mut sf = "0";
    let mut traced = false;
    let mut cap_eff = "";
    let mut cap_prm = "";
    let mut cap_bnd = "";
    for line in status_text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k {
            "NoNewPrivs" => nnp = v,
            "Seccomp" => sec = v,
            "Seccomp_filters" => sf = v,
            "TracerPid" => traced = v != "0" && !v.is_empty(),
            "CapEff" => cap_eff = v,
            "CapPrm" => cap_prm = v,
            "CapBnd" => cap_bnd = v,
            _ => {}
        }
    }
    harness::format_status_sig(nnp, sec, sf, traced, cap_eff, cap_prm, cap_bnd)
}

fn parse_mem_scan_sig(mem_text: &str) -> String {
    let Ok(doc) = json::parse(mem_text) else {
        return mem_text.trim().to_string();
    };
    if !doc.get("readable").and_then(Json::as_bool).unwrap_or(false) {
        let err = doc.get("error").and_then(Json::as_str).unwrap_or("EACCES");
        return cat2("readable=false|err=", err);
    }
    let tp = doc
        .get("token_present")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    cat2("readable=true|token=", if tp { "true" } else { "false" })
}

fn parse_fd_sig(fd_text: &str) -> String {
    let Ok(doc) = json::parse(fd_text) else {
        return fd_text.trim().to_string();
    };
    if let Some(err) = doc.get("error").and_then(Json::as_str) {
        return cat2("err=", err);
    }
    let Some(arr) = doc.as_arr() else {
        return fd_text.trim().to_string();
    };
    let mut items = Vec::with_capacity(arr.len());
    for item in arr {
        if let (Some(fd), Some(t)) = (
            item.get("fd").and_then(Json::as_i64),
            item.get("target").and_then(Json::as_str),
        ) {
            items.push(cat3(&i64_str(fd), ":", &harness::normalize_fd_target(t)));
        }
    }
    sort_strings(&mut items);
    items.join("|")
}

fn parse_task_sig(task_text: &str) -> String {
    let Ok(doc) = json::parse(task_text) else {
        return task_text.trim().to_string();
    };
    let Some(arr) = doc.as_arr() else {
        return task_text.trim().to_string();
    };
    let mut comms = Vec::with_capacity(arr.len());
    for item in arr {
        if let Some(c) = item.get("comm").and_then(Json::as_str) {
            comms.push(c.to_string());
        }
    }
    sort_strings(&mut comms);
    cat3(&u64_str(arr.len() as u64), "|", &comms.join(","))
}

fn full_fingerprint(p: &ObservedProc, all: &[ObservedProc]) -> String {
    let mut out = String::new();
    out.push_str("user=");
    out.push_str(&p.row.user);
    out.push('\n');
    for i in 0..11 {
        if let Some(v) = p.surf(i) {
            out.push_str(obs_surface_name(i));
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
        if c.is_child && c.row.ppid == p.row.pid {
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
    for i in 1..vals.len() {
        let mut j = i;
        while j > 0 && vals[j - 1] > vals[j] {
            vals.swap(j - 1, j);
            j -= 1;
        }
    }
    vals[vals.len() / 2]
}

fn find_cohort_anomaly(
    cohort: &[&ObservedProc],
    deep_enabled: bool,
    defect: ObserverDefect,
) -> Option<(i32, &'static str, String)> {
    if cohort.len() < 3 {
        return None;
    }
    let limit = if deep_enabled { 11 } else { 3 };
    for (si, surf) in OBS_SURFACES_CSV.split(',').enumerate().take(limit) {
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
                    return Some((p.row.pid, surf, cat3("unique '", surf, "' signature")));
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
            let mut devs = Vec::with_capacity(sts.len());
            for &s in &sts {
                devs.push(s.abs_diff(med));
            }
            let mad = median_u64(&mut devs);
            let thresh = 50_000u64.max(mad.saturating_mul(10));
            let mut best: Option<(i32, u64)> = None;
            for p in cohort {
                if let Some(st) = p.starttime {
                    let d = st.abs_diff(med);
                    if d > thresh && best.map(|(_, bd)| d > bd).unwrap_or(true) {
                        best = Some((p.row.pid, d));
                    }
                }
            }
            if let Some((pid, delta)) = best {
                return Some((
                    pid,
                    "starttime",
                    cat3("starttime outlier (delta=", &u64_str(delta), ")"),
                ));
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
        phase: phase_norm.to_string(),
        pick: choice,
        reason_surface: surface.to_string(),
        reason: reason.to_string(),
        elapsed_sec: Some(0.05),
        evaluator: Some(
            match defect {
                ObserverDefect::None => "reference-blind-v1",
                ObserverDefect::AlwaysAbsent => "defect-always-absent",
                ObserverDefect::AlwaysPickFirst => "defect-always-pick-first",
                ObserverDefect::IgnoreExe => "defect-ignore-exe",
                ObserverDefect::IgnoreMaps => "defect-ignore-maps",
            }
            .to_string(),
        ),
    }
}

fn read_deep_surfaces(pdir: &Path, defect: ObserverDefect, op: &mut ObservedProc) {
    let ro = |name: &str| read_str_in(pdir, name).ok();
    if defect != ObserverDefect::IgnoreExe {
        if let Some(s) = ro("exe") {
            op.set_surf(3, s.trim().to_string());
        }
    }
    if let Some(s) = ro("mem_scan.json") {
        op.set_surf(4, parse_mem_scan_sig(&s));
    }
    if defect != ObserverDefect::IgnoreMaps {
        if let Some(s) = ro("maps") {
            op.set_surf(5, s.trim().to_string());
        }
    }
    if let Some(env_text) = ro("environ") {
        if profile::has_unredacted_secret_in_environ(&env_text) {
            op.leaked_secret_env = true;
        }
        let mut lines = Vec::new();
        for part in env_text.split(['\n', '\0']) {
            let t = part.trim();
            if !t.is_empty() {
                lines.push(t.to_string());
            }
        }
        sort_strings(&mut lines);
        op.set_surf(6, lines.join("\n"));
    }
    if let Some(s) = ro("fd.json") {
        op.set_surf(7, parse_fd_sig(&s));
    }
    if let Some(s) = ro("status") {
        op.set_surf(8, parse_status_sig(&s));
    }
    if let (Some(sc), Some(wc)) = (ro("syscall"), ro("wchan")) {
        op.set_surf(9, cat3(sc.trim(), "|", wc.trim()));
    }
    if let Some(s) = ro("task.json") {
        op.set_surf(10, parse_task_sig(&s));
    }
    if let Some(s) = ro("stat") {
        op.starttime = parse_stat_starttime(&s);
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
        return Err(cat3("invalid phase '", pt, "'"));
    };

    let table_text = read_str_in(blind_dir, "blind-table.txt")?;
    let rows = harness::parse_blind_table(&table_text)?;

    if defect == ObserverDefect::AlwaysAbsent || rows.is_empty() {
        return Ok(make_pick(
            phase_norm,
            defect,
            PickChoice::Absent,
            "absent",
            if rows.is_empty() {
                "empty table"
            } else {
                "planted defect: always absent"
            },
        ));
    }
    if defect == ObserverDefect::AlwaysPickFirst {
        return Ok(make_pick(
            phase_norm,
            defect,
            PickChoice::Pid(rows[0].pid),
            "comm",
            "planted defect: pick first",
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
        let pid = row.pid;
        let ppid = row.ppid;
        let comm = row.comm.clone();
        let args = row.args.clone();
        let mut op = ObservedProc {
            row,
            is_child,
            surfaces: Default::default(),
            surf_mask: 0,
            starttime: None,
            leaked_secret_env: false,
        };
        op.set_surf(0, comm);
        op.set_surf(1, args);
        op.set_surf(
            2,
            if is_child {
                cat2("cluster-parent|has_child=", hc)
            } else {
                cat3(&i64_str(ppid as i64), "|has_child=", hc)
            },
        );

        if deep_enabled {
            let pdir = deep_root.join(i64_str(pid as i64));
            read_deep_surfaces(&pdir, defect, &mut op);
        }
        observed.push(op);
    }

    if let Some(leaker) = observed.iter().find(|p| p.leaked_secret_env) {
        return Ok(make_pick(
            phase_norm,
            defect,
            PickChoice::Pid(leaker.row.pid),
            "environ",
            "unredacted secret detected in environ",
        ));
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

    if roots.len() == 1 {
        return Ok(make_pick(
            phase_norm,
            defect,
            PickChoice::Pid(roots[0].row.pid),
            "comm",
            "sole root process in table",
        ));
    }
    if roots.len() == 2 {
        let msg = if full_fingerprint(roots[0], &observed) == full_fingerprint(roots[1], &observed)
        {
            "exact clone tie across all surfaces"
        } else {
            "two candidates without majority baseline"
        };
        return Ok(make_pick(
            phase_norm,
            defect,
            PickChoice::Ambiguous,
            "ambiguous",
            msg,
        ));
    }

    for cohort in [roots.as_slice(), children.as_slice()] {
        if let Some((pid, surf, reason)) = find_cohort_anomaly(cohort, deep_enabled, defect) {
            return Ok(make_pick(
                phase_norm,
                defect,
                PickChoice::Pid(pid),
                surf,
                &reason,
            ));
        }
    }

    Ok(make_pick(
        phase_norm,
        defect,
        PickChoice::Absent,
        "absent",
        "no anomalous surface detected",
    ))
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
        "PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
        "HOME=/srv/ci".to_string(),
        "LANG=C.UTF-8".to_string(),
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
            weak.identity.exe = leak_exe.to_string();
            weak.auxv.at_execfn = Some(leak_exe.to_string());
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
            weak.memory
                .maps
                .push("<addr> r-xp 00000000 08:01 4242 /usr/lib/libweakmask.so".to_string());
            weak.memory.smaps.push(
                "r-xp /usr/lib/libweakmask.so Rss:128kB Private_Dirty:0kB Anonymous:0kB"
                    .to_string(),
            );
        }
        2 => weak.environ.push("WEAK_MASKER_ACTIVE=1".to_string()),
        _ => {
            weak.identity.comm = "python3".to_string();
            weak.status.name = "python3".to_string();
            if let Some(t) = weak.task.first_mut() {
                t.comm = "python3".to_string();
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
        decoy_token_prefix: "dtok_".to_string(),
    };
    harness::build_run_with_target_override(&opts, target_ov)
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

    fn write_full(&self, w: &mut Jw) {
        w.elem_obj();
        w.k_str("id", self.id);
        w.k_str("name", self.name);
        w.k_bool("ok", self.ok());
        w.k_bool("passing_ok", self.passing_ok);
        w.k_bool("refusal_ok", self.refusal_ok);
        w.k_str("passing_detail", &self.passing_detail);
        w.k_str("refusal_detail", &self.refusal_detail);
        w.obj_close();
    }

    fn write_guard(&self, w: &mut Jw, passing: bool) {
        w.elem_obj();
        w.k_str("id", self.id);
        w.k_str("name", self.name);
        if passing {
            w.k_bool("passing_ok", self.passing_ok);
            w.k_str("detail", &self.passing_detail);
        } else {
            w.k_bool("refusal_ok", self.refusal_ok);
            w.k_str("detail", &self.refusal_detail);
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

fn score_ctrl_ok(run_dir: &Path, pick: &Pick, ctrl: &str, name: &str) -> Result<bool, String> {
    let pp = run_dir.join(name);
    write_file(&pp, pick.to_json_str().as_bytes())?;
    let sc_s = score::score_runs(&[(run_dir.to_path_buf(), pp)])?;
    let sc = json::parse(&sc_s)?;
    Ok(sc
        .get("controls")
        .and_then(|c| c.get(ctrl))
        .and_then(|c| c.get("ok"))
        .and_then(Json::as_bool)
        .unwrap_or(false))
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

#[inline(never)]
fn pd_dirs(work_root: &Path, tag: &str) -> (PathBuf, PathBuf) {
    (
        work_root.join(cat2(tag, "-run")),
        work_root.join(cat2(tag, "-blind")),
    )
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

fn pd_ctrl_case(
    work_root: &Path,
    base_prof: &Profile,
    spec: &PdCtrlSpec,
) -> Result<PdResult, String> {
    let (run_dir, blind_dir) = pd_dirs(work_root, spec.tag);
    let rr = build_case(
        base_prof,
        spec.ctrl,
        spec.level,
        spec.decoys,
        spec.seed,
        &[],
        &run_dir,
        Some(&blind_dir),
        None,
    )?;
    let isolated = !spec.check_isolated
        || (!blind_dir.join("answer.json").exists()
            && !blind_dir.join("population.json").exists()
            && !blind_dir.join("profile.json").exists());
    let good = reference_observe(&blind_dir, spec.phase)?;
    let good_ok = score_ctrl_ok(&run_dir, &good, spec.ctrl.id(), "pick-good.json")?;
    let bad = observe_with_defect(&blind_dir, spec.phase, spec.bad_defect)?;
    let bad_ok = score_ctrl_ok(&run_dir, &bad, spec.ctrl.id(), "pick-bad.json")?;
    let pick_ok = match rr.target_pids.first() {
        Some(&tpid) => good.pick == PickChoice::Pid(tpid),
        None => good.pick == PickChoice::Absent,
    };
    Ok(pd_item(
        spec.id,
        spec.name,
        isolated && good_ok && pick_ok,
        !bad_ok,
        bstr(isolated && good_ok).to_string(),
        bstr(bad_ok).to_string(),
    ))
}

#[allow(clippy::too_many_arguments)]
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
    let (run_dir, blind_dir) = pd_dirs(work_root, tag);
    let rr = build_case(
        base_prof,
        Control::C06Main,
        5,
        12,
        seed,
        hns,
        &run_dir,
        Some(&blind_dir),
        target_ov,
    )?;
    let expected_pid = if hns.is_empty() {
        rr.target_pids[0]
    } else {
        let ans = json::parse(&read_str_in(&run_dir, "answer.json")?)?;
        ans.req_arr("hard_negatives")?[0]
            .get("pid")
            .and_then(Json::as_i64)
            .ok_or("missing hn pid")? as i32
    };
    let good = reference_observe(&blind_dir, "deep")?;
    let bad = observe_with_defect(&blind_dir, "deep", bad_defect)?;
    Ok(pd_item(
        id,
        name,
        good.pick == PickChoice::Pid(expected_pid) && good.reason_surface == surface,
        bad.pick != PickChoice::Pid(expected_pid),
        good.reason_surface,
        bstr(bad.pick != PickChoice::Pid(expected_pid)).to_string(),
    ))
}

fn pd05_case(work_root: &Path, base_prof: &Profile) -> Result<PdResult, String> {
    let (run_c07, blind_c07) = pd_dirs(work_root, "pd05-c07");
    build_case(
        base_prof,
        Control::C07HiddenByMask,
        5,
        10,
        1005,
        &[],
        &run_c07,
        Some(&blind_c07),
        None,
    )?;
    let c07_pick = reference_observe(&blind_c07, "deep")?;
    let c07_ok = score::verify_run(&run_c07, None, &[])?.ok;

    let run_bad = work_root.join("pd05-tampered");
    let rr_bad = build_case(
        base_prof,
        Control::C06Main,
        5,
        10,
        1005,
        &[],
        &run_bad,
        None,
        None,
    )?;
    let tpid_s = i64_str(rr_bad.target_pids[0] as i64);
    let tbl_path = run_bad.join("blind-table.txt");
    let orig = read_str(&tbl_path)?;
    let mut stripped = String::with_capacity(orig.len());
    for l in orig.lines() {
        if l.split_ascii_whitespace().next() != Some(tpid_s.as_str()) {
            stripped.push_str(l);
            stripped.push('\n');
        }
    }
    write_file(&tbl_path, stripped.as_bytes())?;

    let ver_bad = score::verify_run(&run_bad, None, &[])?;
    let ver_flagged = !ver_bad.ok && !ver_bad.target_presence_ok;
    let p_abs = run_bad.join("pick.json");
    write_file(&p_abs, c07_pick.to_json_str().as_bytes())?;
    let scorer_refused = score::score_runs(&[(run_bad, p_abs)]).is_err();

    Ok(pd_item(
        "PD-05",
        "Missing target PID guard (LDKit regression)",
        c07_pick.pick == PickChoice::Absent && c07_ok,
        ver_flagged && scorer_refused,
        bstr(c07_ok).to_string(),
        bstr(ver_flagged && scorer_refused).to_string(),
    ))
}

fn pd06_case(work_root: &Path, base_prof: &Profile) -> Result<PdResult, String> {
    const PLANTED_SECRET: &str = "ghp_PlantedTestSecretToken0123456789abcd";
    let mut leaky = base_prof.clone();
    leaky.environ.push(cat2("APP_TOKEN=", PLANTED_SECRET));
    let prof_rejected = leaky.validate(&[PLANTED_SECRET]).is_err() && leaky.validate(&[]).is_err();

    let run_dir = work_root.join("pd06-run");
    let rr = build_case(
        base_prof,
        Control::C06Main,
        5,
        10,
        1006,
        &[],
        &run_dir,
        None,
        None,
    )?;
    let tpid = rr.target_pids[0];
    let env_path = run_dir
        .join("deep")
        .join(i64_str(tpid as i64))
        .join("environ");
    let mut body = read_str(&env_path)?;
    body.push_str("APP_TOKEN=");
    body.push_str(PLANTED_SECRET);
    body.push('\n');
    write_file(&env_path, body.as_bytes())?;

    let obs = reference_observe(&run_dir, "deep")?;
    let ver = score::verify_run(&run_dir, None, &[PLANTED_SECRET])?;
    let ver_rejected = !ver.ok && ver.has_secret_leaks;

    Ok(pd_item(
        "PD-06",
        "Planted secret in environ hygiene & scan guard",
        obs.pick == PickChoice::Pid(tpid) && obs.reason_surface == "environ",
        prof_rejected && ver_rejected,
        obs.reason_surface,
        bstr(prof_rejected && ver_rejected).to_string(),
    ))
}

fn run_pd_suite(work_root: &Path) -> Result<Vec<PdResult>, String> {
    let base_prof = clean_profile("ci-runner", false);
    let mut target_exe = base_prof.clone();
    target_exe.identity.exe = "/opt/planted/unique-target-exe".to_string();

    Ok(vec![
        pd_ctrl_case(
            work_root,
            &base_prof,
            &PdCtrlSpec {
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
        )?,
        pd_ctrl_case(
            work_root,
            &base_prof,
            &PdCtrlSpec {
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
        )?,
        pd_deep_surface_case(
            work_root,
            &base_prof,
            "pd03",
            "PD-03",
            "Unique exe deep-phase detection",
            1003,
            "exe",
            ObserverDefect::IgnoreExe,
            &[],
            Some(&target_exe),
        )?,
        pd_deep_surface_case(
            work_root,
            &base_prof,
            "pd04",
            "PD-04",
            "Unique maps decoy (HN-05) deep-phase detection",
            1004,
            "maps",
            ObserverDefect::IgnoreMaps,
            &[HardNeg::Hn05Maps],
            None,
        )?,
        pd05_case(work_root, &base_prof)?,
        pd06_case(work_root, &base_prof)?,
    ])
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

fn write_selftest_doc(
    w: &mut Jw,
    ok: bool,
    arr_key: &str,
    pds: &[PdResult],
    mode: u8,
    disc_json: Option<&str>,
) {
    w.reset(true);
    w.obj_open();
    w.k_i64("schema", SELFTEST_SCHEMA as i64);
    w.k_bool("ok", ok);
    w.k_arr(arr_key);
    for p in pds {
        match mode {
            0 => p.write_guard(w, true),
            1 => p.write_guard(w, false),
            _ => p.write_full(w),
        }
    }
    w.arr_close();
    if let Some(dj) = disc_json {
        w.k_raw("discrimination", dj);
        w.k_str("observer", "reference-blind-v1");
        w.k_str("residual", DEFAULT_RESIDUAL);
    }
    w.obj_close();
}

/// Run the complete 9/10 planted-defect (`PD-01`..`PD-06`) and discrimination
/// acceptance suite (`psgen selftest`), returning `(ok, pretty_json)`.
///
/// When `out_dir` is `Some(dir)`, writes `passing.json` and `planted-defects.json`
/// inside `dir`. Returns `Err(...)` if any guard or discrimination assertion fails.
pub fn run_selftest(out_dir: Option<&Path>) -> Result<(bool, String), String> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let scratch_name = cat3(
        "psgen-selftest-",
        &u64_str(std::process::id() as u64),
        &cat2("-", &u64_str(seq)),
    );
    let scratch: PathBuf = std::env::temp_dir().join(scratch_name);
    let _ = fs::remove_dir_all(&scratch);
    mkdir_all(&scratch)?;

    let pd_res = run_pd_suite(&scratch);
    let disc_res = run_discrimination_matrix(&scratch);
    let _ = fs::remove_dir_all(&scratch);

    let pds = pd_res?;
    let disc = disc_res?;

    let all_pd_ok = pds.iter().all(PdResult::ok);
    let overall_ok = all_pd_ok && disc.ok;

    let mut dw = Jw::new(true);
    dw.obj_open();
    dw.k_bool("ok", disc.ok);
    dw.k_i64("runs_per_tier", disc.runs_per_tier as i64);
    dw.k_str(
        "matrix",
        "3 seeds x 3 decoy counts (10,50,200) x 2 profiles (single,tree)",
    );
    dw.k_i64("survived_9of10", disc.survived_9of10 as i64);
    dw.k_i64("survived_7of10", disc.survived_7of10 as i64);
    dw.k_f64_r6("survival_9of10", disc.survival_9of10);
    dw.k_f64_r6("survival_7of10", disc.survival_7of10);
    dw.k_f64_pair_r6("ci_95_9of10", disc.ci_9of10);
    dw.k_f64_pair_r6("ci_95_7of10", disc.ci_7of10);
    dw.k_f64("threshold_9of10_min", 0.90);
    dw.k_f64("threshold_7of10_max", 0.50);
    dw.obj_close();
    let disc_json = dw.finish();

    let mut w = Jw::new(true);
    if let Some(dir) = out_dir {
        mkdir_all(dir)?;
        write_selftest_doc(&mut w, overall_ok, "guards", &pds, 0, Some(&disc_json));
        w.write_to(&dir.join("passing.json"))?;
        write_selftest_doc(&mut w, all_pd_ok, "planted_defects", &pds, 1, None);
        w.write_to(&dir.join("planted-defects.json"))?;
    }

    write_selftest_doc(
        &mut w,
        overall_ok,
        "planted_defects",
        &pds,
        2,
        Some(&disc_json),
    );
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
        assert_eq!(pds.len(), 6);
        for pd in pds {
            assert!(pd.req_bool("ok").unwrap(), "guard failed: {pd}");
            assert!(pd.req_bool("passing_ok").unwrap());
            assert!(pd.req_bool("refusal_ok").unwrap());
        }

        let _ = fs::remove_dir_all(&out);
    }
}
