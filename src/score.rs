//! Blind evaluation scorer, Wilson 95% confidence intervals, per-surface
//! confusion matrix, multi-run aggregator, offline replay, and run verifier
//! (`psgen score`, `psgen replay`, `psgen verify`).

use crate::harness::{self, DEFAULT_RESIDUAL};
use crate::json::{self, cat2, cat3, cat4, read_str, read_str_in, JRead, Json, Jw};
use crate::profile::{self, Profile};
use crate::sha256;
use std::fs;
use std::path::{Path, PathBuf};

pub const PICK_SCHEMA: u32 = 1;
pub const SCORE_SCHEMA: u32 = 1;

const CANONICAL_CSV: &str =
    "comm,cmdline,exe,ppid,starttime,environ,memory,maps,fd,status,syscall,threads";
const ALL_REASONS_CSV: &str =
    "comm,cmdline,exe,ppid,starttime,environ,memory,maps,fd,status,syscall,threads,absent,ambiguous";
const CONTROLS_CSV: &str = "C-01,C-02,C-03,C-04,C-05,C-06,C-07";
const HNS_CSV: &str = "HN-01,HN-02,HN-03,HN-04,HN-05,HN-06,HN-07,HN-08,HN-09,HN-10";

const WILSON_Z95: f64 = 1.959_963_984_540_054;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum PickChoice {
    Pid(i32),
    Absent,
    Ambiguous,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Pick {
    pub schema: u32,
    pub phase: String,
    pub pick: PickChoice,
    pub reason_surface: String,
    pub reason: String,
    pub elapsed_sec: Option<f64>,
    pub evaluator: Option<String>,
}

impl Pick {
    pub fn parse_str(input: &str) -> Result<Pick, String> {
        let doc = json::parse(input)?;
        Pick::from_json(&doc)
    }

    #[inline(never)]
    pub fn from_json(val: &Json) -> Result<Pick, String> {
        let mut r = JRead::new(
            val,
            "schema,phase,pick,reason_surface,reason,elapsed_sec,evaluator",
            "pick",
        )?;
        let schema = r.u32("schema");
        let pt = r.str_ref("phase").trim();
        let raw_surf = r.str_ref("reason_surface").trim();
        let reason = r.str("reason");
        let elapsed_sec = r.opt_f64("elapsed_sec");
        let evaluator = r.opt_str("evaluator");
        r.check()?;

        if schema != PICK_SCHEMA {
            return Err("pick.schema: unsupported version".to_string());
        }
        let phase = if pt.eq_ignore_ascii_case("table") {
            "table"
        } else if pt.eq_ignore_ascii_case("deep") {
            "deep"
        } else {
            return Err(cat3("pick.phase: invalid '", pt, "'"));
        }
        .to_string();

        let pick = match val.get("pick") {
            Some(Json::Int(n)) if *n > 0 && *n <= i32::MAX as i64 => PickChoice::Pid(*n as i32),
            Some(Json::Str(s)) => {
                let st = s.trim();
                if st.eq_ignore_ascii_case("absent") {
                    PickChoice::Absent
                } else if st.eq_ignore_ascii_case("ambiguous") || st.eq_ignore_ascii_case("unknown")
                {
                    PickChoice::Ambiguous
                } else {
                    return Err(cat3("pick.pick: invalid '", st, "'"));
                }
            }
            None => return Err("pick: missing 'pick'".to_string()),
            _ => return Err("pick.pick: expected positive PID, 'absent', or 'ambiguous'".into()),
        };

        let Some(canon_surf) = ALL_REASONS_CSV
            .split(',')
            .find(|s| s.eq_ignore_ascii_case(raw_surf))
        else {
            return Err(cat3("pick.reason_surface: invalid '", raw_surf, "'"));
        };
        if let Some(f) = elapsed_sec {
            if f < 0.0 || !f.is_finite() {
                return Err("pick.elapsed_sec: must be >= 0".to_string());
            }
        }

        Ok(Pick {
            schema,
            phase,
            pick,
            reason_surface: canon_surf.to_string(),
            reason,
            elapsed_sec,
            evaluator,
        })
    }

    pub fn to_json_str(&self) -> String {
        let mut w = Jw::new(true);
        w.obj_open();
        w.k_i64("schema", self.schema as i64);
        w.k_str("phase", &self.phase);
        match self.pick {
            PickChoice::Pid(p) => w.k_i64("pick", p as i64),
            PickChoice::Absent => w.k_str("pick", "absent"),
            PickChoice::Ambiguous => w.k_str("pick", "ambiguous"),
        }
        w.k_str("reason_surface", &self.reason_surface);
        w.k_str("reason", &self.reason);
        match self.elapsed_sec {
            Some(f) => w.k_f64("elapsed_sec", f),
            None => w.k_null("elapsed_sec"),
        }
        w.k_opt_str("evaluator", &self.evaluator);
        w.obj_close();
        w.out.push('\n');
        w.finish()
    }
}

/// Wilson score 95% confidence interval (`[low, high]` clamped to `[0.0, 1.0]`).
pub fn wilson_ci_95(successes: usize, total: usize) -> (f64, f64) {
    if total == 0 {
        return (0.0, 0.0);
    }
    let s = successes.min(total) as f64;
    let n = total as f64;
    let p = s / n;
    let z2 = WILSON_Z95 * WILSON_Z95;
    let denom = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denom;
    let rad = (p * (1.0 - p) + z2 / (4.0 * n)) / n;
    let margin = (WILSON_Z95 / denom) * rad.max(0.0).sqrt();
    (
        (center - margin).clamp(0.0, 1.0),
        (center + margin).clamp(0.0, 1.0),
    )
}

fn median_f64(vals: &mut [f64]) -> Option<f64> {
    if vals.is_empty() {
        return None;
    }
    for i in 1..vals.len() {
        let mut j = i;
        while j > 0 && vals[j - 1].total_cmp(&vals[j]).is_gt() {
            vals.swap(j - 1, j);
            j -= 1;
        }
    }
    let mid = vals.len() / 2;
    if vals.len() % 2 == 1 {
        Some(vals[mid])
    } else {
        Some((vals[mid - 1] + vals[mid]) / 2.0)
    }
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

struct ParsedAnswer {
    control: String,
    level: u8,
    mode: String,
    observer_uid: u32,
    target_present: bool,
    target_visible_in_table: bool,
    target_pids: Vec<i32>,
    exact_clone_pids: Vec<i32>,
    hard_negatives: Vec<(i32, String, String)>,
    differing_target_surfaces: Vec<String>,
    residual: String,
}

#[inline(never)]
fn parse_answer_file(run_dir: &Path) -> Result<ParsedAnswer, String> {
    let text = read_str_in(run_dir, "answer.json")?;
    let doc = json::parse(&text).map_err(|e| cat2("invalid answer.json: ", &e))?;
    let mut r = JRead::unchecked(&doc, "answer");
    if r.u64("schema") != 1 {
        return Err("answer.schema: unsupported version".to_string());
    }

    let mut hard_negatives = Vec::new();
    for item in doc.req_arr("hard_negatives")? {
        let mut hr = JRead::unchecked(item, "answer.hn");
        let t = (hr.i32("pid"), hr.str("hn_id"), hr.str("surface"));
        hr.check()?;
        hard_negatives.push(t);
    }

    let mut differing_target_surfaces = Vec::new();
    if let Some(arr) = doc
        .get("differing_surfaces")
        .and_then(|d| d.get("target_vs_decoys"))
        .and_then(Json::as_arr)
    {
        for item in arr {
            if let Some(s) = item.as_str() {
                push_unique(&mut differing_target_surfaces, s.to_string());
            }
        }
    }

    let ans = ParsedAnswer {
        control: r.str("control"),
        level: r.u64("level") as u8,
        mode: r.str("mode"),
        observer_uid: r.u32("observer_uid"),
        target_present: r.bool("target_present"),
        target_visible_in_table: r.bool("target_visible_in_table"),
        target_pids: r.i32_arr("target_pids", false),
        exact_clone_pids: r.i32_arr("exact_clone_pids", true),
        hard_negatives,
        differing_target_surfaces,
        residual: r
            .opt_str("residual")
            .unwrap_or_else(|| DEFAULT_RESIDUAL.to_string()),
    };
    r.check()?;
    Ok(ans)
}

fn check_target_presence(run_dir: &Path, ans: &ParsedAnswer) -> Result<(), String> {
    let table_text = read_str_in(run_dir, "blind-table.txt")?;
    harness::verify_target_presence(
        &table_text,
        ans.target_visible_in_table,
        &ans.target_pids,
        ans.mode != "table",
        &run_dir.join("deep"),
    )
}

#[derive(Clone, Copy, Default)]
struct SurfaceConfusion {
    target_hits: usize,
    decoy_hits: usize,
    hn_hits: usize,
    wrong_reason_hits: usize,
}

#[derive(Clone, Copy, Default)]
struct ControlStat {
    total: usize,
    passed: usize,
}

#[derive(Clone, Copy, Default)]
struct HnStat {
    exposed: usize,
    picked: usize,
}

fn idx_of_csv(csv: &str, key: &str) -> Option<usize> {
    csv.split(',').position(|s| s == key)
}

fn compute_population_score(
    max_level: u8,
    distinct_hns: usize,
    control_stats: &[ControlStat; 7],
    has_two_phases: bool,
    all_manifests_present: bool,
) -> u32 {
    let distinct_ctrls = control_stats.iter().filter(|s| s.total > 0).count();
    let has_c01 = control_stats[0].total > 0;
    let has_c04 = control_stats[3].total > 0;

    match max_level {
        0 => 0,
        1 => 1 + u32::from(distinct_ctrls >= 2),
        2 => 3 + u32::from(distinct_ctrls >= 2),
        3 => 5 + u32::from(distinct_hns >= 2 || distinct_ctrls >= 2),
        4 => 7 + u32::from(distinct_hns >= 3 && distinct_ctrls >= 2),
        5 | 6 => {
            if distinct_hns >= 6
                && distinct_ctrls >= 3
                && has_c01
                && has_c04
                && has_two_phases
                && all_manifests_present
            {
                9
            } else if distinct_hns >= 2 || distinct_ctrls >= 2 {
                8
            } else {
                7
            }
        }
        _ => 0,
    }
}

#[derive(Default)]
struct ScoreAcc {
    t_runs: usize,
    n_runs: usize,
    p_t: usize,
    p_d_target: usize,
    a_target: usize,
    p_d_no_target: usize,
    u_total: usize,
    wrong_reason_picks: usize,
    elapsed_samples: Vec<f64>,
    reason_counts: [usize; 14],
    hn_stats: [HnStat; 10],
    confusion: [SurfaceConfusion; 12],
    control_stats: [ControlStat; 7],
    max_level: u8,
    phases_mask: u8,
    observer_uids: Vec<u32>,
    evaluators: Vec<String>,
    residuals: Vec<String>,
    all_manifests_present: bool,
}

impl ScoreAcc {
    fn new() -> Self {
        Self {
            all_manifests_present: true,
            ..Default::default()
        }
    }

    #[inline(never)]
    fn ingest(&mut self, run_dir: &Path, ans: &ParsedAnswer, pick: &Pick) {
        if !run_dir.join("MANIFEST.sha256").is_file() {
            self.all_manifests_present = false;
        }
        self.max_level = self.max_level.max(ans.level);
        if ans.mode == "both" {
            self.phases_mask |= 3;
        }
        if pick.phase == "table" {
            self.phases_mask |= 1;
        } else if pick.phase == "deep" {
            self.phases_mask |= 2;
        }
        push_unique(&mut self.observer_uids, ans.observer_uid);
        push_unique(&mut self.residuals, ans.residual.clone());
        if let Some(ref ev) = pick.evaluator {
            let trimmed = ev.trim();
            if !trimmed.is_empty() {
                push_unique(&mut self.evaluators, trimmed.to_string());
            }
        }
        if let Some(sec) = pick.elapsed_sec {
            self.elapsed_samples.push(sec);
        }

        if let Some(ri) = idx_of_csv(ALL_REASONS_CSV, &pick.reason_surface) {
            self.reason_counts[ri] += 1;
        }
        for (_, hid, _) in &ans.hard_negatives {
            if let Some(hi) = idx_of_csv(HNS_CSV, hid) {
                self.hn_stats[hi].exposed += 1;
            }
        }

        let surf_idx = idx_of_csv(CANONICAL_CSV, &pick.reason_surface);
        let is_visible_target = ans.target_present && ans.target_visible_in_table;
        if is_visible_target {
            self.t_runs += 1;
        } else {
            self.n_runs += 1;
        }
        match pick.pick {
            PickChoice::Pid(pid) => {
                if is_visible_target && ans.target_pids.contains(&pid) {
                    self.p_t += 1;
                    if let Some(si) = surf_idx {
                        self.confusion[si].target_hits += 1;
                        if ans.control != "C-05"
                            && ans.control != "C-03"
                            && !ans.differing_target_surfaces.contains(&pick.reason_surface)
                        {
                            self.wrong_reason_picks += 1;
                            self.confusion[si].wrong_reason_hits += 1;
                        }
                    }
                } else {
                    if is_visible_target {
                        self.p_d_target += 1;
                    } else {
                        self.p_d_no_target += 1;
                    }
                    if let Some(si) = surf_idx {
                        self.confusion[si].decoy_hits += 1;
                    }
                    if let Some((_, hid, hsurf)) =
                        ans.hard_negatives.iter().find(|(p, _, _)| *p == pid)
                    {
                        if let Some(hi) = idx_of_csv(HNS_CSV, hid) {
                            self.hn_stats[hi].picked += 1;
                        }
                        if let Some(si) = surf_idx {
                            self.confusion[si].hn_hits += 1;
                        }
                        if pick.reason_surface != *hsurf {
                            self.wrong_reason_picks += 1;
                            if let Some(si) = surf_idx {
                                self.confusion[si].wrong_reason_hits += 1;
                            }
                        }
                    }
                }
            }
            PickChoice::Absent => {
                if is_visible_target {
                    self.a_target += 1;
                }
            }
            PickChoice::Ambiguous => self.u_total += 1,
        }

        let passed = match ans.control.as_str() {
            "C-01" | "C-05" => {
                matches!(pick.pick, PickChoice::Pid(p) if ans.target_pids.contains(&p))
            }
            "C-02" | "C-04" | "C-07" => pick.pick == PickChoice::Absent,
            "C-03" => {
                pick.pick == PickChoice::Ambiguous
                    || matches!(pick.pick, PickChoice::Pid(p) if ans.target_pids.contains(&p) || ans.exact_clone_pids.contains(&p))
            }
            "C-06" => !matches!(pick.pick, PickChoice::Pid(p) if ans.target_pids.contains(&p)),
            _ => false,
        };
        if let Some(ci) = idx_of_csv(CONTROLS_CSV, &ans.control) {
            self.control_stats[ci].total += 1;
            if passed {
                self.control_stats[ci].passed += 1;
            }
        }
    }

    fn build_json(mut self, runs: usize) -> String {
        let rate = |num: usize, den: usize| -> f64 {
            if den == 0 {
                0.0
            } else {
                num as f64 / den as f64
            }
        };
        let target_survival = if self.t_runs > 0 {
            1.0 - rate(self.p_t, self.t_runs)
        } else {
            0.0
        };
        let median_time = median_f64(&mut self.elapsed_samples);

        let mut total_ctrl_runs = 0usize;
        let mut passed_ctrl_runs = 0usize;
        for st in &self.control_stats {
            total_ctrl_runs += st.total;
            passed_ctrl_runs += st.passed;
        }
        let control_pass_rate = rate(passed_ctrl_runs, total_ctrl_runs);
        let distinct_hns = self.hn_stats.iter().filter(|s| s.exposed > 0).count();
        let pop_score = compute_population_score(
            self.max_level,
            distinct_hns,
            &self.control_stats,
            self.phases_mask == 3,
            self.all_manifests_present,
        );

        let mut observer_desc = String::from("local ");
        for (i, &u) in self.observer_uids.iter().enumerate() {
            if i > 0 {
                observer_desc.push(',');
            }
            observer_desc.push_str("uid:");
            json::push_u64(&mut observer_desc, u as u64);
        }
        if !self.evaluators.is_empty() {
            observer_desc.push_str(" (evaluators: ");
            observer_desc.push_str(&self.evaluators.join(","));
            observer_desc.push(')');
        }
        let residual_desc = if self.residuals.is_empty() {
            DEFAULT_RESIDUAL.to_string()
        } else {
            self.residuals.join("; ")
        };

        let mut w = Jw::new(true);
        w.obj_open();
        w.k_i64("schema", SCORE_SCHEMA as i64);
        w.k_i64("runs", runs as i64);
        w.k_i64("psgen_population_score", pop_score as i64);

        w.k_obj("metrics");
        for (k, v) in [
            ("T", self.t_runs),
            ("N", self.n_runs),
            ("P_t", self.p_t),
            ("P_d", self.p_d_target),
            ("P_d_no_target", self.p_d_no_target),
            ("A", self.a_target),
            ("U", self.u_total),
        ] {
            w.k_i64(k, v as i64);
        }
        for (k, v) in [
            ("target_survival", target_survival),
            ("decoy_pick_rate", rate(self.p_d_target, self.t_runs)),
            ("absent_rate", rate(self.a_target, self.t_runs)),
            ("false_positive_rate", rate(self.p_d_no_target, self.n_runs)),
            (
                "false_negative_rate",
                rate(self.a_target + self.p_d_target, self.t_runs),
            ),
            (
                "ambiguity_rate",
                rate(self.u_total, self.t_runs + self.n_runs),
            ),
        ] {
            w.k_f64_r6(k, v);
        }
        match median_time {
            Some(v) => w.k_f64_r6("median_time_to_pick_sec", v),
            None => w.k_null("median_time_to_pick_sec"),
        }
        w.k_f64_r6("control_pass_rate", control_pass_rate);
        w.obj_close();

        w.k_obj("confidence_intervals_95");
        for (k, pair) in [
            (
                "target_survival",
                wilson_ci_95(self.t_runs.saturating_sub(self.p_t), self.t_runs),
            ),
            (
                "false_positive_rate",
                wilson_ci_95(self.p_d_no_target, self.n_runs),
            ),
            (
                "false_negative_rate",
                wilson_ci_95(self.a_target + self.p_d_target, self.t_runs),
            ),
        ] {
            w.k_f64_pair_r6(k, pair);
        }
        w.obj_close();

        w.k_obj("controls");
        for (i, cid) in CONTROLS_CSV.split(',').enumerate() {
            let st = self.control_stats[i];
            if st.total == 0 {
                continue;
            }
            w.k_obj(cid);
            w.k_i64("total", st.total as i64);
            w.k_i64("passed", st.passed as i64);
            w.k_f64_r6("pass_rate", rate(st.passed, st.total));
            w.k_bool("ok", st.passed == st.total);
            w.obj_close();
        }
        w.k_f64_r6("control_pass_rate", control_pass_rate);
        w.obj_close();

        w.k_obj("reason_distribution");
        for (i, k) in ALL_REASONS_CSV.split(',').enumerate() {
            if self.reason_counts[i] > 0 {
                w.k_i64(k, self.reason_counts[i] as i64);
            }
        }
        w.obj_close();

        w.k_i64("wrong_reason_picks", self.wrong_reason_picks as i64);

        w.k_obj("hard_negative_survival");
        for (i, hid) in HNS_CSV.split(',').enumerate() {
            let st = self.hn_stats[i];
            if st.exposed == 0 {
                continue;
            }
            w.k_obj(hid);
            w.k_i64("exposed", st.exposed as i64);
            w.k_i64("picked", st.picked as i64);
            w.k_f64_r6("survival", 1.0 - rate(st.picked, st.exposed));
            w.obj_close();
        }
        w.obj_close();

        w.k_obj("confusion_matrix");
        for (i, surf) in CANONICAL_CSV.split(',').enumerate() {
            let c = self.confusion[i];
            w.k_obj(surf);
            for (k, v) in [
                ("target_hits", c.target_hits),
                ("decoy_hits", c.decoy_hits),
                ("hn_hits", c.hn_hits),
                ("wrong_reason_hits", c.wrong_reason_hits),
            ] {
                w.k_i64(k, v as i64);
            }
            w.obj_close();
        }
        w.obj_close();

        w.k_str("observer", &observer_desc);
        w.k_str("residual", &residual_desc);
        w.obj_close();
        w.finish()
    }
}

/// Score one or more `(run_dir, pick_json_path)` evaluation runs and return pretty JSON.
pub fn score_runs(pairs: &[(PathBuf, PathBuf)]) -> Result<String, String> {
    if pairs.is_empty() {
        return Err("score_runs requires at least one run".to_string());
    }
    let mut acc = ScoreAcc::new();
    for (run_dir, pick_path) in pairs {
        let ans = parse_answer_file(run_dir)?;
        check_target_presence(run_dir, &ans)?;
        let pick_text = read_str(pick_path)?;
        let pick = Pick::parse_str(&pick_text)?;
        acc.ingest(run_dir, &ans, &pick);
    }
    Ok(acc.build_json(pairs.len()))
}

pub struct VerifyResult {
    pub ok: bool,
    pub target_presence_ok: bool,
    pub has_secret_leaks: bool,
    pub json: String,
}

#[derive(Default)]
struct LeakReport {
    secrets: Vec<String>,
    host_paths: Vec<String>,
    errors: Vec<String>,
}

impl LeakReport {
    fn push_secret(&mut self, msg: String) {
        self.secrets.push(msg.clone());
        self.errors.push(msg);
    }

    fn push_host(&mut self, msg: String) {
        self.host_paths.push(msg.clone());
        self.errors.push(msg);
    }

    fn scan_text(
        &mut self,
        label: &str,
        text: &str,
        allow_runner: bool,
        is_environ: bool,
        forbidden_secrets: &[&str],
    ) {
        for &secret in forbidden_secrets {
            if !secret.is_empty() && text.contains(secret) {
                self.push_secret(cat2(label, ": forbidden secret"));
            }
        }
        let has_secret = if is_environ {
            profile::has_unredacted_secret_in_environ(text)
        } else {
            profile::contains_unredacted_secret_pattern(text)
        };
        if has_secret {
            self.push_secret(cat2(label, ": unredacted secret pattern"));
        }
        if let Some(pat) = profile::contains_host_home_path(text, allow_runner) {
            self.push_host(cat4(label, ": host path '", pat, "'"));
        }
    }

    fn scan_file(&mut self, path: &Path, label: &str, is_environ: bool, forbidden: &[&str]) {
        if let Ok(raw) = json::read_bytes(path) {
            self.scan_text(
                label,
                &String::from_utf8_lossy(&raw),
                true,
                is_environ,
                forbidden,
            );
        }
    }
}

fn scan_deep_leaks(run_dir: &Path, forbidden_secrets: &[&str], leaks: &mut LeakReport) {
    let Ok(entries) = fs::read_dir(run_dir.join("deep")) else {
        return;
    };
    for entry in entries.flatten() {
        let pdir = entry.path();
        if !pdir.is_dir() {
            continue;
        }
        let pid_name = entry.file_name().to_string_lossy().into_owned();
        for fname in "environ,cmdline,cwd,exe,maps,smaps,fd.json".split(',') {
            leaks.scan_file(
                &pdir.join(fname),
                &cat4("deep/", &pid_name, "/", fname),
                fname == "environ",
                forbidden_secrets,
            );
        }
        if let Ok(fd_entries) = fs::read_dir(pdir.join("fd")) {
            for fde in fd_entries.flatten() {
                let fd_name = fde.file_name().to_string_lossy().into_owned();
                leaks.scan_file(
                    &fde.path(),
                    &cat4("deep/", &pid_name, "/fd/", &fd_name),
                    false,
                    forbidden_secrets,
                );
            }
        }
    }
}

/// Verify manifest integrity, profile schema & secret hygiene, relocatability
/// (zero host home paths), target-presence consistency, and optional pick replay.
pub fn verify_run(
    run_dir: &Path,
    pick_path: Option<&Path>,
    forbidden_secrets: &[&str],
) -> Result<VerifyResult, String> {
    if !run_dir.is_dir() {
        return Err(cat2(
            "run directory does not exist: ",
            &run_dir.to_string_lossy(),
        ));
    }

    let mut leaks = LeakReport::default();

    let manifest_res = sha256::verify_manifest(run_dir);
    let manifest_ok = match &manifest_res {
        Ok(chk) if chk.is_ok() => true,
        Ok(_) => {
            leaks
                .errors
                .push("manifest integrity check failed".to_string());
            false
        }
        Err(e) => {
            leaks.errors.push(e.clone());
            false
        }
    };

    let profile_valid =
        match read_str_in(run_dir, "profile.json").and_then(|t| Profile::parse_str(&t)) {
            Ok(prof) => match prof.validate(forbidden_secrets) {
                Ok(()) => true,
                Err(e) => {
                    leaks.push_secret(cat2("profile.json: ", &e));
                    false
                }
            },
            Err(e) => {
                leaks.errors.push(e);
                false
            }
        };

    for spec in
        "blind-table.txt:0,profile.json:1,population.json:1,answer.json:0,evidence/metadata.json:0"
            .split(',')
    {
        if let Some((rel, flag)) = spec.split_once(':') {
            match read_str(&run_dir.join(rel)) {
                Ok(text) => leaks.scan_text(rel, &text, flag == "1", false, forbidden_secrets),
                Err(_) => leaks.errors.push(cat2("missing ", rel)),
            }
        }
    }

    scan_deep_leaks(run_dir, forbidden_secrets, &mut leaks);

    let target_presence_ok =
        match parse_answer_file(run_dir).and_then(|ans| check_target_presence(run_dir, &ans)) {
            Ok(()) => true,
            Err(e) => {
                leaks.errors.push(e);
                false
            }
        };

    let replay_score = pick_path.and_then(|pp| {
        score_runs(&[(run_dir.to_path_buf(), pp.to_path_buf())])
            .map_err(|e| leaks.errors.push(e))
            .ok()
    });

    let has_secret_leaks = !leaks.secrets.is_empty();
    let ok = manifest_ok
        && profile_valid
        && !has_secret_leaks
        && leaks.host_paths.is_empty()
        && target_presence_ok
        && leaks.errors.is_empty();

    let mut w = Jw::new(true);
    w.obj_open();
    w.k_i64("schema", SCORE_SCHEMA as i64);
    w.k_bool("ok", ok);
    w.k_obj("manifest");
    match manifest_res {
        Ok(chk) => {
            w.k_bool("ok", manifest_ok);
            w.k_i64("verified", chk.verified as i64);
            for (k, v) in [
                ("missing", &chk.missing),
                ("mismatched", &chk.mismatched),
                ("extra", &chk.extra),
                ("invalid_entries", &chk.invalid_entries),
            ] {
                w.k_str_arr(k, v);
            }
        }
        Err(e) => {
            w.k_bool("ok", false);
            w.k_str("error", &e);
        }
    }
    w.obj_close();
    w.k_bool("profile_valid", profile_valid);
    w.k_str_arr("secret_leaks", &leaks.secrets);
    w.k_str_arr("host_path_leaks", &leaks.host_paths);
    w.k_bool("target_presence_ok", target_presence_ok);
    w.k_str_arr("errors", &leaks.errors);
    if let Some(ref sc) = replay_score {
        w.k_raw("replay_score", sc);
    }
    w.obj_close();

    Ok(VerifyResult {
        ok,
        target_presence_ok,
        has_secret_leaks,
        json: w.finish(),
    })
}

/// Deterministic offline rescore without respawning processes or reading `/proc`.
pub fn replay_run(run_dir: &Path, pick_path: &Path) -> Result<String, String> {
    score_runs(&[(run_dir.to_path_buf(), pick_path.to_path_buf())])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{self, Control, HardNeg, Mode, RunOpts};
    use crate::profile;

    fn test_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("psgen-score-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create test dir");
        p
    }

    fn make_opts(out_dir: PathBuf, control: Control, level: u8, hns: Vec<HardNeg>) -> RunOpts {
        let mut prof = profile::synthetic_default_profile("ci-runner", false);
        prof.memory.token_present = true;
        RunOpts {
            profile: prof,
            decoys: 8,
            seed: 42,
            mode: Mode::Both,
            level,
            control,
            hard_negatives: hns,
            observer_uid: Some(2000),
            out_dir,
            blind_dir: None,
            run_id: None,
            live_target_pids: Vec::new(),
            live_decoy_pids: Vec::new(),
            decoy_token_prefix: "dtok_".to_string(),
        }
    }

    #[test]
    fn pick_parser_strict_validation() {
        let p = Pick::parse_str(
            r#"{"schema":1,"phase":"deep","pick":1234,"reason_surface":"exe","reason":"unique binary","elapsed_sec":4.5,"evaluator":"eval-a"}"#,
        )
        .unwrap();
        assert_eq!(p.pick, PickChoice::Pid(1234));
        assert_eq!(p.phase, "deep");
        assert_eq!(p.elapsed_sec, Some(4.5));

        let round = Pick::parse_str(&p.to_json_str()).unwrap();
        assert_eq!(round, p);

        let absent = Pick::parse_str(
            r#"{"schema":1,"phase":"table","pick":"absent","reason_surface":"absent","reason":"none"}"#,
        )
        .unwrap();
        assert_eq!(absent.pick, PickChoice::Absent);

        assert!(Pick::parse_str(
            r#"{"schema":2,"phase":"table","pick":"absent","reason_surface":"absent","reason":"x"}"#
        )
        .is_err());
        assert!(Pick::parse_str(
            r#"{"schema":1,"phase":"table","pick":"absent","reason_surface":"absent","reason":"x","extra":1}"#
        )
        .is_err());
        assert!(Pick::parse_str(
            r#"{"schema":1,"phase":"table","pick":-1,"reason_surface":"comm","reason":"x"}"#
        )
        .is_err());
        assert!(Pick::parse_str(
            r#"{"schema":1,"phase":"table","pick":"absent","reason_surface":"bogus","reason":"x"}"#
        )
        .is_err());
    }

    #[test]
    fn wilson_ci_bounds_are_valid() {
        assert_eq!(wilson_ci_95(0, 0), (0.0, 0.0));
        let (lo, hi) = wilson_ci_95(9, 10);
        assert!(lo > 0.55 && lo < 0.65, "lo={lo}");
        assert!(hi > 0.96 && hi < 0.995, "hi={hi}");
        let (lo0, hi0) = wilson_ci_95(0, 20);
        assert_eq!(lo0, 0.0);
        assert!(hi0 > 0.10 && hi0 < 0.25, "hi0={hi0}");
        let (lo1, hi1) = wilson_ci_95(20, 20);
        assert!(lo1 > 0.80 && lo1 < 0.90, "lo1={lo1}");
        assert_eq!(hi1, 1.0);
    }

    #[test]
    fn multi_run_scoring_controls_wrong_reason_and_population_score() {
        let base = test_dir("multi");

        let d_c01 = base.join("c01");
        let r_c01 =
            harness::build_run(&make_opts(d_c01.clone(), Control::C01Obvious, 1, vec![])).unwrap();
        let p_c01 = d_c01.join("pick.json");
        let pick1 = Pick {
            schema: 1,
            phase: "table".into(),
            pick: PickChoice::Pid(r_c01.target_pids[0]),
            reason_surface: "comm".into(),
            reason: "unique comm".into(),
            elapsed_sec: Some(2.0),
            evaluator: Some("eval-1".into()),
        };
        fs::write(&p_c01, pick1.to_json_str()).unwrap();

        let d_c04 = base.join("c04");
        harness::build_run(&make_opts(d_c04.clone(), Control::C04NoTarget, 5, vec![])).unwrap();
        let p_c04 = d_c04.join("pick.json");
        let pick4 = Pick {
            schema: 1,
            phase: "deep".into(),
            pick: PickChoice::Absent,
            reason_surface: "absent".into(),
            reason: "homogeneous".into(),
            elapsed_sec: Some(6.0),
            evaluator: Some("eval-1".into()),
        };
        fs::write(&p_c04, pick4.to_json_str()).unwrap();

        let d_c06 = base.join("c06");
        let r_c06 = harness::build_run(&make_opts(
            d_c06.clone(),
            Control::C06Main,
            5,
            HardNeg::all().to_vec(),
        ))
        .unwrap();
        let p_c06 = d_c06.join("pick.json");
        let pick6 = Pick {
            schema: 1,
            phase: "deep".into(),
            pick: PickChoice::Pid(r_c06.target_pids[0]),
            reason_surface: "exe".into(),
            reason: "guessed exe".into(),
            elapsed_sec: Some(10.0),
            evaluator: Some("eval-1".into()),
        };
        fs::write(&p_c06, pick6.to_json_str()).unwrap();

        let score_s = score_runs(&[
            (d_c01.clone(), p_c01.clone()),
            (d_c04.clone(), p_c04.clone()),
            (d_c06.clone(), p_c06.clone()),
        ])
        .unwrap();
        let score = json::parse(&score_s).unwrap();

        assert_eq!(score.req_i64("runs").unwrap(), 3);
        assert_eq!(score.req_i64("psgen_population_score").unwrap(), 9);
        assert_eq!(score.req_i64("wrong_reason_picks").unwrap(), 1);

        let metrics = score.get("metrics").unwrap();
        assert_eq!(metrics.req_i64("T").unwrap(), 2);
        assert_eq!(metrics.req_i64("N").unwrap(), 1);
        assert_eq!(metrics.req_i64("P_t").unwrap(), 2);
        assert_eq!(metrics.req_f64("false_positive_rate").unwrap(), 0.0);
        assert_eq!(metrics.req_f64("median_time_to_pick_sec").unwrap(), 6.0);

        let controls = score.get("controls").unwrap();
        assert!(controls.get("C-01").unwrap().req_bool("ok").unwrap());
        assert!(controls.get("C-04").unwrap().req_bool("ok").unwrap());
        assert!(!controls.get("C-06").unwrap().req_bool("ok").unwrap());

        let rep = json::parse(&replay_run(&d_c01, &p_c01).unwrap()).unwrap();
        assert_eq!(rep.req_i64("runs").unwrap(), 1);

        let ver = verify_run(&d_c06, Some(&p_c06), &[]).unwrap();
        assert!(ver.ok, "verify failed: {}", ver.json);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn verify_catches_tampering_secrets_host_paths_and_missing_target() {
        let base = test_dir("verify-guards");
        let out = base.join("run");
        let res = harness::build_run(&make_opts(out.clone(), Control::C06Main, 5, vec![])).unwrap();

        assert!(verify_run(&out, None, &[]).unwrap().ok);

        let tpid_str = res.target_pids[0].to_string();
        let orig_table = fs::read_to_string(out.join("blind-table.txt")).unwrap();
        let stripped: String = orig_table
            .lines()
            .filter(|l| l.split_ascii_whitespace().next() != Some(tpid_str.as_str()))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(out.join("blind-table.txt"), stripped).unwrap();

        let ver_tampered = verify_run(&out, None, &[]).unwrap();
        assert!(!ver_tampered.ok);
        assert!(!ver_tampered.target_presence_ok);

        let pick_path = out.join("pick.json");
        let p = Pick {
            schema: 1,
            phase: "table".into(),
            pick: PickChoice::Absent,
            reason_surface: "absent".into(),
            reason: "not found".into(),
            elapsed_sec: Some(1.0),
            evaluator: None,
        };
        fs::write(&pick_path, p.to_json_str()).unwrap();
        assert!(score_runs(&[(out.clone(), pick_path)]).is_err());

        let out_hp = base.join("hostpath");
        let res_hp =
            harness::build_run(&make_opts(out_hp.clone(), Control::C06Main, 5, vec![])).unwrap();
        let meta_path = out_hp.join("evidence/metadata.json");
        let mut meta = fs::read_to_string(&meta_path).unwrap();
        meta = meta.replace("same-uid", "/home/alice/secret");
        fs::write(&meta_path, meta).unwrap();
        // Also plant a leak in deep/<pid>/maps and population.json to verify expanded coverage.
        let maps_path = out_hp.join(format!("deep/{}/maps", res_hp.target_pids[0]));
        let mut maps = fs::read_to_string(&maps_path).unwrap();
        maps.push_str("<addr> r-xp 00000000 00:00 0 /Users/bob/libfoo.so\n");
        fs::write(&maps_path, maps).unwrap();

        let ver_hp = verify_run(&out_hp, None, &[]).unwrap();
        assert!(!ver_hp.ok);
        let ver_hp_doc = json::parse(&ver_hp.json).unwrap();
        let hp_leaks = ver_hp_doc.req_arr("host_path_leaks").unwrap();
        assert!(
            hp_leaks.len() >= 2,
            "expected >=2 host path leaks, got {hp_leaks:?}"
        );

        let _ = fs::remove_dir_all(&base);
    }
}
