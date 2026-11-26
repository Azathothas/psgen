//! Blind evaluation scorer, Wilson 95% confidence intervals, per-surface
//! confusion matrix & fidelity table, survival-gated scoring, multi-run
//! aggregator, offline replay, and fail-closed run/blind-dir verifier
//! (`psgen score`, `psgen replay`, `psgen verify`).

use crate::harness::{self, DEFAULT_RESIDUAL};
use crate::json::{
    self, cat2, cat3, cat4, csv_idx, csv_nth, i64_str, join_strs, lossy, next_csv, own, path_lossy,
    push_u64, push_unique_str, read_bytes, read_str, read_str_in, sort_strings, JRead, Json, Jw,
};
use crate::profile::{self, Profile};
use crate::sha256;
use std::fs;
use std::path::{Path, PathBuf};

pub const PICK_SCHEMA: u32 = 1;
pub const SCORE_SCHEMA: u32 = 1;

/// Canonical 15 `/proc` + `ps` surfaces tracked in `score.json`'s `surface_fidelity` table.
pub const FIDELITY_SURFACES: [&str; 15] = [
    "comm",
    "cmdline",
    "ppid",
    "exe",
    "maps",
    "environ",
    "status",
    "stat",
    "cwd",
    "fds",
    "auxv",
    "memory",
    "threads",
    "syscall",
    "starttime",
];

const PS_SURFACE_INDICES: [usize; 4] = [0, 1, 2, 14];

const CANONICAL_CSV: &str =
    "comm,cmdline,exe,ppid,starttime,environ,memory,maps,fd,status,syscall,threads,cwd,auxv,stat";
const ALL_REASONS_CSV: &str =
    "comm,cmdline,exe,ppid,starttime,environ,memory,maps,fd,status,syscall,threads,cwd,auxv,stat,absent,ambiguous";
const CONTROLS_CSV: &str = "C-01,C-02,C-03,C-04,C-05,C-06,C-07";
const HNS_CSV: &str = "HN-01,HN-02,HN-03,HN-04,HN-05,HN-06,HN-07,HN-08,HN-09,HN-10";

const BLIND_MANIFEST_NAME: &str = "BLIND_MANIFEST.sha256";
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
            return Err(own("bad pick.schema"));
        }
        let phase = own(if pt.eq_ignore_ascii_case("table") {
            "table"
        } else if pt.eq_ignore_ascii_case("deep") {
            "deep"
        } else {
            return Err(cat2("bad pick.phase ", pt));
        });

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
                    return Err(cat2("bad pick ", st));
                }
            }
            _ => return Err(own("bad pick")),
        };

        let norm_surf = if raw_surf.eq_ignore_ascii_case("fds") {
            "fd"
        } else {
            raw_surf
        };
        let Some(si) = csv_idx(ALL_REASONS_CSV, norm_surf, true) else {
            return Err(cat2("bad reason_surface ", raw_surf));
        };
        if let Some(f) = elapsed_sec {
            if f < 0.0 || !f.is_finite() {
                return Err(own("bad elapsed_sec"));
            }
        }

        Ok(Pick {
            schema,
            phase,
            pick,
            reason_surface: own(csv_nth(ALL_REASONS_CSV, si)),
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
        w.k_strs(
            "reason_surface,reason",
            &[&self.reason_surface, &self.reason],
        );
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
#[inline(never)]
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

fn rate(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

fn median_f64(vals: &mut [f64]) -> Option<f64> {
    let n = vals.len();
    if n == 0 {
        return None;
    }
    json::shell_sort_by(vals, |a, b| a.total_cmp(b).is_gt());
    let mid = n / 2;
    let b = *vals.get(mid)?;
    if n % 2 == 1 {
        Some(b)
    } else {
        Some((*vals.get(mid - 1)? + b) / 2.0)
    }
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

fn normalize_fidelity_surface(s: &str) -> Option<usize> {
    let norm = if s.eq_ignore_ascii_case("fd") {
        "fds"
    } else if s.eq_ignore_ascii_case("smaps") {
        "maps"
    } else if s.eq_ignore_ascii_case("wchan") {
        "syscall"
    } else if s.eq_ignore_ascii_case("task") {
        "threads"
    } else {
        s
    };
    FIDELITY_SURFACES
        .iter()
        .position(|&f| f.eq_ignore_ascii_case(norm))
}

fn surface_matches(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
        || match (normalize_fidelity_surface(a), normalize_fidelity_surface(b)) {
            (Some(ia), Some(ib)) => ia == ib,
            _ => false,
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
    total_decoys: u64,
    ps_indistinguishable_decoys: Option<u64>,
    proc_indistinguishable_decoys: Option<u64>,
    per_surface_parity: Vec<(String, f64)>,
    residual: String,
}

#[inline(never)]
fn parse_per_surface_parity(val: &Json, out: &mut Vec<(String, f64)>) {
    if let Some(entries) = val.as_obj() {
        for (k, v) in entries {
            if let Some(f) = v.as_f64() {
                out.push((own(k), f.clamp(0.0, 1.0)));
            }
        }
    } else if let Some(items) = val.as_arr() {
        for item in items {
            let pair = if let Some(arr) = item.as_arr() {
                if arr.len() == 2 {
                    arr.first()
                        .and_then(Json::as_str)
                        .zip(arr.get(1).and_then(Json::as_f64))
                } else {
                    None
                }
            } else {
                item.get("surface")
                    .and_then(Json::as_str)
                    .zip(item.get("parity").and_then(Json::as_f64))
            };
            if let Some((k, f)) = pair {
                out.push((own(k), f.clamp(0.0, 1.0)));
            }
        }
    }
}

fn opt_u64_fb(r: &mut JRead<'_>, sf: Option<&Json>, k: &str) -> Option<u64> {
    r.opt_u64(k)
        .or_else(|| sf.and_then(|o| o.get(k)).and_then(Json::as_u64))
}

#[inline(never)]
fn parse_answer_file(run_dir: &Path) -> Result<ParsedAnswer, String> {
    let text = read_str_in(run_dir, "answer.json")?;
    let doc = json::parse(&text).map_err(|e| cat2("bad answer.json: ", &e))?;
    let mut r = JRead::unchecked(&doc, "answer");
    if r.u64("schema") != 1 {
        return Err(own("bad answer.schema"));
    }

    let mut hard_negatives = Vec::new();
    for item in doc.req_arr("hard_negatives")? {
        let mut hr = JRead::unchecked(item, "answer.hn");
        let (pid, hid, surf) = (hr.i32("pid"), hr.str_ref("hn_id"), hr.str_ref("surface"));
        hr.check()?;
        hard_negatives.push((pid, own(hid), own(surf)));
    }

    let mut differing_target_surfaces = Vec::new();
    if let Some(arr) = doc
        .get("differing_surfaces")
        .and_then(|d| d.get("target_vs_decoys"))
        .and_then(Json::as_arr)
    {
        for item in arr {
            if let Some(s) = item.as_str() {
                push_unique_str(&mut differing_target_surfaces, s);
            }
        }
    }

    let target_pids = r.i32_arr("target_pids", false);
    let decoy_pids = r.i32_arr("decoy_pids", true);
    let exact_clone_pids = r.i32_arr("exact_clone_pids", true);

    let sf_obj = doc.get("surface_fidelity");
    let total_decoys = opt_u64_fb(&mut r, sf_obj, "total_decoys")
        .or_else(|| r.opt_u64("decoy_count"))
        .or_else(|| {
            r.opt_u64("population_size")
                .map(|n| n.saturating_sub(target_pids.len() as u64))
        })
        .unwrap_or((decoy_pids.len() + exact_clone_pids.len()) as u64);

    let ps_indistinguishable_decoys = opt_u64_fb(&mut r, sf_obj, "ps_indistinguishable_decoys");
    let proc_indistinguishable_decoys = opt_u64_fb(&mut r, sf_obj, "proc_indistinguishable_decoys");

    let mut per_surface_parity = Vec::new();
    if let Some(psp) = doc
        .get("per_surface_parity")
        .or_else(|| sf_obj.and_then(|sf| sf.get("per_surface")))
    {
        parse_per_surface_parity(psp, &mut per_surface_parity);
    }

    let ans = ParsedAnswer {
        control: r.str("control"),
        level: r.u64("level") as u8,
        mode: r.str("mode"),
        observer_uid: r.u32("observer_uid"),
        target_present: r.bool("target_present"),
        target_visible_in_table: r.bool("target_visible_in_table"),
        target_pids,
        exact_clone_pids,
        hard_negatives,
        differing_target_surfaces,
        total_decoys,
        ps_indistinguishable_decoys,
        proc_indistinguishable_decoys,
        per_surface_parity,
        residual: r
            .opt_str("residual")
            .unwrap_or_else(|| own(DEFAULT_RESIDUAL)),
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

#[derive(Default)]
struct FidelityAcc {
    runs: usize,
    total_decoys: u64,
    ps_indistinguishable_decoys: u64,
    proc_indistinguishable_decoys: u64,
    parity_sum: [f64; 15],
    parity_count: [usize; 15],
    separating_mask: u16,
    extra_separating: Vec<String>,
    max_differing_surfaces: usize,
}

impl FidelityAcc {
    #[inline(never)]
    fn ingest(&mut self, ans: &ParsedAnswer) {
        self.runs += 1;
        self.total_decoys = self.total_decoys.saturating_add(ans.total_decoys);

        let mut diff_mask: u16 = 0;
        let mut unknown_diff = 0usize;
        for s in &ans.differing_target_surfaces {
            if let Some(idx) = normalize_fidelity_surface(s) {
                diff_mask |= 1 << idx;
            } else {
                unknown_diff += 1;
                push_unique_str(&mut self.extra_separating, s);
            }
        }

        let mut run_parity = [1.0f64; 15];
        for (i, slot) in run_parity.iter_mut().enumerate() {
            if (diff_mask & (1 << i)) != 0 {
                *slot = 0.0;
            }
        }
        for (surf, ratio) in &ans.per_surface_parity {
            if let Some(idx) = normalize_fidelity_surface(surf) {
                let clamped = ratio.clamp(0.0, 1.0);
                run_parity[idx] = clamped;
                if clamped < 1.0 {
                    diff_mask |= 1 << idx;
                }
            }
        }
        for (i, &val) in run_parity.iter().enumerate() {
            self.parity_sum[i] += val;
            self.parity_count[i] += 1;
        }

        self.separating_mask |= diff_mask;
        let run_diff_count = (diff_mask.count_ones() as usize) + unknown_diff;
        self.max_differing_surfaces = self.max_differing_surfaces.max(run_diff_count);

        let ps_indist = match ans.ps_indistinguishable_decoys {
            Some(v) => v.min(ans.total_decoys),
            None => {
                if PS_SURFACE_INDICES
                    .iter()
                    .all(|&idx| (diff_mask & (1 << idx)) == 0)
                {
                    ans.total_decoys
                } else {
                    0
                }
            }
        };
        let proc_indist = match ans.proc_indistinguishable_decoys {
            Some(v) => v.min(ans.total_decoys),
            None => {
                if diff_mask == 0 && unknown_diff == 0 {
                    ans.total_decoys
                } else {
                    0
                }
            }
        };
        self.ps_indistinguishable_decoys =
            self.ps_indistinguishable_decoys.saturating_add(ps_indist);
        self.proc_indistinguishable_decoys = self
            .proc_indistinguishable_decoys
            .saturating_add(proc_indist);
    }

    fn avg_parity(&self, idx: usize) -> f64 {
        if self.parity_count[idx] == 0 {
            1.0
        } else {
            (self.parity_sum[idx] / self.parity_count[idx] as f64).clamp(0.0, 1.0)
        }
    }

    fn separating_surfaces(&self) -> Vec<String> {
        let mut out = self.extra_separating.clone();
        for (i, &name) in FIDELITY_SURFACES.iter().enumerate() {
            if (self.separating_mask & (1 << i)) != 0 || self.avg_parity(i) < 1.0 {
                push_unique_str(&mut out, name);
            }
        }
        sort_strings(&mut out);
        out
    }
}

fn idx_of_csv(csv: &str, key: &str) -> Option<usize> {
    csv_idx(csv, key, false)
}

/// Inputs to the empirical survival-gated 0–10 population score formula.
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct PopulationScoreInput {
    pub max_level: u8,
    pub distinct_hns: usize,
    pub distinct_controls: usize,
    pub has_two_phases: bool,
    pub all_manifests_present: bool,
    pub c06_runs: usize,
    pub c06_survival: f64,
    pub non_c06_control_runs: usize,
    pub non_c06_control_pass_rate: f64,
    pub c04_runs: usize,
    pub c04_false_positive_rate: f64,
    pub wrong_reason_picks: usize,
    pub max_c06_differing_surfaces: usize,
}

/// Survival-gated 0–10 population score.
#[inline(never)]
pub fn compute_population_score(input: &PopulationScoreInput) -> u32 {
    let mut score = match input.max_level {
        1 => 1 + u32::from(input.distinct_controls >= 2),
        2 => 3 + u32::from(input.distinct_controls >= 2),
        3 => 5 + u32::from(input.distinct_hns >= 2 || input.distinct_controls >= 2),
        4 => 7 + u32::from(input.distinct_hns >= 3 && input.distinct_controls >= 2),
        5 => {
            7 + u32::from(
                input.all_manifests_present
                    && input.has_two_phases
                    && (input.distinct_hns >= 2 || input.distinct_controls >= 2),
            )
        }
        6 => {
            if input.all_manifests_present && input.has_two_phases {
                9 + u32::from(input.distinct_hns >= 3)
            } else {
                7 + u32::from(
                    input.all_manifests_present
                        || input.has_two_phases
                        || input.distinct_hns >= 2
                        || input.distinct_controls >= 2,
                )
            }
        }
        _ => 0,
    };

    if input.c06_runs > 0 {
        let cap = if input.c06_survival <= 0.0 {
            2
        } else if input.c06_survival < 0.50 {
            4
        } else if input.c06_survival < 0.75 {
            6
        } else if input.c06_survival < 0.90 {
            8
        } else {
            10
        };
        score = score.min(cap);
    }

    if input.c04_runs > 0 && input.c04_false_positive_rate > 0.0 {
        score = score.min(if input.c04_false_positive_rate > 0.20 {
            4
        } else {
            7
        });
    }

    if input.non_c06_control_runs > 0 && input.non_c06_control_pass_rate < 1.0 {
        score = score.min(if input.non_c06_control_pass_rate < 0.80 {
            4
        } else {
            7
        });
    }

    if input.wrong_reason_picks > 0 {
        score = score.min(7).saturating_sub(input.wrong_reason_picks as u32);
    }

    if input.max_c06_differing_surfaces >= 3 {
        score = score.min(5);
    } else if input.max_c06_differing_surfaces >= 1 {
        score = score.min(7);
    }

    let meets_9 = input.max_level >= 6
        && input.all_manifests_present
        && input.has_two_phases
        && (input.c06_runs == 0 || input.c06_survival >= 0.90)
        && (input.non_c06_control_runs == 0 || input.non_c06_control_pass_rate >= 1.0)
        && (input.c04_runs == 0 || input.c04_false_positive_rate <= 0.0)
        && input.wrong_reason_picks == 0
        && input.max_c06_differing_surfaces == 0;
    if !meets_9 {
        score = score.min(8);
    } else if !(input.distinct_hns >= 3 && input.c06_runs > 0 && input.c06_survival >= 0.95) {
        score = score.min(9);
    }
    score
}

#[derive(Default)]
struct ScoreAcc {
    t_runs: usize,
    n_runs: usize,
    p_t: usize,
    p_d_target: usize,
    a_target: usize,
    p_d_no_target: usize,
    c04_fp: usize,
    u_total: usize,
    wrong_reason_picks: usize,
    elapsed_samples: Vec<f64>,
    reason_counts: [usize; 17],
    hn_stats: [HnStat; 10],
    confusion: [SurfaceConfusion; 15],
    control_stats: [ControlStat; 7],
    c06_fidelity: FidelityAcc,
    all_fidelity: FidelityAcc,
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
        push_unique_str(&mut self.residuals, &ans.residual);
        if let Some(ref ev) = pick.evaluator {
            let trimmed = ev.trim();
            if !trimmed.is_empty() {
                push_unique_str(&mut self.evaluators, trimmed);
            }
        }
        if let Some(sec) = pick.elapsed_sec {
            self.elapsed_samples.push(sec);
        }

        if let Some(slot) = idx_of_csv(ALL_REASONS_CSV, &pick.reason_surface)
            .and_then(|i| self.reason_counts.get_mut(i))
        {
            *slot += 1;
        }
        for (_, hid, _) in &ans.hard_negatives {
            if let Some(st) = idx_of_csv(HNS_CSV, hid).and_then(|i| self.hn_stats.get_mut(i)) {
                st.exposed += 1;
            }
        }

        let ctrl_idx = idx_of_csv(CONTROLS_CSV, &ans.control);
        self.all_fidelity.ingest(ans);
        if ctrl_idx == Some(5) {
            self.c06_fidelity.ingest(ans);
        }

        let surf_idx = idx_of_csv(CANONICAL_CSV, &pick.reason_surface);
        let is_visible_target = ans.target_present && ans.target_visible_in_table;
        if is_visible_target {
            self.t_runs += 1;
        } else {
            self.n_runs += 1;
        }
        let mut wrong_reason = false;
        match pick.pick {
            PickChoice::Pid(pid) => {
                if ctrl_idx == Some(3) {
                    self.c04_fp += 1;
                }
                if is_visible_target && ans.target_pids.contains(&pid) {
                    self.p_t += 1;
                    if let Some(c) = surf_idx.and_then(|i| self.confusion.get_mut(i)) {
                        c.target_hits += 1;
                        if !matches!(ctrl_idx, Some(2 | 4))
                            && !ans
                                .differing_target_surfaces
                                .iter()
                                .any(|s| surface_matches(s, &pick.reason_surface))
                        {
                            wrong_reason = true;
                        }
                    }
                } else {
                    if is_visible_target {
                        self.p_d_target += 1;
                    } else {
                        self.p_d_no_target += 1;
                    }
                    let mut is_hn = false;
                    if let Some((_, hid, hsurf)) =
                        ans.hard_negatives.iter().find(|(p, _, _)| *p == pid)
                    {
                        is_hn = true;
                        if let Some(st) =
                            idx_of_csv(HNS_CSV, hid).and_then(|i| self.hn_stats.get_mut(i))
                        {
                            st.picked += 1;
                        }
                        if !surface_matches(&pick.reason_surface, hsurf) {
                            wrong_reason = true;
                        }
                    }
                    if let Some(c) = surf_idx.and_then(|i| self.confusion.get_mut(i)) {
                        c.decoy_hits += 1;
                        if is_hn {
                            c.hn_hits += 1;
                        }
                    }
                }
                if wrong_reason {
                    self.wrong_reason_picks += 1;
                    if let Some(c) = surf_idx.and_then(|i| self.confusion.get_mut(i)) {
                        c.wrong_reason_hits += 1;
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

        let passed = match ctrl_idx {
            Some(0 | 4) => matches!(pick.pick, PickChoice::Pid(p) if ans.target_pids.contains(&p)),
            Some(1 | 3 | 6) => pick.pick == PickChoice::Absent,
            Some(2) => {
                pick.pick == PickChoice::Ambiguous
                    || matches!(pick.pick, PickChoice::Pid(p) if ans.target_pids.contains(&p) || ans.exact_clone_pids.contains(&p))
            }
            Some(5) => !matches!(pick.pick, PickChoice::Pid(p) if ans.target_pids.contains(&p)),
            _ => false,
        };
        if let Some(st) = ctrl_idx.and_then(|i| self.control_stats.get_mut(i)) {
            st.total += 1;
            if passed {
                st.passed += 1;
            }
        }
    }

    #[inline(never)]
    fn build_json(mut self, runs: usize) -> String {
        let target_survival = if self.t_runs > 0 {
            1.0 - rate(self.p_t, self.t_runs)
        } else {
            0.0
        };
        let overall_fpr = rate(self.p_d_no_target, self.n_runs);
        let median_time = median_f64(&mut self.elapsed_samples);

        let mut total_ctrl_runs = 0usize;
        let mut passed_ctrl_runs = 0usize;
        let mut non_c06_runs = 0usize;
        let mut non_c06_passed = 0usize;
        for (i, st) in self.control_stats.iter().enumerate() {
            total_ctrl_runs += st.total;
            passed_ctrl_runs += st.passed;
            if i != 5 {
                non_c06_runs += st.total;
                non_c06_passed += st.passed;
            }
        }
        let control_pass_rate = rate(passed_ctrl_runs, total_ctrl_runs);
        let non_c06_control_pass_rate = rate(non_c06_passed, non_c06_runs);
        let c06_runs = self.control_stats[5].total;
        let c06_survival = rate(self.control_stats[5].passed, c06_runs);
        let c04_runs = self.control_stats[3].total;
        let c04_fpr = rate(self.c04_fp, c04_runs);
        let distinct_hns = self.hn_stats.iter().filter(|s| s.exposed > 0).count();
        let distinct_controls = self.control_stats.iter().filter(|s| s.total > 0).count();
        let max_c06_diff = self.c06_fidelity.max_differing_surfaces;

        let score_input = PopulationScoreInput {
            max_level: self.max_level,
            distinct_hns,
            distinct_controls,
            has_two_phases: self.phases_mask == 3,
            all_manifests_present: self.all_manifests_present,
            c06_runs,
            c06_survival,
            non_c06_control_runs: non_c06_runs,
            non_c06_control_pass_rate,
            c04_runs,
            c04_false_positive_rate: c04_fpr,
            wrong_reason_picks: self.wrong_reason_picks,
            max_c06_differing_surfaces: max_c06_diff,
        };
        let pop_score = compute_population_score(&score_input);

        let fid = if self.c06_fidelity.runs > 0 {
            &self.c06_fidelity
        } else {
            &self.all_fidelity
        };
        let separating = fid.separating_surfaces();
        let gate_ctrl_rate = if non_c06_runs > 0 {
            non_c06_control_pass_rate
        } else {
            control_pass_rate
        };
        let gate_fpr = if c04_runs > 0 { c04_fpr } else { overall_fpr };
        let gate_passed = c06_runs > 0
            && c06_survival >= 0.90
            && (non_c06_runs == 0 || non_c06_control_pass_rate >= 1.0)
            && gate_fpr <= 0.0
            && self.wrong_reason_picks == 0
            && max_c06_diff == 0;

        let mut observer_desc = own("local ");
        for (i, &u) in self.observer_uids.iter().enumerate() {
            if i > 0 {
                observer_desc.push(',');
            }
            observer_desc.push_str("uid:");
            push_u64(&mut observer_desc, u as u64);
        }
        if !self.evaluators.is_empty() {
            observer_desc.push_str(" (evaluators: ");
            observer_desc.push_str(&join_strs(&self.evaluators, ","));
            observer_desc.push(')');
        }
        let residual_desc = if self.residuals.is_empty() {
            own(DEFAULT_RESIDUAL)
        } else {
            join_strs(&self.residuals, "; ")
        };

        let mut w = Jw::new(true);
        w.obj_open();
        w.k_i64s(
            "schema,runs,psgen_population_score",
            &[SCORE_SCHEMA as i64, runs as i64, pop_score as i64],
        );

        w.k_obj("metrics");
        w.k_i64s(
            "T,N,P_t,P_d,P_d_no_target,A,U",
            &[
                self.t_runs as i64,
                self.n_runs as i64,
                self.p_t as i64,
                self.p_d_target as i64,
                self.p_d_no_target as i64,
                self.a_target as i64,
                self.u_total as i64,
            ],
        );
        w.k_f64s_r6(
            "target_survival,decoy_pick_rate,absent_rate,false_positive_rate,false_negative_rate,ambiguity_rate",
            &[
                target_survival,
                rate(self.p_d_target, self.t_runs),
                rate(self.a_target, self.t_runs),
                overall_fpr,
                rate(self.a_target + self.p_d_target, self.t_runs),
                rate(self.u_total, self.t_runs + self.n_runs),
            ],
        );
        match median_time {
            Some(v) => w.k_f64_r6("median_time_to_pick_sec", v),
            None => w.k_null("median_time_to_pick_sec"),
        }
        w.k_f64_r6("control_pass_rate", control_pass_rate);
        w.obj_close();

        w.k_obj("confidence_intervals_95");
        for (k, s, t) in [
            (
                "target_survival",
                self.t_runs.saturating_sub(self.p_t),
                self.t_runs,
            ),
            ("false_positive_rate", self.p_d_no_target, self.n_runs),
            (
                "false_negative_rate",
                self.a_target + self.p_d_target,
                self.t_runs,
            ),
        ] {
            w.k_f64_pair_r6(k, wilson_ci_95(s, t));
        }
        w.obj_close();

        w.k_obj("controls");
        let mut csv = CONTROLS_CSV;
        for st in &self.control_stats {
            let cid = next_csv(&mut csv);
            if st.total == 0 {
                continue;
            }
            w.k_obj(cid);
            w.k_i64s("total,passed", &[st.total as i64, st.passed as i64]);
            w.k_f64_r6("pass_rate", rate(st.passed, st.total));
            w.k_bool("ok", st.passed == st.total);
            w.obj_close();
        }
        w.k_f64_r6("control_pass_rate", control_pass_rate);
        w.obj_close();

        w.k_obj("reason_distribution");
        let mut csv = ALL_REASONS_CSV;
        for &cnt in &self.reason_counts {
            let k = next_csv(&mut csv);
            if cnt > 0 {
                w.k_i64(k, cnt as i64);
            }
        }
        w.obj_close();

        w.k_i64("wrong_reason_picks", self.wrong_reason_picks as i64);

        w.k_obj("hard_negative_survival");
        let mut csv = HNS_CSV;
        for st in &self.hn_stats {
            let hid = next_csv(&mut csv);
            if st.exposed == 0 {
                continue;
            }
            w.k_obj(hid);
            w.k_i64s("exposed,picked", &[st.exposed as i64, st.picked as i64]);
            w.k_f64_r6("survival", 1.0 - rate(st.picked, st.exposed));
            w.obj_close();
        }
        w.obj_close();

        w.k_obj("confusion_matrix");
        let mut csv = CANONICAL_CSV;
        for c in &self.confusion {
            let surf = next_csv(&mut csv);
            w.k_obj(surf);
            w.k_i64s(
                "target_hits,decoy_hits,hn_hits,wrong_reason_hits",
                &[
                    c.target_hits as i64,
                    c.decoy_hits as i64,
                    c.hn_hits as i64,
                    c.wrong_reason_hits as i64,
                ],
            );
            w.obj_close();
        }
        w.obj_close();

        w.k_obj("surface_fidelity");
        w.k_u64s(
            "ps_indistinguishable_decoys,proc_indistinguishable_decoys,total_decoys",
            &[
                fid.ps_indistinguishable_decoys,
                fid.proc_indistinguishable_decoys,
                fid.total_decoys,
            ],
        );
        w.k_obj("per_surface");
        for (i, &surf) in FIDELITY_SURFACES.iter().enumerate() {
            w.k_f64_r6(surf, fid.avg_parity(i));
        }
        w.obj_close();
        w.k_str_arr("separating_surfaces", &separating);
        w.k_obj("discrimination_gate");
        w.k_bool("passed", gate_passed);
        w.k_f64s_r6(
            "c06_survival,control_pass_rate,false_positive_rate",
            &[c06_survival, gate_ctrl_rate, gate_fpr],
        );
        w.k_u64s(
            "wrong_reason_picks,max_separating_surfaces",
            &[
                self.wrong_reason_picks as u64,
                fid.max_differing_surfaces as u64,
            ],
        );
        w.obj_close();
        w.obj_close();

        w.k_strs("observer,residual", &[&observer_desc, &residual_desc]);
        w.obj_close();
        w.finish()
    }
}

#[inline(never)]
fn ingest_one_run(acc: &mut ScoreAcc, run_dir: &Path, pick_path: &Path) -> Result<(), String> {
    let ans = parse_answer_file(run_dir)?;
    check_target_presence(run_dir, &ans)?;
    let pick_text = read_str(pick_path)?;
    let pick = Pick::parse_str(&pick_text)?;
    acc.ingest(run_dir, &ans, &pick);
    Ok(())
}

/// Score one or more `(run_dir, pick_json_path)` evaluation runs and return pretty JSON.
pub fn score_runs(pairs: &[(PathBuf, PathBuf)]) -> Result<String, String> {
    if pairs.is_empty() {
        return Err(own("score_runs requires at least one run"));
    }
    let mut acc = ScoreAcc::new();
    for (run_dir, pick_path) in pairs {
        ingest_one_run(&mut acc, run_dir, pick_path)?;
    }
    Ok(acc.build_json(pairs.len()))
}

pub struct VerifyResult {
    pub ok: bool,
    pub target_presence_ok: bool,
    pub has_secret_leaks: bool,
    pub blind_dir_ok: bool,
    pub failures: Vec<String>,
    pub json: String,
}

#[derive(Default)]
struct LeakReport {
    secrets: Vec<String>,
    host_paths: Vec<String>,
    errors: Vec<String>,
}

impl LeakReport {
    fn record(dst: &mut Vec<String>, err_dst: &mut Vec<String>, msg: String) {
        dst.push(own(&msg));
        err_dst.push(msg);
    }

    #[inline(never)]
    fn scan_text_into(
        &mut self,
        label: &str,
        text: &str,
        allow_runner: bool,
        is_environ: bool,
        forbidden_secrets: &[&str],
        extra_err: Option<&mut Vec<String>>,
    ) {
        let errs = extra_err.unwrap_or(&mut self.errors);
        for &secret in forbidden_secrets {
            if !secret.is_empty() && text.contains(secret) {
                Self::record(&mut self.secrets, errs, cat2(label, ": forbidden secret"));
            }
        }
        let has_secret = if is_environ {
            profile::has_unredacted_secret_in_environ(text)
        } else {
            profile::contains_unredacted_secret_pattern(text)
        };
        if has_secret {
            Self::record(
                &mut self.secrets,
                errs,
                cat2(label, ": unredacted secret pattern"),
            );
        }
        if let Some(pat) = profile::contains_host_home_path(text, allow_runner) {
            Self::record(
                &mut self.host_paths,
                errs,
                cat4(label, ": host path '", pat, "'"),
            );
        }
    }

    #[inline(never)]
    fn scan_file(&mut self, path: &Path, label: &str, is_environ: bool, forbidden: &[&str]) {
        if let Ok(raw) = read_bytes(path) {
            self.scan_text_into(label, &lossy(&raw), true, is_environ, forbidden, None);
        }
    }
}

#[inline(never)]
fn scan_deep_leaks(run_dir: &Path, forbidden_secrets: &[&str], leaks: &mut LeakReport) {
    let Ok(entries) = fs::read_dir(run_dir.join("deep")) else {
        return;
    };
    for entry in entries.flatten() {
        let pdir = entry.path();
        if !pdir.is_dir() {
            continue;
        }
        let fname_os = entry.file_name();
        let pid_name = fname_os.to_string_lossy();
        let mut csv = "environ,cmdline,cwd,exe,maps,smaps,fd.json";
        while !csv.is_empty() {
            let fname = next_csv(&mut csv);
            leaks.scan_file(
                &pdir.join(fname),
                &cat4("deep/", &pid_name, "/", fname),
                fname == "environ",
                forbidden_secrets,
            );
        }
        if let Ok(fd_entries) = fs::read_dir(pdir.join("fd")) {
            for fde in fd_entries.flatten() {
                let fdn = fde.file_name();
                leaks.scan_file(
                    &fde.path(),
                    &cat4("deep/", &pid_name, "/fd/", &fdn.to_string_lossy()),
                    false,
                    forbidden_secrets,
                );
            }
        }
    }
}

fn is_forbidden_blind_filename(name: &str) -> bool {
    csv_idx(
        "answer.json,population.json,profile.json,manifest.sha256,target.pid,real_pid,answer.txt",
        name,
        true,
    )
    .is_some()
        || name
            .get(name.len().saturating_sub(4)..)
            .is_some_and(|s| s.len() == 4 && s.eq_ignore_ascii_case(".pid"))
}

fn is_allowed_blind_evaluator_file(rel: &str) -> bool {
    !rel.contains('/')
        && (rel == "pick.json"
            || (rel.starts_with("pick-") && rel.ends_with(".json") && rel.len() > 10))
}

fn check_blind_rel(rel: &str) -> Option<&'static str> {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.ends_with('/')
        || rel.contains('\\')
        || rel.contains('\0')
        || rel == BLIND_MANIFEST_NAME
    {
        return Some("unsafe path");
    }
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Some("unsafe path");
        }
        if is_forbidden_blind_filename(comp) {
            return Some("forbidden");
        }
    }
    None
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn contains_ascii_ci(hay: &[u8], needle_lower: &[u8]) -> bool {
    needle_lower.is_empty()
        || (hay.len() >= needle_lower.len()
            && hay.windows(needle_lower.len()).any(|w| {
                w.iter()
                    .zip(needle_lower.iter())
                    .all(|(&a, &b)| a.to_ascii_lowercase() == b)
            }))
}

#[inline(never)]
fn contains_labeled_pid(text: &str, pid_str: &str) -> bool {
    let hb = text.as_bytes();
    let pb = pid_str.as_bytes();
    if pb.is_empty() {
        return false;
    }
    let mut csv = "target_pid,target-pid,targetpid,real_pid,real-pid,target,pid";
    while !csv.is_empty() {
        let label = next_csv(&mut csv).as_bytes();
        let mut i = 0usize;
        while i + label.len() + 1 + pb.len() <= hb.len() {
            let boundary_ok = i == 0 || !hb.get(i - 1).is_some_and(u8::is_ascii_alphanumeric);
            if boundary_ok
                && hb.get(i..i + label.len()).is_some_and(|w| {
                    w.iter()
                        .zip(label.iter())
                        .all(|(&a, &b)| a.to_ascii_lowercase() == b)
                })
            {
                let mut j = i + label.len();
                let mut saw_sep = false;
                while let Some(&b) = hb.get(j) {
                    if !matches!(b, b' ' | b'\t' | b'=' | b':' | b'-' | b'_' | b'"' | b'\'') {
                        break;
                    }
                    if matches!(b, b' ' | b'\t' | b'=' | b':' | b'-' | b'_') {
                        saw_sep = true;
                    }
                    j += 1;
                }
                if saw_sep
                    && hb.get(j..j + pb.len()) == Some(pb)
                    && !hb.get(j + pb.len()).is_some_and(u8::is_ascii_digit)
                {
                    return true;
                }
            }
            i += 1;
        }
    }
    false
}

#[inline(never)]
fn push_err(v: &mut Vec<String>, pfx: &str, arg: &str) {
    v.push(cat2(pfx, arg));
}

#[inline(never)]
fn collect_blind_files(
    root: &Path,
    rel_prefix: &str,
    files: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    let dir = if rel_prefix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel_prefix)
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        push_err(failures, "blind_dir: read ", &path_lossy(&dir));
        return;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            push_err(failures, "blind_dir: entry err", "");
            continue;
        };
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            push_err(failures, "blind_dir: non-utf8", "");
            continue;
        };
        let rel = if rel_prefix.is_empty() {
            own(name_str)
        } else {
            cat3(rel_prefix, "/", name_str)
        };
        if is_forbidden_blind_filename(name_str) {
            push_err(failures, "blind_dir: forbidden ", &rel);
        }
        match fs::symlink_metadata(entry.path()) {
            Err(_) => push_err(failures, "blind_dir: stat ", &rel),
            Ok(m) if m.file_type().is_symlink() => push_err(failures, "blind_dir: symlink ", &rel),
            Ok(m) if m.is_dir() => collect_blind_files(root, &rel, files, failures),
            Ok(m) if m.is_file() => files.push(rel),
            Ok(_) => push_err(failures, "blind_dir: non-regular ", &rel),
        }
    }
}

fn blind_line_err(line_no: usize, msg: &str, rel: Option<&str>) -> String {
    let ln = json::u64_str(line_no as u64);
    json::concat(&[
        "blind_dir: manifest:",
        &ln,
        ": ",
        msg,
        rel.map_or("", |_| " "),
        rel.unwrap_or(""),
    ])
}

struct BlindCheck {
    ok: bool,
    verified: usize,
    failures: Vec<String>,
}

const BLIND_FORBIDDEN_LINES: &str = concat!(
    "/workspaces/psgen\n",
    "/workspaces/pmask\n",
    "/workspaces/\n",
    "answer.json\n",
    "population.json\n",
    "\"target_pids\"\n",
    "\"real_target\"\n",
    "\"role\":\"target\"\n",
    "\"role\": \"target\"",
);

#[inline(never)]
fn verify_blind_dir(
    bdir: &Path,
    ans: Option<&ParsedAnswer>,
    forbidden_secrets: &[&str],
    leaks: &mut LeakReport,
) -> BlindCheck {
    let mut failures = Vec::new();
    if !bdir.is_dir() {
        push_err(&mut failures, "blind_dir missing: ", &path_lossy(bdir));
        return BlindCheck {
            ok: false,
            verified: 0,
            failures,
        };
    }

    let mut actual_files = Vec::new();
    collect_blind_files(bdir, "", &mut actual_files, &mut failures);
    sort_strings(&mut actual_files);

    let manifest_path = bdir.join(BLIND_MANIFEST_NAME);
    let mut manifest_entries: Vec<String> = Vec::new();
    let mut verified = 0usize;

    match fs::symlink_metadata(&manifest_path) {
        Ok(m) if !m.file_type().is_symlink() && m.is_file() => match read_str(&manifest_path) {
            Ok(content) => {
                for (idx, raw_line) in content.lines().enumerate() {
                    if raw_line.is_empty() {
                        continue;
                    }
                    let line_no = idx + 1;
                    let Some((digest, rel)) = raw_line.split_once("  ") else {
                        failures.push(blind_line_err(line_no, "malformed", None));
                        continue;
                    };
                    let bad_line = if !is_lower_hex64(digest) {
                        Some(("bad hex", None))
                    } else if let Some(msg) = check_blind_rel(rel) {
                        Some((msg, Some(rel)))
                    } else if manifest_entries.iter().any(|s| s == rel) {
                        Some(("duplicate", Some(rel)))
                    } else {
                        None
                    };
                    if let Some((msg, r)) = bad_line {
                        failures.push(blind_line_err(line_no, msg, r));
                        continue;
                    }
                    manifest_entries.push(own(rel));
                    let full = bdir.join(rel);
                    let file_err = match fs::symlink_metadata(&full) {
                        Err(_) => Some("blind_dir: missing "),
                        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                            Some("blind_dir: non-regular ")
                        }
                        Ok(_) => match sha256::hash_file(&full) {
                            Ok(actual) if actual == digest => {
                                verified += 1;
                                None
                            }
                            Ok(_) => Some("blind_dir: sha256 mismatch "),
                            Err(_) => Some("blind_dir: unreadable "),
                        },
                    };
                    if let Some(pfx) = file_err {
                        push_err(&mut failures, pfx, rel);
                    }
                }
                if manifest_entries.is_empty() {
                    push_err(&mut failures, "blind_dir: empty manifest", "");
                }
            }
            Err(e) => push_err(&mut failures, "blind_dir: manifest read: ", &e),
        },
        _ => push_err(&mut failures, "blind_dir: missing manifest", ""),
    }

    for rel in &actual_files {
        let base = rel.rsplit('/').next().unwrap_or(rel);
        if rel != BLIND_MANIFEST_NAME
            && !is_forbidden_blind_filename(base)
            && !manifest_entries.iter().any(|m| m == rel)
            && !is_allowed_blind_evaluator_file(rel)
        {
            push_err(&mut failures, "blind_dir: unlisted ", rel);
        }
    }

    for rel in &manifest_entries {
        let Ok(raw) = read_bytes(&bdir.join(rel)) else {
            continue;
        };
        let text = lossy(&raw);
        let label = cat2("blind_dir/", rel);
        let is_environ = rel == "environ" || rel.ends_with("/environ");
        leaks.scan_text_into(
            &label,
            &text,
            true,
            is_environ,
            forbidden_secrets,
            Some(&mut failures),
        );
        for bad in BLIND_FORBIDDEN_LINES.lines() {
            if text.contains(bad) {
                let msg = cat3(&label, ": leak ", bad);
                if bad.contains('/') {
                    leaks.host_paths.push(own(&msg));
                }
                failures.push(msg);
            }
        }
        if contains_ascii_ci(text.as_bytes(), b"c:\\users\\") {
            LeakReport::record(
                &mut leaks.host_paths,
                &mut failures,
                cat2(&label, ": leak C:\\Users\\"),
            );
        }
    }

    if let Some(ans) = ans {
        if !ans.target_pids.is_empty() {
            let readme = read_str_in(bdir, "README.txt").ok();
            for &tpid in &ans.target_pids {
                let pid_s = i64_str(tpid as i64);
                if readme
                    .as_deref()
                    .is_some_and(|r| contains_labeled_pid(r, &pid_s))
                {
                    push_err(&mut failures, "blind_dir/README.txt: target pid ", &pid_s);
                }
                for rel in &actual_files {
                    if !rel.starts_with("deep/")
                        && rel != BLIND_MANIFEST_NAME
                        && !is_allowed_blind_evaluator_file(rel)
                        && (contains_labeled_pid(rel, &pid_s)
                            || (contains_ascii_ci(rel.as_bytes(), b"target")
                                && rel.contains(&pid_s)))
                    {
                        push_err(&mut failures, "blind_dir: pid leak ", rel);
                    }
                }
            }
        }
    }

    BlindCheck {
        ok: failures.is_empty(),
        verified,
        failures,
    }
}

/// Verify manifest integrity, profile schema & secret hygiene, relocatability
/// (zero host home paths), target-presence consistency, and optional pick replay.
pub fn verify_run(
    run_dir: &Path,
    pick_path: Option<&Path>,
    forbidden_secrets: &[&str],
) -> Result<VerifyResult, String> {
    verify_run_with_blind(run_dir, pick_path, None, forbidden_secrets)
}

/// Fail-closed verifier for `run_dir`, optional `pick_path`, and optional isolated `blind_dir`.
#[inline(never)]
pub fn verify_run_with_blind(
    run_dir: &Path,
    pick_path: Option<&Path>,
    blind_dir: Option<&Path>,
    forbidden_secrets: &[&str],
) -> Result<VerifyResult, String> {
    if !run_dir.is_dir() {
        return Err(cat2("run_dir missing: ", &path_lossy(run_dir)));
    }

    let mut leaks = LeakReport::default();

    let manifest_res = sha256::verify_manifest(run_dir);
    let manifest_ok = match &manifest_res {
        Ok(chk) if chk.is_ok() => true,
        Ok(_) => {
            push_err(&mut leaks.errors, "manifest failed", "");
            false
        }
        Err(e) => {
            push_err(&mut leaks.errors, e, "");
            false
        }
    };

    let profile_valid =
        match read_str_in(run_dir, "profile.json").and_then(|t| Profile::parse_str(&t)) {
            Ok(prof) => match prof.validate(forbidden_secrets) {
                Ok(()) => true,
                Err(e) => {
                    LeakReport::record(
                        &mut leaks.secrets,
                        &mut leaks.errors,
                        cat2("profile.json: ", &e),
                    );
                    false
                }
            },
            Err(e) => {
                leaks.errors.push(e);
                false
            }
        };

    let mut csv =
        "blind-table.txt:0,profile.json:1,population.json:1,answer.json:0,evidence/metadata.json:0";
    while !csv.is_empty() {
        if let Some((rel, flag)) = next_csv(&mut csv).split_once(':') {
            match read_str_in(run_dir, rel) {
                Ok(text) => {
                    leaks.scan_text_into(rel, &text, flag == "1", false, forbidden_secrets, None)
                }
                Err(_) => push_err(&mut leaks.errors, "missing ", rel),
            }
        }
    }

    scan_deep_leaks(run_dir, forbidden_secrets, &mut leaks);

    let parsed_ans = parse_answer_file(run_dir);
    let target_presence_ok = match &parsed_ans {
        Ok(ans) => match check_target_presence(run_dir, ans) {
            Ok(()) => true,
            Err(e) => {
                leaks.errors.push(e);
                false
            }
        },
        Err(e) => {
            push_err(&mut leaks.errors, e, "");
            false
        }
    };

    let blind_check = blind_dir.map(|bdir| {
        let chk = verify_blind_dir(
            bdir,
            parsed_ans.as_ref().ok(),
            forbidden_secrets,
            &mut leaks,
        );
        for f in &chk.failures {
            push_err(&mut leaks.errors, f, "");
        }
        chk
    });
    let blind_dir_ok = blind_check.as_ref().map_or(true, |c| c.ok);

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
        && blind_dir_ok
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
            w.k_str_arrs(
                "missing,mismatched,extra,invalid_entries",
                &[
                    &chk.missing,
                    &chk.mismatched,
                    &chk.extra,
                    &chk.invalid_entries,
                ],
            );
        }
        Err(e) => {
            w.k_bool("ok", false);
            w.k_str("error", &e);
        }
    }
    w.obj_close();
    w.k_bool("profile_valid", profile_valid);
    w.k_str_arrs(
        "secret_leaks,host_path_leaks",
        &[&leaks.secrets, &leaks.host_paths],
    );
    w.k_bool("target_presence_ok", target_presence_ok);
    if let Some(ref bchk) = blind_check {
        w.k_obj("blind_dir");
        w.k_bool("ok", bchk.ok);
        w.k_i64("verified", bchk.verified as i64);
        w.k_str_arr("failures", &bchk.failures);
        w.obj_close();
    }
    w.k_str_arrs("errors,failures", &[&leaks.errors, &leaks.errors]);
    if let Some(ref sc) = replay_score {
        w.k_raw("replay_score", sc);
    }
    w.obj_close();

    Ok(VerifyResult {
        ok,
        target_presence_ok,
        has_secret_leaks,
        blind_dir_ok,
        failures: leaks.errors,
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
            redact_tokens: Vec::new(),
            redact_envs: Vec::new(),
            live_mode: false,
        }
    }

    fn write_blind_manifest(bdir: &Path) {
        let mut files = Vec::new();
        let mut errs = Vec::new();
        collect_blind_files(bdir, "", &mut files, &mut errs);
        files.retain(|f| f != BLIND_MANIFEST_NAME && !is_allowed_blind_evaluator_file(f));
        sort_strings(&mut files);
        let mut body = String::new();
        for rel in &files {
            let digest = sha256::hash_file(&bdir.join(rel)).unwrap();
            body.push_str(&digest);
            body.push_str("  ");
            body.push_str(rel);
            body.push('\n');
        }
        fs::write(bdir.join(BLIND_MANIFEST_NAME), body).unwrap();
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

        let fds = Pick::parse_str(
            r#"{"schema":1,"phase":"deep","pick":12,"reason_surface":"fds","reason":"unique fd"}"#,
        )
        .unwrap();
        assert_eq!(fds.reason_surface, "fd");

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
    fn population_score_is_strictly_survival_gated() {
        let perfect = PopulationScoreInput {
            max_level: 6,
            distinct_hns: 6,
            distinct_controls: 4,
            has_two_phases: true,
            all_manifests_present: true,
            c06_runs: 10,
            c06_survival: 1.0,
            non_c06_control_runs: 5,
            non_c06_control_pass_rate: 1.0,
            c04_runs: 2,
            c04_false_positive_rate: 0.0,
            wrong_reason_picks: 0,
            max_c06_differing_surfaces: 0,
        };
        assert_eq!(compute_population_score(&perfect), 10);

        let score9 = PopulationScoreInput {
            distinct_hns: 1,
            c06_survival: 0.90,
            ..perfect
        };
        assert_eq!(compute_population_score(&score9), 9);

        let zero_survival = PopulationScoreInput {
            c06_survival: 0.0,
            ..perfect
        };
        assert!(
            compute_population_score(&zero_survival) <= 2,
            "zero C-06 survival must be <= 2"
        );

        let low_survival = PopulationScoreInput {
            c06_survival: 0.40,
            ..perfect
        };
        assert!(compute_population_score(&low_survival) <= 4);

        let mid_survival = PopulationScoreInput {
            c06_survival: 0.70,
            ..perfect
        };
        assert!(compute_population_score(&mid_survival) <= 6);

        let sub90_survival = PopulationScoreInput {
            c06_survival: 0.85,
            ..perfect
        };
        assert!(compute_population_score(&sub90_survival) <= 8);

        let c04_fp_small = PopulationScoreInput {
            c04_false_positive_rate: 0.10,
            ..perfect
        };
        assert!(compute_population_score(&c04_fp_small) <= 7);

        let c04_fp_high = PopulationScoreInput {
            c04_false_positive_rate: 0.50,
            ..perfect
        };
        assert!(compute_population_score(&c04_fp_high) <= 4);

        let ctrl_fail_minor = PopulationScoreInput {
            non_c06_control_pass_rate: 0.90,
            ..perfect
        };
        assert!(compute_population_score(&ctrl_fail_minor) <= 7);

        let ctrl_fail_major = PopulationScoreInput {
            non_c06_control_pass_rate: 0.50,
            ..perfect
        };
        assert!(compute_population_score(&ctrl_fail_major) <= 4);

        let wrong_reason = PopulationScoreInput {
            wrong_reason_picks: 1,
            ..perfect
        };
        assert!(compute_population_score(&wrong_reason) <= 7);
        assert!(
            compute_population_score(&PopulationScoreInput {
                wrong_reason_picks: 2,
                ..perfect
            }) < compute_population_score(&wrong_reason)
        );

        let sep_two = PopulationScoreInput {
            max_c06_differing_surfaces: 2,
            ..perfect
        };
        assert!(compute_population_score(&sep_two) <= 7);

        let sep_three = PopulationScoreInput {
            max_c06_differing_surfaces: 3,
            ..perfect
        };
        assert!(compute_population_score(&sep_three) <= 5);

        let level5_only = PopulationScoreInput {
            max_level: 5,
            ..perfect
        };
        assert!(compute_population_score(&level5_only) <= 8);
    }

    #[test]
    fn multi_run_scoring_controls_wrong_reason_and_surface_fidelity() {
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
        harness::build_run(&make_opts(d_c04.clone(), Control::C04NoTarget, 6, vec![])).unwrap();
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
            6,
            HardNeg::all().to_vec(),
        ))
        .unwrap();
        let p_c06_caught = base.join("pick-caught.json");
        let pick6_caught = Pick {
            schema: 1,
            phase: "deep".into(),
            pick: PickChoice::Pid(r_c06.target_pids[0]),
            reason_surface: "exe".into(),
            reason: "guessed exe".into(),
            elapsed_sec: Some(10.0),
            evaluator: Some("eval-1".into()),
        };
        fs::write(&p_c06_caught, pick6_caught.to_json_str()).unwrap();

        let score_caught_s = score_runs(&[
            (d_c01.clone(), p_c01.clone()),
            (d_c04.clone(), p_c04.clone()),
            (d_c06.clone(), p_c06_caught.clone()),
        ])
        .unwrap();
        let score_caught = json::parse(&score_caught_s).unwrap();

        assert_eq!(score_caught.req_i64("runs").unwrap(), 3);
        assert!(
            score_caught.req_i64("psgen_population_score").unwrap() <= 2,
            "C-06 0% survival must cap score <= 2, got {}",
            score_caught.req_i64("psgen_population_score").unwrap()
        );
        assert_eq!(score_caught.req_i64("wrong_reason_picks").unwrap(), 1);

        let metrics = score_caught.get("metrics").unwrap();
        assert_eq!(metrics.req_i64("T").unwrap(), 2);
        assert_eq!(metrics.req_i64("N").unwrap(), 1);
        assert_eq!(metrics.req_i64("P_t").unwrap(), 2);
        assert_eq!(metrics.req_f64("false_positive_rate").unwrap(), 0.0);
        assert_eq!(metrics.req_f64("median_time_to_pick_sec").unwrap(), 6.0);

        let controls = score_caught.get("controls").unwrap();
        assert!(controls.get("C-01").unwrap().req_bool("ok").unwrap());
        assert!(controls.get("C-04").unwrap().req_bool("ok").unwrap());
        assert!(!controls.get("C-06").unwrap().req_bool("ok").unwrap());

        // Now verify surviving C-06 achieves 10/10 and complete surface_fidelity table.
        let p_c06_surv = d_c06.join("pick.json");
        let pick6_surv = Pick {
            schema: 1,
            phase: "deep".into(),
            pick: PickChoice::Absent,
            reason_surface: "absent".into(),
            reason: "indistinguishable".into(),
            elapsed_sec: Some(9.0),
            evaluator: Some("eval-1".into()),
        };
        fs::write(&p_c06_surv, pick6_surv.to_json_str()).unwrap();
        let score_surv_s = score_runs(&[
            (d_c01.clone(), p_c01.clone()),
            (d_c04.clone(), p_c04.clone()),
            (d_c06.clone(), p_c06_surv.clone()),
        ])
        .unwrap();
        let score_surv = json::parse(&score_surv_s).unwrap();
        assert_eq!(score_surv.req_i64("psgen_population_score").unwrap(), 10);

        let sf = score_surv.get("surface_fidelity").unwrap();
        assert!(sf.req_u64("total_decoys").unwrap() >= 8);
        assert_eq!(
            sf.req_u64("ps_indistinguishable_decoys").unwrap(),
            sf.req_u64("total_decoys").unwrap()
        );
        assert_eq!(
            sf.req_u64("proc_indistinguishable_decoys").unwrap(),
            sf.req_u64("total_decoys").unwrap()
        );
        let ps = sf.get("per_surface").unwrap();
        for &surf in &FIDELITY_SURFACES {
            assert_eq!(ps.req_f64(surf).unwrap(), 1.0, "surface {surf}");
        }
        assert!(sf.req_arr("separating_surfaces").unwrap().is_empty());
        let dg = sf.get("discrimination_gate").unwrap();
        assert!(dg.req_bool("passed").unwrap());
        assert_eq!(dg.req_f64("c06_survival").unwrap(), 1.0);
        assert_eq!(dg.req_f64("control_pass_rate").unwrap(), 1.0);
        assert_eq!(dg.req_f64("false_positive_rate").unwrap(), 0.0);
        assert_eq!(dg.req_u64("wrong_reason_picks").unwrap(), 0);
        assert_eq!(dg.req_u64("max_separating_surfaces").unwrap(), 0);

        let rep = json::parse(&replay_run(&d_c01, &p_c01).unwrap()).unwrap();
        assert_eq!(rep.req_i64("runs").unwrap(), 1);

        let ver = verify_run(&d_c06, Some(&p_c06_surv), &[]).unwrap();
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

    #[test]
    fn verify_with_blind_dir_passes_clean_and_fails_closed_on_contamination() {
        let base = test_dir("blind-verify");
        let run_dir = base.join("run");
        let blind_dir = base.join("blind");
        let mut opts = make_opts(run_dir.clone(), Control::C06Main, 6, vec![]);
        opts.blind_dir = Some(blind_dir.clone());
        let res = harness::build_run(&opts).unwrap();

        // Newly generated blind_dir includes BLIND_MANIFEST.sha256 and verifies cleanly.
        assert!(blind_dir.join(BLIND_MANIFEST_NAME).is_file());
        let v_init = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
        assert!(v_init.ok, "initial blind_dir failed: {}", v_init.json);
        assert!(v_init.blind_dir_ok);

        // Missing BLIND_MANIFEST.sha256 fails closed.
        fs::remove_file(blind_dir.join(BLIND_MANIFEST_NAME)).unwrap();
        let v_no_man = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
        assert!(!v_no_man.ok);
        assert!(!v_no_man.blind_dir_ok);

        // Missing directory fails closed.
        let missing_bdir = base.join("does-not-exist");
        let v_missing = verify_run_with_blind(&run_dir, None, Some(&missing_bdir), &[]).unwrap();
        assert!(!v_missing.ok);
        assert!(!v_missing.blind_dir_ok);

        // Write valid BLIND_MANIFEST.sha256 + allowed evaluator pick-table.json -> passes!
        write_blind_manifest(&blind_dir);
        fs::write(
            blind_dir.join("pick-table.json"),
            r#"{"schema":1,"phase":"table","pick":"absent","reason_surface":"absent","reason":"none"}"#,
        )
        .unwrap();
        let v_clean = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
        assert!(v_clean.ok, "clean blind_dir failed: {}", v_clean.json);
        assert!(v_clean.blind_dir_ok);
        assert!(v_clean.failures.is_empty());

        // Planting forbidden files (answer.json, population.json, profile.json, decoys.pid) fails closed.
        for fname in [
            "answer.json",
            "population.json",
            "profile.json",
            "decoys.pid",
        ] {
            let planted = blind_dir.join(fname);
            fs::write(&planted, b"{}\n").unwrap();
            let v = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
            assert!(!v.ok, "expected fail closed for {fname}");
            assert!(!v.blind_dir_ok, "expected blind_dir_ok=false for {fname}");
            let _ = fs::remove_file(&planted);
        }

        // Unlisted stray file fails closed.
        let stray = blind_dir.join("notes.txt");
        fs::write(&stray, b"stray").unwrap();
        let v_stray = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
        assert!(!v_stray.ok);
        let _ = fs::remove_file(&stray);

        // Tampered manifest-covered file fails closed.
        let readme_path = blind_dir.join("README.txt");
        let orig_readme = fs::read_to_string(&readme_path).unwrap();
        fs::write(&readme_path, format!("{orig_readme}tampered\n")).unwrap();
        let v_tamper = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
        assert!(!v_tamper.ok);

        // Host path leak inside blind dir (even if re-hashed in manifest!) fails closed.
        fs::write(
            &readme_path,
            format!("{orig_readme}path=/workspaces/psgen/foo\n"),
        )
        .unwrap();
        write_blind_manifest(&blind_dir);
        let v_host = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
        assert!(!v_host.ok);

        // Secret leak inside blind dir fails closed.
        fs::write(&readme_path, format!("{orig_readme}MY_SECRET_TOKEN_XYZ\n")).unwrap();
        write_blind_manifest(&blind_dir);
        let v_sec =
            verify_run_with_blind(&run_dir, None, Some(&blind_dir), &["MY_SECRET_TOKEN_XYZ"])
                .unwrap();
        assert!(!v_sec.ok);
        assert!(v_sec.has_secret_leaks);

        // Target PID labeled in README.txt fails closed.
        fs::write(
            &readme_path,
            format!("{orig_readme}target_pid={}\n", res.target_pids[0]),
        )
        .unwrap();
        write_blind_manifest(&blind_dir);
        let v_tpid = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
        assert!(!v_tpid.ok);

        // Path traversal or forbidden reference in BLIND_MANIFEST.sha256 fails closed.
        let zeros = "0".repeat(64);
        fs::write(
            blind_dir.join(BLIND_MANIFEST_NAME),
            format!("{zeros}  ../escape.txt\n{zeros}  /etc/passwd\n{zeros}  answer.json\n"),
        )
        .unwrap();
        let v_trav = verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[]).unwrap();
        assert!(!v_trav.ok);
        assert!(v_trav.failures.len() >= 3);

        // Restore clean README & manifest -> passes again.
        fs::write(&readme_path, &orig_readme).unwrap();
        write_blind_manifest(&blind_dir);
        assert!(
            verify_run_with_blind(&run_dir, None, Some(&blind_dir), &[])
                .unwrap()
                .ok
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn surface_fidelity_handles_differing_surfaces_and_fd_normalization() {
        let base = test_dir("sf-diff");
        let d = base.join("c06");
        let mut opts = make_opts(d.clone(), Control::C06Main, 6, vec![]);
        let mut leaky = opts.profile.clone();
        leaky.identity.exe = "/opt/leaky/target-bin".to_string();
        leaky.fds.push(profile::ProfileFd {
            fd: 9,
            target: "/tmp/unique-secret.sock".to_string(),
        });
        opts.decoys = 10;
        harness::build_run_with_target_override(&opts, Some(&leaky)).unwrap();

        let p = d.join("pick.json");
        let pick = Pick {
            schema: 1,
            phase: "deep".into(),
            pick: PickChoice::Absent,
            reason_surface: "absent".into(),
            reason: "none".into(),
            elapsed_sec: Some(3.0),
            evaluator: Some("eval-sf".into()),
        };
        fs::write(&p, pick.to_json_str()).unwrap();

        let sc_s = score_runs(&[(d.clone(), p)]).unwrap();
        let sc = json::parse(&sc_s).unwrap();
        assert!(
            sc.req_i64("psgen_population_score").unwrap() <= 7,
            "differing surfaces must cap score <= 7"
        );
        let sf = sc.get("surface_fidelity").unwrap();
        let ps = sf.get("per_surface").unwrap();
        assert_eq!(ps.req_f64("exe").unwrap(), 0.0);
        assert_eq!(ps.req_f64("fds").unwrap(), 0.0);
        assert_eq!(ps.req_f64("comm").unwrap(), 1.0);
        let sep: Vec<&str> = sf
            .req_arr("separating_surfaces")
            .unwrap()
            .iter()
            .filter_map(Json::as_str)
            .collect();
        assert!(sep.contains(&"exe"), "sep={sep:?}");
        assert!(sep.contains(&"fds"), "sep={sep:?}");
        assert_eq!(sf.req_u64("proc_indistinguishable_decoys").unwrap(), 0);
        assert_eq!(
            sf.req_u64("ps_indistinguishable_decoys").unwrap(),
            sf.req_u64("total_decoys").unwrap()
        );
        let dg = sf.get("discrimination_gate").unwrap();
        assert!(!dg.req_bool("passed").unwrap());
        assert!(dg.req_u64("max_separating_surfaces").unwrap() >= 2);

        let _ = fs::remove_dir_all(&base);
    }
}
