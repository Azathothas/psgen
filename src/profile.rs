//! Process profile schema (`schema: 1`), strict JSON validator, secret redaction,
//! host-path sanitization, and live `/proc/<pid>` extractor.

use crate::json::{self, cat2, cat3, cat4, push_i64, push_u64, u64_str, JRead, Json, Jw};
use crate::sys;
use std::fs;
use std::io;
use std::path::Path;

pub const PROFILE_SCHEMA: u32 = 1;

const MAX_PROC_READ: usize = 4 * 1024 * 1024;
const MAX_MAPS_LINES: usize = 512;
const MAX_SMAPS_LINES: usize = 256;
const MAX_MEM_SCAN_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Profile {
    pub schema: u32,
    pub source: ProfileSource,
    pub identity: ProfileIdentity,
    pub status: ProfileStatus,
    pub stat: ProfileStat,
    pub memory: ProfileMemory,
    pub fds: Vec<ProfileFd>,
    pub auxv: ProfileAuxv,
    pub environ: Vec<String>,
    pub task: Vec<ProfileTask>,
    pub syscall: ProfileSyscall,
    pub timing: ProfileTiming,
    pub dumpable: Option<bool>,
    pub children: Vec<Profile>,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileSource {
    pub masker: String,
    pub profile: String,
    pub version: String,
    pub observer_uid: Option<u32>,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileIdentity {
    pub label: String,
    pub comm: String,
    pub argv: Vec<String>,
    pub cmdline_raw_nuls: Option<usize>,
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    pub starttime: u64,
    pub cwd: String,
    pub root: String,
    pub exe: String,
    pub exe_memfd: Option<String>,
    pub ns: ProfileNs,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileNs {
    pub pid: Option<String>,
    pub mnt: Option<String>,
    pub user: Option<String>,
    pub net: Option<String>,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileStatus {
    pub name: String,
    pub state: String,
    pub ppid: i32,
    pub uid: String,
    pub gid: String,
    pub threads: u32,
    pub tracer_pid: i32,
    pub no_new_privs: u32,
    pub seccomp: u32,
    pub seccomp_filters: u32,
    pub cap_eff: String,
    pub cap_prm: String,
    pub cap_bnd: String,
    pub vm_lck: Option<u64>,
    pub rss_shmem: Option<u64>,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileStat {
    pub ppid: i32,
    pub num_threads: u32,
    pub starttime: u64,
    pub vsize: u64,
    pub rss: u64,
    pub flags: Option<u64>,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    pub startstack: u64,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileMemory {
    pub maps: Vec<String>,
    pub smaps: Vec<String>,
    pub token_present: bool,
    pub token_sha256: Option<String>,
    pub readable_by: Vec<String>,
    pub denied_by: Vec<String>,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileFd {
    pub fd: i32,
    pub target: String,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileAuxv {
    pub at_execfn: Option<String>,
    pub at_platform: Option<String>,
    pub at_base: u64,
    pub at_entry: u64,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileTask {
    pub tid: i32,
    pub comm: String,
    pub state: String,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileSyscall {
    pub syscall: String,
    pub wchan: String,
    pub policy: i32,
    pub priority: i32,
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ProfileTiming {
    pub exec_ms: f64,
    pub first_conceal_ms: f64,
}

pub struct ExtractOpts {
    pub pid: i32,
    pub label: Option<String>,
    pub masker: String,
    pub profile_name: String,
    pub version: String,
    pub tree: bool,
    pub redact_tokens: Vec<String>,
    pub redact_envs: Vec<String>,
    pub max_depth: usize,
}

impl ExtractOpts {
    pub fn for_pid(pid: i32) -> Self {
        Self {
            pid,
            label: None,
            masker: "live".to_string(),
            profile_name: "single".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            tree: false,
            redact_tokens: Vec::new(),
            redact_envs: Vec::new(),
            max_depth: 4,
        }
    }
}

fn fill_profile_json(val: &Json, p: &mut Profile) -> Result<(), String> {
    let mut r = JRead::new(
        val,
        "schema,source,identity,status,stat,memory,fds,auxv,environ,task,syscall,timing,dumpable,children",
        "profile",
    )?;
    p.schema = r.u32("schema");
    if p.schema != PROFILE_SCHEMA {
        return Err("profile.schema: unsupported schema version".to_string());
    }
    r.fill_str_arr("environ", &mut p.environ);
    p.dumpable = r.opt_bool("dumpable");

    if r.enter(val, "source", "masker,profile,version,observer_uid") {
        r.fill_str("masker", &mut p.source.masker);
        r.fill_str("profile", &mut p.source.profile);
        r.fill_str("version", &mut p.source.version);
        p.source.observer_uid = r.opt_u32("observer_uid");
    }

    if r.enter(
        val,
        "identity",
        "label,comm,argv,cmdline_raw_nuls,pid,ppid,uid,gid,starttime,cwd,root,exe,exe_memfd,ns",
    ) {
        p.identity.cmdline_raw_nuls = r.opt_u32("cmdline_raw_nuls").map(|n| n as usize);
        r.fill_str("label", &mut p.identity.label);
        r.fill_str("comm", &mut p.identity.comm);
        r.fill_str_arr("argv", &mut p.identity.argv);
        p.identity.pid = r.i32("pid");
        p.identity.ppid = r.i32("ppid");
        p.identity.uid = r.u32("uid");
        p.identity.gid = r.u32("gid");
        p.identity.starttime = r.u64("starttime");
        r.fill_str("cwd", &mut p.identity.cwd);
        r.fill_str("root", &mut p.identity.root);
        r.fill_str("exe", &mut p.identity.exe);
        r.fill_opt_str("exe_memfd", &mut p.identity.exe_memfd);
        let id_val = val.get("identity").unwrap_or(&Json::Null);
        if r.enter(id_val, "ns", "pid,mnt,user,net") {
            r.fill_opt_str("pid", &mut p.identity.ns.pid);
            r.fill_opt_str("mnt", &mut p.identity.ns.mnt);
            r.fill_opt_str("user", &mut p.identity.ns.user);
            r.fill_opt_str("net", &mut p.identity.ns.net);
        }
    }

    if r.enter(
        val,
        "status",
        "Name,State,PPid,Uid,Gid,Threads,TracerPid,NoNewPrivs,Seccomp,Seccomp_filters,CapEff,CapPrm,CapBnd,VmLck,RssShmem",
    ) {
        r.fill_str("Name", &mut p.status.name);
        r.fill_str("State", &mut p.status.state);
        p.status.ppid = r.i32("PPid");
        r.fill_str("Uid", &mut p.status.uid);
        r.fill_str("Gid", &mut p.status.gid);
        p.status.threads = r.u32("Threads");
        p.status.tracer_pid = r.i32("TracerPid");
        p.status.no_new_privs = r.u32("NoNewPrivs");
        p.status.seccomp = r.u32("Seccomp");
        p.status.seccomp_filters = r.u32("Seccomp_filters");
        r.fill_str("CapEff", &mut p.status.cap_eff);
        r.fill_str("CapPrm", &mut p.status.cap_prm);
        r.fill_str("CapBnd", &mut p.status.cap_bnd);
        p.status.vm_lck = r.opt_u64("VmLck");
        p.status.rss_shmem = r.opt_u64("RssShmem");
    }

    if r.enter(
        val,
        "stat",
        "ppid,num_threads,starttime,vsize,rss,flags,arg_start,arg_end,env_start,env_end,startstack",
    ) {
        p.stat.ppid = r.i32("ppid");
        p.stat.num_threads = r.u32("num_threads");
        p.stat.starttime = r.u64("starttime");
        p.stat.vsize = r.u64("vsize");
        p.stat.rss = r.u64("rss");
        p.stat.flags = r.opt_u64("flags");
        p.stat.arg_start = r.u64("arg_start");
        p.stat.arg_end = r.u64("arg_end");
        p.stat.env_start = r.u64("env_start");
        p.stat.env_end = r.u64("env_end");
        p.stat.startstack = r.u64("startstack");
    }

    if r.enter(
        val,
        "memory",
        "maps,smaps,token_present,token_sha256,readable_by,denied_by",
    ) {
        r.fill_str_arr("maps", &mut p.memory.maps);
        r.fill_str_arr("smaps", &mut p.memory.smaps);
        p.memory.token_present = r.bool("token_present");
        r.fill_opt_str("token_sha256", &mut p.memory.token_sha256);
        r.fill_str_arr("readable_by", &mut p.memory.readable_by);
        r.fill_str_arr("denied_by", &mut p.memory.denied_by);
    }

    if r.enter(val, "auxv", "AT_EXECFN,AT_PLATFORM,AT_BASE,AT_ENTRY") {
        r.fill_opt_str("AT_EXECFN", &mut p.auxv.at_execfn);
        r.fill_opt_str("AT_PLATFORM", &mut p.auxv.at_platform);
        p.auxv.at_base = r.u64("AT_BASE");
        p.auxv.at_entry = r.u64("AT_ENTRY");
    }

    if r.enter(val, "syscall", "syscall,wchan,policy,priority") {
        r.fill_str("syscall", &mut p.syscall.syscall);
        r.fill_str("wchan", &mut p.syscall.wchan);
        p.syscall.policy = r.i32("policy");
        p.syscall.priority = r.i32("priority");
    }

    if r.enter(val, "timing", "exec_ms,first_conceal_ms") {
        p.timing.exec_ms = r.f64("exec_ms");
        p.timing.first_conceal_ms = r.f64("first_conceal_ms");
    }

    r.check()?;

    for item in val.req_arr("fds")? {
        let mut fr = JRead::new(item, "fd,target", "fds")?;
        let fd = fr.i32("fd");
        if fd < 0 {
            return Err("fds.fd: must be non-negative".to_string());
        }
        let target = fr.str("target");
        fr.check()?;
        p.fds.push(ProfileFd { fd, target });
    }

    for item in val.req_arr("task")? {
        let mut tr = JRead::new(item, "tid,comm,state", "task")?;
        let tid = tr.i32("tid");
        let comm = tr.str("comm");
        let state = tr.str("state");
        tr.check()?;
        p.task.push(ProfileTask { tid, comm, state });
    }

    match val.get("children") {
        None | Some(Json::Null) => {}
        Some(Json::Arr(arr)) => {
            p.children.reserve(arr.len());
            for child in arr {
                p.children.push(Profile::from_json(child)?);
            }
        }
        Some(_) => return Err("profile.children: expected array or null".to_string()),
    }
    Ok(())
}

impl Profile {
    /// Parse a JSON string into a strictly validated `schema: 1` `Profile`.
    pub fn parse_str(input: &str) -> Result<Profile, String> {
        let doc = json::parse(input)?;
        Profile::from_json(&doc)
    }

    /// Parse a `Json` DOM into a `Profile`, rejecting unknown fields at every level
    /// and enforcing `schema == 1`.
    pub fn from_json(val: &Json) -> Result<Profile, String> {
        let mut p = Profile::default();
        fill_profile_json(val, &mut p)?;
        Ok(p)
    }

    pub fn write_json(&self, w: &mut Jw) {
        w.obj_open();
        w.k_i64("schema", self.schema as i64);

        w.k_obj("source");
        w.k_str("masker", &self.source.masker);
        w.k_str("profile", &self.source.profile);
        w.k_str("version", &self.source.version);
        w.k_some_u64("observer_uid", self.source.observer_uid.map(u64::from));
        w.obj_close();

        w.k_obj("identity");
        w.k_str("label", &self.identity.label);
        w.k_str("comm", &self.identity.comm);
        w.k_str_arr("argv", &self.identity.argv);
        w.k_some_u64(
            "cmdline_raw_nuls",
            self.identity.cmdline_raw_nuls.map(|n| n as u64),
        );
        w.k_i64("pid", self.identity.pid as i64);
        w.k_i64("ppid", self.identity.ppid as i64);
        w.k_i64("uid", self.identity.uid as i64);
        w.k_i64("gid", self.identity.gid as i64);
        w.k_u64("starttime", self.identity.starttime);
        w.k_str("cwd", &self.identity.cwd);
        w.k_str("root", &self.identity.root);
        w.k_str("exe", &self.identity.exe);
        w.k_some_str("exe_memfd", &self.identity.exe_memfd);
        w.k_obj("ns");
        w.k_some_str("pid", &self.identity.ns.pid);
        w.k_some_str("mnt", &self.identity.ns.mnt);
        w.k_some_str("user", &self.identity.ns.user);
        w.k_some_str("net", &self.identity.ns.net);
        w.obj_close();
        w.obj_close();

        w.k_obj("status");
        w.k_str("Name", &self.status.name);
        w.k_str("State", &self.status.state);
        w.k_i64("PPid", self.status.ppid as i64);
        w.k_str("Uid", &self.status.uid);
        w.k_str("Gid", &self.status.gid);
        w.k_i64("Threads", self.status.threads as i64);
        w.k_i64("TracerPid", self.status.tracer_pid as i64);
        w.k_i64("NoNewPrivs", self.status.no_new_privs as i64);
        w.k_i64("Seccomp", self.status.seccomp as i64);
        w.k_i64("Seccomp_filters", self.status.seccomp_filters as i64);
        w.k_str("CapEff", &self.status.cap_eff);
        w.k_str("CapPrm", &self.status.cap_prm);
        w.k_str("CapBnd", &self.status.cap_bnd);
        w.k_some_u64("VmLck", self.status.vm_lck);
        w.k_some_u64("RssShmem", self.status.rss_shmem);
        w.obj_close();

        w.k_obj("stat");
        w.k_i64("ppid", self.stat.ppid as i64);
        w.k_i64("num_threads", self.stat.num_threads as i64);
        w.k_u64("starttime", self.stat.starttime);
        w.k_u64("vsize", self.stat.vsize);
        w.k_u64("rss", self.stat.rss);
        w.k_some_u64("flags", self.stat.flags);
        w.k_u64("arg_start", self.stat.arg_start);
        w.k_u64("arg_end", self.stat.arg_end);
        w.k_u64("env_start", self.stat.env_start);
        w.k_u64("env_end", self.stat.env_end);
        w.k_u64("startstack", self.stat.startstack);
        w.obj_close();

        w.k_obj("memory");
        w.k_str_arr("maps", &self.memory.maps);
        w.k_str_arr("smaps", &self.memory.smaps);
        w.k_bool("token_present", self.memory.token_present);
        w.k_opt_str("token_sha256", &self.memory.token_sha256);
        w.k_str_arr("readable_by", &self.memory.readable_by);
        w.k_str_arr("denied_by", &self.memory.denied_by);
        w.obj_close();

        w.k_arr("fds");
        for f in &self.fds {
            w.elem_obj();
            w.k_i64("fd", f.fd as i64);
            w.k_str("target", &f.target);
            w.obj_close();
        }
        w.arr_close();

        w.k_obj("auxv");
        w.k_opt_str("AT_EXECFN", &self.auxv.at_execfn);
        w.k_opt_str("AT_PLATFORM", &self.auxv.at_platform);
        w.k_u64("AT_BASE", self.auxv.at_base);
        w.k_u64("AT_ENTRY", self.auxv.at_entry);
        w.obj_close();

        w.k_str_arr("environ", &self.environ);

        w.k_arr("task");
        for t in &self.task {
            w.elem_obj();
            w.k_i64("tid", t.tid as i64);
            w.k_str("comm", &t.comm);
            w.k_str("state", &t.state);
            w.obj_close();
        }
        w.arr_close();

        w.k_obj("syscall");
        w.k_str("syscall", &self.syscall.syscall);
        w.k_str("wchan", &self.syscall.wchan);
        w.k_i64("policy", self.syscall.policy as i64);
        w.k_i64("priority", self.syscall.priority as i64);
        w.obj_close();

        w.k_obj("timing");
        w.k_f64("exec_ms", self.timing.exec_ms);
        w.k_f64("first_conceal_ms", self.timing.first_conceal_ms);
        w.obj_close();

        if let Some(d) = self.dumpable {
            w.k_bool("dumpable", d);
        }
        if !self.children.is_empty() {
            w.k_arr("children");
            for child in &self.children {
                w.elem();
                child.write_json(w);
            }
            w.arr_close();
        }
        w.obj_close();
    }

    pub fn to_json_str(&self, pretty: bool) -> String {
        let mut w = Jw::new(pretty);
        self.write_json(&mut w);
        w.finish()
    }

    #[cfg(test)]
    pub fn to_json(&self) -> Json {
        json::parse(&self.to_json_str(false)).expect("valid profile json")
    }

    /// Validate schema invariants and verify zero real secrets leaked anywhere in the profile.
    pub fn validate(&self, forbidden_secrets: &[&str]) -> Result<(), String> {
        let bad = if self.schema != PROFILE_SCHEMA {
            Some("invalid profile schema (expected 1)")
        } else if self.identity.comm.trim().is_empty() {
            Some("profile identity.comm must not be empty")
        } else if self.identity.label.trim().is_empty() {
            Some("profile identity.label must not be empty")
        } else if self.identity.pid < 0 || self.identity.ppid < 0 {
            Some("profile identity.pid and ppid must be non-negative")
        } else if self.status.threads == 0 || self.stat.num_threads == 0 {
            Some("profile thread count must be >= 1")
        } else if self.memory.token_sha256.as_deref().is_some_and(|h| {
            h.len() != 64 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        }) {
            Some("profile memory.token_sha256 must be 64 lowercase hex chars")
        } else if !self.timing.exec_ms.is_finite()
            || self.timing.exec_ms < 0.0
            || !self.timing.first_conceal_ms.is_finite()
            || self.timing.first_conceal_ms < 0.0
        {
            Some("profile timing values must be finite and non-negative")
        } else {
            None
        };
        if let Some(msg) = bad {
            return Err(msg.to_string());
        }

        // Check for unredacted sensitive environment entries.
        for entry in &self.environ {
            if let Some((k, v)) = entry.split_once('=') {
                if is_sensitive_env_key(k) && !v.is_empty() && !v.starts_with("<REDACTED") {
                    return Err(cat3(
                        "unredacted sensitive environment variable '",
                        k,
                        "' in profile",
                    ));
                }
            }
            if contains_unredacted_secret_pattern(entry) {
                return Err("unredacted secret pattern in profile environ".to_string());
            }
        }
        for arg in &self.identity.argv {
            if contains_unredacted_secret_pattern(arg) {
                return Err("unredacted secret pattern in profile argv".to_string());
            }
        }

        // Serialize and scan the entire profile JSON for any forbidden secret value.
        if !forbidden_secrets.is_empty() {
            let serialized = self.to_json_str(false);
            for &secret in forbidden_secrets {
                if !secret.is_empty() && serialized.contains(secret) {
                    return Err("forbidden secret leaked in serialized profile JSON".to_string());
                }
            }
        }

        for child in &self.children {
            child.validate(forbidden_secrets)?;
        }
        Ok(())
    }
}

fn contains_ascii_ci(hay: &str, needle_upper: &[u8]) -> bool {
    let hb = hay.as_bytes();
    if needle_upper.len() > hb.len() {
        return false;
    }
    hb.windows(needle_upper.len()).any(|w| {
        w.iter()
            .zip(needle_upper.iter())
            .all(|(&a, &b)| a.to_ascii_uppercase() == b)
    })
}

pub fn is_sensitive_env_key(key: &str) -> bool {
    "SECRET,TOKEN,PASSWORD,PASSWD,API_KEY,APIKEY,PRIVATE_KEY,CREDENTIAL,AUTH_KEY"
        .split(',')
        .any(|k| contains_ascii_ci(key, k.as_bytes()))
}

pub fn contains_unredacted_secret_pattern(s: &str) -> bool {
    if (s.contains("-----BEGIN ") && s.contains("PRIVATE KEY-----"))
        || s.contains("ghp_")
        || s.contains("github_pat_")
        || s.contains("xoxb-")
        || s.contains("xoxp-")
    {
        return true;
    }
    // AWS access key ID pattern: AKIA + 16 uppercase alphanumeric chars
    let bytes = s.as_bytes();
    if bytes.len() >= 20 {
        for i in 0..=bytes.len() - 20 {
            if &bytes[i..i + 4] == b"AKIA"
                && bytes[i + 4..i + 20]
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return true;
            }
        }
    }
    false
}

pub fn has_unredacted_secret_in_environ(env_text: &str) -> bool {
    if env_text.trim().starts_with("EACCES") {
        return false;
    }
    if contains_unredacted_secret_pattern(env_text) {
        return true;
    }
    for part in env_text.split(['\n', '\0']) {
        if let Some((k, v)) = part.trim().split_once('=') {
            if is_sensitive_env_key(k) && !v.is_empty() && !v.starts_with("<REDACTED") {
                return true;
            }
        }
    }
    false
}

fn is_win_drive(b: &[u8], i: usize) -> bool {
    i + 2 < b.len()
        && b[i].is_ascii_alphabetic()
        && b[i + 1] == b':'
        && matches!(b[i + 2], b'\\' | b'/')
        && !(i > 0 && b[i - 1].is_ascii_alphanumeric())
}

fn is_runner_home(after: &str) -> bool {
    after.starts_with("runner")
        && matches!(
            after.as_bytes().get(6).copied(),
            None | Some(b'"' | b'/' | b':' | b' ' | b'\n' | b'\0')
        )
}

/// Detect host home paths (`/Users/`, `/home/<non-runner>`, or Windows drive paths `C:\`).
pub fn contains_host_home_path(text: &str, allow_synthetic_runner: bool) -> Option<&'static str> {
    if text.contains("/Users/") {
        return Some("/Users/");
    }
    let bytes = text.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if is_win_drive(bytes, i) {
            return Some("C:\\");
        }
    }
    let mut start = 0usize;
    while let Some(rel) = text[start..].find("/home/") {
        let pos = start + rel;
        if !(allow_synthetic_runner && is_runner_home(&text[pos + 6..])) {
            return Some("/home/");
        }
        start = pos + 6;
    }
    None
}

/// Sanitize ALL occurrences of `/Users/<user>`, `/home/<user>` (except synthetic `/home/runner`),
/// and Windows drive paths (`C:\...`, `c:/...`) into neutral `/srv/work` paths.
#[inline(never)]
pub fn sanitize_host_home(s: &str) -> String {
    let mut out = s.to_string();
    for prefix in ["/Users/", "/home/"] {
        let mut cursor = 0usize;
        while let Some(rel) = out[cursor..].find(prefix) {
            let pos = cursor + rel;
            let after_idx = pos + prefix.len();
            let after = &out[after_idx..];
            if prefix == "/home/" && is_runner_home(after) {
                cursor = after_idx;
                continue;
            }
            let user_end = after
                .find(['/', ':', ' ', '"', '\'', '\n', '\0'])
                .unwrap_or(after.len());
            out.replace_range(pos..after_idx + user_end, "/srv/work");
            cursor = pos + 9;
        }
    }

    let mut cursor = 0usize;
    while cursor + 2 < out.len() {
        if !is_win_drive(out.as_bytes(), cursor) {
            cursor += 1;
            continue;
        }
        let rest = &out[cursor + 3..];
        let seg_end = rest
            .find([' ', '\t', '\n', '\r', '"', '\'', ';', '\0'])
            .unwrap_or(rest.len());
        let mut norm_tail = rest[..seg_end].replace('\\', "/");
        if let Some(after_users) = norm_tail
            .strip_prefix("Users/")
            .or_else(|| norm_tail.strip_prefix("users/"))
        {
            let uend = after_users.find('/').unwrap_or(after_users.len());
            norm_tail = after_users[uend..].trim_start_matches('/').to_string();
        }
        let rep = if norm_tail.is_empty() {
            "/srv/work".to_string()
        } else {
            cat2("/srv/work/", &norm_tail)
        };
        let nlen = rep.len();
        out.replace_range(cursor..cursor + 3 + seg_end, &rep);
        cursor += nlen;
    }
    out
}

fn redacted_marker(len: usize) -> String {
    cat3("<REDACTED:len=", &u64_str(len as u64), ">")
}

#[inline(never)]
fn scrub_tokens(s: &str, tokens: &[String], found: &mut bool) -> String {
    let mut out = s.to_string();
    for tok in tokens {
        if !tok.is_empty() && out.contains(tok.as_str()) {
            *found = true;
            out = out.replace(tok.as_str(), &redacted_marker(tok.len()));
        }
    }
    out
}

fn is_perm_errno(e: i32) -> bool {
    matches!(e, libc::EACCES | libc::EPERM)
}

fn is_perm_denied(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied || err.raw_os_error().is_some_and(is_perm_errno)
}

#[inline(never)]
fn read_proc_bytes(path: &str, max_len: usize) -> Result<Vec<u8>, i32> {
    let fd = sys::open(
        path.as_bytes(),
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    );
    if fd < 0 {
        return Err(sys::errno());
    }
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while out.len() < max_len {
        let want = (max_len - out.len()).min(chunk.len());
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), want) };
        if n > 0 {
            out.extend_from_slice(&chunk[..n as usize]);
        } else if n == 0 {
            break;
        } else {
            let e = sys::errno();
            if e == libc::EINTR {
                continue;
            }
            sys::close(fd);
            return Err(e);
        }
    }
    sys::close(fd);
    Ok(out)
}

fn proc_path(pid: i32, suffix: &str) -> String {
    let mut s = String::with_capacity(16 + suffix.len());
    s.push_str("/proc/");
    push_i64(&mut s, pid as i64);
    if !suffix.is_empty() {
        s.push('/');
        s.push_str(suffix);
    }
    s
}

fn detect_exe_memfd(exe: &str) -> Option<String> {
    let trimmed = exe.strip_prefix('/').unwrap_or(exe);
    let rest = trimmed.strip_prefix("memfd:")?;
    let name = rest.strip_suffix(" (deleted)").unwrap_or(rest).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn parse_cmdline(raw: &[u8]) -> (Vec<String>, usize) {
    let mut end = raw.len();
    while end > 0 && raw[end - 1] == 0 {
        end -= 1;
    }
    let trailing_nuls = raw.len() - end;
    if end == 0 {
        return (Vec::new(), trailing_nuls);
    }
    let argv = raw[..end]
        .split(|&b| b == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    (argv, trailing_nuls)
}

struct ParsedStat {
    comm: String,
    state: String,
    ppid: i32,
    flags: u64,
    priority: i32,
    num_threads: u32,
    starttime: u64,
    vsize: u64,
    rss: u64,
    startstack: u64,
    policy: i32,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
}

fn stat_u64(fields: &[&str], idx: usize) -> Option<u64> {
    fields.get(idx).and_then(|s| json::parse_u64_s(s))
}

fn stat_i32(fields: &[&str], idx: usize) -> Option<i32> {
    fields.get(idx).and_then(|s| json::parse_i32_s(s))
}

fn parse_proc_stat(raw: &[u8]) -> Result<ParsedStat, String> {
    let bad = "malformed /proc/PID/stat";
    let open = raw.iter().position(|&b| b == b'(').ok_or(bad)?;
    let close = raw.iter().rposition(|&b| b == b')').ok_or(bad)?;
    if close <= open {
        return Err(bad.to_string());
    }
    let comm = String::from_utf8_lossy(&raw[open + 1..close]).into_owned();
    let rest = std::str::from_utf8(&raw[close + 1..]).unwrap_or("");
    let f: Vec<&str> = rest.split_ascii_whitespace().collect();
    if f.len() < 22 {
        return Err(bad.to_string());
    }
    Ok(ParsedStat {
        comm,
        state: f[0].to_string(),
        ppid: stat_i32(&f, 1).ok_or(bad)?,
        flags: stat_u64(&f, 6).unwrap_or(0),
        priority: stat_i32(&f, 15).unwrap_or(0),
        num_threads: stat_u64(&f, 17).ok_or(bad)?.max(1) as u32,
        starttime: stat_u64(&f, 19).ok_or(bad)?,
        vsize: stat_u64(&f, 20).ok_or(bad)?,
        rss: stat_u64(&f, 21).ok_or(bad)?,
        startstack: stat_u64(&f, 25).unwrap_or(0),
        policy: stat_i32(&f, 38).unwrap_or(0),
        arg_start: stat_u64(&f, 45).unwrap_or(0),
        arg_end: stat_u64(&f, 46).unwrap_or(0),
        env_start: stat_u64(&f, 47).unwrap_or(0),
        env_end: stat_u64(&f, 48).unwrap_or(0),
    })
}

fn parse_status_kb_field(val: &str) -> Option<u64> {
    val.split_ascii_whitespace()
        .next()
        .and_then(json::parse_u64_s)
}

fn parse_ugid_eff(val: &str) -> u32 {
    let mut parts = val.split_ascii_whitespace();
    let real = parts.next().and_then(json::parse_u32_s).unwrap_or(0);
    parts.next().and_then(json::parse_u32_s).unwrap_or(real)
}

fn normalize_ws_join(val: &str) -> String {
    let mut out = String::new();
    for (i, part) in val.split_ascii_whitespace().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(part);
    }
    out
}

fn default_status() -> ProfileStatus {
    ProfileStatus {
        state: "S".to_string(),
        uid: "0 0 0 0".to_string(),
        gid: "0 0 0 0".to_string(),
        threads: 1,
        cap_eff: "0000000000000000".to_string(),
        cap_prm: "0000000000000000".to_string(),
        cap_bnd: "0000000000000000".to_string(),
        ..Default::default()
    }
}

fn parse_proc_status(raw: &[u8]) -> (ProfileStatus, u32, u32) {
    let mut st = default_status();
    let mut euid = 0u32;
    let mut egid = 0u32;

    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k {
            "Name" => st.name = v.to_string(),
            "State" => {
                if let Some(code) = v.split_ascii_whitespace().next() {
                    st.state = code.to_string();
                }
            }
            "PPid" => st.ppid = json::parse_i32_s(v).unwrap_or(0),
            "Uid" => {
                st.uid = normalize_ws_join(v);
                euid = parse_ugid_eff(v);
            }
            "Gid" => {
                st.gid = normalize_ws_join(v);
                egid = parse_ugid_eff(v);
            }
            "Threads" => st.threads = json::parse_u32_s(v).unwrap_or(1).max(1),
            "TracerPid" => st.tracer_pid = json::parse_i32_s(v).unwrap_or(0),
            "NoNewPrivs" => st.no_new_privs = json::parse_u32_s(v).unwrap_or(0),
            "Seccomp" => st.seccomp = json::parse_u32_s(v).unwrap_or(0),
            "Seccomp_filters" => st.seccomp_filters = json::parse_u32_s(v).unwrap_or(0),
            "CapEff" => st.cap_eff = v.to_string(),
            "CapPrm" => st.cap_prm = v.to_string(),
            "CapBnd" => st.cap_bnd = v.to_string(),
            "VmLck" => st.vm_lck = parse_status_kb_field(v),
            "RssShmem" => st.rss_shmem = parse_status_kb_field(v),
            _ => {}
        }
    }
    (st, euid, egid)
}

fn normalize_maps(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for line in text.lines().take(MAX_MAPS_LINES) {
        let mut parts = line.split_ascii_whitespace();
        let Some(_addr_range) = parts.next() else {
            continue;
        };
        let Some(perms) = parts.next() else {
            continue;
        };
        let offset = parts.next().unwrap_or("00000000");
        let dev = parts.next().unwrap_or("00:00");
        let inode = parts.next().unwrap_or("0");
        let mut s = String::with_capacity(64);
        s.push_str("<addr> ");
        s.push_str(perms);
        s.push(' ');
        s.push_str(offset);
        s.push(' ');
        s.push_str(dev);
        s.push(' ');
        s.push_str(inode);
        for p in parts {
            s.push(' ');
            s.push_str(p);
        }
        out.push(s);
    }
    out
}

fn normalize_smaps(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    let mut cur_header: Option<String> = None;
    let mut rss = 0u64;
    let mut pdirty = 0u64;
    let mut anon = 0u64;

    let flush = |out: &mut Vec<String>, hdr: &mut Option<String>, r: u64, p: u64, a: u64| {
        if let Some(h) = hdr.take() {
            if out.len() < MAX_SMAPS_LINES {
                let mut line = String::with_capacity(h.len() + 48);
                line.push_str(&h);
                line.push_str(" Rss:");
                push_u64(&mut line, r);
                line.push_str("kB Private_Dirty:");
                push_u64(&mut line, p);
                line.push_str("kB Anonymous:");
                push_u64(&mut line, a);
                line.push_str("kB");
                out.push(line);
            }
        }
    };

    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if !k.contains(' ') && !k.contains('-') {
                match k {
                    "Rss" => rss = parse_status_kb_field(v).unwrap_or(0),
                    "Private_Dirty" => pdirty = parse_status_kb_field(v).unwrap_or(0),
                    "Anonymous" => anon = parse_status_kb_field(v).unwrap_or(0),
                    _ => {}
                }
                continue;
            }
        }
        // Header line of a mapping block: `<start>-<end> <perms> <off> <dev> <ino> [path]`
        flush(&mut out, &mut cur_header, rss, pdirty, anon);
        rss = 0;
        pdirty = 0;
        anon = 0;
        let mut parts = line.split_ascii_whitespace();
        let _addr = parts.next();
        let perms = parts.next().unwrap_or("----");
        let _off = parts.next();
        let _dev = parts.next();
        let _ino = parts.next();
        let mut hdr = String::with_capacity(48);
        hdr.push_str(perms);
        let mut any = false;
        for p in parts {
            hdr.push(' ');
            hdr.push_str(p);
            any = true;
        }
        if !any {
            hdr.push_str(" [anon]");
        }
        cur_header = Some(hdr);
    }
    flush(&mut out, &mut cur_header, rss, pdirty, anon);
    out
}

fn read_mem_cstring(pid: i32, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let path = proc_path(pid, "mem");
    let fd = sys::open(path.as_bytes(), libc::O_RDONLY | libc::O_CLOEXEC, 0);
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 256];
    let n = sys::pread_fd(fd, &mut buf, addr);
    sys::close(fd);
    if n <= 0 {
        return None;
    }
    let slice = &buf[..n as usize];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if nul == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&slice[..nul]).into_owned())
}

fn parse_auxv(pid: i32, raw: &[u8], exe_fallback: &str, mem_readable: bool) -> ProfileAuxv {
    const AT_NULL: usize = 0;
    const AT_BASE: usize = 7;
    const AT_ENTRY: usize = 9;
    const AT_PLATFORM: usize = 15;
    const AT_EXECFN: usize = 31;

    let word = std::mem::size_of::<usize>();
    let pair = word * 2;
    let mut aux = ProfileAuxv::default();
    let mut execfn_ptr = 0u64;
    let mut platform_ptr = 0u64;

    let mut off = 0;
    while off + pair <= raw.len() {
        let mut a_buf = [0u8; std::mem::size_of::<usize>()];
        let mut v_buf = [0u8; std::mem::size_of::<usize>()];
        a_buf.copy_from_slice(&raw[off..off + word]);
        v_buf.copy_from_slice(&raw[off + word..off + pair]);
        let a_type = usize::from_ne_bytes(a_buf);
        let a_val = usize::from_ne_bytes(v_buf);
        off += pair;

        if a_type == AT_NULL {
            break;
        }
        match a_type {
            AT_BASE => aux.at_base = a_val as u64,
            AT_ENTRY => aux.at_entry = a_val as u64,
            AT_EXECFN => execfn_ptr = a_val as u64,
            AT_PLATFORM => platform_ptr = a_val as u64,
            _ => {}
        }
    }

    if execfn_ptr != 0 {
        aux.at_execfn = if mem_readable {
            read_mem_cstring(pid, execfn_ptr)
        } else {
            None
        }
        .or_else(|| {
            if !exe_fallback.is_empty() {
                Some(exe_fallback.to_string())
            } else {
                None
            }
        });
    }

    if platform_ptr != 0 {
        aux.at_platform = if mem_readable {
            read_mem_cstring(pid, platform_ptr)
        } else {
            None
        }
        .or_else(|| Some(std::env::consts::ARCH.to_string()));
    }

    aux
}

fn decode_syscall_static(nr: i64) -> Option<&'static str> {
    let nr = libc::c_long::try_from(nr).ok()?;
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_poll {
            return Some("poll");
        }
        if nr == libc::SYS_select {
            return Some("select");
        }
        if nr == libc::SYS_pause {
            return Some("pause");
        }
        if nr == libc::SYS_epoll_wait {
            return Some("epoll_wait");
        }
    }
    match nr {
        libc::SYS_read => Some("read"),
        libc::SYS_write => Some("write"),
        libc::SYS_ppoll => Some("ppoll"),
        libc::SYS_pselect6 => Some("pselect6"),
        libc::SYS_epoll_pwait => Some("epoll_pwait"),
        libc::SYS_nanosleep => Some("nanosleep"),
        libc::SYS_clock_nanosleep => Some("clock_nanosleep"),
        libc::SYS_futex => Some("futex"),
        libc::SYS_wait4 => Some("wait4"),
        libc::SYS_rt_sigsuspend => Some("rt_sigsuspend"),
        libc::SYS_accept4 => Some("accept4"),
        libc::SYS_recvfrom => Some("recvfrom"),
        _ => None,
    }
}

fn parse_proc_syscall(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let first = text.split_ascii_whitespace().next().unwrap_or("");
    if first.is_empty() {
        return "unknown".to_string();
    }
    if first == "running" {
        return "running".to_string();
    }
    match json::parse_i64_s(first) {
        Some(nr) if nr >= 0 => match decode_syscall_static(nr) {
            Some(name) => name.to_string(),
            None => cat2("syscall_", &json::i64_str(nr)),
        },
        _ => first.to_string(),
    }
}

/// Scan writable anonymous, `[stack]`, `[heap]`, and `[anon:...]` memory regions for tokens.
/// Prioritizes `[stack]` and `[heap]` first so large anonymous arenas never exhaust
/// `MAX_MEM_SCAN_BYTES` before reaching `[stack]`.
fn scan_anon_mem_for_tokens(pid: i32, raw_maps: &[u8], tokens: &[String]) -> bool {
    let mut max_needle = 0usize;
    for t in tokens {
        max_needle = max_needle.max(t.len());
    }
    if max_needle == 0 {
        return false;
    }
    let path = proc_path(pid, "mem");
    let fd = sys::open(path.as_bytes(), libc::O_RDONLY | libc::O_CLOEXEC, 0);
    if fd < 0 {
        return false;
    }

    let text = String::from_utf8_lossy(raw_maps);
    let mut regions: Vec<(u8, u64, u64)> = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_ascii_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !perms.starts_with("rw") {
            continue;
        }
        let pathname = parts.nth(3).unwrap_or("");
        let prio = if pathname == "[stack]" || pathname.starts_with("[stack:") {
            0u8
        } else if pathname == "[heap]" {
            1u8
        } else if pathname.is_empty() || pathname.starts_with("[anon:") {
            2u8
        } else {
            continue;
        };
        let Some((s_hex, e_hex)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            u64::from_str_radix(s_hex, 16),
            u64::from_str_radix(e_hex, 16),
        ) else {
            continue;
        };
        if end > start {
            let p = if prio == 2 && (end - start) > 1024 * 1024 {
                3
            } else {
                prio
            };
            regions.push((p, start, end));
        }
    }

    let mut total_scanned = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    let overlap = max_needle.saturating_sub(1).min(buf.len() / 2);
    let mut found = false;

    'scan: for target_prio in 0..=3u8 {
        for &(prio, start, end) in &regions {
            if prio != target_prio {
                continue;
            }
            let mut addr = start;
            while addr < end && total_scanned < MAX_MEM_SCAN_BYTES {
                let rem = (end - addr).min((MAX_MEM_SCAN_BYTES - total_scanned) as u64);
                let want = (rem as usize).min(buf.len());
                let n = sys::pread_fd(fd, &mut buf[..want], addr);
                if n <= 0 {
                    break;
                }
                let got = n as usize;
                total_scanned += got;
                let hay = &buf[..got];
                for t in tokens {
                    let nb = t.as_bytes();
                    if !nb.is_empty() && hay.windows(nb.len()).any(|w| w == nb) {
                        found = true;
                        break 'scan;
                    }
                }
                if got <= overlap || addr + got as u64 >= end {
                    break;
                }
                addr += (got - overlap) as u64;
            }
        }
    }

    sys::close(fd);
    found
}

fn push_unique_i32(v: &mut Vec<i32>, x: i32) {
    if !v.contains(&x) {
        v.push(x);
    }
}

fn sort_i32(v: &mut [i32]) {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && v[j - 1] > v[j] {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
}

#[inline(never)]
pub fn read_numeric_dir(dir: &str) -> io::Result<Vec<i32>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)?.flatten() {
        if let Some(n) = entry.file_name().to_str().and_then(json::parse_i32_s) {
            if n >= 0 {
                out.push(n);
            }
        }
    }
    sort_i32(&mut out);
    Ok(out)
}

fn discover_child_pids(pid: i32) -> Vec<i32> {
    let mut children: Vec<i32> = Vec::new();
    let task_dir = proc_path(pid, "task");
    let mut used_proc_children = false;
    if let Ok(tids) = read_numeric_dir(&task_dir) {
        for tid in tids {
            let p = cat3(
                &task_dir,
                "/",
                &cat2(&json::i64_str(tid as i64), "/children"),
            );
            if let Ok(text) = json::read_str(Path::new(&p)) {
                used_proc_children = true;
                for tok in text.split_ascii_whitespace() {
                    if let Some(cpid) = json::parse_i32_s(tok) {
                        if cpid > 0 && cpid != pid {
                            push_unique_i32(&mut children, cpid);
                        }
                    }
                }
            }
        }
    }

    if !used_proc_children {
        if let Ok(pids) = read_numeric_dir("/proc") {
            for cpid in pids {
                if cpid <= 0 || cpid == pid {
                    continue;
                }
                if let Ok(raw) = read_proc_bytes(&proc_path(cpid, "stat"), 4096) {
                    if let Ok(parsed) = parse_proc_stat(&raw) {
                        if parsed.ppid == pid {
                            push_unique_i32(&mut children, cpid);
                        }
                    }
                }
            }
        }
    }
    sort_i32(&mut children);
    children
}

struct ProcCtx<'a> {
    dir: String,
    toks: &'a [String],
    hit: bool,
    readable: &'a mut Vec<String>,
    denied: &'a mut Vec<String>,
}

impl<'a> ProcCtx<'a> {
    fn path(&self, rel: &str) -> String {
        cat3(&self.dir, "/", rel)
    }

    fn s(&mut self, v: &str) -> String {
        scrub_tokens(v, self.toks, &mut self.hit)
    }

    fn sv(&mut self, mut items: Vec<String>) -> Vec<String> {
        for item in &mut items {
            *item = self.s(item);
        }
        items
    }

    fn read(&mut self, name: &str, max: usize, track: bool) -> Option<Vec<u8>> {
        match read_proc_bytes(&self.path(name), max) {
            Ok(b) => {
                if track {
                    self.readable.push(name.to_string());
                }
                Some(b)
            }
            Err(e) => {
                if is_perm_errno(e) {
                    self.denied.push(name.to_string());
                }
                None
            }
        }
    }

    fn read_str(&self, rel: &str, max: usize) -> Option<String> {
        read_proc_bytes(&self.path(rel), max)
            .ok()
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
    }

    fn read_link(&self, rel: &str) -> Option<String> {
        fs::read_link(self.path(rel))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn read_fds(&mut self) -> Vec<ProfileFd> {
        let mut fds = Vec::new();
        let fd_dir = self.path("fd");
        match read_numeric_dir(&fd_dir) {
            Ok(nums) => {
                self.readable.push("fd".to_string());
                for fd in nums {
                    let p = cat3(&fd_dir, "/", &json::i64_str(fd as i64));
                    if let Ok(target) = fs::read_link(&p) {
                        let t = self.s(&target.to_string_lossy());
                        fds.push(ProfileFd { fd, target: t });
                    }
                }
            }
            Err(e) if is_perm_denied(&e) => self.denied.push("fd".to_string()),
            Err(_) => {}
        }
        fds
    }

    fn read_environ(&mut self, redact_envs: &[String]) -> Vec<String> {
        let mut environ = Vec::new();
        if let Some(raw) = self.read("environ", MAX_PROC_READ, true) {
            for part in raw.split(|&b| b == 0) {
                if part.is_empty() {
                    continue;
                }
                let entry = String::from_utf8_lossy(part);
                if let Some((k, v)) = entry.split_once('=') {
                    let flagged = is_sensitive_env_key(k)
                        || redact_envs.iter().any(|r| r.eq_ignore_ascii_case(k))
                        || contains_unredacted_secret_pattern(v);
                    let val = if flagged {
                        self.hit = true;
                        redacted_marker(v.len())
                    } else {
                        self.s(v)
                    };
                    environ.push(cat3(k, "=", &val));
                } else {
                    environ.push(self.s(&entry));
                }
            }
        }
        environ
    }

    fn read_tasks(&mut self, pid: i32, comm: &str, state: &str) -> Vec<ProfileTask> {
        let mut task = Vec::new();
        let task_root = self.path("task");
        if let Ok(tids) = read_numeric_dir(&task_root) {
            for tid in tids {
                let tbase = cat3(&task_root, "/", &json::i64_str(tid as i64));
                let t_comm = read_proc_bytes(&cat2(&tbase, "/comm"), 256)
                    .ok()
                    .map(|b| String::from_utf8_lossy(&b).trim().to_string())
                    .unwrap_or_else(|| comm.to_string());
                let t_state = read_proc_bytes(&cat2(&tbase, "/stat"), 4096)
                    .ok()
                    .and_then(|b| parse_proc_stat(&b).ok())
                    .map(|s| s.state)
                    .unwrap_or_else(|| state.to_string());
                task.push(ProfileTask {
                    tid,
                    comm: self.s(&t_comm),
                    state: t_state,
                });
            }
        }
        if task.is_empty() {
            task.push(ProfileTask {
                tid: pid,
                comm: comm.to_string(),
                state: state.to_string(),
            });
        }
        task
    }
}

/// Extract a live `schema: 1` `Profile` from `/proc/<pid>`.
pub fn extract_live(opts: &ExtractOpts) -> Result<Profile, String> {
    let mut visited: Vec<i32> = Vec::new();
    extract_live_inner(opts, opts.pid, 0, &mut visited)
}

fn extract_live_inner(
    opts: &ExtractOpts,
    pid: i32,
    depth: usize,
    visited: &mut Vec<i32>,
) -> Result<Profile, String> {
    if pid <= 0 {
        return Err(cat2("invalid pid ", &json::i64_str(pid as i64)));
    }
    push_unique_i32(visited, pid);

    let proc_dir = proc_path(pid, "");
    if !Path::new(&proc_dir).exists() {
        return Err(cat3(
            "process ",
            &json::i64_str(pid as i64),
            " does not exist in /proc",
        ));
    }

    let stat_path = cat2(&proc_dir, "/stat");
    let stat_raw = read_proc_bytes(&stat_path, 8192).map_err(|e| {
        cat4(
            "cannot read ",
            &stat_path,
            ": errno ",
            &json::i64_str(e as i64),
        )
    })?;
    let pstat = parse_proc_stat(&stat_raw)?;

    let observer_uid = sys::geteuid();
    let mut prof = Profile {
        schema: PROFILE_SCHEMA,
        source: ProfileSource {
            masker: opts.masker.clone(),
            profile: String::new(),
            version: opts.version.clone(),
            observer_uid: Some(observer_uid),
        },
        stat: ProfileStat {
            ppid: pstat.ppid,
            num_threads: pstat.num_threads,
            starttime: pstat.starttime,
            vsize: pstat.vsize,
            rss: pstat.rss,
            flags: Some(pstat.flags),
            arg_start: pstat.arg_start,
            arg_end: pstat.arg_end,
            env_start: pstat.env_start,
            env_end: pstat.env_end,
            startstack: pstat.startstack,
        },
        ..Default::default()
    };
    prof.memory
        .readable_by
        .push(cat2("uid:", &u64_str(observer_uid as u64)));

    let mut ctx = ProcCtx {
        dir: proc_dir,
        toks: &opts.redact_tokens,
        hit: false,
        readable: &mut prof.memory.readable_by,
        denied: &mut prof.memory.denied_by,
    };

    let comm_raw = ctx
        .read_str("comm", 256)
        .filter(|s| !s.is_empty())
        .unwrap_or(pstat.comm);
    let comm = ctx.s(&comm_raw);

    let (raw_argv, cmdline_raw_nuls) = match ctx.read("cmdline", 512 * 1024, false) {
        Some(b) => parse_cmdline(&b),
        None => (Vec::new(), 0),
    };

    let (mut status, euid, egid) = match read_proc_bytes(&ctx.path("status"), MAX_PROC_READ) {
        Ok(b) => parse_proc_status(&b),
        Err(_) => {
            let mut st = default_status();
            st.name = comm.clone();
            st.state = pstat.state;
            st.ppid = pstat.ppid;
            st.threads = pstat.num_threads;
            (st, 0, 0)
        }
    };
    status.name = if status.name.is_empty() {
        comm.clone()
    } else {
        ctx.s(&status.name)
    };
    prof.status = status;

    let exe_raw = match fs::read_link(ctx.path("exe")) {
        Ok(p) => {
            ctx.readable.push("exe".to_string());
            p.to_string_lossy().into_owned()
        }
        Err(e) => {
            if is_perm_denied(&e) {
                ctx.denied.push("exe".to_string());
            }
            String::new()
        }
    };
    let exe = ctx.s(&exe_raw);
    prof.identity.exe_memfd = detect_exe_memfd(&exe);
    prof.identity.label = ctx.s(opts.label.as_deref().unwrap_or(&comm));
    prof.identity.comm = comm;
    prof.identity.argv = ctx.sv(raw_argv);
    prof.identity.cmdline_raw_nuls = Some(cmdline_raw_nuls);
    prof.identity.pid = pid;
    prof.identity.ppid = pstat.ppid;
    prof.identity.uid = euid;
    prof.identity.gid = egid;
    prof.identity.starttime = pstat.starttime;
    prof.identity.cwd = ctx.s(&ctx.read_link("cwd").unwrap_or_default());
    prof.identity.root = ctx.read_link("root").unwrap_or_else(|| "/".to_string());
    prof.identity.exe = exe;
    prof.identity.ns = ProfileNs {
        pid: ctx.read_link("ns/pid"),
        mnt: ctx.read_link("ns/mnt"),
        user: ctx.read_link("ns/user"),
        net: ctx.read_link("ns/net"),
    };

    let mem_fd = sys::open(
        ctx.path("mem").as_bytes(),
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    );
    let mem_readable = if mem_fd >= 0 {
        sys::close(mem_fd);
        ctx.readable.push("mem".to_string());
        true
    } else {
        if is_perm_errno(sys::errno()) {
            ctx.denied.push("mem".to_string());
        }
        false
    };

    if let Some(raw_maps) = ctx.read("maps", MAX_PROC_READ, true) {
        prof.memory.maps = ctx.sv(normalize_maps(&raw_maps));
        if mem_readable
            && pid != sys::getpid()
            && !opts.redact_tokens.is_empty()
            && scan_anon_mem_for_tokens(pid, &raw_maps, &opts.redact_tokens)
        {
            ctx.hit = true;
        }
    }

    if let Ok(raw) = read_proc_bytes(&ctx.path("smaps"), MAX_PROC_READ) {
        prof.memory.smaps = ctx.sv(normalize_smaps(&raw));
    }

    prof.fds = ctx.read_fds();

    if let Some(raw) = ctx.read("auxv", 64 * 1024, true) {
        prof.auxv = parse_auxv(pid, &raw, &prof.identity.exe, mem_readable);
        if let Some(ref execfn) = prof.auxv.at_execfn {
            prof.auxv.at_execfn = Some(ctx.s(execfn));
        }
    }

    prof.environ = ctx.read_environ(&opts.redact_envs);
    prof.task = ctx.read_tasks(pid, &prof.identity.comm, &prof.status.state);
    prof.syscall = ProfileSyscall {
        syscall: read_proc_bytes(&ctx.path("syscall"), 512)
            .map(|b| parse_proc_syscall(&b))
            .unwrap_or_else(|_| "unknown".to_string()),
        wchan: ctx
            .read_str("wchan", 256)
            .unwrap_or_else(|| "0".to_string()),
        policy: pstat.policy,
        priority: pstat.priority,
    };
    prof.memory.token_present = ctx.hit;

    if observer_uid != 0 && observer_uid == euid {
        let any_denied = prof
            .memory
            .denied_by
            .iter()
            .any(|s| "environ,maps,auxv,exe,fd,mem".split(',').any(|d| d == s));
        prof.dumpable = Some(!any_denied);
    }

    if opts.tree && depth < opts.max_depth {
        for cpid in discover_child_pids(pid) {
            if !visited.contains(&cpid) {
                if let Ok(child_prof) = extract_live_inner(opts, cpid, depth + 1, visited) {
                    prof.children.push(child_prof);
                }
            }
        }
    }

    prof.source.profile = if !opts.profile_name.is_empty() {
        opts.profile_name.clone()
    } else if !prof.children.is_empty() {
        "tree".to_string()
    } else {
        "single".to_string()
    };
    Ok(prof)
}

/// Shared synthetic 3-line `maps` & `smaps` builder (used by `synthetic_default_profile` & `harness.rs`).
#[inline(never)]
pub fn basic_maps_smaps(
    exe: &str,
    exe_ino: &str,
    exe_kb: u64,
    heap_kb: u64,
) -> (Vec<String>, Vec<String>) {
    let maps = vec![
        cat4("<addr> r-xp 00001000 08:01 ", exe_ino, " ", exe),
        "<addr> rw-p 00000000 00:00 0 [heap]".to_string(),
        "<addr> rw-p 00000000 00:00 0 [stack]".to_string(),
    ];
    let exe_s = u64_str(exe_kb);
    let heap_s = u64_str(heap_kb);
    let smaps = vec![
        cat4(
            "r-xp ",
            exe,
            " Rss:",
            &cat2(&exe_s, "kB Private_Dirty:0kB Anonymous:0kB"),
        ),
        cat4(
            "rw-p [heap] Rss:",
            &heap_s,
            "kB Private_Dirty:",
            &cat4(&heap_s, "kB Anonymous:", &heap_s, "kB"),
        ),
        "rw-p [stack] Rss:128kB Private_Dirty:128kB Anonymous:128kB".to_string(),
    ];
    (maps, smaps)
}

/// Build a canonical synthetic `schema: 1` `Profile` for `selftest` and unit tests.
#[inline(never)]
pub fn synthetic_default_profile(label: &str, tree: bool) -> Profile {
    const BASE_JSON: &str = concat!(
        r#"{"schema":1,"source":{"masker":"synthetic","profile":"single","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","observer_uid":2000},"identity":{"label":"ci-runner","comm":"ci-runner","argv":["ci-runner","--serve"],"cmdline_raw_nuls":1,"pid":1234,"ppid":1,"uid":2000,"gid":2000,"starttime":123456,"cwd":"/srv/ci","root":"/","exe":"/srv/ci/ci-runner","ns":{"pid":"pid:[4026531836]","mnt":"mnt:[4026531841]","user":"user:[4026531837]","net":"net:[4026531992]"}},"status":{"Name":"ci-runner","State":"S","PPid":1,"Uid":"2000 2000 2000 2000","Gid":"2000 2000 2000 2000","Threads":1,"TracerPid":0,"NoNewPrivs":0,"Seccomp":0,"Seccomp_filters":0,"CapEff":"0000000000000000","CapPrm":"0000000000000000","CapBnd":"0000000000000000","VmLck":0,"RssShmem":0},"stat":{"ppid":1,"num_threads":1,"starttime":123456,"vsize":12345344,"rss":1024,"flags":4194304,"arg_start":140000000000000,"arg_end":140000000000018,"env_start":140000000000018,"env_end":140000000000114,"startstack":140000000000000},"memory":{"maps":[],"smaps":[],"token_present":false,"token_sha256":null,"readable_by":["uid:2000","exe","mem","maps","fd","auxv","environ"],"denied_by":[]},"fds":[{"fd":0,"target":"/dev/null"},{"fd":1,"target":"pipe:[12345]"},{"fd":2,"target":"pipe:[12345]"}],"auxv":{"AT_EXECFN":"/srv/ci/ci-runner","AT_PLATFORM":""#,
        "",
        r#"","AT_BASE":0,"AT_ENTRY":0},"environ":["PATH=/usr/local/bin:/usr/bin:/bin","HOME=/home/runner","LANG=C.UTF-8"],"task":[{"tid":1234,"comm":"ci-runner","state":"S"}],"syscall":{"syscall":"epoll_wait","wchan":"do_epoll_wait","policy":0,"priority":20},"timing":{"exec_ms":3.2,"first_conceal_ms":18.0},"dumpable":true}"#,
    );
    let clean_label = if label.trim().is_empty() {
        "ci-runner"
    } else {
        label.trim()
    };
    let comm: String = clean_label.chars().take(15).collect();
    let exe = cat2("/srv/ci/", clean_label);
    let (maps, smaps) = basic_maps_smaps(&exe, "1001", 1536, 2432);
    let arg_len = (clean_label.len() + 9) as u64;

    let mut root = Profile::parse_str(BASE_JSON).expect("base synth json");
    if tree {
        root.source.profile = "tree".to_string();
    }
    root.identity.label = clean_label.to_string();
    root.identity.comm = comm.clone();
    root.identity.argv[0] = clean_label.to_string();
    root.identity.exe = exe.clone();
    root.status.name = comm.clone();
    root.task[0].comm = comm;
    root.auxv.at_execfn = Some(exe);
    root.auxv.at_platform = Some(std::env::consts::ARCH.to_string());
    root.memory.maps = maps;
    root.memory.smaps = smaps;
    root.stat.arg_end = root.stat.arg_start + arg_len;
    root.stat.env_start = root.stat.arg_end;
    root.stat.env_end = root.stat.env_start + 96;

    if tree {
        let mut child = root.clone();
        child.identity.pid = 1235;
        child.identity.ppid = 1234;
        child.status.ppid = 1234;
        child.stat.ppid = 1234;
        child.identity.starttime = 123_474;
        child.stat.starttime = 123_474;
        child.identity.argv[1] = "--worker".to_string();
        child.stat.arg_end = child.stat.arg_start + (clean_label.len() + 10) as u64;
        child.stat.env_start = child.stat.arg_end;
        child.stat.env_end = child.stat.env_start + 96;
        child.task[0].tid = 1235;
        root.children.push(child);
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_single_and_tree() {
        for tree in [false, true] {
            let prof = synthetic_default_profile("ci-runner", tree);
            prof.validate(&[]).unwrap();
            assert_eq!(prof.stat.vsize % 4096, 0);
            assert_eq!(prof.memory.maps.len(), 3);
            assert_eq!(prof.memory.smaps.len(), 3);
            if tree {
                assert_eq!(
                    prof.children[0].identity.starttime,
                    prof.identity.starttime + 18
                );
            }

            let compact = prof.to_json().to_string();
            let parsed = Profile::parse_str(&compact).unwrap();
            assert_eq!(parsed, prof);

            let pretty = prof.to_json().to_pretty();
            let parsed_pretty = Profile::parse_str(&pretty).unwrap();
            assert_eq!(parsed_pretty, prof);
        }
    }

    #[test]
    fn sanitize_host_home_handles_multiple_and_windows() {
        let s = "/home/alice/a:/home/bob/b /Users/carol/c C:\\Users\\dave\\proj c:/temp/x /home/runner/ok";
        let clean = sanitize_host_home(s);
        assert!(
            contains_host_home_path(&clean, true).is_none(),
            "still had host path: {clean}"
        );
        assert!(clean.contains("/home/runner/ok"));
    }

    #[test]
    fn rejects_unknown_fields_at_every_level() {
        let base = synthetic_default_profile("ci-runner", true);

        // Top-level unknown field
        let mut root = base.to_json();
        if let Json::Obj(ref mut entries) = root {
            entries.push(("bogus".into(), Json::Int(1)));
        }
        assert!(Profile::from_json(&root).is_err());

        // Unknown field inside nested `identity.ns`
        let mut nested = base.to_json();
        if let Json::Obj(ref mut entries) = nested {
            for (k, v) in entries.iter_mut() {
                if k == "identity" {
                    if let Json::Obj(ref mut id_entries) = v {
                        for (ik, iv) in id_entries.iter_mut() {
                            if ik == "ns" {
                                if let Json::Obj(ref mut ns_entries) = iv {
                                    ns_entries.push(("ipc_extra".into(), Json::Str("x".into())));
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(Profile::from_json(&nested).is_err());

        // Unknown field inside `status`
        let mut st_bad = base.to_json();
        if let Json::Obj(ref mut entries) = st_bad {
            for (k, v) in entries.iter_mut() {
                if k == "status" {
                    if let Json::Obj(ref mut s_entries) = v {
                        s_entries.push(("UnknownField".into(), Json::Int(0)));
                    }
                }
            }
        }
        assert!(Profile::from_json(&st_bad).is_err());

        // Unsupported schema version
        let mut ver_bad = base.to_json();
        if let Json::Obj(ref mut entries) = ver_bad {
            for (k, v) in entries.iter_mut() {
                if k == "schema" {
                    *v = Json::Int(2);
                }
            }
        }
        assert!(Profile::from_json(&ver_bad).is_err());
    }

    #[test]
    fn secret_redaction_and_validation() {
        let secret = "SUPER_SECRET_LIVE_TOKEN_987654321";
        let mut prof = synthetic_default_profile("ci-runner", false);
        prof.environ.push(format!("APP_TOKEN={secret}"));
        assert!(prof.validate(&[secret]).is_err());
        assert!(prof.validate(&[]).is_err());

        // Scrubbing replaces secret and prevents leak in serialized JSON.
        let mut found = false;
        prof.environ = prof
            .environ
            .into_iter()
            .map(|e| {
                if let Some((k, v)) = e.split_once('=') {
                    if is_sensitive_env_key(k) {
                        found = true;
                        return format!("{k}=<REDACTED:len={}>", v.len());
                    }
                }
                scrub_tokens(&e, &[secret.to_string()], &mut found)
            })
            .collect();
        prof.memory.token_present = found;
        prof.memory.token_sha256 = None;

        let serialized = prof.to_json().to_pretty();
        assert!(!serialized.contains(secret));
        assert!(prof.memory.token_present);
        assert!(prof.memory.token_sha256.is_none());
        prof.validate(&[secret]).unwrap();
    }

    #[test]
    fn parse_stat_with_spaces_and_parens_in_comm() {
        let sample = b"4242 (my (weird) proc) S 100 4242 4242 0 -1 4194304 10 0 0 0 1 2 0 0 20 0 3 0 98765 52428800 4096 18446744073709551615 1 2 140737488347136 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 3 4 5 140737488348000 140737488348020 140737488348021 140737488348100 0\n";
        let st = parse_proc_stat(sample).unwrap();
        assert_eq!(st.comm, "my (weird) proc");
        assert_eq!(st.state, "S");
        assert_eq!(st.ppid, 100);
        assert_eq!(st.flags, 4_194_304);
        assert_eq!(st.priority, 20);
        assert_eq!(st.num_threads, 3);
        assert_eq!(st.starttime, 98_765);
        assert_eq!(st.vsize, 52_428_800);
        assert_eq!(st.rss, 4096);
        assert_eq!(st.startstack, 140_737_488_347_136);
        assert_eq!(st.arg_start, 140_737_488_348_000);
        assert_eq!(st.arg_end, 140_737_488_348_020);
        assert_eq!(st.env_start, 140_737_488_348_021);
        assert_eq!(st.env_end, 140_737_488_348_100);
        assert!(parse_proc_stat(b"4242 (short) S 100").is_err());
    }

    #[test]
    fn detect_memfd_exe_paths() {
        assert_eq!(
            detect_exe_memfd("/memfd:ci-runner (deleted)"),
            Some("ci-runner".to_string())
        );
        assert_eq!(detect_exe_memfd("memfd:worker"), Some("worker".to_string()));
        assert_eq!(detect_exe_memfd("/usr/bin/sleep"), None);
    }

    #[test]
    fn live_self_pid_extraction_and_roundtrip() {
        let pid = sys::getpid();
        let mut opts = ExtractOpts::for_pid(pid);
        opts.redact_tokens
            .push("DO_NOT_LEAK_SELF_TOKEN".to_string());
        let prof = extract_live(&opts).expect("extract live self pid");
        assert_eq!(prof.schema, PROFILE_SCHEMA);
        assert_eq!(prof.identity.pid, pid);
        assert!(!prof.identity.comm.is_empty());
        assert!(!prof.task.is_empty());
        assert!(prof.memory.token_sha256.is_none());
        prof.validate(&["DO_NOT_LEAK_SELF_TOKEN"]).unwrap();

        let json_str = prof.to_json().to_string();
        assert!(!json_str.contains("DO_NOT_LEAK_SELF_TOKEN"));
        let roundtripped = Profile::parse_str(&json_str).unwrap();
        assert_eq!(roundtripped, prof);
    }

    #[test]
    fn live_child_redaction_and_tree_extraction() {
        let secret = "LIVE_CHILD_SECRET_VALUE_XYZ_999";
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .env("MY_APP_SECRET", secret)
            .env("NORMAL_VAR", format!("holder-{secret}-end"))
            .spawn()
            .expect("spawn sleep child");
        let cpid = child.id() as i32;

        // Extract child directly with redaction.
        let mut child_opts = ExtractOpts::for_pid(cpid);
        child_opts.redact_tokens.push(secret.to_string());
        let cprof = extract_live(&child_opts).expect("extract live child");
        assert_eq!(cprof.identity.pid, cpid);
        assert!(cprof.memory.token_present);
        assert!(cprof.memory.token_sha256.is_none());
        let cjson = cprof.to_json().to_string();
        assert!(!cjson.contains(secret));
        cprof.validate(&[secret]).unwrap();

        // Extract self with tree=true and verify child appears in children.
        let mut tree_opts = ExtractOpts::for_pid(sys::getpid());
        tree_opts.tree = true;
        tree_opts.redact_tokens.push(secret.to_string());
        let tprof = extract_live(&tree_opts).expect("extract live tree");
        assert!(tprof.children.iter().any(|c| c.identity.pid == cpid));
        tprof.validate(&[secret]).unwrap();

        let _ = child.kill();
        let _ = child.wait();
    }
}
