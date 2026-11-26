//! Process profile schema (`schema: 2`), strict JSON validator, secret redaction,
//! host-path sanitization, and live `/proc/<pid>` extractor.

use crate::json::{
    self, cat2, cat3, cat4, csv_has, lossy, next_csv, own, path_lossy, push_i64, push_u64, u64_str,
    JRead, Json, Jw,
};
use crate::sha256;
use crate::sys;
use std::fs;
use std::io;
use std::path::Path;

pub const PROFILE_SCHEMA: u32 = 2;

const MAX_PROC_READ: usize = 4 * 1024 * 1024;
const MAX_MAPS_LINES: usize = 512;
const MAX_SMAPS_LINES: usize = 256;
const MAX_MEM_SCAN_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
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
    pub environ_raw_len: u64,
    pub environ_all_nul: bool,
    pub task: Vec<ProfileTask>,
    pub syscall: ProfileSyscall,
    pub timing: ProfileTiming,
    pub dumpable: Option<bool>,
    pub children: Vec<Profile>,
    pub parent: Option<Box<Profile>>,
    pub tracer: Option<Box<Profile>>,
}

#[inline(never)]
fn default_profile() -> Profile {
    Profile::default()
}

impl Clone for Profile {
    #[inline(never)]
    fn clone(&self) -> Self {
        let s = self.to_json_str(false);
        let mut p = default_profile();
        if let Ok(doc) = json::parse(&s) {
            let _ = fill_profile_json(&doc, &mut p, false);
        }
        p
    }
}

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
pub struct ProfileSource {
    pub masker: String,
    pub profile: String,
    pub version: String,
    pub observer_uid: Option<u32>,
}

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
pub struct ProfileIdentity {
    pub label: String,
    pub comm: String,
    pub argv: Vec<String>,
    pub cmdline_raw_nuls: Option<usize>,
    pub pid: i32,
    pub ppid: i32,
    pub pgid: i32,
    pub sid: i32,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub starttime: u64,
    pub cwd: String,
    pub root: String,
    pub exe: String,
    pub exe_memfd: Option<String>,
    pub ns: ProfileNs,
}

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
pub struct ProfileNs {
    pub pid: Option<String>,
    pub mnt: Option<String>,
    pub user: Option<String>,
    pub net: Option<String>,
}

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
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

#[derive(Clone, Copy, Default)]
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

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
pub struct ProfileMemory {
    pub maps: Vec<String>,
    pub smaps: Vec<String>,
    pub token_present: bool,
    pub token_sha256: Option<String>,
    pub token_len: Option<u32>,
    pub token_charset: Option<String>,
    pub token_placements: Vec<String>,
    pub readable_by: Vec<String>,
    pub denied_by: Vec<String>,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ProfileFd {
    pub fd: i32,
    pub target: String,
}

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
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

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
pub struct ProfileSyscall {
    pub syscall: String,
    pub wchan: String,
    pub policy: i32,
    pub priority: i32,
}

#[derive(Clone, Copy, Default)]
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
    pub ancestors: bool,
    pub redact_tokens: Vec<String>,
    pub redact_envs: Vec<String>,
    pub max_depth: usize,
}

impl ExtractOpts {
    pub fn for_pid(pid: i32) -> Self {
        Self {
            pid,
            label: None,
            masker: own("live"),
            profile_name: own("single"),
            version: own(env!("CARGO_PKG_VERSION")),
            tree: false,
            ancestors: true,
            redact_tokens: Vec::new(),
            redact_envs: Vec::new(),
            max_depth: 4,
        }
    }
}

/// Read newline-separated redaction tokens from a file (or `"-"` for stdin),
/// trimming `\r\n` and skipping empty lines.
#[inline(never)]
pub fn read_redact_tokens_file(path: &str) -> Result<Vec<String>, String> {
    let text = if path == "-" {
        let raw = read_fd_bytes(0, MAX_PROC_READ).map_err(|_| own("stdin read failed"))?;
        String::from_utf8(raw).map_err(|_| own("invalid utf-8"))?
    } else {
        json::read_str(Path::new(path))?
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_end_matches('\r');
        if !trimmed.is_empty() {
            out.push(own(trimmed));
        }
    }
    Ok(out)
}

/// Classify a token's character shape without leaking secret suffixes:
/// `"prefix:<pfx>:hex"`, `"prefix:<pfx>:alnum"`, `"hex"`, `"alnum"`, `"base64"`, or `"ascii"`.
#[inline(never)]
pub fn classify_token_charset(tok: &str) -> String {
    if tok.is_empty() {
        return own("ascii");
    }
    if let Some(pos) = tok.bytes().rposition(|b| b == b'-' || b == b'_') {
        if let (Some(pfx), Some(suffix)) = (tok.get(..=pos), tok.get(pos + 1..)) {
            if pfx.len() >= 2
                && pfx.len() <= 8
                && suffix.len() >= 3
                && suffix.len() >= pfx.len()
                && pfx.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && pfx
                    .bytes()
                    .all(|b| b.is_ascii_alphabetic() || b == b'-' || b == b'_')
            {
                if suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return cat3("prefix:", pfx, ":hex");
                }
                if suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return cat3("prefix:", pfx, ":alnum");
                }
            }
        }
    }
    own(if tok.bytes().all(|b| b.is_ascii_hexdigit()) {
        "hex"
    } else if tok.bytes().all(|b| b.is_ascii_alphanumeric()) {
        "alnum"
    } else if tok
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
    {
        "base64"
    } else {
        "ascii"
    })
}

#[allow(dead_code)]
fn push_sized_token(out: &mut String, token: &str, want: usize) {
    if want == 0 {
        return;
    }
    let src = if token.is_empty() { "x" } else { token };
    let mut rem = want;
    while rem > 0 {
        let mut end = rem.min(src.len());
        while end > 0 && !src.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            out.push('x');
            rem -= 1;
        } else {
            out.push_str(&src[..end]);
            rem -= end;
        }
    }
}

/// Replace `<REDACTED:len=N>` (and `<REDACTED>`) placeholders with `token`,
/// matching exact byte length `N` for length-tagged markers.
#[allow(dead_code)]
#[inline(never)]
pub fn substitute_redacted(s: &str, token: &str) -> String {
    const PFX: &str = "<REDACTED:len=";
    if !s.contains("<REDACTED") {
        return own(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("<REDACTED") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        if let Some(num_rest) = after.strip_prefix(PFX) {
            if let Some(gt) = num_rest.find('>') {
                if let Some(want_u64) = json::parse_u64_s(&num_rest[..gt]) {
                    let want = (want_u64 as usize).min(4096);
                    push_sized_token(&mut out, token, want);
                    rest = &num_rest[gt + 1..];
                    continue;
                }
            }
        }
        if let Some(tail) = after.strip_prefix("<REDACTED>") {
            out.push_str(token);
            rest = tail;
        } else {
            out.push_str("<REDACTED");
            rest = &after[9..];
        }
    }
    out.push_str(rest);
    out
}

#[inline(never)]
fn parse_child_profile(val: &Json, strict: bool) -> Result<Profile, String> {
    let mut p = default_profile();
    fill_profile_json(val, &mut p, strict)?;
    Ok(p)
}

#[inline(never)]
fn parse_opt_profile(val: &Json, key: &str, strict: bool) -> Result<Option<Box<Profile>>, String> {
    match val.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(obj) => Ok(Some(Box::new(parse_child_profile(obj, strict)?))),
    }
}

#[inline(never)]
fn fill_profile_json(val: &Json, p: &mut Profile, strict: bool) -> Result<(), String> {
    let mut r = JRead::new(
        val,
        "schema,source,identity,status,stat,memory,fds,auxv,environ,environ_raw_len,environ_all_nul,task,syscall,timing,dumpable,children,parent,tracer",
        "profile",
    )?;
    p.schema = r.u32("schema");
    if strict && p.schema != PROFILE_SCHEMA {
        return Err(own("bad profile schema"));
    }
    r.fill_str_arr("environ", &mut p.environ);
    p.environ_raw_len = r.u64("environ_raw_len");
    p.environ_all_nul = r.bool("environ_all_nul");
    p.dumpable = r.opt_bool("dumpable");

    if r.enter(val, "source", "masker,profile,version,observer_uid") {
        r.fill_strs(
            "masker,profile,version",
            &mut [
                &mut p.source.masker,
                &mut p.source.profile,
                &mut p.source.version,
            ],
        );
        p.source.observer_uid = r.opt_u32("observer_uid");
    }

    if r.enter(
        val,
        "identity",
        "label,comm,argv,cmdline_raw_nuls,pid,ppid,pgid,sid,uid,gid,groups,starttime,cwd,root,exe,exe_memfd,ns",
    ) {
        p.identity.cmdline_raw_nuls = r.opt_u32("cmdline_raw_nuls").map(|n| n as usize);
        r.fill_strs(
            "label,comm,cwd,root,exe",
            &mut [
                &mut p.identity.label,
                &mut p.identity.comm,
                &mut p.identity.cwd,
                &mut p.identity.root,
                &mut p.identity.exe,
            ],
        );
        r.fill_str_arr("argv", &mut p.identity.argv);
        r.fill_i32s(
            "pid,ppid,pgid,sid",
            &mut [
                &mut p.identity.pid,
                &mut p.identity.ppid,
                &mut p.identity.pgid,
                &mut p.identity.sid,
            ],
        );
        r.fill_u32s("uid,gid", &mut [&mut p.identity.uid, &mut p.identity.gid]);
        p.identity.groups = r.u32_arr("groups", false);
        p.identity.starttime = r.u64("starttime");
        r.fill_opt_str("exe_memfd", &mut p.identity.exe_memfd);
        let id_val = val.get("identity").unwrap_or(&Json::Null);
        if r.enter(id_val, "ns", "pid,mnt,user,net") {
            r.fill_opt_strs(
                "pid,mnt,user,net",
                &mut [
                    &mut p.identity.ns.pid,
                    &mut p.identity.ns.mnt,
                    &mut p.identity.ns.user,
                    &mut p.identity.ns.net,
                ],
            );
        }
    }

    if r.enter(
        val,
        "status",
        "Name,State,PPid,Uid,Gid,Threads,TracerPid,NoNewPrivs,Seccomp,Seccomp_filters,CapEff,CapPrm,CapBnd,VmLck,RssShmem",
    ) {
        r.fill_strs(
            "Name,State,Uid,Gid,CapEff,CapPrm,CapBnd",
            &mut [
                &mut p.status.name,
                &mut p.status.state,
                &mut p.status.uid,
                &mut p.status.gid,
                &mut p.status.cap_eff,
                &mut p.status.cap_prm,
                &mut p.status.cap_bnd,
            ],
        );
        r.fill_i32s("PPid,TracerPid", &mut [&mut p.status.ppid, &mut p.status.tracer_pid]);
        r.fill_u32s(
            "Threads,NoNewPrivs,Seccomp,Seccomp_filters",
            &mut [
                &mut p.status.threads,
                &mut p.status.no_new_privs,
                &mut p.status.seccomp,
                &mut p.status.seccomp_filters,
            ],
        );
        r.fill_opt_u64s("VmLck,RssShmem", &mut [&mut p.status.vm_lck, &mut p.status.rss_shmem]);
    }

    if r.enter(
        val,
        "stat",
        "ppid,num_threads,starttime,vsize,rss,flags,arg_start,arg_end,env_start,env_end,startstack",
    ) {
        p.stat.ppid = r.i32("ppid");
        p.stat.num_threads = r.u32("num_threads");
        p.stat.flags = r.opt_u64("flags");
        r.fill_u64s(
            "starttime,vsize,rss,arg_start,arg_end,env_start,env_end,startstack",
            &mut [
                &mut p.stat.starttime,
                &mut p.stat.vsize,
                &mut p.stat.rss,
                &mut p.stat.arg_start,
                &mut p.stat.arg_end,
                &mut p.stat.env_start,
                &mut p.stat.env_end,
                &mut p.stat.startstack,
            ],
        );
    }

    if r.enter(
        val,
        "memory",
        "maps,smaps,token_present,token_sha256,token_len,token_charset,token_placements,readable_by,denied_by",
    ) {
        r.fill_str_arrs(
            "maps,smaps,token_placements,readable_by,denied_by",
            &mut [
                &mut p.memory.maps,
                &mut p.memory.smaps,
                &mut p.memory.token_placements,
                &mut p.memory.readable_by,
                &mut p.memory.denied_by,
            ],
        );
        p.memory.token_present = r.bool("token_present");
        p.memory.token_len = r.opt_u32("token_len");
        r.fill_opt_strs(
            "token_sha256,token_charset",
            &mut [&mut p.memory.token_sha256, &mut p.memory.token_charset],
        );
    }

    if r.enter(val, "auxv", "AT_EXECFN,AT_PLATFORM,AT_BASE,AT_ENTRY") {
        r.fill_opt_strs(
            "AT_EXECFN,AT_PLATFORM",
            &mut [&mut p.auxv.at_execfn, &mut p.auxv.at_platform],
        );
        r.fill_u64s(
            "AT_BASE,AT_ENTRY",
            &mut [&mut p.auxv.at_base, &mut p.auxv.at_entry],
        );
    }

    if r.enter(val, "syscall", "syscall,wchan,policy,priority") {
        r.fill_strs(
            "syscall,wchan",
            &mut [&mut p.syscall.syscall, &mut p.syscall.wchan],
        );
        r.fill_i32s(
            "policy,priority",
            &mut [&mut p.syscall.policy, &mut p.syscall.priority],
        );
    }

    if r.enter(val, "timing", "exec_ms,first_conceal_ms") {
        p.timing.exec_ms = r.f64("exec_ms");
        p.timing.first_conceal_ms = r.f64("first_conceal_ms");
    }

    r.check()?;

    for item in val.req_arr("fds")? {
        let mut fr = JRead::new(item, "fd,target", "fds")?;
        let fd = fr.i32("fd");
        let target = fr.str_ref("target");
        fr.check()?;
        if strict && fd < 0 {
            return Err(own("fds.fd < 0"));
        }
        p.fds.push(ProfileFd {
            fd,
            target: own(target),
        });
    }

    for item in val.req_arr("task")? {
        let mut tr = JRead::new(item, "tid,comm,state", "task")?;
        let (tid, comm, state) = (tr.i32("tid"), tr.str_ref("comm"), tr.str_ref("state"));
        tr.check()?;
        p.task.push(ProfileTask {
            tid,
            comm: own(comm),
            state: own(state),
        });
    }

    match val.get("children") {
        None | Some(Json::Null) => {}
        Some(Json::Arr(arr)) => {
            p.children.reserve(arr.len());
            for child in arr {
                p.children.push(parse_child_profile(child, strict)?);
            }
        }
        Some(_) => return Err(own("profile.children: expected array")),
    }
    p.parent = parse_opt_profile(val, "parent", strict)?;
    p.tracer = parse_opt_profile(val, "tracer", strict)?;
    Ok(())
}

impl Profile {
    /// Parse a JSON string into a strictly validated `schema: 2` `Profile`.
    #[inline(never)]
    pub fn parse_str(input: &str) -> Result<Profile, String> {
        let doc = json::parse(input)?;
        Profile::from_json(&doc)
    }

    /// Parse a `Json` DOM into a `Profile`, rejecting unknown fields at every level
    /// and enforcing `schema == 2`.
    #[inline(never)]
    pub fn from_json(val: &Json) -> Result<Profile, String> {
        parse_child_profile(val, true)
    }

    #[inline(never)]
    pub fn write_json(&self, w: &mut Jw) {
        w.obj_open();
        w.k_i64("schema", self.schema as i64);

        w.k_obj("source");
        w.k_strs(
            "masker,profile,version",
            &[
                &self.source.masker,
                &self.source.profile,
                &self.source.version,
            ],
        );
        w.k_some_u64("observer_uid", self.source.observer_uid.map(u64::from));
        w.obj_close();

        w.k_obj("identity");
        w.k_strs(
            "label,comm,cwd,root,exe",
            &[
                &self.identity.label,
                &self.identity.comm,
                &self.identity.cwd,
                &self.identity.root,
                &self.identity.exe,
            ],
        );
        w.k_str_arr("argv", &self.identity.argv);
        w.k_some_u64(
            "cmdline_raw_nuls",
            self.identity.cmdline_raw_nuls.map(|n| n as u64),
        );
        w.k_i64s(
            "pid,ppid,pgid,sid,uid,gid",
            &[
                self.identity.pid as i64,
                self.identity.ppid as i64,
                self.identity.pgid as i64,
                self.identity.sid as i64,
                self.identity.uid as i64,
                self.identity.gid as i64,
            ],
        );
        w.k_u32_arr("groups", &self.identity.groups);
        w.k_u64("starttime", self.identity.starttime);
        w.k_some_str("exe_memfd", &self.identity.exe_memfd);
        w.k_obj("ns");
        w.k_some_strs(
            "pid,mnt,user,net",
            &[
                &self.identity.ns.pid,
                &self.identity.ns.mnt,
                &self.identity.ns.user,
                &self.identity.ns.net,
            ],
        );
        w.obj_close();
        w.obj_close();

        w.k_obj("status");
        w.k_strs(
            "Name,State,Uid,Gid,CapEff,CapPrm,CapBnd",
            &[
                &self.status.name,
                &self.status.state,
                &self.status.uid,
                &self.status.gid,
                &self.status.cap_eff,
                &self.status.cap_prm,
                &self.status.cap_bnd,
            ],
        );
        w.k_i64s(
            "PPid,Threads,TracerPid,NoNewPrivs,Seccomp,Seccomp_filters",
            &[
                self.status.ppid as i64,
                self.status.threads as i64,
                self.status.tracer_pid as i64,
                self.status.no_new_privs as i64,
                self.status.seccomp as i64,
                self.status.seccomp_filters as i64,
            ],
        );
        w.k_some_u64("VmLck", self.status.vm_lck);
        w.k_some_u64("RssShmem", self.status.rss_shmem);
        w.obj_close();

        w.k_obj("stat");
        w.k_i64s(
            "ppid,num_threads",
            &[self.stat.ppid as i64, self.stat.num_threads as i64],
        );
        w.k_u64s(
            "starttime,vsize,rss,arg_start,arg_end,env_start,env_end,startstack",
            &[
                self.stat.starttime,
                self.stat.vsize,
                self.stat.rss,
                self.stat.arg_start,
                self.stat.arg_end,
                self.stat.env_start,
                self.stat.env_end,
                self.stat.startstack,
            ],
        );
        w.k_some_u64("flags", self.stat.flags);
        w.obj_close();

        w.k_obj("memory");
        w.k_str_arrs(
            "maps,smaps,token_placements,readable_by,denied_by",
            &[
                &self.memory.maps,
                &self.memory.smaps,
                &self.memory.token_placements,
                &self.memory.readable_by,
                &self.memory.denied_by,
            ],
        );
        w.k_bool("token_present", self.memory.token_present);
        w.k_opt_str("token_sha256", &self.memory.token_sha256);
        w.k_some_u64("token_len", self.memory.token_len.map(u64::from));
        w.k_some_str("token_charset", &self.memory.token_charset);
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
        w.k_u64s("AT_BASE,AT_ENTRY", &[self.auxv.at_base, self.auxv.at_entry]);
        w.obj_close();

        w.k_str_arr("environ", &self.environ);
        w.k_u64("environ_raw_len", self.environ_raw_len);
        w.k_bool("environ_all_nul", self.environ_all_nul);

        w.k_arr("task");
        for t in &self.task {
            w.elem_obj();
            w.k_i64("tid", t.tid as i64);
            w.k_strs("comm,state", &[&t.comm, &t.state]);
            w.obj_close();
        }
        w.arr_close();

        w.k_obj("syscall");
        w.k_strs(
            "syscall,wchan",
            &[&self.syscall.syscall, &self.syscall.wchan],
        );
        w.k_i64s(
            "policy,priority",
            &[self.syscall.policy as i64, self.syscall.priority as i64],
        );
        w.obj_close();

        w.k_obj("timing");
        w.k_f64("exec_ms", self.timing.exec_ms);
        w.k_f64("first_conceal_ms", self.timing.first_conceal_ms);
        w.obj_close();

        if let Some(d) = self.dumpable {
            w.k_bool("dumpable", d);
        }
        w.k_arr("children");
        for child in &self.children {
            w.elem();
            child.write_json(w);
        }
        w.arr_close();
        for (k, opt) in [("parent", &self.parent), ("tracer", &self.tracer)] {
            if let Some(ref p) = opt {
                w.key(k);
                p.write_json(w);
            }
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
    #[inline(never)]
    pub fn validate(&self, forbidden_secrets: &[&str]) -> Result<(), String> {
        self.validate_inner(forbidden_secrets, true)
    }

    fn validate_inner(
        &self,
        forbidden_secrets: &[&str],
        check_serialized: bool,
    ) -> Result<(), String> {
        let bad = if self.schema != PROFILE_SCHEMA {
            Some("bad schema")
        } else if self.identity.comm.trim().is_empty() || self.identity.label.trim().is_empty() {
            Some("empty comm/label")
        } else if self.identity.pid < 0 || self.identity.ppid < 0 {
            Some("negative pid/ppid")
        } else if self.status.threads == 0 || self.stat.num_threads == 0 {
            Some("zero threads")
        } else if self.memory.token_sha256.as_deref().is_some_and(|h| {
            h.len() != 64 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        }) {
            Some("bad token_sha256")
        } else if self
            .memory
            .token_placements
            .iter()
            .any(|pl| !csv_has("anon,argv,environ,heap,stack", pl))
        {
            Some("bad token_placements")
        } else if !self.timing.exec_ms.is_finite()
            || self.timing.exec_ms < 0.0
            || !self.timing.first_conceal_ms.is_finite()
            || self.timing.first_conceal_ms < 0.0
        {
            Some("bad timing")
        } else {
            None
        };
        if let Some(msg) = bad {
            return Err(own(msg));
        }

        for entry in &self.environ {
            if let Some((k, v)) = entry.split_once('=') {
                if is_sensitive_env_key(k) && !v.is_empty() && !v.starts_with("<REDACTED") {
                    return Err(cat2("unredacted env ", k));
                }
            }
            if contains_unredacted_secret_pattern(entry) {
                return Err(own("secret in environ"));
            }
        }
        for arg in &self.identity.argv {
            if contains_unredacted_secret_pattern(arg) {
                return Err(own("secret in argv"));
            }
        }

        if check_serialized && !forbidden_secrets.is_empty() {
            let serialized = self.to_json_str(false);
            for &secret in forbidden_secrets {
                if !secret.is_empty() && serialized.contains(secret) {
                    return Err(own("forbidden secret leaked"));
                }
            }
        }

        if let Some(ref p) = self.parent {
            p.validate_inner(forbidden_secrets, false)?;
        }
        if let Some(ref p) = self.tracer {
            p.validate_inner(forbidden_secrets, false)?;
        }
        for child in &self.children {
            child.validate_inner(forbidden_secrets, false)?;
        }
        Ok(())
    }
}

fn contains_ascii_ci(hay: &str, needle_upper: &[u8]) -> bool {
    let hb = hay.as_bytes();
    needle_upper.len() <= hb.len()
        && hb.windows(needle_upper.len()).any(|w| {
            w.iter()
                .zip(needle_upper.iter())
                .all(|(&a, &b)| a.to_ascii_uppercase() == b)
        })
}

#[inline(never)]
pub fn is_sensitive_env_key(key: &str) -> bool {
    let mut csv = "SECRET,TOKEN,PASSWORD,PASSWD,API_KEY,APIKEY,PRIVATE_KEY,CREDENTIAL,AUTH_KEY";
    while !csv.is_empty() {
        if contains_ascii_ci(key, next_csv(&mut csv).as_bytes()) {
            return true;
        }
    }
    false
}

fn is_akia_at(b: &[u8]) -> bool {
    b.len() >= 20
        && b.starts_with(b"AKIA")
        && b.get(4..20).is_some_and(|s| {
            s.iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        })
}

#[inline(never)]
pub fn contains_unredacted_secret_pattern(s: &str) -> bool {
    if (s.contains("-----BEGIN ") && s.contains("PRIVATE KEY-----"))
        || s.contains("ghp_")
        || s.contains("github_pat_")
        || s.contains("xoxb-")
        || s.contains("xoxp-")
    {
        return true;
    }
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(19) {
        if let Some(rest) = bytes.get(i..) {
            if is_akia_at(rest) {
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
    matches!(
        (b.get(i), b.get(i + 1), b.get(i + 2)),
        (Some(c), Some(&b':'), Some(b'\\' | b'/')) if c.is_ascii_alphabetic()
    ) && !(i > 0 && b.get(i - 1).is_some_and(u8::is_ascii_alphanumeric))
}

fn is_runner_home(after: &str) -> bool {
    after.starts_with("runner")
        && matches!(
            after.as_bytes().get(6).copied(),
            None | Some(b'"' | b'/' | b':' | b' ' | b'\n' | b'\0')
        )
}

/// Detect host home paths (`/Users/`, `/home/<non-runner>`, or Windows drive paths `C:\`).
#[inline(never)]
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
    while let Some(rel) = text.get(start..).and_then(|t| t.find("/home/")) {
        let pos = start + rel + 6;
        if !(allow_synthetic_runner && text.get(pos..).is_some_and(is_runner_home)) {
            return Some("/home/");
        }
        start = pos;
    }
    None
}

/// Sanitize ALL occurrences of `/Users/<user>`, `/home/<user>` (except synthetic `/home/runner`),
/// and Windows drive paths (`C:\...`, `c:/...`) into neutral `/srv/work` paths.
#[inline(never)]
pub fn sanitize_host_home(s: &str) -> String {
    let mut mid = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let p_u = rest.find("/Users/");
        let p_h = rest.find("/home/");
        let next = match (p_u, p_h) {
            (Some(a), Some(b)) if a <= b => Some((a, 7usize, false)),
            (Some(_), Some(b)) => Some((b, 6, true)),
            (Some(a), None) => Some((a, 7, false)),
            (None, Some(b)) => Some((b, 6, true)),
            (None, None) => None,
        };
        let Some((pos, plen, is_home)) = next else {
            mid.push_str(rest);
            break;
        };
        mid.push_str(rest.get(..pos).unwrap_or(""));
        let after = rest.get(pos + plen..).unwrap_or("");
        if is_home && is_runner_home(after) {
            mid.push_str("/home/");
            rest = after;
        } else {
            let uend = after
                .bytes()
                .position(|b| matches!(b, b'/' | b':' | b' ' | b'"' | b'\'' | b'\n' | b'\0'))
                .unwrap_or(after.len());
            mid.push_str("/srv/work");
            rest = after.get(uend..).unwrap_or("");
        }
    }

    let bytes = mid.as_bytes();
    let mut out = String::with_capacity(mid.len());
    let mut i = 0usize;
    let mut copied = 0usize;
    while i + 2 < bytes.len() {
        if !is_win_drive(bytes, i) {
            i += 1;
            continue;
        }
        out.push_str(mid.get(copied..i).unwrap_or(""));
        let after = mid.get(i + 3..).unwrap_or("");
        let seg_end = after
            .bytes()
            .position(|b| {
                matches!(
                    b,
                    b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b';' | b'\0'
                )
            })
            .unwrap_or(after.len());
        let mut tail = String::with_capacity(seg_end);
        for c in after.get(..seg_end).unwrap_or("").chars() {
            tail.push(if c == '\\' { '/' } else { c });
        }
        let trimmed = if let Some(au) = tail
            .strip_prefix("Users/")
            .or_else(|| tail.strip_prefix("users/"))
        {
            let uend = au.find('/').unwrap_or(au.len());
            au.get(uend..).unwrap_or("").trim_start_matches('/')
        } else {
            tail.as_str()
        };
        out.push_str("/srv/work");
        if !trimmed.is_empty() {
            out.push('/');
            out.push_str(trimmed);
        }
        i += 3 + seg_end;
        copied = i;
    }
    out.push_str(mid.get(copied..).unwrap_or(""));
    out
}

fn strip_proc_newline(raw: &[u8]) -> String {
    let mut s = raw;
    if let Some(t) = s.strip_suffix(b"\n") {
        s = t;
    }
    if let Some(t) = s.strip_suffix(b"\r") {
        s = t;
    }
    lossy(s)
}

#[inline(never)]
fn find_inline_secret_bytes(hay: &[u8]) -> Option<&[u8]> {
    const RULES: &[(&[u8], usize, usize, u8)] = &[
        (b"TOK-", 10, 68, 7),
        (b"github_pat_", 21, 107, 2),
        (b"ghp_", 14, 68, 0),
        (b"xoxb-", 13, 69, 1),
        (b"xoxp-", 13, 69, 1),
    ];
    for i in 0..hay.len() {
        let Some(rest) = hay.get(i..) else { break };
        let boundary = i == 0 || !hay.get(i - 1).is_some_and(u8::is_ascii_alphanumeric);
        for &(pfx, min_len, max_len, flags) in RULES {
            if ((flags & 4) == 0 || boundary) && rest.starts_with(pfx) {
                let mut end = pfx.len();
                let lim = rest.len().min(max_len);
                while let Some(&b) = rest.get(end) {
                    if end >= lim
                        || !(b.is_ascii_alphanumeric()
                            || ((flags & 1) != 0 && b == b'-')
                            || ((flags & 2) != 0 && b == b'_'))
                    {
                        break;
                    }
                    end += 1;
                }
                if end >= min_len {
                    return rest.get(..end);
                }
            }
        }
        if boundary && is_akia_at(rest) {
            return rest.get(..20);
        }
    }
    None
}

fn find_inline_secret_str(s: &str) -> Option<&str> {
    find_inline_secret_bytes(s.as_bytes()).and_then(|b| std::str::from_utf8(b).ok())
}

fn redacted_marker(len: usize) -> String {
    cat3("<REDACTED:len=", &u64_str(len as u64), ">")
}

#[inline(never)]
fn scrub_tokens_with<'a>(
    s: &str,
    tokens: &'a [String],
    matched: &mut Option<&'a str>,
) -> (String, bool) {
    let mut out = own(s);
    let mut hit = false;
    for tok in tokens {
        if !tok.is_empty() && out.contains(tok.as_str()) {
            hit = true;
            if matched.is_none() {
                *matched = Some(tok.as_str());
            }
            out = out.replace(tok.as_str(), &redacted_marker(tok.len()));
        }
    }
    (out, hit)
}

#[cfg(test)]
fn scrub_tokens(s: &str, tokens: &[String], found: &mut bool) -> String {
    let mut m = None;
    let (out, hit) = scrub_tokens_with(s, tokens, &mut m);
    if hit {
        *found = true;
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
fn read_fd_bytes(fd: i32, max_len: usize) -> Result<Vec<u8>, i32> {
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
            return Err(e);
        }
    }
    Ok(out)
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
    let res = read_fd_bytes(fd, max_len);
    sys::close(fd);
    res
}

#[inline(never)]
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
    (!name.is_empty()).then(|| own(name))
}

fn parse_cmdline(raw: &[u8]) -> (Vec<String>, usize) {
    let mut end = raw.len();
    while end > 0 && raw.get(end - 1) == Some(&0) {
        end -= 1;
    }
    let trailing_nuls = raw.len() - end;
    let mut argv = Vec::new();
    if let Some(body) = raw.get(..end) {
        if !body.is_empty() {
            for part in body.split(|&b| b == 0) {
                argv.push(lossy(part));
            }
        }
    }
    (argv, trailing_nuls)
}

#[derive(Default)]
struct ParsedStat {
    comm: String,
    state: String,
    ppid: i32,
    pgid: i32,
    sid: i32,
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

#[inline(never)]
fn parse_proc_stat(raw: &[u8]) -> Result<ParsedStat, String> {
    let (Some(open), Some(close)) = (
        raw.iter().position(|&b| b == b'('),
        raw.iter().rposition(|&b| b == b')'),
    ) else {
        return Err(own("bad stat"));
    };
    let Some(comm_b) = raw.get(open + 1..close) else {
        return Err(own("bad stat"));
    };
    let mut ps = ParsedStat {
        comm: lossy(comm_b),
        ..Default::default()
    };
    let rest = raw
        .get(close + 1..)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("");
    let mut count = 0usize;
    let mut req_mask = 0u8;
    for (idx, tok) in rest.split_ascii_whitespace().enumerate() {
        count = idx + 1;
        if idx == 0 {
            json::assign_str(&mut ps.state, tok);
            continue;
        }
        let u_opt = json::parse_u64_s(tok);
        let u = u_opt.unwrap_or(0);
        let iv = || json::parse_i32_s(tok);
        match idx {
            1 => {
                if let Some(v) = iv() {
                    ps.ppid = v;
                    req_mask |= 1;
                }
            }
            2 => ps.pgid = iv().unwrap_or(0),
            3 => ps.sid = iv().unwrap_or(0),
            6 => ps.flags = u,
            15 => ps.priority = iv().unwrap_or(0),
            17 => {
                if u_opt.is_some() {
                    ps.num_threads = u.max(1) as u32;
                    req_mask |= 2;
                }
            }
            19 => {
                if u_opt.is_some() {
                    ps.starttime = u;
                    req_mask |= 4;
                }
            }
            20 => {
                if u_opt.is_some() {
                    ps.vsize = u;
                    req_mask |= 8;
                }
            }
            21 => {
                if u_opt.is_some() {
                    ps.rss = u;
                    req_mask |= 16;
                }
            }
            25 => ps.startstack = u,
            38 => ps.policy = iv().unwrap_or(0),
            45 => ps.arg_start = u,
            46 => ps.arg_end = u,
            47 => ps.env_start = u,
            48 => ps.env_end = u,
            _ => {}
        }
    }
    if count < 22 || req_mask != 0b11111 {
        return Err(own("bad stat"));
    }
    Ok(ps)
}

fn parse_status_kb_field(val: &str) -> Option<u64> {
    val.split_ascii_whitespace()
        .next()
        .and_then(json::parse_u64_s)
}

#[inline(never)]
fn parse_ugid(val: &str, dst: &mut String, eff: &mut u32) {
    dst.clear();
    let mut real = 0u32;
    let mut got_eff = false;
    for (i, part) in val.split_ascii_whitespace().enumerate() {
        if i > 0 {
            dst.push(' ');
        }
        dst.push_str(part);
        if i == 0 {
            real = json::parse_u32_s(part).unwrap_or(0);
        } else if i == 1 {
            if let Some(v) = json::parse_u32_s(part) {
                *eff = v;
                got_eff = true;
            }
        }
    }
    if !got_eff {
        *eff = real;
    }
}

#[inline(never)]
fn default_status() -> ProfileStatus {
    ProfileStatus {
        state: own("S"),
        uid: own("0 0 0 0"),
        gid: own("0 0 0 0"),
        threads: 1,
        cap_eff: own("0000000000000000"),
        cap_prm: own("0000000000000000"),
        cap_bnd: own("0000000000000000"),
        ..Default::default()
    }
}

#[inline(never)]
fn parse_proc_status(raw: &[u8]) -> (ProfileStatus, u32, u32, Vec<u32>) {
    let mut st = default_status();
    let mut euid = 0u32;
    let mut egid = 0u32;
    let mut groups = Vec::new();
    let text = lossy(raw);
    for line in text.lines() {
        let Some((k, raw_v)) = line.split_once(':') else {
            continue;
        };
        if k == "Name" {
            json::assign_str(&mut st.name, raw_v.trim_start_matches('\t'));
            continue;
        }
        let v = raw_v.trim();
        let u32v = json::parse_u32_s(v).unwrap_or(0);
        let i32v = json::parse_i32_s(v).unwrap_or(0);
        match k {
            "State" => {
                if let Some(code) = v.split_ascii_whitespace().next() {
                    json::assign_str(&mut st.state, code);
                }
            }
            "Uid" => parse_ugid(v, &mut st.uid, &mut euid),
            "Gid" => parse_ugid(v, &mut st.gid, &mut egid),
            "Groups" => {
                for tok in v.split_ascii_whitespace() {
                    if let Some(g) = json::parse_u32_s(tok) {
                        groups.push(g);
                    }
                }
            }
            "CapEff" => json::assign_str(&mut st.cap_eff, v),
            "CapPrm" => json::assign_str(&mut st.cap_prm, v),
            "CapBnd" => json::assign_str(&mut st.cap_bnd, v),
            "PPid" => st.ppid = i32v,
            "TracerPid" => st.tracer_pid = i32v,
            "Threads" => st.threads = u32v,
            "NoNewPrivs" => st.no_new_privs = u32v,
            "Seccomp" => st.seccomp = u32v,
            "Seccomp_filters" => st.seccomp_filters = u32v,
            "VmLck" => st.vm_lck = parse_status_kb_field(v),
            "RssShmem" => st.rss_shmem = parse_status_kb_field(v),
            _ => {}
        }
    }
    st.threads = st.threads.max(1);
    (st, euid, egid, groups)
}

#[inline(never)]
fn format_smaps_entry(hdr: &str, r: u64, p: u64, a: u64) -> String {
    let mut line = String::with_capacity(hdr.len() + 48);
    line.push_str(hdr);
    line.push_str(" Rss:");
    push_u64(&mut line, r);
    line.push_str("kB Private_Dirty:");
    push_u64(&mut line, p);
    line.push_str("kB Anonymous:");
    push_u64(&mut line, a);
    line.push_str("kB");
    line
}

#[inline(never)]
fn normalize_maps(raw: &[u8]) -> Vec<String> {
    let text = lossy(raw);
    let mut out = Vec::new();
    for line in text.lines().take(MAX_MAPS_LINES) {
        let mut parts = line.split_ascii_whitespace();
        let (Some(_), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        let mut s = own("<addr>");
        for p in [
            perms,
            parts.next().unwrap_or("00000000"),
            parts.next().unwrap_or("00:00"),
            parts.next().unwrap_or("0"),
        ] {
            s.push(' ');
            s.push_str(p);
        }
        for p in parts {
            s.push(' ');
            s.push_str(p);
        }
        out.push(s);
    }
    out
}

#[inline(never)]
fn normalize_smaps(raw: &[u8]) -> Vec<String> {
    let text = lossy(raw);
    let mut out = Vec::new();
    let mut cur_header: Option<String> = None;
    let mut counts = [0u64; 3];
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if !k.contains(' ') && !k.contains('-') {
                let idx = match k {
                    "Rss" => Some(0),
                    "Private_Dirty" => Some(1),
                    "Anonymous" => Some(2),
                    _ => None,
                };
                if let Some(i) = idx {
                    counts[i] = parse_status_kb_field(v).unwrap_or(0);
                }
                continue;
            }
        }
        if let Some(h) = cur_header.take() {
            if out.len() < MAX_SMAPS_LINES {
                out.push(format_smaps_entry(&h, counts[0], counts[1], counts[2]));
            }
        }
        counts = [0; 3];
        let mut parts = line.split_ascii_whitespace();
        let _addr = parts.next();
        let mut hdr = own(parts.next().unwrap_or("----"));
        let mut any = false;
        for p in parts.skip(3) {
            hdr.push(' ');
            hdr.push_str(p);
            any = true;
        }
        if !any {
            hdr.push_str(" [anon]");
        }
        cur_header = Some(hdr);
    }
    if let Some(h) = cur_header {
        if out.len() < MAX_SMAPS_LINES {
            out.push(format_smaps_entry(&h, counts[0], counts[1], counts[2]));
        }
    }
    out
}

#[inline(never)]
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
    let slice = buf.get(..usize::try_from(n).ok()?)?;
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    (nul > 0).then(|| lossy(slice.get(..nul).unwrap_or(b"")))
}

#[inline(never)]
fn parse_auxv(pid: i32, raw: &[u8], exe_fallback: &str, mem_readable: bool) -> ProfileAuxv {
    const W: usize = std::mem::size_of::<usize>();
    let mut aux = ProfileAuxv::default();
    let mut execfn_ptr = 0u64;
    let mut platform_ptr = 0u64;

    for chunk in raw.chunks_exact(W * 2) {
        let (Some(ab), Some(vb)) = (chunk.get(..W), chunk.get(W..W * 2)) else {
            break;
        };
        let (Ok(a_arr), Ok(v_arr)) = (ab.try_into(), vb.try_into()) else {
            break;
        };
        let a_type = usize::from_ne_bytes(a_arr);
        let a_val = usize::from_ne_bytes(v_arr) as u64;
        match a_type {
            0 => break,
            7 => aux.at_base = a_val,
            9 => aux.at_entry = a_val,
            15 => platform_ptr = a_val,
            31 => execfn_ptr = a_val,
            _ => {}
        }
    }

    if execfn_ptr != 0 {
        aux.at_execfn = mem_readable
            .then(|| read_mem_cstring(pid, execfn_ptr))
            .flatten()
            .or_else(|| (!exe_fallback.is_empty()).then(|| own(exe_fallback)));
    }
    if platform_ptr != 0 {
        aux.at_platform = mem_readable
            .then(|| read_mem_cstring(pid, platform_ptr))
            .flatten()
            .or_else(|| Some(own(std::env::consts::ARCH)));
    }
    aux
}

#[inline(never)]
fn parse_proc_syscall(raw: &[u8]) -> String {
    const TABLE: &[(libc::c_long, &str)] = &[
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_poll, "poll"),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_select, "select"),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_pause, "pause"),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_epoll_wait, "epoll_wait"),
        (libc::SYS_read, "read"),
        (libc::SYS_write, "write"),
        (libc::SYS_ppoll, "ppoll"),
        (libc::SYS_pselect6, "pselect6"),
        (libc::SYS_epoll_pwait, "epoll_pwait"),
        (libc::SYS_nanosleep, "nanosleep"),
        (libc::SYS_clock_nanosleep, "clock_nanosleep"),
        (libc::SYS_futex, "futex"),
        (libc::SYS_wait4, "wait4"),
        (libc::SYS_rt_sigsuspend, "rt_sigsuspend"),
        (libc::SYS_accept4, "accept4"),
        (libc::SYS_recvfrom, "recvfrom"),
    ];
    let text = lossy(raw);
    let first = text.split_ascii_whitespace().next().unwrap_or("");
    if first.is_empty() {
        return own("unknown");
    }
    if first == "running" {
        return own("running");
    }
    match json::parse_i64_s(first) {
        Some(nr) if nr >= 0 => {
            let cnr = nr as libc::c_long;
            if (cnr as i64) == nr {
                if let Some(&(_, name)) = TABLE.iter().find(|&&(n, _)| n == cnr) {
                    return own(name);
                }
            }
            cat2("syscall_", &json::i64_str(nr))
        }
        _ => own(first),
    }
}

struct MemScanResult {
    placements: Vec<&'static str>,
    matched_tok: Option<String>,
    matched_explicit: bool,
}

#[inline(never)]
fn parse_hex_u64(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for b in s.bytes() {
        let d = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            _ => return None,
        };
        v = v.checked_mul(16)?.checked_add(d)?;
    }
    Some(v)
}

#[inline(never)]
fn find_tok_in_bytes<'a>(hay: &[u8], toks: &'a [String]) -> Option<&'a str> {
    for t in toks {
        let nb = t.as_bytes();
        if !nb.is_empty() && hay.windows(nb.len()).any(|w| w == nb) {
            return Some(t.as_str());
        }
    }
    None
}

/// Scan writable `[stack]`, `[heap]`, and anonymous (`rw*`) memory regions for tokens.
#[inline(never)]
fn scan_anon_mem_for_tokens(
    pid: i32,
    raw_maps: &[u8],
    explicit_tokens: &[String],
    extra_tokens: &[String],
    arg_range: (u64, u64),
    env_range: (u64, u64),
) -> MemScanResult {
    let mut res = MemScanResult {
        placements: Vec::new(),
        matched_tok: None,
        matched_explicit: false,
    };

    let mut max_needle = 0usize;
    for toks in [explicit_tokens, extra_tokens] {
        for t in toks {
            max_needle = max_needle.max(t.len());
        }
    }
    let has_needles = max_needle > 0;
    if !has_needles {
        max_needle = 108;
    }

    let path = proc_path(pid, "mem");
    let fd = sys::open(path.as_bytes(), libc::O_RDONLY | libc::O_CLOEXEC, 0);
    if fd < 0 {
        return res;
    }

    let text = lossy(raw_maps);
    let mut regions: Vec<(u8, u8, u64, u64)> = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_ascii_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !perms.starts_with("rw") {
            continue;
        }
        let pathname = parts.nth(3).unwrap_or("");
        let (prio, pbit) = if pathname == "[stack]" || pathname.starts_with("[stack:") {
            (0u8, 0u8)
        } else if pathname == "[heap]" {
            (1u8, 1u8)
        } else if pathname.is_empty() || pathname.starts_with("[anon") {
            (2u8, 2u8)
        } else {
            continue;
        };
        let Some((s_hex, e_hex)) = range.split_once('-') else {
            continue;
        };
        let (Some(start), Some(end)) = (parse_hex_u64(s_hex), parse_hex_u64(e_hex)) else {
            continue;
        };
        if end > start {
            let p = if prio == 2 && (end - start) > 1024 * 1024 {
                3
            } else {
                prio
            };
            regions.push((p, pbit, start, end));
        }
    }

    let mut total_scanned = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    let overlap = max_needle.saturating_sub(1).min(buf.len() / 2);
    let mut found_mask = 0u8;

    'scan: for target_prio in 0..=3u8 {
        for &(prio, pbit, start, end) in &regions {
            if prio != target_prio || (found_mask & (1 << pbit)) != 0 {
                continue;
            }
            let mut addr = start;
            while addr < end && total_scanned < MAX_MEM_SCAN_BYTES {
                let rem = (end - addr).min((MAX_MEM_SCAN_BYTES - total_scanned) as u64);
                let want = (rem as usize).min(buf.len());
                let Some(dst) = buf.get_mut(..want) else {
                    break;
                };
                let n = sys::pread_fd(fd, dst, addr);
                if n <= 0 {
                    break;
                }
                let got = n as usize;
                total_scanned += got;
                if pbit == 0 {
                    for &(ex_s, ex_e) in &[arg_range, env_range] {
                        if ex_s < ex_e {
                            let ov_s = addr.max(ex_s);
                            let ov_e = (addr + got as u64).min(ex_e);
                            if ov_s < ov_e {
                                if let Some(sl) =
                                    buf.get_mut((ov_s - addr) as usize..(ov_e - addr) as usize)
                                {
                                    sl.fill(0);
                                }
                            }
                        }
                    }
                }
                let hay = buf.get(..got).unwrap_or(b"");
                let mut hit_here = false;
                if has_needles {
                    for (is_exp, toks) in [(true, explicit_tokens), (false, extra_tokens)] {
                        if let Some(t) = find_tok_in_bytes(hay, toks) {
                            if (is_exp && !res.matched_explicit) || res.matched_tok.is_none() {
                                res.matched_tok = Some(own(t));
                                res.matched_explicit |= is_exp;
                            }
                            hit_here = true;
                            break;
                        }
                    }
                }
                if !hit_here {
                    if let Some(tok_s) =
                        find_inline_secret_bytes(hay).and_then(|b| std::str::from_utf8(b).ok())
                    {
                        if res.matched_tok.is_none() {
                            res.matched_tok = Some(own(tok_s));
                        }
                        hit_here = true;
                    }
                }
                if hit_here {
                    found_mask |= 1 << pbit;
                    if found_mask == 0b111 {
                        break 'scan;
                    }
                    break;
                }
                if got <= overlap || addr + got as u64 >= end {
                    break;
                }
                addr += (got - overlap) as u64;
            }
        }
    }

    sys::close(fd);
    for (bit, name) in [(2, "anon"), (1, "heap"), (0, "stack")] {
        if (found_mask & (1 << bit)) != 0 {
            res.placements.push(name);
        }
    }
    res
}

fn is_stop_ancestor_comm(comm: &str) -> bool {
    csv_has(
        "init,systemd,podman-init,tini,dumb-init,conmon,catatonit,docker-init,pause,s6-svscan,supervisord,runit,sshd,login",
        comm.trim(),
    )
}

#[inline(never)]
fn should_capture_ancestor(apid: i32, target_uid: u32, is_tracer: bool, visited: &[i32]) -> bool {
    if apid <= 1 || visited.contains(&apid) {
        return false;
    }
    let Ok(status_raw) = read_proc_bytes(&proc_path(apid, "status"), 64 * 1024) else {
        return false;
    };
    let (st, aeuid, _, _) = parse_proc_status(&status_raw);
    !is_stop_ancestor_comm(&st.name) && (aeuid == target_uid || is_tracer)
}

fn push_unique_i32(v: &mut Vec<i32>, x: i32) {
    if !v.contains(&x) {
        v.push(x);
    }
}

fn sort_i32(v: &mut [i32]) {
    json::shell_sort_by(v, |a, b| a > b);
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

#[inline(never)]
fn task_leaf_path(task_dir: &str, tid: i32, leaf: &str) -> String {
    let tid_s = json::i64_str(tid as i64);
    json::concat(&[task_dir, "/", &tid_s, "/", leaf])
}

#[inline(never)]
fn discover_child_pids(pid: i32) -> Vec<i32> {
    let mut children: Vec<i32> = Vec::new();
    let task_dir = proc_path(pid, "task");
    let mut used_proc_children = false;
    if let Ok(tids) = read_numeric_dir(&task_dir) {
        for tid in tids {
            if let Ok(text) = json::read_str(Path::new(&task_leaf_path(&task_dir, tid, "children")))
            {
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
                if cpid > 0 && cpid != pid {
                    if let Ok(raw) = read_proc_bytes(&proc_path(cpid, "stat"), 4096) {
                        if parse_proc_stat(&raw).is_ok_and(|p| p.ppid == pid) {
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
    matched_tok: Option<String>,
    matched_explicit: bool,
    placements: Vec<&'static str>,
    mem_extra_toks: Vec<String>,
    readable: &'a mut Vec<String>,
    denied: &'a mut Vec<String>,
}

impl<'a> ProcCtx<'a> {
    fn path(&self, rel: &str) -> String {
        cat3(&self.dir, "/", rel)
    }

    fn note_placement(&mut self, pl: &'static str) {
        if !self.placements.contains(&pl) {
            self.placements.push(pl);
        }
    }

    #[inline(never)]
    fn record_match(&mut self, tok: &str, placement: Option<&'static str>, explicit: bool) {
        self.hit = true;
        if let Some(pl) = placement {
            self.note_placement(pl);
        }
        if !tok.is_empty() {
            if (explicit && !self.matched_explicit) || self.matched_tok.is_none() {
                self.matched_tok = Some(own(tok));
                self.matched_explicit = explicit;
            }
            if !explicit
                && tok.len() >= 4
                && !self.toks.iter().any(|t| t == tok)
                && !self.mem_extra_toks.iter().any(|t| t == tok)
            {
                self.mem_extra_toks.push(own(tok));
            }
        }
    }

    #[inline(never)]
    fn scrub_explicit(&mut self, v: &str, pl: Option<&'static str>) -> (String, bool) {
        let mut matched: Option<&str> = None;
        let (out, hit) = scrub_tokens_with(v, self.toks, &mut matched);
        if hit {
            self.record_match(matched.unwrap_or(""), pl, true);
        }
        (out, hit)
    }

    #[inline(never)]
    fn scrub_inline(&mut self, mut s: String, pl: &'static str) -> String {
        while let Some(found) = find_inline_secret_str(&s).map(own) {
            self.record_match(&found, Some(pl), false);
            s = s.replace(&found, &redacted_marker(found.len()));
        }
        s
    }

    fn s(&mut self, v: &str) -> String {
        self.scrub_explicit(v, None).0
    }

    #[inline(never)]
    fn sv(&mut self, mut items: Vec<String>) -> Vec<String> {
        for item in &mut items {
            *item = self.s(item);
        }
        items
    }

    #[inline(never)]
    fn scrub_argv(&mut self, raw_argv: Vec<String>) -> Vec<String> {
        let mut out = Vec::with_capacity(raw_argv.len());
        for arg in raw_argv {
            let (clean, _) = self.scrub_explicit(&arg, Some("argv"));
            let mut clean = self.scrub_inline(clean, "argv");
            if contains_unredacted_secret_pattern(&clean) {
                let copy = own(&clean);
                self.record_match(&copy, Some("argv"), false);
                clean = redacted_marker(clean.len());
            }
            out.push(clean);
        }
        out
    }

    #[inline(never)]
    fn read(&mut self, name: &str, max: usize, track: bool) -> Option<Vec<u8>> {
        match read_proc_bytes(&self.path(name), max) {
            Ok(b) => {
                if track {
                    self.readable.push(own(name));
                }
                Some(b)
            }
            Err(e) => {
                if is_perm_errno(e) {
                    self.denied.push(own(name));
                }
                None
            }
        }
    }

    #[inline(never)]
    fn read_str(&self, rel: &str, max: usize) -> Option<String> {
        read_proc_bytes(&self.path(rel), max)
            .ok()
            .map(|b| own(lossy(&b).trim()))
    }

    #[inline(never)]
    fn read_link(&self, rel: &str) -> Option<String> {
        fs::read_link(self.path(rel)).ok().map(|p| path_lossy(&p))
    }

    #[inline(never)]
    fn read_exe(&mut self) -> String {
        match fs::read_link(self.path("exe")) {
            Ok(p) => {
                self.readable.push(own("exe"));
                let raw = path_lossy(&p);
                self.s(&raw)
            }
            Err(e) => {
                if is_perm_denied(&e) {
                    self.denied.push(own("exe"));
                }
                String::new()
            }
        }
    }

    #[inline(never)]
    fn check_mem_readable(&mut self) -> bool {
        let mem_fd = sys::open(
            self.path("mem").as_bytes(),
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        );
        if mem_fd >= 0 {
            sys::close(mem_fd);
            self.readable.push(own("mem"));
            true
        } else {
            if is_perm_errno(sys::errno()) {
                self.denied.push(own("mem"));
            }
            false
        }
    }

    #[inline(never)]
    fn read_fds(&mut self) -> Vec<ProfileFd> {
        let mut fds = Vec::new();
        let fd_dir = self.path("fd");
        match read_numeric_dir(&fd_dir) {
            Ok(nums) => {
                self.readable.push(own("fd"));
                for fd in nums {
                    let p = cat3(&fd_dir, "/", &json::i64_str(fd as i64));
                    if let Ok(target) = fs::read_link(&p) {
                        let t = self.s(&path_lossy(&target));
                        fds.push(ProfileFd { fd, target: t });
                    }
                }
            }
            Err(e) if is_perm_denied(&e) => self.denied.push(own("fd")),
            Err(_) => {}
        }
        fds
    }

    #[inline(never)]
    fn parse_environ_raw(
        &mut self,
        raw: &[u8],
        redact_envs: &[String],
    ) -> (Vec<String>, u64, bool) {
        let mut environ = Vec::new();
        let raw_len = raw.len() as u64;
        let all_nul = !raw.is_empty() && raw.iter().all(|&b| b == 0);
        for part in raw.split(|&b| b == 0) {
            if part.is_empty() {
                continue;
            }
            let entry = lossy(part);
            if let Some((k, v)) = entry.split_once('=') {
                let (clean_v, exp_hit) = self.scrub_explicit(v, Some("environ"));
                let key_flagged = (is_sensitive_env_key(k)
                    || redact_envs.iter().any(|r| r.eq_ignore_ascii_case(k)))
                    && !v.is_empty()
                    && !v.starts_with("<REDACTED");
                let pat_flagged = contains_unredacted_secret_pattern(&clean_v);
                let val = if key_flagged || pat_flagged {
                    if !exp_hit {
                        let tok_src = find_inline_secret_str(&clean_v).unwrap_or(v);
                        self.record_match(tok_src, Some("environ"), false);
                    }
                    redacted_marker(v.len())
                } else {
                    self.scrub_inline(clean_v, "environ")
                };
                environ.push(cat3(k, "=", &val));
            } else {
                let (clean, _) = self.scrub_explicit(&entry, Some("environ"));
                environ.push(clean);
            }
        }
        (environ, raw_len, all_nul)
    }

    #[inline(never)]
    fn read_tasks(&mut self, pid: i32, comm: &str, state: &str) -> Vec<ProfileTask> {
        let mut task = Vec::new();
        let task_root = self.path("task");
        if let Ok(tids) = read_numeric_dir(&task_root) {
            for tid in tids {
                let t_comm = read_proc_bytes(&task_leaf_path(&task_root, tid, "comm"), 256)
                    .ok()
                    .map(|b| strip_proc_newline(&b))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| own(comm));
                let t_state = read_proc_bytes(&task_leaf_path(&task_root, tid, "stat"), 4096)
                    .ok()
                    .and_then(|b| parse_proc_stat(&b).ok())
                    .map(|s| s.state)
                    .unwrap_or_else(|| own(state));
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
                comm: own(comm),
                state: own(state),
            });
        }
        task
    }
}

#[inline(never)]
fn try_capture_ancestor(
    opts: &ExtractOpts,
    apid: i32,
    uid: u32,
    is_tracer: bool,
    depth: usize,
    visited: &mut Vec<i32>,
) -> Option<Box<Profile>> {
    if should_capture_ancestor(apid, uid, is_tracer, visited) {
        extract_live_inner(opts, apid, depth + 1, visited, false, true)
            .ok()
            .map(Box::new)
    } else {
        None
    }
}

/// Extract a live `schema: 2` `Profile` from `/proc/<pid>`.
pub fn extract_live(opts: &ExtractOpts) -> Result<Profile, String> {
    let mut visited: Vec<i32> = Vec::new();
    // Exclude the caller's own ancestor chain (the launching shell/harness above
    // `psgen`) so upward `--tree` traversal captures target supervisors/tracers
    // without cloning the outer test/shell runner.
    if opts.tree && opts.ancestors {
        let mut cur = sys::getpid();
        for _ in 0..32 {
            let Ok(raw) = read_proc_bytes(&proc_path(cur, "stat"), 4096) else {
                break;
            };
            let Ok(st) = parse_proc_stat(&raw) else {
                break;
            };
            if st.ppid <= 1 || st.ppid == opts.pid || visited.contains(&st.ppid) {
                break;
            }
            visited.push(st.ppid);
            cur = st.ppid;
        }
    }
    extract_live_inner(
        opts,
        opts.pid,
        0,
        &mut visited,
        opts.tree,
        opts.tree && opts.ancestors,
    )
}

#[inline(never)]
fn extract_live_inner(
    opts: &ExtractOpts,
    pid: i32,
    depth: usize,
    visited: &mut Vec<i32>,
    walk_down: bool,
    walk_up: bool,
) -> Result<Profile, String> {
    if pid <= 0 {
        return Err(cat2("invalid pid ", &json::i64_str(pid as i64)));
    }
    push_unique_i32(visited, pid);

    let proc_dir = proc_path(pid, "");
    let stat_path = cat2(&proc_dir, "/stat");
    let stat_raw = read_proc_bytes(&stat_path, 8192).map_err(|e| {
        if e == libc::ENOENT {
            cat3("pid ", &json::i64_str(pid as i64), " not found")
        } else {
            cat4("read ", &stat_path, ": errno ", &json::i64_str(e as i64))
        }
    })?;
    let pstat = parse_proc_stat(&stat_raw)?;

    let observer_uid = sys::geteuid();
    let mut readable = vec![cat2("uid:", &u64_str(observer_uid as u64))];
    let mut denied = Vec::new();

    let mut ctx = ProcCtx {
        dir: proc_dir,
        toks: &opts.redact_tokens,
        hit: false,
        matched_tok: None,
        matched_explicit: false,
        placements: Vec::new(),
        mem_extra_toks: Vec::new(),
        readable: &mut readable,
        denied: &mut denied,
    };

    let comm_raw = read_proc_bytes(&ctx.path("comm"), 256)
        .ok()
        .map(|b| strip_proc_newline(&b))
        .filter(|s| !s.is_empty())
        .unwrap_or(pstat.comm);
    let comm = ctx.s(&comm_raw);

    let (raw_argv, cmdline_raw_nuls) = match ctx.read("cmdline", 512 * 1024, false) {
        Some(b) => parse_cmdline(&b),
        None => (Vec::new(), 0),
    };

    let (mut status, euid, egid, groups) = match read_proc_bytes(&ctx.path("status"), MAX_PROC_READ)
    {
        Ok(b) => parse_proc_status(&b),
        Err(_) => {
            let mut st = default_status();
            json::assign_str(&mut st.name, &comm);
            st.state = pstat.state;
            st.ppid = pstat.ppid;
            st.threads = pstat.num_threads;
            (st, 0, 0, Vec::new())
        }
    };
    let sname = if status.name.is_empty() {
        own(&comm)
    } else {
        ctx.s(&status.name)
    };
    json::assign_str(&mut status.name, &sname);

    let exe = ctx.read_exe();
    let exe_memfd = detect_exe_memfd(&exe);
    let label = ctx.s(opts.label.as_deref().unwrap_or(&comm));
    let argv = ctx.scrub_argv(raw_argv);
    let cwd = ctx.s(&ctx.read_link("cwd").unwrap_or_default());
    let root = ctx.read_link("root").unwrap_or_else(|| own("/"));
    let ns = ProfileNs {
        pid: ctx.read_link("ns/pid"),
        mnt: ctx.read_link("ns/mnt"),
        user: ctx.read_link("ns/user"),
        net: ctx.read_link("ns/net"),
    };

    let (environ, environ_raw_len, environ_all_nul) = match ctx.read("environ", MAX_PROC_READ, true)
    {
        Some(raw) => ctx.parse_environ_raw(&raw, &opts.redact_envs),
        None => (Vec::new(), 0, false),
    };

    let mem_readable = ctx.check_mem_readable();

    let maps = if let Some(raw_maps) = ctx.read("maps", MAX_PROC_READ, true) {
        let m = ctx.sv(normalize_maps(&raw_maps));
        if mem_readable && pid != sys::getpid() {
            let mres = scan_anon_mem_for_tokens(
                pid,
                &raw_maps,
                &opts.redact_tokens,
                &ctx.mem_extra_toks,
                (pstat.arg_start, pstat.arg_end),
                (pstat.env_start, pstat.env_end),
            );
            if !mres.placements.is_empty() {
                for pl in mres.placements {
                    ctx.note_placement(pl);
                }
                ctx.record_match(
                    mres.matched_tok.as_deref().unwrap_or(""),
                    None,
                    mres.matched_explicit,
                );
            }
        }
        m
    } else {
        Vec::new()
    };

    let smaps = match read_proc_bytes(&ctx.path("smaps"), MAX_PROC_READ) {
        Ok(raw) => ctx.sv(normalize_smaps(&raw)),
        Err(_) => Vec::new(),
    };

    let fds = ctx.read_fds();

    let mut auxv = match ctx.read("auxv", 64 * 1024, true) {
        Some(raw) => parse_auxv(pid, &raw, &exe, mem_readable),
        None => ProfileAuxv::default(),
    };
    if let Some(ref mut execfn) = auxv.at_execfn {
        let cleaned = ctx.s(execfn);
        json::assign_str(execfn, &cleaned);
    }

    let task = ctx.read_tasks(pid, &comm, &status.state);
    let syscall = ProfileSyscall {
        syscall: read_proc_bytes(&ctx.path("syscall"), 512)
            .map(|b| parse_proc_syscall(&b))
            .unwrap_or_else(|_| own("unknown")),
        wchan: ctx.read_str("wchan", 256).unwrap_or_else(|| own("0")),
        policy: pstat.policy,
        priority: pstat.priority,
    };

    let matched_tok = ctx.matched_tok.take();
    let token_present = ctx.hit || matched_tok.is_some();
    let mut placements = Vec::with_capacity(ctx.placements.len());
    for pl in ctx.placements {
        placements.push(own(pl));
    }
    json::sort_strings(&mut placements);

    let (token_sha256, token_len, token_charset) = match matched_tok {
        Some(ref tok) => (
            Some(sha256::hash_hex(tok.as_bytes())),
            Some(tok.len() as u32),
            Some(classify_token_charset(tok)),
        ),
        None => (None, None, None),
    };

    let dumpable = if observer_uid != 0 && observer_uid == euid {
        // Under Yama ptrace_scope=1, a dumpable sibling still denies `/proc/<pid>/mem`
        // (PTRACE_MODE_ATTACH) while keeping environ/maps/auxv/exe/fd readable.
        // True non-dumpable (`PR_SET_DUMPABLE=0`) denies all of those surfaces.
        let non_mem_denied = denied
            .iter()
            .any(|s| csv_has("environ,maps,auxv,exe,fd", s));
        Some(!non_mem_denied)
    } else {
        None
    };

    let mut children = Vec::new();
    if walk_down && depth < opts.max_depth {
        for cpid in discover_child_pids(pid) {
            if !visited.contains(&cpid) {
                if let Ok(child_prof) =
                    extract_live_inner(opts, cpid, depth + 1, visited, true, false)
                {
                    children.push(child_prof);
                }
            }
        }
    }

    let (parent, tracer) = if walk_up && depth < opts.max_depth {
        let ppid = pstat.ppid;
        let tpid = status.tracer_pid;
        let par = try_capture_ancestor(opts, ppid, euid, ppid == tpid, depth, visited);
        let tr = if tpid > 0 && tpid != ppid {
            try_capture_ancestor(opts, tpid, euid, true, depth, visited)
        } else {
            None
        };
        (par, tr)
    } else {
        (None, None)
    };

    let profile_kind = if !opts.profile_name.is_empty() {
        opts.profile_name.as_str()
    } else if !children.is_empty() || parent.is_some() || tracer.is_some() {
        "tree"
    } else {
        "single"
    };

    Ok(Profile {
        schema: PROFILE_SCHEMA,
        source: ProfileSource {
            masker: own(&opts.masker),
            profile: own(profile_kind),
            version: own(&opts.version),
            observer_uid: Some(observer_uid),
        },
        identity: ProfileIdentity {
            label,
            comm,
            argv,
            cmdline_raw_nuls: Some(cmdline_raw_nuls),
            pid,
            ppid: pstat.ppid,
            pgid: pstat.pgid,
            sid: pstat.sid,
            uid: euid,
            gid: egid,
            groups,
            starttime: pstat.starttime,
            cwd,
            root,
            exe,
            exe_memfd,
            ns,
        },
        status,
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
        memory: ProfileMemory {
            maps,
            smaps,
            token_present,
            token_sha256,
            token_len,
            token_charset,
            token_placements: placements,
            readable_by: readable,
            denied_by: denied,
        },
        fds,
        auxv,
        environ,
        environ_raw_len,
        environ_all_nul,
        task,
        syscall,
        timing: ProfileTiming::default(),
        dumpable,
        children,
        parent,
        tracer,
    })
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
        own("<addr> rw-p 00000000 00:00 0 [heap]"),
        own("<addr> rw-p 00000000 00:00 0 [stack]"),
    ];
    let smaps = vec![
        format_smaps_entry(&cat2("r-xp ", exe), exe_kb, 0, 0),
        format_smaps_entry("rw-p [heap]", heap_kb, heap_kb, heap_kb),
        own("rw-p [stack] Rss:128kB Private_Dirty:128kB Anonymous:128kB"),
    ];
    (maps, smaps)
}

/// Build a canonical synthetic `schema: 2` `Profile` for `selftest` and unit tests.
#[inline(never)]
pub fn synthetic_default_profile(label: &str, tree: bool) -> Profile {
    const BASE_JSON: &str = concat!(
        r#"{"schema":2,"source":{"masker":"synthetic","profile":"single","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","observer_uid":2000},"identity":{"label":"ci-runner","comm":"ci-runner","argv":["ci-runner","--serve"],"cmdline_raw_nuls":1,"pid":1234,"ppid":1,"pgid":1234,"sid":1234,"uid":2000,"gid":2000,"groups":[],"starttime":123456,"cwd":"/srv/ci","root":"/","exe":"/srv/ci/ci-runner","ns":{"pid":"pid:[4026531836]","mnt":"mnt:[4026531841]","user":"user:[4026531837]","net":"net:[4026531992]"}},"status":{"Name":"ci-runner","State":"S","PPid":1,"Uid":"2000 2000 2000 2000","Gid":"2000 2000 2000 2000","Threads":1,"TracerPid":0,"NoNewPrivs":0,"Seccomp":0,"Seccomp_filters":0,"CapEff":"0000000000000000","CapPrm":"0000000000000000","CapBnd":"0000000000000000","VmLck":0,"RssShmem":0},"stat":{"ppid":1,"num_threads":1,"starttime":123456,"vsize":12345344,"rss":1024,"flags":4194304,"arg_start":140000000000000,"arg_end":140000000000018,"env_start":140000000000018,"env_end":140000000000114,"startstack":140000000000000},"memory":{"maps":[],"smaps":[],"token_present":false,"token_sha256":null,"token_placements":[],"readable_by":["uid:2000","exe","mem","maps","fd","auxv","environ"],"denied_by":[]},"fds":[{"fd":0,"target":"/dev/null"},{"fd":1,"target":"pipe:[12345]"},{"fd":2,"target":"pipe:[12345]"}],"auxv":{"AT_EXECFN":"/srv/ci/ci-runner","AT_PLATFORM":""#,
        "",
        r#"","AT_BASE":0,"AT_ENTRY":0},"environ":["PATH=/usr/local/bin:/usr/bin:/bin","HOME=/home/runner","LANG=C.UTF-8"],"environ_raw_len":66,"environ_all_nul":false,"task":[{"tid":1234,"comm":"ci-runner","state":"S"}],"syscall":{"syscall":"epoll_wait","wchan":"do_epoll_wait","policy":0,"priority":20},"timing":{"exec_ms":3.2,"first_conceal_ms":18.0},"dumpable":true,"children":[]}"#,
    );
    let clean_label = if label.trim().is_empty() {
        "ci-runner"
    } else {
        label.trim()
    };
    let comm_end = clean_label
        .char_indices()
        .nth(15)
        .map_or(clean_label.len(), |(i, _)| i);
    let comm = clean_label.get(..comm_end).unwrap_or(clean_label);
    let exe = cat2("/srv/ci/", clean_label);
    let (maps, smaps) = basic_maps_smaps(&exe, "1001", 1536, 2432);
    let arg_len = (clean_label.len() + 9) as u64;

    let mut root = Profile::parse_str(BASE_JSON).unwrap_or_else(|_| default_profile());
    if tree {
        json::assign_str(&mut root.source.profile, "tree");
    }
    json::assign_str(&mut root.identity.label, clean_label);
    json::assign_str(&mut root.identity.comm, comm);
    if let Some(a0) = root.identity.argv.first_mut() {
        json::assign_str(a0, clean_label);
    }
    json::assign_str(&mut root.identity.exe, &exe);
    json::assign_str(&mut root.status.name, comm);
    if let Some(t0) = root.task.first_mut() {
        json::assign_str(&mut t0.comm, comm);
    }
    root.auxv.at_execfn = Some(exe);
    root.auxv.at_platform = Some(own(std::env::consts::ARCH));
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
        if let Some(a1) = child.identity.argv.get_mut(1) {
            json::assign_str(a1, "--worker");
        }
        child.stat.arg_end = child.stat.arg_start + (clean_label.len() + 10) as u64;
        child.stat.env_start = child.stat.arg_end;
        child.stat.env_end = child.stat.env_start + 96;
        if let Some(t0) = child.task.first_mut() {
            t0.tid = 1235;
        }
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
                    *v = Json::Int(1);
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
        assert_eq!(st.pgid, 4242);
        assert_eq!(st.sid, 4242);
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
        assert!(prof.identity.sid > 0);
        assert!(prof.identity.pgid > 0);
        assert!(!prof.identity.comm.is_empty());
        assert!(!prof.task.is_empty());
        if prof.memory.token_present {
            assert!(prof.memory.token_sha256.is_some());
        } else {
            assert!(prof.memory.token_sha256.is_none());
        }
        prof.validate(&["DO_NOT_LEAK_SELF_TOKEN"]).unwrap();

        let json_str = prof.to_json().to_string();
        assert!(!json_str.contains("DO_NOT_LEAK_SELF_TOKEN"));
        let roundtripped = Profile::parse_str(&json_str).unwrap();
        assert_eq!(roundtripped, prof);
    }

    #[test]
    fn live_child_redaction_and_tree_extraction() {
        let secret = "TOK-a1b2c3d4e5f60718";
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("10")
            .env_clear()
            .env("MY_APP_SECRET", secret)
            .env("NORMAL_VAR", format!("holder-{secret}-end"))
            .spawn()
            .expect("spawn sleep child");
        let cpid = child.id() as i32;
        for _ in 0..100 {
            if read_proc_bytes(&proc_path(cpid, "environ"), 4096)
                .is_ok_and(|b| b.windows(secret.len()).any(|w| w == secret.as_bytes()))
            {
                break;
            }
            sys::nanosleep(0, 5_000_000);
        }

        // Extract child directly with redaction.
        let mut child_opts = ExtractOpts::for_pid(cpid);
        child_opts.redact_tokens.push(secret.to_string());
        let cprof = extract_live(&child_opts).expect("extract live child");
        assert_eq!(cprof.identity.pid, cpid);
        assert!(cprof.environ_raw_len > 0);
        assert!(!cprof.environ_all_nul);
        assert!(cprof.memory.token_present);
        assert_eq!(
            cprof.memory.token_sha256.as_deref(),
            Some(sha256::hash_hex(secret.as_bytes()).as_str())
        );
        assert_eq!(cprof.memory.token_len, Some(secret.len() as u32));
        assert_eq!(
            cprof.memory.token_charset.as_deref(),
            Some("prefix:TOK-:hex")
        );
        assert!(cprof
            .memory
            .token_placements
            .contains(&"environ".to_string()));
        let cjson = cprof.to_json().to_string();
        assert!(!cjson.contains(secret));
        assert!(cjson.contains("\"children\":[]"));
        cprof.validate(&[secret]).unwrap();

        // Extract child with tree=true, ancestors=true and verify upward parent capture!
        let mut anc_opts = ExtractOpts::for_pid(cpid);
        anc_opts.tree = true;
        anc_opts.ancestors = true;
        anc_opts.redact_tokens.push(secret.to_string());
        let aprof = extract_live(&anc_opts).expect("extract live child with ancestors");
        let parent = aprof
            .parent
            .as_ref()
            .expect("upward parent should be captured under tree+ancestors");
        assert_eq!(parent.identity.pid, sys::getpid());
        assert!(parent.children.is_empty());
        aprof.validate(&[secret]).unwrap();

        // Extract child with tree=true, ancestors=false and verify parent is NOT captured.
        anc_opts.ancestors = false;
        let no_anc = extract_live(&anc_opts).expect("extract live child without ancestors");
        assert!(no_anc.parent.is_none());

        // Extract self with tree=true and verify child appears in children.
        let mut tree_opts = ExtractOpts::for_pid(sys::getpid());
        tree_opts.tree = true;
        tree_opts.ancestors = false;
        tree_opts.redact_tokens.push(secret.to_string());
        let tprof = extract_live(&tree_opts).expect("extract live tree");
        assert!(tprof.children.iter().any(|c| c.identity.pid == cpid));
        tprof.validate(&[secret]).unwrap();

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn trailing_space_comm_and_status_groups_preserved() {
        assert_eq!(strip_proc_newline(b"ci-runner      \n"), "ci-runner      ");
        assert_eq!(
            strip_proc_newline(b"ci-runner      \r\n"),
            "ci-runner      "
        );
        let raw_status = b"Name:\tci-runner      \nState:\tS (sleeping)\nPPid:\t100\nUid:\t2000\t2000\t2000\t2000\nGid:\t2000\t2000\t2000\t2000\nGroups:\t4 27 2000 \nThreads:\t1\nTracerPid:\t0\n";
        let (st, euid, egid, groups) = parse_proc_status(raw_status);
        assert_eq!(st.name, "ci-runner      ");
        assert_eq!(euid, 2000);
        assert_eq!(egid, 2000);
        assert_eq!(groups, vec![4, 27, 2000]);

        let mut prof = synthetic_default_profile("ci-runner", false);
        prof.identity.comm = "ci-runner      ".to_string();
        prof.status.name = "ci-runner      ".to_string();
        prof.task[0].comm = "ci-runner      ".to_string();
        prof.validate(&[]).unwrap();
        let rt = Profile::parse_str(&prof.to_json_str(false)).unwrap();
        assert_eq!(rt.identity.comm, "ci-runner      ");
        assert_eq!(rt.status.name, "ci-runner      ");
        assert_eq!(rt.task[0].comm, "ci-runner      ");
    }

    #[test]
    fn classify_token_charset_and_substitute_redacted() {
        assert_eq!(
            classify_token_charset("TOK-deadbeef0123"),
            "prefix:TOK-:hex"
        );
        assert_eq!(classify_token_charset("TOK-abcXYZ123"), "prefix:TOK-:alnum");
        assert_eq!(
            classify_token_charset("sk_live_AbCd1234"),
            "prefix:sk_live_:hex"
        );
        assert_eq!(
            classify_token_charset("sk_live_AbGz1234"),
            "prefix:sk_live_:alnum"
        );
        assert_eq!(classify_token_charset("DECOY-012345"), "prefix:DECOY-:hex");
        assert_eq!(classify_token_charset("deadbeef01234567"), "hex");
        assert_eq!(classify_token_charset("AbGzEf0123456789"), "alnum");
        assert_eq!(classify_token_charset("YWJjZGVm+/=="), "base64");
        assert_eq!(classify_token_charset("p@ss!word$123"), "ascii");
        // Long descriptive prefixes must not leak secret words into token_charset.
        assert_eq!(classify_token_charset("FAKE_SECRET_12345"), "base64");

        assert_eq!(
            substitute_redacted("SECRET=<REDACTED:len=10>", "DECOY-0123456789"),
            "SECRET=DECOY-0123"
        );
        assert_eq!(
            substitute_redacted("A=<REDACTED:len=6>,B=<REDACTED>", "XY"),
            "A=XYXYXY,B=XY"
        );
        assert_eq!(substitute_redacted("plain", "TOK"), "plain");
    }

    #[test]
    fn read_redact_tokens_file_trims_crlf_and_skips_blank() {
        let path =
            std::env::temp_dir().join(format!("psgen-redact-tokens-{}.txt", std::process::id()));
        fs::write(&path, "TOK-11112222\r\n\n\r\nTOK-33334444\n").unwrap();
        let toks = read_redact_tokens_file(path.to_str().unwrap()).unwrap();
        let _ = fs::remove_file(&path);
        assert_eq!(toks, vec!["TOK-11112222", "TOK-33334444"]);
    }

    #[test]
    fn schema_v2_roundtrip_all_new_fields() {
        let mut parent = synthetic_default_profile("ci-super", false);
        parent.identity.pid = 1000;
        parent.identity.ppid = 1;
        parent.identity.pgid = 1000;
        parent.identity.sid = 1000;
        parent.identity.groups = vec![10, 2000];

        let mut tracer = synthetic_default_profile("ci-trace", false);
        tracer.identity.pid = 1001;

        let mut prof = synthetic_default_profile("ci-runner", true);
        prof.identity.comm = "ci-runner      ".to_string();
        prof.identity.pgid = 1234;
        prof.identity.sid = 1234;
        prof.identity.groups = vec![4, 24, 2000];
        prof.environ.clear();
        prof.environ_raw_len = 81;
        prof.environ_all_nul = true;
        prof.memory.token_present = true;
        prof.memory.token_sha256 = Some(sha256::hash_hex(b"TOK-abcdef123456"));
        prof.memory.token_len = Some(16);
        prof.memory.token_charset = Some("prefix:TOK-:hex".to_string());
        prof.memory.token_placements = vec!["anon".to_string(), "heap".to_string()];
        prof.parent = Some(Box::new(parent));
        prof.tracer = Some(Box::new(tracer));

        prof.validate(&["TOK-abcdef123456"]).unwrap();
        let compact = prof.to_json_str(false);
        let parsed = Profile::parse_str(&compact).unwrap();
        assert_eq!(parsed, prof);
        let pretty = prof.to_json_str(true);
        let parsed_pretty = Profile::parse_str(&pretty).unwrap();
        assert_eq!(parsed_pretty, prof);

        // Secret leaked inside parent or tracer must be caught by validate().
        let mut leaky = prof.clone();
        leaky
            .parent
            .as_mut()
            .unwrap()
            .environ
            .push("SECRET_TOKEN=LEAKED_PARENT_SECRET".to_string());
        assert!(leaky.validate(&["LEAKED_PARENT_SECRET"]).is_err());

        // Invalid token placement must be rejected by validate().
        let mut bad_pl = prof.clone();
        bad_pl.memory.token_placements.push("bogus".to_string());
        assert!(bad_pl.validate(&[]).is_err());
    }

    #[test]
    fn environ_all_nul_and_raw_len_captured_correctly() {
        // Direct unit check of all-NUL blanked environ buffer.
        let mut readable = Vec::new();
        let mut denied = Vec::new();
        let mut ctx = ProcCtx {
            dir: String::new(),
            toks: &[],
            hit: false,
            matched_tok: None,
            matched_explicit: false,
            placements: Vec::new(),
            mem_extra_toks: Vec::new(),
            readable: &mut readable,
            denied: &mut denied,
        };
        let blank = vec![0u8; 58];
        let (env_entries, raw_len, all_nul) = ctx.parse_environ_raw(&blank, &[]);
        assert!(env_entries.is_empty());
        assert_eq!(raw_len, 58);
        assert!(all_nul);

        // Live child check with exact K=V\0 env.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("10")
            .env_clear()
            .env("K", "V")
            .spawn()
            .expect("spawn sleep");
        let cpid = child.id() as i32;
        for _ in 0..100 {
            if read_proc_bytes(&proc_path(cpid, "environ"), 64).is_ok_and(|b| b == b"K=V\0") {
                break;
            }
            sys::nanosleep(0, 5_000_000);
        }
        let prof = extract_live(&ExtractOpts::for_pid(cpid)).expect("extract");
        assert_eq!(prof.environ, vec!["K=V".to_string()]);
        assert_eq!(prof.environ_raw_len, 4); // b"K=V\0"
        assert!(!prof.environ_all_nul);
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn live_argv_inline_token_redacted_and_hashed() {
        let tok = "TOK-1234567890ab";
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 10; :", "sh", tok])
            .env_clear()
            .spawn()
            .expect("spawn sh");
        let cpid = child.id() as i32;
        for _ in 0..100 {
            if read_proc_bytes(&proc_path(cpid, "cmdline"), 4096)
                .is_ok_and(|b| b.windows(tok.len()).any(|w| w == tok.as_bytes()))
            {
                break;
            }
            sys::nanosleep(0, 5_000_000);
        }

        // Even WITHOUT passing redact_tokens, inline TOK-... in argv is detected, hashed, and redacted.
        let prof = extract_live(&ExtractOpts::for_pid(cpid)).expect("extract sh");
        assert!(prof.memory.token_present);
        assert_eq!(
            prof.memory.token_sha256.as_deref(),
            Some(sha256::hash_hex(tok.as_bytes()).as_str())
        );
        assert_eq!(prof.memory.token_len, Some(tok.len() as u32));
        assert_eq!(
            prof.memory.token_charset.as_deref(),
            Some("prefix:TOK-:hex")
        );
        assert!(prof.memory.token_placements.contains(&"argv".to_string()));
        assert!(!prof.to_json_str(false).contains(tok));
        prof.validate(&[tok]).unwrap();

        let _ = child.kill();
        let _ = child.wait();
    }
}
