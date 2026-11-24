//! Zero-dependency RFC 8259 JSON parser, DOM helpers, canonical serializer,
//! and compact shared formatting/sorting/I/O utilities (zero `core::fmt::float`).

#[cfg(test)]
use std::fmt;
use std::fs;
use std::path::Path;

/// Maximum allowed nesting depth for arrays and objects.
const MAX_DEPTH: usize = 64;

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

/// Zero-DOM streaming JSON writer backed directly by a `String`.
pub struct Jw {
    pub out: String,
    depth: usize,
    need_comma: bool,
    pretty: bool,
}

impl Jw {
    pub fn new(pretty: bool) -> Self {
        Jw {
            out: String::with_capacity(256),
            depth: 0,
            need_comma: false,
            pretty,
        }
    }

    pub fn reset(&mut self, pretty: bool) {
        self.out.clear();
        self.depth = 0;
        self.need_comma = false;
        self.pretty = pretty;
    }

    pub fn finish(self) -> String {
        self.out
    }

    pub fn write_to(&mut self, path: &Path) -> Result<(), String> {
        self.out.push('\n');
        write_file(path, self.out.as_bytes())
    }

    fn sep(&mut self) {
        if self.need_comma {
            self.out.push(',');
        }
        if self.pretty {
            self.out.push('\n');
            push_indent(self.depth, &mut self.out);
        }
        self.need_comma = true;
    }

    fn open(&mut self, ch: char) {
        self.out.push(ch);
        self.depth += 1;
        self.need_comma = false;
    }

    fn close(&mut self, ch: char) {
        self.depth -= 1;
        if self.need_comma && self.pretty {
            self.out.push('\n');
            push_indent(self.depth, &mut self.out);
        }
        self.out.push(ch);
        self.need_comma = true;
    }

    pub fn obj_open(&mut self) {
        self.open('{');
    }

    pub fn obj_close(&mut self) {
        self.close('}');
    }

    pub fn arr_open(&mut self) {
        self.open('[');
    }

    pub fn arr_close(&mut self) {
        self.close(']');
    }

    pub fn elem(&mut self) {
        self.sep();
    }

    pub fn elem_obj(&mut self) {
        self.sep();
        self.open('{');
    }

    #[inline(never)]
    pub fn key(&mut self, k: &str) {
        self.sep();
        push_escaped_str(k, &mut self.out);
        self.out.push(':');
        if self.pretty {
            self.out.push(' ');
        }
    }

    pub fn k_obj(&mut self, k: &str) {
        self.key(k);
        self.open('{');
    }

    pub fn k_arr(&mut self, k: &str) {
        self.key(k);
        self.open('[');
    }

    #[inline(never)]
    pub fn k_str(&mut self, k: &str, v: &str) {
        self.key(k);
        push_escaped_str(v, &mut self.out);
    }

    pub fn k_opt_str(&mut self, k: &str, v: &Option<String>) {
        match v {
            Some(s) => self.k_str(k, s),
            None => self.k_null(k),
        }
    }

    #[inline(never)]
    pub fn k_i64(&mut self, k: &str, v: i64) {
        self.key(k);
        push_i64(&mut self.out, v);
    }

    #[inline(never)]
    pub fn k_u64(&mut self, k: &str, v: u64) {
        self.key(k);
        push_u64(&mut self.out, v);
    }

    pub fn k_f64(&mut self, k: &str, v: f64) {
        self.key(k);
        push_float(v, &mut self.out);
    }

    pub fn k_bool(&mut self, k: &str, v: bool) {
        self.key(k);
        self.out.push_str(if v { "true" } else { "false" });
    }

    pub fn k_null(&mut self, k: &str) {
        self.key(k);
        self.out.push_str("null");
    }

    #[inline(never)]
    pub fn k_str_arr(&mut self, k: &str, items: &[String]) {
        self.k_arr(k);
        for s in items {
            self.sep();
            push_escaped_str(s, &mut self.out);
        }
        self.arr_close();
    }

    pub fn k_i32_arr(&mut self, k: &str, items: &[i32]) {
        self.k_arr(k);
        for &n in items {
            self.sep();
            push_i64(&mut self.out, n as i64);
        }
        self.arr_close();
    }

    pub fn k_some_str(&mut self, k: &str, v: &Option<String>) {
        if let Some(ref s) = v {
            self.k_str(k, s);
        }
    }

    pub fn k_some_u64(&mut self, k: &str, v: Option<u64>) {
        if let Some(n) = v {
            self.k_u64(k, n);
        }
    }

    pub fn k_f64_r6(&mut self, k: &str, v: f64) {
        self.k_f64(k, round6(v));
    }

    pub fn k_f64_pair_r6(&mut self, k: &str, p: (f64, f64)) {
        self.k_f64_pair(k, round6(p.0), round6(p.1));
    }

    pub fn k_f64_pair(&mut self, k: &str, a: f64, b: f64) {
        self.k_arr(k);
        self.sep();
        push_float(a, &mut self.out);
        self.sep();
        push_float(b, &mut self.out);
        self.arr_close();
    }

    pub fn k_raw(&mut self, k: &str, raw_json: &str) {
        self.key(k);
        let trimmed = raw_json.trim_end();
        if !self.pretty {
            self.out.push_str(trimmed);
            return;
        }
        for (i, line) in trimmed.lines().enumerate() {
            if i > 0 {
                self.out.push('\n');
                push_indent(self.depth, &mut self.out);
            }
            self.out.push_str(line);
        }
    }
}

pub fn parse_u64_s(s: &str) -> Option<u64> {
    crate::str::parse_u64(s.as_bytes())
}

pub fn parse_i64_s(s: &str) -> Option<i64> {
    crate::str::parse_i64(s.as_bytes())
}

pub fn parse_i32_s(s: &str) -> Option<i32> {
    i32::try_from(parse_i64_s(s)?).ok()
}

pub fn parse_u32_s(s: &str) -> Option<u32> {
    u32::try_from(parse_u64_s(s)?).ok()
}

// --- Compact shared string/formatting/sorting/I/O helpers ---

#[inline(never)]
pub fn cat2(a: &str, b: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len());
    s.push_str(a);
    s.push_str(b);
    s
}

#[inline(never)]
pub fn cat3(a: &str, b: &str, c: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len() + c.len());
    s.push_str(a);
    s.push_str(b);
    s.push_str(c);
    s
}

pub fn cat4(a: &str, b: &str, c: &str, d: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len() + c.len() + d.len());
    s.push_str(a);
    s.push_str(b);
    s.push_str(c);
    s.push_str(d);
    s
}

#[inline(never)]
pub fn push_u64(out: &mut String, mut n: u64) {
    if n == 0 {
        out.push('0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        out.push(tmp[i] as char);
    }
}

pub fn push_i64(out: &mut String, n: i64) {
    if n < 0 {
        out.push('-');
        push_u64(out, n.unsigned_abs());
    } else {
        push_u64(out, n as u64);
    }
}

pub fn u64_str(n: u64) -> String {
    let mut s = String::with_capacity(20);
    push_u64(&mut s, n);
    s
}

pub fn i64_str(n: i64) -> String {
    let mut s = String::with_capacity(21);
    push_i64(&mut s, n);
    s
}

fn push_str_right(out: &mut String, s: &str, width: usize) {
    for _ in s.len()..width {
        out.push(' ');
    }
    out.push_str(s);
}

pub fn push_u64_right(out: &mut String, n: u64, width: usize) {
    push_str_right(out, &u64_str(n), width);
}

pub fn push_i64_right(out: &mut String, n: i64, width: usize) {
    push_str_right(out, &i64_str(n), width);
}

pub fn push_str_left(out: &mut String, s: &str, width: usize) {
    out.push_str(s);
    for _ in s.len()..width {
        out.push(' ');
    }
}

#[inline(never)]
pub fn err_io(op: &str, path: &Path, e: &std::io::Error) -> String {
    let mut s = String::with_capacity(op.len() + 48);
    s.push_str(op);
    s.push(' ');
    s.push_str(&path.to_string_lossy());
    if let Some(code) = e.raw_os_error() {
        s.push_str(": errno ");
        push_i64(&mut s, code as i64);
    } else {
        s.push_str(": io error");
    }
    s
}

#[inline(never)]
pub fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| err_io("cannot read", path, &e))
}

#[inline(never)]
pub fn read_str(path: &Path) -> Result<String, String> {
    let raw = read_bytes(path)?;
    String::from_utf8(raw).map_err(|_| cat2("invalid utf-8 in ", &path.to_string_lossy()))
}

pub fn read_str_in(dir: &Path, rel: &str) -> Result<String, String> {
    read_str(&dir.join(rel))
}

#[inline(never)]
pub fn write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    fs::write(path, data).map_err(|e| err_io("cannot write", path, &e))
}

pub fn write_in(dir: &Path, rel: &str, data: &[u8]) -> Result<(), String> {
    write_file(&dir.join(rel), data)
}

#[inline(never)]
pub fn mkdir_all(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| err_io("cannot create", path, &e))
}

/// Deferred-error file writer for a directory (eliminates O(N^2) `?` drop glue).
pub struct OutDir<'a> {
    pub dir: &'a Path,
    pub err: Option<String>,
}

impl<'a> OutDir<'a> {
    pub fn new(dir: &'a Path) -> Self {
        OutDir { dir, err: None }
    }

    pub fn write(&mut self, rel: &str, data: &[u8]) {
        if self.err.is_none() {
            if let Err(e) = write_in(self.dir, rel, data) {
                self.err = Some(e);
            }
        }
    }

    pub fn line(&mut self, rel: &str, line: &str) {
        let mut s = String::with_capacity(line.len() + 1);
        s.push_str(line);
        s.push('\n');
        self.write(rel, s.as_bytes());
    }

    pub fn lines(&mut self, rel: &str, items: &[String]) {
        let mut s = items.join("\n");
        if !s.is_empty() {
            s.push('\n');
        }
        self.write(rel, s.as_bytes());
    }

    pub fn jw(&mut self, rel: &str, w: &mut Jw) {
        w.out.push('\n');
        self.write(rel, w.out.as_bytes());
    }

    pub fn check(self) -> Result<(), String> {
        match self.err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Compact Ciura shellsort (avoids ~20 KiB `core::slice::sort::driftsort` per type).
pub fn shell_sort_by<T>(v: &mut [T], mut gt: impl FnMut(&T, &T) -> bool) {
    const GAPS: &[usize] = &[701, 301, 132, 57, 23, 10, 4, 1];
    let n = v.len();
    for &gap in GAPS {
        if gap >= n {
            continue;
        }
        for i in gap..n {
            let mut j = i;
            while j >= gap && gt(&v[j - gap], &v[j]) {
                v.swap(j - gap, j);
                j -= gap;
            }
        }
    }
}

pub fn sort_strings(v: &mut [String]) {
    shell_sort_by(v, |a, b| a > b);
}

pub fn round6(v: f64) -> f64 {
    if !v.is_finite() {
        return 0.0;
    }
    (v * 1_000_000.0).round() / 1_000_000.0
}

fn err_missing(key: &str) -> String {
    cat3("missing required field '", key, "'")
}

fn err_type(key: &str, expected: &str) -> String {
    cat4("field '", key, "' must be ", expected)
}

impl Json {
    pub fn as_obj(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(n) if *n >= 0 => Some(*n as u64),
            Json::Float(f)
                if f.is_finite()
                    && *f >= 0.0
                    && f.fract() == 0.0
                    && *f <= 9_007_199_254_740_992.0 =>
            {
                Some(*f as u64)
            }
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Float(f) if f.is_finite() => Some(*f),
            Json::Int(n) => Some(*n as f64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_obj()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    #[cfg(test)]
    pub fn req_str(&self, key: &str) -> Result<&str, String> {
        let v = self.get(key).ok_or_else(|| err_missing(key))?;
        v.as_str().ok_or_else(|| err_type(key, "a string"))
    }

    #[cfg(test)]
    pub fn req_i64(&self, key: &str) -> Result<i64, String> {
        let v = self.get(key).ok_or_else(|| err_missing(key))?;
        v.as_i64().ok_or_else(|| err_type(key, "an integer"))
    }

    #[cfg(test)]
    pub fn req_u64(&self, key: &str) -> Result<u64, String> {
        let v = self.get(key).ok_or_else(|| err_missing(key))?;
        v.as_u64()
            .ok_or_else(|| err_type(key, "a non-negative integer"))
    }

    #[cfg(test)]
    pub fn req_f64(&self, key: &str) -> Result<f64, String> {
        let v = self.get(key).ok_or_else(|| err_missing(key))?;
        v.as_f64().ok_or_else(|| err_type(key, "a finite number"))
    }

    #[cfg(test)]
    pub fn req_bool(&self, key: &str) -> Result<bool, String> {
        let v = self.get(key).ok_or_else(|| err_missing(key))?;
        v.as_bool().ok_or_else(|| err_type(key, "a boolean"))
    }

    pub fn req_arr(&self, key: &str) -> Result<&[Json], String> {
        let v = self.get(key).ok_or_else(|| err_missing(key))?;
        v.as_arr().ok_or_else(|| err_type(key, "an array"))
    }

    #[cfg(test)]
    pub fn req_obj(&self, key: &str) -> Result<&[(String, Json)], String> {
        let v = self.get(key).ok_or_else(|| err_missing(key))?;
        v.as_obj().ok_or_else(|| err_type(key, "an object"))
    }

    /// Reject any key not present in comma-separated `allowed_csv`, as well as duplicate keys.
    pub fn reject_unknown_keys_csv(&self, allowed_csv: &str, ctx: &str) -> Result<(), String> {
        let entries = self
            .as_obj()
            .ok_or_else(|| cat2(ctx, ": expected JSON object"))?;
        for (i, (k, _)) in entries.iter().enumerate() {
            if !allowed_csv.split(',').any(|a| a == k.as_str()) {
                return Err(cat4(ctx, ": unknown field '", k, "'"));
            }
            if entries[..i].iter().any(|(prev, _)| prev == k) {
                return Err(cat4(ctx, ": duplicate field '", k, "'"));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn reject_unknown_keys(&self, allowed: &[&str], ctx: &str) -> Result<(), String> {
        self.reject_unknown_keys_csv(&allowed.join(","), ctx)
    }

    /// Compact canonical JSON serialization (tests only; prod streams via `Jw`).
    #[cfg(test)]
    pub fn to_compact(&self) -> String {
        let mut out = String::new();
        write_json(self, None, &mut out);
        out
    }

    /// Pretty-printed canonical JSON serialization (tests only; prod streams via `Jw`).
    #[cfg(test)]
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        write_json(self, Some(0), &mut out);
        out
    }
}

/// Deferred-error JSON object reader: records the first field error instead of
/// emitting `O(N^2)` per-field `?` drop glue in struct parsers.
pub struct JRead<'a> {
    v: &'a Json,
    ctx: &'a str,
    pub err: Option<String>,
}

impl<'a> JRead<'a> {
    pub fn new(v: &'a Json, allowed_csv: &str, ctx: &'a str) -> Result<Self, String> {
        v.reject_unknown_keys_csv(allowed_csv, ctx)?;
        Ok(JRead { v, ctx, err: None })
    }

    pub fn unchecked(v: &'a Json, ctx: &'a str) -> Self {
        JRead { v, ctx, err: None }
    }

    #[inline(never)]
    pub fn enter(&mut self, parent: &'a Json, key: &'a str, allowed_csv: &str) -> bool {
        if self.err.is_some() {
            return false;
        }
        let Some(v) = parent.get(key) else {
            self.err = Some(err_missing(key));
            return false;
        };
        if let Err(e) = v.reject_unknown_keys_csv(allowed_csv, key) {
            self.err = Some(e);
            return false;
        }
        self.v = v;
        self.ctx = key;
        true
    }

    #[inline(never)]
    fn fail(&mut self, k: &str, msg: &str) {
        if self.err.is_none() {
            self.err = Some(cat4(self.ctx, ".", k, msg));
        }
    }

    fn req_val(&mut self, k: &str) -> Option<&'a Json> {
        match self.v.get(k) {
            Some(v) => Some(v),
            None => {
                self.fail(k, ": missing");
                None
            }
        }
    }

    pub fn str_ref(&mut self, k: &str) -> &'a str {
        let Some(v) = self.req_val(k) else {
            return "";
        };
        match v.as_str() {
            Some(s) => s,
            None => {
                self.fail(k, ": expected string");
                ""
            }
        }
    }

    pub fn str(&mut self, k: &str) -> String {
        self.str_ref(k).to_string()
    }

    #[inline(never)]
    pub fn fill_str(&mut self, k: &str, dst: &mut String) {
        dst.clear();
        dst.push_str(self.str_ref(k));
    }

    pub fn fill_opt_str(&mut self, k: &str, dst: &mut Option<String>) {
        *dst = self.opt_str(k);
    }

    pub fn fill_str_arr(&mut self, k: &str, dst: &mut Vec<String>) {
        *dst = self.str_arr(k);
    }

    pub fn opt_str(&mut self, k: &str) -> Option<String> {
        match self.v.get(k) {
            None | Some(Json::Null) => None,
            Some(Json::Str(s)) => Some(s.clone()),
            Some(_) => {
                self.fail(k, ": expected string");
                None
            }
        }
    }

    pub fn u64(&mut self, k: &str) -> u64 {
        let Some(v) = self.req_val(k) else {
            return 0;
        };
        match v.as_u64() {
            Some(n) => n,
            None => {
                self.fail(k, ": expected u64");
                0
            }
        }
    }

    pub fn opt_u64(&mut self, k: &str) -> Option<u64> {
        match self.v.get(k) {
            None | Some(Json::Null) => None,
            Some(v) => match v.as_u64() {
                Some(n) => Some(n),
                None => {
                    self.fail(k, ": expected u64");
                    None
                }
            },
        }
    }

    pub fn opt_u32(&mut self, k: &str) -> Option<u32> {
        let n = self.opt_u64(k)?;
        match u32::try_from(n) {
            Ok(v) => Some(v),
            Err(_) => {
                self.fail(k, ": out of range");
                None
            }
        }
    }

    pub fn i32(&mut self, k: &str) -> i32 {
        let Some(v) = self.req_val(k) else {
            return 0;
        };
        match v.as_i64().and_then(|n| i32::try_from(n).ok()) {
            Some(n) => n,
            None => {
                self.fail(k, ": expected i32");
                0
            }
        }
    }

    pub fn u32(&mut self, k: &str) -> u32 {
        let n = self.u64(k);
        match u32::try_from(n) {
            Ok(v) => v,
            Err(_) => {
                self.fail(k, ": expected u32");
                0
            }
        }
    }

    pub fn f64(&mut self, k: &str) -> f64 {
        let Some(v) = self.req_val(k) else {
            return 0.0;
        };
        match v.as_f64() {
            Some(f) => f,
            None => {
                self.fail(k, ": expected number");
                0.0
            }
        }
    }

    pub fn opt_f64(&mut self, k: &str) -> Option<f64> {
        match self.v.get(k) {
            None | Some(Json::Null) => None,
            Some(v) => match v.as_f64() {
                Some(f) => Some(f),
                None => {
                    self.fail(k, ": expected number");
                    None
                }
            },
        }
    }

    pub fn bool(&mut self, k: &str) -> bool {
        let Some(v) = self.req_val(k) else {
            return false;
        };
        match v.as_bool() {
            Some(b) => b,
            None => {
                self.fail(k, ": expected bool");
                false
            }
        }
    }

    pub fn opt_bool(&mut self, k: &str) -> Option<bool> {
        match self.v.get(k) {
            None | Some(Json::Null) => None,
            Some(Json::Bool(b)) => Some(*b),
            Some(_) => {
                self.fail(k, ": expected bool");
                None
            }
        }
    }

    pub fn str_arr(&mut self, k: &str) -> Vec<String> {
        let Some(v) = self.req_val(k) else {
            return Vec::new();
        };
        let Some(arr) = v.as_arr() else {
            self.fail(k, ": expected array");
            return Vec::new();
        };
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            match item.as_str() {
                Some(s) => out.push(s.to_string()),
                None => {
                    self.fail(k, ": expected string array");
                    return Vec::new();
                }
            }
        }
        out
    }

    pub fn i32_arr(&mut self, k: &str, optional: bool) -> Vec<i32> {
        let Some(v) = (if optional {
            self.v.get(k)
        } else {
            self.req_val(k)
        }) else {
            return Vec::new();
        };
        let Some(arr) = v.as_arr() else {
            self.fail(k, ": expected array");
            return Vec::new();
        };
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            match item.as_i64().and_then(|n| i32::try_from(n).ok()) {
                Some(n) => out.push(n),
                None => {
                    self.fail(k, ": expected i32 array");
                    return Vec::new();
                }
            }
        }
        out
    }

    pub fn check(self) -> Result<(), String> {
        match self.err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_compact())
    }
}

fn err_off(msg: &str, off: usize) -> String {
    let mut s = String::with_capacity(msg.len() + 24);
    s.push_str(msg);
    s.push_str(" at offset ");
    push_u64(&mut s, off as u64);
    s
}

/// Parse an RFC 8259 JSON document.
pub fn parse(input: &str) -> Result<Json, String> {
    let mut p = Parser {
        src: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let val = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != p.src.len() {
        return Err(err_off("unexpected trailing byte", p.pos));
    }
    Ok(val)
}

/// Hand-rolled decimal `f64` parser to avoid linking `core::num::dec2flt`.
fn parse_f64_decimal(bytes: &[u8]) -> Option<f64> {
    if bytes.is_empty() {
        return None;
    }
    let mut i = 0;
    let neg = if bytes[i] == b'-' {
        i += 1;
        true
    } else {
        false
    };

    let mut mant: u64 = 0;
    let mut digits = 0u32;
    let mut exp10: i32 = 0;

    while i < bytes.len() && bytes[i].is_ascii_digit() {
        let d = (bytes[i] - b'0') as u64;
        if mant == 0 && d == 0 {
            // leading zero
        } else if digits < 19 {
            mant = mant * 10 + d;
            digits += 1;
        } else {
            exp10 = exp10.saturating_add(1);
        }
        i += 1;
    }

    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            let d = (bytes[i] - b'0') as u64;
            if mant == 0 && d == 0 {
                exp10 = exp10.saturating_sub(1);
            } else if digits < 19 {
                mant = mant * 10 + d;
                digits += 1;
                exp10 = exp10.saturating_sub(1);
            }
            i += 1;
        }
    }

    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        i += 1;
        let exp_neg = if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
            let is_neg = bytes[i] == b'-';
            i += 1;
            is_neg
        } else {
            false
        };
        let mut e_val: i32 = 0;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            if e_val < 10_000 {
                e_val = e_val * 10 + (bytes[i] - b'0') as i32;
            }
            i += 1;
        }
        if exp_neg {
            exp10 = exp10.saturating_sub(e_val);
        } else {
            exp10 = exp10.saturating_add(e_val);
        }
    }

    if i != bytes.len() {
        return None;
    }
    if mant == 0 {
        return Some(0.0);
    }

    let val = apply_pow10(mant as f64, exp10);
    if !val.is_finite() {
        return None;
    }
    Some(if neg { -val } else { val })
}

fn pow10_pos(mut exp: u32) -> f64 {
    const POWS: [f64; 9] = [1e1, 1e2, 1e4, 1e8, 1e16, 1e32, 1e64, 1e128, 1e256];
    let mut acc = 1.0f64;
    let mut idx = 0;
    while exp > 0 && idx < POWS.len() {
        if (exp & 1) != 0 {
            acc *= POWS[idx];
        }
        exp >>= 1;
        idx += 1;
    }
    acc
}

fn apply_pow10(mut v: f64, exp10: i32) -> f64 {
    if exp10 == 0 {
        return v;
    }
    if exp10 > 0 {
        if exp10 > 309 {
            return f64::INFINITY;
        }
        if exp10 > 300 {
            v *= pow10_pos(300);
            v *= pow10_pos((exp10 - 300) as u32);
        } else {
            v *= pow10_pos(exp10 as u32);
        }
        v
    } else {
        let neg_e = -exp10;
        if neg_e > 340 {
            return 0.0;
        }
        if neg_e > 300 {
            v /= pow10_pos(300);
            v /= pow10_pos((neg_e - 300) as u32);
        } else {
            v /= pow10_pos(neg_e as u32);
        }
        v
    }
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err("JSON nesting depth exceeds limit".to_string());
        }
        self.skip_ws();
        let b = self
            .peek()
            .ok_or_else(|| err_off("unexpected end of input", self.pos))?;
        match b {
            b'n' => self.parse_literal(b"null", Json::Null),
            b't' => self.parse_literal(b"true", Json::Bool(true)),
            b'f' => self.parse_literal(b"false", Json::Bool(false)),
            b'"' => self.parse_string().map(Json::Str),
            b'[' => self.parse_array(depth + 1),
            b'{' => self.parse_object(depth + 1),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(err_off("unexpected character", self.pos)),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], val: Json) -> Result<Json, String> {
        let start = self.pos;
        if self.src.len().saturating_sub(self.pos) >= lit.len()
            && &self.src[self.pos..self.pos + lit.len()] == lit
        {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err(err_off("invalid literal", start))
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err("JSON nesting depth exceeds limit".to_string());
        }
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            let v = self.parse_value(depth)?;
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => {
                    return Err(err_off("expected ',' or ']' in array", self.pos));
                }
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err("JSON nesting depth exceeds limit".to_string());
        }
        self.pos += 1; // '{'
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(err_off("expected object key string", self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(err_off("expected ':' after object key", self.pos));
            }
            let val = self.parse_value(depth)?;
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(entries));
                }
                _ => {
                    return Err(err_off("expected ',' or '}' in object", self.pos));
                }
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        let start = self.pos;
        self.pos += 1; // '"'
        let mut out = String::new();
        let mut chunk_start = self.pos;
        while let Some(b) = self.peek() {
            if b == b'"' {
                if self.pos > chunk_start {
                    let s = std::str::from_utf8(&self.src[chunk_start..self.pos])
                        .map_err(|_| err_off("invalid UTF-8 in string", start))?;
                    out.push_str(s);
                }
                self.pos += 1;
                return Ok(out);
            }
            if b < 0x20 {
                return Err(err_off("unescaped control character in string", self.pos));
            }
            if b == b'\\' {
                if self.pos > chunk_start {
                    let s = std::str::from_utf8(&self.src[chunk_start..self.pos])
                        .map_err(|_| err_off("invalid UTF-8 in string", start))?;
                    out.push_str(s);
                }
                self.pos += 1;
                let esc = self
                    .bump()
                    .ok_or_else(|| err_off("unterminated escape", self.pos))?;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let code = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            if self.src.len().saturating_sub(self.pos) < 2
                                || self.src[self.pos] != b'\\'
                                || self.src[self.pos + 1] != b'u'
                            {
                                return Err(err_off("unpaired high surrogate", self.pos));
                            }
                            self.pos += 2;
                            let low = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(err_off("invalid low surrogate", self.pos));
                            }
                            let cp =
                                0x10000 + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                            let ch = char::from_u32(cp)
                                .ok_or_else(|| err_off("invalid Unicode scalar", self.pos))?;
                            out.push(ch);
                        } else if (0xDC00..=0xDFFF).contains(&code) {
                            return Err(err_off("unpaired low surrogate", self.pos));
                        } else {
                            let ch = char::from_u32(code as u32)
                                .ok_or_else(|| err_off("invalid Unicode scalar", self.pos))?;
                            out.push(ch);
                        }
                    }
                    _ => {
                        return Err(err_off("invalid escape sequence", self.pos - 1));
                    }
                }
                chunk_start = self.pos;
            } else {
                self.pos += 1;
            }
        }
        Err(err_off("unterminated string", start))
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        if self.src.len().saturating_sub(self.pos) < 4 {
            return Err(err_off("truncated \\uXXXX escape", self.pos));
        }
        let mut val = 0u16;
        for _ in 0..4 {
            let b = self.src[self.pos];
            let d = match b {
                b'0'..=b'9' => (b - b'0') as u16,
                b'a'..=b'f' => (b - b'a' + 10) as u16,
                b'A'..=b'F' => (b - b'A' + 10) as u16,
                _ => {
                    return Err(err_off("invalid hex digit in \\uXXXX", self.pos));
                }
            };
            val = (val << 4) | d;
            self.pos += 1;
        }
        Ok(val)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(err_off("leading zero in number", start));
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(err_off("invalid number", start)),
        }

        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(err_off("expected digit after decimal point", self.pos));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(err_off("expected digit in exponent", self.pos));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        let bytes = &self.src[start..self.pos];
        if !is_float {
            if let Some(i) = crate::str::parse_i64(bytes) {
                return Ok(Json::Int(i));
            }
        }
        let f = parse_f64_decimal(bytes).ok_or_else(|| err_off("invalid float", start))?;
        Ok(Json::Float(f))
    }
}

#[inline(never)]
pub fn push_escaped_str(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push_str("\\u00");
                out.push(HEX[((code >> 4) & 0xf) as usize] as char);
                out.push(HEX[(code & 0xf) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_fixed9(scaled: u64, out: &mut String) {
    const SCALE: u64 = 1_000_000_000;
    let whole = scaled / SCALE;
    let frac = scaled % SCALE;
    push_u64(out, whole);
    out.push('.');
    if frac == 0 {
        out.push('0');
        return;
    }
    let mut digits = [b'0'; 9];
    let mut rem = frac;
    for i in (0..9).rev() {
        digits[i] = b'0' + (rem % 10) as u8;
        rem /= 10;
    }
    let mut end = 9;
    while end > 1 && digits[end - 1] == b'0' {
        end -= 1;
    }
    for &b in &digits[..end] {
        out.push(b as char);
    }
}

/// Hand-rolled decimal `f64` serializer to avoid linking `core::fmt::float`.
#[inline(never)]
fn push_float(f: f64, out: &mut String) {
    if !f.is_finite() {
        out.push_str("null");
        return;
    }
    if f == 0.0 {
        out.push_str("0.0");
        return;
    }
    let v = if f < 0.0 {
        out.push('-');
        -f
    } else {
        f
    };

    if v < 9_007_199_254_740_992.0 && v.fract() == 0.0 {
        push_u64(out, v as u64);
        out.push_str(".0");
        return;
    }
    if (1e-4..1e9).contains(&v) {
        let scaled = (v * 1_000_000_000.0).round() as u64;
        push_fixed9(scaled, out);
        return;
    }

    let mut m = v;
    let mut exp: i32 = 0;
    while m >= 10.0 {
        m /= 10.0;
        exp += 1;
    }
    while m < 1.0 {
        m *= 10.0;
        exp -= 1;
    }
    let mut scaled = (m * 1_000_000_000.0).round() as u64;
    if scaled >= 10_000_000_000 {
        scaled /= 10;
        exp += 1;
    }
    push_fixed9(scaled, out);
    out.push('e');
    push_i64(out, exp as i64);
}

fn push_indent(level: usize, out: &mut String) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

#[cfg(test)]
#[cfg(test)]
fn write_json(val: &Json, indent: Option<usize>, out: &mut String) {
    match val {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(n) => push_i64(out, *n),
        Json::Float(f) => push_float(*f, out),
        Json::Str(s) => push_escaped_str(s, out),
        Json::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            if indent.is_some() {
                out.push('\n');
            }
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if indent.is_some() {
                        out.push('\n');
                    }
                }
                if let Some(ind) = indent {
                    push_indent(ind + 1, out);
                    write_json(item, Some(ind + 1), out);
                } else {
                    write_json(item, None, out);
                }
            }
            if let Some(ind) = indent {
                out.push('\n');
                push_indent(ind, out);
            }
            out.push(']');
        }
        Json::Obj(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            if indent.is_some() {
                out.push('\n');
            }
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if indent.is_some() {
                        out.push('\n');
                    }
                }
                if let Some(ind) = indent {
                    push_indent(ind + 1, out);
                }
                push_escaped_str(k, out);
                out.push(':');
                if let Some(ind) = indent {
                    out.push(' ');
                    write_json(v, Some(ind + 1), out);
                } else {
                    write_json(v, None, out);
                }
            }
            if let Some(ind) = indent {
                out.push('\n');
                push_indent(ind, out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_primitives_and_numbers() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse(" true ").unwrap(), Json::Bool(true));
        assert_eq!(parse("\n\tfalse\r").unwrap(), Json::Bool(false));
        assert_eq!(parse("0").unwrap(), Json::Int(0));
        assert_eq!(parse("-0").unwrap(), Json::Int(0));
        assert_eq!(parse("-42").unwrap(), Json::Int(-42));
        assert_eq!(parse("9223372036854775807").unwrap(), Json::Int(i64::MAX));
        assert_eq!(parse("-9223372036854775808").unwrap(), Json::Int(i64::MIN));
        assert_eq!(parse("3.25").unwrap(), Json::Float(3.25));
        assert_eq!(parse("1e3").unwrap(), Json::Float(1000.0));
        assert_eq!(parse("-2.5E-2").unwrap(), Json::Float(-0.025));
    }

    #[test]
    fn parse_escapes_and_surrogate_pairs() {
        let s = parse(r#""a\"b\\c\/d\be\ff\ng\rh\ti""#).unwrap();
        assert_eq!(s.as_str(), Some("a\"b\\c/d\u{0008}e\u{000C}f\ng\rh\ti"));

        let bmp = parse(r#""\u0041\u03b1""#).unwrap();
        assert_eq!(bmp.as_str(), Some("Aα"));

        // U+1F600 (GRINNING FACE) = \uD83D\uDE00
        let emoji = parse(r#""\uD83D\uDE00""#).unwrap();
        assert_eq!(emoji.as_str(), Some("😀"));

        // Lone surrogates must fail.
        assert!(parse(r#""\uD83D""#).is_err());
        assert!(parse(r#""\uD83Dabc""#).is_err());
        assert!(parse(r#""\uDE00""#).is_err());
        assert!(parse(r#""\uD83D\u0041""#).is_err());
    }

    #[test]
    fn reject_invalid_json() {
        assert!(parse("").is_err());
        assert!(parse("01").is_err());
        assert!(parse("-01").is_err());
        assert!(parse("+1").is_err());
        assert!(parse(".5").is_err());
        assert!(parse("1.").is_err());
        assert!(parse("1e").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\":1,}").is_err());
        assert!(parse("true false").is_err());
        assert!(parse("\"raw\nnewline\"").is_err());
        assert!(parse("\"raw\x01ctrl\"").is_err());
        assert!(parse("\"\\x41\"").is_err());
        assert!(parse("NaN").is_err());
        assert!(parse("Infinity").is_err());
    }

    #[test]
    fn depth_limit_enforced() {
        let ok = format!("{}{}", "[".repeat(64), "]".repeat(64));
        assert!(parse(&ok).is_ok());

        let too_deep = format!("{}{}", "[".repeat(65), "]".repeat(65));
        assert!(parse(&too_deep).is_err());
    }

    #[test]
    fn helpers_and_reject_unknown_keys() {
        let doc =
            parse(r#"{"s":"hi","i":-5,"u":42,"f":1.5,"b":true,"a":[1,2],"o":{"k":"v"}}"#).unwrap();
        assert_eq!(doc.req_str("s").unwrap(), "hi");
        assert_eq!(doc.req_i64("i").unwrap(), -5);
        assert_eq!(doc.req_u64("u").unwrap(), 42);
        assert_eq!(doc.req_f64("f").unwrap(), 1.5);
        assert_eq!(doc.req_f64("u").unwrap(), 42.0);
        assert!(doc.req_bool("b").unwrap());
        assert_eq!(doc.req_arr("a").unwrap().len(), 2);
        assert_eq!(doc.req_obj("o").unwrap().len(), 1);
        assert!(doc.req_u64("i").is_err());
        assert!(doc.req_str("missing").is_err());

        doc.reject_unknown_keys(&["s", "i", "u", "f", "b", "a", "o"], "root")
            .unwrap();
        assert!(doc
            .reject_unknown_keys(&["s", "i", "u", "f", "b", "a"], "root")
            .is_err());

        let dup = parse(r#"{"a":1,"a":2}"#).unwrap();
        assert!(dup.reject_unknown_keys(&["a"], "dup").is_err());
    }

    #[test]
    fn compact_and_pretty_roundtrip() {
        let orig = Json::Obj(vec![
            ("empty_arr".into(), Json::Arr(vec![])),
            ("empty_obj".into(), Json::Obj(vec![])),
            ("ctrl".into(), Json::Str("line1\n\"quoted\"\\\x07\t".into())),
            ("num".into(), Json::Int(123)),
            ("flt".into(), Json::Float(18.0)),
            (
                "nested".into(),
                Json::Arr(vec![Json::Bool(true), Json::Null]),
            ),
        ]);
        let compact = orig.to_string();
        assert_eq!(parse(&compact).unwrap(), orig);
        let pretty = orig.to_pretty();
        assert!(pretty.contains("\n  \"ctrl\": "));
        assert_eq!(parse(&pretty).unwrap(), orig);
    }
}
