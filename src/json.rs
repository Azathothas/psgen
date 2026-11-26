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

    #[inline(never)]
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

    #[inline(never)]
    fn open(&mut self, ch: char) {
        self.out.push(ch);
        self.depth += 1;
        self.need_comma = false;
    }

    #[inline(never)]
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

    #[inline(never)]
    fn k_open(&mut self, k: &str, ch: char) {
        self.key(k);
        self.open(ch);
    }

    pub fn k_obj(&mut self, k: &str) {
        self.k_open(k, '{');
    }

    pub fn k_arr(&mut self, k: &str) {
        self.k_open(k, '[');
    }

    #[inline(never)]
    pub fn k_str(&mut self, k: &str, v: &str) {
        self.key(k);
        push_escaped_str(v, &mut self.out);
    }

    #[inline(never)]
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

    #[inline(never)]
    pub fn k_f64(&mut self, k: &str, v: f64) {
        self.key(k);
        push_float(v, &mut self.out);
    }

    #[inline(never)]
    fn k_lit(&mut self, k: &str, lit: &str) {
        self.key(k);
        self.out.push_str(lit);
    }

    pub fn k_bool(&mut self, k: &str, v: bool) {
        self.k_lit(k, if v { "true" } else { "false" });
    }

    pub fn k_null(&mut self, k: &str) {
        self.k_lit(k, "null");
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

    #[inline(never)]
    pub fn k_i32_arr(&mut self, k: &str, items: &[i32]) {
        self.k_arr(k);
        for &n in items {
            self.sep();
            push_i64(&mut self.out, n as i64);
        }
        self.arr_close();
    }

    pub fn k_u32_arr(&mut self, k: &str, items: &[u32]) {
        self.k_arr(k);
        for &n in items {
            self.sep();
            push_u64(&mut self.out, n as u64);
        }
        self.arr_close();
    }

    #[inline(never)]
    pub fn k_some_str(&mut self, k: &str, v: &Option<String>) {
        if let Some(ref s) = v {
            self.k_str(k, s);
        }
    }

    #[inline(never)]
    pub fn k_some_u64(&mut self, k: &str, v: Option<u64>) {
        if let Some(n) = v {
            self.k_u64(k, n);
        }
    }

    #[inline(never)]
    fn push_r6(&mut self, v: f64) {
        push_float(round6(v), &mut self.out);
    }

    #[inline(never)]
    pub fn k_f64_r6(&mut self, k: &str, v: f64) {
        self.key(k);
        self.push_r6(v);
    }

    #[inline(never)]
    pub fn k_f64_pair_r6(&mut self, k: &str, p: (f64, f64)) {
        self.k_arr(k);
        self.sep();
        self.push_r6(p.0);
        self.sep();
        self.push_r6(p.1);
        self.arr_close();
    }

    #[inline(never)]
    pub fn k_strs(&mut self, mut csv: &str, vals: &[&str]) {
        for &v in vals {
            self.k_str(next_csv(&mut csv), v);
        }
    }

    pub fn k_some_strs(&mut self, mut csv: &str, vals: &[&Option<String>]) {
        for &v in vals {
            self.k_some_str(next_csv(&mut csv), v);
        }
    }

    #[inline(never)]
    pub fn k_i64s(&mut self, mut csv: &str, vals: &[i64]) {
        for &v in vals {
            self.k_i64(next_csv(&mut csv), v);
        }
    }

    #[inline(never)]
    pub fn k_u64s(&mut self, mut csv: &str, vals: &[u64]) {
        for &v in vals {
            self.k_u64(next_csv(&mut csv), v);
        }
    }

    #[inline(never)]
    pub fn k_f64s_r6(&mut self, mut csv: &str, vals: &[f64]) {
        for &v in vals {
            self.k_f64_r6(next_csv(&mut csv), v);
        }
    }

    #[inline(never)]
    pub fn k_str_arrs(&mut self, mut csv: &str, vals: &[&[String]]) {
        for &v in vals {
            self.k_str_arr(next_csv(&mut csv), v);
        }
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
pub fn next_csv<'a>(csv: &mut &'a str) -> &'a str {
    match csv.split_once(',') {
        Some((k, rest)) => {
            *csv = rest;
            k
        }
        None => {
            let k = *csv;
            *csv = "";
            k
        }
    }
}

#[inline(never)]
pub fn csv_idx(mut csv: &str, needle: &str, ci: bool) -> Option<usize> {
    let mut i = 0;
    while !csv.is_empty() {
        let item = next_csv(&mut csv);
        if if ci {
            item.eq_ignore_ascii_case(needle)
        } else {
            item == needle
        } {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn csv_has(csv: &str, needle: &str) -> bool {
    csv_idx(csv, needle, false).is_some()
}

pub fn csv_nth(mut csv: &str, idx: usize) -> &str {
    for _ in 0..idx {
        let _ = next_csv(&mut csv);
    }
    next_csv(&mut csv)
}

#[inline(never)]
pub fn lossy(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

#[inline(never)]
pub fn path_lossy(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[inline(never)]
pub fn own(s: &str) -> String {
    String::from(s)
}

#[inline(never)]
pub fn assign_str(dst: &mut String, s: &str) {
    dst.clear();
    dst.push_str(s);
}

#[inline(never)]
pub fn concat(parts: &[&str]) -> String {
    let mut len = 0;
    for &p in parts {
        len += p.len();
    }
    let mut s = String::with_capacity(len);
    for &p in parts {
        s.push_str(p);
    }
    s
}

#[inline(never)]
pub fn cat2(a: &str, b: &str) -> String {
    concat(&[a, b])
}

#[inline(never)]
pub fn cat3(a: &str, b: &str, c: &str) -> String {
    concat(&[a, b, c])
}

#[inline(never)]
pub fn cat4(a: &str, b: &str, c: &str, d: &str) -> String {
    concat(&[a, b, c, d])
}

#[inline(never)]
pub fn join_strs(items: &[String], sep: &str) -> String {
    let mut out = String::new();
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(sep);
        }
        out.push_str(s);
    }
    out
}

#[inline(never)]
pub fn push_unique_str(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(own(s));
    }
}

#[inline(never)]
pub fn push_u64(out: &mut String, mut n: u64) {
    if n == 0 {
        out.push('0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 && i < tmp.len() {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        out.push(tmp[i] as char);
    }
}

#[inline(never)]
pub fn push_i64(out: &mut String, n: i64) {
    if n < 0 {
        out.push('-');
        push_u64(out, n.unsigned_abs());
    } else {
        push_u64(out, n as u64);
    }
}

#[inline(never)]
pub fn u64_str(n: u64) -> String {
    let mut s = String::new();
    push_u64(&mut s, n);
    s
}

#[inline(never)]
pub fn i64_str(n: i64) -> String {
    let mut s = String::new();
    push_i64(&mut s, n);
    s
}

#[inline(never)]
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

#[inline(never)]
pub fn push_str_left(out: &mut String, s: &str, width: usize) {
    out.push_str(s);
    for _ in s.len()..width {
        out.push(' ');
    }
}

#[inline(never)]
pub fn err_io(op: &str, path: &Path, e: &std::io::Error) -> String {
    let mut s = cat3(op, " ", &path_lossy(path));
    if let Some(code) = e.raw_os_error() {
        s.push_str(": errno ");
        push_i64(&mut s, code as i64);
    }
    s
}

#[inline(never)]
pub fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| err_io("read", path, &e))
}

#[inline(never)]
pub fn read_str(path: &Path) -> Result<String, String> {
    String::from_utf8(read_bytes(path)?).map_err(|_| own("invalid utf-8"))
}

#[inline(never)]
pub fn read_str_in(dir: &Path, rel: &str) -> Result<String, String> {
    read_str(&dir.join(rel))
}

#[inline(never)]
pub fn read_opt_in(dir: &Path, rel: &str) -> Option<String> {
    read_str_in(dir, rel).ok()
}

#[inline(never)]
pub fn write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    fs::write(path, data).map_err(|e| err_io("write", path, &e))
}

pub fn write_in(dir: &Path, rel: &str, data: &[u8]) -> Result<(), String> {
    write_file(&dir.join(rel), data)
}

#[inline(never)]
pub fn mkdir_all(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| err_io("mkdir", path, &e))
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

    #[inline(never)]
    pub fn write(&mut self, rel: &str, data: &[u8]) {
        if self.err.is_none() {
            if let Err(e) = write_in(self.dir, rel, data) {
                self.err = Some(e);
            }
        }
    }

    #[inline(never)]
    pub fn line(&mut self, rel: &str, line: &str) {
        self.write(rel, cat2(line, "\n").as_bytes());
    }

    #[inline(never)]
    pub fn lines(&mut self, rel: &str, items: &[String]) {
        let mut s = join_strs(items, "\n");
        if !s.is_empty() {
            s.push('\n');
        }
        self.write(rel, s.as_bytes());
    }

    #[inline(never)]
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
        for i in gap..n {
            let mut j = i;
            while j >= gap {
                let k = j - gap;
                let (Some(a), Some(b)) = (v.get(k), v.get(j)) else {
                    break;
                };
                if !gt(a, b) {
                    break;
                }
                v.swap(k, j);
                j = k;
            }
        }
    }
}

#[inline(never)]
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
    cat2("missing ", key)
}

#[cfg(test)]
fn err_type(key: &str, expected: &str) -> String {
    cat3(key, ": expected ", expected)
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
                if *f >= 0.0 && *f <= 9_007_199_254_740_992.0 && (*f as u64) as f64 == *f =>
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

    #[inline(never)]
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_obj()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key)?.as_str()
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key)?.as_bool()
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key)?.as_i64()
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key)?.as_u64()
    }

    pub fn get_arr(&self, key: &str) -> Option<&[Json]> {
        self.get(key)?.as_arr()
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

    #[inline(never)]
    pub fn req_arr(&self, key: &str) -> Result<&[Json], String> {
        self.get_arr(key).ok_or_else(|| err_missing(key))
    }

    #[cfg(test)]
    pub fn req_obj(&self, key: &str) -> Result<&[(String, Json)], String> {
        let v = self.get(key).ok_or_else(|| err_missing(key))?;
        v.as_obj().ok_or_else(|| err_type(key, "an object"))
    }

    /// Reject any key not present in comma-separated `allowed_csv`, as well as duplicate keys.
    #[inline(never)]
    pub fn reject_unknown_keys_csv(&self, allowed_csv: &str, ctx: &str) -> Result<(), String> {
        let entries = self.as_obj().ok_or_else(|| cat2(ctx, ": obj"))?;
        for (i, (k, _)) in entries.iter().enumerate() {
            let dup = entries
                .get(..i)
                .is_some_and(|prev| prev.iter().any(|(p, _)| p == k));
            if !csv_has(allowed_csv, k) || dup {
                return Err(cat2("bad field ", k));
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
    #[inline(never)]
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

    #[inline(never)]
    fn get_val(&mut self, k: &str, req: bool) -> Option<&'a Json> {
        match self.v.get(k) {
            Some(Json::Null) if !req => None,
            Some(v) => Some(v),
            None => {
                if req {
                    self.fail(k, ": missing");
                }
                None
            }
        }
    }

    #[inline(never)]
    pub fn str_ref(&mut self, k: &str) -> &'a str {
        let Some(v) = self.get_val(k, true) else {
            return "";
        };
        match v.as_str() {
            Some(s) => s,
            None => {
                self.fail(k, ": str");
                ""
            }
        }
    }

    pub fn str(&mut self, k: &str) -> String {
        own(self.str_ref(k))
    }

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

    #[inline(never)]
    pub fn fill_strs(&mut self, mut csv: &str, dsts: &mut [&mut String]) {
        for dst in dsts {
            self.fill_str(next_csv(&mut csv), dst);
        }
    }

    #[inline(never)]
    pub fn fill_opt_strs(&mut self, mut csv: &str, dsts: &mut [&mut Option<String>]) {
        for dst in dsts {
            **dst = self.opt_str(next_csv(&mut csv));
        }
    }

    #[inline(never)]
    pub fn fill_str_arrs(&mut self, mut csv: &str, dsts: &mut [&mut Vec<String>]) {
        for dst in dsts {
            **dst = self.str_arr(next_csv(&mut csv));
        }
    }

    #[inline(never)]
    pub fn fill_i32s(&mut self, mut csv: &str, dsts: &mut [&mut i32]) {
        for dst in dsts {
            **dst = self.i32(next_csv(&mut csv));
        }
    }

    #[inline(never)]
    pub fn fill_u32s(&mut self, mut csv: &str, dsts: &mut [&mut u32]) {
        for dst in dsts {
            **dst = self.u32(next_csv(&mut csv));
        }
    }

    #[inline(never)]
    pub fn fill_u64s(&mut self, mut csv: &str, dsts: &mut [&mut u64]) {
        for dst in dsts {
            **dst = self.u64(next_csv(&mut csv));
        }
    }

    #[inline(never)]
    pub fn fill_opt_u64s(&mut self, mut csv: &str, dsts: &mut [&mut Option<u64>]) {
        for dst in dsts {
            **dst = self.opt_u64(next_csv(&mut csv));
        }
    }

    #[inline(never)]
    pub fn opt_str(&mut self, k: &str) -> Option<String> {
        let v = self.get_val(k, false)?;
        match v.as_str() {
            Some(s) => Some(own(s)),
            None => {
                self.fail(k, ": str");
                None
            }
        }
    }

    #[inline(never)]
    fn read_u64(&mut self, k: &str, req: bool, max: u64) -> Option<u64> {
        let v = self.get_val(k, req)?;
        match v.as_u64() {
            Some(n) if n <= max => Some(n),
            _ => {
                self.fail(k, ": int");
                None
            }
        }
    }

    pub fn u64(&mut self, k: &str) -> u64 {
        self.read_u64(k, true, u64::MAX).unwrap_or(0)
    }

    pub fn opt_u64(&mut self, k: &str) -> Option<u64> {
        self.read_u64(k, false, u64::MAX)
    }

    pub fn opt_u32(&mut self, k: &str) -> Option<u32> {
        self.read_u64(k, false, u32::MAX as u64).map(|n| n as u32)
    }

    #[inline(never)]
    pub fn i32(&mut self, k: &str) -> i32 {
        let Some(v) = self.get_val(k, true) else {
            return 0;
        };
        match v.as_i64().and_then(|n| i32::try_from(n).ok()) {
            Some(n) => n,
            None => {
                self.fail(k, ": i32");
                0
            }
        }
    }

    pub fn u32(&mut self, k: &str) -> u32 {
        self.read_u64(k, true, u32::MAX as u64).unwrap_or(0) as u32
    }

    #[inline(never)]
    fn read_f64(&mut self, k: &str, req: bool) -> Option<f64> {
        let v = self.get_val(k, req)?;
        match v.as_f64() {
            Some(f) => Some(f),
            None => {
                self.fail(k, ": num");
                None
            }
        }
    }

    pub fn f64(&mut self, k: &str) -> f64 {
        self.read_f64(k, true).unwrap_or(0.0)
    }

    pub fn opt_f64(&mut self, k: &str) -> Option<f64> {
        self.read_f64(k, false)
    }

    #[inline(never)]
    fn read_bool(&mut self, k: &str, req: bool) -> Option<bool> {
        let v = self.get_val(k, req)?;
        match v.as_bool() {
            Some(b) => Some(b),
            None => {
                self.fail(k, ": bool");
                None
            }
        }
    }

    pub fn bool(&mut self, k: &str) -> bool {
        self.read_bool(k, true).unwrap_or(false)
    }

    pub fn opt_bool(&mut self, k: &str) -> Option<bool> {
        self.read_bool(k, false)
    }

    #[inline(never)]
    fn arr_slice(&mut self, k: &str, optional: bool) -> Option<&'a [Json]> {
        let v = if optional {
            self.v.get(k)?
        } else {
            self.get_val(k, true)?
        };
        match v.as_arr() {
            Some(arr) => Some(arr),
            None => {
                self.fail(k, ": arr");
                None
            }
        }
    }

    #[inline(never)]
    pub fn str_arr(&mut self, k: &str) -> Vec<String> {
        let Some(arr) = self.arr_slice(k, false) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            match item.as_str() {
                Some(s) => out.push(own(s)),
                None => {
                    self.fail(k, ": str[]");
                    return Vec::new();
                }
            }
        }
        out
    }

    #[inline(never)]
    fn int_arr_bits(&mut self, k: &str, optional: bool, signed: bool) -> Vec<u32> {
        let Some(arr) = self.arr_slice(k, optional) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            let parsed = if signed {
                item.as_i64()
                    .and_then(|n| i32::try_from(n).ok())
                    .map(|n| n as u32)
            } else {
                item.as_u64().and_then(|n| u32::try_from(n).ok())
            };
            match parsed {
                Some(n) => out.push(n),
                None => {
                    self.fail(k, ": int[]");
                    return Vec::new();
                }
            }
        }
        out
    }

    #[inline(never)]
    pub fn i32_arr(&mut self, k: &str, optional: bool) -> Vec<i32> {
        let raw = self.int_arr_bits(k, optional, true);
        let mut out = Vec::with_capacity(raw.len());
        for n in raw {
            out.push(n as i32);
        }
        out
    }

    pub fn u32_arr(&mut self, k: &str, optional: bool) -> Vec<u32> {
        self.int_arr_bits(k, optional, false)
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

#[inline(never)]
fn err_off(off: usize) -> String {
    cat2("invalid json at ", &u64_str(off as u64))
}

/// Parse an RFC 8259 JSON document.
#[inline(never)]
pub fn parse(input: &str) -> Result<Json, String> {
    let mut p = Parser {
        src: input.as_bytes(),
        pos: 0,
    };
    let val = p.parse_value(0).ok_or_else(|| err_off(p.pos))?;
    p.skip_ws();
    if p.pos != p.src.len() {
        return Err(err_off(p.pos));
    }
    Ok(val)
}

/// Hand-rolled decimal `f64` parser to avoid linking `core::num::dec2flt`.
fn parse_f64_decimal(bytes: &[u8]) -> Option<f64> {
    let (neg, rest) = match bytes.strip_prefix(b"-") {
        Some(r) => (true, r),
        None => (false, bytes),
    };
    let mut mant = 0u64;
    let mut digits = 0u32;
    let mut exp10 = 0i32;
    let mut e_val = 0i32;
    let mut in_frac = false;
    let mut in_exp = false;
    let mut exp_neg = false;
    for &b in rest {
        if in_exp {
            if b == b'-' {
                exp_neg = true;
            } else if b.is_ascii_digit() && e_val < 10_000 {
                e_val = e_val * 10 + (b - b'0') as i32;
            }
        } else if b.is_ascii_digit() {
            let d = (b - b'0') as u64;
            if mant == 0 && d == 0 {
                if in_frac {
                    exp10 -= 1;
                }
            } else if digits < 19 {
                mant = mant * 10 + d;
                digits += 1;
                if in_frac {
                    exp10 -= 1;
                }
            } else if !in_frac {
                exp10 += 1;
            }
        } else if b == b'.' {
            in_frac = true;
        } else if matches!(b, b'e' | b'E') {
            in_exp = true;
        }
    }
    exp10 = if exp_neg {
        exp10.saturating_sub(e_val)
    } else {
        exp10.saturating_add(e_val)
    };
    if mant == 0 {
        return Some(0.0);
    }
    if exp10 > 309 {
        return None;
    }
    if exp10 < -340 {
        return Some(0.0);
    }
    let mut v = mant as f64;
    while exp10 > 0 {
        v *= 10.0;
        exp10 -= 1;
    }
    while exp10 < 0 {
        v /= 10.0;
        exp10 += 1;
    }
    v.is_finite().then_some(if neg { -v } else { v })
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
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn eat_digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos - start
    }

    #[inline(never)]
    fn parse_value(&mut self, depth: usize) -> Option<Json> {
        self.skip_ws();
        match self.peek()? {
            b'n' => self.parse_literal(b"null", Json::Null),
            b't' => self.parse_literal(b"true", Json::Bool(true)),
            b'f' => self.parse_literal(b"false", Json::Bool(false)),
            b'"' => self.parse_string().map(Json::Str),
            b'[' if depth < MAX_DEPTH => {
                self.pos += 1;
                self.skip_ws();
                let mut items = Vec::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Some(Json::Arr(items));
                }
                loop {
                    items.push(self.parse_value(depth + 1)?);
                    self.skip_ws();
                    match self.bump()? {
                        b',' => {}
                        b']' => return Some(Json::Arr(items)),
                        _ => return None,
                    }
                }
            }
            b'{' if depth < MAX_DEPTH => {
                self.pos += 1;
                self.skip_ws();
                let mut entries = Vec::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Some(Json::Obj(entries));
                }
                loop {
                    self.skip_ws();
                    if self.peek() != Some(b'"') {
                        return None;
                    }
                    let key = self.parse_string()?;
                    self.skip_ws();
                    if self.bump() != Some(b':') {
                        return None;
                    }
                    let val = self.parse_value(depth + 1)?;
                    entries.push((key, val));
                    self.skip_ws();
                    match self.bump()? {
                        b',' => {}
                        b'}' => return Some(Json::Obj(entries)),
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => None,
        }
    }

    fn parse_literal(&mut self, lit: &[u8], val: Json) -> Option<Json> {
        if self.src.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Some(val)
        } else {
            None
        }
    }

    #[inline(never)]
    fn parse_string(&mut self) -> Option<String> {
        self.pos += 1;
        let mut out = String::new();
        let mut chunk_start = self.pos;
        while let Some(b) = self.peek() {
            if b < 0x20 {
                return None;
            }
            if b != b'"' && b != b'\\' {
                self.pos += 1;
                continue;
            }
            if let Some(chunk) = self.src.get(chunk_start..self.pos) {
                if !chunk.is_empty() {
                    out.push_str(std::str::from_utf8(chunk).ok()?);
                }
            }
            self.pos += 1;
            if b == b'"' {
                return Some(out);
            }
            let ch = match self.bump()? {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\x08',
                b'f' => '\x0c',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => {
                    let code = self.parse_hex4()?;
                    let cp = if (0xD800..=0xDBFF).contains(&code) {
                        if self.src.get(self.pos..self.pos + 2) != Some(b"\\u") {
                            return None;
                        }
                        self.pos += 2;
                        let low = self.parse_hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&low) {
                            return None;
                        }
                        0x10000 + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00))
                    } else if (0xDC00..=0xDFFF).contains(&code) {
                        return None;
                    } else {
                        code as u32
                    };
                    char::from_u32(cp)?
                }
                _ => return None,
            };
            out.push(ch);
            chunk_start = self.pos;
        }
        None
    }

    fn parse_hex4(&mut self) -> Option<u16> {
        let slice = self.src.get(self.pos..self.pos + 4)?;
        let mut val = 0u16;
        for &b in slice {
            let d = if b.is_ascii_digit() {
                b - b'0'
            } else if (b | 32).wrapping_sub(b'a') < 6 {
                (b | 32) - b'a' + 10
            } else {
                return None;
            };
            val = (val << 4) | d as u16;
            self.pos += 1;
        }
        Some(val)
    }

    fn parse_number(&mut self) -> Option<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek()? {
            b'0' => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return None;
                }
            }
            b'1'..=b'9' => {
                self.eat_digits();
            }
            _ => return None,
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if self.eat_digits() == 0 {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.eat_digits() == 0 {
                return None;
            }
        }
        let bytes = self.src.get(start..self.pos)?;
        if !is_float {
            if let Some(i) = crate::str::parse_i64(bytes) {
                return Some(Json::Int(i));
            }
        }
        parse_f64_decimal(bytes).map(Json::Float)
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
                let code = c as u8;
                let hex = |n: u8| if n < 10 { b'0' + n } else { b'a' + n - 10 } as char;
                out.push_str("\\u00");
                out.push(hex(code >> 4));
                out.push(hex(code & 0xf));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_fixed9(scaled: u64, out: &mut String) {
    push_u64(out, scaled / 1_000_000_000);
    out.push('.');
    let mut rem = scaled % 1_000_000_000;
    let mut div = 100_000_000u64;
    loop {
        out.push((b'0' + (rem / div) as u8) as char);
        rem %= div;
        div /= 10;
        if rem == 0 || div == 0 {
            break;
        }
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
    let mut v = if f < 0.0 {
        out.push('-');
        -f
    } else {
        f
    };
    if (1e-4..1e9).contains(&v) {
        push_fixed9((v * 1_000_000_000.0 + 0.5) as u64, out);
        return;
    }
    let mut exp = 0i32;
    while v >= 10.0 {
        v /= 10.0;
        exp += 1;
    }
    while v < 1.0 {
        v *= 10.0;
        exp -= 1;
    }
    let mut scaled = (v * 1_000_000_000.0 + 0.5) as u64;
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

    #[test]
    fn u32_arr_write_and_read() {
        let mut w = Jw::new(false);
        w.obj_open();
        w.k_u32_arr("groups", &[0, 4, 2000, 65534]);
        w.obj_close();
        let doc = parse(&w.finish()).unwrap();
        let mut r = JRead::new(&doc, "groups", "root").unwrap();
        let groups = r.u32_arr("groups", false);
        r.check().unwrap();
        assert_eq!(groups, vec![0, 4, 2000, 65534]);
    }
}
