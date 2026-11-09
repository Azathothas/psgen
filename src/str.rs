//! Byte-string building and parsing without `core::fmt`.

pub struct Buf {
    pub v: Vec<u8>,
}

impl Buf {
    pub fn new() -> Buf {
        Buf { v: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Buf {
        Buf {
            v: Vec::with_capacity(n),
        }
    }

    pub fn push(&mut self, b: u8) {
        self.v.push(b);
    }

    pub fn push_str(&mut self, s: &str) {
        self.v.extend_from_slice(s.as_bytes());
    }

    pub fn push_bytes(&mut self, s: &[u8]) {
        self.v.extend_from_slice(s);
    }

    pub fn push_u64(&mut self, mut n: u64) {
        let mut tmp = [0u8; 20];
        let mut i = 0;
        if n == 0 {
            self.v.push(b'0');
            return;
        }
        while n > 0 {
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
        while i > 0 {
            i -= 1;
            self.v.push(tmp[i]);
        }
    }

    /// Right-aligned unsigned integer in a field of `width` bytes.
    pub fn push_u64_width(&mut self, n: u64, width: usize) {
        let mut tmp = [0u8; 20];
        let mut i = 0;
        let mut v = n;
        if v == 0 {
            tmp[0] = b'0';
            i = 1;
        } else {
            while v > 0 {
                tmp[i] = b'0' + (v % 10) as u8;
                v /= 10;
                i += 1;
            }
        }
        let mut pad = width.saturating_sub(i);
        while pad > 0 {
            self.v.push(b' ');
            pad -= 1;
        }
        while i > 0 {
            i -= 1;
            self.v.push(tmp[i]);
        }
    }

    /// One decimal place from a value in tenths, right-aligned.
    pub fn push_tenths_width(&mut self, tenths: u32, width: usize) {
        let whole = tenths / 10;
        let frac = tenths % 10;
        let mut tmp = [0u8; 20];
        let mut i = 0;
        let mut v = whole;
        if v == 0 {
            tmp[0] = b'0';
            i = 1;
        } else {
            while v > 0 {
                tmp[i] = b'0' + (v % 10) as u8;
                v /= 10;
                i += 1;
            }
        }
        let total = i + 2;
        let mut pad = width.saturating_sub(total);
        while pad > 0 {
            self.v.push(b' ');
            pad -= 1;
        }
        while i > 0 {
            i -= 1;
            self.v.push(tmp[i]);
        }
        self.v.push(b'.');
        self.v.push(b'0' + frac as u8);
    }

    /// One decimal place, no padding: `0.4`.
    pub fn push_tenths_plain(&mut self, tenths: u32) {
        self.push_u64((tenths / 10) as u64);
        self.v.push(b'.');
        self.v.push(b'0' + (tenths % 10) as u8);
    }

    pub fn push_time(&mut self, secs: u64) {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        if h > 0 {
            self.push_u64(h);
            self.push(b':');
            self.push_two(m);
            self.push(b':');
            self.push_two(s);
        } else {
            self.push_u64(m);
            self.push(b':');
            self.push_two(s);
        }
    }

    /// Two decimal digits, zero padded.
    pub fn push_two(&mut self, n: u64) {
        self.v.push(b'0' + (n / 10) as u8);
        self.v.push(b'0' + (n % 10) as u8);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.v
    }
}

pub fn starts_with(a: &[u8], b: &[u8]) -> bool {
    a.len() >= b.len() && &a[..b.len()] == b
}

pub fn find(a: &[u8], b: &[u8]) -> Option<usize> {
    if b.is_empty() {
        return Some(0);
    }
    if a.len() < b.len() {
        return None;
    }
    let mut i = 0;
    while i + b.len() <= a.len() {
        if &a[i..i + b.len()] == b {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn trim(a: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = a.len();
    while start < end
        && (a[start] == b' ' || a[start] == b'\t' || a[start] == b'\r' || a[start] == b'\n')
    {
        start += 1;
    }
    while end > start
        && (a[end - 1] == b' ' || a[end - 1] == b'\t' || a[end - 1] == b'\r' || a[end - 1] == b'\n')
    {
        end -= 1;
    }
    &a[start..end]
}

pub fn parse_u64(a: &[u8]) -> Option<u64> {
    let a = trim(a);
    if a.is_empty() {
        return None;
    }
    let mut n = 0u64;
    let mut i = 0;
    while i < a.len() {
        let c = a[i];
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((c - b'0') as u64)?;
        i += 1;
    }
    Some(n)
}

pub fn parse_i64(a: &[u8]) -> Option<i64> {
    let a = trim(a);
    if a.is_empty() {
        return None;
    }
    if a[0] == b'-' {
        let n = parse_u64(&a[1..])?;
        if n == i64::MAX as u64 + 1 {
            Some(i64::MIN)
        } else if n <= i64::MAX as u64 {
            Some(-(n as i64))
        } else {
            None
        }
    } else {
        let digits = if a[0] == b'+' { &a[1..] } else { a };
        let n = parse_u64(digits)?;
        if n <= i64::MAX as u64 {
            Some(n as i64)
        } else {
            None
        }
    }
}

pub fn basename(path: &[u8]) -> &[u8] {
    let mut last = 0;
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'/' {
            last = i + 1;
        }
        i += 1;
    }
    &path[last..]
}
