//! A small xoshiro256** generator. Deterministic when a seed is supplied.

use crate::sys;

pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        let mut s = [0u64; 4];
        let mut x = seed ^ 0x9e3779b97f4a7c15;
        for slot in s.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *slot = x;
        }
        Rng { s }
    }

    pub fn from_entropy() -> Rng {
        let mut bytes = [0u8; 32];
        if !sys::getrandom(&mut bytes) {
            let t = sys::now_secs() ^ ((sys::getpid() as u64) << 32);
            let mut x = t | 1;
            for chunk in bytes.chunks_mut(8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                chunk.copy_from_slice(&x.to_le_bytes());
            }
        }
        let mut s = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(chunk);
            s[i] = u64::from_le_bytes(b);
        }
        if s == [0; 4] {
            s[0] = 1;
        }
        Rng { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform in `[0, n)`. Modulo bias is irrelevant at these sizes.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.below(hi - lo + 1)
        }
    }

    pub fn hex(&mut self, digits: usize, out: &mut [u8]) {
        let mut i = 0;
        while i < digits {
            let v = self.next_u64();
            let mut j = 0;
            while j < 16 && i < digits {
                let d = ((v >> (j * 4)) & 0xf) as u8;
                out[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
                i += 1;
                j += 1;
            }
        }
    }
}
