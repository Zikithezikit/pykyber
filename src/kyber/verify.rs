//! Comparison and conditional move for the round-3 Kyber re-encryption check.
//!
//! The standard library has no constant-time guarantee. `black_box` is an
//! optimization barrier: the compiler may not assume what the accumulated
//! difference or the select mask is, so it cannot prove them to be 0/1 and
//! rewrite the select as a branch (the pattern behind CVE-2024-37880,
//! "Clangover"). It is best effort, so the release assembly is checked (see
//! SECURITY.md). The ML-KEM side does the same in `mlkem::ct`. `len` is public
//! and must not exceed either slice.

use core::hint::black_box;

/// Shift that moves the top bit of a `u16` to bit 0.
const FLAG_SHIFT: u32 = u16::BITS - 1;

/// Returns 0 if the first `len` bytes of `a` and `b` are equal, 1 otherwise.
pub fn verify(a: &[u8], b: &[u8], len: usize) -> u8 {
    let mut r = 0u8;
    for i in 0..len {
        r |= a[i] ^ b[i];
    }
    // bit = 1 if r != 0 else 0: for r in 1..=255 the top bit of `-r` as a u16 is set.
    let wide = u16::from(black_box(r));
    black_box(((wide | wide.wrapping_neg()) >> FLAG_SHIFT) as u8)
}

/// Copies the first `len` bytes of `x` into `r` if `b` is 1, and leaves `r`
/// alone if `b` is 0. `b` must be 0 or 1.
pub fn cmov(r: &mut [u8], x: &[u8], len: usize, b: u8) {
    // 0x00 (keep r) or 0xff (take x).
    let mask = black_box(black_box(b).wrapping_neg());
    for i in 0..len {
        r[i] ^= mask & (x[i] ^ r[i]);
    }
}
