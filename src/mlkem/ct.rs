//! Constant-time selection for the implicit rejection of ML-KEM.Decaps_internal
//! (FIPS 203 Algorithm 18, steps 9-11).
//!
//! `c != c'` is a secret (it tells an attacker whether a chosen ciphertext was
//! well formed), so it is neither returned nor stored: `reject_on_mismatch`
//! turns it into a byte mask, applies it and overwrites it before returning.
//! There is no branch on the comparison and no early exit from the loops.
//!
//! The standard library has no constant-time guarantee. `black_box` is an
//! optimization barrier that keeps the compiler from proving what the
//! accumulator or the mask is and turning the select back into a branch (the
//! pattern behind CVE-2024-37880, "Clangover"). It is best effort, so the release
//! assembly is checked (see the PR for WP-3 and the gate of WP-8). This is not
//! `kyber::verify`, which has no barrier and trusts a caller-supplied length.

use crate::kyber::params::KYBER_SSBYTES;
use core::hint::black_box;
use zeroize::Zeroize;

/// Shift that moves the top bit of a `u16` to bit 0.
const FLAG_SHIFT: u32 = u16::BITS - 1;

/// Overwrites `k` with `k_bar` if `a` and `b` differ in length or content, and
/// leaves it alone if they are equal (Algorithm 18, steps 9-11, where `a = c`,
/// `b = c'`, `k = K'` and `k_bar = J(z || c)`).
///
/// The lengths of `a` and `b` are public. Differing lengths count as a
/// mismatch, so a caller bug fails closed instead of comparing a prefix.
pub(crate) fn reject_on_mismatch(
    k: &mut [u8; KYBER_SSBYTES],
    k_bar: &[u8; KYBER_SSBYTES],
    a: &[u8],
    b: &[u8],
) {
    // OR of all byte differences: zero exactly when the slices are equal.
    let mut diff = u8::from(a.len() != b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    // bit = 1 if diff != 0 else 0. For diff in 1..=255, `-diff` as a u16 has
    // its top bit set; for 0 both terms are 0.
    let mut wide = u16::from(black_box(diff));
    let mut bit = ((wide | wide.wrapping_neg()) >> FLAG_SHIFT) as u8;
    // 0x00 (keep K') or 0xff (take K-bar).
    let mut mask = black_box(black_box(bit).wrapping_neg());

    for (ki, kb) in k.iter_mut().zip(k_bar.iter()) {
        *ki ^= mask & (*ki ^ *kb);
    }

    // The reject flag shall be destroyed (FIPS 203 section 6.3).
    diff.zeroize();
    wide.zeroize();
    bit.zeroize();
    mask.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::params::{MlKem1024, MlKem512, MlKem768};

    const K_PRIME: [u8; KYBER_SSBYTES] = [0x11; KYBER_SSBYTES];
    const K_BAR: [u8; KYBER_SSBYTES] = [0xee; KYBER_SSBYTES];

    fn run(a: &[u8], b: &[u8]) -> [u8; KYBER_SSBYTES] {
        let mut k = K_PRIME;
        reject_on_mismatch(&mut k, &K_BAR, a, b);
        k
    }

    #[test]
    fn equal_inputs_keep_k_prime() {
        for len in [
            0,
            1,
            MlKem512::CT_BYTES,
            MlKem768::CT_BYTES,
            MlKem1024::CT_BYTES,
        ] {
            let c: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(run(&c, &c.clone()), K_PRIME, "len {len}");
        }
    }

    #[test]
    fn any_single_bit_difference_selects_k_bar() {
        let c: Vec<u8> = (0..MlKem768::CT_BYTES).map(|i| (i * 7) as u8).collect();
        for pos in 0..c.len() {
            for bit in 0..u8::BITS {
                let mut other = c.clone();
                other[pos] ^= 1 << bit;
                assert_eq!(run(&c, &other), K_BAR, "byte {pos} bit {bit}");
            }
        }
    }

    #[test]
    fn every_byte_difference_selects_k_bar() {
        // The accumulator covers all 255 nonzero byte values, not only one bit.
        for delta in 1..=u8::MAX {
            assert_eq!(run(&[0], &[delta]), K_BAR, "delta {delta}");
        }
    }

    #[test]
    fn differing_lengths_select_k_bar() {
        let c = [7u8; 16];
        assert_eq!(run(&c, &c[..15]), K_BAR);
        assert_eq!(run(&c[..15], &c), K_BAR);
        assert_eq!(run(&c, &[]), K_BAR);
    }

    #[test]
    fn k_bar_equal_to_k_prime_is_harmless() {
        let mut k = K_PRIME;
        reject_on_mismatch(&mut k, &K_PRIME, &[1], &[2]);
        assert_eq!(k, K_PRIME);
    }
}
