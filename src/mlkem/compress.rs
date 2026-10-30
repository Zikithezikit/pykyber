//! Compress_d with ByteEncode_d for the ML-KEM compression widths.
//!
//! The legacy `polyvec_compress_1024` reuses the d = 4/5/10 multiplier
//! (10321345 >> 35), which is off by one at the residues 1875 and 3125 when
//! d = 11. Legacy output is frozen, so ML-KEM gets its own routine, generic over
//! `d`, which also covers d = 1 (messages), 4, 5 and 10.

use crate::kyber::params::{KYBER_N, KYBER_Q};
use crate::kyber::poly::Poly;

/// Shift that moves the sign bit of an `i16` to bit 0.
const SIGN_SHIFT: u32 = i16::BITS - 1;
/// (q - 1) / 2, the rounding offset: q is odd, so adding it before the floor
/// rounds halves up.
const HALF_Q: u32 = (KYBER_Q as u32 - 1) / 2;
/// ceil(2^RECIPROCAL_SHIFT / q), so that `x * RECIPROCAL >> RECIPROCAL_SHIFT`
/// is `x / q` for the inputs below (verified over all of Z_q, for every `d`
/// used by ML-KEM, by the tests).
const RECIPROCAL: u64 = 645_084;
const RECIPROCAL_SHIFT: u32 = 31;

/// Bytes of one polynomial compressed to `d` bits per coefficient
/// (FIPS 203 Algorithm 5: 256 coefficients of `d` bits).
pub(crate) const fn compressed_bytes(d: u32) -> usize {
    KYBER_N * d as usize / u8::BITS as usize
}

/// Compress_d then ByteEncode_d (FIPS 203 (4.7), Algorithm 5).
///
/// `Compress_d(x) = round(2^d * x / q) mod 2^d`, with halves rounding up.
/// For 0 <= x < q this equals
/// `((x << d) + HALF_Q) * RECIPROCAL >> RECIPROCAL_SHIFT`, checked over every
/// x in the unit test below. Coefficients may be negative representatives in
/// (-q, q). There is no division, and no branch or index depends on the data;
/// the only loop condition counts bits, which is public. `d` is a public
/// parameter in 1..=11. `r` must hold `compressed_bytes(d)` bytes.
pub(crate) fn poly_compress(r: &mut [u8], a: &Poly, d: u32) {
    debug_assert_eq!(r.len(), compressed_bytes(d));
    let d_mask: u32 = (1 << d) - 1;
    // Bit accumulator: little-endian bit order, as in Algorithm 5.
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    let mut idx = 0usize;
    for &coeff in a.coeffs.iter() {
        let mut u = coeff;
        u += (u >> SIGN_SHIFT) & KYBER_Q as i16;
        let scaled = ((u as u32) << d) + HALF_Q;
        let compressed = ((scaled as u64 * RECIPROCAL) >> RECIPROCAL_SHIFT) as u32 & d_mask;
        acc |= compressed << acc_bits;
        acc_bits += d;
        while acc_bits >= u8::BITS {
            r[idx] = acc as u8;
            idx += 1;
            acc >>= u8::BITS;
            acc_bits -= u8::BITS;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::params::KYBER_1024_K;
    use crate::kyber::polyvec::{polyvec_compress_1024, Polyvec1024};

    const Q: i64 = KYBER_Q as i64;
    /// The residues where the legacy d = 11 routine is off by one.
    const LEGACY_DEVIATING: [i16; 2] = [1875, 3125];
    /// Polynomials in a Kyber-1024 vector.
    const K: usize = KYBER_1024_K;
    /// Compression widths ML-KEM uses: the message (1), dv (4, 5) and du (10, 11).
    const D_MESSAGE: u32 = 1;
    const D_V_512_768: u32 = 4;
    const D_V_1024: u32 = 5;
    const D_U_512_768: u32 = 10;
    const D_U_1024: u32 = 11;
    const ALL_D: [u32; 5] = [D_MESSAGE, D_V_512_768, D_V_1024, D_U_512_768, D_U_1024];

    /// FIPS 203 (4.7) in exact integers: floor((2^(d+1) * x + q) / 2q) mod 2^d.
    fn spec_compress(d: u32, x: i64) -> i64 {
        ((2 * (x << d) + Q) / (2 * Q)) & ((1 << d) - 1)
    }

    /// Algorithm 5, little-endian bit packing of 256 d-bit values.
    fn spec_byte_encode(d: u32, f: &[i64]) -> Vec<u8> {
        let d = d as usize;
        let mut out = vec![0u8; KYBER_N * d / 8];
        for (i, &v) in f.iter().enumerate() {
            for j in 0..d {
                let k = i * d + j;
                out[k / 8] |= (((v >> j) & 1) as u8) << (k % 8); // bit k of the stream
            }
        }
        out
    }

    fn constant_poly(x: i16) -> Poly {
        let mut p = Poly::new();
        p.coeffs = [x; KYBER_N];
        p
    }

    fn exact_for_every_residue(d: u32) {
        // All of Z_q, and every negative representative -(q-1)..=-1 that the
        // conditional add inside the routine maps back into Z_q.
        for x in (0..Q as i16).chain((1..Q as i16).map(|x| x - Q as i16)) {
            let mut got = vec![0u8; compressed_bytes(d)];
            poly_compress(&mut got, &constant_poly(x), d);
            let residue = (x as i64).rem_euclid(Q);
            let want = spec_byte_encode(d, &[spec_compress(d, residue); KYBER_N]);
            assert_eq!(got, want, "d = {d}, x = {x}");
        }
    }

    #[test]
    fn exact_for_every_residue_and_negative_representative() {
        for d in ALL_D {
            exact_for_every_residue(d);
        }
    }

    #[test]
    fn packs_distinct_coefficients_in_order() {
        let mut p = Poly::new();
        for (i, c) in p.coeffs.iter_mut().enumerate() {
            // Arbitrary fill: distinct-looking values across the whole range.
            *c = ((i * 13 + 7) % KYBER_Q) as i16;
        }
        let mut got = vec![0u8; compressed_bytes(D_U_1024)];
        poly_compress(&mut got, &p, D_U_1024);
        let f: Vec<i64> = p
            .coeffs
            .iter()
            .map(|&x| spec_compress(D_U_1024, x as i64))
            .collect();
        assert_eq!(got, spec_byte_encode(D_U_1024, &f));
    }

    #[test]
    fn d11_differs_from_legacy_only_at_the_two_legacy_residues() {
        let bytes = compressed_bytes(D_U_1024);
        for x in 0..KYBER_Q as i16 {
            let mut ours = vec![0u8; bytes];
            poly_compress(&mut ours, &constant_poly(x), D_U_1024);
            let mut v = Polyvec1024::new();
            v.vec[0] = constant_poly(x);
            let mut legacy = vec![0u8; K * bytes];
            polyvec_compress_1024(&mut legacy, v);
            let same = ours[..] == legacy[..bytes];
            assert_eq!(same, !LEGACY_DEVIATING.contains(&x), "x = {x}");
        }
    }
}
