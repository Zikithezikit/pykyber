//! Compress_11 and ByteEncode_11 for ML-KEM-1024 (du = 11).
//!
//! The legacy `polyvec_compress_1024` reuses the d = 4/5/10 multiplier
//! (10321345 >> 35), which is off by one at the residues 1875 and 3125. Legacy
//! output is frozen, so ML-KEM gets its own routine.

use crate::kyber::params::{KYBER_N, KYBER_Q};
use crate::kyber::poly::Poly;

/// Compression bits: du for ML-KEM-1024 (FIPS 203 Table 2).
const D: u32 = 11;
/// Mask for a compressed value, the "mod 2^d" of Compress_d.
const D_MASK: u32 = (1 << D) - 1;
/// Shift that moves the sign bit of an `i16` to bit 0.
const SIGN_SHIFT: u32 = i16::BITS - 1;
/// (q - 1) / 2, the rounding offset: q is odd, so adding it before the floor
/// rounds halves up.
const HALF_Q: u32 = (KYBER_Q as u32 - 1) / 2;
/// ceil(2^RECIPROCAL_SHIFT / q), so that `x * RECIPROCAL >> RECIPROCAL_SHIFT`
/// is `x / q` for the inputs below (verified over all of Z_q by the tests).
const RECIPROCAL: u64 = 645_084;
const RECIPROCAL_SHIFT: u32 = 31;

/// Bytes of one polynomial compressed to `D` bits per coefficient.
pub(crate) const POLY_COMPRESSED_D11_BYTES: usize = KYBER_N * D as usize / u8::BITS as usize;

/// Compress_11 then ByteEncode_11 (FIPS 203 (4.7), Algorithm 5 with d = 11).
///
/// `Compress_11(x) = round(2^11 * x / q) mod 2^11`, with halves rounding up.
/// For 0 <= x < q this equals
/// `((x << D) + HALF_Q) * RECIPROCAL >> RECIPROCAL_SHIFT`, checked over every
/// x in the unit test below. Coefficients may be negative representatives in
/// (-q, q). There is no division, and no branch or index depends on the data;
/// the only loop condition counts bits, which is public.
pub(crate) fn poly_compress_d11(r: &mut [u8], a: &Poly) {
    debug_assert_eq!(r.len(), POLY_COMPRESSED_D11_BYTES);
    // Bit accumulator: little-endian bit order, as in Algorithm 5.
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    let mut idx = 0usize;
    for &coeff in a.coeffs.iter() {
        let mut u = coeff;
        u += (u >> SIGN_SHIFT) & KYBER_Q as i16;
        let scaled = ((u as u32) << D) + HALF_Q;
        let compressed = ((scaled as u64 * RECIPROCAL) >> RECIPROCAL_SHIFT) as u32 & D_MASK;
        acc |= compressed << acc_bits;
        acc_bits += D;
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

    /// FIPS 203 (4.7) in exact integers: floor((2^(d+1) * x + q) / 2q) mod 2^d.
    fn spec_compress_11(x: i64) -> i64 {
        ((2 * (x << D) + Q) / (2 * Q)) & D_MASK as i64
    }

    /// Algorithm 5, little-endian bit packing of 256 11-bit values.
    fn spec_byte_encode_11(f: &[i64]) -> Vec<u8> {
        let mut out = vec![0u8; POLY_COMPRESSED_D11_BYTES];
        for (i, &v) in f.iter().enumerate() {
            for j in 0..D as usize {
                let k = i * D as usize + j;
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

    #[test]
    fn exact_for_every_residue_and_negative_representative() {
        // All of Z_q, and every negative representative -(q-1)..=-1 that the
        // conditional add inside the routine maps back into Z_q.
        for x in (0..Q as i16).chain((1..Q as i16).map(|x| x - Q as i16)) {
            let mut got = [0u8; POLY_COMPRESSED_D11_BYTES];
            poly_compress_d11(&mut got, &constant_poly(x));
            let residue = (x as i64).rem_euclid(Q);
            let want = spec_byte_encode_11(&[spec_compress_11(residue); KYBER_N]);
            assert_eq!(got.to_vec(), want, "x = {x}");
        }
    }

    #[test]
    fn packs_distinct_coefficients_in_order() {
        let mut p = Poly::new();
        for (i, c) in p.coeffs.iter_mut().enumerate() {
            // Arbitrary fill: distinct-looking values across the whole range.
            *c = ((i * 13 + 7) % KYBER_Q) as i16;
        }
        let mut got = [0u8; POLY_COMPRESSED_D11_BYTES];
        poly_compress_d11(&mut got, &p);
        let f: Vec<i64> = p
            .coeffs
            .iter()
            .map(|&x| spec_compress_11(x as i64))
            .collect();
        assert_eq!(got.to_vec(), spec_byte_encode_11(&f));
    }

    #[test]
    fn differs_from_legacy_only_at_the_two_legacy_residues() {
        for x in 0..KYBER_Q as i16 {
            let mut ours = [0u8; POLY_COMPRESSED_D11_BYTES];
            poly_compress_d11(&mut ours, &constant_poly(x));
            let mut v = Polyvec1024::new();
            v.vec[0] = constant_poly(x);
            let mut legacy = vec![0u8; K * POLY_COMPRESSED_D11_BYTES];
            polyvec_compress_1024(&mut legacy, v);
            let same = ours[..] == legacy[..POLY_COMPRESSED_D11_BYTES];
            assert_eq!(same, !LEGACY_DEVIATING.contains(&x), "x = {x}");
        }
    }
}
