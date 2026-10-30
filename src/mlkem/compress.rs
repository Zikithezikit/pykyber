//! Compress_d / Decompress_d with ByteEncode_d / ByteDecode_d for the ML-KEM
//! compression widths, and the message codec.
//!
//! The legacy `polyvec_compress_1024` reuses the d = 4/5/10 multiplier
//! (10321345 >> 35), which is off by one at the residues 1875 and 3125 when
//! d = 11. Legacy output is frozen, so ML-KEM gets its own routine, generic over
//! `d`, which also covers d = 1 (messages), 4, 5 and 10.

use crate::kyber::params::{KYBER_N, KYBER_Q};
use crate::kyber::poly::Poly;
use core::hint::black_box;

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

/// Bytes of a message m: one bit per coefficient (Algorithm 5 with d = 1).
pub(crate) const MSG_BYTES: usize = compressed_bytes(1);
/// Decompress_1(1) = round(q / 2) = ceil(q / 2) (FIPS 203 (4.8) with d = 1).
const DECOMPRESSED_ONE: i16 = KYBER_Q.div_ceil(2) as i16;

/// ByteDecode_d then Decompress_d (FIPS 203 Algorithm 6, (4.8)).
///
/// `Decompress_d(y) = round(q * y / 2^d)`, with halves rounding up, which is
/// `(y * q + 2^(d-1)) >> d` for `0 <= y < 2^d`: exact, and no division. `d` is
/// a public parameter in 1..=11. `a` must hold `compressed_bytes(d)` bytes; a
/// shorter slice reads as zeros.
pub(crate) fn poly_decompress(r: &mut Poly, a: &[u8], d: u32) {
    debug_assert_eq!(a.len(), compressed_bytes(d));
    let d_mask: u32 = (1 << d) - 1;
    let mut bytes = a.iter();
    // Bit accumulator: little-endian bit order, as in Algorithm 6.
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    for coeff in r.coeffs.iter_mut() {
        while acc_bits < d {
            acc |= (*bytes.next().unwrap_or(&0) as u32) << acc_bits;
            acc_bits += u8::BITS;
        }
        let y = acc & d_mask;
        acc >>= d;
        acc_bits -= d;
        *coeff = ((y * KYBER_Q as u32 + (1 << (d - 1))) >> d) as i16;
    }
}

/// `Decompress_1(ByteDecode_1(m))` (FIPS 203 Algorithm 14, step 20).
///
/// `m` is secret. Each bit becomes an all-zeros or all-ones mask that goes
/// through `black_box` before it is applied, so the compiler cannot see that
/// it is 0 or -1 and turn the selection into a branch (the pattern of
/// CVE-2024-37880 in the legacy `poly_frommsg`). `black_box` is a best-effort
/// barrier, which is why the release assembly is checked in WP-8.
pub(crate) fn poly_from_msg(r: &mut Poly, m: &[u8; MSG_BYTES]) {
    for (i, coeff) in r.coeffs.iter_mut().enumerate() {
        // Bit i of the message, little-endian within each byte (Algorithm 4, BytesToBits).
        let bit = ((m[i / u8::BITS as usize] >> (i % u8::BITS as usize)) & 1) as i16;
        *coeff = black_box(bit.wrapping_neg()) & DECOMPRESSED_ONE;
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

    /// FIPS 203 (4.8) in exact integers: floor((2 * q * y + 2^d) / 2^(d+1)).
    fn spec_decompress(d: u32, y: i64) -> i64 {
        (2 * Q * y + (1 << d)) / (1 << (d + 1))
    }

    fn decompress_matches_spec(d: u32) {
        for y in 0..1i64 << d {
            let packed = spec_byte_encode(d, &[y; KYBER_N]);
            let mut got = Poly::new();
            poly_decompress(&mut got, &packed, d);
            assert_eq!(
                got.coeffs,
                [spec_decompress(d, y) as i16; KYBER_N],
                "d = {d}, y = {y}"
            );
        }
    }

    #[test]
    fn decompress_is_exact_for_every_input() {
        for d in ALL_D {
            decompress_matches_spec(d);
        }
    }

    #[test]
    fn decompress_reads_distinct_values_in_order() {
        let ys: Vec<i64> = (0..KYBER_N as i64)
            .map(|i| (i * 37 + 5) % (1 << D_U_1024))
            .collect();
        let mut got = Poly::new();
        poly_decompress(&mut got, &spec_byte_encode(D_U_1024, &ys), D_U_1024);
        let want: Vec<i16> = ys
            .iter()
            .map(|&y| spec_decompress(D_U_1024, y) as i16)
            .collect();
        assert_eq!(got.coeffs.to_vec(), want);
    }

    #[test]
    fn compress_inverts_decompress() {
        // FIPS 203 section 4.2.1: Compress_d(Decompress_d(y)) = y for d < 12.
        for d in ALL_D {
            let ys: Vec<i64> = (0..KYBER_N as i64).map(|i| i * 29 % (1 << d)).collect();
            let packed = spec_byte_encode(d, &ys);
            let mut p = Poly::new();
            poly_decompress(&mut p, &packed, d);
            let mut again = vec![0u8; compressed_bytes(d)];
            poly_compress(&mut again, &p, d);
            assert_eq!(again, packed, "d = {d}");
        }
    }

    #[test]
    fn message_bits_map_to_zero_and_ceil_half_q() {
        let mut m = [0u8; MSG_BYTES];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x9d) ^ 0x5a;
        }
        let mut p = Poly::new();
        poly_from_msg(&mut p, &m);
        for (i, &c) in p.coeffs.iter().enumerate() {
            let bit = (m[i / 8] >> (i % 8)) & 1;
            // 1665 = (3329 + 1) / 2, written out so the test does not reuse the constant.
            assert_eq!(c, if bit == 1 { 1665 } else { 0 }, "i = {i}");
        }
        // Compress_1 returns the message, as K-PKE.Decrypt does.
        let mut back = [0u8; MSG_BYTES];
        poly_compress(&mut back, &p, D_MESSAGE);
        assert_eq!(back, m);
    }
}
