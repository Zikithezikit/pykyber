//! Vector of `K` polynomials, generic over `K`, built on the legacy `Poly` and
//! its NTT / reduction / byte-encoding routines (see the table in `mod.rs`).
//!
//! The Montgomery conventions are the legacy ones: `basemul_acc` carries a
//! factor 2^-16 and `invntt_tomont` a factor 2^16, which cancel when the two
//! are composed as in K-PKE. Coefficients must stay reduced between steps;
//! `poly_add` is a plain i16 add.

use crate::kyber::params::{KYBER_POLYBYTES, KYBER_Q};
use crate::kyber::poly::{
    poly_add, poly_base_multiply, poly_frombytes, poly_invntt_tomont, poly_ntt, poly_reduce,
    poly_tobytes, Poly,
};
use zeroize::Zeroize;

/// Shift that moves the sign bit of an `i16` to bit 0, for the conditional add
/// of q on negative representatives.
const SIGN_SHIFT: u32 = i16::BITS - 1;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PolyVec<const K: usize> {
    pub vec: [Poly; K],
}

impl<const K: usize> Default for PolyVec<K> {
    fn default() -> Self {
        PolyVec {
            vec: core::array::from_fn(|_| Poly::new()),
        }
    }
}

impl<const K: usize> PolyVec<K> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ntt(&mut self) {
        for p in self.vec.iter_mut() {
            poly_ntt(p);
        }
    }

    pub fn invntt_tomont(&mut self) {
        for p in self.vec.iter_mut() {
            poly_invntt_tomont(p);
        }
    }

    pub fn reduce(&mut self) {
        for p in self.vec.iter_mut() {
            poly_reduce(p);
        }
    }

    pub fn add(&mut self, other: &Self) {
        for (a, b) in self.vec.iter_mut().zip(other.vec.iter()) {
            poly_add(a, b);
        }
    }

    /// `r = sum_i a[i] * b[i]` in the NTT domain (inner product of two
    /// vectors), reduced.
    pub fn basemul_acc(r: &mut Poly, a: &Self, b: &Self) {
        let mut t = Poly::new();
        poly_base_multiply(r, &a.vec[0], &b.vec[0]);
        for i in 1..K {
            poly_base_multiply(&mut t, &a.vec[i], &b.vec[i]);
            poly_add(r, &t);
        }
        poly_reduce(r);
    }

    /// ByteEncode12 of every polynomial (FIPS 203 Algorithm 5, d = 12).
    /// Coefficients must be in (-q, q). `out` must hold `K * 384` bytes.
    pub fn to_bytes(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), K * KYBER_POLYBYTES);
        for (i, p) in self.vec.iter().enumerate() {
            poly_tobytes(
                &mut out[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES],
                p.clone(),
            );
        }
    }

    /// ByteDecode12 of every polynomial (FIPS 203 Algorithm 6, d = 12).
    /// Unlike the legacy `poly_frombytes`, every coefficient is reduced mod q
    /// as the standard specifies, so `to_bytes(from_bytes(b)) == b` holds
    /// exactly when `b` is a canonical encoding (the check of section 7.2).
    /// `bytes` must hold `K * 384` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), K * KYBER_POLYBYTES);
        let mut v = Self::new();
        for (i, p) in v.vec.iter_mut().enumerate() {
            poly_frombytes(p, &bytes[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES]);
            for c in p.coeffs.iter_mut() {
                // 12-bit input is below 2q, so one conditional subtraction
                // reduces it. The data is public (an encapsulation key).
                let t = *c - KYBER_Q as i16;
                *c = t + ((t >> SIGN_SHIFT) & KYBER_Q as i16);
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::polyvec::*;

    /// Random vector pairs per parameter set.
    const ROUNDS: usize = 20;

    struct Prng(u64);
    impl Prng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn fill<const K: usize>(&mut self, v: &mut PolyVec<K>) {
            for p in v.vec.iter_mut() {
                for c in p.coeffs.iter_mut() {
                    *c = (self.next() % KYBER_Q as u64) as i16;
                }
            }
        }
    }

    fn coeffs<const K: usize>(v: &PolyVec<K>) -> Vec<i16> {
        v.vec.iter().flat_map(|p| p.coeffs).collect()
    }

    /// Runs every operation on `PolyVec<K>` and on the legacy per-level type
    /// and requires identical coefficients and bytes.
    macro_rules! matches_legacy {
        ($name:ident, $k:literal, $legacy:ty, $ntt:ident, $invntt:ident, $reduce:ident,
         $add:ident, $basemul:ident, $tobytes:ident, $frombytes:ident) => {
            #[test]
            fn $name() {
                let mut rng = Prng(0x1234_5678_9abc_def1 ^ $k);
                for _ in 0..ROUNDS {
                    let (mut a, mut b) = (PolyVec::<$k>::new(), PolyVec::<$k>::new());
                    rng.fill(&mut a);
                    rng.fill(&mut b);
                    let (mut la, mut lb) = (<$legacy>::new(), <$legacy>::new());
                    for i in 0..$k {
                        la.vec[i].coeffs = a.vec[i].coeffs;
                        lb.vec[i].coeffs = b.vec[i].coeffs;
                    }

                    a.ntt();
                    $ntt(&mut la);
                    assert_eq!(
                        coeffs(&a),
                        la.vec.iter().flat_map(|p| p.coeffs).collect::<Vec<_>>()
                    );
                    b.ntt();
                    $ntt(&mut lb);

                    let (mut r, mut lr) = (Poly::new(), Poly::new());
                    PolyVec::basemul_acc(&mut r, &a, &b);
                    $basemul(&mut lr, &la, &lb);
                    assert_eq!(r.coeffs, lr.coeffs);

                    a.add(&b);
                    $add(&mut la, &lb);
                    a.reduce();
                    $reduce(&mut la);
                    assert_eq!(
                        coeffs(&a),
                        la.vec.iter().flat_map(|p| p.coeffs).collect::<Vec<_>>()
                    );

                    a.invntt_tomont();
                    $invntt(&mut la);
                    a.reduce();
                    $reduce(&mut la);
                    assert_eq!(
                        coeffs(&a),
                        la.vec.iter().flat_map(|p| p.coeffs).collect::<Vec<_>>()
                    );

                    let mut bytes = vec![0u8; $k * KYBER_POLYBYTES];
                    let mut lbytes = vec![0u8; $k * KYBER_POLYBYTES];
                    a.to_bytes(&mut bytes);
                    $tobytes(&mut lbytes, &la);
                    assert_eq!(bytes, lbytes);

                    let back = PolyVec::<$k>::from_bytes(&bytes);
                    let mut lback = <$legacy>::new();
                    $frombytes(&mut lback, &bytes);
                    assert_eq!(
                        coeffs(&back),
                        lback.vec.iter().flat_map(|p| p.coeffs).collect::<Vec<_>>()
                    );
                }
            }
        };
    }

    matches_legacy!(
        k2_matches_legacy_512,
        2,
        Polyvec512,
        polyvec_ntt_512,
        polyvec_invntt_tomont_512,
        polyvec_reduce_512,
        polyvec_add_512,
        polyvec_basemul_acc_montgomery_512,
        polyvec_tobytes_512,
        polyvec_frombytes_512
    );
    matches_legacy!(
        k3_matches_legacy_768,
        3,
        Polyvec,
        polyvec_ntt,
        polyvec_invntt_tomont,
        polyvec_reduce,
        polyvec_add,
        polyvec_basemul_acc_montgomery,
        polyvec_tobytes,
        polyvec_frombytes
    );
    matches_legacy!(
        k4_matches_legacy_1024,
        4,
        Polyvec1024,
        polyvec_ntt_1024,
        polyvec_invntt_tomont_1024,
        polyvec_reduce_1024,
        polyvec_add_1024,
        polyvec_basemul_acc_montgomery_1024,
        polyvec_tobytes_1024,
        polyvec_frombytes_1024
    );

    #[test]
    fn from_bytes_reduces_mod_q_like_bytedecode12() {
        // 0xFFF is the largest 12-bit value and decodes to 4095 mod q; q itself
        // decodes to 0. Two 12-bit values share three bytes (Algorithm 5).
        const MAX_12_BIT: u16 = (1 << 12) - 1;
        let mut bytes = vec![0u8; 2 * KYBER_POLYBYTES];
        let (c0, c1) = (MAX_12_BIT, KYBER_Q as u16);
        bytes[0] = c0 as u8;
        bytes[1] = (c0 >> 8) as u8 | (c1 << 4) as u8;
        bytes[2] = (c1 >> 4) as u8;
        let v = PolyVec::<2>::from_bytes(&bytes);
        assert_eq!(v.vec[0].coeffs[0], MAX_12_BIT as i16 - KYBER_Q as i16);
        assert_eq!(v.vec[0].coeffs[1], 0);
        assert!(v
            .vec
            .iter()
            .flat_map(|p| p.coeffs)
            .all(|c| (0..KYBER_Q as i16).contains(&c)));
        // Non-canonical input does not round-trip, which is what the
        // modulus check of FIPS 203 section 7.2 detects.
        let mut again = vec![0u8; 2 * KYBER_POLYBYTES];
        v.to_bytes(&mut again);
        assert_ne!(again, bytes);
    }
}
