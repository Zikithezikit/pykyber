//! K-PKE, the public-key encryption scheme inside ML-KEM (FIPS 203 section 5):
//! KeyGen (Algorithm 13), Encrypt (Algorithm 14) and Decrypt (Algorithm 15),
//! generic over the parameter set.
//!
//! Step numbers in comments refer to the algorithm named in the same comment.
//! The matrix is public (it is derived from rho), so it is re-sampled one row or
//! column at a time instead of being stored; only `[Poly; K]` arrays are used
//! because stable Rust cannot size arrays from `ParamSet` constants.
//!
//! Everything derived from `d`, `m`, `r`, `sigma`, `s` or `y` is secret. Loops
//! and indices depend only on `K` and the public sampling of the matrix, secret
//! intermediates are `Zeroizing` or `Poly`/`PolyVec` (zeroized on drop), and the
//! message goes through `compress::poly_from_msg` and `poly_compress` with
//! `d = 1`.

use super::compress::{compressed_bytes, poly_compress, poly_decompress, poly_from_msg, MSG_BYTES};
use super::params::{prf_bytes, ParamSet};
use super::polyvec::PolyVec;
use super::sample::{sample_ntt, INPUT_BYTES};
use crate::kyber::cbd::{cbd2, cbd3};
use crate::kyber::error::KyberError;
use crate::kyber::params::KYBER_SYMBYTES;
use crate::kyber::poly::{poly_add, poly_invntt_tomont, poly_reduce, poly_sub, poly_tomont, Poly};
use crate::kyber::symmetric::{hash_sha3_512, shake256_prf_expand};
use zeroize::Zeroizing;

/// Seeds d, rho, sigma and the randomness r are 32 bytes (FIPS 203 Table 1).
const SEED_BYTES: usize = KYBER_SYMBYTES;
/// Input of G in Algorithm 13: `d || k`.
const KEYGEN_INPUT_BYTES: usize = SEED_BYTES + 1;
/// Output of G: two 32-byte seeds.
const G_OUTPUT_BYTES: usize = 2 * SEED_BYTES;
/// The two values of eta in Table 2 and the CBD routine each one selects.
const ETA_2: usize = 2;
const ETA_3: usize = 3;
/// Largest PRF output for one noise polynomial (eta = 3).
const MAX_NOISE_BYTES: usize = prf_bytes(ETA_3);
/// Compression width of the message in Decrypt (Algorithm 15, step 7).
const D_MESSAGE: u32 = 1;

type Seed = [u8; SEED_BYTES];

/// One noise polynomial: `SamplePolyCBD_eta(PRF_eta(seed, nonce))`, then the
/// nonce counter `N` advances (Algorithm 13 steps 9-10, 13-14; Algorithm 14
/// steps 10-11, 14-15, 17). `eta` is a public parameter.
fn sample_noise(out: &mut Poly, seed: &Seed, nonce: &mut u8, eta: usize) {
    let mut buf = Zeroizing::new([0u8; MAX_NOISE_BYTES]);
    let len = prf_bytes(eta);
    shake256_prf_expand(&mut buf[..len], len, seed, *nonce);
    match eta {
        ETA_2 => cbd2(out, &buf[..len]),
        ETA_3 => cbd3(out, &buf[..len]),
        _ => unreachable!("ML-KEM defines eta in {{2, 3}}"),
    }
    *nonce += 1;
}

/// `K` noise polynomials in a row, as in the loops of Algorithms 13 and 14.
fn sample_noise_vec<const K: usize>(out: &mut PolyVec<K>, seed: &Seed, nonce: &mut u8, eta: usize) {
    for p in out.vec.iter_mut() {
        sample_noise(p, seed, nonce, eta);
    }
}

/// Row `i` of the matrix, or with `transposed` its column `i` (row `i` of the
/// transpose), in the NTT domain. Entry `A[i][j]` is `SampleNTT(rho || j || i)`
/// (Algorithm 13 step 5, Algorithm 14 step 6). Public data.
fn matrix_row<const K: usize>(rho: &Seed, i: usize, transposed: bool) -> PolyVec<K> {
    let mut row = PolyVec::<K>::new();
    for (j, p) in row.vec.iter_mut().enumerate() {
        // `A[row][col] = SampleNTT(rho || col || row)`; K <= 4 fits a byte.
        let (row_index, col_index) = if transposed { (j, i) } else { (i, j) };
        let mut input = [0u8; INPUT_BYTES];
        input[..SEED_BYTES].copy_from_slice(rho);
        input[SEED_BYTES] = col_index as u8;
        input[SEED_BYTES + 1] = row_index as u8;
        *p = sample_ntt(&input);
    }
    row
}

fn check_len(param: &'static str, expected: usize, actual: usize) -> Result<(), KyberError> {
    if expected == actual {
        Ok(())
    } else {
        Err(KyberError::invalid_input(param, expected, actual))
    }
}

/// K-PKE.KeyGen (Algorithm 13): returns `(ek_PKE, dk_PKE)`.
pub(crate) fn keygen<const K: usize>(d: &Seed) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    // Step 1: (rho, sigma) <- G(d || k). The byte k is the domain separator.
    let mut g_input = Zeroizing::new([0u8; KEYGEN_INPUT_BYTES]);
    g_input[..SEED_BYTES].copy_from_slice(d);
    g_input[SEED_BYTES] = ParamSet::<K>::K as u8;
    let mut g_output = Zeroizing::new([0u8; G_OUTPUT_BYTES]);
    hash_sha3_512(&mut g_output[..], &g_input[..], KEYGEN_INPUT_BYTES);
    let mut rho = [0u8; SEED_BYTES];
    rho.copy_from_slice(&g_output[..SEED_BYTES]);
    let mut sigma = Zeroizing::new([0u8; SEED_BYTES]);
    sigma.copy_from_slice(&g_output[SEED_BYTES..]);
    keygen_expanded::<K>(&rho, &sigma)
}

/// Algorithm 13 from step 2 on, for a given `(rho, sigma)`. Split from `keygen`
/// so the CCTV tests can feed the `G(d)` derivation of the pre-final standard.
pub(crate) fn keygen_expanded<const K: usize>(
    rho: &Seed,
    sigma: &Seed,
) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    // Steps 2, 8-15: s and e from sigma, nonces 0..K and K..2K.
    let mut nonce = 0u8;
    let mut s = PolyVec::<K>::new();
    let mut e = PolyVec::<K>::new();
    sample_noise_vec(&mut s, sigma, &mut nonce, ParamSet::<K>::ETA1);
    sample_noise_vec(&mut e, sigma, &mut nonce, ParamSet::<K>::ETA1);

    // Steps 16-17.
    s.ntt();
    e.ntt();

    // Step 18: t = A s + e. The product carries 2^-16; poly_tomont removes it.
    let mut t = PolyVec::<K>::new();
    for (i, ti) in t.vec.iter_mut().enumerate() {
        PolyVec::basemul_acc(ti, &matrix_row::<K>(rho, i, false), &s);
        poly_tomont(ti);
    }
    t.add(&e);
    t.reduce();

    // Steps 19-20.
    let mut ek = vec![0u8; ParamSet::<K>::EK_BYTES];
    let (ek_t, ek_rho) = ek.split_at_mut(ParamSet::<K>::DK_PKE_BYTES);
    t.to_bytes(ek_t);
    ek_rho.copy_from_slice(rho);
    let mut dk = Zeroizing::new(vec![0u8; ParamSet::<K>::DK_PKE_BYTES]);
    s.to_bytes(&mut dk);
    (ek, dk)
}

/// K-PKE.Encrypt (Algorithm 14). Fails if `ek` is not `EK_BYTES` long; the
/// modulus check of FIPS 203 section 7.2 belongs to the caller.
pub(crate) fn encrypt<const K: usize>(
    ek: &[u8],
    m: &[u8; MSG_BYTES],
    r: &Seed,
) -> Result<Vec<u8>, KyberError> {
    check_len("ek", ParamSet::<K>::EK_BYTES, ek.len())?;
    let (ek_t, ek_rho) = ek.split_at(ParamSet::<K>::DK_PKE_BYTES);

    // Steps 2-3.
    let t = PolyVec::<K>::from_bytes(ek_t);
    let mut rho = [0u8; SEED_BYTES];
    rho.copy_from_slice(ek_rho);

    // Steps 1, 9-17: y, e1 (eta2) and e2 (eta2) from r.
    let mut nonce = 0u8;
    let mut y = PolyVec::<K>::new();
    let mut e1 = PolyVec::<K>::new();
    let mut e2 = Poly::new();
    sample_noise_vec(&mut y, r, &mut nonce, ParamSet::<K>::ETA1);
    sample_noise_vec(&mut e1, r, &mut nonce, ParamSet::<K>::ETA2);
    sample_noise(&mut e2, r, &mut nonce, ParamSet::<K>::ETA2);

    // Step 18.
    y.ntt();

    // Step 19: u = NTT^-1(A^T y) + e1. basemul's 2^-16 and invntt's 2^16 cancel.
    let mut u = PolyVec::<K>::new();
    for (i, ui) in u.vec.iter_mut().enumerate() {
        PolyVec::basemul_acc(ui, &matrix_row::<K>(&rho, i, true), &y);
    }
    u.invntt_tomont();
    u.add(&e1);
    u.reduce();

    // Steps 20-21: v = NTT^-1(t^T y) + e2 + mu.
    let mut mu = Poly::new();
    poly_from_msg(&mut mu, m);
    let mut v = Poly::new();
    PolyVec::basemul_acc(&mut v, &t, &y);
    poly_invntt_tomont(&mut v);
    poly_add(&mut v, &e2);
    poly_add(&mut v, &mu);
    poly_reduce(&mut v);

    // Steps 22-24: c = c1 || c2.
    let u_bytes = ParamSet::<K>::POLY_COMPRESSED_U_BYTES;
    let mut c = vec![0u8; ParamSet::<K>::CT_BYTES];
    let (c1, c2) = c.split_at_mut(K * u_bytes);
    for (ci, ui) in c1.chunks_exact_mut(u_bytes).zip(u.vec.iter()) {
        poly_compress(ci, ui, ParamSet::<K>::DU as u32);
    }
    poly_compress(c2, &v, ParamSet::<K>::DV as u32);
    Ok(c)
}

/// K-PKE.Decrypt (Algorithm 15). Fails if `dk` is not `DK_PKE_BYTES` long or
/// `c` is not `CT_BYTES` long; both lengths are checked before any work.
pub(crate) fn decrypt<const K: usize>(
    dk: &[u8],
    c: &[u8],
) -> Result<Zeroizing<[u8; MSG_BYTES]>, KyberError> {
    check_len("dk", ParamSet::<K>::DK_PKE_BYTES, dk.len())?;
    check_len("c", ParamSet::<K>::CT_BYTES, c.len())?;

    // Steps 1-4.
    let u_bytes = ParamSet::<K>::POLY_COMPRESSED_U_BYTES;
    let (c1, c2) = c.split_at(K * u_bytes);
    let mut u = PolyVec::<K>::new();
    for (ui, ci) in u.vec.iter_mut().zip(c1.chunks_exact(u_bytes)) {
        poly_decompress(ui, ci, ParamSet::<K>::DU as u32);
    }
    let mut v = Poly::new();
    poly_decompress(&mut v, c2, ParamSet::<K>::DV as u32);

    // Step 5.
    let s = PolyVec::<K>::from_bytes(dk);

    // Step 6: w = v' - NTT^-1(s^T NTT(u')). poly_sub(r, a) sets r = a - r.
    u.ntt();
    let mut w = Poly::new();
    PolyVec::basemul_acc(&mut w, &s, &u);
    poly_invntt_tomont(&mut w);
    poly_sub(&mut w, &v);
    poly_reduce(&mut w);

    // Step 7: m = ByteEncode_1(Compress_1(w)).
    let mut m = Zeroizing::new([0u8; MSG_BYTES]);
    debug_assert_eq!(m.len(), compressed_bytes(D_MESSAGE));
    poly_compress(&mut m[..], &w, D_MESSAGE);
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::fips202::sha3_512;
    use crate::mlkem::params::{MlKem1024, MlKem512, MlKem768};

    /// Distinct inputs per set in the round-trip test.
    const ROUNDS: usize = 8;

    /// xorshift64*, enough to vary test inputs; not a source of secrets.
    struct Prng(u64);
    impl Prng {
        fn seed(&mut self) -> Seed {
            let mut out = [0u8; SEED_BYTES];
            for byte in out.iter_mut() {
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                *byte = (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8;
            }
            out
        }
    }

    fn g(input: &[u8]) -> [u8; G_OUTPUT_BYTES] {
        let mut out = [0u8; G_OUTPUT_BYTES];
        sha3_512(&mut out, input, input.len());
        out
    }

    fn keygen_uses_g_of_d_and_k<const K: usize>() {
        let d = Prng(1).seed();
        let (ek, dk) = keygen::<K>(&d);
        assert_eq!(ek.len(), ParamSet::<K>::EK_BYTES);
        assert_eq!(dk.len(), ParamSet::<K>::DK_PKE_BYTES);
        // rho is the first half of G(d || k), the trailing seed of ek.
        let mut input = d.to_vec();
        input.push(K as u8);
        assert_eq!(ek[ek.len() - SEED_BYTES..], g(&input)[..SEED_BYTES]);
        // Round-3 Kyber used G(d); it must not be what ML-KEM produces.
        assert_ne!(ek[ek.len() - SEED_BYTES..], g(&d)[..SEED_BYTES]);
        // Deterministic in d.
        let (ek2, dk2) = keygen::<K>(&d);
        assert_eq!((ek.clone(), dk.to_vec()), (ek2, dk2.to_vec()));
    }

    #[test]
    fn keygen_uses_g_of_d_and_k_for_all_sets() {
        keygen_uses_g_of_d_and_k::<{ MlKem512::K }>();
        keygen_uses_g_of_d_and_k::<{ MlKem768::K }>();
        keygen_uses_g_of_d_and_k::<{ MlKem1024::K }>();
    }

    fn round_trip<const K: usize>() {
        let mut rng = Prng(K as u64);
        for round in 0..ROUNDS {
            let (ek, dk) = keygen::<K>(&rng.seed());
            // Include the all-zeros and all-ones messages, then random ones.
            let m = match round {
                0 => [0u8; MSG_BYTES],
                1 => [0xff; MSG_BYTES],
                _ => rng.seed(),
            };
            let r = rng.seed();
            let c = encrypt::<K>(&ek, &m, &r).unwrap();
            assert_eq!(c.len(), ParamSet::<K>::CT_BYTES);
            assert_eq!(c, encrypt::<K>(&ek, &m, &r).unwrap(), "deterministic in r");
            assert_ne!(c, encrypt::<K>(&ek, &m, &rng.seed()).unwrap());
            assert_eq!(*decrypt::<K>(&dk, &c).unwrap(), m, "K = {K}, round {round}");
        }
    }

    #[test]
    fn decrypt_inverts_encrypt_for_all_sets() {
        round_trip::<{ MlKem512::K }>();
        round_trip::<{ MlKem768::K }>();
        round_trip::<{ MlKem1024::K }>();
    }

    #[test]
    fn a_different_key_does_not_decrypt() {
        let mut rng = Prng(7);
        let (ek, _) = keygen::<{ MlKem768::K }>(&rng.seed());
        let (_, other_dk) = keygen::<{ MlKem768::K }>(&rng.seed());
        let m = rng.seed();
        let c = encrypt::<{ MlKem768::K }>(&ek, &m, &rng.seed()).unwrap();
        assert_ne!(*decrypt::<{ MlKem768::K }>(&other_dk, &c).unwrap(), m);
    }

    #[test]
    fn lengths_are_checked_before_any_work() {
        type P = MlKem768;
        let mut rng = Prng(9);
        let (ek, dk) = keygen::<{ P::K }>(&rng.seed());
        let m = rng.seed();
        let c = encrypt::<{ P::K }>(&ek, &m, &rng.seed()).unwrap();
        let bad = |param, expected, actual| KyberError::invalid_input(param, expected, actual);
        assert_eq!(
            encrypt::<{ P::K }>(&ek[1..], &m, &m),
            Err(bad("ek", P::EK_BYTES, P::EK_BYTES - 1))
        );
        assert_eq!(
            decrypt::<{ P::K }>(&dk[1..], &c).map(|m| *m),
            Err(bad("dk", P::DK_PKE_BYTES, P::DK_PKE_BYTES - 1))
        );
        assert_eq!(
            decrypt::<{ P::K }>(&dk, &c[1..]).map(|m| *m),
            Err(bad("c", P::CT_BYTES, P::CT_BYTES - 1))
        );
        assert!(decrypt::<{ P::K }>(&[], &[]).is_err());
    }
}
