//! ML-KEM (FIPS 203 sections 6 and 7): KeyGen_internal, Encaps_internal and
//! Decaps_internal (Algorithms 16 to 18) and the wrappers KeyGen, Encaps and
//! Decaps (Algorithms 19 to 21), generic over the parameter set.
//!
//! Unlike round-3 Kyber, `m` is not hashed before use and the shared secret
//! does not depend on `H(c)`: `(K, r) = G(m || H(ek))` (Algorithm 17).
//!
//! The `*_internal` functions take caller-chosen randomness or unchecked keys.
//! FIPS 203 section 3.3 allows them for testing only, so they are private; the
//! vector tests reach them through `acvp`, which exists under
//! `cfg(any(test, feature = "acvp"))`. The public functions are `keygen`,
//! `keygen_from_seed` (the stored `(d, z)` seed of section 3.3), `encaps` and
//! `decaps`; the input checks of sections 7.2 and 7.3 and the OS random
//! generator sit in front of them.
//!
//! Every secret intermediate (`d`, `z`, `m`, `r`, `K`, `K'`, `K-bar`, the
//! hash outputs and the re-encrypted ciphertext) is `Zeroizing`, so it is
//! wiped on the error paths too. The implicit-rejection flag exists only inside
//! `ct::reject_on_mismatch`.

use super::check::{check_ct, check_dk, check_ek, check_len, split_dk, DkParts, HASH_BYTES};
use super::compress::MSG_BYTES;
use super::ct::reject_on_mismatch;
use super::kpke;
use super::params::ParamSet;
use crate::kyber::error::KyberError;
use crate::kyber::params::{KYBER_SSBYTES, KYBER_SYMBYTES};
use crate::kyber::symmetric::{hash_sha3_256, hash_sha3_512, shake256_kdf};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// The seeds d and z and the randomness m are 32 bytes (FIPS 203 Table 1).
const SEED_BYTES: usize = KYBER_SYMBYTES;
/// Output of G: the shared secret K (or K') and the randomness r (or r').
const G_OUTPUT_BYTES: usize = KYBER_SSBYTES + SEED_BYTES;
/// Input of G in Algorithms 17 and 18: `m || H(ek)` or `m' || h`.
const G_INPUT_BYTES: usize = MSG_BYTES + HASH_BYTES;

type Seed = [u8; SEED_BYTES];
/// A 32-byte shared secret, wiped on drop.
pub(crate) type SharedSecret = Zeroizing<[u8; KYBER_SSBYTES]>;
/// `(ek, dk)`; `dk` is wiped on drop.
pub(crate) type Keypair = (Vec<u8>, Zeroizing<Vec<u8>>);

/// Algorithm 16, ML-KEM.KeyGen_internal.
fn keygen_internal<const K: usize>(d: &Seed, z: &Seed) -> Keypair {
    // Step 1: (ek_PKE, dk_PKE) <- K-PKE.KeyGen(d). Step 2: ek <- ek_PKE.
    let (ek, dk_pke) = kpke::keygen::<K>(d);
    // Step 3: dk <- dk_PKE || ek || H(ek) || z.
    let mut h = [0u8; HASH_BYTES];
    hash_sha3_256(&mut h, &ek, ek.len());
    // Exact capacity: growing the vector would leave an unwiped copy of dk_PKE.
    let mut dk = Zeroizing::new(Vec::with_capacity(ParamSet::<K>::DK_BYTES));
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h);
    dk.extend_from_slice(z);
    (ek, dk)
}

/// Algorithm 17, ML-KEM.Encaps_internal. `ek` must have passed `check_ek`;
/// the length is re-checked here so that a wrong size cannot panic.
fn encaps_internal<const K: usize>(
    ek: &[u8],
    m: &[u8; MSG_BYTES],
) -> Result<(SharedSecret, Vec<u8>), KyberError> {
    check_len("ek", ParamSet::<K>::EK_BYTES, ek.len())?;

    // Step 1: (K, r) <- G(m || H(ek)). No H(m) first, unlike round-3 Kyber.
    let mut g_input = Zeroizing::new([0u8; G_INPUT_BYTES]);
    g_input[..MSG_BYTES].copy_from_slice(m);
    hash_sha3_256(&mut g_input[MSG_BYTES..], ek, ek.len());
    let mut g_output = Zeroizing::new([0u8; G_OUTPUT_BYTES]);
    hash_sha3_512(&mut g_output[..], &g_input[..], G_INPUT_BYTES);
    let mut k = Zeroizing::new([0u8; KYBER_SSBYTES]);
    k.copy_from_slice(&g_output[..KYBER_SSBYTES]);
    let mut r = Zeroizing::new([0u8; SEED_BYTES]);
    r.copy_from_slice(&g_output[KYBER_SSBYTES..]);

    // Step 2: c <- K-PKE.Encrypt(ek, m, r). Step 3: return (K, c).
    let c = kpke::encrypt::<K>(ek, m, &r)?;
    Ok((k, c))
}

/// Algorithm 18, ML-KEM.Decaps_internal. Both lengths are re-checked here so
/// that a wrong size cannot panic; the hash check of section 7.3 is
/// `check_dk`'s job. The return value is `K'` for a valid ciphertext and
/// `J(z || c)` otherwise, picked without a branch.
fn decaps_internal<const K: usize>(dk: &[u8], c: &[u8]) -> Result<SharedSecret, KyberError> {
    check_ct::<K>(c)?;
    // Steps 1-4: dk_PKE, ek_PKE, h and z.
    let DkParts { dk_pke, ek, h, z } = split_dk::<K>(dk)?;

    // Step 5: m' <- K-PKE.Decrypt(dk_PKE, c).
    let m = kpke::decrypt::<K>(dk_pke, c)?;

    // Step 6: (K', r') <- G(m' || h).
    let mut g_input = Zeroizing::new([0u8; G_INPUT_BYTES]);
    g_input[..MSG_BYTES].copy_from_slice(&m[..]);
    g_input[MSG_BYTES..].copy_from_slice(h);
    let mut g_output = Zeroizing::new([0u8; G_OUTPUT_BYTES]);
    hash_sha3_512(&mut g_output[..], &g_input[..], G_INPUT_BYTES);
    let mut k_prime = Zeroizing::new([0u8; KYBER_SSBYTES]);
    k_prime.copy_from_slice(&g_output[..KYBER_SSBYTES]);
    let mut r_prime = Zeroizing::new([0u8; SEED_BYTES]);
    r_prime.copy_from_slice(&g_output[KYBER_SSBYTES..]);

    // Step 7: K-bar <- J(z || c), with J = SHAKE256 and 32 bytes of output.
    let mut j_input = Zeroizing::new(Vec::with_capacity(z.len() + c.len()));
    j_input.extend_from_slice(z);
    j_input.extend_from_slice(c);
    let mut k_bar = Zeroizing::new([0u8; KYBER_SSBYTES]);
    shake256_kdf(&mut k_bar[..], &j_input, j_input.len());

    // Step 8: c' <- K-PKE.Encrypt(ek_PKE, m', r'). It depends on m', so it is wiped too.
    let c_prime = Zeroizing::new(kpke::encrypt::<K>(ek, &m, &r_prime)?);

    // Steps 9-11: if c != c' then K' <- K-bar, without a branch.
    reject_on_mismatch(&mut k_prime, &k_bar, c, &c_prime);

    // Step 12.
    Ok(k_prime)
}

/// A 32-byte seed (d, z or m) from `rng`; a failing generator is an error, never
/// a fallback (Algorithm 19 steps 3-5, Algorithm 20 steps 2-4).
fn random_seed<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Zeroizing<Seed>, KyberError> {
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    rng.try_fill_bytes(&mut seed[..])
        .map_err(|_| KyberError::RandomBytesGeneration)?;
    Ok(seed)
}

/// Algorithm 19 with the generator as a parameter, so tests can make it fail.
fn keygen_with<const K: usize, R: RngCore + CryptoRng>(rng: &mut R) -> Result<Keypair, KyberError> {
    // Steps 1-2: d and z, 32 random bytes each.
    let d = random_seed(rng)?;
    let z = random_seed(rng)?;
    // Step 6.
    Ok(keygen_internal::<K>(&d, &z))
}

/// Algorithm 20 with the generator as a parameter. The key is checked before
/// any randomness is drawn.
fn encaps_with<const K: usize, R: RngCore + CryptoRng>(
    ek: &[u8],
    rng: &mut R,
) -> Result<(SharedSecret, Vec<u8>), KyberError> {
    check_ek::<K>(ek)?;
    // Step 1: m, 32 random bytes.
    let m = random_seed(rng)?;
    // Step 5.
    encaps_internal::<K>(ek, &m)
}

/// ML-KEM.KeyGen (Algorithm 19), with `d` and `z` from the OS generator.
pub(crate) fn keygen<const K: usize>() -> Result<Keypair, KyberError> {
    keygen_with::<K, _>(&mut OsRng)
}

/// ML-KEM.KeyGen_internal from a stored seed `(d, z)` (section 3.3 allows
/// keeping the seed in place of the key). The seed is as sensitive as `dk`.
pub(crate) fn keygen_from_seed<const K: usize>(d: &Seed, z: &Seed) -> Keypair {
    keygen_internal::<K>(d, z)
}

/// ML-KEM.Encaps (Algorithm 20): checks `ek` (section 7.2), draws `m` from the
/// OS generator and returns `(K, c)`.
pub(crate) fn encaps<const K: usize>(ek: &[u8]) -> Result<(SharedSecret, Vec<u8>), KyberError> {
    encaps_with::<K, _>(ek, &mut OsRng)
}

/// ML-KEM.Decaps (Algorithm 21): checks `c` and `dk` (section 7.3), then runs
/// Algorithm 18. An invalid but well-formed ciphertext is not an error: it
/// yields the implicit-rejection secret.
pub(crate) fn decaps<const K: usize>(dk: &[u8], c: &[u8]) -> Result<SharedSecret, KyberError> {
    check_ct::<K>(c)?;
    check_dk::<K>(dk)?;
    decaps_internal::<K>(dk, c)
}

/// Algorithms 16 to 18 for vector tests. Not for applications (section 3.3).
#[cfg(any(test, feature = "acvp"))]
pub(crate) mod acvp {
    use super::*;

    pub(crate) fn keygen_internal<const K: usize>(d: &Seed, z: &Seed) -> Keypair {
        super::keygen_internal::<K>(d, z)
    }

    pub(crate) fn encaps_internal<const K: usize>(
        ek: &[u8],
        m: &[u8; MSG_BYTES],
    ) -> Result<(SharedSecret, Vec<u8>), KyberError> {
        super::encaps_internal::<K>(ek, m)
    }

    pub(crate) fn decaps_internal<const K: usize>(
        dk: &[u8],
        c: &[u8],
    ) -> Result<SharedSecret, KyberError> {
        super::decaps_internal::<K>(dk, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::fips202::{sha3_256, sha3_512, shake256};
    use crate::kyber::params::KYBER_Q;
    use crate::mlkem::params::{MlKem1024, MlKem512, MlKem768};
    use core::num::NonZeroU32;

    /// Round trips per parameter set.
    const ROUNDS: usize = 4;
    /// Bits in one coefficient of ByteEncode12 (FIPS 203 Algorithm 5, d = 12).
    const COEFF_BITS: u32 = 12;
    /// The bits of such a coefficient that spill into the second byte.
    const SECOND_BYTE_BITS: u8 = (1 << (COEFF_BITS - u8::BITS)) - 1;
    /// Ciphertext positions flipped in the rejection tests, spread over c1 and c2.
    const FLIP_POSITIONS: usize = 7;

    /// A generator that yields zeros and fails after `ok_calls` successful fills.
    struct FailingRng {
        ok_calls: usize,
        calls: usize,
    }
    impl FailingRng {
        fn new(ok_calls: usize) -> Self {
            FailingRng { ok_calls, calls: 0 }
        }
    }
    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.calls += 1;
            if self.calls > self.ok_calls {
                return Err(NonZeroU32::new(rand_core::Error::CUSTOM_START)
                    .unwrap()
                    .into());
            }
            dest.fill(0xa5);
            Ok(())
        }
    }
    impl CryptoRng for FailingRng {}

    fn h(input: &[u8]) -> [u8; HASH_BYTES] {
        let mut out = [0u8; HASH_BYTES];
        sha3_256(&mut out, input, input.len());
        out
    }

    fn g(input: &[u8]) -> [u8; G_OUTPUT_BYTES] {
        let mut out = [0u8; G_OUTPUT_BYTES];
        sha3_512(&mut out, input, input.len());
        out
    }

    fn j(input: &[u8]) -> [u8; KYBER_SSBYTES] {
        let mut out = [0u8; KYBER_SSBYTES];
        shake256(&mut out, KYBER_SSBYTES, input, input.len());
        out
    }

    /// Runs the generic test `$name::<K>` for each of the three parameter sets.
    macro_rules! all_sets {
        ($name:ident, $test:ident) => {
            #[test]
            fn $test() {
                $name::<{ MlKem512::K }>();
                $name::<{ MlKem768::K }>();
                $name::<{ MlKem1024::K }>();
            }
        };
    }

    fn round_trip<const K: usize>() {
        for round in 0..ROUNDS {
            let (ek, dk) = keygen::<K>().unwrap();
            assert_eq!(ek.len(), ParamSet::<K>::EK_BYTES);
            assert_eq!(dk.len(), ParamSet::<K>::DK_BYTES);
            let (k_enc, c) = encaps::<K>(&ek).unwrap();
            assert_eq!(c.len(), ParamSet::<K>::CT_BYTES);
            let k_dec = decaps::<K>(&dk, &c).unwrap();
            assert_eq!(*k_enc, *k_dec, "K = {K}, round {round}");
            // Fresh randomness each time.
            let (k_again, c_again) = encaps::<K>(&ek).unwrap();
            assert_ne!(c, c_again);
            assert_ne!(*k_enc, *k_again);
        }
    }
    all_sets!(round_trip, round_trip_for_all_sets);

    /// Algorithm 16 step 3: dk = dk_PKE || ek || H(ek) || z, deterministic in (d, z).
    fn keygen_layout<const K: usize>() {
        let (d, z) = ([1u8; SEED_BYTES], [2u8; SEED_BYTES]);
        let (ek, dk) = keygen_from_seed::<K>(&d, &z);
        let (pke_ek, dk_pke) = kpke::keygen::<K>(&d);
        assert_eq!(ek, pke_ek);
        let parts = split_dk::<K>(&dk).unwrap();
        assert_eq!(parts.dk_pke, &dk_pke[..]);
        assert_eq!(parts.ek, &ek[..]);
        assert_eq!(parts.h, h(&ek));
        assert_eq!(parts.z, z);
        let (ek2, dk2) = keygen_from_seed::<K>(&d, &z);
        assert_eq!((&ek, &*dk), (&ek2, &*dk2));
        // z only changes the tail of dk; d changes ek.
        let (ek3, dk3) = keygen_from_seed::<K>(&d, &[3u8; SEED_BYTES]);
        assert_eq!(ek, ek3);
        assert_eq!(dk[..dk.len() - SEED_BYTES], dk3[..dk3.len() - SEED_BYTES]);
        assert_ne!(dk, dk3);
        assert_ne!(ek, keygen_from_seed::<K>(&[9u8; SEED_BYTES], &z).0);
    }
    all_sets!(keygen_layout, keygen_layout_for_all_sets);

    /// Algorithm 17: (K, r) = G(m || H(ek)), no H(m), no H(c).
    fn encaps_derivation<const K: usize>() {
        let (ek, _) = keygen_from_seed::<K>(&[4u8; SEED_BYTES], &[5u8; SEED_BYTES]);
        let m = [6u8; MSG_BYTES];
        let (k, c) = acvp::encaps_internal::<K>(&ek, &m).unwrap();
        let kr = g(&[&m[..], &h(&ek)].concat());
        assert_eq!(*k, kr[..KYBER_SSBYTES]);
        let r: Seed = kr[KYBER_SSBYTES..].try_into().unwrap();
        assert_eq!(c, kpke::encrypt::<K>(&ek, &m, &r).unwrap());
        // Round-3 Kyber hashes m first and puts H(c) in the KDF; neither may happen here.
        let round3 = g(&[&h(&m)[..], &h(&ek)].concat());
        assert_ne!(*k, round3[..KYBER_SSBYTES]);
        let (k2, c2) = acvp::encaps_internal::<K>(&ek, &m).unwrap();
        assert_eq!((*k, c), (*k2, c2));
    }
    all_sets!(encaps_derivation, encaps_derivation_for_all_sets);

    /// A modified ciphertext gives J(z || c), different from K and from the
    /// secret of any other modified ciphertext, and the same on every call.
    fn implicit_rejection<const K: usize>() {
        let (d, z) = ([7u8; SEED_BYTES], [8u8; SEED_BYTES]);
        let (ek, dk) = keygen_from_seed::<K>(&d, &z);
        let (k, c) = acvp::encaps_internal::<K>(&ek, &[9u8; MSG_BYTES]).unwrap();
        assert_eq!(*decaps::<K>(&dk, &c).unwrap(), *k);

        let mut seen = vec![*k];
        let step = c.len() / FLIP_POSITIONS;
        for pos in (0..c.len()).step_by(step) {
            let mut bad = c.clone();
            bad[pos] ^= 1;
            let rejected = decaps::<K>(&dk, &bad).unwrap();
            assert_eq!(*rejected, j(&[&z[..], &bad].concat()), "pos {pos}");
            assert_eq!(*rejected, *decaps::<K>(&dk, &bad).unwrap(), "deterministic");
            assert!(!seen.contains(&*rejected), "pos {pos}");
            seen.push(*rejected);
        }
        // The last byte of c2 and an all-zero ciphertext are rejected too.
        let mut tail = c.clone();
        *tail.last_mut().unwrap() ^= u8::MAX;
        assert_eq!(
            *decaps::<K>(&dk, &tail).unwrap(),
            j(&[&z[..], &tail].concat())
        );
        let zeros = vec![0u8; c.len()];
        assert_eq!(
            *decaps::<K>(&dk, &zeros).unwrap(),
            j(&[&z[..], &zeros].concat())
        );
        // A key that did not make the ciphertext rejects it as well.
        let (_, other_dk) = keygen_from_seed::<K>(&[10u8; SEED_BYTES], &[11u8; SEED_BYTES]);
        let other = decaps::<K>(&other_dk, &c).unwrap();
        assert_ne!(*other, *k);
        assert_eq!(*other, j(&[&[11u8; SEED_BYTES][..], &c].concat()));
    }
    all_sets!(implicit_rejection, implicit_rejection_for_all_sets);

    fn encaps_rejects_bad_keys_before_drawing_randomness<const K: usize>() {
        let (ek, _) = keygen_from_seed::<K>(&[12u8; SEED_BYTES], &[13u8; SEED_BYTES]);
        let mut rng = FailingRng::new(usize::MAX);

        let len = ParamSet::<K>::EK_BYTES;
        for bad in [&ek[1..], &ek[..0], &[&ek[..], &[0]].concat()[..]] {
            assert_eq!(
                encaps_with::<K, _>(bad, &mut rng),
                Err(KyberError::invalid_input("ek", len, bad.len()))
            );
        }
        // First coefficient set to q: 12 bits, little endian across bytes 0 and 1.
        let mut unreduced = ek.clone();
        let [low, high] = (KYBER_Q as u16).to_le_bytes();
        unreduced[0] = low;
        unreduced[1] = (unreduced[1] & !SECOND_BYTE_BITS) | high;
        assert_eq!(
            encaps_with::<K, _>(&unreduced, &mut rng),
            Err(KyberError::InvalidEncapsulationKey)
        );
        assert_eq!(rng.calls, 0, "the generator was not touched");
        // The same ek passes once the key is fine.
        assert!(encaps_with::<K, _>(&ek, &mut rng).is_ok());
        assert_eq!(rng.calls, 1);
    }
    all_sets!(
        encaps_rejects_bad_keys_before_drawing_randomness,
        encaps_rejects_bad_keys_for_all_sets
    );

    fn decaps_rejects_bad_inputs<const K: usize>() {
        let (ek, dk) = keygen_from_seed::<K>(&[14u8; SEED_BYTES], &[15u8; SEED_BYTES]);
        let (_, c) = acvp::encaps_internal::<K>(&ek, &[16u8; MSG_BYTES]).unwrap();
        let bad_c = |n| KyberError::invalid_input("c", ParamSet::<K>::CT_BYTES, n);
        let bad_dk = |n| KyberError::invalid_input("dk", ParamSet::<K>::DK_BYTES, n);
        // The ciphertext length is checked on every call, valid key or not.
        assert_eq!(
            decaps::<K>(&dk, &c[1..]).map(|k| *k),
            Err(bad_c(c.len() - 1))
        );
        assert_eq!(decaps::<K>(&dk, &[]).map(|k| *k), Err(bad_c(0)));
        assert_eq!(
            decaps::<K>(&dk, &[&c[..], &[0]].concat()).map(|k| *k),
            Err(bad_c(c.len() + 1))
        );
        assert_eq!(
            decaps::<K>(&dk[1..], &c).map(|k| *k),
            Err(bad_dk(dk.len() - 1))
        );
        assert_eq!(decaps::<K>(&[], &c).map(|k| *k), Err(bad_dk(0)));
        // Hash check: the stored H(ek) and the embedded ek must agree.
        let h_at = ParamSet::<K>::DK_PKE_BYTES + ParamSet::<K>::EK_BYTES;
        for flip in [h_at, ParamSet::<K>::DK_PKE_BYTES] {
            let mut bad = dk.to_vec();
            bad[flip] ^= 1;
            assert_eq!(
                decaps::<K>(&bad, &c).map(|k| *k),
                Err(KyberError::InvalidDecapsulationKey)
            );
        }
        // The internal function does not check the hash, but never panics on lengths.
        assert!(acvp::decaps_internal::<K>(&dk[1..], &c).is_err());
        assert!(acvp::decaps_internal::<K>(&dk, &c[1..]).is_err());
        assert!(acvp::encaps_internal::<K>(&ek[1..], &[0u8; MSG_BYTES]).is_err());
    }
    all_sets!(
        decaps_rejects_bad_inputs,
        decaps_rejects_bad_inputs_for_all_sets
    );

    #[test]
    fn a_failing_generator_is_an_error_not_a_fallback() {
        type P = MlKem768;
        let err = Err(KyberError::RandomBytesGeneration);
        // d fails, z fails, both fine.
        assert_eq!(keygen_with::<{ P::K }, _>(&mut FailingRng::new(0)), err);
        assert_eq!(keygen_with::<{ P::K }, _>(&mut FailingRng::new(1)), err);
        assert!(keygen_with::<{ P::K }, _>(&mut FailingRng::new(2)).is_ok());
        let (ek, _) = keygen_from_seed::<{ P::K }>(&[0u8; SEED_BYTES], &[0u8; SEED_BYTES]);
        assert_eq!(
            encaps_with::<{ P::K }, _>(&ek, &mut FailingRng::new(0)).map(|(k, _)| *k),
            Err(KyberError::RandomBytesGeneration)
        );
    }
}
