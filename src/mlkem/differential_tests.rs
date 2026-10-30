//! Differential test against RustCrypto `ml-kem` 0.3.3 (a dev-dependency, FIPS
//! 203 final, written independently of this crate; no code is shared).
//!
//! Random inputs come from a fixed-seed generator, so a failure reproduces and
//! the case number in the message says which input it was. For every parameter
//! set, per round:
//! - KeyGen from a seed `d || z`: same `ek`, same expanded `dk`.
//! - Encaps with a given `m`: same `c` and `K`.
//! - Decaps of the valid ciphertext, of one with a flipped bit and of a random
//!   one: same `K` (the last two are the implicit-rejection path).
//! - Decaps with a `dk` whose `dk_PKE` or `z` bytes were changed.
//! - The key checks: a random byte of `ek` or `dk` is replaced and both
//!   implementations must agree on whether the key is accepted (section 7.2
//!   modulus check, section 7.3 hash check), plus a coefficient forced into
//!   q..2^12-1.

use super::check::{check_dk, check_ek};
use super::kem::acvp;
use super::params::{MlKem1024, MlKem512, MlKem768, ParamSet};
use crate::kyber::params::{KYBER_N, KYBER_Q, KYBER_SYMBYTES};
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, KeyExport};
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{FromSeed, TryKeyInit};

/// Rounds per parameter set; each round draws fresh seeds, `m` and mutations.
const ROUNDS: usize = 200;
/// Seed of the generator below.
const PRNG_SEED: u64 = 0x2545_f491_4f6c_dd1d;
/// Bits in the 12-bit coefficient encoding of the keys (ByteEncode12).
const COEFFICIENT_BITS: u32 = 12;
const SEED_BYTES: usize = KYBER_SYMBYTES;
const BYTE_BITS: usize = u8::BITS as usize;

/// Shifts of Marsaglia's xorshift64 as used in xorshift64* (Vigna).
const XORSHIFT_RIGHT_1: u32 = 12;
const XORSHIFT_LEFT: u32 = 25;
const XORSHIFT_RIGHT_2: u32 = 27;
/// Output multiplier of xorshift64* (Vigna).
const OUTPUT_MULTIPLIER: u64 = 0x2545_f491_4f6c_dd1d;

/// xorshift64*, enough for reproducible test inputs.
struct Prng(u64);

impl Prng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> XORSHIFT_RIGHT_1;
        self.0 ^= self.0 << XORSHIFT_LEFT;
        self.0 ^= self.0 >> XORSHIFT_RIGHT_2;
        self.0.wrapping_mul(OUTPUT_MULTIPLIER)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() >> u32::BITS) as usize % bound
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        out.iter_mut()
            .for_each(|b| *b = (self.next() >> u32::BITS) as u8);
        out
    }

    fn vec(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> u32::BITS) as u8).collect()
    }
}

/// Sets the 12-bit coefficient number `index` of an encoded polynomial vector.
fn set_coefficient(encoded: &mut [u8], index: usize, value: u16) {
    let first_bit = index * COEFFICIENT_BITS as usize;
    for bit in 0..COEFFICIENT_BITS as usize {
        let (byte, shift) = ((first_bit + bit) / BYTE_BITS, (first_bit + bit) % BYTE_BITS);
        encoded[byte] = (encoded[byte] & !(1 << shift)) | ((((value >> bit) & 1) as u8) << shift);
    }
}

macro_rules! differential_test {
    ($name:ident, $params:ident, $module:ident, $reference:ident) => {
        #[test]
        fn $name() {
            use ml_kem::$module::{Ciphertext, DecapsulationKey, EncapsulationKey};
            const K: usize = $params::K;
            let mut rng = Prng(PRNG_SEED);
            // dk = dk_PKE || ek || H(ek) || z (Algorithm 16 step 3), and ek = t || rho.
            let t_bytes = ParamSet::<K>::DK_PKE_BYTES;
            let z_start = ParamSet::<K>::DK_BYTES - SEED_BYTES;

            for round in 0..ROUNDS {
                let (d, z, m) = (
                    rng.bytes::<SEED_BYTES>(),
                    rng.bytes::<SEED_BYTES>(),
                    rng.bytes::<SEED_BYTES>(),
                );

                // KeyGen.
                let seed = Array::try_from([&d[..], &z[..]].concat().as_slice()).unwrap();
                let (ref_dk, ref_ek) = ml_kem::$reference::from_seed(&seed);
                let (ek, dk) = acvp::keygen_internal::<K>(&d, &z);
                assert_eq!(
                    ek.as_slice(),
                    ref_ek.to_bytes().as_slice(),
                    "round {round}: ek"
                );
                #[allow(deprecated)]
                let ref_expanded = ref_dk.to_expanded_bytes();
                assert_eq!(dk.as_slice(), ref_expanded.as_slice(), "round {round}: dk");

                // Encaps.
                let (k, c) = acvp::encaps_internal::<K>(&ek, &m).unwrap();
                let (ref_c, ref_k) = ref_ek.encapsulate_deterministic(&Array::from(m));
                assert_eq!(c.as_slice(), ref_c.as_slice(), "round {round}: c");
                assert_eq!(k.as_slice(), ref_k.as_slice(), "round {round}: K");

                // Decaps: valid, one flipped bit, random.
                let mut flipped = c.clone();
                flipped[rng.below(c.len())] ^= 1 << rng.below(BYTE_BITS);
                for (label, input) in [
                    ("valid", c.clone()),
                    ("flipped", flipped),
                    ("random", rng.vec(c.len())),
                ] {
                    let ours = acvp::decaps_internal::<K>(&dk, &input).unwrap();
                    let theirs =
                        ref_dk.decapsulate(&Ciphertext::try_from(input.as_slice()).unwrap());
                    assert_eq!(
                        ours.as_slice(),
                        theirs.as_slice(),
                        "round {round}: decaps of {label}"
                    );
                    assert_eq!(
                        ours.as_slice() == k.as_slice(),
                        label == "valid",
                        "round {round}: {label}"
                    );
                }

                // Decaps with a changed dk_PKE or z (both pass the section 7.3 checks).
                let mut changed = dk.to_vec();
                let position = [rng.below(t_bytes), z_start + rng.below(SEED_BYTES)][rng.below(2)];
                changed[position] ^= 1 << rng.below(BYTE_BITS);
                #[allow(deprecated)]
                let ref_changed = DecapsulationKey::from_expanded_bytes(
                    &Array::try_from(changed.as_slice()).unwrap(),
                );
                let ref_changed =
                    ref_changed.expect("hash check passes when only dk_PKE or z changes");
                check_dk::<K>(&changed).unwrap();
                let ours = acvp::decaps_internal::<K>(&changed, &c).unwrap();
                let theirs = ref_changed.decapsulate(&ref_c);
                assert_eq!(
                    ours.as_slice(),
                    theirs.as_slice(),
                    "round {round}: decaps, changed dk byte {position}"
                );

                // Key checks: both must give the same verdict on a random byte change.
                let mut bad_ek = ek.clone();
                bad_ek[rng.below(ek.len())] = rng.bytes::<1>()[0];
                let ours = check_ek::<K>(&bad_ek).is_ok();
                let theirs = EncapsulationKey::new_from_slice(&bad_ek).is_ok();
                assert_eq!(ours, theirs, "round {round}: ek check after a random byte");

                let mut overflow_ek = ek.clone();
                let value = KYBER_Q + rng.below((1 << COEFFICIENT_BITS) - KYBER_Q);
                set_coefficient(
                    &mut overflow_ek[..t_bytes],
                    rng.below(K * KYBER_N),
                    value as u16,
                );
                assert!(
                    check_ek::<K>(&overflow_ek).is_err(),
                    "round {round}: coefficient {value}"
                );
                assert!(
                    EncapsulationKey::new_from_slice(&overflow_ek).is_err(),
                    "round {round}: reference, {value}"
                );

                let mut bad_dk = dk.to_vec();
                let position = t_bytes + rng.below(z_start - t_bytes);
                bad_dk[position] =
                    bad_dk[position].wrapping_add(1 + rng.below(u8::MAX as usize) as u8);
                let ours = check_dk::<K>(&bad_dk).is_ok();
                #[allow(deprecated)]
                let theirs = DecapsulationKey::from_expanded_bytes(
                    &Array::try_from(bad_dk.as_slice()).unwrap(),
                )
                .is_ok();
                assert_eq!(
                    ours, theirs,
                    "round {round}: dk check after a change at byte {position}"
                );
                assert!(
                    !ours,
                    "round {round}: a change inside ek or H(ek) must fail the hash check"
                );
            }
        }
    };
}

differential_test!(
    ml_kem_512_matches_the_reference,
    MlKem512,
    ml_kem_512,
    MlKem512
);
differential_test!(
    ml_kem_768_matches_the_reference,
    MlKem768,
    ml_kem_768,
    MlKem768
);
differential_test!(
    ml_kem_1024_matches_the_reference,
    MlKem1024,
    ml_kem_1024,
    MlKem1024
);
