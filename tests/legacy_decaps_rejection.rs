//! Implicit rejection in the legacy (round-3) decapsulation: a ciphertext that
//! does not re-encrypt to itself must give `KDF(z || H(c))` (not an error, and
//! not the real shared secret). The expected value is derived here from `z` and
//! `c` with the public hash functions, independently of the code under test, so
//! it covers `verify`, `cmov` and the rest of the decapsulation tail.

use pykyber::kyber::fips202::{sha3_256, shake256};
use pykyber::kyber::params::*;
use pykyber::kyber::{
    crypto_kem_dec, crypto_kem_dec_1024, crypto_kem_dec_512, crypto_kem_enc, crypto_kem_enc_1024,
    crypto_kem_enc_512, crypto_kem_keypair, crypto_kem_keypair_1024, crypto_kem_keypair_512,
};
use rand_core::{CryptoRng, Error, RngCore};

/// Seeded paths never draw randomness; this generator must not be asked to.
struct NoRandomness;

impl RngCore for NoRandomness {
    fn next_u32(&mut self) -> u32 {
        unreachable!()
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!()
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unreachable!()
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
        unreachable!()
    }
}

impl CryptoRng for NoRandomness {}

/// Fixed seeds `d`, `z` and `m` (arbitrary test data).
const D_SEED: [u8; KYBER_SYMBYTES] = [0x11; KYBER_SYMBYTES];
const Z_SEED: [u8; KYBER_SYMBYTES] = [0x22; KYBER_SYMBYTES];
const M_SEED: [u8; KYBER_SYMBYTES] = [0x33; KYBER_SYMBYTES];

/// `KDF(z || H(c))`, the shared secret of an implicitly rejected ciphertext.
fn rejection_secret(z: &[u8], ct: &[u8]) -> [u8; KYBER_SSBYTES] {
    let mut h = [0u8; KYBER_SYMBYTES];
    sha3_256(&mut h, ct, ct.len());
    let mut input = [0u8; 2 * KYBER_SYMBYTES];
    input[..KYBER_SYMBYTES].copy_from_slice(z);
    input[KYBER_SYMBYTES..].copy_from_slice(&h);
    let mut ss = [0u8; KYBER_SSBYTES];
    shake256(&mut ss, KYBER_SSBYTES, &input, input.len());
    ss
}

type Decaps = fn(&mut [u8], &[u8], &[u8]) -> Result<(), pykyber::kyber::KyberError>;

/// Byte positions to damage: the first, the last and a few in between,
/// covering the compressed vector part and the compressed `v` part.
fn damaged_positions(ct_len: usize) -> [usize; 5] {
    [0, 1, ct_len / 3, ct_len - KYBER_SYMBYTES, ct_len - 1]
}

fn check(pk: &[u8], sk: &[u8], ct: &[u8], real_ss: &[u8], dec: Decaps) {
    let z = &sk[sk.len() - KYBER_SYMBYTES..];

    let mut ss = [0u8; KYBER_SSBYTES];
    dec(&mut ss, ct, sk).unwrap();
    assert_eq!(ss, real_ss, "valid ciphertext (pk length {})", pk.len());

    for pos in damaged_positions(ct.len()) {
        for bit in [0u8, 7u8] {
            let mut bad = ct.to_vec();
            bad[pos] ^= 1 << bit;
            let mut got = [0u8; KYBER_SSBYTES];
            dec(&mut got, &bad, sk).expect("implicit rejection is not an error");
            assert_ne!(got, real_ss, "byte {pos} bit {bit} gave the real secret");
            assert_eq!(
                got,
                rejection_secret(z, &bad),
                "byte {pos} bit {bit} of a ciphertext of {} bytes",
                ct.len()
            );
        }
    }
}

#[test]
fn kyber_512_rejects_implicitly() {
    let mut pk = vec![0u8; KYBER_512_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_512_SECRETKEYBYTES];
    crypto_kem_keypair_512(
        &mut pk,
        &mut sk,
        &mut NoRandomness,
        Some((&D_SEED, &Z_SEED)),
    )
    .unwrap();
    let (mut ct, mut ss) = (vec![0u8; KYBER_512_CIPHERTEXTBYTES], [0u8; KYBER_SSBYTES]);
    crypto_kem_enc_512(&mut ct, &mut ss, &pk, &mut NoRandomness, Some(&M_SEED)).unwrap();
    check(&pk, &sk, &ct, &ss, crypto_kem_dec_512);
}

#[test]
fn kyber_768_rejects_implicitly() {
    let mut pk = vec![0u8; KYBER_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_SECRETKEYBYTES];
    crypto_kem_keypair(
        &mut pk,
        &mut sk,
        &mut NoRandomness,
        Some((&D_SEED, &Z_SEED)),
    )
    .unwrap();
    let (mut ct, mut ss) = (vec![0u8; KYBER_CIPHERTEXTBYTES], [0u8; KYBER_SSBYTES]);
    crypto_kem_enc(&mut ct, &mut ss, &pk, &mut NoRandomness, Some(&M_SEED)).unwrap();
    check(&pk, &sk, &ct, &ss, crypto_kem_dec);
}

#[test]
fn kyber_1024_rejects_implicitly() {
    let mut pk = vec![0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_1024_SECRETKEYBYTES];
    crypto_kem_keypair_1024(
        &mut pk,
        &mut sk,
        &mut NoRandomness,
        Some((&D_SEED, &Z_SEED)),
    )
    .unwrap();
    let (mut ct, mut ss) = (vec![0u8; KYBER_1024_CIPHERTEXTBYTES], [0u8; KYBER_SSBYTES]);
    crypto_kem_enc_1024(&mut ct, &mut ss, &pk, &mut NoRandomness, Some(&M_SEED)).unwrap();
    check(&pk, &sk, &ct, &ss, crypto_kem_dec_1024);
}
