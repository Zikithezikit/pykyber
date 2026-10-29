//! Golden-vector freeze for legacy Kyber: pykyber v1.0.5 must keep producing
//! byte-identical output. The vector file `tests/vectors/legacy-kyber-v1.0.5.json`
//! is append-only (captured from the pinned PyPI wheel and a worktree at tag
//! v1.0.5 by tests/vectors/generate.py). If these tests fail, the bug is in
//! current code; the vectors are never regenerated or edited to pass.

use pykyber::kyber::kem::{
    crypto_kem_dec, crypto_kem_dec_1024, crypto_kem_dec_512, crypto_kem_enc, crypto_kem_enc_1024,
    crypto_kem_enc_512, crypto_kem_keypair, crypto_kem_keypair_1024, crypto_kem_keypair_512,
};
use pykyber::kyber::params::{
    KYBER_1024_CIPHERTEXTBYTES, KYBER_1024_PUBLICKEYBYTES, KYBER_1024_SECRETKEYBYTES,
    KYBER_512_CIPHERTEXTBYTES, KYBER_512_PUBLICKEYBYTES, KYBER_512_SECRETKEYBYTES,
    KYBER_768_CIPHERTEXTBYTES, KYBER_768_PUBLICKEYBYTES, KYBER_768_SECRETKEYBYTES, KYBER_SSBYTES,
};
use rand_core::{CryptoRng, RngCore};
use serde::Deserialize;
use std::fs;

const VECTORS_FILE: &str = "tests/vectors/legacy-kyber-v1.0.5.json";

/// Panicking RNG: the seeded v1.0.5 paths must not consume randomness. These
/// vectors freeze the seeded paths only; any rng use here is a bug.
struct PanicRng;
impl RngCore for PanicRng {
    fn next_u32(&mut self) -> u32 {
        panic!("rng consumed on a seeded path")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("rng consumed on a seeded path")
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        panic!("rng consumed on a seeded path")
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("rng consumed on a seeded path")
    }
}
impl CryptoRng for PanicRng {}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex digit"))
        .collect()
}

#[derive(Deserialize)]
struct GoldenFile {
    meta: serde_json::Value,
    vectors: Vec<GoldenVector>,
}

#[derive(Deserialize)]
struct GoldenVector {
    parameter_set: String,
    key_seed_hex: String,
    enc_seed_hex: String,
    keypair_public_key_hex: String,
    keypair_secret_key_hex: String,
    ciphertext_hex: String,
    shared_secret_encaps_hex: String,
    shared_secret_decaps_hex: String,
}

fn check_vector(v: &GoldenVector, index: usize) {
    let where_ = format!("legacy vector #{} (Kyber-{})", index, v.parameter_set);
    let d = &hex_decode(&v.key_seed_hex)[..32];
    let z = &hex_decode(&v.key_seed_hex)[32..];
    let enc_seed = hex_decode(&v.enc_seed_hex);
    assert_eq!(d.len(), 32);
    assert_eq!(z.len(), 32);
    assert_eq!(enc_seed.len(), 32);

    match v.parameter_set.as_str() {
        "512" => check_512(&where_, v, d, z, &enc_seed),
        "768" => check_768(&where_, v, d, z, &enc_seed),
        "1024" => check_1024(&where_, v, d, z, &enc_seed),
        other => panic!("{}: unknown parameter set", other),
    }
}

fn check_512(where_: &str, v: &GoldenVector, d: &[u8], z: &[u8], enc_seed: &[u8]) {
    let mut pk = vec![0u8; KYBER_512_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_512_SECRETKEYBYTES];
    crypto_kem_keypair_512(&mut pk, &mut sk, &mut PanicRng, Some((d, z))).expect("keygen");
    assert_eq!(
        &pk,
        hex_decode(&v.keypair_public_key_hex).as_slice(),
        "{}: public key differs from v1.0.5",
        where_
    );
    assert_eq!(
        &sk,
        hex_decode(&v.keypair_secret_key_hex).as_slice(),
        "{}: secret key differs from v1.0.5",
        where_
    );

    let mut ct = vec![0u8; KYBER_512_CIPHERTEXTBYTES];
    let mut ss_enc = vec![0u8; KYBER_SSBYTES];
    crypto_kem_enc_512(&mut ct, &mut ss_enc, &pk, &mut PanicRng, Some(enc_seed))
        .expect("seeded encapsulation");
    assert_eq!(
        &ct,
        hex_decode(&v.ciphertext_hex).as_slice(),
        "{}: ciphertext differs from v1.0.5",
        where_
    );
    assert_eq!(
        &ss_enc,
        hex_decode(&v.shared_secret_encaps_hex).as_slice(),
        "{}: shared secret differs from v1.0.5",
        where_
    );

    let mut ss_dec = vec![0u8; KYBER_SSBYTES];
    crypto_kem_dec_512(&mut ss_dec, &ct, &sk).expect("decapsulation");
    assert_eq!(
        &ss_dec,
        hex_decode(&v.shared_secret_decaps_hex).as_slice(),
        "{}: decapsulation differs from v1.0.5",
        where_
    );
}

fn check_768(where_: &str, v: &GoldenVector, d: &[u8], z: &[u8], enc_seed: &[u8]) {
    let mut pk = vec![0u8; KYBER_768_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_768_SECRETKEYBYTES];
    crypto_kem_keypair(&mut pk, &mut sk, &mut PanicRng, Some((d, z))).expect("keygen");
    assert_eq!(
        &pk,
        hex_decode(&v.keypair_public_key_hex).as_slice(),
        "{}: public key differs from v1.0.5",
        where_
    );
    assert_eq!(
        &sk,
        hex_decode(&v.keypair_secret_key_hex).as_slice(),
        "{}: secret key differs from v1.0.5",
        where_
    );

    let mut ct = vec![0u8; KYBER_768_CIPHERTEXTBYTES];
    let mut ss_enc = vec![0u8; KYBER_SSBYTES];
    crypto_kem_enc(&mut ct, &mut ss_enc, &pk, &mut PanicRng, Some(enc_seed))
        .expect("seeded encapsulation");
    assert_eq!(
        &ct,
        hex_decode(&v.ciphertext_hex).as_slice(),
        "{}: ciphertext differs from v1.0.5",
        where_
    );
    assert_eq!(
        &ss_enc,
        hex_decode(&v.shared_secret_encaps_hex).as_slice(),
        "{}: shared secret differs from v1.0.5",
        where_
    );

    let mut ss_dec = vec![0u8; KYBER_SSBYTES];
    crypto_kem_dec(&mut ss_dec, &ct, &sk).expect("decapsulation");
    assert_eq!(
        &ss_dec,
        hex_decode(&v.shared_secret_decaps_hex).as_slice(),
        "{}: decapsulation differs from v1.0.5",
        where_
    );
}

fn check_1024(where_: &str, v: &GoldenVector, d: &[u8], z: &[u8], enc_seed: &[u8]) {
    let mut pk = vec![0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_1024_SECRETKEYBYTES];
    crypto_kem_keypair_1024(&mut pk, &mut sk, &mut PanicRng, Some((d, z))).expect("keygen");
    assert_eq!(
        &pk,
        hex_decode(&v.keypair_public_key_hex).as_slice(),
        "{}: public key differs from v1.0.5",
        where_
    );
    assert_eq!(
        &sk,
        hex_decode(&v.keypair_secret_key_hex).as_slice(),
        "{}: secret key differs from v1.0.5",
        where_
    );

    let mut ct = vec![0u8; KYBER_1024_CIPHERTEXTBYTES];
    let mut ss_enc = vec![0u8; KYBER_SSBYTES];
    crypto_kem_enc_1024(&mut ct, &mut ss_enc, &pk, &mut PanicRng, Some(enc_seed))
        .expect("seeded encapsulation");
    assert_eq!(
        &ct,
        hex_decode(&v.ciphertext_hex).as_slice(),
        "{}: ciphertext differs from v1.0.5",
        where_
    );
    assert_eq!(
        &ss_enc,
        hex_decode(&v.shared_secret_encaps_hex).as_slice(),
        "{}: shared secret differs from v1.0.5",
        where_
    );

    let mut ss_dec = vec![0u8; KYBER_SSBYTES];
    crypto_kem_dec_1024(&mut ss_dec, &ct, &sk).expect("decapsulation");
    assert_eq!(
        &ss_dec,
        hex_decode(&v.shared_secret_decaps_hex).as_slice(),
        "{}: decapsulation differs from v1.0.5",
        where_
    );
}

#[test]
fn legacy_kyber_v1_0_5_outputs_are_frozen() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let text = fs::read_to_string(format!("{}/{}", manifest_dir, VECTORS_FILE))
        .expect("read golden vector file");
    let file: GoldenFile = serde_json::from_str(&text).expect("parse golden vector file");
    assert_eq!(
        file.meta["append_only"], true,
        "golden vector file meta must state append_only=true"
    );
    assert_eq!(file.vectors.len(), 9, "expected 3 seeds x 3 parameter sets");
    for (index, vector) in file.vectors.iter().enumerate() {
        check_vector(vector, index);
    }
}
