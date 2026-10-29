//! Golden-vector freeze for legacy Kyber: pykyber v1.0.5 must keep producing
//! byte-identical output. The vector file `tests/vectors/legacy-kyber-v1.0.5.json`
//! is append-only (captured from the pinned PyPI wheel and a worktree at tag
//! v1.0.5 by tests/vectors/generate.py). If these tests fail, the bug is in
//! current code; the vectors are never regenerated or edited to pass.

use pykyber::kyber::error::KyberError;
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

/// Seed layout: key seed is `d || z`, encapsulation seed is `m`.
const SEED_HALF_BYTES: usize = 32;
const KEY_SEED_BYTES: usize = 2 * SEED_HALF_BYTES;
const ENC_SEED_BYTES: usize = 32;

/// Three key seeds per parameter set, three parameter sets (see generate.py).
const SEEDS_PER_SET: usize = 3;
const PARAMETER_SETS: usize = 3;

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
    assert_eq!(s.len() % 2, 0, "hex string must have even length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex digit"))
        .collect()
}

#[derive(Deserialize)]
struct GoldenMeta {
    append_only: bool,
}

#[derive(Deserialize)]
struct GoldenFile {
    meta: GoldenMeta,
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

type KeypairFn =
    fn(&mut [u8], &mut [u8], &mut PanicRng, Option<(&[u8], &[u8])>) -> Result<(), KyberError>;
type EncFn =
    fn(&mut [u8], &mut [u8], &[u8], &mut PanicRng, Option<&[u8]>) -> Result<(), KyberError>;
type DecFn = fn(&mut [u8], &[u8], &[u8]) -> Result<(), KyberError>;

/// The legacy entry points and buffer sizes of one parameter set.
struct Suite {
    pk_bytes: usize,
    sk_bytes: usize,
    ct_bytes: usize,
    keypair: KeypairFn,
    enc: EncFn,
    dec: DecFn,
}

fn suite(parameter_set: &str) -> Suite {
    match parameter_set {
        "512" => Suite {
            pk_bytes: KYBER_512_PUBLICKEYBYTES,
            sk_bytes: KYBER_512_SECRETKEYBYTES,
            ct_bytes: KYBER_512_CIPHERTEXTBYTES,
            keypair: crypto_kem_keypair_512::<PanicRng>,
            enc: crypto_kem_enc_512::<PanicRng>,
            dec: crypto_kem_dec_512,
        },
        "768" => Suite {
            pk_bytes: KYBER_768_PUBLICKEYBYTES,
            sk_bytes: KYBER_768_SECRETKEYBYTES,
            ct_bytes: KYBER_768_CIPHERTEXTBYTES,
            keypair: crypto_kem_keypair::<PanicRng>,
            enc: crypto_kem_enc::<PanicRng>,
            dec: crypto_kem_dec,
        },
        "1024" => Suite {
            pk_bytes: KYBER_1024_PUBLICKEYBYTES,
            sk_bytes: KYBER_1024_SECRETKEYBYTES,
            ct_bytes: KYBER_1024_CIPHERTEXTBYTES,
            keypair: crypto_kem_keypair_1024::<PanicRng>,
            enc: crypto_kem_enc_1024::<PanicRng>,
            dec: crypto_kem_dec_1024,
        },
        other => panic!("unknown parameter set {other:?}"),
    }
}

fn check_vector(v: &GoldenVector, index: usize) {
    let at = format!("legacy vector #{index} (Kyber-{})", v.parameter_set);
    let key_seed = hex_decode(&v.key_seed_hex);
    let enc_seed = hex_decode(&v.enc_seed_hex);
    assert_eq!(key_seed.len(), KEY_SEED_BYTES, "{at}: key seed length");
    assert_eq!(enc_seed.len(), ENC_SEED_BYTES, "{at}: enc seed length");
    let (d, z) = key_seed.split_at(SEED_HALF_BYTES);

    let s = suite(&v.parameter_set);
    let mut pk = vec![0u8; s.pk_bytes];
    let mut sk = vec![0u8; s.sk_bytes];
    (s.keypair)(&mut pk, &mut sk, &mut PanicRng, Some((d, z))).expect("keygen");
    assert_eq!(
        pk,
        hex_decode(&v.keypair_public_key_hex),
        "{at}: public key differs from v1.0.5"
    );
    assert_eq!(
        sk,
        hex_decode(&v.keypair_secret_key_hex),
        "{at}: secret key differs from v1.0.5"
    );

    let mut ct = vec![0u8; s.ct_bytes];
    let mut ss_enc = vec![0u8; KYBER_SSBYTES];
    (s.enc)(&mut ct, &mut ss_enc, &pk, &mut PanicRng, Some(&enc_seed))
        .expect("seeded encapsulation");
    assert_eq!(
        ct,
        hex_decode(&v.ciphertext_hex),
        "{at}: ciphertext differs from v1.0.5"
    );
    assert_eq!(
        ss_enc,
        hex_decode(&v.shared_secret_encaps_hex),
        "{at}: encapsulated shared secret differs from v1.0.5"
    );

    let mut ss_dec = vec![0u8; KYBER_SSBYTES];
    (s.dec)(&mut ss_dec, &ct, &sk).expect("decapsulation");
    assert_eq!(
        ss_dec,
        hex_decode(&v.shared_secret_decaps_hex),
        "{at}: decapsulation differs from v1.0.5"
    );
}

#[test]
fn legacy_kyber_v1_0_5_outputs_are_frozen() {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), VECTORS_FILE);
    let text = fs::read_to_string(&path).expect("read golden vector file");
    let file: GoldenFile = serde_json::from_str(&text).expect("parse golden vector file");
    assert!(
        file.meta.append_only,
        "golden vector file meta must state append_only=true"
    );
    assert_eq!(
        file.vectors.len(),
        SEEDS_PER_SET * PARAMETER_SETS,
        "expected {SEEDS_PER_SET} seeds x {PARAMETER_SETS} parameter sets"
    );
    for (index, vector) in file.vectors.iter().enumerate() {
        check_vector(vector, index);
    }
}
