//! Golden-vector capture harness for legacy Kyber tag v1.0.5.
//!
//! This file is NOT part of the normal test build: the generator
//! `tests/vectors/generate.py` copies it into a git worktree of tag v1.0.5 as
//! `examples/gen_capture.rs` and runs it there with `cargo run --example`,
//! feeding one `parameter_set key_seed enc_seed` line per vector on stdin.
//! It prints one JSON object per line with the seeded key-generation, seeded
//! encapsulation and decapsulation outputs of pykyber v1.0.5.
//!
//! The passed RNG must never be consumed: v1.0.5's seeded keygen and seeded
//! encapsulation ignore it, so panicking on any rng use catches an accidental
//! capture of a non-seeded (OS-random) path instead of silently recording it.

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
use std::io::{BufRead, Write};

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

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    assert_eq!(bytes.len() % 2, 0, "hex string must have even length");
    (0..bytes.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex digit"))
        .collect()
}

fn print_vector(
    set: &str,
    key_seed: &[u8],
    enc_seed: &[u8],
    pk: &[u8],
    sk: &[u8],
    ct: &[u8],
    ss_enc: &[u8],
    ss_dec: &[u8],
) {
    println!(
        "{{\"parameter_set\":\"{}\",\"key_seed_hex\":\"{}\",\"enc_seed_hex\":\"{}\",\
\"keypair_public_key_hex\":\"{}\",\"keypair_secret_key_hex\":\"{}\",\"ciphertext_hex\":\"{}\",\
\"shared_secret_encaps_hex\":\"{}\",\"shared_secret_decaps_hex\":\"{}\"}}",
        set,
        hex(key_seed),
        hex(enc_seed),
        hex(pk),
        hex(sk),
        hex(ct),
        hex(ss_enc),
        hex(ss_dec)
    );
}

fn capture_512(key_seed: &[u8], enc_seed: &[u8]) {
    let mut pk = vec![0u8; KYBER_512_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_512_SECRETKEYBYTES];
    crypto_kem_keypair_512(
        &mut pk,
        &mut sk,
        &mut PanicRng,
        Some((&key_seed[..32], &key_seed[32..])),
    )
    .expect("seeded keygen");
    let mut ct = vec![0u8; KYBER_512_CIPHERTEXTBYTES];
    let mut ss_enc = vec![0u8; KYBER_SSBYTES];
    crypto_kem_enc_512(&mut ct, &mut ss_enc, &pk, &mut PanicRng, Some(enc_seed))
        .expect("seeded encapsulation");
    let mut ss_dec = vec![0u8; KYBER_SSBYTES];
    crypto_kem_dec_512(&mut ss_dec, &ct, &sk).expect("decapsulation");
    print_vector("512", key_seed, enc_seed, &pk, &sk, &ct, &ss_enc, &ss_dec);
}

fn capture_768(key_seed: &[u8], enc_seed: &[u8]) {
    let mut pk = vec![0u8; KYBER_768_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_768_SECRETKEYBYTES];
    crypto_kem_keypair(
        &mut pk,
        &mut sk,
        &mut PanicRng,
        Some((&key_seed[..32], &key_seed[32..])),
    )
    .expect("seeded keygen");
    let mut ct = vec![0u8; KYBER_768_CIPHERTEXTBYTES];
    let mut ss_enc = vec![0u8; KYBER_SSBYTES];
    crypto_kem_enc(&mut ct, &mut ss_enc, &pk, &mut PanicRng, Some(enc_seed))
        .expect("seeded encapsulation");
    let mut ss_dec = vec![0u8; KYBER_SSBYTES];
    crypto_kem_dec(&mut ss_dec, &ct, &sk).expect("decapsulation");
    print_vector("768", key_seed, enc_seed, &pk, &sk, &ct, &ss_enc, &ss_dec);
}

fn capture_1024(key_seed: &[u8], enc_seed: &[u8]) {
    let mut pk = vec![0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_1024_SECRETKEYBYTES];
    crypto_kem_keypair_1024(
        &mut pk,
        &mut sk,
        &mut PanicRng,
        Some((&key_seed[..32], &key_seed[32..])),
    )
    .expect("seeded keygen");
    let mut ct = vec![0u8; KYBER_1024_CIPHERTEXTBYTES];
    let mut ss_enc = vec![0u8; KYBER_SSBYTES];
    crypto_kem_enc_1024(&mut ct, &mut ss_enc, &pk, &mut PanicRng, Some(enc_seed))
        .expect("seeded encapsulation");
    let mut ss_dec = vec![0u8; KYBER_SSBYTES];
    crypto_kem_dec_1024(&mut ss_dec, &ct, &sk).expect("decapsulation");
    print_vector("1024", key_seed, enc_seed, &pk, &sk, &ct, &ss_enc, &ss_dec);
}

fn main() {
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.expect("read stdin");
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let set = fields.next().expect("parameter set");
        let key_seed_hex = fields.next().expect("key seed");
        let enc_seed_hex = fields.next().expect("encapsulation seed");
        let key_seed = hex_decode(key_seed_hex);
        let enc_seed = hex_decode(enc_seed_hex);
        assert_eq!(key_seed.len(), 64, "key seed must be 64 bytes (d || z)");
        assert_eq!(enc_seed.len(), 32, "encapsulation seed must be 32 bytes");
        match set {
            "512" => capture_512(&key_seed, &enc_seed),
            "768" => capture_768(&key_seed, &enc_seed),
            "1024" => capture_1024(&key_seed, &enc_seed),
            other => panic!("unknown parameter set {}", other),
        }
    }
    let _ = std::io::stdout().flush();
}
