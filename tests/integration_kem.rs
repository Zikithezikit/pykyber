//! Integration tests for Kyber KEM

use pykyber::kyber::api::{decapsulate, encapsulate, keypair};
use pykyber::kyber::crypto_kem_dec_1024;
use pykyber::kyber::crypto_kem_dec_512;
use pykyber::kyber::crypto_kem_enc_1024;
use pykyber::kyber::crypto_kem_enc_512;
use pykyber::kyber::crypto_kem_keypair_1024;
use pykyber::kyber::crypto_kem_keypair_512;
use pykyber::kyber::params::*;
use rand::thread_rng;

#[test]
fn test_kyber_512_keypair_sizes() {
    let mut rng = thread_rng();
    let mut pk = vec![0u8; KYBER_512_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_512_SECRETKEYBYTES];
    crypto_kem_keypair_512(&mut pk, &mut sk, &mut rng, None).unwrap();

    assert_eq!(pk.len(), KYBER_512_PUBLICKEYBYTES);
    assert_eq!(sk.len(), KYBER_512_SECRETKEYBYTES);
}

#[test]
fn test_kyber_768_keypair_sizes() {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).unwrap();

    assert_eq!(keys.public.len(), KYBER_768_PUBLICKEYBYTES);
    assert_eq!(keys.secret.len(), KYBER_768_SECRETKEYBYTES);
}

#[test]
fn test_kyber_1024_keypair_sizes() {
    let mut rng = thread_rng();
    let mut pk = vec![0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_1024_SECRETKEYBYTES];
    crypto_kem_keypair_1024(&mut pk, &mut sk, &mut rng, None).unwrap();

    assert_eq!(pk.len(), KYBER_1024_PUBLICKEYBYTES);
    assert_eq!(sk.len(), KYBER_1024_SECRETKEYBYTES);
}

#[test]
fn test_kyber_512_encapsulate_decapsulate() {
    let mut rng = thread_rng();
    let mut pk = vec![0u8; KYBER_512_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_512_SECRETKEYBYTES];
    crypto_kem_keypair_512(&mut pk, &mut sk, &mut rng, None).unwrap();

    let mut ct = vec![0u8; KYBER_512_CIPHERTEXTBYTES];
    let mut ss = vec![0u8; KYBER_SSBYTES];
    crypto_kem_enc_512(&mut ct, &mut ss, &pk, &mut rng, None).unwrap();

    assert_eq!(ct.len(), KYBER_512_CIPHERTEXTBYTES);
    assert_eq!(ss.len(), KYBER_SSBYTES);

    let mut ss2 = vec![0u8; KYBER_SSBYTES];
    crypto_kem_dec_512(&mut ss2, &ct, &sk).unwrap();
    assert_eq!(ss, ss2);
}

#[test]
fn test_kyber_768_encapsulate_decapsulate() {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).unwrap();

    let (ct, ss) = encapsulate(&keys.public, &mut rng).unwrap();
    assert_eq!(ct.len(), KYBER_768_CIPHERTEXTBYTES);
    assert_eq!(ss.len(), KYBER_SSBYTES);

    let ss2 = decapsulate(&ct, &keys.secret).unwrap();
    assert_eq!(ss.to_vec(), ss2.to_vec());
}

#[test]
fn test_kyber_1024_encapsulate_decapsulate() {
    let mut rng = thread_rng();
    let mut pk = vec![0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_1024_SECRETKEYBYTES];
    crypto_kem_keypair_1024(&mut pk, &mut sk, &mut rng, None).unwrap();

    let mut ct = vec![0u8; KYBER_1024_CIPHERTEXTBYTES];
    let mut ss = vec![0u8; KYBER_SSBYTES];
    crypto_kem_enc_1024(&mut ct, &mut ss, &pk, &mut rng, None).unwrap();

    assert_eq!(ct.len(), KYBER_1024_CIPHERTEXTBYTES);
    assert_eq!(ss.len(), KYBER_SSBYTES);

    let mut ss2 = vec![0u8; KYBER_SSBYTES];
    crypto_kem_dec_1024(&mut ss2, &ct, &sk).unwrap();
    assert_eq!(ss, ss2);
}

#[test]
fn test_different_keypairs_produce_different_secrets() {
    let mut rng = thread_rng();
    let keys1 = keypair(&mut rng).unwrap();
    let keys2 = keypair(&mut rng).unwrap();

    let (ct1, ss1) = encapsulate(&keys1.public, &mut rng).unwrap();
    let (ct2, ss2) = encapsulate(&keys2.public, &mut rng).unwrap();

    let ss1_dec = decapsulate(&ct1, &keys1.secret).unwrap();
    let ss2_dec = decapsulate(&ct2, &keys2.secret).unwrap();

    assert_eq!(ss1.to_vec(), ss1_dec.to_vec());
    assert_eq!(ss2.to_vec(), ss2_dec.to_vec());
    assert_ne!(ss1.to_vec(), ss2.to_vec());
}

#[test]
fn test_wrong_key_fails() {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).unwrap();
    let wrong_keys = keypair(&mut rng).unwrap();

    let (ct, ss) = encapsulate(&keys.public, &mut rng).unwrap();
    let ss_wrong = decapsulate(&ct, &wrong_keys.secret).unwrap();

    assert_ne!(ss.to_vec(), ss_wrong.to_vec());
}

#[test]
fn test_decapsulation_is_deterministic() {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).unwrap();

    let (ct, _) = encapsulate(&keys.public, &mut rng).unwrap();

    for _ in 0..5 {
        let ss = decapsulate(&ct, &keys.secret).unwrap();
        assert_eq!(
            ss.to_vec(),
            decapsulate(&ct, &keys.secret).unwrap().to_vec(),
            "decapsulation should be deterministic"
        );
    }
}

#[test]
fn test_invalid_public_key_length() {
    let result = encapsulate(b"short", &mut thread_rng());
    assert!(result.is_err());
}

#[test]
fn test_invalid_ciphertext_length() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let result = decapsulate(b"short", &keys.secret);
    assert!(result.is_err());
}

#[test]
fn test_invalid_secret_key_length() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let (ct, _) = encapsulate(&keys.public, &mut thread_rng()).unwrap();
    let result = decapsulate(&ct, b"short");
    assert!(result.is_err());
}

#[test]
fn test_empty_public_key() {
    let result = encapsulate(&[], &mut thread_rng());
    assert!(result.is_err());
}

#[test]
fn test_empty_ciphertext() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let result = decapsulate(&[], &keys.secret);
    assert!(result.is_err());
}

#[test]
fn test_keypair_not_all_zeros() {
    let keys = keypair(&mut thread_rng()).unwrap();
    assert!(keys.public.iter().any(|&x| x != 0));
    assert!(keys.secret.iter().any(|&x| x != 0));
}

#[test]
fn test_shared_secret_not_all_zeros() {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).unwrap();
    let (ct, ss) = encapsulate(&keys.public, &mut rng).unwrap();

    assert!(ss.iter().any(|&x| x != 0));

    let ss2 = decapsulate(&ct, &keys.secret).unwrap();
    assert!(ss2.iter().any(|&x| x != 0));
}
