//! API tests for Kyber KEM - equivalent to src/lib.rs tests

use pykyber::kyber::api::{decapsulate, derive, encapsulate, keypair, public, Keypair};
use pykyber::kyber::params::*;
use rand::thread_rng;

#[test]
fn test_keypair_generation() {
    let mut rng = thread_rng();
    let result = keypair(&mut rng);
    assert!(result.is_ok());
    let keys = result.unwrap();
    assert_eq!(keys.public.len(), KYBER_PUBLICKEYBYTES);
    assert_eq!(keys.secret.len(), KYBER_SECRETKEYBYTES);
}

#[test]
fn test_encapsulate_decapsulate() {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).unwrap();

    let (ct, ss) = encapsulate(&keys.public, &mut thread_rng()).unwrap();
    assert_eq!(ct.len(), KYBER_CIPHERTEXTBYTES);
    assert_eq!(ss.len(), KYBER_SSBYTES);

    let ss2 = decapsulate(&ct, &keys.secret).unwrap();
    assert_eq!(ss, ss2);
}

#[test]
fn test_invalid_public_key_length() {
    let result = encapsulate(b"short", &mut thread_rng());
    assert!(result.is_err());
}

#[test]
fn test_invalid_ciphertext_length() {
    let result = decapsulate(b"short", &[0u8; KYBER_SECRETKEYBYTES]);
    assert!(result.is_err());
}

#[test]
fn test_invalid_secret_key_length() {
    let result = decapsulate(&[0u8; KYBER_CIPHERTEXTBYTES], b"short");
    assert!(result.is_err());
}

#[test]
fn test_different_keypairs_produce_different_secrets() {
    let keys1 = keypair(&mut thread_rng()).unwrap();
    let keys2 = keypair(&mut thread_rng()).unwrap();

    let (ct1, ss1) = encapsulate(&keys1.public, &mut thread_rng()).unwrap();
    let (ct2, ss2) = encapsulate(&keys2.public, &mut thread_rng()).unwrap();

    let ss1_dec = decapsulate(&ct1, &keys1.secret).unwrap();
    let ss2_dec = decapsulate(&ct2, &keys2.secret).unwrap();

    assert_eq!(ss1, ss1_dec);
    assert_eq!(ss2, ss2_dec);
    assert_ne!(ss1, ss2);
}

#[test]
fn test_wrong_secret_key_fails() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let wrong_keys = keypair(&mut thread_rng()).unwrap();

    let (ct, ss) = encapsulate(&keys.public, &mut thread_rng()).unwrap();
    let ss_wrong = decapsulate(&ct, &wrong_keys.secret).unwrap();

    assert_ne!(ss, ss_wrong);
}

#[test]
fn test_keypair_struct() {
    let keys = keypair(&mut thread_rng()).unwrap();
    assert_eq!(keys.public.len(), KYBER_PUBLICKEYBYTES);
    assert_eq!(keys.secret.len(), KYBER_SECRETKEYBYTES);
}

#[test]
fn test_keypair_generate_method() {
    let keys = Keypair::generate(&mut thread_rng()).unwrap();
    assert_eq!(keys.public.len(), KYBER_PUBLICKEYBYTES);
    assert_eq!(keys.secret.len(), KYBER_SECRETKEYBYTES);
}

#[test]
fn test_derive_keypair() {
    let seed = [0u8; 64];
    let result = derive(&seed);
    assert!(result.is_ok());
    let keys = result.unwrap();
    assert_eq!(keys.public.len(), KYBER_PUBLICKEYBYTES);
    assert_eq!(keys.secret.len(), KYBER_SECRETKEYBYTES);
}

#[test]
fn test_derive_invalid_seed_length() {
    let seed = [0u8; 32];
    let result = derive(&seed);
    assert!(result.is_err());
}

#[test]
fn test_public_key_extraction() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let extracted_pub = public(&keys.secret);
    assert_eq!(extracted_pub.len(), KYBER_INDCPA_PUBLICKEYBYTES);
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
fn test_empty_secret_key() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let (ct, _) = encapsulate(&keys.public, &mut thread_rng()).unwrap();
    let result = decapsulate(&ct, &[]);
    assert!(result.is_err());
}

#[test]
fn test_multiple_encapsulations_same_pk() {
    let keys = keypair(&mut thread_rng()).unwrap();

    let mut ciphertexts = Vec::new();
    let mut secrets = Vec::new();

    for _ in 0..5 {
        let (ct, ss) = encapsulate(&keys.public, &mut thread_rng()).unwrap();
        ciphertexts.push(ct);
        secrets.push(ss);
    }

    let mut all_different = false;
    for i in 0..ciphertexts.len() {
        for j in 0..i {
            if ciphertexts[i] != ciphertexts[j] {
                all_different = true;
            }
        }
    }
    assert!(all_different);

    for (ct, ss) in ciphertexts.iter().zip(secrets.iter()) {
        let decapsulated = decapsulate(ct, &keys.secret).unwrap();
        assert_eq!(*ss, decapsulated);
    }
}

#[test]
fn test_deterministic_decapsulation() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let (ct, _) = encapsulate(&keys.public, &mut thread_rng()).unwrap();

    let ss1 = decapsulate(&ct, &keys.secret).unwrap();
    let ss2 = decapsulate(&ct, &keys.secret).unwrap();
    let ss3 = decapsulate(&ct, &keys.secret).unwrap();

    assert_eq!(ss1, ss2);
    assert_eq!(ss2, ss3);
}

#[test]
fn test_all_zero_keypair() {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).unwrap();

    assert!(keys.public.iter().any(|&x| x != 0));
    assert!(keys.secret.iter().any(|&x| x != 0));
}

#[test]
fn test_shared_secret_all_zeros() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let (ct, ss) = encapsulate(&keys.public, &mut thread_rng()).unwrap();

    assert!(ss.iter().any(|&x| x != 0));

    let ss2 = decapsulate(&ct, &keys.secret).unwrap();
    assert!(ss2.iter().any(|&x| x != 0));
}

#[test]
fn test_boundary_public_key_length() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let mut short_pk = keys.public.to_vec();
    short_pk.pop();

    let result = encapsulate(&short_pk, &mut thread_rng());
    assert!(result.is_err());
}

#[test]
fn test_boundary_secret_key_length() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let (ct, _) = encapsulate(&keys.public, &mut thread_rng()).unwrap();

    let mut short_sk = keys.secret.to_vec();
    short_sk.pop();

    let result = decapsulate(&ct, &short_sk);
    assert!(result.is_err());
}

#[test]
fn test_boundary_ciphertext_length() {
    let keys = keypair(&mut thread_rng()).unwrap();
    let short_ct = vec![0u8; KYBER_CIPHERTEXTBYTES - 1];

    let result = decapsulate(&short_ct, &keys.secret);
    assert!(result.is_err());
}
