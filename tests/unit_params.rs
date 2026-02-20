//! Unit tests for Kyber parameters

use pykyber::kyber::params::*;

#[test]
fn test_kyber_512_params() {
    assert_eq!(KYBER_512_K, 2);
    assert_eq!(KYBER_512_POLYVECBYTES, 2 * 384);
    assert_eq!(KYBER_512_POLYVECCOMPRESSEDBYTES, 2 * 320);
    assert_eq!(KYBER_512_INDCPA_PUBLICKEYBYTES, 2 * 384 + 32);
    assert_eq!(KYBER_512_PUBLICKEYBYTES, 800);
    assert_eq!(KYBER_512_SECRETKEYBYTES, 2 * 384 + (2 * 384 + 32) + 2 * 32);
    assert_eq!(KYBER_512_CIPHERTEXTBYTES, 2 * 320 + 128);
}

#[test]
fn test_kyber_768_params() {
    assert_eq!(KYBER_768_K, 3);
    assert_eq!(KYBER_768_POLYVECBYTES, 3 * 384);
    assert_eq!(KYBER_768_POLYVECCOMPRESSEDBYTES, 3 * 320);
    assert_eq!(KYBER_768_INDCPA_PUBLICKEYBYTES, 3 * 384 + 32);
    assert_eq!(KYBER_768_PUBLICKEYBYTES, 1184);
    assert_eq!(KYBER_768_SECRETKEYBYTES, 3 * 384 + (3 * 384 + 32) + 2 * 32);
    assert_eq!(KYBER_768_CIPHERTEXTBYTES, 3 * 320 + 128);
}

#[test]
fn test_kyber_1024_params() {
    assert_eq!(KYBER_1024_K, 4);
    assert_eq!(KYBER_1024_POLYVECBYTES, 4 * 384);
    assert_eq!(KYBER_1024_POLYVECCOMPRESSEDBYTES, 4 * 320);
    assert_eq!(KYBER_1024_INDCPA_PUBLICKEYBYTES, 4 * 384 + 32);
    assert_eq!(KYBER_1024_PUBLICKEYBYTES, 1568);
    assert_eq!(KYBER_1024_SECRETKEYBYTES, 4 * 384 + (4 * 384 + 32) + 2 * 32);
    assert_eq!(KYBER_1024_CIPHERTEXTBYTES, 4 * 320 + 128);
}

#[test]
fn test_common_params() {
    assert_eq!(KYBER_N, 256);
    assert_eq!(KYBER_Q, 3329);
    assert_eq!(KYBER_ETA1, 2);
    assert_eq!(KYBER_ETA2, 2);
    assert_eq!(KYBER_SYMBYTES, 32);
    assert_eq!(KYBER_SSBYTES, 32);
    assert_eq!(KYBER_POLYBYTES, 384);
    assert_eq!(KYBER_POLYCOMPRESSEDBYTES, 128);
}

#[test]
fn test_default_kyber_k() {
    assert_eq!(KYBER_K, 3);
    assert_eq!(KYBER_POLYVECBYTES, KYBER_K * KYBER_POLYBYTES);
    assert_eq!(KYBER_PUBLICKEYBYTES, KYBER_INDCPA_PUBLICKEYBYTES);
}
