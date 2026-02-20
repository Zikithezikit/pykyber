pub mod kyber;

use kyber::{
    crypto_kem_dec_1024, crypto_kem_dec_512, crypto_kem_enc_1024, crypto_kem_enc_512,
    crypto_kem_keypair_1024, crypto_kem_keypair_512, decapsulate, encapsulate, keypair,
    KYBER_1024_CIPHERTEXTBYTES, KYBER_1024_PUBLICKEYBYTES, KYBER_1024_SECRETKEYBYTES,
    KYBER_512_CIPHERTEXTBYTES, KYBER_512_PUBLICKEYBYTES, KYBER_512_SECRETKEYBYTES,
};
use pyo3::prelude::*;
use rand::thread_rng;

/// Generate a Kyber-768 keypair.
/// Returns (public_key, secret_key).
#[pyfunction]
fn generate_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    match keypair(&mut rng) {
        Ok(keys) => Ok((keys.public.to_vec(), keys.secret.to_vec())),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

/// Encapsulate a shared secret using a public key.
/// Args:
///     pk: public key bytes
/// Returns (ciphertext, shared_secret).
#[pyfunction]
fn encapsulate_key(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    match encapsulate(pk, &mut rng) {
        Ok((ct, ss)) => Ok((ct.to_vec(), ss.to_vec())),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

/// Decapsulate a shared secret using a ciphertext and secret key.
/// Args:
///     ct: ciphertext bytes
///     sk: secret key bytes
/// Returns shared_secret bytes.
#[pyfunction]
fn decapsulate_key(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
    match decapsulate(ct, sk) {
        Ok(ss) => Ok(ss.to_vec()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

/// Generate a Kyber-512 keypair.
/// Returns (public_key, secret_key).
#[pyfunction]
fn generate_keypair_512() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    let mut pk = vec![0u8; KYBER_512_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_512_SECRETKEYBYTES];
    match crypto_kem_keypair_512(&mut pk, &mut sk, &mut rng, None) {
        Ok(()) => Ok((pk, sk)),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

/// Generate a Kyber-1024 keypair.
/// Returns (public_key, secret_key).
#[pyfunction]
fn generate_keypair_1024() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    let mut pk = vec![0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_1024_SECRETKEYBYTES];
    match crypto_kem_keypair_1024(&mut pk, &mut sk, &mut rng, None) {
        Ok(()) => Ok((pk, sk)),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

/// Encapsulate a shared secret using a Kyber-512 public key.
#[pyfunction]
fn encapsulate_key_512(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    let mut ct = vec![0u8; KYBER_512_CIPHERTEXTBYTES];
    let mut ss = vec![0u8; 32];
    match crypto_kem_enc_512(&mut ct, &mut ss, pk, &mut rng, None) {
        Ok(()) => Ok((ct, ss)),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

/// Encapsulate a shared secret using a Kyber-1024 public key.
#[pyfunction]
fn encapsulate_key_1024(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    let mut ct = vec![0u8; KYBER_1024_CIPHERTEXTBYTES];
    let mut ss = vec![0u8; 32];
    match crypto_kem_enc_1024(&mut ct, &mut ss, pk, &mut rng, None) {
        Ok(()) => Ok((ct, ss)),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

/// Decapsulate a shared secret using a Kyber-512 ciphertext and secret key.
#[pyfunction]
fn decapsulate_key_512(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
    let mut ss = vec![0u8; 32];
    crypto_kem_dec_512(&mut ss, ct, sk);
    Ok(ss)
}

/// Decapsulate a shared secret using a Kyber-1024 ciphertext and secret key.
#[pyfunction]
fn decapsulate_key_1024(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
    let mut ss = vec![0u8; 32];
    crypto_kem_dec_1024(&mut ss, ct, sk);
    Ok(ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kyber::api::{derive, public};
    use kyber::params::*;

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
        let keys = kyber::api::keypair(&mut thread_rng()).unwrap();
        assert_eq!(keys.public.len(), KYBER_PUBLICKEYBYTES);
        assert_eq!(keys.secret.len(), KYBER_SECRETKEYBYTES);
    }

    #[test]
    fn test_keypair_generate_method() {
        let keys = kyber::api::Keypair::generate(&mut thread_rng()).unwrap();
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

        // Test multiple encapsulations
        let mut ciphertexts = Vec::new();
        let mut secrets = Vec::new();

        for _ in 0..5 {
            let (ct, ss) = encapsulate(&keys.public, &mut thread_rng()).unwrap();
            ciphertexts.push(ct);
            secrets.push(ss);
        }

        // All ciphertexts should be different (random)
        let mut all_different = false;
        for i in 0..ciphertexts.len() {
            for j in 0..i {
                if ciphertexts[i] != ciphertexts[j] {
                    all_different = true;
                }
            }
        }
        assert!(all_different);

        // But all should decapsulate correctly
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

        // Keys should not be all zeros
        assert!(keys.public.iter().any(|&x| x != 0));
        assert!(keys.secret.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_shared_secret_all_zeros() {
        let keys = keypair(&mut thread_rng()).unwrap();
        let (ct, ss) = encapsulate(&keys.public, &mut thread_rng()).unwrap();

        // Shared secret should not be all zeros
        assert!(ss.iter().any(|&x| x != 0));

        // Decapsulated should also not be all zeros
        let ss2 = decapsulate(&ct, &keys.secret).unwrap();
        assert!(ss2.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_boundary_public_key_length() {
        // Test with public key that's 1 byte too short
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
}

#[pymodule]
mod _pykyber {
    use pyo3::prelude::*;

    #[pyfunction]
    pub fn _generate_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::generate_keypair()
    }

    #[pyfunction]
    pub fn _encapsulate(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::encapsulate_key(pk)
    }

    #[pyfunction]
    pub fn _decapsulate(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
        super::decapsulate_key(ct, sk)
    }

    #[pyfunction]
    pub fn _keypair_512() -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::generate_keypair_512()
    }

    #[pyfunction]
    pub fn _keypair_768() -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::generate_keypair()
    }

    #[pyfunction]
    pub fn _keypair_1024() -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::generate_keypair_1024()
    }

    #[pyfunction]
    pub fn _encapsulate_512(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::encapsulate_key_512(pk)
    }

    #[pyfunction]
    pub fn _encapsulate_768(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::encapsulate_key(pk)
    }

    #[pyfunction]
    pub fn _encapsulate_1024(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::encapsulate_key_1024(pk)
    }

    #[pyfunction]
    pub fn _decapsulate_512(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
        super::decapsulate_key_512(ct, sk)
    }

    #[pyfunction]
    pub fn _decapsulate_768(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
        super::decapsulate_key(ct, sk)
    }

    #[pyfunction]
    pub fn _decapsulate_1024(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
        super::decapsulate_key_1024(ct, sk)
    }
}
