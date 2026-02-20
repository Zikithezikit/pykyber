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
