pub mod kyber;

use kyber::{
    crypto_kem_dec_1024, crypto_kem_dec_512, crypto_kem_enc_1024, crypto_kem_enc_512,
    crypto_kem_keypair_1024, crypto_kem_keypair_512, decapsulate, encapsulate, error::KyberError,
    keypair, KYBER_1024_CIPHERTEXTBYTES, KYBER_1024_PUBLICKEYBYTES, KYBER_1024_SECRETKEYBYTES,
    KYBER_512_CIPHERTEXTBYTES, KYBER_512_PUBLICKEYBYTES, KYBER_512_SECRETKEYBYTES,
};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use rand::thread_rng;

fn make_kyber_error(msg: &str) -> PyErr {
    PyException::new_err(msg.to_string())
}

#[pyfunction]
fn generate_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    keypair(&mut rng)
        .map(|keys| (keys.public.to_vec(), keys.secret.to_vec()))
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn encapsulate_key(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    encapsulate(pk, &mut rng)
        .map(|(ct, ss)| (ct.to_vec(), ss.to_vec()))
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn decapsulate_key(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
    decapsulate(ct, sk)
        .map(|ss| ss.to_vec())
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn generate_keypair_512() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    let mut pk = vec![0u8; KYBER_512_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_512_SECRETKEYBYTES];
    crypto_kem_keypair_512(&mut pk, &mut sk, &mut rng, None)
        .map(|_| (pk, sk))
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn generate_keypair_1024() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    let mut pk = vec![0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut sk = vec![0u8; KYBER_1024_SECRETKEYBYTES];
    crypto_kem_keypair_1024(&mut pk, &mut sk, &mut rng, None)
        .map(|_| (pk, sk))
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn encapsulate_key_512(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if pk.len() != KYBER_512_PUBLICKEYBYTES {
        return Err(make_kyber_error(
            &KyberError::invalid_input("pk", KYBER_512_PUBLICKEYBYTES, pk.len()).to_string(),
        ));
    }
    let mut rng = thread_rng();
    let mut ct = vec![0u8; KYBER_512_CIPHERTEXTBYTES];
    let mut ss = vec![0u8; 32];
    crypto_kem_enc_512(&mut ct, &mut ss, pk, &mut rng, None)
        .map(|_| (ct, ss))
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn encapsulate_key_1024(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if pk.len() != KYBER_1024_PUBLICKEYBYTES {
        return Err(make_kyber_error(
            &KyberError::invalid_input("pk", KYBER_1024_PUBLICKEYBYTES, pk.len()).to_string(),
        ));
    }
    let mut rng = thread_rng();
    let mut ct = vec![0u8; KYBER_1024_CIPHERTEXTBYTES];
    let mut ss = vec![0u8; 32];
    crypto_kem_enc_1024(&mut ct, &mut ss, pk, &mut rng, None)
        .map(|_| (ct, ss))
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn decapsulate_key_512(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
    if ct.len() != KYBER_512_CIPHERTEXTBYTES {
        return Err(make_kyber_error(
            &KyberError::invalid_input("ct", KYBER_512_CIPHERTEXTBYTES, ct.len()).to_string(),
        ));
    }
    if sk.len() != KYBER_512_SECRETKEYBYTES {
        return Err(make_kyber_error(
            &KyberError::invalid_input("sk", KYBER_512_SECRETKEYBYTES, sk.len()).to_string(),
        ));
    }
    let mut ss = vec![0u8; 32];
    crypto_kem_dec_512(&mut ss, ct, sk)
        .map(|_| ss)
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn decapsulate_key_1024(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
    if ct.len() != KYBER_1024_CIPHERTEXTBYTES {
        return Err(make_kyber_error(
            &KyberError::invalid_input("ct", KYBER_1024_CIPHERTEXTBYTES, ct.len()).to_string(),
        ));
    }
    if sk.len() != KYBER_1024_SECRETKEYBYTES {
        return Err(make_kyber_error(
            &KyberError::invalid_input("sk", KYBER_1024_SECRETKEYBYTES, sk.len()).to_string(),
        ));
    }
    let mut ss = vec![0u8; 32];
    crypto_kem_dec_1024(&mut ss, ct, sk)
        .map(|_| ss)
        .map_err(|e| make_kyber_error(&e.to_string()))
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
