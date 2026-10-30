pub mod kyber;
pub(crate) mod mlkem;
mod pymlkem;

use kyber::{
    crypto_kem_dec_1024, crypto_kem_dec_512, crypto_kem_enc_1024, crypto_kem_enc_512,
    crypto_kem_keypair_1024, crypto_kem_keypair_512, decapsulate, encapsulate, error::KyberError,
    keypair, KYBER_1024_CIPHERTEXTBYTES, KYBER_1024_PUBLICKEYBYTES, KYBER_1024_SECRETKEYBYTES,
    KYBER_512_CIPHERTEXTBYTES, KYBER_512_PUBLICKEYBYTES, KYBER_512_SECRETKEYBYTES,
};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

fn make_kyber_error(msg: &str) -> PyErr {
    PyException::new_err(msg.to_string())
}

/// Secret bytes (a secret key or a shared secret) on their way to Python. The
/// Python `bytes` object is built from a copy, and this Rust buffer is wiped
/// when it is dropped right after, instead of being freed with the secret in it.
/// The Python object itself cannot be wiped.
struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(Zeroizing::new(bytes))
    }

    /// Copies a fixed-size secret and wipes the original.
    fn from_array<const N: usize>(mut bytes: [u8; N]) -> Self {
        let copy = SecretBytes::new(bytes.to_vec());
        bytes.zeroize();
        copy
    }
}

impl<'py> IntoPyObject<'py> for SecretBytes {
    type Target = PyBytes;
    type Output = Bound<'py, PyBytes>;
    type Error = std::convert::Infallible;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(PyBytes::new(py, &self.0))
    }
}

/// A failed OS random generator is raised as `pykyber.RandomnessError` (a
/// `KyberError` subclass), like the ML-KEM functions do. Every other error keeps
/// the plain exception the legacy functions have always raised.
fn legacy_err(error: &KyberError) -> PyErr {
    match error {
        KyberError::RandomBytesGeneration => {
            Python::attach(|py| pymlkem::to_py_err(py, KyberError::RandomBytesGeneration))
        }
        _ => make_kyber_error(&error.to_string()),
    }
}

#[pyfunction]
fn generate_keypair(seed: Option<&[u8]>) -> PyResult<(Vec<u8>, SecretBytes)> {
    if let Some(s) = seed {
        if s.len() != 64 {
            return Err(make_kyber_error("Seed must be 64 bytes"));
        }
        kyber::derive(s)
            .map(|keys| (keys.public.to_vec(), SecretBytes::new(keys.secret.to_vec())))
            .map_err(|e| legacy_err(&e))
    } else {
        let mut rng = OsRng;
        keypair(&mut rng)
            .map(|keys| (keys.public.to_vec(), SecretBytes::new(keys.secret.to_vec())))
            .map_err(|e| legacy_err(&e))
    }
}

#[pyfunction]
fn generate_keypair_512(seed: Option<&[u8]>) -> PyResult<(Vec<u8>, SecretBytes)> {
    let mut rng = OsRng;
    let mut pk = vec![0u8; KYBER_512_PUBLICKEYBYTES];
    let mut sk = Zeroizing::new(vec![0u8; KYBER_512_SECRETKEYBYTES]);
    let s_opt = if let Some(s) = seed {
        if s.len() != 64 {
            return Err(make_kyber_error("Seed must be 64 bytes"));
        }
        Some((&s[..32], &s[32..]))
    } else {
        None
    };
    crypto_kem_keypair_512(&mut pk, &mut sk, &mut rng, s_opt)
        .map(|_| (pk, SecretBytes(sk)))
        .map_err(|e| legacy_err(&e))
}

#[pyfunction]
fn generate_keypair_1024(seed: Option<&[u8]>) -> PyResult<(Vec<u8>, SecretBytes)> {
    let mut rng = OsRng;
    let mut pk = vec![0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut sk = Zeroizing::new(vec![0u8; KYBER_1024_SECRETKEYBYTES]);
    let s_opt = if let Some(s) = seed {
        if s.len() != 64 {
            return Err(make_kyber_error("Seed must be 64 bytes"));
        }
        Some((&s[..32], &s[32..]))
    } else {
        None
    };
    crypto_kem_keypair_1024(&mut pk, &mut sk, &mut rng, s_opt)
        .map(|_| (pk, SecretBytes(sk)))
        .map_err(|e| legacy_err(&e))
}

#[pyfunction]
fn encapsulate_key(pk: &[u8]) -> PyResult<(Vec<u8>, SecretBytes)> {
    let mut rng = OsRng;
    encapsulate(pk, &mut rng)
        .map(|(ct, ss)| (ct.to_vec(), SecretBytes::from_array(ss)))
        .map_err(|e| legacy_err(&e))
}

#[pyfunction]
fn decapsulate_key(ct: &[u8], sk: &[u8]) -> PyResult<SecretBytes> {
    decapsulate(ct, sk)
        .map(SecretBytes::from_array)
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn encapsulate_key_512(pk: &[u8]) -> PyResult<(Vec<u8>, SecretBytes)> {
    if pk.len() != KYBER_512_PUBLICKEYBYTES {
        return Err(make_kyber_error(
            &KyberError::invalid_input("pk", KYBER_512_PUBLICKEYBYTES, pk.len()).to_string(),
        ));
    }
    let mut rng = OsRng;
    let mut ct = vec![0u8; KYBER_512_CIPHERTEXTBYTES];
    let mut ss = Zeroizing::new(vec![0u8; 32]);
    crypto_kem_enc_512(&mut ct, &mut ss, pk, &mut rng, None)
        .map(|_| (ct, SecretBytes(ss)))
        .map_err(|e| legacy_err(&e))
}

#[pyfunction]
fn encapsulate_key_1024(pk: &[u8]) -> PyResult<(Vec<u8>, SecretBytes)> {
    if pk.len() != KYBER_1024_PUBLICKEYBYTES {
        return Err(make_kyber_error(
            &KyberError::invalid_input("pk", KYBER_1024_PUBLICKEYBYTES, pk.len()).to_string(),
        ));
    }
    let mut rng = OsRng;
    let mut ct = vec![0u8; KYBER_1024_CIPHERTEXTBYTES];
    let mut ss = Zeroizing::new(vec![0u8; 32]);
    crypto_kem_enc_1024(&mut ct, &mut ss, pk, &mut rng, None)
        .map(|_| (ct, SecretBytes(ss)))
        .map_err(|e| legacy_err(&e))
}

#[pyfunction]
fn decapsulate_key_512(ct: &[u8], sk: &[u8]) -> PyResult<SecretBytes> {
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
    let mut ss = Zeroizing::new(vec![0u8; 32]);
    crypto_kem_dec_512(&mut ss, ct, sk)
        .map(|_| SecretBytes(ss))
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pyfunction]
fn decapsulate_key_1024(ct: &[u8], sk: &[u8]) -> PyResult<SecretBytes> {
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
    let mut ss = Zeroizing::new(vec![0u8; 32]);
    crypto_kem_dec_1024(&mut ss, ct, sk)
        .map(|_| SecretBytes(ss))
        .map_err(|e| make_kyber_error(&e.to_string()))
}

#[pymodule]
mod _pykyber {
    use pyo3::prelude::*;

    #[pymodule_export]
    use super::pymlkem::{
        _mlkem_1024_decaps, _mlkem_1024_encaps, _mlkem_1024_keygen, _mlkem_512_decaps,
        _mlkem_512_encaps, _mlkem_512_keygen, _mlkem_768_decaps, _mlkem_768_encaps,
        _mlkem_768_keygen,
    };

    #[pyfunction]
    pub fn _generate_keypair(seed: Option<&[u8]>) -> PyResult<(Vec<u8>, super::SecretBytes)> {
        super::generate_keypair(seed)
    }

    #[pyfunction]
    pub fn _encapsulate(pk: &[u8]) -> PyResult<(Vec<u8>, super::SecretBytes)> {
        super::encapsulate_key(pk)
    }

    #[pyfunction]
    pub fn _decapsulate(ct: &[u8], sk: &[u8]) -> PyResult<super::SecretBytes> {
        super::decapsulate_key(ct, sk)
    }

    #[pyfunction]
    pub fn _keypair_512(seed: Option<&[u8]>) -> PyResult<(Vec<u8>, super::SecretBytes)> {
        super::generate_keypair_512(seed)
    }

    #[pyfunction]
    pub fn _keypair_768(seed: Option<&[u8]>) -> PyResult<(Vec<u8>, super::SecretBytes)> {
        super::generate_keypair(seed)
    }

    #[pyfunction]
    pub fn _keypair_1024(seed: Option<&[u8]>) -> PyResult<(Vec<u8>, super::SecretBytes)> {
        super::generate_keypair_1024(seed)
    }

    #[pyfunction]
    pub fn _encapsulate_512(pk: &[u8]) -> PyResult<(Vec<u8>, super::SecretBytes)> {
        super::encapsulate_key_512(pk)
    }

    #[pyfunction]
    pub fn _encapsulate_768(pk: &[u8]) -> PyResult<(Vec<u8>, super::SecretBytes)> {
        super::encapsulate_key(pk)
    }

    #[pyfunction]
    pub fn _encapsulate_1024(pk: &[u8]) -> PyResult<(Vec<u8>, super::SecretBytes)> {
        super::encapsulate_key_1024(pk)
    }

    #[pyfunction]
    pub fn _decapsulate_512(ct: &[u8], sk: &[u8]) -> PyResult<super::SecretBytes> {
        super::decapsulate_key_512(ct, sk)
    }

    #[pyfunction]
    pub fn _decapsulate_768(ct: &[u8], sk: &[u8]) -> PyResult<super::SecretBytes> {
        super::decapsulate_key(ct, sk)
    }

    #[pyfunction]
    pub fn _decapsulate_1024(ct: &[u8], sk: &[u8]) -> PyResult<super::SecretBytes> {
        super::decapsulate_key_1024(ct, sk)
    }
}
