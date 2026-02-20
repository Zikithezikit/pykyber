pub mod kyber;

use pyo3::prelude::*;
use kyber::{keypair, encapsulate, decapsulate};
use rand::thread_rng;

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

#[pyfunction]
fn decapsulate_key(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
    match decapsulate(ct, sk) {
        Ok(ss) => Ok(ss.to_vec()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}

#[pymodule]
mod _pykyber {
    use pyo3::prelude::*;

    #[pyfunction]
    pub fn generate_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::generate_keypair()
    }

    #[pyfunction]
    pub fn encapsulate(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::encapsulate_key(pk)
    }

    #[pyfunction]
    pub fn decapsulate(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
        super::decapsulate_key(ct, sk)
    }

    #[pyfunction]
    pub fn keypair_512() -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::generate_keypair()
    }

    #[pyfunction]
    pub fn keypair_768() -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::generate_keypair()
    }

    #[pyfunction]
    pub fn keypair_1024() -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::generate_keypair()
    }

    #[pyfunction]
    pub fn encapsulate_512(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::encapsulate_key(pk)
    }

    #[pyfunction]
    pub fn encapsulate_768(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::encapsulate_key(pk)
    }

    #[pyfunction]
    pub fn encapsulate_1024(pk: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        super::encapsulate_key(pk)
    }

    #[pyfunction]
    pub fn decapsulate_512(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
        super::decapsulate_key(ct, sk)
    }

    #[pyfunction]
    pub fn decapsulate_768(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
        super::decapsulate_key(ct, sk)
    }

    #[pyfunction]
    pub fn decapsulate_1024(ct: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
        super::decapsulate_key(ct, sk)
    }
}
