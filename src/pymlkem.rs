//! PyO3 glue for ML-KEM: one keygen, encaps and decaps function per parameter
//! set, calling the public functions of `crate::mlkem::kem`. The `acvp`
//! feature and `kem::acvp` are never used here (FIPS 203 section 3.3).
//!
//! Every `KyberError` becomes an instance of a Python subclass of
//! `pykyber.KyberError`, looked up by name in `pykyber._error` when the error
//! is raised. Secrets reach Python as `bytes` built straight from the Rust
//! slice, so the only copy besides the zeroized Rust one is the Python object,
//! which cannot be wiped.

use crate::kyber::error::KyberError;
use crate::kyber::params::KYBER_SYMBYTES;
use crate::mlkem::kem;
use crate::mlkem::params::{MlKem1024, MlKem512, MlKem768};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Python module that defines the exception classes.
const ERROR_MODULE: &str = "pykyber._error";
/// The seed is `d || z`, 32 bytes each (FIPS 203 Algorithm 19, steps 1-2).
const SEED_BYTES: usize = 2 * KYBER_SYMBYTES;

/// Name of the `KyberError` subclass in `ERROR_MODULE` for `error`.
fn error_class(error: &KyberError) -> &'static str {
    match error {
        KyberError::InvalidInput { .. } => "InvalidInputError",
        KyberError::Decapsulation => "DecapsulationError",
        KyberError::RandomBytesGeneration => "RandomnessError",
        KyberError::InvalidEncapsulationKey => "InvalidEncapsulationKeyError",
        KyberError::InvalidDecapsulationKey => "InvalidDecapsulationKeyError",
    }
}

pub(crate) fn to_py_err(py: Python<'_>, error: KyberError) -> PyErr {
    py.import(ERROR_MODULE)
        .and_then(|module| module.getattr(error_class(&error)))
        .and_then(|class| class.call1((error.to_string(),)))
        .map_or_else(|failure| failure, PyErr::from_value)
}

/// Split the 64-byte seed into `(d, z)`.
fn split_seed(seed: &[u8]) -> Result<(&[u8; KYBER_SYMBYTES], &[u8; KYBER_SYMBYTES]), KyberError> {
    let wrong_size = || KyberError::invalid_input("seed", SEED_BYTES, seed.len());
    if seed.len() != SEED_BYTES {
        return Err(wrong_size());
    }
    let (d, z) = seed.split_at(KYBER_SYMBYTES);
    Ok((
        d.try_into().map_err(|_| wrong_size())?,
        z.try_into().map_err(|_| wrong_size())?,
    ))
}

type BytesPair<'py> = (Bound<'py, PyBytes>, Bound<'py, PyBytes>);

/// `(ek, dk)`, from the seed when there is one and from the OS generator otherwise.
fn keygen<'py, const K: usize>(py: Python<'py>, seed: Option<&[u8]>) -> PyResult<BytesPair<'py>> {
    let (ek, dk) = match seed {
        Some(seed) => {
            let (d, z) = split_seed(seed).map_err(|e| to_py_err(py, e))?;
            kem::keygen_from_seed::<K>(d, z)
        }
        None => kem::keygen::<K>().map_err(|e| to_py_err(py, e))?,
    };
    Ok((PyBytes::new(py, &ek), PyBytes::new(py, &dk)))
}

/// `(c, K)`: ciphertext first, like the legacy functions.
fn encaps<'py, const K: usize>(py: Python<'py>, ek: &[u8]) -> PyResult<BytesPair<'py>> {
    let (shared_secret, ciphertext) = kem::encaps::<K>(ek).map_err(|e| to_py_err(py, e))?;
    Ok((
        PyBytes::new(py, &ciphertext),
        PyBytes::new(py, &shared_secret[..]),
    ))
}

fn decaps<'py, const K: usize>(
    py: Python<'py>,
    ciphertext: &[u8],
    dk: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let shared_secret = kem::decaps::<K>(dk, ciphertext).map_err(|e| to_py_err(py, e))?;
    Ok(PyBytes::new(py, &shared_secret[..]))
}

/// The three `#[pyfunction]`s of one parameter set.
macro_rules! parameter_set {
    ($keygen:ident, $encaps:ident, $decaps:ident, $params:ty) => {
        #[pyfunction]
        #[pyo3(signature = (seed=None))]
        pub fn $keygen<'py>(py: Python<'py>, seed: Option<&[u8]>) -> PyResult<BytesPair<'py>> {
            keygen::<{ <$params>::K }>(py, seed)
        }

        #[pyfunction]
        pub fn $encaps<'py>(py: Python<'py>, ek: &[u8]) -> PyResult<BytesPair<'py>> {
            encaps::<{ <$params>::K }>(py, ek)
        }

        #[pyfunction]
        pub fn $decaps<'py>(
            py: Python<'py>,
            ciphertext: &[u8],
            dk: &[u8],
        ) -> PyResult<Bound<'py, PyBytes>> {
            decaps::<{ <$params>::K }>(py, ciphertext, dk)
        }
    };
}

parameter_set!(
    _mlkem_512_keygen,
    _mlkem_512_encaps,
    _mlkem_512_decaps,
    MlKem512
);
parameter_set!(
    _mlkem_768_keygen,
    _mlkem_768_encaps,
    _mlkem_768_decaps,
    MlKem768
);
parameter_set!(
    _mlkem_1024_keygen,
    _mlkem_1024_encaps,
    _mlkem_1024_decaps,
    MlKem1024
);
