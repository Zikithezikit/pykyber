//! ML-KEM (FIPS 203) core, work in progress.
//!
//! Round-3 Kyber and ML-KEM differ in `G(d || k)`, the missing `H(m)` and the
//! missing `H(c)` in the KDF, so the KEM layer is separate code. The
//! primitives below it are shared with `crate::kyber` where verified.

pub mod params;
pub mod polyvec;
