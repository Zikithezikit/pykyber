//! ML-KEM parameter sets as one type generic over `k` (FIPS 203 Table 2).
//!
//! `k` fixes every other parameter, so there is a single `ParamSet<K>` and the
//! three standard sets are aliases. Stable Rust cannot use these associated
//! constants in array lengths of generic code, so byte buffers in generic
//! functions are slices or `Vec`s sized from them; only `[Poly; K]` is a
//! plain array.

#[cfg(test)]
use crate::kyber::params::KYBER_SSBYTES;
use crate::kyber::params::{KYBER_N, KYBER_POLYBYTES, KYBER_SYMBYTES};

/// Parameter set selected by `K`. Using `ParamSet<K>` for a `K` outside
/// {2, 3, 4} fails at compile time.
pub struct ParamSet<const K: usize>;

/// ML-KEM-512 (k = 2).
pub type MlKem512 = ParamSet<2>;
/// ML-KEM-768 (k = 3).
pub type MlKem768 = ParamSet<3>;
/// ML-KEM-1024 (k = 4).
pub type MlKem1024 = ParamSet<4>;

/// Bytes of ByteEncode_d for one polynomial: 256 coefficients of `d` bits
/// (FIPS 203 Algorithm 5).
const fn encoded_bytes(d: usize) -> usize {
    KYBER_N * d / u8::BITS as usize
}

/// Bytes PRF_eta must produce for one noise polynomial: 2 * eta bits per
/// coefficient (FIPS 203 Algorithm 8, input of 64 * eta bytes).
pub(crate) const fn prf_bytes(eta: usize) -> usize {
    KYBER_N * 2 * eta / u8::BITS as usize
}

// The parameter values below are FIPS 203 Table 2, one arm per set.
const fn eta1(k: usize) -> usize {
    match k {
        2 => 3,
        3 | 4 => 2,
        _ => panic!("ML-KEM defines k in {{2, 3, 4}}"),
    }
}

const fn du(k: usize) -> usize {
    match k {
        2 | 3 => 10,
        4 => 11,
        _ => panic!("ML-KEM defines k in {{2, 3, 4}}"),
    }
}

const fn dv(k: usize) -> usize {
    match k {
        2 | 3 => 4,
        4 => 5,
        _ => panic!("ML-KEM defines k in {{2, 3, 4}}"),
    }
}

impl<const K: usize> ParamSet<K> {
    /// Number of polynomials in a vector (the `k` of FIPS 203).
    pub const K: usize = {
        // Evaluating the const is what rejects an unsupported `K`.
        let _ = eta1(K);
        K
    };
    /// Noise parameter for s, e and y.
    pub const ETA1: usize = eta1(K);
    /// Noise parameter for e1 and e2.
    pub const ETA2: usize = 2;
    /// Compression bits for the vector u in the ciphertext.
    pub const DU: usize = du(K);
    /// Compression bits for the polynomial v in the ciphertext.
    pub const DV: usize = dv(K);

    /// Encapsulation key: ByteEncode12 of t-hat, then the seed rho.
    pub const EK_BYTES: usize = KYBER_POLYBYTES * K + KYBER_SYMBYTES;
    /// K-PKE decryption key: ByteEncode12 of s-hat.
    pub const DK_PKE_BYTES: usize = KYBER_POLYBYTES * K;
    /// ML-KEM decapsulation key: dk_PKE || ek || H(ek) || z (Algorithm 16);
    /// H(ek) and z are 32 bytes each.
    pub const DK_BYTES: usize = Self::DK_PKE_BYTES + Self::EK_BYTES + 2 * KYBER_SYMBYTES;
    /// Ciphertext: c1 (k polynomials of du bits) || c2 (dv bits).
    pub const CT_BYTES: usize = K * Self::POLY_COMPRESSED_U_BYTES + Self::POLY_COMPRESSED_V_BYTES;
    /// Shared secret. Only the parameter-table test reads it.
    #[cfg(test)]
    pub const SS_BYTES: usize = KYBER_SSBYTES;
    /// Bytes of one compressed polynomial of u.
    pub const POLY_COMPRESSED_U_BYTES: usize = encoded_bytes(Self::DU);
    /// Bytes of the compressed polynomial v.
    pub const POLY_COMPRESSED_V_BYTES: usize = encoded_bytes(Self::DV);
    /// Bytes drawn from the PRF for one eta1 noise polynomial (parameter-table test only).
    #[cfg(test)]
    pub const NOISE1_BYTES: usize = prf_bytes(Self::ETA1);
    /// Bytes drawn from the PRF for one eta2 noise polynomial (parameter-table test only).
    #[cfg(test)]
    pub const NOISE2_BYTES: usize = prf_bytes(Self::ETA2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::params::{
        KYBER_1024_CIPHERTEXTBYTES, KYBER_1024_K, KYBER_1024_PUBLICKEYBYTES,
        KYBER_1024_SECRETKEYBYTES, KYBER_512_CIPHERTEXTBYTES, KYBER_512_K,
        KYBER_512_PUBLICKEYBYTES, KYBER_512_SECRETKEYBYTES, KYBER_768_CIPHERTEXTBYTES, KYBER_768_K,
        KYBER_768_PUBLICKEYBYTES, KYBER_768_SECRETKEYBYTES,
    };

    #[test]
    fn matches_fips_203_table_2() {
        // (k, eta1, eta2, du, dv), FIPS 203 Table 2.
        assert_eq!(
            (
                MlKem512::K,
                MlKem512::ETA1,
                MlKem512::ETA2,
                MlKem512::DU,
                MlKem512::DV
            ),
            (2, 3, 2, 10, 4)
        );
        assert_eq!(
            (
                MlKem768::K,
                MlKem768::ETA1,
                MlKem768::ETA2,
                MlKem768::DU,
                MlKem768::DV
            ),
            (3, 2, 2, 10, 4)
        );
        assert_eq!(
            (
                MlKem1024::K,
                MlKem1024::ETA1,
                MlKem1024::ETA2,
                MlKem1024::DU,
                MlKem1024::DV
            ),
            (4, 2, 2, 11, 5)
        );
    }

    #[test]
    fn sizes_match_fips_203_table_3() {
        // (ek, dk, ciphertext), FIPS 203 Table 3.
        assert_eq!(
            (MlKem512::EK_BYTES, MlKem512::DK_BYTES, MlKem512::CT_BYTES),
            (800, 1632, 768)
        );
        assert_eq!(
            (MlKem768::EK_BYTES, MlKem768::DK_BYTES, MlKem768::CT_BYTES),
            (1184, 2400, 1088)
        );
        assert_eq!(
            (
                MlKem1024::EK_BYTES,
                MlKem1024::DK_BYTES,
                MlKem1024::CT_BYTES
            ),
            (1568, 3168, 1568)
        );
        assert_eq!(MlKem768::SS_BYTES, 32);
    }

    #[test]
    fn sizes_equal_the_legacy_kyber_sizes() {
        // Same sizes as Kyber: the two families cannot be told apart by length.
        assert_eq!(MlKem512::K, KYBER_512_K);
        assert_eq!(MlKem768::K, KYBER_768_K);
        assert_eq!(MlKem1024::K, KYBER_1024_K);
        assert_eq!(MlKem512::EK_BYTES, KYBER_512_PUBLICKEYBYTES);
        assert_eq!(MlKem768::EK_BYTES, KYBER_768_PUBLICKEYBYTES);
        assert_eq!(MlKem1024::EK_BYTES, KYBER_1024_PUBLICKEYBYTES);
        assert_eq!(MlKem512::DK_BYTES, KYBER_512_SECRETKEYBYTES);
        assert_eq!(MlKem768::DK_BYTES, KYBER_768_SECRETKEYBYTES);
        assert_eq!(MlKem1024::DK_BYTES, KYBER_1024_SECRETKEYBYTES);
        assert_eq!(MlKem512::CT_BYTES, KYBER_512_CIPHERTEXTBYTES);
        assert_eq!(MlKem768::CT_BYTES, KYBER_768_CIPHERTEXTBYTES);
        assert_eq!(MlKem1024::CT_BYTES, KYBER_1024_CIPHERTEXTBYTES);
    }

    #[test]
    fn derived_noise_and_compression_sizes() {
        assert_eq!(MlKem512::NOISE1_BYTES, 192);
        assert_eq!(MlKem768::NOISE1_BYTES, 128);
        assert_eq!(MlKem768::NOISE2_BYTES, 128);
        assert_eq!(MlKem768::POLY_COMPRESSED_U_BYTES, 320);
        assert_eq!(MlKem1024::POLY_COMPRESSED_U_BYTES, 352);
        assert_eq!(MlKem768::POLY_COMPRESSED_V_BYTES, 128);
        assert_eq!(MlKem1024::POLY_COMPRESSED_V_BYTES, 160);
    }
}
