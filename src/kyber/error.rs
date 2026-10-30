#[derive(Debug, PartialEq)]
pub enum KyberError {
    InvalidInput {
        param: &'static str,
        expected: usize,
        actual: usize,
    },
    Decapsulation,
    RandomBytesGeneration,
    /// ML-KEM encapsulation key failed the modulus check of FIPS 203 section 7.2.
    InvalidEncapsulationKey,
    /// ML-KEM decapsulation key failed the hash check of FIPS 203 section 7.3.
    InvalidDecapsulationKey,
}

impl KyberError {
    pub fn invalid_input(param: &'static str, expected: usize, actual: usize) -> Self {
        KyberError::InvalidInput {
            param,
            expected,
            actual,
        }
    }
}

impl core::fmt::Display for KyberError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            KyberError::InvalidInput {
                param,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Invalid input for '{}': expected {} bytes, got {}",
                    param, expected, actual
                )
            }
            KyberError::Decapsulation => write!(
                f,
                "Decapsulation Failure: unable to obtain shared secret from ciphertext"
            ),
            KyberError::RandomBytesGeneration => write!(f, "Random bytes generation failed"),
            KyberError::InvalidEncapsulationKey => write!(
                f,
                "Invalid encapsulation key: coefficients are not reduced modulo q"
            ),
            KyberError::InvalidDecapsulationKey => write!(
                f,
                "Invalid decapsulation key: the stored hash of the encapsulation key does not match"
            ),
        }
    }
}

impl std::error::Error for KyberError {}
