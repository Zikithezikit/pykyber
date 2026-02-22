#[derive(Debug, PartialEq)]
pub enum KyberError {
    InvalidInput {
        param: &'static str,
        expected: usize,
        actual: usize,
    },
    Decapsulation,
    RandomBytesGeneration,
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
        }
    }
}

impl std::error::Error for KyberError {}
