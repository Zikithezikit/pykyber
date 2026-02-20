#[derive(Debug, PartialEq)]
pub enum KyberError {
    InvalidInput,
    Decapsulation,
    RandomBytesGeneration,
}

impl core::fmt::Display for KyberError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            KyberError::InvalidInput => write!(f, "Function input is of incorrect length"),
            KyberError::Decapsulation => write!(
                f,
                "Decapsulation Failure, unable to obtain shared secret from ciphertext"
            ),
            KyberError::RandomBytesGeneration => {
                write!(f, "Random bytes generation function failed")
            }
        }
    }
}
