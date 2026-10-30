"""Kyber error exception."""


class KyberError(Exception):
    """Kyber error exception - raised when invalid input is provided."""
    pass


# The classes below are what the Rust bindings raise for ML-KEM; the Rust side
# looks them up by name in this module (src/pymlkem.rs, `error_class`).


class InvalidInputError(KyberError):
    """An argument has the wrong type or length."""


class InvalidEncapsulationKeyError(KyberError):
    """The encapsulation key failed the modulus check of FIPS 203 section 7.2."""


class InvalidDecapsulationKeyError(KyberError):
    """The decapsulation key failed the hash check of FIPS 203 section 7.3."""


class RandomnessError(KyberError):
    """The operating system random generator failed."""


class DecapsulationError(KyberError):
    """Decapsulation failed."""


class AlgorithmMismatchError(KyberError, TypeError):
    """An object of another algorithm or parameter set was passed.

    Kyber and ML-KEM keys, ciphertexts and shared secrets have identical sizes,
    so only the object type can tell them apart.
    """
