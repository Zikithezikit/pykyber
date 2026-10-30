"""ML-KEM (FIPS 203) key encapsulation: ML_KEM_512, ML_KEM_768 and ML_KEM_1024.

ML-KEM is not round-3 Kyber. The keys have the same sizes, but the algorithms
differ, so the shared secrets, ciphertexts and keys of the two families are
not interchangeable. Raw ``bytes`` cannot be told apart; the Kyber and ML-KEM
objects can, and an ML-KEM method refuses a Kyber object.

Secrets cross from Rust into immutable Python ``bytes`` objects that cannot be
wiped. Rust zeroizes its own copies, but the ``bytes`` you get back (secret
key, shared secret, seed) stay in memory until the interpreter frees them.
"""

from typing import Optional, Union

from . import _pykyber
from ._types import MlKemEncapsulationResult, MlKemKeypair
from ._validation import _validate_ml_kem_bytes, _validate_ml_kem_seed

# FIPS 203 section 2.4 and Table 2.
_N = 256  # coefficients per polynomial
_BITS_PER_BYTE = 8
_POLY_BITS = 12  # ByteEncode12 of the keys
_SEED_HALF_BYTES = 32  # d, z, m, rho, H(ek)
_POLY_BYTES = _N * _POLY_BITS // _BITS_PER_BYTE


def _sizes(k: int, du: int, dv: int) -> tuple:
    """(ek, dk, c) sizes in bytes for the parameters of FIPS 203 Table 2."""
    ek = _POLY_BYTES * k + _SEED_HALF_BYTES  # t-hat || rho
    dk = _POLY_BYTES * k + ek + 2 * _SEED_HALF_BYTES  # dk_PKE || ek || H(ek) || z (Algorithm 16)
    ct = _N * (du * k + dv) // _BITS_PER_BYTE  # c1 || c2 (Algorithm 14)
    return ek, dk, ct


_Key = Union[bytes, MlKemKeypair]


class _MlKem:
    """Shared behaviour of the three parameter sets."""

    ALGORITHM: str
    PUBLIC_KEY_SIZE: int
    SECRET_KEY_SIZE: int
    CIPHERTEXT_SIZE: int
    SHARED_SECRET_SIZE = _SEED_HALF_BYTES
    SEED_SIZE = 2 * _SEED_HALF_BYTES  # d || z

    # The private Rust functions, set per parameter set.
    _keygen: staticmethod
    _encaps: staticmethod
    _decaps: staticmethod

    def __new__(cls, seed: Optional[bytes] = None) -> MlKemKeypair:
        """Generate a new key pair, optionally from a 64-byte seed ``d || z``.

        The seed is secret: it determines the secret key. The keypair has a
        ``seed`` attribute only if it was generated from one.
        """
        seed = _validate_ml_kem_seed(seed, cls.SEED_SIZE, cls.ALGORITHM)
        public_key, secret_key = cls._keygen(seed)
        return MlKemKeypair(cls, public_key, secret_key, seed)

    @classmethod
    def encapsulate(cls, public_key: _Key) -> MlKemEncapsulationResult:
        """Encapsulate a shared secret using a public key (no keypair needed)."""
        method = cls.ALGORITHM + ".encapsulate"
        public_key = _validate_ml_kem_bytes(public_key, "public_key", cls.ALGORITHM, cls.PUBLIC_KEY_SIZE, method)
        ciphertext, shared_secret = cls._encaps(public_key)
        return MlKemEncapsulationResult(cls.ALGORITHM, ciphertext, shared_secret)

    @classmethod
    def decapsulate(cls, ciphertext: Union[bytes, MlKemEncapsulationResult], secret_key: _Key) -> bytes:
        """Decapsulate a shared secret using ciphertext and secret key (no keypair needed).

        A well-formed ciphertext that was not made for this key does not raise:
        it yields a different, pseudorandom secret (implicit rejection).
        """
        method = cls.ALGORITHM + ".decapsulate"
        ciphertext = _validate_ml_kem_bytes(ciphertext, "ciphertext", cls.ALGORITHM, cls.CIPHERTEXT_SIZE, method)
        secret_key = _validate_ml_kem_bytes(secret_key, "secret_key", cls.ALGORITHM, cls.SECRET_KEY_SIZE, method)
        return cls._decaps(ciphertext, secret_key)

    @classmethod
    def from_keys(cls, public_key: _Key, secret_key: _Key) -> MlKemKeypair:
        """Create a Keypair object from existing public and secret keys.

        Only the sizes are checked here; the checks of FIPS 203 sections 7.2
        and 7.3 run when the keys are used.
        """
        method = cls.ALGORITHM + ".from_keys"
        public_key = _validate_ml_kem_bytes(public_key, "public_key", cls.ALGORITHM, cls.PUBLIC_KEY_SIZE, method)
        secret_key = _validate_ml_kem_bytes(secret_key, "secret_key", cls.ALGORITHM, cls.SECRET_KEY_SIZE, method)
        return MlKemKeypair(cls, public_key, secret_key)


class ML_KEM_512(_MlKem):
    """ML-KEM-512 (FIPS 203, security category 1)."""

    ALGORITHM = "ML-KEM-512"
    PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, CIPHERTEXT_SIZE = _sizes(k=2, du=10, dv=4)
    _keygen = staticmethod(_pykyber._mlkem_512_keygen)
    _encaps = staticmethod(_pykyber._mlkem_512_encaps)
    _decaps = staticmethod(_pykyber._mlkem_512_decaps)


class ML_KEM_768(_MlKem):
    """ML-KEM-768 (FIPS 203, security category 3; NIST's recommended default)."""

    ALGORITHM = "ML-KEM-768"
    PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, CIPHERTEXT_SIZE = _sizes(k=3, du=10, dv=4)
    _keygen = staticmethod(_pykyber._mlkem_768_keygen)
    _encaps = staticmethod(_pykyber._mlkem_768_encaps)
    _decaps = staticmethod(_pykyber._mlkem_768_decaps)


class ML_KEM_1024(_MlKem):
    """ML-KEM-1024 (FIPS 203, security category 5)."""

    ALGORITHM = "ML-KEM-1024"
    PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, CIPHERTEXT_SIZE = _sizes(k=4, du=11, dv=5)
    _keygen = staticmethod(_pykyber._mlkem_1024_keygen)
    _encaps = staticmethod(_pykyber._mlkem_1024_encaps)
    _decaps = staticmethod(_pykyber._mlkem_1024_decaps)
