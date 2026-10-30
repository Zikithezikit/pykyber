"""Kyber post-quantum key encapsulation."""

from typing import Optional
from ._deprecation import _deprecated_kyber
from ._error import KyberError
from ._types import EncapsulationResult, Keypair
from ._validation import (
    _validate_decapsulate,
    _validate_encapsulate,
    _validate_key_binding,
    _validate_keypair,
    _validate_pk,
)

# Bytes of one serialized polynomial (ByteEncode12 of 256 coefficients).
_POLY_BYTES = 384
# Module rank k: the IND-CPA secret key s of a round-3 Kyber secret key is k polynomials.
_K_512, _K_768, _K_1024 = 2, 3, 4


class Kyber512:
    """Kyber-512 key encapsulation (security ~AES-128)."""
    
    PUBLIC_KEY_SIZE = 800
    SECRET_KEY_SIZE = 1632
    CIPHERTEXT_SIZE = 768
    SHARED_SECRET_SIZE = 32
    
    @_deprecated_kyber
    def __new__(cls, seed: Optional[bytes] = None) -> Keypair:
        """Generate a new key pair, optionally from a 64-byte seed."""
        from . import _pykyber
        pk, sk = _validate_keypair(_pykyber._keypair_512)(seed)
        return Keypair(sk, pk, 
                       _validate_encapsulate(_pykyber._encapsulate_512, Kyber512.PUBLIC_KEY_SIZE, "Kyber512"),
                       _validate_decapsulate(_pykyber._decapsulate_512, Kyber512.CIPHERTEXT_SIZE, "Kyber512"))
    
    @staticmethod
    @_deprecated_kyber
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        """Encapsulate a shared secret using a public key (no keypair needed)."""
        from . import _pykyber
        return EncapsulationResult(*_validate_encapsulate(_pykyber._encapsulate_512, Kyber512.PUBLIC_KEY_SIZE, "Kyber512.encapsulate")(public_key))
    
    @staticmethod
    @_deprecated_kyber
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext and secret key (no keypair needed)."""
        from . import _pykyber
        return _validate_decapsulate(_pykyber._decapsulate_512, Kyber512.CIPHERTEXT_SIZE, "Kyber512.decapsulate")(ciphertext, secret_key)

    @classmethod
    @_deprecated_kyber
    def from_keys(cls, public_key: bytes, secret_key: bytes) -> Keypair:
        """Create a Keypair object from existing public and secret keys.

        Raises KyberError if the public key is not the one stored inside the secret key.
        """
        from . import _pykyber
        _validate_pk(public_key, cls.PUBLIC_KEY_SIZE, f"{cls.__name__}.from_keys")
        _validate_key_binding(public_key, secret_key, cls.SECRET_KEY_SIZE, _K_512 * _POLY_BYTES, f"{cls.__name__}.from_keys")
        return Keypair(secret_key, public_key, 
                       _validate_encapsulate(_pykyber._encapsulate_512, cls.PUBLIC_KEY_SIZE, cls.__name__),
                       _validate_decapsulate(_pykyber._decapsulate_512, cls.CIPHERTEXT_SIZE, cls.__name__))


class Kyber768:
    """Kyber-768 key encapsulation (security ~AES-192)."""
    
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32
    
    @_deprecated_kyber
    def __new__(cls, seed: Optional[bytes] = None) -> Keypair:
        """Generate a new key pair, optionally from a 64-byte seed."""
        from . import _pykyber
        pk, sk = _validate_keypair(_pykyber._keypair_768)(seed)
        return Keypair(sk, pk, 
                       _validate_encapsulate(_pykyber._encapsulate_768, Kyber768.PUBLIC_KEY_SIZE, "Kyber768"),
                       _validate_decapsulate(_pykyber._decapsulate_768, Kyber768.CIPHERTEXT_SIZE, "Kyber768"))
    
    @staticmethod
    @_deprecated_kyber
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        """Encapsulate a shared secret using a public key (no keypair needed)."""
        from . import _pykyber
        return EncapsulationResult(*_validate_encapsulate(_pykyber._encapsulate_768, Kyber768.PUBLIC_KEY_SIZE, "Kyber768.encapsulate")(public_key))
    
    @staticmethod
    @_deprecated_kyber
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext and secret key (no keypair needed)."""
        from . import _pykyber
        return _validate_decapsulate(_pykyber._decapsulate_768, Kyber768.CIPHERTEXT_SIZE, "Kyber768.decapsulate")(ciphertext, secret_key)

    @classmethod
    @_deprecated_kyber
    def from_keys(cls, public_key: bytes, secret_key: bytes) -> Keypair:
        """Create a Keypair object from existing public and secret keys.

        Raises KyberError if the public key is not the one stored inside the secret key.
        """
        from . import _pykyber
        _validate_pk(public_key, cls.PUBLIC_KEY_SIZE, f"{cls.__name__}.from_keys")
        _validate_key_binding(public_key, secret_key, cls.SECRET_KEY_SIZE, _K_768 * _POLY_BYTES, f"{cls.__name__}.from_keys")
        return Keypair(secret_key, public_key, 
                       _validate_encapsulate(_pykyber._encapsulate_768, cls.PUBLIC_KEY_SIZE, cls.__name__),
                       _validate_decapsulate(_pykyber._decapsulate_768, cls.CIPHERTEXT_SIZE, cls.__name__))


class Kyber1024:
    """Kyber-1024 key encapsulation (security ~AES-256)."""
    
    PUBLIC_KEY_SIZE = 1568
    SECRET_KEY_SIZE = 3168
    CIPHERTEXT_SIZE = 1568
    SHARED_SECRET_SIZE = 32
    
    @_deprecated_kyber
    def __new__(cls, seed: Optional[bytes] = None) -> Keypair:
        """Generate a new key pair, optionally from a 64-byte seed."""
        from . import _pykyber
        pk, sk = _validate_keypair(_pykyber._keypair_1024)(seed)
        return Keypair(sk, pk, 
                       _validate_encapsulate(_pykyber._encapsulate_1024, Kyber1024.PUBLIC_KEY_SIZE, "Kyber1024"),
                       _validate_decapsulate(_pykyber._decapsulate_1024, Kyber1024.CIPHERTEXT_SIZE, "Kyber1024"))
    
    @staticmethod
    @_deprecated_kyber
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        """Encapsulate a shared secret using a public key (no keypair needed)."""
        from . import _pykyber
        return EncapsulationResult(*_validate_encapsulate(_pykyber._encapsulate_1024, Kyber1024.PUBLIC_KEY_SIZE, "Kyber1024.encapsulate")(public_key))
    
    @staticmethod
    @_deprecated_kyber
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext and secret key (no keypair needed)."""
        from . import _pykyber
        return _validate_decapsulate(_pykyber._decapsulate_1024, Kyber1024.CIPHERTEXT_SIZE, "Kyber1024.decapsulate")(ciphertext, secret_key)

    @classmethod
    @_deprecated_kyber
    def from_keys(cls, public_key: bytes, secret_key: bytes) -> Keypair:
        """Create a Keypair object from existing public and secret keys.

        Raises KyberError if the public key is not the one stored inside the secret key.
        """
        from . import _pykyber
        _validate_pk(public_key, cls.PUBLIC_KEY_SIZE, f"{cls.__name__}.from_keys")
        _validate_key_binding(public_key, secret_key, cls.SECRET_KEY_SIZE, _K_1024 * _POLY_BYTES, f"{cls.__name__}.from_keys")
        return Keypair(secret_key, public_key, 
                       _validate_encapsulate(_pykyber._encapsulate_1024, cls.PUBLIC_KEY_SIZE, cls.__name__),
                       _validate_decapsulate(_pykyber._decapsulate_1024, cls.CIPHERTEXT_SIZE, cls.__name__))

