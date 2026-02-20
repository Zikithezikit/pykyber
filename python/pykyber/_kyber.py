"""Kyber post-quantum key encapsulation."""

from dataclasses import dataclass
from typing import Tuple, Callable


@dataclass(frozen=True)
class EncapsulationResult:
    """Result of a Kyber encapsulation."""

    ciphertext: bytes
    shared_secret: bytes

    def __repr__(self) -> str:
        return (
            f"EncapsulationResult("
            f"ciphertext={len(self.ciphertext)} bytes, "
            f"shared_secret={len(self.shared_secret)} bytes)"
        )


@dataclass
class Keypair:
    """Keypair containing private key material with decapsulate method."""
    _secret_key: bytes
    _public_key: bytes
    _encapsulate_fn: Callable[[bytes], Tuple[bytes, bytes]]
    _decapsulate_fn: Callable[[bytes, bytes], bytes]

    def encapsulate(self) -> EncapsulationResult:
        """Encapsulate a shared secret using the public key."""
        return EncapsulationResult(*self._encapsulate_fn(self._public_key))


    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext."""
        return self._decapsulate_fn(ciphertext, self._secret_key)
    
    @property
    def secret_key(self) -> bytes:
        """Return the raw secret key bytes."""
        return self._secret_key
    
    @property
    def public_key(self) -> bytes:
        """Return the raw public key bytes."""
        return self._public_key
    
    def __repr__(self) -> str:
        return f"Keypair(secret_key={len(self._secret_key)} bytes, public_key={len(self._public_key)} bytes)"


class Kyber512:
    """Kyber-512 key encapsulation (security ~AES-128)."""
    
    PUBLIC_KEY_SIZE = 800
    SECRET_KEY_SIZE = 1632
    CIPHERTEXT_SIZE = 768
    SHARED_SECRET_SIZE = 32
    
    def __new__(cls) -> Keypair:
        """Generate a new key pair."""
        from . import _pykyber
        pk, sk = _pykyber._keypair_512()
        return Keypair(sk, pk, _pykyber._encapsulate_512, _pykyber._decapsulate_512)


class Kyber768:
    """Kyber-768 key encapsulation (security ~AES-192)."""
    
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32
    
    def __new__(cls) -> Keypair:
        """Generate a new key pair."""
        from . import _pykyber
        pk, sk = _pykyber._keypair_768()
        return Keypair(sk, pk, _pykyber._encapsulate_768, _pykyber._decapsulate_768)


class Kyber1024:
    """Kyber-1024 key encapsulation (security ~AES-256)."""
    
    PUBLIC_KEY_SIZE = 1568
    SECRET_KEY_SIZE = 3168
    CIPHERTEXT_SIZE = 1568
    SHARED_SECRET_SIZE = 32
    
    def __new__(cls) -> Keypair:
        """Generate a new key pair."""
        from . import _pykyber
        pk, sk = _pykyber._keypair_1024()
        return Keypair(sk, pk, _pykyber._encapsulate_1024, _pykyber._decapsulate_1024)
