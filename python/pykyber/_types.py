"""Kyber types and data structures."""

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

    def __iter__(self):
        yield self.ciphertext
        yield self.shared_secret


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

    def __iter__(self):
        yield self._public_key
        yield self._secret_key
