"""Kyber types and data structures."""

import base64
from dataclasses import dataclass
from typing import Tuple, Callable, Dict, Any


@dataclass(frozen=True)
class EncapsulationResult:
    """Result of a Kyber encapsulation."""

    ciphertext: bytes
    shared_secret: bytes

    @property
    def ciphertext_hex(self) -> str:
        """Return the ciphertext in hex format."""
        return self.ciphertext.hex()

    @property
    def shared_secret_hex(self) -> str:
        """Return the shared secret in hex format."""
        return self.shared_secret.hex()

    @property
    def ciphertext_b64(self) -> str:
        """Return the ciphertext in base64 format."""
        return base64.b64encode(self.ciphertext).decode("utf-8")

    @property
    def shared_secret_b64(self) -> str:
        """Return the shared secret in base64 format."""
        return base64.b64encode(self.shared_secret).decode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a dictionary."""
        return {
            "ciphertext": self.ciphertext_hex,
            "shared_secret": self.shared_secret_hex,
        }

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

    @property
    def public_key_hex(self) -> str:
        """Return the public key in hex format."""
        return self._public_key.hex()

    @property
    def secret_key_hex(self) -> str:
        """Return the secret key in hex format."""
        return self._secret_key.hex()

    @property
    def public_key_b64(self) -> str:
        """Return the public key in base64 format."""
        return base64.b64encode(self._public_key).decode("utf-8")

    @property
    def secret_key_b64(self) -> str:
        """Return the secret key in base64 format."""
        return base64.b64encode(self._secret_key).decode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        """Convert keypair to a dictionary (using hex encoding)."""
        return {
            "public_key": self.public_key_hex,
            "secret_key": self.secret_key_hex,
        }
    
    def __repr__(self) -> str:
        return f"Keypair(secret_key={len(self._secret_key)} bytes, public_key={len(self._public_key)} bytes)"

    def __iter__(self):
        yield self._public_key
        yield self._secret_key
