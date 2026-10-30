"""Kyber types and data structures."""

import base64
from dataclasses import dataclass
from typing import Tuple, Callable, Dict, Any, Optional


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


# ML-KEM objects are separate classes, not subclasses of the Kyber ones above:
# Kyber and ML-KEM keys, ciphertexts and shared secrets have identical sizes,
# so the type is the only thing that tells them apart (see _validation.py).


class MlKemEncapsulationResult:
    """Result of an ML-KEM encapsulation: ``ciphertext, shared_secret = result``."""

    __slots__ = ("algorithm", "ciphertext", "shared_secret")

    def __init__(self, algorithm: str, ciphertext: bytes, shared_secret: bytes) -> None:
        self.algorithm = algorithm
        self.ciphertext = ciphertext
        self.shared_secret = shared_secret

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
        """Convert result to a dictionary (using hex encoding)."""
        return {
            "ciphertext": self.ciphertext_hex,
            "shared_secret": self.shared_secret_hex,
        }

    def __repr__(self) -> str:
        return (
            f"MlKemEncapsulationResult({self.algorithm}, "
            f"ciphertext={len(self.ciphertext)} bytes, "
            f"shared_secret={len(self.shared_secret)} bytes)"
        )

    def __iter__(self):
        yield self.ciphertext
        yield self.shared_secret


class MlKemKeypair:
    """An ML-KEM keypair: ``public_key, secret_key = keypair``.

    ``seed`` is the 64-byte ``d || z`` the keys were generated from, or None
    when they came from the random generator or from ``from_keys``.
    """

    __slots__ = ("algorithm", "_cls", "_public_key", "_secret_key", "_seed")

    def __init__(self, cls: Any, public_key: bytes, secret_key: bytes, seed: Optional[bytes] = None) -> None:
        self.algorithm = cls.ALGORITHM
        self._cls = cls
        self._public_key = public_key
        self._secret_key = secret_key
        self._seed = seed

    def encapsulate(self) -> MlKemEncapsulationResult:
        """Encapsulate a shared secret using the public key."""
        return self._cls.encapsulate(self._public_key)

    def decapsulate(self, ciphertext: Any) -> bytes:
        """Decapsulate a shared secret using ciphertext."""
        return self._cls.decapsulate(ciphertext, self._secret_key)

    @property
    def secret_key(self) -> bytes:
        """Return the raw secret key bytes."""
        return self._secret_key

    @property
    def public_key(self) -> bytes:
        """Return the raw public key bytes."""
        return self._public_key

    @property
    def seed(self) -> Optional[bytes]:
        """The 64-byte seed ``d || z`` (secret, as sensitive as the secret key).

        None unless the keypair was generated from a seed.
        """
        return self._seed

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
        """Convert keypair to a dictionary (using hex encoding); the seed is left out."""
        return {
            "public_key": self.public_key_hex,
            "secret_key": self.secret_key_hex,
        }

    def __repr__(self) -> str:
        return (
            f"MlKemKeypair({self.algorithm}, secret_key={len(self._secret_key)} bytes, "
            f"public_key={len(self._public_key)} bytes)"
        )

    def __iter__(self):
        yield self._public_key
        yield self._secret_key
