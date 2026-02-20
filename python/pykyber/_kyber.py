"""Kyber post-quantum key encapsulation."""

import pykyber
from abc import ABC, abstractmethod
from typing import Tuple, Callable


class Kyber(ABC):
    """Abstract base class for Kyber key encapsulation."""
    
    PUBLIC_KEY_SIZE: int
    SECRET_KEY_SIZE: int
    CIPHERTEXT_SIZE: int
    SHARED_SECRET_SIZE: int
    
    @classmethod
    @abstractmethod
    def _keypair_fn(cls) -> Tuple[bytes, bytes]:
        """Return the keypair generation function."""
        pass
    
    @classmethod
    @abstractmethod
    def _encapsulate_fn(cls) -> Callable[[bytes], Tuple[bytes, bytes]]:
        """Return the encapsulate function."""
        pass
    
    @classmethod
    @abstractmethod
    def _decapsulate_fn(cls) -> Callable[[bytes, bytes], bytes]:
        """Return the decapsulate function."""
        pass
    
    @classmethod
    def generate_keypair(cls) -> 'PrivateKey':
        """Generate a key pair. Returns PrivateKey (which has .public_key property)."""
        pk, sk = cls._keypair_fn()
        return PrivateKey(sk, pk, cls._encapsulate_fn(), cls._decapsulate_fn())
    
    @staticmethod
    def encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using a public key."""
        raise NotImplementedError("Use variant-specific class")
    
    @staticmethod
    def decapsulate(ct: bytes, sk: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext and secret key."""
        raise NotImplementedError("Use variant-specific class")


class PublicKey:
    """Public key with encapsulate method."""
    
    def __init__(self, public_key_bytes: bytes, 
                 encapsulate_fn: Callable[[bytes], Tuple[bytes, bytes]],
                 decapsulate_fn: Callable[[bytes, bytes], bytes]):
        self._public_key = public_key_bytes
        self._encapsulate_fn = encapsulate_fn
        self._decapsulate_fn = decapsulate_fn
    
    def encapsulate(self) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""
        return self._encapsulate_fn(self._public_key)
    
    @property
    def public_key(self) -> bytes:
        """Return the raw public key bytes."""
        return self._public_key
    
    def __repr__(self) -> str:
        return f"PublicKey({len(self._public_key)} bytes)"


class PrivateKey:
    """Private key with decapsulate method."""
    
    def __init__(self, secret_key_bytes: bytes, public_key_bytes: bytes,
                 encapsulate_fn: Callable[[bytes], Tuple[bytes, bytes]],
                 decapsulate_fn: Callable[[bytes, bytes], bytes]):
        self._secret_key = secret_key_bytes
        self._public_key = public_key_bytes
        self._encapsulate_fn = encapsulate_fn
        self._decapsulate_fn = decapsulate_fn
    
    @property
    def public_key(self) -> PublicKey:
        """Return the corresponding public key (for encapsulation)."""
        return PublicKey(self._public_key, self._encapsulate_fn, self._decapsulate_fn)
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext."""
        return self._decapsulate_fn(ciphertext, self._secret_key)
    
    @property
    def secret_key(self) -> bytes:
        """Return the raw secret key bytes."""
        return self._secret_key
    
    def __repr__(self) -> str:
        return f"PrivateKey({len(self._secret_key)} bytes)"


class Kyber512(Kyber):
    """Kyber-512 key encapsulation (security ~AES-128)."""
    
    PUBLIC_KEY_SIZE = 800
    SECRET_KEY_SIZE = 1632
    CIPHERTEXT_SIZE = 768
    SHARED_SECRET_SIZE = 32
    
    @classmethod
    def _keypair_fn(cls) -> Tuple[bytes, bytes]:
        return pykyber._keypair_512()
    
    @classmethod
    def _encapsulate_fn(cls) -> Callable[[bytes], Tuple[bytes, bytes]]:
        return pykyber._encapsulate_512
    
    @classmethod
    def _decapsulate_fn(cls) -> Callable[[bytes, bytes], bytes]:
        return pykyber._decapsulate_512


class Kyber768(Kyber):
    """Kyber-768 key encapsulation (security ~AES-192)."""
    
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32
    
    @classmethod
    def _keypair_fn(cls) -> Tuple[bytes, bytes]:
        return pykyber._keypair_768()
    
    @classmethod
    def _encapsulate_fn(cls) -> Callable[[bytes], Tuple[bytes, bytes]]:
        return pykyber._encapsulate_768
    
    @classmethod
    def _decapsulate_fn(cls) -> Callable[[bytes, bytes], bytes]:
        return pykyber._decapsulate_768


class Kyber1024(Kyber):
    """Kyber-1024 key encapsulation (security ~AES-256)."""
    
    PUBLIC_KEY_SIZE = 1568
    SECRET_KEY_SIZE = 3168
    CIPHERTEXT_SIZE = 1568
    SHARED_SECRET_SIZE = 32
    
    @classmethod
    def _keypair_fn(cls) -> Tuple[bytes, bytes]:
        return pykyber._keypair_1024()
    
    @classmethod
    def _encapsulate_fn(cls) -> Callable[[bytes], Tuple[bytes, bytes]]:
        return pykyber._encapsulate_1024
    
    @classmethod
    def _decapsulate_fn(cls) -> Callable[[bytes, bytes], bytes]:
        return pykyber._decapsulate_1024

