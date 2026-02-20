"""Kyber post-quantum key encapsulation."""

import pykyber
from typing import Tuple


class Kyber512:
    """Kyber-512 key encapsulation (security ~AES-128)."""
    
    PUBLIC_KEY_SIZE = 800
    SECRET_KEY_SIZE = 1632
    CIPHERTEXT_SIZE = 768
    SHARED_SECRET_SIZE = 32
    
    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generate a public/secret key pair."""
        return pykyber.keypair_512()
    
    @staticmethod
    def encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using a public key."""
        return pykyber.encapsulate_512(pk)
    
    @staticmethod
    def decapsulate(ct: bytes, sk: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext and secret key."""
        return pykyber.decapsulate_512(ct, sk)


class Kyber768:
    """Kyber-768 key encapsulation (security ~AES-192)."""
    
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32
    
    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generate a public/secret key pair."""
        return pykyber.keypair_768()
    
    @staticmethod
    def encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using a public key."""
        return pykyber.encapsulate_768(pk)
    
    @staticmethod
    def decapsulate(ct: bytes, sk: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext and secret key."""
        return pykyber.decapsulate_768(ct, sk)


class Kyber1024:
    """Kyber-1024 key encapsulation (security ~AES-256)."""
    
    PUBLIC_KEY_SIZE = 1568
    SECRET_KEY_SIZE = 3168
    CIPHERTEXT_SIZE = 1568
    SHARED_SECRET_SIZE = 32
    
    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generate a public/secret key pair."""
        return pykyber.keypair_1024()
    
    @staticmethod
    def encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using a public key."""
        return pykyber.encapsulate_1024(pk)
    
    @staticmethod
    def decapsulate(ct: bytes, sk: bytes) -> bytes:
        """Decapsulate a shared secret using ciphertext and secret key."""
        return pykyber.decapsulate_1024(ct, sk)


class Kyber768KeyPair:
    """Kyber-768 key pair with encapsulation methods."""
    
    def __init__(self, public_key: bytes, secret_key: bytes):
        self.public_key = public_key
        self.secret_key = secret_key
    
    @classmethod
    def generate(cls) -> 'Kyber768KeyPair':
        """Generate a new key pair."""
        public_key, secret_key = pykyber.generate_keypair()
        return cls(public_key, secret_key)
    
    @classmethod
    def from_bytes(cls, public_key: bytes, secret_key: bytes) -> 'Kyber768KeyPair':
        """Create a key pair from existing keys."""
        return cls(public_key, secret_key)
    
    def encapsulate(self) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""
        return pykyber.encapsulate(self.public_key)
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the secret key."""
        return pykyber.decapsulate(ciphertext, self.secret_key)
    
    def __repr__(self) -> str:
        return f"Kyber768KeyPair(public_key={len(self.public_key)} bytes, secret_key={len(self.secret_key)} bytes)"


class Kyber512KeyPair:
    """Kyber-512 key pair with encapsulation methods."""
    
    def __init__(self, public_key: bytes, secret_key: bytes):
        self.public_key = public_key
        self.secret_key = secret_key
    
    @classmethod
    def generate(cls) -> 'Kyber512KeyPair':
        """Generate a new key pair."""
        public_key, secret_key = pykyber.keypair_512()
        return cls(public_key, secret_key)
    
    @classmethod
    def from_bytes(cls, public_key: bytes, secret_key: bytes) -> 'Kyber512KeyPair':
        """Create a key pair from existing keys."""
        return cls(public_key, secret_key)
    
    def encapsulate(self) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""
        return pykyber.encapsulate_512(self.public_key)
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the secret key."""
        return pykyber.decapsulate_512(ciphertext, self.secret_key)
    
    def __repr__(self) -> str:
        return f"Kyber512KeyPair(public_key={len(self.public_key)} bytes, secret_key={len(self.secret_key)} bytes)"


class Kyber1024KeyPair:
    """Kyber-1024 key pair with encapsulation methods."""
    
    def __init__(self, public_key: bytes, secret_key: bytes):
        self.public_key = public_key
        self.secret_key = secret_key
    
    @classmethod
    def generate(cls) -> 'Kyber1024KeyPair':
        """Generate a new key pair."""
        public_key, secret_key = pykyber.keypair_1024()
        return cls(public_key, secret_key)
    
    @classmethod
    def from_bytes(cls, public_key: bytes, secret_key: bytes) -> 'Kyber1024KeyPair':
        """Create a key pair from existing keys."""
        return cls(public_key, secret_key)
    
    def encapsulate(self) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""
        return pykyber.encapsulate_1024(self.public_key)
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the secret key."""
        return pykyber.decapsulate_1024(ciphertext, self.secret_key)
    
    def __repr__(self) -> str:
        return f"Kyber1024KeyPair(public_key={len(self.public_key)} bytes, secret_key={len(self.secret_key)} bytes)"


# Default aliases
Kyber = Kyber768
KeyPair = Kyber768KeyPair
