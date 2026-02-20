"""Kyber post-quantum key encapsulation."""

from typing import Tuple

from ._pykyber import (
    generate_keypair as _generate_keypair,
    encapsulate as _encapsulate,
    decapsulate as _decapsulate,
    keypair_512 as _keypair_512,
    keypair_768 as _keypair_768,
    keypair_1024 as _keypair_1024,
    encapsulate_512 as _encapsulate_512,
    encapsulate_768 as _encapsulate_768,
    encapsulate_1024 as _encapsulate_1024,
    decapsulate_512 as _decapsulate_512,
    decapsulate_768 as _decapsulate_768,
    decapsulate_1024 as _decapsulate_1024,
)

from .kyber import (
    Kyber,
    Kyber768,
    Kyber512,
    Kyber1024,
    KeyPair,
    Kyber768KeyPair,
    Kyber512KeyPair,
    Kyber1024KeyPair,
)


def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a Kyber-768 keypair. Returns (public_key, secret_key)."""
    return _generate_keypair()


def encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret using a public key. Returns (ciphertext, shared_secret)."""
    return _encapsulate(pk)


def decapsulate(ct: bytes, sk: bytes) -> bytes:
    """Decapsulate a shared secret using ciphertext and secret key. Returns shared_secret."""
    return _decapsulate(ct, sk)


def keypair_512() -> Tuple[bytes, bytes]:
    """Generate a Kyber-512 keypair. Returns (public_key, secret_key)."""
    return _keypair_512()


def keypair_768() -> Tuple[bytes, bytes]:
    """Generate a Kyber-768 keypair. Returns (public_key, secret_key)."""
    return _keypair_768()


def keypair_1024() -> Tuple[bytes, bytes]:
    """Generate a Kyber-1024 keypair. Returns (public_key, secret_key)."""
    return _keypair_1024()


def encapsulate_512(pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate using Kyber-512. Returns (ciphertext, shared_secret)."""
    return _encapsulate_512(pk)


def encapsulate_768(pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate using Kyber-768. Returns (ciphertext, shared_secret)."""
    return _encapsulate_768(pk)


def encapsulate_1024(pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate using Kyber-1024. Returns (ciphertext, shared_secret)."""
    return _encapsulate_1024(pk)


def decapsulate_512(ct: bytes, sk: bytes) -> bytes:
    """Decapsulate using Kyber-512. Returns shared_secret."""
    return _decapsulate_512(ct, sk)


def decapsulate_768(ct: bytes, sk: bytes) -> bytes:
    """Decapsulate using Kyber-768. Returns shared_secret."""
    return _decapsulate_768(ct, sk)


def decapsulate_1024(ct: bytes, sk: bytes) -> bytes:
    """Decapsulate using Kyber-1024. Returns shared_secret."""
    return _decapsulate_1024(ct, sk)
