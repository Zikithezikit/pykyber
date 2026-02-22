"""Kyber post-quantum key encapsulation."""

from ._kyber import (
    Kyber768,
    Kyber512,
    Kyber1024,
)

__all__ = ["Kyber512", "Kyber768", "Kyber1024"]

# Import underscored functions from Rust
from ._pykyber import (
    _generate_keypair,
    _encapsulate,
    _decapsulate,
    _keypair_512,
    _keypair_768,
    _keypair_1024,
    _encapsulate_512,
    _encapsulate_768,
    _encapsulate_1024,
    _decapsulate_512,
    _decapsulate_768,
    _decapsulate_1024,
)
