"""Kyber post-quantum key encapsulation."""





from ._kyber import (
    Kyber768,
    Kyber512,
    Kyber1024,
    KyberError,
    _validate_encapsulate,
    _validate_decapsulate,
    _validate_keypair,
)

__all__ = ["Kyber512", "Kyber768", "Kyber1024", "KyberError"]

from . import _pykyber

_generate_keypair = _validate_keypair(_pykyber._generate_keypair)
_encapsulate = _validate_encapsulate(_pykyber._encapsulate, 1184, "_generate_keypair")
_decapsulate = _validate_decapsulate(_pykyber._decapsulate, 1088, "_generate_keypair")
_keypair_512 = _validate_keypair(_pykyber._keypair_512)
_keypair_768 = _validate_keypair(_pykyber._keypair_768)
_keypair_1024 = _validate_keypair(_pykyber._keypair_1024)
_encapsulate_512 = _validate_encapsulate(_pykyber._encapsulate_512, Kyber512.PUBLIC_KEY_SIZE, "_encapsulate_512")
_encapsulate_768 = _validate_encapsulate(_pykyber._encapsulate_768, Kyber768.PUBLIC_KEY_SIZE, "_encapsulate_768")
_encapsulate_1024 = _validate_encapsulate(_pykyber._encapsulate_1024, Kyber1024.PUBLIC_KEY_SIZE, "_encapsulate_1024")
_decapsulate_512 = _validate_decapsulate(_pykyber._decapsulate_512, Kyber512.CIPHERTEXT_SIZE, "_decapsulate_512")
_decapsulate_768 = _validate_decapsulate(_pykyber._decapsulate_768, Kyber768.CIPHERTEXT_SIZE, "_decapsulate_768")
_decapsulate_1024 = _validate_decapsulate(_pykyber._decapsulate_1024, Kyber1024.CIPHERTEXT_SIZE, "_decapsulate_1024")
