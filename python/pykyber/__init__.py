"""Kyber post-quantum key encapsulation."""





from ._kyber import (
    Kyber768,
    Kyber512,
    Kyber1024,
    KyberError,
    _wrap_encapsulate,
    _wrap_decapsulate,
    _wrap_keypair,
)

__all__ = ["Kyber512", "Kyber768", "Kyber1024", "KyberError"]

from . import _pykyber

_generate_keypair = _wrap_keypair(_pykyber._generate_keypair)
_encapsulate = _wrap_encapsulate(_pykyber._encapsulate)
_decapsulate = _wrap_decapsulate(_pykyber._decapsulate)
_keypair_512 = _wrap_keypair(_pykyber._keypair_512)
_keypair_768 = _wrap_keypair(_pykyber._keypair_768)
_keypair_1024 = _wrap_keypair(_pykyber._keypair_1024)
_encapsulate_512 = _wrap_encapsulate(_pykyber._encapsulate_512)
_encapsulate_768 = _wrap_encapsulate(_pykyber._encapsulate_768)
_encapsulate_1024 = _wrap_encapsulate(_pykyber._encapsulate_1024)
_decapsulate_512 = _wrap_decapsulate(_pykyber._decapsulate_512)
_decapsulate_768 = _wrap_decapsulate(_pykyber._decapsulate_768)
_decapsulate_1024 = _wrap_decapsulate(_pykyber._decapsulate_1024)
