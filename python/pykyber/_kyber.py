"""Kyber post-quantum key encapsulation."""

from ._error import KyberError
from ._types import EncapsulationResult, Keypair
from ._validation import _validate_encapsulate, _validate_decapsulate, _validate_keypair


class Kyber512:
    """Kyber-512 key encapsulation (security ~AES-128)."""
    
    PUBLIC_KEY_SIZE = 800
    SECRET_KEY_SIZE = 1632
    CIPHERTEXT_SIZE = 768
    SHARED_SECRET_SIZE = 32
    
    def __new__(cls) -> Keypair:
        """Generate a new key pair."""
        from . import _pykyber
        pk, sk = _validate_keypair(_pykyber._keypair_512)()
        return Keypair(sk, pk, 
                       _validate_encapsulate(_pykyber._encapsulate_512, Kyber512.PUBLIC_KEY_SIZE, "Kyber512"),
                       _validate_decapsulate(_pykyber._decapsulate_512, Kyber512.CIPHERTEXT_SIZE, "Kyber512"))
    
    @staticmethod
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        """Encapsulate a shared secret using a public key (no keypair needed)."""
        from . import _pykyber
        return EncapsulationResult(*_validate_encapsulate(_pykyber._encapsulate_512, Kyber512.PUBLIC_KEY_SIZE, "Kyber512.encapsulate")(public_key))


class Kyber768:
    """Kyber-768 key encapsulation (security ~AES-192)."""
    
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32
    
    def __new__(cls) -> Keypair:
        """Generate a new key pair."""
        from . import _pykyber
        pk, sk = _validate_keypair(_pykyber._keypair_768)()
        return Keypair(sk, pk, 
                       _validate_encapsulate(_pykyber._encapsulate_768, Kyber768.PUBLIC_KEY_SIZE, "Kyber768"),
                       _validate_decapsulate(_pykyber._decapsulate_768, Kyber768.CIPHERTEXT_SIZE, "Kyber768"))
    
    @staticmethod
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        """Encapsulate a shared secret using a public key (no keypair needed)."""
        from . import _pykyber
        return EncapsulationResult(*_validate_encapsulate(_pykyber._encapsulate_768, Kyber768.PUBLIC_KEY_SIZE, "Kyber768.encapsulate")(public_key))


class Kyber1024:
    """Kyber-1024 key encapsulation (security ~AES-256)."""
    
    PUBLIC_KEY_SIZE = 1568
    SECRET_KEY_SIZE = 3168
    CIPHERTEXT_SIZE = 1408
    SHARED_SECRET_SIZE = 32
    
    def __new__(cls) -> Keypair:
        """Generate a new key pair."""
        from . import _pykyber
        pk, sk = _validate_keypair(_pykyber._keypair_1024)()
        return Keypair(sk, pk, 
                       _validate_encapsulate(_pykyber._encapsulate_1024, Kyber1024.PUBLIC_KEY_SIZE, "Kyber1024"),
                       _validate_decapsulate(_pykyber._decapsulate_1024, Kyber1024.CIPHERTEXT_SIZE, "Kyber1024"))
    
    @staticmethod
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        """Encapsulate a shared secret using a public key (no keypair needed)."""
        from . import _pykyber
        return EncapsulationResult(*_validate_encapsulate(_pykyber._encapsulate_1024, Kyber1024.PUBLIC_KEY_SIZE, "Kyber1024.encapsulate")(public_key))
