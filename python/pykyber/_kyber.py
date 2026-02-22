"""Kyber post-quantum key encapsulation."""

from dataclasses import dataclass
from typing import Tuple, Callable


class KyberError(Exception):
    """Kyber error exception - raised when invalid input is provided."""
    pass

def _validate_pk(pk: bytes, expected_size: int, method_name: str) -> None:
    """Validate public key length with a clear error message."""
    actual_size = len(pk)
    if actual_size != expected_size:
        raise KyberError(
            f"Invalid public key for {method_name}: expected {expected_size} bytes, got {actual_size}. "
            f"Ensure you're using the correct Kyber variant (Kyber512={800}, Kyber768={1184}, Kyber1024={1568})."
        )


def _validate_encapsulate(fn: Callable[[bytes], Tuple[bytes, bytes]], expected_pk_size: int, method_name: str) -> Callable[[bytes], Tuple[bytes, bytes]]:
    """Validate public key and call Rust encapsulate function."""
    def wrapper(pk: bytes) -> Tuple[bytes, bytes]:
        _validate_pk(pk, expected_pk_size, method_name)
        try:
            return fn(pk)
        except Exception as e:
            raise KyberError(str(e)) from None
    return wrapper


def _validate_ct(ct: bytes, expected_size: int, method_name: str) -> None:
    """Validate ciphertext length with a clear error message."""
    actual_size = len(ct)
    if actual_size != expected_size:
        raise KyberError(
            f"Invalid ciphertext for {method_name}: expected {expected_size} bytes, got {actual_size}."
        )


def _validate_decapsulate(fn: Callable[[bytes, bytes], bytes], expected_ct_size: int, method_name: str) -> Callable[[bytes, bytes], bytes]:
    """Validate ciphertext and call Rust decapsulate function."""
    def wrapper(ct: bytes, sk: bytes) -> bytes:
        _validate_ct(ct, expected_ct_size, method_name)
        try:
            return fn(ct, sk)
        except Exception as e:
            raise KyberError(str(e)) from None
    return wrapper


def _wrap_keypair(fn: Callable[[], Tuple[bytes, bytes]]) -> Callable[[], Tuple[bytes, bytes]]:
    """Wrap a Rust keypair function to raise KyberError on failure."""
    def wrapper() -> Tuple[bytes, bytes]:
        try:
            return fn()
        except Exception as e:
            raise KyberError(str(e)) from None
    return wrapper


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


class Kyber512:
    """Kyber-512 key encapsulation (security ~AES-128)."""
    
    PUBLIC_KEY_SIZE = 800
    SECRET_KEY_SIZE = 1632
    CIPHERTEXT_SIZE = 768
    SHARED_SECRET_SIZE = 32
    
    def __new__(cls) -> Keypair:
        """Generate a new key pair."""
        from . import _pykyber
        pk, sk = _wrap_keypair(_pykyber._keypair_512)()
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
        pk, sk = _wrap_keypair(_pykyber._keypair_768)()
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
        pk, sk = _wrap_keypair(_pykyber._keypair_1024)()
        return Keypair(sk, pk, 
                       _validate_encapsulate(_pykyber._encapsulate_1024, Kyber1024.PUBLIC_KEY_SIZE, "Kyber1024"),
                       _validate_decapsulate(_pykyber._decapsulate_1024, Kyber1024.CIPHERTEXT_SIZE, "Kyber1024"))
    
    @staticmethod
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        """Encapsulate a shared secret using a public key (no keypair needed)."""
        from . import _pykyber
        return EncapsulationResult(*_validate_encapsulate(_pykyber._encapsulate_1024, Kyber1024.PUBLIC_KEY_SIZE, "Kyber1024.encapsulate")(public_key))
