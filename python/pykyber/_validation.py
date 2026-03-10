"""Kyber validation helpers."""

from typing import Tuple, Callable, Optional

from ._error import KyberError


def _validate_pk(pk: bytes, expected_size: int, method_name: str) -> None:
    """Validate public key length with a clear error message."""
    actual_size = len(pk)
    if actual_size != expected_size:
        raise KyberError(
            f"Invalid public key for {method_name}: expected {expected_size} bytes, got {actual_size}. "
            f"Ensure you're using the correct Kyber variant (Kyber512={800}, Kyber768={1184}, Kyber1024={1568})."
        )


def _validate_seed(seed: Optional[bytes], expected_size: int = 64) -> None:
    """Validate seed length."""
    if seed is not None:
        actual_size = len(seed)
        if actual_size != expected_size:
            raise KyberError(
                f"Invalid seed size: expected {expected_size} bytes, got {actual_size}."
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


def _validate_keypair(fn: Callable[[Optional[bytes]], Tuple[bytes, bytes]]) -> Callable[[Optional[bytes]], Tuple[bytes, bytes]]:
    """Wrap a Rust keypair function to raise KyberError on failure."""
    def wrapper(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        _validate_seed(seed)
        try:
            return fn(seed)
        except Exception as e:
            raise KyberError(str(e)) from None
    return wrapper
