"""Kyber validation helpers."""

from typing import Tuple, Callable, Optional

from ._error import AlgorithmMismatchError, InvalidInputError, KyberError
from ._types import EncapsulationResult, Keypair, MlKemEncapsulationResult, MlKemKeypair


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


def _validate_ml_kem_bytes(value: object, kind: str, algorithm: str, expected_size: int, method_name: str) -> bytes:
    """Return the ``kind`` bytes ("public_key", "secret_key" or "ciphertext") of ``value``.

    ``value`` is ``bytes`` or an ML-KEM object of the same ``algorithm``. A
    Kyber object, or an ML-KEM object of another parameter set, is refused by
    type: Kyber and ML-KEM keys have identical sizes, so a length check cannot
    catch the mix-up. Raw bytes cannot be told apart and are taken as given.
    """
    if isinstance(value, (Keypair, EncapsulationResult)):
        raise AlgorithmMismatchError(
            f"{method_name} was given a Kyber {type(value).__name__} object, but {algorithm} is not "
            f"round-3 Kyber: the sizes match, the keys and secrets are not interchangeable."
        )
    if isinstance(value, (MlKemKeypair, MlKemEncapsulationResult)):
        if value.algorithm != algorithm:
            raise AlgorithmMismatchError(
                f"{method_name} was given a {value.algorithm} object, but this is {algorithm}."
            )
        value = getattr(value, kind, None)
    if not isinstance(value, bytes):
        raise InvalidInputError(
            f"Invalid {kind} for {method_name}: expected bytes or a {algorithm} object holding one, "
            f"got {type(value).__name__}."
        )
    if len(value) != expected_size:
        raise InvalidInputError(
            f"Invalid {kind} for {method_name}: expected {expected_size} bytes, got {len(value)}."
        )
    return value


def _validate_ml_kem_seed(seed: Optional[bytes], expected_size: int, method_name: str) -> Optional[bytes]:
    """Check the optional 64-byte seed ``d || z`` (bytes only) and return it."""
    if seed is None:
        return None
    if not isinstance(seed, bytes):
        raise InvalidInputError(f"Invalid seed for {method_name}: expected bytes, got {type(seed).__name__}.")
    if len(seed) != expected_size:
        raise InvalidInputError(
            f"Invalid seed for {method_name}: expected {expected_size} bytes, got {len(seed)}."
        )
    return seed
