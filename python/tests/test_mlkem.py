"""The public ML-KEM classes: round trips, validation, seeds, and the refusal
to mix Kyber and ML-KEM objects. Official vectors are in test_mlkem_acvp.py."""

import base64

import pytest

import pykyber
from pykyber import (
    AlgorithmMismatchError,
    InvalidDecapsulationKeyError,
    InvalidEncapsulationKeyError,
    InvalidInputError,
    KyberError,
)

# FIPS 203 Table 3 and section 3.3, as expected values (ek, dk, c).
SIZES = {
    "ML-KEM-512": (800, 1632, 768),
    "ML-KEM-768": (1184, 2400, 1088),
    "ML-KEM-1024": (1568, 3168, 1568),
}
SHARED_SECRET_BYTES = 32
SEED_HALF_BYTES = 32  # d and z
SEED_BYTES = 2 * SEED_HALF_BYTES
HASH_BYTES = 32  # H(ek) inside dk

PAIRS = [
    (pykyber.ML_KEM_512, pykyber.Kyber512),
    (pykyber.ML_KEM_768, pykyber.Kyber768),
    (pykyber.ML_KEM_1024, pykyber.Kyber1024),
]
CLASSES = [ml for ml, _ in PAIRS]
PAIR_IDS = [ml.ALGORITHM for ml in CLASSES]

SEED = bytes(range(SEED_BYTES))


@pytest.fixture(params=CLASSES, ids=PAIR_IDS)
def cls(request):
    return request.param


@pytest.fixture(params=PAIRS, ids=PAIR_IDS)
def pair(request):
    return request.param


def test_sizes(cls):
    assert (cls.PUBLIC_KEY_SIZE, cls.SECRET_KEY_SIZE, cls.CIPHERTEXT_SIZE) == SIZES[cls.ALGORITHM]
    assert cls.SHARED_SECRET_SIZE == SHARED_SECRET_BYTES
    assert cls.SEED_SIZE == SEED_BYTES


def test_keypair_round_trip(cls):
    key = cls()
    ek, dk, ct_size = SIZES[cls.ALGORITHM]
    assert (len(key.public_key), len(key.secret_key)) == (ek, dk)
    result = key.encapsulate()
    assert len(result.ciphertext) == ct_size
    assert len(result.shared_secret) == SHARED_SECRET_BYTES
    assert key.decapsulate(result.ciphertext) == result.shared_secret
    assert key.decapsulate(result) == result.shared_secret


def test_static_methods_and_from_keys(cls):
    key = cls()
    result = cls.encapsulate(key.public_key)
    assert cls.decapsulate(result.ciphertext, key.secret_key) == result.shared_secret
    rebuilt = cls.from_keys(key.public_key, key.secret_key)
    assert rebuilt.decapsulate(result.ciphertext) == result.shared_secret
    assert rebuilt.seed is None
    # An ML-KEM object of the same set can stand in for its bytes.
    assert cls.decapsulate(result, key) == result.shared_secret
    assert cls.from_keys(key, key).public_key == key.public_key


def test_encapsulations_differ(cls):
    key = cls()
    first, second = key.encapsulate(), key.encapsulate()
    assert first.ciphertext != second.ciphertext
    assert first.shared_secret != second.shared_secret


def test_tuple_unpacking_and_encodings(cls):
    key = cls()
    public_key, secret_key = key
    assert (public_key, secret_key) == (key.public_key, key.secret_key)
    result = key.encapsulate()
    ciphertext, shared_secret = result
    assert (ciphertext, shared_secret) == (result.ciphertext, result.shared_secret)

    assert key.public_key_hex == public_key.hex() and key.secret_key_hex == secret_key.hex()
    assert key.public_key_b64 == base64.b64encode(public_key).decode()
    assert key.secret_key_b64 == base64.b64encode(secret_key).decode()
    assert key.to_dict() == {"public_key": public_key.hex(), "secret_key": secret_key.hex()}
    assert result.ciphertext_hex == ciphertext.hex() and result.shared_secret_hex == shared_secret.hex()
    assert result.ciphertext_b64 == base64.b64encode(ciphertext).decode()
    assert result.shared_secret_b64 == base64.b64encode(shared_secret).decode()
    assert result.to_dict() == {"ciphertext": ciphertext.hex(), "shared_secret": shared_secret.hex()}


def test_repr_shows_no_secret(cls):
    key = cls(SEED)
    result = key.encapsulate()
    for text in (repr(key), repr(result)):
        assert cls.ALGORITHM in text
        for secret in (key.secret_key, SEED, result.shared_secret):
            assert secret.hex() not in text


def test_modified_ciphertext_gives_implicit_rejection_secret(cls):
    key = cls()
    result = key.encapsulate()
    bad = bytearray(result.ciphertext)
    bad[0] ^= 1
    rejected = key.decapsulate(bytes(bad))
    assert len(rejected) == SHARED_SECRET_BYTES
    assert rejected != result.shared_secret
    assert key.decapsulate(bytes(bad)) == rejected  # deterministic for this key


def test_seed_is_deterministic_and_exposed(cls):
    first, second = cls(SEED), cls(SEED)
    assert (first.public_key, first.secret_key) == (second.public_key, second.secret_key)
    assert first.seed == SEED
    assert cls(bytes(SEED_BYTES)).public_key != first.public_key
    # dk ends with z, the second half of the seed (FIPS 203 Algorithm 16).
    assert first.secret_key.endswith(SEED[SEED_HALF_BYTES:])
    # d then z: swapping the halves is a different key.
    swapped = SEED[SEED_HALF_BYTES:] + SEED[:SEED_HALF_BYTES]
    assert cls(swapped).public_key != first.public_key


def test_random_keypair_has_no_seed(cls):
    assert cls().seed is None
    assert cls().public_key != cls().public_key
    assert "seed" not in cls(SEED).to_dict()


def test_same_seed_gives_different_keys_than_kyber(pair):
    ml_kem, kyber = pair
    assert ml_kem(SEED).public_key != kyber(SEED).public_key


@pytest.mark.parametrize("length", [0, SEED_BYTES - 1, SEED_BYTES + 1])
def test_bad_seed_length(cls, length):
    with pytest.raises(InvalidInputError, match="seed"):
        cls(bytes(length))


@pytest.mark.parametrize("seed", ["x" * SEED_BYTES, bytearray(SEED_BYTES), 7])
def test_bad_seed_type(cls, seed):
    with pytest.raises(InvalidInputError, match="seed"):
        cls(seed)


def test_bad_public_key_and_secret_key_and_ciphertext(cls):
    key = cls()
    result = key.encapsulate()
    for bad in (key.public_key[:-1], key.public_key + b"\0", b"", None, "text", bytearray(key.public_key), 5):
        with pytest.raises(InvalidInputError, match="public_key"):
            cls.encapsulate(bad)
        with pytest.raises(InvalidInputError, match="public_key"):
            cls.from_keys(bad, key.secret_key)
    for bad in (key.secret_key[:-1], key.secret_key + b"\0", b"", None, "text", bytearray(key.secret_key)):
        with pytest.raises(InvalidInputError, match="secret_key"):
            cls.decapsulate(result.ciphertext, bad)
        with pytest.raises(InvalidInputError, match="secret_key"):
            cls.from_keys(key.public_key, bad)
    for bad in (result.ciphertext[:-1], result.ciphertext + b"\0", b"", None, "text"):
        with pytest.raises(InvalidInputError, match="ciphertext"):
            cls.decapsulate(bad, key.secret_key)
        with pytest.raises(InvalidInputError, match="ciphertext"):
            key.decapsulate(bad)


def test_validation_errors_are_kyber_errors(cls):
    with pytest.raises(KyberError):
        cls.encapsulate(b"")
    assert issubclass(InvalidInputError, KyberError)


def test_ek_that_fails_the_modulus_check(cls):
    # Section 7.2: every 12-bit coefficient 4095 is >= q.
    with pytest.raises(InvalidEncapsulationKeyError) as info:
        cls.encapsulate(b"\xff" * cls.PUBLIC_KEY_SIZE)
    assert isinstance(info.value, KyberError)


def test_dk_that_fails_the_hash_check(cls):
    key = cls()
    result = key.encapsulate()
    broken = bytearray(key.secret_key)
    broken[cls.SECRET_KEY_SIZE - SEED_HALF_BYTES - HASH_BYTES] ^= 1  # first byte of H(ek)
    with pytest.raises(InvalidDecapsulationKeyError) as info:
        cls.decapsulate(result.ciphertext, bytes(broken))
    assert isinstance(info.value, KyberError)


def test_refuses_kyber_objects(pair):
    ml_kem, kyber = pair
    kyber_key = kyber()
    kyber_result = kyber_key.encapsulate()
    ml_key = ml_kem()
    ml_result = ml_key.encapsulate()

    with pytest.raises(AlgorithmMismatchError):
        ml_kem.decapsulate(ml_result.ciphertext, kyber_key)
    with pytest.raises(AlgorithmMismatchError):
        ml_kem.decapsulate(kyber_result, ml_key.secret_key)
    with pytest.raises(AlgorithmMismatchError):
        ml_kem.encapsulate(kyber_key)
    with pytest.raises(AlgorithmMismatchError):
        ml_kem.from_keys(kyber_key, ml_key.secret_key)
    with pytest.raises(AlgorithmMismatchError):
        ml_kem.from_keys(ml_key.public_key, kyber_key)
    with pytest.raises(AlgorithmMismatchError):
        ml_key.decapsulate(kyber_result)

    error = AlgorithmMismatchError
    assert issubclass(error, KyberError) and issubclass(error, TypeError)


def test_refuses_other_parameter_sets():
    key_768 = pykyber.ML_KEM_768()
    result_768 = key_768.encapsulate()
    for other in (pykyber.ML_KEM_512, pykyber.ML_KEM_1024):
        with pytest.raises(AlgorithmMismatchError, match="ML-KEM-768"):
            other.encapsulate(key_768)
        with pytest.raises(AlgorithmMismatchError):
            other.decapsulate(result_768, other())
        with pytest.raises(AlgorithmMismatchError):
            other.decapsulate(other().encapsulate().ciphertext, key_768)


def test_kyber_methods_do_not_accept_ml_kem_objects(pair):
    ml_kem, kyber = pair
    ml_key = ml_kem()
    ml_result = ml_key.encapsulate()
    kyber_key = kyber()
    refusals = (TypeError, KyberError)
    with pytest.raises(refusals):
        kyber.encapsulate(ml_key)
    with pytest.raises(refusals):
        kyber.decapsulate(ml_result, kyber_key.secret_key)
    with pytest.raises(refusals):
        kyber.decapsulate(kyber_key.encapsulate().ciphertext, ml_key)
    with pytest.raises(refusals):
        kyber.from_keys(ml_key, kyber_key.secret_key)


def test_raw_bytes_cannot_be_told_apart(pair):
    # The documented limit: Kyber bytes are accepted by ML-KEM (same sizes) and
    # give a different secret, which is why the objects carry their algorithm.
    ml_kem, kyber = pair
    kyber_key = kyber()
    kyber_result = kyber_key.encapsulate()
    mixed = ml_kem.decapsulate(kyber_result.ciphertext, kyber_key.secret_key)
    assert len(mixed) == SHARED_SECRET_BYTES
    assert mixed != kyber_result.shared_secret
