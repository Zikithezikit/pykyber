"""Golden-vector freeze for legacy Kyber: pykyber v1.0.5 must keep producing
byte-identical output.

The vector file ``tests/vectors/legacy-kyber-v1.0.5.json`` is append-only,
captured from the pinned PyPI wheel and a git worktree at tag v1.0.5 by
``tests/vectors/generate.py``. If these tests fail, the bug is in current
code; the vectors are never regenerated or edited to pass.
"""

import hashlib
import json
from pathlib import Path

import pytest

import pykyber

REPO_ROOT = Path(__file__).resolve().parents[2]
VECTORS_FILE = REPO_ROOT / "tests" / "vectors" / "legacy-kyber-v1.0.5.json"

GOLDEN = json.loads(VECTORS_FILE.read_text(encoding="ascii"))

# Layout constants of the frozen format (round-3 Kyber, FIPS 202 SHA3-256).
SEED_BYTES = 64  # d || z
SEED_HALF_BYTES = SEED_BYTES // 2
POLY_BYTES = 384  # one polynomial, 12 bits per coefficient
PUBLIC_SEED_BYTES = 32  # rho at the end of the public key
HASH_BYTES = 32  # H(ek)
SEEDS_PER_SET = 3
PARAMETER_SETS = 3

CLASSES = {
    "512": pykyber.Kyber512,
    "768": pykyber.Kyber768,
    "1024": pykyber.Kyber1024,
}


def _vector_id(vector):
    return "kyber{}-seed{}".format(vector["parameter_set"], vector["key_seed_hex"][:8])


@pytest.mark.parametrize("vector", GOLDEN["vectors"], ids=[_vector_id(v) for v in GOLDEN["vectors"]])
def test_seeded_keygen_matches_v1_0_5(vector):
    cls = CLASSES[vector["parameter_set"]]
    key = cls(seed=bytes.fromhex(vector["key_seed_hex"]))
    assert key.public_key == bytes.fromhex(vector["keypair_public_key_hex"])
    assert key.secret_key == bytes.fromhex(vector["keypair_secret_key_hex"])


@pytest.mark.parametrize("vector", GOLDEN["vectors"], ids=[_vector_id(v) for v in GOLDEN["vectors"]])
def test_decapsulate_matches_v1_0_5(vector):
    cls = CLASSES[vector["parameter_set"]]
    shared_secret = cls.decapsulate(
        bytes.fromhex(vector["ciphertext_hex"]),
        bytes.fromhex(vector["keypair_secret_key_hex"]),
    )
    assert shared_secret == bytes.fromhex(vector["shared_secret_decaps_hex"])


@pytest.mark.parametrize("vector", GOLDEN["vectors"], ids=[_vector_id(v) for v in GOLDEN["vectors"]])
def test_from_keys_decapsulate_matches_v1_0_5(vector):
    cls = CLASSES[vector["parameter_set"]]
    key = cls.from_keys(
        bytes.fromhex(vector["keypair_public_key_hex"]),
        bytes.fromhex(vector["keypair_secret_key_hex"]),
    )
    assert key.decapsulate(bytes.fromhex(vector["ciphertext_hex"])) == bytes.fromhex(
        vector["shared_secret_decaps_hex"]
    )


@pytest.mark.parametrize("vector", GOLDEN["vectors"], ids=[_vector_id(v) for v in GOLDEN["vectors"]])
def test_encapsulate_against_v1_0_5_keys_roundtrips(vector):
    """Current encapsulate must stay compatible with 1.0.5 key material."""
    cls = CLASSES[vector["parameter_set"]]
    result = cls.encapsulate(bytes.fromhex(vector["keypair_public_key_hex"]))
    shared_secret = cls.decapsulate(
        result.ciphertext, bytes.fromhex(vector["keypair_secret_key_hex"])
    )
    assert shared_secret == result.shared_secret


def test_vector_shapes_match_class_sizes():
    for parameter_set, cls in CLASSES.items():
        vector = next(v for v in GOLDEN["vectors"] if v["parameter_set"] == parameter_set)
        assert len(bytes.fromhex(vector["keypair_public_key_hex"])) == cls.PUBLIC_KEY_SIZE
        assert len(bytes.fromhex(vector["keypair_secret_key_hex"])) == cls.SECRET_KEY_SIZE
        assert len(bytes.fromhex(vector["ciphertext_hex"])) == cls.CIPHERTEXT_SIZE
        assert len(bytes.fromhex(vector["shared_secret_decaps_hex"])) == cls.SHARED_SECRET_SIZE


def test_vector_file_internals_depend_only_on_the_file():
    """Re-verify the vector file's own layout invariants on every machine,
    independently of the Rust library and of any replay outcome.

    Round-3 Kyber keys are written as sk = s || ek || H(ek) || z (the layout
    frozen by pykyber v1.0.5; cf. src/kyber/kem.rs, hash_sha3_256 over the
    encoded public key), and the encapsulation shared secret must equal the
    decapsulation one. If the file is accidentally or deliberately edited, the
    replay tests can only fail when the current code produces different bytes;
    these checks fail additionally when the stored bytes are not internally
    coherent at all."""

    # Provenance preamble: file declares append-only and its capture basis.
    meta = GOLDEN["meta"]
    assert meta["append_only"] is True
    assert meta["generator"] == "tests/vectors/generate.py"
    assert meta["pypi_package"] == "pykyber==1.0.5"
    assert (
        meta["pypi_wheel_sha256"]
        == "0bd5d644e7783f4cf3bfffaa04fa42f96f43a68b6954e5927bc8bd94a2f2592a"
    )
    assert meta["rust_tag"] == "v1.0.5"
    assert len(GOLDEN["vectors"]) == SEEDS_PER_SET * PARAMETER_SETS

    seen_public_keys = set()
    for vector in GOLDEN["vectors"]:
        ps = vector["parameter_set"]
        cls = CLASSES[ps]
        seed = bytes.fromhex(vector["key_seed_hex"])
        pk = bytes.fromhex(vector["keypair_public_key_hex"])
        sk = bytes.fromhex(vector["keypair_secret_key_hex"])
        ct = bytes.fromhex(vector["ciphertext_hex"])
        ss_encaps = bytes.fromhex(vector["shared_secret_encaps_hex"])
        ss_decaps = bytes.fromhex(vector["shared_secret_decaps_hex"])

        assert len(seed) == SEED_BYTES, ps  # d || z
        assert len(pk) == cls.PUBLIC_KEY_SIZE, ps
        assert len(sk) == cls.SECRET_KEY_SIZE, ps
        assert len(ct) == cls.CIPHERTEXT_SIZE, ps
        assert len(ss_encaps) == len(ss_decaps) == cls.SHARED_SECRET_SIZE, ps
        assert ss_encaps == ss_decaps, ps
        assert pk not in seen_public_keys, "duplicate public key in the vector file"
        seen_public_keys.add(pk)

        k = (len(pk) - PUBLIC_SEED_BYTES) // POLY_BYTES  # pk is 384*k + 32 bytes
        offset = POLY_BYTES * k
        assert sk[offset : offset + len(pk)] == pk, ps  # sk embeds ek verbatim
        hash_field = sk[offset + len(pk) : offset + len(pk) + HASH_BYTES]
        assert hash_field == hashlib.sha3_256(pk).digest(), ps  # sk embeds H(ek)
        assert sk[offset + len(pk) + HASH_BYTES :] == seed[SEED_HALF_BYTES:], ps  # sk z-tail == seed z
