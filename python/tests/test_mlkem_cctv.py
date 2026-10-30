"""C2SP CCTV ML-KEM vectors (repository C2SP/CCTV, directory ML-KEM) through
the public Python API.

The files are fetched by ``scripts/fetch_vectors.py`` into
``tests/vectors/external`` and never committed; a missing file fails the run.

- modulus: encapsulation keys with a coefficient in q..2**12-1 must be refused
  by ``encapsulate`` (FIPS 203 section 7.2), at every position and value.
- unluckysample: a key pair whose ``rho`` needs more than 575 XOF bytes in
  SampleNTT; ``encapsulate`` and ``decapsulate`` must work on it.
- strcmp: a modified ciphertext that a ``strcmp`` based comparison would accept;
  ``decapsulate`` must return the implicit-rejection secret.

The unluckysample files were made before the final standard added ``k`` to the
key generation hash (``rho`` is ``G(d)`` there), so their ``d`` cannot be fed to
``ML_KEM_*(seed=...)``. The accumulated vectors and the exact ``m`` of
encapsulation need internal functions and are checked in Rust
(``src/mlkem/cctv_tests.rs``).
"""

import gzip
from pathlib import Path

import pytest

import pykyber

CCTV_DIR = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "external" / "cctv"
CLASSES = (pykyber.ML_KEM_512, pykyber.ML_KEM_768, pykyber.ML_KEM_1024)
SHARED_SECRET_BYTES = 32
N = 256  # coefficients per polynomial
Q = 3329
COEFFICIENT_BITS = 12
BITS_PER_BYTE = 8
POLY_BYTES = N * COEFFICIENT_BITS // BITS_PER_BYTE
# modulus.go: four edge keys per polynomial, then a sweep that runs until every
# value in q..2**12-1 and every position has been used.
EDGE_KEYS_PER_POLY = 4
OVERFLOW_VALUES = (1 << COEFFICIENT_BITS) - Q


def _read(relative):
    path = CCTV_DIR / relative
    if not path.exists():
        raise FileNotFoundError("%s is missing; run scripts/fetch_vectors.py" % path)
    return path.read_bytes()


def _record(relative):
    """The ``name = hex`` fields of a one-record file."""
    fields = {}
    for line in _read(relative).decode("ascii").splitlines():
        name, _, value = line.partition(" = ")
        assert name not in fields, "%s repeats %s" % (relative, name)
        fields[name] = bytes.fromhex(value)
    return fields


def _polynomials(cls):
    """k, from ``ek = k * 384 + 32`` bytes (ByteEncode12 of t, then rho)."""
    return (cls.PUBLIC_KEY_SIZE - SHARED_SECRET_BYTES) // POLY_BYTES


@pytest.mark.parametrize("cls", CLASSES, ids=lambda cls: cls.ALGORITHM)
def test_modulus_check_negatives(cls):
    lines = gzip.decompress(_read("modulus/%s.txt.gz" % cls.ALGORITHM)).decode("ascii").splitlines()
    k = _polynomials(cls)
    assert len(lines) == EDGE_KEYS_PER_POLY * k + max(OVERFLOW_VALUES, k * N)
    for line in lines:
        ek = bytes.fromhex(line)
        assert len(ek) == cls.PUBLIC_KEY_SIZE
        with pytest.raises(pykyber.InvalidEncapsulationKeyError):
            cls.encapsulate(ek)


@pytest.mark.parametrize("cls", CLASSES, ids=lambda cls: cls.ALGORITHM)
def test_unlucky_sampling_key_pair(cls):
    fields = _record("unluckysample/%s.txt" % cls.ALGORITHM)
    result = cls.encapsulate(fields["ek"])
    assert cls.decapsulate(result.ciphertext, fields["dk"]) == result.shared_secret
    assert cls.decapsulate(fields["c"], fields["dk"]) == fields["K"]
    assert cls.from_keys(fields["ek"], fields["dk"]).decapsulate(fields["c"]) == fields["K"]


@pytest.mark.parametrize("cls", CLASSES, ids=lambda cls: cls.ALGORITHM)
def test_strcmp_ciphertext_is_rejected_implicitly(cls):
    fields = _record("strcmp/%s.txt" % cls.ALGORITHM)
    assert len(fields["K"]) == SHARED_SECRET_BYTES
    assert cls.decapsulate(fields["c"], fields["dk"]) == fields["K"]
