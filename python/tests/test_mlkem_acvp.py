"""NIST ACVP ML-KEM vectors (ACVP-Server, internalProjection files) through the
public Python API.

The files are fetched by ``scripts/fetch_vectors.py`` into
``tests/vectors/external`` and never committed; a missing file fails the run.

- keyGen: the seed ``d || z`` gives exactly the vector's ``ek`` and ``dk``.
- decapsulation: ``dk`` passes the hash check, so the public decapsulate must
  return the vector's ``k`` (also for the "modified ciphertext" cases, which
  pin the implicit-rejection secret).
- encapsulation: the vector fixes ``m``, which the public API does not allow,
  so the check is that the output decapsulates, with the paired ``dk``, to the
  same secret.
- key checks: the modulus check (section 7.2) and the hash check (section 7.3)
  through ``encapsulate`` and ``decapsulate``.
"""

import json
from pathlib import Path

import pytest

import pykyber

ACVP_DIR = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "external" / "acvp"
KEYGEN_FILE = ACVP_DIR / "ML-KEM-keyGen-FIPS203" / "internalProjection.json"
ENCAP_DECAP_FILE = ACVP_DIR / "ML-KEM-encapDecap-FIPS203" / "internalProjection.json"

CLASSES = {
    "ML-KEM-512": pykyber.ML_KEM_512,
    "ML-KEM-768": pykyber.ML_KEM_768,
    "ML-KEM-1024": pykyber.ML_KEM_1024,
}
SHARED_SECRET_BYTES = 32


def _load(path):
    if not path.exists():
        raise FileNotFoundError("%s is missing; run scripts/fetch_vectors.py" % path)
    return json.loads(path.read_text(encoding="ascii"))["testGroups"]


def _cases(path, function=None):
    """(id, class, test) for the groups of ``function`` (None for keyGen)."""
    cases = []
    for group in _load(path):
        if function is not None and group["function"] != function:
            continue
        cls = CLASSES[group["parameterSet"]]
        for test in group["tests"]:
            cases.append(pytest.param(cls, test, id="%s-tc%d" % (cls.ALGORITHM, test["tcId"])))
    return cases


def _b(test, field):
    return bytes.fromhex(test[field])


@pytest.mark.parametrize("cls, test", _cases(KEYGEN_FILE))
def test_keygen_from_seed(cls, test):
    key = cls(seed=_b(test, "d") + _b(test, "z"))
    assert key.public_key == _b(test, "ek")
    assert key.secret_key == _b(test, "dk")


@pytest.mark.parametrize("cls, test", _cases(ENCAP_DECAP_FILE, "decapsulation"))
def test_decapsulation(cls, test):
    assert cls.decapsulate(_b(test, "c"), _b(test, "dk")) == _b(test, "k")
    assert cls.from_keys(_b(test, "ek"), _b(test, "dk")).decapsulate(_b(test, "c")) == _b(test, "k")


@pytest.mark.parametrize("cls, test", _cases(ENCAP_DECAP_FILE, "encapsulation"))
def test_encapsulation_decapsulates_to_the_same_secret(cls, test):
    result = cls.encapsulate(_b(test, "ek"))
    assert len(result.ciphertext) == len(_b(test, "c"))
    assert len(result.shared_secret) == SHARED_SECRET_BYTES
    assert cls.decapsulate(result.ciphertext, _b(test, "dk")) == result.shared_secret


@pytest.mark.parametrize("cls, test", _cases(ENCAP_DECAP_FILE, "encapsulationKeyCheck"))
def test_encapsulation_key_check(cls, test):
    ek = _b(test, "ek")
    if test["testPassed"]:
        assert len(cls.encapsulate(ek).ciphertext) == cls.CIPHERTEXT_SIZE
    else:
        with pytest.raises(pykyber.InvalidEncapsulationKeyError):
            cls.encapsulate(ek)


@pytest.mark.parametrize("cls, test", _cases(ENCAP_DECAP_FILE, "decapsulationKeyCheck"))
def test_decapsulation_key_check(cls, test):
    dk = _b(test, "dk")
    ciphertext = bytes(cls.CIPHERTEXT_SIZE)  # any well-formed ciphertext reaches the key check
    if test["testPassed"]:
        assert len(cls.decapsulate(ciphertext, dk)) == SHARED_SECRET_BYTES
    else:
        with pytest.raises(pykyber.InvalidDecapsulationKeyError):
            cls.decapsulate(ciphertext, dk)
