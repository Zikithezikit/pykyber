"""C2SP Wycheproof ML-KEM vectors (repository C2SP/wycheproof, directory
``testvectors_v1``) through the public Python API.

The files are fetched by ``scripts/fetch_vectors.py`` into
``tests/vectors/external`` and never committed; a missing file fails the run.

``result`` follows ``schemas/common.json`` of the pinned commit: ``valid``
must succeed with the given output, ``invalid`` must raise ``KyberError``, and
``acceptable`` may do either but must give the output if it succeeds. The
flags only name the bug a case targets. The pinned files have no
``acceptable`` case; the rule is here so a pin bump cannot slip one through.

- ``mlkem_N_test.json``: a seed that is not 64 bytes, or a ciphertext of the
  wrong length, is ``invalid``; otherwise the key from the seed decapsulates
  ``c`` to ``K``.
- ``mlkem_N_encaps_test.json``: the public API draws ``m`` itself, so a
  ``valid`` case checks that ``encapsulate`` accepts ``ek`` and returns sizes
  that fit; the exact ``c`` and ``K`` for the given ``m`` are checked in Rust
  (``src/mlkem/wycheproof_tests.rs``).
- ``mlkem_N_keygen_seed_test.json``: the seed gives exactly ``ek`` and ``dk``.
- ``mlkem_N_semi_expanded_decaps_test.json``: ``decapsulate`` with the given
  ``dk``.
"""

import json
from pathlib import Path

import pytest

import pykyber

WYCHEPROOF_DIR = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "external" / "wycheproof"
CLASSES = {
    "ML-KEM-512": pykyber.ML_KEM_512,
    "ML-KEM-768": pykyber.ML_KEM_768,
    "ML-KEM-1024": pykyber.ML_KEM_1024,
}
SHARED_SECRET_BYTES = 32


def _cases(kind, schema):
    """(class, test) for every case of the ``kind`` file of each parameter set."""
    cases = []
    for name, cls in CLASSES.items():
        path = WYCHEPROOF_DIR / ("mlkem_%s_%s.json" % (name.rsplit("-", 1)[1], kind))
        if not path.exists():
            raise FileNotFoundError("%s is missing; run scripts/fetch_vectors.py" % path)
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert doc["algorithm"] == "ML-KEM" and doc["schema"] == schema, path
        tests = [t for group in doc["testGroups"] for t in group["tests"]]
        assert len(tests) == doc["numberOfTests"], path
        assert all(g["parameterSet"] == name for g in doc["testGroups"]), path
        cases += [pytest.param(cls, t, id="%s-tc%d" % (name, t["tcId"])) for t in tests]
    return cases


def _b(test, field):
    return bytes.fromhex(test[field])


def _judge(test, run, expected):
    """Apply the ``result`` rule to ``run()``; ``expected`` is the output of a valid case."""
    result = test["result"]
    assert result in ("valid", "invalid", "acceptable"), test["tcId"]
    try:
        output = run()
    except pykyber.KyberError:
        assert result != "valid", "tcId %d: valid case refused" % test["tcId"]
        return
    assert result != "invalid", "tcId %d: invalid case accepted" % test["tcId"]
    if result == "valid" or expected:
        assert output == expected, "tcId %d" % test["tcId"]


@pytest.mark.parametrize("cls, test", _cases("test", "mlkem_test_schema.json"))
def test_decapsulation_from_seed(cls, test):
    def run():
        key = cls(seed=_b(test, "seed"))
        assert key.public_key == _b(test, "ek")
        return key.decapsulate(_b(test, "c"))

    _judge(test, run, _b(test, "K"))


@pytest.mark.parametrize("cls, test", _cases("encaps_test", "mlkem_encaps_test_schema.json"))
def test_encapsulation_key_check(cls, test):
    def run():
        result = cls.encapsulate(_b(test, "ek"))
        assert len(result.ciphertext) == cls.CIPHERTEXT_SIZE
        assert len(result.shared_secret) == SHARED_SECRET_BYTES
        return b""

    _judge(test, run, b"")


@pytest.mark.parametrize("cls, test", _cases("keygen_seed_test", "mlkem_keygen_seed_test_schema.json"))
def test_key_generation_from_seed(cls, test):
    assert test["result"] == "valid"
    key = cls(seed=_b(test, "seed"))
    assert key.public_key == _b(test, "ek")
    assert key.secret_key == _b(test, "dk")


@pytest.mark.parametrize(
    "cls, test", _cases("semi_expanded_decaps_test", "mlkem_semi_expanded_decaps_test_schema.json")
)
def test_decapsulation_with_a_given_key(cls, test):
    expected = _b(test, "K") if "K" in test else b""
    _judge(test, lambda: cls.decapsulate(_b(test, "c"), _b(test, "dk")), expected)
