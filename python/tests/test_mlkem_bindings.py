"""The private ML-KEM functions of ``pykyber._pykyber``: output shapes and the
exception each Rust error becomes. The public classes are tested in
``test_mlkem.py``."""

import pytest

from pykyber import KyberError, _pykyber
from pykyber import _error

# FIPS 203 Table 3 (ek, dk, c sizes) and section 3.3 (32-byte shared secret).
SETS = {
    512: (800, 1632, 768),
    768: (1184, 2400, 1088),
    1024: (1568, 3168, 1568),
}
SHARED_SECRET_BYTES = 32
SEED_HALF_BYTES = 32  # d and z
SEED_BYTES = 2 * SEED_HALF_BYTES
HASH_BYTES = 32  # H(ek) inside dk


def _fns(level):
    return tuple(getattr(_pykyber, "_mlkem_%d_%s" % (level, name)) for name in ("keygen", "encaps", "decaps"))


@pytest.mark.parametrize("level", SETS)
def test_round_trip_and_sizes(level):
    keygen, encaps, decaps = _fns(level)
    ek_size, dk_size, ct_size = SETS[level]
    ek, dk = keygen()
    assert (len(ek), len(dk)) == (ek_size, dk_size)
    ct, ss = encaps(ek)
    assert len(ct) == ct_size and len(ss) == SHARED_SECRET_BYTES
    assert decaps(ct, dk) == ss
    assert all(type(x) is bytes for x in (ek, dk, ct, ss))


@pytest.mark.parametrize("level", SETS)
def test_seed_is_d_then_z(level):
    keygen = _fns(level)[0]
    d, z = bytes(range(SEED_HALF_BYTES)), bytes(range(SEED_HALF_BYTES, SEED_BYTES))
    ek, dk = keygen(d + z)
    assert (ek, dk) == keygen(d + z)
    assert dk.endswith(z)
    assert keygen(z + d) != (ek, dk)


@pytest.mark.parametrize("level", SETS)
def test_errors_are_kyber_error_subclasses(level):
    keygen, encaps, decaps = _fns(level)
    ek_size, dk_size, ct_size = SETS[level]
    ek, dk = keygen()
    ct, _ = encaps(ek)

    with pytest.raises(_error.InvalidInputError) as info:
        keygen(bytes(SEED_BYTES - 1))
    assert "seed" in str(info.value)
    with pytest.raises(_error.InvalidInputError):
        encaps(ek[:-1])
    with pytest.raises(_error.InvalidInputError):
        decaps(ct[:-1], dk)
    with pytest.raises(_error.InvalidInputError):
        decaps(ct, dk[:-1])

    # Section 7.2: a coefficient of ek equal to 2^12 - 1 is not reduced mod q.
    with pytest.raises(_error.InvalidEncapsulationKeyError):
        encaps(b"\xff" * ek_size)
    # Section 7.3: the stored H(ek) no longer matches.
    bad = bytearray(dk)
    bad[dk_size - SEED_HALF_BYTES - HASH_BYTES] ^= 1  # first byte of H(ek)
    with pytest.raises(_error.InvalidDecapsulationKeyError):
        decaps(ct, bytes(bad))

    for cls in (_error.InvalidInputError, _error.InvalidEncapsulationKeyError, _error.InvalidDecapsulationKeyError):
        assert issubclass(cls, KyberError)
