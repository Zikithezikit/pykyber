"""Deprecation warning for the legacy round-3 Kyber classes."""

import functools
import threading
import warnings

MIGRATION_GUIDE_URL = "https://github.com/Zikithezikit/pykyber/blob/main/docs/migration.md"

# warnings.warn() frames to skip: 1 is _warn_once, 2 is the wrapper made by
# _deprecated_kyber, 3 is the user's code that called the Kyber entry point.
_CALLER_STACKLEVEL = 3

_MESSAGE = (
    "Kyber512, Kyber768 and Kyber1024 implement round-3 CRYSTALS-Kyber, which is "
    "deprecated in favor of ML-KEM (FIPS 203): ML_KEM_512, ML_KEM_768 and "
    "ML_KEM_1024. Kyber (round 3) and ML-KEM are not interoperable, so both sides "
    "must switch, and switching changes the shared secret. "
    f"See {MIGRATION_GUIDE_URL}"
)

_lock = threading.Lock()
_warned = False


class KyberDeprecationWarning(DeprecationWarning):
    """The legacy round-3 Kyber classes are deprecated in favor of ML-KEM."""


def _warn_once() -> None:
    """Warn on the first call in this process, then do nothing.

    The flag is our own: the default warning filter keeps one registry entry per
    call site, so it would repeat the warning for every new location.
    """
    global _warned
    with _lock:
        if _warned:
            return
        _warned = True
    warnings.warn(_MESSAGE, KyberDeprecationWarning, stacklevel=_CALLER_STACKLEVEL)


def _deprecated_kyber(func):
    """Decorate a Kyber entry point so its first use warns."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        _warn_once()
        return func(*args, **kwargs)

    return wrapper
