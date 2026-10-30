"""The Kyber* classes warn once per process (KyberDeprecationWarning) and
nothing else changes. Counting is done in subprocesses, because the flag is
per process and pytest would otherwise share it across the whole run."""

import json
import os
import subprocess
import sys
import textwrap

import pytest

import pykyber
from pykyber import _deprecation

KYBER_CLASSES = ["Kyber512", "Kyber768", "Kyber1024"]
ENTRY_POINTS = ["new", "from_keys", "encapsulate", "decapsulate"]
MIGRATION_GUIDE_URL = "https://github.com/Zikithezikit/pykyber/blob/main/docs/migration.md"
REPEATS = 3  # uses of every class and entry point per child process
CHILD_TIMEOUT_SECONDS = 120

# Records every warning the child sees, one JSON object per warning on stdout.
# {body} runs under a "record everything" filter so the child reports what is
# really emitted, whatever filters the parent passed with -W.
CHILD_TEMPLATE = textwrap.dedent(
    """
    import json, sys, warnings
    import pykyber
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
    {body}
    print(json.dumps([[w.category.__name__, str(w.message), w.filename] for w in seen]))
    """
)

KYBER_BODY = """
        for _ in range({repeats}):
            for name in {classes!r}:
                cls = getattr(pykyber, name)
                kp = cls()
                res = cls.encapsulate(kp.public_key)
                cls.decapsulate(res.ciphertext, kp.secret_key)
                cls.from_keys(kp.public_key, kp.secret_key)
"""

MLKEM_BODY = """
        for name in ("ML_KEM_512", "ML_KEM_768", "ML_KEM_1024"):
            cls = getattr(pykyber, name)
            kp = cls()
            res = cls.encapsulate(kp.public_key)
            cls.decapsulate(res.ciphertext, kp.secret_key)
            cls.from_keys(kp.public_key, kp.secret_key)
"""


def run_child(body, *flags):
    """Run CHILD_TEMPLATE with body in a fresh interpreter and return its warnings."""
    code = CHILD_TEMPLATE.replace("{body}", textwrap.indent(textwrap.dedent(body), "    "))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONWARNINGS"}
    proc = subprocess.run(
        [sys.executable, *flags, "-c", code],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT_SECONDS,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def kyber_body():
    return KYBER_BODY.format(repeats=REPEATS, classes=KYBER_CLASSES)


@pytest.mark.parametrize("flag", ["always::DeprecationWarning", "default"])
def test_many_uses_warn_exactly_once(flag):
    seen = run_child(kyber_body(), "-W", flag)
    assert [category for category, _, _ in seen] == ["KyberDeprecationWarning"]


def test_import_alone_warns_nothing():
    assert run_child("pass", "-W", "always::DeprecationWarning") == []


def test_ml_kem_never_warns():
    assert run_child(MLKEM_BODY, "-W", "always::DeprecationWarning") == []


def test_message_content():
    ((_, message, _),) = run_child(kyber_body())
    assert "not interoperable" in message
    assert "both sides must switch" in message
    assert "changes the shared secret" in message
    assert MIGRATION_GUIDE_URL in message


def test_library_caller_is_silent_by_default(tmp_path):
    """Python hides DeprecationWarning unless it is attributed to __main__, so a
    call made from an imported module prints nothing under the default filters."""
    (tmp_path / "uses_kyber.py").write_text("import pykyber\npykyber.Kyber768()\n")
    code = f"import sys; sys.path.insert(0, {str(tmp_path)!r}); import uses_kyber"
    env = {k: v for k, v in os.environ.items() if k != "PYTHONWARNINGS"}
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT_SECONDS,
        env=env,
    )
    assert proc.returncode == 0
    assert "KyberDeprecationWarning" not in proc.stderr
    assert proc.stderr == ""


def test_main_caller_is_shown_by_default():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONWARNINGS"}
    proc = subprocess.run(
        [sys.executable, "-c", "import pykyber\npykyber.Kyber768()"],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT_SECONDS,
        env=env,
    )
    assert proc.returncode == 0
    assert "KyberDeprecationWarning" in proc.stderr


def test_warning_is_exported_and_is_a_deprecation_warning():
    assert "KyberDeprecationWarning" in pykyber.__all__
    assert issubclass(pykyber.KyberDeprecationWarning, DeprecationWarning)
    assert not issubclass(pykyber.KyberDeprecationWarning, pykyber.KyberError)


def call_entry_point(cls, entry_point, kp, res):
    """Make one call to a Kyber entry point from this file."""
    if entry_point == "new":
        return cls()
    if entry_point == "from_keys":
        return cls.from_keys(kp.public_key, kp.secret_key)
    if entry_point == "encapsulate":
        return cls.encapsulate(kp.public_key)
    return cls.decapsulate(res.ciphertext, kp.secret_key)


@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
@pytest.mark.parametrize("class_name", KYBER_CLASSES)
def test_warning_is_attributed_to_the_callers_file(class_name, entry_point, monkeypatch):
    cls = getattr(pykyber, class_name)
    monkeypatch.setattr(_deprecation, "_warned", True)  # keep the setup quiet
    kp = cls()
    res = cls.encapsulate(kp.public_key)
    monkeypatch.setattr(_deprecation, "_warned", False)
    with pytest.warns(pykyber.KyberDeprecationWarning) as record:
        call_entry_point(cls, entry_point, kp, res)
    assert len(record) == 1
    assert record[0].filename == __file__
