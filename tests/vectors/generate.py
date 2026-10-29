#!/usr/bin/env python3
"""Capture the legacy Kyber golden vectors from pykyber v1.0.5.

The output file ``tests/vectors/legacy-kyber-v1.0.5.json`` is APPEND-ONLY:
it is the byte-frozen record of what pykyber 1.0.5 produced, and no test is
ever allowed to be fixed by regenerating or editing it. This script is the
only supported way to (re)build it, and it only ever reads from v1.0.5
artifacts, never from the current working tree:

1. Download the pinned pykyber==1.0.5 wheel from PyPI, verify its SHA-256
   against the pin below, and install it into a throwaway venv.
2. Create a git worktree of tag v1.0.5, copy ``gen_capture.rs`` (sibling of
   this file) into its ``examples/`` directory, and run it there with
   ``cargo run --release --example gen_capture``.
3. Ask the v1.0.5 Python layer for seeded keypairs and decapsulation through
   ``KyberK(seed=...)`` / ``KyberK.decapsulate``.
4. Assert that every 1.0.5 layer agrees (Python seeded keygen == Rust seeded
   keygen; Python decaps == Rust decaps == Rust seeded-encaps shared secret),
   then write the merged vectors.

Usage::

    python3 tests/vectors/generate.py [--force] [--keep-worktree]

The default output path is refused if it already exists, unless ``--force``
is passed; rerunning with ``--force`` is a deliberate re-capture from the
v1.0.5 artifacts, never a way to make a failing test pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

PARAM_SETS = ("512", "768", "1024")

# Seed inputs: fixed so the capture is reproducible from the artifacts alone.
# d || z (64 bytes) seeds keygen; enc_seed (32 bytes) seeds encapsulation.
KEY_SEEDS = [bytes(range(64)), bytes(64), bytes(range(64, 128))]
ENC_SEEDS = [bytes(range(32)), bytes(32), bytes(range(32, 64))]

# Capture basis, pinned so anyone can re-derive the exact vectors.
PYPI_WHEEL = "pykyber-1.0.5-cp38-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
PYPI_WHEEL_SHA256 = "0bd5d644e7783f4cf3bfffaa04fa42f96f43a68b6954e5927bc8bd94a2f2592a"
PYPI_VERSION = "pykyber==1.0.5"
RUST_TAG = "v1.0.5"

# (public_key, secret_key, ciphertext, shared_secret) byte lengths, checked
# against every capture before it is written out; a mismatch means the
# artifacts are not what we think they are and the capture fails loudly.
EXPECTED_SIZES = {k: tuple(v) for k, v in json.loads(__SIZES_JSON__).items()}

DEFAULT_OUT = REPO_ROOT / "tests" / "vectors" / "legacy-kyber-v1.0.5.json"

PY_CAPTURE = r"""import json, sys
import pykyber

CLASSES = {"512": pykyber.Kyber512, "768": pykyber.Kyber768, "1024": pykyber.Kyber1024}
SIZES = {k: tuple(v) for k, v in json.loads(__SIZES_JSON__).items()}

def fail(msg):
    sys.stderr.write("capture mismatch: %s\n" % msg)
    sys.exit(2)

def vectors_from_stdin():
    for line in sys.stdin:
        line = line.strip()
        if line:
            yield json.loads(line)

for rust in vectors_from_stdin():
    ps = rust["parameter_set"]
    seed = bytes.fromhex(rust["key_seed_hex"])
    ct = bytes.fromhex(rust["ciphertext_hex"])
    sk = bytes.fromhex(rust["keypair_secret_key_hex"])
    pk = bytes.fromhex(rust["keypair_public_key_hex"])
    sizes = SIZES[ps]

    k = CLASSES[ps](seed=seed)
    py_pk, py_sk = k.public_key, k.secret_key
    if (len(py_pk), len(py_sk)) != sizes[:2]:
        fail("unexpected key lengths for %s" % ps)
    if py_pk != pk or py_sk != sk:
        fail("python seeded keygen != rust seeded keygen for %s" % ps)

    py_ss = CLASSES[ps].decapsulate(ct, sk)
    if len(py_ss) != sizes[3]:
        fail("unexpected shared secret length for %s" % ps)
    if py_ss != bytes.fromhex(rust["shared_secret_encaps_hex"]):
        fail("python decaps != rust seeded encaps shared secret for %s" % ps)
    if bytes.fromhex(rust["shared_secret_decaps_hex"]) != py_ss:
        fail("python decaps != rust decaps for %s" % ps)

    print(json.dumps({
        "parameter_set": ps,
        "key_seed_hex": rust["key_seed_hex"],
        "enc_seed_hex": rust["enc_seed_hex"],
        "keypair_public_key_hex": py_pk.hex(),
        "keypair_secret_key_hex": py_sk.hex(),
        "ciphertext_hex": ct.hex(),
        "shared_secret_encaps_hex": rust["shared_secret_encaps_hex"],
        "shared_secret_decaps_hex": py_ss.hex(),
    }), flush=True)
"""


def run(cmd, **kwargs):
    kwargs.setdefault("check", True)
    return subprocess.run(cmd, **kwargs)


def git(args, cwd=None):
    result = subprocess.run(["git"] + args, cwd=cwd or REPO_ROOT, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def prepare_worktree(path: Path) -> str:
    """Create (or reuse) a worktree pinned to tag v1.0.5; return its commit."""
    tag_commit = git(["rev-parse", RUST_TAG + "^{commit}"])
    if path.exists():
        head = git(["rev-parse", "HEAD"], cwd=path)
        if head != tag_commit:
            raise SystemExit(
                f"worktree {path} exists but is at {head}, expected {tag_commit} "
                f"({RUST_TAG}). Move it away or pass a different --worktree."
            )
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "worktree", "add", str(path), RUST_TAG])
    return tag_commit


def fetch_and_install_wheel(tmp: Path) -> Path:
    """Download the pinned wheel, verify its hash, install it into a venv."""
    wheel_dir = tmp / "wheel"
    wheel_dir.mkdir()
    run([sys.executable, "-m", "pip", "download", PYPI_VERSION, "--no-deps",
         "--only-binary=pykyber", "-d", str(wheel_dir), "-q"])
    wheel = wheel_dir / PYPI_WHEEL
    if not wheel.exists():
        raise SystemExit(
            f"pip did not fetch the pinned wheel {PYPI_WHEEL}; "
            f"got {sorted(p.name for p in wheel_dir.iterdir())}"
        )
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if digest != PYPI_WHEEL_SHA256:
        raise SystemExit(
            f"wheel sha256 mismatch: got {digest}, expected {PYPI_WHEEL_SHA256}"
        )

    venv = tmp / "venv"
    run([sys.executable, "-m", "venv", str(venv)])
    run([str(venv / "bin" / "pip"), "install", "--no-index", "-q", str(wheel)])
    python = str(venv / "bin" / "python")
    run([python, "-c", "import pykyber"], stdout=subprocess.DEVNULL)
    return venv


def run_rust_capture(worktree: Path, prompts) -> list[dict]:
    """Copy gen_capture.rs into the worktree and run it there."""
    examples = worktree / "examples"
    examples.mkdir(exist_ok=True)
    shutil.copy(HERE / "gen_capture.rs", examples / "gen_capture.rs")
    stdin = "\n".join(prompts) + "\n"
    proc = run(["cargo", "run", "--quiet", "--release", "--example", "gen_capture"],
               cwd=worktree, input=stdin, text=True, capture_output=True)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def run_python_capture(venv: Path, rust_vectors) -> list[dict]:
    """Cross-check the Python side of v1.0.5 against the Rust-side capture."""
    capture_py = venv.parent / "py_capture.py"
    script = PY_CAPTURE.replace("__SIZES_JSON__", repr(json.dumps(EXPECTED_SIZES)))
    capture_py.write_text(script, encoding="ascii")
    stdin = "".join(json.dumps(v) + "\n" for v in rust_vectors)
    proc = run([str(venv / "bin" / "python"), str(capture_py)], input=stdin,
               text=True, capture_output=True)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def build_meta(tag_commit: str) -> dict:
    try:
        rustc = run(["rustc", "--version"], stdout=subprocess.PIPE, text=True,
                    check=False).stdout.strip()
        if not rustc:
            rustc = "unknown"
    except OSError:
        rustc = "unknown"
    return {
        "description": (
            "Golden vectors of legacy Kyber (round-3) as produced by pykyber "
            "v1.0.5. This file is append-only: never regenerate or edit it to "
            "make a test pass. If current code disagrees with these bytes, the "
            "current code is wrong. The only supported generator is "
            "tests/vectors/generate.py, which reads solely from the pinned "
            "PyPI wheel and the v1.0.5 git tag, never from current code."
        ),
        "append_only": True,
        "generator": "tests/vectors/generate.py",
        "captured_at": date.today().isoformat(),
        "pypi_package": PYPI_VERSION,
        "pypi_wheel": PYPI_WHEEL,
        "pypi_wheel_sha256": PYPI_WHEEL_SHA256,
        "rust_tag": RUST_TAG,
        "rust_tag_commit": tag_commit,
        "rust_build_profile": "release",
        "rustc_version": rustc,
        "python_version": platform.python_version(),
        "path_families": {
            "keypair": "crypto_kem_keypair(pk, sk, rng, Some((d, z))) at tag "
                       "v1.0.5; Python KyberK(seed=d||z) asserted equal",
            "encapsulation": "crypto_kem_enc(ct, ss, pk, rng, Some(r_seed)) at "
                             "tag v1.0.5 (32-byte r seed); Python encapsulate "
                             "is randomized and not golden",
            "decapsulation": "crypto_kem_dec(ss, ct, sk) at tag v1.0.5, "
                             "recorded via the Python KyberK.decapsulate() "
                             "wrapper and asserted equal to the Rust output",
        },
    }


def default_worktree() -> Path:
    """Worktree root under the platform temp dir; machine-neutral by design."""
    return Path(tempfile.gettempdir()) / "wp6" / "v105-wt"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--worktree", type=Path, default=None)
    parser.add_argument("--keep-worktree", action="store_true",
                        help="keep the v1.0.5 worktree (default: remove it)")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing output file")
    args = parser.parse_args()
    if args.worktree is None:
        args.worktree = default_worktree()

    if args.out.exists() and not args.force:
        raise SystemExit(
            f"{args.out} exists. This file is append-only; rerunning with "
            "--force is a deliberate re-capture from the v1.0.5 artifacts."
        )

    tmp = Path(tempfile.mkdtemp(prefix="pykyber-golden-"))
    try:
        tag_commit = prepare_worktree(args.worktree)
        venv = fetch_and_install_wheel(tmp)

        prompts = []
        for ps in PARAM_SETS:
            for key_seed, enc_seed in zip(KEY_SEEDS, ENC_SEEDS):
                prompts.append(f"{ps} {key_seed.hex()} {enc_seed.hex()}")

        rust_vectors = run_rust_capture(args.worktree, prompts)
        if len(rust_vectors) != len(prompts):
            raise SystemExit(
                f"capture produced {len(rust_vectors)} vectors, expected {len(prompts)}"
            )
        for v in rust_vectors:
            sizes = EXPECTED_SIZES[v["parameter_set"]]
            got = (len(bytes.fromhex(v["keypair_public_key_hex"])),
                   len(bytes.fromhex(v["keypair_secret_key_hex"])),
                   len(bytes.fromhex(v["ciphertext_hex"])),
                   len(bytes.fromhex(v["shared_secret_encaps_hex"])))
            if got != sizes:
                raise SystemExit(
                    f"unexpected captured lengths for {v['parameter_set']}: "
                    f"{got} != {sizes}"
                )

        vectors = run_python_capture(venv, rust_vectors)
        if len(vectors) != len(rust_vectors):
            raise SystemExit(
                f"python capture produced {len(vectors)} vectors, expected {len(rust_vectors)}"
            )

        document = {"meta": build_meta(tag_commit), "vectors": vectors}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
        print(f"wrote {args.out} with {len(vectors)} vectors "
              f"({len(KEY_SEEDS)} seeds x {len(PARAM_SETS)} parameter sets)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if not args.keep_worktree and args.worktree.exists():
            subprocess.run(["git", "worktree", "remove", "--force", str(args.worktree)],
                           cwd=REPO_ROOT, check=False)

    return 0


if __name__ == "__main__":
    sys.exit(main())
