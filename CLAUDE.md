# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## What this is

PyKyber: a Python package (`pykyber`) exposing round-3 CRYSTALS-Kyber, implemented from scratch in Rust (its own Keccak/FIPS 202, NTT, etc.; no external crypto crate) and bound with PyO3 + maturin (abi3, Python ≥3.8). Unlicense. Current version 1.0.5; the version lives in both `Cargo.toml` and `pyproject.toml`, so keep them in sync.

Active work is 2.0 (issue #3): add ML-KEM (FIPS 203) beside the legacy Kyber classes. The plan, the work packages and the verified spec facts are in `PLAN-2.0.md`.

## Commands

```bash
maturin develop                 # build the Rust extension into .venv; required before Python tests
make dev-build                  # clean + maturin develop + regenerate python/pykyber/_pykyber.pyi (pyo3-stubgen)
make benchmark                  # .venv/bin/python performance-tests/benchmark.py

cargo test --no-fail-fast       # Rust tests (src unit tests + tests/*.rs)
cargo test --test api_kem       # one Rust integration test file
cargo test <name>               # single Rust test by name
cargo clippy --all-targets -- -D warnings   # clean since #25; keep it that way

pytest python/tests             # Python tests; `pip install -r requirements-dev.txt` for pytest + maturin
scripts/check.sh                # the full gate: fmt, clippy -D warnings, cargo test, maturin develop, pytest
pytest python/tests/test_kyber.py::test_kyber768_new_api
```

`make clean` deletes `target/`, the built `.so`, and the `.pyi`; rebuild afterwards.

Known baseline (2026-10-30): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` and `pytest python/tests` all pass on `dev-v2`, and the legacy golden vectors (#6) are in. CI (`.github/workflows/CI.yml`) has a `test` job (Linux/macOS/Windows, Python 3.8 and newest) and an `every commit passes` job that runs `scripts/check.sh` over each commit of a PR via `git rebase --exec`; making them required checks on `dev-v2` is a branch-protection setting only the maintainer can change (#7). The clippy lints `needless_range_loop`, `identity_op` and `explicit_counter_loop` are allowed per module in `src/kyber/` because the legacy loops mirror the reference C code; don't add new code that needs them.

## Architecture

Three layers:

1. **Rust core `src/kyber/`**: round-3 Kyber (`kem.rs` pre-hashes `m` and puts `H(c)` into the KDF, so it is not ML-KEM). `params.rs` holds constants per level. `kem.rs`/`indcpa.rs`/`polyvec.rs` are copied per level as `_512`, unsuffixed (= 768, `KYBER_K = 3`), and `_1024` functions. `api.rs` is a safe Rust API for 768 only. `verify.rs` has the constant-time compare/`cmov`; `error.rs` has `KyberError`; secrets use `zeroize`.
2. **PyO3 boundary `src/lib.rs`**: private `#[pyfunction]`s (`_keypair_{512,768,1024}`, `_encapsulate_*`, `_decapsulate_*`, plus unsuffixed 768 aliases) in module `pykyber._pykyber` (`module-name` in `pyproject.toml`; the Python source root is `python/`). Errors are raised as a generic `PyException`. Key generation uses `rand::thread_rng()`.
3. **Python wrapper `python/pykyber/`**:
   - `_kyber.py` has the `Kyber512/768/1024` classes (an instance is a keypair; static `encapsulate`/`decapsulate`/`from_keys`).
   - `_types.py` has `Keypair`/`EncapsulationResult` (tuple-unpackable, hex/b64/dict).
   - `_validation.py` has decorators that size-check inputs before calling Rust.
   - `__init__.py` wraps the `_pykyber` functions with those validators and sets `__all__`.

Other locations: docs are in `docs/` (`api.md`, `index.md`), the benchmark is in `performance-tests/`, and `CHANGELOG.md` is maintained by hand.

`.opencode/` (another agent tool's notes, including a `SECURITY.md` log of past fixes: constant-time division removal, Kyber-512 η1=3) is **gitignored**, so other contributors don't have it. PLAN-2.0 WP-0 migrates that log to a root `SECURITY.md`.

## Repo state

- GitHub `Zikithezikit/pykyber`. The default branch is still `dev`; `main` exists. **2.0 work happens on `dev-v2`**: branch from it and open PRs against it, never `main` or `dev`. The maintainer merges `dev-v2` into `main` once at the end, and `main` then becomes the default.
- Issues #4–#18 are the 2.0 work packages, all sub-issues of #3 in milestone `2.0.0`, with "blocked by" links set.
- Tags are `v0.1.0`…`v0.2.0` and `v1.0.5`. The legacy golden vectors should come from `v1.0.5` / the PyPI 1.0.5 wheel.
- Commit style is Conventional Commits (`fix:`, `feat:`, `security:`).
