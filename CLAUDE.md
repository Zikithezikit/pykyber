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

Known baseline (2026-10-30, after WP-4 / #12, WP-5 / #13, WP-6 / #14 and WP-7 / #15 merged): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` and `pytest python/tests` all pass on `dev-v2`, and the legacy golden vectors (#6) are in. The `Kyber*` classes warn once per process on first use (`KyberDeprecationWarning`, counted in subprocess tests), `docs/migration.md` is the Kyber to ML-KEM guide, and the version in `Cargo.toml` and `pyproject.toml` is already 2.0.0 with its changelog entry. `scripts/asm_check.py` (release-assembly check: division and unreviewed conditional branches in the decaps closure for x86_64, aarch64, i686, armv7; reviewed branches live in `scripts/asm_check_allowlist.json`) runs in its own CI job `release assembly check` on a pinned rustc, not in `scripts/check.sh`; rerun it on every toolchain bump and release. `scripts/timing_decaps.py` is the manual dudect-style timing test; results are in `SECURITY.md`. CI (`.github/workflows/CI.yml`) has a `test` job (Linux/macOS/Windows, Python 3.8 and newest) and an `every commit passes` job that runs `scripts/check.sh` over each commit of a PR via `git rebase --exec`; making them required checks on `dev-v2` is a branch-protection setting only the maintainer can change (#7). The clippy lints `needless_range_loop`, `identity_op` and `explicit_counter_loop` are allowed per module in `src/kyber/` because the legacy loops mirror the reference C code; don't add new code that needs them. CI installs the latest stable toolchain, which can be newer than the one on your machine and bring new clippy lints (rustc 1.99 added `chunks_exact_to_as_chunks`, which failed PR #28 although 1.95 was clean), so run clippy with a recent stable before pushing: `rustup toolchain install stable` and `cargo +stable clippy --all-targets -- -D warnings`.

## Architecture

Three layers (the legacy Kyber path; ML-KEM sits beside it, see below):

1. **Rust core `src/kyber/`**: round-3 Kyber (`kem.rs` pre-hashes `m` and puts `H(c)` into the KDF, so it is not ML-KEM). `params.rs` holds constants per level. `kem.rs`/`indcpa.rs`/`polyvec.rs` are copied per level as `_512`, unsuffixed (= 768, `KYBER_K = 3`), and `_1024` functions. `api.rs` is a safe Rust API for 768 only. `verify.rs` has the constant-time compare/`cmov`; `error.rs` has `KyberError`; secrets use `zeroize`.
2. **PyO3 boundary `src/lib.rs`**: private `#[pyfunction]`s (`_keypair_{512,768,1024}`, `_encapsulate_*`, `_decapsulate_*`, plus unsuffixed 768 aliases) in module `pykyber._pykyber` (`module-name` in `pyproject.toml`; the Python source root is `python/`). Errors are raised as a generic `PyException`. Key generation uses `rand::thread_rng()`.
3. **Python wrapper `python/pykyber/`**:
   - `_kyber.py` has the `Kyber512/768/1024` classes (an instance is a keypair; static `encapsulate`/`decapsulate`/`from_keys`).
   - `_types.py` has `Keypair`/`EncapsulationResult` (tuple-unpackable, hex/b64/dict).
   - `_validation.py` has decorators that size-check inputs before calling Rust.
   - `__init__.py` wraps the `_pykyber` functions with those validators and sets `__all__`.

ML-KEM (WP-3 to WP-5, merged): `src/mlkem/` is the FIPS 203 core, generic over `K` (`params.rs`, `kpke.rs`, `kem.rs`, `check.rs` for the section 7.2/7.3 checks, `ct.rs` for the constant-time reject select); it shares only audited primitives with `src/kyber/` (the list is in the module docs of `src/mlkem/mod.rs`). `src/pymlkem.rs` holds the private PyO3 functions `_mlkem_{512,768,1024}_{keygen,encaps,decaps}`; it calls only the public functions of `mlkem::kem`, never `kem::acvp` or the `acvp` feature, and raises the `KyberError` subclasses defined in `python/pykyber/_error.py` (looked up by name at raise time). `python/pykyber/_mlkem.py` has `ML_KEM_512/768/1024` (one base class, three thin subclasses); `MlKemKeypair` and `MlKemEncapsulationResult` in `_types.py` are deliberately not subclasses of the Kyber types, and `_validation.py` refuses Kyber objects in ML-KEM methods by type. Tests: `python/tests/test_mlkem*.py`; the ACVP files come from `scripts/fetch_vectors.py` and a missing file fails the run.

Official vectors (WP-4, merged): the manifest pins ACVP, C2SP CCTV and Wycheproof files by commit and SHA-256 (`tests/vectors/manifest.json`); the Rust side is `src/mlkem/{acvp,cctv,wycheproof,differential}_tests.rs` and the Python side `python/tests/test_mlkem_{acvp,cctv,wycheproof}.py`. Two things to know. The CCTV `unluckysample` files and accumulated hashes were made with the pre-final `G(d)` (no `k` byte), so `cctv_tests.rs` builds those keys with `kpke::keygen_expanded` and the old derivation; the final one is covered by ACVP, and the CCTV tests are not evidence about `G(d || k)`. The differential test compares against the dev-only `ml-kem` 0.3.3 crate (needs rustc 1.87+); `flate2` is a dev-dependency for the gzip modulus files. `cargo test` takes about a minute because the 10 000-run CCTV hashes run in the dev profile; `PYKYBER_CCTV_RUNS=1000000 cargo test --release --lib accumulated` runs the million-run hashes (about 8 minutes).

Other locations: docs are in `docs/` (`api.md`, `index.md`), the benchmark is in `performance-tests/`, and `CHANGELOG.md` is maintained by hand.

`.opencode/` (another agent tool's notes, including a `SECURITY.md` log of past fixes: constant-time division removal, Kyber-512 η1=3) is **gitignored**, so other contributors don't have it. PLAN-2.0 WP-0 migrates that log to a root `SECURITY.md`.

## Repo state

- GitHub `Zikithezikit/pykyber`. The default branch is still `dev`; `main` exists. **2.0 work happens on `dev-v2`**: branch from it and open PRs against it, never `main` or `dev`. The maintainer merges `dev-v2` into `main` once at the end, and `main` then becomes the default.
- Issues #4–#18 are the 2.0 work packages, all sub-issues of #3 in milestone `2.0.0`, with "blocked by" links set.
- Tags are `v0.1.0`…`v0.2.0` and `v1.0.5`. The legacy golden vectors should come from `v1.0.5` / the PyPI 1.0.5 wheel.
- Commit style is Conventional Commits (`fix:`, `feat:`, `security:`).
