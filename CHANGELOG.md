# Changelog

## Unreleased

- Docs: the README is shorter and rewritten in plain prose. The benchmark (`performance-tests/benchmark.py`) now times `ML_KEM_*` as well as the Kyber classes on a release build, writes `results.json`, and draws two charts (`latency.png`, `ml_kem_vs_kyber.png`) that replace the four old ones. The old README figures were for the Kyber classes only. `make benchmark` builds the release extension first, and the chart dependency is in `performance-tests/requirements.txt`.

- Security pass over the legacy Kyber code (issue #18): the random bytes for `Kyber*` key generation and encapsulation now come from the operating system generator (`OsRng`) instead of `thread_rng()`, and a failure of that generator is raised as `RandomnessError` (a `KyberError`) instead of panicking or being retried with a weaker source. Seeded paths and all Kyber output are unchanged.
- Security pass over the legacy Kyber code (issue #18), continued: optimization barriers in `poly_frommsg`, `verify` and `cmov`; decapsulation and the PRF noise buffers are wiped on every exit; secrets returned to Python are wiped on the Rust side; the Rust keypair and encapsulation functions check buffer lengths; `rand` is 0.8.6 in `Cargo.lock`. The findings, the CVE and paper table and the two decisions not to fix (Compress_11, Keccak stack spills) are in `SECURITY.md`. Kyber output is unchanged.
- Behavior change, `Kyber512/768/1024.from_keys` (issue #18): it now raises `KyberError` when the public key is not the copy stored inside the secret key (a round-3 Kyber secret key is `sk_pke || pk || H(pk) || z`). Before, any public key and secret key of the right sizes were accepted, so `Kyber768.from_keys(a.public_key, b.secret_key)` built a keypair whose `decapsulate` silently returned a different secret than `encapsulate` had produced. A key pair that matches is accepted as before, and a wrong-size key keeps its existing size error. `ML_KEM_*.from_keys` is not changed.

## v2.0.0

Planned release; not tagged or published yet. Adds ML-KEM (FIPS 203) beside the legacy Kyber classes, which are deprecated. Kyber output is unchanged from 1.0.5. Kyber (round 3) and ML-KEM are not interoperable, so both sides of a connection must switch; see `docs/migration.md`.

- 2.0 development: repo setup (issue #4), including CI on pushes to `dev-v2`, new `CONTRIBUTING.md`, root `SECURITY.md` (vulnerability-reporting policy + migrated security findings log), PR and issue templates, `CODEOWNERS` routing `src/` and `SECURITY.md` to the maintainer for review, and PR-description rules for agents in AGENTS.md (plain prose, ASCII-checked post text, REST fallback).
- Legacy freeze (issue #6): golden vectors capture the byte output of pykyber v1.0.5 (append-only `tests/vectors/legacy-kyber-v1.0.5.json`, with the generator); Rust and Python tests fail on any change to seeded keygen, seeded encapsulation, or decapsulation output.
- CI (issue #7): a `test` job on Linux, macOS and Windows (oldest and newest Python) runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --locked`, `maturin develop` and `pytest`; a `commits` job re-runs them on every commit of a PR via `git rebase --exec scripts/check.sh`. `requirements-dev.txt` declares maturin and pytest; wheel release now waits for `test`.
- ML-KEM (issue #13): new classes `ML_KEM_512`, `ML_KEM_768` and `ML_KEM_1024` (FIPS 203) with the same shape as `Kyber*` (an instance is a keypair; static `encapsulate`, `decapsulate`, `from_keys`; hex/b64/dict; tuple unpacking). A 64-byte seed `d || z` gives deterministic keys and is exposed as `.seed` only for such keypairs. ML-KEM methods refuse `Kyber*` objects by type (`AlgorithmMismatchError`); raw bytes cannot be told apart. New `KyberError` subclasses: `InvalidInputError`, `InvalidEncapsulationKeyError`, `InvalidDecapsulationKeyError`, `RandomnessError`, `DecapsulationError`, `AlgorithmMismatchError`. The Kyber classes are unchanged.
- Kyber deprecation (issue #14): the first use of any `Kyber512/768/1024` entry point (constructor, `from_keys`, static `encapsulate` or `decapsulate`) emits one `KyberDeprecationWarning` (a `DeprecationWarning` subclass, exported from `pykyber`) per process. Importing does not warn, `ML_KEM_*` never warns, and Kyber output is unchanged. Python shows `DeprecationWarning` by default only when it is attributed to `__main__`; run with `-W default::DeprecationWarning` or call `warnings.simplefilter` to see it elsewhere.
- Docs (issue #15): the README quick start, `docs/api.md` and `docs/index.md` use `ML_KEM_768` (NIST's default parameter set, FIPS 203 section 8), the Kyber classes are documented as deprecated, and the new `docs/migration.md` explains the move from Kyber to ML-KEM. The version is 2.0.0 in `Cargo.toml` and `pyproject.toml`.

## v1.0.5

- CI: add Android wheel builds (aarch64-linux-android, armv7-linux-androideabi, x86_64-linux-android × Python 3.8–3.14) — proper Termux support via PEP 738 android platform tags
- CI: remove redundant termux job (built manylinux aarch64/armv7, already covered by linux job; not Termux-compatible)

## v1.0.3

- CI: add PyPy 3.11 setup step to restore PyPy wheel builds

## v1.0.2

- chore: bump version to v1.0.2

## v1.0.1

Fix PyPI classifier for Unlicense (use `License :: Public Domain`).

## v1.0.0

First stable release. Public domain (Unlicense).

### Features
- Kyber-512, Kyber-768, Kyber-1024 post-quantum KEM
- Object-oriented Python API (`Kyber512`, `Kyber768`, `Kyber1024` classes)
- Static methods for encapsulate/decapsulate without a keypair instance
- Deterministic key generation from 64-byte seed
- Serialization: hex, base64, dict for both `Keypair` and `EncapsulationResult`
- Tuple unpacking for `Keypair` → `(pk, sk)` and `EncapsulationResult` → `(ct, ss)`
- Input validation with clear `KyberError` messages

### Security
- Constant-time arithmetic to mitigate timing side-channels
- Corrected Kyber-512 noise distribution (ETA1=3)
- NIST FIPS-203 compliant Kyber-1024 compression parameters (du=11, dv=5)
- Secret material zeroed on drop via `zeroize` crate
- Safe Keccak squeeze (no buffer overruns)
- Hardened NTT butterfly bounds

### Performance
| Variant | Keypair | Encapsulate | Decapsulate |
|---------|---------|-------------|-------------|
| Kyber-512 | 0.44 ms | 0.58 ms | 0.71 ms |
| Kyber-768 | 0.76 ms | 0.90 ms | 1.08 ms |
| Kyber-1024 | 1.08 ms | 1.35 ms | 1.55 ms |

## v0.2.0

- Merge security hardening and deterministic key feature branch
- Memory zeroing and cryptographic primitive hardening
- Deterministic key generation and serialization utilities

## v0.1.7

- Version bump (pre-security-hardening)

## v0.1.6

- New decapsulate feature
- Stress tests and performance graphs

## v0.1.5

- Error handling section in README

## v0.1.4

- Better Python file structure
- More verbose error messages
- Additional panic tests and error handling

## v0.1.3

- LSP syntax support (`.pyi` stubs)

## v0.1.2

- Python 3.8+ support via `abi3`
- Termux (aarch64, armv7) wheel builds

## v0.1.1

- Python 3.8+ support with `abi3`

## v0.1.0

- Initial release to PyPI
- Basic Kyber-768 support
