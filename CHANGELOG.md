# Changelog

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
