# Using PyKyber in a company

What a security, legal or platform team usually asks before approving a dependency, with the facts as they stand. If a statement here is not true of the release you run, the release is wrong, so tell us.

## License

MIT OR Apache-2.0, at your option ([LICENSE-MIT](../LICENSE-MIT), [LICENSE-APACHE](../LICENSE-APACHE)). Both are permissive and allow commercial and closed-source use. Apache-2.0 includes an explicit patent grant for contributions. Version 1.0.5 was released under the Unlicense, and it still is.

## What it depends on

- Python: no runtime dependencies. The wheel is a single compiled extension plus a small pure-Python wrapper.
- Rust, compiled into the wheel: `pyo3`, `zeroize`, `rand` and `rand_core`. All cryptography (Keccak/SHAKE, the NTT, ML-KEM itself) is in this repository, with no third-party crypto crate.
- Dev-only crates (test vectors, a reference ML-KEM for differential tests) are never linked into the wheel.
- `Cargo.lock` is committed and CI runs the Rust tests with `--locked`, so a given commit resolves to the same dependency versions.

## Platforms

Python 3.8 or newer (one abi3 wheel per platform). CI builds wheels for Linux (glibc and musl; x86_64, x86, aarch64, armv7, s390x, ppc64le), macOS (Intel and Apple silicon), Windows (x64, x86, arm64) and Android, plus an sdist. Tests run on Linux, macOS and Windows.

## Supply chain

- Release wheels are built in GitHub Actions and carry a build-provenance attestation (`actions/attest-build-provenance`). Verify a downloaded file with `gh attestation verify <wheel> --repo Zikithezikit/pykyber`.
- Pin the version and, if you can, the hash: `pip install --require-hashes -r requirements.txt` with `pykyber==<version> --hash=sha256:...`.
- Building from the sdist needs a stable Rust toolchain and `maturin`.

## Security status, stated plainly

- Tested against the official NIST ACVP vectors, the C2SP CCTV vectors and the Wycheproof vectors, and against an independent implementation in a development-only differential test. CI runs these on every commit.
- Not independently audited. Not FIPS 140-3 (CMVP) validated, so it cannot by itself satisfy a requirement for a validated module.
- No constant-time claim. Secret-dependent branches and divisions were reviewed and removed, but that is evidence, not proof. [SECURITY.md](../SECURITY.md) lists what was checked, what was fixed and what is still open (for example stack copies left by the Keccak permutation).
- Secrets are returned to Python as immutable `bytes`, which cannot be wiped from memory.
- Key and ciphertext inputs are length- and format-checked (including the FIPS 203 section 7.2 and 7.3 checks) before any secret-dependent work, and errors are typed (`KyberError` and subclasses). Keys come from the operating system random generator, and a failure is raised, never retried with a weaker source.

If a standard or contract requires an audited or validated module, treat PyKyber as an input to your own assessment, not a replacement for one.

## Reporting and response

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md). PyKyber is independently maintained and unfunded, so there is no support contract or response-time guarantee: reports are acknowledged on a best-effort basis, aiming for a few days, and disclosure is coordinated. Fixes are logged in [CHANGELOG.md](../CHANGELOG.md) and in the findings log.

## Versioning and deprecation

- Version numbers follow semantic versioning, and breaking changes are listed in the changelog.
- The legacy `Kyber*` classes are frozen: their output is checked byte for byte against 1.0.5 in CI, and they warn on first use. They are not interoperable with ML-KEM; see the [migration guide](migration.md).
- A hybrid construction (for example X25519 combined with ML-KEM) is not provided. Build it on top if your policy requires one.
