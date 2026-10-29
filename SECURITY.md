# Security Policy

pykyber implements cryptographically-sensitive code, and its users run it to
protect secrets. Please treat potential weakness in it accordingly.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private
vulnerability reporting, which is enabled on this repository:

> <https://github.com/Zikithezikit/pykyber/security/advisories/new>

(reachable from the repo's Security tab, "Report a vulnerability").

What helps us triage fastest:

- A clear description of the weakness and your assessment of impact.
- Affected version(s) and/or commit, and which parameter set is involved
  (`Kyber512/768/1024`, from 2.0 on also `ML_KEM_*`).
- A minimal reproduction (script or test patch), passing random keys.
  Please **do not paste real key material, seeds, or shared secrets** into
  the report.
- For timing findings: how you demonstrated or estimated the leak (code
  path, compiler/optimizer version, measurement setting).
- A suggested fix, if you have one.

## Response and disclosure

- This is an independently maintained, unfunded, public-domain project: we
  acknowledge reports on a best-effort basis, aiming for a few days.
- We prefer coordinated disclosure. We will keep you informed, credit you in
  the advisory if you wish (including anonymously is fine), and publish the
  advisory once a fix ships.
- We will handle timing-attack claims by the standard in this repo: suspect
  secret-dependent behavior must be backed by generated assembly or a
  dynamic measurement, not just code reading.

## Scope

In scope: the published `pykyber` package and everything under `src/`:
timing side channels, secret zeroization and memory hygiene, input
validation, randomness source and failure handling, panics reachable from
Python, cryptographic correctness against the reference documents (round-3
CRYSTALS-Kyber for the `Kyber*` classes, FIPS 203 for the `ML_KEM_*`
classes), and wrong-key-family/parameter confusion in the Python API.

Out of scope: issues only exploitable by the party that already controls
the key or the machine; availability of the benchmark harness in
`performance-tests/`; breakages of third-party libraries that merely import
pykyber; social engineering.

## Findings log

Audits and hardening work performed on this codebase are logged here so the
history of known issues and their resolutions stays visible to every
contributor. Ongoing 2.0 security work is planned in `PLAN-2.0.md`
(WP-8/WP-9) and tracked issue-by-issue.

The log below was migrated on 2026-10-29 from
`.opencode/SECURITY.md`, a maintainer/agent working log that was
gitignored and therefore invisible to other contributors. The item content
is unchanged; each item is fixed in the current release.

# Security Audit Notes (migrated log)

This log tracks identified security concerns, cryptographic vulnerabilities,
and NIST compliance issues within the `pykyber` implementation.

## 1. Timing Side-Channel Vulnerabilities [RESOLVED]

### Non-Constant Time Arithmetic
The implementation used the standard division operator (`/`) on sensitive data in several performance-critical functions. 
- **Affected Functions:** `poly_compress`, `poly_tomsg`, `polyvec_compress`, etc.
- **Resolution:** Replaced all divisions with constant-time modular arithmetic using high-precision reciprocals and bit-shifts.
- **Status:** FIXED.

## 2. Weakened Security (Kyber-512) [RESOLVED]

### Incorrect Noise Distribution
The implementation hardcoded the noise parameter `KYBER_ETA1` to `2` for all security levels. 
- **Affected Constants:** `KYBER_512_K`, `KYBER_ETA1` in `src/kyber/params.rs`.
- **Resolution:** Updated `ETA1` to 3 for Kyber-512 and implemented `cbd3` noise generation.
- **Status:** FIXED.

## 3. NIST Non-Compliance (Kyber-1024) [RESOLVED]

### Incorrect Compression Parameters
The implementation used incorrect compression parameters for Kyber-1024 ($d_u=10, d_v=4$ instead of $11, 5$).
- **Resolution:** Corrected compression parameters and updated byte size constants. Implemented variant-specific compression/decompression logic for Kyber-1024.
- **Status:** FIXED.

## 4. Memory Safety [RESOLVED]

### Secret Material Persistence
Sensitive data could persist in memory due to Python's garbage collection and Rust's default drop behavior.
- **Resolution:** Integrated the `zeroize` crate. Implemented automatic zeroing on drop for `Poly`, `Polyvec`, `Keypair`, and `KeccakState` structs. Manually zeroed temporary local buffers in cryptographic functions.
- **Status:** FIXED.

## 5. Logic Errors in Keccak Implementation [RESOLVED]

### Buffer Overflow in Squeeze
The `keccak_squeeze` function used `store_u64` blindly, which could write past the end of the output buffer if the requested length was not a multiple of 8.
- **Resolution:** Refactored `keccak_squeeze` to handle arbitrary lengths safely while maintaining data-independent timing.
- **Status:** FIXED.

## 6. Integer Overflow Hardening [RESOLVED]

### NTT Butterfly Bounds
The 7-layer Number Theoretic Transform (NTT) used `i16` intermediate values. While mathematically bounded, it was close to the limit.
- **Resolution:** Hardened NTT butterfly logic using explicit `i32` arithmetic and updated `barrett_reduce` to handle a wider input range.
- **Status:** FIXED.
