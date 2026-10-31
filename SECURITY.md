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

- This is an independently maintained, unfunded, open-source project: we
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
contributor. Ongoing 2.0 security work is tracked issue-by-issue.

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

# Legacy Kyber security pass (issue #18, WP-9)

Audit and fixes for the round-3 `Kyber*` code, done on 2026-10-30 on branch
`wp9-legacy-security`. The result is evidence, not a proof, and this was done
by the project's own tooling, not by a third party.

Method and limits. Assembly was read from release builds (`opt-level = 3`,
one codegen unit) of rustc 1.95.0 with `llvm-objdump`, for x86_64 and aarch64
(and i686 and armv7 for the division scan). One compiler version, one flag set
and a disassembly show what that compiler did; they do not show that another
compiler, flag set or CPU will do the same, and nothing in this repo guarantees
constant time. The barriers below (`core::hint::black_box`) are best effort.
There is no dynamic timing test for the legacy code (that is WP-8, not merged).
Memory hygiene is limited to what safe Rust can do: moves and register spills
leave copies that cannot be wiped without `unsafe`, and every secret that
crosses into Python becomes a Python `bytes` object that cannot be wiped.

No finding is High or above.

## 7. `poly_frommsg` mask (SEC-001, Low, hardened)

`poly_frommsg` builds `-(bit)` from a message bit, the pattern behind
CVE-2024-37880 ("Clangover"). In the release builds checked here (rustc 1.95,
x86_64 and aarch64) it was vectorized with no branch on message bits, so the
leak was not observed. The bit and the mask now go through `black_box`.
Disassembly after the change: the only branches are the bounds check and the
loop counter. Output is unchanged. Status: HARDENED.

## 8. `verify` and `cmov` (SEC-002, Info, hardened)

Before the change the compare ended in `setg` and the select was a vector
`and/andn/or`, with no branch on the result. The accumulated difference, the
flag and the mask now go through `black_box`, as `mlkem::ct` does. Disassembly
after the change shows `setne`/`cset` and a vector select; in `crypto_kem_dec`
the flag is stored, reloaded and passed to the select with no branch on it.
Status: HARDENED.

## 9. Randomness source (SEC-003, Low, fixed)

Legacy key generation and encapsulation used `rand::thread_rng()`, and the KEM
functions called `fill_bytes`, which panics when the generator fails. They now
use `OsRng` and `try_fill_bytes`, return `KyberError::RandomBytesGeneration`,
and Python raises `RandomnessError`. No fallback source exists. The half-built
secret key is wiped if the second draw fails. Checked by Rust tests with a
generator that fails, and end to end with `strace -e inject=getrandom:error=EIO`
(all six Python entry points raised `RandomnessError`, no panic). Status: FIXED.

## 10. Decapsulation intermediates (SEC-004, Low, fixed)

`m'`, the KDF input and the re-encrypted ciphertext were wiped only on the
normal exit path, the reject flag was never wiped, and the PRF output buffers in
`poly_getnoise_*` (the secret noise: the key in key generation, `r` in
encryption) were never wiped. They are now `Zeroizing`, so they are wiped on
unwinding too. The release disassembly shows the flag and buffer wipes on both
the normal and the cleanup path. There is no runtime test of the wipe (it needs
`unsafe` or an allocator hook); the implicit-rejection output is covered by a
new test. Status: FIXED, with the limits stated above.

## 11. `from_keys` binding (SEC-005, Low, fixed, behavior change)

`Kyber512/768/1024.from_keys` accepted any public key and secret key of the
right sizes, so a pair from two key pairs decapsulated to a different secret
with no error (the class of bug in CVE-2026-115408 for another library). It now
raises `KyberError` when the public key is not the copy in the secret key
(`sk = sk_pke || pk || H(pk) || z`). `H(pk)` and `z` are not checked.
`ML_KEM_*.from_keys` has the same gap and is not changed here. Status: FIXED
for `Kyber*`.

## 12. Secrets returned to Python (SEC-006, Low, fixed)

The bindings returned secret keys and shared secrets as `Vec<u8>`, freed with
the secret still in the allocation after PyO3 copied it into `bytes`. They are
now wiped after the copy. Status: FIXED. The Python `bytes` objects remain.

## 13. Length checks in the Rust API (SEC-007) and `DummyRng` (SEC-008), Info, fixed

`crypto_kem_keypair*` and `crypto_kem_enc*` indexed caller buffers and seeds
with no length check and panicked on a short one. The Python bindings size
every buffer, so no Python path reached this. They now return `InvalidInput`.
`DummyRng` (the stand-in on the seeded path, never asked for bytes) returned a
panic from `try_fill_bytes`; it now returns an error. `api::public` still
slices its argument and would panic on a short `sk`; no Python path calls it.
Status: FIXED, one Rust-only note left.

## 14. Compress_11 differs from FIPS 203 (SEC-009, Info, not fixed)

`polyvec_compress_1024` (`du = 11`) gives a result one too high at x = 1875 and
3125 compared with exact rounding (found in #28, pinned by
`legacy_compress_11_deviates_from_spec_at_two_residues`). It uses the d = 4/5/10
multiplier 10321345 >> 35, which is not exact for d = 11.

A fix was written and tested on 2026-10-31 and then reverted by the maintainer's
decision, to keep Kyber-1024 output compatible with v1.0.5. The replacement was
`(((x << 11) + 1664) * 645084) >> 31`, which matches exact rounding at every
residue (checked over all of Z_q). Its cost was: golden vector #6 and #7
(Kyber-1024) in `tests/vectors/legacy-kyber-v1.0.5.json` changed one or more
ciphertext bytes, and by estimate about 46% of Kyber-1024 ciphertexts
(1 - (1 - 2/3329)^1024, assuming uniform coefficients; not measured) contain a
coefficient at one of the two residues, so a 1.x ciphertext would decapsulate to
the implicit-rejection secret across the change and the reverse.

What stays correct: ML-KEM-1024 does not use this routine. `kpke` calls
`compress::poly_compress` with d = 11 and the exact multiplier 645084 >> 31,
which is tested against FIPS 203 (4.7) for every residue and negative
representative, by the ACVP and Wycheproof vectors, and by the differential test
against the `ml-kem` crate. Both ends of one legacy version use the same routine,
so Kyber-1024 round trips work; only interoperability with other round-3
implementations (which use exact rounding) is affected at those two residues.
Status: NOT FIXED, by decision. Anyone who needs exact Compress_11 should use
`ML_KEM_1024`.

## 15. Keccak stack spills (SEC-010, Low, not fixed)

What the issue is. `keccakf1600_statepermute` runs the 24 rounds with the state
in registers and stack temporaries. Zeroizing the 25-word state array after the
hash (`s.zeroize()` in `fips202.rs`) clears the array, not the temporaries. The
temporaries depend on the hashed input: `m`, `z`, the PRF seed and the
decapsulation intermediates all pass through SHA3 or SHAKE. A reader of freed
stack memory (a core dump, a swapped page, a memory-disclosure bug, cold boot)
could find parts of them after the call returns.

What was measured. Release build of this branch, rustc 1.95.0, `llvm-objdump`
on x86_64 (2026-10-31): one copy of the permutation, six callee-saved pushes, a
`subq $0x78, %rsp` frame and 22 `mov` stores to `(%rsp)`. The #28 figures
(0xf8-byte frame, about 70 spill stores) did not reproduce on this build, so the
size of the leak is not stable; its existence is. aarch64, i686 and armv7 were
not looked at.

Why it is not fixed.
- Safe Rust cannot reach it. The temporaries exist only inside a compiler-chosen
  frame that is dead after `ret`; clearing them needs a volatile write to
  addresses the compiler picked (`unsafe`, forbidden here) or hand-written
  assembly (also `unsafe`).
- The safe workaround, a stack-scrub call that writes a large zeroed local
  through `black_box` after each hash, is a guess about where the old frame was.
  Frame size and layout change with compiler version, target and inlining (the
  0x78 against 0xf8 above is an example), so the scrub would be too small on
  some builds and hide the problem with no way to test it. It also costs a
  memset per hash. I judged a mitigation that cannot be verified worse than a
  documented limit.
- It is not the only copy. Registers spilled by callers, moves of secret arrays,
  and the Python `bytes` objects holding keys and shared secrets all leave
  copies that cannot be wiped either (see "Method and limits" above), so fixing this one would not
  make the process memory clean.
- The permutation is shared with ML-KEM (`src/mlkem/mod.rs`); any change to it
  belongs in its own reviewed change with new assembly evidence, not in a
  security log commit.

What would close it. A permutation written to keep the state in a fixed
`Zeroizing` buffer end to end (no temporaries the compiler can spill, which
cannot be guaranteed in safe Rust), or an `unsafe` stack scrub gated on a
maintainer decision to allow `unsafe` in one audited function.
Status: NOT FIXED, documented limit.

## 16. Dependency advisories (SEC-011, SEC-012, Info)

Queried OSV (which carries RustSec) on 2026-10-30 for the locked runtime
dependencies; `cargo audit` is not installed here, so this is not its output.
`rand` 0.8.5 has RUSTSEC-2026-0097 (needs the `log` feature, which is off):
`Cargo.lock` moved to 0.8.6. `pyo3` 0.27.2 has RUSTSEC-2026-0176 (`nth` on list
and tuple iterators) and RUSTSEC-2026-0177 (`PyCFunction::new_closure`), both
fixed only in 0.29.0; this code uses neither API, and the 0.29 upgrade is left
to the maintainer. `zeroize`, `rand_core`, `getrandom`, `rand_chacha`: none.

## Checked, no findings

- Panics reachable from Python: none. About 1000 inputs (random, all-0xFF and
  coefficient-edge public keys, secret keys and ciphertexts, and wrong sizes for
  every argument and seed) went through the `_pykyber` functions in a build with
  overflow checks on; every result was a success or a plain exception.
- Integer overflow: sizes are compile-time constants or `len()` of a checked
  slice; the fuzz above had overflow checks on. Not a proof for adversarial
  coefficients beyond those tried.
- Length checks before secret work: `crypto_kem_dec*` and every binding check
  `ct`, `sk`, `pk` and the seed before touching secrets.
- Ciphertext compare covers the full ciphertext (see CVE-2026-6330 below).
- KyberSlash scan: see the table.

## CVE and paper review

Dates are 2026-10-30. "Primary" means the issuing page or the paper itself.

| Item | Status | Evidence |
|---|---|---|
| KyberSlash 1 (division in `poly_tomsg`) and 2 (`poly_compress`, `polyvec_compress`), <https://eprint.iacr.org/2024/1049> (primary, read) | Not affected | The kyberslash.cr.yp.to page could not be fetched (transport error); the paper and search results agree the bug is a division by q on secret data. The code uses multiply-and-shift (`* 10321345 >> 35`). Whole-library release disassembly has no `div`/`idiv`/`udiv`/`sdiv` and no `__aeabi_*div`/`__udiv*` relocation on x86_64, aarch64, i686 and armv7; a control function with a runtime divisor does show them. This covers all three levels, compress, decompress, `poly_tomsg` and the ML-KEM code. The constant divisions became multiplies; their timing on cores with a data-dependent multiplier was not assessed. |
| CVE-2024-14041 (KyberSlash in Bouncy Castle Java) | Not affected | Other library; found in search (mondoo), not on the primary page. |
| CVE-2024-37880 (Clangover, `poly_frommsg`) | Mitigated | Not observed with rustc 1.95 on x86_64 and aarch64; barrier added (item 7). Record read via mirrors (Debian tracker, OSV, INCIBE); the NVD page itself did not render. The CVE names LLVM Clang through 18; Rust also uses LLVM, so the class applies. |
| CVE-2026-115408 (crypto11 ML-KEM key pair lookup) | Not affected, class addressed | Another library (Go). Read on OpenCVE (NVD status "Received"); not yet on NVD proper. Same class as `from_keys`: fixed for `Kyber*` (item 11), still open for `ML_KEM_*.from_keys`. |
| CVE-2026-6330 (wolfSSL ML-KEM ARM64 NEON compares half the ciphertext) | Not affected | CVE record read via the MITRE API listing and Debian tracker, not NVD. Our compare covers the whole ciphertext; the rejection test damages the first, middle and last bytes at all three levels. An AVX2 variant that compares 1536 of 1568 bytes appears in one vendor-blog result, unconfirmed. |
| 2026 SEALSQ and LightSec work on ML-KEM key generation and encoding | Unconfirmed, out of scope | Press release only (thequantuminsider, 2026-10-14); the paper was not read. It concerns hardware leakage through profiling plus lattice reduction; power and EM attacks are out of scope for this project. |
| Airtight side-channel testing framework (AFIT, <https://scholar.afit.edu/facpub/3612>) | Not assessed | The AFIT page was not found by search; a paper with that title exists at ECCWS (academic-conferences.org). The framework was not run; dynamic timing tests are WP-8, which is not merged. |
| Reference implementations (Go, BoringSSL, RustCrypto, libcrux) | Not assessed | Comparison only; no code was copied. |

## Benchmark (release wheels, base `8e56f40` vs this branch)

`python/tests/test_kyber.py -k performance`, 100 iterations per op, median of
three alternating runs, one machine, noisy: decapsulation about the same at all
levels (+0.9%, 0.0%, -4.2%); key generation and encapsulation slower by up to
about 0.02 ms (Kyber768 keygen 0.051 to 0.074 ms, Kyber1024 keygen 0.087 to
0.113 ms, encapsulation +7% to +13%), most likely the `getrandom` call that
replaced `thread_rng`. The full key exchange moved -14% to +2%, inside the noise.
