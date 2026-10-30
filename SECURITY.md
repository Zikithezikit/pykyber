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

## Release gate: compiler-level results (WP-8, issue #16)

Run on 2026-10-30. This section records what the two tools found, what they
cannot show, and how to rerun them. Both tools look at one compiler, one flag
set and the targets named here. None of it is a constant-time guarantee.

### Tools and versions

| item | value |
| --- | --- |
| rustc / cargo | 1.95.0 (59807616e 2026-04-14) / 1.95.0 (f2d3ce0bd 2026-03-21) |
| disassembler | `llvm-objdump` from the toolchain's `llvm-tools` component, LLVM 22.1.2-rust-1.95.0-stable |
| build | `cargo rustc --locked --release --lib --crate-type rlib --target <triple>`, no `RUSTFLAGS`, release profile (opt-level 3, codegen-units 16, no LTO) |
| targets | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (full), `i686-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf` (spot check; the same checks run) |
| timing machine | Intel Core i7-7700, Linux 7.0, CPython 3.14.4, `powersave` governor, process pinned to CPU 2 |

### Assembly check (`scripts/asm_check.py`)

The script builds an rlib per target, disassembles every function, and starts
at the decapsulation entry points: ML-KEM `mlkem::kem::decaps` (three
parameter sets) and the legacy `kyber::kem::crypto_kem_dec`, `_512`, `_1024`.
It follows the call relocations and checks every function reachable from them
(39 to 47 functions per family). That is how the leaf functions are found
without touching `src/`: release builds inline `poly_from_msg`, the compress
routines, `verify` and `cmov` into their callers, and the closure covers them
wherever they end up. The script also lists which of the leaf functions named
in the issue exist as symbols of their own.

Per function it checks:

- division: `div`/`idiv`/`udiv`/`sdiv`, calls to `__udivdi3`, `__aeabi_idiv`
  and the like, and the panic for a division by a non-constant;
- calls to `memcmp`/`bcmp`;
- computed jumps (jump tables, `br`, `tbb`, `jmp *reg`);
- conditional branches, classified by shape because a tool cannot tell a
  secret from a public condition: a backward branch is a loop, a branch to a
  block that ends in a panic call is a bounds/length guard, and everything
  else is "other". Every "other" branch must be covered by
  `scripts/asm_check_allowlist.json`: a reviewed ceiling per function and
  target, with a reason. More branches than the ceiling is a finding, so a
  compiler or source change that adds a branch forces a new review.

Result for the five checks above, on all four targets, both families:

| area | ML-KEM | legacy Kyber |
| --- | --- | --- |
| division instruction or helper call in the decaps closure | no findings | no findings |
| `poly_tomsg`, `poly_compress`, `poly_decompress`, `polyvec_*compress` | n/a (ML-KEM uses `compress::poly_compress`/`poly_decompress`: no findings) | no findings |
| `poly_frommsg` / `poly_from_msg` | no findings | no findings (inlined into `indcpa_enc`; no branch on the message) |
| compare and select (`reject_on_mismatch`; `verify`, `cmov`) | no findings | no findings (inlined into `crypto_kem_dec`: only the three length checks branch) |
| computed jumps | no findings | no findings |
| unreviewed conditional branches | none | none |

What the reviewed "other" branches are: input length checks at entry,
`Result` tag tests, remainder and loop-exit tests on public lengths and
counters (vector-loop prologues, zeroize loops), rejection sampling of the
public matrix A, and sponge-buffer position tests. In every listing read the
compared operand was an immediate, a length, a position counter, or a tag, and
none came from `m'`, `K`, `c'` or the reject flag. The one exception to "no
data compare" is the `dk` hash check `H(ek) == h` (FIPS 203 section 7.3),
which compares two values derived from the public `ek`; on armv7 that 32-byte
compare is a `bcmp` call and is allowlisted for that reason. The 144
branches of `shake256` on aarch64 are unrolled byte-copy tails; on i686 the
length they are compared with lives in a stack slot, which I inferred and did
not trace.

Mutation check of the tool itself (on a scratch copy, not committed):
replacing a multiply-shift in `compress.rs` by a division by a non-constant was
reported as `div`/`udiv` plus the divide-by-zero panic on x86_64 and aarch64,
and replacing the mask select in `reject_on_mismatch` by `if black_box(diff) !=
0` raised the branch count of `decaps` above its ceiling on both. Rewriting it
with a plain `if diff != 0` did not produce a finding because LLVM turned it
back into a select; the tool reports what the compiler emitted, which is the
point, and also why a source-level `if` is not proof of a branch.

What this check does not show:

- Backward branches are assumed to be loops on public counters and panic
  guards to depend on public lengths. A secret-indexed table lookup would look
  like a bounds-check panic guard and would not be caught; that rule rests on
  source review.
- It reads the rlib, not the final extension module, and the rlib is not linked
  with LTO. A different profile, `-C target-cpu`, LTO, PGO or another LLVM
  can change the result. Cross-compiled targets were not executed.
- Cryptographic state in registers and stack is not looked at (zeroization is
  checked only by the existing tests and review).
- Not covered: `s390x`, `ppc64le`, the Android targets, `musl`, Windows and
  macOS builds, all of which are in the wheel matrix. No floating-point check.
- The `armv7` and `i686` entries were checked by listing the compare operand of
  each branch, as for the others, but they are spot checks of the same
  closure, not a separate review of the source.

### Timing test (`scripts/timing_decaps.py`)

For one fixed key it times decapsulation of valid ciphertexts against
ciphertexts with one flipped bit and against random bytes. Run:
`--sets 512,768,1024 -n 100000 --cpu 2` (seed 20261030, 100 000 timings per
class, 300 000 per parameter set and family, interleaved in a seeded random
order, Welch t on raw timings and after cropping at the 99th, 95th, 90th and
80th percentile; a pair is flagged only if |t| > 5.0 overall and in both halves
with the same sign).

Result: no flag for either family at 512, 768 and 1024. The largest |t| over
all tests was 2.59 (ML-KEM-1024). The smallest difference the run could have
detected at |t| = 5, from the observed variance, was 300 to 920 ns on the
uncropped timings, 160 to 450 ns at the 99th percentile crop, and 16 to 410 ns
at the 80th percentile crop (the smallest values are for the quiet runs),
against decapsulation times of 40 to 100 us. Positive control (`--inject-ns`): 100 ns and 200 ns
added to the non-valid classes were flagged for ML-KEM-768 and Kyber-768 at
the same count (on the 95th-percentile and 80th-percentile crops; the uncropped
test did not reach threshold at 100 ns). So a leak of a few hundred ns that shows on every call would be
found; one below roughly 100 ns in a call of 60 us (about 0.15 percent) is not
excluded, and the noisier runs (Kyber-768 here) detect less.

Limits: the valid ciphertexts come from `encapsulate()` and use the OS random
generator, so a rerun is not bit-identical (key pair, flip positions, random
ciphertexts, order are seeded). Timing goes through the Python call, so
interpreter jitter adds to the noise. Only x86_64 was measured. A different CPU
or compiler needs its own run.

The test is a measurement tool, not a correctness test, so it is not part of
`cargo test`, `pytest` or `scripts/check.sh`.

The valgrind/ctgrind variant (mark the secret key undefined and let memcheck
report branches and indexes that depend on it) was **not run**: valgrind is not
installed on the review machine and could not be installed. It also needs a
test inside the crate (the ML-KEM internals are `pub(crate)`) that issues
`VALGRIND_MAKE_MEM_UNDEFINED` on `dk`, which would be a change under `src/` or a
test module that this task did not make. To try it later:
`valgrind --error-exitcode=1 --track-origins=yes target/release/deps/<test binary> <test name>`
on a release build of such a test.

### Findings

Format as in AGENTS.md. Nothing under `src/` or `python/pykyber/` was changed.

```
ID: SEC-001
Title: Legacy verify/cmov/poly_frommsg have no optimization barrier
Severity: Low (not demonstrated: the release assembly is branch-free on all four targets)
Location: src/kyber/verify.rs (verify, cmov); src/kyber/poly.rs (poly_frommsg)
Class: timing
Evidence: source reads `(r.wrapping_neg() >> 63)`, `b.wrapping_neg()` masks and `((msg >> j) & 1).wrapping_neg()` with no black_box. rustc 1.95.0 keeps them branch-free
  (crypto_kem_dec has three length-check branches only, indcpa_enc/indcpa_dec only counters). The pattern is the one of CVE-2024-37880; nothing guarantees a
  different compiler or flag does the same. Hypothesis for other toolchains.
Related: CVE-2024-37880 https://nvd.nist.gov/vuln/detail/CVE-2024-37880 ; https://pqshield.com/?p=3736
Legacy impact: no (a barrier changes no output; golden vectors still decide)
Suggested fix + test: route the masks through core::hint::black_box as src/mlkem/ct.rs and compress.rs do; keep scripts/asm_check.py in CI as the regression test.
Proposed for #18, not filed.

ID: SEC-002
Title: variable-time 32-byte compare in the dk hash check on armv7
Severity: Info (both operands derive from the public ek)
Location: src/mlkem/check.rs check_dk, inlined into kem::decaps
Class: timing
Evidence: `bcmp` call at decaps+0x88 in the armv7 listing; aarch64 and x86_64 use a word-compare chain and a branch.
Related: FIPS 203 section 7.3
Legacy impact: no
Suggested fix + test: none needed; if a stricter policy is wanted, use the constant-time compare of src/mlkem/ct.rs. The allowlist records the single permitted call.
Not a finding against "ML-KEM passes": it is on public data.
```

No finding was made for the ML-KEM code. "ML-KEM passes" is met in the
sense that the tools above found nothing; the limits listed above apply.

### Sources checked (2026-10-30)

- KyberSlash: <https://kyberslash.cr.yp.to/> could not be fetched here (parse error). RUSTSEC-2023-0079 (`pqc_kyber`, division of a secret by a public value) read via search results at <https://rustsec.org/advisories/RUSTSEC-2023-0079>. No change to what is assumed; the script has no division in either decaps closure. No RustSec advisory for the `ml-kem` crate turned up in one search (not confirmed against the RustSec index).
- CVE-2024-37880 (reference implementation, Clang, `poly_frommsg`): <https://nvd.nist.gov/vuln/detail/CVE-2024-37880>; the NVD page body did not load, the description was confirmed from search snippets and <https://pqshield.com/?p=3736>. Treated as confirmed for the pattern; see SEC-001.
- CVE-2026-6330 (wolfSSL, ARM64 NEON ML-KEM ciphertext comparison covers half of the input): confirmed on NVD (published 2026-06-25) via search results, <https://nvd.nist.gov/vuln/detail/CVE-2026-6330>. Different library and code; relevant here as the class "comparison that skips part of the ciphertext". `reject_on_mismatch` is exercised by a test that flips every bit of a full-length ciphertext (src/mlkem/ct.rs) and the timing test flips random positions over the whole ciphertext; the release assembly shows a full-length loop. Not affected as far as these show.
- CVE-2026-115408 (crypto11): no result in one search; still unconfirmed. The earlier note in PLAN-2.0.md stands.
- 2026 side-channel news item (SEALSQ) and the AFIT framework: not rechecked; no change.

### Rerunning

```bash
rustup component add llvm-tools
rustup target add aarch64-unknown-linux-gnu i686-unknown-linux-gnu armv7-unknown-linux-gnueabihf
python scripts/asm_check.py                       # exit 1 on a finding; --show-other lists each reviewed branch with its compare
python scripts/asm_check.py --toolchain 1.95.0    # pin a toolchain (CI does)

python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/maturin develop --release
.venv/bin/python scripts/timing_decaps.py --sets 512,768,1024 -n 100000 --cpu 2
.venv/bin/python scripts/timing_decaps.py --sets 768 -n 100000 --cpu 2 --inject-ns 100   # positive control
```

Rerun the assembly check for every release and whenever the Rust toolchain
changes. When the ceilings in `scripts/asm_check_allowlist.json` have to move,
read the new listing with `--show-other` first and update the entry's reason.
