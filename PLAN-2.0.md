# PyKyber 2.0 — implementation & security plan

Source of truth for scope: GitHub issue #3, "[2.0] Add ML-KEM (FIPS 203) support while keeping legacy Kyber API with deprecation". This plan breaks that issue into reviewable work packages. If this plan and the issue disagree, the issue wins: raise it on the issue, don't silently diverge.

Agents and contributors working on this plan must also follow `AGENTS.md`.

## 1. Scope (from issue #3)

| Issue requirement | Where it is delivered | Acceptance check |
|---|---|---|
| Add `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024` | WP-3, WP-5 | Python classes exported; ACVP + CCTV + Wycheproof vectors pass (WP-4) |
| Keep `Kyber512/768/1024` working with old behavior | WP-1 (golden vectors), every PR | Golden vectors captured from `v1.0.5` pass unchanged in CI |
| Deprecation warning the first time a `Kyber*` class is used | WP-6 | Subprocess test: N uses -> exactly 1 warning |
| Warning only once per process | WP-6 | Same test, across all three classes and static methods |
| Docs/examples point at ML-KEM | WP-7 | README, `docs/`, examples use ML-KEM; Kyber marked deprecated |
| Security pass (recent CVEs + side channels), written up in `SECURITY.md` | WP-8 (gate items), WP-9 (full pass) | `SECURITY.md` at repo root with findings log |
| Don't break the current API | all | No removed/renamed public names; existing tests unchanged |
| Rust backend stays ours, MIT OR Apache-2.0 (was Unlicense) | all | No new **runtime** crypto dependencies; dev-only deps allowed for testing |
| Move default branch to `main` | Release | Maintainer merges `dev-v2` into `main` at the end; GitHub default = `main`, protected |
| May trade some speed for side-channel resistance | WP-8/9 | Benchmarks recorded before/after each hardening PR |

Out of scope for 2.0: removing the Kyber classes, hybrid KEMs (X25519+ML-KEM), ML-DSA, masking against power/EM analysis.

## 2. Spec facts (verified against FIPS 203 final text, 2026-10-29)

Verified from <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf>. Algorithm numbers refer to that document; cite them in code comments.

- **Parameters (Table 2/3)**: 512: k=2, η1=3, η2=2, du=10, dv=4. 768: k=3, η1=2, η2=2, du=10, dv=4. 1024: k=4, η1=2, η2=2, du=11, dv=5. Sizes (ek/dk/ct/ss): 800/1632/768/32, 1184/2400/1088/32, 1568/3168/1568/32 — identical to Kyber, so **sizes cannot tell the two apart**.
- **KeyGen_internal(d, z)** (Alg 16): `dk = dkPKE ‖ ek ‖ H(ek) ‖ z`. K-PKE.KeyGen (Alg 13) does `(ρ, σ) = G(d ‖ k)`: the one-byte k is the domain separator added in the final standard (App. C.2).
- **Encaps_internal(ek, m)** (Alg 17): `(K, r) = G(m ‖ H(ek))`, `c = K-PKE.Encrypt(ek, m, r)`. Unlike round-3 Kyber, `m` is **not** pre-hashed and `K` is **not** derived from `H(c)` (App. C.1).
- **Decaps_internal(dk, c)** (Alg 18): decrypt -> `(K', r') = G(m' ‖ h)` -> `K̄ = J(z ‖ c)` -> re-encrypt -> if `c ≠ c'` then `K' = K̄`. The reject flag is secret and **shall be destroyed**, never returned (§6.3).
- **Input checks** (§7.2, §7.3): ek type check + modulus check `ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k]`; ciphertext length check on **every** decaps; dk length check + hash check `H(dk[384k:768k+32]) == dk[768k+32:768k+64]`.
- **Section 3.3 requirements**: intermediate values shall be destroyed; only exceptions are the seed `(d, z)` (may be stored, treat as a secret key) and the matrix Â. `*_internal` interfaces should not be exposed to applications except for testing. RBG must be approved; KeyGen/Encaps return an error if randomness fails. No floating point.
- NIST recommends ML-KEM-768 as the default parameter set (§8).

The current code is **round-3 Kyber** (`kem.rs`: `m` is hashed, `H(c)` goes into the KDF, `G(d)` has no k byte), so ML-KEM gets a separate code path.

## 3. How we work (multi-developer)

- **Tracking**: GitHub milestone `2.0.0`; one sub-issue per work package below, linked from #3. Labels to add: `ml-kem`, `security`, `legacy-kyber`, `ci`.
- **Branches**: all 2.0 work goes into `dev-v2` (cut from `dev`). Protect it: PR required, 1 approving review, required status checks, no force push, linear history. Feature branches are cut from `dev-v2` as `wp<N>-<short-name>` (e.g. `wp3-mlkem-keygen`), and every PR targets `dev-v2`. Nobody merges into `main` or `dev` during 2.0. When everything is done, the maintainer opens the single `dev-v2` -> `main` PR, makes `main` the default branch and retires `dev`.
- **PR size**: one work package per PR or smaller; crypto PRs ≤ ~400 changed lines excluding vectors. No mixed refactor + behavior changes in one PR.
- **Commits**: Conventional Commits, matching existing history (`feat:`, `fix:`, `test:`, `ci:`, `docs:`, `security:`, `refactor:`). Every commit in a PR must build and pass the tests on its own. Fixes found in review or CI are folded into the commit that introduced the problem (`git commit --fixup` + `git rebase --autosquash`), never added as separate "fix" commits. Branches are rebased on `dev-v2`, never merged with it.
- **Merging**: PRs are **rebase-merged** into `dev-v2`, so the reviewed commits land unchanged. Squash and merge commits are turned off in repo settings (WP-0).
- **Reviews**: anything under `src/` that touches secret data needs a reviewer to tick the PR template's constant-time checklist. `CODEOWNERS` routes `src/` and `SECURITY.md` to the maintainer.
- **Changelog**: every user-visible PR adds a line under `## Unreleased` in `CHANGELOG.md`.
- **Sources**: each WP starts with a dated source check (Section 9), recorded in the PR description: what was checked, date, and result ("no change" counts).
- **Agents**: agent-written PRs follow `AGENTS.md` and get the same review as human PRs. Agents never merge.

## 4. Work packages

Dependencies: WP-0 -> WP-1 -> (WP-2, WP-3) -> WP-4 -> WP-5 -> (WP-6, WP-7) -> WP-8 -> release. WP-9 runs in parallel from WP-1 onward.

### WP-0 — Repo hygiene & collaboration setup
- Protect `dev-v2` (rules in Section 3). In repo settings allow only rebase merging (turn off squash and merge commits). Add `dev-v2` to the `push` triggers in `CI.yml` (currently `main` + tags; `pull_request` already covers PRs into any branch). Switching the default branch to `main` waits for the release.
- Add `CONTRIBUTING.md` (build/test commands, branch/commit rules, how to run vectors), `.github/pull_request_template.md` (with security checklist from `AGENTS.md`), `.github/CODEOWNERS`, issue templates (bug, feature, security -> redirect to private advisory).
- Add root `SECURITY.md` with a reporting policy (GitHub private vulnerability reporting enabled) and migrate the findings log from `.opencode/SECURITY.md`, which is **gitignored** and so invisible to other contributors.
- Track `AGENTS.md`/`CLAUDE.md`; keep `.opencode/` ignored.

### WP-1 — Green baseline + legacy freeze
- Fix `tests/unit_params.rs::test_kyber_1024_params` (expects 1280, gets 1408). Decide whether the test or the constant is wrong **by checking the Kyber round-3 spec**, not by editing the assertion to match.
- Add `pytest` (+ `maturin`) as dev deps (`requirements-dev.txt` or a `[dependency-groups]` table); `.venv` currently lacks pytest.
- **Golden vectors**: install `pykyber==1.0.5` from PyPI in a clean venv; for fixed seeds, record keygen outputs (seeded), decaps outputs for fixed ciphertexts, and encaps outputs where determinism allows (encaps currently has no seed in Python, so record via the Rust `crypto_kem_enc(.., Some(seed))` path at tag `v1.0.5`). Store as `tests/vectors/legacy-kyber-v1.0.5.json` with the generator script. These files are append-only.
- CI: add a `test` job (Linux, macOS, Windows; one old and one current Python) running `cargo fmt --check`, `cargo clippy -- -D warnings` (fix or explicitly `allow` the current 59 diagnostics in a separate PR first), `cargo test`, `maturin develop` + `pytest`. Make it a required check.

### WP-2 — Shared-primitive audit (prep for reuse)
- Decide which legacy modules ML-KEM can share unchanged: `fips202`, `ntt`, `reduce`, `cbd`, poly (de)serialization, compress. Rule: shared code may be **hardened** (constant-time fixes) only if legacy golden vectors still pass byte-for-byte.
- Introduce a generic `const K: usize` (or param-trait) poly-vector type for the new code instead of a fourth set of `_512/_768/_1024` copies. Legacy duplicated code stays as is.

### WP-3 — ML-KEM core in Rust (`src/mlkem/`)
- Implement Alg 13–18 (K-PKE KeyGen/Encrypt/Decrypt, KeyGen/Encaps/Decaps internal) and Alg 19–21 wrappers, generic over the parameter set.
- Input checks per §7.2/§7.3 return typed errors, and they run before any secret-dependent work.
- Visibility: `*_internal` functions are `pub(crate)`; expose them only under `#[cfg(any(test, feature = "acvp"))]` for vector tests (§3.3). Public Rust API: `keygen()`, `keygen_from_seed(d, z)`, `encaps(ek)`, `decaps(dk, c)`.
- Randomness: `OsRng`/`getrandom`; errors propagate (Alg 19/20 return ⊥). No `thread_rng()` for key material in new code.
- Secrets: all intermediates (`m`, `r`, `K̄`, `σ`, noise vectors, the reject flag) zeroized before return; use `Zeroizing<..>` wrappers.
- Constant-time: re-encryption compare and `K'`/`K̄` select are branch-free with an optimization barrier (in-house, no new runtime crate); no division/modulo on secrets; no secret-indexed table lookups.

### WP-4 — Official vectors (gate for "passes the official test vectors")
- NIST ACVP-Server `gen-val/json-files/ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203` (internalProjection + expectedResults), including decapsulation-key-check and encapsulation-key-check groups.
- C2SP CCTV ML-KEM: modulus-check negatives, "unlucky" XOF vectors, and the accumulated/strcmp vectors.
- Wycheproof ML-KEM test files.
- External vector files are **not committed**. A fetch script downloads them at test time from a pinned commit and checks each file against a SHA-256 in `tests/vectors/manifest.json`; CI caches the downloads and the folder is gitignored. The repo only holds our own code, our parsers, and our own legacy golden vectors.
- Dev-only differential fuzz against an independent implementation (RustCrypto `ml-kem` or `libcrux-ml-kem` as a `[dev-dependencies]` entry). Never a runtime dependency.

### WP-5 — Python bindings & classes
- `src/lib.rs`: `_mlkem_{512,768,1024}_{keygen,encaps,decaps}`; map Rust errors to `KyberError` subclasses (not bare `PyException`).
- `python/pykyber/`: `ML_KEM_512/768/1024` mirroring the `Kyber*` surface (instance = keypair; static `encapsulate`/`decapsulate`/`from_keys`; serialization; tuple unpacking). Seed = 64 bytes `d ‖ z` (Alg 19 order). Add `.seed` support only if keygen came from a seed, and document that it is secret.
- **Mix-up resistance**: since sizes are identical, results/keys carry their algorithm; `ML_KEM_768.decapsulate` refuses a `Kyber768` keypair object (raw bytes can't be distinguished, so say so in the docs).
- Regenerate `.pyi` stubs; type hints; `__all__` updated.

### WP-6 — Kyber deprecation
- First use of any `Kyber*` entry point (constructor, `from_keys`, static `encapsulate`/`decapsulate`) emits one warning per process, guarded by a module-level flag. Import alone does not warn.
- Category: `KyberDeprecationWarning(DeprecationWarning)` so users can filter it precisely. Note: Python hides `DeprecationWarning` by default unless it's attributed to `__main__`; use `stacklevel` so it points to user code. Staying quiet is deliberate for now (D2).
- Message says that Kyber (round 3) and ML-KEM are **not interoperable** and that switching changes the shared secret, and links the migration guide.
- Tests in a subprocess: warning count == 1 across mixed classes and methods; outputs unchanged (golden vectors).

### WP-7 — Docs
- README quick-start and `docs/api.md` switch to `ML_KEM_768` (NIST's default). Add a "Kyber -> ML-KEM migration" page: not interoperable, both sides must upgrade, seed format, key sizes the same.
- CHANGELOG `2.0.0` entry; version bump in **both** `Cargo.toml` and `pyproject.toml` (plus the docs link in `pyproject.toml`).

### WP-8 — Security release gate (required before 2.0.0)
Minimum security work on the new code before tagging:
- Constant-time review checklist (see `AGENTS.md`) signed off on `src/mlkem/` and any shared primitives it uses.
- Assembly check on release builds for `x86_64` and `aarch64` (and a spot check on `armv7`/`x86` 32-bit, which CI ships): no secret-dependent branches and no `div`/`udiv`/`sdiv` in decaps, `poly_tomsg`/compress, `poly_frommsg`, select/compare. Script it with `cargo asm` or `objdump` so it can run again.
- Dynamic timing test (dudect-style, or valgrind "secret = undefined" à la ctgrind) on decaps with valid vs. invalid ciphertexts.
- `cargo audit` + `cargo deny` clean; CI actions pinned by SHA.
- Fuzz targets (`cargo fuzz`) for ek/dk/ct parsing and decaps run ≥ 1 CPU-hour each without panics.
- `SECURITY.md` updated with the results.

### WP-9 — Full security pass (parallel; may continue after 2.0 as 2.0.x)
The issue comment allows this to land after the version release. Track each finding as its own issue/PR and log it in `SECURITY.md`.
- Legacy code, same checklist as WP-8. Starting points found while writing this plan (unconfirmed, need assembly or dynamic evidence):
  - `src/kyber/poly.rs` `poly_frommsg`: `((msg >> j) & 1).wrapping_neg()` mask is the CVE-2024-37880 ("Clangover") pattern that compilers have turned into a branch.
  - `poly_tomsg` uses the multiply-shift replacement for `/q` (KyberSlash fix); verify all compress paths (`poly_compress`, `polyvec_compress*`) do too.
  - `verify.rs` `verify`/`cmov`: check for optimization barriers.
  - `api.rs` `DummyRng` panics by design; confirm no path from Python reaches it, and that panics can't cross the PyO3 boundary.
  - `lib.rs` uses `thread_rng()` for key material; compare with `OsRng`.
  - Decaps doesn't zeroize every intermediate; Python `bytes` copies of secrets can't be wiped (document this).
- Review against each CVE/paper in Section 9 and record "affected / not affected / mitigated" with evidence.
- Any change to legacy code must keep golden vectors byte-identical.

## 5. Release checklist (2.0.0)

- [ ] All issue #3 "Done when" items ticked with links to the proving test/CI run
- [ ] WP-8 gate complete; `SECURITY.md` current
- [ ] Release candidate `2.0.0rc1` on TestPyPI; install the wheels from **every** CI target and run the test suite against them (not only the build)
- [ ] Source re-check (Section 9) done within 7 days of the tag
- [ ] Maintainer opens the `dev-v2` -> `main` PR and merges it; `main` becomes the default branch; `dev` is retired
- [ ] Update `pyproject.toml` URLs and doc links that point at `dev` or `v1.0.5`
- [ ] Tag `v2.0.0` from `main`, publish, GitHub release notes link the migration guide

## 6. Open decisions for the maintainer

- **D1 (decided)**: external test vectors are downloaded at test time with pinned hashes, never committed. Other implementations are for reference and output comparison only; no third-party code is copied into the repo.
- **D2 (decided)**: quiet `DeprecationWarning` for now (via a `KyberDeprecationWarning` subclass), plus a note in the README.
- **D3**: hold 2.0.0 for any WP-9 findings, or ship with WP-8 only and follow up in 2.0.x (the issue comment suggests the latter).
- **D4**: whether to expose ML-KEM in the public Rust crate API now or keep the crate Python-only for 2.0.

## 7. Risks

- Shared-primitive changes silently altering legacy output -> golden vectors are a required CI check.
- Compiler-introduced timing leaks (KyberSlash, Clangover) -> assembly check is scripted and re-run per release and per Rust toolchain bump.
- Key confusion between Kyber and ML-KEM (same sizes) -> typed objects, docs, distinct class names in errors.
- Test-vector schema drift (ACVP revisions such as FIPS203-tr1 seed-form dk) -> pin the commit SHA; re-check at release.

## 8. Definition of done (per PR)

`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `pytest` green **on every commit** in the PR; review fixes folded into their commits and the branch rebased on `dev-v2`; golden vectors untouched and passing; new behavior has tests (vectors for crypto); CHANGELOG line; source check recorded; constant-time checklist ticked if secrets were touched.

## 9. Source checklist (re-check at the start of every WP and before release)

Record the date and result in the PR. Treat secondary sources (news, blogs) as leads, not facts.

Primary:
- FIPS 203 (final) and errata: <https://csrc.nist.gov/pubs/fips/203/final>
- SP 800-227 (KEM recommendations, referenced by FIPS 203 §3.3): <https://csrc.nist.gov/pubs/sp/800/227/final>
- ACVP ML-KEM spec: <https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html>
- ACVP-Server vectors: <https://github.com/usnistgov/ACVP-Server>
- C2SP CCTV ML-KEM: <https://c2sp.org/CCTV/ML-KEM>
- Wycheproof: <https://github.com/C2SP/wycheproof>
- NVD search ("ML-KEM", "Kyber", "mlkem"): <https://nvd.nist.gov/vuln/search>
- GitHub Advisory DB (pip, rust): <https://github.com/advisories>; RustSec: <https://rustsec.org>
- NIST pqc-forum: <https://groups.google.com/a/list.nist.gov/g/pqc-forum>

Known issues to assess against this code base:
- KyberSlash 1/2, division timing (TCHES 2025): <https://kyberslash.cr.yp.to/>, <https://eprint.iacr.org/2024/1049>
- CVE-2024-37880, `poly_frommsg` compiler-induced branch: <https://pqshield.com/?p=3736>
- 2026 items found on 2026-10-29, **not yet confirmed on NVD**: CVE-2026-115408 (crypto11 ML-KEM key-pair lookup binding, via OSV/Vulners <https://vulners.com/osv_cve/OSV:CVE-2026-115408>); CVE-2026-6330 (wolfSSL ML-KEM bug, mentioned in <https://blog.cr.yp.to/20260704-bugs.html>). Both look like API/integration bugs in other libraries; check whether the same class of mistake applies to our `from_keys` (binding a pk to the wrong sk).
- 2026 side-channel research on ML-KEM keygen/encoding (SEALSQ, LightSec 2026; news only so far): <https://thequantuminsider.com/2026/10/14/sealsq-research-side-channel-attacks-ml-kem/>
- Airtight side-channel testing framework (AFIT): <https://scholar.afit.edu/facpub/3612>
- Reference implementations to compare against: Go `crypto/mlkem`, BoringSSL, RustCrypto `ml-kem`, Cryspen `libcrux` (formally verified).
