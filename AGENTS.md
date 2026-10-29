# AGENTS.md — instructions for AI coding agents

You are working on **pykyber**, a post-quantum KEM library: an in-house Rust implementation (no third-party crypto at runtime) with PyO3 bindings, released under the Unlicense. People will run your code to protect real secrets. A test that passes is necessary but not sufficient; code that is correct but leaks timing is a vulnerability.

Current work: the 2.0 release (GitHub issue #3), planned in `PLAN-2.0.md`. Read the work package (WP) you are assigned before you start.

## Non-negotiables

1. **Legacy Kyber output never changes.** `Kyber512/768/1024` must produce byte-identical results to v1.0.5. The golden vectors in `tests/vectors/legacy-kyber-v1.0.5.json` are append-only: never regenerate or edit them to make a test pass. If a change breaks them, the change is wrong.
2. **Follow the spec, not memory.** ML-KEM code implements FIPS 203 (final). Before writing or reviewing an algorithm, read its text in the standard and cite it in a comment (`// FIPS 203 Alg 18, step 9`). Round-3 Kyber and ML-KEM differ in ways that look like typos (`G(d‖k)`, no `H(m)`, no `H(c)` in the KDF); don't "fix" one into the other.
3. **Never weaken a test to make it pass.** Don't loosen an assertion, regenerate expected values from the code under test, or mark a test `#[ignore]`/`skip`. If you think a test is wrong, show evidence from a primary source and say so.
4. **No new runtime dependencies** without maintainer approval. Dev-only crates for testing (e.g. a reference ML-KEM for differential tests, `cargo-fuzz`) are fine in `[dev-dependencies]`.
5. **Don't touch the public API** beyond what the WP asks. No renames, no removals, no behavior changes to existing classes (other than the WP-6 deprecation warning).
6. **Don't claim what you didn't verify.** In PR descriptions and reports, separate "verified (how)" from "believed". If you couldn't run something, say so.

## Constant-time and secret-handling rules (Rust)

These apply to any value derived from a secret key, seed, `m`, `r`, noise, a decrypted message, or the implicit-rejection flag.

- No `if`, `match`, `&&`/`||` short-circuit, `?`, early `return`, or loop bound that depends on secret data.
- No `/` or `%` on secret values; use the existing multiply-and-shift (Barrett/Montgomery) helpers. Division by public constants on public lengths is fine.
- No array indexing with secret-derived indices.
- No `==` on secret byte slices. Use the constant-time compare/select in `verify.rs` (or its ML-KEM successor), which must sit behind an optimization barrier.
- Mask idioms like `x.wrapping_neg() & y` are **not** guaranteed constant-time: LLVM has turned them into branches (CVE-2024-37880, "Clangover"). Route the bit through a barrier, and check the assembly when in doubt.
- Zeroize every secret intermediate before the function returns (`zeroize::Zeroizing`, or `.zeroize()` on every exit path). FIPS 203 §3.3 requires it, and the decaps reject flag must never be returned or stored.
- Validate inputs (lengths, the §7.2 modulus check, the §7.3 hash check) **before** any secret-dependent work, and return typed errors.
- Randomness for keys and encapsulation comes from the OS RNG; propagate failure as an error and never fall back to a weaker source.
- No `unsafe`. No `unwrap`/`expect`/`panic!`/indexing that can panic on attacker-controlled input outside tests. Panics must not cross the PyO3 boundary.
- No floating point anywhere in crypto code (FIPS 203 §3.3).
- `*_internal` functions that take caller-chosen randomness are test-only: `pub(crate)`, exposed only under `cfg(any(test, feature = "acvp"))`.

## Python rules

- Public classes mirror the existing `Kyber*` shape (instance = keypair, static `encapsulate`/`decapsulate`/`from_keys`, hex/b64/dict, tuple unpacking). Keep `__all__` and the `.pyi` stubs in sync.
- Validate sizes in `_validation.py` before calling Rust; raise `KyberError` (or a subclass), never a bare `Exception`.
- Kyber and ML-KEM keys have identical sizes. Never accept an object from one family in the other's methods.

## Workflow

- Branch from `dev-v2` as `wp<N>-<short-name>`, and open every PR against `dev-v2`. Never target `main` or `dev`: the maintainer merges `dev-v2` into `main` once, when 2.0 is done.
- One WP (or less) per PR; Conventional Commit messages (`feat:`, `fix:`, `test:`, `ci:`, `docs:`, `security:`, `refactor:`). Never push directly to `dev-v2`, `main` or `dev`, never merge, never force-push shared branches.
- **Every commit must pass on its own.** PRs are rebase-merged, so each commit lands on `dev-v2` as is. Each commit must build and pass the checks below, not just the last one in the PR.
- **Fix code in the commit that introduced it.** When review or CI finds a problem, don't add a "fix review comments" commit. Make a fixup commit and fold it in:
  ```bash
  git commit --fixup=<sha-of-commit-being-fixed>
  GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash dev-v2
  git push --force-with-lease          # only ever on your own wp<N>-* branch
  ```
  Rebase onto the latest `dev-v2` the same way instead of merging `dev-v2` into your branch.
- Keep refactors separate from behavior changes. Crypto PRs should stay under about 400 changed lines, not counting vector files.
- Match the surrounding code style. New ML-KEM code is generic over the parameter set; don't add more `_512/_768/_1024` copies.
- Add a line under `## Unreleased` in `CHANGELOG.md` for user-visible changes. Version numbers live in **both** `Cargo.toml` and `pyproject.toml`.

### Before saying you're done

Run all of these and report the results:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --no-fail-fast
maturin develop && pytest python/tests
```

Then prove every commit in the branch passes, not only the tip:

```bash
git rebase --exec 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --no-fail-fast && maturin develop && pytest python/tests' dev-v2
```

If you touched secret-handling code, also complete the PR checklist below and include evidence (e.g. the assembly grep output) in the PR.

## Online sources

Standards and advisories change. At the start of each WP, and whenever you rely on a spec detail or a vulnerability claim:

1. Check the primary sources listed in `PLAN-2.0.md` §9 (FIPS 203, SP 800-227, ACVP, C2SP/Wycheproof, NVD/GHSA/RustSec, pqc-forum).
2. Record in the PR: source URL, date checked, and what you found (including "no change").
3. Treat blogs, news, and search-engine summaries as leads. Confirm on the primary source before acting on them, and label anything unconfirmed as such.
4. External test vectors are never committed. They're downloaded at test time from a pinned commit and checked against `tests/vectors/manifest.json` (SHA-256). Don't silently change a pin or a hash.
5. Other implementations (Go `crypto/mlkem`, BoringSSL, RustCrypto `ml-kem`, libcrux) are for reading and for comparing outputs in dev-only tests. Never copy their code into this repo, not even with edits. Write ours from the FIPS 203 text. If you think copying is needed, stop and ask.

## Security-review agents

When asked to audit code (WP-8/WP-9), you are a reviewer, not an implementer: don't change code in the same task unless told to. For each issue, report:

```
ID: SEC-<NNN>
Title:
Severity: Critical / High / Medium / Low / Info (with one-line rationale)
Location: path:line (function)
Class: timing | memory-hygiene | input-validation | rng | panic/DoS | api-misuse | spec-deviation | supply-chain
Evidence: what you observed (code, asm snippet, test output). Mark it "hypothesis" if not demonstrated.
Related: CVE / paper / spec section, with link
Legacy impact: does a fix change Kyber v1.0.5 output? (must be "no", or the fix needs another approach)
Suggested fix + test that would catch a regression
```

Check at least: everything in the constant-time rules above; KyberSlash (division by q) and Clangover (mask-to-branch) patterns in `poly`, `polyvec` and `verify`; implicit-rejection selection; input checks; zeroization on every exit path including errors; RNG source and error handling; reachability of panics from Python; and key/algorithm confusion in the Python API (cf. 2026 CVEs about binding a key to the wrong pair). Report "no findings" per area explicitly instead of omitting it.

## PR checklist (copy into the PR description)

```
- [ ] Spec sections cited in code for new crypto logic
- [ ] Legacy golden vectors pass unchanged
- [ ] No secret-dependent branches, divisions, or indexing (asm checked: yes/no/n.a.)
- [ ] Secret intermediates zeroized on all paths
- [ ] Inputs validated before secret-dependent work
- [ ] No new runtime deps; no unsafe; no panics on untrusted input
- [ ] Tests added (vectors for crypto); fmt/clippy/test/pytest green on every commit (`git rebase --exec`)
- [ ] Review fixes folded into the commits they fix (no "fix review" commits); rebased on current `dev-v2`
- [ ] CHANGELOG updated (if user-visible)
- [ ] Sources checked: <url> — <date> — <result>
```
