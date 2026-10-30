//! ML-KEM (FIPS 203) core, work in progress.
//!
//! Round-3 Kyber and ML-KEM differ in `G(d || k)`, the missing `H(m)` and the
//! missing `H(c)` in the KDF, so the KEM layer is separate code. The
//! primitives below it are shared with `crate::kyber` where verified. New code
//! is generic over `k` (`params::ParamSet`, `polyvec::PolyVec`); do not add
//! another `_512/_768/_1024` copy.
//!
//! # What is shared with the legacy code, and what is not
//!
//! Audit for WP-2 against FIPS 203 (final, published 2024-08-13). Every
//! "shared" row is checked by `tests/mlkem_shared_primitives.rs` (or the unit
//! tests next to the new code) against a literal transcription of the
//! algorithm, or against hashlib vectors for SHA-3/SHAKE.
//!
//! Shared as is:
//! - `fips202` / `symmetric`: H = `sha3_256`, G = `sha3_512`, J and PRF =
//!   `shake256`, XOF = SHAKE128 absorb / squeeze-blocks. Lengths around the
//!   rates and multi-block outputs are covered. `sha3_256` / `sha3_512` now
//!   zeroize their state. `xof_absorb_bytes(state, rho, a, b)` absorbs
//!   `rho || a || b`, so Algorithm 13's `rho || j || i` is `(j, i)`.
//! - `reduce`: Montgomery and Barrett reduction, pure arithmetic mod q, the
//!   only division is by the public constant q.
//! - `ntt`: `ZETAS` are `17^BitRev7(i) * 2^16 mod q`. `ntt_forward` is
//!   Algorithm 9. `ntt_inverse` is Algorithm 10 times 2^16 ("tomont"), and
//!   `poly_base_multiply` is Algorithms 11/12 times 2^-16, so compose them as
//!   K-PKE does in the legacy code and the factors cancel.
//! - `cbd`: `cbd2` and `cbd3` are Algorithm 8 (signed representatives instead
//!   of `mod q`, equal mod q).
//! - `poly_tobytes`: ByteEncode12 for coefficients in (-q, q).
//! - Compress / Decompress for d = 1 (`poly_tomsg`), 4, 5 and 10 are exact
//!   over all of Z_q, and Decompress for d = 11 is exact. `poly_tomsg` is
//!   arithmetically right; see "Checked in release builds" below.
//!   K-PKE does not call them: `compress::poly_compress` and `poly_decompress`
//!   are generic over d and cover every width, since the d = 10 / 11 legacy loops
//!   exist only inside the per-level polyvec functions.
//! - `rej_uniform` (now `pub(crate)`), used by `sample::sample_ntt`.
//!
//! Not shared:
//! - `poly_frombytes`: no reduction mod q, unlike ByteDecode12. A modulus
//!   check built on it would always pass. Use `PolyVec::from_bytes`.
//! - Compress_11 (`polyvec_compress_1024`): the multiplier 10321345 >> 35 is
//!   not exact for d = 11 and is off by one at the residues 1875 and 3125.
//!   Kyber-1024 output must not change (applying the fix makes the golden
//!   vector test fail), so ML-KEM-1024 uses `compress::poly_compress` with d = 11,
//!   with `((x << 11) + 1664) * 645084 >> 31`. That multiplier is checked
//!   against FIPS 203 (4.7) for every residue; the pq-crystals reference
//!   implementation also uses it. Decompress_11 in the legacy code is exact.
//! - `poly_frommsg`: builds the message mask with `wrapping_neg()` of a bit,
//!   the pattern of CVE-2024-37880. rustc 1.95 did not turn it into a branch
//!   on x86_64 or aarch64 (checked in release builds), but nothing guarantees
//!   that for other compilers or flags, so ML-KEM needs its own version that
//!   passes the bit through an optimization barrier: `compress::poly_from_msg`.
//! - `verify` / `cmov` (`verify.rs`): no optimization barrier and a
//!   caller-supplied length. ML-KEM needs its own compare and select.
//! - `poly_getnoise_*`: eta is hard-coded per function. Call the PRF and
//!   `cbd2` / `cbd3` with `ParamSet::ETA1` / `ETA2` instead.
//! - `gen_matrix*`, `indcpa_*`, `crypto_kem_*`, the `Polyvec{512,768,1024}`
//!   types and `api.rs`: per-level copies and round-3 logic.
//!
//! # Checked in release builds
//!
//! rustc 1.95, `--release`, inspected with objdump (x86_64) and `--emit asm`
//! (aarch64-linux-android): `poly_tomsg`, `poly_compress`, `poly_compress_1024`,
//! `polyvec_compress`, `polyvec_compress_1024`, `poly_tobytes` and
//! `compress::poly_compress` with d = 11 (x86_64 only) contain no division, and every
//! conditional branch compares a length, a loop counter or a bounds check, never
//! a coefficient. `sha3_256` and `sha3_512` keep the stores that zero their
//! state. This is not the WP-8 gate: armv7 and i686 are not covered and the
//! result holds for this toolchain only.
//!
//! K-PKE (WP-3), same toolchain, x86_64, objdump of the release test binary:
//! `kpke::keygen`, `encrypt`, `decrypt`, `sample_noise` and `matrix_row` contain
//! no division. Probes around `poly_from_msg`, `poly_compress` (d = 1, 10) and
//! `poly_decompress` (d = 10) show conditional branches only on loop counters,
//! output bounds and slice ends. `poly_from_msg` turns each message bit into a
//! mask with `bt` / `sbb`, stores it to the stack through `black_box` and applies
//! it with `and`. The `setcc` / `cmov` pairs in `decrypt` compare slice offsets
//! (public). Neither armv7 nor i686 nor aarch64 was looked at for K-PKE.
//!
//! Known limit: the Keccak permutation spills round temporaries into its own
//! stack frame (about 70 spill stores in a 0xf8-byte frame on x86_64), and
//! zeroizing the state array cannot clear those. Closing that needs stack
//! scrubbing, which is out of scope here; WP-9 should record it.
//!
//! Range discipline: `poly_add` and `poly_sub` are plain `i16` operations (they
//! panic on overflow in debug builds, wrap in release), so reduce between
//! steps as the legacy code does.

#[cfg(test)]
mod acvp_tests;
#[cfg(test)]
mod cctv_tests;
pub mod check;
pub mod compress;
pub mod ct;
#[cfg(test)]
mod differential_tests;
pub mod kem;
pub mod kpke;
pub mod params;
pub mod polyvec;
pub mod sample;
#[cfg(test)]
mod wycheproof_tests;
