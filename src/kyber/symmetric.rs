#![allow(dead_code)]

pub use super::fips202::{
    sha3_256, sha3_512, shake128_absorb_once, shake256, KeccakState, SHAKE128_RATE,
};

pub const AES256CTR_BLOCKBYTES: usize = 64;

pub const XOF_BLOCKBYTES: usize = SHAKE128_RATE;

pub type XofState = KeccakState;

/// SHA3-256 hash function (H) used in Kyber for hashing messages
/// and other cryptographic operations requiring a 256-bit hash.
pub fn hash_sha3_256(out: &mut [u8], input: &[u8], inlen: usize) {
    sha3_256(out, input, inlen);
}

/// SHA3-512 hash function (G) used in Kyber for generating
/// pseudorandom bytes from a seed.
pub fn hash_sha3_512(out: &mut [u8], input: &[u8], inlen: usize) {
    sha3_512(out, input, inlen);
}

/// XOF (Extendable Output Function) absorb operation for SHAKE128.
/// Absorbs input bytes into the XOF state with coordinate parameters.
pub fn xof_absorb_bytes(state: &mut XofState, input: &[u8], x_coord: u8, y_coord: u8) {
    kyber_shake128_absorb(state, input, x_coord, y_coord);
}

/// XOF squeeze operation that outputs blocks of SHAKE128.
pub fn xof_squeeze_blocks(out: &mut [u8], outblocks: usize, state: &mut XofState) {
    kyber_shake128_squeezeblocks(out, outblocks, state);
}

/// PRF (Pseudorandom Function) using SHAKE256 for expanding a key
/// and nonce into arbitrary-length output.
/// Used in Kyber for generating random bytes from a seed and nonce.
pub fn shake256_prf_expand(out: &mut [u8], outbytes: usize, key: &[u8], nonce: u8) {
    shake256_prf(out, outbytes, key, nonce);
}

/// KDF (Key Derivation Function) using SHAKE256 to derive
/// a 32-byte output from input bytes.
/// Used in Kyber for key expansion.
pub fn shake256_kdf(out: &mut [u8], input: &[u8], inlen: usize) {
    shake256(out, 32, input, inlen);
}

/// Internal: Absorbs input into SHAKE128 XOF with extended seed (coordinates).
/// Combines the input seed with x and y coordinates for domain separation.
fn kyber_shake128_absorb(state: &mut KeccakState, input: &[u8], x_coord: u8, y_coord: u8) {
    let mut extseed = [0u8; 34];
    extseed[..32].copy_from_slice(input);
    extseed[32] = x_coord;
    extseed[33] = y_coord;
    shake128_absorb_once(state, &extseed, 34);
}

/// Internal: Squeezes output blocks from SHAKE128 XOF state.
fn kyber_shake128_squeezeblocks(output: &mut [u8], nblocks: usize, state: &mut KeccakState) {
    super::fips202::shake128_squeezeblocks(output, nblocks, state);
}

/// Internal: SHA implementation that extends a key and nonce
/// into arbitrary-length output using SHAKE256.
fn shake256_prf(output: &mut [u8], outlen: usize, key: &[u8], nonce: u8) {
    let mut extkey = [0u8; 33];
    extkey[..32].copy_from_slice(key);
    extkey[32] = nonce;
    shake256(output, outlen, &extkey, 33);
}
