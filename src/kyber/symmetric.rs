#![allow(dead_code)]

pub use super::fips202::{
    sha3_256, sha3_512, shake128_absorb_once, shake256, KeccakState, SHAKE128_RATE,
};

pub const AES256CTR_BLOCKBYTES: usize = 64;

pub const XOF_BLOCKBYTES: usize = SHAKE128_RATE;

pub type XofState = KeccakState;

pub fn hash_h(out: &mut [u8], input: &[u8], inlen: usize) {
    sha3_256(out, input, inlen);
}

pub fn hash_g(out: &mut [u8], input: &[u8], inlen: usize) {
    sha3_512(out, input, inlen);
}

pub fn xof_absorb(state: &mut XofState, input: &[u8], x: u8, y: u8) {
    kyber_shake128_absorb(state, input, x, y);
}

pub fn xof_squeezeblocks(out: &mut [u8], outblocks: usize, state: &mut XofState) {
    kyber_shake128_squeezeblocks(out, outblocks, state);
}

pub fn prf(out: &mut [u8], outbytes: usize, key: &[u8], nonce: u8) {
    shake256_prf(out, outbytes, key, nonce);
}

pub fn kdf(out: &mut [u8], input: &[u8], inlen: usize) {
    shake256(out, 32, input, inlen);
}

fn kyber_shake128_absorb(s: &mut KeccakState, input: &[u8], x: u8, y: u8) {
    let mut extseed = [0u8; 34];
    extseed[..32].copy_from_slice(input);
    extseed[32] = x;
    extseed[33] = y;
    shake128_absorb_once(s, &extseed, 34);
}

fn kyber_shake128_squeezeblocks(output: &mut [u8], nblocks: usize, s: &mut KeccakState) {
    super::fips202::shake128_squeezeblocks(output, nblocks, s);
}

fn shake256_prf(output: &mut [u8], outlen: usize, key: &[u8], nonce: u8) {
    let mut extkey = [0u8; 33];
    extkey[..32].copy_from_slice(key);
    extkey[32] = nonce;
    shake256(output, outlen, &extkey, 33);
}
