#![allow(clippy::needless_range_loop, dead_code)]

pub const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;
const SHA3_256_RATE: usize = 136;
const SHA3_512_RATE: usize = 72;
const NROUNDS: usize = 24;

use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeccakState {
    pub s: [u64; 25],
    pub pos: usize,
}

impl KeccakState {
    pub fn new() -> Self {
        KeccakState {
            s: [0u64; 25],
            pos: 0usize,
        }
    }

    pub fn reset(&mut self) {
        self.s = [0u64; 25];
        self.pos = 0;
    }
}

/// Rotate left operation for 64-bit values.
/// Rotates `value` left by `offset` bits.
fn rotate_left(value: u64, offset: u64) -> u64 {
    (value << offset) | (value >> (64 - offset))
}

/// Load 8 bytes from little-endian byte array into a 64-bit unsigned integer.
pub fn load_u64(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    for i in 0..8 {
        result |= (bytes[i] as u64) << (8 * i);
    }
    result
}

/// Store a 64-bit unsigned integer into little-endian byte array.
pub fn store_u64(bytes: &mut [u8], mut value: u64) {
    for byte in bytes.iter_mut().take(8) {
        *byte = value as u8;
        value >>= 8;
    }
}

const KECCAKF_ROUNDCONSTANTS: [u64; NROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

pub fn keccakf1600_statepermute(state: &mut [u64]) {
    let mut aba = state[0];
    let mut abe = state[1];
    let mut abi = state[2];
    let mut abo = state[3];
    let mut abu = state[4];
    let mut aga = state[5];
    let mut age = state[6];
    let mut agi = state[7];
    let mut ago = state[8];
    let mut agu = state[9];
    let mut aka = state[10];
    let mut ake = state[11];
    let mut aki = state[12];
    let mut ako = state[13];
    let mut aku = state[14];
    let mut ama = state[15];
    let mut ame = state[16];
    let mut ami = state[17];
    let mut amo = state[18];
    let mut amu = state[19];
    let mut asa = state[20];
    let mut ase = state[21];
    let mut asi = state[22];
    let mut aso = state[23];
    let mut asu = state[24];

    for round in (0..NROUNDS).step_by(2) {
        let mut bca = aba ^ aga ^ aka ^ ama ^ asa;
        let mut bce = abe ^ age ^ ake ^ ame ^ ase;
        let mut bci = abi ^ agi ^ aki ^ ami ^ asi;
        let mut bco = abo ^ ago ^ ako ^ amo ^ aso;
        let mut bcu = abu ^ agu ^ aku ^ amu ^ asu;

        let mut da = bcu ^ rotate_left(bce, 1);
        let mut de = bca ^ rotate_left(bci, 1);
        let mut di = bce ^ rotate_left(bco, 1);
        let mut d_o = bci ^ rotate_left(bcu, 1);
        let mut du = bco ^ rotate_left(bca, 1);

        aba ^= da;
        bca = aba;
        age ^= de;
        bce = rotate_left(age, 44);
        aki ^= di;
        bci = rotate_left(aki, 43);
        amo ^= d_o;
        bco = rotate_left(amo, 21);
        asu ^= du;
        bcu = rotate_left(asu, 14);
        let mut eba = bca ^ ((!bce) & bci);
        eba ^= KECCAKF_ROUNDCONSTANTS[round];
        let mut ebe = bce ^ ((!bci) & bco);
        let mut ebi = bci ^ ((!bco) & bcu);
        let mut ebo = bco ^ ((!bcu) & bca);
        let mut ebu = bcu ^ ((!bca) & bce);

        abo ^= d_o;
        bca = rotate_left(abo, 28);
        agu ^= du;
        bce = rotate_left(agu, 20);
        aka ^= da;
        bci = rotate_left(aka, 3);
        ame ^= de;
        bco = rotate_left(ame, 45);
        asi ^= di;
        bcu = rotate_left(asi, 61);
        let mut ega = bca ^ ((!bce) & bci);
        let mut ege = bce ^ ((!bci) & bco);
        let mut egi = bci ^ ((!bco) & bcu);
        let mut ego = bco ^ ((!bcu) & bca);
        let mut egu = bcu ^ ((!bca) & bce);

        abe ^= de;
        bca = rotate_left(abe, 1);
        agi ^= di;
        bce = rotate_left(agi, 6);
        ako ^= d_o;
        bci = rotate_left(ako, 25);
        amu ^= du;
        bco = rotate_left(amu, 8);
        asa ^= da;
        bcu = rotate_left(asa, 18);
        let mut eka = bca ^ ((!bce) & bci);
        let mut eke = bce ^ ((!bci) & bco);
        let mut eki = bci ^ ((!bco) & bcu);
        let mut eko = bco ^ ((!bcu) & bca);
        let mut eku = bcu ^ ((!bca) & bce);

        abu ^= du;
        bca = rotate_left(abu, 27);
        aga ^= da;
        bce = rotate_left(aga, 36);
        ake ^= de;
        bci = rotate_left(ake, 10);
        ami ^= di;
        bco = rotate_left(ami, 15);
        aso ^= d_o;
        bcu = rotate_left(aso, 56);
        let mut ema = bca ^ ((!bce) & bci);
        let mut eme = bce ^ ((!bci) & bco);
        let mut emi = bci ^ ((!bco) & bcu);
        let mut emo = bco ^ ((!bcu) & bca);
        let mut emu = bcu ^ ((!bca) & bce);

        abi ^= di;
        bca = rotate_left(abi, 62);
        ago ^= d_o;
        bce = rotate_left(ago, 55);
        aku ^= du;
        bci = rotate_left(aku, 39);
        ama ^= da;
        bco = rotate_left(ama, 41);
        ase ^= de;
        bcu = rotate_left(ase, 2);
        let mut esa = bca ^ ((!bce) & bci);
        let mut ese = bce ^ ((!bci) & bco);
        let mut esi = bci ^ ((!bco) & bcu);
        let mut eso = bco ^ ((!bcu) & bca);
        let mut esu = bcu ^ ((!bca) & bce);

        bca = eba ^ ega ^ eka ^ ema ^ esa;
        bce = ebe ^ ege ^ eke ^ eme ^ ese;
        bci = ebi ^ egi ^ eki ^ emi ^ esi;
        bco = ebo ^ ego ^ eko ^ emo ^ eso;
        bcu = ebu ^ egu ^ eku ^ emu ^ esu;

        da = bcu ^ rotate_left(bce, 1);
        de = bca ^ rotate_left(bci, 1);
        di = bce ^ rotate_left(bco, 1);
        d_o = bci ^ rotate_left(bcu, 1);
        du = bco ^ rotate_left(bca, 1);

        eba ^= da;
        bca = eba;
        ege ^= de;
        bce = rotate_left(ege, 44);
        eki ^= di;
        bci = rotate_left(eki, 43);
        emo ^= d_o;
        bco = rotate_left(emo, 21);
        esu ^= du;
        bcu = rotate_left(esu, 14);
        aba = bca ^ ((!bce) & bci);
        aba ^= KECCAKF_ROUNDCONSTANTS[round + 1];
        abe = bce ^ ((!bci) & bco);
        abi = bci ^ ((!bco) & bcu);
        abo = bco ^ ((!bcu) & bca);
        abu = bcu ^ ((!bca) & bce);

        ebo ^= d_o;
        bca = rotate_left(ebo, 28);
        egu ^= du;
        bce = rotate_left(egu, 20);
        eka ^= da;
        bci = rotate_left(eka, 3);
        eme ^= de;
        bco = rotate_left(eme, 45);
        esi ^= di;
        bcu = rotate_left(esi, 61);
        aga = bca ^ ((!bce) & bci);
        age = bce ^ ((!bci) & bco);
        agi = bci ^ ((!bco) & bcu);
        ago = bco ^ ((!bcu) & bca);
        agu = bcu ^ ((!bca) & bce);

        ebe ^= de;
        bca = rotate_left(ebe, 1);
        egi ^= di;
        bce = rotate_left(egi, 6);
        eko ^= d_o;
        bci = rotate_left(eko, 25);
        emu ^= du;
        bco = rotate_left(emu, 8);
        esa ^= da;
        bcu = rotate_left(esa, 18);
        aka = bca ^ ((!bce) & bci);
        ake = bce ^ ((!bci) & bco);
        aki = bci ^ ((!bco) & bcu);
        ako = bco ^ ((!bcu) & bca);
        aku = bcu ^ ((!bca) & bce);

        ebu ^= du;
        bca = rotate_left(ebu, 27);
        ega ^= da;
        bce = rotate_left(ega, 36);
        eke ^= de;
        bci = rotate_left(eke, 10);
        emi ^= di;
        bco = rotate_left(emi, 15);
        eso ^= d_o;
        bcu = rotate_left(eso, 56);
        ama = bca ^ ((!bce) & bci);
        ame = bce ^ ((!bci) & bco);
        ami = bci ^ ((!bco) & bcu);
        amo = bco ^ ((!bcu) & bca);
        amu = bcu ^ ((!bca) & bce);

        ebi ^= di;
        bca = rotate_left(ebi, 62);
        ego ^= d_o;
        bce = rotate_left(ego, 55);
        eku ^= du;
        bci = rotate_left(eku, 39);
        ema ^= da;
        bco = rotate_left(ema, 41);
        ese ^= de;
        bcu = rotate_left(ese, 2);
        asa = bca ^ ((!bce) & bci);
        ase = bce ^ ((!bci) & bco);
        asi = bci ^ ((!bco) & bcu);
        aso = bco ^ ((!bcu) & bca);
        asu = bcu ^ ((!bca) & bce);
    }

    state[0] = aba;
    state[1] = abe;
    state[2] = abi;
    state[3] = abo;
    state[4] = abu;
    state[5] = aga;
    state[6] = age;
    state[7] = agi;
    state[8] = ago;
    state[9] = agu;
    state[10] = aka;
    state[11] = ake;
    state[12] = aki;
    state[13] = ako;
    state[14] = aku;
    state[15] = ama;
    state[16] = ame;
    state[17] = ami;
    state[18] = amo;
    state[19] = amu;
    state[20] = asa;
    state[21] = ase;
    state[22] = asi;
    state[23] = aso;
    state[24] = asu;
}

fn keccak_squeezeblocks(h: &mut [u8], mut nblocks: usize, s: &mut [u64], r: usize) {
    let mut idx = 0usize;
    while nblocks > 0 {
        keccakf1600_statepermute(s);
        for i in 0..r / 8 {
            store_u64(&mut h[idx + 8 * i..], s[i])
        }
        idx += r;
        nblocks -= 1;
    }
}

pub fn shake128_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut KeccakState) {
    keccak_squeezeblocks(out, nblocks, &mut state.s, SHAKE128_RATE);
}

pub fn shake256(out: &mut [u8], mut outlen: usize, input: &[u8], inlen: usize) {
    let mut state = KeccakState::new();
    let mut idx = 0;
    shake256_absorb_once(&mut state, input, inlen);
    let nblocks = outlen / SHAKE256_RATE;
    shake256_squeezeblocks(&mut out[idx..], nblocks, &mut state);
    outlen -= nblocks * SHAKE256_RATE;
    idx += nblocks * SHAKE256_RATE;
    shake256_squeeze(&mut out[idx..], outlen, &mut state);
}

pub fn sha3_256(h: &mut [u8], input: &[u8], inlen: usize) {
    let mut s = [0u64; 25];
    keccak_absorb_once(&mut s, SHA3_256_RATE, input, inlen, 0x06);
    keccakf1600_statepermute(&mut s);
    for i in 0..4 {
        store_u64(&mut h[8 * i..], s[i]);
    }
}

pub fn sha3_512(h: &mut [u8], input: &[u8], inlen: usize) {
    let mut s = [0u64; 25];
    keccak_absorb_once(&mut s, SHA3_512_RATE, input, inlen, 0x06);
    keccakf1600_statepermute(&mut s);
    for i in 0..8 {
        store_u64(&mut h[8 * i..], s[i]);
    }
}

fn keccak_finalize(s: &mut [u64], pos: usize, r: usize, p: u8) {
    s[pos / 8] ^= (p as u64) << 8 * (pos % 8);
    s[r / 8 - 1] ^= 1u64 << 63;
}

pub fn keccak_absorb_once(s: &mut [u64], r: usize, input: &[u8], mut inlen: usize, p: u8) {
    s.fill(0);

    let mut idx = 0usize;
    while inlen >= r {
        for i in 0..(r / 8) {
            s[i] ^= load_u64(&input[idx + 8 * i..]);
        }
        idx += r;
        inlen -= r;
        keccakf1600_statepermute(s);
    }

    for i in 0..inlen {
        s[i / 8] ^= (input[idx + i] as u64) << 8 * (i % 8);
    }
    s[inlen / 8] ^= (p as u64) << 8 * (inlen % 8);
    s[(r - 1) / 8] ^= 1u64 << 63;
}

fn keccak_squeeze(
    out: &mut [u8],
    mut outlen: usize,
    s: &mut [u64],
    mut pos: usize,
    r: usize,
) -> usize {
    let mut idx = 0;
    while outlen > 0 {
        if pos == r {
            keccakf1600_statepermute(s);
            pos = 0
        }
        let mut i = pos;
        while i < r && outlen > 0 {
            if outlen >= 8 && i % 8 == 0 && i + 8 <= r {
                store_u64(&mut out[idx..], s[i / 8]);
                idx += 8;
                outlen -= 8;
                i += 8;
            } else {
                out[idx] = (s[i / 8] >> (8 * (i % 8))) as u8;
                idx += 1;
                outlen -= 1;
                i += 1;
            }
        }
        pos = i;
    }
    pos
}

pub fn shake128_absorb_once(state: &mut KeccakState, input: &[u8], inlen: usize) {
    keccak_absorb_once(&mut state.s, SHAKE128_RATE, input, inlen, 0x1F);
    state.pos = SHAKE128_RATE;
}

fn shake256_init(state: &mut KeccakState) {
    state.reset();
}

fn shake256_finalize(state: &mut KeccakState) {
    keccak_finalize(&mut state.s, state.pos, SHAKE256_RATE, 0x1F);
    state.pos = SHAKE256_RATE;
}

fn shake256_squeeze(out: &mut [u8], outlen: usize, state: &mut KeccakState) {
    state.pos = keccak_squeeze(out, outlen, &mut state.s, state.pos, SHAKE256_RATE);
}

fn shake256_absorb_once(state: &mut KeccakState, input: &[u8], inlen: usize) {
    keccak_absorb_once(&mut state.s, SHAKE256_RATE, input, inlen, 0x1F);
    state.pos = SHAKE256_RATE;
}

fn shake256_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut KeccakState) {
    keccak_squeezeblocks(out, nblocks, &mut state.s, SHAKE256_RATE);
}

fn shake128(out: &mut [u8], mut outlen: usize, input: &[u8], inlen: usize) {
    let mut state = KeccakState::new();
    let mut idx = 0;
    shake128_absorb_once(&mut state, input, inlen);
    let nblocks = outlen / SHAKE128_RATE;
    shake128_squeezeblocks(&mut out[idx..], nblocks, &mut state);
    outlen -= nblocks * SHAKE128_RATE;
    idx += nblocks * SHAKE128_RATE;
    shake128_squeeze(&mut out[idx..], outlen, &mut state);
}

fn shake128_squeeze(out: &mut [u8], outlen: usize, state: &mut KeccakState) {
    state.pos = keccak_squeeze(out, outlen, &mut state.s, state.pos, SHAKE128_RATE);
}
