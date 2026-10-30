//! WP-2: checks that the legacy primitives ML-KEM wants to reuse agree with
//! the FIPS 203 / FIPS 202 text. Each reference below is a literal, slow
//! transcription of the algorithm in the standard (integers mod q, bit
//! arrays), written from the PDF and not from the code under test.
//!
//! Source: FIPS 203 (final, published 2024-08-13),
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf>.
//! The SHA-3/SHAKE expected values were produced with Python's hashlib
//! (OpenSSL), an independent implementation; the input is the byte pattern
//! `i % 251` for `i` in `0..len`.

use pykyber::kyber::cbd::{cbd2, cbd3};
use pykyber::kyber::fips202::{sha3_256, sha3_512, shake256};
use pykyber::kyber::ntt::{ntt_forward, ntt_inverse, ZETAS};
use pykyber::kyber::params::{
    KYBER_1024_POLYCOMPRESSEDBYTES, KYBER_N, KYBER_POLYBYTES, KYBER_POLYCOMPRESSEDBYTES, KYBER_Q,
    KYBER_SYMBYTES,
};
use pykyber::kyber::poly::{
    poly_base_multiply, poly_compress, poly_compress_1024, poly_decompress, poly_decompress_1024,
    poly_tobytes, poly_tomsg, Poly,
};
use pykyber::kyber::polyvec::{
    polyvec_compress, polyvec_compress_1024, polyvec_decompress, polyvec_decompress_1024, Polyvec,
    Polyvec1024,
};
use pykyber::kyber::symmetric::{
    shake256_prf_expand, xof_absorb_bytes, xof_squeeze_blocks, XofState, XOF_BLOCKBYTES,
};

const Q: i64 = KYBER_Q as i64;
const R: i64 = 1 << 16;
/// The 256th root of unity of FIPS 203 section 2.5 (written zeta there).
const ZETA: i64 = 17;
/// 128^-1 mod q, the scaling in Algorithm 10 line 14.
const HALF_N_INV: i64 = 3303;
/// Coefficient pairs, i.e. the degree-one factors of the NTT domain.
const PAIRS: usize = KYBER_N / 2;
/// Digest sizes of SHA3-256 (H) and SHA3-512 (G).
const H_BYTES: usize = 32;
const G_BYTES: usize = 64;
/// Bytes of a message / ByteEncode_1 polynomial, and of ByteEncode_d.
const MSG_BYTES: usize = KYBER_SYMBYTES;
const fn encoded_bytes(d: usize) -> usize {
    KYBER_N * d / u8::BITS as usize
}
/// Bytes of the PRF output for eta (Algorithm 8 takes 64 * eta bytes).
const fn cbd_bytes(eta: usize) -> usize {
    KYBER_N / 4 * eta
}
/// Polynomials in the exhaustive compression tests: 26 are needed to hold every
/// residue and negative representative, rounded up to a multiple of 1, 2, 3 and
/// 4 so the tests can build vectors of any Kyber size from them.
const TEST_POLYS: usize = 36;
/// Random inputs per differential test.
const ROUNDS: usize = 50;
const CBD_ROUNDS: usize = 200;
/// The residues where the legacy d = 11 routine is off by one.
const LEGACY_DEVIATING: [i16; 2] = [1875, 3125];

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic xorshift, enough to cover the input space without a new dependency.
struct Prng(u64);
impl Prng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

fn modq(x: i64) -> i64 {
    x.rem_euclid(Q)
}

fn pow_mod(mut b: i64, mut e: u32) -> i64 {
    let mut r = 1;
    b = modq(b);
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % Q;
        }
        b = b * b % Q;
        e >>= 1;
    }
    r
}

fn bitrev7(i: usize) -> u32 {
    (0..7).fold(0, |acc, b| acc | (((i >> b) & 1) << (6 - b)) as u32)
}

/// zeta^BitRev7(i) mod q with zeta = 17 (FIPS 203 section 2.5, Appendix A).
fn zeta_pow(i: usize) -> i64 {
    pow_mod(ZETA, bitrev7(i))
}

// ---- FIPS 202: H, G, J, PRF, XOF ------------------------------------------

#[test]
fn sha3_256_matches_hashlib() {
    // H(s) = SHA3-256(s), FIPS 203 (4.4). Lengths straddle the 136-byte rate.
    let cases = [
        (
            0,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        ),
        (
            1,
            "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0",
        ),
        (
            135,
            "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2",
        ),
        (
            136,
            "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5",
        ),
        (
            137,
            "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca",
        ),
        (
            1600,
            "ee74d621ed5fca2a7e0df941f27d648cbd61ef3fca28e5e41e2223f5bd524457",
        ),
    ];
    for (len, want) in cases {
        let input = pattern(len);
        let mut out = [0u8; H_BYTES];
        sha3_256(&mut out, &input, input.len());
        assert_eq!(hex(&out), want, "SHA3-256 len {len}");
    }
}

#[test]
fn sha3_512_matches_hashlib() {
    // G(c) = SHA3-512(c), FIPS 203 (4.5). Lengths straddle the 72-byte rate.
    let cases = [
        (0, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
        (64, "cb29601efbee71f4dfbb7f1c2bdaeafdb212df6ae35f8bb1ee6c0a245b99f3f35a82957567a30cfb01ae28b94c7223a62c5c786e8624b8faddcb913e3ab2ce71"),
        (71, "3ccc850d53a1287af7b4560b2ef0d43eb5d9a80d62a0e9cf1dbc040135921104d4395168e90bfc871773ebb34bca1bd67056e1cc7dc7a48ff7c3167d389f117c"),
        (72, "5d63f2bbe971a983ac6847480106e4e1264ee3a0befd79954914e1d86e795b2e18238f12fc5e46cb9cc78efdec610a93647cc04e1c23d8caaa6a58c21dd26c07"),
        (73, "921d9b7b2b0f3066a1646dbb058c979cb3925dec0f8c269faaa7f9648e73465ae55ec527257d5d5e1cfdbf5d6799bea1004b6186f5108c74e3b92fe924166558"),
        (1600, "50341eb0b689264de10ddaefb0fb2dd7612c8cb4f53de0cd87652595670760f915331c2f3925dc2f039868c9462f871112ed463f64cfa1d9ec00581e7bd08cf6"),
    ];
    for (len, want) in cases {
        let input = pattern(len);
        let mut out = [0u8; G_BYTES];
        sha3_512(&mut out, &input, input.len());
        assert_eq!(hex(&out), want, "SHA3-512 len {len}");
    }
}

#[test]
fn shake256_matches_hashlib() {
    // J(s) = SHAKE256(s, 256 bits) with s = z || c up to 32 + 1568 bytes, and
    // PRF_eta outputs of 64 * eta bytes (128 or 192, i.e. more than one block).
    // The expected value is SHA3-256 of the full SHAKE256 output.
    let cases = [
        (
            0,
            32,
            "46b14d3a928b31be5d9f6061fd205dd3d18098988afe3f1d5582236c4a55e937",
        ),
        (
            33,
            192,
            "d538d308117d3f95872dc11773170ccfd47e51c4a2edc54638f6d1a8a52eddbb",
        ),
        (
            135,
            136,
            "17c08e19c1fb127796032dc1d21e52d53073e28f0f8cc7c654387ba3a48298fa",
        ),
        (
            136,
            200,
            "0d95a081b2c703ed77878a0fbc83b3f77338d51e61ccb36d0c7a4966c3a0a77e",
        ),
        (
            1600,
            32,
            "87af496f9906d39ce1056f3eb4432874c8d498e014aa428996caff25c5daa2cf",
        ),
        (
            1600,
            300,
            "d8d474b58aaae109f477d90b0f90395eff0ad605c7fda5601e57aa454e77d8e2",
        ),
    ];
    for (len, outlen, want) in cases {
        let input = pattern(len);
        let mut out = vec![0u8; outlen];
        shake256(&mut out, outlen, &input, input.len());
        let mut digest = [0u8; H_BYTES];
        sha3_256(&mut digest, &out, out.len());
        assert_eq!(hex(&digest), want, "SHAKE256 len {len} out {outlen}");
    }
}

#[test]
fn prf_is_shake256_of_seed_and_counter() {
    // PRF_eta(s, b) = SHAKE256(s || b, 8 * 64 * eta), FIPS 203 (4.3).
    let seed = pattern(32);
    for (eta, nonce) in [(2usize, 0u8), (3, 1), (2, 7), (3, 255)] {
        let mut got = vec![0u8; cbd_bytes(eta)];
        shake256_prf_expand(&mut got, cbd_bytes(eta), &seed, nonce);
        let mut input = seed.clone();
        input.push(nonce);
        let mut want = vec![0u8; cbd_bytes(eta)];
        shake256(&mut want, cbd_bytes(eta), &input, input.len());
        assert_eq!(got, want);
    }
}

#[test]
fn xof_is_shake128_of_seed_and_indices() {
    // XOF = SHAKE128 over rho || j || i, FIPS 203 Algorithm 7 / section 4.1.
    let seed = pattern(32);
    let mut state = XofState::new();
    xof_absorb_bytes(&mut state, &seed, 1, 2);
    const BLOCKS: usize = 3;
    let mut buf = [0u8; BLOCKS * XOF_BLOCKBYTES];
    xof_squeeze_blocks(&mut buf, BLOCKS, &mut state);
    let mut digest = [0u8; H_BYTES];
    sha3_256(&mut digest, &buf, buf.len());
    assert_eq!(
        hex(&digest),
        "9d1773faeaf6307f2b09a1cc695c318715b8f7e2c802f9418bbf07146c9294dd"
    );
}

// ---- NTT (Algorithms 9, 10, 11, 12) ----------------------------------------

#[test]
fn zetas_are_montgomery_form_of_17_pow_bitrev7() {
    // The legacy table holds zeta^BitRev7(i) * 2^16 mod q (centered); Appendix A
    // lists zeta^BitRev7(i) mod q.
    for (i, &z) in ZETAS.iter().enumerate().skip(1) {
        assert_eq!(modq(z as i64), zeta_pow(i) * R % Q, "ZETAS[{i}]");
    }
}

fn spec_ntt(f: &[i64]) -> Vec<i64> {
    let mut f: Vec<i64> = f.to_vec();
    let mut i = 1;
    let mut len = PAIRS;
    while len >= 2 {
        let mut start = 0;
        while start < KYBER_N {
            let zeta = zeta_pow(i);
            i += 1;
            for j in start..start + len {
                let t = zeta * f[j + len] % Q;
                f[j + len] = modq(f[j] - t);
                f[j] = modq(f[j] + t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
    f
}

fn spec_ntt_inverse(f: &[i64]) -> Vec<i64> {
    let mut f: Vec<i64> = f.to_vec();
    let mut i = 127;
    let mut len = 2;
    while len <= PAIRS {
        let mut start = 0;
        while start < KYBER_N {
            let zeta = zeta_pow(i);
            i -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = modq(t + f[j + len]);
                f[j + len] = zeta * modq(f[j + len] - t) % Q;
            }
            start += 2 * len;
        }
        len *= 2;
    }
    f.iter().map(|x| x * HALF_N_INV % Q).collect()
}

fn spec_multiply_ntts(f: &[i64], g: &[i64]) -> Vec<i64> {
    let mut h = vec![0i64; KYBER_N];
    for i in 0..PAIRS {
        let gamma = zeta_pow_odd(i);
        let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);
        h[2 * i] = modq(a0 * b0 + a1 * b1 % Q * gamma);
        h[2 * i + 1] = modq(a0 * b1 + a1 * b0);
    }
    h
}

/// zeta^(2*BitRev7(i)+1) mod q, the gamma of Algorithm 11.
fn zeta_pow_odd(i: usize) -> i64 {
    pow_mod(ZETA, 2 * bitrev7(i) + 1)
}

fn random_residues(rng: &mut Prng) -> Vec<i64> {
    (0..256).map(|_| (rng.next() % Q as u64) as i64).collect()
}

#[test]
fn ntt_matches_algorithm_9() {
    let mut rng = Prng(0x9e3779b97f4a7c15);
    for _ in 0..ROUNDS {
        let f = random_residues(&mut rng);
        let mut c: Vec<i16> = f.iter().map(|&x| x as i16).collect();
        ntt_forward(&mut c);
        let got: Vec<i64> = c.iter().map(|&x| modq(x as i64)).collect();
        assert_eq!(got, spec_ntt(&f));
    }
}

#[test]
fn inverse_ntt_is_algorithm_10_times_montgomery_factor() {
    // ntt_inverse is the reference "invntt_tomont": the 1441 scaling folds a
    // factor 2^16 into the result, so it equals Algorithm 10 times R mod q.
    let mut rng = Prng(0xdeadbeefcafef00d);
    for _ in 0..ROUNDS {
        let f = random_residues(&mut rng);
        let mut c: Vec<i16> = f.iter().map(|&x| x as i16).collect();
        ntt_inverse(&mut c);
        let got: Vec<i64> = c.iter().map(|&x| modq(x as i64)).collect();
        let want: Vec<i64> = spec_ntt_inverse(&f).iter().map(|x| x * R % Q).collect();
        assert_eq!(got, want);
    }
}

#[test]
fn base_multiply_is_algorithm_11_times_inverse_montgomery_factor() {
    // Each product carries one factor 2^-16 (Montgomery reduction).
    let r_inv = pow_mod(R, (Q - 2) as u32);
    let mut rng = Prng(0x0123456789abcdef);
    for _ in 0..ROUNDS {
        let f = random_residues(&mut rng);
        let g = random_residues(&mut rng);
        let (mut a, mut b, mut out) = (Poly::new(), Poly::new(), Poly::new());
        for i in 0..KYBER_N {
            a.coeffs[i] = f[i] as i16;
            b.coeffs[i] = g[i] as i16;
        }
        poly_base_multiply(&mut out, &a, &b);
        let got: Vec<i64> = out.coeffs.iter().map(|&x| modq(x as i64)).collect();
        let want: Vec<i64> = spec_multiply_ntts(&f, &g)
            .iter()
            .map(|x| x * r_inv % Q)
            .collect();
        assert_eq!(got, want);
    }
}

// ---- Algorithm 8: SamplePolyCBD ---------------------------------------------

fn spec_cbd(eta: usize, b: &[u8]) -> Vec<i64> {
    assert_eq!(b.len(), 64 * eta);
    let bit = |k: usize| ((b[k / 8] >> (k % 8)) & 1) as i64;
    (0..256)
        .map(|i| {
            let x: i64 = (0..eta).map(|j| bit(2 * i * eta + j)).sum();
            let y: i64 = (0..eta).map(|j| bit(2 * i * eta + eta + j)).sum();
            modq(x - y)
        })
        .collect()
}

#[test]
fn cbd_matches_algorithm_8() {
    let mut rng = Prng(0x5555aaaa12345678);
    for _ in 0..CBD_ROUNDS {
        let buf2 = rng.bytes(cbd_bytes(2));
        let mut p = Poly::new();
        cbd2(&mut p, &buf2);
        let got: Vec<i64> = p.coeffs.iter().map(|&x| modq(x as i64)).collect();
        assert_eq!(got, spec_cbd(2, &buf2));

        let buf3 = rng.bytes(cbd_bytes(3));
        cbd3(&mut p, &buf3);
        let got: Vec<i64> = p.coeffs.iter().map(|&x| modq(x as i64)).collect();
        assert_eq!(got, spec_cbd(3, &buf3));
    }
}

// ---- Compress_d, Decompress_d, ByteEncode_d (section 4.2.1) -------------------

fn spec_compress(d: u32, x: i64) -> i64 {
    // round-half-up(2^d * x / q) mod 2^d, in exact integers.
    ((2 * (x << d) + Q) / (2 * Q)) & ((1 << d) - 1)
}

fn spec_decompress(d: u32, y: i64) -> i64 {
    (2 * Q * y + (1 << d)) / (2 << d)
}

/// Algorithm 5 for d < 12: little-endian bit packing of 256 d-bit values.
fn spec_byte_encode(d: u32, f: &[i64]) -> Vec<u8> {
    let mut out = vec![0u8; encoded_bytes(d as usize)];
    for (i, &v) in f.iter().enumerate() {
        for j in 0..d as usize {
            let k = i * d as usize + j;
            out[k / 8] |= (((v >> j) & 1) as u8) << (k % 8);
        }
    }
    out
}

/// Every residue in 0..q, then every negative representative -(q-1)..=-1,
/// padded with zeros to `TEST_POLYS` polynomials.
fn all_inputs() -> Vec<Poly> {
    let mut vals: Vec<i16> = (0..Q as i16).collect();
    vals.extend((1..Q as i16).map(|x| x - Q as i16));
    vals.resize(TEST_POLYS * KYBER_N, 0);
    vals.chunks(KYBER_N)
        .map(|c| {
            let mut p = Poly::new();
            p.coeffs.copy_from_slice(c);
            p
        })
        .collect()
}

fn residues(p: &Poly) -> Vec<i64> {
    p.coeffs.iter().map(|&x| modq(x as i64)).collect()
}

#[test]
fn compress_1_matches_spec() {
    // Decrypt: ByteEncode_1(Compress_1(w)), FIPS 203 Algorithm 15 line 7.
    for p in all_inputs() {
        let mut msg = [0u8; MSG_BYTES];
        poly_tomsg(&mut msg, p.clone());
        let want: Vec<i64> = residues(&p).iter().map(|&x| spec_compress(1, x)).collect();
        assert_eq!(msg.to_vec(), spec_byte_encode(1, &want));
    }
}

#[test]
fn compress_4_and_5_match_spec() {
    for p in all_inputs() {
        let enc = |d| {
            let c: Vec<i64> = residues(&p).iter().map(|&x| spec_compress(d, x)).collect();
            spec_byte_encode(d, &c)
        };
        let mut r4 = [0u8; KYBER_POLYCOMPRESSEDBYTES];
        poly_compress(&mut r4, p.clone());
        assert_eq!(r4.to_vec(), enc(4));
        let mut r5 = [0u8; KYBER_1024_POLYCOMPRESSEDBYTES];
        poly_compress_1024(&mut r5, p.clone());
        assert_eq!(r5.to_vec(), enc(5));
    }
}

#[test]
fn compress_10_matches_spec() {
    let enc = |p: &Poly| {
        let c: Vec<i64> = residues(p).iter().map(|&x| spec_compress(10, x)).collect();
        spec_byte_encode(10, &c)
    };
    for group in all_inputs().chunks(3) {
        let mut v = Polyvec::new();
        v.vec.clone_from_slice(group);
        let mut out = vec![0u8; 3 * encoded_bytes(10)];
        polyvec_compress(&mut out, v);
        let want: Vec<u8> = group.iter().flat_map(enc).collect();
        assert_eq!(out, want);
    }
}

/// Characterization of a legacy deviation, not a requirement: Kyber-1024's
/// d = 11 compression uses the d = 4/5/10 multiplier (10321345 >> 35), which is
/// not exact for d = 11. It disagrees with FIPS 203 Compress_11 at exactly two
/// residues, 1875 and 3125 (each off by one). Legacy output must not change,
/// and ML-KEM-1024 must not share this routine: with 1024 coefficients per
/// ciphertext a hit is likely, and the bytes would differ from the standard.
#[test]
fn legacy_compress_11_deviates_from_spec_at_two_residues() {
    let mut deviating = Vec::new();
    for x in 0..Q as i16 {
        let mut v = Polyvec1024::new();
        for p in v.vec.iter_mut() {
            p.coeffs = [x; KYBER_N];
        }
        let mut out = vec![0u8; 4 * encoded_bytes(11)];
        polyvec_compress_1024(&mut out, v);
        let c = vec![spec_compress(11, x as i64); KYBER_N];
        let want: Vec<u8> = (0..4).flat_map(|_| spec_byte_encode(11, &c)).collect();
        if out != want {
            deviating.push(x);
        }
    }
    assert_eq!(deviating, LEGACY_DEVIATING.to_vec());
}

/// `TEST_POLYS` polynomials whose coefficients run through 0..2^d in order, wrapping.
fn all_d_bit_values(d: u32) -> Vec<Vec<i64>> {
    (0..TEST_POLYS)
        .map(|n| {
            (0..KYBER_N)
                .map(|i| ((n * KYBER_N + i) as i64) % (1 << d))
                .collect()
        })
        .collect()
}

#[test]
fn decompress_matches_spec() {
    for ys in all_d_bit_values(4) {
        let mut p = Poly::new();
        poly_decompress(&mut p, &spec_byte_encode(4, &ys));
        let want: Vec<i64> = ys.iter().map(|&y| spec_decompress(4, y)).collect();
        assert_eq!(p.coeffs.iter().map(|&x| x as i64).collect::<Vec<_>>(), want);
    }
    for ys in all_d_bit_values(5) {
        let mut p = Poly::new();
        poly_decompress_1024(&mut p, &spec_byte_encode(5, &ys));
        let want: Vec<i64> = ys.iter().map(|&y| spec_decompress(5, y)).collect();
        assert_eq!(p.coeffs.iter().map(|&x| x as i64).collect::<Vec<_>>(), want);
    }
    let d10 = all_d_bit_values(10);
    for group in d10.chunks(3) {
        let bytes: Vec<u8> = group
            .iter()
            .flat_map(|ys| spec_byte_encode(10, ys))
            .collect();
        let mut v = Polyvec::new();
        polyvec_decompress(&mut v, &bytes);
        for (p, ys) in v.vec.iter().zip(group) {
            let want: Vec<i64> = ys.iter().map(|&y| spec_decompress(10, y)).collect();
            assert_eq!(p.coeffs.iter().map(|&x| x as i64).collect::<Vec<_>>(), want);
        }
    }
    let d11 = all_d_bit_values(11);
    for group in d11.chunks(4) {
        let bytes: Vec<u8> = group
            .iter()
            .flat_map(|ys| spec_byte_encode(11, ys))
            .collect();
        let mut v = Polyvec1024::new();
        polyvec_decompress_1024(&mut v, &bytes);
        for (p, ys) in v.vec.iter().zip(group) {
            let want: Vec<i64> = ys.iter().map(|&y| spec_decompress(11, y)).collect();
            assert_eq!(p.coeffs.iter().map(|&x| x as i64).collect::<Vec<_>>(), want);
        }
    }
}

#[test]
fn byte_encode_12_matches_spec() {
    // Algorithm 5 with d = 12. poly_tobytes accepts the signed range (-q, q).
    for p in all_inputs() {
        let mut out = [0u8; KYBER_POLYBYTES];
        poly_tobytes(&mut out, p.clone());
        let mut want = vec![0u8; KYBER_POLYBYTES];
        for (i, v) in residues(&p).iter().enumerate() {
            for j in 0..12 {
                let k = i * 12 + j;
                want[k / 8] |= (((v >> j) & 1) as u8) << (k % 8);
            }
        }
        assert_eq!(out.to_vec(), want);
    }
}
