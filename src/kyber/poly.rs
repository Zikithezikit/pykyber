use super::cbd::poly_cbd_eta1;
use super::cbd::poly_cbd_eta1_512;
use super::cbd::poly_cbd_eta2;
use super::ntt::{base_multiply, ntt_forward, ntt_inverse, ZETAS};
use super::params::*;
use super::reduce::{barrett_reduce, montgomery_reduce};
use super::symmetric::shake256_prf_expand;

use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Poly {
    pub coeffs: [i16; KYBER_N],
}

impl Default for Poly {
    fn default() -> Self {
        Poly {
            coeffs: [0i16; KYBER_N],
        }
    }
}

impl Poly {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn poly_compress(r: &mut [u8], a: Poly) {
    let mut t = [0u8; 8];
    let mut k = 0usize;
    let mut u: i16;

    for i in 0..KYBER_N / 8 {
        for j in 0..8 {
            u = a.coeffs[8 * i + j];
            u += (u >> 15) & KYBER_Q as i16;
            let d = (((u as u32) << 4) + 1664) as u64;
            t[j] = (((d * 10321345) >> 35) & 15) as u8;
        }
        r[k] = t[0] | (t[1] << 4);
        r[k + 1] = t[2] | (t[3] << 4);
        r[k + 2] = t[4] | (t[5] << 4);
        r[k + 3] = t[6] | (t[7] << 4);
        k += 4;
    }
}

pub fn poly_compress_1024(r: &mut [u8], a: Poly) {
    let mut t = [0u8; 8];
    let mut k = 0usize;
    let mut u: i16;

    for i in 0..KYBER_N / 8 {
        for j in 0..8 {
            u = a.coeffs[8 * i + j];
            u += (u >> 15) & KYBER_Q as i16;
            let d = (((u as u32) << 5) + 1664) as u64;
            t[j] = (((d * 10321345) >> 35) & 31) as u8;
        }
        r[k] = t[0] | (t[1] << 5);
        r[k + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        r[k + 2] = (t[3] >> 1) | (t[4] << 4);
        r[k + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        r[k + 4] = (t[6] >> 2) | (t[7] << 3);
        k += 5;
    }
}

pub fn poly_decompress(r: &mut Poly, a: &[u8]) {
    let mut idx = 0usize;
    for i in 0..KYBER_N / 2 {
        r.coeffs[2 * i + 0] = ((((a[idx] & 15) as usize * KYBER_Q) + 8) >> 4) as i16;
        r.coeffs[2 * i + 1] = ((((a[idx] >> 4) as usize * KYBER_Q) + 8) >> 4) as i16;
        idx += 1;
    }
}

pub fn poly_decompress_1024(r: &mut Poly, a: &[u8]) {
    let mut idx = 0usize;
    for i in 0..KYBER_N / 8 {
        r.coeffs[8 * i + 0] = ((((a[idx + 0] & 31) as usize * KYBER_Q) + 16) >> 5) as i16;
        r.coeffs[8 * i + 1] =
            (((((a[idx + 0] >> 5) | ((a[idx + 1] & 3) << 3)) as usize * KYBER_Q) + 16) >> 5) as i16;
        r.coeffs[8 * i + 2] = (((((a[idx + 1] >> 2) & 31) as usize * KYBER_Q) + 16) >> 5) as i16;
        r.coeffs[8 * i + 3] =
            (((((a[idx + 1] >> 7) | ((a[idx + 2] & 15) << 1)) as usize * KYBER_Q) + 16) >> 5)
                as i16;
        r.coeffs[8 * i + 4] =
            (((((a[idx + 2] >> 4) | ((a[idx + 3] & 1) << 4)) as usize * KYBER_Q) + 16) >> 5) as i16;
        r.coeffs[8 * i + 5] = (((((a[idx + 3] >> 1) & 31) as usize * KYBER_Q) + 16) >> 5) as i16;
        r.coeffs[8 * i + 6] =
            (((((a[idx + 3] >> 6) | ((a[idx + 4] & 7) << 2)) as usize * KYBER_Q) + 16) >> 5) as i16;
        r.coeffs[8 * i + 7] = ((((a[idx + 4] >> 3) as usize * KYBER_Q) + 16) >> 5) as i16;
        idx += 5;
    }
}

pub fn poly_tobytes(r: &mut [u8], a: Poly) {
    let (mut t0, mut t1);

    for i in 0..(KYBER_N / 2) {
        t0 = a.coeffs[2 * i];
        t0 += (t0 >> 15) & KYBER_Q as i16;
        t1 = a.coeffs[2 * i + 1];
        t1 += (t1 >> 15) & KYBER_Q as i16;
        r[3 * i + 0] = (t0 >> 0) as u8;
        r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        r[3 * i + 2] = (t1 >> 4) as u8;
    }
}

pub fn poly_frombytes(r: &mut Poly, a: &[u8]) {
    for i in 0..(KYBER_N / 2) {
        r.coeffs[2 * i + 0] =
            ((a[3 * i + 0] >> 0) as u16 | ((a[3 * i + 1] as u16) << 8) & 0xFFF) as i16;
        r.coeffs[2 * i + 1] =
            ((a[3 * i + 1] >> 4) as u16 | ((a[3 * i + 2] as u16) << 4) & 0xFFF) as i16;
    }
}

pub fn poly_getnoise_eta1(r: &mut Poly, seed: &[u8], nonce: u8) {
    const LENGTH: usize = KYBER_ETA1 * KYBER_N / 4;
    let mut buf = [0u8; LENGTH];
    shake256_prf_expand(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta1(r, &buf);
}

pub fn poly_getnoise_eta1_512(r: &mut Poly, seed: &[u8], nonce: u8) {
    const LENGTH: usize = KYBER_512_ETA1 * KYBER_N / 4;
    let mut buf = [0u8; LENGTH];
    shake256_prf_expand(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta1_512(r, &buf);
}

pub fn poly_getnoise_eta2(r: &mut Poly, seed: &[u8], nonce: u8) {
    const LENGTH: usize = KYBER_ETA2 * KYBER_N / 4;
    let mut buf = [0u8; LENGTH];
    shake256_prf_expand(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta2(r, &buf);
}

pub fn poly_getnoise_eta2_512(r: &mut Poly, seed: &[u8], nonce: u8) {
    const LENGTH: usize = KYBER_512_ETA2 * KYBER_N / 4;
    let mut buf = [0u8; LENGTH];
    shake256_prf_expand(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta2(r, &buf);
}

pub fn poly_ntt(r: &mut Poly) {
    ntt_forward(&mut r.coeffs);
    poly_reduce(r);
}

pub fn poly_invntt_tomont(r: &mut Poly) {
    ntt_inverse(&mut r.coeffs);
}

pub fn poly_base_multiply(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..(KYBER_N / 4) {
        base_multiply(
            &mut r.coeffs[4 * i..],
            &a.coeffs[4 * i..],
            &b.coeffs[4 * i..],
            ZETAS[64 + i],
        );
        base_multiply(
            &mut r.coeffs[4 * i + 2..],
            &a.coeffs[4 * i + 2..],
            &b.coeffs[4 * i + 2..],
            -(ZETAS[64 + i]),
        );
    }
}

pub fn poly_tomont(r: &mut Poly) {
    let f = ((1u64 << 32) % KYBER_Q as u64) as i16;
    for i in 0..KYBER_N {
        let a = r.coeffs[i] as i32 * f as i32;
        r.coeffs[i] = montgomery_reduce(a);
    }
}

pub fn poly_reduce(r: &mut Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] = barrett_reduce(r.coeffs[i] as i32);
    }
}

pub fn poly_add(r: &mut Poly, b: &Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] += b.coeffs[i];
    }
}

pub fn poly_sub(r: &mut Poly, a: &Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] = a.coeffs[i] - r.coeffs[i];
    }
}

pub fn poly_frommsg(r: &mut Poly, msg: &[u8]) {
    let mut mask;
    for i in 0..KYBER_N / 8 {
        for j in 0..8 {
            mask = ((msg[i] as u16 >> j) & 1).wrapping_neg();
            r.coeffs[8 * i + j] = (mask & ((KYBER_Q + 1) / 2) as u16) as i16;
        }
    }
}

pub fn poly_tomsg(msg: &mut [u8], a: Poly) {
    let mut t;

    for i in 0..KYBER_N / 8 {
        msg[i] = 0;
        for j in 0..8 {
            t = a.coeffs[8 * i + j];
            t += (t >> 15) & KYBER_Q as i16;
            let d = (((t as u32) << 1) + 1664) as u64;
            t = (((d * 10321345) >> 35) & 1) as i16;
            msg[i] |= (t << j) as u8;
        }
    }
}
