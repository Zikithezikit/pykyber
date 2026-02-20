use super::cbd::poly_cbd_eta1;
use super::cbd::poly_cbd_eta2;
use super::ntt::{basemul, invntt, ntt, ZETAS};
use super::params::*;
use super::reduce::{barrett_reduce, montgomery_reduce};
use super::symmetric::prf;

#[derive(Clone, Copy)]
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
            t[j] = (((((u as u16) << 4) + KYBER_Q as u16 / 2) / KYBER_Q as u16) & 15) as u8;
        }
        r[k] = t[0] | (t[1] << 4);
        r[k + 1] = t[2] | (t[3] << 4);
        r[k + 2] = t[4] | (t[5] << 4);
        r[k + 3] = t[6] | (t[7] << 4);
        k += 4;
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
    prf(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta1(r, &buf);
}

pub fn poly_getnoise_eta2(r: &mut Poly, seed: &[u8], nonce: u8) {
    const LENGTH: usize = KYBER_ETA2 * KYBER_N / 4;
    let mut buf = [0u8; LENGTH];
    prf(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta2(r, &buf);
}

pub fn poly_ntt(r: &mut Poly) {
    ntt(&mut r.coeffs);
    poly_reduce(r);
}

pub fn poly_invntt_tomont(r: &mut Poly) {
    invntt(&mut r.coeffs);
}

pub fn poly_basemul(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..(KYBER_N / 4) {
        basemul(
            &mut r.coeffs[4 * i..],
            &a.coeffs[4 * i..],
            &b.coeffs[4 * i..],
            ZETAS[64 + i],
        );
        basemul(
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
        r.coeffs[i] = barrett_reduce(r.coeffs[i]);
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
            t = (((t << 1) + KYBER_Q as i16 / 2) / KYBER_Q as i16) & 1;
            msg[i] |= (t << j) as u8;
        }
    }
}
