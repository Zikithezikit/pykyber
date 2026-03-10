use super::error::KyberError;
use super::params::*;
use super::poly::*;
use super::polyvec::*;
use super::symmetric::{
    hash_sha3_512, xof_absorb_bytes, xof_squeeze_blocks, XofState, XOF_BLOCKBYTES,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

fn pack_pk(r: &mut [u8], pk: &mut Polyvec, seed: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_POLYVECBYTES;
    polyvec_tobytes(r, pk);
    r[KYBER_POLYVECBYTES..END].copy_from_slice(&seed[..KYBER_SYMBYTES]);
}

fn unpack_pk(pk: &mut Polyvec, seed: &mut [u8], packedpk: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_POLYVECBYTES;
    polyvec_frombytes(pk, packedpk);
    seed[..KYBER_SYMBYTES].copy_from_slice(&packedpk[KYBER_POLYVECBYTES..END]);
}

fn pack_sk(r: &mut [u8], sk: &mut Polyvec) {
    polyvec_tobytes(r, sk);
}

fn unpack_sk(sk: &mut Polyvec, packedsk: &[u8]) {
    polyvec_frombytes(sk, packedsk);
}

fn pack_ciphertext(r: &mut [u8], b: &mut Polyvec, v: Poly) {
    polyvec_compress(r, b.clone());
    poly_compress(&mut r[KYBER_POLYVECCOMPRESSEDBYTES..], v);
}

fn unpack_ciphertext(b: &mut Polyvec, v: &mut Poly, c: &[u8]) {
    polyvec_decompress(b, c);
    poly_decompress(v, &c[KYBER_POLYVECCOMPRESSEDBYTES..]);
}

fn rej_uniform(r: &mut [i16], len: usize, buf: &[u8], buflen: usize) -> usize {
    let (mut ctr, mut pos) = (0usize, 0usize);
    let (mut val0, mut val1);

    while ctr < len && pos + 3 <= buflen {
        val0 = ((buf[pos + 0] >> 0) as u16 | (buf[pos + 1] as u16) << 8) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) as u16 | (buf[pos + 2] as u16) << 4) & 0xFFF;
        pos += 3;

        if val0 < KYBER_Q as u16 {
            r[ctr] = val0 as i16;
            ctr += 1;
        }
        if ctr < len && val1 < KYBER_Q as u16 {
            r[ctr] = val1 as i16;
            ctr += 1;
        }
    }
    ctr
}

fn gen_a(a: &mut [Polyvec], b: &[u8]) {
    gen_matrix(a, b, false);
}

fn gen_at(a: &mut [Polyvec], b: &[u8]) {
    gen_matrix(a, b, true);
}

fn gen_matrix(a: &mut [Polyvec], seed: &[u8], transposed: bool) {
    let mut ctr;
    const GEN_MATRIX_NBLOCKS: usize =
        (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES;
    let mut buf = [0u8; GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    let mut buflen: usize;
    let mut off: usize;
    let mut state = XofState::new();

    for i in 0..KYBER_K {
        for j in 0..KYBER_K {
            if transposed {
                xof_absorb_bytes(&mut state, seed, i as u8, j as u8);
            } else {
                xof_absorb_bytes(&mut state, seed, j as u8, i as u8);
            }
            xof_squeeze_blocks(&mut buf, GEN_MATRIX_NBLOCKS, &mut state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(&mut a[i].vec[j].coeffs, KYBER_N, &buf, buflen);

            while ctr < KYBER_N {
                off = buflen % 3;
                for k in 0..off {
                    buf[k] = buf[buflen - off + k];
                }
                xof_squeeze_blocks(&mut buf[off..], 1, &mut state);
                buflen = off + XOF_BLOCKBYTES;
                ctr += rej_uniform(&mut a[i].vec[j].coeffs[ctr..], KYBER_N - ctr, &buf, buflen);
            }
        }
    }
}

pub fn indcpa_keypair<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _seed: Option<(&[u8], &[u8])>,
    _rng: &mut R,
) -> Result<(), KyberError>
where
    R: CryptoRng + RngCore,
{
    let mut a: [Polyvec; KYBER_K] = core::array::from_fn(|_| Polyvec::new());
    let (mut e, mut pkpv, mut skpv) = (Polyvec::new(), Polyvec::new(), Polyvec::new());
    let mut nonce = 0u8;
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYMBYTES];

    if let Some(s) = _seed {
        randbuf[..KYBER_SYMBYTES].copy_from_slice(&s.0);
    } else {
        _rng.fill_bytes(&mut randbuf[..KYBER_SYMBYTES]);
    }

    hash_sha3_512(&mut buf, &randbuf, KYBER_SYMBYTES);

    let (publicseed, noiseseed) = buf.split_at(KYBER_SYMBYTES);
    gen_a(&mut a, publicseed);

    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut skpv.vec[i], noiseseed, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut e.vec[i], noiseseed, nonce);
        nonce += 1;
    }

    polyvec_ntt(&mut skpv);
    polyvec_ntt(&mut e);

    for i in 0..KYBER_K {
        polyvec_basemul_acc_montgomery(&mut pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&mut pkpv.vec[i]);
    }
    polyvec_add(&mut pkpv, &e);
    polyvec_reduce(&mut pkpv);

    pack_sk(sk, &mut skpv);
    pack_pk(pk, &mut pkpv, publicseed);

    a.zeroize();
    buf.zeroize();
    randbuf.zeroize();
    Ok(())
}

pub fn indcpa_enc(c: &mut [u8], m: &[u8], pk: &[u8], coins: &[u8]) {
    let mut at: [Polyvec; KYBER_K] = core::array::from_fn(|_| Polyvec::new());
    let (mut sp, mut pkpv, mut ep, mut b) = (
        Polyvec::new(),
        Polyvec::new(),
        Polyvec::new(),
        Polyvec::new(),
    );
    let (mut v, mut k, mut epp) = (Poly::new(), Poly::new(), Poly::new());
    let mut seed = [0u8; KYBER_SYMBYTES];
    let mut nonce = 0u8;

    unpack_pk(&mut pkpv, &mut seed, pk);
    poly_frommsg(&mut k, m);
    gen_at(&mut at, &seed);

    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut sp.vec[i], coins, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta2(&mut ep.vec[i], coins, nonce);
        nonce += 1;
    }
    poly_getnoise_eta2(&mut epp, coins, nonce);

    polyvec_ntt(&mut sp);

    for i in 0..KYBER_K {
        polyvec_basemul_acc_montgomery(&mut b.vec[i], &at[i], &sp);
    }

    polyvec_basemul_acc_montgomery(&mut v, &pkpv, &sp);
    polyvec_invntt_tomont(&mut b);
    poly_invntt_tomont(&mut v);

    polyvec_add(&mut b, &ep);
    poly_add(&mut v, &epp);
    poly_add(&mut v, &k);
    polyvec_reduce(&mut b);
    poly_reduce(&mut v);

    pack_ciphertext(c, &mut b, v.clone());
    seed.zeroize();
}

pub fn indcpa_dec(m: &mut [u8], c: &[u8], sk: &[u8]) {
    let (mut b, mut skpv) = (Polyvec::new(), Polyvec::new());
    let (mut v, mut mp) = (Poly::new(), Poly::new());

    unpack_ciphertext(&mut b, &mut v, c);
    unpack_sk(&mut skpv, sk);

    polyvec_ntt(&mut b);
    polyvec_basemul_acc_montgomery(&mut mp, &skpv, &b);
    poly_invntt_tomont(&mut mp);

    poly_sub(&mut mp, &v);
    poly_reduce(&mut mp);

    poly_tomsg(m, mp);
}

fn pack_pk_512(r: &mut [u8], pk: &mut Polyvec512, seed: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_512_POLYVECBYTES;
    polyvec_tobytes_512(r, pk);
    r[KYBER_512_POLYVECBYTES..END].copy_from_slice(&seed[..KYBER_SYMBYTES]);
}

fn unpack_pk_512(pk: &mut Polyvec512, seed: &mut [u8], packedpk: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_512_POLYVECBYTES;
    polyvec_frombytes_512(pk, packedpk);
    seed[..KYBER_SYMBYTES].copy_from_slice(&packedpk[KYBER_512_POLYVECBYTES..END]);
}

fn pack_ciphertext_512(r: &mut [u8], b: &mut Polyvec512, v: Poly) {
    polyvec_compress_512(r, b.clone());
    poly_compress(&mut r[KYBER_512_POLYVECCOMPRESSEDBYTES..], v);
}

fn unpack_ciphertext_512(b: &mut Polyvec512, v: &mut Poly, c: &[u8]) {
    polyvec_decompress_512(b, c);
    poly_decompress(v, &c[KYBER_512_POLYVECCOMPRESSEDBYTES..]);
}

fn gen_matrix_512(a: &mut [Polyvec512], seed: &[u8], transposed: bool) {
    let mut ctr;
    const K: usize = KYBER_512_K;
    const GEN_MATRIX_NBLOCKS: usize =
        (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES;
    let mut buf = [0u8; GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    let mut buflen: usize;
    let mut off: usize;
    let mut state = XofState::new();

    for i in 0..K {
        for j in 0..K {
            if transposed {
                xof_absorb_bytes(&mut state, seed, i as u8, j as u8);
            } else {
                xof_absorb_bytes(&mut state, seed, j as u8, i as u8);
            }
            xof_squeeze_blocks(&mut buf, GEN_MATRIX_NBLOCKS, &mut state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(&mut a[i].vec[j].coeffs, KYBER_N, &buf, buflen);

            while ctr < KYBER_N {
                off = buflen % 3;
                for k in 0..off {
                    buf[k] = buf[buflen - off + k];
                }
                xof_squeeze_blocks(&mut buf[off..], 1, &mut state);
                buflen = off + XOF_BLOCKBYTES;
                ctr += rej_uniform(&mut a[i].vec[j].coeffs[ctr..], KYBER_N - ctr, &buf, buflen);
            }
        }
    }
}

fn gen_a_512(a: &mut [Polyvec512], b: &[u8]) {
    gen_matrix_512(a, b, false);
}

fn gen_at_512(a: &mut [Polyvec512], b: &[u8]) {
    gen_matrix_512(a, b, true);
}

pub fn indcpa_keypair_512<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _seed: Option<(&[u8], &[u8])>,
    _rng: &mut R,
) -> Result<(), KyberError>
where
    R: CryptoRng + RngCore,
{
    const K: usize = KYBER_512_K;
    let mut a: [Polyvec512; K] = core::array::from_fn(|_| Polyvec512::new());
    let (mut e, mut pkpv, mut skpv) = (Polyvec512::new(), Polyvec512::new(), Polyvec512::new());
    let mut nonce = 0u8;
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYMBYTES];

    if let Some(s) = _seed {
        randbuf[..KYBER_SYMBYTES].copy_from_slice(&s.0);
    } else {
        _rng.fill_bytes(&mut randbuf[..KYBER_SYMBYTES]);
    }

    hash_sha3_512(&mut buf, &randbuf, KYBER_SYMBYTES);

    let (publicseed, noiseseed) = buf.split_at(KYBER_SYMBYTES);
    gen_a_512(&mut a, publicseed);

    for i in 0..K {
        poly_getnoise_eta1_512(&mut skpv.vec[i], noiseseed, nonce);
        nonce += 1;
    }
    for i in 0..K {
        poly_getnoise_eta1_512(&mut e.vec[i], noiseseed, nonce);
        nonce += 1;
    }

    polyvec_ntt_512(&mut skpv);
    polyvec_ntt_512(&mut e);

    for i in 0..K {
        polyvec_basemul_acc_montgomery_512(&mut pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&mut pkpv.vec[i]);
    }
    polyvec_add_512(&mut pkpv, &e);
    polyvec_reduce_512(&mut pkpv);

    polyvec_tobytes_512(sk, &skpv);
    pack_pk_512(pk, &mut pkpv, publicseed);

    a.zeroize();
    buf.zeroize();
    randbuf.zeroize();
    Ok(())
}

pub fn indcpa_enc_512(c: &mut [u8], m: &[u8], pk: &[u8], coins: &[u8]) {
    const K: usize = KYBER_512_K;
    let mut at: [Polyvec512; K] = core::array::from_fn(|_| Polyvec512::new());
    let (mut sp, mut pkpv, mut ep, mut b) = (
        Polyvec512::new(),
        Polyvec512::new(),
        Polyvec512::new(),
        Polyvec512::new(),
    );
    let (mut v, mut k, mut epp) = (Poly::new(), Poly::new(), Poly::new());
    let mut seed = [0u8; KYBER_SYMBYTES];
    let mut nonce = 0u8;

    unpack_pk_512(&mut pkpv, &mut seed, pk);
    poly_frommsg(&mut k, m);
    gen_at_512(&mut at, &seed);

    for i in 0..K {
        poly_getnoise_eta1_512(&mut sp.vec[i], coins, nonce);
        nonce += 1;
    }
    for i in 0..K {
        poly_getnoise_eta2_512(&mut ep.vec[i], coins, nonce);
        nonce += 1;
    }
    poly_getnoise_eta2_512(&mut epp, coins, nonce);

    polyvec_ntt_512(&mut sp);

    for i in 0..K {
        polyvec_basemul_acc_montgomery_512(&mut b.vec[i], &at[i], &sp);
    }

    polyvec_basemul_acc_montgomery_512(&mut v, &pkpv, &sp);
    polyvec_invntt_tomont_512(&mut b);
    poly_invntt_tomont(&mut v);

    polyvec_add_512(&mut b, &ep);
    poly_add(&mut v, &epp);
    poly_add(&mut v, &k);
    polyvec_reduce_512(&mut b);
    poly_reduce(&mut v);

    pack_ciphertext_512(c, &mut b, v.clone());
    at.zeroize();
    seed.zeroize();
}

pub fn indcpa_dec_512(m: &mut [u8], c: &[u8], sk: &[u8]) {
    let (mut b, mut skpv) = (Polyvec512::new(), Polyvec512::new());
    let (mut v, mut mp) = (Poly::new(), Poly::new());

    unpack_ciphertext_512(&mut b, &mut v, c);
    polyvec_frombytes_512(&mut skpv, sk);

    polyvec_ntt_512(&mut b);
    polyvec_basemul_acc_montgomery_512(&mut mp, &skpv, &b);
    poly_invntt_tomont(&mut mp);

    poly_sub(&mut mp, &v);
    poly_reduce(&mut mp);

    poly_tomsg(m, mp);
}

fn pack_pk_1024(r: &mut [u8], pk: &mut Polyvec1024, seed: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_1024_POLYVECBYTES;
    polyvec_tobytes_1024(r, pk);
    r[KYBER_1024_POLYVECBYTES..END].copy_from_slice(&seed[..KYBER_SYMBYTES]);
}

fn unpack_pk_1024(pk: &mut Polyvec1024, seed: &mut [u8], packedpk: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_1024_POLYVECBYTES;
    polyvec_frombytes_1024(pk, packedpk);
    seed[..KYBER_SYMBYTES].copy_from_slice(&packedpk[KYBER_1024_POLYVECBYTES..END]);
}

fn pack_ciphertext_1024(r: &mut [u8], b: &mut Polyvec1024, v: Poly) {
    polyvec_compress_1024(r, b.clone());
    poly_compress_1024(&mut r[KYBER_1024_POLYVECCOMPRESSEDBYTES..], v);
}

fn unpack_ciphertext_1024(b: &mut Polyvec1024, v: &mut Poly, c: &[u8]) {
    polyvec_decompress_1024(b, c);
    poly_decompress_1024(v, &c[KYBER_1024_POLYVECCOMPRESSEDBYTES..]);
}

fn gen_matrix_1024(a: &mut [Polyvec1024], seed: &[u8], transposed: bool) {
    let mut ctr;
    const K: usize = KYBER_1024_K;
    const GEN_MATRIX_NBLOCKS: usize =
        (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES;
    let mut buf = [0u8; GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    let mut buflen: usize;
    let mut off: usize;
    let mut state = XofState::new();

    for i in 0..K {
        for j in 0..K {
            if transposed {
                xof_absorb_bytes(&mut state, seed, i as u8, j as u8);
            } else {
                xof_absorb_bytes(&mut state, seed, j as u8, i as u8);
            }
            xof_squeeze_blocks(&mut buf, GEN_MATRIX_NBLOCKS, &mut state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(&mut a[i].vec[j].coeffs, KYBER_N, &buf, buflen);

            while ctr < KYBER_N {
                off = buflen % 3;
                for k in 0..off {
                    buf[k] = buf[buflen - off + k];
                }
                xof_squeeze_blocks(&mut buf[off..], 1, &mut state);
                buflen = off + XOF_BLOCKBYTES;
                ctr += rej_uniform(&mut a[i].vec[j].coeffs[ctr..], KYBER_N - ctr, &buf, buflen);
            }
        }
    }
}

fn gen_a_1024(a: &mut [Polyvec1024], b: &[u8]) {
    gen_matrix_1024(a, b, false);
}

fn gen_at_1024(a: &mut [Polyvec1024], b: &[u8]) {
    gen_matrix_1024(a, b, true);
}

pub fn indcpa_keypair_1024<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _seed: Option<(&[u8], &[u8])>,
    _rng: &mut R,
) -> Result<(), KyberError>
where
    R: CryptoRng + RngCore,
{
    const K: usize = KYBER_1024_K;
    let mut a: [Polyvec1024; K] = core::array::from_fn(|_| Polyvec1024::new());
    let (mut e, mut pkpv, mut skpv) = (Polyvec1024::new(), Polyvec1024::new(), Polyvec1024::new());
    let mut nonce = 0u8;
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYMBYTES];

    if let Some(s) = _seed {
        randbuf[..KYBER_SYMBYTES].copy_from_slice(&s.0);
    } else {
        _rng.fill_bytes(&mut randbuf[..KYBER_SYMBYTES]);
    }

    hash_sha3_512(&mut buf, &randbuf, KYBER_SYMBYTES);

    let (publicseed, noiseseed) = buf.split_at(KYBER_SYMBYTES);
    gen_a_1024(&mut a, publicseed);

    for i in 0..K {
        poly_getnoise_eta1(&mut skpv.vec[i], noiseseed, nonce);
        nonce += 1;
    }
    for i in 0..K {
        poly_getnoise_eta1(&mut e.vec[i], noiseseed, nonce);
        nonce += 1;
    }

    polyvec_ntt_1024(&mut skpv);
    polyvec_ntt_1024(&mut e);

    for i in 0..K {
        polyvec_basemul_acc_montgomery_1024(&mut pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&mut pkpv.vec[i]);
    }
    polyvec_add_1024(&mut pkpv, &e);
    polyvec_reduce_1024(&mut pkpv);

    polyvec_tobytes_1024(sk, &skpv);
    pack_pk_1024(pk, &mut pkpv, publicseed);

    a.zeroize();
    buf.zeroize();
    randbuf.zeroize();
    Ok(())
}

pub fn indcpa_enc_1024(c: &mut [u8], m: &[u8], pk: &[u8], coins: &[u8]) {
    const K: usize = KYBER_1024_K;
    let mut at: [Polyvec1024; K] = core::array::from_fn(|_| Polyvec1024::new());
    let (mut sp, mut pkpv, mut ep, mut b) = (
        Polyvec1024::new(),
        Polyvec1024::new(),
        Polyvec1024::new(),
        Polyvec1024::new(),
    );
    let (mut v, mut k, mut epp) = (Poly::new(), Poly::new(), Poly::new());
    let mut seed = [0u8; KYBER_SYMBYTES];
    let mut nonce = 0u8;

    unpack_pk_1024(&mut pkpv, &mut seed, pk);
    poly_frommsg(&mut k, m);
    gen_at_1024(&mut at, &seed);

    for i in 0..K {
        poly_getnoise_eta1(&mut sp.vec[i], coins, nonce);
        nonce += 1;
    }
    for i in 0..K {
        poly_getnoise_eta2(&mut ep.vec[i], coins, nonce);
        nonce += 1;
    }
    poly_getnoise_eta2(&mut epp, coins, nonce);

    polyvec_ntt_1024(&mut sp);

    for i in 0..K {
        polyvec_basemul_acc_montgomery_1024(&mut b.vec[i], &at[i], &sp);
    }

    polyvec_basemul_acc_montgomery_1024(&mut v, &pkpv, &sp);
    polyvec_invntt_tomont_1024(&mut b);
    poly_invntt_tomont(&mut v);

    polyvec_add_1024(&mut b, &ep);
    poly_add(&mut v, &epp);
    poly_add(&mut v, &k);
    polyvec_reduce_1024(&mut b);
    poly_reduce(&mut v);

    pack_ciphertext_1024(c, &mut b, v.clone());
    at.zeroize();
    seed.zeroize();
}

pub fn indcpa_dec_1024(m: &mut [u8], c: &[u8], sk: &[u8]) {
    let (mut b, mut skpv) = (Polyvec1024::new(), Polyvec1024::new());
    let (mut v, mut mp) = (Poly::new(), Poly::new());

    unpack_ciphertext_1024(&mut b, &mut v, c);
    polyvec_frombytes_1024(&mut skpv, sk);

    polyvec_ntt_1024(&mut b);
    polyvec_basemul_acc_montgomery_1024(&mut mp, &skpv, &b);
    poly_invntt_tomont(&mut mp);

    poly_sub(&mut mp, &v);
    poly_reduce(&mut mp);

    poly_tomsg(m, mp);
}
