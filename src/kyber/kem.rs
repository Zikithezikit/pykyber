use super::error::KyberError;
use super::indcpa::{
    indcpa_dec, indcpa_dec_1024, indcpa_dec_512, indcpa_enc, indcpa_enc_1024, indcpa_enc_512,
    indcpa_keypair, indcpa_keypair_1024, indcpa_keypair_512,
};
use super::params::*;
use super::symmetric::{hash_sha3_256, hash_sha3_512, shake256_kdf};
use super::verify::{cmov, verify};
use rand_core::{CryptoRng, RngCore};

pub fn crypto_kem_keypair<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _rng: &mut R,
    _seed: Option<(&[u8], &[u8])>,
) -> Result<(), KyberError>
where
    R: RngCore + CryptoRng,
{
    const PK_START: usize = KYBER_SECRETKEYBYTES - (2 * KYBER_SYMBYTES);
    const SK_START: usize = KYBER_SECRETKEYBYTES - KYBER_SYMBYTES;
    const END: usize = KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_keypair(pk, sk, _seed, _rng)?;

    sk[KYBER_INDCPA_SECRETKEYBYTES..END].copy_from_slice(&pk[..KYBER_INDCPA_PUBLICKEYBYTES]);
    hash_sha3_256(&mut sk[PK_START..], pk, KYBER_PUBLICKEYBYTES);

    if let Some(s) = _seed {
        sk[SK_START..].copy_from_slice(&s.1)
    } else {
        _rng.fill_bytes(&mut sk[SK_START..SK_START + KYBER_SYMBYTES]);
    }
    Ok(())
}

pub fn crypto_kem_enc<R>(
    ct: &mut [u8],
    ss: &mut [u8],
    pk: &[u8],
    _rng: &mut R,
    _seed: Option<&[u8]>,
) -> Result<(), KyberError>
where
    R: RngCore + CryptoRng,
{
    let mut kr = [0u8; 2 * KYBER_SYMBYTES];
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYMBYTES];

    if let Some(s) = _seed {
        randbuf[..KYBER_SYMBYTES].copy_from_slice(&s);
    } else {
        _rng.fill_bytes(&mut randbuf);
    }

    hash_sha3_256(&mut buf, &randbuf, KYBER_SYMBYTES);
    hash_sha3_256(&mut buf[KYBER_SYMBYTES..], pk, KYBER_PUBLICKEYBYTES);
    hash_sha3_512(&mut kr, &buf, 2 * KYBER_SYMBYTES);

    indcpa_enc(ct, &buf, pk, &kr[KYBER_SYMBYTES..]);

    hash_sha3_256(&mut kr[KYBER_SYMBYTES..], ct, KYBER_CIPHERTEXTBYTES);
    shake256_kdf(ss, &kr, 2 * KYBER_SYMBYTES);
    Ok(())
}

pub fn crypto_kem_dec(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> () {
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut kr = [0u8; 2 * KYBER_SYMBYTES];
    let mut cmp = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];

    pk.copy_from_slice(&sk[KYBER_INDCPA_SECRETKEYBYTES..][..KYBER_INDCPA_PUBLICKEYBYTES]);

    indcpa_dec(&mut buf, ct, sk);

    const START: usize = KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES;
    const END: usize = KYBER_SECRETKEYBYTES - KYBER_SYMBYTES;
    buf[KYBER_SYMBYTES..].copy_from_slice(&sk[START..END]);
    hash_sha3_512(&mut kr, &buf, 2 * KYBER_SYMBYTES);

    indcpa_enc(&mut cmp, &buf, &pk, &kr[KYBER_SYMBYTES..]);
    let fail = verify(ct, &cmp, KYBER_CIPHERTEXTBYTES);
    hash_sha3_256(&mut kr[KYBER_SYMBYTES..], ct, KYBER_CIPHERTEXTBYTES);
    cmov(&mut kr, &sk[END..], KYBER_SYMBYTES, fail);
    shake256_kdf(ss, &kr, 2 * KYBER_SYMBYTES);
}

pub fn crypto_kem_keypair_512<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _rng: &mut R,
    _seed: Option<(&[u8], &[u8])>,
) -> Result<(), KyberError>
where
    R: RngCore + CryptoRng,
{
    const PK_START: usize = KYBER_512_SECRETKEYBYTES - (2 * KYBER_SYMBYTES);
    const SK_START: usize = KYBER_512_SECRETKEYBYTES - KYBER_SYMBYTES;
    const END: usize = KYBER_512_INDCPA_PUBLICKEYBYTES + KYBER_512_INDCPA_SECRETKEYBYTES;

    indcpa_keypair_512(pk, sk, _seed, _rng)?;

    sk[KYBER_512_INDCPA_SECRETKEYBYTES..END]
        .copy_from_slice(&pk[..KYBER_512_INDCPA_PUBLICKEYBYTES]);
    hash_sha3_256(&mut sk[PK_START..], pk, KYBER_512_PUBLICKEYBYTES);

    if let Some(s) = _seed {
        sk[SK_START..].copy_from_slice(&s.1)
    } else {
        _rng.fill_bytes(&mut sk[SK_START..SK_START + KYBER_SYMBYTES]);
    }
    Ok(())
}

pub fn crypto_kem_enc_512<R>(
    ct: &mut [u8],
    ss: &mut [u8],
    pk: &[u8],
    _rng: &mut R,
    _seed: Option<&[u8]>,
) -> Result<(), KyberError>
where
    R: RngCore + CryptoRng,
{
    let mut kr = [0u8; 2 * KYBER_SYMBYTES];
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYMBYTES];

    if let Some(s) = _seed {
        randbuf[..KYBER_SYMBYTES].copy_from_slice(&s);
    } else {
        _rng.fill_bytes(&mut randbuf);
    }

    hash_sha3_256(&mut buf, &randbuf, KYBER_SYMBYTES);
    hash_sha3_256(&mut buf[KYBER_SYMBYTES..], pk, KYBER_512_PUBLICKEYBYTES);
    hash_sha3_512(&mut kr, &buf, 2 * KYBER_SYMBYTES);

    indcpa_enc_512(ct, &buf, pk, &kr[KYBER_SYMBYTES..]);

    hash_sha3_256(&mut kr[KYBER_SYMBYTES..], ct, KYBER_512_CIPHERTEXTBYTES);
    shake256_kdf(ss, &kr, 2 * KYBER_SYMBYTES);
    Ok(())
}

pub fn crypto_kem_dec_512(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> () {
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut kr = [0u8; 2 * KYBER_SYMBYTES];
    let mut cmp = [0u8; KYBER_512_CIPHERTEXTBYTES];
    let mut pk = [0u8; KYBER_512_INDCPA_PUBLICKEYBYTES];

    pk.copy_from_slice(&sk[KYBER_512_INDCPA_SECRETKEYBYTES..][..KYBER_512_INDCPA_PUBLICKEYBYTES]);

    indcpa_dec_512(&mut buf, ct, sk);

    const START: usize = KYBER_512_SECRETKEYBYTES - 2 * KYBER_SYMBYTES;
    const END: usize = KYBER_512_SECRETKEYBYTES - KYBER_SYMBYTES;
    buf[KYBER_SYMBYTES..].copy_from_slice(&sk[START..END]);
    hash_sha3_512(&mut kr, &buf, 2 * KYBER_SYMBYTES);

    indcpa_enc_512(&mut cmp, &buf, &pk, &kr[KYBER_SYMBYTES..]);
    let fail = verify(ct, &cmp, KYBER_512_CIPHERTEXTBYTES);
    hash_sha3_256(&mut kr[KYBER_SYMBYTES..], ct, KYBER_512_CIPHERTEXTBYTES);
    cmov(&mut kr, &sk[END..], KYBER_SYMBYTES, fail);
    shake256_kdf(ss, &kr, 2 * KYBER_SYMBYTES);
}

pub fn crypto_kem_keypair_1024<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _rng: &mut R,
    _seed: Option<(&[u8], &[u8])>,
) -> Result<(), KyberError>
where
    R: RngCore + CryptoRng,
{
    const PK_START: usize = KYBER_1024_SECRETKEYBYTES - (2 * KYBER_SYMBYTES);
    const SK_START: usize = KYBER_1024_SECRETKEYBYTES - KYBER_SYMBYTES;
    const END: usize = KYBER_1024_INDCPA_PUBLICKEYBYTES + KYBER_1024_INDCPA_SECRETKEYBYTES;

    indcpa_keypair_1024(pk, sk, _seed, _rng)?;

    sk[KYBER_1024_INDCPA_SECRETKEYBYTES..END]
        .copy_from_slice(&pk[..KYBER_1024_INDCPA_PUBLICKEYBYTES]);
    hash_sha3_256(&mut sk[PK_START..], pk, KYBER_1024_PUBLICKEYBYTES);

    if let Some(s) = _seed {
        sk[SK_START..].copy_from_slice(&s.1)
    } else {
        _rng.fill_bytes(&mut sk[SK_START..SK_START + KYBER_SYMBYTES]);
    }
    Ok(())
}

pub fn crypto_kem_enc_1024<R>(
    ct: &mut [u8],
    ss: &mut [u8],
    pk: &[u8],
    _rng: &mut R,
    _seed: Option<&[u8]>,
) -> Result<(), KyberError>
where
    R: RngCore + CryptoRng,
{
    let mut kr = [0u8; 2 * KYBER_SYMBYTES];
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYMBYTES];

    if let Some(s) = _seed {
        randbuf[..KYBER_SYMBYTES].copy_from_slice(&s);
    } else {
        _rng.fill_bytes(&mut randbuf);
    }

    hash_sha3_256(&mut buf, &randbuf, KYBER_SYMBYTES);
    hash_sha3_256(&mut buf[KYBER_SYMBYTES..], pk, KYBER_1024_PUBLICKEYBYTES);
    hash_sha3_512(&mut kr, &buf, 2 * KYBER_SYMBYTES);

    indcpa_enc_1024(ct, &buf, pk, &kr[KYBER_SYMBYTES..]);

    hash_sha3_256(&mut kr[KYBER_SYMBYTES..], ct, KYBER_1024_CIPHERTEXTBYTES);
    shake256_kdf(ss, &kr, 2 * KYBER_SYMBYTES);
    Ok(())
}

pub fn crypto_kem_dec_1024(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> () {
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut kr = [0u8; 2 * KYBER_SYMBYTES];
    let mut cmp = [0u8; KYBER_1024_CIPHERTEXTBYTES];
    let mut pk = [0u8; KYBER_1024_INDCPA_PUBLICKEYBYTES];

    pk.copy_from_slice(&sk[KYBER_1024_INDCPA_SECRETKEYBYTES..][..KYBER_1024_INDCPA_PUBLICKEYBYTES]);

    indcpa_dec_1024(&mut buf, ct, sk);

    const START: usize = KYBER_1024_SECRETKEYBYTES - 2 * KYBER_SYMBYTES;
    const END: usize = KYBER_1024_SECRETKEYBYTES - KYBER_SYMBYTES;
    buf[KYBER_SYMBYTES..].copy_from_slice(&sk[START..END]);
    hash_sha3_512(&mut kr, &buf, 2 * KYBER_SYMBYTES);

    indcpa_enc_1024(&mut cmp, &buf, &pk, &kr[KYBER_SYMBYTES..]);
    let fail = verify(ct, &cmp, KYBER_1024_CIPHERTEXTBYTES);
    hash_sha3_256(&mut kr[KYBER_SYMBYTES..], ct, KYBER_1024_CIPHERTEXTBYTES);
    cmov(&mut kr, &sk[END..], KYBER_SYMBYTES, fail);
    shake256_kdf(ss, &kr, 2 * KYBER_SYMBYTES);
}
