use super::error::KyberError;
use super::kem::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
use super::params::*;
use rand_core::{CryptoRng, RngCore};

pub fn keypair<R>(rng: &mut R) -> Result<Keypair, KyberError>
where
    R: RngCore + CryptoRng,
{
    let mut public = [0u8; KYBER_PUBLICKEYBYTES];
    let mut secret = [0u8; KYBER_SECRETKEYBYTES];
    crypto_kem_keypair(&mut public, &mut secret, rng, None)?;
    Ok(Keypair { public, secret })
}

pub fn encapsulate<R>(pk: &[u8], rng: &mut R) -> Encapsulated
where
    R: CryptoRng + RngCore,
{
    if pk.len() != KYBER_PUBLICKEYBYTES {
        return Err(KyberError::invalid_input(
            "pk",
            KYBER_PUBLICKEYBYTES,
            pk.len(),
        ));
    }
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut ss = [0u8; KYBER_SSBYTES];
    crypto_kem_enc(&mut ct, &mut ss, pk, rng, None)?;
    Ok((ct, ss))
}

pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Decapsulated {
    if ct.len() != KYBER_CIPHERTEXTBYTES {
        return Err(KyberError::invalid_input(
            "ct",
            KYBER_CIPHERTEXTBYTES,
            ct.len(),
        ));
    }
    if sk.len() != KYBER_SECRETKEYBYTES {
        return Err(KyberError::invalid_input(
            "sk",
            KYBER_SECRETKEYBYTES,
            sk.len(),
        ));
    }
    let mut ss = [0u8; KYBER_SSBYTES];
    crypto_kem_dec(&mut ss, ct, sk)?;
    Ok(ss)
}

use zeroize::Zeroize;

#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl Keypair {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Keypair, KyberError> {
        keypair(rng)
    }
}

struct DummyRng {}
impl CryptoRng for DummyRng {}
impl RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 {
        panic!()
    }
    fn next_u64(&mut self) -> u64 {
        panic!()
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        panic!()
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!()
    }
}

pub fn derive(seed: &[u8]) -> Result<Keypair, KyberError> {
    let mut public = [0u8; KYBER_PUBLICKEYBYTES];
    let mut secret = [0u8; KYBER_SECRETKEYBYTES];
    let mut _rng = DummyRng {};
    if seed.len() != 64 {
        return Err(KyberError::invalid_input("seed", 64, seed.len()));
    }
    crypto_kem_keypair(
        &mut public,
        &mut secret,
        &mut _rng,
        Some((&seed[..32], &seed[32..])),
    )?;
    Ok(Keypair { public, secret })
}

pub fn public(sk: &[u8]) -> PublicKey {
    let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
    pk.copy_from_slice(
        &sk[KYBER_INDCPA_SECRETKEYBYTES..KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES],
    );
    pk
}

pub type PublicKey = [u8; KYBER_PUBLICKEYBYTES];
pub type SecretKey = [u8; KYBER_SECRETKEYBYTES];
pub type Encapsulated = Result<(Ciphertext, SharedSecret), KyberError>;
pub type Decapsulated = Result<SharedSecret, KyberError>;
pub type Ciphertext = [u8; KYBER_CIPHERTEXTBYTES];
pub type SharedSecret = [u8; KYBER_SSBYTES];
