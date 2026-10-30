//! A failing random generator must surface as `KyberError::RandomBytesGeneration`
//! from every legacy keypair and encapsulation function (no panic, no fallback
//! to another source), and a failure after the IND-CPA secret key was written must
//! not leave that key in the caller's buffer.

use pykyber::kyber::error::KyberError;
use pykyber::kyber::params::*;
use pykyber::kyber::{
    crypto_kem_enc, crypto_kem_enc_1024, crypto_kem_enc_512, crypto_kem_keypair,
    crypto_kem_keypair_1024, crypto_kem_keypair_512, keypair,
};
use rand_core::{CryptoRng, Error, RngCore};

/// Byte every successful fill writes.
const FILL: u8 = 0x42;
/// Keypair generation asks the generator twice: `d` first, then `z`.
const CALLS_BEFORE_Z: usize = 1;

/// Generator that fills `ok_calls` requests and then reports a failure.
struct FailingRng {
    ok_calls: usize,
}

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        panic!("the legacy code must use try_fill_bytes");
    }
    fn next_u64(&mut self) -> u64 {
        panic!("the legacy code must use try_fill_bytes");
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("the legacy code must use try_fill_bytes");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        if self.ok_calls == 0 {
            return Err(Error::new("simulated failure of the OS generator"));
        }
        self.ok_calls -= 1;
        dest.fill(FILL);
        Ok(())
    }
}

impl CryptoRng for FailingRng {}

fn assert_randomness_error<T: std::fmt::Debug>(result: Result<T, KyberError>) {
    assert_eq!(result.unwrap_err(), KyberError::RandomBytesGeneration);
}

type KeypairFn =
    fn(&mut [u8], &mut [u8], &mut FailingRng, Option<(&[u8], &[u8])>) -> Result<(), KyberError>;

/// `(public key length, secret key length, function)` for each level.
fn keypair_levels() -> [(usize, usize, KeypairFn); 3] {
    [
        (
            KYBER_512_PUBLICKEYBYTES,
            KYBER_512_SECRETKEYBYTES,
            crypto_kem_keypair_512::<FailingRng>,
        ),
        (
            KYBER_PUBLICKEYBYTES,
            KYBER_SECRETKEYBYTES,
            crypto_kem_keypair::<FailingRng>,
        ),
        (
            KYBER_1024_PUBLICKEYBYTES,
            KYBER_1024_SECRETKEYBYTES,
            crypto_kem_keypair_1024::<FailingRng>,
        ),
    ]
}

#[test]
fn keypair_fails_when_d_cannot_be_drawn() {
    for (pk_len, sk_len, run) in keypair_levels() {
        let (mut pk, mut sk) = (vec![0u8; pk_len], vec![0u8; sk_len]);
        let mut rng = FailingRng { ok_calls: 0 };
        assert_randomness_error(run(&mut pk, &mut sk, &mut rng, None));
    }
}

#[test]
fn keypair_scrubs_the_secret_key_when_z_cannot_be_drawn() {
    for (pk_len, sk_len, run) in keypair_levels() {
        let (mut pk, mut sk) = (vec![0u8; pk_len], vec![0u8; sk_len]);
        let mut rng = FailingRng {
            ok_calls: CALLS_BEFORE_Z,
        };
        assert_randomness_error(run(&mut pk, &mut sk, &mut rng, None));
        assert!(
            sk.iter().all(|&b| b == 0),
            "sk length {sk_len} not scrubbed"
        );
    }
}

#[test]
fn encapsulation_fails_when_m_cannot_be_drawn() {
    let mut rng = FailingRng { ok_calls: 0 };
    let mut ss = [0u8; KYBER_SSBYTES];

    let pk = [0u8; KYBER_512_PUBLICKEYBYTES];
    let mut ct = [0u8; KYBER_512_CIPHERTEXTBYTES];
    assert_randomness_error(crypto_kem_enc_512(&mut ct, &mut ss, &pk, &mut rng, None));

    let pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    assert_randomness_error(crypto_kem_enc(&mut ct, &mut ss, &pk, &mut rng, None));

    let pk = [0u8; KYBER_1024_PUBLICKEYBYTES];
    let mut ct = [0u8; KYBER_1024_CIPHERTEXTBYTES];
    assert_randomness_error(crypto_kem_enc_1024(&mut ct, &mut ss, &pk, &mut rng, None));
}

#[test]
fn safe_api_reports_the_failure() {
    assert_randomness_error(keypair(&mut FailingRng { ok_calls: 0 }));
    assert_randomness_error(keypair(&mut FailingRng {
        ok_calls: CALLS_BEFORE_Z,
    }));
}
