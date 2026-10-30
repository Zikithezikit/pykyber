//! The legacy keypair and encapsulation functions index caller-supplied buffers
//! and seeds, so they must reject a wrong length with `InvalidInput` instead of
//! panicking (decapsulation already did).

use pykyber::kyber::error::KyberError;
use pykyber::kyber::params::*;
use pykyber::kyber::{
    crypto_kem_enc, crypto_kem_enc_1024, crypto_kem_enc_512, crypto_kem_keypair,
    crypto_kem_keypair_1024, crypto_kem_keypair_512, derive,
};
use rand::rngs::OsRng;

fn is_invalid_input<T: std::fmt::Debug>(result: Result<T, KyberError>, param: &str) -> bool {
    matches!(result, Err(KyberError::InvalidInput { param: p, .. }) if p == param)
}

/// `(public key length, secret key length, ciphertext length, keypair, encapsulate)` per level.
type Keypair =
    fn(&mut [u8], &mut [u8], &mut OsRng, Option<(&[u8], &[u8])>) -> Result<(), KyberError>;
type Encaps = fn(&mut [u8], &mut [u8], &[u8], &mut OsRng, Option<&[u8]>) -> Result<(), KyberError>;

fn levels() -> [(usize, usize, usize, Keypair, Encaps); 3] {
    [
        (
            KYBER_512_PUBLICKEYBYTES,
            KYBER_512_SECRETKEYBYTES,
            KYBER_512_CIPHERTEXTBYTES,
            crypto_kem_keypair_512::<OsRng>,
            crypto_kem_enc_512::<OsRng>,
        ),
        (
            KYBER_PUBLICKEYBYTES,
            KYBER_SECRETKEYBYTES,
            KYBER_CIPHERTEXTBYTES,
            crypto_kem_keypair::<OsRng>,
            crypto_kem_enc::<OsRng>,
        ),
        (
            KYBER_1024_PUBLICKEYBYTES,
            KYBER_1024_SECRETKEYBYTES,
            KYBER_1024_CIPHERTEXTBYTES,
            crypto_kem_keypair_1024::<OsRng>,
            crypto_kem_enc_1024::<OsRng>,
        ),
    ]
}

#[test]
fn keypair_rejects_wrong_buffer_and_seed_lengths() {
    let half = [0u8; KYBER_SYMBYTES];
    for (pk_len, sk_len, _, keypair, _) in levels() {
        let (mut pk, mut sk) = (vec![0u8; pk_len], vec![0u8; sk_len]);
        let mut rng = OsRng;
        assert!(is_invalid_input(
            keypair(&mut pk[1..], &mut sk, &mut rng, None),
            "pk"
        ));
        assert!(is_invalid_input(
            keypair(&mut pk, &mut sk[1..], &mut rng, None),
            "sk"
        ));
        assert!(is_invalid_input(
            keypair(&mut pk, &mut sk, &mut rng, Some((&half[1..], &half))),
            "seed d"
        ));
        assert!(is_invalid_input(
            keypair(&mut pk, &mut sk, &mut rng, Some((&half, &[]))),
            "seed z"
        ));
        // The right sizes still work, seeded and not.
        keypair(&mut pk, &mut sk, &mut rng, Some((&half, &half))).unwrap();
        keypair(&mut pk, &mut sk, &mut rng, None).unwrap();
    }
}

#[test]
fn encapsulate_rejects_wrong_buffer_and_seed_lengths() {
    let m = [0u8; KYBER_SYMBYTES];
    for (pk_len, sk_len, ct_len, keypair, enc) in levels() {
        let (mut pk, mut sk) = (vec![0u8; pk_len], vec![0u8; sk_len]);
        keypair(&mut pk, &mut sk, &mut OsRng, None).unwrap();
        let (mut ct, mut ss) = (vec![0u8; ct_len], [0u8; KYBER_SSBYTES]);
        let mut rng = OsRng;
        assert!(is_invalid_input(
            enc(&mut ct[1..], &mut ss, &pk, &mut rng, None),
            "ct"
        ));
        assert!(is_invalid_input(
            enc(&mut ct, &mut ss[1..], &pk, &mut rng, None),
            "ss"
        ));
        assert!(is_invalid_input(
            enc(&mut ct, &mut ss, &pk[1..], &mut rng, None),
            "pk"
        ));
        assert!(is_invalid_input(
            enc(&mut ct, &mut ss, &pk, &mut rng, Some(&m[1..])),
            "seed"
        ));
        enc(&mut ct, &mut ss, &pk, &mut rng, Some(&m)).unwrap();
    }
}

#[test]
fn derive_rejects_a_wrong_seed_length() {
    assert!(is_invalid_input(derive(&[0u8; 63]).map(|_| ()), "seed"));
    assert!(derive(&[0u8; 64]).is_ok());
}
