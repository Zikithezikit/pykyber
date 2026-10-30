//! Input checks of FIPS 203 sections 7.2 and 7.3, plus the layout of the
//! decapsulation key (Algorithm 16, step 3).
//!
//! Every check works on public data: the length, the encoded `t` and `rho` of
//! the encapsulation key, the stored `H(ek)`. None of them reads `dk_PKE` or
//! `z`, so the plain comparisons below are not a timing channel for secrets.
//! They run before any secret-dependent work, and a failure is a typed error.

use super::params::ParamSet;
use super::polyvec::PolyVec;
use crate::kyber::error::KyberError;
use crate::kyber::fips202::sha3_256;
use crate::kyber::params::KYBER_SYMBYTES;

/// H(ek) and z are 32 bytes each.
pub(crate) const HASH_BYTES: usize = KYBER_SYMBYTES;

pub(crate) fn check_len(
    param: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), KyberError> {
    if expected == actual {
        Ok(())
    } else {
        Err(KyberError::invalid_input(param, expected, actual))
    }
}

/// The four fields of `dk = dk_PKE || ek || H(ek) || z` (Algorithm 16 step 3,
/// Algorithm 18 steps 1-4). `dk_PKE` and `z` are secret.
pub(crate) struct DkParts<'a> {
    pub dk_pke: &'a [u8],
    pub ek: &'a [u8],
    pub h: &'a [u8],
    pub z: &'a [u8],
}

/// Splits a decapsulation key after checking its length (section 7.3, check 2).
pub(crate) fn split_dk<const K: usize>(dk: &[u8]) -> Result<DkParts<'_>, KyberError> {
    check_len("dk", ParamSet::<K>::DK_BYTES, dk.len())?;
    let (dk_pke, rest) = dk.split_at(ParamSet::<K>::DK_PKE_BYTES);
    let (ek, rest) = rest.split_at(ParamSet::<K>::EK_BYTES);
    let (h, z) = rest.split_at(HASH_BYTES);
    Ok(DkParts { dk_pke, ek, h, z })
}

/// Ciphertext type check (section 7.3, check 1), required on every decapsulation.
pub(crate) fn check_ct<const K: usize>(c: &[u8]) -> Result<(), KyberError> {
    check_len("c", ParamSet::<K>::CT_BYTES, c.len())
}

/// Encapsulation key check (section 7.2): length, then the modulus check
/// `ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k]` (equation 7.1).
pub(crate) fn check_ek<const K: usize>(ek: &[u8]) -> Result<(), KyberError> {
    check_len("ek", ParamSet::<K>::EK_BYTES, ek.len())?;
    let t = &ek[..ParamSet::<K>::DK_PKE_BYTES];
    // `from_bytes` reduces mod q, so a coefficient >= q does not survive the round trip.
    let mut test = vec![0u8; t.len()];
    PolyVec::<K>::from_bytes(t).to_bytes(&mut test);
    if test == t {
        Ok(())
    } else {
        Err(KyberError::InvalidEncapsulationKey)
    }
}

/// Decapsulation key check (section 7.3): length, then the hash check
/// `H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64]` (equation 7.2).
pub(crate) fn check_dk<const K: usize>(dk: &[u8]) -> Result<(), KyberError> {
    let parts = split_dk::<K>(dk)?;
    let mut test = [0u8; HASH_BYTES];
    sha3_256(&mut test, parts.ek, parts.ek.len());
    if test == parts.h {
        Ok(())
    } else {
        Err(KyberError::InvalidDecapsulationKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::params::{KYBER_POLYBYTES, KYBER_Q};
    use crate::mlkem::kpke;
    use crate::mlkem::params::{MlKem1024, MlKem512, MlKem768};

    /// Bits in one coefficient of ByteEncode12.
    const COEFF_BITS: u32 = 12;
    /// The part of a 12-bit coefficient that lives in the second byte.
    const SECOND_BYTE_BITS: u8 = ((1u16 << (COEFF_BITS - u8::BITS)) - 1) as u8;

    /// Overwrites the first 12-bit coefficient (bytes 0 and the low nibble of byte 1).
    fn set_first_coeff(ek: &mut [u8], value: u16) {
        ek[0] = value as u8;
        ek[1] = (ek[1] & !SECOND_BYTE_BITS) | (value >> u8::BITS) as u8;
    }

    fn keys<const K: usize>() -> (Vec<u8>, Vec<u8>) {
        let (ek, dk_pke) = kpke::keygen::<K>(&[K as u8; KYBER_SYMBYTES]);
        let mut h = [0u8; HASH_BYTES];
        sha3_256(&mut h, &ek, ek.len());
        let dk = [&dk_pke[..], &ek, &h, &[0x5a; KYBER_SYMBYTES]].concat();
        (ek, dk)
    }

    fn each_set(check: fn(usize)) {
        check(MlKem512::K);
        check(MlKem768::K);
        check(MlKem1024::K);
    }

    macro_rules! per_set {
        ($f:ident, $k:expr) => {
            match $k {
                MlKem512::K => $f::<{ MlKem512::K }>(),
                MlKem768::K => $f::<{ MlKem768::K }>(),
                _ => $f::<{ MlKem1024::K }>(),
            }
        };
    }

    fn ek_checks<const K: usize>() {
        let (ek, _) = keys::<K>();
        assert_eq!(check_ek::<K>(&ek), Ok(()));
        // Length: one byte short, one byte long, empty.
        let bad = |actual| KyberError::invalid_input("ek", ParamSet::<K>::EK_BYTES, actual);
        assert_eq!(check_ek::<K>(&ek[1..]), Err(bad(ek.len() - 1)));
        assert_eq!(
            check_ek::<K>(&[&ek[..], &[0]].concat()),
            Err(bad(ek.len() + 1))
        );
        assert_eq!(check_ek::<K>(&[]), Err(bad(0)));
        // Modulus: q - 1 is the largest canonical value, q is the smallest bad one.
        let mut edited = ek.clone();
        set_first_coeff(&mut edited, KYBER_Q as u16 - 1);
        assert_eq!(check_ek::<K>(&edited), Ok(()));
        for value in [KYBER_Q as u16, KYBER_Q as u16 + 1, (1 << COEFF_BITS) - 1] {
            set_first_coeff(&mut edited, value);
            assert_eq!(
                check_ek::<K>(&edited),
                Err(KyberError::InvalidEncapsulationKey)
            );
        }
        // A bad coefficient in the last polynomial is found as well.
        let mut late = ek.clone();
        let last = ParamSet::<K>::DK_PKE_BYTES - KYBER_POLYBYTES;
        set_first_coeff(&mut late[last..], KYBER_Q as u16);
        assert_eq!(
            check_ek::<K>(&late),
            Err(KyberError::InvalidEncapsulationKey)
        );
        // rho (the trailing seed) is not range-checked: any 32 bytes are valid.
        let mut seed = ek.clone();
        *seed.last_mut().unwrap() ^= u8::MAX;
        assert_eq!(check_ek::<K>(&seed), Ok(()));
    }

    #[test]
    fn encapsulation_key_checks_for_all_sets() {
        each_set(|k| per_set!(ek_checks, k));
    }

    fn dk_checks<const K: usize>() {
        let (ek, dk) = keys::<K>();
        assert_eq!(check_dk::<K>(&dk), Ok(()));
        let bad = |actual| KyberError::invalid_input("dk", ParamSet::<K>::DK_BYTES, actual);
        assert_eq!(check_dk::<K>(&dk[1..]), Err(bad(dk.len() - 1)));
        assert_eq!(
            check_dk::<K>(&[&dk[..], &[0]].concat()),
            Err(bad(dk.len() + 1))
        );
        assert_eq!(check_dk::<K>(&[]), Err(bad(0)));
        // A stored hash with one flipped bit.
        let h_at = ParamSet::<K>::DK_PKE_BYTES + ParamSet::<K>::EK_BYTES;
        let mut wrong_h = dk.clone();
        wrong_h[h_at] ^= 1;
        assert_eq!(
            check_dk::<K>(&wrong_h),
            Err(KyberError::InvalidDecapsulationKey)
        );
        // An embedded ek with one flipped bit no longer matches the stored hash.
        let mut wrong_ek = dk.clone();
        wrong_ek[ParamSet::<K>::DK_PKE_BYTES] ^= 1;
        assert_eq!(
            check_dk::<K>(&wrong_ek),
            Err(KyberError::InvalidDecapsulationKey)
        );
        // dk_PKE and z are not covered by the hash check (section 7.3).
        let mut secret_part = dk.clone();
        secret_part[0] ^= 1;
        *secret_part.last_mut().unwrap() ^= 1;
        assert_eq!(check_dk::<K>(&secret_part), Ok(()));
        // The split follows the layout dk_PKE || ek || H(ek) || z.
        let parts = split_dk::<K>(&dk).unwrap();
        assert_eq!(parts.ek, &ek[..]);
        assert_eq!(parts.dk_pke.len(), ParamSet::<K>::DK_PKE_BYTES);
        assert_eq!((parts.h.len(), parts.z.len()), (HASH_BYTES, HASH_BYTES));
    }

    #[test]
    fn decapsulation_key_checks_for_all_sets() {
        each_set(|k| per_set!(dk_checks, k));
    }

    fn ct_checks<const K: usize>() {
        let ok = vec![0u8; ParamSet::<K>::CT_BYTES];
        assert_eq!(check_ct::<K>(&ok), Ok(()));
        let bad = |actual| KyberError::invalid_input("c", ParamSet::<K>::CT_BYTES, actual);
        assert_eq!(check_ct::<K>(&ok[1..]), Err(bad(ok.len() - 1)));
        assert_eq!(
            check_ct::<K>(&[&ok[..], &[0]].concat()),
            Err(bad(ok.len() + 1))
        );
        assert_eq!(check_ct::<K>(&[]), Err(bad(0)));
    }

    #[test]
    fn ciphertext_check_for_all_sets() {
        each_set(|k| per_set!(ct_checks, k));
    }
}
