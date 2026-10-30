//! K-PKE against the NIST ACVP ML-KEM vectors (ACVP-Server, internalProjection
//! files, fetched by `scripts/fetch_vectors.py` and never committed).
//!
//! KeyGen_internal (Algorithm 16) starts with K-PKE.KeyGen(d), so the keyGen
//! vectors pin `ek_PKE` and `dk_PKE` through `kpke`, and the whole `(ek, dk)`
//! through `kem::acvp::keygen_internal`. The encapDecap vectors run
//! `encaps_internal` and `decaps_internal` (Algorithms 17 and 18) and the key
//! checks of FIPS 203 sections 7.2 and 7.3. A missing file fails the test: run
//! the fetch script.

use super::check::{check_dk, check_ek};
use super::kem::acvp;
use super::kpke::{encrypt, keygen};
use super::params::{MlKem1024, MlKem512, MlKem768, ParamSet};
use crate::kyber::fips202::{sha3_256, sha3_512};
use crate::kyber::params::KYBER_SYMBYTES;
use serde_json::Value;

/// Folder the fetch script fills, under `tests/vectors/external`.
const ACVP_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/external/acvp/");
const KEYGEN_FILE: &str = "ML-KEM-keyGen-FIPS203/internalProjection.json";
const ENCAP_DECAP_FILE: &str = "ML-KEM-encapDecap-FIPS203/internalProjection.json";
/// Hex digits per byte.
const HEX_DIGITS_PER_BYTE: usize = 2;
const HEX_RADIX: u32 = 16;
const SEED_BYTES: usize = KYBER_SYMBYTES;

fn load(file: &str) -> Value {
    let path = format!("{ACVP_DIR}{file}");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}; run scripts/fetch_vectors.py"));
    serde_json::from_str(&text).expect("ACVP file is JSON")
}

fn hex(value: &Value, field: &str) -> Vec<u8> {
    let digits = value[field]
        .as_str()
        .unwrap_or_else(|| panic!("no {field}"));
    (0..digits.len())
        .step_by(HEX_DIGITS_PER_BYTE)
        .map(|i| u8::from_str_radix(&digits[i..i + HEX_DIGITS_PER_BYTE], HEX_RADIX).unwrap())
        .collect()
}

fn seed(value: &Value, field: &str) -> [u8; SEED_BYTES] {
    hex(value, field).try_into().expect("32-byte field")
}

fn h(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; SEED_BYTES];
    sha3_256(&mut out, input, input.len());
    out
}

fn g(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 2 * SEED_BYTES];
    sha3_512(&mut out, input, input.len());
    out
}

/// Run `check::<K>` for the groups of `function` (None for keyGen groups).
fn for_groups(file: &str, function: Option<&str>, check: fn(usize, &Value) -> usize) -> usize {
    let mut cases = 0;
    for group in load(file)["testGroups"].as_array().unwrap() {
        if function.is_some() && group["function"].as_str() != function {
            continue;
        }
        let k = match group["parameterSet"].as_str().unwrap() {
            "ML-KEM-512" => MlKem512::K,
            "ML-KEM-768" => MlKem768::K,
            "ML-KEM-1024" => MlKem1024::K,
            other => panic!("unknown parameter set {other}"),
        };
        for test in group["tests"].as_array().unwrap() {
            cases += check(k, test);
        }
    }
    cases
}

/// Calls the generic `$f::<K>` for the runtime `k` of a vector group.
macro_rules! by_k {
    ($f:ident, $k:expr, $($arg:expr),*) => {
        match $k {
            MlKem512::K => $f::<{ MlKem512::K }>($($arg),*),
            MlKem768::K => $f::<{ MlKem768::K }>($($arg),*),
            MlKem1024::K => $f::<{ MlKem1024::K }>($($arg),*),
            other => panic!("unsupported k = {other}"),
        }
    };
}

fn keygen_case<const K: usize>(t: &Value) -> usize {
    let (ek, dk) = keygen::<K>(&seed(t, "d"));
    assert_eq!(ek, hex(t, "ek"), "tcId {}", t["tcId"]);
    // dk = dk_PKE || ek || H(ek) || z (Algorithm 16 step 3).
    assert_eq!(
        dk.to_vec(),
        hex(t, "dk")[..ParamSet::<K>::DK_PKE_BYTES],
        "tcId {}",
        t["tcId"]
    );
    1
}

#[test]
fn k_pke_keygen_matches_acvp() {
    let cases = for_groups(KEYGEN_FILE, None, |k, t| by_k!(keygen_case, k, t));
    assert_eq!(cases, 3 * 25);
}

/// Algorithm 17 steps 1-2: (K, r) = G(m || H(ek)); c = K-PKE.Encrypt(ek, m, r).
fn encaps_case<const K: usize>(t: &Value) -> usize {
    let (ek, m) = (hex(t, "ek"), seed(t, "m"));
    let kr = g(&[&m[..], &h(&ek)].concat());
    assert_eq!(kr[..SEED_BYTES], hex(t, "k"), "tcId {}", t["tcId"]);
    let r = kr[SEED_BYTES..].try_into().unwrap();
    assert_eq!(
        encrypt::<K>(&ek, &m, &r).unwrap(),
        hex(t, "c"),
        "tcId {}",
        t["tcId"]
    );
    1
}

#[test]
fn k_pke_encrypt_matches_acvp_encapsulation() {
    let cases = for_groups(ENCAP_DECAP_FILE, Some("encapsulation"), |k, t| {
        by_k!(encaps_case, k, t)
    });
    assert_eq!(cases, 3 * 25);
}

/// Algorithm 17 end to end: `encaps_internal(ek, m)` gives `(k, c)`.
fn encaps_internal_case<const K: usize>(t: &Value) -> usize {
    let (k, c) = acvp::encaps_internal::<K>(&hex(t, "ek"), &seed(t, "m")).unwrap();
    assert_eq!(*k, hex(t, "k")[..], "tcId {}", t["tcId"]);
    assert_eq!(c, hex(t, "c"), "tcId {}", t["tcId"]);
    1
}

#[test]
fn encaps_internal_matches_acvp() {
    let cases = for_groups(ENCAP_DECAP_FILE, Some("encapsulation"), |k, t| {
        by_k!(encaps_internal_case, k, t)
    });
    assert_eq!(cases, 3 * 25);
}

/// Algorithm 16 end to end: `keygen_internal(d, z)` gives the whole `(ek, dk)`.
fn keygen_internal_case<const K: usize>(t: &Value) -> usize {
    let (ek, dk) = acvp::keygen_internal::<K>(&seed(t, "d"), &seed(t, "z"));
    assert_eq!(ek, hex(t, "ek"), "tcId {}", t["tcId"]);
    assert_eq!(dk.to_vec(), hex(t, "dk"), "tcId {}", t["tcId"]);
    1
}

#[test]
fn keygen_internal_matches_acvp() {
    let cases = for_groups(KEYGEN_FILE, None, |k, t| by_k!(keygen_internal_case, k, t));
    assert_eq!(cases, 3 * 25);
}

/// Algorithm 18: the expected secret is `K'` for a valid ciphertext and
/// `J(z || c)` for a modified one, so one equality covers both.
fn decaps_internal_case<const K: usize>(t: &Value) -> usize {
    let k = acvp::decaps_internal::<K>(&hex(t, "dk"), &hex(t, "c")).unwrap();
    assert_eq!(*k, hex(t, "k")[..], "tcId {}", t["tcId"]);
    1
}

#[test]
fn decaps_internal_matches_acvp() {
    let cases = for_groups(ENCAP_DECAP_FILE, Some("decapsulation"), |k, t| {
        by_k!(decaps_internal_case, k, t)
    });
    // Five valid and five modified ciphertexts in each of the three groups.
    assert_eq!(cases, 3 * 10);
}

/// Sections 7.2 and 7.3: `testPassed` says whether the check accepts the key.
fn key_check_case<const K: usize>(t: &Value, encapsulation: bool) -> usize {
    let passed = t["testPassed"].as_bool().unwrap();
    let result = if encapsulation {
        check_ek::<K>(&hex(t, "ek"))
    } else {
        check_dk::<K>(&hex(t, "dk"))
    };
    assert_eq!(result.is_ok(), passed, "tcId {}: {result:?}", t["tcId"]);
    1
}

#[test]
fn key_checks_match_acvp() {
    let ek_cases = for_groups(ENCAP_DECAP_FILE, Some("encapsulationKeyCheck"), |k, t| {
        by_k!(key_check_case, k, t, true)
    });
    let dk_cases = for_groups(ENCAP_DECAP_FILE, Some("decapsulationKeyCheck"), |k, t| {
        by_k!(key_check_case, k, t, false)
    });
    assert_eq!((ek_cases, dk_cases), (3 * 10, 3 * 10));
}
