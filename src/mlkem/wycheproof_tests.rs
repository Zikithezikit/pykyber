//! ML-KEM against the C2SP Wycheproof vectors (repository C2SP/wycheproof,
//! directory `testvectors_v1`, fetched by `scripts/fetch_vectors.py` at the
//! commit pinned in `tests/vectors/manifest.json` and never committed). A
//! missing file fails the test: run the fetch script.
//!
//! The four file kinds and their schemas (`schemas/mlkem_*_test_schema.json`
//! and `schemas/common.json` at the same commit):
//! - `mlkem_N_test.json`: `seed` (`d || z`), `ek`, `c`, `K`. The key is made
//!   from the seed; `valid` means decapsulating `c` gives `K`. `invalid` is a
//!   seed that is not 64 bytes or a ciphertext of the wrong length.
//! - `mlkem_N_encaps_test.json`: `ek`, `m`, `c`, `K`. `valid` means
//!   `Encaps_internal(ek, m)` gives `(K, c)`; `invalid` is an `ek` of the wrong
//!   length or one that fails the modulus check (section 7.2).
//! - `mlkem_N_keygen_seed_test.json`: `seed` gives exactly `ek` and `dk`.
//! - `mlkem_N_semi_expanded_decaps_test.json`: `dk`, `ek`, `c`, `K`. `valid`
//!   means decapsulating `c` with `dk` gives `K` (an altered ciphertext still
//!   gives the implicit-rejection `K`); `invalid` is a wrong length of `dk` or
//!   `c`, or a `dk` that fails the hash check (section 7.3).
//!
//! `result` is `valid`, `invalid` or `acceptable` (schemas/common.json). A
//! `valid` case must succeed with the given output, an `invalid` case must be
//! refused, and for an `acceptable` case either is fine, but if it succeeds it
//! must give the output. The flags (`Strcmp`, `MalleableCiphertext`,
//! `ModulusOverflow`, ...) only describe the bug a case targets: none of them
//! changes what the result requires (`notes` in each file). The pinned files
//! have no `acceptable` case; the rule is implemented anyway, so a future pin
//! bump cannot make one pass silently.

use super::check::check_ek;
use super::kem::{acvp, decaps, encaps};
use super::params::{MlKem1024, MlKem512, MlKem768, ParamSet};
use crate::kyber::params::KYBER_SYMBYTES;
use serde_json::Value;

const WYCHEPROOF_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/external/wycheproof/"
);
const HEX_DIGITS_PER_BYTE: usize = 2;
const HEX_RADIX: u32 = 16;
const SEED_BYTES: usize = KYBER_SYMBYTES;
/// The `d || z` seed of Algorithm 19.
const FULL_SEED_BYTES: usize = 2 * SEED_BYTES;

fn unhex(digits: &str) -> Vec<u8> {
    (0..digits.len())
        .step_by(HEX_DIGITS_PER_BYTE)
        .map(|i| u8::from_str_radix(&digits[i..i + HEX_DIGITS_PER_BYTE], HEX_RADIX).unwrap())
        .collect()
}

fn field(test: &Value, name: &str) -> Vec<u8> {
    unhex(test[name].as_str().unwrap_or_else(|| panic!("no {name}")))
}

fn halves(seed: &[u8]) -> ([u8; SEED_BYTES], [u8; SEED_BYTES]) {
    let (d, z) = seed.split_at(SEED_BYTES);
    (d.try_into().unwrap(), z.try_into().unwrap())
}

/// Applies the `result` rule of the schema to the outcome of a case: `None` is
/// a refusal, `Some(output)` a success. `expected` is the `K` of the case.
fn judge(tc_id: u64, result: &str, outcome: Option<Vec<u8>>, expected: &[u8]) {
    match (result, outcome) {
        ("valid", Some(output)) => assert_eq!(output, expected, "tcId {tc_id}"),
        ("valid", None) => panic!("tcId {tc_id}: valid case was refused"),
        ("invalid", outcome) => assert!(outcome.is_none(), "tcId {tc_id}: invalid case accepted"),
        ("acceptable", Some(output)) if !expected.is_empty() => {
            assert_eq!(output, expected, "tcId {tc_id}")
        }
        ("acceptable", _) => {}
        (other, _) => panic!("tcId {tc_id}: unknown result {other}"),
    }
}

/// Runs `check::<K>(test) -> Option<Vec<u8>>` on every case of a file and
/// judges it. Returns the number of cases run, which must be `numberOfTests`.
fn run_file<const K: usize>(
    file: &str,
    schema: &str,
    parameter_set: &str,
    check: fn(&Value) -> Option<Vec<u8>>,
    expected_field: &str,
) -> usize {
    let path = format!("{WYCHEPROOF_DIR}{file}");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}; run scripts/fetch_vectors.py"));
    let doc: Value = serde_json::from_str(&text).expect("Wycheproof file is JSON");
    assert_eq!(doc["algorithm"], "ML-KEM", "{file}");
    assert_eq!(doc["schema"], schema, "{file}");
    let mut cases = 0;
    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["parameterSet"], parameter_set, "{file}");
        for test in group["tests"].as_array().unwrap() {
            let expected = test
                .get(expected_field)
                .map_or(Vec::new(), |_| field(test, expected_field));
            judge(
                test["tcId"].as_u64().unwrap(),
                test["result"].as_str().unwrap(),
                check(test),
                &expected,
            );
            cases += 1;
        }
    }
    assert_eq!(
        cases as u64,
        doc["numberOfTests"].as_u64().unwrap(),
        "{file}: numberOfTests"
    );
    cases
}

/// `mlkem_N_test.json`. A seed that is not `d || z` cannot be passed to the
/// typed Rust API (two 32-byte arrays), and the Python test covers it through
/// `seed=`; here such a case counts as refused, as the type system does.
fn seed_case<const K: usize>(test: &Value) -> Option<Vec<u8>> {
    let seed = field(test, "seed");
    if seed.len() != FULL_SEED_BYTES {
        return None;
    }
    let (d, z) = halves(&seed);
    let (ek, dk) = acvp::keygen_internal::<K>(&d, &z);
    assert_eq!(ek, field(test, "ek"), "tcId {}", test["tcId"]);
    decaps::<K>(&dk, &field(test, "c")).ok().map(|k| k.to_vec())
}

/// `mlkem_N_encaps_test.json`: the public `encaps` refuses a bad `ek` before it
/// draws `m`; for a good one `Encaps_internal(ek, m)` must give `(K, c)`.
fn encaps_case<const K: usize>(test: &Value) -> Option<Vec<u8>> {
    let ek = field(test, "ek");
    let refused = encaps::<K>(&ek).is_err();
    assert_eq!(
        refused,
        check_ek::<K>(&ek).is_err(),
        "tcId {}",
        test["tcId"]
    );
    if refused {
        return None;
    }
    let m: [u8; SEED_BYTES] = field(test, "m").try_into().expect("32-byte m");
    let (k, c) = acvp::encaps_internal::<K>(&ek, &m).unwrap();
    assert_eq!(c, field(test, "c"), "tcId {}", test["tcId"]);
    Some(k.to_vec())
}

/// `mlkem_N_keygen_seed_test.json`: no refusal is possible, `K` is the `ek`.
fn keygen_case<const K: usize>(test: &Value) -> Option<Vec<u8>> {
    let (d, z) = halves(&field(test, "seed"));
    let (ek, dk) = acvp::keygen_internal::<K>(&d, &z);
    assert_eq!(dk.to_vec(), field(test, "dk"), "tcId {}", test["tcId"]);
    Some(ek)
}

/// `mlkem_N_semi_expanded_decaps_test.json`.
fn decaps_case<const K: usize>(test: &Value) -> Option<Vec<u8>> {
    let (dk, c) = (field(test, "dk"), field(test, "c"));
    let output = decaps::<K>(&dk, &c).ok().map(|k| k.to_vec());
    if output.is_some() {
        // The ek the file lists is the one embedded in dk (Algorithm 16 step 3).
        let embedded = &dk[ParamSet::<K>::DK_PKE_BYTES..][..ParamSet::<K>::EK_BYTES];
        assert_eq!(embedded, field(test, "ek"), "tcId {}", test["tcId"]);
    }
    output
}

fn run_level<const K: usize>(size: usize) -> [usize; 4] {
    let set = format!("ML-KEM-{size}");
    let name = |kind: &str| format!("mlkem_{size}_{kind}.json");
    [
        run_file::<K>(
            &name("test"),
            "mlkem_test_schema.json",
            &set,
            seed_case::<K>,
            "K",
        ),
        run_file::<K>(
            &name("encaps_test"),
            "mlkem_encaps_test_schema.json",
            &set,
            encaps_case::<K>,
            "K",
        ),
        run_file::<K>(
            &name("keygen_seed_test"),
            "mlkem_keygen_seed_test_schema.json",
            &set,
            keygen_case::<K>,
            "ek",
        ),
        run_file::<K>(
            &name("semi_expanded_decaps_test"),
            "mlkem_semi_expanded_decaps_test_schema.json",
            &set,
            decaps_case::<K>,
            "K",
        ),
    ]
}

// The case counts are those of the pinned files (`numberOfTests`), so a file
// that lost cases would fail here as well as on its hash.
#[test]
fn wycheproof_ml_kem_512() {
    assert_eq!(run_level::<{ MlKem512::K }>(512), [200, 261, 100, 9]);
}

#[test]
fn wycheproof_ml_kem_768() {
    assert_eq!(run_level::<{ MlKem768::K }>(768), [201, 265, 100, 9]);
}

#[test]
fn wycheproof_ml_kem_1024() {
    assert_eq!(run_level::<{ MlKem1024::K }>(1024), [202, 269, 100, 9]);
}
