//! ML-KEM against the C2SP CCTV vectors (repository C2SP/CCTV, directory
//! ML-KEM, fetched by `scripts/fetch_vectors.py` at the commit pinned in
//! `tests/vectors/manifest.json` and never committed). A missing file fails the
//! test: run the fetch script.
//!
//! What each set proves:
//! - `modulus/`: encapsulation keys with one coefficient in q..2^12-1; the
//!   section 7.2 modulus check must reject every one, at every position.
//! - `unluckysample/`: a `d` whose `rho` makes SampleNTT (Algorithm 7) read
//!   more than 575 bytes of the XOF for `A[0][0]`, so the refill path runs.
//! - `strcmp/`: a modified ciphertext whose first byte is zero and whose
//!   re-encryption starts with the same zero byte, so a C string compare would
//!   accept it. Decaps must return the implicit-rejection secret.
//! - the accumulated vectors: the README fixes a SHAKE128 stream of inputs and
//!   the hash of all outputs of the pq-crystals reference, over 10 000 runs.
//!
//! The `unluckysample` files and the accumulated hashes were made before the final
//! standard: `(rho, sigma)` there is `G(d)` and the final one is `G(d || k)`
//! (FIPS 203 Algorithm 13 step 1, see `kpke::keygen`). So `draft_keygen` below
//! builds the key pair with the old derivation from `kpke::keygen_expanded`,
//! which is the rest of Algorithms 13 and 16 unchanged. The final derivation is
//! covered by the ACVP vectors.

use super::check::{check_dk, check_ek, split_dk};
use super::compress::MSG_BYTES;
use super::kem::{acvp, decaps, encaps};
use super::kpke::{decrypt, encrypt, keygen_expanded};
use super::params::{MlKem1024, MlKem512, MlKem768, ParamSet};
use crate::kyber::error::KyberError;
use crate::kyber::fips202::{
    keccakf1600_statepermute, sha3_256, sha3_512, shake128_absorb_once, shake128_squeezeblocks,
    shake256, KeccakState, SHAKE128_RATE,
};
use crate::kyber::params::{KYBER_N, KYBER_Q, KYBER_SSBYTES, KYBER_SYMBYTES};
use crate::kyber::symmetric::{xof_absorb_bytes, xof_squeeze_blocks, XOF_BLOCKBYTES};
use std::collections::HashMap;
use std::io::Read;

const CCTV_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/external/cctv/");
const HEX_DIGITS_PER_BYTE: usize = 2;
const HEX_RADIX: u32 = 16;
const SEED_BYTES: usize = KYBER_SYMBYTES;
/// Bytes of the XOF stream SampleNTT needs for 256 coefficients in the unlucky
/// case or more (README, "Unlucky NTT sampling vector").
const UNLUCKY_MIN_BYTES: usize = 575;
/// Bytes consumed by one pair of candidates d1, d2 (Algorithm 7 lines 5-7).
const PAIR_BYTES: usize = 3;
/// Bits per candidate, so a candidate is below 2^12 (Algorithm 7 lines 6-7).
const CANDIDATE_BITS: u32 = 12;
/// Bits of the middle byte that belong to d1 (the rest belong to d2).
const NIBBLE_BITS: u32 = CANDIDATE_BITS - u8::BITS;
/// Lanes of the Keccak state (FIPS 202 section 3.1: 1600 bits of 64).
const KECCAK_LANES: usize = 25;
const LANE_BYTES: usize = u64::BITS as usize / u8::BITS as usize;
/// A modulus-vector file has this many keys in addition to the sweep over
/// positions: two positions times two values, per polynomial (modulus.go).
const EDGE_VECTORS_PER_POLY: usize = 4;
/// Values q..2^12-1 swept by the modulus vectors.
const OVERFLOW_VALUES: usize = (1 << CANDIDATE_BITS) - KYBER_Q;

/// Runs `$f::<K>(name)` for the three parameter sets.
macro_rules! each_level {
    ($f:ident) => {
        $f::<{ MlKem512::K }>("ML-KEM-512");
        $f::<{ MlKem768::K }>("ML-KEM-768");
        $f::<{ MlKem1024::K }>("ML-KEM-1024");
    };
}

fn unhex(digits: &str) -> Vec<u8> {
    (0..digits.len())
        .step_by(HEX_DIGITS_PER_BYTE)
        .map(|i| u8::from_str_radix(&digits[i..i + HEX_DIGITS_PER_BYTE], HEX_RADIX).unwrap())
        .collect()
}

fn read(path: &str) -> Vec<u8> {
    let path = format!("{CCTV_DIR}{path}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}; run scripts/fetch_vectors.py"))
}

/// A `name = hex` file with one record (the `unluckysample` and `strcmp` files).
fn record(path: &str) -> HashMap<String, Vec<u8>> {
    let text = String::from_utf8(read(path)).expect("ASCII file");
    let mut fields = HashMap::new();
    for line in text.lines() {
        let (name, value) = line.split_once(" = ").expect("`name = hex` line");
        assert!(
            fields.insert(name.to_string(), unhex(value)).is_none(),
            "{path}: repeated {name}"
        );
    }
    fields
}

fn seed(fields: &HashMap<String, Vec<u8>>, name: &str) -> [u8; SEED_BYTES] {
    fields[name].clone().try_into().expect("32-byte field")
}

/// Bytes of the SHAKE128 stream for `rho || 0 || 0` that Algorithm 7 reads
/// before it has 256 coefficients below q.
fn sample_ntt_bytes(rho: &[u8]) -> usize {
    let mut state = KeccakState::new();
    xof_absorb_bytes(&mut state, rho, 0, 0);
    let mut stream = Vec::new();
    let (mut accepted, mut used) = (0, 0);
    while accepted < KYBER_N {
        if used + PAIR_BYTES > stream.len() {
            let mut block = [0u8; XOF_BLOCKBYTES];
            xof_squeeze_blocks(&mut block, 1, &mut state);
            stream.extend_from_slice(&block);
        }
        let c = &stream[used..used + PAIR_BYTES];
        used += PAIR_BYTES;
        // Algorithm 7 lines 6-7.
        let d1 = c[0] as usize + (1 << u8::BITS) * (c[1] as usize % (1 << NIBBLE_BITS));
        let d2 = (c[1] as usize >> NIBBLE_BITS) + (1 << NIBBLE_BITS) * c[2] as usize;
        for d in [d1, d2] {
            if d < KYBER_Q && accepted < KYBER_N {
                accepted += 1;
            }
        }
    }
    used
}

/// Algorithm 16 with `(rho, sigma) = G(d)`, as in the standard before it added `k`.
fn draft_keygen<const K: usize>(d: &[u8; SEED_BYTES], z: &[u8; SEED_BYTES]) -> (Vec<u8>, Vec<u8>) {
    let mut g = [0u8; 2 * SEED_BYTES];
    sha3_512(&mut g, d, d.len());
    let (rho, sigma) = g.split_at(SEED_BYTES);
    let (ek, dk_pke) = keygen_expanded::<K>(rho.try_into().unwrap(), sigma.try_into().unwrap());
    let mut h = [0u8; SEED_BYTES];
    sha3_256(&mut h, &ek, ek.len());
    let dk = [&dk_pke[..], &ek, &h, z].concat();
    (ek, dk)
}

fn unlucky_level<const K: usize>(name: &str) {
    let f = record(&format!("unluckysample/{name}.txt"));
    let (ek, dk, c) = (&f["ek"], &f["dk"], &f["c"]);
    let (d, m) = (seed(&f, "d"), seed(&f, "m"));
    let rho = &ek[ek.len() - SEED_BYTES..];

    // Draft derivation of rho, not the final one; see the module comment.
    let mut g = [0u8; 2 * SEED_BYTES];
    sha3_512(&mut g, &d, d.len());
    assert_eq!(g[..SEED_BYTES], *rho, "{name}: rho is G(d)");
    assert!(
        sample_ntt_bytes(rho) > UNLUCKY_MIN_BYTES,
        "{name}: not an unlucky rho"
    );

    check_ek::<K>(ek).unwrap();
    check_dk::<K>(dk).unwrap();
    let (k, ct) = acvp::encaps_internal::<K>(ek, &m).unwrap();
    assert_eq!(
        (k.to_vec(), &ct),
        (f["K"].clone(), c),
        "{name}: encaps_internal"
    );
    assert_eq!(*decaps::<K>(dk, c).unwrap(), f["K"][..], "{name}: decaps");
}

#[test]
fn unlucky_sampling_vectors() {
    each_level!(unlucky_level);
}

fn strcmp_level<const K: usize>(name: &str) {
    let f = record(&format!("strcmp/{name}.txt"));
    let (dk, c) = (&f["dk"], &f["c"]);
    assert_eq!(*decaps::<K>(dk, c).unwrap(), f["K"][..], "{name}: decaps");

    // The expected secret is the implicit-rejection one, J(z || c) (Algorithm 18 step 7).
    let parts = split_dk::<K>(dk).unwrap();
    let mut j = [0u8; KYBER_SSBYTES];
    let input = [parts.z, c].concat();
    shake256(&mut j, KYBER_SSBYTES, &input, input.len());
    assert_eq!(j[..], f["K"][..], "{name}: K is J(z || c)");

    // Re-encrypt as Algorithm 18 steps 5-6 do; the strcmp trap is that the
    // ciphertexts differ only after the first zero byte.
    let m = decrypt::<K>(parts.dk_pke, c).unwrap();
    let mut kr = [0u8; 2 * SEED_BYTES];
    let g_input: [u8; MSG_BYTES + SEED_BYTES] = [&m[..], parts.h].concat().try_into().unwrap();
    sha3_512(&mut kr, &g_input, g_input.len());
    let reencrypted = encrypt::<K>(parts.ek, &m, kr[SEED_BYTES..].try_into().unwrap()).unwrap();
    let zero = c.iter().position(|&b| b == 0).expect("a zero byte in c");
    assert_eq!(
        reencrypted[..=zero],
        c[..=zero],
        "{name}: equal up to the zero byte"
    );
    assert_ne!(reencrypted, *c, "{name}: c is not the re-encryption");
}

#[test]
fn strcmp_vectors() {
    each_level!(strcmp_level);
}

fn modulus_level<const K: usize>(name: &str) {
    let mut text = String::new();
    flate2::read::GzDecoder::new(&read(&format!("modulus/{name}.txt.gz"))[..])
        .read_to_string(&mut text)
        .unwrap();
    let mut keys = 0;
    for line in text.lines() {
        let ek = unhex(line);
        assert_eq!(
            ek.len(),
            ParamSet::<K>::EK_BYTES,
            "{name}: key {keys} has the right length"
        );
        assert!(
            matches!(check_ek::<K>(&ek), Err(KyberError::InvalidEncapsulationKey)),
            "{name}: check_ek accepted key {keys}"
        );
        assert!(
            matches!(encaps::<K>(&ek), Err(KyberError::InvalidEncapsulationKey)),
            "{name}: encaps accepted key {keys}"
        );
        keys += 1;
    }
    // modulus.go: four edge keys per polynomial, then a sweep that runs until
    // every value and every position has been used.
    let sweep = OVERFLOW_VALUES.max(K * KYBER_N);
    assert_eq!(
        keys,
        EDGE_VECTORS_PER_POLY * K + sweep,
        "{name}: number of keys"
    );
}

#[test]
fn modulus_check_negatives() {
    each_level!(modulus_level);
}

/// The README of the pinned commit, which holds the hashes below.
fn readme() -> String {
    String::from_utf8(read("README.md")).unwrap()
}

/// Accumulated vectors, README "Accumulated pq-crystals vectors". The values
/// are the hashes printed there, for 10 000 and 1 000 000 runs.
const ACCUMULATED: [(&str, usize, &str); 6] = [
    (
        "ML-KEM-512",
        10_000,
        "845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4",
    ),
    (
        "ML-KEM-768",
        10_000,
        "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3",
    ),
    (
        "ML-KEM-1024",
        10_000,
        "47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543",
    ),
    (
        "ML-KEM-512",
        1_000_000,
        "578eeaa1156848cbf7a15bafef963b4ccabe3308ddfb7dbdd20ad965f634e81d",
    ),
    (
        "ML-KEM-768",
        1_000_000,
        "70090cc5842aad0ec43d5042c783fae9bc320c047b5dafcb6e134821db02384d",
    ),
    (
        "ML-KEM-1024",
        1_000_000,
        "7ccc6d803739d3db3c5ce39c7130f459db32a199c6605e3be210e5a89d4c4b95",
    ),
];
/// Runs per parameter set unless `PYKYBER_CCTV_RUNS` says otherwise (the
/// million-run hash needs a release build: `cargo test --release`).
const DEFAULT_RUNS: usize = 10_000;
const RUNS_VARIABLE: &str = "PYKYBER_CCTV_RUNS";
/// First bytes of the deterministic stream, as printed in the README.
const STREAM_START: [u8; 16] = [
    0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
];
/// SHAKE128 output bytes of the final hash (32, as in the README).
const HASH_BYTES: usize = 32;
/// SHAKE128 domain separation byte (FIPS 202 section 6.2).
const SHAKE_SUFFIX: u8 = 0x1F;

/// The README's deterministic RNG: one SHAKE128 instance over the empty string.
struct Stream {
    state: KeccakState,
    block: [u8; SHAKE128_RATE],
    pos: usize,
}

impl Stream {
    fn new() -> Self {
        let mut state = KeccakState::new();
        shake128_absorb_once(&mut state, &[], 0);
        Stream {
            state,
            block: [0; SHAKE128_RATE],
            pos: SHAKE128_RATE,
        }
    }

    fn take(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            if self.pos == SHAKE128_RATE {
                shake128_squeezeblocks(&mut self.block, 1, &mut self.state);
                self.pos = 0;
            }
            *byte = self.block[self.pos];
            self.pos += 1;
        }
    }

    fn seed(&mut self) -> [u8; SEED_BYTES] {
        let mut out = [0u8; SEED_BYTES];
        self.take(&mut out);
        out
    }
}

/// An incremental SHAKE128 that absorbs byte strings one after another.
struct Hasher {
    s: [u64; KECCAK_LANES],
    pos: usize,
}

impl Hasher {
    fn new() -> Self {
        Hasher {
            s: [0; KECCAK_LANES],
            pos: 0,
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.s[self.pos / LANE_BYTES] ^=
                (byte as u64) << (u8::BITS as usize * (self.pos % LANE_BYTES));
            self.pos += 1;
            if self.pos == SHAKE128_RATE {
                keccakf1600_statepermute(&mut self.s);
                self.pos = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; HASH_BYTES] {
        self.s[self.pos / LANE_BYTES] ^=
            (SHAKE_SUFFIX as u64) << (u8::BITS as usize * (self.pos % LANE_BYTES));
        self.s[(SHAKE128_RATE - 1) / LANE_BYTES] ^= 1 << (u64::BITS - 1);
        keccakf1600_statepermute(&mut self.s);
        let lanes = self.s.iter().flat_map(|lane| lane.to_le_bytes());
        let mut out = [0u8; HASH_BYTES];
        for (byte, value) in out.iter_mut().zip(lanes) {
            *byte = value;
        }
        out
    }
}

fn accumulated_level<const K: usize>(name: &str) {
    let runs = std::env::var(RUNS_VARIABLE).map_or(DEFAULT_RUNS, |v| v.parse().unwrap());
    let expected = ACCUMULATED
        .iter()
        .find(|(n, r, _)| *n == name && *r == runs)
        .unwrap_or_else(|| panic!("no hash for {runs} runs of {name}"))
        .2;
    assert!(
        readme().contains(expected),
        "{name}: hash not in the pinned README"
    );

    let mut stream = Stream::new();
    let mut hasher = Hasher::new();
    for run in 0..runs {
        let (d, z, m) = (stream.seed(), stream.seed(), stream.seed());
        let mut random_ct = vec![0u8; ParamSet::<K>::CT_BYTES];
        stream.take(&mut random_ct);
        let (ek, dk) = draft_keygen::<K>(&d, &z);
        let (k, ct) = acvp::encaps_internal::<K>(&ek, &m).unwrap();
        let decapsulated = acvp::decaps_internal::<K>(&dk, &ct).unwrap();
        assert_eq!(*k, *decapsulated, "{name}: run {run} does not decapsulate");
        let rejected = acvp::decaps_internal::<K>(&dk, &random_ct).unwrap();
        for part in [&ek[..], &dk[..], &ct[..], &k[..], &rejected[..]] {
            hasher.absorb(part);
        }
    }
    let hash: String = hasher.finish().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hash, expected, "{name}: accumulated hash over {runs} runs");
}

#[test]
fn rng_stream_starts_as_in_the_readme() {
    let mut first = [0u8; STREAM_START.len()];
    Stream::new().take(&mut first);
    assert_eq!(first, STREAM_START);
}

// One test per parameter set so the harness runs them in parallel.
#[test]
fn accumulated_vectors_512() {
    accumulated_level::<{ MlKem512::K }>("ML-KEM-512");
}

#[test]
fn accumulated_vectors_768() {
    accumulated_level::<{ MlKem768::K }>("ML-KEM-768");
}

#[test]
fn accumulated_vectors_1024() {
    accumulated_level::<{ MlKem1024::K }>("ML-KEM-1024");
}
