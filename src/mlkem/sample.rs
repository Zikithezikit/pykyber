//! SampleNTT (FIPS 203 Algorithm 7) on top of the legacy SHAKE128 XOF and
//! `rej_uniform`.

use crate::kyber::indcpa::rej_uniform;
use crate::kyber::params::{KYBER_N, KYBER_Q, KYBER_SYMBYTES};
use crate::kyber::poly::Poly;
use crate::kyber::symmetric::{xof_absorb_bytes, xof_squeeze_blocks, XofState, XOF_BLOCKBYTES};

/// Bits of one rejection-sampling candidate (q < 2^12).
const CANDIDATE_BITS: usize = 12;
/// Stream bytes consumed per pair of candidates d1, d2 (Algorithm 7 lines 5-7).
const PAIR_BYTES: usize = 3;
/// Seed rho, then the two index bytes `j || i`.
const INDEX_BYTES: usize = 2;
const SEED_BYTES: usize = KYBER_SYMBYTES;
/// Input of Algorithm 7: `rho || j || i`.
pub(crate) const INPUT_BYTES: usize = SEED_BYTES + INDEX_BYTES;

/// Blocks squeezed up front; enough for 256 coefficients with high probability.
const NBLOCKS: usize = (CANDIDATE_BITS * KYBER_N / u8::BITS as usize * (1 << CANDIDATE_BITS)
    / KYBER_Q
    + XOF_BLOCKBYTES)
    / XOF_BLOCKBYTES;

/// Algorithm 7: `b` is `rho || j || i` (a 32-byte seed and two index bytes).
/// The input is public, so the rejection loop may branch on the stream.
pub(crate) fn sample_ntt(b: &[u8; INPUT_BYTES]) -> Poly {
    let mut state = XofState::new();
    xof_absorb_bytes(
        &mut state,
        &b[..SEED_BYTES],
        b[SEED_BYTES],
        b[SEED_BYTES + 1],
    );
    let mut out = Poly::new();
    // Room to carry the unread tail of the previous block (at most PAIR_BYTES - 1).
    let mut buf = [0u8; NBLOCKS * XOF_BLOCKBYTES + PAIR_BYTES - 1];
    xof_squeeze_blocks(&mut buf, NBLOCKS, &mut state);
    let mut buflen = NBLOCKS * XOF_BLOCKBYTES;
    let mut ctr = rej_uniform(&mut out.coeffs, KYBER_N, &buf, buflen);
    while ctr < KYBER_N {
        // Carry the unread tail (buflen % PAIR_BYTES bytes) in front of the next block
        // so no stream byte is skipped.
        let off = buflen % PAIR_BYTES;
        buf.copy_within(buflen - off..buflen, 0);
        xof_squeeze_blocks(&mut buf[off..], 1, &mut state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(&mut out.coeffs[ctr..], KYBER_N - ctr, &buf, buflen);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Long enough that the reference sampler never runs out of stream.
    const SPEC_STREAM_BLOCKS: usize = 40;
    /// Random inputs to compare; enough that some need more than NBLOCKS blocks.
    const INPUTS: usize = 3000;

    /// Algorithm 7 transcribed line by line over a long SHAKE128 stream. The
    /// literals in d1 and d2 are the ones printed in the standard (lines 6-7).
    /// Returns the polynomial and the number of stream bytes consumed.
    fn spec_sample_ntt(b: &[u8; INPUT_BYTES]) -> ([i16; KYBER_N], usize) {
        let mut state = XofState::new();
        xof_absorb_bytes(
            &mut state,
            &b[..SEED_BYTES],
            b[SEED_BYTES],
            b[SEED_BYTES + 1],
        );
        let mut stream = vec![0u8; SPEC_STREAM_BLOCKS * XOF_BLOCKBYTES];
        xof_squeeze_blocks(&mut stream, SPEC_STREAM_BLOCKS, &mut state);
        let (mut a, mut j, mut pos) = ([0i16; KYBER_N], 0, 0);
        while j < KYBER_N {
            let c = &stream[pos..pos + 3];
            pos += 3;
            let d1 = c[0] as u16 + 256 * (c[1] as u16 % 16);
            let d2 = (c[1] as u16) / 16 + 16 * c[2] as u16;
            if d1 < KYBER_Q as u16 {
                a[j] = d1 as i16;
                j += 1;
            }
            if d2 < KYBER_Q as u16 && j < KYBER_N {
                a[j] = d2 as i16;
                j += 1;
            }
        }
        (a, pos)
    }

    #[test]
    fn matches_algorithm_7_including_the_refill_path() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut refills = 0;
        for _ in 0..INPUTS {
            let mut b = [0u8; INPUT_BYTES];
            for byte in b.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *byte = (x >> 24) as u8;
            }
            let (want, used) = spec_sample_ntt(&b);
            if used > NBLOCKS * XOF_BLOCKBYTES {
                refills += 1;
            }
            assert_eq!(sample_ntt(&b).coeffs, want);
        }
        // The extra-block branch must actually have been exercised.
        assert!(refills > 0, "no input needed more than {NBLOCKS} blocks");
    }
}
