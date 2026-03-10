use super::reduce::*;

/// Twiddle factors (primitive roots of unity) used in the Number Theoretic Transform.
/// These are Montgomery-friendly constants precomputed for the Kyber polynomial ring.
pub const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// Field multiplication in the Kyber polynomial ring (q = 3329).
/// Uses Montgomery multiplication to compute a * b mod q.
pub fn field_multiply(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

/// Forward Number Theoretic Transform (NTT) on a polynomial.
/// Transforms coefficients from standard to NTT domain using iterative Cooley-Tukey algorithm.
/// Input is in-place on the coefficient array.
pub fn ntt_forward(coeffs: &mut [i16]) {
    let mut j;
    let mut zeta_index = 1usize;
    let mut layer_length = 128;
    let (mut temp, mut zeta);

    while layer_length >= 2 {
        let mut start = 0;
        while start < 256 {
            zeta = ZETAS[zeta_index];
            zeta_index += 1;
            j = start;
            while j < (start + layer_length) {
                temp = field_multiply(zeta, coeffs[j + layer_length]);
                coeffs[j + layer_length] = (coeffs[j] as i32 - temp as i32) as i16;
                coeffs[j] = (coeffs[j] as i32 + temp as i32) as i16;
                j += 1;
            }
            start = j + layer_length;
        }
        layer_length >>= 1;
    }
}

/// Inverse Number Theuristic Transform (INTT) on a polynomial.
/// Transforms coefficients from NTT domain back to standard representation.
/// Uses inverse butterflies with Barrett reduction and final scaling factor.
pub fn ntt_inverse(coeffs: &mut [i16]) {
    let mut j;
    let mut zeta_index = 127usize;
    let mut layer_length = 2;
    let (mut temp, mut zeta);
    const F: i16 = 1441;
    while layer_length <= 128 {
        let mut start = 0;
        while start < 256 {
            zeta = ZETAS[zeta_index];
            zeta_index -= 1;
            j = start;
            while j < (start + layer_length) {
                temp = coeffs[j];
                coeffs[j] = barrett_reduce(temp as i32 + coeffs[j + layer_length] as i32);
                coeffs[j + layer_length] = (coeffs[j + layer_length] as i32 - temp as i32) as i16;
                coeffs[j + layer_length] = field_multiply(zeta, coeffs[j + layer_length]);
                j += 1
            }
            start = j + layer_length;
        }
        layer_length <<= 1;
    }
    for j in 0..256 {
        coeffs[j] = field_multiply(coeffs[j], F);
    }
}

/// Base multiplication for two polynomials in the NTT domain.
/// Computes point-wise multiplication of polynomials a and b,
/// using the provided twiddle factor zeta for the butterfly operation.
pub fn base_multiply(result: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    result[0] = field_multiply(a[1], b[1]);
    result[0] = field_multiply(result[0], zeta);
    result[0] += field_multiply(a[0], b[0]);

    result[1] = field_multiply(a[0], b[1]);
    result[1] += field_multiply(a[1], b[0]);
}
