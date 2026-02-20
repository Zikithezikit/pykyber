pub fn verify(a: &[u8], b: &[u8], len: usize) -> u8 {
    let mut r = 0u64;
    for i in 0..len {
        r |= (a[i] ^ b[i]) as u64;
    }
    r = r.wrapping_neg() >> 63;
    r as u8
}

pub fn cmov(r: &mut [u8], x: &[u8], len: usize, mut b: u8) {
    b = b.wrapping_neg();
    for i in 0..len {
        r[i] ^= b & (x[i] ^ r[i]);
    }
}
