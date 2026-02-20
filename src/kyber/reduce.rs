use super::params::*;

const QINV: i32 = 62209;

pub fn montgomery_reduce(a: i32) -> i16 {
    let ua = a.wrapping_mul(QINV) as i16;
    let u = ua as i32;
    let mut t = u * KYBER_Q as i32;
    t = a - t;
    t >>= 16;
    t as i16
}

pub fn barrett_reduce(a: i16) -> i16 {
    let v = ((1u32 << 26) / KYBER_Q as u32 + 1) as i32;
    let mut t = v * a as i32 + (1 << 25);
    t >>= 26;
    t *= KYBER_Q as i32;
    a - t as i16
}
