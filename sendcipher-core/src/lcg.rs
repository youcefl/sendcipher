/* Created on 2025.11.11 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

#[cfg(test)]
/// Predefined LCGs
pub(crate) const LCG_PARAMS: [(u64, u64); 11] = [
    (3, 257),
    (2, 10501),
    (3, 65537),
    (5, 19131877),
    (2, 86093443),
    (5, 258280327),
    (2, 2441406251),
    (3, 20100080249),
    (22, 206158430209),
    (2, 15258789062501),
    (3, 411782264189299),
];

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct Lcg {
    /// The primitive root modulo p
    a: u64,
    /// The prime number
    p: u64,
    /// The current value
    xn: u128,
}

#[cfg(test)]
impl Lcg {
    pub fn new(a: u64, p: u64) -> Self {
        Self {
            a: a,
            p: p,
            xn: 1u128,
        }
    }
    pub fn next(&mut self) -> u64 {
        self.xn = (self.xn * self.a as u128) % self.p as u128;
        self.xn as u64
    }
    pub fn scrambled_next(&mut self) -> u64 {
        Self::scramble(self.next())
    }
    fn scramble(x: u64) -> u64 {
        // Effet boule de neige (ou avalanche) chaque bit influence tous les autres
        // Snowball effect: each bit influences all others
        // Step 1: xor with golden ratio (integer part of phi * 2^64)
        let mut y = x ^ 0x9E3779B97F4A7C15;
        y = y.wrapping_mul(0x9E3779B97F4A7C15); // Step 2: multiply by golden ration
        y ^= y >> 32; // Step 3: mix bits high and low
        y
    }
}
