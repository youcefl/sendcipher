/* Created on 2025.10.19 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use rand::RngCore;
use crate::error::Error;

pub fn get_rand_bytes(length: usize) -> Result<Vec<u8>, Error> {
    // /!\ Must be a CSPRNG
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; length];
    rng.fill_bytes(&mut buf);
    Ok(buf)
}
