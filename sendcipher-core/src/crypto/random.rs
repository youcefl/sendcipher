/* Created on 2025.10.19 */
/* Copyright Youcef Lemsafer, all rights reserved */

use rand::RngCore;
use crate::error::Error;

pub fn get_rand_bytes(length: usize) -> Result<Vec<u8>, Error> {
    // /!\ Must be a CSPRNG
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; length];
    rng.fill_bytes(&mut buf);
    Ok(buf)
}
