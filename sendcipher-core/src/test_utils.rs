/* Created on 2025.11.22 */
/* Copyright Youcef Lemsafer, all rights reserved */


use crate::crypto::{Argon2idParams, random};

   
/// Creates UNSECURE parameters for fast tests
pub fn create_argon2id_params_for_tests() -> Argon2idParams {
    Argon2idParams {
        m_cost: 512u32, // 50MB/100 i.e. hundred times less than value used in production
        t_cost: 1,
        p_cost: 1,
        salt: random::get_rand_bytes(32).expect("Generation of random bytes should succeed"),
    }
}

