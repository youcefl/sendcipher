/* Created on 2025.10.18 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use crate::crypto::Argon2idParams;
use crate::crypto::random::*;
use argon2::Argon2;
use hmac::Mac;
use serde::Deserialize;
use serde::Serialize;

impl From<argon2::Error> for crate::error::Error {
    fn from(argon2_error: argon2::Error) -> Self {
        crate::error::Error::Any(argon2_error.to_string())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CypherKey {
    key: Vec<u8>,
}

impl CypherKey {
    pub fn with_key(key: Vec<u8>) -> Self {
        Self { key: key }
    }
    pub fn new() -> Result<Self, crate::error::Error> {
        Ok(Self {
            key: crate::crypto::random::get_rand_bytes(32)?,
        })
    }

    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn derive_key(&self, context: &[u8]) -> Vec<u8> {
        let output_len = self.key.len();
        hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.key)
            .expect("Expected a key valid for HMAC-SHA256")
            .chain_update(context)
            .finalize()
            .into_bytes()[..output_len]
            .to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            key: bytes.to_vec(),
        }
    }

    pub fn to_bytes(&self) -> &Vec<u8> {
        &self.key
    }
}

#[derive(Clone)]
pub struct Argon2IdKeyProducer {
    argon2id_params: Argon2idParams,
    key: Vec<u8>,
}

impl Argon2IdKeyProducer {
    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn get_parameters(&self) -> &Argon2idParams {
        &self.argon2id_params
    }

    pub(crate) fn with_default_parameters(password: &str) -> Self {
        Self::new(
            password,
            &Argon2idParams {
                m_cost: 50 * 1024, // 50MB memory
                t_cost: 3,         // iterations
                p_cost: 1,         // parallelism
                salt: get_rand_bytes(32).expect("Failed to get random bytes"),
            },
        )
    }

    pub fn new(password: &str, parameters: &Argon2idParams) -> Self {
        let key = Self::derive_key(password, &parameters).expect("").to_vec();
        let inst = Argon2IdKeyProducer {
            argon2id_params: parameters.clone(),
            key: key,
        };
        inst
    }

    fn derive_key(
        password: &str,
        params: &Argon2idParams,
    ) -> Result<[u8; 32], crate::error::Error> {
        let argon2_params = argon2::Params::new(
            params.m_cost, // memory
            params.t_cost, // iterations
            params.p_cost, // parallelism
            Some(params.salt.len()),
        )?;

        let argon2_inst = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        );

        let mut key = [0u8; 32];
        argon2_inst.hash_password_into(password.as_bytes(), &params.salt, &mut key)?;

        Ok(key)
    }
}
