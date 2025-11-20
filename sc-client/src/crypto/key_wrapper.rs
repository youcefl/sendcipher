/* Created on 2025.11.06 */
/* Copyright Youcef Lemsafer, all rights reserved. */

use crate::crypto::{Argon2IdKeyProducer, Argon2idParams, blob_header::KdfAlgorithm};

pub trait KeyWrapper {
    /// Wraps a key: DEK -> enc(DEK)
    fn wrap_key(&self, key: Vec<u8>) -> Vec<u8>;
    /// Unwraps key: enc(DEK) -> DEK
    fn unwrap_key(&self, encrypted_key: Vec<u8>) -> Vec<u8>;
}

pub trait KdfBasedKeyWrapper: KeyWrapper {
    fn kdf_algorithm(&self) -> KdfAlgorithm;
    fn get_raw_parameters(&self) -> Result<Vec<u8>, crate::error::Error>;
    fn derive_key(&self) -> &Vec<u8>;
}

pub enum AnyKeyWrapper {
    Kdf(Box<dyn KdfBasedKeyWrapper>),
}

impl KeyWrapper for AnyKeyWrapper {
    fn wrap_key(&self, dek: Vec<u8>) -> Vec<u8> {
        match self {
            Self::Kdf(wrapper) => wrapper.wrap_key(dek),
        }
    }
    fn unwrap_key(&self, wrapped: Vec<u8>) -> Vec<u8> {
        match self {
            Self::Kdf(wrapper) => wrapper.unwrap_key(wrapped),
        }
    }
}

pub struct Argon2idKeyWrapper {
    parameters: Argon2idParams,
    key: Vec<u8>,
}

impl KdfBasedKeyWrapper for Argon2idKeyWrapper {
    fn kdf_algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::Argon2id
    }
    fn get_raw_parameters(&self) -> Result<Vec<u8>, crate::error::Error> {
        Ok(self.parameters.to_bytes()?)
    }
    fn derive_key(&self) -> &Vec<u8> {
        &self.key
    }
}

impl KeyWrapper for Argon2idKeyWrapper {
    fn wrap_key(&self, _key: Vec<u8>) -> Vec<u8> {
        todo!("Use self.derive_key() to encrypt key, return encrypted key")
    }

    fn unwrap_key(&self, _encrypted_key: Vec<u8>) -> Vec<u8> {
        todo!("Use self.derive_key() to decrypt key, return decrypted key")
    }
}
impl Argon2idKeyWrapper {
    pub fn new(password: &str, parameters: Argon2idParams) -> Self {
        Self {
            key: Argon2IdKeyProducer::new(password, &parameters)
                .get_key()
                .clone(),
            parameters: parameters.clone(),
        }
    }
    pub fn with_default_parameters(password: &str) -> Self {
        let prod = Argon2IdKeyProducer::with_default_parameters(password);
        Self {
            key: prod.get_key().clone(),
            parameters: prod.get_parameters().clone(),
        }
    }
}

#[cfg(test)]
pub(crate) struct TestKdfKeyWrapper {
    salt: Vec<u8>,
    key: Vec<u8>,
}

#[cfg(test)]
impl TestKdfKeyWrapper {
    pub fn new(password: &str) -> Self {
        let salt = crate::crypto::random::get_rand_bytes(16).unwrap();

        Self {
            key: Self::do_derive_key(password, &salt),
            salt: salt,
        }
    }
    pub fn with_salt(password: &str, salt: Vec<u8>) -> Self {
        Self {
            key: Self::do_derive_key(password, &salt),
            salt: salt,
        }
    }
    fn do_derive_key(password: &str, salt: &Vec<u8>) -> Vec<u8> {
        // Need something ultrafast compared to Argon2id,
        // sha256 of password and salt does the job.
        use sha2::Digest;

        // use crate::crypto::random::get_rand_bytes;
        let mut hasher = sha2::Sha256::new();
        hasher.update(password);
        hasher.update(&salt);
        let key: [u8; 32] = hasher.finalize().into();
        key.to_vec()
    }
}

#[cfg(test)]
impl KdfBasedKeyWrapper for TestKdfKeyWrapper {
    fn kdf_algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::Test
    }
    fn get_raw_parameters(&self) -> Result<Vec<u8>, crate::error::Error> {
        Ok(self.salt.clone())
    }
    fn derive_key(&self) -> &Vec<u8> {
        &self.key
    }
}

#[cfg(test)]
impl KeyWrapper for TestKdfKeyWrapper {
    fn wrap_key(&self, key: Vec<u8>) -> Vec<u8> {
        todo!("Use self.derive_key() to encrypt key, return encrypted key")
    }

    fn unwrap_key(&self, encrypted_key: Vec<u8>) -> Vec<u8> {
        todo!("Use self.derive_key() to decrypt key, return decrypted key")
    }
}
