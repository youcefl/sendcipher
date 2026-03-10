/* Created on 2025.11.06 */
/* Copyright Youcef Lemsafer, all rights reserved. */

use serde::{Deserialize, Serialize};

use crate::crypto::{
    Aes256GcmParams, Argon2IdKeyProducer, Argon2idParams, KeyEnvelope, KeyEnvelopeType, blob_header::KdfAlgorithm, crypto, decrypt_in_place
};

pub trait KeyWrapper: Send {
    /// Envelope type identifier
    fn envelope_type(&self) -> KeyEnvelopeType;
    /// Serialization
    fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error>;
}

pub trait KdfBasedKeyWrapper: KeyWrapper {
    fn kdf_algorithm(&self) -> KdfAlgorithm;
    fn update_salt(&mut self, salt: Vec<u8>) -> Result<(), crate::error::Error>;
    fn unwrap_key(&self, password: &str) -> Result<Vec<u8>, crate::error::Error>;
    fn impl_to_bytes(&self) -> Result<Vec<u8>, crate::error::Error>;
    fn kdf_wrapper_to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        let mut buffer = Vec::<u8>::with_capacity(32);
        buffer.extend(self.kdf_algorithm().to_bytes());
        buffer.extend(self.impl_to_bytes()?);
        Ok(buffer)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AnyKeyWrapper {
    Argon2id(Argon2idKeyWrapper),
    Pgp(PgpKeyWrapper),
    Age(AgeKeyWrapper),
}

impl KeyWrapper for AnyKeyWrapper {
    fn envelope_type(&self) -> KeyEnvelopeType {
        match self {
            AnyKeyWrapper::Argon2id(_) => KeyEnvelopeType::Kdf,
            AnyKeyWrapper::Pgp(_) => KeyEnvelopeType::Pgp,
            AnyKeyWrapper::Age(_) => KeyEnvelopeType::Age,
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        match self {
            AnyKeyWrapper::Argon2id(kw) => kw.to_bytes(),
            AnyKeyWrapper::Pgp(kw) => kw.to_bytes(),
            AnyKeyWrapper::Age(kw) => kw.to_bytes(),
        }
    }
}

impl AnyKeyWrapper {
    pub fn as_kdf_based(&self) -> Option<&dyn KdfBasedKeyWrapper> {
        match self {
            AnyKeyWrapper::Argon2id(kw) => Some(kw),
            _ => None,
        }
    }
    pub fn expect_kdf_based(&self) -> Result<&dyn KdfBasedKeyWrapper, crate::error::Error> {
        let opt = self.as_kdf_based();
        match opt {
            Some(x) => Ok(x),
            None => Err(crate::error::Error::LogicError(
                "Expecting a KDF based key wrapper".to_string(),
            )),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Argon2idKeyWrapper {
    version: u8,
    parameters: Argon2idParams,
    wrapped_key: Vec<u8>,
    authentication_data: Vec<u8>,
}

impl KdfBasedKeyWrapper for Argon2idKeyWrapper {
    fn kdf_algorithm(&self) -> KdfAlgorithm {
        KdfAlgorithm::Argon2id
    }

    fn update_salt(&mut self, salt: Vec<u8>) -> Result<(), crate::error::Error> {
        use crate::crypto::random;
        self.parameters.salt = salt;
        // OPSEC: garble the wrapped key and the authentication data!
        self.wrapped_key = random::get_rand_bytes(self.wrapped_key.len())?;
        self.authentication_data = random::get_rand_bytes(self.authentication_data.len())?;
        Ok(())
    }

    fn unwrap_key(&self, password: &str) -> Result<Vec<u8>, crate::error::Error> {
        let mut dek = self.wrapped_key.clone();
        let kek = Argon2IdKeyProducer::new(password, &self.parameters).get_key().clone();
        decrypt_in_place(
            &mut dek,
            &<[u8;32]>::try_from(kek).map_err(|e| crate::error::Error::DecryptionError("".to_string()))?,
            &Aes256GcmParams {
                nonce: vec![0u8; 12],
            },
            &self.authentication_data,
        )?;
        Ok(dek)
    }
    
    fn impl_to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        Ok(bincode::serialize(self).map_err(|e| crate::error::Error::SerializationError(e.to_string()))?)
    }
}

impl KeyWrapper for Argon2idKeyWrapper {
    fn envelope_type(&self) -> KeyEnvelopeType {
        KeyEnvelopeType::Kdf
    }
    
    fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        self.kdf_wrapper_to_bytes()
    }
}

impl Argon2idKeyWrapper {
    const CURRENT_VERSION: u8 = 1;
    pub fn new(
        password: &str,
        parameters: &Argon2idParams,
        dek: &Vec<u8>,
    ) -> Result<Self, crate::error::Error> {
        let key_prod = Argon2IdKeyProducer::new(password, &parameters);
        Self::construct_inst(&key_prod, dek)
    }
    pub fn with_default_parameters(
        password: &str,
        dek: &Vec<u8>,
    ) -> Result<Self, crate::error::Error> {
        let key_prod = Argon2IdKeyProducer::with_default_parameters(password);
        Self::construct_inst(&key_prod, dek)
    }
    fn construct_inst(
        key_prod: &Argon2IdKeyProducer,
        dek: &Vec<u8>,
    ) -> Result<Self, crate::error::Error> {
        let mut inst = Self {
            version: Self::CURRENT_VERSION,
            parameters: key_prod.get_parameters().clone(),
            wrapped_key: dek.clone(),
            authentication_data: vec![],
        };
        let aes256gcm_params = Aes256GcmParams {
            nonce: vec![0u8; 12],
        };
        inst.authentication_data = crypto::encrypt_in_place(
            &mut inst.wrapped_key,
            &key_prod.get_key().clone().try_into().unwrap(),
            &aes256gcm_params,
        )?;
        Ok(inst)
    }
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::Error> {
        bincode::deserialize(data)
            .map_err(|e| crate::error::Error::DeserializationError(e.to_string()))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PgpKeyWrapper {}

impl KeyWrapper for PgpKeyWrapper {
    fn envelope_type(&self) -> KeyEnvelopeType {
        KeyEnvelopeType::Pgp
    }

    fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        todo!("Not implemented yet: serialization of PgpKeyWrapper")
    }
}
impl PgpKeyWrapper {
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::Error> {
        todo!()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AgeKeyWrapper {}

impl KeyWrapper for AgeKeyWrapper {
    fn envelope_type(&self) -> KeyEnvelopeType {
        KeyEnvelopeType::Age
    }

    fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        todo!("Not implemented yet: serialization of AgeKeyWrapper")
    }
}
impl AgeKeyWrapper {
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::Error> {
        todo!()
    }
}

pub(crate) fn from_key_envelope(key_envelope: &KeyEnvelope) -> Result<AnyKeyWrapper, crate::error::Error> {
    match key_envelope.envelope_type {
        KeyEnvelopeType::Invalid => Err(crate::error::Error::DeserializationError(
            "Invalid key envelop type tag".to_string(),
        )),
        KeyEnvelopeType::Kdf => {
            let data = key_envelope.envelope_data();
            let (kdf_algo, pos_after_kdf_algo) =
                KdfAlgorithm::from_bytes(data)?;
            match kdf_algo {
                KdfAlgorithm::Invalid => {
                    return Err(crate::error::Error::DeserializationError(
                        "Invalid KDF algorithm tag".to_string(),
                    ));
                }
                KdfAlgorithm::Argon2id => {
                    Ok(AnyKeyWrapper::Argon2id(Argon2idKeyWrapper::from_bytes(
                        &data[pos_after_kdf_algo..],
                    )?))
                }
            }
        }
        KeyEnvelopeType::Pgp => Ok(AnyKeyWrapper::Pgp(PgpKeyWrapper::from_bytes(
            &key_envelope.envelope_data(),
        )?)),
        KeyEnvelopeType::Age => Ok(AnyKeyWrapper::Age(AgeKeyWrapper::from_bytes(
            &key_envelope.envelope_data(),
        )?)),
    }
}
