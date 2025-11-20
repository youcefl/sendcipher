/*
* Created on 2025.09.29
* Copyright Youcef Lemsafer, all rights reserved.
*/

use crate::crypto::*;
use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadMutInPlace, KeyInit},
};
use anyhow::Result;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CypherContext {
    /// The name of the file being encrypted/decrypted
    file_name: String,
    /// Type of file being encrypted/decrypted
    file_type: FileType,
    /// The blob header.
    /// When encrypting it is written unciphered to the resulting blob.
    /// When decrypting it is read from the blob.
    blob_header: BlobHeader,
    /// The data encryption key
    cypher_key: CypherKey,
    /// AES-256GCM parameters
    aes256gcm_params: Aes256GcmParams,
}

impl CypherContext {
    /// Constructs an instance for encryption
    fn for_encryption(
        file_name: &str,
        blob_header: BlobHeader,
        cypher_key: CypherKey,
    ) -> Result<Self, crate::error::Error> {
        let inst = CypherContext {
            file_name: file_name.to_string(),
            file_type: FileType::RegularFile,
            cypher_key: cypher_key,
            blob_header,
            aes256gcm_params: Aes256GcmParams {
                nonce: random::get_rand_bytes(12)?,
            },
        };
        Ok(inst)
    }

    fn for_decryption(
        blob_header: BlobHeader,
        cypher_key: CypherKey,
    ) -> Result<Self, crate::error::Error> {
        let aes256gcm_params = Aes256GcmParams::from_bytes(&blob_header.cipher_raw_params)?;
        Ok(CypherContext {
            file_name: String::new(),
            file_type: FileType::Manifest,
            blob_header,
            cypher_key,
            aes256gcm_params: aes256gcm_params,
        })
    }

    pub fn file_name(&self) -> &String {
        &self.file_name
    }

    pub(crate) fn set_file_name(&mut self, file_name: &str) {
        self.file_name = file_name.to_string()
    }

    pub fn get_key(&mut self) -> &Vec<u8> {
        self.cypher_key.get_key()
    }

    pub fn setup_chunk_encryption(&mut self, chunk_index: u64) -> &mut Self {
        self.file_type = FileType::Chunk;
        let new_key = self.derive_chunk_key(chunk_index);
        let new_salt = &crate::crypto::random::get_rand_bytes(32)
            .unwrap()
            .try_into()
            .unwrap();
        let new_nonce = &crate::crypto::random::get_rand_bytes(12)
            .unwrap()
            .try_into()
            .unwrap();
        self.set_key(&new_key)
            .set_salt(new_salt)
            .set_nonce(new_nonce)
    }

    pub fn setup_chunk_decryption(&mut self, chunk_index: u64) -> &mut Self {
        self.file_type = FileType::Chunk;
        self.set_key(&self.derive_chunk_key(chunk_index));
        // Zeroize them to make it clear that they have to be read from
        // the chunk header!
        self.set_nonce(&[0u8; 12]);
        self.set_salt(&[0u8; 32]);
        self
    }

    pub fn setup_manifest_encryption(&mut self) -> &mut Self {
        self.file_type = FileType::Manifest;
        self
    }

    fn derive_chunk_key(&self, chunk_index: u64) -> [u8; 32] {
        let mut okm = [0u8; 32];
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"::chunk_key::"), self.cypher_key.get_key());
        hk.expand(&chunk_index.to_le_bytes(), &mut okm)
            .expect("HKDF expansion failed");
        okm
    }

    fn set_key(&mut self, new_key: &[u8; 32]) -> &mut Self {
        self.cypher_key = CypherKey::with_key(new_key.to_vec());
        self
    }

    fn set_salt(&mut self, new_salt: &[u8; 32]) -> &mut Self {
        BlobHeader::change_salt(&mut self.blob_header, new_salt.to_vec());
        self
    }

    fn set_nonce(&mut self, nonce: &[u8; 12]) -> &mut Self {
        self.aes256gcm_params.nonce = nonce.to_vec();
        self
    }
}

pub fn prepare_file_encryption(
    file_name: &str,
    key_wrapper: &key_wrapper::AnyKeyWrapper,
) -> Result<CypherContext, crate::error::Error> {
    let mut file_header = BlobHeader::new();
    // V0 does not support something other than KDF
    // In V1 we'll implement support of PGP and AGE
    let mut key = None;
    match key_wrapper {
        AnyKeyWrapper::Kdf(kdf_wrapper) => {
            file_header.kdf_algorithm = kdf_wrapper.kdf_algorithm();
            file_header.kdf_raw_params = kdf_wrapper.get_raw_parameters()?;
            file_header.kdf_param_length = file_header.kdf_raw_params.len() as u32;
            key = Some(kdf_wrapper.derive_key());
        }
        _ => {
            todo!("Support wrapping by other than KDF based wrappers")
        }
    }
    file_header.cipher_algorithm = CipherAlgorithm::Aes256Gcm;

    Ok(CypherContext::for_encryption(
        file_name,
        file_header,
        CypherKey::with_key(key.unwrap().clone()),
    )?)
}

fn derive_key_from_header(
    header: &BlobHeader,
    password: &str,
) -> Result<Vec<u8>, crate::error::Error> {
    log::debug!("Deriving key from header");
    log::debug!("  KDF algorithm: {:?}", header.kdf_algorithm);
    log::debug!("  KDF raw params: {:?}", header.kdf_raw_params);
    match header.kdf_algorithm {
        KdfAlgorithm::Argon2id => {
            let (params, _) = Argon2idParams::from_bytes(&header.kdf_raw_params)?;
            Ok(Argon2IdKeyProducer::new(password, &params)
                .get_key()
                .clone())
        }
        KdfAlgorithm::Invalid => Err(crate::error::Error::InvalidAlgorithm(
            "Invalid KDF algorithm".to_string(),
        )),
        #[cfg(test)]
        KdfAlgorithm::Test => {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(password);
            hasher.update(&header.kdf_raw_params);
            let key: [u8; 32] = hasher.finalize().into();
            Ok(key.to_vec())
        }
    }
}

pub fn setup_file_decryption(
    manifest_blob: &mut Blob,
    password: &str,
) -> Result<CypherContext, crate::error::Error> {
    log::debug!("Setting up file decryption");
    manifest_blob.parse_header()?;
    log::debug!("Header parsed");
    let blob_header = manifest_blob.get_header().clone().ok_or_else(|| {
        crate::error::Error::BlobParsingError("Error while parsing blob header".to_string())
    })?;
    let key = derive_key_from_header(&blob_header, password)?;
    log::debug!("Key derived from header: {:?}", key);
    log::debug!("About to create context");
    Ok(CypherContext::for_decryption(
        blob_header,
        CypherKey::with_key(key),
    )?)
}

fn get_padding_size(data_len: usize) -> usize {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Random padding, size 0-64KB (or 0-256KB for larger files)
    let max_padding = if data_len < 10 * 1024 * 1024 {
        65536
    } else {
        262144
    };
    rng.gen_range(0..=max_padding) as usize
}

fn append_random_padding(buffer: &mut Vec<u8>, padding_size: usize) {
    let old_len = buffer.len();
    buffer.resize(old_len + padding_size, 0u8);
    rand::thread_rng().fill_bytes(&mut buffer[old_len..]);
}

pub fn encrypt(
    data: &[u8],
    encryption_context: &CypherContext,
) -> Result<Blob, crate::error::Error> {
    let mut blob_header = encryption_context.blob_header.clone();
    blob_header.authentication_data = vec![0u8; 16]; // AES256-GCM tag length
    blob_header.authentication_data_length = blob_header.authentication_data.len() as u16;
    blob_header.cipher_raw_params = encryption_context.aes256gcm_params.to_bytes()?;
    blob_header.cipher_param_length = blob_header.cipher_raw_params.len() as u32;

    log::debug!(
        "Encrypting with:\n  KDF parameters: {:?}",
        blob_header.kdf_raw_params
    );
    log::debug!("  nonce: {:?}", &encryption_context.aes256gcm_params.nonce);
    log::debug!("  type of file: {:?}", encryption_context.file_type);

    let padding_size = get_padding_size(data.len());
    let meta_data = Metadata::new(
        encryption_context.file_type.clone(),
        &encryption_context.file_name,
        data.len() as u64,
        padding_size as u32,
    );
    let metadata_bytes = meta_data.to_bytes()?;
    let blob_header_len = blob_header.serialized_size();
    let mut blob =
        Vec::with_capacity(blob_header_len + metadata_bytes.len() + data.len() + padding_size);
    blob.resize(blob_header_len, 0u8);
    blob.extend((metadata_bytes.len() as u32).to_le_bytes());
    blob.extend(metadata_bytes);
    blob.extend(data);
    append_random_padding(&mut blob, padding_size);
    blob_header.cipher_length = (blob.len() - blob_header_len) as u64;

    let aes256gcm_params = &encryption_context.aes256gcm_params;
    let nonce = Nonce::from_slice(&aes256gcm_params.nonce);
    let key: [u8; 32] = encryption_context
        .cypher_key
        .get_key()
        .clone()
        .try_into()
        .unwrap();
    log::debug!("  key: {:?}", key);

    let mut encryptor_foreal = Aes256Gcm::new(&key.into());
    let auth_tag = encryptor_foreal
        .encrypt_in_place_detached(nonce, b"", &mut blob[blob_header_len..])
        .map_err(|e| crate::error::Error::EncryptionError(e.to_string()))?;
    assert!(blob_header.authentication_data_length as usize == auth_tag.len());
    assert!(blob_header.authentication_data.len() == auth_tag.len());

    log::debug!(
        "Encrypted bytes: {:02x?}",
        &blob[blob_header_len..blob_header_len + 32]
    );
    blob_header.authentication_data = auth_tag.to_vec();

    log::debug!(
        "Writing blob header with cipher_parameters_length = {}",
        blob_header.cipher_param_length
    );
    blob_header.write_to_slice(&mut blob[..blob_header_len]);

    Ok(Blob::new_parsed(blob, blob_header, blob_header_len as u64))
}

pub struct DecryptionResult {
    file_name: String,
    data: Vec<u8>,
}

impl DecryptionResult {
    pub fn new(file_name: String, data: Vec<u8>) -> Self {
        Self { file_name, data }
    }

    pub fn file_name(&self) -> String {
        self.file_name.clone()
    }

    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }
}

pub fn decrypt_blob(
    blob: &mut Blob,
    decryption_context: &CypherContext,
) -> Result<DecryptedBlob, crate::error::Error> {
    log::debug!("decrypt_blob called");
    if blob.get_header().is_none() {
        log::debug!("decrypt_blob: parsing header");
        blob.parse_header()?;
    }
    let blob_header = blob
        .get_header()
        .as_ref()
        .ok_or_else(|| {
            // @todo: may be a better message?
            crate::error::Error::BlobParsingError("Could not read header from blob".to_string())
        })?
        .clone();
    let cipher_params = Aes256GcmParams::from_bytes(&blob_header.cipher_raw_params)?;
    log::debug!("  decrypt_blob has blob header");
    //@todo: we need some checks here (magic, version, etc.)
    log::debug!("  nonce: {:?}", &cipher_params.nonce);
    log::debug!("  type of file: {:?}", decryption_context.file_type);

    // Key derivation, nonce, etc... leading to decryption.
    let key: [u8; 32] = decryption_context
        .cypher_key
        .get_key()
        .as_slice()
        .try_into()
        .map_err(|_| {
            crate::error::Error::DecryptionError("Key must be exactly 32 bytes long".to_string())
        })?;
    log::debug!("  key: {:?}", key);

    let mut cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&cipher_params.nonce);
    let after_header_pos = blob.get_position_after_header().unwrap();
    log::debug!("** After header position: {:?} **", after_header_pos);
    log::debug!("** Cipher length: {:?} **", blob_header.cipher_length);
    let encrypted_data = &mut blob.data_mut()[after_header_pos as usize..];
    log::debug!(
        "Encrypted bytes: {:02x?}",
        &encrypted_data[..128.min(encrypted_data.len())]
    );
    let auth_tag = Tag::from_exact_iter(blob_header.authentication_data.clone().into_iter());
    cipher
        .decrypt_in_place_detached(nonce, b"", encrypted_data, auth_tag.as_ref().unwrap())
        .map_err(|e| crate::error::Error::DecryptionError(e.to_string()))?;
    let decrypted_data = encrypted_data;
    // decrypted_data is expected to look like this:
    // metadata length (4 bytes unsigned LE)
    // metadata
    // data
    // padding
    log::debug!(
        "Decrypted bytes: {:02x?}",
        &decrypted_data[..128.min(decrypted_data.len())]
    );

    const METADATA_LENGTH_LENGTH: usize = size_of::<u32>();
    let metadata_length_bytes: [u8; METADATA_LENGTH_LENGTH] = decrypted_data
        [..METADATA_LENGTH_LENGTH]
        .try_into()
        .map_err(|_| {
            crate::error::Error::DecryptionError("Failed to read metadata, truncated".to_string())
        })?;
    let read_metadata_length = u32::from_le_bytes(metadata_length_bytes) as usize;
    log::debug!("About to read metadata");
    let (metadata, metadata_length) =
        Metadata::from_bytes_ex(&decrypted_data[METADATA_LENGTH_LENGTH..])?;
    log::debug!("Metadata length: {:?}", metadata_length);
    // Check that read bytes == expected metadata length
    if metadata_length as usize != read_metadata_length {
        return Err(crate::error::Error::InvalidInput(
            "Invalid/corrupt file (bad metadata)".to_string(),
        ));
    }
    // {metadata version}{metadata length}{metadata}{data}{padding}
    let file_data_offset = METADATA_LENGTH_LENGTH + metadata_length;
    let file_data =
        decrypted_data[file_data_offset..file_data_offset + metadata.file_size as usize].to_vec();
    Ok(DecryptedBlob::new(blob_header, file_data, metadata))
}

//
