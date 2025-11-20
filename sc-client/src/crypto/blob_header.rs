/*
* Created on 2025.09.29
* Author: Youcef Lemsafer
* Copyright Youcef Lemsafer, all rights reserved.
*/

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};

mod constants {
    pub const CURRENT_BLOB_HEADER_VERSION: u32 = 0;
}

#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
/// FILE FORMAT PREFIX LAYOUT.
/// THIS MUST NEVER CHANGE
/// The prefix is part of the on-disk binary format and is used for
/// streaming / incremental parsing. If you modify the fields, their
/// types, ordering, or size, all previously written files will
/// become unreadable.
///
/// If format updates are needed, bump `version` instead and evolve
/// the *rest* of the header format conditionally.
pub struct HeaderPrefix {
    pub magic: [u8; 4],
    pub version: u32,
    pub remaining_header_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobHeader {
    pub prefix: HeaderPrefix,
    pub kdf_algorithm: KdfAlgorithm,
    pub kdf_param_length: u32,
    pub cipher_algorithm: CipherAlgorithm,
    pub cipher_param_length: u32,
    pub kdf_raw_params: Vec<u8>,
    pub cipher_raw_params: Vec<u8>,
    pub authentication_data_length: u16,
    pub authentication_data: Vec<u8>,
    pub cipher_length: u64,
}

#[repr(u32)]
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq)]
pub enum CipherAlgorithm {
    Invalid = 0,
    Aes256Gcm = 1,
}

impl CipherAlgorithm {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Invalid),
            1 => Some(Self::Aes256Gcm),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq)]
pub enum KdfAlgorithm {
    Invalid = 0,
    Argon2id = 1,
    #[cfg(test)]
    // Tests only, do not use in production
    Test = u32::MAX,
}

impl KdfAlgorithm {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Invalid),
            1 => Some(Self::Argon2id),
            #[cfg(test)]
            u32::MAX => Some(Self::Test),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Argon2idParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Aes256GcmParams {
    pub nonce: Vec<u8>,
}

#[repr(u8)]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum FileType {
    RegularFile = 1,
    Chunk = 2,
    Manifest = 3,
}

#[repr(u8)]
#[derive(Serialize, Deserialize)]
pub enum CompressionType {
    NopCompression = 1, // identity
    Zstd,
    Lzma2,
    Bz2,
    Zlib,
}

#[derive(Serialize, Deserialize)]
pub struct CompressionInfo {
    pub version: u16,
    pub compression_type: CompressionType,
    pub compression_level: u16,
    pub raw_compression_parameters: Vec<u8>,
}

impl CompressionInfo {
    const CURRENT_VERSION: u16 = 1;

    pub fn new(compression_type: CompressionType, compression_level: u16) -> Self {
        CompressionInfo {
            version: CompressionInfo::CURRENT_VERSION,
            compression_type: compression_type,
            compression_level: compression_level,
            raw_compression_parameters: vec![],
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub version: u16,
    pub file_type: FileType,
    pub file_name: String,
    pub file_size: u64,
    pub padding_size: u32,
    pub compression_info: CompressionInfo,
}

impl Metadata {
    const CURRENT_VERSION: u16 = 1;

    pub fn new(file_type: FileType, file_name: &str, file_size: u64, padding_size: u32) -> Self {
        Metadata {
            version: Metadata::CURRENT_VERSION,
            file_type: file_type,
            file_name: file_name.to_string(),
            file_size: file_size,
            padding_size: padding_size,
            compression_info: CompressionInfo::new(CompressionType::NopCompression, 0),
        }
    }
}

impl HeaderPrefix {
    const HEADER_PREFIX_LENGTH: usize = size_of::<HeaderPrefix>();
    const MAGIC: [u8; 4] = *b"SDCR";

    pub fn new() -> Self {
        HeaderPrefix {
            magic: Self::MAGIC,
            version: constants::CURRENT_BLOB_HEADER_VERSION,
            remaining_header_bytes: 0,
        }
    }

    pub fn length() -> usize {
        HeaderPrefix::HEADER_PREFIX_LENGTH
    }

    pub fn write_all(&self, cursor: &mut Cursor<&mut [u8]>) -> Result<(), crate::error::Error> {
        cursor.write_all(&self.magic)?;
        cursor.write_all(&self.version.to_le_bytes())?;
        cursor.write_all(&self.remaining_header_bytes.to_le_bytes())?;
        Ok(())
    }

    pub fn parse(buffer: &[u8]) -> Result<(Option<HeaderPrefix>, usize), crate::error::Error> {
        log::debug!("About to parse buffer in HeaderPrefix");
        if buffer.len() < Self::length() {
            return Ok((None, 0));
        }
        let mut prefix = Self::new();
        let mut cursor = Cursor::new(buffer);
        cursor.read_exact(&mut prefix.magic)?;
        if prefix.magic != Self::MAGIC {
            return Err(crate::error::Error::DeserializationError(
                format!(
                    "Unexpected magic '{:?}' while parsing blob header",
                    prefix.magic
                )
                .to_string(),
            ));
        }
        prefix.version = cursor.read_u32::<LittleEndian>()?;
        prefix.remaining_header_bytes = cursor.read_u32::<LittleEndian>()?;
        Ok((Some(prefix), cursor.position() as usize))
    }
}

impl BlobHeader {
    pub fn serialized_size(&self) -> usize {
        HeaderPrefix::length()
            + size_of_val(&self.kdf_algorithm)
            + size_of_val(&self.kdf_param_length)
            + size_of_val(&self.cipher_algorithm)
            + size_of_val(&self.cipher_param_length)
            + self.kdf_raw_params.len()
            + self.cipher_raw_params.len()
            + size_of_val(&self.authentication_data_length)
            + self.authentication_data.len()
            + size_of_val(&self.cipher_length)
    }

    pub fn get_cipher_length_pos(&self) -> usize {
        self.serialized_size() - size_of_val(&self.cipher_length)
    }

    pub fn get_cipher_length_length(&self) -> usize {
        size_of_val(&self.cipher_length)
    }

    pub fn write_to_slice(&self, buffer: &mut [u8]) -> Result<(), crate::error::Error> {
        let mut copied_prefix = self.prefix.clone();
        let mut cursor = Cursor::new(&mut buffer[..]);
        copied_prefix.write_all(&mut cursor)?;
        let end_of_prefix_pos = cursor.position() as u32;
        cursor.write_all(&self.kdf_algorithm.as_u32().to_le_bytes())?;
        cursor.write_all(&self.kdf_param_length.to_le_bytes())?;
        cursor.write_all(&self.cipher_algorithm.as_u32().to_le_bytes())?;
        cursor.write_all(&self.cipher_param_length.to_le_bytes())?;
        cursor.write_all(&self.kdf_raw_params)?;
        cursor.write_all(&self.cipher_raw_params)?;
        cursor.write_all(&self.authentication_data_length.to_le_bytes())?;
        cursor.write_all(&self.authentication_data)?;
        cursor.write_all(&self.cipher_length.to_le_bytes())?;
        let end_of_header_pos = cursor.position() as u32;
        copied_prefix.remaining_header_bytes = end_of_header_pos - end_of_prefix_pos;
        let mut cursor2 = Cursor::new(&mut buffer[..]);
        copied_prefix.write_all(&mut cursor2)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buffer = Vec::with_capacity(self.serialized_size());
        self.write_to_slice(&mut buffer);
        Ok(buffer)
    }

    pub fn new() -> BlobHeader {
        let mut inst = BlobHeader {
            prefix: HeaderPrefix::new(),
            kdf_algorithm: KdfAlgorithm::Invalid,
            kdf_param_length: 0,
            cipher_algorithm: CipherAlgorithm::Invalid,
            cipher_param_length: 0,
            kdf_raw_params: vec![0u8; 0],
            cipher_raw_params: vec![0u8; 0],
            authentication_data_length: 0,
            authentication_data: vec![0u8; 0],
            cipher_length: 0,
        };
        inst
    }

    pub fn parse(buffer: &[u8]) -> Result<(Self, u64), crate::error::Error> {
        let mut file_header = BlobHeader::new();
        // Read prefix (magic, version, remaining_bytes) and all the following fields
        let (prefix, header_prefix_length) = HeaderPrefix::parse(buffer)?;
        if prefix.is_none()
            || (header_prefix_length + prefix.as_ref().unwrap().remaining_header_bytes as usize
                > buffer.len())
        {
            // Not enough bytes
            return Err(crate::error::Error::BlobParsingError(
                "Cannot read blob header, not enough data".to_string(),
            ));
        }
        file_header.prefix = prefix.unwrap();
        let mut cursor = Cursor::new(&buffer[header_prefix_length..]);

        file_header.kdf_algorithm = KdfAlgorithm::from_u32(cursor.read_u32::<LittleEndian>()?)
            .expect("Invalid KDF algorithm id");
        file_header.kdf_param_length = cursor.read_u32::<LittleEndian>()?;
        file_header.cipher_algorithm =
            CipherAlgorithm::from_u32(cursor.read_u32::<LittleEndian>()?)
                .expect("Invalid cipher algorithm id");
        file_header.cipher_param_length = cursor.read_u32::<LittleEndian>()?;
        log::debug!(
            "Cipher parameters length: {}",
            file_header.cipher_param_length
        );
        file_header.kdf_raw_params = vec![0u8; file_header.kdf_param_length as usize];
        cursor.read_exact(&mut file_header.kdf_raw_params)?;
        file_header.cipher_raw_params = vec![0u8; file_header.cipher_param_length as usize];
        cursor.read_exact(&mut file_header.cipher_raw_params)?;
        file_header.authentication_data_length = cursor.read_u16::<LittleEndian>()?;
        file_header.authentication_data =
            vec![0u8; file_header.authentication_data_length as usize];
        cursor.read_exact(&mut file_header.authentication_data)?;
        file_header.cipher_length = cursor.read_u64::<LittleEndian>()?;

        if file_header.prefix.remaining_header_bytes != cursor.position() as u32 {
            log::debug!(
                "** EPIC FAIL: {:?} != {:?}",
                file_header.prefix.remaining_header_bytes,
                cursor.position()
            );
            return Err(crate::error::Error::BlobParsingError(
                "Corrupt blob encountered, unexpected header length".to_string(),
            ));
        }

        Ok((file_header, header_prefix_length as u64 + cursor.position()))
    }

    pub fn change_salt(&mut self, new_salt: Vec<u8>) -> Result<(), crate::error::Error> {
        match self.kdf_algorithm {
            KdfAlgorithm::Argon2id => {
                let (mut params, _) = Argon2idParams::from_bytes(&self.kdf_raw_params)?;
                params.salt = new_salt;
                self.kdf_raw_params = Argon2idParams::to_bytes(&params)?;
                self.kdf_param_length = self.kdf_raw_params.len() as u32;
            }
            KdfAlgorithm::Invalid => {
                return Err(crate::error::Error::InvalidAlgorithm(
                    "Invalid KDF algorithm".to_string(),
                ));
            }
            #[cfg(test)]
            KdfAlgorithm::Test => {
                self.kdf_param_length = new_salt.len() as u32;
                self.kdf_raw_params = new_salt;
            }
        }
        Ok(())
    }
}

impl Argon2idParams {
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        bincode::serialize(self).map_err(|e| crate::error::Error::BincodeError(e.to_string()))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, u64), crate::error::Error> {
        log::debug!(
            "Reading Argon2idParams from bytes, buffer size: {}",
            bytes.len()
        );
        let mut cursor = Cursor::new(bytes);
        Ok((
            bincode::deserialize_from(&mut cursor)
                .map_err(|e| crate::error::Error::BincodeError(e.to_string()))?,
            cursor.position(),
        ))
    }
}

impl Aes256GcmParams {
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        bincode::serialize(self).map_err(|e| crate::error::Error::BincodeError(e.to_string()))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        log::debug!(
            "Reading Aes256GcmParams from buffer of size {}",
            bytes.len()
        );
        bincode::deserialize(bytes).map_err(|e| crate::error::Error::BincodeError(e.to_string()))
    }
}

impl Metadata {
    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        bincode::serialize(self).map_err(|e| crate::error::Error::BincodeError(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        bincode::deserialize(bytes).map_err(|e| crate::error::Error::BincodeError(e.to_string()))
    }

    pub fn from_bytes_ex(bytes: &[u8]) -> Result<(Self, usize), crate::error::Error> {
        let mut cursor = Cursor::new(bytes);
        let metadata: Metadata = bincode::deserialize_from(&mut cursor)
            .map_err(|e| crate::error::Error::BincodeError(e.to_string()))?;
        let metadata_size = cursor.position() as usize;
        Ok((metadata, metadata_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = 4;
        assert_eq!(result, 4);
    }
}
