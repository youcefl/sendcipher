/* Created on 2025.09.29 */
/* Copyright Youcef Lemsafer, all rights reserved. */

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};

mod constants {
    pub const CURRENT_BLOB_HEADER_VERSION: u32 = 1;
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
    pub envelopes: Vec<KeyEnvelope>,
    pub cipher_algorithm: CipherAlgorithm,
    pub cipher_param_length: u32,
    pub cipher_raw_params: Vec<u8>,
    pub authentication_data_length: u16,
    pub authentication_data: Vec<u8>,
    pub cipher_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEnvelope {
    pub version: u32,
    pub envelope_type: KeyEnvelopeType,
    pub envelope_data: Vec<u8>,
}

impl KeyEnvelope {
    const CURRENT_VERSION: u32 = 1;
    pub fn new(envelope_type: KeyEnvelopeType, envelope_data: Vec<u8>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            envelope_type,
            envelope_data,
        }
    }
    pub fn envelope_data(&self) -> &Vec<u8> {
        &self.envelope_data
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyEnvelopeType {
    Invalid = 0,
    Kdf = 1,
    Pgp = 2,
    Age = 3,
}

impl KeyEnvelopeType {
    pub fn from_bytes(data: &[u8]) -> Result<(KeyEnvelopeType, usize), crate::error::Error> {
        Ok((
            bincode::deserialize(data)
                .map_err(|e| crate::error::Error::DeserializationError(e.to_string()))?,
            1,
        ))
    }
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

#[repr(u16)]
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq)]
pub enum KdfAlgorithm {
    Invalid = 0,
    Argon2id = 1,
}

impl KdfAlgorithm {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Invalid),
            1 => Some(Self::Argon2id),
            _ => None,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        self.as_u16().to_le_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(KdfAlgorithm, usize), crate::error::Error> {
        if bytes.len() < 2 {
            return Err(crate::error::Error::DeserializationError(
                format!(
                    "Cannot read an u16 from a byte sequence of length {:?}",
                    bytes.len()
                )
                .to_string(),
            ));
        }
        match Self::from_u16(u16::from_le_bytes(bytes[0..2].try_into().unwrap())) {
            Some(kdf_algo) => Ok((kdf_algo, 2 as usize)),
            None => Err(crate::error::Error::DeserializationError(
                "Unexpected KDF algorithm tag value".to_string(),
            )),
        }
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
    pub fn serialized_size(&self) -> Result<usize, crate::error::Error> {
        Ok(HeaderPrefix::length()
            + self.size_of_envelopes()?
            + size_of_val(&self.cipher_algorithm)
            + size_of_val(&self.cipher_param_length)
            + self.cipher_raw_params.len()
            + size_of_val(&self.authentication_data_length)
            + self.authentication_data.len()
            + size_of_val(&self.cipher_length))
    }

    fn size_of_envelopes(&self) -> Result<usize, crate::error::Error> {
        Ok(bincode::serialized_size(&self.envelopes)
            .map_err(|e| crate::error::Error::SerializationError(e.to_string()))?
            as usize)
    }

    pub fn get_cipher_length_pos(&self) -> Result<usize, crate::error::Error> {
        Ok(self.serialized_size()? - size_of_val(&self.cipher_length))
    }

    pub fn get_cipher_length_length(&self) -> usize {
        size_of_val(&self.cipher_length)
    }

    pub fn write_to_slice(&self, buffer: &mut [u8]) -> Result<(), crate::error::Error> {
        let mut copied_prefix = self.prefix.clone();
        let mut cursor = Cursor::new(&mut buffer[..]);
        // We write a header prefix with a temporary remaining_bytes value until
        // the real one is known
        copied_prefix.write_all(&mut cursor)?;
        let end_of_prefix_pos = cursor.position() as u32;
        log::debug!("Writing key envelopes at offset {:?}", end_of_prefix_pos);
        bincode::serialize_into(&mut cursor, &self.envelopes)
            .map_err(|e| crate::error::Error::SerializationError(e.to_string()))?;
        cursor.write_all(&self.cipher_algorithm.as_u32().to_le_bytes())?;
        cursor.write_all(&self.cipher_param_length.to_le_bytes())?;
        cursor.write_all(&self.cipher_raw_params)?;
        cursor.write_all(&self.authentication_data_length.to_le_bytes())?;
        cursor.write_all(&self.authentication_data)?;
        cursor.write_all(&self.cipher_length.to_le_bytes())?;
        let end_of_header_pos = cursor.position() as u32;
        copied_prefix.remaining_header_bytes = end_of_header_pos - end_of_prefix_pos;
        // Overwrite header prefix with correct remaining_bytes value
        let mut cursor2 = Cursor::new(&mut buffer[..]);
        copied_prefix.write_all(&mut cursor2)?;
        log::debug!("Blob header written to buffer: {:02x?}", buffer);
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        let mut buffer = Vec::with_capacity(self.serialized_size()?);
        self.write_to_slice(&mut buffer)?;
        Ok(buffer)
    }

    pub fn new() -> BlobHeader {
        Self {
            prefix: HeaderPrefix::new(),
            envelopes: vec![],
            cipher_algorithm: CipherAlgorithm::Invalid,
            cipher_param_length: 0,
            cipher_raw_params: vec![0u8; 0],
            authentication_data_length: 0,
            authentication_data: vec![0u8; 0],
            cipher_length: 0,
        }
    }

    pub fn parse(buffer: &[u8]) -> Result<(Self, u64), crate::error::Error> {
        log::debug!(
            "Parsing buffer form {:02x?} [truncated to 256 bytes]",
            &buffer[..buffer.len().min(256)]
        );
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
        log::debug!("Reading key envelopes at offset {:?}", header_prefix_length);
        file_header.envelopes = bincode::deserialize_from(&mut cursor)
            .map_err(|e| crate::error::Error::DeserializationError(e.to_string()))?;
        log::debug!("Read {:?} key envelope", file_header.envelopes.len());
        log::debug!("Envelope: {:?}", file_header.envelopes.first());

        file_header.cipher_algorithm =
            CipherAlgorithm::from_u32(cursor.read_u32::<LittleEndian>()?)
                .expect("Invalid cipher algorithm id");
        file_header.cipher_param_length = cursor.read_u32::<LittleEndian>()?;
        log::debug!(
            "Cipher parameters length: {}",
            file_header.cipher_param_length
        );
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

