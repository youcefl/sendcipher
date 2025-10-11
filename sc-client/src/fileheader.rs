/*
* Created on 2025.09.29
* Author: Youcef Lemsafer
* Copyright Youcef Lemsafer, all rights reserved.
*/

//use std::fs::File;
use std::io::{Cursor, Read, Write};
use serde::{Serialize, Deserialize};
use byteorder::{ReadBytesExt, LittleEndian};


#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherAlgorithm {
    Invalid = 0,
    Aes256Gcm = 1
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
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KdfAlgorithm {
    Invalid = 0,
    Argon2id = 1
}

impl KdfAlgorithm {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Invalid),
            1 => Some(Self::Argon2id),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}


pub struct FileHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub kdf_algorithm: KdfAlgorithm,
    pub kdf_param_length: u32,
    pub cipher_algorithm: CipherAlgorithm,
    pub cipher_param_length: u32,
    pub cipher_length: u64,
    pub kdf_raw_params: Vec<u8>,
    pub cipher_raw_params: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct Argon2idParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct Aes256GcmParams {
    pub nonce: Vec<u8>
}


#[repr(u8)]
#[derive(Serialize, Deserialize)]
pub enum FileType {
    RegularFile = 1,
    Manifest,
    Chunk
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub file_type: FileType,
    pub file_name: String,
    pub file_size: u64,
    pub padding_size: u32
}


impl FileHeader {

    pub fn serialized_size(&self) -> usize {
        size_of_val(&self.magic)
        + size_of_val(&self.version)
        + size_of_val(&self.kdf_algorithm)
        + size_of_val(&self.kdf_param_length)
        + size_of_val(&self.cipher_algorithm)
        + size_of_val(&self.cipher_param_length)
        + size_of_val(&self.cipher_length)
        + self.kdf_raw_params.len()
        + self.cipher_raw_params.len()
    }


    pub fn write_to_slice(&self, buffer: &mut [u8]) -> Result<(), std::io::Error> {
        let mut cursor = Cursor::new(buffer);
        cursor.write_all(&self.magic)?;
        cursor.write_all(&self.version.to_le_bytes())?;
        cursor.write_all(&self.kdf_algorithm.as_u32().to_le_bytes())?;
        cursor.write_all(&self.kdf_param_length.to_le_bytes())?;
        cursor.write_all(&self.cipher_algorithm.as_u32().to_le_bytes())?;
        cursor.write_all(&self.cipher_param_length.to_le_bytes())?;
        cursor.write_all(&self.cipher_length.to_le_bytes())?;
        cursor.write_all(&self.kdf_raw_params)?;
        cursor.write_all(&self.cipher_raw_params)?;
        Ok(())
    }

    pub fn new() -> FileHeader {
        let inst = FileHeader{
            magic: [0u8;4],
            version: 0,
            kdf_algorithm: KdfAlgorithm::Invalid,
            kdf_param_length: 0,
            cipher_algorithm: CipherAlgorithm::Invalid,
            cipher_param_length: 0,
            cipher_length: 0,
            kdf_raw_params: vec![0u8; 0],
            cipher_raw_params: vec![0u8; 0]
        };
        inst
    }

    pub fn parse(buffer: &[u8]) -> Result<(Self, &[u8]), Box<dyn std::error::Error>> {
        let mut cursor = Cursor::new(buffer);
        let mut file_header = FileHeader::new();
        // Read magic and all following fields
        cursor.read_exact(&mut file_header.magic)?;
        file_header.version = cursor.read_u32::<LittleEndian>()?;
        file_header.kdf_algorithm = KdfAlgorithm::from_u32(cursor.read_u32::<LittleEndian>()?)
                                       .expect("Invalid KDF algorithm id");
        file_header.kdf_param_length = cursor.read_u32::<LittleEndian>()?;
        file_header.cipher_algorithm = CipherAlgorithm::from_u32(cursor.read_u32::<LittleEndian>()?)
                                        .expect("Invalid cipher algorithm id");
        file_header.cipher_param_length = cursor.read_u32::<LittleEndian>()?;
        file_header.cipher_length = cursor.read_u64::<LittleEndian>()?;
        file_header.kdf_raw_params = vec![0u8; file_header.kdf_param_length as usize];
        cursor.read_exact(&mut file_header.kdf_raw_params)?;
        file_header.cipher_raw_params = vec![0u8; file_header.cipher_param_length as usize];
        cursor.read_exact(&mut file_header.cipher_raw_params)?;

        let remaining_data = &buffer[cursor.position() as usize..];

        Ok((file_header, remaining_data))
    }

}

impl Argon2idParams {
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error>  {
        bincode::serialize(self)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl Aes256GcmParams {
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error>  {
        bincode::serialize(self)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl Metadata {
    pub fn version(&self) -> u16 {
        1u16
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    pub fn from_bytes_ex(bytes: &[u8]) -> Result<(Self, usize), bincode::Error> {
        let mut cursor = Cursor::new(bytes);
        let metadata: Metadata = bincode::deserialize_from(&mut cursor)?;
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
