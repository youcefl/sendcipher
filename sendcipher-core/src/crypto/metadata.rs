/* Created on 2025.11.28 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */
/// @file metadata.rs
/// Defines the metadata to be written encrypted in the blobs
use serde::{Deserialize, Serialize};
use std::io::Cursor;

#[repr(u8)]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum FileType {
    Manifest = 1,
    Chunk = 2,
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
    pub mfp: Option<Vec<u8>>,
    pub compression_info: CompressionInfo,
}

impl Metadata {
    const CURRENT_VERSION: u16 = 1;

    pub fn new(
        file_type: FileType,
        file_name: &str,
        file_size: u64,
        padding_size: u32,
        mfp: Option<Vec<u8>>,
    ) -> Self {
        Self {
            version: Metadata::CURRENT_VERSION,
            file_type,
            file_name: file_name.to_string(),
            file_size,
            padding_size,
            mfp,
            compression_info: CompressionInfo::new(CompressionType::NopCompression, 0),
        }
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
