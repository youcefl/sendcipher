/* Created on 2025-10-24 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use digest::typenum::Length;

use crate::crypto::random;
use crate::crypto::checksum::*;

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ChunkDescriptor {
    id: String,
    checksum: Vec<u8>,
    offset: u64,
    length: u64
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct Manifest {
    version: u32,
    file_name: String,
    file_size: u64,
    /// Manifest fingerprint
    mfp: Vec<u8>,
    /// Checksum algorithm to use for computing chunk checksums
    checksum_algorithm: ChecksumAlgorithm,
    /// Chunks information
    chunks: Vec<ChunkDescriptor>,
}

impl ChunkDescriptor {
    pub fn new(id: String, checksum: Vec<u8>, offset: u64, length: u64) -> Self {
        Self {id, checksum, offset, length}
    }
    pub fn id(&self) -> &String {
        &self.id
    }
    pub fn set_id(&mut self, chunk_id: String) {
        self.id = chunk_id;
    }
    pub fn checksum(&self) -> &Vec<u8> {
        &self.checksum
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn length(&self) -> u64 {
        self.length
    }
}

impl Manifest {
    const CURRENT_VERSION: u32 = 1;
    const MFP_LENGTH: usize = 48;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        return bincode::deserialize_from(bytes)
            .map_err(|e| crate::error::Error::DeserializationError(e.to_string()));
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        return bincode::serialize(self)
            .map_err(|e| crate::error::Error::SerializationError(e.to_string()));
    }

    pub fn new(file_name: String, file_size: u64) -> Result<Self, crate::error::Error> {
        Ok(Self {
            version: Manifest::CURRENT_VERSION,
            file_name: file_name,
            file_size: file_size,
            mfp: random::get_rand_bytes(Manifest::MFP_LENGTH)?,
            checksum_algorithm: ChecksumAlgorithm::Blake3,
            chunks: vec![],
        })
    }

    pub fn file_name(&self) -> &String {
        &self.file_name
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    pub fn set_file_size(&mut self, file_size: u64) -> &mut Self {
        self.file_size = file_size;
        self
    }

    pub fn chunks_count(&self) -> usize {
        self.chunks.len()
    }

    pub fn chunks(&self) -> &Vec<ChunkDescriptor> {
        &self.chunks
    }

    pub fn chunks_mut(&mut self) -> &mut Vec<ChunkDescriptor> {
        &mut self.chunks
    }

    pub fn mfp(&self) -> &Vec<u8> {
        &self.mfp
    }

    pub fn checksum_algorithm(&self) -> ChecksumAlgorithm {
        self.checksum_algorithm.clone()
    }
}
