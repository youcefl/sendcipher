/* Created on 2025-10-24 */
/* Copyright Youcef Lemsafer, all rights reserved */

use blake3;
use digest::Digest;
use std::collections::BTreeMap;

use crate::crypto::random;

#[repr(u16)]
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Default)]
pub enum ChecksumAlgorithm {
    #[default]
    Blake3 = 1,
    Sha256,
    Sha384,
    Sha512,
}

pub enum HashComputer {
    Blake3(blake3::Hasher),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl ChecksumAlgorithm {
    pub(crate) fn get_checksum_computer(&self) -> HashComputer {
        match self {
            ChecksumAlgorithm::Blake3 => HashComputer::Blake3(blake3::Hasher::new()),
            ChecksumAlgorithm::Sha256 => HashComputer::Sha256(sha2::Sha256::new()),
            ChecksumAlgorithm::Sha384 => HashComputer::Sha384(sha2::Sha384::new()),
            ChecksumAlgorithm::Sha512 => HashComputer::Sha512(sha2::Sha512::new()),
        }
    }
    pub(crate) fn checksum_length(&self) -> u32 {
        match self {
            ChecksumAlgorithm::Blake3 => blake3::OUT_LEN as u32,
            ChecksumAlgorithm::Sha256 => 32u32,
            ChecksumAlgorithm::Sha384 => 48u32,
            ChecksumAlgorithm::Sha512 => 64u32,
        }
    }
}

impl HashComputer {
    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            HashComputer::Blake3(hasher) => {
                hasher.update(data);
            }
            HashComputer::Sha256(hasher) => hasher.update(data),
            HashComputer::Sha384(hasher) => hasher.update(data),
            HashComputer::Sha512(hasher) => hasher.update(data),
        }
    }
    pub(crate) fn finalize(&mut self) -> Vec<u8> {
        match self {
            HashComputer::Blake3(hasher) => hasher.finalize().as_bytes().to_vec(),
            HashComputer::Sha256(hasher) => std::mem::take(hasher).finalize().to_vec(),
            HashComputer::Sha384(hasher) => std::mem::take(hasher).finalize().to_vec(),
            HashComputer::Sha512(hasher) => std::mem::take(hasher).finalize().to_vec(),
        }
    }
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
    /// Chunks dictionary, the key is the 0 based index of the chunk
    chunks: BTreeMap<u64, (String, Vec<u8>)>,
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
            chunks: BTreeMap::<u64, (String, Vec<u8>)>::new(),
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

    pub fn chunks(&self) -> &BTreeMap<u64, (String, Vec<u8>)> {
        &self.chunks
    }

    pub fn chunks_mut(&mut self) -> &mut BTreeMap<u64, (String, Vec<u8>)> {
        &mut self.chunks
    }

    pub fn mfp(&self) -> &Vec<u8> {
        &self.mfp
    }

    pub fn checksum_algorithm(&self) -> ChecksumAlgorithm {
        self.checksum_algorithm.clone()
    }
}
