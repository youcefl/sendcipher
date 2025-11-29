/* Created on 2025.11.29 */
/* Copyright Youcef Lemsafer, all rights reserved */

use blake3;
use digest::Digest;

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
