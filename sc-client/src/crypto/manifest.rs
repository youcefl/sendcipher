/* Created on 2025-10-24 */
/* Copyright Youcef Lemsafer, all rights reserved */

use std::collections::BTreeMap;

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct Manifest {
    version: u32,
    file_name: String,
    file_size: u64,
    chunks: BTreeMap<u64, String>,
}


impl Manifest {

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        return bincode::deserialize_from(bytes)
            .map_err(|e| crate::error::Error::DeserializationError(e.to_string()));
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::Error> {
        return bincode::serialize(self)
            .map_err(|e| crate::error::Error::SerializationError(e.to_string()));
    }

    pub fn new(file_name: String, file_size: u64) -> Self {
        Manifest {
            version: 1,
            file_name: file_name,
            file_size: file_size,
            chunks: BTreeMap::<u64, String>::new(),
        }
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

    pub fn chunks(&self) -> &BTreeMap<u64, String> {
        &self.chunks
    }

    pub fn chunks_mut(&mut self) -> &mut BTreeMap<u64, String> {
        &mut self.chunks
    }

}
