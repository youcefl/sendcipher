/* Created 2025.10.14 */
/* Copyright Youcef Lemsafer, all rights reserved */

use crate::chunking::*;
use crate::crypto::crypto;
use crate::crypto::{Argon2IdKeyProducer, CypherContext};
#[cfg(feature = "wasm")]
use crate::crypto::{Argon2idParams, BlobHeader, CypherKey};
use crate::stream_encryptor::*;
use std::collections::BTreeMap;
use std::io::Cursor;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use web_sys::js_sys;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmFileEncryptor {
    /// Underlying encryptor
    encryptor: StreamEncryptor<RandomChunkGenerator>,
    /// Chunks to encrypt and upload indexed by their indexes
    unencrypted_chunks: BTreeMap<u32, Chunk>,
    /// Index of the last chunk received from the underlying encryptor
    /// is None until we get a chunk
    last_chunk_index: Option<u32>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmFileEncryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(
        file_name: &str,
        password: &str,
        chunking_threshold: u32,
        min_chunk_size: u32,
        max_chunk_size: u32,
    ) -> Result<WasmFileEncryptor, JsError> {
        Ok(WasmFileEncryptor {
            encryptor: StreamEncryptor::<RandomChunkGenerator>::with_rand_chunks(
                file_name,
                password,
                chunking_threshold as u64,
                min_chunk_size as u64,
                max_chunk_size as u64,
            )?,
            unencrypted_chunks: BTreeMap::<u32, Chunk>::new(),
            last_chunk_index: None,
        })
    }

    /// Processes given data.
    /// Returns list of ids of chunks to be encrypted
    /// This is the main processing loop to be called repetitively until end of stream.
    #[wasm_bindgen]
    pub fn process_data(&mut self, data: &[u8]) -> Vec<u32> {
        let chunks = self.encryptor.process_data(data);
        self.handle_new_chunks(chunks)
    }

    /// Finalizes the encryption, to be called when the stream is exhausted
    /// in order to get the remaining chunks in need of encryption.
    #[wasm_bindgen]
    pub fn finalize(&mut self) -> Vec<u32> {
        let chunks = self.encryptor.finalize();
        self.handle_new_chunks(chunks)
    }

    /// Returns the data in the chunk of given index, raises an error if data is not found.
    /// The data is not found if either the index is invalid or it corresponds to a chunk
    /// that has been registered has encrypted and thus was removed from the unencrypted
    /// chunks table.
    #[wasm_bindgen]
    pub fn get_chunk_data(&self, chunk_index: u32) -> Result<js_sys::Uint8Array, JsValue> {
        let kv = self.unencrypted_chunks.get_key_value(&chunk_index);
        match kv {
            Some((_index, chunk)) => Ok(js_sys::Uint8Array::from(&chunk.data()[..])),
            None => Err(JsValue::from_str(&format!(
                "Data requested for chunk index {} not found",
                chunk_index
            ))),
        }
    }

    /// Deletes given chunk
    /// To be called from JS after a chunk has been encrypted
    #[wasm_bindgen]
    pub fn delete_chunk(&mut self, chunk_index: u32) {
        self.unencrypted_chunks.remove(&chunk_index);
    }

    /// Returns the index of the last chunk received from the underlying encryptor
    /// Raises an error if no chunk have been received
    /// @pre at least one chunk has been created
    #[wasm_bindgen]
    pub fn get_last_chunk_index(&self) -> Result<u32, JsValue> {
        let chunks_count = self.encryptor.get_chunks_count();
        if chunks_count > 0 {
            Ok((chunks_count - 1) as u32)
        } else {
            Err(JsValue::from_str(
                "Cannot return last chunk index when no chunk has been created",
            ))
        }
    }

    #[wasm_bindgen(getter)]
    pub fn chunks_count(&self) -> u32 {
        self.encryptor.get_chunks_count() as u32
    }

    /// Handles new chunks received from the underlying encrypter and returns the ones that are ready
    /// Upon reception the chunks are registered in self.unencrypted_chunks
    /// (which maps them by their indexes).
    /// @return indexes of the received chunks that are ready
    fn handle_new_chunks(&mut self, chunks: Vec<Chunk>) -> Vec<u32> {
        let mut result = Vec::<u32>::new();
        chunks.into_iter().for_each(|chnk| {
            let index = chnk.index() as u32;
            if chnk.is_ready() {
                result.push(index);
            }
            self.unencrypted_chunks.insert(index, chnk);
        });
        result
    }

    /// Encrypts a chunk given by id
    /// Encrypted chunks are removed from self.unencrypted_chunks
    ///
    #[wasm_bindgen]
    pub fn encrypt_chunk(&mut self, chunk_id: u32) -> Result<Vec<u8>, JsValue> {
        match self.unencrypted_chunks.remove(&chunk_id) {
            Some(chunk) => {
                let mut result = self
                    .encryptor
                    .encrypt_chunk(&chunk)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                Ok(std::mem::take(&mut result.data_mut()))
            }
            None => {
                // @todo: FIXME, this is not coherent with what is done in parallel_encrypt_chunks,
                // that function fails on unexpected id
                // Nop, ignore unknown index
                Ok(vec![])
            }
        }
    }

    /// Returns encrypted manifest to be served as map of file chunks
    pub fn get_encrypted_manifest(&self) -> Result<Vec<u8>, JsValue> {
        let mut encrypted_manifest = self
            .encryptor
            .get_encrypted_manifest()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(std::mem::take(encrypted_manifest.data_mut()))
    }

    /// Associates the id received from the server to a chunk after upload
    /// @param index Index of the chunk
    /// @param id String id received from the server for the chunk of given index
    #[wasm_bindgen]
    pub fn register_encrypted_chunk(&mut self, index: u32, server_id: &str) {
        self.encryptor
            .register_encrypted_chunk(index as u64, server_id);
    }

    #[wasm_bindgen]
    pub fn get_registered_chunk_id(&self, chunk_index: u32) -> Result<String, JsValue> {
        self.encryptor
            .get_registered_chunk_id(chunk_index as u64)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn encrypt_chunks(&mut self, chunk_ids: Vec<u32>) -> Result<EncryptedChunks, JsValue> {
        self.parallel_encrypt_chunks(chunk_ids, 1)
    }

    // Not exported to WASM.
    //
    // Browser WASM doesn’t support real multithreading unless you go down the
    // COOP/COEP rabbit hole — which is brittle and not worth the pain.
    // Parallelism is instead handled at the JS level using Web Workers.
    fn parallel_encrypt_chunks(
        &mut self,
        chunk_ids: Vec<u32>,
        max_threads: u32,
    ) -> Result<EncryptedChunks, JsValue> {
        let chunks: Vec<Chunk> = chunk_ids
            .iter()
            .map(|idx| {
                self.unencrypted_chunks.remove(idx).ok_or_else(|| {
                    JsValue::from_str(&format!(
                        "Invalid chunk id or missing chunk (index: {})",
                        idx
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let encrypted_chunks = self
            .encryptor
            .parallel_encrypt_chunks(&chunks, max_threads)
            .map_err(|e| JsValue::from_str(&e.to_string()))?
            .iter_mut()
            .map(|x| (x.0, std::mem::take(x.1.data_mut())))
            .collect();

        Ok(EncryptedChunks { encrypted_chunks })
    }

    #[wasm_bindgen]
    pub fn get_raw_encryption_context(&self, chunk_index: u32) -> Result<Vec<u8>, JsValue> {
        let chunk = self.unencrypted_chunks.get(&chunk_index).ok_or_else(|| {
            JsValue::from_str(&format!(
                "Requested encryption context missing (chunk {})",
                chunk_index
            ))
        })?;
        let encryption_context = self
            .encryptor
            .get_encryption_context(chunk)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_cbor::to_vec(&encryption_context).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the number of chunks registered
    #[wasm_bindgen]
    pub fn get_registered_chunks_count(&self) -> u32 {
        return self.encryptor.get_registered_chunks_count() as u32;
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn encrypt_chunk(raw_encryption_context: &[u8], chunk_data: &[u8]) -> Result<Vec<u8>, JsValue> {
    let encryption_context = serde_cbor::from_slice(raw_encryption_context)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut tmp =
        StreamEncryptor::<RandomChunkGenerator>::do_encrypt_chunk(&encryption_context, chunk_data)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(std::mem::take(tmp.data_mut()))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct EncryptedChunks {
    encrypted_chunks: Vec<(u64, Vec<u8>)>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl EncryptedChunks {
    #[wasm_bindgen]
    pub fn size(&self) -> usize {
        self.encrypted_chunks.len()
    }

    #[wasm_bindgen]
    pub fn index_at(&self, i: usize) -> Result<u32, JsValue> {
        let chunk = self
            .encrypted_chunks
            .get(i as usize)
            .ok_or_else(|| JsValue::from_str("Index out of bounds"))?;
        Ok(chunk.0 as u32)
    }

    #[wasm_bindgen]
    pub fn data_at(&self, i: usize) -> Result<js_sys::Uint8Array, JsValue> {
        let chunk = self
            .encrypted_chunks
            .get(i as usize)
            .ok_or_else(|| JsValue::from_str("Index out of bounds"))?;
        Ok(unsafe { js_sys::Uint8Array::view(&chunk.1) })
    }
}
