/* Created 2025.10.14 */
/* Copyright Youcef Lemsafer, all rights reserved */

use crate::chunking::*;
use crate::crypto::crypto;
use crate::crypto::{Argon2IdKeyProducer, CypherContext};
#[cfg(feature = "wasm")]
use crate::crypto::{Argon2idParams, BlobHeader, ChecksumAlgorithm, CypherKey};
use crate::stream_encryptor::*;
#[cfg(feature = "wasm")]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Cursor;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use web_sys::js_sys;

#[cfg(feature = "wasm")]
#[derive(Serialize, Deserialize)]
/// Intentionally no wasm_bindgen on this, the JS code has no business
/// accessing it!
pub struct WasmEncryptionContext {
    cypher_context: CypherContext,
    checksum_algorithm: ChecksumAlgorithm,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmFileEncryptor {
    /// Underlying encryptor
    encryptor: StreamEncryptor<RandomChunkGenerator>,
    /// Chunks to encrypt and upload indexed by their indexes.
    /// As the name implies, once a chunk is encrypted it is removed from this map
    /// to avoid unbounded memory consumption.
    unencrypted_chunks: BTreeMap<u32, Chunk>,
    /// Chunk spans dictionary, maps chunk index -> corresponding span in the original file.
    /// This is for progress tracking: each time a chunk is fully processed the user of this
    /// class can request the corresponding span to know by how much of the processing of the
    /// file has progressed.
    /// It is OK to have an entry for each chunk: even a 96GB file produces only about 8200 spans
    /// (for reasonnable chunk sizes i.e. 8MB-16MB range).
    spans: HashMap<u32, Span>,
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
            spans: HashMap::<u32, Span>::new(),
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

    /// Signals the end of data, to be called when the stream is exhausted
    /// in order to get the remaining chunks in need of encryption.
    #[wasm_bindgen]
    pub fn on_end_of_data(&mut self) -> Vec<u32> {
        let chunks = self.encryptor.on_end_of_data();
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

    /// Handles new chunks received from the underlying encryptor and returns the ones that are ready
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
            let span = Span::new(chnk.span().start(), chnk.span().size());
            self.unencrypted_chunks.insert(index, chnk);
            self.spans.insert(index, span);
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

    /// Registers an encrypted chunk i.e. associates to it its id on the server
    /// @param[in] chunk_index Index of the chunk
    /// @param[in] id String id received from the server for the chunk of given index
    /// @param[in] checksum The checksum of the chunk
    /// @param[in] span The span corresponding to this chunk in the untransformed original file,
    /// obtained by calling self.get_span(chunk_index).
    #[wasm_bindgen]
    pub fn register_encrypted_chunk(
        &mut self,
        chunk_index: u32,
        server_id: &str,
        checksum: &[u8],
        span: Span,
    ) {
        use crate::crypto::ChunkDescriptor;

        let chunk_desc = ChunkDescriptor::new(
            server_id.to_string(),
            checksum.to_vec(),
            span.start(),
            span.length(),
        );
        self.encryptor
            .register_encrypted_chunk_descriptor(chunk_index as u64, chunk_desc);
    }

    /// Finalizes processing of the stream
    /// Returns the encrypted manifest corresponding to the input file
    /// @pre all chunks have been encrypted and registered
    pub fn finalize(&mut self) -> Result<Vec<u8>, JsValue> {
        let mut encrypted_manifest = self
            .encryptor
            .finalize()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(std::mem::take(encrypted_manifest.data_mut()))
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
    /// Returns the context needed for encrypting the chunk of given index
    /// @param[in] chunk_index index of the chunk
    /// @return array of bytes representing the context to be passed to encrypt_chunk
    pub fn get_context(&self, chunk_index: u32) -> Result<Vec<u8>, JsValue> {
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
        let wasm_encryption_context = WasmEncryptionContext {
            cypher_context: encryption_context,
            checksum_algorithm: self.encryptor.chunk_hash_algorithm(),
        };

        serde_cbor::to_vec(&wasm_encryption_context).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the number of chunks registered
    #[wasm_bindgen]
    pub fn get_registered_chunks_count(&self) -> u32 {
        return self.encryptor.get_registered_chunks_count() as u32;
    }

    /// Returns the span corresponding to the chunk in the original file
    /// Reports an error on invalid chunk index
    /// @pre chunk_index is a valid  chunk index i.e. results from a call to process_data or finalize.
    #[wasm_bindgen]
    pub fn get_span(&self, chunk_index: u32) -> Result<Span, JsValue> {
        match self.spans.get(&chunk_index) {
            Some(span) => Ok(span.clone()),
            None => Err(JsValue::from_str("Invalid chunk index")),
        }
    }
}

#[cfg(feature = "wasm")]
#[derive(Clone)]
#[wasm_bindgen]
struct Span {
    /// Start offset
    start: u64,
    /// Length
    length: u64,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl Span {
    #[wasm_bindgen(constructor)]
    pub fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    #[wasm_bindgen(getter)]
    pub fn start(&self) -> u64 {
        self.start
    }

    #[wasm_bindgen(getter)]
    pub fn length(&self) -> u64 {
        self.length
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Encrypts the given chunk data in the given context
/// @param[in] context context obtained by calling WasmFileEncryptor::get_context()
/// @param[in] chunk_index the index of the chunk
/// @param[in] chunk_data the data constituting the chunk
/// @return encryption result containing the encrypted blob and its checksum
pub fn encrypt_chunk(
    context: &[u8],
    chunk_data: &[u8],
    span: Span,
) -> Result<EncryptionResult, JsValue> {
    let wasm_encryption_context: WasmEncryptionContext =
        serde_cbor::from_slice(context).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (mut blob, checksum) = StreamEncryptor::<RandomChunkGenerator>::do_encrypt_chunk(
        &wasm_encryption_context.cypher_context,
        chunk_data,
        wasm_encryption_context.checksum_algorithm
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(EncryptionResult {
        blob: std::mem::take(blob.data_mut()),
        checksum,
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct EncryptionResult {
    /// The encrypted blob
    blob: Vec<u8>,
    /// The checksum of the encrypted blob
    checksum: Vec<u8>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl EncryptionResult {
    /// Returns the encrypted blob
    /// Note: this consumes the blob, so only the first call will get it!
    #[wasm_bindgen]
    pub fn take_blob(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.blob)
    }
    #[wasm_bindgen]
    /// The checksum of the encrypted blob
    /// Note: this consumes the checksum, so only the first call will get it!
    pub fn take_checksum(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.checksum)
    }
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
