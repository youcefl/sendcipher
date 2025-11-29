/* Created on 2025.11.15 */
/* Copyright Youcef Lemsafer, all rights reserved. */

#[cfg(feature = "wasm")]
use crate::crypto::{ChecksumAlgorithm, CypherContext};
use crate::{crypto::blob::*, stream_decryptor::*};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmFileDecryptor {
    decryptor: StreamDecryptor,
}

#[cfg(feature = "wasm")]
#[derive(Serialize, Deserialize)]
// Does not have wasm_bindgen, this is intentional
struct WasmDecryptionContext {
    decryption_context: CypherContext,
    checksum_algorithm: ChecksumAlgorithm,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmFileDecryptor {
    #[wasm_bindgen(constructor)]
    pub fn with_password(password: &str, manifest_bytes: Vec<u8>) -> Result<Self, JsError> {
        Ok(Self {
            decryptor: StreamDecryptor::with_password(password, &mut Blob::new(manifest_bytes))?,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn file_name(&self) -> String {
        self.decryptor.file_name().clone()
    }

    #[wasm_bindgen(getter)]
    pub fn file_size(&self) -> u64 {
        self.decryptor.file_size()
    }

    #[wasm_bindgen(getter)]
    pub fn chunks_count(&self) -> u32 {
        self.decryptor.get_manifest().chunks_count() as u32
    }

    #[wasm_bindgen]
    pub fn get_start(&self, chunk_index: u32) -> Result<u64, JsValue> {
        let chunks = self.decryptor.get_manifest().chunks();
        if chunk_index as usize >= chunks.len() {
            return Err(JsValue::from_str(
                &format!("Index {} is out of bounds", chunk_index).to_string(),
            ));
        }
        Ok(chunks[chunk_index as usize].offset())
    }

    #[wasm_bindgen]
    pub fn get_length(&self, chunk_index: u32) -> Result<u64, JsValue> {
        let chunks = self.decryptor.get_manifest().chunks();
        if chunk_index as usize >= chunks.len() {
            return Err(JsValue::from_str(
                &format!("Index {} is out of bounds", chunk_index).to_string(),
            ));
        }
        Ok(chunks[chunk_index as usize].length())
    }

    #[wasm_bindgen]
    pub fn get_chunk_id(&self, chunk_index: u32) -> Result<String, JsValue> {
        let chunks = self.decryptor.get_manifest().chunks();
        if chunk_index as usize >= chunks.len() {
            return Err(JsValue::from_str("Invalid chunk index"));
        }
        Ok(chunks[chunk_index as usize].id().clone())
    }

    #[wasm_bindgen]
    pub fn decrypt_chunk(&self, chunk_index: u32, data: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let mut cypherchunk = CypherChunk::new(chunk_index as u64, Blob::new(data));
        let mut decrypted_blob = self
            .decryptor
            .decrypt_chunk(&mut cypherchunk)
            .map_err(|e| JsValue::from_str(&format!("Decryption failed: {:?}", e).to_string()))?;
        Ok(std::mem::take(decrypted_blob.get_text_mut()))
    }

    #[wasm_bindgen]
    /// Returns the context to pass when calling decrypt_chunk(context: &[u8], ...)
    pub fn get_context(&self) -> Result<Vec<u8>, JsValue> {
        let context = WasmDecryptionContext {
            decryption_context: self.decryptor.get_decryption_context().clone(),
            checksum_algorithm: self.decryptor.get_manifest().checksum_algorithm(),
        };

        serde_cbor::to_vec(&context).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    /// Returns an array containing the checksums of the chunks constituting the file
    /// in order: [checksum of chunk 0 | checksum of chunk 1 | ... | checksum of last chunk]
    pub fn get_all_checksums(&self) -> Vec<u8> {
        let chunks = self.decryptor.get_manifest().chunks();
        let mut all_checksums = Vec::with_capacity(self.checksum_length() as usize * chunks.len());
        chunks
            .iter()
            .for_each(|chunk_desc| all_checksums.extend(chunk_desc.checksum()));
        all_checksums
    }

    #[wasm_bindgen(getter)]
    /// The length of a checksum, so the k-th chunk checksum is get_all_checksums()[k * checksum_length]
    pub fn checksum_length(&self) -> u32 {
        self.decryptor
            .get_manifest()
            .checksum_algorithm()
            .checksum_length()
    }
}

/// Performs stateless and threadsafe chunk decrypting
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn decrypt_chunk(
    context: &[u8],
    chunk_index: u32,
    chunk_data: Vec<u8>,
    checksum: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut cypherchunk = CypherChunk::new(chunk_index as u64, Blob::new(chunk_data));
    let wcontext: WasmDecryptionContext = serde_cbor::from_slice(context)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {:?}", e).to_string()))?;
    let decryption_result = StreamDecryptor::do_decrypt_chunk(
        &wcontext.decryption_context,
        &mut cypherchunk,
        wcontext.checksum_algorithm,
        &checksum,
    );
    if decryption_result.is_err() {
        if matches!(
            &decryption_result.as_ref().err().unwrap(),
            &crate::error::Error::ChunkChecksumError(_)
        ) {
            return Err(JsValue::from_str("ERR_BAD_CHECKSUM"));
        }
        return Err(JsValue::from_str(
            &decryption_result.err().unwrap().to_string(),
        ));
    }
    Ok(std::mem::take(
        decryption_result.ok().unwrap().get_text_mut(),
    ))
}
