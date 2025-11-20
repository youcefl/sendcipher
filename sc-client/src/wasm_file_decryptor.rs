/* Created on 2025.11.15 */
/* Copyright Youcef Lemsafer, all rights reserved. */

use crate::{crypto::blob::*, stream_decryptor::*};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmFileDecryptor {
    decryptor: StreamDecryptor,
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
    pub fn get_chunk_id(&self, chunk_index: u32) -> Result<String, JsValue> {
        self.decryptor
            .get_manifest()
            .chunks()
            .get(&(chunk_index as u64))
            .ok_or_else(|| JsValue::from_str("Invalid chunk index")).cloned()
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
    pub fn get_raw_decryption_context(&self) -> Result<Vec<u8>, JsValue> {
        let encryption_context = self.decryptor.get_decryption_context();

        serde_cbor::to_vec(&encryption_context).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// Performs stateless and threadsafe chunk decrypting
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn decrypt_chunk(
    raw_decryption_context: &[u8],
    chunk_index: u32,
    chunk_data: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut cypherchunk = CypherChunk::new(chunk_index as u64, Blob::new(chunk_data));
    let decryption_context = serde_cbor::from_slice(raw_decryption_context)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {:?}", e).to_string()))?;
    let mut decrypted_blob =
        StreamDecryptor::do_decrypt_chunk(&decryption_context, &mut cypherchunk)
            .map_err(|e| JsValue::from_str(&format!("Decryption failed: {:?}", e).to_string()))?;
    Ok(std::mem::take(decrypted_blob.get_text_mut()))
}
