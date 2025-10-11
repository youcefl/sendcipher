/*
* Created on 2025.09.29
* Copyright Youcef Lemsafer, all rights reserved.
*/

use std::io::Cursor;
use byteorder::{ReadBytesExt, LittleEndian};
use rand::RngCore;
use web_sys::window;
use anyhow::Result;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use wasm_bindgen::prelude::*;
use argon2::{
    Argon2
};
mod fileheader;
use fileheader::*;


#[wasm_bindgen]
pub fn encrypt_file(file_name: &str, data: &[u8], password: &str)
         -> Result<Vec<u8>, JsValue> {
    println!("Encrypting {} bytes", data.len());
    let mut file_header = FileHeader::new();
    file_header.magic = *b"SDCR";
    file_header.version = 1;
    file_header.kdf_algorithm = KdfAlgorithm::Argon2id;
    file_header.cipher_algorithm = CipherAlgorithm::Aes256Gcm;

    let encrypted_data = do_encrypt_file(file_name,
        data,
        password,
        &mut file_header)?;

    file_header.cipher_length = encrypted_data.len() as u64;

    let header_size = file_header.serialized_size();
    let mut result = Vec::with_capacity(header_size + encrypted_data.len());
    result.resize(header_size, 0u8);
    file_header.write_to_slice(& mut result[0..header_size])
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

fn get_rand_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
    let mut buf = vec![0u8; length];

    if let Some(win) = window() {
        let crypto = win.crypto().map_err(|_| JsValue::from_str("No crypto available"))?;
        crypto.get_random_values_with_u8_array(&mut buf)?;
    } else {
        return Err(JsValue::from_str("No window object available"));
    }

    Ok(buf)
}

fn derive_key(password: &str, params: &Argon2idParams) -> Result<[u8; 32]> {
    let argon2_params = argon2::Params::new(
        params.m_cost, // memory
        params.t_cost, // iterations
        params.p_cost, // parallelism
        Some(params.salt.len())
    ).map_err(|e| anyhow::anyhow!("Argon2 params error: {:?}", e))?;

    let argon2_inst = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut key = [0u8; 32];
    argon2_inst.hash_password_into(password.as_bytes(), &params.salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 hashing error: {:?}", e))?;

    Ok(key)
}

fn add_padding(data: &[u8]) -> (Vec<u8>, u32) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Random padding, size 0-64KB (or 0-256KB for larger files)
    let max_padding = if data.len() > 10*1024*1024 { 65536 } else { 262144 };
    let padding_size = rng.gen_range(0..=max_padding) as u32;
    let mut padded = data.to_vec();
    let mut padding = vec![0u8; padding_size as usize];

    rand::thread_rng().fill_bytes(&mut padding);
    padded.extend(padding);

    (padded, padding_size)
}

fn do_encrypt_file(file_name: &str, data: &[u8], password: &str, file_header: &mut FileHeader)
            -> Result<Vec<u8>, JsValue> {

    let argon2id_params = Argon2idParams {
        m_cost: 50 * 1024, // 19MB memory
        t_cost: 3, // iterations
        p_cost: 1, // parallelism
        salt: get_rand_bytes(32)?
    };
    file_header.kdf_raw_params = argon2id_params.to_bytes()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    file_header.kdf_param_length = file_header.kdf_raw_params.len() as u32;
    let key = derive_key(password, &argon2id_params)
                            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let aes256gcm_params = Aes256GcmParams {
        nonce: get_rand_bytes(12)?
    };
    file_header.cipher_raw_params = aes256gcm_params.to_bytes()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    file_header.cipher_param_length = file_header.cipher_raw_params.len() as u32;

    let nonce = Nonce::from_slice(&aes256gcm_params.nonce);

    let (padded_data, padding_size) = add_padding(data);
    let meta_data = Metadata{
        file_type: FileType::RegularFile,
        file_name: String::from(file_name),
        file_size: data.len() as u64,
        padding_size: padding_size
    };
    // Encrypt {metadata version:2 bytes LE}{serialized metadata length:4 bytes LE}
    //         {serialized metadata}{padded_data}
    let mut to_encrypt = (meta_data.version() as u16).to_le_bytes().to_vec();
    let metadata_bytes = meta_data.to_bytes()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_encrypt.extend((metadata_bytes.len() as u32).to_le_bytes());
    to_encrypt.extend(metadata_bytes);
    to_encrypt.extend(padded_data);
    let cipher = Aes256Gcm::new(&key.into());
    let ciphertext = cipher.encrypt(nonce, to_encrypt.as_slice())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(ciphertext)
}

#[wasm_bindgen]
pub struct DecryptionResult {
    file_name: String,
    data: Vec<u8>
}

#[wasm_bindgen]
impl DecryptionResult {
    #[wasm_bindgen(constructor)]
    pub fn new(file_name: String, data: Vec<u8>) -> Self {
        Self { file_name, data }
    }

    #[wasm_bindgen(getter)]
    pub fn file_name(&self) -> String {
        self.file_name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

}

#[wasm_bindgen]
pub fn decrypt_file(data: &[u8], password: &str)
         -> Result<DecryptionResult, JsValue> {
    let (file_header, remaining_data) = FileHeader::parse(data)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
    //@todo: we need some checks here (magic, version, etc.)
    let argon2id_params = Argon2idParams::from_bytes(&file_header.kdf_raw_params)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    // Key derivation, nonce, etc... leading to decryption.
    let key = derive_key(password, &argon2id_params)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let cipher = Aes256Gcm::new(&key.into());
    let cipher_params = Aes256GcmParams::from_bytes(&file_header.cipher_raw_params)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let nonce = Nonce::from_slice(&cipher_params.nonce);
    let decrypted_data = cipher.decrypt(nonce, remaining_data)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    // decrypted_data is expected to look like this:
    // metadata version (2 bytes unsigned LE)
    // metadata size (4 bytes unsigned LE)
    // metadata
    // data
    // padding
    let map_err_js = |e| JsValue::from_str(&format!("IO error: {}", e));
    let mut cursor = Cursor::new(&decrypted_data);
    let metadata_version = cursor.read_u16::<LittleEndian>().map_err(map_err_js)?;
    let metadata_length = cursor.read_u32::<LittleEndian>().map_err(map_err_js)?;
    let metadata_heading_size = size_of_val(&metadata_version) + size_of_val(&metadata_length);
    let (metadata, metadata_size) = Metadata::from_bytes_ex(
        &decrypted_data[metadata_heading_size..])
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    // Check that read bytes == expected metadata length
    if metadata_length as usize != metadata_size {
        return Err(JsValue::from_str("Invalid/corrupt file (bad metadata)"));
    }
    // {metadata version}{metadata length}{metadata}{data}{padding}
    let file_data = decrypted_data[
        metadata_heading_size + metadata_size..
        metadata_heading_size + metadata_size + metadata.file_size as usize].to_vec();
    Ok(DecryptionResult::new(metadata.file_name, file_data))
}

//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = 2+2;
        assert_eq!(result, 4);
    }
}
