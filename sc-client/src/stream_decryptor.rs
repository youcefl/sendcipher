/* Created Oct 13, 2025 */
/* Copyright Youcef Lemsafer, all rights reserved. */

use crate::crypto::*;

pub(crate) struct CypherChunk {
    index: u64,
    blob: Blob,
}

impl CypherChunk {
    pub fn new(index: u64, blob: Blob) -> Self {
        Self {
            index: index,
            blob: blob,
        }
    }

    pub fn get_index(&self) -> u64 {
        self.index
    }
}

pub struct StreamDecryptor {
    /// The decryption context
    decryption_context: CypherContext,
    /// The manifest associated with the stream being decrypted
    manifest: Manifest,
}

impl StreamDecryptor {
    /// Constructs an instance with a password and an encrypted manifest
    pub fn with_password(
        password: &str,
        manifest_blob: &mut Blob,
    ) -> Result<Self, crate::error::Error> {
        let mut decryption_context = setup_file_decryption(manifest_blob, password)?;
        log::debug!("Decryption context created");
        let decrypted_blob = crypto::decrypt_blob(manifest_blob, &decryption_context)?;
        let metadata: &Metadata = decrypted_blob
            .get_metadata()
            .as_ref()
            .ok_or_else(|| crate::error::Error::DecryptionError("Missing metadata".to_string()))?;
        if metadata.file_type != FileType::Manifest {
            return Err(crate::error::Error::DecryptionError(
                "Unexpected file type, a manifest was expected".to_string(),
            ));
        }
        decryption_context.set_file_name(&metadata.file_name);
        log::debug!("From decrypted data: file_name=`{}'", metadata.file_name);
        log::debug!(
            "About to deserialize manifest from {:02x?}",
            decrypted_blob.get_text()
        );
        let manfest = Manifest::from_bytes(decrypted_blob.get_text())?;

        Ok(Self {
            decryption_context: decryption_context,
            manifest: manfest,
        })
    }

    /// Returns the decryption context
    pub(crate) fn get_decryption_context(&self) -> &CypherContext {
        &self.decryption_context
    }

    /// Returns the name of the file being decrypted
    pub fn file_name(&self) -> &String {
        self.manifest.file_name()
    }

    /// Returns the size of the file being decrypted
    pub fn file_size(&self) -> u64 {
        self.manifest.file_size()
    }

    /// Decrypts a chunk and returns decrypted text
    /// Takes ownership of the chunk and does the decryption in place
    pub fn decrypt_chunk(
        &self,
        cypherchunk: &mut CypherChunk,
    ) -> Result<DecryptedBlob, crate::error::Error> {
        Self::do_decrypt_chunk(&self.decryption_context, cypherchunk)
    }

    /// Decrypts a chunk and returns decrypted text
    /// Takes ownership of the chunk and does the decryption in place
    pub(crate) fn do_decrypt_chunk(
        decryption_context: &CypherContext,
        cypherchunk: &mut CypherChunk,
    ) -> Result<DecryptedBlob, crate::error::Error> {
        let mut chunk_decryption_context = decryption_context.clone();
        chunk_decryption_context.setup_chunk_decryption(cypherchunk.get_index());
        crypto::decrypt_blob(&mut cypherchunk.blob, &chunk_decryption_context)
    }

    /// Gets the manifest associated with the file being decrypted
    pub(crate) fn get_manifest(&self) -> &Manifest {
        &self.manifest
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{chunking::*, lcg::*, stream_encryptor::StreamEncryptor, test_utils::*};

    mod utils {
        use super::*;

        pub(crate) fn create_file_contents(length: usize, lcg: &mut Lcg) -> Vec<u8> {
            if length == 0 {
                return Vec::new();
            }
            let mut buffer = Vec::<u8>::with_capacity(length);
            let lcg_value_size = size_of_val(&lcg.clone().scrambled_next());
            for _ in 0..(length / lcg_value_size) {
                buffer.extend(lcg.scrambled_next().to_le_bytes());
            }
            let remainder = length % lcg_value_size;
            if remainder != 0 {
                buffer.extend_from_slice(&lcg.scrambled_next().to_le_bytes()[0..remainder]);
            }
            buffer
        }

    }

    #[test]
    /// Basic encryption/decryption test focusing on the manifest
    fn test_decrypt_manifest() {
        /*    let _ = env_logger::builder()
                .filter_level(log::LevelFilter::Debug)
                .is_test(true)
                .try_init();
        */
        log::debug!("Test test_decrypt_manifest starts");
        let chunk_generator = RandomChunkGenerator::with_seed(
            20 * 1024 * 1024,
            5 * 1024 * 1024,
            10 * 1024 * 1024,
            1u128,
        );
        let mut encryptor = StreamEncryptor::new("whatever_file_name.txt", chunk_generator, |k| {
            Ok(AnyKeyWrapper::Argon2id(
                Argon2idKeyWrapper::new("password", &create_argon2id_params_for_tests(), k)?,
            ))
        })
        .expect("Encryptor creation should succeed");

        let mut lcg = Lcg::new(LCG_PARAMS[0].0, LCG_PARAMS[0].1);
        let file_contents = utils::create_file_contents(10, &mut lcg);
        let mut chunks = Vec::new();
        chunks.extend(encryptor.process_data(&file_contents));
        chunks.extend(encryptor.finalize());
        let mut encrypted_blobs = encryptor.encrypt_chunks(&chunks).unwrap();
        encrypted_blobs
            .iter()
            .for_each(|blob| encryptor.register_encrypted_chunk(blob.0, &format!("id{}", blob.0)));
        let mut manifest_blob = encryptor.get_encrypted_manifest().unwrap();
        // In this test we want exactly one chunk (besides the manifest)
        assert_eq!(encrypted_blobs.len(), 1);

        let decryptor = StreamDecryptor::with_password("password", &mut manifest_blob).unwrap();
        let manifest = decryptor.get_manifest();

        // Check decrypted manifest correctness
        assert_eq!(manifest.file_size(), 10);
        assert_eq!(manifest.file_name(), "whatever_file_name.txt");
        assert_eq!(decryptor.file_name(), "whatever_file_name.txt");
        assert_eq!(manifest.chunks_count(), 1);
        let chunks_dict = manifest.chunks();
        assert_eq!(chunks_dict.len(), 1);
        assert_eq!(chunks_dict.get(&0u64), Some(&"id0".to_string()));

        // Decrypt and check the unique chunk
        let (chunk_index, blob) = encrypted_blobs.first_mut().unwrap();
        let decrypted_blob = decryptor
            .decrypt_chunk(&mut CypherChunk::new(*chunk_index, std::mem::take(blob)))
            .unwrap();

        assert_eq!(decrypted_blob.get_text(), &file_contents);
    }
}
