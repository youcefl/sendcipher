/* Created Oct 13, 2025
   Copyright Youcef Lemsafer, all rights reserved
*/

use crate::chunking::*;
use crate::crypto;
use crate::crypto::CypherContext;
use crate::crypto::*;
use crate::error;
use std::sync::RwLock;
use std::sync::{Arc, Mutex};

pub struct StreamEncryptor<C: ChunkGenerator> {
    /// The name of the file to encrypt
    file_name: String,
    chunk_generator: C,
    /// Encryption data
    encryption_context: CypherContext,
    /// The manifest (lists the chunks)
    manifest: Arc<RwLock<Manifest>>,
}

// Crate only constructors
impl<C: ChunkGenerator> StreamEncryptor<C> {
    pub(crate) fn new(
        file_name: &str,
        chunk_generator: C,
        key_wrapper: &AnyKeyWrapper,
    ) -> Result<Self, crate::error::Error> {
        let file_enc_ctx = crypto::prepare_file_encryption(file_name, key_wrapper)
            .map_err(|e| error::Error::EncryptionError(e.to_string()))?;

        let inst = Self {
            file_name: file_name.to_string(),
            chunk_generator: chunk_generator,
            encryption_context: file_enc_ctx,
            manifest: Arc::new(RwLock::new(Manifest::new(file_name.to_string(), 0))),
        };
        Ok(inst)
    }
}

impl StreamEncryptor<RandomChunkGenerator> {
    pub fn with_rand_chunks(
        file_name: &str,
        password: &str,
        chunking_threshold: u64,
        min_chunk_size: u64,
        max_chunk_size: u64,
    ) -> Result<Self, error::Error> {
        let chunk_generator =
            RandomChunkGenerator::new(chunking_threshold, min_chunk_size, max_chunk_size);
        Self::new(
            file_name,
            chunk_generator,
            &AnyKeyWrapper::Kdf(Box::new(Argon2idKeyWrapper::with_default_parameters(
                password,
            ))),
        )
    }

    pub fn with_rand_chunks_seed(
        file_name: &str,
        password: &str,
        chunking_threshold: u64,
        min_chunk_size: u64,
        max_chunk_size: u64,
        seed: u128,
    ) -> Result<Self, error::Error> {
        let chunk_generator = RandomChunkGenerator::with_seed(
            chunking_threshold,
            min_chunk_size,
            max_chunk_size,
            seed,
        );
        Self::new(
            file_name,
            chunk_generator,
            &AnyKeyWrapper::Kdf(Box::new(Argon2idKeyWrapper::with_default_parameters(
                password,
            ))),
        )
    }
}

impl<C: ChunkGenerator> StreamEncryptor<C> {
    /// Processes given data.
    ///
    /// This is the main processing loop to be called repetitively until end of stream.
    pub fn process_data(&mut self, data: &[u8]) -> Vec<Chunk> {
        self.chunk_generator.process_data(data)
    }

    /// Finalizes the encryption
    ///
    /// Must be called when the stream is exhausted to get the last remaining chunks to encrypt.
    /// Returns the final chunks that were previously not ready.
    pub fn finalize(&mut self) -> Vec<Chunk> {
        let remaining_chunks = self.chunk_generator.signal_eos();
        // Now we know the size so we put it in the manifest...
        let file_size = self.chunk_generator.chunked_bytes_count();
        self.manifest.write().unwrap().set_file_size(file_size);
        remaining_chunks
    }

    /// Returns the given chunks as encrypted data
    ///
    /// @pre c.is_ready() for all c in chunks
    pub fn encrypt_chunks(&self, chunks: &Vec<Chunk>) -> Result<Vec<(u64, Blob)>, error::Error> {
        chunks
            .iter()
            .map(|chunk| {
                let data = self.encrypt_chunk(chunk)?;
                Ok((chunk.index(), data))
            })
            .collect()
    }

    /// Performs parallel encryption of given chunks using up to max_threads conccurent threads
    ///
    /// @pre c.is_ready() for all c in chunks
    pub fn parallel_encrypt_chunks(
        &self,
        chunks: &Vec<Chunk>,
        max_threads: u32,
    ) -> Result<Vec<(u64, Blob)>, error::Error> {
        // Avoid unnecessary threading overhead in single-thread case or when less than 2 chunks
        if max_threads < 2 || chunks.len() < 2 {
            return self.encrypt_chunks(chunks);
        }
        let chunk_stk = Arc::new(Mutex::new((0..chunks.len()).collect::<Vec<usize>>()));
        let results = Arc::new(Mutex::new(Vec::<(u64, Blob)>::new()));
        let errors = Arc::new(Mutex::new(Vec::<error::Error>::new()));

        std::thread::scope(|s| {
            for _ in 0..std::cmp::min(max_threads as usize, chunks.len()) {
                let chunk_stk = Arc::clone(&chunk_stk);
                let results = Arc::clone(&results);
                let errors = Arc::clone(&errors);
                s.spawn(move || {
                    while let Some(idx) = {
                        let mut stk = chunk_stk.lock().unwrap();
                        stk.pop()
                    } {
                        let chnk = &chunks[idx];
                        let res = self.encrypt_chunk(chnk);
                        if res.is_err() {
                            errors.lock().unwrap().push(res.unwrap_err());
                        } else {
                            results.lock().unwrap().push((chnk.index(), res.unwrap()));
                        }
                    }
                });
            }
        });

        let errors_vec = {
            let guard = errors.lock().unwrap();
            guard.clone()
        };
        if errors_vec.len() != 0 {
            return Err(crate::error::Error::Any(errors_vec[0].to_string()));
        }

        let results_mutex = Arc::try_unwrap(results)
            .map_err(|_| error::Error::Any("Failed to unwrap results".to_string()))?;
        Ok(results_mutex.into_inner().unwrap())
    }

    /// Returns chunk encryption context
    /// @pre chunk must be ready for encryption
    pub(crate) fn get_encryption_context(&self, chunk: &Chunk) -> CypherContext {
        assert!(chunk.is_ready(), "Chunk not ready for encryption");

        Self::derive_chunk_encryption_context(&self.encryption_context, chunk.index())
    }

    /// Returns the given chunk as encrypted data
    ///
    /// @pre chunk.is_ready()
    pub fn encrypt_chunk(&self, chunk: &Chunk) -> Result<Blob, error::Error> {
        assert!(chunk.is_ready(), "Chunk not ready for encryption");

        Self::do_encrypt_chunk(&self.get_encryption_context(chunk), chunk.data())
    }

    ///
    fn derive_chunk_encryption_context(
        main_encryption_context: &CypherContext,
        chunk_index: u64,
    ) -> CypherContext {
        let mut chunk_encryption_context = main_encryption_context.clone();
        chunk_encryption_context
            .setup_chunk_encryption(chunk_index)
            .clone()
    }

    /// Returns encrypted data resulting from encryption of given chunk data.
    /// Advanced! Must remain crate only, use at your own risk.
    ///
    /// @param[in] encryption_context encryption context (master key, params, etc..)
    /// @param[in] chunk_index index of the chunk
    /// @param[in] chunk_data data to be encrypted
    pub(crate) fn do_encrypt_chunk(
        encryption_context: &CypherContext,
        chunk_data: &[u8],
    ) -> Result<Blob, error::Error> {
        let encrypted_chunk = crypto::encrypt(chunk_data, &mut encryption_context.clone())
            .map_err(|e| error::Error::Any(e.to_string()))?;

        Ok(encrypted_chunk)
    }

    /// Returns an encrypted version of the manifest
    /// @pre finalize has been called and all chunks have been registered
    pub fn get_encrypted_manifest(&self) -> Result<Blob, crate::error::Error> {
        let manifest_bytes = {
            let manifest = self.manifest.read().unwrap();
            manifest.to_bytes()?
        };
        log::debug!("In StreamEncryptor::get_encrypted_manifest manifest is {:02x?}", manifest_bytes);
        crypto::encrypt(
            &manifest_bytes,
            &mut self.encryption_context.clone().setup_manifest_encryption(),
        )
    }

    /// Associates a string id to an encrypted chunk identified by its index
    pub fn register_encrypted_chunk(&mut self, chunk_index: u64, id: &str) {
        self.manifest
            .write()
            .unwrap()
            .chunks_mut()
            .insert(chunk_index, id.to_string());
    }

    /// Gets the id assigned to chunk at index chunk_index
    /// @pre chunk of index chunk_index as been registered by calling register_encrypted_chunk
    pub fn get_registered_chunk_id(&self, chunk_index: u64) -> Result<String, error::Error> {
        let manifest = self
            .manifest
            .read()
            .map_err(|_| error::Error::Any("Failed to get manifest".to_string()))?;
        let entry = manifest.chunks().get_key_value(&chunk_index);
        if entry.is_none() {
            return Err(error::Error::Any(format!(
                "Failed to get the id of the chunk at index {}",
                chunk_index
            )));
        }
        Ok(entry.unwrap().1.clone())
    }

    /// Returns the total number of chunks so far
    /// Increases as we keep piling chunks but may decrease e.g. on finalize if merging last chunks
    pub fn get_chunks_count(&self) -> u64 {
        self.chunk_generator.chunks_count()
    }

    /// Returns the number of registered encrypted chunks i.e.
    /// the number of chunks on which register_encrypted_chunk has
    /// been called.
    pub fn get_registered_chunks_count(&self) -> u64 {
        self.manifest.read().unwrap().chunks_count() as u64
    }
}

#[cfg(test)]
mod tests {

    use core::num;
    use proptest::string;
    use std::io::Write;

    use super::*;
    use crate::crypto::KdfAlgorithm;
    use crate::lcg::*;

    #[test]
    fn test_chunking() {
        let mut start = std::time::Instant::now();
        let min_chunk_size = 512 * 1024u64;
        let max_chunk_size = 2 * 1024 * 1024u64;
        let chunk_generator =
            RandomChunkGenerator::with_seed(0, min_chunk_size, max_chunk_size, 1u128);
        let mut encrypter = StreamEncryptor::new(
            "whatever_file_name",
            chunk_generator,
            &AnyKeyWrapper::Kdf(Box::new(TestKdfKeyWrapper::new("Whatever!Password!"))),
        )
        .unwrap();
        log::debug!("Encrypter construction: {:?}", start.elapsed());

        start = std::time::Instant::now();
        let mut lcg = Lcg::new(LCG_PARAMS[4].0, LCG_PARAMS[4].1);
        let num_bytes = 5 * 1024 * 1024;
        let mut data = Vec::with_capacity(num_bytes);
        let start_filling = std::time::Instant::now();
        for _ in 0..num_bytes / std::mem::size_of::<u64>() {
            data.extend_from_slice(&lcg.next().to_le_bytes());
        }
        log::debug!(
            "Data allocation/filling: {:?} (size: {}), filling only: {:?}",
            start.elapsed(),
            data.len(),
            start_filling.elapsed()
        );

        start = std::time::Instant::now();
        let mut chunks = encrypter.process_data(&data);
        log::debug!("Data processing: {:?}", start.elapsed());
        start = std::time::Instant::now();
        chunks.append(&mut encrypter.finalize());
        log::debug!("Finalization: {:?}", start.elapsed());

        let data_size: usize = chunks.iter().map(|c| c.size() as usize).sum();
        assert_eq!(data.len(), data_size);
    }

    #[test]
    fn test_encryption() {
        // Set up
        let mut start = std::time::Instant::now();
        let min_chunk_size = 8 * 1024 * 1024u64;
        let max_chunk_size = 24 * 1024 * 1024u64;
        let chunk_generator =
            RandomChunkGenerator::with_seed(0, min_chunk_size, max_chunk_size, 1u128);
        let mut encrypter = StreamEncryptor::new(
            "whatever_file_name",
            chunk_generator,
            &AnyKeyWrapper::Kdf(Box::new(TestKdfKeyWrapper::new("Whatever!Password!"))),
        )
        .unwrap();

        let mut lcg = Lcg::new(LCG_PARAMS[4].0, LCG_PARAMS[4].1);
        let num_bytes = 5 * 1024 * 1024;
        let mut data = Vec::with_capacity(num_bytes);
        let start_filling = std::time::Instant::now();
        for _ in 0..num_bytes / std::mem::size_of::<u64>() {
            data.extend_from_slice(&lcg.next().to_le_bytes());
        }
        log::debug!("Setup took {:?}", start.elapsed());

        // Processing
        start = std::time::Instant::now();
        let mut chunks = Vec::new();
        for _ in 0..10 {
            // Simple test case, just reuse the same block again and again
            chunks.extend(encrypter.process_data(&data));
        }
        chunks.extend(encrypter.finalize());
        log::debug!("Chunking took {:?}", start.elapsed());
        log::debug!("Number of chunks: {}", chunks.len());
        log::debug!(
            "Total size in bytes: {}",
            encrypter.chunk_generator.chunked_bytes_count()
        );

        start = std::time::Instant::now();
        chunks.iter().for_each(|chnk| {
            encrypter.encrypt_chunk(chnk).unwrap();
            encrypter.register_encrypted_chunk(chnk.index(), &chnk.index().to_string());
        });

        log::debug!("Encryption took {:?}", start.elapsed());

        let manifest = &encrypter.manifest;

        assert_eq!(chunks.len(), manifest.read().unwrap().chunks_count());
    }

    #[test]
    fn test_parallel_encryption() {
        // Set up
        let mut start = std::time::Instant::now();
        let min_chunk_size = 8 * 1024 * 1024u64;
        let max_chunk_size = 24 * 1024 * 1024u64;

        let chunk_generator =
            RandomChunkGenerator::with_seed(0, min_chunk_size, max_chunk_size, 3u128);
        let mut encrypter = StreamEncryptor::new(
            "whatever_file_name",
            chunk_generator,
            &AnyKeyWrapper::Kdf(Box::new(TestKdfKeyWrapper::new("Whatever!Password!"))),
        )
        .unwrap();

        let mut gcl = Lcg::new(LCG_PARAMS[4].0, LCG_PARAMS[4].1);
        let num_bytes = 4 * 1024 * 1024;
        let mut data = Vec::with_capacity(num_bytes);
        let start_filling = std::time::Instant::now();
        log::debug!("Setup took {:?}", start.elapsed());

        // Processing
        let mut chunking_duration = core::time::Duration::ZERO;
        let mut encryption_duration = core::time::Duration::ZERO;
        let mut gcl_duration = core::time::Duration::ZERO;
        let mut chunks = Vec::new();
        let gcl_value_size = std::mem::size_of::<u64>();
        let num_threads = 8u32;
        for i in 0..256 {
            // 256 * 4MB = 1GB
            let mut k = 0;
            start = std::time::Instant::now();
            (0..num_bytes / gcl_value_size).for_each(|_| {
                if i == 0 {
                    data.extend_from_slice(&gcl.next().to_le_bytes());
                } else {
                    data[k..k + gcl_value_size].copy_from_slice(&gcl.next().to_le_bytes());
                    k += gcl_value_size;
                }
            });
            gcl_duration += start.elapsed();
            start = std::time::Instant::now();
            chunks.extend(encrypter.process_data(&data));
            chunking_duration += start.elapsed();
            start = std::time::Instant::now();
            if chunks.len() >= num_threads as usize {
                // Yes limit the number of chunks!! We are simulating the processing of a 1GB file!
                let encrypted_chunks = encrypter
                    .parallel_encrypt_chunks(&chunks, num_threads)
                    .unwrap();
                assert_eq!(encrypted_chunks.len(), chunks.len());
                chunks.iter().for_each(|chnk| {
                    encrypter.register_encrypted_chunk(chnk.index(), &chnk.index().to_string())
                });
                chunks.clear();
            }
            encryption_duration += start.elapsed();
        }
        start = std::time::Instant::now();
        chunks.extend(encrypter.finalize());
        chunking_duration += start.elapsed();
        start = std::time::Instant::now();
        let encrypted_chunks = encrypter
            .parallel_encrypt_chunks(&chunks, num_threads)
            .unwrap();
        assert_eq!(encrypted_chunks.len(), chunks.len());
        chunks.iter().for_each(|chnk| {
            encrypter.register_encrypted_chunk(chnk.index(), &chnk.index().to_string())
        });
        chunks.clear();
        encryption_duration += start.elapsed();
        log::debug!(
            "Encryption using up to {} threads took {:?}",
            num_threads, encryption_duration
        );
        log::debug!(
            "Generating {} values using the LCG::next took {:?}",
            encrypter.chunk_generator.chunked_bytes_count() as usize / gcl_value_size,
            gcl_duration
        );
        log::debug!(
            "Total size in bytes: {}",
            encrypter.chunk_generator.chunked_bytes_count()
        );

        let manifest = &encrypter.manifest.read().unwrap();
        assert_eq!(
            manifest.chunks_count(),
            encrypter.chunk_generator.chunks_count() as usize
        );
        let mismatch_pos = manifest
            .chunks()
            .keys()
            .zip(0..encrypter.chunk_generator.chunked_bytes_count() - 1)
            .position(|(&actual, expected)| actual != expected);
        assert_eq!(
            mismatch_pos, None,
            "Chunk keys not sequential. First mismatch at position: {:?}",
            mismatch_pos
        );
    }
}
