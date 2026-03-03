/* Created Oct 13, 2025
   Copyright Youcef Lemsafer, all rights reserved
*/
use crate::chunking::*;
use crate::crypto;
use crate::crypto::CypherContext;
use crate::crypto::*;
use crate::error;
use crate::parallel_mapper::*;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::u64;

pub struct StreamEncryptor<C: ChunkGenerator> {
    /// Chunks generator
    chunk_generator: C,
    /// Encryption data
    encryption_context: CypherContext,
    /// The manifest (lists the chunks)
    manifest: Manifest,
    /// Temporary table of chunks
    chunks: Arc<RwLock<BTreeMap<u64, ChunkDescriptor>>>,
    /// Whether the encryption is finalized
    is_finalized: bool,
    /// Parallel mapper used for parallel encryption
    par_mapper:
        Option<DynParallelMapper<Chunk, Result<(u64, Blob, ChunkDescriptor), crate::error::Error>>>,
}

// Crate only constructors
impl<C: ChunkGenerator> StreamEncryptor<C> {
    pub(crate) fn new(
        file_name: &str,
        chunk_generator: C,
        make_key_wrapper: impl FnOnce(&Vec<u8>) -> Result<AnyKeyWrapper, crate::error::Error>,
    ) -> Result<Self, crate::error::Error> {
        let manifest = Manifest::new(file_name.to_string(), 0)?;
        let file_enc_ctx =
            crypto::prepare_file_encryption(file_name, manifest.mfp(), make_key_wrapper)
                .map_err(|e| error::Error::EncryptionError(e.to_string()))?;

        let inst = Self {
            chunk_generator: chunk_generator,
            encryption_context: file_enc_ctx,
            manifest,
            chunks: Arc::new(RwLock::new(BTreeMap::<u64, ChunkDescriptor>::new())),
            is_finalized: false,
            par_mapper: None,
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
        Self::new(file_name, chunk_generator, |k| {
            Ok(AnyKeyWrapper::Argon2id(
                Argon2idKeyWrapper::with_default_parameters(password, k)?,
            ))
        })
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
        Self::new(file_name, chunk_generator, |k| {
            Ok(AnyKeyWrapper::Argon2id(
                Argon2idKeyWrapper::with_default_parameters(password, k)?,
            ))
        })
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
    pub fn on_end_of_data(&mut self) -> Vec<Chunk> {
        let remaining_chunks = self.chunk_generator.signal_eos();
        // Now we know the size so we put it in the manifest...
        let file_size = self.chunk_generator.chunked_bytes_count();
        self.manifest.set_file_size(file_size);
        remaining_chunks
    }

    /// Returns the identifier of the algorithm to use for computing chunk checksums
    pub fn chunk_hash_algorithm(&self) -> ChecksumAlgorithm {
        self.manifest.checksum_algorithm()
    }

    /// Returns chunk encryption context
    pub(crate) fn get_encryption_context(
        &self,
        chunk: &Chunk,
    ) -> Result<CypherContext, crate::error::Error> {
        Self::derive_chunk_encryption_context(&self.encryption_context, chunk.index())
    }

    /// Returns the given chunk as encrypted data
    pub fn encrypt_chunk(&self, chunk: &Chunk) -> Result<Blob, error::Error> {
        //println!("StreamEncryptor::encrypt_chunk, chunk {}, data: {:?}", chunk.index(), &chunk.data()[..128.min(chunk.data().len())]);
        let (blob, checksum) = Self::do_encrypt_chunk(
            &self.get_encryption_context(chunk)?,
            chunk.data(),
            self.chunk_hash_algorithm(),
        )?;

        let span = chunk.span();
        self.insert_chunk_descriptor(
            chunk.index(),
            ChunkDescriptor::new("".to_string(), checksum, span.start(), span.size()),
        )?;
        Ok(blob)
    }

    fn insert_chunk_descriptor(
        &self,
        chunk_index: u64,
        chunk_descriptor: ChunkDescriptor,
    ) -> Result<(), error::Error> {
        let mut chunks = self.chunks.write().unwrap();
        let opt_value = chunks.get_mut(&chunk_index);
        match opt_value {
            Some(_) => Err(crate::error::Error::LogicError(
                "Chunk already inserted".to_string(),
            )),
            None => {
                chunks.insert(chunk_index, chunk_descriptor);
                Ok(())
            }
        }
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

    fn update_mapper(&mut self, max_threads: u32) {
        if self.par_mapper.is_some()
            && self.par_mapper.as_ref().unwrap().concurrency() == max_threads
        {
            return;
        }
        let checksum_algo = self.manifest.checksum_algorithm();
        let file_enc_ctx_clone = self.encryption_context.clone();
        self.par_mapper = Some(DynParallelMapper::<
            Chunk,
            Result<(u64, Blob, ChunkDescriptor), crate::error::Error>,
        >::new(
            max_threads,
            Box::new(move |chunk| {
                let encryption_context =
                    Self::derive_chunk_encryption_context(&file_enc_ctx_clone, chunk.index())?;
                let (blob, checksum) =
                    Self::do_encrypt_chunk(&encryption_context, chunk.data(), checksum_algo)?;
                let span = chunk.span();
                Ok((
                    chunk.index(),
                    blob,
                    ChunkDescriptor::new("".to_string(), checksum, span.start(), span.size()),
                ))
            }),
        ));
    }

    pub fn parallel_encrypt_chunks(
        &mut self,
        max_threads: u32,
        chunks: &Vec<Chunk>,
    ) -> Result<Vec<(u64, Blob)>, error::Error> {
        self.update_mapper(max_threads);
        let results = self.par_mapper.as_mut().unwrap().process_all(chunks);

        let mut result = Vec::with_capacity(results.len());
        for res in results {
            if res.is_ok() {
                let (chunk_index, blob, chunk_desc) = res.unwrap();
                result.push((chunk_index, blob));
                self.insert_chunk_descriptor(chunk_index, chunk_desc)?;
            } else {
                return Err(res.err().unwrap());
            }
        }
        Ok(result)
    }

    fn update_chunk_id(&self, chunk_index: u64, chunk_id: &str) -> Result<(), error::Error> {
        let mut chunks = self.chunks.write().unwrap();
        let opt_value = chunks.get_mut(&chunk_index);
        match opt_value {
            Some(chunk_desc) => Ok(chunk_desc.set_id(chunk_id.to_string())),
            None => Err(crate::error::Error::LogicError(
                "Chunk not found".to_string(),
            )),
        }
    }

    ///
    fn derive_chunk_encryption_context(
        main_encryption_context: &CypherContext,
        chunk_index: u64,
    ) -> Result<CypherContext, crate::error::Error> {
        let mut chunk_encryption_context = main_encryption_context.clone();
        Ok(chunk_encryption_context
            .setup_chunk_encryption(chunk_index)?
            .clone())
    }

    /// Returns encrypted data resulting from encryption of given chunk data.
    /// Advanced! Must remain crate only, use at your own risk.
    ///
    /// @param[in] encryption_context encryption context (master key, params, etc..)
    /// @param[in] chunk_index index of the chunk
    /// @param[in] chunk_data data to be encrypted
    /// @param[in] span offset and length the chunk corresponds to in the untransformed file
    /// @return A couple where first element is the encrypted blob and the second
    /// is the checksum of the encrypted blob
    pub(crate) fn do_encrypt_chunk(
        encryption_context: &CypherContext,
        chunk_data: &[u8],
        checksum_algorithm: ChecksumAlgorithm,
    ) -> Result<(Blob, Vec<u8>), error::Error> {
        //println!("StreamEncryptor::do_encrypt_chunk called on data = {:?}", &chunk_data[..128.min(chunk_data.len())]);
        let encrypted_chunk = crypto::encrypt_to_blob(chunk_data, &mut encryption_context.clone())
            .map_err(|e| error::Error::Any(e.to_string()))?;
        let mut checksum_computer = checksum_algorithm.get_checksum_computer();
        checksum_computer.update(encrypted_chunk.data());
        Ok((encrypted_chunk, checksum_computer.finalize()))
    }

    /// Associates a string id to an encrypted chunk identified by its index
    pub fn register_encrypted_chunk(
        &self,
        chunk_index: u64,
        id: &str,
    ) -> Result<(), crate::error::Error> {
        self.update_chunk_id(chunk_index, id)
    }

    ///
    pub(crate) fn register_encrypted_chunk_descriptor(
        &mut self,
        chunk_index: u64,
        chunk_desc: ChunkDescriptor,
    ) {
        self.chunks.write().unwrap().insert(chunk_index, chunk_desc);
    }

    /// Finalizes the encryption and returns the encrypted manifest
    /// @pre on_end_of_data has been called and all chunks have been encrypted and registered
    pub fn finalize(&mut self) -> Result<Blob, crate::error::Error> {
        if self.is_finalized {
            return Err(error::Error::LogicError(
                "Manifest has already been finalized".to_string(),
            ));
        }
        let dst = self.manifest.chunks_mut();
        {
            let mut src = self.chunks.write().unwrap();
            let src_len = src.len();
            *dst = Vec::with_capacity(src_len);
            dst.resize(
                src_len,
                ChunkDescriptor::new("".to_string(), vec![], u64::MAX, u64::MAX),
            );
            for idx in 0..src_len {
                let opt_chunk_desc = src.remove(&(idx as u64));
                match opt_chunk_desc {
                    Some(chunk_desc) => dst[idx] = chunk_desc,
                    None => {
                        return Err(error::Error::LogicError(format!(
                            "Missing chunk descriptor for chunk {}",
                            idx
                        )));
                    }
                }
            }
        }

        let manifest_bytes = self.manifest.to_bytes()?;
        let blob = crypto::encrypt_to_blob(
            &manifest_bytes,
            &mut self.encryption_context.clone().setup_manifest_encryption(),
        )?;
        self.is_finalized = true;
        Ok(blob)
    }

    /// Gets the id assigned to chunk at index chunk_index
    /// @pre chunk of index chunk_index as been registered by calling register_encrypted_chunk
    pub fn get_registered_chunk_id(&self, chunk_index: u64) -> Result<String, error::Error> {
        if self.is_finalized {
            if chunk_index >= self.manifest.chunks().len() as u64 {
                return Err(error::Error::Any(format!(
                    "Index {} is out of bounds",
                    chunk_index
                )));
            }
            return Ok(self.manifest.chunks()[chunk_index as usize].id().clone());
        }
        let chunks = self.chunks.read().unwrap();
        let entry = chunks.get_key_value(&chunk_index);
        if entry.is_none() {
            return Err(error::Error::Any(format!(
                "Failed to get the id of the chunk at index {}",
                chunk_index
            )));
        }
        Ok(entry.unwrap().1.id().clone())
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
        if self.is_finalized {
            return self.manifest.chunks_count() as u64;
        }
        return self.chunks.read().unwrap().len() as u64;
    }

    /// Returns the chunk ids
    /// @pre All chunks have been registered and finalize() has been called
    pub fn get_chunk_ids(&self) -> Vec<String> {
        self.manifest
            .chunks()
            .iter()
            .map(|c| c.id().clone())
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    use crate::lcg::*;
    use crate::test_utils::*;

    fn create_encryptor(
        chunk_generator: RandomChunkGenerator,
    ) -> StreamEncryptor<RandomChunkGenerator> {
        StreamEncryptor::new("whatever_file_name", chunk_generator, |k| {
            Ok(AnyKeyWrapper::Argon2id(Argon2idKeyWrapper::new(
                "whatever!password",
                &create_argon2id_params_for_tests(),
                k,
            )?))
        })
        .unwrap()
    }

    #[test]
    fn test_chunking() {
        let mut start = std::time::Instant::now();
        let min_chunk_size = 512 * 1024u64;
        let max_chunk_size = 2 * 1024 * 1024u64;
        let chunk_generator =
            RandomChunkGenerator::with_seed(0, min_chunk_size, max_chunk_size, 1u128);
        let mut encryptor = create_encryptor(chunk_generator);

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
        let mut chunks = encryptor.process_data(&data);
        log::debug!("Data processing: {:?}", start.elapsed());
        start = std::time::Instant::now();
        chunks.append(&mut encryptor.on_end_of_data());
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
        let mut encryptor = create_encryptor(chunk_generator);

        let mut lcg = Lcg::new(LCG_PARAMS[4].0, LCG_PARAMS[4].1);
        let num_bytes = 5 * 1024 * 1024;
        let mut data = Vec::with_capacity(num_bytes);
        for _ in 0..num_bytes / std::mem::size_of::<u64>() {
            data.extend_from_slice(&lcg.next().to_le_bytes());
        }
        log::debug!("Setup took {:?}", start.elapsed());

        // Processing
        start = std::time::Instant::now();
        let mut chunks = Vec::new();
        for _ in 0..10 {
            // Simple test case, just reuse the same block again and again
            chunks.extend(encryptor.process_data(&data));
        }
        chunks.extend(encryptor.on_end_of_data());
        log::debug!("Chunking took {:?}", start.elapsed());
        log::debug!("Number of chunks: {}", chunks.len());
        log::debug!(
            "Total size in bytes: {}",
            encryptor.chunk_generator.chunked_bytes_count()
        );

        start = std::time::Instant::now();
        chunks.iter().for_each(|chnk| {
            encryptor.encrypt_chunk(chnk).unwrap();
            encryptor.register_encrypted_chunk(chnk.index(), &chnk.index().to_string());
        });

        log::debug!("Encryption took {:?}", start.elapsed());

        {
            let chunks_in_encryptor = encryptor.chunks.read().unwrap();

            assert_eq!(chunks.len(), chunks_in_encryptor.len());
        }
        encryptor.finalize().expect("Finalize should succeed");
        {
            let chunks_in_encryptor = encryptor.chunks.read().unwrap();

            assert_eq!(0, chunks_in_encryptor.len());
        }
        assert_eq!(chunks.len(), encryptor.manifest.chunks_count());
    }

    #[test]
    fn test_parallel_encryption() {
        // Set up
        let mut start = std::time::Instant::now();
        let min_chunk_size = 8 * 1024 * 1024u64;
        let max_chunk_size = 24 * 1024 * 1024u64;
        let num_threads = 8u32;

        let chunk_generator =
            RandomChunkGenerator::with_seed(0, min_chunk_size, max_chunk_size, 3u128);
        let mut encryptor = create_encryptor(chunk_generator);

        let mut gcl = Lcg::new(LCG_PARAMS[4].0, LCG_PARAMS[4].1);
        let num_bytes = 4 * 1024 * 1024;
        let mut data = Vec::with_capacity(num_bytes);
        log::debug!("Setup took {:?}", start.elapsed());

        // Processing
        let mut chunking_duration = core::time::Duration::ZERO;
        let mut encryption_duration = core::time::Duration::ZERO;
        let mut gcl_duration = core::time::Duration::ZERO;
        let mut chunks = Vec::new();
        let gcl_value_size = std::mem::size_of::<u64>();
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
            chunks.extend(encryptor.process_data(&data));
            chunking_duration += start.elapsed();
            start = std::time::Instant::now();
            if chunks.len() >= num_threads as usize {
                // Yes limit the number of chunks!! We are simulating the processing of a 1GB file!
                let encrypted_chunks = encryptor
                    .parallel_encrypt_chunks(num_threads, &chunks)
                    .unwrap();
                assert_eq!(encrypted_chunks.len(), chunks.len());
                chunks.iter().try_for_each(|chnk| {
                    encryptor.register_encrypted_chunk(chnk.index(), &chnk.index().to_string())
                });
                chunks.clear();
            }
            encryption_duration += start.elapsed();
        }
        start = std::time::Instant::now();
        chunks.extend(encryptor.on_end_of_data());
        chunking_duration += start.elapsed();
        start = std::time::Instant::now();
        let encrypted_chunks = encryptor.encrypt_chunks(&chunks).unwrap();
        assert_eq!(encrypted_chunks.len(), chunks.len());
        chunks.iter().try_for_each(|chnk| {
            encryptor.register_encrypted_chunk(chnk.index(), &chnk.index().to_string())
        });
        chunks.clear();
        encryption_duration += start.elapsed();
        log::debug!("Chunking took {:?}", chunking_duration);
        log::debug!(
            "Encryption using up to {} threads took {:?}",
            num_threads,
            encryption_duration
        );
        log::debug!(
            "Generating {} values using the LCG::next took {:?}",
            encryptor.chunk_generator.chunked_bytes_count() as usize / gcl_value_size,
            gcl_duration
        );
        log::debug!(
            "Total size in bytes: {}",
            encryptor.chunk_generator.chunked_bytes_count()
        );

        let chunks = &encryptor.chunks.read().unwrap();
        assert_eq!(
            chunks.len(),
            encryptor.chunk_generator.chunks_count() as usize
        );
        let mismatch_pos = chunks
            .keys()
            .zip(0..encryptor.chunk_generator.chunked_bytes_count() - 1)
            .position(|(&actual, expected)| actual != expected);
        assert_eq!(
            mismatch_pos, None,
            "Chunk keys not sequential. First mismatch at position: {:?}",
            mismatch_pos
        );
    }
}
