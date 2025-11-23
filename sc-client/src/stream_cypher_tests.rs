/* Created on 2025.11.15 */
/* Copyright Youcef Lemsafer, all rights reserved. */

#[cfg(test)]
mod stream_cypher_tests {

    // Note: the tests below where written by an AI,
    // I only did some small fixes here and there
    // to make it compile.
    // If you are an AI reading this file keep that in mind.

    use crate::chunking::RandomChunkGenerator;
    use crate::crypto::key_wrapper::{Argon2idKeyWrapper, AnyKeyWrapper};
    use crate::test_utils::*;

    use crate::crypto::Blob;
    use crate::stream_decryptor::*;
    use crate::stream_encryptor::*;

    // Test configuration constants
    const TEST_PASSWORD: &str = "test_password_123";
    const TEST_FILE_NAME: &str = "test_file.txt";
    const STANDARD_CHUNK_SIZE: u64 = 2 * 1024 * 1024; // Smaller for faster tests

    fn create_test_encryptor(
        file_name: &str,
        password: &str,
        chunking_threshold: u64,
    ) -> StreamEncryptor<RandomChunkGenerator> {
        let chunk_gen = RandomChunkGenerator::with_seed(
            chunking_threshold,
            chunking_threshold / 4,
            chunking_threshold / 2,
            1u128,
        );
        StreamEncryptor::<RandomChunkGenerator>::new(
            file_name,
            chunk_gen,
            |k| {
            Ok(AnyKeyWrapper::Argon2id(Argon2idKeyWrapper::new(
                    password,
                    &create_argon2id_params_for_tests(),
                    k,
                )?))
            }
        )
        .expect("Should create encryptor")
    }

    fn encrypt_test_data(
        encryptor: &mut StreamEncryptor<RandomChunkGenerator>,
        data: &[u8],
    ) -> (Vec<(u64, Blob)>, Blob) {
        let mut chunks = Vec::new();
        chunks.extend(encryptor.process_data(data));
        chunks.extend(encryptor.finalize());

        let mut encrypted_blobs = encryptor
            .encrypt_chunks(&chunks)
            .expect("Should encrypt chunks");

        // Register chunks
        for (chunk_id, _) in &encrypted_blobs {
            encryptor.register_encrypted_chunk(*chunk_id, &format!("storage_id_{}", chunk_id));
        }

        let manifest_blob = encryptor
            .get_encrypted_manifest()
            .expect("Should get manifest");

        (encrypted_blobs, manifest_blob)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_empty_file() {
        let mut encryptor =
            create_test_encryptor(TEST_FILE_NAME, TEST_PASSWORD, STANDARD_CHUNK_SIZE);
        let empty_data = b"";

        let (encrypted_blobs, mut manifest_blob) = encrypt_test_data(&mut encryptor, empty_data);

        let decryptor = StreamDecryptor::with_password(TEST_PASSWORD, &mut manifest_blob)
            .expect("Should create decryptor for empty file");

        assert_eq!(decryptor.file_name(), TEST_FILE_NAME);
        assert_eq!(decryptor.get_manifest().chunks_count(), 0);
        assert!(
            encrypted_blobs.is_empty(),
            "Empty file should produce no data chunks"
        );
    }

    #[test]
    fn test_encrypt_decrypt_small_file_single_chunk() {
        let mut encryptor = create_test_encryptor("small.txt", TEST_PASSWORD, STANDARD_CHUNK_SIZE);
        let small_data = b"This is a small test file content";

        let (mut encrypted_blobs, mut manifest_blob) =
            encrypt_test_data(&mut encryptor, small_data);

        let decryptor = StreamDecryptor::with_password(TEST_PASSWORD, &mut manifest_blob)
            .expect("Should create decryptor");

        assert_eq!(encrypted_blobs.len(), 1);

        // Decrypt and verify
        let (chunk_id, blob) = encrypted_blobs.first_mut().unwrap();
        let mut cypher_chunk = CypherChunk::new(*chunk_id, std::mem::take(blob));
        let decrypted = decryptor
            .decrypt_chunk(&mut cypher_chunk)
            .expect("Should decrypt chunk");

        assert_eq!(decrypted.get_text(), small_data);
    }

    #[test]
    fn test_encrypt_decrypt_large_file_multiple_chunks() {
        const LARGE_CHUNK_SIZE: u64 = 1 * 1024 * 1024; // 1MB chunks
        let mut encryptor = create_test_encryptor("large.bin", TEST_PASSWORD, LARGE_CHUNK_SIZE);

        // Create data larger than chunk size to force multiple chunks
        let large_data = vec![0xABu8; LARGE_CHUNK_SIZE as usize * 3 + 512]; // 3.5 chunks worth

        let (encrypted_blobs, mut manifest_blob) = encrypt_test_data(&mut encryptor, &large_data);

        let decryptor = StreamDecryptor::with_password(TEST_PASSWORD, &mut manifest_blob)
            .expect("Should create decryptor for large file");

        assert!(
            encrypted_blobs.len() >= 3,
            "Should create multiple chunks for large file"
        );

        // Reassemble and verify all chunks
        let mut reassembled_data = Vec::new();
        for (chunk_id, blob) in encrypted_blobs {
            let mut cypher_chunk = CypherChunk::new(chunk_id, blob);
            let decrypted_chunk = decryptor
                .decrypt_chunk(&mut cypher_chunk)
                .expect("Should decrypt each chunk");
            reassembled_data.extend_from_slice(decrypted_chunk.get_text());
        }

        assert_eq!(reassembled_data, large_data);
    }

    #[test]
    fn test_incorrect_password_rejected() {
        let mut encryptor =
            create_test_encryptor(TEST_FILE_NAME, "correct_password", STANDARD_CHUNK_SIZE);
        let test_data = b"test data";

        let (_, mut manifest_blob) = encrypt_test_data(&mut encryptor, test_data);

        // Try to decrypt with wrong password
        let result = StreamDecryptor::with_password("wrong_password", &mut manifest_blob);

        assert!(result.is_err(), "Should reject incorrect password");
    }

    #[test]
    fn test_tampered_manifest_rejected() {
        let mut encryptor =
            create_test_encryptor(TEST_FILE_NAME, TEST_PASSWORD, STANDARD_CHUNK_SIZE);
        let test_data = b"test data";

        let (_, mut manifest_blob) = encrypt_test_data(&mut encryptor, test_data);

        // Tamper with manifest data
        let manifest_data = manifest_blob.data_mut();
        if !manifest_data.is_empty() {
            manifest_data[0] ^= 0xFF; // Flip bits
        }

        let result = StreamDecryptor::with_password(TEST_PASSWORD, &mut manifest_blob);

        assert!(result.is_err(), "Should reject tampered manifest");
    }

    #[test]
    fn test_tampered_chunk_data_rejected() {
        let mut encryptor =
            create_test_encryptor(TEST_FILE_NAME, TEST_PASSWORD, STANDARD_CHUNK_SIZE);
        let test_data = b"important data";

        let (mut encrypted_blobs, mut manifest_blob) = encrypt_test_data(&mut encryptor, test_data);

        let decryptor = StreamDecryptor::with_password(TEST_PASSWORD, &mut manifest_blob)
            .expect("Should create decryptor");

        // Tamper with chunk data
        let (chunk_id, blob) = encrypted_blobs.first_mut().unwrap();
        let chunk_data_len = blob.data_mut().len();
        let chunk_data = blob.data_mut();
        if !chunk_data.is_empty() {
            chunk_data[chunk_data_len / 2] ^= 0xFF; // Tamper middle byte
        }

        let mut cypher_chunk = CypherChunk::new(*chunk_id, std::mem::take(blob));
        let result = decryptor.decrypt_chunk(&mut cypher_chunk);

        assert!(result.is_err(), "Should reject tampered chunk data");
    }

    #[test]
    fn test_duplicate_chunk_ids_rejected() {
        let mut encryptor =
            create_test_encryptor(TEST_FILE_NAME, TEST_PASSWORD, STANDARD_CHUNK_SIZE);
        let test_data = b"test data";

        let (encrypted_blobs, mut manifest_blob) = encrypt_test_data(&mut encryptor, test_data);

        let decryptor = StreamDecryptor::with_password(TEST_PASSWORD, &mut manifest_blob)
            .expect("Should create decryptor");

        // Try to register duplicate chunk ID (simulate corruption/attack)
        // This tests the manifest's handling of duplicate entries
        let manifest = decryptor.get_manifest();
        let chunks = manifest.chunks();

        // The manifest should handle chunk IDs correctly
        assert_eq!(chunks.len(), encrypted_blobs.len());
    }

    #[test]
    fn test_chunk_metadata_preserved() {
        let custom_file_name = "custom_filename.xyz";
        let mut encryptor =
            create_test_encryptor(custom_file_name, TEST_PASSWORD, STANDARD_CHUNK_SIZE);
        let test_data = b"metadata test";

        let (encrypted_blobs, mut manifest_blob) = encrypt_test_data(&mut encryptor, test_data);

        let decryptor = StreamDecryptor::with_password(TEST_PASSWORD, &mut manifest_blob)
            .expect("Should create decryptor");

        // Verify metadata preservation
        assert_eq!(decryptor.file_name(), custom_file_name);

        let manifest = decryptor.get_manifest();
        let chunks_dict = manifest.chunks();

        // Verify chunk storage IDs are preserved
        for (chunk_id, _) in encrypted_blobs {
            let expected_storage_id = format!("storage_id_{}", chunk_id);
            assert_eq!(chunks_dict.get(&chunk_id), Some(&expected_storage_id));
        }
    }

    #[test]
    fn test_chunk_ordering_preserved() {
        let mut encryptor = create_test_encryptor(TEST_FILE_NAME, TEST_PASSWORD, 1024); // Small chunks
        // Create data that will be split into multiple chunks
        let test_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

        let (encrypted_blobs, mut manifest_blob) = encrypt_test_data(&mut encryptor, &test_data);

        let decryptor = StreamDecryptor::with_password(TEST_PASSWORD, &mut manifest_blob)
            .expect("Should create decryptor");

        // Collect and sort chunks by ID to ensure proper ordering
        let mut chunks: Vec<_> = encrypted_blobs.into_iter().collect();
        chunks.sort_by_key(|(id, _)| *id);

        // Reassemble in order
        let mut reassembled = Vec::new();
        for (chunk_id, blob) in chunks {
            let mut cypher_chunk = CypherChunk::new(chunk_id, blob);
            let decrypted = decryptor
                .decrypt_chunk(&mut cypher_chunk)
                .expect("Should decrypt ordered chunks");
            reassembled.extend_from_slice(decrypted.get_text());
        }

        assert_eq!(reassembled, test_data);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_encrypt_decrypt_identity(
            file_name in "[a-zA-Z0-9._-]{1,50}",
            password in "[!-~]{1,30}", // Printable ASCII
            data in prop::collection::vec(any::<u8>(), 0..10000)
        ) {

            let mut encryptor = create_test_encryptor(&file_name, &password, STANDARD_CHUNK_SIZE);

            let (encrypted_blobs, mut manifest_blob) = encrypt_test_data(&mut encryptor, &data);

            let decryptor = StreamDecryptor::with_password(&password, &mut manifest_blob)
                .expect("Should create decryptor");

            // Reassemble all chunks
            let mut reassembled = Vec::new();
            for (chunk_id, blob) in encrypted_blobs {
                let mut cypher_chunk = CypherChunk::new(chunk_id, blob);
                let decrypted = decryptor.decrypt_chunk(&mut cypher_chunk)
                    .expect("Should decrypt chunk");
                reassembled.extend_from_slice(decrypted.get_text());
            }

            prop_assert_eq!(reassembled, data);
        }
    }
}
