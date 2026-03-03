/* Created on 2025.12.02 */
/* Copyright Youcef Lemsafer, all rights reserved */

use crate::configuration::UploadConfiguration;
use crate::error::Error;
use crate::password::*;
use crate::pgp::*;
use crate::progress::*;
use crate::server::*;
use sc_client::chunking::*;
use sc_client::parallel_mapper::*;
use sc_client::stream_encryptor::*;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub(crate) struct Uploader {
    /// URL of the target server
    server_url: String,
    /// User token
    token: String,
    /// Maximum number of concurrent threads to use during encryption-upload
    threads: u32,
    /// Public PGP key to use for encryption of the user file
    /// Optional, if not provided one of password or AGE key must be provided
    pgp_public_key: Option<Vec<u8>>,
    /// Password to use for encryption of the user file
    /// Optional, if not provided one of PGP or AGE key must be provided
    password: Option<String>,
    /// Target server (initialized lazily)
    server: Option<Server>,
    chunk_processor: DynParallelMapper<
        (
            Arc<RwLock<StreamEncryptor<RandomChunkGenerator>>>,
            Chunk,
            Server,
            String,
            String,
            Arc<Progress<u64>>,
        ),
        Result<(), Error>,
    >,
}

impl Uploader {
    /// Constructs an instance given a configuration
    pub fn new<Conf>(upload_configuration: &Conf) -> Result<Self, Error>
    where
        Conf: UploadConfiguration,
    {
        Ok(Self {
            server_url: upload_configuration.server().clone(),
            token: Self::get_token(upload_configuration.token_file())?,
            threads: upload_configuration.threads(),
            pgp_public_key: read_pgp_public_key(&upload_configuration.pgp_public_key_path())?,
            password: read_password_file(&upload_configuration.password_file())?,
            server: None,
            chunk_processor: DynParallelMapper::<
                (
                    Arc<RwLock<StreamEncryptor<RandomChunkGenerator>>>,
                    Chunk,
                    Server,
                    String,
                    String,
                    Arc<Progress<u64>>,
                ),
                Result<(), Error>,
            >::new(
                upload_configuration.threads(),
                Box::new(
                    |(encryptor, chunk, server, token, upload_session_id, progress)| {
                        let blob = encryptor.read().unwrap().encrypt_chunk(&chunk)?;
                        let chunk_index = chunk.index();
                        let chunk_id = server.upload(&token, &upload_session_id, blob.data())?;
                        encryptor
                            .read()
                            .unwrap()
                            .register_encrypted_chunk(chunk_index, &chunk_id)?;
                        progress.add(chunk.span().size());
                        Ok(())
                    },
                ),
            ),
        })
    }

    fn init_server(&mut self) -> Result<(), Error> {
        if self.server.is_none() {
            println!("Connecting to server {}", self.server_url);
            self.server = Some(Server::new(
                self.server_url.clone(),
                std::time::Duration::from_secs(7),
            ));
            self.server.as_ref().unwrap().ping()?;
        }
        Ok(())
    }

    fn get_token(token_file: &Option<PathBuf>) -> Result<String, Error> {
        match token_file {
            Some(path) => {
                let mut token = String::new();
                std::fs::File::open(path)?.read_to_string(&mut token);
                token = token.trim_end().to_string();
                Ok(token)
            }
            None => std::env::var("SENDCIPHER_TOKEN").map_err(|e| {
                Error::EnvError(format!(
                    "Error while getting SENDCIPHER_TOKEN: {}",
                    e.to_string()
                ))
            }),
        }
    }

    pub fn upload(&mut self, user_file: PathBuf) -> Result<(), Error> {
        // Fail immediately if the file to encrypt-upload cannot be opened
        let mut file = std::fs::File::open(user_file.as_path())?;
        let file_size = file.metadata()?.len();

        self.init_server()?;
        let server = self.server.as_ref().unwrap().clone();
        let token = self.token.clone();
        let upload_session_id = server.start_upload(&token, file_size)?;
        println!("Encrypting file {}", user_file.as_path().to_str().unwrap());
        let start = std::time::Instant::now();
        let encryptor = Arc::new(std::sync::RwLock::new(self.make_encryptor(&user_file)?));

        let progress = Self::create_progress(file_size);

        let buff_size = 8 * 1024 * 1024usize;
        let mut buff = vec![0u8; buff_size];
        let position_before = file.stream_position()?;
        let mut read_bytes = file.read(&mut buff)?;
        while read_bytes != 0 {
            let chunks = encryptor.write().unwrap().process_data(&buff[..read_bytes]);
            self.process_chunks(
                chunks,
                &server,
                &token,
                &upload_session_id,
                &encryptor,
                &progress,
            )?;
            read_bytes = file.read(&mut buff)?;
        }
        let chunks = encryptor.write().unwrap().on_end_of_data();
        self.process_chunks(
            chunks,
            &server,
            &token,
            &upload_session_id,
            &encryptor,
            &progress,
        )?;
        self.chunk_processor.wait();
        progress.end();
        println!("");
        let manifest = encryptor.write().unwrap().finalize()?;
        let shareable_id = server.upload(&self.token, &upload_session_id, manifest.data())?;
        let file_size = file.stream_position()? - position_before;
        let expiration_date = server.commit_upload(
            &token,
            &upload_session_id,
            file_size,
            encryptor.read().unwrap().get_chunk_ids(),
            &shareable_id,
        )?;
        println!(
            "File {} ({} bytes) has been uploaded, share id is {}",
            user_file.as_path().clone().to_str().unwrap(),
            file_size,
            shareable_id
        );
        println!(
            "Share link: https://sendcipher.com/d/{}", shareable_id
        );
        
        println!("The file will expire on: {}", expiration_date.with_timezone(&chrono::Local));
        let elapsed_secs = start.elapsed().as_secs_f64();
        println!(
            "Took {:.2}s ({:.2} bytes/s)",
            elapsed_secs,
            file_size as f64 / elapsed_secs
        );
        Ok(())
    }

    fn create_progress(file_size: u64) -> Arc<Progress<u64>> {
        Arc::new(Progress::<u64>::new(
            0u64,
            file_size,
            Duration::from_millis(200),
            Box::new(|percent: f64| {
                print!("\rUpload is {:.1}% complete", percent);
                std::io::stdout().flush();
            }),
        ))
    }

    fn process_chunks(
        &mut self,
        chunks: Vec<Chunk>,
        server: &Server,
        token: &String,
        upload_session_id: &String,
        encryptor: &Arc<RwLock<StreamEncryptor<RandomChunkGenerator>>>,
        progress: &Arc<Progress<u64>>,
    ) -> Result<(), Error> {
        chunks.iter().try_for_each(|chunk| {
            self.chunk_processor.push((
                encryptor.clone(),
                chunk.clone(),
                server.clone(),
                token.clone(),
                upload_session_id.clone(),
                progress.clone(),
            ));
            for r in self.chunk_processor.pop_all() {
                if r.is_err() {
                    return Err(r.unwrap_err());
                }
            }
            Ok::<(), Error>(())
        })
    }

    fn make_encryptor(
        &mut self,
        user_file: &PathBuf,
    ) -> Result<StreamEncryptor<RandomChunkGenerator>, Error> {
        let mut start = std::time::Instant::now();
        let min_chunk_size = 8 * 1024 * 1024u64;
        let max_chunk_size = 24 * 1024 * 1024u64;
        let mut encryptor = StreamEncryptor::with_rand_chunks(
            user_file.file_name().unwrap().to_str().unwrap(),
            self.password.as_ref().unwrap(),
            max_chunk_size,
            min_chunk_size,
            max_chunk_size,
        )?;
        Ok(encryptor)
    }
}
