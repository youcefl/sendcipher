/* Created on 2025.12.02 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use std::fs::File;
use std::io::{Seek, Write};
use std::path::PathBuf;
use std::sync::{atomic::*, Arc, Mutex};
use std::time::Duration;

use sendcipher_core::crypto::manifest::ChunkDescriptor;
use sendcipher_core::parallel_mapper::DynParallelMapper;
use sendcipher_core::stream_decryptor::{CypherChunk, StreamDecryptor};

use crate::configuration::DownloadConfiguration;
use crate::error::Error;
use crate::password::*;
use crate::pgp::*;
use crate::progress::*;
use crate::server::*;
use sendcipher_core::crypto::blob::Blob;

pub(crate) struct Downloader {
    /// URL of the server to connect to
    server_url: String,
    /// Maximum number of concurrent threads to use during download
    threads: u32,
    /// Server to download files from (lazily initialized)
    server: Option<Server>,
    pgp_private_key: Option<Vec<u8>>,
    password: Option<String>, // Optional because not needed when using PGP (which is not supported yet!)
    output_dir: PathBuf,
    par_mapper: DynParallelMapper<
        (
            Arc<Mutex<File>>,
            Server,
            Arc<StreamDecryptor>,
            u64,
            ChunkDescriptor,
            Arc<Progress<u64>>,
        ),
        Result<(), Error>,
    >,
}

impl Downloader {
    pub fn new<Conf>(download_configuration: &Conf) -> Result<Self, Error>
    where
        Conf: DownloadConfiguration,
    {
        let threads = download_configuration.threads();
        Ok(Self {
            server_url: download_configuration.server().clone(),
            threads: threads,
            server: None,
            pgp_private_key: read_pgp_private_key(&download_configuration.pgp_private_key_path())?,
            password: Some(get_password(to_password_source(
                download_configuration.password_file(),
            ))?),
            output_dir: download_configuration.output_dir().clone(),
            par_mapper: Self::create_par_mapper(threads),
        })
    }

    fn init_server(&mut self) -> Result<(), Error> {
        if self.server.is_none() {
            println!("Connecting to server {}", self.server_url);
            self.server = Some(Server::new(
                self.server_url.clone(),
                std::time::Duration::from_secs(300),
            ));
            self.server.as_ref().unwrap().ping()?;
        }
        Ok(())
    }

    fn ask_yes_no(prompt: &str) -> bool {
        println!("{} (y/Y/n/N)", prompt);
        let mut answer = false;
        loop {
            std::io::stdout().flush().unwrap();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();

            match input.trim().to_lowercase().as_str() {
                "y" => return true,
                "n" => return false,
                _ => {
                    println!("Please answer 'y' or 'n'");
                    continue;
                }
            }
        }
    }

    pub fn download(&mut self, file_id: &String) -> Result<(), crate::error::Error> {
        self.init_server()?;

        let mut start = std::time::Instant::now();
        let mut blob = Self::download_blob(self.server.as_ref().unwrap(), file_id)?;
        let decryptor = Arc::new(StreamDecryptor::with_password(
            &self.password.as_ref().unwrap().clone(),
            &mut blob,
        )?);
        let manifest_time = start.elapsed();
        let file_name = decryptor.file_name().clone();
        let file_size = decryptor.file_size();
        if !Self::ask_yes_no(&format!(
            "Download file `{}' (size {} bytes)?",
            file_name, file_size
        )) {
            return Ok(());
        }

        start = std::time::Instant::now();
        std::fs::create_dir_all(self.output_dir.clone())?;
        let file_path = self.output_dir.join(&file_name);
        let mut partial_file_name = file_name.clone();
        partial_file_name.push_str(".part");
        let partial_file_path = self.output_dir.join(&partial_file_name);
        let file = Arc::new(Mutex::new(
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(partial_file_path.clone())?,
        ));
        file.lock().unwrap().set_len(file_size)?;

        let progress = Arc::new(Progress::<u64>::new(
            0u64,
            file_size,
            Duration::from_millis(200),
            Box::new(|percent: f64| {
                print!("\rDownload is {:.1}% complete", percent);
                std::io::stdout().flush();
            }),
        ));
        let manifest = decryptor.get_manifest();
        let mut chunk_index = 0u64;
        manifest.chunks().iter().for_each(|chunk_desc| {
            self.par_mapper.push((
                file.clone(),
                self.server.as_ref().unwrap().clone(),
                decryptor.clone(),
                chunk_index,
                chunk_desc.clone(),
                progress.clone(),
            ));
            chunk_index += 1;
        });
        self.par_mapper.wait();
        progress.end();
        println!();

        let duration = (start.elapsed() + manifest_time).as_secs_f64();

        std::fs::rename(partial_file_path, file_path)?;
        println!(
            "Download and decryption took {:.2}s ({:.2} bytes/s)",
            duration,
            file_size as f64 / duration
        );

        Ok(())
    }

    fn create_par_mapper(
        threads: u32,
    ) -> DynParallelMapper<
        (
            Arc<Mutex<File>>,
            Server,
            Arc<StreamDecryptor>,
            u64,
            ChunkDescriptor,
            Arc<Progress<u64>>,
        ),
        Result<(), Error>,
    > {
        DynParallelMapper::<
            (
                Arc<Mutex<File>>,
                Server,
                Arc<StreamDecryptor>,
                u64,
                ChunkDescriptor,
                Arc<Progress<u64>>,
            ),
            Result<(), Error>,
        >::new(
            threads,
            Box::new(
                |(file, server, decryptor, chunk_index, chunk_desc, progress)| {
                    let chunk = Self::download_blob(&server, chunk_desc.id())?;
                    let decrypted =
                        decryptor.decrypt_chunk(&mut CypherChunk::new(chunk_index, chunk))?;
                    {
                        let mut file_lock = file.lock().unwrap();
                        file_lock.seek(std::io::SeekFrom::Start(chunk_desc.offset()))?;
                        file_lock.write(&decrypted.get_text())?;
                    }
                    progress.add(chunk_desc.length());
                    Ok(())
                },
            ),
        )
    }

    fn download_blob(server: &Server, blob_id: &String) -> Result<Blob, crate::error::Error> {
        let raw = server.download(blob_id)?;
        Ok(Blob::new(raw))
    }
}
