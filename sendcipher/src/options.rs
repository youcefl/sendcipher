/* Created on 2025.12.02 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use clap::*;
use std::path::PathBuf;

use crate::configuration::{DownloadConfiguration, UploadConfiguration};

#[derive(Clone, clap::Parser)]
#[command(name = "sendcipher")]
#[command(about = "Encrypted file transfer for the people")]
pub(crate) struct Options {
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Options {
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        self.command.validate()
    }
}

#[derive(Clone, Subcommand)]
pub(crate) enum Command {
    Upload(UploadOptions),
    Download(DownloadOptions),
}

impl Command {
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        match self {
            Command::Upload(upload_options) => upload_options.validate(),
            Command::Download(download_options) => download_options.validate(),
        }
    }
}

/// Upload a file to a SendCipher server.
#[derive(Clone, clap::Args)]
pub(crate) struct UploadOptions {
    /// Number of parallel worker threads used for chunk encryption
    /// and network transmission.
    ///
    /// Higher values improve throughput on multi-core systems.
    /// Defaults to 4.
    #[arg(long)]
    pub threads: usize,

    /// Base URL of the SendCipher server.
    ///
    /// Examples:
    ///   --server http://localhost:19431
    ///   --server https://example.com
    ///
    /// This argument is required.
    #[arg(short, long, required = true, value_name = "URL")]
    pub server: String,

    /// Path to a file containing the user token
    #[arg(long)]
    pub token_file: Option<PathBuf>,

    /// Path to a PGP public key used to encrypt the manifest and metadata.
    ///
    /// If omitted, no PGP encryption is applied.  
    /// Use this when sending encrypted data to a recipient who holds
    /// the corresponding private key.
    #[arg(long = "pgp_pub")]
    pub pgp_public_key: Option<PathBuf>,

    /// File containing the password for symmetric encryption
    #[arg(long = "password_file")]
    pub password_file: Option<PathBuf>,

    /// Input file to upload.
    ///
    /// This path must point to an existing file.
    pub input_path: PathBuf,
}

impl UploadConfiguration for UploadOptions {
    fn server(&self) -> &String {
        &self.server
    }

    fn token_file(&self) -> &Option<PathBuf> {
        &self.token_file
    }

    fn threads(&self) -> u32 {
        self.threads as u32
    }

    fn pgp_public_key_path(&self) -> &Option<PathBuf> {
        &self.pgp_public_key
    }

    fn password_file(&self) -> &Option<PathBuf> {
        &self.password_file
    }
}

impl UploadOptions {
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if self.pgp_public_key.is_none() && self.password_file.is_none() {
            return Err(crate::error::Error::InvalidCommandLine(
                "At least one of password file or PGP key must be provided".to_string()
            ));
        }
        Ok(())
    }
}

/// Download and decrypt a file from a SendCipher server
/// using the file ID returned during upload.
#[derive(Clone, clap::Args)]
#[command(group(
    clap::ArgGroup::new("decrypt_method")
        .required(true)
        .args(["password_file", "pgp_private_key"])
))]
pub struct DownloadOptions {
    /// Number of threads used for parallel chunk fetching and decryption.
    ///
    /// Higher thread counts increase throughput.
    /// Defaults to 4.
    #[arg(long, default_value_t = 4)]
    pub threads: usize,

    /// Base URL of the Sendcipher server.
    ///
    /// Required. Example:
    ///   --server http://localhost:19431
    #[arg(long)]
    pub server: String,

    /// Path to a PGP private key used to decrypt the manifest.
    ///
    /// Necessary only if the upload was performed with --pgp_pub.
    /// If the wrong key is provided, decryption will fail immediately.
    #[arg(long = "pgp_priv")]
    pub pgp_private_key: Option<PathBuf>,

    /// File containing the password for symmetric encryption
    #[arg(long = "password_file")]
    pub password_file: Option<PathBuf>,

    #[arg(long = "output_dir")]
    pub output_dir: PathBuf,

    /// File ID returned during upload.
    ///
    /// This ID allows retrieving metadata and encrypted chunks.
    pub id: String,
}

impl DownloadConfiguration for DownloadOptions {
    fn server(&self) -> &String {
        &self.server
    }

    fn threads(&self) -> u32 {
        self.threads as u32
    }

    fn pgp_private_key_path(&self) -> &Option<PathBuf> {
        &self.pgp_private_key
    }

    fn password_file(&self) -> &Option<PathBuf> {
        &self.password_file
    }
    
    fn output_dir(&self) -> &PathBuf {
        &self.output_dir
    }
}

impl DownloadOptions {
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if self.pgp_private_key.is_none() && self.password_file.is_none() {
            return Err(crate::error::Error::InvalidCommandLine(
                "At least one of password file or PGP key must be provided".to_string()
            ));
        }
        Ok(())
    }
}
