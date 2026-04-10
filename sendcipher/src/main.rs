/* Created on 2025.12.02 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

mod configuration;
mod downloader;
mod error;
mod options;
mod password;
mod pgp;
mod progress;
mod server;
mod uploader;

use crate::downloader::*;
use crate::options::*;
use crate::uploader::*;
use clap::Parser;

fn main() -> Result<(), error::Error> {
    let options = Options::parse();
    let validation_result = options.validate();

    if !validation_result.is_err() {
        match options.command {
            Command::Upload(upload_options) => {
                Uploader::new(&upload_options)?.upload(upload_options.input_path)?;
            }
            Command::Download(download_options) => {
                Downloader::new(&download_options)?.download(&download_options.id)?;
            }
        }
        return Ok(());
    }

    let mut ret_code = 1;
    match validation_result.err().unwrap() {
        error::Error::InvalidCommandLine(msg) => {
            eprintln!("{msg}");
            ret_code = 3;
        }
        err => {
            let err_str = err.to_string();
            eprintln!("{err_str}");
        }
    }
    std::process::exit(ret_code);
}
