/* Created on 2025.12.02 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use crate::error::Error;
use std::fs::File;
use std::path::PathBuf;

pub(crate) enum PasswordSource {
    File(PathBuf),
    Interactive,
}

impl PasswordSource {
    pub fn interactive() -> Self {
        Self::Interactive
    }
    pub fn from_file(path: &PathBuf) -> Self {
        Self::File(path.clone())
    }
}

pub(crate) fn to_password_source(opt_path: &Option<PathBuf>) -> PasswordSource {
    match opt_path {
        Some(path) => PasswordSource::from_file(path),
        None => PasswordSource::interactive(),
    }
}

/// Gets the password from the file or prompts the user to define one
pub(crate) fn get_or_define_password(source: PasswordSource) -> Result<String, Error> {
    match source {
        PasswordSource::File(path) => read_password_file(&path),
        PasswordSource::Interactive => {
            println!("Please enter a password for file encryption");
            let pwd = rpassword::read_password()?;
            println!("Please confirm the password");
            let confirm = rpassword::read_password()?;
            if pwd != confirm {
                return Err(Error::NonMatchingPasswords("Passwords do not match".to_string()));
            }
            Ok(pwd)
        }
    }
}

/// Gets the password from the file or prompts the user to enter it
pub(crate) fn get_password(source: PasswordSource) -> Result<String, Error> {
    match source {
        PasswordSource::File(path) => read_password_file(&path),
        PasswordSource::Interactive => {
            println!("Please enter the password for decryption of the file");
            Ok(rpassword::read_password()?)
        },
    }
}

/// Reads the password from provided path
fn read_password_file(path: &PathBuf) -> Result<String, Error> {
    let file = File::open(path)?;
    let read_str = std::io::read_to_string(file)?;
    Ok(read_str.trim_end().to_string())
}
