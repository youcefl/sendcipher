/* Created on 2025.12.02 */
/* Copyright Youcef Lemsafer, all rights reserved */

use std::fs;
use std::path::PathBuf;

pub(crate) fn read_pgp_public_key(
    path: &Option<PathBuf>,
) -> Result<Option<Vec<u8>>, crate::error::Error> {
    read_file(path)
}

pub(crate) fn read_pgp_private_key(
    path: &Option<PathBuf>,
) -> Result<Option<Vec<u8>>, crate::error::Error> {
    read_file(path)
}

fn read_file(path: &Option<PathBuf>) -> Result<Option<Vec<u8>>, crate::error::Error> {
    match path {
        Some(path) => Ok(Some(std::fs::read(path)?)),
        None => Ok(None),
    }
}
