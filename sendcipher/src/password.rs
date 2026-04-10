/* Created on 2025.12.02 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use std::fs::File;
use std::path::PathBuf;

pub(crate) fn read_password_file(path: &Option<PathBuf>) -> Result<Option<String>, crate::error::Error> {
    match path {
        Some(path) => {
            let file = File::open(path)?;
            let read_str = std::io::read_to_string(file)?;
            Ok(Some(read_str.trim_end().to_string()))
        },
        None => Ok(None),
    }
}
