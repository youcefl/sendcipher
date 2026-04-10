/* Created on 2025.10.13 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Any(String),
    #[error("0")]
    BincodeError(String),
    #[error("0")]
    BlobParsingError(String),
    #[error("{0}")]
    ChunkChecksumError(String),
    #[error("{0}")]
    EncryptionError(String),
    #[error("{0}")]
    DecryptionError(String),
    #[error("{0}")]
    InvalidAlgorithm(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    IoError(String),
    #[error("{0}")]
    SerializationError(String),
    #[error("{0}")]
    DeserializationError(String),
    #[error("{0}")]
    LogicError(String)
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Any(s)
    }
}
impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Any(s.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(io_error: std::io::Error) -> Self {
        Error::IoError(io_error.to_string())
    }
}
