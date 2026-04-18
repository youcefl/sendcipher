/* Created on 2025.12.02 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

#[derive(Debug)]
pub(crate) enum Error {
    Lib(sendcipher_core::error::Error),
    Io(String),
    InvalidCommandLine(String),
    ServerError(String),
    EnvError(String),
    MissingUploadSessionId(String),
    SerdeError(String),
    NonMatchingPasswords(String)
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<sendcipher_core::error::Error> for Error {
    fn from(value: sendcipher_core::error::Error) -> Self {
        Self::Lib(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::SerdeError(value.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.to_string()))
    }
}
