/* Created on 2025.12.02 */
/* Copyright Youcef Lemsafer, all rights reserved. */

#[derive(Debug)]
pub(crate) enum Error {
    Lib(sc_client::error::Error),
    Io(String),
    InvalidCommandLine(String),
    ServerError(String),
    EnvError(String)
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<sc_client::error::Error> for Error {
    fn from(value: sc_client::error::Error) -> Self {
        Self::Lib(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.to_string()))
    }
}
