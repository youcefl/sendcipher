pub mod chunking;
pub mod error;
pub mod stream_decryptor;
pub mod stream_encryptor;
pub mod parallel_mapper;

pub mod crypto;
mod lcg;
mod span;
mod span_generator;

#[cfg(feature = "wasm")]
pub mod wasm_file_encryptor;
#[cfg(feature = "wasm")]
pub mod wasm_file_decryptor;
#[cfg(test)]
mod stream_cypher_tests;
#[cfg(test)]
mod test_utils;
