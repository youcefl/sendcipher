/* Created on 2025.11.05 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use crate::crypto::blob_header::*;
use crate::crypto::metadata::*;

#[derive(Debug, Default)]
pub struct Blob {
    /// Fully equipped serialized blob: header + ciphertext
    raw: Vec<u8>,
    /// Parsed header, lazily evaluated from raw
    header: Option<BlobHeader>,
    /// Position of the first byte after the header
    pos_after_header: Option<u64>,
}

impl Blob {
    pub fn new(raw_blob: Vec<u8>) -> Self {
        Blob {
            raw: raw_blob,
            header: None,
            pos_after_header: None,
        }
    }

    pub(crate) fn new_parsed(raw: Vec<u8>, blob_header: BlobHeader, pos_after_header: u64) -> Self {
        Self {
            raw: raw,
            header: Some(blob_header),
            pos_after_header: Some(pos_after_header),
        }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.raw
    }
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.raw
    }

    pub fn parse_header(&mut self) -> Result<&mut Self, crate::error::Error> {
        let (header, pos) = BlobHeader::parse(&self.raw)?;
        self.header = Some(header);
        self.pos_after_header = Some(pos);
        Ok(self)
    }

    pub fn get_header(&self) -> &Option<BlobHeader> {
        &self.header
    }

    pub fn get_position_after_header(&self) -> Option<u64> {
        self.pos_after_header
    }
}

pub struct DecryptedBlob {
    /// The header read from the blob
    header: Option<BlobHeader>,
    /// The metadata revealed by decrypting the ciphertext
    metadata: Option<Metadata>,
    /// Clear text
    text: Vec<u8>,
}

impl DecryptedBlob {
    pub fn new(header: BlobHeader, text: Vec<u8>, metadata: Metadata) -> Self {
        Self {
            header: Some(header),
            metadata: Some(metadata),
            text: text,
        }
    }

    pub fn get_blob_header(&self) -> &Option<BlobHeader> {
        &self.header
    }

    pub fn get_metadata(&self) -> &Option<Metadata> {
        &self.metadata
    }

    pub fn get_text(&self) -> &Vec<u8> {
        &self.text
    }
    pub fn get_text_mut(&mut self) -> &mut Vec<u8> {
        &mut self.text
    }
}
