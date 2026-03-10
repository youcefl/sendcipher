/* Created on 2025-10-27 */
/* Copyright Youcef Lemsafer, all rights reserved. */

use crate::span::*;
use crate::span_generator::*;
use std::sync::Arc;

#[derive(Clone)]
pub struct Chunk {
    span: Span,
    data: Arc<Vec<u8>>,
}
pub trait ChunkGenerator: Send + Sync {
    fn process_data(&mut self, data: &[u8]) -> Vec<Chunk>;
    fn signal_eos(&mut self) -> Vec<Chunk>;
    /// Total number of chunks generated
    fn chunks_count(&self) -> u64;
    /// Total number of bytes received by the generator
    fn chunked_bytes_count(&self) -> u64;
}

impl Chunk {
    pub fn index(&self) -> u64 {
        self.span.index()
    }
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
    pub fn span(&self) -> &Span {
        &self.span
    }
}

struct ProtoChunk {
    span: Span,
    data: Vec<u8>,
    is_ready: bool,
}

impl ProtoChunk {
    pub fn index(&self) -> u64 {
        self.span.index()
    }
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
    pub fn span(&self) -> &Span {
        &self.span
    }
    pub fn span_mut(&mut self) -> &mut Span {
        &mut self.span
    }
    pub fn is_ready(&self) -> bool {
        self.is_ready
    }
    pub fn set_is_ready(&mut self, is_ready: bool) {
        self.is_ready = is_ready;
    }
}

pub struct RandomChunkGenerator {
    /// Spans generator used for chunk sizes computation
    span_generator: SpanGenerator,
    chunks: Vec<ProtoChunk>,
    chunks_count: u64,
    chunked_bytes: u64,
}

impl ChunkGenerator for RandomChunkGenerator {
    fn process_data(&mut self, data: &[u8]) -> Vec<Chunk> {
        let mut remaining_data_offset = 0 as usize;
        while remaining_data_offset != data.len() {
            let mut available_space = if self.chunks.is_empty() {
                0u64
            } else {
                let last_chunk = self.chunks.last().unwrap();
                last_chunk.span().size() - last_chunk.size() as u64
            };
            if available_space == 0 {
                self.add_new_chunk();
                available_space = self.chunks.last().unwrap().span().size();
            }
            let copyable_amount =
                ((data.len() - remaining_data_offset) as usize).min(available_space as usize);
            let last_chunk = self.chunks.last_mut().unwrap();
            last_chunk.data_mut().extend_from_slice(
                &data[remaining_data_offset..remaining_data_offset + copyable_amount],
            );
            remaining_data_offset += copyable_amount;
        }
        self.chunked_bytes += data.len() as u64;
        self.update_chunk_readiness();

        let ready_count = self.chunks.iter().take_while(|c| c.is_ready()).count();
        self.chunks
            .drain(0..ready_count)
            .map(|x| Chunk {
                span: x.span,
                data: Arc::new(x.data),
            })
            .collect()
    }

    fn signal_eos(&mut self) -> Vec<Chunk> {
        self.adjust_last_chunks();
        self.chunks
            .drain(0..)
            .map(|x| Chunk {
                span: x.span,
                data: Arc::new(x.data),
            })
            .collect()
    }

    fn chunks_count(&self) -> u64 {
        self.chunks_count
    }

    fn chunked_bytes_count(&self) -> u64 {
        self.chunked_bytes
    }
}

impl RandomChunkGenerator {
    pub fn new(chunking_threshold: u64, min_chunk_size: u64, max_chunk_size: u64) -> Self {
        Self {
            span_generator: SpanGenerator::new(chunking_threshold, min_chunk_size, max_chunk_size),
            chunks: Vec::new(),
            chunks_count: 0,
            chunked_bytes: 0u64,
        }
    }

    pub fn with_seed(
        chunking_threshold: u64,
        min_chunk_size: u64,
        max_chunk_size: u64,
        seed: u128,
    ) -> Self {
        Self {
            span_generator: SpanGenerator::with_seed(
                chunking_threshold,
                min_chunk_size,
                max_chunk_size,
                seed,
            ),
            chunks: Vec::new(),
            chunks_count: 0,
            chunked_bytes: 0u64,
        }
    }

    fn add_new_chunk(&mut self) -> &mut ProtoChunk {
        let chunk = ProtoChunk {
            span: self.span_generator.next_span(),
            data: Vec::new(),
            is_ready: false,
        };
        self.chunks.push(chunk);
        self.chunks_count += 1;
        self.chunks.last_mut().unwrap()
    }

    /// Updates the chunks readiness status
    ///
    /// This has to be called after each slice of data received by process_data
    fn update_chunk_readiness(&mut self) {
        // Skip last two because the last two can become ready only after finalize is called.
        self.chunks
            .iter_mut()
            .rev()
            .skip(2)
            .take_while(|chnk| !chnk.is_ready())
            .for_each(|chnk| chnk.set_is_ready(true));
    }

    /// Performs the necessary adjustements when the final size is known (i.e. upon finalization).
    pub fn adjust_last_chunks(&mut self) {
        // Now all chunks are ready, we mark them as such
        self.chunks
            .iter_mut()
            .take_while(|chnk| !chnk.is_ready())
            .for_each(|chnk| chnk.set_is_ready(true));
        let opt_first_changed_index = self.span_generator.finalize(self.chunked_bytes);
        // Move data over if at least one of the last two spans changed
        if opt_first_changed_index.is_none() {
            return;
        }
        let first_changed_index = opt_first_changed_index.unwrap();
        // Get the first changed span/chunk
        let pos_in_chunks = self
            .chunks
            .iter()
            .rposition(|chnk| chnk.index() == first_changed_index)
            .unwrap();
        let last_spans = self.span_generator.last_spans();
        let pos_in_spans = last_spans
            .iter()
            .rposition(|sp| sp.index() == first_changed_index)
            .unwrap();
        let chunk_data_len = self.chunks[pos_in_chunks].data().len();
        if chunk_data_len as u64 > last_spans[pos_in_spans].size() {
            // Move surplus to next chunk
            let surplus = chunk_data_len - last_spans[pos_in_spans].size() as usize;
            let (left_chunks, right_chunks) = self.chunks.split_at_mut(pos_in_chunks + 1);
            let lchunk = left_chunks.last_mut().unwrap();
            let rchunk = right_chunks.first_mut().unwrap();
            rchunk
                .data_mut()
                .splice(0..0, lchunk.data_mut().split_off(chunk_data_len - surplus));
        } else if (chunk_data_len as u64) < last_spans[pos_in_spans].size() {
            // Take deficit from next chunk if any
            if pos_in_chunks + 1 < self.chunks.len() {
                let deficit = last_spans[pos_in_spans].size() as usize - chunk_data_len;
                let (left_chunks, right_chunks) = self.chunks.split_at_mut(pos_in_chunks + 1);
                let lchunk = left_chunks.last_mut().unwrap();
                let rchunk = right_chunks.first_mut().unwrap();
                lchunk
                    .data_mut()
                    .extend(rchunk.data_mut().drain(0..deficit));
            }
        }
        // @todo: what if last chunk size became 0 ???
        self.chunks
            .iter_mut()
            .skip(pos_in_chunks)
            .zip(last_spans.iter().skip(pos_in_spans))
            .for_each(|(chnk, spn)| *chnk.span_mut() = spn.clone());
    }
}
