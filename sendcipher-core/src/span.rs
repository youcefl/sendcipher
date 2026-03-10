/*
* Created on 2025.10.16
* Author: Youcef Lemsafer
* Copyright Youcef Lemsafer, all rights reserved.
*/

#[derive(Clone)]
pub struct Span {
    index: u64,
    start: u64,
    end: u64,
}

impl Span {
    pub fn new(index: u64, first: u64, last: u64) -> Self {
        Span {
            index,
            start: first,
            end: last,
        }
    }
    pub fn index(&self) -> u64 {
        self.index
    }
    pub fn start(&self) -> u64 {
        self.start
    }
    pub fn end(&self) -> u64 {
        self.end
    }
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
    pub fn resize(&mut self, new_size: u64) {
        self.end = self.start + new_size
    }
}
