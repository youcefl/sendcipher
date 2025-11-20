/*
* Created on 2025.10.16
* Author: Youcef Lemsafer
* Copyright Youcef Lemsafer, all rights reserved.
*/

use digest::Digest;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::crypto::random::*;
use crate::span::Span;

pub(crate) struct SpanGenerator {
    seed: u128,
    activate_after_size: u64,
    min_span_size: u64,
    max_span_size: u64,
    last_two_spans: Vec<Span>,
    rng: ChaCha20Rng,
    current_size: u64,
}

impl SpanGenerator {
    /// Generates a new seed
    pub(crate) fn generate_seed() -> u128 {
        let seed_array: [u8; 16] = get_rand_bytes(16).unwrap().try_into().unwrap();
        u128::from_le_bytes(seed_array)
    }

    /// Creates an instance with a newly generated seed
    pub fn new(activate_after_size: u64, min_span_size: u64, max_span_size: u64) -> Self {
        Self::validate_size_range(min_span_size, max_span_size);
        Self::with_seed(
            activate_after_size,
            min_span_size,
            max_span_size,
            Self::generate_seed(),
        )
    }

    /// Creates an instance with a given seed
    pub fn with_seed(
        activate_after_size: u64,
        min_span_size: u64,
        max_span_size: u64,
        seed: u128,
    ) -> Self {
        Self::validate_size_range(min_span_size, max_span_size);
        let rng = ChaCha20Rng::from_seed(sha2::Sha256::digest(seed.to_le_bytes()).into());
        SpanGenerator {
            activate_after_size: activate_after_size,
            seed: seed,
            min_span_size: min_span_size as u64,
            max_span_size: max_span_size as u64,
            last_two_spans: Vec::new(),
            rng: rng,
            current_size: 0u64,
        }
    }

    /// Generate spans for cases where the target size is known
    pub fn generate_spans(&mut self, target_size: u64) -> Vec<Span> {
        let mut all_spans = Vec::<Span>::new();
        while self.current_size() < target_size {
            all_spans.push(self.next_span());
        }
        let first_changed_index = self.finalize(target_size);

        if !first_changed_index.is_some() {
            return all_spans;
        }

        let first_changed_index_val = first_changed_index.unwrap();
        all_spans
            .iter_mut()
            .skip(first_changed_index_val as usize)
            .zip(
                self.last_spans()
                    .iter()
                    .skip_while(|&e| e.index() != first_changed_index_val),
            )
            .for_each(|(u, v)| *u = v.clone());

        all_spans
    }

    /// Validates span size range
    ///
    /// Does basic validation of min and max span size, panics if min >= max
    /// otherwise does nothing.
    fn validate_size_range(min_span_size: u64, max_span_size: u64) {
        assert!(
            min_span_size < max_span_size,
            "SpanGenerator: minimum size must be smaller than maximum size"
        );
        assert!(
            min_span_size > 0,
            "SpanGenerator: minimum size must be non-zero"
        );
    }

    /// Returns total size of all spans generated so far
    pub fn current_size(&self) -> u64 {
        self.current_size
    }

    /// Returns the seed used for generating the random sequence of span sizes
    pub fn seed(&self) -> u128 {
        self.seed
    }

    /// Generates a new span
    pub fn next_span(&mut self) -> Span {
        match self.last_two_spans.len() {
            0 => {
                let new_span_size = self.new_span_size() as u64;
                self.last_two_spans
                    .push(Span::new(0u64, 0u64, new_span_size));
                self.current_size += new_span_size;
                self.last_two_spans.last().unwrap().clone()
            }
            1 | 2 => {
                if self.last_two_spans.len() == 2 {
                    self.last_two_spans.swap_remove(0);
                }
                let new_span = self.new_span(&self.last_two_spans[0].clone());
                let new_span_size = new_span.size();
                self.last_two_spans.push(new_span);
                self.current_size += new_span_size;
                self.last_two_spans.last().unwrap().clone()
            }
            _ => {
                panic!(
                    "Internal error: SpanGenerator: invariant broken: unexpected number of spans"
                );
            }
        }
    }

    /// Fixes the last two spans so that the size of the last span is in the expected
    /// range and the overall size is equal to a given target overall size, returns
    /// the index of the first span affected by the fix.
    /// The fix may leave the last two spans unchanged in which case the function does nothing
    /// and returns None.
    pub fn finalize(&mut self, target_overall_size: u64) -> Option<u64> {
        if self.last_two_spans.is_empty() {
            debug_assert!(
                target_overall_size == 0,
                "SpanGenerator: invalid state, finalize called without previous span generation"
            );
            return None;
        }

        if target_overall_size < self.current_size {
            let surplus = self.current_size - target_overall_size;
            //log::debug!("*** SpanGenerator: target size = {}, current size = {}, surplus = {}",
            //            target_overall_size, self.current_size, surplus);
            // Need to remove surplus from last span which may affect the previous one
            if self.last_two_spans.last().unwrap().size() >= surplus {
                let new_size = self.last_two_spans.last().unwrap().size() - surplus;
                //log::debug!("*** SpanGenerator: new_size = {}", new_size);
                self.current_size = target_overall_size;
                if new_size == 0 {
                    let last_span = self.last_two_spans.last_mut().unwrap();
                    last_span.resize(0u64);
                    return Some(last_span.index());
                } else if new_size < self.min_span_size {
                    // last span is going to be smaller than min size, we try to avoid that
                    // by taking from previous one if possible
                    if self.last_two_spans.len() < 2 {
                        // No previous span, there is nothing we can do
                        let last_span = self.last_two_spans.last_mut().unwrap();
                        //log::debug!("*** Resizing last span to {}", new_size);
                        last_span.resize(new_size);
                        return Some(last_span.index());
                    } else {
                        // Have previous span, try to take (min_span_size - new_size) from it
                        let (previous, last) = self.last_two_spans.split_at_mut(1);
                        let previous_span = &mut previous[0];
                        let last_span = &mut last[0];
                        //log::debug!("*** SpanGenerator: have to take from previous span, prev size = {}, last size = {}",
                        //    previous_span.size(), last_span.size());
                        if previous_span.size() > 2 * self.min_span_size - new_size {
                            previous_span
                                .resize(previous_span.size() - self.min_span_size + new_size);
                            *last_span = Span::new(
                                last_span.index(),
                                previous_span.end(),
                                previous_span.end() + self.min_span_size,
                            );
                            return Some(previous_span.index());
                        } else {
                            // Can't take from previous so merge last two
                            previous_span.resize(previous_span.size() + last_span.size() - surplus);
                            *last_span = Span::new(
                                last_span.index(),
                                previous_span.end(),
                                previous_span.end(),
                            );
                            return Some(previous_span.index());
                        }
                    }
                } else {
                    // new_size >= self.min_span_size
                    let last_span = self.last_two_spans.last_mut().unwrap();
                    //log::debug!("*** SpanGenerator: resizing span {} to {}", last_span.index(), new_size);
                    last_span.resize(new_size);
                    return Some(last_span.index());
                }
            } else {
                // Last span is smaller than surplus
                // Should never happen! Missing call to next_span detected.
                //log::debug!("Current size: {}", self.current_size);
                assert!(
                    false,
                    "SpanGenerator: missing call to next_span before finalize"
                );
                None
            }
        } else if target_overall_size > self.current_size {
            // Should not happen! Missing call to next_span
            assert!(
                false,
                "SpanGenerator: missing call to next_span before finalize"
            );
            None
        } else {
            // target_overall_size == self.current_size
            // Nothing to do in this case
            None
        }
    }

    /// Returns the last span
    /// @pre next_span has been called at least once
    pub fn last_span(&self) -> Span {
        self.last_two_spans.last().unwrap().clone()
    }

    pub fn last_spans(&self) -> Vec<Span> {
        self.last_two_spans.clone()
    }

    fn new_span_size(&mut self) -> u64 {
        self.rng.gen_range(self.min_span_size..=self.max_span_size) as u64
    }

    fn new_span(&mut self, previous_span: &Span) -> Span {
        let index_of_previous = previous_span.index();
        let end_of_previous = previous_span.end();
        Span::new(
            index_of_previous + 1,
            end_of_previous,
            end_of_previous + self.new_span_size(),
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use proptest::prelude::*;
    use test_case::test_case;

    const MIN_SPAN_SIZE: u64 = 4 * 1024 * 1024;
    const MAX_SPAN_SIZE: u64 = 16 * 1024 * 1024;

    fn generate_spans(target_size: u64) -> (SpanGenerator, Vec<Span>) {
        let mut spgen = SpanGenerator::with_seed(0, MIN_SPAN_SIZE, MAX_SPAN_SIZE, 1u128);
        let all_spans = spgen.generate_spans(target_size);
        (spgen, all_spans)
    }

    #[test]
    fn test_one_span() {
        let mut spgen = SpanGenerator::with_seed(0, MIN_SPAN_SIZE, MAX_SPAN_SIZE, 1u128);
        let span_1 = spgen.next_span();
        assert!(span_1.size() >= MIN_SPAN_SIZE as u64);
        assert_eq!(spgen.current_size(), span_1.size());

        let target_size: u64 = 7 * 1024 * 1024;
        assert!(spgen.current_size() >= target_size);
        let first_changed = spgen.finalize(target_size);

        let last_span = spgen.last_span();
        assert_eq!(last_span.index(), 0);
        assert_eq!(last_span.start(), 0u64);
        assert_eq!(last_span.end(), target_size);
        assert_eq!(last_span.size(), target_size);
        assert!(first_changed.is_some());
        assert_eq!(first_changed.unwrap(), 0);
    }

    #[test]
    fn test_two_spans() {
        let mut spgen = SpanGenerator::with_seed(0, MIN_SPAN_SIZE, MAX_SPAN_SIZE, 1u128);
        let span_1 = spgen.next_span();
        let span_2 = spgen.next_span();
        assert_eq!(span_1.index(), 0);
        assert_eq!(span_2.index(), 1);
        assert_eq!(span_1.size() + span_2.size(), spgen.current_size());
        let target_size = (span_1.size() + spgen.current_size()) / 2;

        let first_changed = spgen.finalize(target_size);

        let last_spans = spgen.last_spans();
        assert_eq!(last_spans.len(), 2);
        assert!(first_changed.is_some());
        assert_eq!(first_changed.unwrap(), 1);
        assert_eq!(last_spans[0].size() + last_spans[1].size(), target_size);
        assert_eq!(spgen.current_size(), target_size);
    }

    #[test_case(37_098_979u64)]
    #[test_case(40_742_172u64)]
    #[test_case(40_742_173u64)]
    #[test_case(40_742_174u64)]
    #[test_case(71_923_298u64)]
    #[test_case(99_101_007u64)]
    fn test_n_spans(target_size: u64) {
        let (spgen, all_spans) = generate_spans(target_size);

        assert_eq!(spgen.current_size(), target_size);
        let sizes_sum: u64 = all_spans.iter().map(|span| span.size()).sum();
        assert_eq!(sizes_sum, target_size);
        assert!(
            all_spans.windows(2).all(|w| w[0].end() == w[1].start()),
            "Spans are not properly adjacent"
        );
    }

    proptest! {

        #[test]
        fn generated_spans_size_is_target_size(target_size in 991u64..105_906_176u64) {
            let (spgen, all_spans) = generate_spans(target_size);

            assert_eq!(spgen.current_size(), target_size);
            let total: u64 = all_spans.iter().map(|s| s.size()).sum();
            assert_eq!(total, target_size);
        }


        #[test]
        fn spans_are_contiguous(target_size in 991u64..105_906_176u64) {
            let (_, all_spans) = generate_spans(target_size);
            assert!(all_spans.windows(2).all(|w| w[0].end() == w[1].start()),
               "Spans should be contiguous");
        }

    }
}
