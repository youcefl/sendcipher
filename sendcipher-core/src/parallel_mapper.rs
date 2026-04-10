/* Created on 2025.12.03 */
/* Copyright (c) 2025-2026 Youcef Lemsafer */
/* SPDX-License-Identifier: MIT */

use parking_lot::{Condvar, Mutex};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;

pub struct ParallelMapper<Input, Output, Map>
where
    Input: Send + 'static,
    Output: Send + 'static,
    Map: Fn(Input) -> Output + Send + Sync + 'static,
{
    /// The maximum number of workers in this parallel workshop
    max_workers: u32,
    /// Number of active/busy workers
    active_workers_count: Arc<AtomicU32>,
    /// The working class
    workers: Vec<thread::JoinHandle<()>>,
    /// Number of pending work items
    pending: Arc<AtomicU32>,
    /// Condition variable to notify about full work queue
    queue_filled_cond: Arc<Condvar>,
    /// Condition variable to notify about empty work queue
    queue_empty_cond: Arc<Condvar>,
    /// Work queue (has at most one element)
    work_queue: Arc<Mutex<Option<Input>>>,
    /// Whether to shutdown i.e. no more work
    is_shutdown: Arc<AtomicBool>,
    /// Condition variable notifying about result availability
    new_result_cond: Arc<Condvar>,
    /// The results produced by the workers
    results: Arc<Mutex<Vec<Output>>>,
    /// The transformation performed by the workers on the input they receive
    map: Arc<Map>,
}

impl<Input, Output, Map> ParallelMapper<Input, Output, Map>
where
    Input: Send + 'static,
    Output: Send + 'static,
    Map: Fn(Input) -> Output + Send + Sync + 'static,
{
    pub fn new(max_workers: u32, map: Map) -> Self {
        Self {
            max_workers,
            active_workers_count: Arc::new(AtomicU32::new(0u32)),
            // Lazy creation of workers
            workers: Vec::with_capacity(max_workers as usize),
            pending: Arc::new(AtomicU32::new(0u32)),
            queue_filled_cond: Arc::new(Condvar::new()),
            queue_empty_cond: Arc::new(Condvar::new()),
            work_queue: Arc::new(Mutex::new(None)),
            is_shutdown: Arc::new(AtomicBool::new(false)),
            new_result_cond: Arc::new(Condvar::new()),
            results: Arc::new(Mutex::new(Vec::new())),
            map: Arc::new(map),
        }
    }

    pub fn concurrency(&self) -> u32 {
        self.max_workers
    }

    pub fn push(&mut self, input: Input) {
        debug_assert!(!self.is_shutdown.load(Ordering::Relaxed));
        self.pending.fetch_add(1, Ordering::AcqRel);
        // The fast and easy path, no worker yet, push input and create a worker
        if self.workers.is_empty() {
            {
                let mut wq = self.work_queue.lock();
                debug_assert!(wq.is_none());
                wq.insert(input);
            }
            return self.spawn_worker();
        }

        // Wait for the queue to become available
        let mut wq = self.work_queue.lock();
        while wq.is_some() {
            self.queue_empty_cond.wait(&mut wq);
        }
        wq.insert(input);
        self.queue_filled_cond.notify_one();
        drop(wq);

        let are_all_busy =
            self.active_workers_count.load(Ordering::Relaxed) == self.workers.len() as u32;
        if are_all_busy && self.workers.len() < self.max_workers as usize {
            self.spawn_worker();
        }
    }

    /// Pops and returns result if any
    pub fn pop_result(&mut self) -> Option<Output> {
        let mut results = self.results.lock();
        if results.is_empty() {
            return None;
        }
        results.pop()
    }

    /// Pops and returns all results if any
    pub fn pop_all(&mut self) -> Vec<Output> {
        let mut results = self.results.lock();
        std::mem::take(results.as_mut())
    }

    /// Processes the provided inputs in parallel.
    /// 
    /// # Ordering
    /// The order of outputs is **not guaranteed** to match the input order.
    /// Outputs are returned in completion order.
    pub fn process_all<I>(&mut self, inputs: I) -> Vec<Output>
    where
        I: IntoIterator,
        I::Item: std::borrow::Borrow<Input>,
        Input: Clone,
    {
        inputs.into_iter().for_each(|input| {
            self.push(std::borrow::Borrow::borrow(&input).clone());
        });
        self.wait();
        self.pop_all()
    }

    pub fn wait(&self) {
        if self.is_shutdown.load(Ordering::Relaxed) {
            return;
        }
        while self.pending.load(Ordering::Relaxed) != 0 {
            let mut res = self.results.lock();
            while res.is_empty() {
                self.new_result_cond.wait(&mut res);
            }
        }
    }

    pub fn finish(&mut self) -> Vec<Output> {
        self.is_shutdown.store(true, Ordering::Relaxed);
        self.queue_filled_cond.notify_all();
        for w in self.workers.drain(..) {
            w.join();
        }
        let mut results = self.results.lock();
        std::mem::take(results.as_mut())
    }

    fn spawn_worker(&mut self) {
        let is_shutdown = Arc::clone(&self.is_shutdown);
        let active_workers_count = Arc::clone(&self.active_workers_count);
        let pending = Arc::clone(&self.pending);
        let work_queue = Arc::clone(&self.work_queue);
        let queue_empty_cond = Arc::clone(&self.queue_empty_cond);
        let queue_filled_cond = Arc::clone(&self.queue_filled_cond);
        let new_result_cond = Arc::clone(&self.new_result_cond);
        let results = Arc::clone(&self.results);
        let map = Arc::clone(&self.map);
        //let worker_id = self.workers.len() + 1;

        self.workers.push(thread::spawn(move || {
            //  println!("Worker {} starts", worker_id);
            loop {
                //    println!("Worker {} loops", worker_id);
                let mut input = {
                    let mut wq = work_queue.lock();
                    queue_filled_cond.wait_while(&mut wq, |q| {
                        q.is_none() && !is_shutdown.load(Ordering::Acquire)
                    });
                    active_workers_count.fetch_add(1, Ordering::AcqRel);
                    let inpt = wq.take();
                    queue_empty_cond.notify_one();
                    inpt
                };
                if input.is_none() && is_shutdown.load(Ordering::Acquire) {
                    active_workers_count.fetch_sub(1, Ordering::AcqRel);
                    break;
                }
                if input.is_some() {
                    //        println!("Worker {} processes {}", worker_id, *input.as_ref().unwrap());
                    let result = map(input.take().unwrap());
                    results.lock().push(result);
                    pending.fetch_sub(1, Ordering::AcqRel);
                    new_result_cond.notify_one();
                }
                active_workers_count.fetch_sub(1, Ordering::AcqRel);
            }
            //  println!("Worker {} ends", worker_id);
        }));
    }
}

impl<Input, Output, Map> Drop for ParallelMapper<Input, Output, Map>
where
    Input: Send + 'static,
    Output: Send + 'static,
    Map: Fn(Input) -> Output + Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.is_shutdown.store(true, Ordering::Relaxed);
        self.queue_filled_cond.notify_all();
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

pub struct DynParallelMapper<Input, Output>
where
    Input: Send + 'static,
    Output: Send + 'static,
{
    par_mapper: ParallelMapper<Input, Output, Box<dyn Fn(Input) -> Output + Send + Sync>>,
}

impl<Input, Output> DynParallelMapper<Input, Output>
where
    Input: Send + 'static,
    Output: Send + 'static,
{
    pub fn new(max_workers: u32, map: Box<dyn Fn(Input) -> Output + Send + Sync>) -> Self {
        Self {
            par_mapper: ParallelMapper::new(max_workers, map),
        }
    }
    pub fn concurrency(&self) -> u32 {
        self.par_mapper.concurrency()
    }
    pub fn process_all<I>(&mut self, inputs: I) -> Vec<Output>
    where
        I: IntoIterator,
        I::Item: std::borrow::Borrow<Input>,
        Input: Clone,
    {
        self.par_mapper.process_all(inputs)
    }
    pub fn push(&mut self, input: Input) {
        self.par_mapper.push(input)
    }
    pub fn pop(&mut self) -> Option<Output> {
        self.par_mapper.pop_result()
    }
    pub fn pop_all(&mut self) -> Vec<Output> {
        self.par_mapper.pop_all()
    }
    pub fn wait(&self) {
        self.par_mapper.wait();
    }
    pub fn finish(&mut self) -> Vec<Output> {
        self.par_mapper.finish()
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use crate::parallel_mapper::{DynParallelMapper, ParallelMapper};

    #[test]
    fn test_basic_workers() {
        let mut square_computers = ParallelMapper::<i32, i32, _>::new(4, |x| {
            std::thread::sleep(Duration::from_millis(50));
            x * x
        });

        (1..5).for_each(|x| square_computers.push(x));
        let res = square_computers.finish();

        assert_eq!(4, res.len());
        assert!(res.contains(&1));
        assert!(res.contains(&4));
        assert!(res.contains(&9));
        assert!(res.contains(&16));
    }

    #[test]
    fn test_workers_with_various_completion_time() {
        let mut par_mapper = ParallelMapper::<i32, i32, _>::new(4, |x| {
            thread::sleep(Duration::from_micros(x as u64));
            x * x
        });
        let inputs = [17, 11, 7, 23, 61, 31, 79];
        let first_batch_len = 4;
        (0..first_batch_len).for_each(|i| par_mapper.push(inputs[i]));

        assert!(par_mapper.workers.len() <= 4);

        let res1 = par_mapper.pop_result();
        (first_batch_len..inputs.len()).for_each(|i| par_mapper.push(inputs[i]));

        assert!(par_mapper.workers.len() <= 4);

        let res2 = par_mapper.pop_result();
        let mut results = Vec::new();
        if res1.is_some() {
            results.push(res1.unwrap());
        }
        if res2.is_some() {
            results.push(res2.unwrap());
        }
        results.extend(par_mapper.finish());
        results.sort();

        let mut expected_outputs = inputs.map(|x| x * x);
        expected_outputs.sort();
        assert_eq!(results, expected_outputs);
    }

    #[test]
    fn test_drop_parallel_mapper_instance() {
        let mut par_mapper = ParallelMapper::<i32, i32, _>::new(4, |x| {
            thread::sleep(Duration::from_micros(100));
            x * x
        });
        let inputs_count = 16;
        (0..inputs_count).for_each(|x| par_mapper.push(x));
        drop(par_mapper);
    }

    #[test]
    fn test_interleave_push_pop() {
        let mut workers = ParallelMapper::<i32, i32, _>::new(4, |x| {
            thread::sleep(Duration::from_micros(if x % 2 != 0 { 20 } else { 12 }));
            x * x
        });

        let iterations_count = 1024i32;
        let mut results = Vec::<i32>::with_capacity(iterations_count as usize);
        (0..iterations_count).for_each(|x| {
            workers.push(x);
            if let Some(res) = workers.pop_result() {
                results.push(res);
            }
        });
        results.extend(workers.finish());
        results.sort();
        let expected_results = (0..iterations_count).map(|x| x * x).collect::<Vec<i32>>();

        assert_eq!(results.len(), expected_results.len());
        assert_eq!(results, expected_results);
    }

    #[test]
    fn test_wait() {
        let mut par_mapper = ParallelMapper::<u32, u32, _>::new(4, |x|{
            thread::sleep(Duration::from_micros(x as u64));
            x * x
        });

        let inputs: Vec<u32> = vec![2, 7, 97, 31, 257, 929, 19, 313];
        let mut results = Vec::<u32>::with_capacity(inputs.len());
        inputs.iter().for_each(|x| {
            par_mapper.push(*x);
            results.extend(par_mapper.pop_all());
        });
        par_mapper.wait();
        results.extend(par_mapper.pop_all());
        results.sort();

        let mut expected: Vec<u32> = inputs.iter().map(|x| x*x).collect();
        expected.sort();

        assert_eq!(results.len(), expected.len());
        assert_eq!(results, expected);
    }

    #[test]
    fn test_process_all() {
        let mut workers = ParallelMapper::<u32, u32, _>::new(4, |x| {
            thread::sleep(Duration::from_micros(x as u64));
            x * x
        });
        let inputs = vec![23, 11, 67, 251, 7, 8, 641, 37];
        let mut res = workers.process_all(&inputs);

        let mut expected: Vec<u32> = inputs.iter().map(|x| x*x).collect();
        res.sort();
        expected.sort();
        assert_eq!(res, expected);
    }

    #[test]
    fn test_dyn_parallel_mapper() {
        let mut par_mapper = DynParallelMapper::<i32, i32>::new(4, Box::new(|x| x * x));
        par_mapper.push(5);
        par_mapper.push(7);
        thread::sleep(Duration::from_millis(10));
        let mut results = par_mapper.pop_all();
        results.extend(par_mapper.finish());

        assert_eq!(results.len(), 2 as usize);
        assert!(results.contains(&25));
        assert!(results.contains(&49));
    }
}
