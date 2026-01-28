/* Created on 2026.01.25 */
/* Copyright Youcef Lemsafer, all rights reserved */

use std::ops::Mul;
use std::sync::{Arc, Mutex, atomic::*};
use std::thread::JoinHandle;
use std::time::Duration;


pub(crate) trait AtomicOf {
    type Atomic;
    fn new_atomic(v: Self) -> Self::Atomic;
    fn load(a: &Self::Atomic, ordering: Ordering) -> Self;
    fn fetch_add(a: &Self::Atomic, v: Self, ordering: Ordering) -> Self;
    fn as_f64(val: Self) -> f64;
}

pub(crate) struct Progress<T>
where
    T: AtomicOf + Send + Copy + PartialEq + Default + 'static,
    <T as AtomicOf>::Atomic: Send + Sync,
{
    current_value: Arc<<T as AtomicOf>::Atomic>,
    target_value: T,
    period: Duration,
    worker: Mutex<Option<JoinHandle<()>>>,
    is_finished: Arc<AtomicBool>,
}

impl AtomicOf for u64 {
    type Atomic = AtomicU64;
    fn new_atomic(v: u64) -> AtomicU64 {
        AtomicU64::new(v)
    }

    fn load(a: &AtomicU64, ordering: Ordering) -> u64 {
        a.load(ordering)
    }

    fn fetch_add(a: &AtomicU64, v: Self, ordering: Ordering) -> u64 {
        a.fetch_add(v, ordering)
    }

    fn as_f64(val: u64) -> f64 {
        val as f64
    }
}

impl<T: AtomicOf + Send + Copy + PartialEq + Default + 'static> Progress<T>
where
    <T as AtomicOf>::Atomic: Send + Sync,
{
    //type AtomicT = <T as AtomicOf>::Atomic;

    pub fn new(
        initial_value: T,
        target_value: T,
        refresh_period: Duration,
        on_progress_update: Box<dyn Fn(f64) -> () + Send + Sync>,
    ) -> Self {
        let current_value = Arc::new(<T as AtomicOf>::new_atomic(initial_value));
        let is_finished = Arc::new(AtomicBool::default());
        Self {
            current_value: current_value.clone(),
            target_value,
            period: refresh_period,
            worker: Mutex::new(Some(Self::create_worker(
                current_value.clone(),
                target_value,
                refresh_period,
                is_finished.clone(),
                on_progress_update,
            ))),
            is_finished
        }
    }

    pub fn add(&self, increment: T) {
        T::fetch_add(self.current_value.as_ref(), increment, Ordering::Relaxed);
    }

    pub fn end(&self) {
        self.is_finished.store(true, Ordering::Relaxed);
        if let Some(handle) = self.worker.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    fn create_worker(
        current_value: Arc<<T as AtomicOf>::Atomic>,
        target_value: T,
        period: Duration,
        is_finished: Arc<AtomicBool>,
        on_progress_update: Box<dyn Fn(f64) -> () + Send + Sync>,
    ) -> JoinHandle<()> {
        std::thread::spawn(move || {
            loop {
                let progress_percent = if target_value == T::default() {
                    100.0
                } else {
                    T::as_f64(T::load(current_value.as_ref(), Ordering::Relaxed))
                        / T::as_f64(target_value)
                        * 100.0
                };
                on_progress_update(progress_percent);
                if is_finished.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(period);
            }
        })
    }
}

impl<T: AtomicOf + Send + Copy + PartialEq + Default + 'static> Drop for Progress<T>
where
    <T as AtomicOf>::Atomic: Send + Sync,
{
    fn drop(&mut self) {
        self.end();
    }
}
