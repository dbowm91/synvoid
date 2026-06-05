use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct RunningFlag {
    inner: Arc<AtomicBool>,
}

impl RunningFlag {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(true)),
        }
    }

    #[inline]
    pub fn is_running(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    #[inline]
    pub fn get(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    #[inline]
    pub fn stop(&self) {
        self.inner.store(false, Ordering::Release);
    }

    #[inline]
    pub fn set(&self, value: bool) {
        self.inner.store(value, Ordering::Release);
    }
}

impl Default for RunningFlag {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct DrainFlag {
    inner: Arc<AtomicBool>,
}

impl DrainFlag {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    #[inline]
    pub fn is_draining(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    #[inline]
    pub fn get(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    #[inline]
    pub fn start_drain(&self) {
        self.inner.store(true, Ordering::Release);
    }

    #[inline]
    pub fn end_drain(&self) {
        self.inner.store(false, Ordering::Release);
    }

    #[inline]
    pub fn set(&self, value: bool) {
        self.inner.store(value, Ordering::Release);
    }
}

impl Default for DrainFlag {
    fn default() -> Self {
        Self::new()
    }
}
