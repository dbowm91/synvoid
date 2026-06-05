use std::sync::atomic::{AtomicUsize, Ordering};

pub static CURRENT_WORKER_ID: AtomicUsize = AtomicUsize::new(0);

pub fn set_current_worker_id(id: usize) {
    CURRENT_WORKER_ID.store(id, Ordering::SeqCst);
}

pub fn get_current_worker_id() -> usize {
    CURRENT_WORKER_ID.load(Ordering::SeqCst)
}
