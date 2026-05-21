use memmap2::{MmapMut, MmapOptions};
use parking_lot::RwLock;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

pub static GLOBAL_SHARED_CONNECTION_TABLE: LazyLock<RwLock<Option<SharedConnectionTable>>> =
    LazyLock::new(|| RwLock::new(None));

/// Shared connection table for distributed load balancing with worker liveness.
/// 
/// Layout:
/// - [0..8]: max_workers (u64)
/// - [8..16]: max_backends (u64)
/// - [16..16 + max_workers * 8]: heartbeats (AtomicU64)
/// - [16 + max_workers * 8 .. ]: connections (AtomicUsize) [worker_id][backend_index]
pub struct SharedConnectionTable {
    mmap: Arc<MmapMut>,
    max_workers: usize,
    max_backends: usize,
}

impl SharedConnectionTable {
    pub fn init_global(path: PathBuf, max_workers: usize, max_backends: usize) -> std::io::Result<()> {
        let table = Self::new(path, max_workers, max_backends)?;
        let mut global = GLOBAL_SHARED_CONNECTION_TABLE.write();
        *global = Some(table);
        Ok(())
    }

    pub fn get_global() -> Option<SharedConnectionTable> {
        GLOBAL_SHARED_CONNECTION_TABLE.read().as_ref().cloned()
    }

    pub fn new(path: PathBuf, max_workers: usize, max_backends: usize) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;

        let header_size = 16;
        let heartbeats_size = max_workers * 8;
        let connections_size = max_workers * max_backends * std::mem::size_of::<AtomicUsize>();
        let total_size = header_size + heartbeats_size + connections_size;

        file.set_len(total_size as u64)?;

        let mmap = unsafe { MmapOptions::new().map_mut(&file)? };
        
        // Initialize header
        unsafe {
            let ptr = mmap.as_ptr() as *mut u64;
            ptr.write(max_workers as u64);
            ptr.add(1).write(max_backends as u64);
        }

        Ok(Self {
            mmap: Arc::new(mmap),
            max_workers,
            max_backends,
        })
    }

    pub fn record_heartbeat(&self, worker_id: usize, timestamp: u64) {
        if let Some(h) = self.get_heartbeat_atomic(worker_id) {
            h.store(timestamp, Ordering::SeqCst);
        }
    }

    pub fn get_heartbeat_atomic(&self, worker_id: usize) -> Option<&AtomicU64> {
        if worker_id >= self.max_workers {
            return None;
        }
        let offset = 16 + worker_id * 8;
        let ptr = unsafe { self.mmap.as_ptr().add(offset) } as *const AtomicU64;
        Some(unsafe { &*ptr })
    }

    pub fn get_counter_atomic(&self, worker_id: usize, backend_index: usize) -> Option<&AtomicUsize> {
        if worker_id >= self.max_workers || backend_index >= self.max_backends {
            return None;
        }
        let offset = 16 + self.max_workers * 8 + (worker_id * self.max_backends + backend_index) * std::mem::size_of::<AtomicUsize>();
        let ptr = unsafe { self.mmap.as_ptr().add(offset) } as *const AtomicUsize;
        Some(unsafe { &*ptr })
    }

    pub fn sum_active_connections(&self, backend_index: usize, timeout_secs: u64) -> usize {
        if backend_index >= self.max_backends {
            return 0;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut total = 0;
        for w in 0..self.max_workers {
            if let Some(h) = self.get_heartbeat_atomic(w) {
                let last_h = h.load(Ordering::Relaxed);
                if now.saturating_sub(last_h) <= timeout_secs {
                    if let Some(c) = self.get_counter_atomic(w, backend_index) {
                        total += c.load(Ordering::Relaxed);
                    }
                }
            }
        }
        total
    }

    pub fn max_backends(&self) -> usize {
        self.max_backends
    }

    pub fn max_workers(&self) -> usize {
        self.max_workers
    }
}

impl Clone for SharedConnectionTable {
    fn clone(&self) -> Self {
        Self {
            mmap: self.mmap.clone(),
            max_workers: self.max_workers,
            max_backends: self.max_backends,
        }
    }
}
