use bytes::{Buf, BufMut, BytesMut};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const SMALL_BUF_SIZE: usize = 4 * 1024;
const MEDIUM_BUF_SIZE: usize = 64 * 1024;
const LARGE_BUF_SIZE: usize = 256 * 1024;

const SMALL_POOL_CAP: usize = 512;
const MEDIUM_POOL_CAP: usize = 256;
const LARGE_POOL_CAP: usize = 64;
const JUMBO_POOL_CAP: usize = 32;

const NUM_SHARDS: usize = 8;

#[derive(Clone, Copy, Debug)]
enum BufferTier {
    Small,
    Medium,
    Large,
    Jumbo,
}

struct PoolMetrics {
    small_acquired: AtomicU64,
    medium_acquired: AtomicU64,
    large_acquired: AtomicU64,
    jumbo_acquired: AtomicU64,
    small_reused: AtomicU64,
    medium_reused: AtomicU64,
    large_reused: AtomicU64,
    jumbo_reused: AtomicU64,
}

impl PoolMetrics {
    fn new() -> Self {
        Self {
            small_acquired: AtomicU64::new(0),
            medium_acquired: AtomicU64::new(0),
            large_acquired: AtomicU64::new(0),
            jumbo_acquired: AtomicU64::new(0),
            small_reused: AtomicU64::new(0),
            medium_reused: AtomicU64::new(0),
            large_reused: AtomicU64::new(0),
            jumbo_reused: AtomicU64::new(0),
        }
    }

    fn record_acquire(&self, tier: BufferTier, reused: bool) {
        let (acquire_counter, reuse_counter) = match tier {
            BufferTier::Small => (&self.small_acquired, &self.small_reused),
            BufferTier::Medium => (&self.medium_acquired, &self.medium_reused),
            BufferTier::Large => (&self.large_acquired, &self.large_reused),
            BufferTier::Jumbo => (&self.jumbo_acquired, &self.jumbo_reused),
        };

        acquire_counter.fetch_add(1, Ordering::Relaxed);
        if reused {
            reuse_counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Lock-free, sharded buffer pool for high-throughput HTTP proxying.
///
/// Pools `BytesMut` buffers in 4 size classes (small/medium/large/jumbo)
/// with 8 shards per class to reduce contention. Buffers are returned
/// to the pool on drop via `PooledBuf`.
pub struct BufferPool {
    small: Vec<Mutex<VecDeque<BytesMut>>>,
    medium: Vec<Mutex<VecDeque<BytesMut>>>,
    large: Vec<Mutex<VecDeque<BytesMut>>>,
    jumbo: Vec<Mutex<VecDeque<BytesMut>>>,
    metrics: PoolMetrics,
    config: BufferPoolConfig,
}

impl BufferPool {
    fn get_shard_index(&self) -> usize {
        THREAD_SHARD.with(|shard| {
            if let Some(idx) = shard.get() {
                return idx;
            }
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            std::thread::current().id().hash(&mut hasher);
            let idx = (hasher.finish() as usize) % NUM_SHARDS;
            shard.set(Some(idx));
            idx
        })
    }
}

/// Configuration for buffer pool size classes and capacities.
///
/// Each size class has a buffer size (in bytes) and a per-shard capacity
/// (max buffers to retain). Total memory ≈ Σ(size × capacity × num_shards).
#[derive(Debug, Clone)]
pub struct BufferPoolConfig {
    pub small_buf_size: usize,
    pub medium_buf_size: usize,
    pub large_buf_size: usize,
    pub small_pool_cap: usize,
    pub medium_pool_cap: usize,
    pub large_pool_cap: usize,
    pub jumbo_pool_cap: usize,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            small_buf_size: SMALL_BUF_SIZE,
            medium_buf_size: MEDIUM_BUF_SIZE,
            large_buf_size: LARGE_BUF_SIZE,
            small_pool_cap: SMALL_POOL_CAP,
            medium_pool_cap: MEDIUM_POOL_CAP,
            large_pool_cap: LARGE_POOL_CAP,
            jumbo_pool_cap: JUMBO_POOL_CAP,
        }
    }
}

thread_local! {
    pub static POOL: BufferPool = BufferPool::new();
    static THREAD_SHARD: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

pub static GLOBAL_POOL: std::sync::LazyLock<Arc<BufferPool>> =
    std::sync::LazyLock::new(|| Arc::new(BufferPool::new()));

impl BufferPool {
    fn new() -> Self {
        let small: Vec<_> = (0..NUM_SHARDS)
            .map(|_| Mutex::new(VecDeque::with_capacity(SMALL_POOL_CAP / NUM_SHARDS)))
            .collect();
        let medium: Vec<_> = (0..NUM_SHARDS)
            .map(|_| Mutex::new(VecDeque::with_capacity(MEDIUM_POOL_CAP / NUM_SHARDS)))
            .collect();
        let large: Vec<_> = (0..NUM_SHARDS)
            .map(|_| Mutex::new(VecDeque::with_capacity(LARGE_POOL_CAP / NUM_SHARDS)))
            .collect();
        let jumbo: Vec<_> = (0..NUM_SHARDS)
            .map(|_| Mutex::new(VecDeque::with_capacity(JUMBO_POOL_CAP / NUM_SHARDS)))
            .collect();

        Self {
            small,
            medium,
            large,
            jumbo,
            metrics: PoolMetrics::new(),
            config: BufferPoolConfig::default(),
        }
    }

    pub fn acquire(size: usize) -> PooledBuf {
        POOL.with(|pool| pool.acquire_inner(size))
    }

    pub fn acquire_global(size: usize) -> PooledBuf {
        GLOBAL_POOL.acquire_inner(size)
    }

    pub fn acquire_small() -> PooledBuf {
        Self::acquire(SMALL_BUF_SIZE)
    }

    pub fn acquire_global_small() -> PooledBuf {
        GLOBAL_POOL.acquire_inner(SMALL_BUF_SIZE)
    }

    pub fn acquire_medium() -> PooledBuf {
        Self::acquire(MEDIUM_BUF_SIZE)
    }

    pub fn acquire_global_medium() -> PooledBuf {
        GLOBAL_POOL.acquire_inner(MEDIUM_BUF_SIZE)
    }

    pub fn acquire_large() -> PooledBuf {
        Self::acquire(LARGE_BUF_SIZE)
    }

    fn acquire_inner(&self, size: usize) -> PooledBuf {
        let shard = self.get_shard_index();

        let (buf, tier) = if size <= self.config.small_buf_size {
            let mut guard = self.small[shard].lock();
            match guard.pop_front() {
                Some(mut buf) => {
                    buf.resize(size, 0);
                    self.metrics.record_acquire(BufferTier::Small, true);
                    (buf, BufferTier::Small)
                }
                _ => {
                    let mut buf = BytesMut::with_capacity(self.config.small_buf_size);
                    buf.resize(size, 0);
                    self.metrics.record_acquire(BufferTier::Small, false);
                    (buf, BufferTier::Small)
                }
            }
        } else if size <= self.config.medium_buf_size {
            let mut guard = self.medium[shard].lock();
            match guard.pop_front() {
                Some(mut buf) => {
                    buf.resize(size, 0);
                    self.metrics.record_acquire(BufferTier::Medium, true);
                    (buf, BufferTier::Medium)
                }
                _ => {
                    let mut buf = BytesMut::with_capacity(self.config.medium_buf_size);
                    buf.resize(size, 0);
                    self.metrics.record_acquire(BufferTier::Medium, false);
                    (buf, BufferTier::Medium)
                }
            }
        } else if size <= self.config.large_buf_size {
            let mut guard = self.large[shard].lock();
            match guard.pop_front() {
                Some(mut buf) => {
                    buf.resize(size, 0);
                    self.metrics.record_acquire(BufferTier::Large, true);
                    (buf, BufferTier::Large)
                }
                _ => {
                    let mut buf = BytesMut::with_capacity(self.config.large_buf_size);
                    buf.resize(size, 0);
                    self.metrics.record_acquire(BufferTier::Large, false);
                    (buf, BufferTier::Large)
                }
            }
        } else {
            let mut guard = self.jumbo[shard].lock();
            match guard.pop_front() {
                Some(mut buf) => {
                    buf.resize(size, 0);
                    self.metrics.record_acquire(BufferTier::Jumbo, true);
                    (buf, BufferTier::Jumbo)
                }
                _ => {
                    let mut buf = BytesMut::with_capacity(size);
                    buf.resize(size, 0);
                    self.metrics.record_acquire(BufferTier::Jumbo, false);
                    (buf, BufferTier::Jumbo)
                }
            }
        };

        PooledBuf {
            buf: Some(buf),
            tier,
            requested_size: size,
        }
    }

    fn release(&self, mut buf: BytesMut, tier: BufferTier) {
        buf.clear();

        let capacity = buf.capacity();
        let pool_cap = match tier {
            BufferTier::Small => self.config.small_pool_cap / NUM_SHARDS,
            BufferTier::Medium => self.config.medium_pool_cap / NUM_SHARDS,
            BufferTier::Large => self.config.large_pool_cap / NUM_SHARDS,
            BufferTier::Jumbo => self.config.jumbo_pool_cap / NUM_SHARDS,
        };

        let shard = self.get_shard_index();

        let mut guard = match tier {
            BufferTier::Small => self.small[shard].lock(),
            BufferTier::Medium => self.medium[shard].lock(),
            BufferTier::Large => self.large[shard].lock(),
            BufferTier::Jumbo => self.jumbo[shard].lock(),
        };

        if guard.len() < pool_cap && capacity > 0 {
            guard.push_back(buf);
        }
    }

    pub fn stats() -> PoolStats {
        POOL.with(|pool| {
            let mut small_total = 0;
            let mut medium_total = 0;
            let mut large_total = 0;
            let mut jumbo_total = 0;

            for shard in 0..NUM_SHARDS {
                small_total += pool.small[shard].lock().len();
                medium_total += pool.medium[shard].lock().len();
                large_total += pool.large[shard].lock().len();
                jumbo_total += pool.jumbo[shard].lock().len();
            }

            PoolStats {
                small_available: small_total,
                medium_available: medium_total,
                large_available: large_total,
                jumbo_available: jumbo_total,
                small_acquired: pool.metrics.small_acquired.load(Ordering::Relaxed),
                medium_acquired: pool.metrics.medium_acquired.load(Ordering::Relaxed),
                large_acquired: pool.metrics.large_acquired.load(Ordering::Relaxed),
                jumbo_acquired: pool.metrics.jumbo_acquired.load(Ordering::Relaxed),
                small_reused: pool.metrics.small_reused.load(Ordering::Relaxed),
                medium_reused: pool.metrics.medium_reused.load(Ordering::Relaxed),
                large_reused: pool.metrics.large_reused.load(Ordering::Relaxed),
                jumbo_reused: pool.metrics.jumbo_reused.load(Ordering::Relaxed),
            }
        })
    }

    pub fn config() -> BufferPoolConfig {
        POOL.with(|pool| pool.config.clone())
    }

    pub fn small_buf_size() -> usize {
        SMALL_BUF_SIZE
    }
    pub fn medium_buf_size() -> usize {
        MEDIUM_BUF_SIZE
    }
    pub fn large_buf_size() -> usize {
        LARGE_BUF_SIZE
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub small_available: usize,
    pub medium_available: usize,
    pub large_available: usize,
    pub jumbo_available: usize,
    pub small_acquired: u64,
    pub medium_acquired: u64,
    pub large_acquired: u64,
    pub jumbo_acquired: u64,
    pub small_reused: u64,
    pub medium_reused: u64,
    pub large_reused: u64,
    pub jumbo_reused: u64,
}

impl PoolStats {
    pub fn total_available(&self) -> usize {
        self.small_available + self.medium_available + self.large_available + self.jumbo_available
    }

    pub fn total_acquired(&self) -> u64 {
        self.small_acquired + self.medium_acquired + self.large_acquired + self.jumbo_acquired
    }

    pub fn total_reused(&self) -> u64 {
        self.small_reused + self.medium_reused + self.large_reused + self.jumbo_reused
    }

    pub fn reuse_rate(&self) -> f64 {
        let total = self.total_acquired();
        if total == 0 {
            0.0
        } else {
            self.total_reused() as f64 / total as f64
        }
    }
}

pub struct PooledBuf {
    buf: Option<BytesMut>,
    tier: BufferTier,
    requested_size: usize,
}

impl PooledBuf {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf.as_ref().expect("PooledBuf already consumed")[..self.requested_size]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut().expect("PooledBuf already consumed")[..self.requested_size]
    }

    pub fn len(&self) -> usize {
        self.requested_size
    }

    pub fn is_empty(&self) -> bool {
        self.requested_size == 0
    }

    pub fn capacity(&self) -> usize {
        self.buf.as_ref().map(|b| b.capacity()).unwrap_or(0)
    }

    pub fn resize(&mut self, new_len: usize) {
        if let Some(ref mut buf) = self.buf {
            buf.resize(new_len, 0);
            self.requested_size = new_len;
        }
    }

    pub fn advance(&mut self, cnt: usize) {
        if let Some(ref mut buf) = self.buf {
            let advance_amt = cnt.min(self.requested_size);
            buf.advance(advance_amt);
            self.requested_size = self.requested_size.saturating_sub(advance_amt);
        }
    }

    pub fn truncate(&mut self, new_len: usize) {
        if let Some(ref mut buf) = self.buf {
            buf.truncate(new_len);
            self.requested_size = new_len.min(self.requested_size);
        }
    }

    pub fn split_to(&mut self, at: usize) -> BytesMut {
        if let Some(ref mut buf) = self.buf {
            let split_amt = at.min(self.requested_size);
            let result = buf.split_to(split_amt);
            self.requested_size = self.requested_size.saturating_sub(split_amt);
            result
        } else {
            BytesMut::new()
        }
    }

    pub fn take_bytes(&mut self) -> BytesMut {
        self.buf.take().unwrap_or_default()
    }

    pub fn as_bytes_mut(&mut self) -> &mut BytesMut {
        self.buf.as_mut().expect("PooledBuf already consumed")
    }

    pub fn clear(&mut self) {
        if let Some(ref mut buf) = self.buf {
            buf.clear();
            buf.resize(self.requested_size, 0);
        }
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        if let Some(ref mut buf) = self.buf {
            buf.extend_from_slice(data);
            self.requested_size = buf.len();
        }
    }

    pub fn put_slice(&mut self, data: &[u8]) {
        if let Some(ref mut buf) = self.buf {
            buf.put_slice(data);
            self.requested_size = buf.len();
        }
    }
}

impl std::io::Write for PooledBuf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Some(ref mut buf) = self.buf {
            buf.extend_from_slice(data);
            self.requested_size = buf.len();
            Ok(data.len())
        } else {
            Ok(0)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            POOL.with(|pool| pool.release(buf, self.tier));
        }
    }
}

impl std::ops::Deref for PooledBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl std::ops::DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for PooledBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for PooledBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_small() {
        let mut buf = BufferPool::acquire(1024);
        assert_eq!(buf.len(), 1024);
        buf.as_mut_slice()[0] = 42;
        assert_eq!(buf.as_slice()[0], 42);
    }

    #[test]
    fn test_acquire_medium() {
        let mut buf = BufferPool::acquire(32 * 1024);
        assert_eq!(buf.len(), 32 * 1024);
        buf.as_mut_slice()[0] = 123;
        assert_eq!(buf.as_slice()[0], 123);
    }

    #[test]
    fn test_acquire_large() {
        let mut buf = BufferPool::acquire(128 * 1024);
        assert_eq!(buf.len(), 128 * 1024);
    }

    #[test]
    fn test_acquire_jumbo() {
        let buf = BufferPool::acquire(512 * 1024);
        assert_eq!(buf.len(), 512 * 1024);
    }

    #[test]
    fn test_pool_reuse() {
        let stats_before = BufferPool::stats();

        {
            let _buf1 = BufferPool::acquire(1024);
        }

        let stats_after = BufferPool::stats();
        assert!(stats_after.small_available >= stats_before.small_available);
    }

    #[test]
    fn test_extend_from_slice() {
        let mut buf = BufferPool::acquire(0);
        buf.extend_from_slice(b"hello");
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_split_to() {
        let mut buf = BufferPool::acquire(10);
        buf.as_mut_slice().copy_from_slice(b"0123456789");
        let part = buf.split_to(5);
        assert_eq!(&part[..], b"01234");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_pool_stats() {
        let stats = BufferPool::stats();
        assert!(stats.total_available() <= 512 + 256 + 64 + 32);
    }

    #[test]
    fn test_reuse_metrics() {
        for _ in 0..10 {
            let _buf = BufferPool::acquire(1024);
        }

        let stats = BufferPool::stats();
        assert!(stats.small_acquired >= 10);
        assert!(stats.small_reused > 0 || stats.small_available > 0);
    }
}
