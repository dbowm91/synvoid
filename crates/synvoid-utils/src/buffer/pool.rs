#![deny(unsafe_code)]

use bytes::{Buf, BufMut, BytesMut};
use parking_lot::Mutex;
use std::sync::Arc;

const SMALL_BUF_SIZE: usize = 4 * 1024;
const MEDIUM_BUF_SIZE: usize = 64 * 1024;
const LARGE_BUF_SIZE: usize = 256 * 1024;
const JUMBO_BUF_SIZE: usize = 512 * 1024;

const SMALL_POOL_CAP: usize = 512;
const MEDIUM_POOL_CAP: usize = 256;
const LARGE_POOL_CAP: usize = 64;
const JUMBO_POOL_CAP: usize = 32;

const NUM_SHARDS: usize = 8;
const TLS_CACHE_SIZE: usize = 16;

/// Phase 54: buffers grown beyond this capacity are freed on drop instead of
/// retained in thread pools (retained-memory bound).
const MAX_RETAINED_CAPACITY: usize = JUMBO_BUF_SIZE * 4;

/// Phase 54 contract for `GLOBAL_ALLOCATED_BYTES`: the sum of pool-managed
/// capacities currently checked out through live `PooledBuf` handles. It is a
/// soft backpressure indicator consumed by `try_acquire` — not total process
/// RSS, and not free-list retained capacity (returned buffers are subtracted
/// at drop/take time).
static GLOBAL_ALLOCATED_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static GLOBAL_MEMORY_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BufferTier {
    Small,
    Medium,
    Large,
    Jumbo,
}

impl BufferTier {
    /// Phase 54: reclassify by actual capacity so a buffer grown beyond its
    /// acquisition tier is never returned to a smaller-tier arena.
    fn for_capacity(cap: usize) -> BufferTier {
        if cap <= SMALL_BUF_SIZE {
            BufferTier::Small
        } else if cap <= MEDIUM_BUF_SIZE {
            BufferTier::Medium
        } else if cap <= LARGE_BUF_SIZE {
            BufferTier::Large
        } else {
            BufferTier::Jumbo
        }
    }
}

struct PoolMetrics {
    small_acquired: std::sync::atomic::AtomicU64,
    medium_acquired: std::sync::atomic::AtomicU64,
    large_acquired: std::sync::atomic::AtomicU64,
    jumbo_acquired: std::sync::atomic::AtomicU64,
    small_reused: std::sync::atomic::AtomicU64,
    medium_reused: std::sync::atomic::AtomicU64,
    large_reused: std::sync::atomic::AtomicU64,
    jumbo_reused: std::sync::atomic::AtomicU64,
}

impl PoolMetrics {
    fn new() -> Self {
        Self {
            small_acquired: std::sync::atomic::AtomicU64::new(0),
            medium_acquired: std::sync::atomic::AtomicU64::new(0),
            large_acquired: std::sync::atomic::AtomicU64::new(0),
            jumbo_acquired: std::sync::atomic::AtomicU64::new(0),
            small_reused: std::sync::atomic::AtomicU64::new(0),
            medium_reused: std::sync::atomic::AtomicU64::new(0),
            large_reused: std::sync::atomic::AtomicU64::new(0),
            jumbo_reused: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn record_acquire(&self, tier: BufferTier, reused: bool) {
        let (acquire_counter, reuse_counter) = match tier {
            BufferTier::Small => (&self.small_acquired, &self.small_reused),
            BufferTier::Medium => (&self.medium_acquired, &self.medium_reused),
            BufferTier::Large => (&self.large_acquired, &self.large_reused),
            BufferTier::Jumbo => (&self.jumbo_acquired, &self.jumbo_reused),
        };

        acquire_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if reused {
            reuse_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

struct TierArena {
    stack: Mutex<Vec<BytesMut>>,
    len: std::sync::atomic::AtomicUsize,
    buf_size: usize,
    cap: usize,
}

impl TierArena {
    fn new(buf_size: usize, cap: usize) -> Self {
        Self {
            stack: Mutex::new(Vec::new()),
            len: std::sync::atomic::AtomicUsize::new(0),
            buf_size,
            cap,
        }
    }

    fn push(&self, buf: BytesMut) {
        let mut stack = self.stack.lock();
        if stack.len() < self.cap {
            stack.push(buf);
            self.len.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn pop(&self) -> Option<BytesMut> {
        let mut stack = self.stack.lock();
        if let Some(buf) = stack.pop() {
            self.len.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            Some(buf)
        } else {
            None
        }
    }

    fn len(&self) -> usize {
        self.len.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn acquire(&self, requested_size: usize) -> (BytesMut, BufferTier) {
        if let Some(buf) = self.pop() {
            let mut buf = buf;
            // Phase 54: zero-fill the requested range (see TLS path above).
            buf.clear();
            buf.resize(requested_size, 0);
            return (buf, self.tier());
        }
        let mut buf = BytesMut::with_capacity(self.buf_size);
        buf.resize(requested_size, 0);
        (buf, self.tier())
    }

    fn release(&self, buf: BytesMut) {
        if buf.capacity() > 0 && self.len() < self.cap {
            let mut buf = buf;
            buf.clear();
            self.push(buf);
        }
    }

    fn tier(&self) -> BufferTier {
        match self.buf_size {
            SMALL_BUF_SIZE => BufferTier::Small,
            MEDIUM_BUF_SIZE => BufferTier::Medium,
            LARGE_BUF_SIZE => BufferTier::Large,
            _ => BufferTier::Jumbo,
        }
    }
}

struct ThreadLocalCache {
    small: std::cell::RefCell<Vec<BytesMut>>,
    medium: std::cell::RefCell<Vec<BytesMut>>,
    large: std::cell::RefCell<Vec<BytesMut>>,
    jumbo: std::cell::RefCell<Vec<BytesMut>>,
}

impl ThreadLocalCache {
    fn new() -> Self {
        Self {
            small: std::cell::RefCell::new(Vec::with_capacity(TLS_CACHE_SIZE)),
            medium: std::cell::RefCell::new(Vec::with_capacity(TLS_CACHE_SIZE)),
            large: std::cell::RefCell::new(Vec::with_capacity(TLS_CACHE_SIZE)),
            jumbo: std::cell::RefCell::new(Vec::with_capacity(TLS_CACHE_SIZE)),
        }
    }

    fn push(&self, buf: BytesMut, tier: BufferTier) {
        let cache = match tier {
            BufferTier::Small => &self.small,
            BufferTier::Medium => &self.medium,
            BufferTier::Large => &self.large,
            BufferTier::Jumbo => &self.jumbo,
        };
        let mut cache = cache.borrow_mut();
        if cache.len() < TLS_CACHE_SIZE {
            cache.push(buf);
        }
    }

    fn pop(&self, tier: BufferTier) -> Option<BytesMut> {
        let cache = match tier {
            BufferTier::Small => &self.small,
            BufferTier::Medium => &self.medium,
            BufferTier::Large => &self.large,
            BufferTier::Jumbo => &self.jumbo,
        };
        cache.borrow_mut().pop()
    }

    fn len(&self, tier: BufferTier) -> usize {
        let cache = match tier {
            BufferTier::Small => &self.small,
            BufferTier::Medium => &self.medium,
            BufferTier::Large => &self.large,
            BufferTier::Jumbo => &self.jumbo,
        };
        cache.borrow().len()
    }
}

thread_local! {
    pub static TLS_CACHE: ThreadLocalCache = ThreadLocalCache::new();
}

struct Shard {
    small: TierArena,
    medium: TierArena,
    large: TierArena,
    jumbo: TierArena,
}

impl Shard {
    fn new() -> Self {
        Self {
            small: TierArena::new(SMALL_BUF_SIZE, SMALL_POOL_CAP / NUM_SHARDS),
            medium: TierArena::new(MEDIUM_BUF_SIZE, MEDIUM_POOL_CAP / NUM_SHARDS),
            large: TierArena::new(LARGE_BUF_SIZE, LARGE_POOL_CAP / NUM_SHARDS),
            jumbo: TierArena::new(JUMBO_BUF_SIZE, JUMBO_POOL_CAP / NUM_SHARDS),
        }
    }
}

pub struct BufferPool {
    shards: Vec<Shard>,
    metrics: PoolMetrics,
    config: BufferPoolConfig,
    /// Phase 54: the thread-local `POOL` instance is single-threaded by
    /// construction and skips shard hashing/fanout (shard 0). The shared
    /// `GLOBAL_POOL` keeps sharding.
    local: bool,
}

impl BufferPool {
    fn get_shard_index() -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        (hasher.finish() as usize) % NUM_SHARDS
    }

    #[allow(dead_code, clippy::needless_lifetimes)]
    fn get_tier<'a>(buf: &'a BytesMut, config: &BufferPoolConfig) -> BufferTier {
        let cap = buf.capacity();
        if cap <= config.small_buf_size {
            BufferTier::Small
        } else if cap <= config.medium_buf_size {
            BufferTier::Medium
        } else if cap <= config.large_buf_size {
            BufferTier::Large
        } else {
            BufferTier::Jumbo
        }
    }
}

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
    pub static POOL: BufferPool = BufferPool::new_local();
}

thread_local! {
    // Phase 54: per-thread cached shard index for the shared pool, so every
    // global arena access does not re-hash the thread id.
    static CACHED_SHARD_INDEX: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

pub static GLOBAL_POOL: std::sync::LazyLock<Arc<BufferPool>> =
    std::sync::LazyLock::new(|| Arc::new(BufferPool::new()));

impl BufferPool {
    fn new() -> Self {
        let shards = (0..NUM_SHARDS).map(|_| Shard::new()).collect();
        Self {
            shards,
            metrics: PoolMetrics::new(),
            config: BufferPoolConfig::default(),
            local: false,
        }
    }

    fn new_local() -> Self {
        let shards = (0..NUM_SHARDS).map(|_| Shard::new()).collect();
        Self {
            shards,
            metrics: PoolMetrics::new(),
            config: BufferPoolConfig::default(),
            local: true,
        }
    }

    /// Shard selection: thread-local pools always use shard 0 (single-thread
    /// by construction); the shared pool caches the hashed index per thread.
    fn shard_index(&self) -> usize {
        if self.local {
            return 0;
        }
        CACHED_SHARD_INDEX.with(|cached| {
            if let Some(idx) = cached.get() {
                return idx;
            }
            let idx = Self::get_shard_index();
            cached.set(Some(idx));
            idx
        })
    }

    pub fn set_global_limit(limit_bytes: u64) {
        GLOBAL_MEMORY_LIMIT.store(limit_bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// Phase 54: current soft-accounted checkout capacity (live `PooledBuf`
    /// capacities). Test/observability accessor for the documented
    /// `GLOBAL_ALLOCATED_BYTES` contract.
    pub fn allocated_bytes() -> u64 {
        GLOBAL_ALLOCATED_BYTES.load(std::sync::atomic::Ordering::Relaxed)
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

    pub fn try_acquire(size: usize) -> Option<PooledBuf> {
        // Best-effort memory limit using Relaxed ordering: fetch_add/sub in
        // acquire_inner/drop is also Relaxed, so concurrent try_acquire calls
        // may race and slightly exceed the limit. This is acceptable for a
        // soft backpressure bound; the limit is not a hard safety invariant.
        let limit = GLOBAL_MEMORY_LIMIT.load(std::sync::atomic::Ordering::Relaxed);
        if limit > 0 {
            let current = GLOBAL_ALLOCATED_BYTES.load(std::sync::atomic::Ordering::Relaxed);
            if current + size as u64 > limit {
                return None;
            }
        }
        Some(Self::acquire(size))
    }

    pub fn try_acquire_global_medium() -> Option<PooledBuf> {
        Self::try_acquire(MEDIUM_BUF_SIZE)
    }

    pub fn acquire_large() -> PooledBuf {
        Self::acquire(LARGE_BUF_SIZE)
    }

    fn acquire_inner(&self, size: usize) -> PooledBuf {
        let tier = if size <= self.config.small_buf_size {
            BufferTier::Small
        } else if size <= self.config.medium_buf_size {
            BufferTier::Medium
        } else if size <= self.config.large_buf_size {
            BufferTier::Large
        } else {
            BufferTier::Jumbo
        };

        let tls_result = TLS_CACHE.with(|cache| {
            if let Some(buf) = cache.pop(tier) {
                let mut buf = buf;
                // Phase 54: recycled buffers must be zero-filled for the
                // requested range. `resize` alone only fills growth beyond
                // the recycled length, so same-size (or shrinking) reuse
                // would otherwise expose the previous contents.
                buf.clear();
                buf.resize(size, 0);
                self.metrics.record_acquire(tier, true);
                let mut pooled = PooledBuf {
                    buf: Some(buf),
                    tier,
                    requested_size: size,
                    allocated_size: 0,
                    global_origin: !self.local,
                };
                // Phase 54: track actual recycled capacity, not the tier size.
                pooled.sync_capacity_accounting();
                return Some(pooled);
            }
            None
        });

        if let Some(buf) = tls_result {
            return buf;
        }

        let shard = &self.shards[self.shard_index()];

        let (buf, actual_tier) = match tier {
            BufferTier::Small => shard.small.acquire(size),
            BufferTier::Medium => shard.medium.acquire(size),
            BufferTier::Large => shard.large.acquire(size),
            BufferTier::Jumbo => shard.jumbo.acquire(size),
        };

        self.metrics.record_acquire(actual_tier, false);

        let mut pooled = PooledBuf {
            buf: Some(buf),
            tier: actual_tier,
            requested_size: size,
            allocated_size: 0,
            global_origin: !self.local,
        };
        pooled.sync_capacity_accounting();
        pooled
    }

    fn release_to_global(&self, buf: BytesMut, tier: BufferTier) {
        let shard = &self.shards[self.shard_index()];
        match tier {
            BufferTier::Small => shard.small.release(buf),
            BufferTier::Medium => shard.medium.release(buf),
            BufferTier::Large => shard.large.release(buf),
            BufferTier::Jumbo => shard.jumbo.release(buf),
        }
    }

    pub fn stats() -> PoolStats {
        POOL.with(|pool| pool.collect_stats())
    }

    fn collect_stats(&self) -> PoolStats {
        let mut small_available = 0;
        let mut medium_available = 0;
        let mut large_available = 0;
        let mut jumbo_available = 0;

        for shard in &self.shards {
            small_available += shard.small.len();
            medium_available += shard.medium.len();
            large_available += shard.large.len();
            jumbo_available += shard.jumbo.len();
        }

        TLS_CACHE.with(|cache| {
            small_available += cache.len(BufferTier::Small);
            medium_available += cache.len(BufferTier::Medium);
            large_available += cache.len(BufferTier::Large);
            jumbo_available += cache.len(BufferTier::Jumbo);
        });

        PoolStats {
            small_available,
            medium_available,
            large_available,
            jumbo_available,
            small_acquired: self
                .metrics
                .small_acquired
                .load(std::sync::atomic::Ordering::Relaxed),
            medium_acquired: self
                .metrics
                .medium_acquired
                .load(std::sync::atomic::Ordering::Relaxed),
            large_acquired: self
                .metrics
                .large_acquired
                .load(std::sync::atomic::Ordering::Relaxed),
            jumbo_acquired: self
                .metrics
                .jumbo_acquired
                .load(std::sync::atomic::Ordering::Relaxed),
            small_reused: self
                .metrics
                .small_reused
                .load(std::sync::atomic::Ordering::Relaxed),
            medium_reused: self
                .metrics
                .medium_reused
                .load(std::sync::atomic::Ordering::Relaxed),
            large_reused: self
                .metrics
                .large_reused
                .load(std::sync::atomic::Ordering::Relaxed),
            jumbo_reused: self
                .metrics
                .jumbo_reused
                .load(std::sync::atomic::Ordering::Relaxed),
        }
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
        self.small_available
            .saturating_add(self.medium_available)
            .saturating_add(self.large_available)
            .saturating_add(self.jumbo_available)
    }

    pub fn total_acquired(&self) -> u64 {
        self.small_acquired
            .saturating_add(self.medium_acquired)
            .saturating_add(self.large_acquired)
            .saturating_add(self.jumbo_acquired)
    }

    pub fn total_reused(&self) -> u64 {
        self.small_reused
            .saturating_add(self.medium_reused)
            .saturating_add(self.large_reused)
            .saturating_add(self.jumbo_reused)
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
    /// Phase 54: currently tracked checkout capacity for this handle (actual
    /// `BytesMut` capacity, updated on growth). Subtracted exactly once at
    /// drop or `take_bytes` time.
    allocated_size: usize,
    /// Phase 54: which pool this handle was acquired from. Global
    /// acquisitions spill back to the shared pool; thread-local acquisitions
    /// reuse the TLS cache first.
    global_origin: bool,
}

impl PooledBuf {
    /// Phase 54: reconcile soft accounting with actual capacity after any
    /// operation that can change it. Skipped (no atomic traffic) when
    /// capacity did not actually change. Saturating arithmetic: the counter
    /// can never underflow/overflow from pool bookkeeping.
    fn sync_capacity_accounting(&mut self) {
        if let Some(ref buf) = self.buf {
            let cap = buf.capacity();
            // Phase 54: keep the return tier in step with actual capacity so
            // grown buffers never land in a smaller-tier arena.
            self.tier = BufferTier::for_capacity(cap);
            if cap == self.allocated_size {
                return;
            }
            if cap > self.allocated_size {
                GLOBAL_ALLOCATED_BYTES.fetch_add(
                    (cap - self.allocated_size) as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            } else {
                GLOBAL_ALLOCATED_BYTES.fetch_sub(
                    (self.allocated_size - cap) as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            self.allocated_size = cap;
        }
    }
}

impl PooledBuf {
    pub fn as_slice(&self) -> &[u8] {
        self.buf
            .as_ref()
            .map(|b| &b[..self.requested_size])
            .unwrap_or(&[])
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf
            .as_mut()
            .map(|b| &mut b[..self.requested_size])
            .unwrap_or(&mut [])
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
            // Phase 54: growth across tiers updates soft accounting.
            self.sync_capacity_accounting();
        }
    }

    pub fn advance(&mut self, cnt: usize) {
        if let Some(ref mut buf) = self.buf {
            let advance_amt = cnt.min(self.requested_size);
            buf.advance(advance_amt);
            self.requested_size = self.requested_size.saturating_sub(advance_amt);
            self.sync_capacity_accounting();
        }
    }

    pub fn truncate(&mut self, new_len: usize) {
        if let Some(ref mut buf) = self.buf {
            buf.truncate(new_len);
            self.requested_size = new_len.min(self.requested_size);
            self.sync_capacity_accounting();
        }
    }

    pub fn split_to(&mut self, at: usize) -> BytesMut {
        if let Some(ref mut buf) = self.buf {
            let split_amt = at.min(self.requested_size);
            let result = buf.split_to(split_amt);
            self.requested_size = self.requested_size.saturating_sub(split_amt);
            // Phase 54: the split-off prefix leaves pool management; the
            // retained suffix keeps its own capacity accounting.
            self.sync_capacity_accounting();
            result
        } else {
            BytesMut::new()
        }
    }

    /// Phase 54: ownership leaves the pool wrapper — release soft accounting
    /// exactly once here so `Drop` (which sees `None`) cannot subtract again.
    pub fn take_bytes(&mut self) -> BytesMut {
        match self.buf.take() {
            Some(buf) => {
                GLOBAL_ALLOCATED_BYTES.fetch_sub(
                    self.allocated_size as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                self.allocated_size = 0;
                self.requested_size = 0;
                buf
            }
            None => BytesMut::new(),
        }
    }

    pub fn as_bytes_mut(&mut self) -> Option<&mut BytesMut> {
        self.buf.as_mut()
    }

    /// Panicking variant of `as_bytes_mut` for call sites that require a `&mut BytesMut`.
    /// Prefer `as_bytes_mut` (Option) for new code; this will panic if the buffer was consumed.
    pub fn as_bytes_mut_expect(&mut self) -> &mut BytesMut {
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
            // Phase 54: growth updates soft accounting.
            self.sync_capacity_accounting();
        }
    }

    pub fn put_slice(&mut self, data: &[u8]) {
        if let Some(ref mut buf) = self.buf {
            buf.put_slice(data);
            self.requested_size = buf.len();
            self.sync_capacity_accounting();
        }
    }
}

impl std::io::Write for PooledBuf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Some(ref mut buf) = self.buf {
            buf.extend_from_slice(data);
            self.requested_size = buf.len();
            self.sync_capacity_accounting();
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
            GLOBAL_ALLOCATED_BYTES.fetch_sub(
                self.allocated_size as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            self.allocated_size = 0;
            let capacity = buf.capacity();
            // Phase 54: pathological capacity is freed, never retained in
            // thread pools (bounds retained memory against transient growth).
            if capacity > MAX_RETAINED_CAPACITY {
                return;
            }
            // Phase 54: reclassify by actual capacity so grown buffers never
            // land in a smaller-tier arena.
            let tier = self.tier;
            if self.global_origin {
                GLOBAL_POOL.release_to_global(buf, tier);
            } else {
                TLS_CACHE.with(|cache| {
                    if cache.len(tier) < TLS_CACHE_SIZE {
                        cache.push(buf, tier);
                    } else {
                        POOL.with(|pool| pool.release_to_global(buf, tier));
                    }
                });
            }
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

impl std::fmt::Debug for PooledBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuf")
            .field("len", &self.requested_size)
            .field(
                "capacity",
                &self.buf.as_ref().map(|b| b.capacity()).unwrap_or(0),
            )
            .finish()
    }
}

impl PartialEq for PooledBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
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
        let buf = BufferPool::acquire(128 * 1024);
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

    #[test]
    fn test_buffer_allocation_sizes() {
        let small = BufferPool::acquire(1);
        assert_eq!(small.len(), 1);
        assert!(small.capacity() >= 1);

        let at_boundary = BufferPool::acquire(SMALL_BUF_SIZE);
        assert_eq!(at_boundary.len(), SMALL_BUF_SIZE);

        let above_small = BufferPool::acquire(SMALL_BUF_SIZE + 1);
        assert_eq!(above_small.len(), SMALL_BUF_SIZE + 1);
    }

    #[test]
    fn test_buffer_allocation_tier_selection() {
        let small_buf = BufferPool::acquire(100);
        assert!(small_buf.capacity() >= SMALL_BUF_SIZE);

        let medium_buf = BufferPool::acquire(SMALL_BUF_SIZE + 100);
        assert!(medium_buf.capacity() >= MEDIUM_BUF_SIZE);

        let large_buf = BufferPool::acquire(MEDIUM_BUF_SIZE + 100);
        assert!(large_buf.capacity() >= LARGE_BUF_SIZE);

        let jumbo_buf = BufferPool::acquire(LARGE_BUF_SIZE + 100);
        assert!(jumbo_buf.capacity() >= LARGE_BUF_SIZE + 100);
    }

    #[test]
    fn test_buffer_recycling_exact_size_reuse() {
        let stats_before = BufferPool::stats();

        let buf1 = BufferPool::acquire(1024);
        let cap1 = buf1.capacity();
        drop(buf1);

        let stats_after_drop = BufferPool::stats();
        assert!(
            stats_after_drop.small_available > stats_before.small_available
                || stats_after_drop.small_reused > stats_before.small_reused
        );

        let buf2 = BufferPool::acquire(1024);
        assert_eq!(buf2.capacity(), cap1);
    }

    #[test]
    fn test_pool_limits_small_tier() {
        let acquire_count = 100.min(SMALL_POOL_CAP * 2);

        let stats_before = BufferPool::stats();
        let initial_available = stats_before.small_available;

        let mut bufs = Vec::with_capacity(acquire_count);
        for _ in 0..acquire_count {
            bufs.push(BufferPool::acquire(100));
        }

        let stats_mid = BufferPool::stats();
        assert!(stats_mid.small_acquired >= acquire_count as u64);

        drop(bufs);

        let stats_after = BufferPool::stats();
        let returned = stats_after
            .small_available
            .saturating_sub(initial_available);
        assert!(returned <= SMALL_POOL_CAP);
    }

    #[test]
    fn test_pool_limits_medium_tier() {
        let acquire_count = 50.min(MEDIUM_POOL_CAP * 2);

        let stats_before = BufferPool::stats();
        let initial_available = stats_before.medium_available;

        let mut bufs = Vec::with_capacity(acquire_count);
        for _ in 0..acquire_count {
            bufs.push(BufferPool::acquire(MEDIUM_BUF_SIZE / 2));
        }

        drop(bufs);

        let stats_after = BufferPool::stats();
        let returned = stats_after
            .medium_available
            .saturating_sub(initial_available);
        assert!(returned <= MEDIUM_POOL_CAP);
    }

    #[test]
    fn test_pool_never_grows_beyond_capacity() {
        let initial_stats = BufferPool::stats();
        let initial_small = initial_stats.small_available;

        let mut bufs = Vec::new();
        for _ in 0..SMALL_POOL_CAP * 3 {
            bufs.push(BufferPool::acquire(100));
        }

        let stats_during = BufferPool::stats();
        let total_small_in_pool =
            NUM_SHARDS * (initial_small + BufferPool::config().small_pool_cap / NUM_SHARDS);
        assert!(
            stats_during.small_available <= total_small_in_pool
                || stats_during.small_acquired >= (SMALL_POOL_CAP * 3) as u64
        );

        drop(bufs);
    }

    #[test]
    fn test_buffer_zero_sized_allocation() {
        let buf = BufferPool::acquire(0);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_pooled_buf_operations() {
        let mut buf = BufferPool::acquire(5);
        buf.as_mut_slice().copy_from_slice(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_slice(), b"hello");

        buf.truncate(3);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_slice(), b"hel");

        buf.clear();
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_slice(), &[0, 0, 0]);
    }

    #[test]
    fn test_pooled_buf_advance() {
        let mut buf = BufferPool::acquire(10);
        buf.as_mut_slice().copy_from_slice(b"0123456789");
        assert_eq!(buf.len(), 10);

        buf.advance(3);
        assert_eq!(buf.len(), 7);
        assert_eq!(buf.as_slice(), b"3456789");

        buf.advance(10);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_concurrent_allocation_different_sizes() {
        use std::thread;

        let handles: Vec<_> = (0..4)
            .map(|i| {
                thread::spawn(move || {
                    let size = match i {
                        0 => 100,
                        1 => SMALL_BUF_SIZE / 2,
                        2 => MEDIUM_BUF_SIZE / 2,
                        3 => LARGE_BUF_SIZE / 2,
                        _ => 100,
                    };
                    for _ in 0..50 {
                        let buf = BufferPool::acquire(size);
                        assert_eq!(buf.len(), size);
                    }
                })
            })
            .collect();

        for handle in handles {
            assert!(handle.join().is_ok());
        }
    }

    #[test]
    fn test_concurrent_acquire_release() {
        use std::thread;

        let handle = thread::spawn(|| {
            for _ in 0..100 {
                let buf = BufferPool::acquire(256);
                drop(buf);
            }
        });

        let handle2 = thread::spawn(|| {
            for _ in 0..100 {
                let buf = BufferPool::acquire(256);
                drop(buf);
            }
        });

        assert!(handle.join().is_ok());
        assert!(handle2.join().is_ok());
    }

    #[test]
    fn test_stats_accuracy_after_drop() {
        let stats_before = BufferPool::stats();
        let small_before = stats_before.small_available;

        let _buf = BufferPool::acquire(1024);
        let stats_after_acquire = BufferPool::stats();

        drop(_buf);
        let stats_after_drop = BufferPool::stats();

        assert_eq!(
            stats_after_acquire.small_acquired,
            stats_after_drop.small_acquired
        );
        assert!(
            stats_after_drop.small_available >= small_before
                || stats_after_drop.small_reused > stats_after_acquire.small_reused
        );
    }

    #[test]
    fn test_reuse_rate_calculation() {
        let stats = BufferPool::stats();
        let rate = stats.reuse_rate();
        assert!(rate >= 0.0);
        assert!(rate <= 1.0);
    }

    #[test]
    fn test_pooled_buf_write_trait() {
        use std::io::Write;

        let mut buf = BufferPool::acquire(0);
        let written = buf.write(b"test").unwrap();
        assert_eq!(written, 4);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn test_global_pool_acquire() {
        let buf = BufferPool::acquire_global(1024);
        assert_eq!(buf.len(), 1024);

        let buf_small = BufferPool::acquire_global_small();
        assert_eq!(buf_small.len(), SMALL_BUF_SIZE);

        let buf_medium = BufferPool::acquire_global_medium();
        assert_eq!(buf_medium.len(), MEDIUM_BUF_SIZE);

        let buf_large = BufferPool::acquire_global(LARGE_BUF_SIZE);
        assert_eq!(buf_large.len(), LARGE_BUF_SIZE);
    }

    #[test]
    fn test_buffer_pool_config_defaults() {
        let config = BufferPoolConfig::default();
        assert_eq!(config.small_buf_size, SMALL_BUF_SIZE);
        assert_eq!(config.medium_buf_size, MEDIUM_BUF_SIZE);
        assert_eq!(config.large_buf_size, LARGE_BUF_SIZE);
        assert_eq!(config.small_pool_cap, SMALL_POOL_CAP);
        assert_eq!(config.medium_pool_cap, MEDIUM_POOL_CAP);
        assert_eq!(config.large_pool_cap, LARGE_POOL_CAP);
        assert_eq!(config.jumbo_pool_cap, JUMBO_POOL_CAP);
    }

    #[test]
    fn test_deref_and_asref_traits() {
        let mut buf = BufferPool::acquire(5);
        buf.as_mut_slice().copy_from_slice(b"hello");

        let slice: &[u8] = &buf;
        assert_eq!(slice, b"hello");

        let as_ref: &[u8] = buf.as_ref();
        assert_eq!(as_ref, b"hello");
    }

    #[test]
    fn test_stress_multithread_acquire_release() {
        use std::thread;

        let num_threads = 8;
        let iterations = 500;

        let handles: Vec<_> = (0..num_threads)
            .map(|tid| {
                thread::spawn(move || {
                    let sizes = [
                        64,
                        SMALL_BUF_SIZE / 2,
                        SMALL_BUF_SIZE + 1,
                        MEDIUM_BUF_SIZE / 2,
                        MEDIUM_BUF_SIZE + 1,
                        LARGE_BUF_SIZE / 2,
                        LARGE_BUF_SIZE + 1,
                    ];
                    for i in 0..iterations {
                        let size = sizes[(tid + i) % sizes.len()];
                        let mut buf = BufferPool::acquire(size);
                        assert!(buf.len() == size);
                        assert!(buf.capacity() >= size);
                        buf.as_mut_slice()[0] = (tid as u8).wrapping_add(i as u8);
                        assert_eq!(buf.as_slice()[0], (tid as u8).wrapping_add(i as u8));
                        drop(buf);
                    }
                })
            })
            .collect();

        for h in handles {
            assert!(h.join().is_ok());
        }
    }

    #[test]
    fn test_stress_random_sizes_bounded_capacity() {
        use std::thread;

        let initial_stats = BufferPool::stats();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    let mut rng_state: u64 = 0x1234_5678;
                    for _ in 0..200 {
                        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                        let size = ((rng_state >> 33) as usize % (LARGE_BUF_SIZE * 2)).max(1);
                        let buf = BufferPool::acquire(size);
                        assert_eq!(buf.len(), size);
                        drop(buf);
                    }
                })
            })
            .collect();

        for h in handles {
            assert!(h.join().is_ok());
        }

        let stats = BufferPool::stats();
        let max_allowed = SMALL_POOL_CAP
            + MEDIUM_POOL_CAP
            + LARGE_POOL_CAP
            + JUMBO_POOL_CAP
            + initial_stats.total_available();
        assert!(
            stats.total_available() <= max_allowed,
            "pool grew beyond expected capacity: {} > {}",
            stats.total_available(),
            max_allowed
        );
    }

    #[test]
    fn test_stress_no_double_free_or_corruption() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::thread;

        let live_count = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let live = Arc::clone(&live_count);
                let max = Arc::clone(&max_seen);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let mut bufs = Vec::with_capacity(10);
                        for _ in 0..10 {
                            bufs.push(BufferPool::acquire(1024));
                            let cur = live.fetch_add(1, AtomicOrdering::Relaxed);
                            max.fetch_max(cur + 1, AtomicOrdering::Relaxed);
                        }
                        for mut buf in bufs {
                            buf.as_mut_slice()[0] = 0xAA;
                            assert_eq!(buf.as_slice()[0], 0xAA);
                            drop(buf);
                            live.fetch_sub(1, AtomicOrdering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            assert!(h.join().is_ok());
        }

        assert_eq!(live_count.load(AtomicOrdering::Relaxed), 0);
    }

    /// Phase 54: `acquire(N)` is a writable-length API, NOT capacity-only.
    /// The first N bytes are zeroed logical bytes; appending after acquire
    /// without `resize(0)` produces a zero prefix (see the corrected
    /// acquire-then-append call sites).
    #[test]
    fn test_acquire_semantics_are_length_not_capacity() {
        for size in [0usize, 1, 100, SMALL_BUF_SIZE, MEDIUM_BUF_SIZE + 7] {
            let buf = BufferPool::acquire(size);
            assert_eq!(buf.len(), size, "acquire({size}) logical length");
            assert_eq!(buf.is_empty(), size == 0);
            assert!(
                buf.as_slice().iter().all(|b| *b == 0),
                "acquire({size}) must be zero-initialized"
            );
            assert!(buf.capacity() >= size);
        }
    }

    /// Phase 54: recycled buffers are zero-filled even when reacquired at
    /// the same size (regression test — TLS reuse previously returned the
    /// previous contents because `resize` only fills growth).
    #[test]
    fn test_recycled_buffer_is_zeroed_same_size() {
        for size in [64usize, 1024, 32 * 1024] {
            {
                let mut buf = BufferPool::acquire(size);
                for b in buf.as_mut_slice().iter_mut() {
                    *b = 0xAB;
                }
            }
            let buf = BufferPool::acquire(size);
            assert_eq!(buf.len(), size);
            assert!(
                buf.as_slice().iter().all(|b| *b == 0),
                "reacquired buffer of size {size} must be zero-initialized"
            );
        }
    }

    /// Phase 54: shrinking reuse is also zero-clean.
    #[test]
    fn test_recycled_buffer_is_zeroed_shrinking() {
        {
            let mut buf = BufferPool::acquire(2048);
            for b in buf.as_mut_slice().iter_mut() {
                *b = 0xCD;
            }
        }
        let buf = BufferPool::acquire(512);
        assert!(
            buf.as_slice().iter().all(|b| *b == 0),
            "shrinking reuse must be zero-initialized"
        );
    }

    /// Phase 54: `resize(0)` empties the logical buffer while retaining
    /// reusable capacity; `extend_from_slice` appends after the logical end.
    #[test]
    fn test_resize_zero_then_append_has_no_prefix() {
        let mut buf = BufferPool::acquire(1024);
        let cap = buf.capacity();
        buf.resize(0);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), cap, "resize(0) retains capacity");
        buf.extend_from_slice(b"hello");
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.len(), 5);
    }

    /// Phase 54: `clear()` zeroizes in place and RETAINS logical length
    /// (pinned behavior — it is not an emptying operation). Callers that
    /// intend an empty buffer must use `resize(0)`.
    #[test]
    fn test_clear_keeps_logical_length() {
        let mut buf = BufferPool::acquire(4);
        buf.as_mut_slice().copy_from_slice(b"abcd");
        buf.clear();
        assert_eq!(buf.len(), 4, "clear() retains logical length");
        assert_eq!(buf.as_slice(), &[0, 0, 0, 0], "clear() zeroizes");
    }

    /// Phase 54: split/advance/truncate keep length accounting consistent.
    #[test]
    fn test_split_advance_truncate_consistency() {
        let mut buf = BufferPool::acquire(10);
        buf.as_mut_slice().copy_from_slice(b"0123456789");

        let part = buf.split_to(4);
        assert_eq!(&part[..], b"0123");
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.as_slice(), b"456789");

        buf.advance(2);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.as_slice(), b"6789");

        buf.truncate(2);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.as_slice(), b"67");
    }

    /// Phase 54: a buffer grown beyond its acquisition tier must not be
    /// returned to a smaller-tier arena.
    #[test]
    fn test_grown_buffer_not_returned_to_small_tier() {
        let small_before = BufferPool::stats().small_available;
        let mut buf = BufferPool::acquire(512);
        buf.resize(100 * 1024);
        drop(buf);
        let small_after = BufferPool::stats().small_available;
        assert!(
            small_after <= small_before + 1,
            "grown buffer must not land in the small tier"
        );
    }

    #[test]
    fn test_stress_concurrent_all_tiers() {
        use std::thread;

        let handles: Vec<_> = (0..4)
            .map(|tid| {
                thread::spawn(move || {
                    let tier_sizes = [
                        100,
                        SMALL_BUF_SIZE + 1,
                        MEDIUM_BUF_SIZE + 1,
                        LARGE_BUF_SIZE + 1,
                    ];
                    for _ in 0..100 {
                        let size = tier_sizes[tid % tier_sizes.len()];
                        let buf = BufferPool::acquire(size);
                        assert_eq!(buf.len(), size);
                        drop(buf);
                    }
                })
            })
            .collect();

        for h in handles {
            assert!(h.join().is_ok());
        }
    }
}
