# Buffer Pool Patterns

This skill documents the buffer pool implementation in the MaluWAF codebase.

## Overview

The buffer pool (`crates/maluwaf-utils/src/buffer/pool.rs`) provides high-performance buffer allocation using sharded mutex backing instead of lock-free CAS (to eliminate ABA hazards).

## Architecture

```
BufferPool (8 shards)
├── Shard[0-7] (parking_lot::Mutex<Vec<BytesMut>>)
│
├── TierArena (small: 4KB)     — capacity 512
├── TierArena (medium: 64KB)  — capacity 256
├── TierArena (large: 256KB)  — capacity 64
└── TierArena (jumbo: 1MB)   — capacity 32
```

## Core API

```rust
pub struct BufferPool {
    shards: Vec<ShardedArena>,  // 8 shards per tier
}

impl BufferPool {
    /// Acquire from shard (uses round-robin to reduce contention)
    pub fn acquire(&self, size: usize) -> PooledBuf;

    /// Acquire specific tier directly
    pub fn acquire_tier(&self, tier: BufferTier) -> PooledBuf;
}

/// RAII wrapper - returns buffer to pool on drop
pub struct PooledBuf {
    inner: BytesMut,
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        // Returns buffer to appropriate shard
    }
}
```

## Sharded Mutex Design

**Why mutex sharding instead of lock-free?**

The previous TreiberStack implementation had an ABA vulnerability:
1. Thread A reads pointer P to node N
2. Thread B pops N, frees it, pushes new node M at same address P
3. Thread A's CAS succeeds incorrectly, assuming stack state unchanged

By using `parking_lot::Mutex<Vec<BytesMut>>` per shard:
- Eliminates ABA completely (no raw pointer manipulation)
- Reduces contention (8 shards vs single global lock)
- `parking_lot` is faster than `std::sync::Mutex` (no syscall in non-contended case)

## ThreadLocalCache

**Location**: `src/buffer/pool.rs`

Uses `RefCell<Vec<BytesMut>>` for interior mutability:
- `thread_local!` guarantees single-threaded access
- `RefCell` provides compile-time borrow checking (zero overhead in release)
- 16 entry cache per thread per tier

## Safety

The module has `#[deny(unsafe_code)]` - no unsafe blocks remain.

## Performance Characteristics

| Operation | Complexity |
|-----------|------------|
| TLS cache hit | O(1) |
| TLS cache miss → shard | O(1) lock acquisition |
| Shard lock contention | Minimized by 8 shards |
| Global pool empty | O(n) allocate (amortized O(1)) |
| Release to TLS | O(1) |
| TLS full → shard | O(1) lock acquisition |

## Anti-Patterns to Avoid

1. **Don't hold PooledBuf across await points** — the buffer may be returned to the pool while you're suspended
2. **Don't use after drop** — buffers are immediately reusable once returned
3. **Don't mix with other allocators** — the pool expects buffers it allocated

## Testing

Run with: `cargo test --lib buffer`