# Buffer Pool Patterns

This skill documents the custom lock-free buffer pool implementation in the MaluWAF codebase.

## Overview

The buffer pool (`src/buffer/pool.rs`) provides high-performance buffer allocation using:
- **TreiberStack**: Lock-free stack with CAS for global pool
- **ThreadLocalCache**: Per-thread cache to avoid contention

## Architecture

```
BufferPool (8 shards)
├── TierArena (small: 4KB)     — capacity 512
├── TierArena (medium: 64KB)  — capacity 256
├── TierArena (large: 256KB)  — capacity 64
└── TierArena (jumbo: 1MB)    — capacity 32

Each TierArena contains:
├── TreiberStack<BytesMut>    — global lock-free stack
└── ThreadLocalCache         — TLS cache (16 entries per tier)
```

## Core API

```rust
pub struct BufferPool {
    shards: [ShardedArena; 8],
}

impl BufferPool {
    /// Acquire from TLS cache first, then global pool
    pub fn acquire(&self, size: usize) -> PooledBuf;

    /// Acquire from global pool only (for cross-thread use)
    pub fn acquire_global(&self, size: usize) -> PooledBuf;

    /// Acquire specific tier directly
    pub fn acquire_tier(&self, tier: BufferTier) -> PooledBuf;
}

/// RAII wrapper - returns buffer to pool on drop
pub struct PooledBuf {
    inner: BytesMut,
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        // Returns to TLS cache or global pool
    }
}
```

## TreiberStack Safety Invariants

**Location**: `src/buffer/pool.rs:65-141`

The TreiberStack is a lock-free stack using `AtomicPtr<StackNode>` with CAS operations.

### Safety Requirements

1. **Ownership model**:
   - Before CAS push: exclusive ownership of the node
   - After CAS: node is owned by the stack (other pushers may publish next node)
   - After CAS pop: unique ownership of the returned node via `Box::from_raw`

2. **ABA Mitigation**:
   - For buffer pools, ABA is mitigated because:
     - Buffers are only returned to the pool after the caller is done
     - Each shard has low contention (8 shards for 8 tiers)
     - `Box` addresses are recycled only after `Box::from_raw` completes

3. **Memory Ordering**:
   - Push uses `SeqCst` for publish (Release semantics via CAS success)
   - Pop uses `SeqCst` for acquire (pairs with push's Release)
   - Len uses `Relaxed` (only used for metrics)

### Unsafe Blocks

All unsafe blocks have explicit safety comments. Key invariants:
- `Box::into_raw()`: caller owns the Box
- `Box::from_raw()`: regains ownership after successful CAS

## ThreadLocalCache

**Location**: `src/buffer/pool.rs:218-273`

Uses `RefCell<Vec<BytesMut>>` for interior mutability:
- `thread_local!` guarantees single-threaded access
- `RefCell` provides compile-time borrow checking (zero overhead in release)
- No raw pointer casts needed

## Performance Characteristics

| Operation | Complexity |
|-----------|------------|
| TLS cache hit | O(1) |
| TLS cache miss → global | O(1) CAS |
| Global pool empty | O(n) allocate ( amortized O(1) ) |
| Release to TLS | O(1) |
| TLS full → global | O(1) CAS push |

## Stress Testing

The pool includes multithreaded stress tests verifying:
- Concurrent acquire/release across 8 threads
- Random buffer sizes
- Capacity bounds maintained
- No double-free or corruption
- Data integrity

Run with: `cargo test --lib buffer`

## Anti-Patterns to Avoid

1. **Don't hold PooledBuf across await points** — the buffer may be returned to the pool while you're suspended
2. **Don't use after drop** — buffers are immediately reusable once returned
3. **Don't mix with other allocators** — the pool expects buffers it allocated