---
name: buffer_pool
description: Sharded mutex buffer pool implementation replacing TreiberStack with ABA-safe design for high-performance buffer allocation.
---

# Buffer Pool Patterns

This skill documents the buffer pool implementation in the SynVoid codebase.

## Overview

The buffer pool (`crates/synvoid-utils/src/buffer/pool.rs`) provides
high-performance buffer allocation using a thread-local cache plus sharded
mutex arenas (to eliminate ABA hazards of the old TreiberStack).

## Architecture

```
thread TLS_CACHE (per tier, 16 entries, RefCell<Vec<BytesMut>>)
thread-local POOL (BufferPool, single-shard fast path, Phase 54)
shared GLOBAL_POOL (BufferPool, 8 hashed shards, cached index per thread)
└── Shard (parking_lot::Mutex<Vec<BytesMut>> per tier)
    ├── small: 4KB   — arena cap 512 total
    ├── medium: 64KB — arena cap 256 total
    ├── large: 256KB — arena cap 64 total
    └── jumbo: 512KB — arena cap 32 total
```

## Core API (unchanged by the performance campaign)

```rust
impl BufferPool {
    pub fn acquire(size: usize) -> PooledBuf;         // thread-local path
    pub fn acquire_global(size: usize) -> PooledBuf;  // shared path
    pub fn allocated_bytes() -> u64;                  // soft-accounted checkout total (Phase 54)
}

pub struct PooledBuf { /* private fields */ }  // RAII: returns buffer to pool on drop
```

## Non-Negotiables (Phase 54 contracts)

1. **`acquire(N)` yields N logical zeroed bytes — it is NOT capacity-only.**
   Never `acquire(n)` + `extend_from_slice(data)` to mean "empty with room
   for n". Either copy into `as_mut_slice()`, or `resize(0)` first and then
   append. Appending to a nonzero acquire leaves a zero prefix.
2. **`clear()` zeroizes in place and KEEPS logical length.** It is not an
   emptying operation. To empty a buffer for refill, use `resize(0)`.
3. **Recycled buffers are zero-filled** (`test_recycled_buffer_is_zeroed_*`).
   Do not "optimize" away the zero-fill on the TLS/arena pop paths.
4. **Do not retain pathological capacity**: buffers grown past 2 MiB are
   freed on drop, never pooled. Grown buffers re-tier by actual capacity.
5. **`take_bytes` releases accounting exactly once**; `Drop` after `take`
   must not subtract again. Growth (`resize`/`extend`/`put`/`Write`)
   updates the soft counter; shrink paths reconcile it.
6. **Origin rule**: thread-local acquisitions reuse TLS first; global
   acquisitions spill back to the shared pool. Do not route global buffers
   into thread-local retention.
7. **Don't hold PooledBuf across await points** — the buffer may be returned
   to the pool while you're suspended.
8. **Don't use after drop** — buffers are immediately reusable once returned.

## Sharded Mutex Design

**Why mutex sharding instead of lock-free?**

The previous TreiberStack implementation had an ABA vulnerability. By using
`parking_lot::Mutex<Vec<BytesMut>>` per shard, the pool eliminates ABA
(no raw pointer manipulation) and reduces contention. `parking_lot` is
faster than `std::sync::Mutex` (no syscall in the non-contended case). The
thread-local `POOL` additionally skips shard hashing (shard 0, single-thread
by construction); the shared pool caches the hashed shard index per thread.

## Safety

The module has `#[deny(unsafe_code)]` - no unsafe blocks remain.

## Testing

- Unit: `cargo test -p synvoid-utils --lib buffer` (contract tests pin
  length/clear/resize/split/advance/truncate semantics).
- Accounting isolation: `cargo test -p synvoid-utils --test pool_accounting`
  (exact-counter tests live in their own binary because the counter is
  process-global; they serialize on a static mutex).
- Microbenchmarks (not routine CI): `cargo bench --bench bench_buffer_pool`.
