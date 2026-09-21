# Phase 54 Plan: Buffer-Pool and Streaming-Memory Efficiency

Status: implementation handoff plan.

Roadmap: `plans/performance_optimization_roadmap.md`.

Depends on: Phase 49 buffer baseline complete. Final evidence should use the landed Phase 50/51 request-path state.

## Objective

Correct buffer-usage invariants discovered during the performance audit, then improve reuse/capacity accounting and cache-tee allocation behavior without changing the public `BufferPool`/`PooledBuf` API or increasing retained memory materially.

Correctness comes before nanosecond optimization in this phase.

## Critical semantic fact to lock down

`BufferPool::acquire(N)` returns a `PooledBuf` with logical length `N`, initialized to zero bytes as needed. It is not equivalent to `Vec::with_capacity(N)`.

Therefore this pattern is wrong:

```rust
let mut buf = BufferPool::acquire(n);
buf.extend_from_slice(data);
```

when the caller intends an empty buffer with capacity for `n`; it produces an initial logical region before the appended data.

The audit found this pattern in security-relevant normalization/streaming code. These defects must be corrected before performance conclusions are drawn from those paths.

## Workstream A — Add contract tests for `PooledBuf`

In `crates/synvoid-utils/src/buffer/pool.rs`, add tests that pin:

- `acquire(N).len() == N`;
- the first N bytes are writable logical bytes;
- `resize(0)` produces an empty logical buffer while retaining reusable capacity;
- `extend_from_slice` appends after the current logical end;
- `clear()` retains the documented logical-size behavior;
- `split_to`, `advance`, `truncate`, and `take_bytes` update length/accounting consistently;
- growth across small/medium/large/jumbo thresholds is handled correctly.

Do not change `acquire(N)` into a capacity-only API. Existing callers rely on writable length.

## Workstream B — Correct acquire-then-append call sites

Audit the entire repository for:

- `BufferPool::acquire(...)` followed by `extend_from_slice`;
- `put_slice`/Write-based appends after nonzero acquire;
- copies that assume acquire creates zero logical length.

Known targets include:

### WAF normalizer borrowed-to-pooled conversion

`crates/synvoid-waf/src/attack_detection/normalizer.rs` contains a borrowed normalized-data path that acquires `s.len()` and then extends with `s.as_bytes()`.

Use direct copy into `as_mut_slice()`, or explicitly `resize(0)` before append, so normalized bytes contain exactly the intended input.

### `NormalizedData` pooled clone

The pooled clone path acquires the source length and then extends from the source. Correct it so cloning produces byte-for-byte parity and the same logical length.

Add tests covering cloned normalized values containing NUL-adjacent/binary/lossy UTF-8 representations where applicable.

### Streaming WAF trailing windows

Streaming code creates some fixed-size pooled windows and then appends previous/current fragments. Correct initialization so the window contains only real trailing bytes, never a zero-filled prefix.

Add adversarial split-pattern tests across chunk boundaries. A performance change must not weaken cross-chunk SQLi/XSS/path/command detection.

Search results are not the acceptance boundary: audit every production caller.

## Workstream C — Correct accounting when ownership/capacity changes

Define and document what `GLOBAL_ALLOCATED_BYTES` means. Recommended contract: bytes/capacity currently checked out through pool-managed buffers, used as a soft backpressure indicator, not total process RSS and not free-list retained capacity.

Then make internal bookkeeping consistent with that definition.

### `take_bytes`

`take_bytes()` transfers the `BytesMut` out of `PooledBuf`; `Drop` then sees `None`.

Ensure accounted bytes are released exactly once when ownership leaves the pool wrapper. Add a regression test even if the current tree has no production call site; this is a public method.

### Growth

When `resize`, `extend_from_slice`, `put_slice`, or `Write::write` causes capacity growth:

- update accounting to reflect the new managed capacity according to the chosen contract;
- never underflow/overflow the counter;
- keep the memory limit explicitly soft;
- avoid an atomic update when capacity did not actually change.

### Return tier

A buffer that grows beyond its original tier must not be returned to a smaller-tier arena solely because its acquisition tier was cached in `PooledBuf`.

Reclassify on spill/return using actual capacity or store an updated tier whenever capacity crosses a threshold.

Avoid retaining pathological jumbo capacity in small/medium pools.

## Workstream D — Clarify local versus global pool behavior

Current design includes:

- `TLS_CACHE`;
- public thread-local `POOL: BufferPool`;
- shared `GLOBAL_POOL`;
- eight mutex-backed shards inside both local and global `BufferPool` instances.

Preserve public symbols/types.

Use Phase 49 benchmarks to evaluate the least invasive internal cleanup:

1. cache shard index per thread instead of hashing `ThreadId` on every arena access;
2. for a thread-local pool, avoid multi-shard hashing when only one thread can use it;
3. preserve sharding for the shared global pool;
4. track buffer origin privately if needed so global acquisitions spill back to the intended shared pool after TLS cache overflow;
5. do not eliminate TLS reuse if it is the dominant fast path.

Do not rewrite the allocator/pool from scratch unless measurements prove the existing structure is a dominant cost.

## Workstream E — Pre-size cache tee buffers from trustworthy size hints

In `crates/synvoid-proxy/src/streaming.rs`, `TeeBody` already:

- obtains an upper size hint;
- verifies it is nonzero and within `max_size`;
- reserves the same amount from `GlobalCacheGovernor`.

When those conditions hold, acquire a buffer sized for the known bounded hint and immediately set logical length to zero before streaming append, e.g. conceptually:

```rust
let mut buf = BufferPool::acquire(size_hint);
buf.resize(0);
```

This retains capacity without inserting zero bytes.

Requirements:

- never preallocate above the cache entry limit;
- release governor reservation exactly as before;
- abort cache fill if the body exceeds the reserved/max size;
- do not change downstream streaming/backpressure behavior;
- do not freeze/retain an oversized pooled allocation in the cache without separate RSS evidence.

## Workstream F — Memory/throughput evidence

Repeat Phase 49:

- small/medium/large same-thread reuse;
- TLS spill;
- global cross-thread reuse;
- grow within and across tiers;
- repeated acquire/grow/drop;
- cache tee at 1 KiB, 16 KiB, 64 KiB, 256 KiB and near max-entry size;
- streaming WAF trailing-window workloads.

Record:

- ns/op;
- allocation/growth count where available;
- pool hit/reuse stats;
- steady-state RSS;
- high-water RSS.

A 1-2% microbenchmark win does not justify a large retained-memory increase.

## Acceptance criteria

Phase 54 is complete only when:

- `BufferPool::acquire(N)` semantics remain unchanged and are explicitly tested;
- every acquire-then-append misuse in production code is audited and corrected;
- normalizer pooled conversion/clone returns byte-identical content with no zero prefix;
- streaming trailing-window detection retains cross-chunk attack coverage;
- `take_bytes` releases accounting exactly once;
- capacity growth cannot leave soft accounting permanently stale;
- grown buffers are not returned to an inappropriate smaller tier;
- public `POOL`, `GLOBAL_POOL`, `BufferPool`, and `PooledBuf` surfaces remain compatible;
- cache tee can exploit a trustworthy bounded size hint without changing streamed bytes;
- throughput does not materially regress and RSS/high-water behavior is acceptable.

## Verification

```bash
cargo test -p synvoid-utils --profile ci
cargo test -p synvoid-waf --profile ci
cargo test -p synvoid-proxy --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1
cargo xtask verify
cargo xtask verify-full
```

Run Phase 49 buffer/RSS/cache-tee benchmarks on the same host/profile.

## Rejection criteria

Reject a change that:

- changes `acquire(N)` to capacity-only semantics;
- fixes performance by weakening streaming cross-chunk detection;
- allows the memory counter to underflow or double-decrement;
- stores jumbo-grown buffers in small arenas;
- removes public pool symbols;
- increases retained RSS materially for a small latency win;
- adds unsafe custom allocation code;
- treats the discovered zero-prefix correctness issue as benchmark noise.
