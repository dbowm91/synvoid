# Shared-Memory Atomic Contract (Phase 42)

Binding decision for `synvoid-upstream::shared_state` (Workstream D), with
the ownership, file-hardening, and API-narrowing contracts from Workstreams
C, E, and F recorded alongside so the unsafe boundary has a single home.

## 1. What is shared

Two supervisor-created, file-backed tables coordinate worker processes:

| Table | Contents | Element types |
|-------|----------|---------------|
| `SharedConnectionTable` | per-worker heartbeats + per-worker/per-backend connection counters | `AtomicU64` heartbeats, `AtomicUsize` counters |
| `SharedRateLimitTable` | per-slot second/minute/five-minute counters + dirty-bit words | `AtomicU32` throughout |

Byte layouts (all header integers little-endian):

```text
connection (v1, magic "SVCT" 0x54435653):
[0..4]   magic u32 = 0x54435653
[4..8]   version u32 = 1
[8..16]  max_workers u64
[16..24] max_backends u64
[24..32] reserved u64 (zero)
[32..32 + max_workers*8]              heartbeats (AtomicU64 per worker)
[32 + max_workers*8 ..]               connections (AtomicUsize [worker][backend])

rate-limit (v1, magic "SVRL" 0x4C525653):
[0..4]   magic u32 = 0x4C525653
[4..8]   version u32 = 1
[8..16]  num_slots u64
[16..16 + N*4]                        second counters (AtomicU32 per slot)
[.. + N*4]                            minute counters
[.. + N*4]                            five-minute counters
[.. + ceil(N/32)*4]                   dirty-bit words (AtomicU32 per 32 slots)
```

## 2. Architecture decision (Workstream D)

- **Supported targets.** Linux x86_64 and Linux aarch64 are the supported
  production targets. Other Unix targets build and run the same code
  best-effort; Windows builds (file-backed `MmapMut` exists there) but
  cross-process atomic sharing on Windows is not a supported performance
  contract — correctness falls back to process-local counters whenever no
  table is opened in the consuming process.
- **Hardware assumption.** The implementation relies on hardware
  cache-coherent process-shared mappings (`MAP_SHARED`, writable) as
  provided by `memmap2::MmapMut` on Linux. No userspace replication,
  file-locking, or explicit cache-maintenance protocol is layered on top:
  coherence comes from the platform's coherent data cache. Targets without
  that guarantee are not claimed supported.
- **`AtomicUsize` width.** Connections-region sizes are computed with
  `size_of::<AtomicUsize>()` at construction (layout validation) and reused
  at access time (offset helpers). A 32-bit and a 64-bit process therefore
  compute different layouts for the same dimensions by construction.
- **Mixed-version / mixed-architecture access is impossible by
  construction.** Mappings are recreated on every supervisor generation
  (`create(true)` + `truncate(true)`) with a magic + version header, and are
  never reinterpreted across binaries. `open_existing` rejects magic
  mismatch, unsupported version, dimension/bound violations, and
  total-length/mapping mismatches as `InvalidData` before any atomic
  reference is constructed. There is no upgrade path that reuses a file
  written by a different binary or architecture.
- **Required mapping type.** Shared, writable, file-backed (`MmapMut`);
  read-only or private mappings cannot back these tables. Creators size the
  file with `set_len` before mapping; openers never truncate or re-size.
- **Ordering semantics.** Heartbeats use `SeqCst` on store (publication) and
  `Relaxed` on load (liveness sampling); connection and rate-limit counters
  use `Relaxed` for fetch-add/load/store except where a call site documents
  otherwise. No counter value is used as a synchronization edge for other
  memory — they are loss-tolerant statistics and liveness hints, which is
  why `Relaxed` is sound here. Cross-process visibility (not ordering) comes
  from the shared mapping itself.
- **What was deliberately not done.** No portability crate was introduced to
  rename the same assumption: the contract above names the actual hardware
  and mapping requirements instead of hiding them behind a facade.

## 3. Ownership and lifecycle (Workstream C)

- The supervisor is the sole creator. `new` truncates, sizes, header-writes
  (safe byte copies, zero other writes needed — `set_len` zero-fills), and
  maps, all before any worker is spawned. Publication to the in-process
  global happens after `new` returns; cross-process publication happens via
  process spawn, which is the happens-before edge.
- Workers never truncate. Any future worker-side observation must go through
  `open_existing`, which validates magic/version/dimensions/total-length and
  mapping alignment with no destructive side effects.
- Inventory result (2026-09-18): no worker maps or opens these files today.
  Worker processes that never call `open_existing` see `None` from the
  per-process globals and use process-local counters (`ConnectionCounter::Local`,
  `SlottedIpRateLimiter::new`). That fallback is intentional and tested, not
  a silent sharing failure.
- Stale files are always truncated by the creator; openers always validate.
  A file from an older binary fails the magic/version check deterministically.

## 4. Layout validation (Workstreams A + B)

- `ConnectionTableLayout::new` / `RateLimitTableLayout::new` are the only
  constructors: nonzero dimensions, explicit upper bounds (4096 workers,
  8192 backends, 2^24 slots), `checked_mul`/`checked_add`/checked
  ceil-division, `u64` convertibility for `set_len`, a 512 MiB mapping
  ceiling, and release-mode alignment proofs for every region base.
  Caller-controlled dimension errors are `InvalidInput` and never panic
  (no `assert!` on the sizing path).
- Every unsafe reference construction proves, in release mode: index in
  range, checked byte offset, offset + element size within the mapping,
  offset and pointer alignment for the element type, and type-exclusive use
  of the region. Construction proves whole-region invariants once;
  per-access checks are bounds plus the documented alignment re-check.
- Each `unsafe` block carries an adjacent `// SAFETY:` comment naming the
  constructor invariant that makes it sound.

## 5. File and path hardening (Workstream E)

- Paths are `PlatformPaths::runtime_dir` + fixed names (`connections.shm`,
  `ratelimit.shm`). No component comes from operator configuration, so there
  is no attacker-controlled path to follow.
- Creators ensure the parent via `SecureDir` (0700 on Unix), reject symlink
  final components (pre-open `symlink_metadata` check plus `O_NOFOLLOW` on
  Unix to close check/open TOCTOU), reject non-regular targets, create with
  mode `0600` on Unix, and re-tighten to `0600` after sizing so truncating a
  pre-existing wider-mode file cannot leave shared state world-readable.
- Platform primitives are reused (`SecureDir`, `set_file_permissions`);
  only the `O_NOFOLLOW` open flag (via `libc`) is local to the crate.

## 6. Narrow API (Workstream F)

- `SharedRateLimitTable::get_mmap()` is removed. Rate-limit consumers use
  typed slices — `second_counters()`, `minute_counters()`,
  `five_min_counters()`, `dirty_words()` — and `num_slots()`.
- The root WAF `CounterArray::Shared` holds a `SharedRateLimitTable` plus a
  `SharedCounterRegion` tag instead of a raw `MmapMut` + offset + length;
  `SlottedIpRateLimiter::from_shared_table` replaces `new_shared(mmap)` and
  fails closed to local counters on a slot-count mismatch. Offset formulas
  exist in exactly one place (`RateLimitTableLayout`).
- The mmap implementation stays in `synvoid-upstream`. `synvoid-rate-limit`
  remains a std-only mechanism crate with no mmap/process policy (Phase 33
  boundary preserved).

## 7. Tests

- `shared_state.rs::layout_tests` (pure, no filesystem): zero dimensions,
  1×1 minimum, production sizes (266×2048, 65536 slots), `usize::MAX`,
  overflow, constructor bounds, dirty-bit ceil boundaries 31/32/33,
  per-region alignment, last-valid/first-invalid indices, `AtomicUsize`-width
  dependence.
- `crates/synvoid-upstream/tests/shared_state.rs` (file-backed): header
  round-trips, independent-handle visibility, garbage/truncation/version
  rejection, fail-closed dimensions and out-of-range access, symlink and
  non-regular rejection, Unix owner-only file/dir modes, and a true
  child-process test (parent creates, child `open_existing`s in a separate
  OS process, acks flow back through the shared mapping).
- Run: `cargo test -p synvoid-upstream --profile ci`.
