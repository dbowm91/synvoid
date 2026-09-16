# Phase 33 Plan: Shared Rate-Limit Primitive Extraction

Status: planned (2026-09-16).

Roadmap: `plans/crate_boundary_reuse_followup_roadmap.md`.

Primary goal: extract reusable rate-limit mechanisms that are already duplicated, stubbed, or trapped behind the root WAF boundary into one small library crate, while leaving all domain-specific policy in its owning subsystem.

## Current problem

SynVoid has several independent limiting implementations and contracts:

- root `src/utils/ratelimit` defines generic `IpRateLimiter`, `KeyedRateLimiter`, `RateLimitResult`, and stats contracts;
- root WAF rate-limit code owns `AtomicSlidingWindow`, sharded/IP-slot machinery, shared-memory counter support, and global limiting mechanics;
- mesh has its own rate-limit implementations and currently reaches a stubbed sliding-window primitive instead of consuming the root WAF implementation;
- IPC, admin/auth, uploads, DNS/mesh and other subsystems own separate limiting policy and/or mechanisms.

The missing boundary is a mechanism crate below those domains. This phase creates that boundary only for code that has at least two concrete consumers or removes an existing stub/duplication.

## Part A — Inventory and classify all rate-limit code

Create a source-level matrix for every rate limiter or sliding-window implementation in the workspace. At minimum inspect:

```text
src/utils/ratelimit/**
src/waf/ratelimit/**
src/waf/asn_tracker.rs
crates/synvoid-mesh/**/rate_limit.rs
crates/synvoid-mesh/**/transport_types.rs
crates/synvoid-ipc/src/ipc_rate_limit.rs
crates/synvoid-admin/src/auth.rs
crates/synvoid-admin/src/rate_limit.rs
crates/synvoid-upload/src/rate_limit.rs
crates/synvoid-dns/**
```

Classify each item as:

- generic mechanism;
- domain policy;
- transport/middleware adapter;
- metrics/observability adapter;
- duplicate/stub;
- intentionally specialized implementation.

Do not force implementations with materially different concurrency or semantics behind one abstraction merely because they share the phrase "rate limit".

## Part B — Create `synvoid-rate-limit` only with a narrow dependency budget

Add a workspace member `crates/synvoid-rate-limit` if Part A confirms the current audit findings.

Target crate responsibilities:

- `RateLimitResult` and generic keyed/IP contracts where they are actually useful across consumers;
- monotonic sliding-window counter primitive;
- reusable sharded/keyed admission mechanics;
- IP-to-slot integration through a low-level helper or local pure function;
- stats structures that are policy-neutral;
- optional shared-memory counter storage only if at least one non-WAF consumer needs it.

The crate should remain low in the graph. Preferred dependencies are std-only or a very small set of synchronization/storage primitives. It must not depend on:

- root `synvoid`;
- `synvoid-config`;
- `synvoid-waf`;
- `synvoid-mesh`;
- `synvoid-ipc`;
- `synvoid-admin`;
- HTTP/Axum/Hyper;
- `synvoid-metrics`.

Depending on `synvoid-utils` is acceptable only for a genuinely canonical leaf helper and only if it does not pull optional/broad functionality. Duplicating a tiny pure hash/slot function may be preferable to an unnecessary upward coupling if ownership is documented.

## Part C — Make time explicit and deterministic

The generic mechanism must not require wall-clock calls buried throughout policy code.

Preferred API patterns:

```rust
window.increment_at(now_tick)
window.count_at(now_tick)
```

with convenience wrappers using a monotonic clock where useful.

Requirements:

- production behavior uses monotonic time for windows;
- tests can advance time deterministically without sleeps;
- duration/tick overflow uses saturating or explicitly checked arithmetic;
- reset/rotation behavior is defined for large time jumps;
- concurrent rotation must not underflow the running sum;
- zero/degenerate configuration is rejected or clamped by documented contract, not by accident.

## Part D — Separate mechanism from policy

The following must remain outside the generic crate unless a later consumer proves they are generic:

- WAF `Blackholed` state and adaptive probe/backoff behavior;
- attack/threat-level decisions;
- auth brute-force lockout semantics;
- admin middleware/Axum extraction;
- upload-specific response policy;
- IPC connection rejection/error types;
- mesh peer reputation/trust policy;
- DNS-specific response behavior;
- SynVoid metric names and logging messages.

Domain crates should adapt the generic result into their existing domain decision types.

Example boundary:

```text
synvoid-rate-limit: window says count/remaining/retry timing
synvoid-waf: decides Limited vs Blackholed and enforcement action
synvoid-ipc: decides connection/message rejection and error
synvoid-admin: maps to middleware response
synvoid-mesh: applies per-peer/global policy
```

## Part E — Migrate consumers incrementally

Recommended order:

1. move the generic root trait/result vocabulary;
2. move `AtomicSlidingWindow` and add deterministic tests;
3. migrate mesh and remove the sliding-window stub;
4. migrate WAF to the shared primitive while preserving WAF policy;
5. evaluate IPC/admin/upload/DNS use one at a time;
6. move shared-memory/IP-slot machinery only after demonstrated reuse.

Each migration must preserve observable limits and defaults. Do not normalize different existing limit values or retry behavior as part of this architectural phase.

## Part F — Shared-memory safety review

If `CounterArray`/mmap-backed counters move into the crate, treat that as a separate unsafe-memory boundary.

Requirements:

- explicit alignment and length validation before casting bytes to atomics;
- checked offset/length arithmetic;
- documented inter-process initialization/versioning assumptions;
- architecture support for atomic width/alignment;
- tests for truncated/corrupt mappings;
- no safe API may construct an invalid shared counter region.

If these requirements make the extraction disproportionately complex and no second consumer needs the mmap implementation, keep shared-memory storage in WAF and extract only the in-process mechanism.

## Part G — API and naming

Avoid embedding WAF terminology in the generic crate.

Prefer names such as:

- `SlidingWindow` / `AtomicSlidingWindow`;
- `LimitDecision` or the existing neutral `RateLimitResult`;
- `KeyedLimiter`;
- `IpLimiter`;
- `WindowStats`.

Do not expose `blackhole`, `threat`, `attack`, `admin`, `upload`, or `mesh` concepts.

The root `src/utils/ratelimit` path may remain a compatibility re-export temporarily if internal/external users require it. New domain code must import `synvoid_rate_limit` directly.

## Part H — Tests and performance evidence

Required correctness tests:

- boundary at exactly N and N+1 events;
- window expiration and bucket rotation;
- long time jumps clearing stale buckets;
- concurrent increments during rotation;
- deterministic retry-after/reset timing;
- IPv4/IPv6 keyed behavior if included;
- shard distribution invariants;
- zero/overflow configuration handling;
- reset semantics.

Use property tests where useful for rotation arithmetic and time jumps.

Add a microbenchmark comparing the extracted primitive with the pre-extraction hot path or preserve the existing benchmark. The extraction must not introduce mutexes/heap allocation per request on the WAF/mesh hot path.

## Acceptance criteria

Phase 33 is complete only when:

- at least two production subsystems consume the extracted mechanism;
- mesh no longer needs a fake/stub sliding-window implementation for ownership reasons;
- WAF/domain policy remains in the domain crates;
- generic crate dependency surface stays narrow;
- no SynVoid metric names or config types leak into the primitive crate;
- deterministic tests require no wall-clock sleeps for window behavior;
- existing configured limits/defaults are behaviorally compatible;
- unsafe shared-memory machinery, if moved, has an explicit safety contract and corruption tests;
- architecture/crate-granularity docs record the new crate and reverse dependencies.

If the inventory fails to find two genuine consumers after removing stubs/duplicates, do not create the crate; instead move the smallest generic primitives into `synvoid-utils` or the nearest canonical owner and record the rejected extraction in the closeout.

## Rejection criteria

Reject an implementation that:

- moves all rate-limit policy into one central crate;
- makes the primitive crate depend on WAF/config/admin/mesh/IPC;
- changes operator limits or blackhole semantics without an explicit separate change;
- introduces blocking synchronization on request hot paths without benchmark evidence;
- preserves the mesh stub after a real shared primitive exists;
- adds mmap/unsafe complexity without a second consumer.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo check -p synvoid-rate-limit --all-targets
cargo test -p synvoid-rate-limit
cargo test -p synvoid-waf
cargo test -p synvoid-mesh
cargo test -p synvoid-ipc
cargo xtask verify
cargo xtask verify-full
cargo check --no-default-features
cargo check --no-default-features --features mesh
```

Run relevant rate-limit benchmarks before and after migration and retain the results in the phase closeout evidence.
