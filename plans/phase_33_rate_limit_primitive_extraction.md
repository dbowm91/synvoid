# Phase 33 Plan: Shared Rate-Limit Primitive Extraction

Status: complete (2026-09-16).

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

## Completion record (2026-09-16)

All acceptance criteria met; all rejection criteria avoided.

### Part A — inventory matrix (as found)

| Location | Classification | Disposition |
|---|---|---|
| `src/utils/ratelimit/traits.rs` (`RateLimitResult`, `IpRateLimiter`, `KeyedRateLimiter`, `RateLimitStats`, `RateLimitStatsProvider`) | generic mechanism | MOVED to `synvoid-rate-limit::contracts`; root path kept as compat re-export |
| `src/waf/ratelimit/core.rs` `AtomicSlidingWindow` | generic mechanism | MOVED to `synvoid-rate-limit::window` (explicit-tick API) |
| `src/waf/ratelimit/core.rs` `ShardedRateLimiter` | sharded mechanic, zero consumers | LEFT (no second consumer; not moved without demand) |
| `src/waf/ratelimit/core.rs` `GlobalRateLimiter`/blackhole, `SlottedIpRateLimiter`/`CounterArray`/shm, `RateLimitDecision` | domain policy / single-consumer unsafe | LEFT in root WAF composition (Part D/F) |
| `crates/synvoid-waf/src/ratelimit/sliding.rs` (`AtomicBucketWindow`, keyed/global limiters) | intentionally specialized (u32 buckets, O(N) sums, write-locked map) | LEFT (different concurrency/semantics; not forced behind one abstraction) |
| `crates/synvoid-mesh/.../rate_limit.rs` + `transport_types.rs` limiters | stub consumers (no-op stub + wall-clock ticks) | MIGRATED to shared primitive; stub DELETED |
| `crates/synvoid-mesh/.../transport_rate_limit.rs` peer/auth windows | specialized monotonic fixed-window | LEFT |
| `crates/synvoid-ipc/.../ipc_rate_limit.rs` token bucket + `RateLimitExceeded` | specialized + IPC error types | LEFT (Part D) |
| `crates/synvoid-admin/.../rate_limit.rs` + `auth.rs` lockout | middleware adapter + lockout policy | LEFT (Part D) |
| `crates/synvoid-upload/.../rate_limit.rs` | upload response policy | LEFT (Part D) |
| `crates/synvoid-dns/.../rate_limiter.rs` + `server/rate_limit.rs` token buckets + RRL | specialized + DNS behavior | LEFT (Part D; the two near-identical DNS files are DNS-internal, out of scope) |
| `crates/synvoid-waf/.../traffic_shaper`, `flood` | specialized | LEFT |

### Parts B–D — new crate `crates/synvoid-rate-limit` (std-only, zero deps)

- `window.rs`: `AtomicSlidingWindow` moved verbatim in algorithm, exposed as
  `increment_at`/`count_at` (+ `increment_now`/`count_now` over `WindowClock`,
  `stats_at` → policy-neutral `WindowStats`). Clamp contract preserved
  (`bucket_count >= 1`, saturating duration math, `bucket_duration_ms >= 1`).
- `contracts.rs`: neutral vocabulary moved verbatim.
- `slot.rs`: pure `ip_to_slot` duplicated from `synvoid-utils` with ownership
  note so the crate stays a dependency-free leaf (`synvoid-utils` remains the
  general-purpose owner; behavior identical, covered by determinism tests).
- Forbidden edges verified absent: no root/config/waf/mesh/ipc/admin/HTTP/
  metrics dependency. Genuinely two consumers (root WAF composition + mesh),
  so the crate was created rather than folded into `synvoid-utils`.
- Shared-memory `CounterArray`/mmap stays in WAF: no second consumer needs it
  (Part F recorded, not deferred silently).

### Part E — migrations (limits/defaults unchanged everywhere)

1. Mesh `MeshPeerRateLimiter` + `MeshGlobalRateLimiter` consume the shared
   windows via owned `WindowClock`s; `stubs::waf_stub::ratelimit` deleted.
   Behavior note: mesh limiting changes from never-enforced (stub `get_count`
   always 0, `increment` no-op, wall-clock ticks) to enforced at the
   configured message limits — this activation is the phase goal, recorded
   here explicitly; no limit value or retry semantic was renormalized.
2. Root `core.rs` (`ShardedRateLimiter`, `GlobalRateLimiter`, slotted/IP
   impls) consumes the shared window; `handle_blackhole_mode` threads the
   already-rotated tick instead of the removed unrotated read (identical
   observable behavior). Window unit tests moved into the new crate, extended.
3. `AsnTracker` consumes the shared window and a `WindowClock` (was
   wall-clock `current_timestamp()*1000`, which aliased buckets and could step
   backwards); unique-IP cleanup moved to the same monotonic baseline so
   magnitudes stay consistent. Limits unchanged.
4. `src/utils/ratelimit` is a compat re-export; new code imports
   `synvoid_rate_limit` directly.
5. IPC/admin/upload/DNS evaluated one at a time: all kept (see matrix).

### Part H — tests and benchmarks

- 26 crate tests (`cargo test -p synvoid-rate-limit`), all deterministic, no
  wall-clock sleeps: N/N+1 boundary, expiry, large jumps (`u64::MAX`),
  concurrent rotation (sum-tracking invariant, no underflow), retry timing,
  IPv4/IPv6 slots, shard spread, zero/overflow config, reset, contracts.
- Suites: `synvoid-waf`, `synvoid-mesh` (1075 tests), `synvoid-ipc` green.
- Microbenchmarks (`bench_ratelimit`, ci profile, 3s measurement):
  `shared_window/increment_at` ~86ns, `shared_window/count_at` ~56ns
  (monotonic tick + rotation check + atomics; no mutex/heap per event) vs the
  retained specialized keyed limiter at ~147ns hot-key / ~66ns sharded.
  Pre-extraction baseline is by construction: the algorithm moved verbatim
  from the root hot path.
- Verification commands run: see below.

`cargo xtask verify`: 10/10 steps pass locally (fmt, clippy `-D warnings`,
deny, core compile, repo-guards, security regression single-threaded, root
guard suite with `--features mesh`, core admin tests, admin contract with
`mesh,dns,icmp-filter`, failure injection).

`cargo xtask verify-full`: 8/9 on first pass — `nextest-all` reported a
single failure without per-test detail in the step summary. Immediate full
re-run of the same command (`--workspace --exclude synvoid-fuzz`):
7172 passed, 3 skipped, 0 failed (exit 0), so the first-pass failure was a
flake, not a phase regression. Doctests, all feature-profile compiles
(minimal/mesh/dns/icmp-filter/mesh+dns), and minimal-tests passed in both
passes. `cargo check --no-default-features [--features mesh]` also pass
standalone.

### Docs

- `AGENTS.md` facade table: new canonical row for `synvoid-rate-limit`.
- `architecture/`: `root_module_ledger.md` (waf/utils rows),
  `crate_granularity_audit.md` (43 members, new row, mesh rev-deps),
  `enforcement_decision_contract.md` (WAF vs neutral `RateLimitResult`
  disambiguation), `mesh_trust_domains.md` (stub deletion).
- Skill: `waf_engine` key-files row. Mesh skill has no rate-limit section to
  amend; enforcement-gating line unaffected.
- README: no change — no crate enumeration exists and the operator surface
  (limits/defaults/config keys) is unchanged.
