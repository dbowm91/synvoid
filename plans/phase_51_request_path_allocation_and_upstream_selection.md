# Phase 51 Plan: Request-Path Allocation and Upstream-Selection Optimization

Status: implemented and closed; retained as historical handoff detail. Closeout: `architecture/performance_optimization_closeout.md`.

Roadmap: `plans/performance_optimization_roadmap.md`.

Depends on: Phase 49 complete. Phase 50 may run independently but final end-to-end comparison should use the landed Phase 50 state.

## Objective

Remove avoidable per-request allocation/copy work from upstream selection and buffered HTTP/WAF dispatch while preserving all public APIs and exact routing/load-balancing capability.

This phase is intentionally narrow: optimize ownership and selection mechanics, not routing policy.

## Workstream A — Eliminate candidate-vector allocation in `UpstreamPool`

Current canonical owner:

`crates/synvoid-upstream/src/pool.rs`

The current implementation materializes `Vec<&Backend>` candidates in several paths. Weighted round-robin then clones those candidates into `Vec<Backend>`.

Refactor private selection helpers so algorithms operate over filtered backend slices/iterators without heap allocation.

Required semantics to preserve:

- primary-before-backup behavior in `select_backend()`;
- current behavior of `select_backend_for_ip()`, including its existing availability/filtering semantics;
- protocol equality filtering in `select_backend_for_protocol()`;
- exclusion of the current backend in `select_next_backend()`;
- backup fallback behavior;
- round-robin counter progression;
- weighted-round-robin weight distribution, including total weight zero behavior;
- Peak-EWMA cost formula;
- LeastConnections/composite-load ordering;
- Random uniform candidate selection;
- returned `Backend` clone semantics;
- `try_select_backend()` nonblocking lock behavior.

Do not "fix" an algorithm's policy while optimizing its mechanics. Any policy change is a separate compatibility decision.

### Suggested private implementation shape

A private predicate-driven selection helper is acceptable if it does not monomorphize into excessive code. Alternatives include:

- two-pass filtered iterators for count/index algorithms;
- one-pass reductions for LeastConnections/PeakEwma;
- two-pass weighted selection (sum weights, then select remainder);
- reservoir selection for Random if distribution tests prove parity.

Do not introduce a temporary `SmallVec` dependency merely to hide the allocation.

## Workstream B — Add distribution/parity tests before changing selection

For deterministic algorithms, compare old/reference and new selection sequences over:

- 1, 4, 16 backends;
- mixed weights including zero;
- unavailable backends;
- primary/backup mixtures;
- protocol filters;
- connection/load/latency differences.

For Random, use statistical/property checks appropriate to the existing contract rather than pinning exact RNG output.

For IP hash, verify stable mapping for the same backend set/order and client IP. Do not change hashing algorithm in this phase.

## Workstream C — Remove unused ownership from canonical buffered-WAF dispatch

Canonical files:

- `crates/synvoid-http/src/buffered_request_waf_dispatch.rs`
- `crates/synvoid-http/src/http_request_postlude.rs`

The public `synvoid_http::maybe_handle_buffered_request_waf` signature currently accepts owned values that the crate-level implementation names as unused, including query/header/body/user-agent snapshots.

Preserve that public function and signature for compatibility.

Add a private/internal core helper with only the data actually required to:

- determine serverless WAF mode;
- execute the supplied WAF check future;
- resolve/render the WAF decision.

Have the existing public function delegate to the internal helper.

Update the canonical in-crate HTTP request path to call the internal helper directly so it does not construct unused:

- query `String`;
- `HeaderMap` clone;
- `Bytes` body clone;
- user-agent `String`;
- other compatibility-only snapshots.

The root compatibility adapter may keep using the public wrapper. Do not move canonical implementation back into `src/http/`.

## Workstream D — Audit closure-capture clones in `http_request_postlude`

After removing arguments that exist only for the public wrapper, inspect the remaining clones around:

- `site_id`;
- method/path;
- query;
- headers;
- bot config;
- user agent;
- JA4;
- target.

Only remove a clone when lifetime/ownership can be simplified without making the request future non-`Send` where callers require `Send`.

Prefer:

- `Arc<str>`/existing Arc-owned config already present in surrounding types;
- moving values once into a closure;
- borrowing before the async boundary where lifetime permits.

Do not redesign public request context structs in this phase.

## Workstream E — Benchmark and allocation evidence

Use Phase 49's upstream benchmark.

Primary comparisons:

- selection ns/op at 1/4/16/64 backends;
- allocations per selection if measurable;
- weighted round-robin;
- least connections;
- IP hash;
- protocol selection;
- retry/next backend.

For buffered HTTP/WAF, use a focused request-pipeline benchmark or allocation counter that reaches `handle_http_request_postlude` with a representative WAF pass. Record clone/copy/allocation delta if practical.

## Acceptance criteria

Phase 51 is complete when:

- all existing public upstream and HTTP/WAF APIs remain source-compatible;
- upstream selection no longer allocates candidate vectors on the targeted hot paths;
- weighted round-robin does not allocate a second cloned vector;
- deterministic selection/failover behavior is covered by parity tests;
- random selection remains statistically consistent with the current contract;
- the canonical buffered-WAF path no longer creates owned values that the internal decision helper does not consume;
- WAF/routing/backend behavior is unchanged;
- Phase 49-comparable benchmarks show improvement or at least no material regression;
- upstream, proxy, HTTP, HTTP/3 parity and root guard suites remain green.

## Verification

```bash
cargo test -p synvoid-upstream --profile ci
cargo test -p synvoid-proxy --profile ci
cargo test -p synvoid-http --profile ci
cargo test --test http_tls_parity --profile ci
cargo xtask test guards
cargo xtask verify
```

Run the Phase 49 upstream/request-path benchmarks at the same profile and host.

## Rejection criteria

Reject a change that:

- changes backend ordering/failover policy to simplify iteration;
- changes public signatures/types to remove a clone;
- swaps the IP hash implementation;
- changes random distribution;
- creates a new dependency for a small candidate buffer instead of removing the allocation;
- moves canonical HTTP logic into root compatibility modules;
- wins a microbenchmark by skipping WAF/backend work.
