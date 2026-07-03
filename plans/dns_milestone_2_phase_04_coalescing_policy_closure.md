# DNS Milestone 2 Phase 4: Query Coalescing Policy Closure

## Objective

Complete query coalescing as a safe production optimization. The first implementation pass added stronger key dimensions, owner/waiter lifecycle behavior, metrics, cancellation, and stale cleanup. This phase aligns coalescing semantics with cache semantics and excludes query classes where coalescing is unsafe.

## Current state

Already improved:

- `QueryKey` includes qname, qtype, qclass, DNSSEC DO bit, EDNS UDP size, and client IP.
- waiters subscribe without holding the in-flight lock.
- owner broadcasts remove the key.
- owner cancellation removes the key.
- metrics exist for hits, misses, evictions, timeouts, lagged receivers, broadcasts, cancels, and in-flight count.

Still requiring closure:

- transport class and authoritative/recursive namespace are not explicit in `QueryKey`;
- EDNS UDP size is derived from raw offsets instead of parsed EDNS data;
- unsafe query classes need explicit exclusion;
- metrics named `_total` are implemented as gauges and may need counter semantics;
- integration tests should prove waiter behavior.

## Primary files

- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/parsed_query.rs`
- `crates/synvoid-dns/src/metrics.rs`

## Workstream 1: Align QueryKey with response-shaping dimensions

Tasks:

- Decide whether `QueryKey` should embed:
  - transport class;
  - authoritative/recursive namespace;
  - ECS/client subnet policy key;
  - qname privacy redaction strategy.
- Align with `CacheKey` where practical.
- Add a documented `CoalescingKeyPolicy` comment explaining any differences from `CacheKey`.
- Replace `edns_udp_size` raw offset extraction with a parsed EDNS value.
- Normalize EDNS payload into buckets if exact size would over-fragment coalescing.

Tests:

- UDP512 and TCP differ if response shape differs.
- authoritative and recursive differ if coalescer is shared.
- DO=true and DO=false differ.
- qclass differs.
- client policy dimension differs.

Acceptance criteria:

- Coalescing key dimensions are explicitly safe.

## Workstream 2: Exclude unsafe query classes

Tasks:

- Exclude AXFR and IXFR from coalescing.
- Exclude UPDATE and NOTIFY.
- Exclude malformed queries.
- Decide whether REFUSED no-zone responses can coalesce; document decision.
- Decide whether DNS cookies affect response shape and should be part of key or exclusion criteria.

Tests:

- AXFR/IXFR bypass coalescer.
- UPDATE/NOTIFY bypass coalescer.
- malformed query bypasses coalescer and receives validator policy.
- cookie challenge/invalid cookie behavior is not incorrectly shared.

Acceptance criteria:

- Coalescing cannot change semantics for stateful/control-plane DNS messages.

## Workstream 3: Owner/waiter concurrency tests

Tasks:

- Add Tokio tests for direct `QueryCoalescer` behavior.
- Add a test with one owner and one waiter.
- Add a test with one owner and many waiters.
- Add owner cancellation behavior test.
- Add waiter timeout behavior test.
- Add cleanup stale entry test.
- Add broadcast-after-cleanup safety test.

Acceptance criteria:

- waiters receive the owner response on success.
- cancelled/timeout paths do not leave stuck entries.

## Workstream 4: Metrics correction

Tasks:

- Review `metrics::gauge!("*_total")` usage.
- Convert monotonic counts to counters if the metrics crate supports it.
- Keep in-flight as a gauge.
- Avoid qname labels.
- Add snapshot method for tests if needed.

Acceptance criteria:

- metric type matches metric semantics.
- operators can distinguish coalescing wins from timeout pathologies.

## Workstream 5: Server integration tests

Tasks:

- Add integration test where two equivalent positive queries coalesce.
- Add equivalent NODATA and NXDOMAIN coalescing tests if policy allows.
- Add test proving non-equivalent DO/EDNS/client queries do not coalesce.
- Add test proving cache hits bypass duplicate work where possible.

Acceptance criteria:

- server integration uses coalescing safely, not only direct unit tests.

## Workstream 6: Documentation

Update docs with:

- coalescing key dimensions;
- excluded query classes;
- timeout/cancel policy;
- metrics meanings;
- relation between cache key and coalescing key.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns query_coalesce
cargo test -p synvoid-dns coalesc
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 4 is complete when coalescing key policy is aligned with response semantics, unsafe query classes are excluded, owner/waiter lifecycle is concurrency-tested, metrics use correct types, and integration tests prove safe behavior.
