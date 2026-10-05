# Phase 127 Plan: DNS Recursive Resolver Runtime-Config Cutover

Status: **PLANNED / READY** (2026-10-04). Unblocked by Phase 126, which closed QUALIFIED on 2026-10-04 with `architecture/dns_runtime_dto_phase126_closeout.md`.

Registered in: `plans/roadmap.md` and
`plans/dns_runtime_dto_conversion_roadmap.md`.

Predecessor evidence: Phase 126 closeout
(`architecture/dns_runtime_dto_phase126_closeout.md`) — the authoritative side
is clean and the residual persistence edge is concentrated in the recursive
subtree plus `runtime_config_deferred.rs`.

## Goal

Remove persisted `synvoid-config` types from the recursive resolver, cache,
ACL and circuit-breaker runtime while preserving open-resolver protections,
DNSSEC-provider truthfulness and authoritative/recursive isolation.

## Workstream A — recursive runtime subtree

Make the recursive server consume a DNS-owned `RecursiveRuntimeConfig`
containing typed values for:

- bind address;
- upstream selection/endpoints;
- recursive cache;
- DNSSEC validation flag;
- QNAME minimization;
- query timeout;
- global concurrency;
- rate limit;
- implemented firewall policy;
- root hints and trust-anchor paths;
- client ACL;
- CNAME/recursion depth;
- per-client concurrency;
- circuit breaker;
- ECS runtime behavior.

No Serde/OpenAPI ownership belongs in this subtree.

## Workstream B — upstream normalization

Replace the persisted ambiguous upstream representation with runtime values that
differentiate:

- System;
- Google;
- Cloudflare;
- Custom endpoint(s);
- true recursive/root-hints operation;
- GlobalNodes only if still required for parity before provider inversion.

Parse custom IP/socket information before runtime startup. Hostnames must remain
distinguishable from literal IP endpoints.

Lower runtime values to Hickory privately.

## Workstream C — ACL policy ownership

Move `RecursiveClientAcl::is_client_allowed()` runtime policy out of
`synvoid-config`.

The runtime ACL should hold parsed networks and an explicit action enum, not
arbitrary strings.

Preserve:

- empty allow-list semantics;
- CIDR matching;
- reject/allow action behavior;
- invalid CIDR rejection before listener startup.

## Workstream D — recursive cache and circuit breaker

Make `RecursiveDnsCache::new()` and `CircuitBreaker::new()` consume
DNS-owned runtime config.

Preserve:

- positive/negative cache separation;
- min/max/stale/negative TTL semantics;
- capacity behavior;
- circuit-breaker thresholds and recovery;
- health-state reporting.

## Workstream E — open-resolver and DNSSEC truthfulness gates

Pin differential tests for:

- rejection of `0.0.0.0` / `::` recursive binds;
- invalid bind rejection before startup;
- custom-upstream requires endpoints;
- depth/concurrency limits;
- forwarder mode warning/truthfulness: no local DNSSEC validation claim;
- true recursive mode validation path with root hints/trust anchor;
- authoritative and recursive caches/listeners remain isolated.

## Workstream F — tests

Migrate recursive DNS crate tests to runtime types.

Root adapter tests retain persisted-config parity and typed validation paths.

At phase close, recursive production code should have no
`synvoid_config::dns::Recursive*` dependency.

## Verification

```bash
cargo test -p synvoid-dns -- recursive --profile ci
cargo test -p synvoid-dns -- recursive_cache --profile ci
cargo test -p synvoid-dns --test dns_recursive_isolation --profile ci
cargo test -p synvoid-dns --test dns_config_fidelity --profile ci
cargo test -p synvoid-config --profile ci
cargo check --no-default-features --features dns --profile ci
cargo xtask verify
cargo deny check
cargo audit
```

## Acceptance criteria

- recursive runtime owns its own config/policy values;
- open-resolver prevention and validation order are unchanged;
- Hickory config remains internal lowering detail;
- cache/ACL/circuit-breaker semantics retain parity;
- no persisted recursive type appears in production recursive APIs.

## Rejection criteria

Reject implementation that:

- weakens open-resolver prevention;
- converts invalid CIDRs lazily on request path;
- represents ACL action as unchecked string runtime state;
- claims DNSSEC validation for forwarder modes that do not perform it;
- merges authoritative and recursive state while refactoring.
