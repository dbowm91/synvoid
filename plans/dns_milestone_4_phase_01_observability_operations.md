# DNS Milestone 4 Phase 1: Observability and Operations Readiness

## Objective

Move the DNS subsystem from correctness-focused implementation to operator-ready behavior. This phase focuses on metrics, logs, health surfaces, diagnostics, runtime status, alertable failure modes, and operational runbooks.

## Context

Milestones 1-3 hardened protocol correctness, runtime/config/cache safety, advanced control-plane behavior, DNSSEC primitives, encrypted transports, and recursive isolation. Milestone 4 should now make those behaviors visible and debuggable in production.

## Non-goals

Do not add new DNS protocol features. Do not perform high-scale load testing in this phase except for light metric sanity checks. Do not claim production release readiness until later Milestone 4 verification phases.

## Primary files

- `crates/synvoid-dns/src/metrics.rs`
- `crates/synvoid-dns/src/server/*`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/recursive.rs`
- `crates/synvoid-dns/src/transfer.rs`
- `crates/synvoid-dns/src/update.rs`
- `crates/synvoid-dns/src/notify.rs`
- `crates/synvoid-dns/src/dot.rs`
- `crates/synvoid-dns/src/doh.rs`
- `crates/synvoid-dns/src/doq.rs`
- DNS docs and dashboard/runtime status integration points

## Workstream 1: Metrics inventory and taxonomy

Tasks:

- Inventory existing DNS metrics.
- Define stable metric names and labels for:
  - transport: udp, tcp, dot, doh, doq;
  - operation: query, update, notify, axfr, ixfr;
  - response code;
  - cache hit/miss/stale/negative;
  - coalescing owner/waiter/timeout/cancel;
  - recursive upstream provider;
  - DNSSEC signing/validation state;
  - zone state;
  - control-plane authorization outcomes.
- Avoid qname, full client IP, TSIG key name, or other high-cardinality/sensitive labels.
- Convert any `_total` gauges to counters unless intentionally measuring in-flight state.
- Add documentation for metric semantics.

Acceptance criteria:

- metrics are stable, low-cardinality, and operator-readable.

## Workstream 2: Health and readiness endpoints/surfaces

Tasks:

- Define DNS health states:
  - listener bound;
  - authoritative zones loaded;
  - recursive mode healthy/degraded/disabled;
  - cache operational;
  - DNSSEC key/signing state;
  - encrypted transport cert state;
  - transfer/update policy state.
- Add or wire health status into existing Synvoid health/admin surfaces.
- Distinguish liveness from readiness.
- Include per-zone health summary without leaking full zone contents.
- Include last load/reload failure and timestamp.

Acceptance criteria:

- operators can tell if DNS is alive, ready, degraded, or unsafe to serve.

## Workstream 3: Structured logging and audit events

Tasks:

- Add structured logs for:
  - zone load/reload success/failure;
  - invalid-zone rejection;
  - UPDATE accepted/refused/failed;
  - NOTIFY accepted/ignored/refused;
  - AXFR/IXFR accepted/refused/fallback;
  - DNSSEC key/signature events;
  - recursive upstream failures/circuit breaker transitions;
  - encrypted transport cert/config failures;
  - cache invalidation events.
- Redact TSIG secrets, private keys, full query payloads, and sensitive client data.
- Ensure log levels are consistent: debug for normal detail, info for lifecycle, warn for degraded/refused policy events, error for failed required operations.

Acceptance criteria:

- production incidents can be diagnosed without enabling unsafe verbose logging.

## Workstream 4: Operator diagnostics commands or docs

Tasks:

- Add documented commands for local DNS diagnostics:
  - UDP/TCP query smoke;
  - DoT/DoH/DoQ smoke;
  - AXFR/IXFR smoke;
  - DNSSEC smoke;
  - recursive safe-default smoke;
  - cache/metrics inspection.
- Add a lightweight script if project conventions allow.
- Keep scripts optional and non-invasive.

Acceptance criteria:

- a maintainer can verify a DNS instance manually from docs.

## Workstream 5: Runtime status documentation

Update:

- `architecture/dns.md`
- `architecture/dns_config_runtime_matrix.md`
- DNS operations docs if present
- agent skill docs

Document:

- metric names;
- alertable conditions;
- health meanings;
- degraded-mode behavior;
- log redaction policy;
- diagnostic commands.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns metrics
cargo test -p synvoid-dns health
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 1 is complete when DNS has stable metrics, health/readiness status, structured audit logs, operational diagnostics, and documentation sufficient for maintainers to diagnose production issues without reading source code first.
