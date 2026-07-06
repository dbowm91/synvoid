# DNS Milestone 4 Phase 2: Performance and Load Testing

## Objective

Establish DNS performance baselines and identify bottlenecks under realistic authoritative, recursive, encrypted transport, cache, transfer, and control-plane workloads. This phase should produce repeatable benchmarks and tuning guidance rather than broad feature changes.

## Context

DNS protocol and safety semantics are now substantially stronger. Performance work should preserve those semantics and avoid regressions in cache key safety, coalescing exclusions, zone validation, DNSSEC correctness, recursive isolation, and transport limits.

## Non-goals

Do not optimize by weakening validation, authorization, DNSSEC behavior, cache dimensions, transport-class separation, or safe defaults. Do not pursue synthetic maximum RPS as the sole metric; include tail latency and resource use.

## Workstream 1: Benchmark harness selection

Tasks:

- Decide benchmark tooling:
  - Rust integration benchmark harness;
  - `dnsperf`/`resperf` if available;
  - `kdig`/`dig` loops for smoke only;
  - custom async load generator if needed.
- Add reproducible benchmark scripts under an appropriate path, such as `scripts/dns/` or `benchmarks/dns/`.
- Include machine/environment recording in output.
- Ensure benchmarks can run locally without requiring privileged ports.

Acceptance criteria:

- maintainers can run the same benchmark suite repeatedly and compare results.

## Workstream 2: Authoritative UDP/TCP baseline

Tasks:

- Benchmark authoritative A/AAAA/NS/SOA positive responses.
- Benchmark NODATA/NXDOMAIN responses with SOA authority.
- Benchmark signed versus unsigned responses if DNSSEC is available.
- Benchmark UDP512, UDP EDNS larger buffer, and TCP.
- Measure throughput, p50/p95/p99 latency, CPU, memory, cache hit rate, and error rate.

Acceptance criteria:

- authoritative baseline is recorded and reproducible.

## Workstream 3: Cache and coalescing performance

Tasks:

- Benchmark cold-cache and warm-cache workloads.
- Benchmark high duplicate-query workloads to measure coalescing benefit.
- Confirm unsafe classes remain excluded from coalescing under load.
- Measure cache insert/lookup/invalidation cost.
- Measure impact of transport/client/DO/qclass namespace dimensions on hit rate.
- Document expected hit-rate tradeoff from safety-first cache keys.

Acceptance criteria:

- cache/coalescing performance is understood without weakening safety invariants.

## Workstream 4: Zone size and mutation scaling

Tasks:

- Benchmark zone load time for small, medium, and large zones.
- Benchmark reload validation time.
- Benchmark cache invalidation for zone-wide reload.
- Benchmark UPDATE add/delete paths.
- Benchmark AXFR and IXFR for representative zone sizes.
- Measure memory overhead for zone history and IXFR deltas.

Acceptance criteria:

- operators have sizing guidance for zone counts, record counts, and transfer history retention.

## Workstream 5: Encrypted transport performance

Tasks:

- Benchmark DoT handshake and steady-state query latency.
- Benchmark DoH POST latency and body-size enforcement overhead.
- Benchmark DoQ if supported; otherwise document deferral.
- Measure TLS/QUIC certificate loading overhead and connection limits.
- Compare encrypted transport overhead against UDP/TCP baseline.

Acceptance criteria:

- encrypted transport overhead is measured and documented.

## Workstream 6: Recursive workload baseline

Tasks:

- Benchmark recursive disabled safe-default path.
- Benchmark recursive cache hit/miss behavior with mock or controlled upstream.
- Benchmark upstream timeout/failure/circuit-breaker behavior.
- Measure concurrency limits and per-client semaphore behavior.
- Avoid external public DNS dependencies in CI benchmarks.

Acceptance criteria:

- recursive mode has controlled, reproducible performance data.

## Workstream 7: Resource limits and failure behavior

Tasks:

- Stress max query size, response size, TCP connection limit, transfer limits, and recursive concurrency limits.
- Confirm overload returns deterministic errors and does not panic.
- Confirm shutdown under load drains or refuses cleanly.
- Confirm no unbounded task growth.
- Confirm memory usage stabilizes under repeated load.

Acceptance criteria:

- overload behavior is bounded and observable.

## Workstream 8: Benchmark reporting and regression guard

Tasks:

- Add benchmark output template.
- Record baseline results in docs or `benchmarks/dns/results/` if appropriate.
- Define thresholds for obvious regressions, but avoid brittle CI performance gates unless environment is stable.
- Add lightweight non-timing stress tests to CI where feasible.

Acceptance criteria:

- performance regressions can be detected manually and optionally by stable smoke tests.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo bench -p synvoid-dns --no-run
cargo check --workspace
```

Benchmark scripts should document their own invocation commands.

## Completion criteria

Phase 2 is complete when DNS has repeatable benchmarks, baseline measurements, overload tests, resource-limit validation, and documented performance guidance for authoritative, recursive, encrypted transport, cache/coalescing, transfer, and zone mutation workloads.
