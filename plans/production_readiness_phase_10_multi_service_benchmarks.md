# Phase 10 Plan: Multi-Service Benchmarks and Performance Claims

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: Phases 02, 03, 04 and 09 for the final workload; the harness and
baseline can be built earlier.

## The finding

The repository has focused hot-path benchmarks (`benches/`) and a manual
HTTP-transport comparison harness (`benchmarks/http_transport/`), but no
multi-service workload:

- no multiple virtual hosts at 10/100/1000 sites;
- no multiple HTTP listener ports (because they are not bound);
- no TCP/UDP service load (because they are not wired);
- no mixed HTTP + TLS + H2/H3 + DNS + admin workload;
- no concurrent large-body upload/streaming test;
- no per-worker memory/event-loop evidence for the default process model.

The documentation also disagrees with itself:

- `architecture/overview.md` describes a design target of “1M+ RPS with
  millions of tenants”.
- `docs/DEPLOYMENT.md` capacity planning estimates ~50,000 req/s on 8 vCPU
  with attack detection.
- `docs/PERFORMANCE.md` records a closed internal performance campaign with
  relative improvements, not an end-to-end multi-service number.

The project rule is that transport benchmarks are manual-only, never CI gates
(`architecture/performance_optimization_closeout.md`,
`benchmarks/http_transport/README.md`). This phase follows that rule.

## Work items

### 10.1 Harness

- Add `benchmarks/multi_service/` with:
  - `README.md` describing the workloads, host assumptions, CLI flags and
    result schema;
  - config templates for the WAF and a local upstream (static file and a
    minimal dynamic backend);
  - a driver that starts one SynVoid process per profile, generates load and
    records JSON/Markdown;
  - scripts for `oha`/`wrk`/`h2load` and small TCP/UDP clients. Prefer tools
    already used by the repo; do not add a new root dependency for the
    benchmark crate (workspace exclusion is fine, as with
    `benchmarks/http_transport`).
- Record: revision SHA, harness SHA, toolchain, build profile, host
  OS/kernel/arch/CPU, topology (loopback, same host), command line and
  concurrency.
- Keep results in dated directories; never overwrite a prior run.

### 10.2 Workloads

Minimum matrix:

| Workload | Purpose |
|---|---|
| `vhost-1`, `vhost-100`, `vhost-1000` | domain-router scaling and per-site policy lookup |
| `h1-keepalive` / `h1-concurrent` | baseline request path |
| `tls-h2` | TLS + ALPN + H2 |
| `h3` | QUIC path, when enabled and qualified |
| `mixed-static-proxy` | backend/static mix under one process |
| `waf-small` / `waf-body` | inline WAF cost and body scanning |
| `upload-chunked` | chunked upload throughput under the Phase 09 cap |
| `tcp-echo` / `tcp-multi-port` | Phase 02 TCP service path |
| `udp-echo` / `udp-multi-port` | Phase 02 UDP request/response path |
| `multi-listener` | Phase 03 ports, if implemented |
| `soak` | 30–60 min at steady state, RSS/FD/event-loop lag |

For each: requests/sec, p50/p95/p99 latency, error rate, CPU, RSS, active
connections, FD count and relevant WAF/rate-limit counters. For TCP/UDP record
packets/bytes and flow count.

### 10.3 Process-model profiles

- `default`: one unified worker, `worker_threads` auto.
- `threads-1`, `threads-N`: show the Tokio-thread scaling curve.
- `workers-2` (with the Phase 04 opt-in): show the isolation cost and the
  state caveat; do not present it as the recommended throughput profile.
- `waf-off` vs `waf-on` vs `waf-block`: separate detection cost from proxy
  cost.

### 10.4 Documentation and claim reconciliation

- Replace or qualify “1M+ RPS” in `architecture/overview.md` with a measured
  statement or “design target, not a release claim”.
- Update the capacity table in `docs/DEPLOYMENT.md` to cite the benchmark
  directory and the exact hardware/workload.
- Add a short “How to reproduce” section to `docs/PERFORMANCE.md` and link the
  dated results.
- Record the known differences between loopback benchmark numbers and a
  real network deployment; do not compare across hosts/architectures.
- If the multi-listener or TCP/UDP phases are deferred, mark those workloads
  as unsupported in the result summary rather than silently omitting them.

### 10.5 Correctness under load

- Run a correctness pass with the load generator:
  - per-site WAF action/paranoia differences (Phase 05);
  - header FP corpus (Phase 06) under browser-like traffic;
  - body cap 413 behavior (Phase 09);
  - admin session/login under the selected worker model (Phase 04);
  - slow-loris/connection-cap behavior and graceful drain.
- A performance run that only measures happy-path 200s is not qualification
  evidence.

## Non-goals

- Adding a routine CI performance gate.
- Comparing against nginx/haproxy without an explicitly scoped, separate
  campaign.
- Publishing provider/customer numbers or a marketing claim.
- Changing production code to make a benchmark easier.

## Verification

- Harness smoke run (`--smoke`) passes on the current HEAD.
- A full run produces a dated result directory with all required metadata.
- The docs cite the result directory and no longer contain an unsupported
  headline number.
- The result includes the unsupported-workload table when a phase is not
  implemented.

## Risks

- Loopback and same-host runs overstate real-world throughput; document the
  topology.
- WAF/body workloads can dominate the profile; keep a no-WAF baseline.
- A benchmark harness can drift from the production binary; build it from the
  same checkout SHA and record the SHA in every result.

## Completion evidence

Implemented 2026-11-11. Added `benchmarks/multi_service/` (stdlib driver,
config templates/examples, upstreams, dated JSON/Markdown results, ownership and
README) covering vhosts, HTTP/TLS/H3, WAF, upload, TCP/UDP, multi-listener and
soak. The driver now isolates server groups and reports unsupported workloads
with reasons. Final smoke `benchmarks/multi_service/results/2026-11-11/2026-11-11T050811Z-85cd26-summary.md`:
13 supported, 4 unsupported (`tls-h2` ALPN, `h3` client, `chunked-upload` upload
MIME policy, `multi-listener` single-listener design). TCP/UDP are supported at
55k/53k and 985/864 pps respectively. `architecture/overview.md` now calls
1M+ RPS a design target, `docs/PERFORMANCE.md` links the harness, and
`docs/DEPLOYMENT.md` no longer publishes unqualified per-vCPU throughput tables.

