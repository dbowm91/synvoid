# Phase 69 Plan: EggServe H1 Adversarial, Performance, and Closeout Qualification

Status: not started; gated by Phase 65 `RETAIN_CURRENT_H1`. No EggServe production runtime exists to compare or close out. See `architecture/eggserve_0_2_2_h1_compatibility_matrix.md`.

Registered in: `plans/roadmap.md`.

Parent campaign: `plans/eggserve_0_2_2_h1_runtime_consolidation_roadmap.md`.

Depends on: Phases 65–68 implementation complete.

Baseline for comparison:

- **before:** the last production revision before Phase 67 routes plaintext H1 through EggServe;
- **after:** the Phase 68 proof-bearing revision with plaintext + TLS-H1 on EggServe.

Record exact immutable SHAs before running benchmarks.

## Primary goal

Prove that the EggServe H1 consolidation is correct, secure, operationally bounded, and performance-acceptable; remove superseded production H1 machinery; and reconcile all current-state documentation/evidence.

This phase decides the terminal state: adopted or retained.

## Workstream A — Build one final H1 conformance matrix

Create:

`architecture/eggserve_0_2_2_h1_runtime_closeout.md`

with an explicit scenario matrix covering both plaintext H1 and TLS-H1.

At minimum include:

### Parsing/framing

- valid GET/HEAD/POST;
- duplicate Content-Length equal and conflicting;
- Transfer-Encoding + Content-Length ambiguity;
- malformed chunk framing;
- invalid/duplicate Host/authority cases covered by current SynVoid policy;
- request-target limit;
- aggregate header limit;
- header count limit;
- parser buffer limit;
- slow header timeout;
- HTTP bytes on TLS port;
- TLS bytes/non-HTTP bytes on plaintext port under strict validation.

### Request bodies

- empty;
- fixed small;
- chunked/unknown length;
- body at/below/above SynVoid ceiling;
- >256 KiB chunk-WAF path;
- >1 MiB post-collection scan path where still applicable;
- WAF block during body;
- body transport error;
- incomplete body/drop;
- deferred/streaming fast path;
- trailers if supported by the current boundary.

### Policy/dispatch

- trusted proxy;
- route by host/local address;
- internal health/ready/drain;
- challenge paths;
- WAF block/drop/tarpit responses;
- static;
- upstream buffered;
- upstream streaming;
- app server;
- serverless/mesh profiles where feature-gated;
- plugin/WASM filter path;
- upload validation.

### Responses/lifecycle

- fixed response;
- streaming response;
- HEAD/body-forbidden response;
- large response;
- client stops reading;
- response producer failure;
- keep-alive reuse;
- multiple requests on one connection;
- idle timeout;
- peer disconnect;
- worker/server shutdown during header read, body read, handler work, response streaming, and idle keep-alive.

### Upgrade/tunnel

- valid WebSocket plaintext;
- valid WebSocket TLS;
- invalid handshake;
- app-server WebSocket;
- upstream WebSocket;
- tunnel backpressure;
- disconnect;
- shutdown;
- no double accept;
- no forged ordinary 101 path.

### Protocol split

- TLS ALPN H1;
- TLS ALPN H2;
- H2 functionality unchanged;
- H3 functionality unchanged;
- plaintext h2c remains exactly whatever the pre-campaign supported state was; do not infer support from old log text.

## Workstream B — Differential wire behavior

Use the test-only legacy Hyper H1 lane retained from Phase 67 and compare it against EggServe on the same hermetic fixtures where the old behavior is security/capability-relevant.

Compare:

- status;
- headers and relevant duplicate semantics;
- body;
- connection close/reuse;
- error status class;
- metrics/log event class when contractual;
- WebSocket handshake and tunnel data.

Do not require identical private error strings.

Where EggServe intentionally tightens malformed-input behavior, classify whether the difference is:

- equivalent fail-closed;
- accepted security hardening with no valid-client regression;
- incompatible regression.

Only the first two may close.

## Workstream C — Immutable performance comparison

Use detached worktrees or equivalent immutable builds for the exact before/after SHAs.

Do not benchmark a dirty tree or compare different harness versions without recording a harness-only transplant.

Measure representative workloads, preferably by extending/reusing the existing benchmark conventions rather than inventing a disconnected microbenchmark.

Required:

- H1 plaintext short keep-alive;
- H1 TLS short keep-alive;
- connection churn;
- concurrent short requests;
- 64 KiB streaming request;
- 64 KiB streaming response;
- larger streaming body representative of SynVoid;
- WebSocket handshake establishment;
- idle keep-alive resource use.

Record:

- throughput;
- p50/p95/p99 latency where the harness supports it;
- failures/timeouts;
- CPU if practical;
- RSS/allocations if practical.

Run enough repetitions to distinguish noise from a real regression.

### Adjudication rule

Treat an unexplained >5% regression in a primary throughput or p95/p99 metric as material.

A bounded regression may be accepted only when:

- repeated evidence is stable;
- mechanism is understood;
- security/maintenance benefit is concrete;
- the affected workload is characterized;
- the closeout record states the tradeoff explicitly.

Do not claim "faster" or "lower footprint" without measurements.

## Workstream D — Dependency/footprint adjudication

Record before/after:

```bash
cargo tree -i eggserve-server
cargo tree -i eggserve-core
cargo tree -i eggserve-primitives
cargo tree -i hyper
cargo tree -i hyper-util
cargo tree -i http-body
cargo tree -i rustls
cargo tree -i tokio-rustls
```

Also record production source that became deletable.

The maintenance claim should distinguish:

- dependencies removed from the whole workspace;
- dependencies still needed by H2/H3/other crates;
- root-local generic H1 code deleted;
- code retained only for tests/compatibility;
- net binary/RSS effect if measured.

Do not claim Hyper is removed if H2 or other crates still use it.

## Workstream E — Remove the differential legacy H1 production implementation

If all correctness/security/performance gates pass:

- delete the old plaintext Hyper H1 connection driver;
- delete the old TLS-H1 Hyper connection driver;
- remove qualification-only switches/helpers;
- retain only minimal test fixtures that do not constitute a second production runtime;
- remove dead `HttpConnection`/prefixed-stream plumbing only if no longer needed (strict protocol prefix preservation may still justify a small stream wrapper);
- remove dead imports/features/dependencies only when `cargo tree` proves they are no longer needed.

No permanent dual-runtime operator setting.

If gates fail, restore the legacy driver as the sole production owner and remove EggServe production wiring. Keep Phase 66 neutrality only if independently justified.

## Workstream F — Shutdown/drain ownership reconciliation

By closeout, there must be one documented answer for:

- who stops accepting;
- who signals active H1 connections;
- how long in-flight requests/tunnels may drain;
- what happens after the drain bound;
- how permits/tasks are released;
- how this composes with `WorkerDrainState` and worker supervision.

Avoid two independent shutdown state machines that can race.

If EggServe connection shutdown semantics are adopted, test immediate shutdown, shutdown-before-task-first-poll, streaming response during shutdown, upload during shutdown, and active tunnel during shutdown.

## Workstream G — Documentation truth

Update as needed:

- `plans/roadmap.md`;
- the parent EggServe roadmap;
- `architecture/http_server.md`;
- `architecture/http_request_pipeline.md`;
- `architecture/http_ownership_convergence.md`;
- `architecture/overview.md`;
- relevant `.opencode/skills/httpserver/SKILL.md`;
- README only if user-facing behavior/dependency claims materially change.

Correct the plaintext protocol claim if still stale.

Add final evidence:

`architecture/eggserve_0_2_2_h1_runtime_closeout.md`.

Do not rewrite historical Phase 20/other records to pretend EggServe existed at the time.

## Workstream H — Full verification

Focused and routine:

```bash
cargo fmt --all -- --check
cargo xtask test guards
cargo xtask verify
```

Run the relevant package suites with nextest.

Feature profiles:

```bash
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Security/dependency:

```bash
cargo deny check
cargo audit
```

Closeout qualification:

```bash
cargo xtask verify-full
cargo xtask verify-release
```

If repository conventions later change those commands, use the then-current canonical equivalents and record them rather than weakening the gate.

## Acceptance criteria — adopted branch

The campaign closes **ADOPTED** only when:

- plaintext and TLS-H1 production use one direct EggServe runtime path;
- listener/flood/TLS/ALPN/H2/H3 ownership remains SynVoid as planned;
- canonical SynVoid request policy remains transport-neutral;
- WebSocket capability is preserved;
- no required body/streaming behavior is buffered away;
- malformed framing remains fail-closed;
- timeout/admission/shutdown policies are explicit and non-duplicated;
- H2/H3 tests show no regression;
- immutable performance evidence is acceptable under the stated rule;
- old production H1 Hyper drivers are removed;
- dependency/maintenance claims are measured/truthful;
- docs/roadmap/evidence agree;
- full/release/security verification passes.

## Acceptance criteria — retained branch

Close **RETAINED** instead when a concrete blocker remains.

Required retained evidence:

- exact failing scenario and command;
- whether blocker is SynVoid architecture, EggServe contract, dependency graph, or performance;
- whether a generally useful upstream EggServe change could resolve it;
- production restored to one Hyper H1 owner;
- qualification-only EggServe production wiring removed;
- Phase 66 transport-neutral boundary either retained with independent justification or reverted;
- roadmap/current docs state that migration is not active.

No ambiguous partial closeout.
