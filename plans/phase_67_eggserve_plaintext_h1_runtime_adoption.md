# Phase 67 Plan: EggServe Plaintext HTTP/1 Runtime Adoption

Status: implementation handoff plan; execute only after Phase 66 closes cleanly.

Registered in: `plans/roadmap.md`.

Parent campaign: `plans/eggserve_0_2_2_h1_runtime_consolidation_roadmap.md`.

Depends on:

- `plans/phase_65_eggserve_runtime_qualification_and_boundary_contract.md`;
- `plans/phase_66_http_transport_neutral_request_and_tunnel_boundary.md`.

Baseline: Phase 66 proof-bearing implementation/qualification SHA.

## Primary goal

Replace SynVoid's plaintext HTTP/1 Hyper connection driver with the direct EggServe caller-owned H1 runtime while preserving SynVoid listener ownership, pre-HTTP security checks, request policy, backend behavior, WebSocket capability, metrics, and configuration.

This phase migrates plaintext H1 only.

Do not touch TLS-H1, HTTP/2, or HTTP/3 production routing here.

## Target architecture

Keep:

```text
synvoid_platform::socket_bind::bind_tcp_reuse
    -> tokio::net::TcpListener
    -> SynVoid flood check
    -> optional strict protocol sniff/prefix preservation
```

Replace only:

```text
Hyper http1::Builder
    -> serve_connection(...)
    -> with_upgrades()
```

with:

```text
eggserve_server::serve_http1_connection(...)
    -> SynvoidEggserveService
    -> canonical synvoid-http pipeline
```

EggServe must not bind the socket.

## Workstream A — Add the narrow production dependency

Use the Phase 65 selected direct-leaf profile.

Expected preferred manifest shape:

```toml
eggserve-server = { version = "=0.2.1", default-features = false }
eggserve-primitives = { version = "=0.2.0", default-features = false }
```

If Phase 65 selected `eggserve-core 0.2.2` instead, record why the direct leaf was insufficient and enable only the minimum interop feature.

Do not enable EggServe TLS, H2, H3, static-serving, CLI, or Python functionality.

Run the dependency graph checks again after production wiring; qualification-only graph results are not enough.

## Workstream B — One canonical RuntimeConfig projection

Implement one internal helper that builds EggServe H1 `RuntimeConfig` from the current SynVoid configuration/transport policy.

Requirements:

- validate before constructing `RuntimeState`;
- `header_read_timeout` from SynVoid;
- `keep_alive_idle_timeout` from SynVoid;
- `max_headers`, request-target ceiling, aggregate header ceiling, parser buffer, and request-body hard ceiling from the Phase 65 mapping;
- `connection_total_timeout = Duration::ZERO` initially;
- no arbitrary new timeout/admission semantics;
- response privacy/server-header policy must not strip or synthesize headers that SynVoid currently owns unless Phase 65 explicitly accepted that behavior.

Add unit tests pinning every mapped field.

### Admission collision

EggServe's server-wide `max_in_flight_requests` must not silently compete with SynVoid's current request semaphore.

Use the exact Phase 65 decision:

- either make EggServe admission intentionally non-interfering and retain SynVoid's current policy owner;
- or migrate the equivalent H1 admission ownership to EggServe with parity tests and remove the duplicate H1 semaphore acquisition.

Do not leave two same-purpose gates whose saturation behavior differs.

If no non-interfering EggServe configuration exists and changing SynVoid's queue/503 semantics was not approved by Phase 65, stop the migration.

## Workstream C — Shared runtime state per worker

Create exactly one `Arc<eggserve_server::RuntimeState>` for the plaintext H1 runtime at the appropriate worker/server composition boundary.

Do not create `RuntimeState` per connection; that would incorrectly make service/tunnel/file budgets per connection.

Keep runtime state alongside the existing long-lived `HttpServerRuntime`/worker state rather than hiding it in request handlers.

If custom EggServe `OpsContext` is used, bridge only the counters/events needed for debugging/qualification. SynVoid metrics remain the operator-facing authority unless a separate observability decision changes that.

## Workstream D — Implement SynvoidEggserveService

Add a narrow root/transport adapter implementing EggServe `Service`.

Responsibilities:

1. receive EggServe canonical request/context;
2. convert request head/body to the Phase 66 `InboundRequest`;
3. map truthful local/remote/scheme metadata;
4. call the existing SynVoid request flow;
5. convert the SynVoid response into EggServe canonical response without eager buffering;
6. map internal errors to sanitized `ServiceError`;
7. preserve cancellation/drop behavior.

The service adapter must not own WAF/routing/backend policy.

### Body policy

Implement `request_body_policy` so EggServe permits the body forms SynVoid already accepts while its runtime hard ceiling remains at least as permissive as the canonical SynVoid body policy.

Do not use EggServe's default `Reject`.

If SynVoid chooses body policy after routing and EggServe requires a decision before service invocation, use a safe transport-level streaming ceiling that does not preempt valid SynVoid requests; let SynVoid continue making the finer policy decision.

## Workstream E — Implement EggServe tunnel adapter

Implement `Service::call_with_tunnel`.

When EggServe supplies a `TunnelCapability`:

- wrap it in the Phase 66 neutral upgrade capability;
- expose only validated intent needed by SynVoid;
- on WebSocket acceptance, pass the current handshake fields into `TunnelCapability::accept`;
- adapt EggServe `TunnelIo` to the neutral boxed Tokio duplex;
- capture request lifecycle if needed for cancellation;
- return the exact accepted handshake semantics required by EggServe;
- do not run an accepted tunnel response through an ordinary path that strips EggServe's runtime-owned Upgrade/Connection framing.

When no tunnel exists, use the same request pipeline.

When SynVoid denies/does not use the capability, ordinary HTTP denial must remain ordinary HTTP.

Required tests:

- normal non-upgrade request;
- valid WebSocket;
- malformed WebSocket handshake;
- route-not-found WebSocket;
- app-server WebSocket;
- upstream WebSocket tunnel;
- peer disconnect;
- double-accept impossible;
- shutdown/cancellation during tunnel.

## Workstream F — Preserve the pre-HTTP accept boundary

Keep in SynVoid:

- `bind_tcp_reuse`;
- `TcpListener::accept`;
- peer/local socket capture;
- `FloodProtector::check_tcp_connection`;
- strict protocol validation;
- TLS-on-HTTP-port rejection metric;
- invalid-protocol rejection metric.

For strict validation, preserve already-read bytes exactly once.

The current `ProtocolValidatingStream` may remain as a root-local prefixed stream and be passed directly to `serve_http1_connection` if Phase 65/66 proved that shape. Do not re-read or lose the prefix.

Rename it only if useful; do not broaden into an unrelated framing rewrite.

## Workstream G — Drive each accepted connection through EggServe

Per accepted plaintext connection:

- construct truthful `ConnectionContext` using observed local/remote addresses and HTTP scheme;
- clone the shared service/runtime state;
- create an unsignaled `ConnectionShutdown` or the Phase 65-approved worker-shutdown bridge;
- invoke `serve_http1_connection`;
- classify/log `ConnectionOutcome` without reflecting hostile parser bytes.

Do not use EggServe's listener-owning `Server` in this phase.

### Shutdown behavior

Do not accidentally make worker shutdown harsher than the current behavior.

If wiring `ConnectionShutdown` to the worker broadcast changes in-flight drain semantics, either:

- prove the new behavior matches the existing drain contract; or
- keep the token unsignaled in Phase 67 and defer coordinated connection shutdown to Phase 69 closeout.

No detached connection task may survive process teardown beyond the existing worker supervision contract.

## Workstream H — Plaintext protocol truth correction

Once plaintext production is truly EggServe H1-only, fix the misleading plaintext startup log that currently says:

`HTTP/1.1 + HTTP/2`

when the actual plaintext driver is H1-only.

Do not add h2c/prior-knowledge support merely to preserve the old log string.

Update architecture docs only after the runtime path lands.

## Workstream I — Keep a bounded differential lane

Retain the legacy Hyper H1 connection driver only as test/qualification code until Phase 69.

It must not remain selectable by operators or production routing.

The same fixtures must be able to compare legacy vs EggServe for:

- ordinary GET/POST;
- keep-alive reuse;
- pipelined requests if currently supported;
- chunked/unknown-length request;
- large body/WAF;
- malformed framing;
- headers/target ceilings;
- internal endpoints;
- upstream/static/app-server/backend errors;
- streaming response;
- WebSocket;
- disconnect.

Mark the old production driver for deletion in Phase 69, not before qualification.

## Verification

Focused:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo nextest run -p synvoid-proxy --cargo-profile ci --profile ci
cargo nextest run -p synvoid-config --cargo-profile ci --profile ci
cargo xtask test guards
```

Profiles:

```bash
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Dependency/security:

```bash
cargo deny check
cargo audit
cargo tree -i eggserve-server
cargo tree -i hyper
cargo tree -i hyper-util
```

Broader gate:

```bash
cargo xtask verify
```

Run focused plaintext loopback/adversarial fixtures under both legacy and EggServe drivers.

## Acceptance criteria

Phase 67 closes only when:

- plaintext production H1 connections are driven by EggServe;
- SynVoid still owns bind, flood checks, protocol sniffing, policy, and application dispatch;
- no TLS/H2/H3 production route changed;
- request/response streaming is incremental;
- body/WAF/framing behavior passes parity;
- WebSocket/app-server/upstream tunnel behavior passes;
- current config values are projected explicitly;
- there is no double admission/timeout policy ambiguity;
- the old Hyper H1 driver is no longer a production path;
- a test-only differential lane remains for Phase 69;
- all supported build profiles and routine verification pass.

If a parity/security blocker remains, revert production routing to the existing H1 driver and record the blocker rather than carrying a split runtime.
