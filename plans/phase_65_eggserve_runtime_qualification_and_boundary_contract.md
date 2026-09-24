# Phase 65 Plan: EggServe Runtime Qualification and Boundary Contract

Status: implementation handoff plan.

Registered in: `plans/roadmap.md`.

Parent campaign: `plans/eggserve_0_2_2_h1_runtime_consolidation_roadmap.md`.

Baseline reviewed: `main` at `11a1fb2844cd648418eefd72801f1aee2090d140`.

Upstream publication facts for this plan:

- `eggserve-core 0.2.2` is the published 0.2.2 artifact;
- `eggserve-server 0.2.1` is the published direct H1 runtime used by the 0.2.2 line;
- `eggserve-primitives 0.2.0` is the published canonical value layer;
- do not invent or wait for an `eggserve-server 0.2.2` unless the registry actually gains one later.

## Primary goal

Prove that EggServe can replace SynVoid's generic HTTP/1 connection runtime without weakening or silently changing SynVoid's existing ingress contracts, and freeze the exact boundary/configuration contract before production routing changes.

This phase must leave production on the current Hyper H1 implementation.

## Workstream A — Dependency and feature qualification

Capture the current foundational graph before adding any qualification dependency:

```bash
cargo tree -i hyper
cargo tree -i hyper-util
cargo tree -i http
cargo tree -i http-body
cargo tree -i tokio
cargo tree -i bytes
cargo tree -i rustls
cargo tree -i tokio-rustls
```

Qualify two candidate integration profiles:

1. **preferred direct leaf**
   - `eggserve-server = "=0.2.1"`
   - `eggserve-primitives = "=0.2.0"`
   - no default features;
   - no EggServe TLS/H2/H3/static ownership.

2. **interop fallback/prototype**
   - `eggserve-core = "=0.2.2"`
   - `default-features = false`
   - only `http-interop` or `tower` when needed to prove a conversion;
   - never enable static/TLS/H2/H3 merely for convenience.

Record exact resolved versions/features and whether core pulls dependencies SynVoid does not otherwise need. The final evidence must state why production chose leaf or core.

## Workstream B — Current ingress ownership inventory

Produce `architecture/eggserve_0_2_2_h1_compatibility_matrix.md` with at least these rows:

- `src/http/server/accept_loop.rs`;
- `src/http/server/connection_types.rs`;
- `src/http/server.rs`;
- `src/tls/server.rs`;
- `crates/synvoid-http/src/request_frontdoor.rs`;
- `request_preparation.rs`;
- `http_request_flow.rs`;
- `body_policy.rs`;
- streaming fast-path/body helpers;
- internal/special endpoint dispatch;
- WebSocket upgrade/dispatch;
- response construction/streaming;
- drain/connection accounting.

For each, classify:

- socket/transport-specific;
- generic H1 runtime mechanism;
- SynVoid policy;
- Hyper type dependency;
- required Phase 66 disposition;
- candidate deletion after Phase 69.

The intended result is not "remove Hyper from SynVoid." H2 and other adapters may continue using Hyper.

## Workstream C — Configuration projection matrix

Build an executable mapping from `synvoid_config::HttpConfig` and existing runtime policy to EggServe `RuntimeConfig`.

At minimum classify:

| SynVoid | EggServe | Required decision |
| --- | --- | --- |
| `header_read_timeout_secs` | `header_read_timeout` | direct |
| `keep_alive_timeout_secs` | `keep_alive_idle_timeout` | direct |
| `max_headers` | `max_headers` | direct |
| `max_request_line_size` | `max_request_target_bytes` | prove semantic parity |
| `max_header_size_ingress` | `max_header_bytes` | prove aggregate-byte parity |
| `max_request_size` | `max_buf_size` | preserve current parser behavior first; field name is not proof of body semantics |
| `max_streaming_body_size` | `max_request_body_bytes` | candidate hard ceiling; prove WAF behavior/order |
| `pipeline_limit` | none exact | do not map to server-wide admission by name |
| `max_connections` / current request semaphore | EggServe service admission | prevent double limiting or changed queue/503 semantics |
| no hard total lifetime | `connection_total_timeout` | set `Duration::ZERO` initially |
| no exact generic handler/write deadline | handler/body/write timeouts | prove non-interference or record blocker |

Write tests for the projection helper. No production path may construct EggServe runtime config ad hoc.

### Mandatory-control rule

If EggServe requires a nonzero bound for a behavior that SynVoid currently leaves unbounded or controls elsewhere, do not pick an arbitrary value.

Choose one of:

- derive it from an existing SynVoid timeout with equivalent scope;
- configure the highest supported non-interfering value and prove it cannot preempt any supported SynVoid request path;
- request a generally useful upstream "disabled" semantic if truly needed;
- stop adoption.

Document the decision.

## Workstream D — Request/body adaptation prototype

Using only tests/qualification code, prove conversion in both directions:

```text
EggServe Request
   -> standard http head + streaming body view
   -> SynVoid candidate neutral request
   -> SynVoid response body
   -> EggServe canonical streaming response
```

Required body cases:

- empty;
- fixed bytes;
- multi-frame body;
- unknown size;
- erroring body;
- trailers;
- early drop/cancellation;
- large body crossing SynVoid chunk-WAF thresholds.

No full buffering may be introduced merely to bridge APIs.

If the direct primitives/server crates cannot support a clean frame-preserving response conversion without importing core, compare that small adapter cost against `eggserve-core 0.2.2`'s dependency cost and record the decision.

## Workstream E — Tunnel/upgrade feasibility prototype

WebSocket capability parity is a hard gate.

Prove that a SynVoid-owned neutral upgrade interface can represent both:

- current Hyper `OnUpgrade`;
- EggServe `TunnelCapability::accept(..., handler)` / `TunnelIo`.

The neutral interface must preserve:

- one-shot acceptance;
- validated request intent;
- handshake response status/headers;
- duplicate/opaque handshake header values needed by current behavior;
- no application control over forbidden framing;
- post-handshake read-ahead bytes exactly once;
- cancellation/disconnect;
- bounded duplex ownership;
- a Tokio `AsyncRead + AsyncWrite` stream for existing WebSocket codec/tunnel code.

Do not expose EggServe types from `synvoid-http` as the new canonical domain API.

If WebSocket behavior cannot be represented without special-casing EggServe throughout the request pipeline, stop and document the blocker rather than shipping a non-WebSocket H1 lane.

## Workstream F — Listener/transport ownership proof

Prototype caller-owned driving over:

1. a loopback `TcpStream`;
2. the current protocol-validating/prefixed stream shape;
3. a `tokio-rustls::server::TlsStream<TcpStream>` test stream.

Prove `serve_http1_connection` can consume all three without EggServe owning bind/TLS.

Also prove truthful `ConnectionContext` propagation for:

- local address;
- remote address;
- HTTP vs HTTPS scheme;
- absence/presence of TLS metadata as chosen by the adapter.

Do not migrate the real TLS path in this phase.

## Workstream G — Existing inconsistency inventory

Record, but do not opportunistically broaden the phase:

- plaintext server log currently claims HTTP/1.1 + HTTP/2 while the shown driver is an H1 builder;
- TLS H1 computes header timeout/max buffer locals that are not applied to its H1 builder.

These become Phase 67/68 cleanup only when the relevant transport is migrated. Do not claim them fixed by planning.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo nextest run -p synvoid-config --cargo-profile ci --profile ci
cargo xtask test guards
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo deny check
cargo audit
cargo xtask verify
```

Add focused adapter tests rather than requiring a production route change.

## Required evidence

Create/update:

`architecture/eggserve_0_2_2_h1_compatibility_matrix.md`

It must contain:

- exact SynVoid baseline SHA;
- exact registry versions/checksums used;
- direct-leaf vs core feature/dependency comparison;
- configuration mapping;
- Hyper-coupling inventory;
- body/response adaptation result;
- tunnel/upgrade adaptation result;
- caller-owned TCP/TLS stream result;
- blocker list;
- explicit `GO_DIRECT_LEAF`, `GO_CORE_ADAPTER`, or `RETAIN_CURRENT_H1` decision.

## Acceptance criteria

Phase 65 passes only when:

- no production routing changed;
- exact published upstream artifacts are recorded truthfully;
- the preferred production dependency shape is explicit;
- every EggServe runtime control has a SynVoid semantic disposition;
- frame-preserving request/response adaptation is proven;
- WebSocket/tunnel adaptation is proven without leaking EggServe into canonical policy APIs;
- caller-owned plaintext and TLS streams are feasible;
- no H2/H3/TLS ownership migration is required;
- dependency/security/profile gates pass;
- the evidence record gives an explicit Phase 66 go/no-go decision.

A retain decision is a valid outcome.
