# Phase 76 Plan: EggServe Plaintext H1 Production Adoption

Status: closed 2026-09-25. Plaintext H1 production is EggServe-driven
(`src/http/server/accept_loop.rs` → `serve_http1_connection_with_policy`
+ `EggserveH1Service`; shared policy/state per listener; per-connection
shutdown tokens bridged to WAF-drop and worker shutdown). Accept
ownership (bind/flood/sniff/replay) verbatim. Evidence:
`tests/eggserve_plaintext_adoption.rs` (6/6) + differential 7/7;
`cargo xtask verify` 10/10. Residuals for 77/78: app-server tunneled
traffic loopback, TLS-H1 migration, same-host performance.

Registered in: `plans/roadmap.md`.

Parent campaign:
`plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`.

## Purpose

Switch only the plaintext HTTP/1 production connection driver from the
root-owned Hyper H1 builder to the qualified caller-owned EggServe direct H1
runtime.

SynVoid continues to own:

- socket bind/listen/accept;
- flood admission;
- strict protocol sniffing;
- per-request admission and WAF/site traffic policy;
- routing/backends;
- shutdown/drain policy.

TLS, H2, and H3 remain untouched in this phase.

## Entry conditions

Phase 76 may begin only when Phase 75 evidence records:

- exact published EggServe artifact;
- differential request/body/response/tunnel parity;
- config-range compatibility;
- per-site response metadata preservation;
- GO for plaintext production migration.

If any Phase 75 residual requires a runtime flag/fallback to Hyper for ordinary
supported configs, stop rather than creating a permanent dual production
runtime.

## Track A — preserve accept-loop ownership

Keep `src/http/server/accept_loop.rs` as the plaintext socket authority.

Preserve in order:

1. `bind_tcp_reuse`;
2. accept error handling;
3. peer/local address capture;
4. flood protector check;
5. optional strict-protocol peek;
6. TLS-on-HTTP rejection;
7. initial-byte replay;
8. worker/server shutdown ownership.

The post-sniff stream should remain a Tokio
`AsyncRead + AsyncWrite + Unpin + Send` stream and be passed directly to
`serve_http1_connection_with_policy`.

Do not wrap it in `hyper_util::TokioIo`; EggServe owns its Hyper adapter
internally.

## Track B — replace per-connection Hyper builder

Remove the production plaintext sequence:

```text
http1::Builder
 -> configure_h1_builder
 -> serve_connection
 -> with_upgrades
```

from the plaintext branch only.

Replace with:

```text
ProtocolValidatingStream<TcpStream>
 -> EggServe caller-owned H1 driver
 -> SynVoidEggserveService
```

using the prevalidated shared H1ConnectionPolicy and RuntimeState created at
server startup.

Do not construct/validate EggServe RuntimeConfig per request or per connection.

## Track C — connection context

Construct EggServe `ConnectionContext` from observed SynVoid transport facts:

- local socket address;
- remote socket address;
- scheme HTTP;
- no fabricated TLS metadata;
- no trusted-proxy metadata unless SynVoid already accepted such a transport
  layer.

Routing still receives the same client/local address values used today.

## Track D — connection shutdown ownership

Create one `ConnectionShutdown` per accepted H1 connection.

Bridge:

- worker/server shutdown -> connection token shutdown;
- WAF request-drop callback -> same connection token, as qualified in Phase 75;
- task cancellation -> existing task ownership/drain path.

Do not add a second independent idle/total shutdown loop around EggServe.

Record `ConnectionOutcome` only as bounded internal observability. Do not turn
it into a new user-visible error contract.

## Track E — request accounting/admission

Preserve the root request semaphore exactly:

- acquisition remains in the SynVoid service/request path;
- queue-time metric semantics remain;
- permit lifetime remains request-scoped;
- EggServe service admission remains External.

Do not reinterpret `http.max_connections` as accepted-TCP count in this
migration.

Per-site `ConnectionLimiter` behavior remains unchanged.

## Track F — parser/config parity

The startup policy projector from Phase 75 is the only mapping authority.

Live tests must prove plaintext:

- header timeout;
- max header count;
- parser buffer;
- canonical aggregate-header 431;
- strict protocol validation;
- deprecated keepalive/request-line/pipeline fields remain exactly as
  documented;
- no new semantic target limit;
- no new body/handler/write/idle timeout;
- no new service/tunnel admission.

Remove no config key and add no new operator-visible EggServe setting.

## Track G — WebSocket/tunnel production path

Use the Phase 75 neutral capability backed by EggServe TunnelCapability.

Verify production loopback:

- WebSocket upgrade;
- selected subprotocol;
- immediate post-upgrade bytes;
- upstream WebSocket;
- app-server WebSocket;
- WAF message block;
- peer close;
- shutdown while tunnel active.

No Hyper `OnUpgrade` should exist in the EggServe plaintext production path.

## Track H — retain differential Hyper lane for tests only

Keep a narrow test helper capable of driving the previous Hyper H1 mechanism
through the same neutral service boundary for Phase 76/78 comparison.

It must not be:

- an operator config;
- an environment flag;
- a runtime fallback;
- a second production listener.

Pin it clearly as test-only and removable at Phase 78.

## Track I — startup/log/docs truth

Update plaintext startup docs/logs to identify HTTP/1.1 capability without
advertising implementation details unless useful for debug-level diagnostics.

Do not claim lower footprint/performance in user docs yet.

Update architecture docs to say:

- plaintext H1 mechanics: EggServe direct runtime;
- TLS-H1: still Hyper until Phase 77;
- H2/H3 unchanged;
- SynVoid owns policy/admission.

## Tests

Required live-loopback matrix:

- ordinary keep-alive GET sequence;
- POST body;
- trailers;
- malformed/ambiguous framing;
- slow headers;
- parser/header maxima;
- WAF 403/block;
- WAF Drop close;
- stall/tarpit;
- streamed upstream response;
- client disconnect;
- server shutdown;
- WebSocket;
- strict-protocol invalid start;
- TLS ClientHello accidentally sent to HTTP port.

Preserve Phase 70/72 parser semantics even though the implementation authority
changes.

## Verification

Run at least:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
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

Hosted CI must be green for the production-switch SHA before Phase 77.

## Acceptance criteria

- [ ] Phase 75 plaintext GO exists.
- [ ] plaintext listener/flood/sniff ownership stays SynVoid-owned.
- [ ] plaintext production H1 is driven by EggServe direct runtime.
- [ ] no per-connection RuntimeConfig construction.
- [ ] request admission/metrics remain SynVoid-owned.
- [ ] body/WAF/response semantics pass live tests.
- [ ] WebSocket/app-server paths pass.
- [ ] no runtime fallback/dual production H1 path exists.
- [ ] TLS-H1/H2/H3 source behavior is unchanged.
- [ ] test-only Hyper differential lane remains available.
- [ ] docs/logs reflect the actual split runtime.
- [ ] full local and hosted CI pass.

## Non-goals

- No TLS-H1 migration.
- No H2/H3 migration.
- No removal of root Hyper dependency.
- No performance conclusion.
- No Phase 78 cleanup.
