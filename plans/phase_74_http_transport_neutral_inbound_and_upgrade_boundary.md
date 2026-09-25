# Phase 74 Plan: HTTP Transport-Neutral Inbound and Upgrade Boundary

Status: closed 2026-09-25. Canonical pipeline consumes neutral
`InboundRequest`/`InboundBody`/`UpgradeCapability`
(`crates/synvoid-http/src/inbound.rs`); Hyper capture lives only in
`hyper_adapter.rs` (guard: `tests/http_transport_neutrality_guard.rs`);
H1/H2/TLS production paths convert at the two root entries and pass the
existing suite unchanged. `cargo xtask verify` 10/10. Production remains
Hyper H1/H2.

Registered in: `plans/roadmap.md`.

Parent campaign:
`plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`.

## Purpose

Remove concrete Hyper H1 request-body and upgrade handles from the canonical
`synvoid-http` policy/backend boundary while production still runs on the
existing Hyper transports.

This phase is a prerequisite refactor, not an EggServe production migration.

The response side should remain on the existing standard
`http::Response<BoxBody<Bytes, Infallible>>` contract unless implementation
evidence proves a narrower adapter is required.

## Current coupling to remove

At the planning baseline, `hyper::body::Incoming` appears in the canonical
request flow across:

- `request_frontdoor.rs`;
- `internal_endpoint_dispatch.rs`;
- `streaming_request_fast_path.rs`;
- `internal_handlers.rs`;
- `body_policy.rs`;
- `special_request_paths.rs`;
- `request_preparation.rs`;
- `response_helpers.rs`;
- `streaming_request_pass.rs`;
- `http_request_flow.rs`;
- `streaming_waf_upstream_dispatch.rs`.

`hyper::upgrade::OnUpgrade` crosses:

- `request_preparation.rs`;
- `backend_dispatch.rs`;
- `websocket_upgrade_dispatch.rs`;
- `websocket_dispatch.rs`.

The new canonical boundary must make those concrete types transport-adapter
details.

Hyper itself remains a dependency for H2 and other repository consumers.

## Track A — neutral inbound body

Introduce one crate-local canonical body type, suggested vocabulary:

```rust
pub struct InboundBody { /* private */ }

pub enum InboundBodyError {
    Transport,
    Cancelled,
    Protocol,
}
```

The exact representation may be a boxed `http_body::Body<Data = Bytes>` or a
private stream adapter, but it must preserve:

- incremental DATA;
- body errors;
- terminal trailers;
- drop/cancellation;
- unknown length;
- size hints only as hints;
- no forced full buffering.

Prefer a narrow owned type over making the entire request pipeline generic over
a body type.

Required constructors/adapters:

- current Hyper `Incoming` -> `InboundBody`;
- deterministic test body from frame streams;
- future EggServe body adapter in Phase 75 without changing the canonical type.

Do not import EggServe into `synvoid-http`.

## Track B — neutral request envelope

Create a narrow request envelope carrying:

- standard `http::request::Parts` or equivalent method/URI/version/header
  representation;
- `InboundBody`;
- optional neutral upgrade capability;
- no Hyper or EggServe types.

Suggested:

```rust
pub struct InboundRequest {
    pub parts: http::request::Parts,
    pub body: InboundBody,
    pub upgrade: Option<Box<dyn UpgradeCapability>>,
}
```

Fields may be private with accessors if that better enforces ownership.

Migrate frontdoor/preflight/body/WAF/backend signatures onto this envelope or
its deconstructed neutral parts.

Do not introduce a second parsing/normalization authority; existing framing,
routing, WAF, and metadata helpers remain canonical.

## Track C — capture Hyper upgrade outside policy code

Today `prepare_request_preflight` calls `hyper::upgrade::on(&mut req)`.

Move that operation into the Hyper transport adapter before the request enters
the neutral pipeline.

Required Hyper adapter behavior:

1. determine whether the request is an eligible WebSocket/upgrade candidate
   using the same existing validation predicate;
2. capture `OnUpgrade` only when required;
3. wrap it in the neutral capability;
4. convert `Incoming` to `InboundBody`;
5. pass the neutral request to the unchanged policy ordering.

Do not duplicate WebSocket validation logic between root and
`synvoid-http`; expose a narrow reusable classification helper if needed.

## Track D — one-shot neutral upgrade capability

Define an object-safe one-shot interface sufficient for both current Hyper and
future EggServe.

Required semantics:

- inspect validated upgrade/tunnel intent without transport types;
- accept at most once;
- application supplies only allowed handshake metadata plus a handler;
- handler receives an opaque Tokio `AsyncRead + AsyncWrite + Unpin + Send`
  stream;
- accept returns neutral handshake status/headers;
- decline/drop stays ordinary HTTP;
- no application control of transfer framing;
- cancellation/peer close is observable;
- immediate read-ahead delivered exactly once.

A viable shape is conceptually:

```rust
type BoxTunnelIo =
    Pin<Box<dyn AsyncReadWrite + Send + 'static>>;

type TunnelHandler =
    Box<dyn FnOnce(BoxTunnelIo) -> TunnelFuture + Send>;

trait UpgradeCapability: Send {
    fn request(&self) -> &UpgradeRequest;
    fn accept(
        self: Box<Self>,
        headers: http::HeaderMap,
        handler: TunnelHandler,
    ) -> Result<UpgradeHandshake, UpgradeError>;
}
```

Exact syntax may differ. Keep the interface one-shot and object-safe.

The neutral handshake description must preserve legal duplicate/opaque header
values. Do not reduce it to a `HashMap<String, String>`.

## Track E — adapt existing WebSocket code

Refactor `websocket_upgrade_dispatch.rs` and `websocket_dispatch.rs` so the
actual WebSocket codec consumes only the neutral tunnel IO.

The current:

`OnUpgrade -> await -> TokioIo<Upgraded> -> WebSocketStream`

becomes:

`BoxTunnelIo -> WebSocketStream::from_raw_socket(...)`.

Preserve:

- upstream WebSocket tunneling;
- app-server WebSocket path;
- WAF message inspection;
- message-size/mask configuration;
- selected subprotocol;
- 101 status/headers;
- metrics/logging;
- cancellation and close behavior.

The Hyper capability adapter may spawn a task that awaits `OnUpgrade` before
calling the neutral handler, preserving today's behavior.

## Track F — body-policy migration

Migrate body consumers to `InboundBody`:

- `collect_and_scan_request_body`;
- chunk WAF collection;
- streaming fast path;
- streaming upstream dispatch;
- special/internal request forwarding where bodies can survive.

Preserve current error semantics exactly. In particular, do not turn transport
errors currently swallowed on a specific path into a new public 500/400
without an explicit behavior decision.

Where current behavior is questionable, pin it in a test and leave correction
to a separate plan.

## Track G — preserve H2 behavior

The existing TLS H2 transport remains Hyper.

Its service adapter should construct the same `InboundRequest` as H1 so the
policy pipeline does not care which Hyper protocol produced it.

Do not add Extended CONNECT/H2 WebSocket support in this phase. Preserve the
current capability set.

## Track H — response contract stays stable

Do not refactor the dozens of backend response producers merely to prepare for
EggServe.

Keep:

```rust
http::Response<BoxBody<Bytes, Infallible>>
```

as the canonical SynVoid response boundary.

Phase 75 owns the single root conversion from this response into EggServe's
canonical response type.

## Track I — structural guards

Add guards/tests proving:

- no `hyper::body::Incoming` in canonical request-policy modules after
  migration;
- no `hyper::upgrade::OnUpgrade` in canonical request/backend/WebSocket
  dispatch APIs;
- Hyper concrete types remain only in explicit transport adapters/tests;
- no EggServe type exists in `crates/synvoid-http/src`.

Avoid brittle line-number checks.

## Required tests

At minimum:

- empty/fixed/multi-frame/unknown body;
- body error;
- trailers;
- early body drop;
- WAF streaming block;
- internal endpoint body/no-body;
- ordinary backend pass;
- H1 WebSocket success;
- WebSocket decline;
- app-server WebSocket;
- immediate post-upgrade bytes;
- duplicate handshake header preservation;
- H2 ordinary request parity;
- current WAF Drop callback still invoked.

Run the existing H1 parser/TLS tests unchanged to ensure this refactor does not
alter transport policy.

## Verification

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo xtask test guards
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo xtask verify
```

## Acceptance criteria

- [ ] Phase 73 is GO.
- [ ] canonical request pipeline accepts a neutral inbound request/body.
- [ ] canonical policy/backend APIs no longer name `Incoming`.
- [ ] canonical WebSocket/backend APIs no longer name `OnUpgrade`.
- [ ] current Hyper plaintext H1 remains production runtime.
- [ ] current Hyper TLS-H1/H2 remain production runtime.
- [ ] body frames/trailers/cancellation preserve behavior.
- [ ] WebSocket/app-server paths preserve behavior.
- [ ] response producer contract is unchanged.
- [ ] no EggServe dependency enters `synvoid-http`.
- [ ] structural guards and full verification pass.

## Non-goals

- No EggServe production driver.
- No response-model rewrite.
- No H2/H3 feature expansion.
- No config semantics change.
- No cleanup of Hyper dependencies outside the canonical inbound boundary.
