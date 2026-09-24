# Phase 66 Plan: Transport-Neutral HTTP Request, Body, and Tunnel Boundary

Status: not started; Phase 65 recorded `RETAIN_CURRENT_H1` because EggServe's mandatory finite handler/body/write deadlines and bounded controls cannot be projected without changing SynVoid behavior. See `architecture/eggserve_0_2_2_h1_compatibility_matrix.md`. Requalify after the upstream runtime contract changes.

Registered in: `plans/roadmap.md`.

Parent campaign: `plans/eggserve_0_2_2_h1_runtime_consolidation_roadmap.md`.

Depends on: `plans/phase_65_eggserve_runtime_qualification_and_boundary_contract.md`.

Baseline: Phase 65 proof-bearing implementation/qualification SHA.

## Primary goal

Remove Hyper-specific transport values from the canonical `synvoid-http` request pipeline while keeping the existing Hyper plaintext/TLS/H2 runtime active.

After this phase, changing the H1 connection driver must be an adapter substitution, not a rewrite of routing/WAF/backend logic.

This phase must not add EggServe to the production request route.

## Design constraints

The new boundary must be SynVoid-owned and transport-neutral.

Do not:

- make `synvoid-http` depend on `eggserve-server`;
- replace `hyper::body::Incoming` with an EggServe body type as the new canonical dependency;
- put raw Hyper/EggServe upgrade objects in routing/WAF types;
- erase body streaming into `Vec<u8>`;
- collapse H1/H2/H3 transport distinctions that are semantically meaningful.

Prefer standard `http` + `http-body` vocabulary for message heads/bodies and a narrow SynVoid capability for upgrades.

## Workstream A — Introduce a canonical inbound body wrapper

Add a concrete transport-neutral body type in `synvoid-http` (exact module/name is implementation choice), conceptually:

```rust
pub struct InboundBody {
    inner: Pin<Box<dyn http_body::Body<Data = Bytes, Error = InboundBodyError> + Send>>,
}
```

Use an unsynchronized boxed body if required; do not add `Sync` merely for convenience.

Requirements:

- preserves DATA frames incrementally;
- preserves trailers where the source transport exposes them;
- preserves size hints truthfully;
- maps transport errors into a narrow internal error without leaking detail to clients;
- drop/cancellation propagates to the source body;
- no hidden full buffering;
- test constructors for empty/fixed/multi-frame/error bodies.

The existing body-policy/WAF helpers should consume this type or a narrow trait over it rather than concrete Hyper `Incoming`.

## Workstream B — Introduce a canonical inbound request envelope

Replace pipeline signatures that take:

`hyper::Request<hyper::body::Incoming>`

with a SynVoid-owned envelope containing:

- standard `http::request::Parts` / request head;
- `InboundBody`;
- optional one-shot upgrade capability;
- only transport metadata already needed by policy (peer/local address remains supplied explicitly where current code does so).

A representative shape is:

```rust
pub struct InboundRequest {
    pub request: http::Request<InboundBody>,
    pub upgrade: Option<Box<dyn UpgradeCapability>>,
}
```

The exact representation may differ if ownership/borrow constraints demand it, but the one-shot upgrade capability must not be clonable.

## Workstream C — Define the neutral upgrade/tunnel capability

Define a SynVoid-owned capability whose acceptance API is sufficient for the current WebSocket dispatcher.

Required semantic surface:

- validated or declared upgrade kind/protocol;
- one-shot `accept`;
- ordered handshake headers or another representation that does not silently lose required duplicate/opaque values;
- handler callback receiving a boxed Tokio duplex;
- deterministic already-used/invalid/unavailable error;
- no raw socket exposure;
- no transport-specific response-framing authority in application code.

Recommended supporting trait alias pattern:

```rust
pub trait TunnelIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> TunnelIo for T where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
```

Use a boxed/pinned owner at the callback boundary.

The capability may return a neutral handshake description (status + ordered headers) after transport-side acceptance. It must not require `synvoid-http` to know Hyper `OnUpgrade` or EggServe `TunnelCapability`.

## Workstream D — Move Hyper upgrade capture to the transport adapter

Today `prepare_request_preflight` calls `hyper::upgrade::on(&mut req)`.

Move that transport operation out of canonical request preparation.

The existing Hyper adapters should:

1. inspect the request headers using the same canonical WebSocket validation helper;
2. capture `OnUpgrade` only when appropriate;
3. wrap it in the SynVoid neutral capability;
4. convert `Incoming` into `InboundBody`;
5. enter the unchanged policy pipeline.

Do not duplicate WebSocket validation logic. The canonical validator remains one authority.

For H2, preserve exactly the behavior that exists before this phase. This phase must not invent Extended CONNECT or new H2 WebSocket support.

## Workstream E — Adapt WebSocket dispatch

Change `websocket_upgrade_dispatch` and downstream tunnel helpers to consume the neutral capability and boxed Tokio duplex.

Preserve:

- current WebSocket handshake validation;
- `Sec-WebSocket-Accept` response behavior;
- app-server WebSocket proxying;
- upstream tunnel proxying;
- WAF message inspection;
- close/error accounting;
- existing task ownership/cancellation semantics.

Current Hyper-specific adaptation may live at the root transport boundary after this phase; application dispatch must not.

## Workstream F — Make body/WAF helpers transport-neutral

Update all helpers currently concrete on `hyper::body::Incoming`, including:

- frontdoor/request-preparation envelopes;
- body collection and chunk-WAF scanning;
- streaming fast path;
- special/internal endpoint pass-through types;
- any tests/helpers constructing Hyper incoming bodies solely to exercise policy.

Do not weaken framing validation. Hyper H1/H2 still performs wire parsing in this phase; SynVoid's existing post-parse ambiguity checks remain canonical and must continue to run.

## Workstream G — Response boundary cleanup only as needed

Do not redesign all response types in Phase 66.

If Phase 65 proves a neutral response adapter is needed for EggServe, introduce the minimum internal response abstraction now, but keep current externally observable response construction unchanged.

Requirements:

- streaming bodies remain streaming;
- response transforms still run in the same order;
- Alt-Svc/header policy remains SynVoid-owned;
- no new normalization authority competes with existing `synvoid-http` behavior before Phase 67.

## Workstream H — Differential tests against the pre-refactor path

Before deleting old signatures, pin behavior with tests covering:

- empty GET;
- POST with fixed body;
- unknown-length chunked body;
- large chunk-WAF body;
- malformed transfer framing;
- duplicate Host/authority rejection;
- internal health/ready/drain;
- route-not-found and backend errors;
- streaming fast path;
- WebSocket handshake success/denial;
- app-server WebSocket route;
- disconnect/drop;
- request-body transport error.

Where practical, run old/new adapters against the same policy helper during the migration commit sequence.

## Verification

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo nextest run -p synvoid-proxy --cargo-profile ci --profile ci
cargo nextest run -p synvoid-app-server --cargo-profile ci --profile ci
cargo xtask test guards
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo xtask verify
```

If the refactor touches upgrade behavior under TLS, include the focused TLS/WebSocket suites before closure.

## Acceptance criteria

Phase 66 is complete only when:

- canonical `synvoid-http` request flow no longer requires `hyper::body::Incoming`;
- canonical WebSocket dispatch no longer requires `hyper::upgrade::OnUpgrade`;
- existing Hyper H1/H2 transport adapters still drive all production traffic;
- body/trailer streaming remains incremental;
- WAF/body/framing behavior is unchanged;
- WebSocket/app-server/upstream tunnel behavior is unchanged;
- no EggServe type became a canonical policy/domain type;
- all supported feature profiles compile/test;
- Phase 67 can implement EggServe through a root/transport adapter without modifying WAF/routing/backend APIs again.

## Stop/rollback rule

If transport neutrality itself causes unacceptable complexity or measurable regression, do not proceed to EggServe adoption. Reconcile the Phase 65 decision and either retain a smaller independently useful abstraction or revert the qualification-only refactor cleanly.
