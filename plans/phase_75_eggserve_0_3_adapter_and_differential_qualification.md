# Phase 75 Plan: EggServe 0.3 Adapter and Differential Qualification

Status: planned; blocked on Phase 74 completion and Phase 73 GO.

Registered in: `plans/roadmap.md`.

Parent campaign:
`plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`.

## Purpose

Build the single SynVoid-owned adapter between EggServe's direct H1 service
contract and the transport-neutral `synvoid-http` request/response/tunnel
boundary, then prove differential parity while production remains on Hyper H1.

No listener or TLS path switches in this phase.

## Ownership location

Keep EggServe integration in the root composition/transport layer, suggested:

`src/http/eggserve_h1.rs`

or an equivalently narrow root module.

Do **not** add EggServe as a dependency of `synvoid-http`.

The adapter owns:

- EggServe RuntimeConfig/H1ConnectionPolicy projection;
- one shared EggServe RuntimeState per SynVoid server/runtime instance;
- EggServe Request -> SynVoid InboundRequest conversion;
- SynVoid response -> EggServe canonical response conversion;
- EggServe TunnelCapability -> neutral UpgradeCapability;
- ConnectionContext and ConnectionShutdown bridging;
- EggServe runtime rejection presentation mapping where needed.

## Track A — exact dependency pin

Use the exact Phase 73 GO artifact, not an open-ended semver range during
initial migration.

If Phase 73 GO is against 0.3.0:

```toml
eggserve-server = { version = "=0.3.0", default-features = false }
eggserve-primitives = { version = "=0.2.1", default-features = false }
```

If GO required a later publication, pin that exact version/checksum instead
and update this plan evidence.

Do not add `eggserve-core`.

## Track B — one configuration projector

Implement one tested function:

```text
HttpConfig + SynVoid response/runtime policy
          ->
EggServe RuntimeConfig
          ->
validated H1ConnectionPolicy + RuntimeState
```

No call site may construct EggServe configuration ad hoc.

Expected ownership profile:

- handler deadline: External;
- request-body deadline: External;
- idle deadline: External;
- response-write progress deadline: External;
- global request-body ceiling: External;
- semantic request-target ceiling: External;
- service admission: External;
- tunnel admission: External;
- total connection timeout: disabled;
- target mode: OriginOnly.

Map mandatory parser fields exactly only after Phase 73 proved full config
range compatibility:

- `header_read_timeout_secs`;
- `max_headers`;
- `max_request_size` -> parser buffer.

For aggregate header bytes, Phase 73 must define a non-interfering EggServe
value/ownership rule. SynVoid's canonical
`max_header_size_ingress` remains the policy authority.

Use valid inert scalar placeholders for externally-owned policies. Tests must
prove changing those placeholders within their valid EggServe range does not
change wire behavior.

## Track C — response policy preservation

Use the Phase 73-approved upstream mechanism that preserves SynVoid's per-site
Date/Server policy.

Required invariant:

EggServe remains framing authority but must not replace a service response's
validated per-site Date/Server metadata with one global runtime value.

Differential tests must cover:

- Date enabled/disabled;
- jittered Date;
- two different site Server tokens;
- no Server token;
- CSP/security/cache headers;
- Set-Cookie duplicates;
- Alt-Svc;
- Last-Modified/Date interaction.

If the selected EggServe artifact cannot do this, stop and return to Phase 73;
do not work around it with globals/task-locals.

## Track D — EggServe Service adapter

Implement a `Service` wrapper around the existing SynVoid request pipeline.

`request_body_policy` must choose a stream policy that does not preempt
SynVoid's own `max_streaming_body_size`/WAF ordering. With EggServe's global
body ceiling externally owned, prefer an effectively non-interfering service
stream limit and let SynVoid policy enforce the configured maximum.

Do not pick a lower convenience limit.

`call_with_tunnel`:

1. converts EggServe request head/body/context into the Phase 74 neutral
   request;
2. wraps optional EggServe TunnelCapability as the neutral upgrade capability;
3. invokes the same SynVoid flow used by Hyper;
4. converts the returned SynVoid response to EggServe canonical response.

Keep routing/WAF/backend policy entirely outside EggServe.

## Track E — request conversion

Preserve exactly:

- method;
- origin-form URI/path/query;
- HTTP version;
- legal duplicate headers and opaque values;
- remote/local addresses from observed SynVoid transport context;
- HTTP vs HTTPS scheme;
- request lifecycle/cancellation;
- body DATA/trailers/errors.

SynVoid remains reverse/origin-facing; do not enable EggServe
`OriginOrAbsolute` merely because the upstream capability exists.

Do not infer JA4 from EggServe. TLS-H1 service composition continues to carry
SynVoid's already-computed JA4 separately in Phase 77.

## Track F — response conversion

Convert:

`http::Response<BoxBody<Bytes, Infallible>>`

to EggServe canonical response without full buffering.

Requirements:

- preserve status;
- preserve ordered duplicate legal headers;
- convert DATA frames to EggServe ResponseStream;
- preserve trailers;
- preserve unknown-length streaming;
- do not synthesize application transfer framing;
- HEAD and body-forbidden statuses remain correct after EggServe
  normalization;
- producer drop/cancellation releases upstream resources;
- committed stream failure cannot synthesize a second response.

Tarpit and upstream streaming responses are hard test cases.

## Track G — tunnel conversion

Wrap EggServe `TunnelCapability` behind Phase 74's neutral one-shot
capability.

Acceptance must call EggServe's native `accept`, supply only allowed
handshake headers, and hand EggServe `TunnelIo` to the neutral handler as an
opaque Tokio stream.

Prove:

- WebSocket 101;
- Sec-WebSocket-Accept;
- selected subprotocol;
- immediate read-ahead bytes;
- app-server tunnel;
- peer close;
- service decline;
- one-shot enforcement;
- external tunnel admission produces no EggServe 503.

Do not reconstruct Hyper `OnUpgrade`.

## Track H — request admission and RuntimeState

SynVoid's existing per-request `connection_limit` semaphore remains the
request queue/admission owner, including queue-time metrics.

EggServe service admission must be External.

EggServe tunnel admission must be External.

Create one shared RuntimeState per owning SynVoid server/runtime, not per
request. Its file-stream semaphore is an internal unused/default mechanism for
this adapter unless a canonical EggServe file body is deliberately returned;
do not map it to SynVoid request admission.

Add tests proving changing EggServe internal service/tunnel numeric fields has
no effect when ownership is External.

## Track I — WAF Drop and connection shutdown

Give each EggServe-driven H1 connection a cloneable `ConnectionShutdown`.

Map SynVoid's request-drop callback to `shutdown()`.

Differential test:

- identical WAF Drop response;
- no next keep-alive request;
- response not truncated;
- connection closes within bounded test time;
- global worker drain remains independent.

If this is stricter/different from current Hyper behavior, do not silently
accept it. Record exact current behavior and either preserve it or create a
separate correctness decision.

## Track J — runtime rejection presenter

Use `RuntimeRejectionPresenter` only for errors genuinely generated before
SynVoid service policy.

Map to SynVoid's generic error representation where possible without leaking
request data.

Cover at least:

- target/parser-related 4xx that are still EggServe-owned;
- internal conversion 500;
- any runtime 503/504 that remains reachable under the External ownership
  profile.

Do not claim the presenter covers Hyper parser errors that EggServe itself
cannot intercept.

## Track K — differential harness

Drive the same scripted request corpus through:

1. current Hyper H1 driver;
2. EggServe direct H1 driver with the new adapter.

Production stays on path 1.

Corpus:

- GET/HEAD/POST;
- keep-alive sequence;
- malformed framing;
- max headers/buffer boundaries;
- aggregate header 431;
- chunked/Content-Length bodies;
- trailers;
- unknown-length/large body;
- WAF block/drop/stall/tarpit;
- upstream buffered/streaming;
- internal endpoints;
- cookies/security headers;
- per-site Date/Server;
- WebSocket/read-ahead;
- early disconnect;
- slow body;
- slow consumer/backpressure;
- graceful shutdown.

Compare status, headers with documented nondeterministic normalization,
response body/frames, close behavior, and relevant metrics/counters.

## Track L — evidence

Create:

`architecture/eggserve_0_3_h1_adapter_qualification.md`

Record:

- dependency graph;
- exact policy projection;
- neutral adapter shapes;
- differential matrix;
- residual differences;
- performance smoke numbers;
- GO/NO-GO for plaintext production migration.

## Acceptance criteria

- [ ] Phase 73 GO and Phase 74 closed.
- [ ] exact direct EggServe dependencies pinned.
- [ ] one tested config/policy projector exists.
- [ ] all duplicate deadline/admission controls are External.
- [ ] per-site response metadata survives final EggServe boundary.
- [ ] EggServe request converts to neutral SynVoid request without buffering.
- [ ] SynVoid streaming response converts to EggServe without buffering.
- [ ] WebSocket/app-server tunnel parity passes.
- [ ] WAF Drop/connection-close behavior is adjudicated.
- [ ] current Hyper and candidate EggServe differential corpus is green or
      every difference is explicitly approved.
- [ ] production still uses Hyper H1.
- [ ] H2/H3 unchanged.
- [ ] full repository/security/profile gates pass.

## Non-goals

- No listener route switch.
- No TLS-H1 route switch.
- No Hyper H1 deletion.
- No H2/H3 migration.
- No new forward-proxy behavior.
