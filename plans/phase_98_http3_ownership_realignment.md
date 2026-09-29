# Phase 98 Plan: HTTP/3 Ownership Realignment

Status: implemented and closed 2026-09-28.

Closeout: `architecture/http3_ownership_phase98_closeout.md`.

Registered in: plans/roadmap.md and plans/architecture_maintenance_auditability_roadmap.md.

Baseline: main at 30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2; execute after Phase 97.

Depends on: Phase 96 guard baseline. Phase 97 should land first to keep campaign ordering simple, but there is no semantic jail dependency.

## Goal

Make synvoid-http3 the canonical owner of HTTP/3-specific request/stream state machines while preserving one protocol-neutral HTTP security-policy layer in synvoid-http.

No HTTP protocol capability may be removed or downgraded. H1 production remains EggServe, H2 remains Hyper, and H3 remains quinn/h3.

## Current-head ownership mismatch

synvoid-http currently declares and exports multiple HTTP/3-specific modules, including:

- http3_body
- http3_buffered_upstream_dispatch
- http3_request_dispatch
- http3_request_flow
- http3_request_prelude
- http3_route_dispatch
- http3_streaming_upstream_dispatch
- http3_terminal
- http3_waf_dispatch

synvoid-http also carries the h3 dependency.

synvoid-http3 already depends on synvoid-http and owns the actual QUIC/H3 server. This permits a one-way move from generic/shared policy toward the protocol-specific server without creating a cycle.

## Workstream A — classify every current http3_* module before moving

For each module, record whether it is:

1. transport/stream specific: mentions h3 stream/request types, HTTP/3 flow-control, QUIC/H3 terminal behavior, or protocol-specific dispatch;
2. protocol-neutral policy with an H3-prefixed wrapper;
3. a thin adapter between the two.

Move category 1 into synvoid-http3.

For category 2, rename/reuse the protocol-neutral primitive in synvoid-http and make synvoid-http3 call it.

For category 3, keep the adapter on the HTTP/3 side.

Do not mechanically move shared normalization/WAF policy merely because a filename begins with http3.

## Workstream B — preserve the canonical security semantics

The following remain canonical/shared rather than forked:

- client IP/trusted proxy resolution where protocol-applicable;
- routing policy and RouteTarget semantics;
- WAF decision/reducer semantics;
- upload validation semantics;
- challenge/terminal action policy where protocol-applicable;
- request body size/security policy;
- upstream TLS/policy adaptation;
- response security/header policy that is intentionally shared.

HTTP/3 may have different framing and body-flow mechanics because QUIC/H3 has explicit frame lengths and stream flow control. Do not force H1 transfer-framing rules onto H3.

## Workstream C — remove H3-specific dependencies from synvoid-http where possible

After migration:

- remove direct h3 dependency from synvoid-http if no neutral module requires it;
- keep quinn/h3 ownership in synvoid-http3;
- ensure synvoid-http does not depend on synvoid-http3;
- ensure synvoid-http3 -> synvoid-http remains the only direction.

Do not add H3 types to synvoid-core merely to preserve an internal import path.

Because synvoid-http and synvoid-http3 are internal workspace crates, workspace call sites may migrate to synvoid_http3. Preserve root/user-facing behavior and documented APIs; do not create a dependency cycle solely to preserve an internal crate path.

## Workstream D — migrate tests and compatibility surfaces

Move unit tests with their implementation owner.

Update:

- root src/http3 compatibility facade if needed;
- architecture/http3_deep_dive.md;
- architecture/http3_request_waf_boundary.md;
- architecture/http_request_pipeline.md;
- architecture/http_ownership_convergence.md/current authority notes;
- request-path capability guards.

Keep the existing Http3WafBackend/narrow-trait boundary or an equivalent that prevents the H3 server from depending on root WafCore concrete types.

## Workstream E — differential capability proof

Required behavior parity includes:

1. H3 request metadata/routing parity for equivalent requests;
2. duplicate/malformed Host policy parity where applicable;
3. WAF pass/block/challenge/tarpit decision mapping parity where supported;
4. buffered and streaming upstream paths;
5. body limit enforcement and scanner behavior;
6. upload validation path;
7. mesh/serverless/backend dispatch under their feature gates;
8. terminal response/status/header semantics;
9. graceful drain/shutdown behavior;
10. H1 and H2 suites remain unchanged/green.

No performance claim is required to close Phase 98, but record any material H3 throughput/allocation regression caused by ownership movement.

## Verification

At minimum:

    cargo test -p synvoid-http --profile ci
    cargo test -p synvoid-http3 --profile ci
    cargo test --test http3_waf_boundary_guard --profile ci
    cargo test --test http_normalization_ownership_guard --profile ci
    cargo test --test http_transport_neutrality_guard --profile ci
    cargo check --no-default-features --profile ci
    cargo check --no-default-features --features mesh --profile ci
    cargo check --no-default-features --features dns --profile ci
    cargo check --no-default-features --features mesh,dns --profile ci
    cargo xtask verify

## Acceptance criteria

- HTTP/3-specific stream/request state machines are canonically owned by synvoid-http3.
- synvoid-http owns only protocol-neutral/shared HTTP policy plus H1/H2-neutral infrastructure.
- synvoid-http has no direct h3 dependency unless a documented neutral use remains.
- No synvoid-http -> synvoid-http3 dependency/cycle exists.
- H1 EggServe and H2 Hyper production ownership is untouched.
- H3 feature behavior, WAF, routing, body, backend, and shutdown semantics are preserved.
- Architecture guards/docs name the new owner accurately.

## Rejection criteria

Reject the phase if it:

- duplicates WAF/normalization policy to make the move easy;
- moves H1/H2 ingress behavior into synvoid-http3;
- creates a dependency cycle;
- removes H3 routes/backend capabilities;
- changes body/framing semantics without a protocol-correctness reason and parity evidence;
- reopens EggServe adoption or egress transport ownership;
- treats file movement alone as closure while old implementations remain live.
