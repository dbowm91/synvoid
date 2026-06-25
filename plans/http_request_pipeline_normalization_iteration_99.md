# HTTP Request Pipeline Normalization — Iteration 99

## Purpose

This phase is the next roadmap item after Iteration 98 data-plane service boundary finalization.

Iteration 98 made `DataPlaneServices` / `RequestServices` a clearer internal boundary. That boundary should now be used to normalize HTTP/1 and HTTP/3 request pipeline structure without changing WAF, routing, upstream, tarpit, bandwidth, or service behavior.

The goal of this pass is not to merge HTTP/1 and HTTP/3 into one implementation. The goal is to make their pipeline stages comparable, named, and testable so future work can share more logic safely.

## Current Context

HTTP/3 has a dedicated dispatch path in:

```text
crates/synvoid-http/src/http3_request_dispatch.rs
crates/synvoid-http3/src/server.rs
src/http3.rs
```

HTTP/1 request handling is likely spread across root/app-server/server modules and WAF-facing handlers, including some of:

```text
src/server/**
src/http/**
src/waf/**
src/worker/context.rs
src/worker/unified_server/services.rs
crates/synvoid-http/**
crates/synvoid-waf/**
crates/synvoid-app-server/**
```

The exact file set must be audited first. Do not guess and rewrite broad request code blindly.

## Problem Statement

HTTP/1 and HTTP/3 request handling should follow the same conceptual stages:

1. Normalize request metadata.
2. Resolve route / upstream target.
3. Collect or stream body according to policy.
4. Apply WAF decision.
5. Apply terminal response handling, tarpit, or block behavior.
6. Dispatch upstream / app / static / serverless response path.
7. Record bandwidth/metrics/logging outcomes.

Today, these stages are likely implemented with different shapes and different dependency passing. HTTP/3 already uses an explicit dispatch function with many parameters. HTTP/1 may use a more root-bound or server-bound handler. The next architecture step is to introduce shared vocabulary and stage boundaries so both protocols can converge incrementally.

## Non-Goals

Do not change WAF decision semantics.

Do not change route matching semantics.

Do not change tarpit behavior.

Do not change bandwidth accounting behavior.

Do not change upstream retry or proxy behavior.

Do not change HTTP/3 QUIC server ownership.

Do not move HTTP/3 transport implementation back into the root crate.

Do not attempt a full shared HTTP/1+HTTP/3 request executor in this pass.

Do not introduce protocol-specific regressions for streaming, body limits, headers, or connection guards.

Do not add dependencies.

## Desired End State

After this pass:

- HTTP/1 and HTTP/3 request handling are described using the same stage vocabulary.
- Shared request metadata/context structs exist where safe.
- HTTP/3 dispatch no longer has a giant parameter list if a context struct can reduce it without behavior change.
- HTTP/1 request handling has an equivalent local context or adapter shape.
- Both protocols consume `RequestServices` or narrower handles, not `UnifiedServerWorkerState`.
- Request-path code does not import worker startup/supervision/shutdown modules.
- Boundary guards prevent reintroducing worker-root state into request execution.
- Behavior remains unchanged.

## Design Rule

Normalize shape before sharing implementation.

Do not force common code until the two pipelines expose equivalent stages. This phase should prefer:

- named context structs;
- small pure adapters;
- comments documenting stage ownership;
- guard tests;
- source-level invariants.

Only extract shared functions if the existing code is already identical enough to move safely.

## Phase 1 — Audit HTTP/1 and HTTP/3 Pipeline Entry Points

Search for request entry points and record the current call graph. Focus on:

```text
crates/synvoid-http/src/http3_request_dispatch.rs
crates/synvoid-http3/src/server.rs
src/http3.rs
src/server/**
src/http/**
src/waf/**
crates/synvoid-http/**
crates/synvoid-waf/**
crates/synvoid-app-server/**
```

Identify:

- protocol entry point;
- route resolution location;
- WAF invocation location;
- body collection/streaming location;
- tarpit/block/terminal-response location;
- upstream dispatch location;
- metrics/bandwidth recording location;
- request service handle access location.

Add short comments near the entry points if the pipeline is not obvious.

Do not refactor during the audit unless the change is only a comment.

## Phase 2 — Introduce Shared Stage Vocabulary

Add a small documentation section in the relevant module docs, likely in:

```text
crates/synvoid-http/src/http3_request_dispatch.rs
```

and/or a new internal doc file:

```text
architecture/http_request_pipeline.md
```

Document the pipeline stages:

```text
Request metadata -> route context -> body policy -> WAF decision -> terminal decision -> upstream/app dispatch -> accounting
```

Keep this concise. It should be a map for implementers, not a user-facing architecture essay.

## Phase 3 — Create Request Metadata Context Structs

If HTTP/3 dispatch currently takes many discrete request metadata arguments, introduce a local struct in `crates/synvoid-http/src/http3_request_dispatch.rs` or an adjacent module.

Suggested shape:

```rust
pub struct RequestMetadata<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub query: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub client_ip: std::net::IpAddr,
    pub headers: &'a http::HeaderMap,
}
```

Adjust names/types to the actual code. Avoid needless allocation.

For HTTP/1, introduce an equivalent adapter or local construction path if practical:

```rust
let metadata = RequestMetadata::from_http1_parts(...);
```

or keep protocol-specific wrappers:

```rust
Http1RequestMetadata
Http3RequestMetadata
```

if the protocols differ enough.

Acceptance:

- request metadata is grouped, not threaded as many independent parameters where easy to avoid;
- no behavior changes;
- tests compile.

## Phase 4 — Create Dispatch Dependency Context Structs

HTTP/3 dispatch likely receives many service/dependency handles. Group them into a context that mirrors the Iteration 98 boundary.

Suggested shape:

```rust
pub struct RequestDispatchDeps {
    pub request_services: Arc<RequestServices>,
    pub http_client: HttpClient,
    pub upstream_registry: UpstreamClientRegistry,
    pub bandwidth: Arc<...>,
    pub metrics: Arc<...>,
    pub config: Arc<MainConfig>,
}
```

Use actual types.

Important:

- This context must not include `UnifiedServerWorkerState`.
- This context must not include startup/supervision/shutdown types.
- Prefer `RequestServices` or narrower handles over `DataPlaneServices` unless a field is truly needed by request execution.
- If `DataPlaneServices` is still required, document why and add a follow-up.

Acceptance:

- the dispatch function signature is smaller and more semantically grouped;
- no root lifecycle state enters request dispatch.

## Phase 5 — Normalize Route/WAF Decision Boundary

Identify where each protocol produces the equivalent of:

```rust
route_result
waf_decision
terminal_response
upstream_request
```

Add small type aliases, local structs, or comments to align naming. Do not change route-matching behavior.

If HTTP/3 uses a distinct `route_result` parameter and HTTP/1 uses direct server state, create a light adapter on the HTTP/1 side rather than moving router internals.

Possible helper names:

```rust
RequestRouteContext
WafEvaluationInput
TerminalResponseDecision
UpstreamDispatchInput
```

Use existing project naming if these concepts already exist.

Acceptance:

- both protocol paths can be reviewed stage-by-stage;
- WAF invocation input is explicit;
- terminal/block/tarpit behavior stays unchanged.

## Phase 6 — Preserve Streaming/Body Semantics

Do not unify body collection blindly. HTTP/1 and HTTP/3 may have different stream types, flow-control behavior, and backpressure semantics.

Instead, document and isolate the decision boundary:

```text
body policy decides whether to collect, stream through WAF, reject, or tarpit
```

If a helper already exists for body limits or streaming WAF behavior, make both pipelines call it only if doing so is behavior-preserving.

Acceptance:

- no new forced buffering;
- no changed size limits;
- no lost streaming WAF behavior;
- no changed HTTP/3 flow-control behavior.

## Phase 7 — Add Boundary Guards

Add or update guard tests, likely in:

```text
tests/data_plane_composition_boundary_guard.rs
tests/http_request_pipeline_boundary_guard.rs
```

Create a new guard file only if existing guard file becomes too broad.

Suggested guards:

### Request dispatch must not import worker lifecycle

```rust
#[test]
fn http_request_dispatch_must_not_import_worker_lifecycle_modules() {
    let files = [
        "crates/synvoid-http/src/http3_request_dispatch.rs",
        // add HTTP/1 dispatch file after audit
    ];
    let forbidden = [
        "UnifiedServerWorkerState",
        "startup_plan",
        "supervision_loop",
        "shutdown_executor",
        "WorkerTaskRegistry",
    ];
    // strip comments and assert absent
}
```

### HTTP/3 dispatch uses context structs

```rust
#[test]
fn http3_dispatch_uses_request_contexts() {
    let source = read("crates/synvoid-http/src/http3_request_dispatch.rs");
    assert!(source.contains("RequestMetadata") || source.contains("Http3RequestMetadata"));
    assert!(source.contains("RequestDispatchDeps") || source.contains("Http3DispatchDeps"));
}
```

### HTTP/1 and HTTP/3 share stage vocabulary

```rust
#[test]
fn request_pipeline_stage_vocabulary_is_documented() {
    let source = read("architecture/http_request_pipeline.md");
    for stage in ["metadata", "route", "body", "WAF", "terminal", "upstream", "accounting"] {
        assert!(source.contains(stage));
    }
}
```

Keep guards targeted and low-noise. Avoid overfitting exact formatting.

## Phase 8 — Update Docs

Update one or more:

```text
architecture/http_request_pipeline.md
architecture/worker_data_plane_composition_root.md
AGENTS.md
src/worker/AGENTS.override.md
.opencode/skills/httpserver/SKILL.md
.opencode/skills/h3_proxy/SKILL.md
.opencode/skills/streaming_waf/SKILL.md
```

Required doc points:

- HTTP/1 and HTTP/3 request pipelines use the same stage vocabulary.
- Shared context structs group request metadata and dispatch dependencies.
- Request dispatch must consume `RequestServices` or narrower handles, not worker lifecycle state.
- Body/streaming semantics are intentionally not unified unless a helper is already behavior-equivalent.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo test --test data_plane_composition_boundary_guard
cargo test --test unified_worker_composition_root_guard
```

Request/WAF focused:

```bash
cargo test -p synvoid-http
cargo test -p synvoid-http3
cargo test -p synvoid-waf
cargo test request_services
cargo test http3_request_dispatch
cargo test streaming_waf
```

Feature checks:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-mesh --features mesh
```

If known unrelated failures exist, document exact error text and run narrower targeted tests.

## Acceptance Criteria

This phase is complete when:

- HTTP/1 and HTTP/3 request stages are documented using the same vocabulary.
- HTTP/3 dispatch parameter sprawl is reduced through metadata/dependency context structs where practical.
- HTTP/1 has an equivalent stage/context mapping, even if not yet fully shared.
- Request dispatch code does not import worker startup/supervision/shutdown state.
- Request dispatch consumes `RequestServices` or narrower handles, not `UnifiedServerWorkerState`.
- Body/streaming behavior is unchanged.
- WAF decisions, routing, tarpit, terminal responses, bandwidth, and metrics behavior are unchanged.
- Guard tests prevent lifecycle-state leakage into request dispatch.

## Expected Files To Touch

Likely:

```text
crates/synvoid-http/src/http3_request_dispatch.rs
crates/synvoid-http3/src/server.rs
src/http3.rs
src/server/**
src/http/**
src/waf/**
tests/data_plane_composition_boundary_guard.rs
architecture/http_request_pipeline.md
architecture/worker_data_plane_composition_root.md
AGENTS.md
```

Possibly:

```text
src/worker/context.rs
src/worker/unified_server/services.rs
tests/http_request_pipeline_boundary_guard.rs
.opencode/skills/httpserver/SKILL.md
.opencode/skills/h3_proxy/SKILL.md
.opencode/skills/streaming_waf/SKILL.md
```

Avoid touching unless required:

```text
src/worker/unified_server/startup_plan.rs
src/worker/unified_server/mesh_attachment.rs
src/worker/unified_server/shutdown_executor.rs
src/worker/unified_server/supervision_loop.rs
crates/synvoid-mesh/**
```

## Review Checklist

Reject or revise the implementation if:

- it changes WAF decisions or route matching;
- it forces HTTP/3 body buffering where streaming existed;
- it moves HTTP/3 transport ownership back into the root crate;
- it introduces `UnifiedServerWorkerState` into request dispatch;
- it imports startup/supervision/shutdown modules from request-path code;
- it uses `DataPlaneServices` where `RequestServices` or a narrower handle would suffice;
- it weakens existing data-plane boundary guards;
- it performs unrelated mesh lifecycle or shutdown cleanup.

## Handoff Summary

Iteration 98 stabilized the data-plane service boundary. Iteration 99 should normalize the shape of HTTP/1 and HTTP/3 request pipelines around that boundary. Keep the work behavior-preserving: introduce shared stage vocabulary, group metadata/dependencies into context structs, add guards against lifecycle-state leakage, and leave body/streaming semantics intact. Full shared request execution can come later only after the two protocol paths are structurally comparable.
