# HTTP Request Pipeline Doc/Guard Polish — Iteration 100

## Purpose

Iteration 99 normalized the shape of the HTTP/1 and HTTP/3 request pipelines without intentionally changing WAF, routing, body, tarpit, bandwidth, metrics, or upstream behavior.

The implementation achieved the intended structural change:

- `Http3RequestMetadata` groups HTTP/3 per-request fields.
- `Http3DispatchDeps` groups HTTP/3 dependency/service handles.
- `handle_http3_request_dispatch()` now takes grouped contexts instead of the previous flat 21-parameter signature.
- `http3_request_dispatch.rs` and `http_request_flow.rs` both document the same seven pipeline stages.
- `tests/http_request_pipeline_boundary_guard.rs` enforces request-dispatch isolation from worker lifecycle state.

Review found one small documentation drift: `architecture/http_request_pipeline.md` contains stale text in the HTTP/3 context section saying there is no separate deps struct and that all dependencies are still passed as parameters to `handle_http3_request_dispatch()`. That is now false after Iteration 99.

This pass should fix the stale documentation and add guard coverage so this drift does not recur.

## Non-Goals

Do not change request behavior.

Do not change WAF semantics.

Do not change routing semantics.

Do not change body collection or streaming behavior.

Do not change HTTP/3 QUIC/server ownership.

Do not introduce new HTTP/1 context structs.

Do not refactor `handle_http3_request_dispatch()` further unless required for a compile fix.

Do not expand this into CLI/supervisor cleanup.

## Current Problem

The code and docs disagree.

The implementation has:

```rust
pub struct Http3DispatchDeps { ... }

pub async fn handle_http3_request_dispatch<Waf, W>(
    metadata: Http3RequestMetadata,
    deps: Http3DispatchDeps,
    request_stream: &mut W,
    connection_guard: Option<&ConnectionTokenGuard>,
    waf: &Waf,
) -> Result<(), BoxError>
```

But `architecture/http_request_pipeline.md` still contains wording equivalent to:

```text
There is no separate "deps" struct — all dependencies are passed as function parameters to handle_http3_request_dispatch().
```

That stale sentence should be removed and replaced with the current contract.

## Desired End State

After this pass:

- `architecture/http_request_pipeline.md` accurately describes `Http3RequestMetadata` and `Http3DispatchDeps`.
- The doc explains that HTTP/1 currently uses existing context/preparation types rather than a new HTTP/1 deps struct.
- The doc explicitly states that HTTP/3 dispatch uses grouped request metadata and grouped dependency handles.
- `tests/http_request_pipeline_boundary_guard.rs` fails if the architecture doc omits `Http3DispatchDeps` or claims there is no deps struct.
- Guard tests continue to verify no worker lifecycle imports in HTTP request dispatch.
- No runtime code changes are necessary.

## Phase 1 — Fix HTTP/3 Context Documentation

Edit:

```text
architecture/http_request_pipeline.md
```

Find the HTTP/3 context section. Replace stale text with accurate wording.

Recommended replacement:

```markdown
### HTTP/3

`Http3RequestPrelude` is the output of `prepare_http3_request_prelude()` after metadata extraction and route resolution. Iteration 99 adapts that prelude into `Http3RequestMetadata`, which is passed to `handle_http3_request_dispatch()`.

```rust
pub struct Http3RequestMetadata {
    pub start: Instant,
    pub route_result: RouteResult,
    pub path: String,
    pub method: Method,
    pub headers: HeaderMap,
    pub host: String,
    pub query_string: Option<String>,
    pub user_agent: Option<String>,
    pub client_ip: IpAddr,
}
```

HTTP/3 service dependencies are grouped in `Http3DispatchDeps`:

```rust
pub struct Http3DispatchDeps {
    pub max_request_size: usize,
    pub streaming_waf_for_body: Option<Box<dyn StreamingWafScanner>>,
    pub streaming_waf_for_upstream: Option<Box<dyn StreamingWafScanner>>,
    pub connection_limiter: Option<Arc<ConnectionLimiter>>,
    pub main_config: Arc<MainConfig>,
    pub client: HttpClient,
    pub upstream_client_registry: Arc<UpstreamClientRegistry>,
    pub bandwidth: Option<Arc<BandwidthTracker>>,
    pub metrics: Option<Arc<WorkerMetrics>>,
}
```

`handle_http3_request_dispatch()` receives `Http3RequestMetadata`, `Http3DispatchDeps`, the request stream, the optional connection guard, and the WAF backend. This keeps QUIC/server ownership in `synvoid-http3` while the protocol-independent dispatch stages remain in `synvoid-http`.
```

Adjust imports/types in the snippet if exact names differ. The doc does not need to compile, but it should match the real public structs.

## Phase 2 — Add Guard For Stale Deps-Struct Wording

Update:

```text
tests/http_request_pipeline_boundary_guard.rs
```

Add a guard that ensures the architecture doc references `Http3DispatchDeps`.

Suggested test:

```rust
#[test]
fn http_request_pipeline_doc_mentions_http3_dispatch_deps() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("architecture/http_request_pipeline.md"))
        .expect("failed to read http_request_pipeline.md");

    assert!(
        source.contains("Http3DispatchDeps"),
        "architecture/http_request_pipeline.md must document Http3DispatchDeps"
    );
    assert!(
        source.contains("Http3RequestMetadata"),
        "architecture/http_request_pipeline.md must document Http3RequestMetadata"
    );
}
```

## Phase 3 — Add Guard Against Known Stale Phrase

Add another guard that rejects the stale phrase.

Suggested test:

```rust
#[test]
fn http_request_pipeline_doc_does_not_claim_http3_has_no_deps_struct() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("architecture/http_request_pipeline.md"))
        .expect("failed to read http_request_pipeline.md");

    let forbidden = [
        "There is no separate \"deps\" struct",
        "There is no separate 'deps' struct",
        "all dependencies are passed as function parameters to `handle_http3_request_dispatch()`",
    ];

    for phrase in forbidden {
        assert!(
            !source.contains(phrase),
            "architecture/http_request_pipeline.md contains stale HTTP/3 deps wording: {}",
            phrase
        );
    }
}
```

If exact phrase differs, include the actual stale sentence from the current doc.

## Phase 4 — Tighten Existing Context Guard Slightly

The existing `http3_dispatch_uses_context_structs` guard only checks that the source contains `Http3RequestMetadata` and `Http3DispatchDeps` somewhere.

Strengthen it enough to verify the function signature is using them, not merely defining them.

Suggested approach:

```rust
#[test]
fn http3_dispatch_signature_uses_context_structs() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
        .expect("failed to read http3_request_dispatch.rs");
    let stripped = strip_comments(&source);

    let fn_start = stripped
        .find("pub async fn handle_http3_request_dispatch")
        .expect("handle_http3_request_dispatch should exist");
    let fn_prefix = &stripped[fn_start..stripped.len().min(fn_start + 600)];

    assert!(fn_prefix.contains("metadata: Http3RequestMetadata"));
    assert!(fn_prefix.contains("deps: Http3DispatchDeps"));
}
```

Keep the older test or replace it with this stronger one. Avoid brittle full parsing.

## Phase 5 — Verify Documentation Consistency Across Skill Docs

Inspect the skill/doc files touched by Iteration 99:

```text
.opencode/skills/h3_proxy/SKILL.md
.opencode/skills/httpserver/SKILL.md
.opencode/skills/streaming_waf/SKILL.md
AGENTS.md
src/worker/AGENTS.override.md
architecture/worker_data_plane_composition_root.md
```

Confirm they do not contain stale wording equivalent to:

```text
There is no separate deps struct
```

If they do, correct them to mention `Http3DispatchDeps`.

Do not duplicate the whole architecture doc into each skill file. One concise sentence is enough.

## Phase 6 — Verification

Run:

```bash
cargo fmt
cargo test --test http_request_pipeline_boundary_guard
cargo check -p synvoid-http
cargo check -p synvoid-http3
```

Recommended broader checks:

```bash
cargo check -p synvoid
cargo test --test data_plane_composition_boundary_guard
cargo test --test unified_worker_composition_root_guard
```

If unrelated failures exist, document exact error text and confirm the targeted guard test passes.

## Acceptance Criteria

This pass is complete when:

- `architecture/http_request_pipeline.md` accurately documents `Http3RequestMetadata` and `Http3DispatchDeps`.
- The stale "no deps struct" statement is removed.
- Guard tests fail if the architecture doc omits `Http3DispatchDeps` or reintroduces the stale phrase.
- Guard tests verify the `handle_http3_request_dispatch()` signature uses the context structs.
- No runtime request handling code changes are required.
- Targeted tests/checks pass or unrelated failures are documented.

## Expected Files To Touch

Likely:

```text
architecture/http_request_pipeline.md
tests/http_request_pipeline_boundary_guard.rs
```

Possibly:

```text
AGENTS.md
src/worker/AGENTS.override.md
architecture/worker_data_plane_composition_root.md
.opencode/skills/h3_proxy/SKILL.md
.opencode/skills/httpserver/SKILL.md
.opencode/skills/streaming_waf/SKILL.md
```

Avoid touching unless required:

```text
crates/synvoid-http/src/http3_request_dispatch.rs
crates/synvoid-http3/src/server.rs
crates/synvoid-http/src/http_request_flow.rs
src/worker/unified_server/**
```

## Handoff Summary

Iteration 99 was structurally correct, but one architecture doc section drifted from the final implementation. Iteration 100 should be a small documentation/guard pass: make `architecture/http_request_pipeline.md` describe `Http3DispatchDeps` accurately, reject the stale phrase with a guard, and strengthen the signature guard so future edits cannot silently regress the documented boundary.
