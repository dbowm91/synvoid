# Phase 01 — TLS Request-Flow Convergence

Status: implementation handoff plan
Depends on: existing Phase 20 HTTP ownership convergence
Baseline: `architecture/http_ownership_convergence.md`

## Objective

Eliminate the remaining semantic duplication between plaintext HTTP and HTTPS request handling by making `HttpsServer::handle_request_with_cache` compose the same canonical request-policy stages used by `HttpServer`, while retaining TLS-specific connection establishment, certificate/SNI/ALPN handling, and listener lifecycle in the TLS layer.

The goal is request-policy convergence, not transport erasure.

## Current state

`src/tls/server.rs` already reuses canonical framing/sniffing helpers from `synvoid_http::framing`, so earlier parser duplication is closed. The remaining residual is that HTTPS still owns a separate request-handling flow rather than calling the canonical `prepare_http_request_flow` and `handle_http_request_postlude` composition used by the normal HTTP path.

This creates long-term risk that trusted-proxy handling, routing, challenge/WAF sequencing, body policy, backend dispatch, response transformation, accounting, or future security checks land on one transport but not the other.

## Scope

Primary files to inspect/modify:

- `src/tls/server.rs`
- `src/http/server.rs` and `src/http/server/*`
- root HTTP adapter modules called from `HttpServer::handle_request`
- `crates/synvoid-http/src/http_request_flow.rs`
- `crates/synvoid-http/src/http_request_postlude.rs`
- `architecture/http_request_pipeline.md`
- `architecture/http_ownership_convergence.md`
- HTTP/TLS integration and normalization tests

Do not move certificate management, TLS accept loops, ALPN, rustls state, SNI, ACME, or HTTPS listener ownership into `synvoid-http`.

## Work plan

### 1. Produce an explicit HTTP-vs-HTTPS request-stage diff

Before changing code, enumerate the exact stages executed by:

- `HttpServer::handle_request`
- `HttpsServer::handle_request_with_cache`

For each stage record inputs, side effects, early-return semantics, metrics/audit effects, and transport-specific dependencies. Cover at minimum:

- client-IP/trusted-proxy resolution
- internal/special paths
- traffic controls
- request metadata extraction
- routing
- framing validation applicable after hyper parsing
- WebSocket upgrade validation
- streaming fast path
- body collection/body WAF policy
- challenge evaluation
- full WAF decision mapping
- backend dispatch
- response transforms/image-rights hooks
- request metrics/accounting/postlude
- drain/runtime state

Add this matrix to `architecture/http_request_pipeline.md` or a focused companion section before implementation so reviewers can detect accidental behavior loss.

### 2. Isolate transport-neutral composition dependencies

Identify what the HTTP path currently receives through `HttpServerRuntime`/`HttpAppBackends` and what HTTPS constructs independently.

Prefer one of these shapes, in order:

1. a shared root-private helper accepting narrow dependency references/closures and calling canonical `synvoid-http` stages; or
2. a small root-private request-runtime bundle reused by both server implementations.

Do not create a new public abstraction merely to reduce line count. Do not move root-owned WAF/router/plugin/supervisor types into `synvoid-http`.

### 3. Convert HTTPS to canonical prelude

Replace HTTPS-local policy sequencing with the same `prepare_http_request_flow` entry point used by HTTP, adapting only transport-specific values at the boundary.

Preserve HTTPS-specific connection metadata that policy genuinely needs. Any behavior intentionally different under TLS must be named and tested; silent divergence is not acceptable.

### 4. Converge postlude/accounting

Make successful, rejected, upgraded, streamed, and backend-error HTTPS requests pass through the same canonical postlude/accounting semantics as HTTP where applicable.

Check especially:

- request/response byte accounting
- status-class metrics
- enforcement/disposition counters
- cache metrics
- connection/request completion bookkeeping
- response header transforms

Avoid double-counting caused by wrapping an existing HTTPS metric path around the canonical postlude.

### 5. Preserve transport-specific semantics

Explicitly keep these outside the shared request-policy path:

- TLS handshake failures
- certificate/SNI selection
- ALPN negotiation
- TLS protocol/cipher metrics
- rustls acceptor lifecycle
- TLS-specific timeout/error mapping before an HTTP request exists

These are connection/transport concerns and should not be forced through request-policy abstractions.

### 6. Add parity tests

Add integration tests that submit semantically equivalent requests over plaintext HTTP and HTTPS and assert equivalent application behavior. Use local/self-signed test TLS infrastructure only; no external network dependency.

Minimum cases:

- normal static/proxy route success
- missing/duplicate host behavior where applicable
- blocked WAF request
- challenge or access-policy rejection
- oversized/invalid body-policy rejection
- trusted-proxy/client-IP behavior
- WebSocket upgrade validation path
- backend failure mapping
- metrics/enforcement disposition parity where observable

The tests should compare semantic outcomes rather than byte-identical transport headers.

### 7. Add ownership guard

Extend `tests/http_normalization_ownership_guard.rs` or add a focused guard so `src/tls/server.rs` cannot quietly reacquire its own request-policy parser/decision pipeline.

The guard should allow TLS connection handling but fail if HTTPS reintroduces duplicate implementations of canonical request preparation or WAF-decision mapping.

## Rejection criteria

Reject an implementation that:

- moves TLS listener/certificate ownership into `synvoid-http`;
- creates a second generic server framework only to make HTTP and HTTPS look structurally identical;
- changes policy ordering without an explicit behavior test;
- shares code by weakening type boundaries with broad `dyn Any` or root-crate imports into domain crates;
- preserves an HTTPS-local WAF/routing/body-policy path after the phase is claimed complete;
- changes HTTP/3 semantics as collateral work.

## Acceptance criteria

1. `HttpsServer::handle_request_with_cache` no longer contains an independently maintained application request-policy sequence.
2. HTTP and HTTPS invoke the same canonical preparation and postlude stages for equivalent requests.
3. Every remaining HTTP/HTTPS behavioral difference is transport-specific and documented.
4. Negative security-policy parity tests exist and pass for both transports.
5. Existing HTTP normalization ownership guards remain green and include TLS regression coverage.
6. `architecture/http_ownership_convergence.md` no longer lists HTTPS request-flow convergence as an unresolved residual.
7. Default and relevant no-default feature builds compile cleanly with no new warnings.

## Verification

Run at minimum:

```text
cargo fmt --all -- --check
cargo test --profile ci http
cargo test --profile ci tls
cargo test --test http_normalization_ownership_guard --profile ci
cargo clippy --profile ci --all-targets -- -D warnings
cargo check --no-default-features --profile ci
```

Also run the repository's normal integration suite after the focused tests are green.
