# HTTP Request Pipeline

Internal architecture reference for developers working on request handling in `crates/synvoid-http/`. Both HTTP/1 and HTTP/3 follow the same conceptual stages but use different stream types, body collection strategies, and dispatch modules. This document maps stages to files.

Phase 01 closed the last plaintext/HTTPS policy fork: `HttpServer::handle_request`
(`src/http/server.rs`) and `HttpsServer::handle_request_with_cache`
(`src/tls/server.rs`) now compose the same canonical
`prepare_http_request_flow` + `handle_http_request_postlude` stages. TLS keeps
only connection/transport work (TCP accept, flood protection, handshake, ALPN,
certificate/SNI selection, JA4 extraction, connection lifecycle); all request
policy is shared. Parity is pinned by `tests/http_tls_parity.rs` and the
`tls_request_flow_stays_converged` guard in
`tests/http_normalization_ownership_guard.rs`.

## Overview

Every inbound HTTP request — whether plaintext HTTP/1.1 over TCP, HTTPS
(HTTP/1.1 or HTTP/2 over TLS), or HTTP/3 over QUIC — flows through seven conceptual stages: metadata extraction, route resolution, body policy, WAF evaluation, terminal response, backend dispatch, and accounting. The pipelines share the `Router`, `WafDecision`, and `RouteTarget` types from `synvoid-proxy` but diverge in stream ownership, backpressure models, and upstream dispatch (boxed body vs. QUIC stream). Each stage has a dedicated file; stage boundaries are enforced by the composition root boundary guard.

## Shared Stage Vocabulary

| Stage | Description | HTTP/1 File | HTTP/3 File |
|-------|-------------|-------------|-------------|
| **Metadata Normalization** | Extract method, path, host, user_agent, client_ip, headers into a structured context; fail closed on framing/authority ambiguity (`framing::validate_request_framing`). | `request_preparation.rs` → `extract_request_metadata()` | `http3_request_prelude.rs` → `prepare_http3_request_prelude()` |
| **Route Resolution** | Match normalized request against the routing table. | `request_preparation.rs` → `router.route_with_local_addr()` | `http3_request_prelude.rs` → `router.route()` |
| **Body Policy** | Decide: collect full body, stream through WAF, reject (too large), or tarpit. | `body_policy.rs` → `collect_and_scan_request_body()` | `http3_body.rs` → `collect_http3_request_body()` |
| **WAF Evaluation** | Run WAF checks (trust-token bypass, streaming, buffered) and produce a decision. | `request_parse.rs` → `should_skip_waf_from_trust_cookie()`, `buffered_request_waf_dispatch.rs` → `full_request_waf_decision()` | `http3_request_dispatch.rs` → `waf.check_request_full()`, `http3_waf_dispatch.rs` → `maybe_handle_http3_waf_decision()` |
| **Terminal Response** | Handle terminal decisions (not-found, error, blocked) before upstream dispatch. | `request_frontdoor.rs` → `dispatch_internal_endpoint()` | `http3_terminal.rs` → `maybe_handle_http3_terminal_route_result()` |
| **Backend Dispatch** | Route to the correct backend (upstream, app server, static, serverless, WASM, etc.). | `backend_dispatch.rs` → `handle_pass_backend_dispatch()` | `http3_route_dispatch.rs` → `handle_http3_found_route()` → `http3_buffered_upstream_dispatch.rs` / `http3_streaming_upstream_dispatch.rs` |
| **Accounting** | Record bandwidth, metrics, latency, and request logs. | `http_request_postlude.rs` → `RequestMetricsAdapter` | Inline in dispatch and upstream modules |

## HTTP-vs-HTTPS Stage Matrix (Phase 01)

Per the Phase 01 plan, the exact stage-by-stage diff between
`HttpServer::handle_request` and the old `HttpsServer::handle_request_with_cache`
before convergence. Every row now resolves to the HTTP column via the canonical
composition; the "Old HTTPS" column is retained so reviewers can detect
accidental behavior loss.

| Stage | Plaintext HTTP (canonical) | Old HTTPS (removed) | Phase 01 resolution |
|-------|---------------------------|---------------------|---------------------|
| Client-IP / trusted-proxy | `request_frontdoor` → `sanitize_and_resolve_client_ip` | raw `client_addr.ip()`, no proxy resolution | HTTPS now uses frontdoor; gains trusted-proxy handling |
| Internal / special paths | frontdoor `dispatch_internal_endpoint` (drain, drain-status, health, ready) + mesh special paths | only `/__internal__/health`, `/__internal__/ready` via local builder | HTTPS gains drain endpoints + canonical health/ready |
| Traffic controls | `maybe_enforce_request_traffic_limits` (connection limiter + bandwidth) + per-site limits + semaphore permit | bandwidth-limit check only; no limiter, no semaphore | HTTPS gains connection limiting + semaphore |
| Request metadata | `extract_request_metadata` (method/path/host/UA/cookies) + trust-token bypass | manual method/path/host/UA, no cookies, no trust-token bypass | HTTPS gains trust-token bypass |
| Routing | `router.route_with_local_addr(host, path, local_addr)` (real local addr) | `route_with_local_addr(host, path, Some(client_addr))` — peer addr mis-passed as local | fixed: local addr captured pre-handshake, matching HTTP |
| Framing validation | `framing::validate_request_framing` fail-closed 400 before routing/WAF | none | HTTPS gains fail-closed framing validation |
| WebSocket upgrade | `validate_websocket_upgrade` in preflight + `maybe_handle_websocket_upgrade` in postlude | none (upgrades fell through as plain requests) | HTTPS gains upgrade validation/dispatch |
| Streaming fast path | canonical conditions (Upstream or Serverless, plugin-aware, `body_buffering_policy`) | Upstream-only, no plugin check, extra cache/quictunnel carve-outs, direct `check_request_full` | canonical conditions for both; JA4 threaded into header check on both |
| Body collection / policy | `collect_and_scan_request_body` → 403 blocked / 413 too-large | custom collect; too-large continued with `None` body into WAF | canonical 413 fail-closed for both; streaming metrics converge to `synvoid.http.*` |
| Challenge evaluation | `maybe_handle_challenge_paths` (honeypot, CSS challenge/assets, alt_svc + logging) | manual honeypot/CSS copies without alt_svc/logging | canonical challenge paths for both |
| Full WAF decision | `maybe_handle_buffered_request_waf` (exhaustive `WafDecision` mapping + canonical counters) | manual `match waf_decision` with `synvoid.https.*` counters + `BandwidthProtocol::Https` egress | canonical mapping/accounting for both; JA4 passed on HTTPS, `None` on HTTP |
| Backend dispatch | `handle_pass_backend_dispatch` (websocket, axum, static, appserver, serverless+mesh, spin, fastcgi/php, cgi, mesh, wasm, upload validation, upstream proxy + transforms) | manual per-backend copies + per-site `ProxyServer` response-cache map + `ForwardedProtocol::Https` manual headers | canonical dispatch for both with `forwarded_protocol` param (`Http` vs `Https`); per-site `ProxyServer` cache map retired (HTTP never used it) |
| Response transforms | `transform_upstream_response` + `apply_security_headers` + Alt-Svc | manual security-header/date/server-token copies | canonical transforms for both |
| Metrics / accounting | `RequestMetricsAdapter` + `record_http_request_latency` + request log | manual `synvoid.https.*` counters + `BandwidthProtocol::Https` | canonical accounting for both; `synvoid.tls.*` handshake/ALPN/flood counters stay transport-specific |
| Drain / runtime | frontdoor drain state + `DrainGuard` active-count | `_drain_state` ignored | HTTPS now honors drain state + active-count |

Remaining transport-specific differences (by design, tested):

- TLS handshake failures, certificate/SNI selection, ALPN negotiation
  (`h2` vs `http/1.1` branches), TLS protocol/cipher metrics
  (`synvoid.tls.handshakes`, `synvoid.tls.alpn`, `synvoid.tls.flood_*`,
  `synvoid.tls.http_on_tls_port`), rustls acceptor lifecycle, and
  pre-request timeout/error mapping stay in `src/tls/server.rs`.
- JA4 fingerprint: computed from the ClientHello in `HttpsConnection::new`
  and threaded as `ja4_hash` into both WAF checks; plaintext passes `None`.
- `X-Forwarded-Proto`: `Https` on TLS, `Http` on plaintext (only forwarded
  header that differs; pinned by `forwarded_headers_agree_except_scheme`).
- `alt_svc`: `None` on TLS (Alt-Svc advertisement stays an HTTP-plane
  concern); the canonical builder omits the header.
- `mesh_backend_pool`: `None` on TLS (never wired there); preserved as-is.
- Listener lifecycle, `SO_REUSEPORT` bind, cert-watch reload, and
  TLS-passthrough raw-TCP proxy (`proxy_raw_tcp`) are untouched.

## Context Structs

### HTTP/1

```rust
// request_preparation.rs
pub struct PreparedRequest {
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    pub target: RouteTarget,
    pub parts: http::request::Parts,
    pub method: http::Method,
    pub path: String,
    pub user_agent: Option<String>,
    pub skip_waf: bool,
    pub full_body_arc: Arc<Bytes>,
    pub request_body_size: u64,
    pub body_slice: Option<Arc<Bytes>>,
}
```

`PreparedRequest` is the output of `prepare_request_preflight()` after metadata extraction, early WAF, route resolution, and body collection. It is consumed by `http_request_postlude.rs` which runs the full WAF decision and backend dispatch.

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

### RequestServices (worker-level narrow handle)

```rust
// src/worker/context.rs
pub struct RequestServices {
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    pub upload_validator: Option<Arc<UploadValidator>>,
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub plugin_manager: Option<Arc<GlobalPluginManager>>,
    pub serverless_registry: Option<Arc<ServerlessRegistry>>,
}
```

`RequestServices` is the narrow service handle passed to request dispatch. It must not grow lifecycle/supervision/shutdown dependencies.

## Body/Streaming Semantics

HTTP/1 and HTTP/3 body handling is intentionally **not** unified:

- **HTTP/1** uses `hyper::body::Incoming` — a `Stream<Item = Result<Bytes, Error>>`. Body collection in `body_policy.rs` routes to either `http_body_util::BodyExt::collect()` (small bodies) or `collect_body_with_chunk_waf()` (large bodies with streaming WAF scan). The collected body is wrapped in `Arc<Bytes>` on `PreparedRequest`.

- **HTTP/3** uses a custom `Http3RequestStream` trait with `recv_data() -> Result<Option<Bytes>>`. Body collection in `http3_body.rs` reads from the QUIC stream directly. The collected body is a `Vec<u8>`. Streaming upstream mode bypasses collection entirely when the route target doesn't need body transforms.

The difference is architectural: HTTP/1 bodies flow through hyper's backpressure model; HTTP/3 bodies flow through QUIC stream-level flow control. Unifying them would require abstracting over both backpressure models, which is not worth the complexity.

## Boundary Invariant

Request dispatch consumes `RequestServices` or narrower handles, never `UnifiedServerWorkerState`.

This is enforced by `tests/boundary_composition_guard.rs`. The guard classifies each file by role (`CompositionRoot`, `RequestPath`, `SharedTypes`, `Unclassified`) and scans for forbidden tokens:

- `CONSTRUCTION_TOKENS` — constructors of concrete infrastructure types
- `TYPE_IMPORT_TOKENS` — direct imports of `UnifiedServerWorkerState`, `MeshTransport`, `BlockStore`, etc.
- `CONTROL_PLANE_OP_TOKENS` — blocklist/threat-intel mutation operations

Request-path files (`src/waf/`, `src/proxy/`, `crates/synvoid-http/`, `crates/synvoid-waf/`, `crates/synvoid-proxy/`, `crates/synvoid-http3/`) may only import narrow traits and config snapshots. Composition roots (`src/worker/unified_server/`, `src/server/mod.rs`) own concrete infrastructure.

## Guard Tests

The former per-boundary guard files (`data_plane_composition_boundary_guard`,
`http_request_pipeline_boundary_guard`, `http3_waf_boundary`,
`request_path_capability_boundary`, `manifest_authority_load_path`) were
consolidated into a single compilation unit, `tests/boundary_composition_guard.rs`.

| Test | What It Enforces |
|------|------------------|
| `tests/boundary_composition_guard.rs` | Composition-boundary role classification; HTTP request dispatch doesn't import worker lifecycle; doc vocabulary checks (`Http3DispatchDeps`, `Http3RequestMetadata`); HTTP/3 WAF leak prevention; manifest authority load paths; exceptions audited |
| `tests/mesh_id_boundary_guard.rs` | Mesh-ID enforcement never called from WAF/request/proxy/HTTP/3 code |
| `tests/security_guard.rs` | Threat-intel raw lookups separated from enforcement (consolidates the former `threat_intel_boundary_guard`) |
| `tests/enforcement_decision_contract_guard.rs` | No unregistered request-disposition enums in request-path crates; adapter registry matches `enforcement_decision_contract.md` |
| `tests/http_normalization_ownership_guard.rs::tls_request_flow_stays_converged` | `src/tls/server.rs` composes `prepare_http_request_flow` + `handle_http_request_postlude`; no forked routing/body/WAF/challenge/upstream/cache pipeline |
| `tests/http_tls_parity.rs` | HTTP/HTTPS behavioral parity: framing fail-closed, trusted-proxy, internal endpoints, WebSocket validation, body-policy mapping, forwarded headers (scheme-only diff) |

Run all boundary guards:

```bash
cargo test --test boundary_composition_guard
cargo test --test mesh_id_boundary_guard
cargo test --test security_guard
cargo test --test http_normalization_ownership_guard
cargo test --test http_tls_parity
```
