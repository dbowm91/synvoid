# HTTP Ownership Convergence (Phase 20)

Phase 20 makes HTTP parsing, normalization, body policy, response
transformation, and reusable dispatch logic have exactly one canonical
implementation. Reusable HTTP domain logic lives in `synvoid-http`
(`crates/synvoid-http/src/`); root `src/http/` retains only application /
runtime composition: socket/server lifecycle, handler wiring, narrow-trait
adapters over root-owned services (`WafCore`, `Router`, `PluginManager`),
and application handlers.

Companion to `architecture/waf_ownership_convergence.md` (Phase 19 settled
the enforcement contract HTTP consumes) and `architecture/http_request_pipeline.md`
(stage vocabulary).

## 1. Root-to-crate module matrix

Every module exported by `src/http/mod.rs`, classified per the Phase 20 plan:

| Root module | Lines | Classification | Canonical owner | Notes |
|-------------|------|----------------|-----------------|-------|
| `app_server_backend_dispatch` | 2 | thin facade | `synvoid-http` | pure re-export |
| `axum_dynamic_dispatch` | 36 | root adapter | `synvoid-http` (+ root `PluginManager` downcast) | narrows root plugin handle to `AxumDynamicRouterLookup` |
| `body_policy` | 25 | root adapter | `synvoid-http` | narrows `WafCore` to `RequestBodyWaf` |
| `buffered_request_waf_dispatch` | 104 | root adapter | `synvoid-http` | supplies WAF check + error-page/tarpit render closures |
| `cgi_backend_dispatch` | 48 | root adapter | `synvoid-http` | clones root config/target types into owned crate call |
| `challenge_paths` | 30 | root adapter | `synvoid-http` | narrows `WafCore` to `ChallengePathWaf` |
| `directory_viewer` | 219 | application handler (root) | root app crate | admin-gated directory listing UI; moving it would pull `ConfigManager`/admin auth into the crate |
| `early_parse` | 2 | thin facade | `synvoid-http` | pure re-export |
| `fastcgi_php_backend_dispatch` | 49 | root adapter | `synvoid-http` | same pattern as CGI |
| `file_manager` | 400 | application handler (root) | root app crate | admin file-manager API; depends on root admin auth + `ConfigManager` |
| `file_manager_ui` | 360 | application handler (root) | root app crate | companion UI for `file_manager` |
| `headers` | 2 | thin facade | `synvoid-http` | pure re-export |
| `image_poisoning` | 5 | stale (deprecated alias) | `synvoid-static-files` via `image_rights` | deprecated shim; do not add callers |
| `image_rights` | 2 | thin facade | `synvoid-static-files` | pure re-export |
| `internal_endpoint_dispatch` | 2 | thin facade | `synvoid-http` | pure re-export |
| `internal_handlers` | 2 | thin facade | `synvoid-http` | pure re-export |
| `mesh_backend_dispatch` | 2 | thin facade | `synvoid-http` | feature-gated re-export |
| `request_parse` | 2 | thin facade | `synvoid-http` | pure re-export |
| `response_builder` | 2 | thin facade | `synvoid-http` | pure re-export |
| `response_helpers` | 2 | thin facade | `synvoid-http` | pure re-export |
| `response_transform` | 2 | thin facade | `synvoid-http` | pure re-export |
| `server` (+ `server/`) | 514 + 433 | application composition (root) | root app crate + `synvoid-http` stages | `HttpServer`/`HttpServerRuntime`/accept loop stay root; request stages called via `prepare_http_request_flow` / `handle_http_request_postlude` |
| `serverless_backend_dispatch` | 2 | thin facade | `synvoid-http` | feature-gated re-export |
| `shared_handler` | 2 | thin facade | `synvoid-http` | pure re-export |
| `special_request_paths` | 3 | thin facade | `synvoid-http` | feature-gated re-export |
| `spin_backend_dispatch` | 1 | thin facade | `synvoid-http` | pure re-export |
| `static_backend_dispatch` | 1 | thin facade | `synvoid-http` | item re-export |
| `streaming_request_fast_path` | 79 | root adapter | `synvoid-http` | narrows `WafCore` to owned check closure + `WafDecision` mapping |
| `streaming_waf_decision` | 1 | thin facade | `synvoid-http` | pure re-export |
| `streaming_waf_upstream_dispatch` | 66 | root adapter | `synvoid-http` | narrows `WafCore::streaming()` to `StreamingWafScanner`; renders root error page on 403 |
| `upload_validation_dispatch` | 1 | thin facade | `synvoid-http` | pure re-export |
| `upstream_buffered_dispatch` | 2 | thin facade | `synvoid-http` | pure re-export |
| `upstream_proxy_dispatch` | 2 | thin facade | `synvoid-http` | pure re-export |
| `upstream_proxy_dispatch_plan` | 2 | thin facade | `synvoid-http` | pure re-export |
| `upstream_response_transform` | 2 | thin facade | `synvoid-http` | pure re-export |
| `upstream_streaming_dispatch` | 2 | thin facade | `synvoid-http` | pure re-export |
| `validation_helpers` | 1 | thin facade | `synvoid-http` | pure re-export |
| `waf_decision` | 1 | thin facade | `synvoid-http` | pure re-export |
| `wasm_filter_dispatch` | 42 | root adapter | `synvoid-http` | narrows root `PluginManager` to `WasmFilterBackend` |
| `webdav` | 775 | application handler (root) | root app crate | WebDAV protocol handler; application composition |
| `websocket_dispatch` | 44 | root adapter | `synvoid-http` | narrows `WafCore` to `WafCoreBackend` |
| `websocket_upgrade_dispatch` | 80 | root adapter | `synvoid-http` | resolves AppServer socket path from root supervisor map, then delegates |

Result: 24 thin facades, 11 root adapters, 5 application handlers,
1 application composition root, 1 deprecated alias. No duplicate
implementation and no stale/dead module remains.

## 2. Canonical normalization pipeline

One sequence runs before security policy evaluates a request. HTTP/1 and
HTTP/3 share the stage vocabulary; transport-specific framing is validated
where the transport semantics live.

### HTTP/1 (hyper service → `prepare_http_request_flow`)

1. Listener sniff — `framing::{is_tls_client_hello, is_valid_http_request_start}`
   (`src/http/server/accept_loop.rs`; single implementation in
   `synvoid-http`, re-exported — previously duplicated in `src/tls/server.rs`).
2. Frontdoor — `request_frontdoor::prepare_request_frontdoor`: trusted-proxy
   sanitization + client-IP resolution, internal endpoints, mesh special paths.
3. Traffic control — `traffic_control::maybe_enforce_request_traffic_limits`.
4. Preflight — `request_preparation::prepare_request_preflight`:
   1. `request_parse::extract_request_metadata` — single extraction of
      method/path/host/user-agent/cookies. Routing and WAF consume this one
      `path` value; there is no second decoding for routing.
   2. `framing::validate_request_framing` — fail-closed transfer-framing +
      authority check (duplicate `Content-Length`, `Content-Length` +
      `Transfer-Encoding`, unsupported codings, malformed lengths, duplicate
      `Host`, absolute-form/origin-form mismatch, missing HTTP/1.1 host).
      Rejections render `400` before routing/WAF.
   3. Trust-token bypass, then `router.route_with_local_addr`.
5. Streaming fast path — `streaming_request_fast_path` (header-only WAF
   verdict for streamable upstream routes).
6. Body policy — `finalize_request_preparation` re-validates framing via the
   same helpers, then `body_policy::collect_and_scan_request_body`.
7. Challenge paths, buffered WAF dispatch
   (`buffered_request_waf_dispatch` → `waf_decision::resolve_full_request_waf_decision`,
   the single WAF-decision→response mapping), backend dispatch
   (`backend_dispatch::handle_pass_backend_dispatch`), accounting
   (`http_request_postlude`).

### Wire details owned elsewhere (not duplicated)

- Header whitespace / obs-fold: rejected by hyper and by httparse
  (`early_parse::EarlyHttpParser` returns `None`) before policy runs.
- Malformed chunk sizes / terminators: hyper `Incoming` state machine;
  decode errors surface as `hyper::Error`.
- Content-encoding expansion: bounded by body policy
  (`max_streaming_body_size`, `MAX_WAF_BODY_SIZE`) and upstream response
  limits, not by framing.
- Path normalization for security decisions: WAF normalizer (overlong
  sequences flagged via `NormalizationFlags`, rejected under
  `strict_normalization`).

### HTTP/3 overlap

QUIC frames carry explicit lengths, so transfer-framing ambiguity does not
exist on that path. The overlapping policy is shared:

- metadata → `http3_request_prelude::prepare_http3_request_prelude`
  (same `resolve_client_ip`, same router types);
- duplicate-`Host` fails closed (`Http3RequestPreludeOutcome::Respond`),
  matching the HTTP/1 canonical rule;
- enforcement mapping in `http3_waf_dispatch::maybe_handle_http3_waf_decision`
  is exhaustive over `WafDecision` and emits the same
  `enforcement_class_total` disposition counter vocabulary as the HTTP/1
  `waf_decision` mapping;
- body collection differs intentionally (`http3_body` over QUIC stream flow
  control vs hyper backpressure) — see `http_request_pipeline.md`.

### WebSocket

- Handshake HTTP policy shares the canonical path: `validate_websocket_upgrade`
  (`validation_helpers`, canonical in `synvoid-http`) runs inside
  `prepare_request_preflight`, and upgrade dispatch
  (`websocket_upgrade_dispatch`) operates on the already-routed target.
- Frame-level policy (`websocket_dispatch` tunnel/app-server pumps) remains
  protocol-specific by design; it is not forced into the HTTP parser.
- Handshake response building is canonical
  (`response_helpers::build_websocket_response`).

## 3. `HttpServer` ownership (Step 6 outcome)

`HttpServer` remains root-owned and `src/http` is classified `keep_app_root`
(application composition). Rationale:

- `HttpServerRuntime` / `HttpAppBackends` bundle root-owned services that
  must not move into the domain crate: `WafCore`, `WorkerDrainState`,
  `FloodProtector`, `PluginManager` (via `dyn Any`), serverless manager,
  Granian supervisor map, mesh transport/pool, IPC stream.
- Reusable stages already live in `synvoid-http` (`http_request_flow`,
  `request_preparation`, `http_request_postlude`, `backend_dispatch`, …);
  `handle_request` is a thin composition of `prepare_http_request_flow` +
  narrow-trait downcasts + `handle_http_request_postlude` + two injected
  closures (QUIC-tunnel send, image-rights marking).
- Moving `HttpServer` would import application services into `synvoid-http`,
  violating the request-path capability boundary — a listed rejection
  criterion, so the move was not forced.

## 4. Adjacent modules (Step 7 outcome)

### TLS — `keep_app_root` (server integration) + `synvoid-tls` (core)

- Certificate parsing/config/reload/ACME/SNI: canonical in `synvoid-tls`.
- Root keeps only `src/tls/server.rs` (`HttpsServer` listener + connection
  handling), which depends on root HTTP/services composition.
- Phase 20 change: deleted the duplicated `is_tls_client_hello` /
  `is_valid_http_request_start` / `HTTP_VALID_METHODS` copies; both servers
  now use `synvoid_http::framing`.
- Phase 01 change (residual closed): `HttpsServer::handle_request_with_cache`
  now composes the same canonical `prepare_http_request_flow` /
  `handle_http_request_postlude` stages as `HttpServer::handle_request`.
  Transport adaptations at the boundary: `ForwardedProtocol::Https`,
  handshake JA4 threaded into both WAF checks, `alt_svc: None`,
  pre-handshake `local_addr` capture (fixing peer-as-local misrouting),
  `mesh_backend_pool: None`. Retired: the HTTPS-local routing/body/WAF/
  challenge/backend/cache pipeline (~1300 lines), the per-site `ProxyServer`
  response-cache map (plaintext never used it), and the `synvoid.https.*` /
  `BandwidthProtocol::Https` request-accounting fork (canonical
  `WorkerMetrics`/`Http` path for both; `synvoid.tls.*` handshake/ALPN/flood
  counters stay transport-specific). Full stage matrix:
  `architecture/http_request_pipeline.md` ("HTTP-vs-HTTPS Stage Matrix").

### HTTP client — `facade_existing_crate` + root QUIC adapter

- Reusable client/pool/TLS/URL/encoding: canonical in `synvoid-http-client`.
- `src/http_client/streaming_waf_body.rs` is a pure re-export shim.
- Root retains only `quic_tunnel_dispatch.rs`, which depends on the root
  tunnel runtime (`QUIC_TUNNEL_REGISTRY`, `crate::tunnel::quic`) and cannot
  move without pulling root services into the crate.

## 5. Guards

`tests/http_normalization_ownership_guard.rs` (registered in
`tests/OWNERSHIP.toml` as `static_policy`):

- `root_http_has_no_second_parser` — bans `httparse::*` / early-parser
  tokens under `src/http` and `src/tls/server.rs`.
- `root_http_dispatch_shims_delegate_to_crate` — every `src/http` module
  except the documented application/composition set must reference
  `synvoid_http`.
- `root_http_has_no_duplicate_waf_decision_tables` — no `WAFDecision::…`
  mapping outside the canonical crate mappers (`server.rs` composition
  exempted).
- `root_http_facades_resolve_to_canonical_modules` — every
  `pub use synvoid_http::…` facade resolves to a declared crate module;
  pins the canonical normalization module set (`framing`, `early_parse`,
  `headers`, `body_policy`, `request_parse`, `request_preparation`,
  `request_frontdoor`, `waf_decision`).
- `tls_request_flow_stays_converged` (Phase 01) — `src/tls/server.rs`
  invokes both canonical stages with `ForwardedProtocol::Https` + JA4 and
  contains none of the forked-pipeline tokens (`route_with_local_addr`,
  `check_request_full(`, `WafDecision::*`, `HONEYPOT_PREFIX`,
  `ProxyServer::new_with_tls`, `send_request_streaming`, …).

Behavioral coverage: `tests/http_tls_parity.rs` (8 tests: framing
fail-closed, trusted-proxy, internal endpoints, WebSocket validation,
body-policy terminal mapping, forwarded-header scheme-only diff) plus
`framing.rs` unit tests (19 tests: duplicate/conflicting
`Content-Length`, `Transfer-Encoding` + `Content-Length`, unsupported/obfuscated
codings, malformed/overflowing lengths, duplicate `Host`, absolute-form vs
origin-form, missing-host policy per version, sniff helpers) plus the
pre-existing `early_parse` suite (obs-fold, whitespace, null-byte, smuggled
request-line cases).

Behavioral coverage: `framing.rs` unit tests (19 tests: duplicate/conflicting
`Content-Length`, `Transfer-Encoding` + `Content-Length`, unsupported/obfuscated
codings, malformed/overflowing lengths, duplicate `Host`, absolute-form vs
origin-form, missing-host policy per version, sniff helpers) plus the
pre-existing `early_parse` suite (obs-fold, whitespace, null-byte, smuggled
request-line cases).
