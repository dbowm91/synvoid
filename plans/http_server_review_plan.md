# HTTP Server & Client Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/http_server.md`, `architecture/http_shared.md`

## Verified Correct Items

- [x] **File structure (http_server.md §2)**: All 14 submodule files exist under `src/http/`. Extra file `file_manager_ui.js` not listed (minor).
- [x] **File structure (http_shared.md)**: `src/http_client/mod.rs`, `erased_pool.rs`, `typed_pool.rs` all exist.
- [x] **HttpServer struct (http_server.md §3)**: All fields verified at `server.rs:336-361`. Field types, `#[cfg(feature = "mesh")]` gates, and names match.
- [x] **HttpServer::new() signature (http_server.md §4)**: Matches `server.rs:364-371` exactly.
- [x] **Builder pattern methods (http_server.md §4)**: All listed methods exist at `server.rs:408-472`.
- [x] **HttpServer::serve() (http_server.md §4)**: `#[cfg(feature = "mesh")]` gate confirmed at `server.rs:474`.
- [x] **HttpConnection struct (http_server.md §3)**: Matches `server.rs:232-235` exactly.
- [x] **ConnectionTokenGuard struct (http_server.md §3)**: Matches `server.rs:42-45` exactly.
- [x] **RequestMetrics struct (http_server.md §3)**: Matches `server.rs:290-293` exactly.
- [x] **BodyCollectionProtocol enum (http_server.md §3)**: Matches `shared_handler.rs:308-312` exactly.
- [x] **WafStreamedBody struct (http_server.md §3)**: Matches `shared_handler.rs:330-337` exactly.
- [x] **RequestContext trait (http_server.md §3)**: Exists at `shared_handler.rs:134-148` with `HttpRequestContext` and `HttpsRequestContext` impls. Note: trait is `#[allow(dead_code)]` — not currently used in request pipeline.
- [x] **StaticResponseBody (http_server.md §6)**: Exists but defined in `src/static_files/mod.rs:96`, not `src/http/server.rs` as implied.
- [x] **IMAGE_PROTECTION_REGEX (http_server.md §6)**: Pattern `r"\.(?:jpe?g|png|gif|webp|bmp|svg|ico)(?:\?|$)"` confirmed at `server.rs:74-75`.
- [x] **IMAGE_POISON_CACHE constants (http_server.md §8)**: `MAX_CAPACITY=1000`, `TTL_SECS=3600` confirmed at `server.rs:85-86`.
- [x] **ProtocolValidatingStream struct (http_server.md §8)**: Matches `server.rs:176-179`.
- [x] **is_tls_client_hello (http_server.md §8)**: Matches `server.rs:172-174` exactly (0x16, 0x03, <=0x03).
- [x] **REQUEST_LOG_RATE_LIMITER (http_server.md §8)**: AtomicU32/U64 confirmed at `server.rs:148-149`.
- [x] **FORBIDDEN_RESPONSE_HEADERS (http_server.md §11)**: Confirmed at `server.rs:107` with exact values.
- [x] **CORS wildcard validation (http_server.md §11)**: Confirmed at `headers.rs:72-88` with warn/error logging.
- [x] **Global security headers (http_server.md §11)**: `Cache-Control`, `X-Content-Type-Options`, `X-Frame-Options` confirmed at `response_builder.rs:133-138`.
- [x] **Internal endpoints (http_server.md §9)**: All 4 endpoints exist in `internal_handlers.rs`.
- [x] **Response builder functions (http_server.md §10)**: `reason_phrase`, `error_body`, `error_response_bytes/full/boxed`, `fallback_error_bytes/full/boxed`, `bad_gateway_bytes/full` all confirmed in `response_builder.rs`.
- [x] **build_response_with_alt_svc (http_server.md §10)**: Confirmed at `response_builder.rs:117-145`.
- [x] **build_response_with_cookie (http_server.md §10)**: Confirmed at `response_builder.rs:147`.
- [x] **build_json_response (http_server.md §10)**: Confirmed in `response_builder.rs`.
- [x] **compute_websocket_accept_key (http_server.md §8)**: GUID and SHA1+base64 logic confirmed at `headers.rs:134-143`.
- [x] **generate_stealth_timestamp (http_server.md §8)**: Random jitter in `[-jitter, +jitter]` confirmed at `headers.rs:145-154`.
- [x] **server.rs line count**: 4907 lines (doc says 4908 — off by 1).
- [x] **UpstreamTlsConfig (http_shared.md)**: All 6 fields match `http_client/mod.rs:226-233`.
- [x] **UpstreamClientKey (http_shared.md)**: Matches `http_client/mod.rs:39-44`.
- [x] **StreamingWafBody (http_shared.md)**: Confirmed at `http_client/mod.rs:135-141` — this is a SEPARATE type from `WafStreamedBody` in `shared_handler.rs`.
- [x] **HttpResponse struct (http_shared.md)**: Matches `http_client/mod.rs:909-913` (status, headers, body fields).
- [x] **HttpResponse::from_hyper (http_shared.md)**: Confirmed at `http_client/mod.rs:916`.
- [x] **ErasedBody trait (http_shared.md)**: Confirmed at `erased_pool.rs:47-53`.
- [x] **ErasedBodyImpl (http_shared.md)**: Confirmed at `erased_pool.rs:55-57`.
- [x] **BoxErasedBody alias (http_shared.md)**: Confirmed at `erased_pool.rs` (via `pub use`).
- [x] **ErasedConnectionPool (http_shared.md)**: Matches `erased_pool.rs:224-232` — `HashMap<PoolKey, VecDeque<Http1PooledConnection>>`, `max_idle_per_host`, `connect_timeout`.
- [x] **Http1PooledConnection (http_shared.md)**: Confirmed at `erased_pool.rs:118`.
- [x] **Http2PooledConnection stub (http_shared.md)**: Confirmed at `erased_pool.rs:125` with `is_available()` always returning `false` (line 204).
- [x] **PoolKey (http_shared.md)**: Confirmed at `erased_pool.rs:112`.
- [x] **TypedPoolKey (http_shared.md)**: Matches `typed_pool.rs:22-27` (authority, is_http2, body_type_id, allow_plaintext).
- [x] **TypedConnectionPool (http_shared.md)**: Confirmed at `typed_pool.rs:69`.
- [x] **TypedHttpClient (http_shared.md)**: Confirmed at `typed_pool.rs:173`.
- [x] **Client cache Moka (http_shared.md)**: `UPSTREAM_CLIENT_CACHE` and `UPSTREAM_STREAMING_CLIENT_CACHE` confirmed at `http_client/mod.rs:77-88`. Max 100, TTL 300s confirmed at lines 67-68.
- [x] **ALPN protocols (http_shared.md)**: `h2`, `http/1.1` confirmed at `http_client/mod.rs:517,561`.
- [x] **aws-lc-rs TLS provider (http_shared.md)**: Confirmed at `http_client/mod.rs:442-445`.
- [x] **HostnameSkippingVerifier (http_shared.md)**: Confirmed at `http_client/mod.rs:571-613` with exact behavior.
- [x] **QUIC tunnel support (http_shared.md)**: `send_request_via_quic_tunnel` confirmed at `http_client/mod.rs:966`.
- [x] **erased_pool feature gate (http_shared.md)**: Confirmed in `Cargo.toml` as default feature (line 22) and empty feature def (line 35).
- [x] **create_http_client (http_shared.md)**: Default 5s timeout, 1000 max idle, 30s idle timeout confirmed at `http_client/mod.rs:276-277`.
- [x] **create_unix_http_client (http_shared.md)**: 100 max idle, 30s idle timeout confirmed at `http_client/mod.rs:640-645`.
- [x] **create_simple_http_client (http_shared.md)**: Confirmed at `http_client/mod.rs:1241`.

## Discrepancies Found

- [http_server.md:23] — Claims `server.rs (4908 lines)`, actual is **4907 lines**. Off by 1.
- [http_server.md:317] — `StaticResponseBody` shown under HTTP Server module but is defined in `src/static_files/mod.rs:96`, not in `src/http/server.rs`. The doc implies it's part of the HTTP server submodule.
- [http_server.md:122-128] — `RequestContext` trait signature shows `fn build_response_with_headers(...)` with `...` elision. Actual signature has explicit params: `(status: u16, body: String, content_type: &str, headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>)`. Minor doc elision, not wrong.
- [http_server.md:133] — `RequestContext` trait is marked `#[allow(dead_code)]` at `shared_handler.rs:133`. The doc doesn't mention this is unused/dead code.
- [http_shared.md:176] — Lists `send_request_with_headers(client, method, url, headers, timeout)` in Request Sending Entry Points. This function **does not exist**. The actual function is `send_request_with_timeout_and_headers` at `http_client/mod.rs:706`.
- [http_shared.md:28] — Lists `HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>`. The `HttpConnector` import is from `hyper_util::client::legacy::connect::HttpConnector`, not `hyper::client::HttpConnector`. Minor, but the doc doesn't specify the crate origin.
- [http_shared.md:324-325] — Doc says normal verification path uses `WebPkiServerVerifier`. Actual code at `http_client/mod.rs:558` uses `builder.with_root_certificates(root_store).with_no_client_auth()` directly (rustls default verification), not an explicit `WebPkiServerVerifier`. Behavior is equivalent but the implementation detail is wrong.
- [http_shared.md:129] — Claims `StreamingWafBody` "Implements `http_body::Body` and scans each chunk via `sw.scan_chunk()`". Actually implements `hyper::body::Body` (line 163), not `http_body::Body`. Also has different scan behavior — uses `StreamingWafDecision::Block` pattern, not just Block/Continue.
- [http_shared.md:265-266] — References `skills/AGENTS.override.md` for HTTP/2 pooling limitation. Should reference the actual skills file path (likely `skills/erased_http_client.md` or similar).
- [http_server.md:340-341] — Lists `dns` feature for "HTTP-01 ACME challenge serving via `mesh_transport.get_http01_challenge()`". The `dns` feature doesn't gate the HTTP-01 challenge code in `server.rs` — the challenge handling at lines 782-808 is behind `#[cfg(feature = "mesh")]`. The `dns` feature may be relevant elsewhere but not for the HTTP server's challenge serving.

## Bugs Identified

- [medium] BUG-HTTP-1: `request_body_size` double assignment at `server.rs:1533,1561` (set by `collect_body_with_chunk_waf` via `&mut` ref) and `server.rs:1633` (overwritten from content-length header). The second assignment overwrites the first, making the WAF's body size tracking unreliable. (AGENTS.md says this was fixed 2026-05-27, but the code still shows the double assignment.)
- [low] BUG-HTTP-2: `RequestContext` trait and `SharedRequestHandler::protocol_name()` are both `#[allow(dead_code)]` (`shared_handler.rs:133,302`). These are dead code that should either be used or removed.
- [low] BUG-HTTP-3: `tls/server.rs:2086` has a separate `collect_body_with_chunk_waf` implementation with a different signature (no `request_body_size: &mut u64`, returns `Bytes` directly instead of `Result<Bytes, ()>`). Code duplication between `server.rs:4665` and `tls/server.rs:2086`.

## Suggested Improvements

- **Documentation**: Update `http_shared.md` to fix the `send_request_with_headers` → `send_request_with_timeout_and_headers` rename.
- **Documentation**: Clarify that `StaticResponseBody` is in `src/static_files/mod.rs`, not `src/http/`.
- **Documentation**: Note that `RequestContext` trait is currently dead code (unused in request pipeline).
- **Documentation**: Fix `build_tls_config` description — normal path doesn't explicitly use `WebPkiServerVerifier`, uses rustls default verification via `with_root_certificates`.
- **Documentation**: Fix `StreamingWafBody` description — implements `hyper::body::Body`, not `http_body::Body`.
- **Dead code**: Either integrate `RequestContext` trait into the request pipeline or remove it and `SharedRequestHandler::protocol_name()`.
- **Code duplication**: Unify `collect_body_with_chunk_waf` implementations in `server.rs` and `tls/server.rs` into `shared_handler.rs`.
- **AGENTS.md**: Remove or update the `request_body_size double assignment` entry from "Verified Already Fixed" since the double assignment still exists at lines 1533/1561 and 1633.
- **Feature gate clarity**: Clarify that the `dns` feature doesn't gate HTTP-01 challenge serving in `server.rs` — that's behind `mesh` feature.

## Stale Content

- [http_server.md:23] — `server.rs (4908 lines)` should be `4907 lines`.
- [http_shared.md:176] — `send_request_with_headers` function name is stale — renamed to `send_request_with_timeout_and_headers`.
- [http_shared.md:265-266] — Reference to `skills/AGENTS.override.md` for HTTP/2 pooling should point to the actual skills file.
- [http_server.md:341] — `dns` feature gate description for HTTP-01 challenge is misleading — challenge serving is behind `mesh` feature.

## Cross-Reference Status

- **AGENTS.md "Known File Path Corrections"**: `src/http/shared_handler.rs` containing `collect_body_with_chunk_waf` and `stream_body_with_waf` — `stream_body_with_waf` IS in `shared_handler.rs:420` (correct), but `collect_body_with_chunk_waf` is in `server.rs:4665` and `tls/server.rs:2086` (not in `shared_handler.rs`). The AGENTS.md correction table is accurate for this.
- **AGENTS.md "request_body_size double assignment"**: Listed as FIXED (2026-05-27) but the double assignment pattern still exists at `server.rs:1533/1561` and `server.rs:1633`. Needs verification of whether this is actually a bug or intentional (content-length header recording may be separate from WAF body size tracking).
- **AGENTS.md "collect_body_with_chunk_waf and stream_body_with_waf"**: These are in `server.rs:4665` and `shared_handler.rs:420` respectively — both confirmed present.
- **AGENTS.md "HTTP/2 available but not enforced"**: Now configurable via `ProxyServer::with_http2()` — confirmed in codebase. The `Http2PooledConnection.is_available()` always returns `false` (erased_pool.rs:204) confirming HTTP/2 pooling remains deferred.
- **AGENTS.md "HTTP2-POOL"**: Still accurate — `Http2PooledConnection` stub exists with `is_available()` returning `false`.
- **AGENTS.md "ErasedHttpClient HTTP/2 pooling"**: Still accurate — `send_request_erased_streaming` accepts `is_http2` param but it's only used for pool key lookup, not actual protocol switching.
- **AGENTS.md "BUG-CORS-1"**: CORS config underscore prefix — the `inject_cors_headers` function in `headers.rs` reads from `SiteCorsConfig` which uses non-underscore field names. The CORS handling is in `headers.rs`, not `admin/mod.rs:860`. May need path update.
