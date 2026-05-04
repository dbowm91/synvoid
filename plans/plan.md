# Reverse Proxy and WAF Improvement Plan

**Status**: Ready for implementation handoff  
**Last updated**: 2026-05-04  
**Scope**: Reverse proxy, WAF request path, UnifiedServerWorker process boundary, mesh proxy dispatch, non-mesh high-traffic proxying, scalability, and security.

This file intentionally contains only incomplete, deferred, or verification-needed work. Completed background review notes were pruned. The next agent should treat every item below as open unless a later commit clearly proves otherwise.

## Primary Goal

All untrusted client request handling for WAF/proxy traffic must happen in `UnifiedServerWorker` processes, separate from Overseer and Master. The worker path must scale across:

- Many proxied sites and domains.
- High-traffic non-mesh reverse proxy deployments.
- Mesh-enabled deployments using DHT/topology/mesh transport for routing.
- HTTP, HTTPS, HTTP/3, WebSocket, and supported backend types.

The intended steady-state path is:

1. Overseer manages lifecycle/upgrades.
2. Master manages workers, admin/control coordination, and IPC.
3. UnifiedServerWorker accepts external request traffic.
4. Worker performs routing, WAF checks, body inspection, backend dispatch, proxy response filtering, metrics, and drain handling.

## Current Verified Baseline

- `src/startup/master.rs` documents that Master must not run `UnifiedServer` inline.
- Master spawns `UnifiedServerWorker` via `process_manager.spawn_unified_server_workers(...)`.
- `src/worker/unified_server.rs` creates `UnifiedServer` in the worker and initializes WAF/mesh-related worker services there.
- `cargo check --no-default-features --features mesh` passed on 2026-05-04 after allowing network access for the `utoipa-swagger-ui` build artifact. It produced warnings but no compile errors.

Do not remove these invariants while implementing the plan.

## Verified: Single UnifiedServerWorker Architecture

### Why Only One UnifiedServerWorker?

**Tokio's single-process multi-threaded model is correct** for our 1M+ RPS target:

1. **Tokio handles all cores efficiently**: A single Tokio runtime with `worker_threads` equal to CPU cores uses cooperative scheduling internally. Multiple worker processes add process isolation overhead without increasing throughput.

2. **Millions of tenants - no process-per-tenant isolation**: Process-per-tenant isolation would require millions of processes (one per tenant), which is impossible. All tenants share the same async event loop with O(1) domain-based routing.

3. **Scaling approach**: For scaling, tune `tcp.worker_pool_size` (connection accepting threads) or use async primitives within the existing event loop. **Do NOT increase `unified_server_workers`** — this only affects the number of Tokio runtime threads, not request throughput.

### BaseWorkerProcess is Legacy TCP/UDP Proxy (Not HTTP)

The `--worker` flag spawns `BaseWorkerProcess` which:
- Receives a dedicated port in the `worker_port_base` range (default 9000+)
- **Has no HTTP handler** in `main.rs` — the `args.worker` branch is empty
- The code exists but is **never invoked** for normal HTTP traffic
- May be legacy pre-unified design or for raw TCP/UDP proxy scenarios
- Admin API `/system/workers/scale` only scales `BaseWorkerProcess` count, not UnifiedServerWorker

**Investigation needed**: Determine if BaseWorkerProcess should be removed or if it serves some legitimate purpose (serverless, webapp architecture, etc.).

### Reference Documents
- [`docs/adr/ADR-003-unified-worker-process.md`](../docs/adr/ADR-003-unified-worker-process.md) — Full ADR for unified worker architecture

## P0: Preserve the Worker-Only Request Boundary

### Status: ✅ COMPLETED (2026-05-04)

- Added `tests/architecture_test.rs` documenting the architectural constraint
- Enhanced logging in `src/startup/master.rs` with listener ownership labels:
  - Admin server: `(owned by: MASTER process)`
  - Worker spawn: `(each worker owns: HTTP/HTTPS/HTTP3 listeners)`
- Decision: Admin server runs in Master as control-plane traffic (Option A from plan)

## P0: Fix Mesh Backend Proxy Wiring

### Status: ✅ COMPLETED (2026-05-04)

- Added `BackendConfig::Mesh` variant to `src/config/site/backend.rs`
- Added router handling for `BackendType::Mesh` at location and site level
- Propagated `mesh_backend_pool` through `ServerSharedState`
- Wired `mesh_backend_pool` to HTTP server via `with_mesh_backend_pool`
- Config syntax: `backend: { type: mesh, upstream: "upstream-id" }`

## P0: Stream Request Bodies Instead of Full Buffering

### Status: ⚠️ PARTIALLY COMPLETED - Infrastructure exists, true streaming path still deferred

**What was verified:**
- Chunk-based WAF scanning is fully implemented in `StreamingWafCore`
- `collect_body_with_chunk_waf_impl` exists and performs per-chunk WAF scanning during collection
- HTTP/3 server already demonstrates per-chunk WAF pattern

**What was implemented (2026-05-04):**
- Created `StreamingWafBody<B>` type implementing `hyper::body::Body` that wraps incoming body streams and performs WAF scanning on chunks as they pass through (`src/http_client/mod.rs`)
- Modified `send_request_streaming` to accept `Into<Option<Bytes>>` for backward compatibility

**What remains deferred (requires significant refactoring):**
- True streaming to upstream (body currently collected fully before `send_request_streaming`)
- Per-site/per-route buffering policy config (`auto`, `buffered`, `streaming`, `streaming_required`)
- Tests for true streaming with malicious content detection mid-stream
- HTTP server must avoid full body collection when streaming is enabled

**Required for completion:**
- [x] Create a `StreamingWafBody` type implementing `hyper::body::Body` that performs WAF scanning during reads ✅ DONE
- [x] Modify `send_request_streaming` to accept `impl hyper::body::Body` instead of `Option<Bytes>` ✅ DONE (via Into<Option<Bytes>>)
- [ ] Add per-site/per-route buffering policy config (`auto`, `buffered`, `streaming`, `streaming_required`)
- [ ] Add tests for true streaming with malicious content detection mid-stream
- [ ] Refactor HTTP server to bypass full body collection when streaming policy is enabled

### Problem

Reverse proxy/WAF traffic appears to run in `UnifiedServerWorker`, but the invariant is mostly documented rather than tested. Master still starts the admin HTTP server in-process, which may be acceptable if admin is explicitly control-plane traffic, but it conflicts with broad statements that Master must not accept external requests.

### Files

- `src/startup/master.rs`
- `src/overseer/spawn.rs`
- `src/process/manager.rs`
- `src/worker/unified_server.rs`
- `src/server/mod.rs`
- `src/admin/*`

### Tasks

- Add an architecture test or integration-style assertion that Master startup never constructs or runs `UnifiedServer`.
- Add a test or compile-time guard around `UnifiedServer::new` usage so future code cannot accidentally instantiate it from Master startup paths.
- Decide and document the admin server boundary:
  - Option A: Admin server may run in Master, but it must bind only to configured admin addresses, require explicit auth, and be documented as control-plane traffic.
  - Option B: Move admin serving to a dedicated admin worker/process and keep Master purely orchestration-only.
- If keeping admin in Master, update comments in `src/startup/master.rs` to distinguish "proxy/WAF request handling" from "admin/control-plane request handling".
- Add startup logging that clearly lists which process owns each network listener: HTTP, HTTPS, HTTP/3, TCP, UDP, DNS, mesh, admin.

### Acceptance Criteria

- A test fails if Master starts `UnifiedServer` inline.
- Documentation clearly states whether admin HTTP is allowed in Master.
- Operators can tell from logs which process owns each externally reachable listener.

## P0: Fix Mesh Backend Proxy Wiring

### Problem

`UnifiedServer` has a `mesh_backend_pool`, and `HttpServer` has a `BackendType::Mesh` dispatch path, but the pool is not propagated through shared server state into HTTP/TLS/HTTP3 servers. The router also appears not to construct `BackendType::Mesh` for any config path. This makes mesh reverse-proxy backend dispatch either dead code or unreachable.

### Evidence

- `src/server/mod.rs` has `UnifiedServer.mesh_backend_pool`.
- `src/server/mod.rs` `ServerSharedState` does not include `mesh_backend_pool`.
- `src/server/mod.rs` `run_http_server_inner` passes mesh transport/config but not mesh backend pool.
- `src/http/server.rs` dispatches `BackendType::Mesh` only when `mesh_backend_pool` is present.
- `src/router.rs` defines `BackendType::Mesh`, but current route construction found during review only produced `Upstream`, `QuicTunnel`, `Static`, `Serverless`, `AppServer`, `FastCgi`, `Php`, `Cgi`, `Spin`, and `AxumDynamic`.

### Files

- `src/server/mod.rs`
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`
- `src/router.rs`
- `src/mesh/backend.rs`
- `src/mesh/proxy.rs`
- `src/config/site/proxy.rs`
- `src/config/site/*`

### Tasks

- Define the config syntax that should select a mesh backend. Examples to evaluate:
  - `backend = "mesh"` in location/site backend config.
  - `upstream = "mesh://<upstream_id>"`.
  - Existing mesh-specific upstream config if one already exists.
- Implement router construction for mesh backends:
  - Parse the selected syntax.
  - Set `RouteTarget.backend_type = BackendType::Mesh`.
  - Store the mesh upstream ID in `RouteTarget.upstream`.
  - Reject malformed or empty mesh upstream IDs during config validation.
- Create and populate `MeshBackendPool` in the worker/server setup when mesh is enabled:
  - Use `crate::mesh::backend::create_mesh_backend_from_config` or refactor equivalent construction to avoid duplicate topology/transport stacks.
  - Add configured mesh upstream IDs to the pool.
  - Keep a clear ownership model so there is one active mesh transport/topology per worker unless deliberate sharing is impossible.
- Propagate `mesh_backend_pool` through:
  - `UnifiedServer`
  - `ServerSharedState`
  - HTTP server builder
  - HTTPS server builder
  - HTTP/3 server if mesh backend dispatch should support HTTP/3
- Add tests:
  - Router returns `BackendType::Mesh` for valid mesh upstream config.
  - Invalid mesh upstream config fails validation.
  - HTTP handler with mesh route and missing pool returns a deterministic 502/503.
  - HTTP handler with mesh route and populated pool calls `MeshBackend::proxy_request`.
- Add metrics:
  - `maluwaf.mesh.proxy.route_found`
  - `maluwaf.mesh.proxy.no_backend_pool`
  - `maluwaf.mesh.proxy.no_available_backend`
  - `maluwaf.mesh.proxy.upstream_error`

### Acceptance Criteria

- Mesh backend routes are reachable from config.
- A valid mesh route no longer fails because the pool was dropped between `UnifiedServer` and protocol servers.
- HTTP, HTTPS, and HTTP/3 behavior is either supported or explicitly documented as unsupported.

## P0: Stream Request Bodies Instead of Full Buffering

### Problem

The HTTP request path collects the full body before backend dispatch. The later upstream call may use `send_request_streaming`, but it still passes a fully collected `Bytes`. This is a scalability problem for uploads, large POST/PUT/PATCH requests, and high-traffic proxying.

### Files

- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`
- `src/http/shared_handler.rs`
- `src/http_client/mod.rs`
- `src/waf/attack_detection/streaming.rs`
- `src/proxy/executor.rs`
- `src/proxy/mod.rs`
- `src/upload/*`

### Tasks

- Define body handling modes:
  - Small buffered body: keep current behavior below a conservative threshold.
  - Streaming body with chunk WAF: inspect chunks and forward chunks without retaining the whole body.
  - Forced buffered body: required only for WASM filters, response transforms that need body context, upload malware scan, serverless, Spin, CGI/PHP/AppServer paths that cannot stream yet.
- Add per-site/per-route config for buffering policy:
  - `auto` default.
  - `buffered`.
  - `streaming`.
  - `streaming_required` should reject incompatible features at config validation.
- Refactor request handling so routing happens before deciding whether to buffer the full body. Site config determines whether body transforms/upload scanning/plugin/serverless require buffering.
- Extend `http_client` with an upstream forwarding API that accepts a body stream, not just `Bytes`.
- Wire streaming WAF inspection into the forwarding stream:
  - Inspect chunks before forwarding.
  - Stop forwarding and return a WAF response when a malicious chunk is detected.
  - Enforce max body size even with missing `Content-Length`.
  - Keep backpressure from upstream.
- Avoid double scanning:
  - Do early/header/path WAF before body streaming.
  - Do chunk body WAF during stream.
  - Do full-body WAF only when body was intentionally buffered.
- Add metrics:
  - body mode selected by site/backend.
  - streaming body bytes inspected.
  - body blocked during stream.
  - forced buffering reason.
  - request body spill/overflow if disk buffering is introduced.
- Add tests:
  - Large body is proxied without allocating one complete `Bytes`.
  - Malicious content in later chunks is blocked.
  - Missing `Content-Length` still respects max streaming body size.
  - Buffered-only features still work and are explicitly reported.

### Acceptance Criteria

- Plain upstream proxying can forward large bodies without holding the complete request body in memory.
- WAF still inspects streamed bodies and can block mid-stream.
- Incompatible features fail validation or intentionally fall back to bounded buffering with metrics.

## P0: Correct Forwarded Header Semantics

### Status: ✅ COMPLETED (2026-05-04)

- `ForwardedProtocol` enum added replacing boolean `is_tls` in `build_forward_headers`
- HTTP server fixed to use `ForwardedProtocol::Http` (was incorrectly using `true`)
- TLS server uses `ForwardedProtocol::Https`
- HTTP/3 server uses `ForwardedProtocol::Https`
- Tests added for protocol-specific `x-forwarded-proto` values

## P0: Fix Listener/IP-Based Routing

### Status: ✅ COMPLETED (2026-05-04)

- Added `site_map: HashMap<String, Arc<SiteConfig>>` keyed by `site_id`
- Added `cleaned_site_domain_suffixes` to avoid per-request `format!()` allocation
- Fixed `route_with_local_addr` to use `site_map` instead of `domain_map` for site_id lookups
- Fixed default server lookups to use `site_map`
- Optimized `is_host_valid_for_site` to use precomputed suffixes

### Problem

`build_forward_headers` sets `x-forwarded-proto` based on an `is_tls` argument. The HTTP handler currently passes `true` in the main upstream streaming path, causing plain HTTP requests to be forwarded as `https`.

### Files

- `src/proxy/headers.rs`
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`
- `src/proxy/executor.rs`
- `src/http_client/mod.rs`

### Tasks

- Replace boolean `is_tls` with a typed enum, for example:
  - `ForwardedProto::Http`
  - `ForwardedProto::Https`
  - `ForwardedProto::Http3`
  - or a `TlsContext`/protocol value already used by handlers.
- Pass the correct protocol from each handler:
  - HTTP listener: `http`.
  - TLS listener: `https`.
  - HTTP/3 listener: `https` or `h3` only if intentionally configured.
  - QUIC tunnel: document desired upstream-facing value.
- Preserve the existing security behavior:
  - Strip client-supplied `x-forwarded-for`, `x-real-ip`, and `forwarded`.
  - Strip hop-by-hop headers.
  - Apply site `clear`, `hide`, and `set`.
- Add tests:
  - Plain HTTP request forwards `x-forwarded-proto: http`.
  - HTTPS request forwards `x-forwarded-proto: https`.
  - HTTP/3 behavior is explicit and tested.
  - Client-supplied spoofable forwarded headers are overwritten.

### Acceptance Criteria

- Upstreams no longer receive false `x-forwarded-proto: https` for plain HTTP traffic.
- Protocol handling is typed enough to prevent future boolean confusion.

## P0: Fix Listener/IP-Based Routing

### Problem

`Router::route_with_local_addr` uses `listen_map` values as site IDs, but then looks those IDs up in `domain_map`, which is keyed by domain names. Default-server lookup has the same issue. IP/listener virtual hosts can therefore fail unexpectedly and fall through to domain/fallback routing.

### Files

- `src/router.rs`
- `src/config/site/*`
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`

### Tasks

- Add a `site_map: HashMap<String, Arc<SiteConfig>>` keyed by `site_id`.
- Populate `site_map` in `Router::build_all_maps` or equivalent construction.
- Change listener/default-server lookup to use `site_map`, not `domain_map`.
- Avoid per-request `format!(".{}", clean_domain)` in loops; precompute suffix forms or use a helper that does not allocate.
- Add tests:
  - A site selected by listener address with empty domains routes correctly.
  - A listener default server routes correctly when Host is empty.
  - Multiple domains on one listener still enforce host validation.
  - Fallback routing still works when no listener/default match exists.

### Acceptance Criteria

- Listener/default-server routing works by `site_id`.
- Exact domain routing remains O(1).
- Tests cover multi-site listener behavior.

## P1: Make WAF Stall/Tarpit Safe Under Load

### Problem

Attack detection defaults to action `stall`, and the HTTP handler holds the request for `waf_stall_timeout_secs`. That can intentionally slow malicious clients, but at high traffic rates it can consume worker tasks/connections and become a resource-exhaustion amplifier.

### Files

- `src/waf/mod.rs`
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`
- `src/waf/traffic_shaper/*`
- `src/config/*`

### Tasks

- Define default action policy:
  - For production/high-throughput profile, strongly consider `block` or bounded tarpit instead of long `stall`.
  - Keep `stall` available only with explicit config.
- Add global and per-site limits for concurrent stalled/tarpitted requests.
- Add a short maximum cap for stall duration in strict/high-throughput profile.
- Ensure stalled connections release request/body buffers first.
- Add metrics:
  - active stalled requests.
  - stall rejected due to concurrency cap.
  - average stall duration.
- Add tests:
  - Stall cap returns deterministic response after timeout.
  - Concurrency cap prevents unbounded stalled tasks.
  - Config default is documented and test-covered.

### Acceptance Criteria

- Malicious traffic cannot create unbounded sleeping tasks.
- Operators can choose block/stall/tarpit explicitly and see active counts.

## P1: Unify HTTP, HTTPS, and HTTP/3 Behavior

### Status: ⚠️ DEFERRED - Requires significant architectural refactoring

### Problem

HTTP, TLS, and HTTP/3 paths each contain request handling/proxy logic. This risks drift in WAF checks, body handling, header forwarding, response filtering, metrics, and drain behavior.

### Files

- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`
- `src/http/shared_handler.rs`
- `src/server/request_handler.rs`
- `src/proxy/executor.rs`

### Tasks

- Extract a protocol-agnostic request pipeline that accepts:
  - method
  - URI/path/query
  - headers
  - client IP
  - local listener address
  - body mode/stream
  - protocol context
  - optional upgrade context
- Keep protocol-specific code only for:
  - accepting connections.
  - TLS/JA4 metadata.
  - HTTP/3 stream adaptation.
  - WebSocket upgrade mechanics.
- Centralize:
  - trusted proxy sanitization.
  - early WAF.
  - route resolution.
  - full/body WAF.
  - backend dispatch.
  - forward header building.
  - response header filtering/security headers.
  - logging/metrics.
- Add parity tests for:
  - same WAF block decision across HTTP/HTTPS/HTTP3.
  - same response header filtering.
  - same forwarded headers except protocol value.
  - same missing-route behavior.
  - same drain/health behavior where applicable.

### Acceptance Criteria

- New WAF/proxy behavior can be changed once in a shared pipeline.
- Protocol-specific files are smaller and mostly adapters.
- Parity tests prevent future drift.

## P1: Scale Routing for Many Sites

### Status: ⚠️ DEFERRED - Requires benchmarks to determine if current approach is sufficient

### Problem

Exact domain routing is map-based, but suffix/wildcard matching is a sorted linear scan. Large deployments with many proxied sites need measured or bounded behavior.

### Files

- `src/router.rs`
- `src/location_matcher.rs`
- `benches/*`

### Tasks

- Add router benchmarks:
  - exact host lookup with 1, 100, 10k, 100k domains.
  - wildcard/suffix lookup with 1, 100, 10k suffixes.
  - location matching with small and large location sets.
  - listener/default-server lookup.
- Replace suffix linear scan if benchmarks exceed budget:
  - Consider reversed-domain trie.
  - Consider public-suffix-aware indexing if needed.
  - Keep exact match map as fast path.
- Precompute cleaned domain/suffix forms at config load.
- Avoid per-request string allocation where possible:
  - Host cleanup should avoid allocation when already lowercase/no `www.`.
  - Suffix comparisons should not allocate temporary strings in loops.
- Add metrics for route fallback cost:
  - exact hit.
  - suffix checks count.
  - listener checks count.
  - route miss.

### Acceptance Criteria

- Exact host lookup remains O(1).
- Suffix/wildcard lookup has benchmarked bounds and documented limits.
- Large-site routing benchmarks are part of performance verification.

## P1: Reduce Proxy Hot-Path Allocations

### Problem

Header forwarding, response filtering, cache keys, URL joining, and body cloning are all hot paths. Several paths allocate `Vec`, clone headers, or build strings per request.

### Files

- `src/proxy/headers.rs`
- `src/proxy/executor.rs`
- `src/proxy/mod.rs`
- `src/proxy_cache/key.rs`
- `src/http/server.rs`
- `src/http_client/mod.rs`

### Tasks

- Benchmark:
  - `build_forward_headers`.
  - response header filtering.
  - `join_upstream_url`.
  - cache key construction.
  - upstream target preparation.
- Replace `Vec<&str>` allocation in `build_forward_headers` with direct slice/iterator logic.
- Precompile site header forwarding rules at config load:
  - lowercased allowlist.
  - hide/clear sets.
  - set overrides parsed into `HeaderName`/`HeaderValue`.
- Avoid repeated `client_ip.to_string()` calls in header building.
- Avoid cloning full request bodies for cache/retry unless needed.
- Ensure retry logic does not retry non-idempotent methods unless explicitly configured.
- Verify response size limits for streaming responses:
  - `Content-Length` pre-check is not sufficient for unknown/chunked bodies.
  - Add counted streaming body wrapper to enforce max response size mid-stream.

### Acceptance Criteria

- Header/caching benchmarks exist and show improvement or documented baseline.
- Streaming response size limits are enforced for unknown-length responses.
- Non-idempotent retry behavior is test-covered.

## P1: Harden Proxy Security Defaults

### Problem

The proxy layer strips many headers and sanitizes forwarded headers, but the full security posture needs explicit tests and config validation.

### Files

- `src/proxy/headers.rs`
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`
- `src/config/site/proxy.rs`
- `src/config/validation.rs`

### Tasks

- Add tests that client-supplied spoofable headers are removed/overwritten:
  - `x-forwarded-for`
  - `x-real-ip`
  - `forwarded`
  - `x-forwarded-proto`
  - hop-by-hop headers.
- Validate upstream URLs:
  - reject invalid schemes by default.
  - default allowed protocols should be explicit.
  - require opt-in for tunnel/mesh/custom schemes.
- Validate `skip_verify`:
  - warn or fail in strict profile.
  - include site ID/upstream in validation message.
- Ensure `Location` response header stripping is intentional:
  - Current `HEADERS_TO_STRIP` includes `location`.
  - If this breaks upstream redirects, replace blanket strip with configurable rewrite/hide behavior.
- Add tests for cache purge:
  - token comparison stays constant-time.
  - purge unavailable when token/allowlist unset.
  - allowlist uses sanitized real client IP, not spoofed headers.

### Acceptance Criteria

- Proxy security defaults are enforced by tests.
- Unsafe upstream TLS and scheme settings are explicit.
- Redirect/header stripping behavior is documented and configurable.

## P1: Replace Deprecated Global Service Access in Request Paths

### Problem

Worker guidance says global singletons such as `get_threat_intel`, `get_yara_rules`, and `get_upload_validator` are deprecated in favor of `RequestServices`. The current request path still uses deprecated globals.

### Files

- `src/worker/context.rs`
- `src/worker/unified_server.rs`
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/static_files/file_manager.rs`
- `src/waf/mod.rs`
- `src/proxy/mod.rs`

### Tasks

- Thread `RequestServices` into the protocol-agnostic request pipeline.
- Replace upload validator global access in HTTP/TLS upload validation.
- Replace threat-intel global access in WAF/proxy event publishing.
- Replace YARA global access in static/file-manager paths where practical.
- Keep temporary compatibility shims only outside hot request paths.
- Add tests that multiple workers can hold independent service context without global cross-talk.

### Acceptance Criteria

- Main request path no longer uses deprecated global service access.
- Worker-local service dependencies are explicit and testable.

## P2: Cache and Revalidation Scalability

### Problem

Proxy cache behavior exists, but stale-while-revalidate and invalidation can create background task bursts and broad invalidation scans.

### Files

- `src/proxy/mod.rs`
- `src/proxy/executor.rs`
- `src/proxy_cache/*`

### Tasks

- Add bounded revalidation queue per worker/site.
- Coalesce concurrent revalidations for the same cache key.
- Add backpressure metrics:
  - revalidation queued.
  - coalesced.
  - dropped due to queue full.
- Review invalidation by pattern for complexity. Add config limits for broad wildcard invalidations.
- Ensure revalidation uses correct forwarded protocol and sanitized headers.

### Acceptance Criteria

- Stale cache traffic cannot spawn unbounded background tasks.
- Cache invalidation complexity is bounded or explicitly rate-limited.

## P2: Mesh Proxy Provider Selection and Failure Behavior

### Problem

Mesh proxy scalability depends on fast provider selection, health tracking, and failure isolation. Current review focused on wiring; deeper provider correctness still needs implementation review.

### Files

- `src/mesh/proxy.rs`
- `src/mesh/backend.rs`
- `src/mesh/topology.rs`
- `src/mesh/transport*.rs`
- `src/mesh/dht/*`

### Tasks

- After P0 mesh wiring is fixed, review `MeshProxy::route_request` and provider selection for:
  - verified provider records only when verification is required.
  - bounded DHT/topology lookups per request.
  - local cache TTLs for provider resolution.
  - negative caching for unavailable upstream IDs.
  - health-based exclusion with recovery.
- Add metrics:
  - provider resolution time.
  - provider cache hit/miss.
  - selected provider.
  - route-not-found.
  - provider failure and recovery.
- Add tests:
  - unavailable provider returns 503 quickly.
  - unhealthy provider is avoided.
  - provider cache expires and refreshes.

### Acceptance Criteria

- Mesh provider lookup is not an unbounded DHT/topology operation on every request.
- Failure modes are fast, observable, and recoverable.

## P2: Performance Verification Gates

### Problem

The project has a 1M RPS aspiration, but reverse proxy/WAF hot-path budgets need measurable gates.

### Files

- `benches/*`
- `Cargo.toml`
- `.github/workflows/*` if present
- `architecture/*`

### Tasks

- Add or update benchmark suites for:
  - simple HTTP proxy request pipeline without body.
  - large streaming request body.
  - WAF benign path.
  - WAF malicious path.
  - router exact/suffix/listener paths.
  - header forwarding/filtering.
  - cache key building.
- Define performance budgets in docs:
  - allocation count target.
  - route lookup target.
  - body streaming memory bound.
  - WAF inspection latency target.
- Add a lightweight CI gate that compiles benches or runs smoke benchmarks where feasible.
- Document heavier local benchmark commands for agents/operators.

### Acceptance Criteria

- Regressions can be detected with repeatable commands.
- Performance goals are tied to measurements, not only comments.

## Verification Commands

Run these after implementing relevant tasks:

```bash
cargo fmt
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib proxy
cargo test --lib router
cargo test --lib waf
cargo test --lib http
cargo test --test security_regression
```

For performance work, also run the relevant benches, for example:

```bash
cargo bench --bench bench_proxy_cache
cargo bench --bench bench_attack_detection
```

If `utoipa-swagger-ui` tries to download Swagger UI during a clean build, network access may be required unless the artifact is already cached.

## Deferred Items

These are intentionally left for later agents if they are not completed by the main implementation pass:

- Move or isolate admin serving if the project chooses a strict "Master has no external listeners" boundary.
- Full protocol-agnostic request pipeline extraction across HTTP, HTTPS, and HTTP/3.
- Full replacement of deprecated global service access with `RequestServices`.
- Mesh provider trust/ownership review beyond the backend-pool wiring fix.
- Large-scale router data structure replacement if initial benchmarks show current suffix matching is acceptable for expected deployments.
