# MaluWAF Traffic Layer Proxy and Routing Improvement Plan

**Status**: OPEN
**Last Updated**: 2026-05-01
**Primary Scope**: HTTP/HTTPS reverse proxying, route selection, upstream pools, retry/failover,
request and response header forwarding, proxy cache behavior, upstream TLS client reuse, mesh
backend routing, and traffic-layer regression coverage.

This section is a handoff plan for a follow-on agent that may not have the adversarial traffic-layer
review context. It is intentionally explicit about files, failure modes, and tests. The work below
is read-only review output; no implementation items are complete yet. Do not delete open or deferred
items from this section unless the implementation is finished, intentionally superseded, or moved to
another tracked plan with a clear reference.

The previously open WAF/security and architecture plans are preserved later in this file. They are
not completed or superseded by this traffic-layer plan.

## Traffic Layer Diagnosis

The traffic layer has strong pieces in isolation:

- `src/router.rs` precomputes exact host maps and location matchers.
- `src/proxy/mod.rs` contains upstream pools, retry/failover, cache handling, WAF-integrated proxy
  request handling, and response-size enforcement.
- `src/upstream/pool.rs` tracks backend health and connection counts.
- `src/http/server.rs` has a direct streaming path for large upstream responses.
- `src/mesh/proxy.rs` and `src/mesh/backend.rs` provide mesh-backed routing.

The problem is that these pieces do not form one coherent data-plane contract. The main HTTP
request path in `src/http/server.rs` builds target URLs and calls HTTP client functions directly,
while `ProxyServer` has separate logic for upstream pools, retries, cache, and response-size
limits. As a result, config surfaces can exist without affecting the dominant request path.
Headers, cache behavior, retries, upstream TLS, and route validation are inconsistent across HTTP,
TLS, proxy-cache, QUIC tunnel, and mesh paths.

The goal of this plan is to converge the traffic layer around a single explicit routing/proxying
contract:

1. A request route resolves to a typed backend target with precomputed proxy policy.
2. Every external upstream path applies the same header, retry, cache, size-limit, and TLS policy
   unless explicitly documented otherwise.
3. Route matching and proxy forwarding avoid avoidable per-request allocation in hot paths.
4. Cache, purge, and stale revalidation target the configured upstream and use the same key model.
5. Mesh and direct upstream routing expose the same behavior where operationally possible.
6. Tests prove behavior at the HTTP server boundary, not only helper functions.

## Traffic Layer Ground Rules

- Read `src/proxy/AGENTS.override.md`, `src/http/AGENTS.override.md`,
  `src/mesh/AGENTS.override.md`, and `src/config/AGENTS.override.md` before editing affected files.
- Keep patches focused. Do not rewrite the whole server while fixing a single routing contract.
- Preserve hot-path discipline. Avoid new per-request `String`, `Vec`, `HashSet`, regex, client,
  or config allocation unless the current path already pays the cost and the patch is a step toward
  removing it.
- Prefer typed, precomputed route/proxy policy over reconstructing behavior from config per request.
- Treat HTTP, TLS, HTTP/3, QUIC tunnel, mesh, and cache as separate entry points that must be tested
  against a common matrix.
- Preserve user/worktree changes. This file is a handoff plan; implementation agents should inspect
  `git status` before editing.

Recommended baseline checks:

```bash
cargo test --lib --no-run
cargo test --lib router
cargo test --lib proxy
cargo test --lib upstream
cargo test --lib http
cargo fmt --check
cargo clippy --lib -- -D warnings
```

When touching TLS or HTTP/3 paths, also run targeted TLS/HTTP3 checks used by the repository. If a
command cannot run locally, record the exact failure and reason in the final handoff notes.

## Priority 1: Define One Proxy Execution Contract

**Status**: COMPLETED (wave17-2026-05-02)

### Problem

**Completed:**

1. **Traffic entrypoint matrix** created at `plans/traffic_entrypoint_matrix.md` documenting all entry points and their behavior
2. **Shared proxy executor module** at `src/proxy/executor.rs` with:
   - `PreparedUpstreamTarget` - URL construction via `join_upstream_url`, timeout from config, max_response_size
   - `UpstreamResponsePolicy` - Response header filter set, security headers, size limits
   - `apply_response_size_limit()` - Enforce max_response_size on buffered bodies
   - `build_upstream_request()` - Build complete upstream Request from prepared target
3. **Main HTTP server** wired to use `PreparedUpstreamTarget` and `apply_response_size_limit`
4. **TLS server** direct path wired to use `PreparedUpstreamTarget`
5. **HTTP/3 server** wired to use `PreparedUpstreamTarget` and `apply_response_size_limit`

### What remains (tracked in other priorities):
- TLS client pooling (P4)
- Retry in main HTTP/TLS/HTTP3 paths (P5 - ProxyServer only)
- Cache in HTTP/HTTP3 paths (P6)
- HTTP/3 response header filtering (P8)

### Problem (original)

There are at least two reverse-proxy implementations:

- `src/http/server.rs` resolves a `RouteTarget`, builds `target_url`, creates a per-site TLS client
  if needed, and calls `send_request_streaming()` or `send_request_with_body_and_timeout()`
  directly.
- `src/proxy/mod.rs` has `ProxyServer`, upstream pools, retry behavior, cache logic, response-size
  enforcement, and separate QUIC tunnel handling.

The dominant HTTP server path does not appear to call `ProxyServer` for normal upstream proxying.
This means `ProxyServer` behavior is not automatically the behavior of production traffic.

Key files:

- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`
- `src/proxy/mod.rs`
- `src/http_client/mod.rs`
- `src/router.rs`
- `src/config/site/proxy.rs`

### Required Outcome

Create a documented contract for how a routed request becomes an upstream request. The contract must
name which component owns:

- upstream URL construction,
- request header forwarding and filtering,
- response header filtering and transforms,
- upstream TLS client selection and pooling,
- response-size enforcement,
- retry and failover,
- proxy cache lookup/store/revalidation/purge,
- QUIC tunnel handling,
- mesh backend handling,
- metrics and request logging.

Then update code so the main HTTP/TLS paths use that contract. The implementation does not have to
fully merge all code in one patch, but there must be no silent split where config is honored by
`ProxyServer` and ignored by `src/http/server.rs`.

### Implementation Steps

1. Create a traffic execution matrix.
   - Suggested file: `plans/traffic_entrypoint_matrix.md`.
   - Rows: HTTP/1, HTTP/2, TLS HTTPS, HTTP/3, direct `ProxyServer`, QUIC tunnel, mesh backend,
     proxy-cache path, static fallback path.
   - Columns: route resolution, request headers, response headers, upstream TLS, retry, cache,
     response limit, streaming/zero-copy, metrics, WAF invocation.

2. Pick the convergence shape.
   - Conservative option: factor a shared `ProxyExecutor` or `UpstreamRequestExecutor` used by
     `src/http/server.rs`, `src/tls/server.rs`, and `ProxyServer`.
   - If a full executor is too large initially, start with shared policy objects and helpers:
     `ProxyRequestPolicy`, `PreparedUpstreamTarget`, `PreparedForwardHeaders`,
     `PreparedResponseFilter`.
   - Do not add another parallel implementation.

3. Make `RouteTarget` carry enough typed information.
   - Avoid repeatedly deriving upstream behavior from raw config in request handling.
   - Add or derive a precomputed proxy policy during router construction if possible.
   - Keep route target cheap to clone. Use `Arc` for shared immutable policy.

4. Update the main HTTP path.
   - Replace direct URL/header/client assembly in `src/http/server.rs` with the shared executor or
     shared policy helpers.
   - Keep existing streaming behavior for large responses, but move policy decisions out of the
     local block.

5. Update TLS and HTTP/3 equivalents.
   - `src/tls/server.rs` duplicates much of the HTTP proxy flow. Align it with the shared contract.
   - HTTP/3 may need a smaller adapter if protocol body types differ.

6. Add tests that fail against the current split.
   - A site with upstream retry config must retry through the main HTTP path.
   - A site with proxy cache config must cache through the main HTTP/TLS path.
   - A site with upstream TLS config must reuse the configured pooled client rather than creating a
     client per request.
   - A configured response-size limit must apply on streaming and buffered upstream paths.

### Done Criteria

- A traffic entrypoint matrix exists.
- The main HTTP and TLS upstream paths use the same proxy contract or shared policy helpers.
- Configured proxy behavior is not isolated in unused or rarely used code paths.
- Tests prove at least retry, cache, TLS client reuse, and response limit behavior from the server
  boundary.

## Priority 2: Fix Host Validation and Route Matching Semantics

**Status**: COMPLETED (wave16-2026-05-01)

- Fixed `route_to_target()` passing site_id instead of cleaned host to `is_host_valid_for_site()`
- Optimized `LocationMatcher::match_uri()` to use scalar best-match tracking instead of 4 vectors
- Commit: `17f251eb`

### Problem

`Router::route_to_target()` checks `reject_unknown_hosts` by passing `site_id` into
`is_host_valid_for_site()` instead of the cleaned request host. That can reject valid hosts or make
the setting meaningless depending on site ID/domain naming.

Location matching also allocates multiple vectors per request in `LocationMatcher::match_uri()`.
For a declared high-throughput target, route matching should not allocate just to classify one
request.

Key files:

- `src/router.rs`
- `src/location_matcher.rs`
- `src/http/server.rs`
- `src/tls/server.rs`
- route tests in existing test modules

### Required Outcome

Host rejection must validate the incoming cleaned host against the selected site. Location matching
must preserve current matching semantics while avoiding per-request allocation for normal matching.

### Implementation Steps

1. Fix the host-validation data flow.
   - Change `route_to_target()` to accept the cleaned request host or a small request route context.
   - Use that host for `reject_unknown_hosts`.
   - Ensure all callers pass the same cleaned host used for domain lookup.

2. Add regression tests for `reject_unknown_hosts`.
   - Exact domain accepted.
   - Allowed subdomain accepted if existing semantics intend that.
   - Unknown host rejected.
   - Site ID differing from domain still works.
   - Empty host uses configured default server only where intended.

3. Review wildcard/suffix semantics.
   - Current suffix logic uses `clean_host.ends_with(domain)`.
   - Confirm behavior for domains containing `*`, leading dots, and suffix tricks such as
     `good.com.attacker.tld`.
   - Add tests before changing behavior. If behavior changes, document migration risk.

4. Optimize `LocationMatcher::match_uri()`.
   - Replace `exact_matches`, `pref_prefix_matches`, `regex_matches`, and `prefix_matches` vectors
     with scalar best-match tracking.
   - Preserve current precedence:
     - exact,
     - longest preferential prefix,
     - first regex,
     - longest prefix.
   - Preserve `original_order` return value.

5. Add route/location tests.
   - Exact location beats prefix.
   - Preferential prefix beats regex.
   - First regex wins among regex matches.
   - Longest prefix wins among normal prefix matches.
   - No heap allocation is preferable but not required to prove with a test. If the repo has an
     allocation test helper, use it; otherwise document the before/after reasoning in comments or
     PR notes.

### Done Criteria

- `reject_unknown_hosts` validates the actual request host.
- Location matching semantics are unchanged and covered by tests.
- Location matching no longer allocates vectors per request.

## Priority 3: Correct Request Header Forwarding

**Status**: COMPLETED (wave16-2026-05-01)

- Changed `build_forward_headers()` to forward all end-to-end headers by default
- Strip hop-by-hop headers and sanitize spoofable forwarded headers
- Respect clear/hide config and apply set overrides
- Commits: `fff18d5a`

### Problem

The main streaming proxy path builds a header map using `build_forward_headers()`. With default
config, that helper forwards only:

- `X-Real-IP`,
- `X-Forwarded-For`,
- `X-Forwarded-Proto`,
- `Host`.

Then `send_request_streaming()` replaces the request headers with exactly that map. This can drop
application-critical headers such as `Authorization`, `Content-Type`, `Accept`, `Cookie`, `Range`,
trace headers, and custom API headers. The buffered path and QUIC tunnel path appear to pass
different header sets, creating inconsistent behavior.

Key files:

- `src/proxy/headers.rs`
- `src/http_client/mod.rs`
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http3/server.rs`
- `src/config/site/proxy.rs`

### Required Outcome

Define and implement one request-header forwarding policy:

- Start from incoming request headers.
- Remove hop-by-hop headers and explicitly hidden/cleared headers.
- Sanitize or replace forwarded identity headers.
- Preserve end-to-end application headers by default.
- Allow operators to add, clear, hide, or override headers through config.
- Apply the same policy in streaming, buffered, QUIC tunnel, TLS, and cache revalidation paths.

### Implementation Steps

1. Define request-header policy explicitly.
   - Add a comment or docs near `ProxyHeadersConfig`.
   - Clarify semantics of `forward`, `clear`, `hide`, and `set`.
   - Decide whether `forward` is an allowlist or an additive list. Recommended:
     - default mode forwards all safe end-to-end headers,
     - optional allowlist mode requires an explicit config name if needed.

2. Replace `build_forward_headers()` or add a new helper.
   - Suggested helper: `build_upstream_request_headers(client_ip, original_headers, config,
     request_scheme, upstream_host_policy)`.
   - It should:
     - clone or move safe end-to-end headers,
     - strip hop-by-hop headers from `Connection` and the standard hop-by-hop list,
     - strip spoofable `X-Real-IP`, `X-Forwarded-*`, `Forwarded` unless trusted-forwarding policy
       says otherwise,
     - append sanitized XFF using the already determined client IP,
     - set `X-Forwarded-Proto` based on the external request scheme, not hardcoded `true`,
     - set `Host` according to documented policy: original host, upstream host, or config override.

3. Apply to all upstream send paths.
   - Main streaming path in `src/http/server.rs`.
   - Buffered path in `src/http/server.rs`.
   - TLS server equivalent.
   - QUIC tunnel path.
   - `ProxyServer::send_single_request()`.
   - Cache revalidation path.

4. Handle `Connection` header tokens.
   - RFC behavior requires removing headers named by the `Connection` header, not just removing the
     `Connection` header itself.
   - Add tests for `Connection: X-Foo` and `X-Foo: secret` not reaching upstream.

5. Add integration-style tests.
   - Authorization header reaches upstream by default.
   - Content-Type reaches upstream by default.
   - Cookie reaches upstream by default unless configured otherwise.
   - Hop-by-hop headers are stripped.
   - Existing spoofed XFF from untrusted client is sanitized.
   - Configured `set` overrides work.
   - Configured `clear`/`hide` removes headers.
   - HTTP and TLS paths behave the same.

### Done Criteria

- Application end-to-end headers are preserved by default.
- Hop-by-hop and spoofable forwarding headers are sanitized.
- Streaming, buffered, TLS, QUIC tunnel, and direct proxy paths share the same header policy.
- Tests prove both preservation and stripping behavior.

## Priority 4: Rework Upstream TLS Client Ownership and Pooling

**Status**: OPEN

### Problem

`src/http/server.rs` constructs a site-specific upstream TLS client inside the request path when
site TLS config exists. This defeats pooling and adds avoidable per-request work. It also risks
behavior drift from `ProxyServer`, which creates clients during construction.

Key files:

- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http_client/mod.rs`
- `src/router.rs`
- `src/config/site/proxy.rs`

### Required Outcome

Upstream clients must be built outside the hot path and reused per site/upstream TLS policy. Client
selection should be part of prepared route/proxy policy, not reconstructed per request.

### Implementation Steps

1. Inventory current client creation.
   - Search for `create_upstream_client` and `create_http_client_with_config`.
   - Identify per-request calls and construction-time calls.

2. Add a client cache or precomputed client handle.
   - Key by site ID plus relevant upstream TLS config and pool config.
   - Store in router snapshot, proxy executor, or a dedicated `UpstreamClientRegistry`.
   - Use `Arc<HttpClient>` if the client type is cheaply cloneable but semantic reuse matters.

3. Preserve TLS security behavior.
   - `skip_verify` should still warn loudly, but not on every request if that creates log storms.
   - Validate `skip_verify_reason` if repo policy requires it.
   - Ensure CA/client cert changes rebuild the client on reload.

4. Wire reload behavior.
   - If upstream TLS config changes, build a new client registry off the hot path and swap it with
     the route/proxy snapshot.
   - Do not mutate existing clients in place.

5. Add tests or observability.
   - If direct testing client reuse is hard, add a unit test around the registry key and use a
     counter/test double if practical.
   - At minimum, add a regression test or code assertion that route execution does not call client
     construction.

### Done Criteria

- No upstream client is created per request for normal site proxying.
- TLS config changes rebuild clients through reload or restart semantics.
- Skip-verify warnings are useful without becoming per-request noise.

## Priority 5: Make Retry and Failover Policy Honest

**Status**: COMPLETED (wave17-2026-05-02)

### Problem

`RetryConfig` exposes `enabled` and `retry_non_idempotent`, but `ProxyServer::forward_with_pool()`
does not check either. It retries based on `max_retries`, status, and error flags. The main HTTP
server direct proxy path does not appear to use this retry code at all.

There is also a possible off-by-one semantics issue: `max_retries` is usually additional tries
after the first attempt, but the loop compares `attempt < max_retries`.

Key files:

- `src/proxy/mod.rs`
- `src/proxy/retry.rs`
- `src/config/site/proxy.rs`
- `src/upstream/pool.rs`
- main upstream path in `src/http/server.rs`

### Required Outcome

Retry and failover behavior must match config:

- No retry when `enabled = false`.
- Idempotent methods retry by default if enabled.
- Non-idempotent methods retry only when `retry_non_idempotent = true`.
- Status-code retry and connection/timeout retry are honored.
- `max_retries` semantics are documented and tested.
- Main HTTP/TLS proxy paths use the same policy.

### Implementation Steps

1. Document retry semantics.
   - Near `RetryConfig`, state whether `max_retries = 3` means 1 initial attempt plus 3 retries or
     3 total attempts. Recommended: 1 initial attempt plus `max_retries` additional retries.

2. Add a retry decision helper.
   - Suggested function inputs:
     - method,
     - attempt index,
     - response status or error classification,
     - `RetryConfig`.
   - Output:
     - retry or not,
     - reason label for metrics/logging.

3. Respect `enabled`.
   - If config is absent or disabled, no retry/failover except possibly selecting a single healthy
     backend once.

4. Respect method safety.
   - Retry `GET`, `HEAD`, `OPTIONS`, `TRACE` as safe/idempotent if enabled.
   - Consider `PUT` and `DELETE` idempotent but operationally sensitive; document choice.
   - Never retry `POST`, `PATCH`, or unknown methods unless `retry_non_idempotent = true`.

5. Fix attempt counting if needed.
   - Add tests first to lock intended behavior.

6. Integrate with upstream pools.
   - Main HTTP path must use upstream pool/retry policy when `proxy.upstream.servers` or
     `backup_servers` are configured.
   - Mark backend success as well as failure. `Backend::record_success()` exists but current
     request path should be checked for calls.

7. Add tests.
   - Disabled retry performs one attempt.
   - Enabled retry on 502 retries safe method.
   - POST does not retry by default.
   - POST retries only with `retry_non_idempotent = true`.
   - Timeout retry honors `retry_on_timeout`.
   - Connection retry honors `retry_on_error`.
   - Backup server is used only when primaries unavailable or according to documented policy.
   - Backend health recovers after successes.

### Done Criteria

- Retry config fields are all honored.
- Attempt count is documented and tested.
- Main HTTP/TLS paths use the same retry/failover policy as direct proxy execution.

## Priority 6: Fix Proxy Cache Key, Purge, and Revalidation Semantics

**Status**: COMPLETED (wave16-continued-2026-05-01)

### Problem

**Completed fixes:**

1. **PURGE fail-closed by default**: When no `cache_purge_token` is configured AND `cache_purge_allowed_ips` is empty, PURGE requests now return 403 "purge not configured". Previously, PURGE was allowed without any authentication.

2. **Targeted purge pattern-based approach**: Instead of reconstructing a fake cache key via `CacheKey::from_cache_string("GET:{}:{}")`, targeted purge now uses `cache.invalidate_by_pattern(&format!("GET:{}:{}:*", host, path))` which matches all scheme variants and vary combinations for that path.

### What remains OPEN:
- Cache lookup/storage still lives in `ProxyServer` - main HTTP path may bypass it
- Stale-while-revalidate rebuilds URL as `scheme://host/path` instead of using configured upstream
- Request-header policy for revalidation may not match normal proxying
- `build_cached_response()` overwrites `Cache-Control` with `public...`

### Problem

Cache behavior has multiple correctness risks:

- Targeted PURGE builds `GET:{host}:{path}` and parses it as a cache key, but real cache keys are
  hashed and include scheme, method, host, URI, vary, and site ID.
- If no purge token is configured and the purge IP allowlist is empty, PURGE is allowed.
- Stale-while-revalidate rebuilds the URL as `scheme://host/path`, which targets the public host,
  not necessarily the configured upstream.
- Request-header policy for revalidation does not match normal proxying.
- Cache lookup/storage lives in `ProxyServer`, but the main HTTP path may bypass it.

Key files:

- `src/proxy/mod.rs`
- `src/proxy/cache.rs`
- `src/proxy_cache/key.rs`
- `src/proxy_cache/store.rs`
- `src/proxy_cache/config.rs`
- `src/http/server.rs`
- `src/tls/server.rs`

### Required Outcome

Proxy cache behavior must be reachable from the main proxy path and must use a consistent key model.
Purge must be safe by default. Revalidation must target the configured upstream through the same
proxy execution policy as a normal miss.

### Implementation Steps

1. Decide cache integration point.
   - Preferred: cache lookup/store wraps the shared proxy executor from Priority 1.
   - Avoid keeping cache behavior only in `ProxyServer` if `ProxyServer` is not the main path.

2. Make purge authentication fail closed.
   - Require a configured token, a non-empty allowed-IP list, or both.
   - If neither is configured, return 403 or disable PURGE with a clear log.
   - Use constant-time token comparison per repository security policy.

3. Fix targeted purge.
   - Do not reconstruct a fake serialized key.
   - Options:
     - build the real key using `CacheKeyBuilder` with scheme/method/host/URI/site/vary context,
     - maintain an index from host/path/site to concrete cache keys,
     - or make targeted purge explicitly pattern-based and document that it purges all variants.
   - Handle vary keys: either purge all variants or require exact vary context.

4. Fix stale revalidation.
   - Store enough upstream target information with the cache entry or revalidation task.
   - Revalidate through the same upstream executor, not `scheme://host`.
   - Include conditional headers (`If-None-Match`, `If-Modified-Since`) if ETag/Last-Modified are
     available, or document that full refetch is used initially.

5. Preserve response cache-control correctly.
   - `build_cached_response()` currently overwrites `Cache-Control` with `public...`.
   - Decide whether that is intended. If not, preserve origin directives and add `Age`/`X-Cache`
     without changing privacy semantics.

6. Add tests.
   - PURGE without token/allowlist is denied.
   - PURGE with correct token succeeds.
   - PURGE with wrong token fails.
   - Targeted purge removes the actual cached entry.
   - Targeted purge removes all variants if that is the chosen behavior.
   - Stale revalidation calls configured upstream, not public host.
   - Cache miss and hit work through the main HTTP path.
   - Private/no-store responses are not cached.

### Done Criteria

- Cache is available through the main proxy path.
- PURGE is fail-closed by default.
- Targeted purge matches real cache keys.
- Revalidation uses the configured upstream executor.
- Cache behavior has server-boundary tests.

## Priority 7: Normalize URL Construction and Path/Query Handling

**Status**: OPEN

### Problem

Several paths build URLs with `format!("{}{}", upstream, path)`. This is fragile when the upstream
has a trailing slash, the request target is absolute-form, the path includes query, or the path
needs percent-encoding preservation. `ProxyServer::forward_with_pool()` trims trailing slashes, but
the main HTTP path does not. `ProxyServer::handle_request()` passes `query_string = None` to WAF,
suggesting path/query splitting is inconsistent.

Key files:

- `src/http/server.rs`
- `src/tls/server.rs`
- `src/proxy/mod.rs`
- `src/http_client/mod.rs`
- `src/router.rs`
- `src/proxy/headers.rs`

### Required Outcome

URL construction should use a single helper that combines configured upstream origin and incoming
path/query safely and predictably. WAF, router, cache, and upstream request execution should agree
on what is path versus query.

### Implementation Steps

1. Inventory URL construction.
   - Search for `format!("{}{}", target.upstream, path)`, `format!("{}{}", upstream_url, path)`,
     and equivalent patterns.

2. Add a URL join helper.
   - It should preserve incoming `path_and_query`.
   - It should avoid double slashes between origin and path.
   - It should not decode or normalize percent-encoding unless explicitly intended.
   - It should reject invalid upstream origins early at config validation time.

3. Use typed URI pieces where possible.
   - Prefer `http::Uri` or a URL parser over string concatenation.
   - If full URL parser dependency is already present, use it.

4. Split path/query consistently for WAF and cache.
   - The router should route on path only unless location matching intentionally includes query.
   - WAF should receive query separately.
   - Cache key should include path and query exactly as intended.

5. Add tests.
   - Upstream with and without trailing slash.
   - Request path with and without leading slash.
   - Query string preserved exactly.
   - Percent-encoded slash behavior is preserved according to documented policy.
   - Absolute-form request targets are rejected or normalized safely.

### Done Criteria

- Ad hoc upstream URL concatenation is removed from traffic hot paths.
- Path/query handling is documented and tested.
- WAF, router, cache, and upstream execution agree on path/query semantics.

## Priority 8: Enforce Response Size and Streaming Policy Consistently

**Status**: OPEN

### Problem

`ProxyServer::send_single_request()` uses `send_request_with_body_and_timeout_with_limit()` for
buffered HTTP responses and checks QUIC tunnel response body length. The main HTTP streaming path
streams large responses without obvious enforcement of per-site `max_response_size`; the buffered
path collects smaller responses after using `send_request_streaming()`.

Key files:

- `src/proxy/mod.rs`
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/http_client/mod.rs`
- `src/config/site/proxy.rs`

### Required Outcome

`max_response_size` must have documented behavior:

- enforced for buffered responses,
- enforced for streamed responses if configured as a hard limit,
- or explicitly documented as applying only to buffered/non-streamed responses.

Recommended: enforce as a hard limit using a limited body wrapper where possible.

### Implementation Steps

1. Define response-size contract.
   - Is the limit per site, global, or both?
   - Does it apply before or after response transforms/compression?
   - What status is returned on limit exceed?

2. Apply to streaming path.
   - Use `http_body_util::Limited` or equivalent around upstream body.
   - Convert limit errors to a clear 502/502-like response if headers have not been sent.
   - For already-streaming responses, decide whether connection close is acceptable and document it.

3. Apply to buffered path.
   - Ensure collected bodies use the same limit and error handling.

4. Apply to QUIC tunnel and mesh responses.
   - At least document if mesh streaming cannot enforce the same limit initially.

5. Add tests.
   - Buffered response over limit fails.
   - Chunked response over limit fails or closes according to contract.
   - Response under limit succeeds.
   - Limit applies through main HTTP path, not only `ProxyServer`.

### Done Criteria

- Response-size behavior is documented.
- Main traffic paths enforce or explicitly defer the limit.
- Tests prove behavior at server boundary.

## Priority 9: Align Mesh Backend Routing with Direct Proxy Policy

**Status**: OPEN

### Problem

Mesh backend routing goes through `mesh_backend_pool` and `MeshProxy::route_request()`. It selects
providers and proxies to peers, then transforms responses. Direct upstream routing has separate
header filtering, metrics, cache, retry, and response-size behavior. This creates policy drift
between mesh-backed and direct upstream sites.

Key files:

- `src/http/server.rs`
- `src/mesh/backend.rs`
- `src/mesh/proxy.rs`
- `src/mesh/transport.rs`
- `src/proxy/headers.rs`
- `src/proxy/mod.rs`

### Required Outcome

Mesh-backed upstreams should clearly document and, where feasible, share:

- request-header forwarding policy,
- response-header filtering policy,
- WAF invocation point,
- response-size limit behavior,
- metrics behavior,
- retry/fallback behavior across providers,
- cache eligibility or explicit non-cacheability.

### Implementation Steps

1. Add mesh row to the traffic matrix from Priority 1.
   - Mark each policy as shared, intentionally different, or not yet supported.

2. Normalize request/response headers.
   - Use the same request-header builder before creating the mesh proxy request.
   - Use the same response-header filter before returning mesh responses.

3. Check provider fallback behavior.
   - `MeshProxy` has provider fallback. Confirm it records failed providers and does not repeatedly
     select unhealthy peers.
   - Add tests for fallback when first provider fails.

4. Decide cache policy.
   - Either allow mesh responses into proxy cache using the same key model, or mark mesh backend
     responses non-cacheable with a documented reason.

5. Add tests.
   - Mesh response strips hop-by-hop and hidden headers.
   - Mesh request preserves application headers according to shared policy.
   - Mesh fallback tries a second provider.
   - Mesh backend records upstream success/failure metrics.

### Done Criteria

- Mesh backend policy is documented in the traffic matrix.
- Shared header policy applies to mesh where possible.
- Intentional mesh differences are visible and tested.

## Priority 10: Add Traffic-Layer Regression Harness

**Status**: OPEN

### Problem

Many traffic-layer risks require server-boundary tests. Helper unit tests alone will not catch
behavior drift between HTTP, TLS, direct proxy, cache, and mesh paths.

### Required Outcome

Create or extend a traffic regression harness that can run representative proxy/routing scenarios
against an in-process upstream test server.

### Implementation Steps

1. Locate existing test harnesses.
   - Search under `tests/` and module tests for HTTP server, upstream, proxy, cache, and router
     harnesses.
   - Reuse existing harnesses where possible.

2. Add an upstream echo test server utility.
   - It should capture method, path, query, headers, and body.
   - It should be able to return selected status codes, headers, bodies, chunked responses, and
     delayed/time-out behavior.

3. Add route/proxy fixtures.
   - Basic upstream route.
   - Upstream with trailing slash.
   - Multiple upstream servers with backup.
   - Site with cache enabled.
   - Site with custom headers.
   - Site with upstream TLS config if local TLS harness exists.

4. Seed regression tests from this plan.
   - Host validation.
   - Header preservation/stripping.
   - Retry disabled/enabled.
   - POST retry behavior.
   - Cache hit/miss/purge/revalidate.
   - URL join and query preservation.
   - Response-size limit.
   - Mesh policy tests where feasible.

5. Keep tests maintainable.
   - Prefer small focused tests over one giant scenario.
   - Use deterministic ports or OS-assigned local ports.
   - Avoid sleeps except where testing timeout/backoff; use short configured durations.

### Done Criteria

- Traffic-layer tests exercise the server boundary with a real upstream handler.
- The reviewed risks have regression coverage.
- Test commands are documented in this plan or adjacent test docs.

## Suggested Traffic Execution Order

1. Priority 2: fix host validation and optimize location matching. It is focused and low-risk.
2. Priority 3: correct request-header forwarding. This is high impact and likely user-visible.
3. Priority 7: normalize URL construction and path/query handling.
4. Priority 4: move upstream TLS client construction out of the request path.
5. Priority 1: define and begin applying the shared proxy execution contract.
6. Priority 5: make retry/failover policy honest and wire it into the main path.
7. Priority 6: fix cache purge/revalidation and integrate cache with the main path.
8. Priority 8: enforce response-size policy consistently.
9. Priority 9: align mesh backend policy.
10. Priority 10: build out the regression harness continuously as the above work lands.

## Handoff Notes for Traffic Agent

- Do not attempt the entire traffic plan in one patch. Start with Priority 2 or Priority 3 and add
  tests first.
- Before editing, inspect `git status --short` and preserve existing user changes.
- If a task reveals a broader reload or architecture issue, reference the preserved architecture
  plan below rather than expanding the patch indefinitely.
- When an item is complete, remove it from this traffic section or mark it complete with the commit
  or PR reference. Leave deferred items visible with a reason.
- If a behavior is intentionally different between direct upstream, mesh, QUIC tunnel, or HTTP/3,
  document it in the traffic matrix and add a regression test for the difference.

---

# Previously Open WAF and Security Improvement Plan

The WAF/security plan below was already present in this file and remains open. It is preserved
because the traffic-layer plan above does not complete or supersede it.

# MaluWAF WAF and Security Protection Improvement Plan

**Status**: OPEN
**Last Updated**: 2026-05-01
**Primary Scope**: WAF request inspection, trusted proxy handling, request-smuggling defenses,
body normalization, serverless/proxy enforcement, attack action semantics, anomaly scoring,
token comparison, and regression coverage.

This plan is written for a follow-on agent that may not have the original adversarial review
context. It is intentionally explicit about files, likely failure modes, and expected tests.

Completed items from the prior plan were checked before this update. No completed items were found:
the previous architecture, systems-layer, and distributed-layer sections are still open or deferred
and are preserved later in this file. Do not delete those sections unless the work is completed,
intentionally superseded, or moved to another tracked plan with a clear reference.

## WAF/Security Diagnosis

The WAF has broad coverage on paper:

- normalized SQLi/XSS/path traversal/RFI/SSRF/SSTI/XXE/JWT/open redirect detectors,
- libinjection-backed SQLi/XSS checks,
- request-smuggling and header-validation checks,
- streaming body scanning,
- threat scoring, bot protection, honeypots, rate limits, block stores, and threat intel,
- forwarded header sanitization and trusted proxy support.

The challenge is that several protection layers do not line up cleanly with the actual request
pipeline. Some controls are implemented but not wired into decisions. Some checks run after the
HTTP parser has already discarded raw ambiguity. Some runtime policy fields are accepted by config
but ignored. Some request classes bypass the full WAF.

The goal of this work is not to make signature matching perfect. The goal is to make the protection
contract honest and enforceable:

1. Every external request path that should be protected actually invokes the same relevant layers.
2. Operator config maps to runtime behavior.
3. Trust boundaries, especially client IP attribution, are unambiguous and tested.
4. Body inspection has clear coverage for UTF-8, non-UTF8, multipart, large bodies, and chunked
   uploads.
5. Request-smuggling defenses are proven against raw parser behavior, not only synthetic
   `HeaderMap` tests.
6. Security-token comparisons follow repository policy.
7. Deferred or intentionally unsupported protections are documented as such.

## WAF/Security Ground Rules

- Read `src/waf/AGENTS.override.md`, `src/http/AGENTS.override.md`,
  `src/proxy/AGENTS.override.md`, `src/auth/AGENTS.override.md`, and
  `src/config/AGENTS.override.md` before editing those areas.
- Avoid broad rewrites. Each priority below should be a focused patch with tests.
- Do not weaken security defaults for compatibility unless the plan explicitly says to add a
  compatibility mode.
- The hot path matters. Avoid adding per-request allocation, regex compilation, or O(n) scans in
  common request paths unless the current path already does it and the change is risk-contained.
- Where raw HTTP behavior matters, add integration or parser-level tests. Unit tests that construct
  `http::HeaderMap` are not enough for request-smuggling claims.
- Prefer fail-closed for enabled security features. If a feature cannot inspect safely, block or
  return a clear error unless a documented explicit bypass config exists.
- Preserve existing user/worktree changes. This file is a handoff plan, not an implementation patch.

Recommended baseline checks:

```bash
cargo test --lib --no-run
cargo test --lib waf
cargo test --lib http
cargo test --lib proxy
cargo fmt --check
cargo clippy --lib -- -D warnings
```

When touching HTTP/3, serverless, or feature-gated paths, also run the relevant feature checks used
by the repository. If a command cannot run locally, record the failure and reason in the final
handoff notes for that task.

## Priority 1: Fix Trusted Proxy and Client IP Attribution

**Status**: COMPLETED (wave17-2026-05-02)

### Problem

`src/waf/request_sanitization.rs` has contradictory `X-Forwarded-For` handling. The comments in
`validate_forwarded_chain()` say all IPs except the last should be trusted proxies and the last IP
is the original client, but `get_real_ip()` returns `ips[0]`.

Standard `X-Forwarded-For` order is normally:

```text
client, proxy1, proxy2
```

The current validation likely rejects normal chains or attributes traffic to the wrong hop. That
undermines rate limits, IP blocklists, threat intel, honeypot bans, violation tracking, bandwidth
attribution, and logs.

Key files:

- `src/waf/request_sanitization.rs`
- `src/http/server.rs`
- `src/http3/server.rs`
- `src/proxy/headers.rs`
- any tests around `RequestSanitizer`

### Required Outcome

Define and enforce one documented trusted-proxy model:

- For direct untrusted clients, remove spoofable forwarded headers.
- For requests from trusted proxy IPs, parse forwarded headers according to a documented chain
  order.
- Return the actual client IP consistently.
- Reject or ignore malformed, private, spoofed, or untrusted chains predictably.
- Keep the original socket peer available for auditing if possible.

### Implementation Steps

1. Decide the chain model and document it near `RequestSanitizer`.
   - Recommended model: use standard XFF order, `client, proxy1, proxy2`.
   - The rightmost trusted suffix represents proxies nearest the WAF.
   - The client is the first untrusted public IP immediately before the trusted suffix, or the
     leftmost public IP if the entire trusted-proxy deployment guarantees sanitized input.
   - Do not accept private/reserved client IPs unless config explicitly permits private clients.

2. Fix `validate_forwarded_chain()`.
   - Validate right-to-left proxy hops, not left-to-right unless documentation explicitly chooses
     a nonstandard model.
   - Reject invalid IPs.
   - Reject chains where the socket peer is not trusted but forwarded headers are present.
   - Treat ambiguous all-trusted chains as suspicious unless explicitly allowed.

3. Fix `get_real_ip()`.
   - Return the selected client IP from the validated chain.
   - Do not return a proxy IP as the client.
   - Ensure `Forwarded: for=` handling follows equivalent rules or is removed/ignored if too hard
     to validate safely.

4. Check call sites.
   - `src/http/server.rs` sanitizes headers early and replaces `client_ip`; confirm this still
     works after fixing the algorithm.
   - Ensure HTTP/3 uses equivalent sanitization if forwarded headers are accepted there.
   - Ensure proxy forwarding adds/truncates XFF consistently in `src/proxy/headers.rs`.

5. Add tests.
   - Direct untrusted client with XFF: forwarded headers removed, real IP is socket IP.
   - Trusted proxy with `1.2.3.4, 10.0.0.10`: real IP is `1.2.3.4` when `10.0.0.10` is trusted.
   - Multiple trusted proxies: `1.2.3.4, 10.0.0.10, 10.0.0.11` returns `1.2.3.4`.
   - Spoofed middle public IP in trusted chain is rejected or ignored according to documented rule.
   - Private client IP in XFF is rejected unless explicitly configured.
   - Malformed XFF falls back to socket IP and logs/debugs.
   - `Forwarded: for=` tests mirror the accepted behavior.

### Done Criteria

- Client IP attribution is documented and tested.
- Rate limiting and block decisions see the expected real client IP in trusted-proxy deployments.
- Spoofed forwarded headers from untrusted peers cannot influence the client IP.

## Priority 2: Remove or Constrain WAF Bypass for Serverless-Only Routes

**Status**: COMPLETED (wave17-2026-05-02)

### Problem

`src/http/server.rs` skips `waf.check_request_full()` when the target backend is Serverless and
`target.site_config.serverless_only` is true. This makes `serverless_only` act like a WAF bypass.
That is risky because serverless handlers can still receive hostile paths, query strings, headers,
and bodies.

Key file:

- `src/http/server.rs`

### Required Outcome

Serverless-only routes should receive the same WAF/security decision path as other external routes
unless there is an explicit, narrowly named, validated opt-out.

### Implementation Steps

1. Inspect serverless request flow.
   - Find where `serverless_only` is defined in config and how Serverless handlers receive
     requests.
   - Confirm whether any serverless-specific sanitizer exists. Do not assume it does.

2. Remove the unconditional skip.
   - Preferred: always call `waf.check_request_full()` before invoking Serverless.
   - Preserve any necessary static/challenge/honeypot special cases that already happen before
     routing.

3. If an opt-out is needed for compatibility, add explicit config.
   - Suggested name: `serverless.bypass_waf` or `site.serverless_waf_mode = "enforce|log|off"`.
   - Default must be enforce.
   - Validation should warn or reject unsafe combinations in production mode if such a mode exists.
   - The old `serverless_only` flag must not imply bypass.

4. Add tests.
   - Serverless-only route with obvious SQLi query is stalled/blocked according to WAF policy.
   - Serverless-only route with XSS body is inspected.
   - Explicit bypass, if added, is the only way to skip WAF.
   - Normal non-serverless route behavior is unchanged.

### Done Criteria

- `serverless_only` no longer bypasses WAF by itself.
- Any bypass is explicit, documented, and tested.

## Priority 3: Make Attack Detection Action Semantics Real

**Status**: COMPLETED (wave17-2026-05-02)

### Problem

`AttackDetectionConfig.action` defaults to `stall`, and site config validates `stall`, `block`, and
`log`. The live path in `src/waf/mod.rs` currently logs detection and returns `WafDecision::Stall`
for attack detections regardless of configured action, except when threat level escalation blocks.

Key files:

- `src/waf/mod.rs`
- `src/waf/attack_detection/config.rs`
- `src/config/site/attack_detection.rs`
- config merge/reload code for site attack detection

### Required Outcome

The configured action must map to runtime behavior:

- `stall`: current tarpit/stall behavior.
- `block`: return a finite 403-style block response.
- `log`: record metrics/logs/threat-level event but allow the request to continue.

If per-site action exists, it must override global action as documented.

### Implementation Steps

1. Trace config construction.
   - Find where global and site attack detection configs merge.
   - Confirm whether `action` is global-only or site-overridable today.

2. Implement a single action decision helper.
   - Suggested helper near `check_attack_patterns()`:
     - input: `AttackDetectionResult`, client IP, threat level, applicable config action.
     - output: `Option<WafDecision>`.
   - Keep metrics and `threat_level.record_attack()` behavior consistent for all actions.

3. Handle `log` carefully.
   - `log` should not call `maybe_escalate_and_block()` unless explicitly intended.
   - Decide whether `log` contributes to threat level. Recommended: yes, record attack metrics, but
     do not block from this single request unless a separate global threat policy says so.
   - Document the behavior.

4. Handle `block`.
   - Use configured or standard status code. If no config exists, use 403.
   - Return an error page response path consistent with existing WAF block handling.

5. Add tests.
   - `action = "stall"` returns `WafDecision::Stall`.
   - `action = "block"` returns `WafDecision::Block(403, ...)`.
   - `action = "log"` returns `None` or `Pass` from the attack layer and request proceeds.
   - Per-site action overrides global action if supported.
   - Invalid action remains rejected by config validation.

### Done Criteria

- Config action is no longer ignored.
- Tests prove all accepted actions.
- Documentation/config comments describe the exact behavior.

## Priority 4: Wire or Remove Anomaly Scoring

**Status**: COMPLETED (wave16-continued-2026-05-01)

### Problem

**Completed fix:**

`check_attack_patterns()` in `src/waf/mod.rs` now calls `check_request_anomaly_scoring()` when `anomaly_scoring.enabled = true`. If the accumulated score exceeds `threshold`, the configured action (stall/block/log) is applied.

### What remains:
- Duplicated detector runs - scoring re-runs many detectors already run by direct detection. This may be acceptable for off-by-default scoring, but if enabled by default, refactoring to collect results once would avoid double work.

### Problem

`AttackDetector::check_request_anomaly_scoring()` computes a cumulative score, and config exposes
`anomaly_scoring.enabled` and `threshold`, but the live WAF decision path does not appear to call
it. This creates a misleading defense: weak signals are not actually combined.

Key files:

- `src/waf/attack_detection/mod.rs`
- `src/waf/attack_detection/config.rs`
- `src/waf/mod.rs`

### Required Outcome

Choose one:

- Wire anomaly scoring into the live WAF path; or
- Remove/disable the config surface and document that anomaly scoring is not currently supported.

Recommended: wire it, because it is useful for combining weak detections.

### Implementation Steps

1. Review score semantics.
   - Determine whether direct detections should still short-circuit before scoring.
   - Decide how score maps to `WafDecision` and configured action.
   - Ensure repeated detector runs do not double-count expensive work if direct detection already
     ran.

2. Integrate scoring.
   - If `anomaly_scoring.enabled`, compute score in `check_attack_patterns()`.
   - If score >= threshold, produce a decision according to attack action.
   - Preserve existing direct detection behavior.

3. Optimize duplicated work.
   - Current scoring re-runs many detectors. That may be acceptable initially for
     non-default/off-by-default scoring.
   - If enabled by default later, refactor to collect detector results once.

4. Add tests.
   - Scoring disabled preserves current behavior.
   - Multiple weak signals below single-rule block threshold exceed anomaly threshold.
   - Below-threshold requests pass.
   - Action handling applies to anomaly-triggered detections.

### Done Criteria

- Enabled anomaly scoring affects decisions.
- Disabled anomaly scoring has no behavior change.
- The config surface is honest.

## Priority 5: Harden Body Inspection for Non-UTF8, Multipart, and Large Bodies

**Status**: COMPLETED (wave17-2026-05-02)

### Problem

**Completed fixes:**

1. **SQLi/XSS detectors**: Use `String::from_utf8_lossy()` instead of `from_utf8().ok()`, preventing non-UTF8 bypass
2. **Normalizer body**: Uses `from_utf8_lossy()` for body normalization
3. **All secondary detectors**: JWT, SSTI, cmd_injection, path_traversal, RFI, SSRF, XXE, LDAP, XPath, open_redirect body checks now use `from_utf8_lossy()`
4. **Streaming WAF**: Falls back to `from_utf8_lossy` when `from_utf8` fails
5. **Generic detector body**: Uses `from_utf8_lossy()` in detector_common

### Remaining (deferred):
- Multipart boundary parsing for targeted field inspection
- Payload-split-across-chunks edge cases in streaming WAF

### Problem (original)

The normal request path only creates a normalized body if `std::str::from_utf8(body)` succeeds.
SQLi/XSS detector entry points convert invalid UTF-8 to an empty string. This allows payloads
embedded in non-UTF8 bodies, multipart bodies, mixed encodings, or binary wrappers to evade
inspection even if the upstream application later extracts dangerous text.

Large-body handling also has a decision mismatch: a secondary chunk scan checks only
`Drop | Block`, while `check_request_body()` generally returns `Stall` on attack detection.

Key files:

- `src/waf/attack_detection/normalizer.rs`
- `src/waf/attack_detection/sqli.rs`
- `src/waf/attack_detection/xss.rs`
- `src/waf/attack_detection/streaming.rs`
- `src/waf/mod.rs`
- `src/http/shared_handler.rs`
- `src/http/server.rs`
- `src/http3/server.rs`

### Required Outcome

Body inspection must have clear behavior for:

- valid UTF-8 text bodies,
- invalid UTF-8 bodies with embedded text-like payloads,
- form URL encoded bodies,
- multipart form data,
- large streamed/chunked bodies,
- payloads split across chunk boundaries.

The expected behavior does not need to be perfect semantic parsing in the first patch, but it must
not silently treat invalid UTF-8 as empty input.

### Implementation Steps

1. Define body inspection policy.
   - Add comments/docs near `NormalizedInputs::normalize_all()` and streaming WAF.
   - Decide whether invalid UTF-8 should be:
     - lossy decoded for signature scanning,
     - scanned as bytes by byte-capable detectors,
     - blocked for content types expected to be text,
     - skipped only for allowed binary content types.

2. Stop converting invalid UTF-8 to empty input.
   - Replace `unwrap_or("")` patterns in SQLi/XSS paths with lossy decode or byte-aware scanning.
   - Avoid excessive allocation in hot paths. Lossy decode only allocates when invalid bytes exist.

3. Update `NormalizedInputs`.
   - For body, consider `String::from_utf8_lossy(body)` instead of `from_utf8().ok()`.
   - If content-type-aware behavior is needed, pass relevant headers into normalization policy.

4. Multipart/form handling.
   - At minimum, scan lossy-decoded multipart bodies for known patterns.
   - Better: parse boundaries cheaply enough to inspect field names and text fields.
   - Do not fully buffer unbounded bodies beyond existing limits.

5. Large-body decision mismatch.
   - In `src/http/server.rs`, treat `WafDecision::Stall` from `check_request_body()` as a blocking
     outcome in the large-body scan loop, consistent with normal WAF behavior.
   - Ensure responses are consistent with existing stall/drop policy.

6. Streaming state isolation.
   - Confirm `waf.streaming()` returns a fresh `StreamingWafCore` per request. It currently appears
     to clone a new streaming scanner. Keep it that way.
   - Add a test to ensure two concurrent streaming scanners do not share `current_input`.

7. Add tests.
   - Invalid UTF-8 prefix/suffix around SQLi still detected.
   - Invalid UTF-8 prefix/suffix around XSS still detected.
   - Multipart text field containing SQLi/XSS is detected.
   - URL-encoded form body with encoded payload is detected.
   - Payload split across chunks is detected by streaming WAF.
   - Large body secondary scan handles `Stall`.
   - Legitimate binary upload without suspicious text does not trigger obvious false positive.

### Done Criteria

- Invalid UTF-8 no longer makes body inspection empty.
- Multipart/form and chunk-boundary coverage has regression tests.
- Large-body scan handles all attack decisions consistently.

## Priority 6: Prove Request-Smuggling Defenses at the Raw Parser Boundary

**Status**: OPEN

### Problem

Request-smuggling checks run mostly on parsed `http::HeaderMap`. Once Hyper or another parser has
accepted/rejected/normalized raw bytes, some dangerous ambiguity may be lost. Unit tests that insert
headers into `HeaderMap` do not prove defense against raw wire forms.

Key files:

- `src/waf/attack_detection/request_smuggling.rs`
- `src/waf/attack_detection/header_validation.rs`
- `src/http/early_parse.rs`
- `src/http/server.rs`
- HTTP/1 server setup and Hyper configuration

### Required Outcome

Document what the HTTP parser rejects before WAF and add tests for raw smuggling cases. The WAF
should not claim to detect cases that the parser rejects earlier, and it should explicitly handle
cases the parser accepts.

### Implementation Steps

1. Inventory parser behavior.
   - Identify Hyper/HTTP configuration for HTTP/1 and HTTP/2.
   - Determine behavior for duplicate `Content-Length`, mixed `Content-Length` and
     `Transfer-Encoding`, invalid whitespace, obs-fold, header name casing, and invalid values.

2. Add raw parser tests.
   - Use existing server harness if available.
   - If not, add low-level tests around the parser/connection handling.
   - Avoid relying only on `HeaderMap` construction.

3. Decide responsibility split.
   - Parser-level reject: malformed raw requests never reach WAF.
   - WAF-level detect: accepted-but-suspicious parsed requests result in WAF decisions.
   - Proxy-level sanitize: never forward hop-by-hop ambiguity upstream.

4. Update detectors.
   - Remove dead duplicate-header checks if `HeaderMap` cannot represent the condition and raw
     parser rejects it.
   - Or move raw duplicate detection earlier if the parser allows it.

5. Add/expand tests for:
   - duplicate matching `Content-Length`,
   - duplicate conflicting `Content-Length`,
   - `Transfer-Encoding: chunked` plus `Content-Length`,
   - obfuscated TE values,
   - obs-fold and line folding,
   - body containing smuggled request split after declared length,
   - HTTP/2 downgrade/h2c headers.

### Done Criteria

- Raw request-smuggling behavior is tested.
- Comments/docs describe parser-rejected versus WAF-detected cases.
- Hop-by-hop headers are stripped before upstream forwarding.

## Priority 7: Make Cache Purge and Other Secret Comparisons Constant-Time

**Status**: COMPLETED (wave17-2026-05-02)

### Problem

**Completed fixes:**

1. **Cache purge token**: Uses `subtle::ConstantTimeEq` in `src/proxy/mod.rs`
2. **CSRF token**: Uses `ct_eq` in `src/auth/mod.rs` and `src/admin/state.rs`
3. **Admin token**: Uses bcrypt (inherently constant-time)
4. **DNS TSIG/cookie**: Uses `ConstantTimeEq`
5. **IPC signatures**: Uses `ConstantTimeEq`
6. **Mesh certs**: Uses `ConstantTimeEq`
7. **Mesh auth tokens**: Fixed `transport_rate_limit.rs` and `config_mesh.rs` to use `ct_eq`
8. **QUIC tunnel tokens**: Uses `ConstantTimeEq`
9. **PoW hash verification**: Uses `subtle::Choice`

### Problem (original)

The repository security guidance requires `subtle::ConstantTimeEq` for secrets, tokens, keys, and
MACs. Cache purge token comparison in `src/proxy/mod.rs` uses normal string equality.

Key files:

- `src/proxy/mod.rs`
- `src/auth/basic.rs`
- `src/admin/*`
- `src/tunnel/*`
- `src/process/ipc_signed.rs`

### Required Outcome

All token/secret comparisons in protection layers use constant-time comparison or a stronger
credential verifier such as bcrypt.

### Implementation Steps

1. Replace cache purge token comparison.
   - Use `subtle::ConstantTimeEq`.
   - Keep length handling safe. Common pattern:
     - compare bytes with `ct_eq`,
     - convert result with `bool::from`.

2. Audit nearby comparisons.
   - Search for `==` involving `token`, `secret`, `key`, `signature`, `csrf`, `session`, and
     `auth`.
   - Do not replace bcrypt password verification in basic auth; bcrypt verification is appropriate.
   - Do replace direct bearer/session/token equality where found.

3. Add tests.
   - Authorized cache purge still works.
   - Wrong token is rejected.
   - Missing token is rejected.
   - IP allowlist behavior remains unchanged.

### Done Criteria

- Cache purge token comparison follows repository policy.
- Any other direct token comparisons in touched protection code are addressed or documented.

## Priority 8: Normalize Policy Across HTTP/1, HTTP/2, HTTP/3, Proxy, and Serverless

**Status**: OPEN

### Problem

Different entry points call WAF layers slightly differently:

- HTTP/1 full request path uses early checks, body collection, streaming checks, routing, then full
  WAF.
- HTTP/3 has its own body read and streaming path.
- `ProxyServer::handle_request()` passes `query_string = None`.
- Serverless-only currently skips WAF.

Inconsistent call paths create bypass risk and make tests incomplete.

Key files:

- `src/http/server.rs`
- `src/http3/server.rs`
- `src/proxy/mod.rs`
- `src/waf/mod.rs`
- serverless handler path around `src/spin/handler.rs` and related modules

### Required Outcome

Create one documented WAF enforcement contract for all external request entry points. Each entry
point should either use that contract or be explicitly documented as internal/trusted.

### Implementation Steps

1. Create a request inspection matrix.
   - Suggested file: `plans/waf_entrypoint_matrix.md`.
   - Rows: HTTP/1, HTTP/2, HTTP/3, proxy direct, serverless, static files, health/ready, admin,
     internal drain, challenge assets.
   - Columns: early IP checks, forwarded sanitization, rate limit, body size, streaming WAF,
     full attack detection, bot/challenge, endpoint block, threat intel, response security headers.

2. Fix `ProxyServer::handle_request()` query handling.
   - It currently passes `query_string = None`.
   - Determine whether its `path` includes query. If yes, split path and query before calling WAF.
   - Add tests for SQLi/XSS in proxy query string.

3. Align HTTP/3 with HTTP/1.
   - Ensure forwarded-header sanitization and real client IP handling are equivalent.
   - Ensure body size overflow returns a fail-closed response instead of merely breaking the read
     loop and continuing with partial body, if that is current behavior.
   - Ensure WAF decisions map consistently.

4. Explicitly classify internal endpoints.
   - Health/ready/drain may bypass WAF only if local/trusted as intended.
   - Public health endpoints should still avoid leaking sensitive state.

5. Add cross-entrypoint tests.
   - Same attack in query string detected on HTTP/1 and HTTP/3.
   - Same attack in body detected on HTTP/1 and HTTP/3.
   - Proxy direct path passes query string to WAF.
   - Serverless route receives WAF.
   - Internal drain remains localhost-only.

### Done Criteria

- Entrypoint matrix exists.
- External entry points have consistent WAF coverage or documented exceptions.
- Query-string and body attacks are tested across entry points.

## Priority 9: Strengthen SSRF and URL-Trust Semantics

**Status**: OPEN

### Problem

The SSRF detector has useful private-IP and localhost logic, but SSRF defense based only on pattern
inspection is inherently bypass-prone. Allowlist logic is string based and needs scrutiny. The real
security boundary for SSRF should be enforced when making outbound requests or when proxying to
configured backends, not only when scanning user-controlled text.

Key files:

- `src/waf/attack_detection/ssrf.rs`
- `src/http_client/*`
- `src/proxy/mod.rs`
- upstream/backend resolution code
- any serverless outbound HTTP helper, if present

### Required Outcome

SSRF detection remains useful, but outbound network policy enforces private/reserved address
blocking where user-controlled URLs can cause egress.

### Implementation Steps

1. Identify outbound request surfaces.
   - Reverse proxy upstreams from config.
   - Serverless/plugin HTTP clients, if exposed.
   - Rule/threat feed clients.
   - Tunnel/proxy helpers.

2. Classify each surface.
   - Config-trusted URL: validated at startup, allowed to target private infrastructure if intended.
   - User-controlled URL: must enforce SSRF network policy at request time.

3. Add or reuse an outbound address policy.
   - Resolve DNS and check final IPs before connect.
   - Block loopback, link-local, private, multicast, unspecified, documentation ranges, and IPv6
     local equivalents unless explicitly allowed.
   - Consider DNS rebinding: connect must use the checked resolved address or re-check after
     resolution.

4. Tighten detector allowlist semantics.
   - Ensure `allowed_domains` matches exact domains and subdomains safely.
   - Avoid suffix tricks such as `allowed.com.attacker.tld`.
   - Add tests for userinfo, ports, percent-encoding, mixed case, IDNA/punycode if supported.

5. Add tests.
   - `http://127.0.0.1`, decimal/octal/hex, IPv6 mapped loopback are blocked.
   - `http://allowed.com.attacker.tld` is not allowlisted.
   - `http://sub.allowed.com` is allowlisted only if intended.
   - DNS result to private IP is blocked for user-controlled outbound fetch.

### Done Criteria

- User-controlled outbound requests cannot reach private/reserved IPs by URL trick alone.
- Detector allowlist behavior is tested against common suffix/userinfo bypasses.

## Priority 10: Add WAF Security Regression Harness and Corpus

**Status**: OPEN

### Problem

Current tests cover many individual detector examples, but there is no obvious corpus-driven
regression suite that exercises the whole request path and known bypass classes.

### Required Outcome

Create a maintainable WAF security corpus with request-level fixtures and detector-level fixtures.

### Implementation Steps

1. Create fixture structure.
   - Suggested:
     - `tests/fixtures/waf/requests/`
     - `tests/fixtures/waf/bodies/`
     - `tests/fixtures/waf/headers/`
   - Include metadata for expected result, attack type, entry point, and notes.

2. Add a corpus runner.
   - It should build requests from fixtures and run WAF decisions.
   - Keep it deterministic and fast enough for CI.

3. Seed corpus with reviewed risks.
   - Trusted proxy XFF chains.
   - Serverless route attack.
   - Invalid UTF-8 SQLi/XSS.
   - Multipart field attack.
   - Chunk-boundary split.
   - Raw CL/TE smuggling.
   - Query-string attack through proxy path.
   - Cache purge auth cases.
   - SSRF encoded/private IP variants.

4. Add negative controls.
   - Normal binary upload.
   - Normal multipart upload.
   - Normal admin/basic auth failure.
   - Benign query strings and JSON bodies.

5. Document update workflow.
   - When fixing a bypass, add a fixture first or in the same patch.
   - Include source/description without pasting exploit database content unnecessarily.

### Done Criteria

- A corpus runner exists.
- The reviewed bypass classes have fixtures.
- CI or documented local commands run the corpus.

## Suggested WAF/Security Execution Order

1. Priority 1: trusted proxy/client IP attribution. This affects almost every other protection.
2. Priority 2: remove serverless WAF bypass.
3. Priority 3: implement attack action semantics.
4. Priority 5: harden body inspection and large-body decision handling.
5. Priority 6: raw request-smuggling regression tests and parser-boundary documentation.
6. Priority 8: entrypoint matrix and cross-entrypoint alignment.
7. Priority 4: anomaly scoring wiring.
8. Priority 7: constant-time token comparison audit.
9. Priority 9: SSRF outbound enforcement and allowlist hardening.
10. Priority 10: corpus harness, seeded throughout the earlier priorities.

## Handoff Notes for WAF/Security Agent

- Do not try to complete all priorities in one patch. Start with Priority 1 and add tests before
  behavior changes.
- When a task exposes a deeper architecture issue, record it under the existing architecture plan
  rather than expanding the current patch.
- If an item is completed, remove it from this top WAF/security section or mark it complete with
  the commit/PR reference. Keep deferred items visible.
- If an item is intentionally deferred, add a short reason and owner/date if known.

---

# Previously Open Architecture Improvement Plan

The architecture plan below was already present in this file and remains open. It is preserved
because the current WAF/security plan does not complete or supersede it.

# MaluWAF Architecture Improvement Plan

**Status**: OPEN
**Last Updated**: 2026-05-01
**Primary Scope**: repository architecture, runtime boundaries, reload semantics, feature
profiles, hot-path routing/request processing, and subsystem ownership.

This plan is written for a follow-on agent that may not have the original architectural review
context. It intentionally avoids prescribing one giant rewrite. The goal is to turn the current
architecture into a set of explicit, testable decisions with safe migration steps.

No architectural implementation work has been completed for this review yet. Items below are open
unless explicitly marked deferred. Existing open systems-layer and distributed-layer work is
preserved later in this file under "Previously Open Systems-Layer Work" and "Previously Open
Distributed-Layer Work". Do not remove those items until they are completed, intentionally
superseded, or moved to a separate tracked plan with clear references.

## Architectural Diagnosis

MaluWAF has several sound individual decisions:

- The Master process is kept out of the untrusted request path.
- Workers handle external traffic and can be restarted by the supervisor.
- The mesh trust-anchor model is explicit rather than elected.
- Request routing uses precomputed maps for exact host lookup.
- Some hot-path state uses `Arc`, caches, and `ArcSwapOption`.
- Some CPU-heavy cryptographic mesh operations are offloaded with `spawn_blocking`.

The main architectural problem is not one bad subsystem. It is that too many subsystems are
compiled, initialized, and reasoned about as one default runtime:

- WAF and reverse proxy
- HTTP/1, HTTP/2, HTTP/3
- DNS and DNSSEC
- Mesh, DHT, Raft, threat intel, YARA distribution
- QUIC/WireGuard tunnels and VPN pieces
- WASM plugins and serverless functions
- Upload scanning and sandboxing
- Honeypot ports
- Admin API and config mutation
- Process supervision and IPC

The result is a broad product surface with weak architectural seams. The codebase has security and
performance aspirations consistent with a focused edge WAF, but the default runtime resembles a
platform bundle.

## Architecture Goals

The follow-on work should drive toward these outcomes:

1. The default build and runtime should be a small, production-safe WAF/reverse proxy core.
2. Mesh, DNS, tunnels, serverless, plugins, and advanced scanning should be opt-in profiles with
   explicit lifecycle ownership.
3. Master/worker responsibilities should stay sharply separated.
4. Data-plane state should be reloadable atomically or explicitly restart-only. Ambiguous hot reload
   behavior should be removed.
5. Request hot paths should have predictable O(1) or near-O(1) behavior and avoid per-request
   allocations where practical.
6. Global singleton state should be reduced or wrapped behind lifecycle-owned handles.
7. Large request-pipeline modules should be split along stable responsibilities without changing
   behavior.
8. Architectural decisions should be captured in ADRs and enforced by tests, feature gates, and CI.

## Ground Rules

- Do not start with a broad rewrite. Each priority below should be done as a focused slice.
- Preserve existing behavior unless a task explicitly changes the contract.
- Avoid weakening security defaults for compatibility.
- Do not move code just for aesthetics. Split modules only when the split creates a clear ownership
  boundary, test boundary, or reload/runtime boundary.
- Read the closest `AGENTS.override.md` before editing subsystem code.
- For hot-path code, measure or reason about allocations, lock contention, and algorithmic
  complexity.
- Keep public config migrations backward compatible where possible. When not possible, add clear
  validation errors and documentation.
- Prefer typed handles and explicit lifecycle structs over process-wide singletons.
- Keep each priority in a separate commit or PR if possible.

Recommended baseline verification commands:

```bash
cargo test --lib --no-run
cargo test --lib router
cargo test --lib waf
cargo test --lib process
cargo test --lib mesh
cargo fmt --check
cargo clippy --lib -- -D warnings
```

For feature/profile work, also run representative combinations:

```bash
cargo check --no-default-features
cargo check --no-default-features --features socket-handoff
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --all-features
```

If a command cannot run locally due to missing platform/tooling support, document that in the task
notes and add a CI or follow-up item instead of claiming completion.

## Priority 1: Define Product Profiles and Reduce Default Runtime Surface

**Status**: OPEN

### Problem

`Cargo.toml` currently enables `socket-handoff`, `post-quantum`, `mesh`, and `dns` by default.
That means a default build pulls in advanced distributed and DNS behavior even for a simple WAF
deployment. This increases compile time, attack surface, runtime initialization complexity, and
reload restrictions.

The default product should be the smallest safe edge WAF/reverse proxy. Advanced capabilities
should be deliberate choices.

### Required Outcome

Create explicit product profiles and make the default profile focused:

- `core`: HTTP/HTTPS WAF reverse proxy, static files if already core, process supervision, admin API.
- `mesh-node`: mesh, DHT, Raft, distributed threat intel, mesh YARA/rule propagation.
- `dns-node`: DNS, DoH/DoT/DoQ, DNSSEC, anycast DNS integrations.
- `edge-full`: a convenience profile combining core plus selected advanced features.
- `dev-all`: broad local-development profile equivalent to today's default/broad behavior.

The exact feature names can differ, but the intent must be explicit and documented.

### Implementation Steps

1. Inventory current feature flags.
   - Inspect `Cargo.toml` dependencies and `#[cfg(feature = "...")]` use.
   - Record which modules are always compiled today despite being advanced or optional.
   - Identify dependencies that should become optional but are currently unconditional, such as
     broad WASM/plugin/serverless, QUIC/HTTP3, tunnel, mesh, DNS, and admin UI related pieces.

2. Draft a profile matrix before changing code.
   - Suggested file: `plans/architecture_profiles.md` or a new docs page.
   - Include feature names, included modules, excluded modules, intended deployment type, and
     expected reload behavior.

3. Change default features conservatively.
   - Target default: core WAF/proxy behavior only.
   - Keep `socket-handoff` only if it is part of the process model and works on the claimed
     default platform.
   - Move `mesh` and `dns` out of default unless there is a documented operational reason not to.
   - Consider moving `post-quantum` out of default if it materially complicates TLS/provider setup.

4. Gate advanced modules and dependencies.
   - Ensure `src/lib.rs` does not unconditionally expose modules whose dependencies are optional.
   - Add `#[cfg(feature = "...")]` or split modules only where necessary.
   - Avoid creating feature combinations that compile but panic at startup.

5. Update config validation.
   - If config enables a disabled-at-compile feature, return a clear validation error.
   - Example: DNS config present but binary built without `dns` should fail with an actionable
     message.

6. Update documentation.
   - Document how to build each profile.
   - Document which profile supports hot reload, mesh, DNS, plugins, tunnels, and serverless.

### Tests

Add or update:

- `cargo check --no-default-features`
- `cargo check --no-default-features --features mesh`
- `cargo check --no-default-features --features dns`
- `cargo check --no-default-features --features mesh,dns`
- Config validation test for enabling a feature not compiled into the binary.

### Done Criteria

- Default build no longer includes mesh and DNS unless intentionally retained with written ADR
  justification.
- Every documented profile compiles.
- Disabled-at-compile feature use fails clearly during config validation.
- Deployment documentation names the supported profiles.

## Priority 2: Make Runtime Ownership Boundaries Explicit

**Status**: OPEN

### Problem

The worker currently owns or initializes a very large set of subsystems: HTTP serving, WAF,
plugins/serverless, upload validator, port honeypot, mesh transport, DHT routing, topology,
threat intel, YARA rules, bandwidth persistence, Granian supervisors, ACME hooks, and more.

This makes lifecycle behavior hard to reason about:

- What starts when a worker starts?
- What stops on graceful drain?
- What restarts on config reload?
- What is per-worker, per-process, per-node, or global?
- Which background tasks are tied to a shutdown token?

### Required Outcome

Create explicit lifecycle owners for major subsystems and make startup/shutdown/reload contracts
visible in code.

### Implementation Steps

1. Create a runtime ownership inventory.
   - Suggested file: `plans/runtime_ownership.md`.
   - For each subsystem, record:
     - Owner: Master, Worker, Overseer, or external process.
     - Scope: per-request, per-site, per-worker, per-node, cluster-wide.
     - Startup location.
     - Shutdown mechanism.
     - Reload behavior.
     - Whether background tasks are tracked and cancellable.

2. Introduce lifecycle traits or structs only after inventory.
   - A minimal useful interface might be:
     - `start()`
     - `shutdown()`
     - `reload(new_config)`
     - `capabilities()`
   - Do not force every subsystem into a trait if simple structs are clearer.

3. Split worker startup into named lifecycle phases.
   - Example phases:
     - Load config and validate profile.
     - Initialize core data plane.
     - Initialize optional data-plane extensions.
     - Initialize distributed/control-plane extensions.
     - Start listeners.
     - Start tracked background workers.
   - Keep behavior unchanged at first; improve structure and naming.

4. Track background tasks.
   - Every `tokio::spawn` started during subsystem initialization should either:
     - receive a shutdown signal and be awaited, or
     - be explicitly documented as detached for process lifetime.
   - Avoid untracked infinite loops unless they are intentionally process-lifetime tasks.

5. Separate data-plane and control-plane optional subsystems.
   - Data-plane examples: WAF, routing, proxy, HTTP, HTTP3.
   - Control/distribution examples: mesh DHT/Raft, YARA distribution, threat feed propagation.
   - Do not require a control-plane subsystem to be initialized for simple core serving.

### Tests

Add tests where practical:

- Worker startup succeeds with core-only profile.
- Worker startup succeeds with mesh profile.
- Shutdown signal causes lifecycle-owned background tasks to stop.
- Reload only calls reloadable subsystem owners.
- Non-reloadable subsystem returns a restart-required result.

### Done Criteria

- A runtime ownership document exists and matches code.
- Worker startup has clear named phases.
- Background tasks started during initialization are tracked or explicitly documented.
- Subsystems have visible reload/restart contracts.

## Priority 3: Resolve Config Reload Semantics

**Status**: OPEN

### Problem

The codebase has config reload APIs, admin config mutation, and `ConfigManager::reload_all()`, but
the serving path captures key data-plane state at startup. The router is built once and stored as
`Arc<Router>`. `UnifiedServer::reload_config()` reloads the config manager but does not rebuild
the router or related derived state. Worker IPC refuses hot reload when the `mesh` feature is
enabled, and `mesh` is currently a default feature.

This creates an ambiguous operational contract: users can request reloads, but important data-plane
behavior may not change until restart.

### Required Outcome

Choose and implement one of two clear models:

- **Atomic hot reload model**: reload builds a complete new immutable runtime snapshot and swaps it
  atomically into serving code.
- **Restart-required model**: config changes that affect data-plane behavior explicitly trigger
  graceful worker replacement; APIs report restart-required instead of pretending hot reload worked.

The preferred long-term model is atomic hot reload for core WAF/proxy routing and restart-required
for mesh/DNS/tunnels/serverless where needed.

### Implementation Steps

1. Classify config fields by reload behavior.
   - Hot reloadable:
     - Site routing.
     - WAF patterns/config where safe.
     - Rate limit config if data structures support it.
     - Security headers.
     - Static/proxy settings where derived handlers can be rebuilt.
   - Restart required:
     - Listener ports/bind addresses.
     - Process counts.
     - Mesh identity/trust anchors unless explicitly designed for reload.
     - DNS listener mode.
     - Plugin runtime global memory policy, unless safely reloadable.

2. Create a reload behavior table.
   - Suggested file: `plans/reload_contract.md` or documentation under `docs/`.
   - Include every top-level config section.

3. Build an immutable data-plane snapshot.
   - Suggested conceptual type: `RuntimeSnapshot`.
   - It should contain derived request-serving state:
     - `Router`
     - WAF core/config handles or swapped detectors
     - static handlers
     - plugin manager handle if request-serving code needs it
     - serverless manager handle if request-serving code needs it
   - Use `ArcSwap` or equivalent to swap snapshots atomically.

4. Update request serving to read the snapshot.
   - Avoid holding `RwLock<ConfigManager>` in request hot paths.
   - Request code should use immutable snapshot state.
   - Avoid rebuilding per request.

5. Make reload two-phase.
   - Phase 1: parse and validate new config.
   - Phase 2: build new derived snapshot off the hot path.
   - Phase 3: atomically swap snapshot.
   - If any restart-required field changed, return a structured restart-required result.

6. Update admin and IPC reload responses.
   - Report:
     - applied hot reload,
     - rejected invalid config,
     - restart required,
     - unsupported in this profile.
   - Do not log success when serving state was not updated.

7. Handle mesh-enabled builds honestly.
   - If mesh prevents hot reload for some fields, block only those fields.
   - Core routing/WAF reload should still work in a mesh-enabled binary if the changed fields are
     independent.
   - If that is too risky initially, document restart-required for mesh profile and make the API
     return that status.

### Tests

Add tests:

- Reloading a site domain updates routing without process restart in core profile.
- Reloading an upstream URL updates proxy target.
- Reloading listener port returns restart-required.
- Reloading mesh identity returns restart-required.
- Invalid config does not replace the active snapshot.
- Concurrent requests see either old or new snapshot, never partial state.

### Done Criteria

- Reload behavior is documented by config section.
- `reload_config()` updates all hot-reloadable serving state or returns restart-required.
- Admin/IPC responses no longer imply successful reload when only `ConfigManager` changed.
- Tests cover routing reload and restart-required detection.

## Priority 4: Remove Process-Wide Singletons from Request-Sensitive State

**Status**: OPEN

### Problem

Several request-sensitive or lifecycle-sensitive components are process-wide singletons:

- Threat intelligence handle.
- YARA rules manager.
- Upload validator.
- Global plugin manager and memory budget.

Singletons make wiring easy, but they create problems:

- Tests can leak state across cases.
- Multi-worker/multi-profile behavior is harder to reason about.
- Reload cannot replace state cleanly.
- Per-site or per-profile differences become awkward.
- Shutdown ownership is unclear.

### Required Outcome

Request-serving state should be owned by worker/runtime snapshots or explicit subsystem owners,
not hidden process globals. Temporary compatibility accessors may remain during migration but should
be marked as such.

### Implementation Steps

1. Inventory all global state.
   - Search for `static`, `LazyLock`, `OnceLock`, `get_global`, and `set_` patterns.
   - Classify globals as:
     - compile-time constants,
     - process metrics,
     - caches,
     - lifecycle-owned services,
     - test-only helpers.

2. Decide which globals are acceptable.
   - Acceptable examples:
     - immutable regex caches with bounded size,
     - process-wide metrics registries,
     - constants.
   - Questionable examples:
     - upload validator,
     - threat intel manager,
     - plugin manager,
     - mutable config-derived services.

3. Introduce explicit context objects.
   - Suggested conceptual type: `RequestServices` or part of `RuntimeSnapshot`.
   - It should carry:
     - threat intel handle,
     - upload validator,
     - YARA manager,
     - plugin/serverless handles,
     - metrics handles as needed.

4. Thread context into request paths.
   - Avoid large function signatures by passing a context struct.
   - Do not clone heavy state per request; clone `Arc` handles at snapshot construction.

5. Deprecate singleton setters/getters.
   - Keep old functions briefly only if required by many call sites.
   - Mark them as compatibility wrappers with comments.
   - Remove once all request paths use explicit context.

6. Fix tests.
   - Tests should construct fresh contexts.
   - Avoid relying on global state order.

### Tests

Add tests:

- Two independent runtime contexts can use different upload validators.
- Threat intel can be absent in core profile without dummy global state.
- Plugin manager memory budget is profile/context-owned.
- Tests can run in parallel without singleton contamination.

### Done Criteria

- Request-serving code does not require mutable process globals.
- Core profile can run without dummy mesh/threat-intel global initialization.
- Tests demonstrate isolated runtime contexts.

## Priority 5: Split the Unified Worker Runtime into Core and Optional Extensions

**Status**: OPEN

### Problem

The unified worker is a single operational container for too many responsibilities. ADR-003 says a
single async worker is simpler and efficient, but the implementation now includes enough optional
subsystems that the worker is no longer just an HTTP/WAF worker.

The architecture does not need to abandon unified serving immediately, but it should distinguish
core serving from optional extensions and allow isolation where risk warrants it.

### Required Outcome

Define a core worker runtime and optional extension runtimes. The default worker should initialize
only core serving. Optional subsystems should be activated by feature/profile/config and have clear
failure behavior.

### Implementation Steps

1. Define `CoreWorkerRuntime`.
   - Owns:
     - config snapshot,
     - HTTP/HTTPS/HTTP3 listeners if enabled,
     - router,
     - WAF,
     - proxy/static handlers,
     - metrics,
     - drain/shutdown.

2. Define extension initialization boundaries.
   - Candidate extension owners:
     - `MeshRuntime`
     - `DnsRuntime`
     - `PluginRuntime`
     - `ServerlessRuntime`
     - `UploadScanningRuntime`
     - `HoneypotRuntime`
     - `TunnelRuntime`
   - Each extension should declare:
     - feature requirement,
     - config requirement,
     - startup failure policy,
     - shutdown behavior,
     - reload behavior.

3. Decide extension failure policy.
   - Security-critical extensions should fail closed if enabled but cannot start.
   - Optional observability/convenience extensions may fail open only if documented.
   - Do not silently start a degraded version unless config explicitly permits degraded mode.

4. Avoid starting disabled subsystem dummy managers.
   - Example: when mesh is disabled, do not create dummy threat-intel managers solely to satisfy
     global access.
   - Replace dummy setup with `Option` handles in the runtime context.

5. Consider process isolation for high-risk extensions.
   - WASM plugins/serverless and upload scanning are candidates for stronger isolation.
   - Mesh control-plane may remain in worker for routing performance initially, but document the
     tradeoff.
   - Do not implement process splitting until lifecycle boundaries are explicit.

### Tests

Add tests:

- Core worker starts with all optional extensions disabled.
- Enabling an extension without its compiled feature fails validation.
- Enabled security-critical extension startup failure fails worker startup.
- Disabled extension does not spawn background tasks.
- Shutdown stops extension tasks.

### Done Criteria

- Core worker startup is understandable without reading mesh/DNS/plugin code.
- Optional extensions are initialized through explicit owners.
- Disabled optional subsystems do not create dummy global services.

## Priority 6: Make Hot-Path Routing and Location Matching Allocation-Conscious

**Status**: OPEN

### Problem

The repository states a high-scale target and warns against per-request allocations and O(n)
operations. Current routing is partially optimized but still has hot-path issues:

- Exact host lookup is O(1), but suffix/wildcard host matching scans a `Vec`.
- `route_with_local_addr()` creates a new `Arc<str>` for lookup.
- Host validation uses `format!(".{}", clean_domain)` inside loops.
- `LocationMatcher::match_uri()` allocates vectors on each request to collect matches.

These are acceptable for small configs but conflict with the stated scale target when site/location
counts grow.

### Required Outcome

Routing and location matching should avoid per-request allocations and should have documented
complexity limits.

### Implementation Steps

1. Benchmark current routing behavior.
   - Add benchmark cases for:
     - exact host routing,
     - wildcard/suffix routing with many domains,
     - local address/default-server routing,
     - location matching with many prefix/regex locations.
   - Record baseline before changes.

2. Remove obvious per-request allocations.
   - Avoid creating `Arc<str>` just to perform a hash lookup.
   - Avoid `format!` inside host validation loops.
   - Avoid allocation in common clean-host path where possible.

3. Rework location matching.
   - Do not allocate four vectors per request.
   - Track best exact/preferential/regex/prefix matches with local `Option<&LocationMatch>`
     variables.
   - Preserve nginx-like precedence semantics.

4. Rework suffix/wildcard matching if needed.
   - Options:
     - reversed-label trie,
     - suffix map by last label,
     - precompiled matcher structure.
   - Keep exact map fast.
   - Preserve longest suffix wins.

5. Add config-scale guidance.
   - If wildcard domains remain linear, document practical limits.
   - Prefer a real data structure if large multi-tenant deployments are expected.

### Tests

Add tests:

- Exact host still resolves correctly.
- Longest wildcard/suffix match wins.
- Local-address default server behavior is unchanged.
- Location precedence remains exact, preferential prefix, regex, prefix.
- No per-request vector allocation in `LocationMatcher::match_uri()` implementation.

### Done Criteria

- Location matching no longer allocates vectors per request.
- Host routing avoids obvious temporary allocations.
- Benchmarks exist for routing/location matching.
- Complexity is documented.

## Priority 7: Revisit ADR-004 and Split Large Request Pipelines by Responsibility

**Status**: OPEN

### Problem

ADR-004 intentionally preserves very large files like `http/server.rs` and `tls/server.rs`, arguing
that cohesive pipelines are better organized with section comments. In practice, files with
thousands of lines are difficult to audit for security and performance. The issue is not line count
alone; it is that unrelated responsibilities accumulate in one module.

### Required Outcome

Update ADR-004 and begin splitting large request-pipeline modules along stable responsibility
boundaries, without changing behavior.

### Implementation Steps

1. Write a replacement or amendment ADR.
   - Keep the good part of ADR-004: avoid over-fragmented subdirectories and pointless splits.
   - Change the bad part: do not protect multi-thousand-line request handlers from decomposition.
   - Define split criteria:
     - security boundary,
     - protocol boundary,
     - transform/filter boundary,
     - backend dispatch boundary,
     - WebSocket/upgrade handling,
     - response transformation,
     - body collection/streaming,
     - challenge/block response construction.

2. Map `src/http/server.rs`.
   - Create a short outline of major sections and helper functions.
   - Identify pure helpers that can move first with low risk.
   - Identify stateful operations that should wait.

3. Move low-risk helpers first.
   - Candidate modules:
     - request validation,
     - response header filtering/injection,
     - WebSocket handling,
     - body collection/WAF scanning,
     - backend dispatch helpers,
     - image protection/poisoning.
   - Preserve public behavior and tests.

4. Keep state ownership clear.
   - Do not make fields `pub(crate)` broadly just to satisfy sibling modules unless that is already
     the local pattern and unavoidable.
   - Prefer passing narrow context structs to helpers.

5. Add focused tests around moved pieces.
   - Every extracted module should have at least basic unit tests if it contains logic.

### Tests

Add tests:

- Request validation helper tests.
- Header transformation helper tests.
- WebSocket upgrade decision tests.
- Backend dispatch decision tests.
- Existing HTTP server tests still pass.

### Done Criteria

- ADR-004 is amended or superseded.
- At least one large request-pipeline file is split by responsibility.
- Behavior remains unchanged.
- Extracted modules have focused tests.

## Priority 8: Clarify Master, Worker, and Mesh Control-Plane Boundaries

**Status**: OPEN

### Problem

The Master is intentionally isolated from external request traffic, which is good. However, workers
also handle mesh connections and distributed control-plane behavior directly. That decision trades
IPC overhead for a larger worker attack surface and failure domain.

The code comments say mesh vulnerabilities do not affect Master, but they can still affect the same
worker handling client traffic.

### Required Outcome

Document and enforce which mesh/control-plane operations belong in workers, which belong in Master,
and which should eventually move to a separate process.

### Implementation Steps

1. Create a control-plane boundary document.
   - Suggested file: `plans/control_plane_boundaries.md` or an ADR.
   - Include:
     - request data plane,
     - local process control plane,
     - mesh/distributed control plane,
     - admin API control plane.

2. Classify mesh operations.
   - Direct request-routing mesh proxy operations may justify worker residency.
   - DHT sync, Raft, threat-intel propagation, YARA distribution, and global topology management
     may be candidates for a control-plane runtime.

3. Choose a near-term model.
   - Near term: keep mesh in worker but isolate lifecycle and rate limits.
   - Medium term: separate mesh control-plane process or dedicated worker type.
   - Document why direct proxying remains in data-plane workers if kept.

4. Add backpressure and failure boundaries.
   - Mesh background work should not starve HTTP/WAF request handling.
   - Distributed sync tasks should have explicit concurrency and rate limits.
   - CPU-heavy verification should stay off the async executor.

5. Update process manager naming.
   - If there will be worker types beyond unified request workers, name them clearly.
   - Avoid using `unified_server_workers` for both scaling and internal accept-thread concepts.

### Tests

Add tests:

- Mesh-disabled core worker has no mesh listener or mesh background tasks.
- Mesh sync task failure does not terminate core HTTP serving unless configured fail-closed.
- Mesh message flood is rate-limited independently from HTTP request handling.

### Done Criteria

- Mesh/control-plane boundaries are documented.
- Current worker residency is justified or changed.
- Mesh background work has explicit backpressure/failure policy.

## Priority 9: Make Plugin and Serverless Isolation a First-Class Decision

**Status**: OPEN

### Problem

WASM plugins and serverless functions run inside the same worker process via a global plugin
manager. Wasmtime provides sandboxing, but a plugin platform is still a high-risk extension point:
resource limits, host functions, memory budgets, hot reload, and tenant boundaries need explicit
architecture.

### Required Outcome

Plugin/serverless runtime should be profile-gated, context-owned, resource-limited, and explicit
about isolation guarantees.

### Implementation Steps

1. Decide whether plugins are core or extension.
   - Recommended: extension, disabled unless profile/config enables it.
   - Core WAF should not require plugin manager initialization.

2. Replace global plugin manager usage in request paths.
   - Move plugin manager into runtime context/snapshot.
   - Memory budget should be owned by that manager/context.

3. Document host function policy.
   - Which host functions exist?
   - Which are allowed by default?
   - Which require explicit capability grants?
   - How are DHT/mesh access prefixes enforced?

4. Revisit hot reload.
   - File watcher lifecycle is currently intentionally leaked to keep it alive.
   - Replace with lifecycle-owned watcher handles that stop on shutdown.
   - Plugin reload should either atomically replace plugin set or clearly require restart.

5. Strengthen resource limits.
   - Confirm fuel/timeouts are enforced for every invocation path.
   - Confirm memory budget cannot be bypassed by reload or duplicate names.
   - Confirm max body sizes are enforced before copying into WASM memory.

6. Consider process isolation for untrusted plugins.
   - Do not implement this immediately unless required.
   - Document whether current Wasmtime isolation is considered enough for the target deployment.

### Tests

Add tests:

- Core profile starts without plugin manager.
- Plugin profile enforces memory budget.
- Plugin reload replaces old plugin behavior atomically or returns restart-required.
- Missing plugin capability blocks host function access.
- Oversized request/response body is rejected before WASM memory copy.

### Done Criteria

- Plugin/serverless is profile-gated.
- Plugin manager is not a hidden process singleton for request handling.
- Lifecycle-owned hot reload watcher exists or hot reload is disabled with clear status.
- Resource limits are tested.

## Priority 10: Add Architecture Regression Gates

**Status**: OPEN

### Problem

Architectural regressions are easy in this codebase because modules can import across boundaries
freely and default features compile many subsystems together. Without tests and CI gates, optional
subsystems will creep back into core paths.

### Required Outcome

Add lightweight automated checks that enforce the intended architecture.

### Implementation Steps

1. Add feature/profile compile checks.
   - Core/no-default profile.
   - Mesh profile.
   - DNS profile.
   - Full/dev profile.

2. Add dependency boundary checks.
   - At minimum, document forbidden imports.
   - Better: add a small script or test that scans for forbidden imports.
   - Examples:
     - core HTTP/router should not depend on mesh unless behind feature/profile and explicit
       backend type requires it.
     - WAF core should not require mesh threat intel globals in core profile.
     - config module should not initialize runtime services.

3. Add reload contract tests.
   - Hot reloadable fields update snapshot.
   - Restart-required fields are detected.
   - Invalid config does not alter active state.

4. Add lifecycle leak checks where possible.
   - Test that extension tasks shut down.
   - Avoid intentionally leaked watchers in new code.

5. Add benchmark gates for hot routing.
   - Benchmarks do not need to fail CI initially.
   - Keep them available so future agents can compare routing changes.

### Done Criteria

- CI or documented local checks cover core, mesh, DNS, and full profiles.
- Boundary checks prevent obvious subsystem coupling regressions.
- Reload contract tests exist.
- Routing/location benchmarks exist.

## Deferred Architectural Items

These are intentionally deferred until the open priorities above are complete:

- Full multi-crate workspace decomposition.
- Moving mesh control-plane into a separate process.
- Moving plugin/serverless execution into a separate process.
- Replacing the admin UI/API architecture.
- A full config schema redesign.
- Replacing Tokio/Hyper/Quinn foundations.
- Large performance rewrites beyond routing/location hot-path cleanup.

## Suggested Execution Order

1. Priority 1: define profiles and reduce default runtime surface.
2. Priority 2: document runtime ownership and add lifecycle boundaries.
3. Priority 3: fix reload semantics or make restart-required behavior explicit.
4. Priority 4: remove request-sensitive singleton dependencies.
5. Priority 5: split core worker runtime from optional extensions.
6. Priority 6: optimize routing/location hot paths.
7. Priority 7: amend ADR-004 and split large request-pipeline modules.
8. Priority 8: clarify mesh/control-plane boundaries.
9. Priority 9: make plugin/serverless isolation explicit.
10. Priority 10: add architecture regression gates.

## Handoff Notes for Architecture Agent

- Start with documents and compile/profile checks before moving code.
- Do not attempt to solve systems-layer platform hardening and architecture separation in the same
  PR unless a compile gate forces it.
- If feature gating reveals platform or IPC problems, refer to the preserved systems-layer plan
  below instead of making ad hoc fixes.
- If mesh/DHT/Raft security behavior changes are needed, refer to the preserved distributed-layer
  plan below.
- Every completed item should be removed or marked complete in this file before handoff. Deferred
  items should remain visible.

---

# Previously Open Systems-Layer Work

The section below was already open in `plans/plan.md` before this architectural plan was added.
It is retained because incomplete or deferred work must remain visible. No completed systems-layer
items were identified during this update.

# MaluWAF Foundational Utilities and Systems Layer Improvement Plan

**Status**: OPEN
**Last Updated**: 2026-05-01
**Primary Scope**: foundational utilities and systems code, especially `src/utils.rs`,
`src/buffer/**`, `src/process/**`, `src/platform/**`, `src/zero_copy.rs`, and platform-specific
support code.

This plan is written for a follow-on agent that may not have the original review context.
No implementation has been completed for this systems-layer review yet. Items below are therefore
open unless explicitly marked deferred.

Existing open distributed-layer work from the previous plan is preserved later in this file under
"Previously Open Distributed-Layer Work". Do not remove those items until they are actually
completed or intentionally superseded.

## Goal

Make the foundational/system layer honest, portable, secure-by-default, and performant enough to
support the rest of MaluWAF without hidden platform traps.

The current codebase is strongest on Linux/Unix. Windows, macOS, and BSD support exists in several
places, but some paths are likely compile-broken, some advertise enforcement that is not actually
active, and several security-sensitive abstractions differ sharply by OS.

## Ground Rules

- Do not write broad rewrites. Fix one subsystem at a time with focused tests.
- Treat Linux as the baseline production target, but make non-Linux support either genuinely
  compile/test clean or explicitly unsupported with clear feature gating.
- Do not weaken default-deny security behavior to keep compatibility.
- Prefer typed structs and explicit platform traits over duplicated ad hoc platform code.
- Use `subtle::ConstantTimeEq` for secrets, keys, MACs, tokens, and comparable auth material.
- Use existing timestamp helpers for persisted/network timestamps.
- Keep hot paths allocation-conscious. Measure or at least reason about every new allocation in
  per-request/per-message code.
- For unsafe code, require a written safety invariant next to the unsafe block and add tests that
  stress the invariant where practical.
- Read the nearest `AGENTS.override.md` before editing subsystem-specific code.

Recommended verification commands:

```bash
cargo test --lib --no-run
cargo test --lib process
cargo test --lib platform
cargo test --lib buffer
cargo test --test ipc_test
cargo test --test process_lifecycle_test
cargo fmt --check
cargo clippy --lib -- -D warnings
```

Cross-platform verification should be added to CI or run manually before claiming completion:

```bash
cargo check --target x86_64-unknown-linux-gnu --all-features
cargo check --target x86_64-apple-darwin --no-default-features
cargo check --target x86_64-pc-windows-msvc --no-default-features
```

If the exact targets are unavailable locally, document that clearly and add CI jobs or a follow-up
item instead of claiming platform support is fixed.

## Current Risk Summary

The highest risk areas found during review:

1. Windows support is likely compile-broken because some modules import Unix-only APIs
   unconditionally and `windows-sys` lacks required feature flags.
2. IPC support is duplicated across several Windows and platform modules, with inconsistent named
   pipe creation, blocking behavior, and security attributes.
3. IPC authentication exists but unsigned paths remain easy to use and named pipe/socket access
   controls are not consistently fail-closed.
4. The sandbox abstraction over-promises: Linux/macOS/BSD/Windows implementations do not provide
   equivalent enforcement and some paths ignore configured write/deny rules.
5. The custom buffer pool uses unsafe lock-free and interior-mutability techniques that need
   formal safety review or replacement.
6. IPC framing and signed IPC allocate and copy heavily; acceptable for low-rate control-plane
   traffic, but risky if used for high-rate worker communication.
7. Process/pidfile and lock-file code has platform-specific behavior mixed into common modules and
   likely does not compile on Windows.
8. Several utility APIs contain small footguns, such as `ip_to_slot(ip, 0)` panic potential and
   duration parsing overflow.

## Priority 1: Establish an Honest Platform Support Matrix

**Status**: OPEN

### Problem

The repository contains code for Linux, generic Unix, Windows, macOS, FreeBSD, OpenBSD, and other
fallbacks, but support is uneven. Some code appears to compile only on Unix while advertising
Windows variants. Examples to inspect first:

- `src/process/pidfile.rs` imports `nix::fcntl::{flock, FlockArg}` and
  `std::os::unix::io::AsRawFd` unconditionally.
- `src/process/ipc_transport.rs` has a Windows `local_addr()` returning
  `tokio::net::unix::SocketAddr`.
- `Cargo.toml` declares `windows-sys` with only `Win32_System_LibraryLoader`, while code uses
  Foundation, Pipes, Security, Threading, Services, and Firewall-related APIs.
- Most IPC/process tests are Unix-gated, so Windows/macOS/BSD regressions are not visible.

### Required Outcome

The project must have a clear, tested platform matrix:

- Linux: supported for production systems-layer behavior.
- macOS: either compile-clean with documented limitations or explicitly gated.
- Windows: either compile-clean with documented limitations or explicitly gated.
- BSD variants: either compile-clean for supported subsets or explicitly gated.
- Unsupported platforms: fail at compile time with clear messages or use documented stubs.

### Implementation Steps

1. Create a platform support table in a repo-local doc.
   - Suggested file: `plans/platform_support_matrix.md` or a section in an existing developer doc.
   - Include: process management, IPC, socket handoff, sandboxing, firewall/filtering, zero-copy,
     service installation, and tests.

2. Run or configure cross-platform `cargo check`.
   - At minimum: Linux, macOS, Windows MSVC.
   - Use `--no-default-features` first to isolate platform compilation.
   - Then test targeted feature combinations such as `socket-handoff`, `icmp-filter`, and
     `macos-sandbox` where supported.

3. Fix unconditional Unix imports and types.
   - Gate Unix-only imports in `src/process/pidfile.rs`.
   - Replace Windows `local_addr()` return type in `src/process/ipc_transport.rs` with a
     platform-neutral enum or remove the API from Windows builds.
   - Audit other files found by `rg "std::os::unix|nix::|tokio::net::unix" src`.

4. Fix `windows-sys` feature declarations.
   - Add the exact `windows-sys` features needed by currently compiled Windows code.
   - Avoid enabling broad unused feature sets.
   - Verify with `cargo check --target x86_64-pc-windows-msvc --no-default-features`.

5. Decide how to gate partially implemented features.
   - Socket FD passing and socket handoff are Unix-native. Non-Unix paths should return clear
     `NotSupported` errors and tests should assert that behavior.
   - Windows named pipes should be the supported IPC replacement, not a partial emulation of Unix
     sockets.

### Tests

Add or update tests:

- Compile-check CI jobs for Linux, macOS, and Windows.
- Unit tests for platform-neutral path helpers.
- Windows-specific compile tests for named-pipe APIs if CI supports Windows.
- Non-Unix tests asserting unsupported socket handoff behavior.

### Done Criteria

- Platform support matrix exists and matches the code.
- `cargo check` succeeds for each claimed platform/feature set.
- Unsupported platform features fail clearly without misleading success paths.

## Priority 2: Consolidate IPC Implementations and Enforce Authentication

**Status**: OPEN

### Problem

IPC behavior is split across:

- `src/process/ipc.rs`
- `src/process/ipc_transport.rs`
- `src/process/ipc_windows.rs`
- `src/master/windows.rs`
- `src/platform/ipc.rs`
- `src/platform/unix.rs`
- `src/platform/windows_impl.rs`

This duplication creates inconsistent behavior. Some paths use signed IPC, some warn and continue
unsigned, some use raw JSON command parsing, and Windows pipe creation currently passes null
security attributes.

### Required Outcome

There should be one clear IPC abstraction for master/worker/command communication. Authentication
must be enforced by default for privileged commands and worker/master channels.

### Implementation Steps

1. Inventory all IPC entry points.
   - Classify each as worker control, master command, socket handoff, status query, or legacy.
   - For each entry point, record whether it uses framing, signing, peer credential checks, named
     pipe ACLs, or raw JSON.

2. Pick one canonical framing/signing implementation.
   - Prefer `src/process/ipc_transport.rs` plus `ipc_framing.rs` and `ipc_signed.rs` if it can
     cover both Unix sockets and Windows named pipes.
   - Mark old or duplicate helpers as compatibility wrappers only.

3. Make unsigned IPC impossible for privileged production paths.
   - Worker/master channels should require a signer unless explicitly in a test-only or
     development mode.
   - Command IPC that can stop/reload/reconfigure the process must require authentication or a
     same-user/administrator credential check.
   - Replace one-time warnings with errors for production paths.

4. Bind IPC identity to OS identity where available.
   - Linux: use `SO_PEERCRED` to check same UID or expected worker PID where possible.
   - macOS/BSD: use available peer credential APIs if implemented; otherwise document limitation.
   - Windows: use named pipe impersonation or explicit pipe ACLs.

5. Secure Windows named pipe creation.
   - Build an explicit security descriptor that restricts pipe access to the current user,
     Administrators, and/or LocalSystem as appropriate.
   - Do not pass null security attributes for privileged command pipes.
   - Use message mode consistently and avoid blocking calls inside async tasks.

6. Remove raw JSON command pipe handling.
   - `src/master/windows.rs::handle_command_connection()` reads raw length-prefixed JSON and
     executes commands.
   - Replace it with the canonical framed/signed command handling path.

7. Keep test hooks explicit.
   - If tests need unsigned IPC, name the constructor accordingly, for example
     `connect_unsigned_for_test`.
   - Avoid generic `connect()` silently choosing unsigned behavior for privileged operations.

### Tests

Add tests:

- Unsigned worker/master message is rejected when enforcement is on.
- Signed worker/master message succeeds.
- Command `Stop`/`ReloadConfig` is rejected without auth.
- Wrong key fails HMAC verification.
- Replay with duplicate nonce fails.
- Windows named pipe ACL creation compiles and is unit-tested where possible.
- Unix peer credential helper rejects wrong UID/PID in isolated tests where feasible.

### Done Criteria

- Privileged IPC has one canonical implementation.
- Unsigned privileged IPC is not reachable by default.
- Windows named pipes have explicit security attributes or are documented as unsupported.
- Duplicate IPC code is removed or downgraded to thin wrappers.

## Priority 3: Harden IPC Signing, Replay Cache, and Key Handling

**Status**: OPEN

### Problem

`src/process/ipc_signed.rs` has good building blocks, but several details need hardening:

- Replay protection uses one global mutex-protected nonce cache for every signer and channel.
- Eviction happens before insert, so the cache can exceed the intended maximum by one entry.
- File key loading on non-Unix lacks symlink/permission/ACL protections.
- `try_from_env()` and `read_ipc_key_file()` duplicate parsing logic.
- `from_secret()` hashes arbitrary strings without KDF parameters and may encourage weak secrets.
- Signed reader paths use single `read()` calls where `read_exact()` is needed for full frames.

### Required Outcome

IPC signing should be fail-closed, bounded, channel-aware, and have one reviewed key-loading path.

### Implementation Steps

1. Centralize hex key parsing.
   - Add one helper that parses exactly 64 hex characters into `[u8; 32]`.
   - Use constant-time comparison where comparing keys or auth material.

2. Replace or scope the replay cache.
   - Cache key should include at least signer/channel identity plus nonce.
   - Keep memory bounded.
   - Evict after insert or use a structure that never exceeds capacity.
   - Consider a per-`IpcSigner` or per-connection cache instead of a process-global cache.

3. Fix signed stream read behavior.
   - Use `read_exact()` for frame length and frame body.
   - Preserve nonblocking behavior only in APIs that explicitly support partial reads.

4. Harden key file handling.
   - Unix: use `O_NOFOLLOW`; check file type, owner, and mode before reading.
   - Windows: validate ACL/owner or avoid file-based secret handoff until implemented safely.
   - Avoid deleting an unvalidated path after a failed read.

5. Clarify `from_secret()`.
   - If kept, document it as test/development only or replace with a KDF helper using salt and
     iteration parameters.
   - Production should prefer generated random session keys.

6. Zeroize secrets where practical.
   - Consider `zeroize` for temporary key buffers and signer storage.
   - Avoid logging key paths if they reveal sensitive deployment layout.

### Tests

Add tests:

- Short read in signed reader returns `UnexpectedEof`, not partial parse.
- Replay cache capacity stays bounded.
- Same nonce on different channels is handled according to the chosen policy.
- Symlink key file is rejected on Unix.
- Key file with world-readable permissions is rejected on Unix.
- Invalid hex parsing is rejected consistently by every loading path.

### Done Criteria

- One key parsing path.
- Replay cache is bounded and channel-aware.
- Signed reads are exact.
- Key-file handoff is secure or explicitly unsupported on platforms where it cannot be made safe.

## Priority 4: Make Socket Paths, PID Files, and Locks Race-Resistant

**Status**: OPEN

### Problem

Socket and pidfile helpers are security-sensitive because they live near process control and IPC.
Current concerns:

- `src/process/socket_path.rs::create_secure_dir_atomic()` uses `metadata()` on existing paths and
  then chmods them, which follows symlinks.
- `/tmp/maluwaf` fallback needs stronger ownership and symlink checks.
- `src/process/pidfile.rs` mixes Unix and Windows logic with unconditional Unix imports.
- `OverseerLockFile` uses `File::create()` before `flock`, which can truncate an existing lock
  before ownership is established.
- Windows process existence checks shell out to `tasklist`.

### Required Outcome

Runtime directories, pidfiles, and locks should be safe under local adversarial conditions and
compile cleanly on every claimed platform.

### Implementation Steps

1. Harden runtime directory creation.
   - On Unix, use `symlink_metadata()` for existing paths.
   - Reject symlinks and non-directories.
   - Verify owner is the current effective UID or root as appropriate.
   - Verify mode is `0700`; only chmod if ownership is trusted.

2. Revisit `/tmp` fallback.
   - Prefer `XDG_RUNTIME_DIR` or `/run/maluwaf` for production.
   - If falling back to `/tmp`, use a per-UID directory such as `/tmp/maluwaf-$uid` and enforce
     ownership/mode checks.

3. Split pidfile platform code.
   - Move Unix lock implementation behind `#[cfg(unix)]`.
   - Move Windows lock/process-existence implementation behind `#[cfg(windows)]`.
   - Keep common serialization/path code platform-neutral.

4. Fix lock acquisition ordering.
   - Open lock files without truncating until lock is acquired.
   - After acquiring lock, write/truncate content.
   - Avoid deleting another process's active lock in cleanup paths.

5. Replace Windows `tasklist` process checks.
   - Use `OpenProcess` with query-limited rights and `GetExitCodeProcess`.
   - Add required `windows-sys` features.

6. Apply file permissions consistently.
   - Private key, pid, lock, and IPC secret files should be `0600` on Unix where applicable.
   - Directories should be `0700`.

### Tests

Add tests:

- Existing symlink runtime dir is rejected.
- Existing world-writable runtime dir owned by another user is rejected or ignored.
- Lock acquisition does not truncate another active lock.
- Stale lock cleanup removes only stale locks.
- Windows compile-check covers process existence helper.

### Done Criteria

- Socket path and pidfile helpers compile on all claimed platforms.
- `/tmp` fallback is not vulnerable to trivial symlink/ownership attacks.
- Lock acquisition is race-resistant.

## Priority 5: Rework Sandbox Abstraction to Match Real Enforcement

**Status**: OPEN

### Problem

`src/platform/sandbox.rs` exposes a common abstraction, but implementations differ dramatically:

- `SandboxPaths::write_paths()` is currently not used by `ProcessSandbox::with_paths()`.
- Linux Landlock uses hardcoded access masks and does not distinguish read/write paths clearly.
- FreeBSD `is_capsicum_available()` calls `cap_enter()`, which can permanently enter capability
  mode just to test availability.
- macOS Seatbelt is disabled unless the `macos-sandbox` feature is enabled, but `is_supported()`
  still reports true.
- Windows Job Object limits do not enforce filesystem path allow/deny rules.

### Required Outcome

Sandboxing must be explicit about what is enforced per OS. APIs should not imply path restrictions
exist when a backend cannot enforce them.

### Implementation Steps

1. Define backend capabilities.
   - Add a `SandboxCapabilities` struct or enum flags.
   - Include: read path allowlist, write path allowlist, deny paths, process limits, network
     restrictions, child-process restrictions, and availability.

2. Fix `SandboxPaths` handling.
   - Pass both read and write paths to backends.
   - Deny paths should either be enforced or reported as unsupported.
   - Do not silently ignore `write_paths()`.

3. Correct Linux Landlock access masks.
   - Use named constants for Landlock access rights rather than `0b111`.
   - Distinguish read-only and writable paths.
   - Set `PR_SET_NO_NEW_PRIVS` before `landlock_restrict_self` if required.
   - Close all opened fds correctly after adding rules.

4. Fix FreeBSD availability detection.
   - Do not call `cap_enter()` during a support check.
   - If no harmless check exists, return "unknown until apply" or test using documented APIs.

5. Fix macOS support reporting.
   - If `macos-sandbox` feature is disabled, `is_supported()` should not claim active enforcement.
   - Basic profile generation currently emits both `(allow default)` and `(deny default)`; verify
     semantics and correct the profile.

6. Clarify Windows behavior.
   - Job Objects are process resource controls, not filesystem sandboxing.
   - Either implement filesystem restrictions via appropriate Windows mechanisms or report path
     sandboxing unsupported.

7. Fail closed where configured strict sandboxing cannot be applied.
   - If a user requests strict sandboxing, do not silently downgrade to logging.
   - Provide a config option only if an explicit degraded mode is desired.

### Tests

Add tests:

- `with_paths()` passes read and write paths to a fake backend.
- Strict sandbox fails when backend cannot enforce requested capabilities.
- macOS support flag reflects `macos-sandbox` feature state.
- FreeBSD support check does not enter sandbox mode.
- Linux Landlock access masks are constructed from named constants.

### Done Criteria

- Sandbox API reports real capabilities.
- Strict mode either enforces requested restrictions or returns an error.
- No backend silently ignores path restrictions while claiming success.

## Priority 6: Audit and Either Prove or Replace the Custom Buffer Pool

**Status**: OPEN

### Problem

`src/buffer/pool.rs` contains unsafe code in two high-risk areas:

- A raw-pointer Treiber stack that frees nodes after pop, exposing classic ABA hazards.
- Thread-local cache mutation by casting shared slices to mutable pointers.

This code sits in a foundational performance path. If the invariants are wrong, memory safety bugs
can surface under load.

### Required Outcome

The buffer pool must be demonstrably memory-safe or replaced with a simpler safe design whose
performance is acceptable.

### Implementation Steps

1. Decide whether the lock-free stack is worth keeping.
   - If not, replace it with a safe `parking_lot::Mutex<Vec<BytesMut>>` per shard and benchmark.
   - For most buffer pooling workloads, sharded mutexes may be fast enough and much safer.

2. If keeping lock-free behavior, add proper memory reclamation.
   - Use a reviewed crate such as `crossbeam_epoch`, or redesign to avoid freeing nodes while
     concurrent readers may still observe pointers.
   - Document ABA prevention.

3. Remove interior mutation through shared slice casts.
   - Use `RefCell`, `Cell`-compatible structures, or store the TLS cache in a mutable thread-local
     wrapper.
   - Avoid creating mutable references from shared references.

4. Add safety comments.
   - Every unsafe block must state preconditions and why aliasing/lifetime/threading is valid.

5. Add stress tests.
   - Multi-thread acquire/release loops.
   - Random buffer sizes.
   - `take_bytes()`, `split_to()`, `advance()`, and drop interactions.
   - Run under Miri if possible for safe portions.

6. Add benchmarks before and after changes.
   - Use existing `benches` style.
   - Compare throughput and allocation behavior.
   - Keep the safer design unless the performance regression is proven unacceptable.

### Tests

Add tests:

- Concurrent acquire/drop does not panic or corrupt lengths.
- Pool capacity stays bounded.
- Buffers are zeroed or cleared according to documented behavior.
- `take_bytes()` prevents returning consumed buffers to the pool.

### Done Criteria

- No unsound unsafe remains, or unsafe invariants are documented and tested.
- Buffer pool passes stress tests.
- Performance impact is measured.

## Priority 7: Reduce IPC Framing Copies and Make Message Size Policy Explicit

**Status**: OPEN

### Problem

IPC framing currently copies data several times:

- `read_message()` drains a buffer and creates `to_vec()` before deserialization.
- `SignedIpcMessage::serialize_signed()` creates serialized payload, HMAC input, and final frame.
- Signed receive allocates a new `Vec` for every message.

This may be acceptable for low-rate control-plane messages, but the code is generic and could be
used in hotter worker communication paths.

### Required Outcome

IPC message handling should have an explicit performance contract:

- Control-plane messages can prioritize simplicity.
- Hot worker telemetry/request paths should avoid unnecessary copies and allocations.
- Message size limits should be centralized and configurable if needed.

### Implementation Steps

1. Classify IPC traffic.
   - Worker lifecycle/control.
   - Request logs and metrics.
   - Command/status.
   - Socket handoff.
   - Any request hot-path IPC.

2. Decide which paths need zero-copy or low-copy handling.
   - If a path is not hot, document that the simple framing is intentional.
   - If a path is hot, use `BytesMut` and deserialize from slices without copying where possible.

3. Centralize message size limits.
   - Avoid multiple independent `1024 * 1024` constants.
   - Consider smaller limits for command/status and separate limits for bulk snapshot/handoff.

4. Optimize signed framing.
   - Compute HMAC over existing buffers without building a duplicate HMAC data vector.
   - Reuse read buffers where possible.
   - Avoid allocating a final frame when `write_all` can write header and payload slices.

5. Add metrics.
   - Count rejected oversized messages.
   - Optionally track IPC message sizes by category.

### Tests

Add tests:

- Oversized message rejected consistently for signed and unsigned framing.
- Signed and unsigned framing agree on length semantics.
- Partial reads work correctly.
- Multiple messages in one read buffer deserialize correctly.

### Done Criteria

- Hot IPC paths avoid obvious duplicate allocations.
- Message size policy is centralized and tested.

## Priority 8: Clean Up Utility Footguns

**Status**: PARTIAL (wave16-continued-2026-05-01)

### Problem

**Completed fixes:**

1. **`ip_to_slot(ip, num_slots)`**: Already fixed in earlier wave16 work - returns `Option<usize>` and handles zero slots correctly.

2. **`parse_duration()`**: Already fixed in earlier wave16 work - uses checked multiplication to prevent overflow.

3. **`urlencoding_decode()` UTF-8 handling**: Non-ASCII percent-encoded bytes (e.g., `%E4`) are now preserved as-is instead of being silently dropped. Invalid sequences like `%GG` are preserved rather than causing silent data loss.

### What remains OPEN:
- `OptionExt::if_none()` is a no-op but appears unused in codebase (no callers via `.if_none()` pattern)
- `RunningFlag` and `DrainFlag` use `SeqCst` without documented rationale - Acquire/Release might suffice for stop/drain flags

### Problem

Several general utilities are small but widely reused. Footguns here can become distributed bugs:

- `ip_to_slot(ip, num_slots)` can panic or divide by zero when `num_slots == 0`.
- `parse_duration()` uses unchecked multiplication and ambiguous millisecond behavior.
- `urlencoding_decode()` only emits ASCII for percent-decoded bytes and does not handle UTF-8
  percent sequences correctly.
- `OptionExt::if_none()` is a no-op and likely not useful.
- `RunningFlag` and `DrainFlag` use `SeqCst` for every operation without a documented need.

### Required Outcome

Utility APIs should either be obviously safe for all inputs or return explicit errors for invalid
inputs.

### Implementation Steps

1. Fix or guard `ip_to_slot`.
   - Prefer returning `Option<usize>` or `Result<usize, Error>` for zero slots.
   - If API compatibility requires `usize`, document and assert at callers before use.
   - Add tests for zero and one slot.

2. Harden duration parsing.
   - Use checked multiplication.
   - Decide whether `1500ms` should round down, round up, or return subsecond information.
   - If only seconds are supported, document truncation explicitly.

3. Replace URL decoding with a UTF-8-aware implementation.
   - Preserve invalid percent sequences as-is or return an error from the `_result` variant.
   - Make `urlencoding_decode_result()` actually report invalid encodings if callers expect that.

4. Review utility extension traits.
   - Remove or deprecate no-op helpers if unused.
   - Avoid adding generic extension methods that obscure control flow.

5. Relax atomic ordering only where safe.
   - For simple stop/drain flags, Acquire/Release is likely sufficient.
   - If keeping `SeqCst`, document why.

### Tests

Add tests:

- `ip_to_slot` with zero slots.
- Duration overflow returns `None` or an error, not wrapped values.
- UTF-8 percent decoding works for non-ASCII strings.
- Invalid percent encodings behave consistently.
- Atomic flag behavior remains correct across clones.

### Done Criteria

- Utility edge cases are tested.
- APIs do not panic on invalid external input unless explicitly documented.

## Priority 9: Platform Firewall, Filtering, and Admin Capability Review

**Status**: OPEN

### Problem

Firewall/filter support spans platform-specific code:

- `src/icmp_filter/**`
- `src/platform/windows/firewall.rs`
- `src/platform/windows/interface_resolver.rs`
- `src/tcp/listener.rs`
- optional eBPF/nftables/pf/winfw/wfp modules

The admin/capability checks are not consistently tied to the actual operation being performed.
Windows helper functions shell out to PowerShell/netsh in several places, and Linux checks mix root,
`CAP_NET_ADMIN`, and unprivileged BPF state.

### Required Outcome

Filtering/firewall operations should clearly report required privileges, supported OS/backend, and
whether they are active.

### Implementation Steps

1. Build a backend capability table.
   - Linux nftables/eBPF.
   - macOS/BSD pf.
   - Windows firewall/WFP.
   - Unsupported stubs.

2. Make privilege checks operation-specific.
   - Binding low ports, loading eBPF, changing nftables, and creating Windows firewall rules need
     different privileges.
   - Avoid one broad `is_admin()` answer for all operations.

3. Reduce shell-out usage where practical.
   - Prefer native APIs for Windows firewall/interface operations if already using `windows-sys`.
   - If shelling out remains, sanitize arguments and handle localized output carefully.

4. Make inactive stubs visible.
   - A backend that returns success without enforcement should be named and logged as inactive.
   - Tests should assert inactive behavior.

### Tests

Add tests:

- Backend reports unsupported without pretending enforcement exists.
- Privilege check returns the expected requirement for each operation.
- Windows command construction cannot inject additional arguments.
- Linux capability parsing handles missing `/proc` fields.

### Done Criteria

- Each filtering backend has documented support and privilege requirements.
- Unsupported/inactive backends cannot be mistaken for active protection.

## Priority 10: Add Systems-Layer CI and Regression Gates

**Status**: OPEN

### Problem

Most systems-layer regressions will not be caught by ordinary Linux unit tests. Cross-platform
compile errors, unsafe buffer issues, IPC auth bypasses, and sandbox degradation need targeted
gates.

### Required Outcome

CI should catch platform compile breaks and core systems-layer regressions before merge.

### Implementation Steps

1. Add CI jobs or documented local scripts for:
   - Linux default features.
   - Linux no-default features.
   - macOS no-default features.
   - Windows MSVC no-default features.

2. Add feature-specific checks:
   - `socket-handoff` on Unix.
   - `macos-sandbox` on macOS if available.
   - Windows service/named-pipe code on Windows.
   - `icmp-filter` feature combinations where dependencies allow.

3. Add unsafe-code gates.
   - Run Miri for utility/buffer tests if feasible.
   - Add stress tests for buffer pool and IPC framing.

4. Add security regression tests.
   - IPC unsigned rejection.
   - Key file symlink rejection.
   - Runtime dir symlink rejection.
   - Sandbox strict-mode failure when unsupported.

5. Document commands in the platform support matrix.

### Done Criteria

- CI or equivalent documented verification covers every claimed platform.
- Security-sensitive systems-layer tests are part of normal validation.

## Deferred Systems-Layer Items

These are intentionally deferred until the open priorities above are complete:

- Full service-manager polish for systemd/launchd/Windows SCM beyond compile and basic behavior.
- Large-scale performance tuning outside IPC framing and buffer pool safety.
- Replacing all shell-outs across the repository.
- Deep WireGuard/TUN backend work, except where platform compile checks require gating.
- New admin APIs for platform capability reporting.

## Suggested Systems-Layer Execution Order

1. Priority 1: establish the platform matrix and fix obvious cross-platform compile blockers.
2. Priority 2 and 3 together: consolidate IPC and harden signing/key/replay behavior.
3. Priority 4: harden runtime dirs, pidfiles, and locks.
4. Priority 5: make sandbox capabilities honest and fail-closed.
5. Priority 6: prove or replace the buffer pool.
6. Priority 7: reduce IPC copies where the traffic classification says it matters.
7. Priority 8: clean up utility edge cases.
8. Priority 9: review platform firewall/filter privilege behavior.
9. Priority 10: add CI/regression gates.

## Handoff Notes for Systems-Layer Agent

- Start with compile checks before code changes. Several problems may reveal themselves as compiler
  errors on non-Linux targets.
- Keep each priority in a separate commit or PR. Cross-platform code is easier to review in small
  slices.
- If a platform cannot be supported now, prefer honest `NotSupported` behavior plus tests over
  partial code that appears to succeed.
- Do not remove existing open distributed-layer work below unless you actually complete or
  supersede it.

---

# Previously Open Distributed-Layer Work

The section below was already open in `plans/plan.md` before the systems-layer plan was added.
It is retained because the user requested that incomplete or deferred items remain in the plan.

# MaluWAF Distributed Layer Hardening Plan

**Status**: OPEN
**Last Updated**: 2026-05-01
**Scope**: `src/mesh/**`, with emphasis on Raft, DHT, quorum, and P2P transport ingress.

This plan is written for a follow-on agent that may not have the full review context.
Completed Wave 15 items have been pruned. The remaining items below are not complete unless
explicitly marked deferred.

## Goal

Make the mesh/Raft/DHT layer fail closed under adversarial P2P conditions.

The current code has many individual hardening mechanisms, but several security and convergence
properties are enforced inconsistently across ingress paths. The work should make these properties
explicit, centralized, tested, and hard to bypass.

## Ground Rules

- Read `src/mesh/AGENTS.override.md` before editing mesh code.
- Keep changes scoped to distributed-layer correctness and security. Avoid broad refactors.
- Prefer postcard/typed structs over JSON or ad hoc string signing.
- Use `crate::mesh::safe_unix_timestamp()` or existing timestamp helpers for network timestamps.
- Use `subtle::ConstantTimeEq` for secrets if adding secret comparison.
- Do not weaken default-deny behavior to preserve compatibility.
- Add regression tests for every fixed bypass.
- Run focused tests before broad tests.

Recommended verification commands:

```bash
cargo test --lib mesh::dht
cargo test --lib mesh::raft
cargo test --lib mesh::transport
cargo test --lib --no-run
cargo fmt --check
cargo clippy --lib -- -D warnings
```

## Current Risk Summary

The highest risk areas found during review:

1. Raft client proposals are accepted by the transport handler without checking command-level
   source identity or signature.
2. Raft replication RPCs depend on outer transport trust rather than explicit Raft membership
   authorization at the handler boundary.
3. DHT has a centralized `verify_for_ingress()` API, but several production ingress paths call
   `store_record()` directly.
4. Global DHT storage can accept remote records with a non-empty signature but missing signer
   public key in some cases.
5. Pending quorum records can be promoted by gossip/sync for some key classes without a quorum
   proof.
6. Regional quorum proof creation and later proof verification do not use the same quorum context.
7. Some DHT background workers are spawned with weak references to temporary `Arc` values and may
   stop immediately after startup.
8. `verify_quorum_proof_authoritative()` synchronously blocks on async topology state.

## Priority 1: Raft Client Proposal Authorization

**Status**: OPEN

### Problem

`RaftCommand::{Set, Delete}` includes `source_node_id` and `signature`, but client write paths
currently populate both as `None`:

- `src/mesh/raft/client.rs`: `raft_write_local()`
- `src/mesh/raft/client.rs`: `raft_write_to_leader()`

The network handler then deserializes a `ClientProposal` and directly calls
`inst.client_write(command)`:

- `src/mesh/transport_peer.rs`: `handle_raft_message()` branch `RaftMsgType::ClientProposal`

This relies on prior transport authentication to be perfect and makes the command fields
effectively decorative.

### Required Outcome

Raft client proposals must be authorized before entering OpenRaft.

### Implementation Steps

1. Define a canonical signable payload for Raft client commands.
   - Put it near `RaftCommand` in `src/mesh/raft/state_machine.rs` or a nearby helper module.
   - Include at least: namespace, key, value hash for `Set`, command kind, source node ID,
     timestamp or nonce, and protocol version.
   - Do not sign raw `Vec<u8>` values directly if a hash is sufficient.

2. Extend `RaftCommand` if needed.
   - Add timestamp/nonce if the existing fields cannot prevent replay.
   - Keep serialization backward-compatibility in mind if persisted log entries already exist.
   - If backward compatibility is risky, introduce a new command variant and keep old variants
     accepted only for local/internal paths with explicit checks.

3. Populate `source_node_id` and `signature` in:
   - `RaftAwareClient::raft_write_local()`
   - `RaftAwareClient::raft_write_to_leader()`
   - Any other call sites constructing `RaftCommand::Set` or `Delete`

4. Add verification before `inst.client_write(command)` in the `ClientProposal` transport branch.
   - Verify command signature.
   - Verify source node is allowed to write the target namespace.
   - Verify peer identity matches or is allowed to proxy the command source.
   - Reject missing signature for remote proposals.
   - Log rejection reason without leaking secret material.

5. Add namespace policy.
   - `Namespace::Org`, `Namespace::Intel`, and `Namespace::Revocation` likely have different
     allowed writers.
   - Default deny unknown or future namespaces.

6. Add replay protection.
   - Minimum acceptable timestamp window should be consistent with mesh message windows.
   - If using nonces/request IDs, maintain a bounded recent-seen cache per source.

### Tests

Add tests covering:

- Remote `ClientProposal` with missing signature is rejected.
- Remote `ClientProposal` with invalid signature is rejected.
- Valid signed proposal from authorized source is accepted.
- Valid signature from unauthorized source is rejected.
- Signature for one namespace/key cannot be replayed for another namespace/key.
- Stale/future timestamp proposal is rejected.

Suggested locations:

- `src/mesh/raft/regression_tests.rs`
- Unit tests near new signable helper
- Transport-level handler tests if existing test harness supports it

### Done Criteria

- No remote Raft client write reaches `inst.client_write()` without explicit authorization.
- Command-level fields are meaningful and tested.
- Existing local writes still work.
- `cargo test --lib mesh::raft` passes.

## Priority 2: Raft Replication RPC Membership Gate

**Status**: OPEN

### Problem

`AppendEntries`, `VoteRequest`, and `InstallSnapshot` are accepted by
`src/mesh/transport_peer.rs::handle_raft_message()` after deserialization and then passed to
OpenRaft. There is no obvious handler-local check that the peer is a current Raft member or
authorized learner.

### Required Outcome

Every Raft RPC handler must verify the sender is authorized for the target Raft cluster before
calling OpenRaft.

### Implementation Steps

1. Thread authenticated peer identity into `handle_raft_message()`.
   - It currently receives `target_node_id` and payload but not an explicit `from_node`.
   - Find the call site and pass the authenticated peer/node ID.
   - Do not trust fields embedded inside the Raft payload as the peer identity.

2. Add a helper such as `is_authorized_raft_peer(from_node, msg_type)`.
   - Check current cluster membership from OpenRaft where possible.
   - Permit learners only for RPCs they should receive/send.
   - Deny edge/origin nodes unless explicitly configured as observers.
   - Consider bootstrap/initialization state separately and fail closed outside bootstrap.

3. Gate these branches:
   - `RaftMsgType::AppendEntries`
   - `RaftMsgType::VoteRequest`
   - `RaftMsgType::InstallSnapshot`
   - Any response handlers if they can mutate state or satisfy pending requests.

4. Add metrics/logging for rejected Raft RPCs.
   - Include peer ID, message type, and reason.
   - Avoid logging raw payload data.

5. Ensure snapshot install cannot be initiated by unauthorized peers.
   - Header and chunk frames should both require the same authorized sender.
   - Bind a snapshot transfer request ID to the authorized sender so chunks from other peers are
     rejected.

### Tests

Add tests covering:

- Non-member cannot send `AppendEntries`.
- Non-member cannot send `VoteRequest`.
- Non-member cannot start `InstallSnapshot`.
- Authorized member can send valid RPCs.
- Snapshot chunks from a different peer than the header are rejected.

### Done Criteria

- All Raft RPC branches have an explicit membership/role gate.
- Snapshot transfer state is peer-bound.
- `cargo test --lib mesh::raft` passes.

## Priority 3: Make DHT Ingress Verification Mandatory

**Status**: OPEN

### Problem

`DhtRecord::verify_for_ingress()` exists but production ingress paths still call
`store_record()` directly. This risks policy drift because each path may enforce a slightly
different subset of content hash, signature, source identity, trust anchor, expiry, and quorum
proof checks.

Important ingress paths:

- `DhtRecordAnnounce`
- `DhtSyncResponse`
- `DhtAntiEntropyResponse`
- `DhtRecordPush`
- `DhtRecordCommit`
- Local create paths
- Disk warmup/load paths

### Required Outcome

Remote DHT records must pass one centralized ingress verifier before storage or cache insertion.

### Implementation Steps

1. Inventory all `store_record(` call sites under `src/mesh`.
   - Classify each as local create, remote announce, sync, anti-entropy, push, commit, disk load,
     or test-only.

2. Add a single wrapper method on `RecordStoreManager`, for example:
   - `store_record_from_ingress(record, ingress_context, source_reputation)`
   - It should call `record.verify_for_ingress(&ctx, &self.access_control)` and then call the
     internal storage path only on success.

3. Make raw `store_record()` harder to misuse.
   - Rename to `store_record_verified_internal()` if practical.
   - Keep it `pub(crate)` if external modules do not need it.
   - Tests can use explicit local contexts instead of bypassing verification.

4. Build `DhtRecordIngressContext` at every network ingress point.
   - Set path accurately: Announce, SnapshotSync, SyncResponse, AntiEntropy, QuorumCommit, Push,
     LocalCreate.
   - Set source classification from authenticated peer role, not from record self-claims.
   - Set `requires_quorum_proof` from access control.
   - Set `requires_trust_anchor` and `is_immutable_key` from key metadata.
   - Set `envelope_signature_valid` only after validating the outer message signature.

5. Bind record identity to authenticated peer identity.
   - Verify record `source_node_id` is allowed for the authenticated peer.
   - If delegation/proxying is allowed, require an explicit signed delegation.
   - Otherwise reject mismatches.

6. Keep local create behavior explicit.
   - Local records may be unsigned before the local signer attaches a signature, but that should
     be represented by `IngressPath::LocalCreate`, not by falling through remote logic.

### Tests

Add regression tests for each ingress path:

- Missing signature rejected on remote announce.
- Missing signer public key rejected on remote global store.
- Source node mismatch rejected.
- Immutable record without trust anchor rejected.
- Quorum-required record without proof rejected on sync, anti-entropy, push, and commit.
- Local create still succeeds and signs when signer is configured.

### Done Criteria

- Remote DHT records cannot reach storage without `verify_for_ingress()`.
- Raw storage helper is not exposed as an easy bypass.
- `cargo test --lib mesh::dht` passes.

## Priority 4: Fix Global DHT Signature Fail-Closed Behavior

**Status**: OPEN

### Problem

For global nodes, `store_record()` can allow a non-empty record signature with no signer public key
to continue into `store_record_global()`. `store_record_global()` rejects an empty signature for
remote records but only verifies when `signer_public_key` is present and non-empty.

### Required Outcome

Every remote signed DHT record must include a signer public key and must verify against that key,
unless the path has a stronger authenticated envelope and an explicit reason to avoid per-record
signatures.

### Implementation Steps

1. Update global storage verification so remote records require:
   - non-empty signature
   - non-empty signer public key
   - signature verifies using `verify_dht_record_signature()` or the centralized ingress verifier

2. Remove or narrow any global-node exception for missing signer key.

3. Ensure record type is derived from `DhtKey` for verification.
   - Avoid hardcoding `SignedRecordType::NodeInfo` for all records if the actual key type is known.

4. Ensure legacy disk records without auth metadata are not promoted into live state for sensitive
   namespaces.

### Tests

Add tests:

- Global store rejects remote record with non-empty signature and missing signer public key.
- Global store rejects remote record signed as wrong record type.
- Global store accepts valid signed record with correct key type.

### Done Criteria

- Missing signer public key is fail-closed for remote records on global nodes.
- Existing valid records still pass.

## Priority 5: Quorum State Transition Consistency

**Status**: OPEN

### Problem

Records that require quorum are stored as `PendingQuorum`, but a remote record can promote a
pending entry to live through gossip/sync when `requires_quorum_proof()` is false. This creates a
dangerous distinction between "requires quorum to create" and "requires proof to confirm."

### Required Outcome

Any record that required quorum to enter pending state must require a valid quorum proof to become
live, regardless of ingress path.

### Implementation Steps

1. Audit access control methods:
   - `requires_quorum()`
   - `requires_quorum_proof()`
   - `requires_confirmation()`
   - Key classifications in `src/mesh/dht/keys.rs`

2. Decide whether `requires_quorum()` should imply `requires_quorum_proof()`.
   - Preferred: yes for all remote promotion paths.
   - If exceptions exist, document and test them explicitly.

3. Update pending-to-live transitions:
   - `store_record_global()` passive confirmation path
   - `commit_record_after_quorum()`
   - `handle_record_commit()`
   - sync and anti-entropy apply paths

4. Ensure a pending local record cannot be overwritten by a remote higher timestamp without valid
   proof.

5. Ensure rejected/timeout pending records are removed from memory and disk.

### Tests

Add tests:

- Pending quorum record is not promoted by gossip without proof.
- Pending quorum record is not promoted by sync without proof.
- Pending quorum record is promoted by valid proof.
- Higher timestamp remote record cannot bypass pending quorum.

### Done Criteria

- Quorum-required records have exactly two states: hidden pending without proof, live with verified
  proof.
- No passive promotion bypass remains.

## Priority 6: Regional Quorum Proof Context

**Status**: OPEN

### Problem

Regional quorum creation can select a subset of global voters, but later verification uses
`regional_voter_set: None` and total global count. That means a valid regional proof may fail
elsewhere, or a verifier may be unable to distinguish which subset was authorized.

### Required Outcome

Regional quorum proofs must carry enough signed context for any node to verify the same quorum rule
that created the proof.

### Implementation Steps

1. Define a `QuorumContext` or extend existing proof metadata.
   - Include quorum mode: full or regional.
   - Include selected voter set for regional mode.
   - Include threshold basis and protocol version.
   - Include request ID, key, value hash, TTL, sequence, origin node, and action.

2. Ensure each quorum signer signs the context.
   - The selected voter set must be covered by signatures.
   - Prevent an attacker from taking regional signatures and claiming a different voter set.

3. Store quorum context with committed records.
   - Add fields to `DhtRecord` or encode context into proof structure.
   - Consider disk serialization/migration if schema changes.

4. Update `verify_quorum_proof_authoritative()`.
   - Pass regional voter set when proof context says regional.
   - Verify every signer is in the selected regional set.
   - Verify selected regional set members are authorized global nodes.
   - Verify required threshold is computed from the selected set.

5. Decide policy for nodes that do not know every selected voter.
   - Preferred: fail closed for sensitive records.
   - Optionally trigger topology refresh before final rejection.

### Tests

Add tests:

- Full quorum proof still verifies.
- Regional proof verifies when voter set and signatures match.
- Regional proof rejects signer outside voter set.
- Regional proof rejects tampered voter set.
- Regional proof rejects unknown global node in voter set.
- Regional proof rejects below regional threshold.

### Done Criteria

- Regional quorum records are portable and verifiable by other nodes.
- Verification uses the same quorum basis as creation.

## Priority 7: Fix DHT Background Worker Lifetimes

**Status**: OPEN

### Problem

`start_background_tasks()` creates weak references from temporary `Arc::new(self.clone())` values.
After the function returns, those temporary strong Arcs are dropped, so workers that call
`upgrade()` may never run useful work.

### Required Outcome

DHT background workers must hold a valid reference for their intended lifetime or receive a proper
shutdown signal.

### Implementation Steps

1. Inspect `RecordStoreManager` ownership.
   - Determine where it is already held in an `Arc`.
   - Prefer changing `start_background_tasks` to take `self: Arc<Self>` if practical.

2. Fix worker spawning.
   - Anti-entropy/cleanup worker should hold `Arc<RecordStoreManager>` or use a strong reference
     plus shutdown channel.
   - Quorum cleanup worker should not use a weak ref to a temporary Arc.
   - Merkle integrity worker should not use a weak ref to a temporary Arc.

3. Add shutdown behavior if missing.
   - Avoid leaked infinite tasks in tests.
   - Reuse existing shutdown mechanisms if present.

4. Add observability.
   - Log when workers start and stop.
   - Consider metrics heartbeat for anti-entropy and integrity workers.

### Tests

Add tests if feasible:

- Worker reference remains upgradeable after `start_background_tasks()` returns.
- Quorum cleanup runs on old pending entries.
- Merkle integrity worker can rebuild drifted tree.

If time-based async tests are flaky, factor worker body into testable methods and unit test those.

### Done Criteria

- Background tasks do not silently exit due to dropped temporary Arcs.
- Tests or structure demonstrate worker logic remains reachable.

## Priority 8: Remove Synchronous Blocking From Quorum Verification

**Status**: OPEN

### Problem

`verify_quorum_proof_authoritative()` calls `tokio::runtime::Handle::current().block_on(...)`
inside a synchronous method. This is brittle in async contexts and can block runtime workers.

### Required Outcome

Quorum verification should be async or use a cached topology snapshot without blocking the Tokio
runtime.

### Implementation Steps

1. Convert `verify_quorum_proof_authoritative()` to async if call sites are async.
2. For synchronous call sites, either:
   - pass in a precomputed `QuorumVerifierContext`, or
   - read from a cached authorized-global-node snapshot maintained outside the hot path.
3. Update call sites:
   - `store_record_global()`
   - `apply_sync()`
   - `handle_record_commit()`
   - any tests
4. Keep hot-path allocations reasonable.
   - Do not repeatedly allocate huge global-node maps per record in bulk sync.
   - For bulk sync, compute verifier context once per batch if possible.

### Tests

Add tests:

- Quorum verification works in async context without `block_on`.
- Bulk sync verifies multiple records using consistent topology state.

### Done Criteria

- No `Handle::current().block_on` remains in DHT quorum verification.
- `cargo test --lib mesh::dht` passes.

## Priority 9: Transport Envelope and Record Identity Binding Audit

**Status**: OPEN

### Problem

Some handlers verify outer message signatures, some verify per-record signatures, and some rely on
authenticated peer IDs. The relationship between these identities is not consistently documented or
enforced.

### Required Outcome

For every mesh P2P message carrying records or consensus state, the code should explicitly state
and enforce which identity is trusted:

- authenticated transport peer
- message envelope signer
- record signer
- record `source_node_id`
- quorum signer

### Implementation Steps

1. Create a short internal document or code comment table near DHT ingress logic.
   - Keep it close to the code, not in a detached design doc only.

2. Audit these message types:
   - `DhtRecordAnnounce`
   - `DhtSyncRequest`
   - `DhtSyncResponse`
   - `DhtAntiEntropyRequest`
   - `DhtAntiEntropyResponse`
   - `DhtRecordPush`
   - `DhtRecordCommit`
   - `QuorumStoreRequest`
   - `QuorumSignatureResponse`
   - `Raft`

3. For each message type, enforce:
   - timestamp window
   - authenticated sender role
   - envelope signature if required
   - record signature if records are included
   - source-node binding
   - replay/request ID handling where applicable

4. Add negative tests for mismatched identities.

### Done Criteria

- Identity assumptions are visible in code.
- Tests cover mismatch between peer ID, source node ID, and signer key.

## Deferred Items

These are intentionally deferred until the above correctness/security work is complete:

- Performance tuning of DHT routing and regional quorum selection.
- Major Raft storage schema changes unrelated to auth metadata.
- New mesh admin APIs for manual quorum or Raft management.
- Changing the public wire protocol beyond the minimum needed for signed context and auth.

## Suggested Execution Order

1. Priority 1: Raft client proposal authorization.
2. Priority 2: Raft replication RPC membership gate.
3. Priority 3 and 4 together: mandatory DHT ingress verification and global signature fail-closed.
4. Priority 5: quorum state transition consistency.
5. Priority 6: regional quorum proof context.
6. Priority 7: background worker lifetimes.
7. Priority 8: remove synchronous blocking.
8. Priority 9: final identity binding audit.

## Handoff Notes

- Expect some tests to require helper refactors before behavior changes.
- Prefer small PRs/commits per priority. This code is security-sensitive and easier to review in
  focused slices.
- When behavior changes reject previously accepted malformed records, add explicit test fixtures so
  future agents understand the rejection is intentional.
- If compatibility with existing deployed records conflicts with fail-closed behavior, default to
  fail closed for sensitive namespaces and document any temporary migration path.
