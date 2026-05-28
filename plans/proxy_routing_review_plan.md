# Proxy & Routing Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/proxy.md`, `architecture/proxy_deep_dive.md`, `architecture/routing_deep_dive.md`, `architecture/upstream.md`, `architecture/proxy_cache.md`, `architecture/streaming.md`, `architecture/location_matcher.md`

## Verified Correct Items

- All documented file paths exist and contain the claimed modules
- `ProxyServer` struct at `src/proxy/mod.rs:73-96` — fields match (with noted additions)
- `ProxyServer` builder methods `with_http2`, `with_cache`, `with_upstream_pool`, `from_config` exist
- `ProxyServer::handle_request()` at `src/proxy/mod.rs:338` — WAF integration matches documented flow
- `ProxyServer::invalidate_cache()` and `invalidate_cache_by_host()` exist at `mod.rs:791,799`
- `ProxyServer::forward_request_via_tunnel()` exists at `mod.rs:614`
- `DispatchParams` struct at `src/proxy/dispatch.rs:14-26` — fields match
- `dispatch_to_upstream()` exists at `dispatch.rs:42`
- `calculate_backoff()`, `is_idempotent_method()`, `is_retryable_status()`, `should_retry_request()` exist in `retry.rs`
- `Backend` struct at `pool.rs:154-167` — all fields match documented names and types
- `ConnectionGuard` RAII pattern at `pool.rs:169-177` — matches
- `ConnectionCounter` enum with `Local` and `Shared` variants at `pool.rs:87-95`
- `LoadBalanceAlgorithm` enum at `pool.rs:48-57` — 6 variants match
- `BackendProtocol` enum at `pool.rs:59-70` — 8 variants match
- `UpstreamPool` struct at `pool.rs:376-382` — fields match
- `UpstreamPool::select_backend()`, `select_next_backend()`, `mark_failed()`, `get_metrics()` — all exist
- `UpstreamPool::new()`, `new_with_backup()` — signatures match
- `UpstreamPool::add_backend_with_protocol()`, `add_backend_with_weight()` — exist
- `UpstreamPool::select_backend_for_ip()`, `select_backend_for_protocol()` — exist
- `Backend::record_success()` and `record_failure()` at `pool.rs:324-343` — circuit breaker logic matches (3 threshold)
- `Backend::record_latency()` at `pool.rs:307` — EWMA formula `(old * 9 + new) / 10` confirmed
- `Backend::composite_load()` at `pool.rs:368-373` — formula `conn * 0.4 + cpu * 0.6` confirmed
- `Backend::connection_scope()` at `pool.rs:302` — RAII guard confirmed
- `GLOBAL_POOL_REGISTRY` at `pool.rs:9` — `LazyLock<DashMap>` confirmed
- `validate_upstream_url()` at `pool.rs:14` with `ALLOWED_SCHEMES` — matches
- `HealthChecker` struct at `health.rs:11-16` — fields match
- `HealthCheckConfig` defaults at `health.rs:37-48` — all values match
- `HealthCheckMethod` variants `Head`, `Get`, `Tcp` — confirmed
- `SharedConnectionTable` layout at `shared_state.rs:14-20` — confirmed
- `GlobalCacheGovernor` at `governor.rs:9` — 512MB default confirmed
- `TeeBody` at `streaming.rs:12-22` — fields match
- `LocationMatcher` struct and `match_uri()` logic at `location_matcher.rs:119-185` — matching priority correct
- `LocationMatch::new()` and `LocationMatch::matches()` — behavior matches
- `Router` struct at `router.rs:32-50` — fields match
- `BackendType` enum at `router.rs:66-78` — variants confirmed
- `RouteTarget` struct at `router.rs:81-94` — fields confirmed
- `ErasedHttpClient` at `erased_pool.rs:415-456` — struct and `send_request()` confirmed
- `ErasedConnectionPool` at `erased_pool.rs:224-232` — struct and `checkout()`/`checkin()` confirmed
- `PoolKey` at `erased_pool.rs:111-115` — `authority` + `is_http2` fields confirmed
- `StreamingWafBody` at `http_client/mod.rs:135-141` — fields match (note: `streaming_waf` field is `Option<StreamingWafCore>` not `Option<Arc<StreamingWafCore>>`)
- `TypedConnectionPool` at `typed_pool.rs:69-73` — struct confirmed
- `ProxyCache` struct at `store.rs:144-161` — fields confirmed
- `CacheKey` at `key.rs:4-12` — fields confirmed
- `revalidation_semaphore` at `store.rs:156` — exists
- Circuit breaker for revalidation at `store.rs:265-287` — implemented
- `MAX_WAF_BODY_SIZE = 1MB` at `mod.rs:372` — confirmed
- HTTP/2 feature gate `#[cfg(feature = "mesh")]` at `mod.rs:554` — confirmed
- Global client cache 100 entries, 5min TTL at `http_client/mod.rs:67-68` — confirmed
- ProxyError and ProxyConfig exist in `streaming/bidirectional.rs`
- `copy_bidirectional()`, `copy_bidirectional_native()`, `copy_bidirectional_auto()` — all exist

## Discrepancies Found

### proxy.md

- **[line 57-63]** `BackendType` — Documented as from "upstream module" with `Single(String)`, `Pool(Vec<Backend>)`, `Fallback(Vec<Backend>)`. **Actual**: `BackendType` is in `src/router.rs:66-78` with 11 completely different variants: `Upstream`, `FastCgi`, `Php`, `Cgi`, `AxumDynamic`, `AppServer`, `Static`, `QuicTunnel`, `Serverless`, `Mesh`, `Spin`. The upstream module has no `BackendType` enum.

- **[line 69-76]** `RetryConfig` — Field `retry_on_connection_error` documented, actual field name is `retry_on_error` (`crates/synvoid-config/src/site/proxy.rs:238`). Also missing `retry_non_idempotent: bool` field.

- **[line 82-110]** `ProxyServer` struct — Missing `proxy_headers_config: Option<Arc<ProxyHeadersConfig>>` field that exists at `mod.rs:95`.

- **[line 92-93]** `with_upstream_pool()` signature — Documented as `with_upstream_pool(mut self, pool: Arc<UpstreamPool>, ...) -> Self`. **Actual**: `with_upstream_pool(mut self, pool: Arc<UpstreamPool>, retry_config: Option<RetryConfig>, buffering_config: Option<BufferingConfig>) -> Self` at `mod.rs:204-214`.

- **[line 210-215]** `calculate_backoff()` — Pseudocode shows jitter: `let jitter = rand() % 100; (base * exponential).saturating_add(jitter)`. **Actual code** at `retry.rs:47-49` has NO jitter: `base_timeout_ms * 2u64.saturating_pow(attempt.min(5))` clamped to 30000. This is a behavioral inaccuracy.

- **[line 248-253]** Named constants `DEFAULT_POOL_MAX_IDLE`, `DEFAULT_POOL_IDLE_TIMEOUT`, `DEFAULT_UPSTREAM_TIMEOUT` — These constants do not exist in the codebase. The values 100 and 30s are inline in `new()` and `from_config()`.

- **[line 239-245]** Feature gates — Documented `http2` feature gate for `is_http2` flag. **Actual**: `is_http2` is a struct field, not a feature gate. The only feature gate in proxy module is `#[cfg(feature = "mesh")]` at `mod.rs:554`.

### proxy_deep_dive.md

- **[line 31]** ProxyServer struct location `mod.rs:73-94` — Actual struct spans lines 73-96 (includes `proxy_headers_config` field at line 95).

- **[line 43]** ProxyExecutor location `executor.rs:96-103` — Actual is at lines 98-107.

- **[line 244]** Revalidation semaphore default — Documented as "Default 32 concurrent revalidations". **Actual**: default is 100 (`config.rs:51`). Config field is `max_concurrent_revalidations`, not `revalidation_capacity`.

- **[line 214]** StreamingWafBody location `mod.rs:133-223` — Actual struct is at lines 135-141; the `impl Body` block extends to line 223. Minor offset.

- **[line 112]** PoolKey Hash derive claimed at `erased_pool.rs:112` — The `#[derive(Hash)]` attribute is at line 111; the struct definition is at line 112. Minor.

### routing_deep_dive.md

- **[line 50]** External GitHub link `https://github.com/synvoid/synvoid/blob/main/src/router.rs#L513` — References a GitHub URL that may not be valid for internal codebase. Should reference local file path instead.

- **[line 65]** External GitHub link `https://github.com/synvoid/synvoid/blob/main/src/upstream/pool.rs#L520-L528` — Same issue, external GitHub link for code reference.

### upstream.md

- **[line 103-105]** `Backend` field types — Documented `cpu_percent: AtomicU32`, `memory_percent: AtomicU32`. **Actual**: `cpu_percent: Arc<AtomicU32>`, `memory_percent: Arc<AtomicU32>` at `pool.rs:164-165`.

- **[line 124-125]** SharedConnectionTable layout — Documented as `[N+1..]: connections`. **Actual**: `[16 + max_workers * 8..]: connections` (`shared_state.rs:20`).

### proxy_cache.md

- **[line 25-32]** `ProxyCacheEntry` struct — Documented fields are completely wrong:
  - Doc: `headers: HashMap<String, String>` → Actual: `headers: HeaderMap` (`store.rs:35`)
  - Doc: `created_at: u64` → Actual: `created_at: Instant` (`store.rs:36`)
  - Doc: `expires_at: u64` → Actual: `expires_at: Option<Instant>` (`store.rs:38`)
  - Doc: `stale: bool` → Actual: no `stale` field; instead `stale_while_revalidate: Option<Instant>`, `stale_if_error: Option<Instant>`, `is_fresh: bool` (`store.rs:39-42`)
  - Missing: `last_accessed`, `content_length` fields

- **[line 34-41]** `CacheKey` struct — `site_id` documented as `Option<String>`, actual is `String` (`key.rs:11`).

- **[line 43-47]** `CacheHit` enum — Documented as `Hit(ProxyCacheEntry), Miss, Stale(ProxyCacheEntry)`. **Actual**: `Hit, Miss, Expired, Stale, StaleWhileRevalidate` — no associated data on any variant (`store.rs:111-117`).

- **[line 49-56]** `ProxyCacheSettings` struct — Fields completely wrong:
  - Doc: `max_memory_entries` → Actual: `max_memory_size` (bytes, not entry count)
  - Doc: `default_ttl` → Actual: `inactive` (Duration) + `stale_while_revalidate` (Option<Duration>)
  - Doc: `valid_status_codes` → Actual: `valid_status`
  - Doc: `valid_methods` → Actual: `methods`
  - Missing: `path`, `use_temp_file`, `use_stale`, `stale_if_error`, `min_uses`, `key_pattern`, `vary_by`, `max_concurrent_revalidations`, `revalidation_failure_threshold`, `revalidation_circuit_breaker_cooldown_secs`, `allowed_headers`

- **[line 20-23]** `ProxyCache` struct — Documented as having `memory_cache: moka::sync::Cache<String, ProxyCacheEntry>` and `disk_cache: Option<DiskCache>`. **Actual**: has `entries: Cache<CacheKey, CacheEntryInner>` (key type is `CacheKey` not `String`, value type is `CacheEntryInner` not `ProxyCacheEntry`) and many more fields including `host_index`, `inflight_requests`, `revalidation_semaphore`, `circuit_open`, etc. No `disk_cache` field.

### streaming.md

- **[line 27-34]** `ProxyError` variants — Documented `ReadError(io::Error)` and `WriteError(io::Error)`. **Actual**: `ReadError(String)` and `WriteError(String)` at `bidirectional.rs:11-12`.

- **[line 33]** `WafBlock(String)` → **Actual**: `WafBlock(u16, String)` (includes status code).

- **[line 24]** `ProxyConfig.waf_scanner` type — Documented as `Option<Arc<StreamingWafCore>>`. **Actual**: `Option<Arc<Mutex<StreamingWafCore>>>` at `bidirectional.rs:46` (requires `tokio::sync::Mutex`).

- **[line 43-46]** Public API — Documented `copy_bidirectional_native(client, upstream).await` taking separate reader/writer. **Actual**: `copy_bidirectional_native<R1, R2>(client, upstream)` takes two stream objects (`bidirectional.rs:289`), not four reader/writer pairs.

### location_matcher.md

- **[line 18-22]** `LocationMatcher` struct fields — Documented as `exact_matches: HashMap<String, usize>`, `prefix_matches: Vec<LocationMatch>`, `regex_matches: Vec<LocationMatch>`. **Actual**: `exact_locations: HashMap<String, (usize, LocationMatchType)>`, `prefix_locations: Vec<(String, (usize, LocationMatchType))>`, `regex_locations: Vec<LocationMatch>` at `location_matcher.rs:119-123`.

- **[line 26]** `LocationMatch` field `compiled_regex` — Actual field name is `regex` at `location_matcher.rs:20`.

## Bugs Identified

- **[LOW] BUG-PROXY-DOC-1**: `calculate_backoff()` in `proxy.md:210-215` shows jitter that doesn't exist in code. Misleads developers about retry behavior. (`src/proxy/retry.rs:47-49`)

- **[LOW] BUG-PROXY-DOC-2**: `BackendType` in `proxy.md:57-63` references completely wrong enum from wrong module. All field names and variants are incorrect. (`architecture/proxy.md:57-63`)

## Suggested Improvements

### Documentation Accuracy

- **proxy.md**: Replace `BackendType` section with reference to `router.rs:66-78` or remove the upstream module claim.
- **proxy.md**: Update `RetryConfig` to use correct field name `retry_on_error` and add `retry_non_idempotent`.
- **proxy.md**: Add `proxy_headers_config` to `ProxyServer` struct listing.
- **proxy.md**: Fix `calculate_backoff()` pseudocode to match actual implementation (no jitter).
- **proxy.md**: Replace named constant references with inline values or create actual constants.
- **proxy.md**: Fix `with_upstream_pool()` signature to include `retry_config` and `buffering_config` parameters.
- **proxy.md**: Remove `http2` feature gate claim — it's a struct field, not a feature gate.
- **proxy_deep_dive.md**: Fix line number references for `ProxyServer` (73-96), `ProxyExecutor` (98-107).
- **proxy_deep_dive.md**: Fix revalidation default from 32 to 100; fix field name from `revalidation_capacity` to `max_concurrent_revalidations`.
- **routing_deep_dive.md**: Replace external GitHub links with local file path references.
- **upstream.md**: Fix `cpu_percent` and `memory_percent` types to `Arc<AtomicU32>`.
- **upstream.md**: Fix SharedConnectionTable layout notation to use actual offsets.
- **proxy_cache.md**: Rewrite entire struct listing section to match actual types. This document is significantly outdated.
- **streaming.md**: Fix `ProxyError` variant types and `ProxyConfig.waf_scanner` type.
- **location_matcher.md**: Fix struct field names and `LocationMatch` field name.

### Code Quality

- **Dead code in proxy/mod.rs**: `is_response_cacheable()` (line 929), `is_retryable_status()` (line 1143), `is_connection_error()` (line 1148), `is_timeout_error()` (line 1153), `calculate_backoff()` (line 1158) — all marked `#[allow(dead_code)]` on `ProxyServer` methods. These are wrapper methods that delegate to the free functions; consider removing or using the free functions directly.

- **Dead code in erased_pool.rs**: `HttpProtocol` enum (line 40-45), `PooledConnection` trait (line 101-109), `Http2PooledConnection` struct (line 124-127) — all `#[allow(dead_code)]`. `Http2PooledConnection` is an empty stub with only an `authority` field and no actual HTTP/2 implementation.

- **Dead code in proxy_cache/store.rs**: `CacheEntryInner::validate()` (line 139-141) — marked dead code, reserved for cache integrity verification.

- **Missing error handling**: `ProxyServer::from_config()` at `mod.rs:310-331` — `ErasedHttpClient::new(100)` hardcodes 100 instead of using the `pool_max_idle` parameter.

### API Inconsistencies

- **StreamingWafBody** vs **StreamingWafCore**: `StreamingWafBody` in `http_client/mod.rs:137` wraps `Option<StreamingWafCore>` (owned), while `ProxyConfig.waf_scanner` in `streaming/bidirectional.rs:46` wraps `Option<Arc<Mutex<StreamingWafCore>>>` (shared). Different ownership patterns for the same WAF scanning concept.

- **CacheKey.uri** contains a hash-prefixed value (`format!("{}:{}", hash, uri_str)` at `key.rs:52`) — the field name suggests a URI but it's actually a hashed cache key component. This is confusing.

## Stale Content

- **proxy.md**: The entire document is superseded by `proxy_deep_dive.md` for detailed struct/API documentation. `proxy.md` contains incorrect struct definitions that `proxy_deep_dive.md` has partially corrected. Consider removing the duplicate struct listings from `proxy.md` and keeping it as a high-level overview only.

- **proxy_cache.md**: Significantly outdated. Struct definitions (`ProxyCacheEntry`, `CacheHit`, `ProxyCacheSettings`, `ProxyCache`) don't match current code. The document describes a simpler cache that has since been enhanced with circuit breakers, revalidation tracking, disk persistence, and site-level memory accounting.

- **proxy.md line 265-267**: References `http_shared.md` — need to verify this document exists.

- **routing_deep_dive.md lines 50, 65**: External GitHub URLs for code references should be replaced with local file paths.

## Cross-Reference Status

- **AGENTS.md "BUG-PROXY-1 Regression"**: Still accurate — `retry_config` fix at `mod.rs:303` confirmed.
- **AGENTS.md "HTTP2-POOL" deferred item**: Still accurate — `Http2PooledConnection` at `erased_pool.rs:124-127` is an empty stub.
- **AGENTS.md "PR-6 ProxyHeadersConfig not passed"**: Partially addressed — `proxy_headers_config` field exists on `ProxyServer` and `with_proxy_headers_config()` builder method exists (`mod.rs:230-236`), but `dispatch_to_upstream()` still clones from request headers rather than using the config. Doc's "Decision" comment at `proxy_deep_dive.md:271-275` is still accurate.
- **AGENTS.md "WRK-BUG-1 is_http2 to executor/dispatch"**: Still accurate — `is_http2` flows through `ProxyExecutor` and `DispatchParams`.
- **AGENTS.md "SiteConnectionLimiter dead code"**: Verified as fixed — no `SiteConnectionLimiter` struct found in `waf/traffic_shaper/limiter.rs`.
- **AGENTS.md "BUG-ROUTER-1"**: Not relevant to proxy/routing module review.
