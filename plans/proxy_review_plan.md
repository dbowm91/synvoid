# Proxy Architecture Review Plan

## Verified Correct

- **BackendType enum (11 variants)**: Confirmed at `src/router.rs:66-78`: Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin
- **LoadBalanceAlgorithm (6 variants)**: Confirmed at `src/upstream/pool.rs:48-57`: RoundRobin (default), Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash
- **PeakEwma cost formula**: Confirmed at `src/upstream/pool.rs:520-521`: `(conn + 1.0) * (latency + 1.0)`
- **Backend struct fields**: Confirmed at `src/upstream/pool.rs:153-167` with all documented fields (url, weight, max_connections, current_connections, is_healthy, consecutive_failures/successes, protocol, is_backup, cpu/memory_percent, latency_ewma)
- **Backend::is_available()**: Confirmed at `src/upstream/pool.rs:281-284`: checks `is_healthy.is_running() && current_connections < max_connections`
- **Backend::record_latency()**: Confirmed at `src/upstream/pool.rs:307-318`: `(old_ewma * 9 + latency_ms) / 10` (90% weight on old EWMA)
- **Backend circuit breaker**: Confirmed at `src/upstream/pool.rs:324-343`: 3 consecutive failures marks unhealthy, 3 consecutive successes marks healthy
- **Backend::composite_load()**: Confirmed at `src/upstream/pool.rs:367-373`: `(conn_load * 0.4) + (cpu_load * 0.6)`
- **HealthChecker defaults**: Confirmed at `src/upstream/health.rs:36-47`: failure_threshold=3, recovery_threshold=2, interval_secs=10, timeout_secs=5
- **GlobalCacheGovernor default**: Confirmed at `src/proxy/governor.rs:12`: `512 * 1024 * 1024` (512MB)
- **WAF body limit**: Confirmed at `src/proxy/mod.rs:353`: `const MAX_WAF_BODY_SIZE: usize = 1024 * 1024` (1MB)
- **WAF decisions**: Confirmed at `src/proxy/mod.rs:405-490`: Drop, Stall, Block, Challenge, ChallengeWithCookie, Tarpit, Pass
- **UpstreamErrorTracker auto-ban**: Confirmed at `src/proxy/mod.rs:512-540`: auto-bans IPs doing upstream vulnerability probing when `auto_ban_elevated_threat` is enabled
- **SharedConnectionTable layout**: Confirmed at `src/upstream/shared_state.rs:14-20`: [max_workers:u64][max_backends:u64][heartbeats:AtomicU64][connections:AtomicUsize] with 10s heartbeat timeout
- **PoolKey structure**: Confirmed at `src/http_client/erased_pool.rs:112-115`: `(authority: String, is_http2: bool)`
- **Three-layer connection pooling**: Confirmed at `src/http_client/mod.rs:67-88` (Global client cache: 100 entry, 5min TTL), `src/http_client/erased_pool.rs:224-250` (Erased connection pool), `src/http_client/typed_pool.rs:69-84` (Typed connection pool)
- **Stale-while-revalidate**: Confirmed at `src/proxy_cache/store.rs:223-225` with semaphore limiting concurrent revalidations
- **ProxyHeadersConfig not passed through**: Confirmed at `src/proxy/mod.rs:1225`: uses `headers.cloned().unwrap_or_default()` directly; custom proxy headers per upstream not supported
- **HTTP/2 hardcoded**: Confirmed at `src/http_client/mod.rs:893`: `let is_http2 = true;`
- **BUG-PROXY-1 FIXED**: Confirmed at `src/proxy/mod.rs:303`: `retry_config: retry_config.clone()` properly passes the retry_config parameter through `from_config()`
- **UpstreamClientRegistry instantiation**: Confirmed at `src/http/server.rs:136,403`, `src/http3/server.rs:27,79`, `src/tls/server.rs` (verified via grep)
- **Retry logic**: Confirmed at `src/proxy/retry.rs`: `is_retryable_status()` defaults to 502-504, `calculate_backoff()` caps at 30s, `should_retry_request()` checks idempotent methods
- **DispatchParams**: Confirmed at `src/proxy/dispatch.rs:12-22`
- **ProxyExecutor**: Confirmed at `src/proxy/executor.rs:96-103`
- **TeeBody**: Confirmed at `src/proxy/streaming.rs:12-22`
- **GlobalCacheGovernor**: Confirmed at `src/proxy/governor.rs:8-54`

## Discrepancies Found

- **ErasedHttpClient line numbers**: Document says `erased_pool.rs:321-370` but actual is `erased_pool.rs:415-456` for the struct definition and `erased_pool.rs:426-451` for `send_request()` method
- **ProxyExecutor line numbers**: Document says `executor.rs:96-103` but actual struct is at `executor.rs:96-103` - this is CORRECT, documentation is accurate for this item
- **TeeBody line numbers**: Document says `streaming.rs:12-22` but actual is `streaming.rs:12-22` - this is CORRECT
- **GlobalCacheGovernor line numbers**: Document says `governor.rs:8-54` but actual is `governor.rs:1-55` (struct starts at line 9 with impl block, but comment starts at line 5) - minor offset
- **Backend line numbers**: Document says `pool.rs:140-154` but actual is `pool.rs:153-167` - minor offset of ~13 lines

## Bugs Identified

- **HTTP/2 not enforced but hardcoded true (Medium)**: At `src/http_client/mod.rs:893`, `is_http2 = true` is hardcoded in `send_request_erased_streaming`. The infrastructure for HTTP/2 exists (Http2PooledConnection, `enable_http2()`, `http2_only(false)`), but upstream HTTP/2 pooling is not actually implemented. This is documented as a "Known" issue in AGENTS.md.

## Suggested Improvements

1. **Update line number references**: Several struct and method line numbers in the document are outdated. Consider using relative anchors orperiodic verification to keep them accurate.
2. **Document the semaphore-based SWR limiting**: The stale-while-revalidate concurrent limit uses `max_concurrent_revalidations` setting but the actual limit value is not clearly documented.
3. **Add test coverage for retry_config flow**: The BUG-PROXY-1 fix should have corresponding test coverage to prevent regression, particularly testing that `from_config` properly propagates retry_config.
4. **Clarify EWMA weight documentation**: The phrase "EWMA latency tracking (90% weight)" is ambiguous. Consider clarifying as "90% weight given to historical value" or "10% smoothing factor".
5. **Document PoolKey hashing**: The PoolKey uses `(authority, is_http2)` for connection multiplexing but this detail is not clearly documented in the architecture.
6. **Add ProxyHeadersConfig enhancement tracking**: The limitation that custom proxy headers per upstream are not supported should be tracked as a feature request with a ticket ID.
