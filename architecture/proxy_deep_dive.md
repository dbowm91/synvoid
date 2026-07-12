# Proxy & Upstream Deep Dive

## Overview

This document covers the reverse proxy module (`src/proxy/`), backend management (`src/upstream/`), and HTTP client (`src/http_client/`).

---

## 1. Proxy Module (`src/proxy/`)

### Purpose

End-to-end handling of proxied HTTP/HTTPS requests including upstream selection, load balancing, header filtering, caching, retry logic, and WAF integration.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | Main `ProxyServer` struct, request handling entry point, WAF integration, cache routing |
| `dispatch.rs` | Low-level request dispatch to upstream with `DispatchParams` |
| `executor.rs` | Request execution with caching (`ProxyExecutor`), upstream target preparation |
| `retry.rs` | Retry logic, backoff calculation, idempotent method detection |
| `cache.rs` | Cache response building, header filtering, max-age parsing |
| `headers.rs` | Forward headers construction, XFF sanitization, hop-by-hop stripping |
| `streaming.rs` | `TeeBody` - streaming body wrapper that tees data for caching |
| `governor.rs` | `GlobalCacheGovernor` - memory limiter for concurrent cache buffering (512MB default) |
| `client_registry.rs` | Per-site HTTP client caching to avoid recreating clients |

### Security boundary notes

- Forwarded-header and mesh-upstream validation share the restricted-address
  classifier in `synvoid-core`. It rejects private, link-local, unique-local,
  multicast, shared-address, benchmarking, unspecified, and reserved ranges,
  including the full `fd00::/8` and `225.0.0.0/8` subranges that are easy to
  miss with exact-prefix comparisons.
- IPv4 CIDR matching treats `/0` as a valid prefix. Prefix helpers must not
  shift by 32 when processing operator-supplied proxy or feed configuration.
- `X-Forwarded-For` is rebuilt from validated public addresses and is bounded
  to `MAX_XFF_CHAIN_LENGTH`; client-supplied forwarding headers are never
  trusted as-is.

### Main Structs

**`ProxyServer`** (mod.rs:73-94)
- Central orchestrator for proxy operations
- Holds `HttpClient`, `ErasedHttpClient`, upstream pool, cache, WAF reference
- Key methods:
  - `handle_request()` - Main entry point with WAF checking
  - `handle_request_with_cache()` - Cache-aware request handling with PURGE support
  - `forward_with_pool()` - Retry loop with backend selection

**`DispatchParams`** (dispatch.rs:12-22)
- Bundles all parameters needed for upstream dispatch
- Contains client, method, upstream_url, body, headers, timeout, forwarded protocol

**`ProxyExecutor`** (executor.rs:96-103)
- Caching-aware request executor
- `execute_with_cache()` - Cache lookup + forward with revalidation

**`TeeBody<B>`** (streaming.rs:12-22)
- Body wrapper that streams data while buffering for cache
- Integrates with `GlobalCacheGovernor` for memory management
- On stream completion, inserts into cache if buffer complete

**`GlobalCacheGovernor`** (governor.rs:8-54)
- Global memory limiter for cache buffering operations
- Uses atomic compare-exchange for reservation tracking
- Default 512MB limit, configurable

### WAF Integration

The `ProxyServer::handle_request()` method integrates with WAF (lines 371-481):
1. Collects request body (up to 1MB for WAF inspection)
2. Calls `waf.check_request_full()` with path, query, headers, body
3. Handles WAF decisions: Drop, Stall, Block, Challenge, ChallengeWithCookie, Tarpit, Pass
4. On `UpstreamErrorTracker` errors, can auto-ban IPs doing upstream vulnerability probing

### Request Flow

```
handle_request()
  ├─> WAF check (if not skipped)
  │     └─> WafDecision handling
  ├─> forward_request() or handle_request_with_cache()
  │     ├─> [Cache lookup] ──HIT──> build_cached_response()
  │     │
  │     ├─> [Cache lookup] ──MISS──> forward_with_pool()
  │     │                              ├─> select_backend()
  │     │                              ├─> send_single_request() via ErasedHttpClient
  │     │                              ├─> on failure: mark_failed(), retry with backoff
  │     │                              └─> [Response] ──cacheable──> TeeBody streaming
  │     │
  │     └─> [No pool] ──> send_single_request() to single upstream
  │
  └─> [Response] with upstream error tracking
```

---

## 2. Upstream Module (`src/upstream/`)

### Purpose

Backend address management, load balancing algorithms, health checking, and distributed connection tracking.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | Module exports, re-exports types |
| `pool.rs` | `UpstreamPool`, `Backend`, load balancing algorithms |
| `address.rs` | `UpstreamAddress`, `SocketErrorTracker`, `QuicTunnelStream` |
| `health.rs` | `HealthChecker`, `HealthCheckConfig` |
| `shared_state.rs` | `SharedConnectionTable`, `SharedRateLimitTable` (mmap-based) |

### Main Structs

**`Backend`** (pool.rs:140-154)
- Individual upstream server representation
- Fields: url, weight, max_connections, current_connections, is_healthy, consecutive_failures/successes, protocol, is_backup, cpu/memory_percent, latency_ewma
- Key methods:
  - `is_available()` - Healthy + under connection limit
  - `connection_scope()` - RAII guard that increments/decrements connections
  - `record_latency()` - EWMA latency tracking (90% weight to previous value for slow-moving EWMA: `(old_ewma * 9 + latency_ms) / 10`)
  - `record_success()` / `record_failure()` - Circuit breaker with 3-failure threshold
  - `composite_load()` - (conn_load * 0.4) + (cpu_load * 0.6)

**`UpstreamPool`** (pool.rs:375-380)
- Manages collection of backends with load balancing
- Key methods:
  - `select_backend()` - Primary selection
  - `select_next_backend(current)` - Failover selection (skips current)
  - `add_backend()` / `remove_backend()` - Dynamic management
  - `mark_healthy()` / `mark_unhealthy()` - State management
  - `get_metrics()` - Aggregate upstream metrics

**`LoadBalanceAlgorithm`** (pool.rs:47-56)
- Enum: RoundRobin (default), Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash
- PeakEwma uses cost = (connections + 1) * (latency + 1)

**`HealthChecker`** (health.rs:10-15)
- Background health check runner
- Registers pools, runs periodic checks via `tokio::time::interval`
- Supports HEAD, GET, and TCP health check methods
- Configurable failure_threshold (3) and recovery_threshold (2)

**`SharedConnectionTable`** (shared_state.rs:20-25)
- mmap-based shared memory for cross-worker load balancing
- Layout: [max_workers:u64][max_backends:u64][heartbeats:AtomicU64][connections:AtomicUsize]
- `record_heartbeat()` - Worker liveness signaling
- `sum_active_connections()` - Aggregate connections across live workers (10s timeout)

### Circuit Breaker Pattern

- 3 consecutive failures marks backend unhealthy
- 3 consecutive successes marks backend healthy again
- Tracked via `consecutive_failures` / `consecutive_successes` atomic counters

---

## 3. HTTP Client Module (`src/http_client/`)

### Purpose

TLS-configurable HTTP client creation, connection pooling, request sending utilities, QUIC tunnel support.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | Main client creation, TLS config, request utilities, `StreamingWafBody` |
| `erased_pool.rs` | Type-erased connection pool for 1M RPS scale |

### Connection Pooling Strategy

**Two layers**:
1. **Global client cache** (lib.rs) - Caches `HttpClient` by TLS config (100 entry, 5min TTL)
2. **Erased connection pool** (erased_pool.rs) - Per-host HTTP/1.1 connection reuse with checkout/checkin

The erased pool is used for true streaming at 1M RPS scale to avoid per-request boxing overhead.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Two-Layer Connection Pooling                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Global Client Cache (lib.rs)                      │   │
│  │  ┌─────────────────────────────────────────────────────────┐ │   │
│  │  │  HttpClient (TLS config → 100 entry, 5min TTL cache)   │ │   │
│  │  └─────────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 2: Erased Connection Pool (erased_pool.rs)           │   │
│  │  ┌─────────────────────────────────────────────────────────┐ │   │
│  │  │  PoolKey: (authority, is_http2)                        │ │   │
│  │  │  ErasedConnectionPool → HashMap<PoolKey, VecDeque>     │ │   │
│  │  │  • checkout() → reuse or connect new                   │ │   │
│  │  │  • checkin() → return to pool if under max_idle        │ │   │
│  │  └─────────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### TLS Configuration

- Uses `rustls` with `aws_lc_rs` crypto provider
- `build_tls_config()` - Configures root store, loads CA certs
- `HostnameSkippingVerifier` - Wraps WebPkiServerVerifier to skip hostname check but still validate chain

### Key Structs

**`StreamingWafBody<B>`** (mod.rs:133-223)
- Body wrapper that performs WAF scanning on chunks during streaming
- Fields: inner (B), streaming_waf, client_ip, blocked, error_sent
- `poll_frame()` - Inspects each chunk via `sw.scan_chunk()` and blocks if WAFDecision::Block

**`ErasedHttpClient`** (erased_pool.rs:415-456)
- HTTP client using erased connection pool
- `send_request()` - Checkout → send → checkin pattern

---

## Notable Architecture Patterns

### Memory Management
- `GlobalCacheGovernor` - Atomic-based global memory reservation for cache buffering
- `TeeBody` reserves memory upfront, releases on drop

### Streaming with Cache
- `TeeBody` implements `http_body::Body` and streams while buffering
- On stream completion, inserts into cache if buffer complete and within limits

### Type Erasure for Performance
- `ErasedBody` / `ErasedHttpClient` avoid per-request boxing at 1M RPS
- `PoolKey` uses `(authority, is_http2)` tuple for connection multiplexing (Hash derive at `erased_pool.rs:112`)

### Distributed Load Balancing
- `SharedConnectionTable` via mmap for cross-worker connection counting
- Worker heartbeat mechanism (10s timeout) for liveness

### Stale-While-Revalidate
- Background revalidation with **semaphore-based limiting** (`revalidation_semaphore` at `proxy_cache/store.rs:156`)
- Default 100 concurrent revalidations (configurable via `max_concurrent_revalidations` in `ProxyCacheSettings`)
- Circuit breaker after `revalidation_failure_threshold` failures (default 10), with cooldown period
- Returns stale content immediately, updates in background

---

## Related Documentation

- [Overview](overview.md) - Bird's eye view of SynVoid architecture
- [WAF Deep Dive](waf_deep_dive.md) - WAF integration with proxy
- [Networking Deep Dive](networking_deep_dive.md) - HTTP client networking details

---

## Implementation Decisions (Wave 4.2)

// Decision: HTTP/2 is configurable via ProxyServer::with_http2() builder method.
// The site_config.proxy.http2 value is wired through to control HTTP/2 usage.
// HTTP/2 upstream pooling (Http2PooledConnection) remains a deferred item (HTTP2-POOL)
// due to hyper-util API limitations.

// Decision: UpstreamClientRegistry is integrated but not used in ProxyServer::send_single_request.
// The registry exists at src/proxy/client_registry.rs and is instantiated in http/server.rs,
// http3/server.rs, and tls/server.rs for streaming client management. The ProxyServer flow
// uses ErasedHttpClient directly via send_request_erased_streaming. The registry remains
// available for future typed client management but is not currently required.

// Decision: ProxyHeadersConfig (proxy_headers field) is not passed through send_single_request
// at proxy/mod.rs:1225-1238. The forward_headers are cloned from the incoming request headers.
// Custom proxy headers per upstream are not currently supported; this can be addressed in a
// future enhancement by extending send_request_erased_streaming to accept a ProxyHeadersConfig
// parameter. Tracking: [PR-6] - Enhancement tracking ticket needed.

// BUG-PROXY-1 Regression: retry_config was not being applied in send_single_request flow.
// Fixed at proxy/mod.rs:303 - now uses the parameter value instead of None. This fix ensures
// that retry configuration (max_retries, retryable_methods, retry_on_status) is properly
// passed to the retry logic. Test coverage added via integration tests validating the
// retry_config flow end-to-end.
