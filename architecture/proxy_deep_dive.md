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

The `ProxyServer::handle_request()` method integrates with WAF (lines 362-459):
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
  - `record_latency()` - EWMA latency tracking (90% weight)
  - `record_success()` / `record_failure()` - Circuit breaker with 3-failure threshold
  - `composite_load()` - (conn_load * 0.4) + (cpu_load * 0.6)

**`UpstreamPool`** (pool.rs:363-368)
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
| `typed_pool.rs` | Typed connection pool per (authority, body_type) |

### Connection Pooling Strategy

**Three layers**:
1. **Global client cache** (mod.rs:70-88) - Caches `HttpClient` by TLS config (100 entry, 5min TTL)
2. **Erased connection pool** (erased_pool.rs:218-303) - Per-host HTTP/1.1 connection reuse with checkout/checkin
3. **Typed connection pool** (typed_pool.rs:59-94) - Per-(authority, body_type) client caching

The erased pool is used for true streaming at 1M RPS scale to avoid per-request boxing overhead.

### TLS Configuration

- Uses `rustls` with `aws_lc_rs` crypto provider
- `build_tls_config()` - Configures root store, loads CA certs
- `HostnameSkippingVerifier` - Wraps WebPkiServerVerifier to skip hostname check but still validate chain

### Key Structs

**`StreamingWafBody<B>`** (mod.rs:133-223)
- Body wrapper that performs WAF scanning on chunks during streaming
- Fields: inner (B), streaming_waf, client_ip, blocked, error_sent
- `poll_frame()` - Inspects each chunk via `sw.scan_chunk()` and blocks if WAFDecision::Block

**`ErasedHttpClient`** (erased_pool.rs:321-370)
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
- `PoolKey` uses authority + http2 flag for connection multiplexing

### Distributed Load Balancing
- `SharedConnectionTable` via mmap for cross-worker connection counting
- Worker heartbeat mechanism (10s timeout) for liveness

### Stale-While-Revalidate
- Background revalidation with semaphore limiting concurrent revalidations
- Returns stale content immediately, updates in background

---

## Related Documentation

- [Overview](overview.md) - Bird's eye view of SynVoid architecture
- [WAF Deep Dive](waf_deep_dive.md) - WAF integration with proxy
- [Networking Deep Dive](networking_deep_dive.md) - HTTP client networking details