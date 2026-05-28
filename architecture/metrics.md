# Metrics Architecture

## 1. Purpose and Responsibility

The Metrics module (`src/metrics/`) provides **centralized metrics collection** with atomic counters, per-site metrics, worker metrics, bandwidth tracking, and health status reporting.

**Core Responsibilities:**
- Atomic counters for lock-free metrics updates
- Per-site request/error/block tracking
- Worker-level latency and throughput metrics
- Bandwidth monitoring per protocol
- Health status reporting

---

## 2. Key Data Structures

```rust
pub struct SiteMetrics {
    total_requests: AtomicU64,
    request_count: AtomicU64,
    blocked: AtomicU64,
    errors: AtomicU64,
    latency_sum: AtomicU64,
    latency_count: AtomicU64,
}

pub struct BandwidthTracker {
    inbound: AtomicU64,
    outbound: AtomicU64,
}

pub struct WorkerMetrics {
    requests_processed: AtomicU64,
    bytes_processed: AtomicU64,
    active_connections: AtomicU32,
}

// Global atomic counters
static PROXY_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static PROXY_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static STATIC_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `record_proxy_cache_hit()` | Increment cache hit counter |
| `record_proxy_cache_miss()` | Increment cache miss counter |
| `get_proxy_cache_hits()` | Read cache hits |
| `get_proxy_cache_misses()` | Read cache misses |
| `record_static_cache_hit()` | Static file cache hit |
| `record_static_cache_miss()` | Static file cache miss |
| `record_dropped_tls_reload_event()` | Track dropped events |
| `SiteMetrics::record_request_start()` | Start request timing |
| `SiteMetrics::record_request_end(latency)` | End request timing |
| `SiteMetrics::record_blocked()` | Track blocked requests |
| `get_global_bandwidth_tracker()` | Global bandwidth monitor |

---

## 4. Integration Points

- **HTTP Server**: Request lifecycle metrics
- **Proxy**: Cache hit/miss tracking
- **WAF**: Blocked request counting
- **Static Files**: Cache hit tracking
- **Admin API**: Metrics endpoints for dashboards
- **Bandwidth**: Protocol-level bandwidth monitoring

---

## 5. Key Implementation Details

- **Lock-free**: All counters use `AtomicU64`/`AtomicU32`
- **Per-site Isolation**: Each site has independent metrics
- **Latency Tracking**: Sum/count pattern for average calculation
- **Protocol Awareness**: Bandwidth tracked per protocol (HTTP, HTTP2, HTTP3)
- **Global Singletons**: Cache counters are process-wide
