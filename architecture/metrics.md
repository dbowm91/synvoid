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
    pub total_requests: AtomicU64,
    pub blocked: AtomicU64,
    pub challenged: AtomicU64,
    pub proxied: AtomicU64,
    pub errors: AtomicU64,
    pub current_concurrent: AtomicU64,
    pub peak_concurrent: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub request_count: AtomicU64,
    pub upstream_successes: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub latency_samples: Mutex<Vec<u64>>,
    pub blocked_by_type: Mutex<HashMap<AttackType, AtomicU64>>,
}

pub struct BandwidthTracker {
    pub total_bytes_received: AtomicU64,
    pub total_bytes_sent: AtomicU64,
    pub proxied_bytes_received: AtomicU64,
    pub proxied_bytes_sent: AtomicU64,
    pub blocked_bytes_sent: AtomicU64,
    pub challenged_bytes_sent: AtomicU64,
    pub error_bytes_sent: AtomicU64,
    pub http_bytes_received: AtomicU64,
    pub http_bytes_sent: AtomicU64,
    pub https_bytes_received: AtomicU64,
    pub https_bytes_sent: AtomicU64,
    pub http3_bytes_received: AtomicU64,
    pub http3_bytes_sent: AtomicU64,
    pub tcp_bytes_received: AtomicU64,
    pub tcp_bytes_sent: AtomicU64,
    pub udp_bytes_received: AtomicU64,
    pub udp_bytes_sent: AtomicU64,
    pub tunnel_bytes_received: AtomicU64,
    pub tunnel_bytes_sent: AtomicU64,
    pub mesh_bytes_received: AtomicU64,
    pub mesh_bytes_sent: AtomicU64,
    pub per_site: RwLock<HashMap<String, SiteBandwidth>>,
    pub per_upstream: RwLock<HashMap<String, UpstreamBandwidth>>,
    mesh_excluded: bool,
    ingress_rate: AtomicU64,
    egress_rate: AtomicU64,
    last_ingress_total: AtomicU64,
    last_egress_total: AtomicU64,
    last_rate_update: RwLock<Instant>,
    monthly_bytes_received: AtomicU64,
    monthly_bytes_sent: AtomicU64,
    monthly_period_start: RwLock<DateTime<Utc>>,
    monthly_reset_config: RwLock<MonthlyResetConfig>,
    persist_path: RwLock<Option<PathBuf>>,
    last_rollover_check: RwLock<Instant>,
}

pub struct WorkerMetrics {
    pub total_requests: AtomicU64,
    pub blocked: AtomicU64,
    pub challenged: AtomicU64,
    pub proxied: AtomicU64,
    pub errors: AtomicU64,
    pub current_concurrent: AtomicU64,
    pub peak_concurrent: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub request_count: AtomicU64,
    pub latency_samples: Mutex<Vec<u64>>,
    pub blocked_by_type: Mutex<HashMap<AttackType, AtomicU64>>,
    pub per_site: Mutex<HashMap<String, SiteMetrics>>,
    pub bandwidth: Arc<BandwidthTracker>,
    pub per_serverless: Mutex<HashMap<String, ServerlessMetrics>>,
}

// Global atomic counters (50+ LazyLock<AtomicU64> in src/metrics/collection.rs)
pub(crate) static PROXY_CACHE_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static PROXY_CACHE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static ACTIVE_STALLED_REQUESTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static STALL_REJECTED_CONCURRENCY_CAP: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static STALL_TIMEOUTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static STATIC_CACHE_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static STATIC_CACHE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_TLS_RELOAD_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_THREAT_LEVEL_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_PROCESS_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_WORKER_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_YARA_BROADCASTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
// ... plus 40+ more counters for TLS passthrough, honeypot, DHT, threat intel,
// behavioral fingerprint, serverless, and latency tracking
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
