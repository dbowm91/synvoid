# Upstream Module Architecture

## 1. Purpose and Responsibility

The `upstream` module provides **upstream connection pooling, load balancing, and health checking** for the SynVoid proxy. It is responsible for:

- Managing connections to backend origin servers
- Distributing request load across multiple backends using various algorithms
- Monitoring backend health and performing automatic failover
- Supporting multiple protocols (HTTP, HTTPS, WebSocket, gRPC, QUIC tunnel, TCP)
- Sharing connection state across multiple worker processes via memory-mapped files

**Module location**: `src/upstream/`

## 2. Submodules and Responsibilities

| Submodule | File | Responsibility |
|-----------|------|----------------|
| `address` | `address.rs` | Parse and manage upstream endpoint addresses (TCP, Unix socket, QUIC tunnel) |
| `health` | `health.rs` | Periodic health checking with configurable methods and thresholds |
| `pool` | `pool.rs` | Core upstream pool management, load balancing, backend selection |
| `shared_state` | `shared_state.rs` | Cross-process shared memory for distributed connection counting |

### 2.1 address.rs - Upstream Address Management

Handles parsing and connecting to various upstream address types:

```
UpstreamAddress
├── Tcp(SocketAddr)           # IPv4/IPv6 with port
├── Unix(PathBuf)              # Unix domain socket path
└── QuicTunnel { peer, port }  # QUIC tunnel proxy endpoint
```

**Key types**:
- `UpstreamError`: Enum with variants for `InvalidAddress`, `ParseError`, `ConnectionError`, `SocketNotFound`
- `SocketErrorTracker`: Rate-limits error logging for Unix sockets (1st-3rd error always logged, then increasingly infrequent)
- `QuicTunnelStream`: Wraps QUIC send/recv streams with peer metadata

**Connection methods**:
- `connect_tcp_stream()`: TCP connection
- `connect_unix_stream()`: Unix socket connection  
- `connect_quictunnel_stream()`: QUIC tunnel streams
- `connect_quictunnel_tcp()`: QUIC tunnel as TCP-like stream

### 2.2 health.rs - Health Checking

Provides periodic health monitoring with configurable failure/recovery thresholds:

```
HealthChecker
├── pools: Arc<RwLock<Vec<Arc<UpstreamPool>>>>  # Registered pools to check
├── config: HealthCheckConfig                    # Check parameters
├── shutdown_tx: broadcast::Sender<()>          # Graceful shutdown
└── client: HttpClient                           # HTTP client for checks
```

**HealthCheckConfig defaults**:
```rust
interval_secs: 10        # Check interval
timeout_secs: 5         # Per-backend timeout
failure_threshold: 3    # Mark unhealthy after 3 consecutive failures
recovery_threshold: 2   # Mark healthy after 2 consecutive successes
health_check_path: "/"  # Path to request
health_check_method: Head  # HEAD or GET HTTP, or TCP connect
max_load_percent: 80.0  # Max load to consider healthy
```

**HealthCheckMethod variants**: `Head`, `Get`, `Tcp`

**Health check flow**:
1. Timer fires every `interval_secs`
2. Collects all backends from registered pools
3. Runs health checks in parallel via `futures::join_all`
4. Updates `consecutive_failures` / `consecutive_successes` counters
5. Marks backend healthy/unhealthy based on thresholds
6. Emits `synvoid.upstream.backend_recovered` / `synvoid.upstream.backend_unhealthy` metrics

### 2.3 pool.rs - Core Pool Management

Core data structures and pool management:

```
UpstreamPool
├── backends: Arc<RwLock<Vec<Backend>>>        # All backends (primary + backup)
├── algorithm: LoadBalanceAlgorithm           # Load balancing strategy
├── round_robin_index: AtomicUsize            # Round-robin counter
├── health_check_task: RwLock<Option<JoinHandle<()>>>  # Health check task handle
└── health_check_config: RwLock<Option<HealthCheckConfig>>
```

```
Backend
├── url: Arc<String>                          # Backend URL
├── weight: u32                               # Weight for weighted algorithms
├── max_connections: usize                    # Connection limit
├── current_connections: ConnectionCounter    # Active connection count
├── is_healthy: RunningFlag                   # Health status flag
├── consecutive_failures: Arc<AtomicU32>      # Failure counter
├── consecutive_successes: Arc<AtomicU32>     # Recovery counter
├── protocol: BackendProtocol                 # Protocol type
├── is_backup: bool                           # Backup flag
├── cpu_percent: Arc<AtomicU32>               # CPU usage (0-10000 -> 0.0-100.0%)
├── memory_percent: Arc<AtomicU32>            # Memory usage
└── latency_ewma: Arc<AtomicUsize>            # Exponential moving average latency (ms)
```

**ConnectionCounter**: Supports both local atomic counter and shared memory counter:
```rust
ConnectionCounter
├── Local(Arc<AtomicUsize>)                    # Single-process counter
└── Shared { table, backend_index, worker_id } # Cross-process shared memory
```

### 2.4 shared_state.rs - Cross-Process State Sharing

Memory-mapped shared tables for multi-worker load balancing:

**SharedConnectionTable layout**:
```
[0..8]:                              max_workers (u64)
[8..16]:                             max_backends (u64)
[16..16 + max_workers * 8]:          heartbeats (AtomicU64) [worker_id]
[16 + max_workers * 8 ..]:           connections (AtomicUsize) [worker_id][backend_index]
```

- Uses `memmap2::MmapMut` for persistent shared memory
- Heartbeat timeout: 10 seconds (workers not updating heartbeat are considered dead)
- `sum_active_connections()` filters by heartbeat liveness before summing

**SharedRateLimitTable**: Cross-worker IP rate limiting (second/minute/5min counters)

**Global initialization**:
- `SharedConnectionTable::init_global(path, max_workers, max_backends)`
- `SharedConnectionTable::get_global() -> Option<SharedConnectionTable>`
- Same pattern for `SharedRateLimitTable`

## 3. Major Data Structures and Types

### Load Balancing Algorithms

```rust
pub enum LoadBalanceAlgorithm {
    RoundRobin,        // Default - cyclic selection
    Random,            // Random selection
    LeastConnections,  // Lowest composite load (connections + CPU)
    PeakEwma,          // (conn+1) * (latency+1) cost minimization
    WeightedRoundRobin, // Weight-proportional cycling
    IpHash,            // Hash of client IP for session affinity
}
```

### Backend Protocols

```rust
pub enum BackendProtocol {
    Http,       // Plain HTTP
    Https,      // HTTP over TLS
    WebSocket,  // WS upgrade
    Wss,        // WSS over TLS
    Grpc,       // gRPC over HTTP
    GrpcTls,    // gRPC over TLS
    Tcp,        // Raw TCP proxy
    QuicTunnel, // QUIC tunnel proxy
}
```

### ConnectionGuard

RAII guard for connection scope management:
```rust
pub struct ConnectionGuard<'a> {
    backend: &'a Backend,
}

impl Drop for ConnectionGuard<'a> {
    fn drop(&mut self) {
        self.backend.decrement_connections();
    }
}
```

**Usage pattern**:
```rust
let _guard = backend.connection_scope();
// Connection automatically decremented when _guard goes out of scope
```

### UpstreamMetrics

Pool-level aggregated metrics:
```rust
pub struct UpstreamMetrics {
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub unhealthy_backends: usize,
    pub total_connections: usize,
    pub average_load: f64,
}
```

## 4. Key APIs and Entry Points

### Module Public API (`src/upstream/mod.rs`)

```rust
// Address types
pub use address::{QuicTunnelStream, SocketErrorTracker, UpstreamAddress, UpstreamError};

// Health checking
pub use health::{HealthCheckConfig, HealthCheckMethod, HealthChecker};

// Pool types
pub use pool::{Backend, BackendProtocol, LoadBalanceAlgorithm, UpstreamMetrics, UpstreamPool};

// Shared state
pub use shared_state::SharedConnectionTable;
```

### UpstreamPool Methods

**Construction**:
```rust
UpstreamPool::new(urls: Vec<String>, algorithm: LoadBalanceAlgorithm) -> Self
UpstreamPool::new_with_backup(urls, backup_urls, algorithm) -> Self
```

**Backend selection**:
```rust
select_backend() -> Option<Backend>           // Normal selection (primaries then backups)
try_select_backend() -> Option<Backend>        // Try-read variant
select_next_backend(current: &Backend) -> Option<Backend>  // Failover to next
select_backend_for_ip(client_ip: &str) -> Option<Backend>   // IP hash specific
select_backend_for_protocol(protocol: BackendProtocol) -> Option<Backend>
```

**Pool mutation**:
```rust
add_backend(url: String)
add_backend_with_protocol(url: String, protocol: BackendProtocol)
add_backend_with_weight(url: String, weight: u32, protocol: BackendProtocol)
remove_backend(url: &str)
mark_healthy(url: &str)
mark_unhealthy(url: &str)
mark_failed(url: &str)  // Records failure, triggers circuit breaker
```

**Health check control**:
```rust
enable_health_check(config: HealthCheckConfig)
start_health_check(self: Arc<Self>)  // Spawns background task
stop_health_check()
```

**Metrics**:
```rust
get_metrics() -> UpstreamMetrics
get_backends() -> RwLockReadGuard<'_, Vec<Backend>>
```

### Backend Methods

**Connection management**:
```rust
is_available() -> bool  // healthy && connections < max
increment_connections()
decrement_connections()
connection_scope() -> ConnectionGuard  // RAII guard
load() -> f64  // connections / max_connections
```

**Health tracking**:
```rust
record_success()   // Increments consecutive_successes, recovers at threshold
record_failure()   // Increments consecutive_failures, trips at 3
record_latency(duration: Duration)  // Updates EWMA latency
```

**Load metrics**:
```rust
composite_load() -> f64  // 0.4 * conn_load + 0.6 * cpu_load
get_cpu_percent() -> f32
set_cpu_percent(f32)
get_memory_percent() -> f32
set_memory_percent(f32)
get_latency_ewma() -> usize
```

**Protocol queries**:
```rust
supports_grpc() -> bool
supports_websocket() -> bool
```

### Global Pool Registry

```rust
get_global_pool(backend_url: &str) -> Option<Arc<UpstreamPool>>
get_or_create_global_pool(backend_url: &str, algorithm: LoadBalanceAlgorithm) -> Arc<UpstreamPool>
remove_global_pool(backend_url: &str)
clear_global_pools()
get_global_pool_count() -> usize
```

### HealthChecker Methods

```rust
HealthChecker::new(config: HealthCheckConfig) -> Self
register_pool(pool: Arc<UpstreamPool>) -> Future   // Async registration
start() -> Future                                   // Starts background checks
shutdown()                                          // Signals shutdown
```

## 5. How Upstream Pool Works

### Pool Initialization

1. `UpstreamPool::new()` creates backends from URL list
2. Each `Backend` is constructed with `Backend::new_internal()`
3. `ConnectionCounter` is set to either:
   - **Local**: If no `SharedConnectionTable` is global
   - **Shared**: If global table exists (hash URL to backend_index, use worker_id)
4. Backends are stored in `Arc<RwLock<Vec<Backend>>>`

### Backend Selection Flow

```
select_backend()
├── Read backends
├── filter_candidates(backup_only=false)  // Only non-backup, available
├── If candidates empty:
│   └── filter_candidates(backup_only=true)  // Fall back to backups
├── apply_algorithm(candidates)
│   └── Match algorithm type:
│       ├── RoundRobin: round_robin_index % len
│       ├── Random: rng.random_range(0..len)
│       ├── LeastConnections: min by composite_load
│       ├── PeakEwma: min by (conn+1)*(latency+1)
│       ├── WeightedRoundRobin: weighted cycling
│       └── IpHash: client_ip_hash % len
└── Return selected Backend clone
```

### Connection Counting

**Local mode**:
- Simple `AtomicUsize` incremented/decremented
- `fetch_add(1, Relaxed)` for increment
- `fetch_update(Relaxed, Relaxed, |v| v.checked_sub(1))` for decrement (prevents underflow)

**Shared mode**:
- Uses mmap-based `SharedConnectionTable`
- `sum_active_connections(backend_index, 10)` checks heartbeat timeout
- Only counts workers with heartbeat within 10 seconds as live

### Circuit Breaker Behavior

**Failure path**:
```rust
record_failure()
├── consecutive_successes = 0
├── consecutive_failures += 1
└── if failures >= 3 && is_healthy:
    is_healthy.set(false)  // Mark unhealthy
    tracing::warn!("Backend marked unhealthy")
```

**Recovery path**:
```rust
record_success()
├── consecutive_failures = 0
├── consecutive_successes += 1
└── if successes >= 3 && !is_healthy:
    is_healthy.set(true)  // Mark healthy
```

**Availability check**:
```rust
is_available() -> bool
└── is_healthy.is_running() && connections < max_connections
```

### ConnectionScope RAII Pattern

```rust
impl Backend {
    pub fn connection_scope(&self) -> ConnectionGuard {
        self.increment_connections();
        ConnectionGuard { backend: self }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.backend.decrement_connections();
    }
}
```

Usage ensures connection counts are always decremented, even on panic.

## 6. Health Check Implementation

### Initialization

```rust
HealthChecker::new(config)
├── Create broadcast channel for shutdown signal
├── Create HTTP client with configured timeout (timeout_secs)
├── Initialize pools RwLock (empty)
└── Clone config for later use
```

### Pool Registration

```rust
register_pool(pool)
└── pools.write().await.push(pool)
```

### Health Check Loop

```rust
start()
├── Clone config, pools, client, shutdown_rx
├── Spawn async task:
│   loop:
│   ├── timer.tick() -> check_all_pools()
│   └── shutdown_rx.recv() -> break
└── Log startup
```

### Check Execution

```
check_all_pools()
├── Collect all backends from all pools (Arc<Backend> clones)
├── If empty: return early
├── Create parallel tasks via join_all:
│   └── check_backend(backend, config, client) for each
├── For each result (backend, is_healthy):
    └── if is_healthy:
        ├── if !is_healthy.is_running():
        │   └── successes += 1
        │   └── if successes >= recovery_threshold:
        │       ├── is_healthy.set(true)
        │       ├── failures = 0
        │       └── counter("backend_recovered")
    └── else (unhealthy):
        ├── failures += 1
        └── if failures >= failure_threshold && is_running:
            ├── is_healthy.set(false)
            └── counter("backend_unhealthy")
```

### Per-Backend Check

```rust
check_backend(backend, config, client)
└── match config.health_check_method:
    ├── Head | Get -> http_health_check()
    │   ├── Build URL: backend.url + health_check_path
    │   ├── Send HEAD or GET request with timeout
    │   ├── Success if status 200-399
    │   └── Failure logs debug message
    └── Tcp -> tcp_health_check()
        ├── Parse address via UpstreamAddress::parse()
        └── Connect with 5s timeout, success if Ok(Ok(_))
```

### TCP Health Check

```rust
tcp_health_check(backend)
├── UpstreamAddress::parse(backend.url)
└── tokio::time::timeout(5s, addr.connect_tcp_stream())
    └── Ok(Ok(_)) = healthy, anything else = unhealthy
```

## 7. Feature Gates

The upstream module has **no feature gates** - it is always compiled. However, the module is used by components that have feature gates:

| Downstream Component | Feature Gate |
|---------------------|--------------|
| DNS server | `dns` |
| Mesh networking | `mesh` |
| QUIC tunnel proxy | (always on) |

**Global pool registry** (`GLOBAL_POOL_REGISTRY`):
- `dashmap::DashMap<String, Arc<UpstreamPool>>`
- Initialized lazily on first access
- Used for cross-cutting upstream pool management (e.g., admin API, mesh topology)

### URL Validation

The module validates upstream URLs at construction time:

```rust
const ALLOWED_SCHEMES: &[&str] = &["http", "https", "ws", "wss", "grpc", "grpcs"];

validate_upstream_url(url)
├── Empty check -> Error
├── Relative path ("/" or "./") -> OK (passthrough)
├── Missing scheme without ":" -> Error
├── Scheme not in ALLOWED_SCHEMES -> Error
└── Unsafe schemes (file://, ftp://, gopher://) -> Error
```

## 8. Relationship to Other Modules

### Used By

| Module | Usage |
|--------|-------|
| `proxy/executor.rs` | UpstreamPool for backend selection |
| `proxy/mod.rs` | ProxyServer holds UpstreamPool |
| `http/server.rs` | PreparedUpstreamTarget for upstream routing |
| `http3/server.rs` | HTTP/3 upstream requests |
| `tls/server.rs` | TLS passthrough to upstream |
| `admin/handlers/upstreams.rs` | Admin API for pool management |
| `mesh/transport_peer.rs` | Mesh DHT topology upstream info |

### Dependencies

| Module | Purpose |
|--------|---------|
| `http_client` | HTTP health checks |
| `tunnel.quic` | QUIC tunnel stream connections |
| `process` | Worker ID for shared connection table |
| `metrics` | Backend healthy/unhealthy counters |
| `tokio` | Async runtime, intervals, spawn |

## 9. Global Pool Registry

The module maintains a process-wide registry of upstream pools:

```rust
static GLOBAL_POOL_REGISTRY: LazyLock<DashMap<String, Arc<UpstreamPool>>> =
    LazyLock::new(DashMap::new);
```

This enables:
- Admin API to list/manage all pools
- Mesh topology to share upstream info
- Dynamic pool creation on demand

**Key functions**:
```rust
get_global_pool(backend_url) -> Option<Arc<UpstreamPool>>
get_or_create_global_pool(backend_url, algorithm) -> Arc<UpstreamPool>
remove_global_pool(backend_url)
clear_global_pools()
get_global_pool_count()
```

## 10. Thread Safety and Concurrency

| Type | Concurrency Model |
|------|-------------------|
| `UpstreamPool.backends` | `Arc<RwLock<Vec<Backend>>>` - Multiple readers, exclusive writer |
| `UpstreamPool.round_robin_index` | `AtomicUsize` - Lock-free |
| `Backend.is_healthy` | `RunningFlag` - Atomic boolean-like |
| `Backend.counters` | `AtomicU32`, `AtomicUsize` - Lock-free |
| `ConnectionCounter::Shared` | Memory-mapped shared memory - Cross-process |

**No parking_lot RwLock for backend iteration**: Uses `parking_lot::RwLockReadGuard` returned by `get_backends()` for external iteration.
