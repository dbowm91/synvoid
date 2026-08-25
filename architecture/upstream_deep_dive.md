# Upstream Deep Dive

SynVoid's upstream crate manages backend server pools with health checking, load balancing, and connection tracking.

## Load Balancing Algorithms

| Algorithm | Implementation | Behavior |
|-----------|---------------|----------|
| **RoundRobin** | Atomic index increment | Default, simple rotation |
| **Random** | `rand::rng().random_range()` | Uniform random selection |
| **LeastConnections** | Composite load (40% connections + 60% CPU) | Prefer least loaded |
| **PeakEwma** | `(connections + 1) * (latency_ewma + 1)` | Balance latency and load |
| **WeightedRoundRobin** | Modular arithmetic over cumulative weight | Weighted distribution |
| **IpHash** | `DefaultHasher` of client IP | Sticky sessions |

## Backend Selection

```rust
impl UpstreamPool {
    pub fn select_backend(&self) -> Option<Backend> {
        // 1. Filter primary backends by is_available()
        // 2. Apply algorithm
        // 3. If no primaries → fallback to backup backends
    }
    
    pub fn select_next_backend(&self, current: &Backend) -> Option<Backend> {
        // Failover excluding current backend
    }
}
```

## Health Checking

```rust
pub struct HealthChecker {
    interval: Duration,      // Default 10s
    timeout: Duration,       // Default 5s
    failure_threshold: u32,  // Default 3
    recovery_threshold: u32, // Default 2
}

pub enum HealthCheckMethod {
    Head,
    Get,
    Tcp,
}
```

### Circuit Breaker

```rust
impl Backend {
    pub fn record_failure(&self) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if self.consecutive_failures() >= 3 {
            self.is_healthy.store(false, Ordering::Relaxed);
        }
    }
    
    pub fn record_success(&self) {
        self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
        if self.consecutive_successes() >= 3 {
            self.is_healthy.store(true, Ordering::Relaxed);
        }
    }
}
```

### EWMA Latency

```rust
pub fn record_latency(&self, duration: Duration) {
    let latency_ms = duration.as_millis() as usize;
    let old_ewma = self.latency_ewma.load(Ordering::Relaxed);
    let new_ewma = if old_ewma == 0 {
        latency_ms
    } else {
        (old_ewma * 9 + latency_ms) / 10
    };
    self.latency_ewma.store(new_ewma, Ordering::Relaxed);
}
```

## Connection Tracking

```rust
pub enum ConnectionCounter {
    Local(Arc<AtomicUsize>),  // Single-process
    Shared {                   // Multi-worker
        table: SharedConnectionTable,
        backend_index: usize,
        worker_id: usize,
    },
}

// RAII guard
pub struct ConnectionGuard<'a> {
    backend: &'a Backend,
}

impl<'a> Drop for ConnectionGuard<'a> {
    fn drop(&mut self) {
        self.backend.decrement_connections();
    }
}
```

## Global Pool Registry

```rust
static GLOBAL_POOL_REGISTRY: LazyLock<DashMap<String, Arc<UpstreamPool>>> = LazyLock::new(DashMap::new);

pub fn get_or_create_global_pool(backend_url: &str, algorithm: LoadBalanceAlgorithm) -> Arc<UpstreamPool> {
    GLOBAL_POOL_REGISTRY
        .entry(backend_url.to_string())
        .or_insert_with(|| UpstreamPool::new(vec![backend_url.to_string()], algorithm))
        .clone()
}
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `UpstreamPool` | `crates/synvoid-upstream/src/pool.rs` | Backend pool |
| `Backend` | `crates/synvoid-upstream/src/pool.rs` | Individual backend |
| `ConnectionGuard` | `crates/synvoid-upstream/src/pool.rs` | RAII connection guard |
| `HealthChecker` | `crates/synvoid-upstream/src/health.rs` | Periodic health checks |
| `SharedConnectionTable` | `crates/synvoid-upstream/src/shared_state.rs` | Cross-worker connection sharing |
| `UpstreamAddress` | `crates/synvoid-upstream/src/address.rs` | Backend address |
