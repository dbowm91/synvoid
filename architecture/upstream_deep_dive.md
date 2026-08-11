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
    pub fn select_backend(&self) -> Option<Arc<Backend>> {
        // 1. Filter primary backends by is_available()
        // 2. Apply algorithm
        // 3. If no primaries → fallback to backup backends
    }
    
    pub fn select_next_backend(&self, current: &Backend) -> Option<Arc<Backend>> {
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
pub fn record_latency(&self, latency: Duration) {
    let old = self.latency_ewma.load(Ordering::Relaxed);
    let new = latency.as_millis() as f64;
    let ewma = (old * 9.0 + new) / 10.0;
    self.latency_ewma.store(ewma as u64, Ordering::Relaxed);
}
```

## Connection Tracking

```rust
pub enum ConnectionCounter {
    Local(Arc<AtomicUsize>),  // Single-process
    Shared {                   // Multi-worker
        table: Arc<SharedConnectionTable>,
        backend_index: usize,
        worker_id: u32,
    },
}

// RAII guard
pub struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}
```

## Global Pool Registry

```rust
static GLOBAL_POOL_REGISTRY: Lazy<DashMap<String, Arc<UpstreamPool>>> = Lazy::new(DashMap::new);

pub fn get_or_create_global_pool(name: &str) -> Arc<UpstreamPool> {
    GLOBAL_POOL_REGISTRY
        .entry(name.to_string())
        .or_insert_with(|| UpstreamPool::new(name))
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
| `SharedConnectionTable` | `crates/synvoid-upstream/src/shared.rs` | Cross-worker connection sharing |
| `UpstreamAddress` | `crates/synvoid-upstream/src/address.rs` | Backend address |
