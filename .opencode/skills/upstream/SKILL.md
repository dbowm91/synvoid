---
name: upstream
description: Upstream backend pool with connection management, load balancing, health checking, and tunnel integration.
---

# Skill: Upstream (Backend Pool)

## Context
The upstream crate manages connections to backend servers: connection pooling, load balancing, health checking, and tunnel transport integration.

## When to Use
- Modifying load balancing algorithms or pool behavior
- Adding health check methods
- Integrating new transport types (QUIC tunnels, WireGuard)
- Debugging connection pool exhaustion or health check failures

## Key Files
- `crates/synvoid-upstream/src/lib.rs` — re-exports
- `crates/synvoid-upstream/src/address.rs` — `UpstreamAddress`, `UpstreamError`, `SocketErrorTracker`, `QuicTunnelStream`
- `crates/synvoid-upstream/src/health.rs` — `HealthCheckConfig`, `HealthCheckMethod`, `HealthChecker`
- `crates/synvoid-upstream/src/pool.rs` — `UpstreamPool`, `Backend`, `BackendProtocol`, `LoadBalanceAlgorithm`, `UpstreamMetrics`
- `crates/synvoid-upstream/src/shared_state.rs` — `SharedConnectionTable`, `SharedRateLimitTable`, checked `ConnectionTableLayout` / `RateLimitTableLayout` (Phase 42 unsafe boundary; contract: `architecture/shared_memory_atomic_contract.md`)
- `crates/synvoid-upstream/src/tls_adapter.rs` — `upstream_tls_from_site_config` site→TLS adapter (Phase 34; keeps `synvoid-http-client` policy-free)
- `crates/synvoid-upstream/src/tunnel.rs` — `TunnelConnector` trait, `NoopTunnelConnector`

## Architecture

### Connection Pool Flow
```
Request → UpstreamPool::get_backend()
  → LoadBalanceAlgorithm selects Backend
  → HealthChecker verifies backend health
  → Connection from SharedConnectionTable (or new)
  → Response → connection returned to pool
```

### Load Balancing Algorithms
- `RoundRobin` — sequential cycling
- `LeastConnections` — fewest active connections
- `IpHash` — consistent hashing by client IP
- `Random` — random selection

### Health Checking
- `None` — no active checks
- `Http` — HTTP GET to health endpoint
- `Tcp` — TCP connect check
- Interval-based with configurable timeout

### Tunnel Integration
```rust
pub trait TunnelConnector: Send + Sync {
    async fn connect(&self, addr: &UpstreamAddress) -> Result<QuicTunnelStream>;
}
```
- `NoopTunnelConnector` — direct connection (default)
- Real implementations bridge to `synvoid-tunnel` QUIC/WireGuard

## Configuration
```toml
[upstream]
pool_size = 64
connect_timeout_ms = 5000
health_check_interval_secs = 30

[[upstream.backends]]
address = "127.0.0.1:8080"
protocol = "http"
weight = 1
```

## Critical Invariants
- Connections are reused across requests when possible
- Health checks run in background; unhealthy backends are excluded from selection
- `SocketErrorTracker` implements circuit-breaker pattern for failing backends
- Shared memory (`shared_state.rs`, Phase 42): checked layout value types own
  all size/offset math (never duplicate formulas); unsafe atomic references
  require release-mode range/bounds/alignment proofs with adjacent `// SAFETY:`
  comments; supervisor-owned creation truncates before workers spawn while
  `open_existing` validates without truncating; files are 0600 under a 0700
  runtime dir with symlink/non-regular rejection; rate-limit consumers use
  typed counter slices (`second/minute/five_min_counters()`, `dirty_words()`)
  via `SlottedIpRateLimiter::from_shared_table` — never raw `MmapMut`
  (removed). Keep mmap/process policy out of `synvoid-rate-limit` (Phase 33
  boundary). Cross-process atomic assumptions: Linux x86_64/aarch64
  `MAP_SHARED` cache-coherent mappings, per-generation files (no mixed-version
  reuse). See `architecture/shared_memory_atomic_contract.md`

## Testing
```bash
cargo test -p synvoid-upstream --all-targets
```
