# Control-Plane Boundary Architecture

**Status**: DRAFT
**Priority**: 8
**Last Updated**: 2026-05-02
**Purpose**: Document and enforce which mesh/control-plane operations belong in workers, which belong in Master, and which should eventually move to a separate process.

---

## Background

The Master process is intentionally isolated from external request traffic. Workers handle client requests directly via HTTP/HTTPS/HTTP3 servers. However, workers also handle mesh connections and distributed control-plane behavior directly. This document clarifies boundaries and documents the tradeoffs of the current architecture.

---

## Control-Plane Layers

### Layer 1: Request Data Plane

**Scope**: Per-worker, handles all external client traffic.

**Components**:
- HTTP/1, HTTP/2 server listeners
- TLS termination
- HTTP/3 (QUIC) server
- TCP SYN flood protection pool
- UDP flood protection pool
- WAF request filtering (attack detection)
- Proxy routing to upstream backends
- Response streaming and buffering

**Ownership**: Worker process only. Master has no direct visibility into request handling.

**Isolation**: Failure in this layer affects only the worker handling the request. Other workers remain unaffected.

**Why it stays in worker**: Request handling is the core function of workers. Moving it to Master would make Master a proxy bottleneck and mix external traffic with management responsibilities.

---

### Layer 2: Local Process Control Plane

**Scope**: Worker-local management and configuration coordination with Master.

**Components**:
- IPC channel to Master (heartbeat, metrics, config updates)
- Worker lifecycle management (startup, graceful shutdown, restart)
- Certificate hot-reload coordination (`MasterCertReload` messages)
- WAF rule pattern updates (`RulePatternsUpdate` messages)
- Threat feed updates (`ThreatFeedUpdate` messages)
- Bandwidth tracking and persistence

**Ownership**: Shared between Worker and Master. Master initiates changes; Worker applies them.

**Isolation**: IPC failures result in worker heartbeat timeout and eventual restart. This does not affect other workers.

**Why it stays in worker**: Configuration coordination must be close to where config is consumed. IPC overhead for every config change would be prohibitive at high request rates.

---

### Layer 3: Mesh/Distributed Control Plane

**Scope**: Cluster-wide coordination across nodes.

**Components** (classified by urgency and data-plane coupling):

#### Class A: Direct Request-Routing Operations (Stay in Worker)

These operations are tightly coupled to request handling and justify worker residency:

| Component | Reason to Stay |
|-----------|---------------|
| Mesh proxying: routing requests to upstream mesh nodes | Must be co-located with request handling to avoid latency overhead |
| Transport-level load balancing decisions | Must respect upstream selection made at request time |
| Mesh health tracking for upstream selection | Must reflect real-time health for routing decisions |

#### Class B: Background Distributed Operations (Candidate for Separation)

These operations run periodically and are loosely coupled to request handling:

| Component | Reason to Move (Medium Term) |
|-----------|-------------------------------|
| DHT sync and routing table maintenance | CPU-intensive, periodic, not request-critical |
| Raft consensus for global state | CPU-intensive verification, failure does not affect requests |
| Threat intelligence propagation | Background gossip, failure does not affect local detection |
| YARA rule distribution via DHT | Periodic fetch/publish, failure does not affect local rules |
| Global topology management | Cluster-wide view, updated infrequently |

**Rationale for keeping Class B in worker (near term)**:
- Moving these to a separate process adds IPC overhead for coordination
- Separate process adds deployment complexity and failure domain
- Current rate limits and concurrency bounds mitigate resource contention
- Medium term: dedicated control-plane process or dedicated worker type will be evaluated

---

### Layer 4: Admin API Control Plane

**Scope**: Node-local administrative operations via REST API.

**Components**:
- Admin API server (separate port, TLS recommended)
- Configuration retrieval and status reporting
- Manual triggering of threat feed updates
- Rule reload and health check endpoints

**Ownership**: Worker hosts the admin API server.

**Isolation**: Admin operations are rate-limited and do not directly affect request handling.

**Notes**: Admin API does not currently require Master coordination for read-only operations. Write operations (e.g., triggering reload) go through IPC to Master.

---

## Backpressure and Failure Boundaries

### Principle: Background Work Must Not Starve Request Handling

Mesh background work runs on the same async executor as HTTP/WAF request handling. To prevent starvation:

1. **Concurrency Limits**: DHT sync, threat-intel propagation, and YARA distribution use bounded channels with explicit capacity limits (typically 100-1000 items).

2. **Rate Limits**: Periodic tasks use `tokio::time::interval` with minimum delays:
   - DHT sync: configurable interval, default 60s
   - Threat feed fetch: configurable interval, default 300s
   - YARA rule fetch: configurable interval, default 600s

3. **CPU-Heavy Operations Offloaded**: Raft verification and cryptographic operations (signature verification, PoW validation) use `spawn_blocking` to avoid blocking the async executor.

4. **Failure Isolation**:
   - Mesh message handling failures do not terminate HTTP serving unless configured fail-closed
   - DHT sync failures log and retry; do not propagate to request path
   - Threat-intel propagation failures do not affect local WAF detection

### Explicit Concurrency Budgets

| Operation | Max Concurrent | Notes |
|-----------|----------------|-------|
| DHT put operations | 16 | Bounded channel |
| DHT get operations | 32 | Bounded channel |
| Threat intel fetch | 4 | Semaphore-limited |
| YARA rule fetch | 2 | Single feed source |
| Mesh broadcast forwarding | 8 | Per-worker limit |

---

## Near-Term Model (Current Architecture)

### Decision: Keep Mesh in Worker with Improved Isolation

**Keep**:
- Mesh transport manager in worker process
- Mesh proxying operations in request path
- DHT sync and routing in worker

**Isolate**:
- Lifecycle: mesh transport initialization separated from HTTP server startup
- Rate limits: all background sync tasks have explicit bounds
- Failure boundaries: mesh failures do not cascade to HTTP serving

### Why Direct Proxying Remains in Data-Plane Workers

1. **Latency**: Mesh proxy decisions must be made at request time. IPC to a separate control-plane process would add 1-2ms per request.

2. **Health Correlation**: Upstream mesh node health must reflect real-time observability from the same worker handling the request.

3. **Failure Domain**: Moving proxying to a separate process does not improve failure isolation—it just moves the failure domain.

4. **Complexity**: Separate process requires coordination protocol for upstream selection and health updates.

---

## Medium-Term Model (Planned)

### Candidate: Separate Mesh Control-Plane Process or Dedicated Worker Type

**Trigger**: When mesh background work demonstrably affects request handling latency or when mesh attack surface becomes a concern.

**Options**:

1. **Dedicated Mesh Worker**: A worker type that only handles mesh operations,不承担HTTP请求。HTTP workers communicate via IPC.

2. **Control-Plane Process**: Separate binary that handles DHT sync, Raft, threat-intel propagation. HTTP workers are thin and only handle requests.

3. **Hybrid**: HTTP workers handle mesh proxying only. Background sync moves to dedicated process.

**Tradeoffs**:
- Option 1: Lowest latency for proxying, requires architecture change for worker types
- Option 2: Cleanest isolation, adds IPC for all mesh operations
- Option 3: Balances latency and isolation, incremental migration path

---

## Process Manager Naming

Current: `unified_server_workers` is used for worker scaling, but it conflates:
- Scaling concept (multiple identical workers)
- Internal accept-thread concept (not the same thing)

**Recommendation**:
- Rename `unified_server_workers` to `request_workers` or `http_workers`
- Mesh operations should not be part of the naming at all if separated
- Consider `mesh_control_workers` if dedicated mesh workers are introduced

---

## Failure Mode Summary

| Failure | Affected Layer | Impact | Recovery |
|---------|---------------|--------|----------|
| Mesh transport disconnect | Layer 3 (mesh) | DHT sync fails, proxy routing limited | Auto-reconnect, fallback to direct |
| DHT sync task panic | Layer 3 (mesh) | Routing table stale | Restart sync task, log error |
| Threat feed fetch fails | Layer 3 (mesh) | Local detection uses stale data | Retry with backoff |
| YARA rule fetch fails | Layer 3 (mesh) | Upload scanning uses local rules only | Retry with backoff |
| HTTP request handling panic | Layer 1 (data) | Single request fails | Worker continues, request returns 502 |
| WAF rule reload fails | Layer 2 (local) | WAF uses old rules | Log error, continue with current rules |

---

## Open Questions

1. **Fail-Closed Configuration**: Should mesh operation failures cause worker to fail-closed (stop handling requests) or fail-open (continue with degraded capability)?

2. **Mesh DHT Bootstrap**: Who provides initial peer list? Master or static config?

3. **Raft Membership**: Who decides node addition/removal? Admin API? Cluster consensus?

4. **Dedicated Worker Migration Path**: What is the minimum change to introduce a dedicated mesh worker type?