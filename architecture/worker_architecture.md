# Worker Architecture & Unified Server

SynVoid's worker data plane is split between a latency-sensitive **UnifiedServerWorker** and bounded **CPU offload workers**. The unified worker keeps socket accept, TLS, parsing, routing, and cheap WAF work inline; CPU-heavy transforms are delegated to the offload plane.

## The UnifiedServerWorker vs worker_pool Module

The `worker_pool` configuration (`tcp.worker_pool_size`) controls the **number of connection-accepting threads** in the unified Tokio runtime, NOT separate worker processes. This is distinct from:

| Component | Purpose | Configuration |
|-----------|---------|---------------|
| **UnifiedServerWorker** | Single process handling HTTP/HTTPS/HTTP3 + WAF + proxy via Tokio async runtime | `--unified-server-worker` flag |
| **`tcp.worker_pool_size`** | Number of connection-accepting threads within the unified event loop | `tcp.worker_pool_size` config |
| **`unified_server_workers`** | Number of unified worker processes (advanced isolation mode) | `defaults.worker_pool.workers` config. Shipped `config/main.toml` sets 4 and `WorkerPoolDefaults::default()` also sets 4 (`crates/synvoid-config/src/defaults.rs:972`). The literal `1` is only `ProcessManagerConfig::default().unified_server_workers` (`manager.rs:226`), which `run_supervisor_mode` always overrides with `main_config.defaults.worker_pool.workers.max(1)` (`src/supervisor/process.rs`). |

**Scaling Guidance:**
- For HTTP scaling, tune `tcp.worker_pool_size` (connection accepting threads) or use async primitives within the existing event loop
- **Do NOT increase `unified_server_workers` for normal scaling** — it increases process count for advanced isolation; use `worker_threads` for runtime parallelism and `tcp.worker_pool_size` for accept throughput
- The unified worker uses a single Tokio runtime optimized for millions of tenants via O(1) domain-based routing

### Inline vs Offload Boundary

Keep these inline in the unified worker:
- listener accept
- TLS orchestration and HTTP parsing
- routing
- cheap WAF checks and rate-limit accounting
- cache-hit response serving
- proxy streaming

Offload to CPU workers when the work becomes expensive:
- minification and compression
- image transforms and rights marking
- YARA scanning
- WASM/plugin execution
- serverless execution
- heavy body inspection and deep regex work

### Buffer Pool Implementation

The `BufferPool` is implemented at `crates/synvoid-utils/src/buffer/pool.rs:211`:
- 8 shards (`NUM_SHARDS = 8`), each shard holding four `TierArena`s; a tier arena is
  a `Mutex<Vec<BytesMut>>` plus an `AtomicUsize` length counter (`pool.rs:96-101`).
  Shard selection hashes with `DefaultHasher`.
- Four tiers: small (4KB), medium (64KB), large (256KB), **jumbo (512KB)** buffers
  (`pool.rs:7-10`) — jumbo is 512 KiB, not 256 KiB.
- Global (`GLOBAL_POOL`, sharded, `Arc<BufferPool>`) and thread-local (`POOL`, shard 0,
  single-threaded by construction) acquisition variants
- Configured via `BufferPoolConfig` at `pool.rs:274`

## The Unified Server

The Unified Server is designed to handle multiple protocols and transport layers within a single Tokio async runtime. This architecture is more efficient than the traditional multi-process model (like NGINX's worker processes) because it minimizes context switching and allows for fine-grained cooperative multitasking.

### Key Capabilities

- **Protocol Support:**
  - **HTTP/1.1:** Fully supported.
  - **HTTP/2:** Enabled via ALPN negotiation on server side (`src/tls/server.rs` `serve()` ALPN branch). `ProxyServer::with_http2()` still exists (`crates/synvoid-proxy/src/server.rs:283`) but is a **retained no-op**: the field it sets is `#[allow(dead_code)]` and the source comment states the legacy transport only used it as a pool-lookup hint, never for protocol switching — the egress lane negotiates via ALPN.
  - **HTTP/3 (QUIC):** Handled via `Quinn`, providing 0-RTT handshakes and improved performance on lossy networks.
  - **TCP & UDP Proxying:** Generic stream and packet proxying with WAF protections.
- **Unified Event Loop:** A single `tokio::select!` based loop (or multiple spawned tasks) manages all incoming connections across all listeners.
- **Dynamic Site Configuration:** The Unified Server can handle thousands of domains (sites) concurrently, each with its own WAF rules, upstreams, and security policies.

---

## Internal Components

### 1. Listener Pools
- **`TcpListenerPool`:** Manages a collection of TCP listeners. It handles auto-tuning based on available parallelism and manages TLS termination.
- **`UdpListenerPool`:** Handles UDP packet reception, protocol detection, and forwarding. Includes protection against reflection/amplification attacks.

### 2. WAF Pipeline
 Every request passing through the Unified Server is processed by the **WAF Pipeline**. This pipeline is modular and executes in stages (verified order in `WafCore::check_request_full`):
 1.  **Rate Limits:** IP-based rate limiting, CIDR filtering, and flood protection.
 2.  **Endpoint Block:** Block specific endpoints/paths.
 3.  **Honeypot Detection:** Hidden link matching and trap endpoints.
 4.  **Bot Protection:** Challenges (JS/CAPTCHA), behavioral analysis, JA3/JA4 fingerprinting. Challenges are issued **inline** within bot protection via `challenge_manager.generate_challenge_page()` within `check_bot_protection()`, not as a separate pipeline stage.
  5.  **Flood Protection:** TCP connection tracking and rate limiting (via `FloodProtector`).
  6.  **Attack Detection:** Deep packet inspection for SQLi, XSS, SSRF, etc. (using `WafCore` and `AttackDetector`).

> Admission note: block-store/threat-intel admission runs at the worker
> composition root before this pipeline; the WAF pipeline itself
> queries/mutates no block/threat state.

### 3. Upstream Management
- **Connection Pooling:** Maintains persistent connections to backend servers (PHP-FPM, Granian, etc.) to reduce latency.
- **Health Monitoring:** Primarily **passive** - monitors backend responses for failures/successes. Active health checks (periodic HTTP GET/TCP connect) are configurable but not the primary mechanism.
- **Load Balancing:** Supports multiple algorithms for distributing traffic across upstream pools.

---

## Request Flow

1.  **Accept:** A connection is accepted by a `ListenerPool`.
2.  **Negotiate:** TLS handshake (if applicable) and protocol negotiation (ALPN).
3.  **Route:** The `Router` matches the request (Host header and Path) to a specific `SiteConfig`.
4.  **Protect:** The request passes through the `WafCore` pipeline.
5.  **Serve/Proxy:**
    - If it's a static file, the `StaticHandler` serves it.
    - If it's a dynamic request, it's proxied to the configured upstream (FastCGI, HTTP, etc.).
    - If it's a serverless function, the `WasmRuntime` executes it.
6.  **Transform:** The response is processed (headers sanitized, compressed) before being sent back to the client.

---

## Resource Management

- **Buffer Pooling:** To minimize allocations and GC pressure, the worker uses a `BufferPool` at `crates/synvoid-utils/src/buffer/pool.rs:211` for IO operations.
- **Concurrency Control:** Semaphores and channels are used to limit the number of concurrent requests per site and globally, preventing resource exhaustion.
- **Zero-Copy:** Where possible, SynVoid utilizes zero-copy techniques for moving data between network buffers and application handlers.

---

## Worker Startup Sequence

```
Supervisor Process
  └── Data Plane
        ├── UnifiedServerWorker(s) (Tokio Runtime)
        │     ├── Initialize ConfigManager
        │     ├── Load site configurations
        │     ├── Start TcpListenerPool (N threads based on worker_pool_size)
        │     ├── Start UdpListenerPool
        │     ├── Initialize WAF pipeline
        │     ├── Start upstream connection pools
        │     └── Begin accepting connections (cooperative multitasking)
        └── CPU Offload Worker(s)
              └── Bounded heavy transforms, scans, and compression tasks
```

### Health Check Integration

Worker health status is exposed via:
- `/health` route at `src/admin/mod.rs:362` (returns basic status; auth-exempt in `src/admin/middleware.rs:95`)
- `/serverless/health` route at `src/admin/routes.rs:669`, handler at `src/admin/handlers/serverless.rs:152` (serverless runtime status)
- Internal `/__internal__/health` at `src/tls/server.rs:969` (detailed worker status) — this lives in the TLS server, not `src/http/server.rs`
