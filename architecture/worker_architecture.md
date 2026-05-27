# Worker Architecture & Unified Server

The Worker process is the data plane of SynVoid, responsible for high-performance request handling and security enforcement. The centerpiece of the worker is the **UnifiedServerWorker** which runs within the Supervisor/Master process hierarchy.

## The UnifiedServerWorker vs worker_pool Module

The `worker_pool` configuration (`tcp.worker_pool_size`) controls the **number of connection-accepting threads** in the unified Tokio runtime, NOT separate worker processes. This is distinct from:

| Component | Purpose | Configuration |
|-----------|---------|---------------|
| **UnifiedServerWorker** | Single process handling HTTP/HTTPS/HTTP3 + WAF + proxy via Tokio async runtime | `--unified-server-worker` flag |
| **`tcp.worker_pool_size`** | Number of connection-accepting threads within the unified event loop | `tcp.worker_pool_size` config |
| **`unified_server_workers`** | Number of Tokio runtime threads (defaults to CPU cores) | `tcp.unified_server_workers` config |

**Scaling Guidance:**
- For HTTP scaling, tune `tcp.worker_pool_size` (connection accepting threads) or use async primitives within the existing event loop
- **Do NOT increase `unified_server_workers` for scaling purposes** — this only affects the number of Tokio runtime threads, not throughput
- The unified worker uses a single Tokio runtime optimized for millions of tenants via O(1) domain-based routing

### Buffer Pool Implementation

The `BufferPool` is implemented at `crates/synvoid-utils/src/buffer/pool.rs:211`:
- Sharded mutex design for ABA-safe concurrent access
- Three tiers: small (4KB), medium (32KB), large (128KB) buffers
- Global and thread-local acquisition variants
- Configured via `BufferPoolConfig` at line 242

## The Unified Server

The Unified Server is designed to handle multiple protocols and transport layers within a single Tokio async runtime. This architecture is more efficient than the traditional multi-process model (like NGINX's worker processes) because it minimizes context switching and allows for fine-grained cooperative multitasking.

### Key Capabilities

- **Protocol Support:**
  - **HTTP/1.1:** Fully supported.
  - **HTTP/2:** Enabled via ALPN negotiation on server side (`src/tls/server.rs:411-487`). Client-side HTTP/2 is configurable via `ProxyServer::with_http2()` builder method.
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
 1.  **Block Store Check:** IP/CIDR block list lookup from threat intelligence.
 2.  **Rate Limits:** IP-based rate limiting, CIDR filtering, and flood protection.
 3.  **Endpoint Block:** Block specific endpoints/paths.
 4.  **Honeypot Detection:** Hidden link matching and trap endpoints.
 5.  **Bot Protection:** Challenges (JS/CAPTCHA), behavioral analysis, JA3/JA4 fingerprinting. Challenges are issued **inline** within bot protection via `challenge_manager.generate_challenge_page()` within `check_bot_protection()`, not as a separate pipeline stage.
  6.  **Flood Protection:** TCP connection tracking and rate limiting (via `FloodProtector`).
  7.  **Attack Detection:** Deep packet inspection for SQLi, XSS, SSRF, etc. (using `WafCore` and `AttackDetector`).

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
  └── Master Process
        └── UnifiedServerWorker (Tokio Runtime)
              ├── Initialize ConfigManager
              ├── Load site configurations
              ├── Start TcpListenerPool (N threads based on worker_pool_size)
              ├── Start UdpListenerPool
              ├── Initialize WAF pipeline
              ├── Start upstream connection pools
              └── Begin accepting connections (cooperative multitasking)
```

### Health Check Integration

Worker health status is exposed via:
- `/health` endpoint at `src/admin/mod.rs:180` (returns basic status)
- `/serverless/health` endpoint at `src/admin/handlers/serverless.rs:122` (serverless runtime status)
- Internal `/__internal__/health` at `src/http/server.rs:286` (detailed worker status)
