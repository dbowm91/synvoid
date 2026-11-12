# Request Routing & Upstream Management

SynVoid uses a high-performance routing engine and a flexible upstream management system to map client requests to backend services.

## The Routing Engine

The `Router` is responsible for determining the `RouteTarget` for every incoming request. It is designed to handle thousands of sites with minimal latency.

### Matching Hierarchy

Listeners are process-wide resources. The canonical `[[http.listeners]]` plan
binds each socket once; a request carries the `ListenerId` that accepted it.
Sites are selected inside that listener's table from the `Host` header:

1.  **Exact Domain Matching:** exact match in the listener's `exact` map.
2.  **Wildcard/Suffix Matching:** reversed-domain Radix tree for that listener.
3.  **Listener Default Site:** `default_site`, when configured.
4.  **Path-Based Matching (Locations):** once a site is identified, the
    `LocationMatcher` evaluates the request path against `location` blocks.
5.  **Fallback:** the global `[fallback] mode`.

`[site].listeners` restricts a site to named listeners; omitted membership
makes it a candidate on every listener. A request never falls through to
another listener's table. `local_addr` is diagnostic only and is not listener
identity. `route()` remains a combined compatibility table for internal callers
and tests; production uses `route_with_listener_id()`.

### Reverse-Domain Radix Tree for Wildcard/Suffix Matching

The router uses a **Radix tree** (compressed trie) with reversed domain names to efficiently match wildcard and suffix patterns:

**How it works:**
1.  Domains are reversed and split into parts: `foo.bar.example.com` → `/foo/bar/example/com`
2.  Wildcard patterns are normalized (e.g., `*.example.com` → `example.com`) and inserted as reversed paths.
3.  Request hosts are similarly reversed and looked up in the tree.

**Matching examples:**
| Pattern | Reversed Inserted Path | Request Host | Reversed Request | Match? |
|---------|------------------------|--------------|------------------|--------|
| `*.example.com` | `/example/com` | `foo.example.com` | `/foo/example/com` | ✅ (prefix match) |
| `*.example.com` | `/example/com` | `bar.example.com` | `/bar/example/com` | ✅ (prefix match) |
| `example.com` | `/example/com` | `example.com` | `/example/com` | ✅ (exact match) |
| `com` | `/com` | `example.com` | `/example/com` | ✅ (suffix match) |

The Radix tree provides O(k) lookup where k is the domain part count (typically 3-5), making wildcard matching both fast and memory-efficient.

### Backend Resolution

The router resolves the request to one of several **Backend Types**:
- **Upstream:** Standard reverse proxy to an external HTTP/HTTPS server.
- **FastCGI / PHP:** Direct connection to a FastCGI process (like PHP-FPM).
- **Php:** PHP via php-cgi executable (separate from FastCGI).
- **Cgi:** Generic CGI execution.
- **Static:** The request is handled by the internal `StaticFileHandler`.
- **AppServer:** Generic application server backend.
- **AxumDynamic:** Dynamic axum-based handler for plugin-based routing.
- **Spin:** Fermyon Spin framework WASM execution.
- **Serverless (WASM):** Execution of a WASM function.
- **Mesh:** Routing the request through the WAF Mesh to a remote peer.
- **QuicTunnel:** Proxying through a specialized QUIC tunnel. URL parsing is unified via `Router::parse_quictunnel_url()` at `crates/synvoid-proxy/src/router.rs:531` at both location and site levels.

---

## Upstream Management

Upstream servers are organized into **Upstream Pools**. This system ensures reliable and efficient connection to backend applications.

### Load Balancing

SynVoid supports multiple load balancing algorithms to distribute traffic across a pool of backends:
- **Round Robin (Default):** Sequential distribution.
- **Weighted Round Robin:** Distribution based on configured backend weights.
- **Least Connections:** Routes to the backend with the fewest active requests.
- **Random:** Randomized selection.
- **PeakEwma:** Cost-based selection using exponential weighted moving average of latency `(conn + 1) * (latency + 1)` at `crates/synvoid-upstream/src/pool.rs`.
- **IP Hash:** Ensures session persistence by hashing the client IP to a specific backend.

### Health Monitoring & Resilience

- **Passive Health Checks:** The Supervisor and Workers monitor backend responses. Consecutive failures trigger a "down" state, while consecutive successes trigger a "healthy" state.
- **Active Health Checks:** Periodic out-of-band requests (HTTP GET, TCP connect) to verify backend availability. Configurable via `HealthCheckConfig.max_load_percent` (default 80%) - backends with CPU/memory load exceeding this threshold are marked unhealthy. Metric labels: `backend`, `pool`, `check_type`.
- **Connection Limits:** Prevents overwhelming backends by enforcing maximum concurrent connection limits.
- **Backup Servers:** Configurable backends that only receive traffic if all primary servers in a pool are down.

---

## Connection Lifecycle

1.  **Target Resolution:** The Router identifies the upstream pool and specific backend.
2.  **Connection Request:** A connection is requested from the pool (enforcing limits via `increment_connections()`).
3.  **Protocol Negotiation:** The handler establishes or reuses a connection (HTTP/1.1 keep-alive, H2 multiplexing).
4.  **Execution:** The request is proxied, and the response is streamed back.
5.  **Release:** The connection is returned to the pool (`decrement_connections()`) or closed.
