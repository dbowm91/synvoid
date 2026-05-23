# Request Routing & Upstream Management

SynVoid uses a high-performance routing engine and a flexible upstream management system to map client requests to backend services.

## The Routing Engine

The `Router` is responsible for determining the `RouteTarget` for every incoming request. It is designed to handle thousands of sites with minimal latency.

### Matching Hierarchy

1.  **Listener-Level Default:** If a request arrives on a listener (IP:Port) that has a `default_server` configured, it may fallback to that site if no other matches are found.
2.  **Exact Domain Matching:** The router first checks for an exact match of the `Host` header in the `domain_map`.
3.  **Wildcard/Suffix Matching:** If no exact match is found, it uses a reversed-domain Radix tree to match wildcard patterns.
4.  **Default Server Fallback:** If no domain matches, falls back to the listener's default server or the global default.
5.  **Path-Based Matching (Locations):** Once a site is identified, the `LocationMatcher` evaluates the request path against defined `location` blocks (e.g., `/api`, `/static`).

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
- **Static:** The request is handled by the internal `StaticFileHandler`.
- **AppServer (Granian):** Built-in support for Python ASGI/WSGI applications.
- **Serverless (WASM):** Execution of a WASM function.
- **Mesh:** Routing the request through the WAF Mesh to a remote peer.
- **QuicTunnel:** Proxying through a specialized QUIC tunnel.

---

## Upstream Management

Upstream servers are organized into **Upstream Pools**. This system ensures reliable and efficient connection to backend applications.

### Load Balancing

SynVoid supports multiple load balancing algorithms to distribute traffic across a pool of backends:
- **Round Robin (Default):** Sequential distribution.
- **Weighted Round Robin:** Distribution based on configured backend weights.
- **Least Connections:** Routes to the backend with the fewest active requests.
- **Random:** Randomized selection.
- **IP Hash:** Ensures session persistence by hashing the client IP to a specific backend.

### Health Monitoring & Resilience

- **Passive Health Checks:** The Supervisor and Workers monitor backend responses. Consecutive failures trigger a "down" state, while consecutive successes trigger a "healthy" state.
- **Active Health Checks:** Periodic out-of-band requests (HTTP GET, TCP connect) to verify backend availability.
- **Connection Limits:** Prevents overwhelming backends by enforcing maximum concurrent connection limits.
- **Backup Servers:** Configurable backends that only receive traffic if all primary servers in a pool are down.

---

## Connection Lifecycle

1.  **Target Resolution:** The Router identifies the upstream pool and specific backend.
2.  **Lease:** A connection is requested from the pool (enforcing limits).
3.  **Protocol Negotiation:** The handler establishes or reuses a connection (HTTP/1.1 keep-alive, H2 multiplexing).
4.  **Execution:** The request is proxied, and the response is streamed back.
5.  **Release:** The connection is returned to the pool or closed.
