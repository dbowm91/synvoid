# Request Routing & Upstream Management

SynVoid uses a high-performance routing engine and a flexible upstream management system to map client requests to backend services.

## The Routing Engine

The `Router` is responsible for determining the `RouteTarget` for every incoming request. It is designed to handle thousands of sites with minimal latency.

### Matching Hierarchy

1.  **Listener-Level Default:** If a request arrives on a listener (IP:Port) that has a `default_server` configured, it may fallback to that site if no other matches are found.
2.  **Exact Domain Matching:** The router first checks for an exact match of the `Host` header in the `domain_map`.
3.  **Wildcard/Suffix Matching:** If no exact match is found, it checks against suffix patterns (e.g., `*.example.com`).
4.  **Path-Based Matching (Locations):** Once a site is identified, the `LocationMatcher` evaluates the request path against defined `location` blocks (e.g., `/api`, `/static`).

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

- **Passive Health Checks:** The Master and Workers monitor backend responses. Consecutive failures trigger a "down" state, while consecutive successes trigger a "healthy" state.
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
