# Traffic Entrypoint Matrix

**Status**: DRAFT
**Created**: 2026-05-02
**Purpose**: Document proxy execution behavior across all entry points for the MaluWAF traffic layer.

## Overview

This matrix documents how requests flow through each entry point and which components/processes handle various proxy behaviors.

## Entrypoints

| Entrypoint | File | Protocol | Notes |
|------------|------|----------|-------|
| HTTP Server | `src/http/server.rs` | HTTP/1.1 | Primary direct proxy path |
| TLS Server | `src/tls/server.rs` | HTTPS | TLS termination then proxy |
| HTTP/3 Server | `src/http3/server.rs` | HTTP/3 | QUIC-based |
| QUIC Tunnel | `src/proxy/mod.rs` | CONNECT-over-QUIC | Tunnel mode |
| ProxyServer | `src/proxy/mod.rs` | Direct | Separate proxy execution |
| Mesh Backend | `src/mesh/proxy.rs` | Mesh P2P | Routes through mesh network |
| Static Fallback | `src/http/server.rs` | Local file | Static file serving |

## Behavior Matrix

| Behavior | HTTP Server | TLS Server | HTTP/3 | ProxyServer | Mesh |
|----------|-------------|------------|--------|-------------|------|
| Route resolution | `Router::route_with_local_addr` | Same | Same | `ProxyServer::forward_request` | `MeshBackendPool::select_backend` |
| Request headers | `build_forward_headers` | Same | Same | `build_forward_headers` | Separate impl |
| Response headers | `filter_response_headers_buf` | Same | Same | `filter_response_headers` | Separate impl |
| Upstream TLS | Per-site client created inline | Same | Same | Per-site client | N/A (mesh) |
| Retry/Failover | `ProxyServer::forward_with_pool` | Same | Same | `forward_with_pool` | Provider fallback |
| Cache lookup | Via `handle_request_with_cache` | Via cache | Via cache | `handle_request_with_cache` | Not cached |
| Response size limit | `send_request_streaming` | `send_request_with_body_and_timeout_with_limit` | Limited | Limited | Unclear |
| Streaming | Yes (zero-copy) | Yes | Yes | Via `send_request_streaming` | Yes |
| WAF invocation | `waf.check_request_full` | Same | Same | Via `forward_request` | `waf.check_request_full` |
| Metrics | `req_metrics` | Same | Same | `metrics` crate | `metrics` crate |

## Key Observations

### 1. Two Proxy Paths
- **Direct path**: `src/http/server.rs` builds URL inline, calls `send_request_streaming` directly
- **ProxyServer path**: `src/proxy/mod.rs` has its own upstream pool, retry, and cache logic

### 2. Header Policy
- All entrypoints use `build_forward_headers` from `src/proxy/headers.rs`
- Response filtering uses `filter_response_headers_buf` (shared)

### 3. TLS Client Creation
- **HTTP Server**: Creates per-site client inline at `src/http/server.rs:2817` when site has TLS config
- **TLS Server**: Similar inline creation
- **ProxyServer**: Creates clients during construction (`new` method)

### 4. Cache Integration
- Cache path goes through `handle_request_with_cache` which calls `ProxyServer`
- Direct HTTP path may bypass cache

### 5. Retry Behavior
- `forward_with_pool` handles retry logic
- HTTP Server doesn't call `forward_with_pool` directly for most requests

## Gaps

1. **TLS Client Reuse**: Per-site TLS clients are created per-request in HTTP Server path
2. **Cache Bypass**: Main HTTP path may not use `handle_request_with_cache`
3. **Response Size Enforcement**: Streaming path may not enforce `max_response_size`
4. **Mesh Policy Drift**: Mesh uses separate header/metric/retry implementation

## Convergence Helpers Added (Wave 16)

### URL Construction
- `join_upstream_url(upstream, path)` in `src/proxy/mod.rs`
- Handles trailing slash normalization
- Available for all entrypoints

### Header Forwarding
- `build_forward_headers()` in `src/proxy/headers.rs`
- Now forwards all end-to-end headers by default
- Strips hop-by-hop, sanitizes XFF

## Next Steps

1. Move TLS client creation out of request path into a client registry
2. Wire main HTTP path through `handle_request_with_cache` when cache is enabled
3. Create `ProxyExecutor` that can be used by HTTP/TLS/HTTP3 server paths
4. Document response-size enforcement behavior for streaming path