# Traffic Entrypoint Matrix

**Status**: ACTIVE
**Created**: 2026-05-02
**Updated**: 2026-05-02
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
| ProxyServer | `src/proxy/mod.rs` | Direct | Separate proxy execution with retry/cache |
| Mesh Backend | `src/mesh/proxy.rs` | Mesh P2P | Routes through mesh network |
| Static Fallback | `src/http/server.rs` | Local file | Static file serving |

## Shared Proxy Execution Contract (Wave 17)

### Shared Policy Helpers (`src/proxy/executor.rs`)

| Helper | Purpose | Used By |
|--------|---------|---------|
| `PreparedUpstreamTarget` | URL construction via `join_upstream_url`, timeout from config, max_response_size | HTTP, TLS, HTTP/3 |
| `UpstreamResponsePolicy` | Response header filter set, security headers, size limits | All entry points |
| `apply_response_size_limit()` | Enforce max_response_size on buffered bodies | HTTP, TLS, HTTP/3 |
| `build_upstream_request()` | Build complete upstream Request from prepared target | Available for all |

### Contract: What Each Component Owns

| Responsibility | Owner | Shared Helper |
|----------------|-------|---------------|
| Upstream URL construction | `PreparedUpstreamTarget::new()` | `join_upstream_url()` |
| Request header forwarding | `build_forward_headers()` in `src/proxy/headers.rs` | Shared |
| Response header filtering | `filter_response_headers_buf()` in `src/proxy/headers.rs` | Shared |
| Upstream TLS client selection | Per-site client creation (needs pooling - P4) | Not yet shared |
| Response-size enforcement | `apply_response_size_limit()` in `src/proxy/executor.rs` | Shared |
| Retry and failover | `forward_with_pool()` in `src/proxy/mod.rs` | ProxyServer only |
| Proxy cache | `handle_request_with_cache()` in `src/proxy/mod.rs` | TLS via ProxyServer |
| QUIC tunnel handling | `send_request_via_quic_tunnel()` in `src/proxy/mod.rs` | ProxyServer |
| Mesh backend handling | `MeshProxy::route_request()` in `src/mesh/proxy.rs` | Separate |
| Metrics and bandwidth | Per-entry-point recording | Not yet shared |

## Behavior Matrix

| Behavior | HTTP Server | TLS Server | HTTP/3 | ProxyServer | Mesh |
|----------|-------------|------------|--------|-------------|------|
| URL construction | `PreparedUpstreamTarget` | `PreparedUpstreamTarget` | `PreparedUpstreamTarget` | `join_upstream_url` | Via topology |
| Timeout | From config (via PreparedUpstreamTarget) | From config | From config | Hardcoded 30s | `config.request_timeout_secs` |
| Response size limit | `apply_response_size_limit` | Streaming (no buffer check) | `apply_response_size_limit` | `max_response_size` check | None |
| Retry/Failover | None (single attempt) | None (single attempt) | None (single attempt) | `forward_with_pool` with config | Provider fallback |
| Cache | None | Via ProxyServer | None | `handle_request_with_cache` | L1/L2 + DHT |
| Request headers | `build_forward_headers` | `build_forward_headers` | `build_forward_headers` | `build_forward_headers` | Separate impl |
| Response headers | `filter_response_headers_buf` | `filter_response_headers_buf` | Hop-by-hop only | Hop-by-hop only | Separate impl |
| Security headers | `apply_security_headers` | `inject_security_headers` | None | None | None |
| Per-site TLS | Inline creation | Inline creation | None (plain client) | At construction | Via transport |
| WAF | `check_request_full` | `check_request_full` | `check_request_full` | `check_request_full` | Delegated to peer |
| WASM | Filters + response transforms | None | None | None | None |
| Upload validation | Yes | Yes | None | None | None |

## Remaining Gaps (Tracked in Plan Priorities)

| Gap | Plan Priority | Status |
|-----|---------------|--------|
| Per-site TLS client created per-request (no pooling) | Traffic P4 | OPEN |
| No retry in main HTTP/TLS/HTTP3 direct paths | Traffic P5 | COMPLETED (ProxyServer path only) |
| No cache in HTTP/HTTP3 direct paths | Traffic P6 | COMPLETED (partial) |
| HTTP/3 missing response header filtering and security headers | Traffic P8/P9 | OPEN |
| Mesh has separate header/metric/retry implementation | Traffic P9 | OPEN |
