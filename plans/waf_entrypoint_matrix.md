# WAF Entrypoint Matrix

**Status**: ACTIVE
**Created**: 2026-05-02
**Purpose**: Document WAF enforcement behavior across all request entry points for MaluWAF.

## Overview

This matrix documents which WAF layers are invoked for each entry point and how they handle request inspection.

## Entrypoints

| Entrypoint | File | Protocol | Notes |
|------------|------|----------|-------|
| HTTP Server | `src/http/server.rs` | HTTP/1.1 | Primary direct proxy path |
| TLS Server | `src/tls/server.rs` | HTTPS | TLS termination then proxy |
| HTTP/3 Server | `src/http3/server.rs` | HTTP/3 | QUIC-based |
| ProxyServer | `src/proxy/mod.rs` | Direct | Separate proxy execution with retry/cache |
| Serverless | `src/spin/handler.rs` | HTTP | Spin-based serverless runtime |
| Static Files | `src/static_files/directory.rs` | Local | Static file serving |
| Health/Ready | `src/http/server.rs` | Localhost | Internal health endpoints |
| Admin | `src/admin/mod.rs` | Various | Admin API endpoints |
| Mesh | `src/mesh/proxy.rs` | Mesh P2P | Routes through mesh network |

## WAF Inspection Columns

| Column | Description |
|--------|-------------|
| early IP checks | Connection limiting, flood protection, bandwidth limits |
| forwarded sanitization | X-Forwarded-For, Forwarded header parsing and sanitization |
| rate limit | Per-client, per-site rate limiting |
| body size | max_request_size enforcement, body too large handling |
| streaming WAF | Chunk-based WAF scanning during body read |
| full attack detection | SQLi, XSS, path traversal, etc. via check_request_full |
| bot/challenge | Bot detection, CSS honeypot, challenge generation |
| endpoint block | IP blocklist, country block, threat intel |
| threat intel | External threat feed lookup, local block store |
| response security headers | Security headers injected on responses |

## Behavior Matrix

### External Entry Points

| Entrypoint | early IP | forwarded san | rate limit | body size | streaming WAF | full attack | bot/challenge | endpoint block | threat intel | resp headers |
|------------|----------|---------------|------------|-----------|---------------|-------------|---------------|----------------|--------------|---------------|
| HTTP Server | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| TLS Server | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTTP/3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| ProxyServer | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |

### Internal/Protected Entry Points

| Entrypoint | early IP | forwarded san | rate limit | body size | streaming WAF | full attack | bot/challenge | endpoint block | threat intel | resp headers |
|------------|----------|---------------|------------|-----------|---------------|-------------|---------------|----------------|--------------|---------------|
| Serverless | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Static Files | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Health/Ready | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Admin | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Mesh | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

## Key Observations

### HTTP Server (Full WAF path)
- Early IP checks via `check_early()` at line 872
- Full forwarded header sanitization via `RequestSanitizer`
- Body collection with chunk-based WAF for large bodies
- Full attack detection via `check_request_full()`
- Bot/challenge handling
- Security headers on responses

### HTTP/3 Server
- Flood protection check at line 154
- Bandwidth limit check at line 228
- Body read with streaming WAF scan on each chunk (line 278)
- Full attack detection via `check_request_full()` (line 320)
- **Missing**: Response security headers (noted as gap in traffic matrix)
- **Note**: Uses `client_ip` from socket directly, not sanitized XFF

### TLS Server  
- Similar to HTTP Server
- No streaming WAF (bodies collected before WAF check)
- Full attack detection

### ProxyServer
- **Issue**: Passes `query_string = None` to WAF (line 327 in proxy/mod.rs)
- This means attacks in query strings bypass WAF detection for direct proxy requests
- Body size not enforced (max_request_size check missing)
- No streaming WAF support

### Serverless
- Respects `ServerlessWafMode` enum:
  - `Enforce` (default): Full WAF enforcement
  - `Log`: WAF runs but doesn't block
  - `Off`: WAF bypassed
- Only path-based routing to functions
- No forwarded header sanitization (trust boundary assumption)

## Required Fixes

### 1. ProxyServer query_string fix (HIGH)
`ProxyServer::handle_request()` passes `query_string = None`. The `path` parameter may contain query string. Need to:
- Split path into path and query before WAF call
- Pass query_string separately to `check_request_full()`

### 2. HTTP/3 forwarded sanitization (MEDIUM)
HTTP/3 uses `client_ip = remote_addr.ip()` directly without checking X-Forwarded-For headers. This is intentional (QUIC connections are trusted) but should be documented.

### 3. ProxyServer body size (MEDIUM)
ProxyServer does not enforce `max_request_size`. Consider adding body size check.

## Intentional Differences (Documented)

| Difference | Reason |
|------------|--------|
| HTTP/3 no response security headers | HTTP/3 response path is different, security headers added at response time |
| Mesh no WAF | Mesh is internal network, WAF applied at edge entry |
| Serverless no bot/challenge | Serverless is internal/trusted path |
| Static files no WAF | Static files are pre-approved content |
| Health/Ready bypass | Internal endpoints for monitoring |

## Status

- ProxyServer query_string fix: **IN PROGRESS**
- ServerlessWafMode: **COMPLETED** (Wave 17)
- HTTP/3 alignment: **PARTIAL** (streaming WAF, full attack detection present)