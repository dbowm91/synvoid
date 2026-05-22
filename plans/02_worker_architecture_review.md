# Worker Architecture Review

**Document Under Review**: `architecture/worker_architecture.md`
**Review Date**: 2026-05-22
**Reviewer**: Claude Code (explore agent)

---

## Verified Claims

### 1. Unified Server Architecture

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **Single Tokio async runtime** manages all protocols | Confirmed in `src/server/mod.rs:1050-1099` - `UnifiedServer::run()` uses `tokio::select!` across HTTP, HTTPS, HTTP3, TCP, UDP, DNS listeners | VERIFIED |
| **HTTP/1.1 & HTTP/2** via Hyper | Confirmed in `src/server/mod.rs:882-951` - `run_http_server_inner()` and `run_https_server_inner()` use hyper | VERIFIED |
| **HTTP/3 (QUIC)** via Quinn | Confirmed in `src/server/mod.rs:953-976` - `run_http3_server_inner()` uses `Http3Server` (QUIC) | VERIFIED |
| **TCP & UDP Proxying** with WAF | Confirmed in `src/tcp/listener.rs:315-356` - `TcpListenerPool::start()` spawns listener tasks; UDP in `src/server/mod.rs:988-996` | VERIFIED |
| **Dynamic Site Configuration** with per-site WAF rules | Confirmed via `Router` struct (`src/router.rs:37`) and `SiteConfig` access throughout | VERIFIED |
| **Unified event loop** with `tokio::select!` | Confirmed in `src/server/mod.rs:1050` | VERIFIED |

### 2. Listener Pools

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **TcpListenerPool** manages TCP listeners | Confirmed in `src/tcp/listener.rs:186-259` - `TcpListenerPool` struct with `worker_pool_size` config | VERIFIED |
| **TLS termination** | Confirmed via `cert_resolver` in `src/server/mod.rs:240-254` | VERIFIED |
| **UdpListenerPool** with reflection/amplification protection | Confirmed in `src/server/mod.rs:182-238` - includes `FloodProtector` for rate limiting | VERIFIED |

### 3. WAF Pipeline

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **Connection Phase** - IP rate limiting, CIDR filtering | Confirmed in `src/waf/mod.rs:534-572` - `check_rate_limits()` with flood protection via `src/waf/flood/` | VERIFIED |
| **Protocol Phase** - HTTP method/header validation | Confirmed via `AttackDetector` and `libinjection` in `src/waf/attack_detection/` | VERIFIED |
| **Request Phase** - Deep packet inspection (SQLi, XSS) | Confirmed via `AttackDetector::check_request()` in `src/waf/mod.rs:473-505` | VERIFIED |
| **Bot Detection** - JS/CAPTCHA, behavioral analysis | Confirmed via `BotDetector` in `src/waf/bot.rs` and `check_bot_protection()` in `src/waf/mod.rs:634-649` | VERIFIED |
| **WafCore** coordinates all WAF checks | Confirmed in `src/waf/mod.rs:438-508` - `WafCore::check_request_full()` struct with rate_limiter, bot_detector, attack_detector | VERIFIED |

### 4. Request Flow

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **Accept** by ListenerPool | Confirmed in `src/http/server.rs:505-643` - listener accept loop | VERIFIED |
| **TLS handshake** + ALPN negotiation | Confirmed via `cert_resolver.build_server_config()` in `src/server/mod.rs:1281` | VERIFIED |
| **Route** via Router | Confirmed via `Router::new()` in `src/router.rs:37-178` | VERIFIED |
| **Protect** via WafCore pipeline | Confirmed via `waf.check_request_full()` in `src/waf/mod.rs:438-508` | VERIFIED |
| **StaticHandler** for static files | Confirmed via `StaticFileHandler` in `src/http/server.rs:2205` and `src/router.rs:288-340` | VERIFIED |
| **Proxy to upstream** (FastCGI, HTTP) | Confirmed via `HttpClient` in `src/http_client/` and proxy handling in `src/http/server.rs` | VERIFIED |
| **WasmRuntime** for serverless | Confirmed via `ServerlessManager` in `src/serverless/manager.rs` and wired in `src/worker/unified_server.rs:401-422` | VERIFIED |
| **Response sanitization/compression** | Confirmed via `filter_response_headers_buf()` in `src/http/server.rs` | VERIFIED |

### 5. Resource Management

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **Buffer Pooling** via BufferPool | Confirmed via `BufferPool` in `src/buffer/` and usage in `src/tcp/listener.rs:738-777` | VERIFIED |
| **Concurrency Control** via semaphores | Confirmed via `Semaphore` in `src/tcp/listener.rs:475-485` and `max_connections` limit | VERIFIED |
| **Zero-copy** techniques | Confirmed via `TunnelMessage::write_data_chunk_zero_copy()` in `src/tcp/listener.rs:743-762` and `copy_bidirectional_native` at line 605, 632 | VERIFIED |

---

## Unverified Claims

| Claim | Uncertainty |
|-------|-------------|
| **"Dynamic Site Configuration: handles thousands of domains concurrently"** | The code supports multi-site via `ConfigManager::sites` HashMap, but no stress testing or limits documented. |
| **"Auto-tuning based on available parallelism"** | `TcpListenerPoolConfig::default()` uses `std::thread::available_parallelism()` (`src/tcp/listener.rs:213`), but no dynamic runtime auto-tuning observed. |

---

## Implementation Gaps

### 1. WAF Pipeline Order Different from Documentation

**Gap**: The architecture lists WAF pipeline stages as:
1. Connection Phase
2. Protocol Phase
3. Request Phase
4. Bot Detection

But actual `WafCore::check_request_full()` (`src/waf/mod.rs:450-508`) executes in this order:
1. Block store check (line 452)
2. Rate limits (line 456)
3. Endpoint block (line 460)
4. Honeypot (line 464)
5. Bot protection (line 468)
6. Attack detection (line 473)

**Impact**: Documentation doesn't accurately reflect implementation order.

---

## Code Improvements

### 1. Heartbeat Holds IPC Lock Too Long

**Location**: `src/worker/unified_server.rs:1332-1376`

```rust
let mut ipc = heartbeat_state.ipc.lock().await;
let _ = ipc.send(&Message::UnifiedServerWorkerHeartbeat { ... }).await;
for (site_id, healthy) in app_health {
    let _ = ipc.send(&Message::AppServerHealth { ... }).await;
}
```

**Issue**: The heartbeat loop holds the IPC lock for the entire iteration including the inner loop. This could cause message queuing backpressure.

**Recommendation**: Release IPC lock between messages or batch messages.

### 2. Hardcoded Drain Timeout in Resize Path

**Location**: `src/worker/unified_server.rs:1737`

```rust
let _remaining = wait_for_drain(
    &ipc_state.drain_state,
    30,  // Hardcoded 30 second timeout
    ...
);
```

**Issue**: Standard drain message uses configurable `timeout_secs`, but resize path hardcodes 30 seconds.

**Recommendation**: Use configurable timeout consistent with drain logic.

### 3. Config Reload Silently Ignored for Mesh

**Location**: `src/worker/unified_server.rs:1462-1468`

```rust
if cfg!(feature = "mesh") {
    tracing::error!("Config hot-reload is not supported when mesh...");
    continue;  // Silently ignores reload - Master not notified
}
```

**Issue**: Master receives no indication that reload was rejected.

**Recommendation**: Send explicit rejection message to Master.

### 4. Magic Number Sleep for App Server Initialization

**Location**: `src/worker/unified_server.rs:500`

```rust
tokio::time::sleep(Duration::from_millis(500)).await;
```

**Issue**: 500ms sleep waits for Granian app servers. No explanation why this is sufficient.

**Recommendation**: Add comments or use proper synchronization.

---

## Bug Reports

### 1. Drain State Not Tracking Request Types

**Location**: `src/http/server.rs:260-279`

```rust
struct DrainGuard {
    state: Option<Arc<WorkerDrainState>>,
}
```

**Bug**: `DrainGuard` always calls `increment_active()`/`decrement_active()` but never uses typed variants to track Short/Long/Streaming request distribution.

**Impact**: Cannot make informed decisions about drain timing without request type data.

### 2. TLS Passthrough Sites Logged as Error but Allow Worker Start

**Location**: `src/worker/unified_server.rs:341-367`

```rust
if !bypass_sites.is_empty() {
    tracing::error!(
        "TLS passthrough is enabled for sites: {:?}. WAF inspection is BYPASSED...",
        bypass_sites
    );
    // Worker still starts!
}
```

**Bug**: Sites without rate limiting are logged as errors but don't prevent worker startup.

**Impact**: Worker runs with potentially insecure configuration.

---

## Security Concerns

### 1. TLS Passthrough BYPASSES WAF for L7 Attacks

**Location**: `src/worker/unified_server.rs:341-352`

**Security Issue**: Sites with `tls_passthrough = true` (without `tls_passthrough_enforce_waf = true`) completely bypass all L7 WAF inspection.

**Mitigation**: Code does log errors about this. Users must explicitly set `tls_passthrough_enforce_waf = true` if they want WAF inspection on passthrough traffic.

### 2. Missing Constant-Time Comparison for Trust Token

**Location**: `src/waf/mod.rs:210-216`

```rust
pub fn verify_trust_token(&self, client_ip: IpAddr, token: &str) -> bool {
    let expected = self.generate_trust_token(client_ip);
    if expected.len() != token.len() {
        return false;
    }
    subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), token.as_bytes()).unwrap_u8() == 1
}
```

**Status**: CORRECT - Uses `ConstantTimeEq` properly for trust token verification.

### 3. JA4 Hash Used for Fingerprinting Only

**Location**: Throughout HTTP server and WAF

**Status**: JA4 appears to be used for logging/metrics only, not access control decisions. No security concern identified.

---

## Missing Documentation

### 1. WAF Pipeline Execution Order

**Not Documented**: The architecture lists conceptual phases but not actual execution order in `check_request_full()`.

### 2. StaticHandler Location

**Not Documented**: Static file serving happens in UnifiedServer, not a separate process. The StaticWorker only handles minification/compression.

### 3. RequestServices vs Global Singletons

**Not Documented**: Transition from global singletons (`THREAT_INTEL`, `YARA_RULES`) to `RequestServices` context is not documented.

### 4. Buffer Pool Tier Sizes

**Not Documented**: Buffer sizes like `acquire_small()`, `acquire_medium()` have undocumented sizes.

---

## Summary

The SynVoid worker architecture document is **mostly accurate** and the implementation closely follows the documented design. The core components (UnifiedServer, WafCore, ListenerPools, request flow) are correctly implemented.

**Key Strengths**:
- Comprehensive multi-protocol support (HTTP/1.1, HTTP/2, HTTP/3, TCP, UDP)
- Proper WAF pipeline with rate limiting, bot detection, and attack pattern matching
- Good resource management with buffer pooling and concurrency control
- Well-implemented drain state management for graceful shutdown
- Correct use of constant-time comparison for trust token verification

**Key Issues to Address**:
1. Update WAF pipeline stage documentation to match actual execution order
2. Document that StaticHandler lives in UnifiedServer (not separate process)
3. Track request types (Short/Long/Streaming) in drain state
4. Make config reload rejection explicit to Master
5. Consider making TLS passthrough warnings fatal or adding startup checks
