# Worker Architecture Review

**Document Under Review**: `architecture/worker_architecture.md`
**Review Date**: 2026-05-06
**Reviewer**: Claude Code

---

## Verified Claims

### 1. Unified Server Architecture

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **Single Tokio async runtime** manages all protocols | Confirmed in `src/server/mod.rs:774-1132` - `UnifiedServer::run()` uses `tokio::select!` across HTTP, HTTPS, HTTP3, TCP, UDP, DNS listeners | VERIFIED |
| **HTTP/1.1 & HTTP/2** via Hyper | Confirmed in `src/server/mod.rs:911-949` - `run_http_server_inner()` and `run_https_server_inner()` use hyper | VERIFIED |
| **HTTP/3 (QUIC)** via Quinn | Confirmed in `src/server/mod.rs:982-1005` - `run_http3_server_inner()` uses `Http3Server` (QUIC) | VERIFIED |
| **TCP & UDP Proxying** with WAF | Confirmed in `src/tcp/listener.rs:300-341` - `TcpListenerPool::start()` spawns listener tasks; UDP in `src/server/mod.rs:1017-1025` | VERIFIED |
| **Dynamic Site Configuration** with per-site WAF rules | Confirmed via `Router` struct (`src/router.rs:31`) and `SiteConfig` access throughout | VERIFIED |
| **Unified event loop** with `tokio::select!` | Confirmed in `src/server/mod.rs:1079-1128` | VERIFIED |

### 2. Listener Pools

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **TcpListenerPool** manages TCP listeners | Confirmed in `src/tcp/listener.rs:171-243` - `TcpListenerPool` struct with auto-tuning via `worker_pool_size` | VERIFIED |
| **TLS termination** | Confirmed via `cert_resolver` in `src/server/mod.rs:239-253` | VERIFIED |
| **UdpListenerPool** with reflection/amplification protection | Confirmed in `src/server/mod.rs:181-237` - includes `FloodProtector` for rate limiting | VERIFIED |

### 3. WAF Pipeline

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **Connection Phase** - IP rate limiting, CIDR filtering | Confirmed in `src/waf/mod.rs:1221-1294` - `check_rate_limit()` and flood protection via `src/waf/flood/` | VERIFIED |
| **Protocol Phase** - HTTP method/header validation | Confirmed via `AttackDetector` and `libinjection` in `src/waf/attack_detection/libinjection.rs` | VERIFIED |
| **Request Phase** - Deep packet inspection (SQLi, XSS) | Confirmed via `AttackDetector` modules in `src/waf/attack_detection/` | VERIFIED |
| **Bot Detection** - JS/CAPTCHA, behavioral analysis | Confirmed via `BotDetector` in `src/waf/bot.rs` and `ChallengeManager` | VERIFIED |
| **WafCore** coordinates all WAF checks | Confirmed in `src/waf/mod.rs:202-229` - `WafCore` struct with rate_limiter, bot_detector, attack_detector, etc. | VERIFIED |

### 4. Request Flow

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **Accept** by ListenerPool | Confirmed in `src/http/server.rs:506-643` - listener accept loop | VERIFIED |
| **TLS handshake** + ALPN negotiation | Confirmed via `cert_resolver.build_server_config()` in `src/server/mod.rs:1304` | VERIFIED |
| **Route** via Router | Confirmed via `Router::new()` in `src/router.rs:31` | VERIFIED |
| **Protect** via WafCore pipeline | Confirmed via `waf.check_request_full()` in `src/waf/mod.rs:1036-1164` | VERIFIED |
| **StaticHandler** for static files | Confirmed via `StaticWorker` in `src/worker/mod.rs:96-521` | VERIFIED |
| **Proxy to upstream** (FastCGI, HTTP) | Confirmed via `HttpClient` in `src/http_client/` and proxy handling | VERIFIED |
| **WasmRuntime** for serverless | Confirmed via `ServerlessManager` in `src/serverless/` | VERIFIED |
| **Response sanitization/compression** | Confirmed via `ResponseBuilder` and `headers` module | VERIFIED |

### 5. Resource Management

| Document Claim | Code Verification | Status |
|---------------|-------------------|--------|
| **Buffer Pooling** via BufferPool | Confirmed via `BufferPool` in `src/buffer/` and usage in `src/tcp/listener.rs:723` | VERIFIED |
| **Concurrency Control** via semaphores | Confirmed via `Semaphore` in `src/http/server.rs:352` and `connection_limit` | VERIFIED |
| **Zero-copy** techniques | Confirmed via `TunnelMessage::write_data_chunk_zero_copy()` in `src/tcp/listener.rs:728-756` | VERIFIED |

---

## Unverified Claims

| Claim | Uncertainty |
|-------|-------------|
| **"Dynamic Site Configuration: handles thousands of domains concurrently"** | The code supports multi-site via `ConfigManager::sites` HashMap, but no stress testing or limits documented. The claim cannot be confirmed or denied without load testing. |
| **"Auto-tuning based on available parallelism"** | `TcpListenerPoolConfig::default()` uses `std::thread::available_parallelism()` (`src/tcp/listener.rs:198`), but actual auto-tuning at runtime (dynamic adjustment) is not implemented - only uses system parallelism at startup. |

---

## Implementation Gaps

### 1. Missing StaticHandler in Unified Server

**Gap**: The architecture document mentions `StaticHandler` in the request flow, but the `UnifiedServer` does not serve static files directly. Instead, static file serving is delegated to a separate **StaticWorker** process (`src/worker/mod.rs:96-521`).

**Impact**: The request flow diagram showing `StaticHandler` serving static files is misleading for the unified worker. Static files are served via IPC to a separate worker process.

### 2. Connection Pooling for Upstreams Not Explicitly Documented

**Gap**: The architecture mentions "Connection Pooling: maintains persistent connections to backend servers (PHP-FPM, Granian, etc.)" but the actual implementation via `UpstreamClientRegistry` and `HttpClient` connection pooling is not detailed.

**Location**: `src/http_client/mod.rs` and `src/proxy/client_registry.rs`

### 3. WAF Pipeline Stages Are Approximate

**Gap**: The document lists WAF pipeline stages as:
1. Connection Phase
2. Protocol Phase
3. Request Phase
4. Bot Detection

But the actual `WafCore::check_request_full()` executes in this order:
1. ASN check
2. Rate limit check
3. IP feed check
4. DHT threat lookup (mesh only)
5. Endpoint block check
6. Suspicious words check
7. Honeypot check
8. Bot protection check
9. Attack pattern check
10. Challenge check

**Impact**: The documented stages do not accurately reflect the implementation order.

---

## Code Improvements

### 1. Inconsistent Error Handling in Mesh Initialization

**Location**: `src/worker/unified_server.rs:547-838`

```rust
#[cfg(feature = "mesh")]
if let Err(e) = crate::mesh::backend::initialize_mesh_transports(...).await {
    tracing::warn!("Mesh transport initialization failed: {}", e);
}
```

**Issue**: Mesh transport initialization failure is only logged as a warning, but the worker continues to operate. This could lead to a false sense of security if mesh features are expected but unavailable.

**Recommendation**: Add a configuration option to control whether mesh transport failure should be fatal or warnings-only.

### 2. Hardcoded Timeouts and Magic Numbers

**Location**: `src/worker/unified_server.rs:433`

```rust
tokio::time::sleep(Duration::from_millis(500)).await;
```

**Issue**: This 500ms sleep is a magic number that waits for Granian app servers to initialize. No comments explaining why 500ms is sufficient or what guarantees this provides.

**Recommendation**: Add a proper synchronization mechanism (e.g., a oneshot channel) to wait for app server initialization instead of arbitrary sleep.

### 3. Static Worker IPC Leaks Memory

**Location**: `src/worker/mod.rs:881-886`

```rust
if let Err(e) = lifecycle.enable_hot_reload(plugin_dir) {
    tracing::debug!("Hot-reload not enabled: {}", e);
}
std::mem::forget(lifecycle);
```

**Issue**: `std::mem::forget(lifecycle)` intentionally leaks the lifecycle object to keep the file watcher alive. This is documented but could cause memory to grow unbounded over time if plugins are loaded/unloaded frequently.

**Recommendation**: Document this as a known memory growth vector and provide a mechanism to limit the number of leaked lifecycle objects.

### 4. Missing Request Type Tracking in HTTP Server

**Location**: `src/http/server.rs:260-279`

```rust
struct DrainGuard {
    state: Option<Arc<WorkerDrainState>>,
}
```

**Issue**: `DrainGuard` always calls `increment_active()`/`decrement_active()` but never uses the typed variants (`increment_active_typed`/`decrement_active_typed`) to track whether requests are Short, Long, or Streaming.

**Recommendation**: Pass request type information to `DrainGuard` so it can track request type distribution during drain.

### 5. TLS Passthrough Warning Logic

**Location**: `src/worker/unified_server.rs:275-309`

The code logs errors when TLS passthrough sites lack rate limiting, but the error handling doesn't prevent the worker from starting.

**Issue**: The worker starts successfully even with these configuration issues. The errors are logged but the system proceeds with potentially insecure defaults.

---

## Bug Reports

### 1. Race Condition in Worker Heartbeat

**Location**: `src/worker/unified_server.rs:1245-1288`

```rust
let heartbeat_handle = tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        // ...
        let mut ipc = heartbeat_state.ipc.lock().await;
        let _ = ipc.send(&Message::UnifiedServerWorkerHeartbeat { ... }).await;
        for (site_id, healthy) in app_health {
            let _ = ipc.send(&Message::AppServerHealth { ... }).await;
        }
    }
});
```

**Bug**: The heartbeat loop holds the IPC lock for the entire iteration, including the inner loop that sends multiple `AppServerHealth` messages. This could cause message queuing backpressure and missed heartbeats if the inner loop is slow.

**Impact**: Master may miss AppServerHealth updates if network is slow.

### 2. Drain Timeout Ignored in Resize Path

**Location**: `src/worker/unified_server.rs:1630-1675`

```rust
Some(Message::UnifiedServerWorkerResize { worker_threads }) => {
    // ...
    let _remaining = wait_for_drain(
        &ipc_state.drain_state,
        30,  // Hardcoded 30 second timeout
        &ipc_state.worker_id,
        "resize request",
    )
    .await;
    // ...
}
```

**Bug**: The resize handler ignores the worker's configuration and hardcodes a 30-second drain timeout, while the standard drain message carries a configurable `timeout_secs`.

**Impact**: Inconsistent drain behavior between resize and standard drain operations.

### 3. Config Reload Silently Fails for Mesh

**Location**: `src/worker/unified_server.rs:1368-1401`

```rust
Some(Message::MasterConfigReload { config_path }) => {
    if cfg!(feature = "mesh") {
        tracing::error!(
            "Config hot-reload is not supported when mesh feature is enabled. \
            Mesh, YARA rules, threat intel, and honeypot changes require full worker restart. \
            Please restart the worker to apply mesh-related configuration changes."
        );
        continue;  // Silently ignores reload request
    }
    // ... reload logic
}
```

**Bug**: When mesh is enabled, the reload request is silently ignored via `continue`. The caller (Master) has no indication that the reload was rejected.

**Impact**: Master may believe config was reloaded when it wasn't.

---

## Security Concerns

### 1. Missing Constant-Time Comparison for JA4 Hash Comparison

**Location**: `src/server/request_handler.rs:96-98`

```rust
impl ConnectionMeta for crate::tls::server::HttpsConnection {
    fn get_ja4(&self) -> Option<String> {
        crate::tls::server::HttpsConnection::get_ja4(self)
    }
}
```

**Concern**: If JA4 hash comparison is used for any security decisions, it should use `subtle::ConstantTimeEq` per the security standards. However, based on the code, JA4 appears to be used for logging/fingerprinting only.

**Status**: No immediate vulnerability identified, but verify JA4 is not used for access control decisions.

### 2. TLS Passthrough BYPASSES WAF for L7 Attacks

**Location**: `src/worker/unified_server.rs:282-293`

```rust
if !bypass_sites.is_empty() {
    tracing::error!(
        "TLS passthrough is enabled for sites: {:?}. WAF inspection is BYPASSED for these sites - L7 attacks will not be blocked.",
        bypass_sites
    );
    // ...
}
```

**Security Issue**: Sites configured with `tls_passthrough = true` (without `tls_passthrough_enforce_waf = true`) completely bypass all L7 WAF inspection. An attacker aware of this configuration could direct attack traffic to these sites to evade detection.

**Mitigation**: The code does log errors about this configuration. The concern is whether users are aware of this security implication.

### 3. Port Honeypot Threat Publishing Without Signature Verification

**Location**: `src/worker/unified_server.rs:1112-1125`

```rust
if let Some(ref runner) = port_honeypot_runner {
    #[cfg(feature = "mesh")]
    if let Some(ref threat_intel) = _threat_intel_manager {
        runner.start_mesh_threat_publishing(threat_intel.clone(), 30);
        // ...
    }
}
```

**Concern**: When port honeypot detects a threat and publishes it to the mesh network, the code should verify that the recipient is a trusted peer before acting on the threat data. Need to verify that `threat_intel.announce_honeypot_indicator()` includes proper signature verification.

---

## Missing Documentation

### 1. UnifiedServer Lifecycle Management

**Not Documented**: The interaction between `UnifiedServer::run()`, worker shutdown signals, and drain state is not well documented.

Key missing details:
- How `shutdown_tx` and `stop_accepting_tx` interact
- The exact order of shutdown operations
- How ongoing requests are handled during drain

### 2. RequestServices Context Transition

**Not Documented**: The architecture uses a mix of global singletons (`THREAT_INTEL`, `YARA_RULES`) and `RequestServices` context. The deprecation comments in `src/waf/mod.rs:119-168` indicate this is transitional, but no migration plan is documented.

### 3. Mesh Transport Initialization Sequence

**Not Documented**: The complex mesh initialization in `src/worker/unified_server.rs:547-1046` has no accompanying documentation explaining:
- Why certain components must be initialized in a specific order
- What happens if DHT routing manager fails to initialize
- How threat intelligence is shared between workers

### 4. Buffer Pool Sizing

**Not Documented**: The buffer sizes used throughout the codebase are hardcoded:
- `TcpListenerPoolConfig::buffer_size = 64 * 1024` (64KB)
- `UdpListenerPoolConfig::buffer_size = 8192` (8KB)
- `BufferPool::acquire_medium()` and `acquire_small()` - sizes not documented

### 5. Static Worker Process Isolation

**Not Documented**: The architecture says the StaticWorker handles "CSS/JS minification, compression" but doesn't explain:
- Why this requires process isolation
- How the IPC protocol works between UnifiedServer and StaticWorker
- What happens if StaticWorker becomes unavailable

---

## Summary

The SynVoid worker architecture document is **mostly accurate** and the implementation closely follows the documented design. The core components (UnifiedServer, WafCore, ListenerPools, request flow) are correctly implemented and well-structured.

**Key Strengths**:
- Comprehensive multi-protocol support (HTTP/1.1, HTTP/2, HTTP/3, TCP, UDP)
- Proper separation of concerns via WAF pipeline stages
- Good resource management with buffer pooling and concurrency control
- Well-implemented drain state management for graceful shutdown

**Key Issues to Address**:
1. Document StaticWorker as a separate process serving static files via IPC (not in UnifiedServer)
2. Update WAF pipeline stage documentation to match actual execution order
3. Add proper synchronization for app server initialization instead of arbitrary sleep
4. Track request types (Short/Long/Streaming) in drain state
5. Make config reload rejection explicit to Master
6. Document the RequestServices transition plan from global singletons
7. Add mesh transport initialization sequence documentation
