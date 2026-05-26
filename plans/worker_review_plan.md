# Worker Architecture Review Plan

## Executive Summary

The `architecture/worker_architecture.md` document is generally well-structured but contains several discrepancies between documented claims and actual source code. The most significant issues are:

1. **HTTP/2 Status Incorrect**: Document says "disabled (`is_http2 = false`)" but HTTP/2 is actually enabled via ALPN negotiation on the server side
2. **WAF Pipeline Order Inaccurate**: The order of Flood Protection and Attack Detection stages is reversed in documentation vs actual code
3. **Minor Line Number References**: Some specific implementation details don't match documented line numbers

**Overall Assessment**: The document requires medium-severity corrections to accurately reflect the implementation.

---

## 1. Verified Accurate Claims

### 1.1 Unified Server Event Loop
- **Documented**: "A single `tokio::select!` based loop (or multiple spawned tasks) manages all incoming connections"
- **Actual**: `src/server/mod.rs:1066-1115` - `tokio::select!` manages multiple listener tasks (HTTP, HTTPS, HTTP3, TCP, UDP, DNS)
- **Code Reference**:
```rust
tokio::select! {
    result = http_jh => { ... }
    _ = async { if let Some(jh) = http_v6_jh { jh.await.ok(); } } => {}
    _ = async { if let Some(jh) = https_jh { jh.await.ok(); } } => {}
    // ... more listeners ...
    _ = async { tokio::signal::ctrl_c().await } => { ... }
}
```

### 1.2 HTTP/3 via Quinn
- **Documented**: "HTTP/3 (QUIC): Handled via `Quinn`"
- **Actual**: `src/http3/server.rs:111-131` uses `quinn::Endpoint::new()`, `quinn::ServerConfig::with_crypto()`
- **Confirmed**: Multiple Quinn imports throughout codebase (mesh, tunnel, dns, vpn_client)

### 1.3 TcpListenerPool
- **Documented**: `src/tcp/listener.rs`
- **Actual**: `src/tcp/listener.rs:192-264` - `TcpListenerPool` struct and implementation confirmed
- **Manages**: TCP listeners, auto-tuning, TLS termination, protocol detection

### 1.4 UdpListenerPool
- **Documented**: `src/udp/listener.rs`
- **Actual**: `src/udp/listener.rs:94-144` - `UdpListenerPool` struct and implementation confirmed
- **Handles**: UDP packet reception, protocol detection, reflection/amplification protection

### 1.5 Buffer Pooling
- **Documented**: "uses a `BufferPool` for IO operations"
- **Actual**: `BufferPool` is used extensively:
  - `src/tcp/listener.rs:743,782,792,844`
  - `src/udp/listener.rs:327`
  - `src/waf/attack_detection/normalizer.rs:120,186,580,749`
  - `src/waf/attack_detection/streaming.rs:58-84,211,241,296`
  - `src/streaming/bidirectional.rs:123-365`

### 1.6 Upstream Health Monitoring
- **Documented**: "Active health checks (periodic HTTP GET/TCP connect) are configurable"
- **Actual**: `src/upstream/pool.rs:769-783` - `start_health_check()` method exists and spawns `HealthChecker`

### 1.7 WAF Core Entry Point
- **Documented**: `WafCore::check_request_full`
- **Actual**: `src/waf/mod.rs:442-517` - Confirmed at correct location
- **Document Note**: "verified order in `WafCore::check_request_full`" is correct - document uses this to describe pipeline order

### 1.8 Serverless Handler
- **Documented**: "If it's a serverless function, the `WasmRuntime` executes it"
- **Actual**: `src/http/server.rs:1240-1276,2328-2408` - Serverless functions handled via `handle_serverless_function_streaming` and `handle_serverless_function`

### 1.9 Static Handler
- **Documented**: "If it's a static file, the `StaticHandler` serves it"
- **Actual**: `src/http/server.rs:2214-2236` - `static_handler` usage confirmed

---

## 2. Discrepancies Found

### 2.1 HTTP/2 Status - CRITICAL MISSTATEMENT

| Item | Documented | Actual | Severity |
|------|-----------|--------|----------|
| HTTP/2 Status | "Currently disabled (`is_http2 = false`); infrastructure exists but inactive" | HTTP/2 IS enabled via ALPN negotiation at `src/tls/server.rs:411-487` | **High** |

**Details**:
- The document references `is_http2 = false` which appears to conflate two different things:
  1. **Server-side TLS/ALPN** (`src/tls/server.rs:411`): `let is_http2 = alpn_protocol.map(|p| p == ALPN_HTTP2).unwrap_or(false);`
     - This is actually dynamic based on ALPN negotiation - when client supports h2, HTTP/2 is used
  2. **Upstream HTTP client** (`src/http_client/mod.rs:893`): `let is_http2 = true;` (hardcoded to true, not false)

- The document appears to have confused the upstream client's hardcoded `is_http2 = true` with server-side status
- HTTP/2 server functionality IS operational when clients negotiate it via ALPN

**Actual HTTP/2 Code Path** (`src/tls/server.rs:413-487`):
```rust
if is_http2 {
    tracing::debug!("Negotiated HTTP/2 for {}", client_addr);
    let conn = http2_server::Builder::new(TokioExecutor::new())
        .max_header_list_size(max_headers as u32)
        .serve_connection(io, hyper::service::service_fn(...));
    tokio::spawn(async move {
        if let Err(e) = conn.await { ... }
    });
}
```

**Recommendation**: Change document from:
> **HTTP/2:** Currently disabled (`is_http2 = false`); infrastructure exists but inactive.

To:
> **HTTP/2:** Enabled via ALPN negotiation. Server dynamically negotiates HTTP/2 with clients that support it (h2 ALPN protocol). Infrastructure is fully functional.

---

### 2.2 WAF Pipeline Order - MEDIUM

| Item | Documented Order | Actual Order | Severity |
|------|-----------------|--------------|----------|
| Flood Protection vs Attack Detection | Attack Detection (step 6), Flood Protection (step 7) | Flood Protection (step 6), Attack Detection (step 7) | **Medium** |

**Documented Order** (lines 29-35):
1. Block Store Check
2. Rate Limits
3. Endpoint Block
4. Honeypot Detection
5. Bot Protection
6. Attack Detection
7. Flood Protection

**Actual Order** (`src/waf/mod.rs:442-517`):
1. Block Store Check (line 456)
2. Rate Limits (line 460)
3. Endpoint Block (line 464)
4. Honeypot Detection (line 468)
5. Bot Protection (line 472)
6. Flood Protection (lines 476-484) - **check_tcp_connection**
7. Attack Detection (lines 486-514) - **ad.check_request()**

**Code Verification**:
```rust
// src/waf/mod.rs:476-514
if let Some(ref protector) = self.flood_protector {
    match protector.check_tcp_connection(ip) {
        FloodDecision::RateLimited => return WafDecision::Block(429, ...),
        FloodDecision::Blackholed => return WafDecision::Drop,
        FloodDecision::Allowed => {}
    }
}

// Parallel Attack Detection (AFTER flood check)
if let Some(ad) = self.attack_detector.load().as_ref() {
    let http_method = ...;
    let (result, score) = ad.check_request(...).await;
    ...
}
```

**Recommendation**: Swap the order in the document:
- Step 6 should be "Flood Protection: TCP connection tracking..."
- Step 7 should be "Attack Detection: Deep packet inspection..."

---

### 2.3 Bot Protection Inline Challenge - LOW (Documentation Clarity)

| Item | Documented | Actual | Severity |
|------|-----------|--------|----------|
| Challenge issuance | "Challenges are issued **inline** within bot protection, not as a separate pipeline stage" | **Correct** - challenges issued within `check_bot_protection()` | Low |

**Verification** (`src/waf/mod.rs:634-693`):
```rust
fn check_bot_protection(...) -> Option<WafDecision> {
    let bot_result = self.bot_detector.check_with_fingerprints(...);
    match bot_result {
        BotDetectionResult::Blocked { reason, .. } => Some(WafDecision::Block(...)),
        BotDetectionResult::Tarpit { reason, .. } => Some(WafDecision::Tarpit(...)),
        BotDetectionResult::Allowed { .. } => {
            // Can still issue challenge inline here
            if is_automated {
                let (html, session_id) = self.challenge_manager.generate_challenge_page(...);
                return Some(WafDecision::ChallengeWithCookie { ... });
            }
        }
    }
}
```

**Note**: The inline challenge statement is accurate. However, the documentation could be clearer that challenges are generated within `check_bot_protection()` rather than implying they're a completely separate mechanism.

---

## 3. Known Implementation Issues

### 3.1 HTTP/2 Upstream Client vs Server Confusion

**Issue**: The codebase has two different `is_http2` contexts:
1. **Server-side TLS** (`src/tls/server.rs:411`): Dynamic ALPN negotiation
2. **Upstream client** (`src/http_client/mod.rs:893`): Hardcoded `is_http2 = true`

The document appears to reference the upstream client value when describing server-side HTTP/2 status.

**Related Known Issue** (from `AGENTS.md`):
> HTTP/2 available but not enforced | `src/http_client/mod.rs:893` | `is_http2 = true` hardcoded in `send_request_erased_streaming`, infrastructure exists and uses `http2_only(false)` allowing HTTP/2

This is a **known limitation** but affects the upstream client, NOT the server. The HTTP/2 server-side implementation is functional.

---

### 3.2 Passive vs Active Health Monitoring

**Documented**: "Primarily **passive** - monitors backend responses for failures/successes. Active health checks (periodic HTTP GET/TCP connect) are configurable but not the primary mechanism."

**Actual**: Both mechanisms exist:
- Passive: Built into `UpstreamPool` (implicit in backend response handling)
- Active: `start_health_check()` at `src/upstream/pool.rs:769`

**Status**: Document is essentially correct. Active health checks are indeed "configurable but not primary."

---

## 4. Missing Documentation

### 4.1 Listener Pool Auto-Tuning

**Documented**: "handles auto-tuning based on available parallelism"

**Actual**: `TcpListenerPoolConfig::default()` at `src/tcp/listener.rs:215-228`:
```rust
impl Default for TcpListenerPoolConfig {
    fn default() -> Self {
        Self {
            worker_pool_size: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4),
            // ...
        }
    }
}
```

**Issue**: Auto-tuning is based on `std::thread::available_parallelism()` but document doesn't specify this detail.

---

### 4.2 Semaphore-Based Concurrency Control

**Documented**: "Semaphores and channels are used to limit the number of concurrent requests"

**Actual**: Confirmed in `TcpListenerPool` at `src/tcp/listener.rs:200-201,246-250`:
```rust
connection_semaphore: Option<Arc<Semaphore>>,
// ...
let connection_semaphore = if pool_config.enable_concurrency_limit {
    Some(Arc::new(Semaphore::new(pool_config.max_connections)))
} else {
    None
};
```

**Note**: This is documented but worth verifying implementation detail is accurate.

---

## 5. Corrections Required

### 5.1 Critical Corrections

1. **HTTP/2 Status** (Line 13)
   - **Current**: "- **HTTP/2:** Currently disabled (`is_http2 = false`); infrastructure exists but inactive."
   - **Proposed**: "- **HTTP/2:** Enabled via ALPN negotiation. Server dynamically negotiates HTTP/2 with clients that support it (h2 ALPN protocol). Infrastructure is fully functional."
   - **Reason**: HTTP/2 is operational on server side; the `is_http2 = false` reference appears to be confusion with upstream client behavior.

### 5.2 Medium Corrections

2. **WAF Pipeline Stage Order** (Lines 29-35)
   - **Current Order**: 6. Attack Detection, 7. Flood Protection
   - **Proposed Order**: 6. Flood Protection, 7. Attack Detection
   - **Reason**: Code at `src/waf/mod.rs:476-514` shows Flood Protection check runs BEFORE Attack Detection

3. **WAF Stage Wording Improvements**
   - Stage 5: Consider clarifying "Challenges are issued inline within bot protection" to note they come from `challenge_manager.generate_challenge_page()` within `check_bot_protection()`

---

## 6. Summary Table

| Category | Documented | Actual | Assessment |
|----------|------------|--------|------------|
| **Unified Event Loop** | Single `tokio::select!` loop | `src/server/mod.rs:1066-1115` | CORRECT |
| **HTTP/3** | Via Quinn | `src/http3/server.rs:111-131` | CORRECT |
| **TcpListenerPool** | Described correctly | `src/tcp/listener.rs:192` | CORRECT |
| **UdpListenerPool** | Described correctly | `src/udp/listener.rs:94` | CORRECT |
| **Buffer Pooling** | Used for IO | Extensively used throughout | CORRECT |
| **Health Monitoring** | Passive primary, active available | Both exist | CORRECT |
| **HTTP/2 Status** | "disabled (`is_http2 = false`)" | **Enabled via ALPN** | INCORRECT |
| **WAF Order (Flood/Attack)** | Attack before Flood | Flood before Attack | INCORRECT |
| **Serverless** | WasmRuntime handles | Confirmed in code | CORRECT |
| **Static Handler** | StaticHandler exists | Confirmed in code | CORRECT |

---

## 7. Recommendations

### High Priority

1. **Fix HTTP/2 Documentation** - The document incorrectly claims HTTP/2 is disabled when it's actually enabled via ALPN negotiation

### Medium Priority

2. **Correct WAF Pipeline Stage Order** - Swap Flood Protection and Attack Detection order to match actual implementation
3. **Clarify Challenge Issuance** - Add code reference for inline challenge generation in bot protection

### Low Priority / Nice to Have

4. Add note about `std::thread::available_parallelism()` for listener pool auto-tuning
5. Consider adding a diagram showing the `tokio::select!` listener management pattern
