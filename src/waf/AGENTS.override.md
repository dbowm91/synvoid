# WAF Module - AGENTS.override.md

## Module Overview

The WAF module (`src/waf/`) provides attack detection, request sanitization, and response handling.

## Key Files

- `src/waf/mod.rs` - WafCore, request handling, threat intel integration
- `src/waf/attack_detection/` - Rule matching and detection engines
- `src/server/waf_handler.rs` - WafResponseIntent, ProtocolAdapter trait, WafContext

## Hot Path

`src/waf/attack_detection/` — WAF rule matching runs per-request on all inputs. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### Rule Matching

- Rule matching executes on every input for every request
- Use `HashMap`/`HashSet` for rule lookups
- Lazy evaluation for rule parsing

### Attack Detection Action Semantics

`check_attack_patterns()` reads action from config:
- `stall` (default): returns `WafDecision::Stall`
- `block`: returns `WafDecision::Block(403, "Forbidden")`
- `log`: records metrics but returns `None` (request passes)

### Trusted Proxy XFF Handling

`get_real_ip()` and `find_client_ip_in_xff()` must scan XFF right-to-left:
- First trusted proxy marks the trusted suffix boundary
- Client is the first untrusted public IP immediately before the trusted suffix
- Never return `ips[0]` - standard XFF order is `client, proxy1, proxy2`

### Body Inspection UTF-8 Hardening

When inspecting request body, use `String::from_utf8_lossy()` instead of `unwrap_or("")`:
```rust
// WRONG - invalid UTF-8 becomes empty string, evading detection
let body_str = std::str::from_utf8(body).unwrap_or("");

// CORRECT - invalid bytes replaced with U+FFFD
let body_str = String::from_utf8_lossy(body);
```

### Serverless Mode

Use `ServerlessWafMode` enum (`enforce|log|off`) instead of boolean `serverless_only`:
- `enforce`: WAF always active
- `log`: WAF runs but doesn't block
- `off`: WAF disabled

### Stall/Tarpit Concurrency Safety

Stall actions can exhaust worker resources at high traffic. Use bounded stall with metrics:
- `max_stalled_requests` config limits concurrent stalls (default 100)
- Metrics: `ACTIVE_STALLED_REQUESTS`, `STALL_REJECTED_CONCURRENCY_CAP`, `STALL_TIMEOUTS`
- When cap reached, return 429 instead of stalling

See `skills/performance_patterns.md` for implementation details.

## RequestServices Context Pattern (Wave 3)

**Status**: ✅ COMPLETE (2026-05-06)

**Problem**: Accessing global services (Threat Intel, Yara) via `ArcSwap` in hot path causes CPU cache contention.

**Solution**: Thread `Arc<RequestServices>` through WafContext instead of using atomic loads.

### Key Changes

1. **WafContext** now holds `Arc<RequestServices>`:
   ```rust
   pub struct WafContext {
       pub services: Arc<RequestServices>,
       // ... other fields
   }
   ```

2. **WafCore::check_request_full** accepts optional services:
   ```rust
   pub fn check_request_full(
       &self,
       path: &str,
       query_string: Option<&str>,
       body: Option<&[u8]>,
       services: Option<Arc<RequestServices>>,
   ) -> WafDecision
   ```

3. **Usage pattern**:
   - `services` parameter defaults to `None`
   - When `None`, falls back to `self.request_services.load()` (backward compat)
   - When `Some(services)`, uses passed services (eliminates atomic load)

4. **All callers updated** to pass `None` as the services parameter to maintain API compatibility. Future work: replace `None` with actual services from context.

## ProtocolAdapter send_waf_response (Wave 2)

**Status**: ✅ COMPLETE (2026-05-06)

Added `send_waf_response` to `ProtocolAdapter` trait in `src/server/waf_handler.rs`:
```rust
async fn send_waf_response(
    &self,
    intent: WafResponseIntent,
) -> Result<http::Response<Full<Bytes>>, anyhow::Error>;
```

Implemented for:
- `HttpProtocolAdapter`
- `HttpsProtocolAdapter`
- `Http3ProtocolAdapter`

Note: The adapters return the built response; actual wire sending is done by the caller.

## Skills Reference

- `skills/streaming_waf.md` — Streaming WAF engine patterns
- `skills/security_patterns.md` — Constant-time comparison, path traversal, XSS prevention
- `skills/performance_patterns.md` — Performance optimization patterns