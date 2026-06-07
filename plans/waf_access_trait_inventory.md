# WAF Access Trait Inventory

**Date**: 2026-06-07
**Task**: HWS-W01

## Summary

Inventory of concrete `WafCore` method accesses in HTTP3 (`src/http3/server.rs`) and HTTP server (`src/http/server.rs`, `src/http/*waf*`, `src/http/*streaming*`) that are **not covered** by existing traits (`WafProcessor`, `WafCoreBackend`, `Http3RequestWaf`, `RequestBodyWaf`, `BufferedRequestWaf`).

## Direct WafCore Access Table

| Access | File/location | Used for | Existing trait covers? | Proposed trait method | Notes |
|--------|---------------|----------|------------------------|----------------------|-------|
| `self.waf.connection_limiter.as_ref()` | `src/http3/server.rs:223` | Passed to `prepare_http3_request_dispatch` as `Option<&Arc<ConnectionLimiter>>` | `BufferedRequestWaf::connection_limiter()` covers it but HTTP3 calls field directly | `connection_limiter()` | Field access, not method call |
| `self.waf.connection_limiter.as_ref()` | `src/http3/server.rs:269` | Passed to `handle_http3_request_dispatch` as `Option<&Arc<ConnectionLimiter>>` | Same as above | `connection_limiter()` | Second call site |
| `self.waf.is_over_bandwidth_limit()` | `src/http3/server.rs:224` | Passed to `prepare_http3_request_dispatch` as `bool` | `BufferedRequestWaf::is_over_bandwidth_limit()` covers it but HTTP3 calls WafCore directly | `is_over_bandwidth_limit()` | Direct method call |
| `self.waf.streaming()` | `src/http3/server.rs:266` | Passed to `handle_http3_request_dispatch` as streaming body scanner | `RequestBodyWaf::streaming()` covers it but HTTP3 calls WafCore directly | `streaming()` | Returns `Option<StreamingWafCore>` |
| `self.waf.streaming()` | `src/http3/server.rs:267` | Passed to `handle_http3_request_dispatch` as streaming upstream scanner | Same as above | `streaming()` | Second call site (same method) |
| `waf.streaming()` | `src/http/streaming_request_fast_path.rs:69` | Gets streaming scanner for request body scanning | `RequestBodyWaf::streaming()` covers it but root code calls WafCore directly | `streaming()` | Root HTTP code |
| `waf.streaming()` | `src/http/streaming_waf_upstream_dispatch.rs:34` | Gets streaming scanner for upstream dispatch | `RequestBodyWaf::streaming()` covers it but root code calls WafCore directly | `streaming()` | Root HTTP code |
| `waf.error_page_manager.render_page_with_theme(...)` | `src/http/streaming_waf_upstream_dispatch.rs:43` | Renders error page for blocked streaming request | Not covered by any trait | **Not proposed** | Root HTTP internal; error page rendering is HTTP-server-specific, not WAF access |
| `waf.error_page_manager.theme()` | `src/http/streaming_waf_upstream_dispatch.rs:52` | Gets theme config for error page | Not covered by any trait | **Not proposed** | Same as above |

## Methods Already Covered by Existing Traits (not proposed for WafAccess)

| Method | Covered by | Notes |
|--------|-----------|-------|
| `check_request_full(...)` | `WafProcessor`, `Http3RequestWaf`, `BufferedRequestWaf` | Request evaluation — WafProcessor's job |
| `check_request_body(chunk)` | `RequestBodyWaf` | Body scanning — WafProcessor's job |
| `generate_tarpit_response(path)` | `Http3RequestWaf`, `BufferedRequestWaf` | Tarpit generation already trait-covered |
| `stream_tarpit(path, user_agent)` | `BufferedRequestWaf` | Tarpit streaming already trait-covered |
| `block_ip_for_honeypot(...)` | `ChallengePathWaf` | IP blocking already trait-covered |
| `block_ip_with_threat_intel(...)` | `UploadValidationWaf` | IP blocking already trait-covered |
| `check_early(...)` | `EarlyWafHooks` | Early check already trait-covered |

## Proposed WafAccess Trait Methods (3 methods)

1. **`connection_limiter()`** → `Option<Arc<ConnectionLimiter>>`
   - Used by HTTP3 at lines 223, 269
   - `ConnectionLimiter` is already in synvoid-waf (`traffic_shaper::ConnectionLimiter`)
   - Returning `Arc` is acceptable; the limiter is a shared resource, not an internal lock

2. **`is_over_bandwidth_limit()`** → `bool`
   - Used by HTTP3 at line 224
   - Simple boolean check, no internal state leakage

3. **`streaming()`** → `Option<StreamingWafCore>`
   - Used by HTTP3 at lines 266, 267
   - `StreamingWafCore` is already in synvoid-waf (`attack_detection::StreamingWafCore`)
   - Returns a cloneable scanner, not internal state

## What is NOT proposed

- **Tarpit/block/drop policy access**: Already covered by `TarpitService`, `ChallengePathWaf`, `Http3RequestWaf` traits
- **Error page rendering**: HTTP-server-specific, not WAF access;留在root
- **`check_request_full`/`check_request_body`**: WafProcessor's job, not WAF access
- **Threat level, violation tracking, probe tracking**: Not used directly by HTTP3/server dispatch code

## Acceptance

```bash
cargo check --lib --no-default-features
```
