# HWD-H02: Defer `Http3Server` WAF Storage to `Arc<dyn Http3RequestWaf>`

## Status: DEFERRED

## Task
Change `Http3Server` WAF storage from `Arc<WafCore>` to `Arc<dyn Http3RequestWaf>`.

## Analysis

### Usages of `self.waf` in `src/http3/server.rs`

| Line | Method | Trait | Object-safe? |
|------|--------|-------|:------------:|
| 226, 272 | `connection_limiter()` | `WafAccess` | Yes |
| 227 | `is_over_bandwidth_limit()` | `WafAccess` | Yes |
| 269, 270 | `streaming()` | `WafAccess` | **No** — associated type `StreamingScanner` |
| 278 | `.as_ref()` → `&WafCore` | `Http3RequestWaf` | Yes |

### Blocker: `WafAccess` is not object-safe

`WafAccess` at `crates/synvoid-waf/src/access.rs:23` has:
```rust
pub trait WafAccess: Send + Sync + 'static {
    type StreamingScanner: Send + Sync + 'static;  // ← associated type kills object-safety
    fn connection_limiter(&self) -> Option<Arc<ConnectionLimiter>>;
    fn is_over_bandwidth_limit(&self) -> bool;
    fn streaming(&self) -> Option<Self::StreamingScanner>;  // ← returns associated type
}
```

A composite trait `Http3WafBackend: Http3RequestWaf + WafAccess` would also **not be object-safe** because `WafAccess` is not object-safe.

### Why workarounds propagate broadly

Even defining a new object-safe trait that duplicates `connection_limiter`/`is_over_bandwidth_limit` (omitting `streaming`) doesn't help — `streaming()` is still needed per-request.

Boxing the streaming scanner requires:
1. A unified trait combining `synvoid_http::shared_handler::StreamingWafScanner` and `synvoid_http_client::StreamingWafScanner` (same method signature, different enums)
2. Changing `handle_http3_request_dispatch`, `collect_http3_request_body`, and `handle_http3_found_route` in `synvoid-http` to accept `Box<dyn CombinedScanner>` instead of generic `S`
3. This violates scope constraints ("Do not move HTTP server, HTTP3 server, WafCore... code")

The streaming scanner generic `S` flows through 3+ function signatures across `synvoid-http`. Boxing it propagates broadly.

## Prerequisites for Future Implementation

1. Remove the `StreamingScanner` associated type from `WafAccess`
2. Change `streaming()` to return `Option<Box<dyn StreamingWafScanner>>` (with a unified scanner trait)
3. Update the 3+ dispatch functions in `synvoid-http` to accept boxed scanners
4. Then `WafAccess` becomes object-safe and a composite trait or direct `dyn Http3RequestWaf` approach works

This is a broader refactor touching `synvoid-waf`, `synvoid-http`, and `synvoid-http-client`.
