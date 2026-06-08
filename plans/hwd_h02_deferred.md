# HWD-H02: Defer `Http3Server` WAF Storage to `Arc<dyn Http3RequestWaf>`

## Status: COMPLETED

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

### Resolved: `WafAccess` object-safety achieved

`WafAccess` at `crates/synvoid-waf/src/access.rs` was refactored to remove the `StreamingScanner` associated type. `streaming()` now returns `Option<Box<dyn StreamingWafScanner>>` where `StreamingWafScanner` is a unified trait defined in `crates/synvoid-core/src/streaming_waf.rs`. Both `synvoid-http` and `synvoid-http-client` re-export from `synvoid-core`.

With `WafAccess` now object-safe, a composite trait `Http3WafBackend: Http3RequestWaf + WafAccess` was introduced and `Http3Server.waf` changed from `Arc<WafCore>` to `Arc<dyn Http3WafBackend>`.

### What was done

1. **Unified `StreamingWafScanner` trait**: Moved to `crates/synvoid-core/src/streaming_waf.rs`. Both `synvoid-http` and `synvoid-http-client` re-export from `synvoid-core`.
2. **`WafAccess` object-safe**: Removed `StreamingScanner` associated type; `streaming()` returns `Option<Box<dyn StreamingWafScanner>>`.
3. **`RequestBodyWaf` object-safe**: Same change — associated type removed, `streaming()` returns boxed trait object.
4. **`Http3WafBackend` composite trait**: `trait Http3WafBackend: Http3RequestWaf + WafAccess`. `Http3Server.waf` is now `Arc<dyn Http3WafBackend>`.
5. **Dispatch generics simplified**: All `S: StreamingWafScanner` generic parameters in HTTP/3 and HTTP/1 dispatch functions replaced with concrete `Option<Box<dyn StreamingWafScanner>>`.
