# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-27)

**All wave implementation items completed and pruned from plan**:
- Wave 1 (BUG-DNS-1, BUG-DNS-4): Completed/Fixed
- Wave 2 (IMPROVE-1, BUG-HTTP-4, AUTH-1, PROXY-1, BUG-PL-3, BUG-WAF-3, DNS-2): All completed
- Wave 3 (documentation fixes): Completed
- Wave 4 (feature enhancements): Completed

Remaining deferred items are documented in `plans/plan.md`.

---

## Deferred Items (Architectural Changes Required)

| ID | Issue | Reason |
|----|-------|--------|
| MESH-14 | Source Node ID Binding Validation | Partial validation exists (node_id vs peer_id via TLS), but no TLS cert chain validation - requires breaking changes |
| HTTP2-POOL | ErasedHttpClient HTTP/2 support | `Http2PooledConnection` is empty stub - hyper-util API investigation needed |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |
| MR-4 | DhtSyncRequest has no auth | Breaking protobuf protocol change - no signature field |
| DNS-QUERY | QueryCoalescer max_wait_ms | Documented limitation, may not be fixable (underscore prefix = unused) |
| PR-6 | ProxyHeadersConfig not passed through send_single_request | Enhancement, not a bug |
| BUG-PL-4 | macOS Seatbelt implementation incomplete | Feature-gated, returns false by default |

---

## Verified Fixes Summary (2026-05-27)

| Bug ID | Issue | Fix |
|--------|-------|-----|
| BUG-DNS-1 | HickoryRecursor DNSSEC policy SecurityUnaware | ✅ FIXED - resolver.rs:693-702 now uses ValidateWithStaticKey |
| BUG-DNS-4 | HickoryResolver always returns false | ✅ DONE - by design (hickory-resolver API limitation for forwarder mode) |
| IMPROVE-1 | HTTP/3 body collection divergence | ✅ DONE - documented in http3/server.rs:343-348 with explanatory comments |
| BUG-HTTP-4 | request_body_size double assignment | ✅ FIXED - removed duplicate assignment at server.rs:1579 |
| AUTH-1 | max_failed_attempts default 5 vs docs 3 | ✅ FIXED - WafCore now uses 3 |
| PROXY-1 | PeakEwma weighting clarification | ✅ DONE - docs clarify 90% weight to previous value |
| BUG-PL-3 | Windows Socket FD Passing Not Functional | ✅ DONE - documented in platform.md (Windows uses WSADuplicateSocketW) |
| BUG-WAF-3 | SiteConnectionLimiter dead code | ✅ FIXED - struct removed from limiter.rs |
| DNS-2 | DNSSEC ECDSA Algorithm Gap | ✅ DONE - RFC5011_TRUST_ANCHOR.md marks ECDSA as "Not implemented" |

---

## Known Implementation Notes

| Item | Location | Issue |
|------|----------|-------|
| ErasedHttpClient Phase 9 | `src/http/server.rs:3302` | `use_erased_client` hardcoded to `false` - Phase 9 never completed |
| HTTP/2 configurable | `src/http_client/mod.rs:893` | Now configurable via `ProxyServer::with_http2()` builder method |
| DNS Cookie Server | `src/dns/cookie.rs` | Fully wired via `validate_cookie()` in query.rs:645-662 |
| Spin instance reuse | `src/spin/runtime.rs:289-303` | Uses `get_or_create_instance()` caching with 5-min idle timeout |
| GOST DS digest | `src/dns/dnssec_validation.rs:260` | Returns error - requires gost94 crate |

---

## Architecture Documents

Key architecture documentation is available in the `architecture/` directory:
- `architecture/overview.md` — Module categorization and layer overview
- `architecture/deep_dive_review.md` — Layer 1-3 and 7 deep dive (IPC, WAF, Proxy, Foundation)
- `architecture/layer_3_5_deep_dive.md` — Layer 3 & 5 deep dive (Proxy & Mesh, PQC, Trust Models)

## Verification Commands

```bash
# All profiles should compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Security regression tests
cargo test --test security_regression

# DNS tests
cargo test --lib dns
```