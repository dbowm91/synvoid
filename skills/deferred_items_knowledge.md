# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-27)

**All fixable deferred items completed**:
- DNS-QUERY (QueryCoalescer max_wait_ms): ✅ Fixed - async redesign
- SUP-1 (gRPC Control Plane TLS): ✅ Fixed - added TLS support
- BUG-PL-4 (macOS Seatbelt): ✅ Fixed - runtime detection
- PR-6 (ProxyHeadersConfig): ✅ Fixed - added field and builder

---

## Remaining Deferred Items (Major Architectural Work)

| ID | Issue | Reason |
|----|-------|--------|
| MESH-14 | Source Node ID Binding Validation | Partial validation exists (node_id bound to TLS), but no TLS cert chain validation for global nodes - requires PKI hierarchy, trust model changes |
| HTTP2-POOL | ErasedHttpClient HTTP/2 pooling | `Http2PooledConnection` is empty stub - hyper-util API requires background task management per connection |
| MR-4 | DhtSyncRequest has no auth | Breaking protobuf protocol change - no signature field, coordinated rollout required |

---

## Completed Fixes Summary (2026-05-27)

| Bug ID | Issue | Fix | Details |
|--------|-------|-----|---------|
| DNS-QUERY | QueryCoalescer max_wait_ms unused | Async redesign | Added max_wait Duration field, changed get_or_wait() to async with tokio::timeout |
| SUP-1 | gRPC Control Plane TLS not implemented | TLS support added | Added control_api_tls config, tonic TLS support, --control-api-tls CLI flag |
| BUG-PL-4 | macOS Seatbelt silent failure | Runtime detection | Added dlsym(RTLD_DEFAULT, "sandbox_init") check, proper error handling |
| PR-6 | ProxyHeadersConfig not passed | Field added | Added proxy_headers_config field to ProxyServer, builder method, apply in send_single_request |

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