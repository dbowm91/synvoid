# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-27)

**Plan items pruned** - All wave implementation items completed:
- MESH-15 (Quorum deadlock): Fixed ✅
- WRK-BUG-1 (HTTP/2): Fixed ✅
- PL-5 (DrainManager): Fixed ✅
- APP-15 (FastCGI streaming): Fixed ✅
- TUNNEL-FIX: Deprecated TunnelBackend removed ✅

Remaining deferred items are documented in `plans/plan.md`.

---

## Deferred Items (Architectural Changes Required)

| ID | Issue | Reason |
|----|-------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | Requires fundamental changes to bind node_id to TLS/cert identity |
| HTTP2-POOL | ErasedHttpClient HTTP/2 support | hyper http2_client::handshake() API incompatible with current hyper-util |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |
| MR-4 | DhtSyncRequest has no auth | Breaking protobuf protocol change |

---

## Known Incomplete Items (Working As Designed)

These are known limitations, not bugs:

| Item | Location | Issue |
|------|----------|-------|
| ErasedHttpClient Phase 9 | `src/http/server.rs:3302` | `use_erased_client` hardcoded to `false` - Phase 9 never completed |
| HTTP/2 available but not enforced | `src/http_client/mod.rs:893` | Configurable via `ProxyServer::with_http2()` builder method |
| DNS Cookie Server | `src/dns/cookie.rs` | Fully wired via `validate_cookie()` in query.rs:648 |
| Minification unused | `src/static_files/mod.rs:134-136` | `new_with_minifier()` accepts minifier params but silently ignored |
| Spin instance reuse | `src/spin/runtime.rs:258` | Uses `get_or_create_instance()` caching with 5-min idle timeout |
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

# Quorum tests
cargo test --lib quorum
```