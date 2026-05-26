# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-26)

**Architecture Review Plan: COMPLETED**

All items from the 2026-05-26 architecture review plan have been verified and completed:
- **Wave 1-5**: All complete
- **Supervisor Migration**: Pending (see `plans/plan.md`)

### Notable Fixes Applied

| Item | Fix |
|------|-----|
| Capsicum `limit_fd()` dead code | Removed unused method from `src/platform/sandbox.rs` |
| SiteConnectionLimiter | Confirmed as dead code but not blocking - HTTP path works via `try_acquire_with_limits()` |

---

## Deferred Items (Architectural Complexity)

These items are intentionally deferred due to architectural complexity:

| ID | Issue | Reason |
|----|-------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | Requires fundamental changes to bind node_id to TLS/cert identity |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete, requires Raft migration |
| APP-15 | FastCGI Response NOT Truly Streamed | Buffers entire stdout, architectural change needed for true streaming |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |

---

## Known Incomplete Items (Working As Designed)

These are known limitations, not bugs:

| Item | Location | Issue |
|------|----------|-------|
| ErasedHttpClient Phase 9 | `src/http/server.rs:3305` | `use_erased_client` hardcoded to `false` - Phase 9 never completed |
| HTTP/2 available but not enforced | `src/http_client/mod.rs:893` | `is_http2 = true` hardcoded, uses `http2_only(false)` allowing protocol negotiation |
| DNS Cookie Server not integrated | `src/dns/cookie.rs`, `src/dns/server/mod.rs` | Complete implementation exists but not wired in |
| Minification unused | `src/static_files/mod.rs:134-136` | `new_with_minifier()` accepts minifier params but silently ignored |
| Spin instance reuse | `src/spin/runtime.rs:260` | Only compiled_runtimes cached, not SpinAppInstance - per-request overhead |
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
```
