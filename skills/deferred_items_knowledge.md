# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-29)

**All fixable deferred items completed**:
- DNS-QUERY (QueryCoalescer max_wait_ms): ✅ Fixed - async redesign
- SUP-1 (gRPC Control Plane TLS): ✅ Fixed - added TLS support
- BUG-PL-4 (macOS Seatbelt): ✅ Fixed - runtime detection
- PR-6 (ProxyHeadersConfig): ✅ Fixed - added field and builder

---

## Remaining Deferred Items (Major Architectural Work)

| ID | Issue | Reason |
|----|-------|--------|
| HTTP2-POOL | ErasedHttpClient HTTP/2 pooling | Erased-client primitives exist, but active streaming proxy path still uses `StreamingHttpClient`; full HTTP/2 pooled streaming lifecycle remains non-default and requires dedicated connection-task management |

### Recently Resolved Former Deferred Items

- `MESH-14` (source node identity/certificate validation):
  - peer certificate verification is wired into connection establishment.
  - mesh TLS trust is explicitly mode-based (`strict` / `tofu` / `permissive`) with strict production baseline.
  - revocation and mode-behavior tests are present in mesh cert/transport tests.
- `MR-4` (signed `DhtSyncRequest` auth rollout):
  - `DhtSyncRequest` includes timestamp/nonce/signature/signer key.
  - default behavior rejects unsigned sync requests (`mesh.dht.require_signed_sync_requests=true`).
  - temporary legacy compatibility requires explicit opt-out (`false`) plus a bounded migration deadline (`mesh.dht.unsigned_sync_compat_until_unix`) in the future.
- `KEY-POL-1` (CanonicalTrustReader injection into RecordStoreManager):
  - Carrier wired in `RecordStoreManager`/`RoutingState`; direct client Push/Announce paths attach for configured contexts.
  - Adapter `validate_dht_key_authority_for_ingress()` active; ingress gate enforces accept/reject/defer for canonical-required keys on configured Push/Announce paths; disabled context preserves legacy.
  - Track complete (Iteration 15). Next step: `AdvisoryRecordSource` before service consumer migration.

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
