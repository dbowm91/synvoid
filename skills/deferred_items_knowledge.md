# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-23)

All waves (1-3) completed and merged. Remaining items are deferred due to architectural complexity or are working-as-designed.

## Deferred Items

| ID | Issue | Reason | Status |
|----|-------|--------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | Fixed via `validate_peer_node_id_binding()` helper in `transport_peer.rs` | **FIXED** - 2026-05-23 |
| MESH-15 | Quorum Deadlock Risk During Partition | RwLock deadlock was overstated; fixed `get_last_log_index()` and sync logic | **FIXED** - 2026-05-23 |
| APP-15 | FastCGI Response NOT Truly Streamed | Known limitation - buffers entire stdout | Deferred - Architectural |
| SUP-1 | Session Establishment Failure Silently Ignored | Intentional - offer doesn't depend on session state | Working As Designed |

## Known Incomplete Items

These are known limitations, not bugs:

| Item | Location | Issue |
|------|----------|-------|
| ErasedHttpClient Phase 9 | `server.rs:3302` | `use_erased_client` hardcoded to `false` - Phase 9 never completed |
| HTTP/2 ALPN enabled | `http_client/mod.rs:889` | `is_http2 = true` now, ALPN configured but connection pooling may need tuning |
| DNS Cookie Server | `server/mod.rs:847,861` | Integrated into DnsServer - needs testing in production |
| Minification unused | `static_files/mod.rs:134-136` | `new_with_minifier()` accepts minifier params but silently ignored |
| Spin instance reuse | `spin/runtime.rs:260` | Only compiled_runtimes cached, not SpinAppInstance - per-request overhead |
| GOST DS digest | `dnssec_validation.rs:260` | Returns error - requires gost94 crate |

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