# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-23)

All waves (1-3) completed and merged. Remaining items are deferred due to architectural complexity or are working-as-designed.

## Deferred Items

| ID | Issue | Reason | Status |
|----|-------|--------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | DHT ingress validation gaps require fundamental changes | Deferred - Architectural |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete per TODO at `instance.rs:214` | Deferred - Requires Raft |
| MESH-17 | Session Establishment Failure Silently Ignored | Intentional - offer doesn't depend on session state | Working As Designed |
| APP-15 | FastCGI Response NOT Truly Streamed | Known limitation - buffers entire stdout | Deferred - Architectural |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS | Working As Designed |
| DOC-MESH-1 | DHT Ingress Verification Gaps Not Documented | Related to MESH-14 | Deferred |

## Known Incomplete Items

These are known limitations, not bugs:

| Item | Location | Issue |
|------|----------|-------|
| ErasedHttpClient Phase 9 | `server.rs:3302` | `use_erased_client` hardcoded to `false` |
| AXFR record types | `transfer.rs:829-878` | Missing SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA |

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