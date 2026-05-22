# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-22)

Wave 6 and Wave 8 have been completed:
- MESH-11: Quorum Manager race condition ✅ FIXED
- APP-17: pip install hash verification ✅ FIXED
- MESH-16: dead code removal ✅ FIXED

## Remaining Deferred Items

| ID | Issue | Reason |
|----|-------|--------|
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete per TODO at `instance.rs:214` |
| APP-15 | FastCGI Response NOT Truly Streamed | Requires architectural change to async streaming |
| MESH-14 | No Source Node ID Binding Validation | Fundamental identity model changes needed |
| DOC-MESH-1 | DHT Ingress Verification Gaps Not Documented | Related to MESH-14 |
| SUP-1 | gRPC Control Plane TLS | Working As Designed - localhost IPC doesn't need TLS |
| MESH-17 | Session Establishment Failure Silently Ignored | Working As Designed - session is optional for key offers |

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

## Previously Completed Items

- All 4 implementation waves (W1-W5) - completed 2026-05-06
- All architecture profiles compile
- All security hardening items
- All buffer pool refactoring
- All IPC consolidation
- PID file lock ordering fix
- Profile compilation fixes (mesh, dns, full)
- Wave 6/8 fixes (MESH-11, APP-17, MESH-16) - completed 2026-05-22