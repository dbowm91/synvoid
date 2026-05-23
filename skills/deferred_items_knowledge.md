# Knowledge Base: Deferred Items

Implementation plan remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-23)

All implementation waves completed. Remaining items are deferred due to architectural complexity.

## Recently Completed (2026-05-23)

During the 2026-05-23 plan verification, these fixes were completed:

| ID | Fix | Verification |
|----|-----|--------------|
| REC-1 | Fast-path patterns expanded from 13 to 38 | `src/waf/attack_detection/mod.rs:156-170` |
| REC-3 | Block status configurable via `block_status` field | `src/waf/attack_detection/config.rs:181-186` |
| REC-5 | Request smuggling indicators added to fast_path | Added `transfer-encoding`, `content-length` patterns |
| DOC-3 | VpnClientBuilder documentation corrected | `architecture/dns_deep_dive.md:222` |
| DOC-4 | DNS modules added to docs | `hsm.rs`, `cookie.rs`, `update.rs`, `transfer.rs` |
| ISSUE-5 | Handler count corrected to 28 | Added `behavioral_intel` handler |
| PLUGIN-3 | verify_caller_permission documented | `src/serverless/manager.rs:145-157` |

## Deferred Items

| ID | Issue | Reason | Status |
|----|-------|--------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | DHT ingress validation gaps require fundamental changes | Deferred - Architectural |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete per TODO at `instance.rs:214` | Deferred - Requires Raft |
| MESH-17 | Session Establishment Failure Silently Ignored | Intentional - offer doesn't depend on session state | Working As Designed |
| APP-15 | FastCGI Response NOT Truly Streamed | Known limitation - buffers entire stdout | Deferred - Architectural |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS | Working As Designed |
| DOC-MESH-1 | DHT Ingress Verification Gaps Not Documented | Related to MESH-14 | Deferred |

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

- All 6 implementation waves (W1-W6) - completed 2026-05-23
- All architecture profiles compile
- All security hardening items
- All buffer pool refactoring
- All IPC consolidation
- PID file lock ordering fix
- Profile compilation fixes (mesh, dns, full)