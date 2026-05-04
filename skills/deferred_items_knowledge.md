# Knowledge Base: Deferred Items

Implementation plan is complete. Remaining items are documented in `plans/plan.md`.

## Current Status (2026-05-04)

All plan items have been verified and completed. The plan file has been pruned to contain only deferred items.

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

## Completed Items (2026-05-04)

The following major items were completed:
- All 4 implementation waves (W1-W4)
- All architecture profiles compile
- All security hardening items
- All buffer pool refactoring
- All IPC consolidation
- PID file lock ordering fix
- Profile compilation fixes (mesh, dns, full)

## Deferred Items

Remaining deferred items are documented in `plans/plan.md` and include:
- Testing infrastructure (Sandbox Leak Test, Socket Hijack Test)
- Plugin isolation (GlobalWasmMemoryBudget wiring)
- Health API integration
- Config reload improvements
- DHT routing optimization for 100k+ node scale
