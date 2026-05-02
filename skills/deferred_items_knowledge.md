# Knowledge Base: Deferred Items Incremental Implementation

This skill provides context on how deferred items from the original `plans/plan.md` were implemented incrementally.

## Completion Status (Wave 21 - 2026-05-02)

Most plan priorities have been completed or removed. Remaining items are documented in `plans/todo_deferred.md`.

## Architecture Documents

Key architecture documentation is available in the `architecture/` directory:
- `architecture/overview.md` — Module categorization and layer overview
- `architecture/deep_dive_review.md` — Layer 1-3 and 7 deep dive (IPC, WAF, Proxy, Foundation)
- `architecture/layer_3_5_deep_dive.md` — Layer 3 & 5 deep dive (Proxy & Mesh, PQC, Trust Models)

## Deferred Items (Not Implemented)

Remaining items tracked in `plans/todo_deferred.md`:

### Systems Layer (Wave 3)
- Deep WireGuard/TUN backend work, except where platform compile checks require gating

### Distributed Layer (Wave 4)
- Performance tuning of DHT routing and regional quorum selection
- Major Raft storage schema changes unrelated to auth metadata
- New mesh admin APIs for manual quorum or Raft management
- Changing the public wire protocol beyond the minimum needed for signed context and auth

## Removed Items
- **Wave 2**: Admin UI/API redesign, config schema redesign, performance rewrites — not aligned with 100k node target
- **Process isolation stubs**: MeshControlPlane and PluginExecution stubs removed (mesh runs in UnifiedServerWorker, Wasmtime provides sandboxing)
- **Workspace decomposition**: WAF module extraction failed due to cross-dependencies; WafCore remains in main crate
- **Foundational stack replacement**: Tokio/Hyper/Quinn works well; changing would be massive disruption
