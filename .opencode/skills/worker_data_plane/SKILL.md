---
name: worker_data_plane
description: UnifiedServerWorker data plane — HTTP+WAF+proxy in one Tokio loop; composition-root ownership rules, DataPlaneServices/RequestServices boundary, task registry, shutdown policy.
---

# Skill: Worker Data Plane (UnifiedServerWorker)

## Context

The data plane handles connection accept, HTTP/TLS, WAF, routing, and proxy streaming in
ONE Tokio event loop per worker process. CPU-heavy offload lives in `src/worker/cpu_task/`.
Full reference: `architecture/worker_data_plane_composition_root.md`,
`architecture/worker_task_lifecycle.md`, `architecture/http_request_pipeline.md`,
`architecture/worker_architecture.md`. Subsystem rules: `src/worker/AGENTS.override.md`.

## When to Use

Use this skill when:
- Adding a capability/service to the worker request path
- Changing worker startup sequencing, supervision loops, or shutdown
- Touching `DataPlaneServices`, `RequestServices`, or mesh attachment
- Adding background tasks (they MUST be registered in `WorkerTaskRegistry`)
- Working on CPU offload (`src/worker/cpu_task/`)

## Key Files

| File | Purpose |
|------|---------|
| `src/worker/unified_server/mod.rs` | Primary composition root (sole owner of readiness/restart/exit policy) |
| `src/worker/unified_server/services.rs` | Data-plane assembly boundary: builds/cross-wires `DataPlaneServices` + `RequestServices` via `build_and_cross_wire()` — never cross-wire manually |
| `src/worker/unified_server/startup_plan.rs` | Startup orchestration: identity → mesh pipeline |
| `src/worker/unified_server/supervision_loop.rs` | Select loop for lifecycle events/task exits/mesh decisions |
| `src/worker/unified_server/shutdown_executor.rs` | Ordered shutdown + `WorkerShutdownPlan` |
| `src/worker/context.rs` | `RequestServices`: narrow request-path handle |
| `src/worker/task_registry.rs` | Task lifecycle classes (`CriticalService`, `RestartableBackground`, `OneShot`) |
| `src/worker/cpu_task/` | CPU offload worker |

## Non-Negotiables

1. **Composition boundary** (guard-enforced by `tests/boundary_composition_guard.rs`):
   request path consumes narrow traits
   (`Arc<dyn BlockListStore>`, `Arc<dyn WafProcessor>`); concrete infra is constructed only
   in composition roots. New files under `src/worker/unified_server/` must get an explicit
   `BoundaryRole` classification or the guard fails closed.
2. **No bare `tokio::spawn`** without an owner and a `// reason:` comment; register tasks
   in the appropriate registry class.
3. **Exit policy**: derive exit codes from `WorkerShutdownCause::exit_code()`; no other
   module may call `std::process::exit()`.
4. **Mesh restart is disabled** in production policy (`restart_enabled = true` is rejected);
   map stray `RestartMesh` decisions to `MeshRestartExhausted`.
5. Request dispatch must not import worker lifecycle modules or `UnifiedServerWorkerState`
   (guard: `tests/http_request_pipeline_boundary_guard.rs`).

## Verification

```bash
cargo nextest run --test boundary_composition_guard --cargo-profile ci --profile ci
cargo nextest run --test composition_root_behavioral --features mesh,dns --cargo-profile ci --profile ci
```
