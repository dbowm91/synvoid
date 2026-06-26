# UnifiedServer Startup and Runtime Architecture

Phase 2 introduced typed boundaries for startup validation, resource construction,
and runtime handle ownership in the UnifiedServer composition root.

## Module Layout

| Module | File | Purpose |
|--------|------|---------|
| `startup_plan` | `src/server/startup_plan.rs` | Pure validated startup state (addresses, rate-limit scaling, feature flags) |
| `resources` | `src/server/resources.rs` | Constructed runtime resources (WAF, pools, TLS, tunnels, DNS) |
| `runtime_handles` | `src/server/runtime_handles.rs` | Owned long-lived task handles with shutdown/drain behavior |
| `plugin_runtime` | `src/server/plugin_runtime.rs` | Plugin load/hot-reload ownership (replaces `mem::forget` leak) |
| `mod.rs` | `src/server/mod.rs` | Public `UnifiedServer` facade and high-level `run()` |

## Startup Flow

1. `UnifiedServer::new()` builds a `UnifiedServerStartupPlan` from config.
2. `UnifiedServerResources::build()` constructs all runtime resources from the plan.
3. `UnifiedServer` stores the plan-derived addresses and resource handles.
4. `run()` spawns protocol listeners and stores handles in `UnifiedServerRuntimeHandles`.

## Lifecycle Rules

- **No `std::mem::forget`** in server or plugin code — enforced by `unified_server_lifecycle_ownership_guard.rs`.
- Plugin hot-reload watcher is owned by `PluginRuntimeOwner` and dropped on server shutdown.
- `UnifiedServerRuntimeHandles` tracks spawned tasks by name and class for graceful shutdown.

## Guardrail Tests

```bash
cargo test --test unified_server_lifecycle_ownership_guard  # No mem::forget in server/plugin
cargo test --lib server::startup_plan                       # Startup validation unit tests
cargo test --lib server::plugin_runtime                     # Plugin lifecycle tests
cargo test --lib server::resources                          # Resource construction tests
cargo test --lib server::runtime_handles                    # Runtime handle tests
```

## Composition Boundary

`UnifiedServerStartupPlan` and `UnifiedServerResources` are composition-root types.
Request-path modules should not import them directly — consume narrow traits instead.
