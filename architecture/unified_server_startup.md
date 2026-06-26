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
4. `run()` spawns protocol listeners with documented ownership.

## Spawn Ownership

Every `tokio::spawn` in `src/server/` must have a `// reason:` comment documenting
its purpose and class. The lifecycle guard test enforces this requirement.

Spawn classes:
- **CriticalServer**: HTTP/1, HTTPS — primary protocol listeners
- **ProtocolListener**: HTTP/3, TCP/UDP pools, DNS — secondary listeners
- **Maintenance**: Background tasks (threat-level auto-scale, ACME renewal)
- **HotReloadWatcher**: Plugin hot-reload file watchers (owned by `PluginRuntimeOwner`)

## Lifecycle Rules

- **No `std::mem::forget`** in server or plugin code — enforced by `unified_server_lifecycle_ownership_guard.rs`.
- **Every `tokio::spawn` must have a `// reason:` comment** — enforced by `tokio_spawns_require_reason_comments`.
- Plugin hot-reload watcher is owned by `PluginRuntimeOwner` and dropped on server shutdown.

## Guardrail Tests

```bash
cargo test --test unified_server_lifecycle_ownership_guard  # No mem::forget + reason comments
cargo test -p synvoid --lib server::startup_plan           # Startup validation unit tests (9 tests)
cargo test -p synvoid --lib server::plugin_runtime         # Plugin lifecycle tests
cargo test -p synvoid --lib server::resources              # Resource construction tests (5 tests)
cargo test -p synvoid --lib server::runtime_handles        # Runtime handle tests
```

## Composition Boundary

`UnifiedServerStartupPlan` and `UnifiedServerResources` are composition-root types.
Request-path modules should not import them directly — consume narrow traits instead.
