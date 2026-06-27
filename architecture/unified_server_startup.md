# UnifiedServer Startup and Runtime Architecture

Phase 2 introduced typed boundaries for startup validation, resource construction,
and runtime handle ownership in the UnifiedServer composition root.

## Module Layout

| Module | File | Purpose |
|--------|------|---------|
| `startup_plan` | `src/server/startup_plan.rs` | Pure validated startup state (addresses, rate-limit scaling, feature flags) |
| `resources` | `src/server/resources.rs` | Constructed runtime resources (WAF, pools, TLS, tunnels, DNS) |
| `runtime_handles` | `src/server/runtime_handles.rs` | **Dead code** — `UnifiedServerRuntimeHandles` is defined but not integrated into `run()` (see below) |
| `plugin_runtime` | `src/server/plugin_runtime.rs` | Plugin load/hot-reload ownership (replaces `mem::forget` leak) |
| `mod.rs` | `src/server/mod.rs` | Public `UnifiedServer` facade and high-level `run()` |

## Startup Flow

1. `UnifiedServer::new()` builds a `UnifiedServerStartupPlan` from config.
2. `UnifiedServerResources::build()` constructs all runtime resources from the plan.
3. `UnifiedServer` stores the plan-derived addresses and resource handles.
4. `run()` spawns protocol listeners with documented ownership.

## UnifiedServerRuntimeHandles — Dead Code

`UnifiedServerRuntimeHandles` (defined in `src/server/runtime_handles.rs`) is **not
integrated into the `run()` method**. It is exported from `src/server/mod.rs` but
never instantiated during server startup. The `run()` method spawns protocol listener
tasks directly via `tokio::spawn()` and collects their `JoinHandle`s inline, then
awaits them in a `tokio::select!` block. The `UnifiedServerRuntimeHandles` type
and its `shutdown_and_join()` drain logic are unused production code.

This type was introduced as part of Phase 2 to provide class-based drain ordering,
but the current `run()` implementation does not use it. The lifecycle guard test
(`unified_server_lifecycle_ownership_guard`) still enforces the `// reason:` comment
requirement on all `tokio::spawn` calls, but does not enforce handle ownership via
this type.

The `RuntimeHandleClass` enum (with variants `CriticalServer`, `ProtocolListener`,
`Maintenance`, `HotReloadWatcher`, `BestEffort`) is also dead code — spawn classes
are documented in `// reason:` comments but not enforced via this enum at runtime.

## Spawn Ownership

Every `tokio::spawn` in `src/server/` must have a `// reason:` comment documenting
its purpose and class. The lifecycle guard test enforces this requirement.

Spawn classes (documented in `// reason:` comments, not enforced via `RuntimeHandleClass`):
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
