# UnifiedServer Startup and Runtime Architecture

Phase 2 introduced typed boundaries for startup validation, resource construction,
and runtime handle ownership in the UnifiedServer composition root. Phase 2.5
(lifecycle closure) integrated `UnifiedServerRuntimeHandles` into `run()` and
established structured shutdown with broadcast/join/abort semantics.

## Module Layout

| Module | File | Purpose |
|--------|------|---------|
| `startup_plan` | `src/server/startup_plan.rs` | Pure validated startup state (addresses, rate-limit scaling, feature flags) |
| `resources` | `src/server/resources.rs` | Constructed runtime resources (WAF, pools, TLS, tunnels, DNS) |
| `runtime_handles` | `src/server/runtime_handles.rs` | `UnifiedServerRuntimeHandles` — registered task tracking, shutdown drain, and spawn helpers |
| `plugin_runtime` | `src/server/plugin_runtime.rs` | Plugin load/hot-reload ownership (replaces `mem::forget` leak) |
| `mod.rs` | `src/server/mod.rs` | Public `UnifiedServer` facade and structured `run()` lifecycle |

## Startup Flow

1. `UnifiedServer::new()` builds a `UnifiedServerStartupPlan` from config.
2. `UnifiedServerResources::build()` constructs all runtime resources from the plan.
3. `UnifiedServer` stores the plan-derived addresses and resource handles.
4. `run()` creates `UnifiedServerRuntimeHandles`, `PluginRuntimeOwner`, and registers
   all server tasks through `spawn_registered` / `spawn_registered_unit`.

## UnifiedServerRuntimeHandles — Integrated

`UnifiedServerRuntimeHandles` is instantiated in `run()` and used as the single
owner of all server-spawned long-lived tasks. Every protocol listener, maintenance
task, and DNS server is registered with a name and class. On shutdown:

1. Shutdown signal is broadcast via `shutdown_tx`.
2. `handles.shutdown_and_join(timeout)` joins all registered tasks within a deadline.
3. Tasks exceeding the deadline are aborted and awaited.
4. A `UnifiedServerRuntimeShutdownReport` is emitted with completion/failure/timeout counts.
5. `PluginRuntimeOwner` is dropped after all tasks have drained.

### Spawn Registration Helpers

```rust
spawn_registered(&mut handles, "http_v4", RuntimeHandleClass::CriticalServer, async { ... });
spawn_registered_unit(&mut handles, "tcp_pool", RuntimeHandleClass::ProtocolListener, async { ... });
```

These helpers wrap `tokio::spawn` and register the resulting `JoinHandle` with the
handles collection. All long-lived server spawns must use these helpers (enforced
by `server_long_lived_spawns_go_through_registration` guard test).

## Task Inventory

| Task | Name | Class | File | Shutdown behavior |
|------|------|-------|------|-------------------|
| HTTP/1 IPv4 | `http_v4` | CriticalServer | `listener_tasks.rs:26` | broadcast + join |
| HTTP/1 IPv6 | `http_v6` | ProtocolListener | `listener_tasks.rs:36` | broadcast + join |
| HTTPS IPv4 | `https_v4` | CriticalServer | `listener_tasks.rs:66` | broadcast + join |
| HTTPS IPv6 | `https_v6` | ProtocolListener | `listener_tasks.rs:94` | broadcast + join |
| HTTP/3 IPv4 | `http3_v4` | ProtocolListener | `listener_tasks.rs:128` | broadcast + join |
| HTTP/3 IPv6 | `http3_v6` | ProtocolListener | `listener_tasks.rs:142` | broadcast + join |
| TCP pool | `tcp_pool` | ProtocolListener | `listener_tasks.rs:159` | broadcast + join |
| UDP pool | `udp_pool` | ProtocolListener | `listener_tasks.rs:169` | broadcast + join |
| DNS server | `dns` | ProtocolListener | `listener_tasks.rs:213` | broadcast + join |
| Threat-level auto-scale | `threat_level_auto_scale` | Maintenance | `service_assembly.rs:158` | shutdown watch + join |
| ACME init/renewal | `acme_init_renewal` | Maintenance | `listener_tasks.rs:242` | shutdown watch + join |
| ACME cert reload IPC | *(short-lived)* | *(exempt)* | `mod.rs` | callback-owned, completes quickly |
| Plugin hot-reload | *(owned by PluginRuntimeOwner)* | HotReloadWatcher | `plugin_runtime.rs` | dropped after task shutdown |

## Spawn Classes

- **CriticalServer**: HTTP/1 IPv4, HTTPS IPv4 — primary protocol listeners whose exit triggers shutdown. `RuntimeHandleClass` also carries `BestEffort` for ephemeral/best-effort tasks (`runtime_handles.rs:17-23`).
- **ProtocolListener**: HTTP/3, TCP/UDP pools, DNS — secondary listeners.
- **Maintenance**: Background tasks (threat-level auto-scale, ACME renewal).
- **HotReloadWatcher**: Plugin hot-reload file watchers (owned by `PluginRuntimeOwner`).
- **BestEffort**: Ephemeral or best-effort tasks.

## Plugin Owner Lifetime

`PluginRuntimeOwner` is created before the first task is spawned and stored as a
local variable in `run()`. It is explicitly dropped (`drop(plugin_owner)`) only
after `handles.shutdown_and_join()` completes. This ensures the hot-reload file
watcher remains alive for the full server runtime lifetime.

## Lifecycle Rules

- **No `std::mem::forget`** in server or plugin code — enforced by the server/plugin section of `tests/lifecycle_task_guard.rs` (there is no standalone `unified_server_lifecycle_ownership_guard.rs` file).
- **Every `tokio::spawn` must have a `// reason:` comment** — enforced by `tokio_spawns_require_reason_comments`.
- **Long-lived spawns must use `spawn_registered`/`spawn_registered_unit`** — enforced by `server_long_lived_spawns_go_through_registration`.
- **`UnifiedServerRuntimeHandles` must be instantiated** — enforced by `unified_server_runtime_handles_are_integrated`.
- **`PluginRuntimeOwner` must outlive task shutdown** — enforced by `plugin_runtime_owner_is_stored_for_runtime_lifetime`.

## Non-Mesh HTTP Behavior

**The HTTP listener serves on all feature profiles**, mesh or not.
`run_http_server_inner()` (`src/server/mod.rs:524`) unconditionally builds the
`HttpServer` and calls `server.serve().await`; the mesh-specific wiring
(`with_mesh_config` / `with_mesh_transport` / `with_mesh_backend_pool`) is the
only part behind `#[cfg(feature = "mesh")]`. The source carries an explicit
qualification comment at `src/server/mod.rs:604-607`:

> NOTE (eggbench qualification): the HTTP listener serves on all profiles. A
> `#[cfg(not(feature = "mesh"))] let _ = server;` stub here silently disabled the
> data plane on minimal builds; the accept loop carries no mesh dependency.

An earlier revision of this document claimed the opposite (a non-mesh binary that
does not serve HTTP). That stub has been removed; the claim is retracted.

## Guardrail Tests

```bash
cargo test --test lifecycle_task_guard  # server/plugin guards: mem::forget, reason comments, handles integrated, spawns registered, plugin owner lifetime
cargo test -p synvoid --lib server::startup_plan           # Startup validation unit tests
cargo test -p synvoid --lib server::plugin_runtime         # Plugin lifecycle tests
cargo test -p synvoid --lib server::resources              # Resource construction tests
cargo test -p synvoid --lib server::runtime_handles        # Runtime handle tests (7 tests)
```

## Composition Boundary

`UnifiedServerStartupPlan` and `UnifiedServerResources` are composition-root types.
Request-path modules should not import them directly — consume narrow traits instead.
