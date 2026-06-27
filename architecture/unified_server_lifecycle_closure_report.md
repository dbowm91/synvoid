# UnifiedServer Lifecycle Closure Report

Date: 2026-06-27
Base: 435d2db088e705ecddda546611f72ca51dc70df3

## Summary

Integrated `UnifiedServerRuntimeHandles` into `UnifiedServer::run()`, replacing
the fire-and-forget `tokio::select!` pattern with structured shutdown:
broadcast → join → abort-on-timeout → report. `PluginRuntimeOwner` now outlives
all server tasks. All long-lived spawns go through `spawn_registered` helpers.

## Spawns Inventory

| Task | Name | Class | Status |
|------|------|-------|--------|
| HTTP/1 IPv4 | `http_v4` | CriticalServer | Registered |
| HTTP/1 IPv6 | `http_v6` | ProtocolListener | Registered |
| HTTPS IPv4 | `https_v4` | CriticalServer | Registered |
| HTTPS IPv6 | `https_v6` | ProtocolListener | Registered |
| HTTP/3 IPv4 | `http3_v4` | ProtocolListener | Registered |
| HTTP/3 IPv6 | `http3_v6` | ProtocolListener | Registered |
| TCP pool | `tcp_pool` | ProtocolListener | Registered |
| UDP pool | `udp_pool` | ProtocolListener | Registered |
| DNS server | `dns` | ProtocolListener | Registered |
| Threat-level auto-scale | `threat_level_auto_scale` | Maintenance | Registered (was fire-and-forget) |
| ACME init/renewal | `acme_init_renewal` | Maintenance | Registered (was fire-and-forget) |
| ACME cert reload IPC | *(short-lived)* | *(exempt)* | Bounded callback |
| Plugin hot-reload | *(PluginRuntimeOwner)* | HotReloadWatcher | Lifetime extended to after shutdown |

## Changes Made

### `src/server/runtime_handles.rs`
- Added `RuntimeTaskExit` enum for task exit classification.
- Added `ServerTaskResult` type alias.
- Changed `NamedRuntimeHandle.join` from `JoinHandle<()>` to `JoinHandle<ServerTaskResult>`.
- Added `names()` method for iterating handle metadata.
- Added `spawn_registered()` and `spawn_registered_unit()` helpers.
- Added `// reason:` comments to infrastructure spawns.
- Added tests: `critical_task_failure_counted_in_report`, `shutdown_and_join_aborts_timeout_task`, `maintenance_task_clean_exit_on_shutdown`, `spawn_registered_helpers_work`, `names_returns_all`.

### `src/server/mod.rs`
- `run()` now creates `UnifiedServerRuntimeHandles::new()` and registers all spawns.
- `PluginRuntimeOwner` created early and dropped only after `shutdown_and_join()`.
- Replaced inline `tokio::spawn` with `spawn_registered` / `spawn_registered_unit`.
- Replaced `tokio::select!` with shutdown-broadcast + oneshot pattern.
- Added `shutdown_and_join(Duration::from_secs(30))` with structured report logging.
- `setup_acme()` no longer spawns init/renewal task (now registered in `run()`).

### `tests/unified_server_lifecycle_ownership_guard.rs`
- Added `unified_server_runtime_handles_are_integrated` test.
- Added `server_long_lived_spawns_go_through_registration` test.
- Added `plugin_runtime_owner_is_stored_for_runtime_lifetime` test.
- Total: 5 guard tests (was 2).

### `architecture/unified_server_startup.md`
- Removed "dead code" status for `UnifiedServerRuntimeHandles`.
- Documented full lifecycle flow, task inventory, and shutdown semantics.
- Documented non-mesh HTTP no-op behavior.

## Tests Run

```bash
cargo test --test unified_server_lifecycle_ownership_guard  # 5 passed
cargo test -p synvoid --lib server::                        # 152 passed
cargo test -p synvoid --lib server::runtime_handles          # 7 passed
```

## Residual Risks

1. **ACME cert reload IPC callback** is a short-lived `tokio::spawn` inside
   `setup_acme()`. It is exempt from handle registration (BoundedShortLived)
   and documented in the guard test allowlist. If ACME internals need deeper
   lifecycle improvement, that belongs to a later plugin hardening phase.

2. **Non-mesh HTTP no-op** behavior is intentional and documented. Full non-mesh
   runtime is not in scope for this pass.

3. **`join_next_finished`** was removed from `UnifiedServerRuntimeHandles` due
   to borrow-checker constraints. The main loop uses shutdown-broadcast +
   oneshot channel for critical failure detection instead. This is simpler and
   avoids self-referential borrow issues.

## Final Acceptance Statement

All 8 acceptance criteria from the plan are met:

1. ✅ `UnifiedServerRuntimeHandles` is instantiated and used by `run()`.
2. ✅ No architecture doc describes it as dead code.
3. ✅ Protocol listener tasks are registered with names and classes.
4. ✅ Threat-level auto-scale and ACME renewal tasks are registered.
5. ✅ `PluginRuntimeOwner` remains alive until after task shutdown.
6. ✅ Shutdown broadcasts, joins, aborts on timeout, and reports.
7. ✅ Direct long-lived `tokio::spawn` rejected by guardrails.
8. ✅ `mem::forget` remains absent.
