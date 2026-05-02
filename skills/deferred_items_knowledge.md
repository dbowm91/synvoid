# Knowledge Base: Deferred Items Incremental Implementation

This skill provides context on how deferred items from the original `plans/plan.md` were implemented incrementally.

## Completion Status (Wave 20 - 2026-05-02)

All major plan priorities (P1-P10) across Traffic, WAF/Security, Architecture, Systems, and Distributed layers have been completed. Remaining items are documented as "Deferred" in `plans/todo_deferred.md`.

## Architecture Layer
- **Multi-Crate Workspace**: A proof-of-concept for workspace decomposition is available in `crates/maluwaf-utils`. Future refactors should move more modules (like `src/serialization.rs` or `src/buffer/pool.rs` which are already moved) into this crate or create new ones.
- **Process Isolation (Mesh & Plugin)**: Scaffolding for externalizing mesh and plugin execution into separate processes exists in `src/process/ipc.rs` (new message types: `MeshControlRequest`, `PluginExecuteRequest`) and `src/master/ipc.rs` (routing scaffolding).
- **Config Redesign**: Use `#[serde(alias = "...")]` for non-breaking renames. For example, `FallbackConfig::mode` now has a `strategy` alias.

## Systems Layer
- **Service Manager Integration**: Systemd readiness notification is implemented using `sd-notify`.
- **Native Platform Calls**: Avoid shell-outs for common tasks. `kill -0` and `uname` have been replaced with native calls from the `nix` crate and `sysinfo`.
- **Capability Reporting**: Use the `/api/v1/system/capabilities` endpoint to inspect enabled compile-time features.

## Distributed Layer
- **DHT Routing Performance**: An LRU cache for `find_closest` lookups is implemented in `src/mesh/dht/routing/table.rs` using the `moka` crate.
- **Mesh Admin APIs**: Scaffolding for Raft status inspection is available in `src/admin/handlers/mesh_admin.rs`.

## Development Guidelines
1. **Incremental over Rewrite**: Never rewrite foundations (like Tokio/Hyper) from scratch. Always look for incremental improvements or scaffolding.
2. **Build Integrity**: Ensure `cargo check` passes on all platforms after any IPC or systems-level change.
3. **Backward Compatibility**: Maintain backward compatibility in config and IPC schemas using versioning or aliasing.

## Deferred Items (Not Implemented)

These items require significant architectural changes and are tracked in `plans/todo_deferred.md`:

### Architecture Layer (Wave 2)
- Full multi-crate workspace decomposition
- Moving mesh control-plane into a separate process
- Moving plugin/serverless execution into a separate process
- Replacing the admin UI/API architecture
- A full config schema redesign
- Replacing Tokio/Hyper/Quinn foundations
- Large performance rewrites beyond routing/location hot-path cleanup

### Systems Layer (Wave 3)
- Full service-manager polish for systemd/launchd/Windows SCM
- Large-scale performance tuning outside IPC framing and buffer pool safety
- Replacing all shell-outs across the repository
- Deep WireGuard/TUN backend work
- New admin APIs for platform capability reporting

### Distributed Layer (Wave 4)
- Performance tuning of DHT routing and regional quorum selection
- Major Raft storage schema changes unrelated to auth metadata
- New mesh admin APIs for manual quorum or Raft management
- Changing the public wire protocol beyond the minimum needed for signed context and auth
