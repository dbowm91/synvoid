# Knowledge Base: Deferred Items Incremental Implementation

This skill provides context on how deferred items from the original `plans/plan.md` were implemented incrementally.

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
