# SynVoid Implementation Plan

> **Note**: Most items from the 2026-05 architecture reviews have been completed.
> This file is pruned to only contain deferred items and known issues.
> For completed items, see git history.

## Priority Key
- **P0**: Critical security/regression bugs
- **P1**: High-impact bugs or architectural issues
- **P2**: Medium-priority improvements
- **P3**: Low-priority documentation/accuracy fixes

---

## Known Deferred Items

These items require significant architectural changes or are intentionally deferred:

| ID | Issue | Reason | Status |
|----|-------|--------|--------|
| **MR-4** | DhtSyncRequest has no auth | Requires breaking protobuf protocol change | Deferred |
| **MESH-14** | No Source Node ID Binding Validation in All Ingress Paths | Requires fundamental changes to bind node_id to TLS/cert identity at connection time | Deferred |
| **MESH-15** | Quorum Deadlock Risk During Partition | Raft implementation incomplete, requires Raft migration | Deferred |
| **APP-15** | FastCGI Response NOT Truly Streamed | Buffers entire stdout; architectural change needed | Deferred |
| **SUP-1** | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS | By Design |
| **PL-5** | DrainManager not ported to Supervisor | Supervisor lacks per-worker connection tracking during drain. Documented limitation at `src/supervisor/process.rs:17-26` | Known Limitation |

---

## Known Implementation Issues

These are tracked for awareness but may not be practical to fix:

| ID | Issue | Impact | Status |
|----|-------|--------|--------|
| **TunnelBackend** | `src/tunnel/upstream.rs:105-123` deprecated with hardcoded 127.0.0.1 | Not used by active routing path (uses `TunnelRouter::resolve_tunnel_backend()` instead) | Deprecated/Reserved |
| **WRK-BUG-1** | HTTP/2 hardcoded to `true` in some proxy paths | Infrastructure exists to make configurable but not all paths use it | Partial Fix |
| **HTTP/2 Pooling** | HTTP/2 upstream connection pooling not fully wired | Infrastructure exists (Http2PooledConnection, typed pool branches) but not used in production | Milestone Planned |

---

## Recently Completed Items

For reference, the following items were completed in recent sprints:

### P0/P1 Fixes (Completed 2026-05-27)
- **BUG-CORS-1**: CORS dead code removed from admin API
- **DNS-1**: DNS Cookie Server wired into query validation
- **PLAT-4**: `is_admin_required_for_tun()` stub fixed for Unix platforms
- **PLUGIN-2/7**: PooledInstance DHT/Body leak fixed
- **PLUGIN-8**: ServerlessManager warmup consistency
- **PLUGIN-9**: Spin manifest validates HTTP trigger routes
- **PLUGIN-10**: Unauthorized DHT query logging elevated to error
- **PLUGIN-11**: WASI configurable per-component in Spin manifest
- **WR-1**: WAF connection limits documentation corrected

### Documentation Fixes (Completed 2026-05-27)
- **MR-5**: hierarchical_routing.rs has `#![allow(dead_code)]` with rationale
- **MR-7**: Regional quorum scaling limits documented
- **APP-3/5/6**: BackendType mapping and InstancePool documentation clarified
- **CFG-BUG-1**: AppServerConfig port mismatch verified as not a bug

---

## Quick Reference: Remaining Bugs

| Bug ID | Severity | Description | Location | Status |
|--------|----------|-------------|----------|--------|
| MR-4 | High | DhtSyncRequest has no auth | `src/mesh/transport_peer.rs:687-704` | Deferred |
| CFG-BUG-1 | Low | AppServerConfig port mismatch | `crates/synvoid-config/src/app_server.rs:49` | Verified Not A Bug |

---

*Last Updated: 2026-05-27*
*This file is pruned - full history available in git*