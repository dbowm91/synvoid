# MaluWAF Implementation Plan

**Status**: Active - All Items Complete
**Last Updated**: 2026-04-26

## Implementation Summary

All 126 implementation items across 8 waves (Critical + Waves 1-7) have been completed.

| Wave | Items | Status |
|------|-------|--------|
| Wave 0 (Critical) | 9 | **COMPLETE** |
| Wave 1 | 14 | **COMPLETE** |
| Wave 2 | 16 | **COMPLETE** |
| Wave 3 | 22 | **COMPLETE** |
| Wave 4 | 20 | **COMPLETE** |
| Wave 5 | 17 | **COMPLETE** (5.1 blocked - skipped) |
| Wave 6 | 14 | **COMPLETE** |
| Wave 7 | 14 | **COMPLETE** (7.11 Org Key Trust Chain deferred) |

## Deferred Items

The following items were intentionally deferred or blocked:

### 5.1: utoipa 4→5 Upgrade
- **Status**: BLOCKED - Dependency version conflicts
- **Reason**: `utoipa-swagger-ui = "9"` requires `utoipa >= 5`, but other dependencies are pinned to utoipa 4
- **Action**: Monitor for resolution of dependency conflicts

### 7.11: Org Key Trust Chain
- **Status**: DEFERRED (4-5 weeks effort)
- **Reason**: Very large implementation requiring new modules (organization.rs, org_key_manager.rs, etc.)
- **Sub-phases**: Core types → DHT integration → OrgKeyManager → Quorum formation → Peer auth → Heartbeat → Auto-renewal → Integration
- **Trust chain**: Genesis Key → Global Nodes (2/3 quorum) → Org Keys → Edge Nodes

### 7.2: hickory-recursor 0.25 → 0.26 Migration
- **Status**: DEFERRED
- **Reason**: Requires Rust 1.85 for ml-kem dependency
- **Action**: Migration guide documented in plan, execute when Rust 1.85 is available

## Configuration Options

### mesh.config
```toml
[mesh.proxy]
request_timeout_secs = 30
policy_cache_ttl_secs = 3600
stale_cache_ttl_secs = 60
whitelist_regex_cache_size = 1000
whitelist_regex_cache_ttl_secs = 3600

[mesh.yara_rules]
fanout_factor = 0.5
re_announce_interval_secs = 3600
```

### limits.config
```toml
[limits.upstream]
min_pool_size = 10
max_pool_size = 1000
dynamic_pool_sizing = false
```

### serverless.config
```toml
[serverless]
enabled = true
default_memory_mb = 64
default_cpu_fuel = 1000000
default_timeout_seconds = 30
default_min_instances = 1
default_max_instances = 10
default_idle_timeout_seconds = 300
event_consumer_interval_secs = 1
pool_stats_broadcast_interval_secs = 10
storage_namespace_isolation = true
```

---

## Key Codebase Facts

- **Architecture**: Overseer → Master → Workers (Unix domain socket IPC)
- **Mesh types**: `MeshBackend`, `MeshBackendPool` in `src/mesh/backend.rs`
- **Mesh routing**: Enable via `mesh_routing = true` in site config
- **Base64**: `get_public_key()` uses `URL_SAFE_NO_PAD`; any decoder using `STANDARD` is wrong
- **Serialization**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary
- **Timestamps**: Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`

---

## Sub-Agent Execution Guide

### Common patterns:
- **Serialization**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary
- **Timestamps**: Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`
- **Concurrency**: Use `DashMap` instead of `RwLock<HashMap>` for hot paths
- **Caching**: Use Moka `Cache` with capacity + TTL bounds
- **Errors**: Use `thiserror` for error types, add variants to existing error enums
- **IPC**: Use `Message` enum in `src/process/ipc.rs` for new message types
- **Metrics**: Add `AtomicU64` counters in `src/metrics/mod.rs` following dropped events pattern

### Verification commands:
```bash
cargo test --lib --no-run          # Verify test code compiles
cargo test --test integration_test # Integration tests (~5s)
cargo fmt                           # Format
cargo clippy -- -D warnings         # Lint
```
