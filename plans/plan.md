# MaluWAF Implementation Plan

**Status**: Active - Implementation Complete, Maintenance Mode
**Last Updated**: 2026-04-26

## Completed Items

### Org Key Trust Chain (7.11) (2026-04-26)
- **Status**: COMPLETED
- **Reason**: Implemented a complete trust chain for mesh nodes.
- **Components**:
  - `OrgKeyManager`: Handles lifecycle, DHT storage, and quorum signature aggregation.
  - `OrgPublicKey`: Public representation of an organization key with global node signatures.
  - `MemberCertificate`: Short-lived certificates issued by organizations to edge nodes.
  - `Quorum Signing`: Integrated into mesh protocol for automated signature collection.
  - `Peer Authentication`: Updated `peer_auth.rs` to verify edge nodes via the complete trust chain (Global Nodes → Org Key → Certificate).
- **Trust chain**: Genesis Key → Global Nodes (2/3 quorum) → Org Keys → Edge Nodes
- **Action**: Fully implemented and integrated into mesh transport and admin API.

### hickory-recursor 0.25 → 0.26 Migration (2026-04-26)
- **Status**: COMPLETED
- **Reason**: Requires extensive API changes (recursor merged into hickory-resolver, RData method→field changes, import path updates)
- **Rust version**: 1.93.0 is now available (was 1.85 requirement, now met)
- **Scope**: 75+ compilation errors due to:
  - `hickory-recursor` crate merged into `hickory-resolver` (behind `recursor` feature)
  - Network protocol support moved from `hickory-proto` to new `hickory-net` crate
  - RData accessors changed from methods to fields (e.g., `soa.refresh()` → `soa.refresh`)
  - `ResolverConfig::google()`/`cloudflare()` removed
- **Action**: Migration executed, dependencies updated to 0.26, TokioResolver API migrated, validation logic updated.

### utoipa 4→5 Upgrade (2026-04-26)
- **Status**: COMPLETED
- **Changes**:
  - Updated `utoipa = "4"` to `utoipa = "5"` in Cargo.toml
  - Fixed 100+ types missing `ToSchema` derive
  - Changed response/request types to use `serde_json::Value` for complex config types
  - Added manual `ToSchema` implementation in `src/admin/schema.rs` for types with `DateTime<Utc>` and `PathBuf` fields
  - Updated OpenAPI tests to use `HttpMethod` instead of `PathItemType` (API change in utoipa 5)
- **Files modified**:
  - `Cargo.toml`
  - `src/admin/schema.rs` (new)
  - `src/admin/audit.rs`
  - `src/admin/openapi.rs`
  - `src/admin/handlers/config.rs`
  - `src/admin/handlers/probes.rs`
  - `src/theme/config.rs`
  - Many config files to add `ToSchema` derives

---

## Deferred Items

The following items were intentionally deferred or blocked:

(None)

---

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

## Common Patterns

### Serialization
Use `crate::serialization::serialize/deserialize` (Postcard) for binary state.

### Timestamps
Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`. Never use `Instant` for persisted/cross-process timestamps.

### Concurrency
- **DashMap**: Preferred over `RwLock<HashMap>` for hot paths (170+ uses)
- **Atomic types**: Use `AtomicU64`, `AtomicU32` for counters and flags
- **Moka Cache**: Use with `max_capacity` and `time_to_live` bounds

### Errors
- Use `thiserror` for error types
- Add variants to existing error enums rather than creating new types

### IPC Messages
Use `Message` enum in `src/process/ipc.rs` for new message types.

### Metrics
Add `AtomicU64` counters in `src/metrics/mod.rs` following dropped events pattern.

---

## Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Check specific modules compile
cargo check --lib -p maluwaf --features <feature>

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```
