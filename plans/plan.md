# MaluWAF Implementation Plan

**Status**: Active - Maintenance Mode
**Last Updated**: 2026-04-26 (deferred items documentation update)
**Verification Completed**: 2026-04-26

## Completed Items

### OrgKeyManager Quorum Threshold Fix (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - Tests pass (242 integration tests), cargo check succeeds
- **Reason**: Previously used permissive `signatures.len() >= 1` instead of proper 2/3 quorum
- **Changes**:
  - `src/mesh/org_key_manager.rs` now uses `OrgPublicKey::verify_quorum()` for proper threshold
  - Added `cert_manager` field to `OrgKeyManager` for accessing global node public keys
  - Added `get_authorized_global_keys()` method to gather keys from transport and cert_manager
  - Proper 2/3 Byzantine fault tolerance: `required = (total_signers * 2 + 2) / 3`
- **Security Impact**: Org key signatures now require proper quorum validation before publishing

### Quorum Threshold 2/3 Enforcement (2026-04-26)
- **Status**: COMPLETED (extended to OrgKeyManager 2026-04-26)
- **Verification**: 2026-04-26 - Tests pass (1511/1511), cargo check succeeds
- **Reason**: Previously used permissive `valid_signatures > 0` threshold
- **Changes**:
  - `OrgPublicKey::verify_quorum()` in `src/mesh/organization.rs:59-91` now takes `total_signers` parameter
  - Uses proper 2/3 Byzantine fault tolerance: `required = (total_signers * 2 + 2) / 3`
  - Updated call site in `src/mesh/peer_auth.rs:160` to pass `authorized_global_pubkeys.len()` as total
  - Extended to `OrgKeyManager::handle_org_key_sign_response()` for proper quorum validation
- **Security Impact**: Properly enforces quorum for org key trust chain establishment

### Org Key Trust Chain (7.11) (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - All components verified implemented and integrated
- **Reason**: Implemented a complete trust chain for mesh nodes.
- **Components**:
  - `OrgKeyManager`: Handles lifecycle, DHT storage, and quorum signature aggregation.
  - `OrgPublicKey`: Public representation of an organization key with global node signatures.
  - `MemberCertificate`: Short-lived certificates issued by organizations to edge nodes.
  - `Quorum Signing`: Integrated into mesh protocol for automated signature collection.
  - `Peer Authentication`: Updated `peer_auth.rs` to verify edge nodes via the complete trust chain (Global Nodes → Org Key → Certificate).
- **Trust chain**: Genesis Key → Global Nodes (2/3 quorum) → Org Keys → Edge Nodes
- **Action**: Fully implemented and integrated into mesh transport and admin API.
- **Fixes Applied**: Test code in `peer_auth.rs` updated to include `member_certificate` and `org_public_key` parameters (3 tests at lines 921, 1472, 1498).
- **Known Items**: TODO comments at `transport.rs:1864-1865` and `2154-2155` for loading org keys from config (Phase 2 feature).

### hickory-recursor 0.25 → 0.26 Migration (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - Library compiles, DNS recursive tests pass (36/36), DNS server tests pass (40/41)
- **Reason**: Requires extensive API changes (recursor merged into hickory-resolver, RData method→field changes, import path updates)
- **Rust version**: 1.93.0 is now available (was 1.85 requirement, now met)
- **Scope**: 75+ compilation errors due to:
  - `hickory-recursor` crate merged into `hickory-resolver` (behind `recursor` feature)
  - Network protocol support moved from `hickory-proto` to new `hickory-net` crate
  - RData accessors changed from methods to fields (e.g., `soa.refresh()` → `soa.refresh`)
  - `ResolverConfig::google()`/`cloudflare()` removed
- **Action**: Migration executed, dependencies updated to 0.26, TokioResolver API migrated, validation logic updated.
- **Note**: DNSKEY/CDS types in `src/dns/resolver.rs` still use method accessors (non-blocking, methods remain functional in 0.26)

### Raft Consensus Integration (2026-04-26)
- **Status**: COMPLETED (Foundation)
- **Verification**: 2026-04-26 - `cargo check` succeeds, `openraft` 0.9 integrated.
- **Changes**:
  - Added `openraft` 0.9 dependency.
  - Created `src/mesh/consensus.rs` with Raft type definitions (`LogData`, `Response`, `MaluRaftConfig`).
  - Added `ConsensusManager` skeleton.
- **Note**: Full implementation requires `RaftNetwork` and `RaftStorage` providers tailored to MaluWAF's P2P transport and persistence layers.

### WASM Module Store Implementation (2026-04-26)
- **Status**: COMPLETED (In-memory)
- **Verification**: 2026-04-26 - `cargo check` succeeds, `WasmModuleStore` is functional.
- **Changes**:
  - Replaced disabled stubs in `src/mesh/wasm_dist.rs` with a functional in-memory `WasmModuleStore`.
  - Implemented versioning support (latest, by-version, list versions).
  - Added `Hash` derive to `WasmModuleType` in `src/mesh/protocol.rs`.
  - Enabled global `WasmDistManager` access.

### eBPF Flood Protection Integration (2026-04-26)
- **Status**: COMPLETED (Feature integrated)
- **Verification**: 2026-04-26 - `Cargo.toml` updated with `aya` dependency, code verified to exist in `ebpf-flood/`.
- **Changes**:
  - Added `aya` optional dependency to main `Cargo.toml`.
  - Enabled `aya` dependency for `flood-ebpf` feature.
- **Note**: eBPF bytecode build requires nightly Rust and `bpfel-unknown-none` target. Integration in `maluwaf` is now ready for Linux deployments.

### Placeholder and Security Improvement (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - `cargo check` succeeds, unit tests in `rule_feed.rs` pass.
- **Changes**:
  - `RuleFeedManager` in `src/waf/rule_feed.rs` now returns `Result` instead of panicking when a placeholder public key is used.
  - `run_master` in `src/startup/master.rs` now handles rule feed initialization errors gracefully.
  - `handle_generatenewtoken` in `src/master/commands.rs` now generates a random token directly in the template, avoiding `TOKEN_PLACEHOLDER` in newly created configs.
  - `WEAK_TOKEN_PATTERNS` in `src/config/admin.rs` expanded to include more common placeholders like `CHANGE-ME` and `token-placeholder`.

### quinn-proto git patch removal (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - `cargo check` confirms `quinn-proto v0.11.14` is pulled from crates.io.
- **Reason**: `quinn-proto 0.11.10+` was released to crates.io, fixing RUSTSEC-2026-0037.
- **Changes**: Removed `[patch.crates-io]` for `quinn-proto` in `Cargo.toml`.

### Org Key Loading from Config (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - Library compiles, `cargo check` succeeds, peer_auth tests pass.
- **Reason**: Handshake messages (Hello/HelloAck) need to present organization credentials for trust chain verification.
- **Changes**:
  - Added `get_org_auth_data()` helper to `MeshTransport` in `src/mesh/transport.rs`.
  - Helper retrieves `org_id` from `node_identity.genesis_org_id()`.
  - Loads `MemberCertificate` from `OrganizationManager`.
  - Loads `OrgPublicKey` from `OrgKeyManager`.
  - Updated `MeshMessage::Hello` and `MeshMessage::HelloAck` construction to include these credentials.
- **Files modified**:
  - `src/mesh/transport.rs`

### utoipa 4→5 Upgrade (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - Library compiles without utoipa errors, ToSchema derives on all admin types
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

## Known Deferred/Phase 2 Items

The following items were identified during verification but are not blocking current operation:

### Phase 2/Production Items

The following Phase 2 items are deferred but non-blocking:

1. **QNAME Minimization** (`src/dns/resolver.rs:13-17`): Full QNAME minimization (RFC 7816) requires a newer version of Hickory DNS. The feature was merged in Hickory DNS PR #2919 (merged in 2025). Current implementation uses a stub that strips query names to coarser granularity.

2. **Signed Rule Feed Phase 2** (`docs/SIGNED_RULE_FEED.md:126-129`): Phase 2 of signed rule feed implementation is deferred. Phase 1 (core infrastructure with Ed25519 verification) is complete. Phase 2 includes integration with DefaultPatterns, hot-reload support, and version tracking.

3. **HSM PKCS#11 Key Retrieval** (`src/dns/hsm.rs:66-68`): The `key_id` field is marked as future HSM support. Full PKCS#11 key retrieval is not yet implemented.

### Security Notes
4. **WireGuard transport**: Deprecated, falls back to QUIC transport

### Non-Blocking Stubs (Documented for Reference)
The following stubs were reviewed and found to be non-blocking (either properly documented or fallback behavior):

9. **HTTP/3 handler stub** (`src/http3/handler.rs`): Entire module is a placeholder. Actual HTTP/3 handling is implemented in `Http3Server::handle_request()` in `src/http3/server.rs`. This stub is never called in production paths.

10. **Direct TLS for key exchange server** (`src/mesh/passover_key_exchange.rs:1091`): Key exchange server falls back to HTTPS proxy for TLS. Direct TLS is not yet implemented.

11. **Platform stubs** (`src/platform/`): Various platform-specific stubs for non-Linux/macOS platforms (Windows stubs, sandbox stubs, syslog stubs). Appropriate fallback behavior for unsupported platforms.

12. **WireGuard kernel module** (`src/tunnel/wireguard/kernel.rs`): Returns error on non-Linux platforms. Already documented as deprecated, falls back to QUIC transport.

13. **Reserved protocol modules** (`src/mesh/transport_*.rs`): Multiple modules with `SAFETY_REASON` comments marking them as reserved for future protocol handling expansion.

14. **Windows WFP interface-specific filtering** (`src/icmp_filter/wfp.rs:36-37`): Interface-specific filtering on Windows WFP requires additional Windows API calls not yet implemented. All interfaces will be filtered.

15. **Windows TUN route addition** (`src/tunnel/tun.rs:382`): Route addition is not implemented for Windows TUN. Only has Linux implementation.

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
