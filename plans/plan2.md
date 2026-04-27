# MaluWAF Improvement Plan v2

**Status**: Planning Phase
**Last Updated**: 2026-04-27
**Phase**: Cleanup then Implementation

---

## Executive Summary

This plan addresses findings from a comprehensive codebase review identifying:
- **Critical**: WireGuard mesh transport dead code requiring cleanup
- **Medium**: Feature flags in various states of completion
- **Medium**: Dead code modules with misleading `#![allow(dead_code)]`
- **Low**: Deprecated code safe to remove
- **Low**: Windows stub artifact needing clarification

**User Directive**: Remove WireGuard mesh transport, preserve Windows implementation/stubs (full Windows support intended), cleanup first then implementation.

---

## Phase 1: Cleanup (Low Risk)

### 1.1 Remove Dead Deprecated Code

**Target**: v0.4.0 cleanup release

| Item | File | Lines | Action |
|------|------|-------|--------|
| `verify_signature_with_signer` | `src/mesh/protocol_message.rs` | 371 | Remove method |
| `verify_signature` | `src/mesh/protocol_message.rs` | 387 | Remove method |
| `get_default_ipc_path_legacy` | `src/platform/ipc.rs` | 119-148 | Remove function |
| `check_connection` | `src/waf/flood/connection_limiter.rs` | 107 | Remove method |
| `register_connection` | `src/waf/flood/connection_limiter.rs` | 115 | Remove method |

**Verification**: `cargo test --lib --no-run` after each removal

---

### 1.2 Fix Misleading `#![allow(dead_code)]`

Remove incorrect allow attributes from actively-used modules:

| File | Reason |
|------|--------|
| `src/waf/flood/syn_flood.rs` | `SynFloodProtector` used in `flood/mod.rs` and `ebpf_flood.rs` |
| `src/challenge/pow.rs` | `PowManager` instantiated in `challenge/mod.rs:138` |
| `src/overseer/connection_tracker.rs` | Used in tests and re-exported in `overseer/mod.rs` |
| `src/overseer/drain_manager.rs` | `DrainManager` used in `overseer/process.rs:99` |
| `src/location_matcher.rs` | `LocationMatcher` used in `router.rs` multiple locations |

For conditionally-enabled transport modules (correct when `mesh` feature disabled):
- `src/mesh/transport_connection.rs`
- `src/mesh/transport_dns.rs`
- `src/mesh/transport_dht.rs`
- `src/mesh/transport_org.rs`
- `src/mesh/transport_routing.rs`
- `src/mesh/transport_global.rs`
- `src/mesh/transport_rate_limit.rs`

**Action**: Verify actual usage via grep before removing attribute

---

### 1.3 Remove `pqc-mesh` Redundant Feature Flag

**Location**: `Cargo.toml:35`

**Reason**: Redundant with `post-quantum` feature. ML-DSA functionality exists in `hybrid_signature.rs` and `ml_dsa.rs` but is controlled by `post-quantum`, not `pqc-mesh`. No `#[cfg(feature = "pqc-mesh")]` usages found in codebase.

**Action**: Remove from Cargo.toml, update any comments referencing it

---

### 1.4 Document Windows Stub

**Location**: `src/platform/windows.rs`

**Current State**: 1-line comment "// Windows platform support (stub)"

**Finding**: The stub serves as a module facade for `windows/` directory. The `windows_impl.rs` contains actual implementation (617 lines). This is not a bug but a confusing artifact.

**Decision**: Keep current structure but add clarifying comment explaining the module architecture:

```rust
// Windows platform support
// Note: Core implementation is in windows_impl.rs
// Platform modules are in windows/ subdirectory
```

---

## Phase 2: WireGuard Mesh Transport Removal (High Priority)

### IMPORTANT: Distinguish Mesh Transport vs VPN Tunnel

This plan removes **WireGuard MESH transport** only. The **WireGuard VPN tunnel** functionality in `src/tunnel/wireguard/` and VPN client (`src/vpn_client/`) should be **PRESERVED**. These are separate concerns:

- **WireGuard Mesh Transport** (REMOVE): How mesh nodes communicate with each other. Removed due to authentication gap (no mesh node identity verification).
- **WireGuard VPN Tunnel** (KEEP): VPN client/server functionality for end-user VPN connections. This is working code with proper implementation.

### 2.1 Files to Remove

| File | Lines | Description |
|------|-------|-------------|
| `src/mesh/wireguard_mesh.rs` | 246 | Entire module - WireGuard mesh runtime (isolated, never called) |

**Do NOT remove:**
- `src/tunnel/wireguard/` - VPN tunnel implementation
- `src/vpn_client/` - VPN client functionality
- `src/bin/server.rs` wireguard transport for VPN client (line ~197) - this is VPN, not mesh

### 2.2 Config Structs to Remove from `src/mesh/config.rs`

| Lines | Item | Type |
|-------|------|------|
| 257-267 | `WireGuardPerformanceProfile` | Enum |
| 267-289 | `WireGuardPerfConfig` | Struct |
| 292-313 | `impl WireGuardPerfConfig` | Impl block |
| 315-337 | `MeshWireGuardConfig` | Struct |
| 339-351 | `impl Default for MeshWireGuardConfig` | Impl |
| 352-372 | `MeshWireGuardPeer` | Struct |
| 374-378 | Blank lines | Cleanup |
| 1471-1492 | `impl MeshWireGuardConfig` | Methods (effective_perf_config) |

**Note**: `MeshTransportPreference::WireGuard` enum variant (line 716) should be **deprecated** rather than removed for backward compatibility. Any TOML configs with `transport_preference = "wireguard"` would break if variant is removed. Mark with `#[deprecated]` and make it map to QUIC like the current behavior.

### 2.3 Config Fields to Remove

| Location | Field | Context |
|----------|-------|---------|
| `config.rs:227` | `wireguard_port: Option<u32>` | `MeshSeedNode` |
| `config.rs:741` | `wireguard_port: Option<u16>` | `MeshNodeEndpoint` |
| `config.rs:749` | `wireguard: MeshWireGuardConfig` | `MeshConfig` |

### 2.4 Default Transport Preference Change

**File**: `src/mesh/config_defaults.rs:48`

**Current**:
```rust
transport_preference: MeshTransportPreference::WireGuard,
```

**Change to**:
```rust
transport_preference: MeshTransportPreference::Quic,
```

### 2.5 Protocol Type Cleanup

**File**: `src/mesh/protocol.rs:1182-1183`

**Current**: WireGuard maps to Quic in `MeshCapabilities` conversion

**Change**: Remove WireGuard arm since only Quic now exists:
```rust
impl From<MeshCapabilities> for MeshTransportPreference {
    fn from(c: MeshCapabilities) -> Self {
        #[cfg(feature = "mesh")]
        if c.quic {
            MeshTransportPreference::Quic
        } else {
            MeshTransportPreference::Quic  // Default to QUIC
        }
        #[cfg(not(feature = "mesh"))]
        MeshTransportPreference::Quic
    }
}
```

### 2.6 Admin UI Mesh Config Cleanup

**Files**: `admin-ui/src/types/mod.rs` and `admin-ui/src/pages/mesh.rs`

**Context**: The `wireguard_enabled` field in the Admin UI `MeshConfig` type relates to **mesh** WireGuard config, not VPN tunnel. This should be removed as part of the mesh cleanup.

| Location | Change |
|----------|--------|
| `admin-ui/src/types/mod.rs:719` | Remove `wireguard_enabled: Option<bool>` from `MeshConfig` |
| `admin-ui/src/pages/mesh.rs:49-56` | Remove wireguard_enabled toggle from mesh config form |

**DO NOT change in admin-ui:**
- `admin-ui/src/pages/site_editor.rs:1713` - WireGuard tunnel protocol dropdown (VPN tunnel, not mesh)
- `admin-ui/src/pages/settings.rs:195` - WireGuard tunnel settings (VPN tunnel, not mesh)
- `admin-ui/src/types/mod.rs:731` - WireGuard in `TunnelConfig` (VPN tunnel, not mesh)

### 2.7 CLI Cleanup

**File**: `src/bin/server.rs:197`

**Note**: This accepts `"wireguard"` for VPN client transport, NOT mesh transport. This is VPN tunnel functionality and should be preserved.

**No change needed** - the wireguard transport option here is for VPN, not mesh.

### 2.8 Module Re-exports to Update

**File**: `src/mesh/mod.rs:81-82`

**Current**:
```rust
pub use config::{
    MeshConfig, MeshMlKemConfig, MeshNodeRole, MeshTransportPreference, MeshWireGuardConfig,
    MeshWireGuardPeer, NodeIdentityConfig,
};
```

**Change**: Remove `MeshWireGuardConfig` and `MeshWireGuardPeer` from re-exports since they're being removed:
```rust
pub use config::{
    MeshConfig, MeshMlKemConfig, MeshNodeRole, MeshTransportPreference,
    NodeIdentityConfig,
};
```

### 2.9 Example Config Cleanup

**File**: `config/mesh-example.toml`

**Lines**: ~244-281 (WireGuard mesh configuration section within `[mesh]`)

**Change**: Remove WireGuard mesh configuration section from `[mesh]` block, keep only QUIC examples. Do NOT remove VPN tunnel (`[tunnel.vpn]`) section.

### 2.10 Documentation Updates

- Update `docs/MESH.md` or relevant mesh docs to reflect QUIC-only transport
- Update `AGENTS.md` security notes section to remove WireGuard mesh reference
- Update any README or architecture docs mentioning WireGuard mesh transport
- **DO NOT** update documentation about WireGuard VPN tunnel functionality

---

## Phase 3: Feature Flag Review

### 3.1 Features to REMOVE

| Feature | Reason | Action |
|---------|--------|--------|
| `pqc-mesh` | Redundant with `post-quantum` | Remove from Cargo.toml |
| `icmp-winfw` | Not defined in Cargo.toml | Remove from code references |
| `icmp-wfp` | Not defined in Cargo.toml | Remove from code references |
| `icmp-pf` | Not defined in Cargo.toml | Remove from code references |
| `icmp-ebpf` | Not defined in Cargo.toml | Remove from code references |

### 3.2 Features to INVESTIGATE and DECIDE

| Feature | Status | Investigation Required |
|---------|--------|------------------------|
| `origin_key_exchange` | Incomplete with `unreachable!()` stubs | Is this needed for mesh integrity? Can it be properly implemented or should it be removed? |
| `icmp-filter` | 12+ compilation errors | Is ICMP filtering planned? Should feature be completed or marked experimental? |
| `tun-rs` | 11+ compilation errors | Is TUN support planned? Missing crate dependency - intentional or oversight? |
| `flood-ebpf` | aya crate fails on macOS | Linux-only feature - should have conditional compilation or separate CI? |
| `wireguard` (VPN) | 1 error - unused imports | VPN tunnel support - fix imports or complete integration? |
| `audit` | Unused `chrono::Utc` warning | Dead code path - remove or implement? |
| `verify-pq` | Unclear purpose | Diagnostic tool? Should be documented or removed? |

**Action**: For each feature, create a tracking issue to decide: Implement / Remove / Mark Experimental

---

## Phase 4: Post-Processing

### 4.1 Verification Steps

After all cleanup:
```bash
# Full verification
cargo fmt
cargo clippy -- -D warnings
cargo test --lib --no-run
cargo test --test integration_test
```

### 4.2 Documentation Updates

- Update `AGENTS.md` placeholder table (outdated - references `TOKEN_PLACEHOLDER` but actual weak tokens are `changeme` and `WEAK_TOKEN_PATTERNS`)
- Update `docs/SECURITY.md` if any security configurations changed
- Update `plans/plan.md` to reflect completed cleanup items

---

## Implementation Order

1. **Phase 1.1** - Remove dead deprecated code (lowest risk)
2. **Phase 1.2** - Fix misleading `#![allow(dead_code)]` (verify usage first)
3. **Phase 1.3** - Remove `pqc-mesh` feature flag (simple removal)
4. **Phase 1.4** - Document Windows stub (clarity, no functional change)

5. **Phase 2** - WireGuard mesh removal (more impact, but code is dead)
   - 2.1 Remove wireguard_mesh.rs
   - 2.2-2.4 Remove config structs and update defaults
   - 2.5 Protocol type cleanup
   - 2.6 Admin UI mesh config cleanup
   - 2.7 CLI (no change - VPN tunnel)
   - 2.8 Module re-exports update
   - 2.9-2.10 Config and docs cleanup

6. **Phase 3** - Feature flag review (requires decisions from team)

7. **Phase 4** - Verification and final documentation

---

## Files Summary

| Phase | Files Modified | Files Removed |
|-------|----------------|---------------|
| 1.1 | `protocol_message.rs`, `ipc.rs`, `connection_limiter.rs` | - |
| 1.2 | 5+ files with `#![allow(dead_code)]` removed | - |
| 1.3 | `Cargo.toml` | - |
| 1.4 | `windows.rs` (add comment) | - |
| 2.1 | - | `wireguard_mesh.rs` |
| 2.2-2.3 | `config.rs` (~150 lines removed) | - |
| 2.4 | `config_defaults.rs` | - |
| 2.5 | `protocol.rs` | - |
| 2.6 | `admin-ui/src/types/mod.rs`, `admin-ui/src/pages/mesh.rs` | - |
| 2.7 | None (VPN client, not mesh) | - |
| 2.8 | `mesh/mod.rs` | - |
| 2.9 | `mesh-example.toml` | - |
| 2.10 | Docs (MESH.md, AGENTS.md, README) | - |
| 3 | Feature flag decisions TBD | - |

**Estimated Cleanup**: ~400 lines removed, 50+ files modified

---

## Risk Assessment

| Item | Risk | Mitigation |
|------|------|------------|
| WireGuard removal | Medium - configs may reference removed options | Search for `transport_preference = "wireguard"` before removal |
| Deprecated code removal | Low - all confirmed dead via grep | Verify no external usage before removing |
| Feature flag removal | Low - only unused flags | Confirm no external usage |
| Config struct removal | Medium - any downstream code using these | grep for type references before removal |

---

## References

- WireGuard deprecation finding: `src/mesh/backend.rs:367`
- Security placeholders (appropriate fail-closed): `src/waf/rule_feed.rs:382-388`
- Feature flag definitions: `Cargo.toml` lines 23-35
- Deprecated code locations: protocol_message.rs, ipc.rs, connection_limiter.rs

---

**Plan Created**: 2026-04-27
**Review Status**: Pending user review before implementation begins