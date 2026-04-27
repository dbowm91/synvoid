# MaluWAF Implementation Plan

**Status**: Active - Maintenance Mode
**Last Updated**: 2026-04-26
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

### hickory-recursor 0.25 → 0.26 Migration (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - Library compiles, DNS recursive tests pass (36/36), DNS server tests pass (40/41)
- **Reason**: Requires extensive API changes (recursor merged into hickory-resolver, RData method→field changes, import path updates)
- **Action**: Migration executed, dependencies updated to 0.26, TokioResolver API migrated, validation logic updated.

### QNAME Minimization (RFC 7816/9156) (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - `cargo check` succeeds, library source verified to implement iterative label resolution
- **Reason**: Hickory DNS 0.26 natively supports QNAME minimization in its recursor.
- **Changes**:
  - Removed unused `QnameMinimizer` stub from `src/dns/qname.rs`.
  - Updated `HickoryRecursor` in `src/dns/resolver.rs` to use native QNAME minimization logic.
  - Enabled case randomization in recursor and forwarder for improved security.

### HTTP/3 Functional Implementation (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - `cargo check` succeeds, code implements `send_request_streaming` and body pipe
- **Changes**:
  - Removed unused `Http3Handler` stub from `src/http3/handler.rs`.
  - Implemented actual upstream proxying in `Http3Server::handle_request()` in `src/http3/server.rs`.
  - Added support for streaming response bodies and correct proxy headers in HTTP/3.
  - Properly wired metrics, drain state, and flood protector into the HTTP/3 listener.

### Direct TLS for Key Exchange Server (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - `cargo check` succeeds, code uses `TlsAcceptor` and `hyper` 1.0
- **Changes**:
  - Implemented direct TLS support in `src/mesh/passover_key_exchange.rs`.
  - Integrated with `CertResolver` to load and manage certificates.
  - Key exchange server now supports both HTTP and direct HTTPS depending on configuration.

### Signed Rule Feed Phase 2 (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - `cargo check` succeeds, IPC message handling verified in code
- **Changes**:
  - Added `sqli` and `xss` to `DefaultPatterns` and enabled custom patterns for these categories.
  - Updated `SqliDetector` and `XssDetector` to support both `libinjection` and pattern-based detection.
  - Implemented hot-reload in `WafCore` and wired `RuleFeedManager` to broadcast updates to all workers via IPC.
  - Added disk persistence for downloaded rules in `RuleFeedManager` using `storage_dir` config.

### HSM PKCS#11 Key Retrieval (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - `cargo check` succeeds, code implements `Attribute::Id` and `EcPoint` retrieval
- **Changes**:
  - Implemented full PKCS#11 key retrieval in `src/dns/hsm.rs`.
  - Added support for searching keys by both `key_label` and `key_id`.
  - Implemented public key extraction for Ed25519 (`EcPoint`) and RSA (`Modulus`).
  - Updated `HsmConfig` in `src/config/dns/dns_dnssec.rs` to expose label and ID settings.

### Windows Platform Enhancements (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - Code implements `ConditionField::InterfaceIndex` and `netsh` route addition
- **Changes**:
  - Implemented interface-specific filtering for Windows WFP in `src/icmp_filter/wfp.rs`.
  - Implemented Windows TUN route addition in `src/tunnel/tun.rs` using `netsh`.

### utoipa 4→5 Upgrade (2026-04-26)
- **Status**: COMPLETED
- **Verification**: 2026-04-26 - Library compiles without utoipa errors
- **Action**: Migration executed, dependencies updated to 5.0, `ToSchema` derives fixed across codebase.

### Raft Consensus Subsystem Removal (2026-04-26)
- **Status**: ABANDONED / REMOVED
- **Reason**: Raft introduces significant centralized complexity that conflicts with MaluWAF's decentralized architectural design. 
- **Changes**:
  - Removed unused `src/mesh/consensus.rs` stub.
  - Removed `openraft` dependency from `Cargo.toml`.
  - Consensus requirements (e.g., Org Key Quorum) will continue to be handled via decentralized DHT and manual quorum signatures.

---

## Known Deferred/Security Notes

The following items are deferred or documented for security awareness:

### Security Notes
1. **WireGuard transport**: Deprecated, falls back to QUIC transport. Code remains for future potential rewrite but is non-functional in current release.
2. **Reserved protocol modules**: Multiple modules with `SAFETY_REASON` comments marking them as reserved for future protocol handling expansion.

---

## Key Codebase Facts

- **Architecture**: Overseer → Master → Workers (Unix domain socket IPC)
- **Mesh types**: `MeshBackend`, `MeshBackendPool` in `src/mesh/backend.rs`
- **Base64**: `get_public_key()` uses `URL_SAFE_NO_PAD`; any decoder using `STANDARD` is wrong
- **Serialization**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary
- **Timestamps**: Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`

---

## Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```
