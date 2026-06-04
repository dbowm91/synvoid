# MESH-14: PKI Hierarchy for Global Nodes — Implementation Plan

## Problem

The BindP gap: TLS peer identity (L1) is not cryptographically bound to the DHT-level `source_node_id` (L4). A node can present a valid TLS certificate but claim to be a different `source_node_id`, and DHT handlers rely on an in-memory mapping populated from the peer's self-reported identity during handshake.

## Current Infrastructure (Closer Than It Looks)

| Component | Status | Location |
|-----------|--------|----------|
| `GlobalNodeAnnounce` carries `public_key` + `signature` | ✅ Exists | `protocol.rs:488` |
| `GlobalNodePublicKey` DHT record type | ✅ Exists | `dht/signed.rs:558` |
| `global_node_public_keys` map in MeshCertManager | ✅ Exists | `cert.rs:155` |
| `register_global_node()` function | ✅ Exists | `cert.rs:485` |
| `verify_global_node_proof()` (GenesisMintingProof) | ✅ Exists | `cert.rs:518` |
| `validate_peer_node_id_binding()` | ⚠️ In-memory only | `transport_peer.rs:1255` |
| Cert chain verification | ❌ Missing | — |
| Cert exchange protocol | ❌ Missing | — |
| `NodeCertBinding` DHT record | ❌ Missing | — |
| PKI enforcement config flag | ❌ Missing | — |

## Implementation Phases

### Phase 1: Foundation — Cert Chain Types (Non-Breaking)

**Goal:** Add types and verification logic that can be used by later phases. No behavior changes.

**New types in `src/mesh/cert.rs`:**

```rust
/// A certificate chain binding a node_id to a TLS certificate via a CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertChain {
    /// DER-encoded leaf certificate (the node's TLS cert)
    pub leaf_cert_der: Vec<u8>,
    /// DER-encoded CA certificate (the issuing global node's CA cert)
    pub ca_cert_der: Vec<u8>,
    /// Ed25519 signature: sign(leaf_cert_der || node_id, ca_private_key)
    pub ca_signature: Vec<u8>,
}

/// A DHT record binding a node_id to its certified public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCertBinding {
    pub node_id: String,
    /// The certified public key (from the leaf cert)
    pub certified_public_key: Vec<u8>,
    /// The CA's public key (from the CA cert)
    pub ca_public_key: Vec<u8>,
    /// Timestamp of binding
    pub timestamp: u64,
}
```

**New verification function in `src/mesh/cert.rs`:**

```rust
/// Verify a certificate chain: leaf cert is signed by CA cert, CA public key
/// matches a registered global node key, and node_id is bound in the chain.
pub fn verify_certificate_chain(
    chain: &CertChain,
    expected_node_id: &str,
    trusted_global_keys: &HashMap<String, Vec<u8>>,
) -> Result<(), MeshCertError>
```

Logic:
1. Parse leaf cert (x509-parser)
2. Parse CA cert (x509-parser)
3. Verify leaf cert is signed by CA cert's public key
4. Verify CA cert's public key exists in `trusted_global_keys`
5. Verify the `ca_signature` covers `leaf_cert_der || expected_node_id`
6. Return Ok or specific error

**New config field in `src/mesh/config.rs`:**

```rust
pub struct MeshTlsConfig {
    // ...existing fields...
    /// Require PKI binding for global node DHT messages (BindP fix).
    /// When true, DHT handlers verify source_node_id against cert chain.
    /// Default: false (backward compatible)
    pub require_pki_binding: bool,
}
```

**Files to modify:**
- `src/mesh/cert.rs` — Add `CertChain`, `NodeCertBinding`, `verify_certificate_chain()`
- `src/mesh/config.rs` — Add `require_pki_binding` to `MeshTlsConfig`

**Tests to add:**
- `test_verify_certificate_chain_valid` — valid chain passes
- `test_verify_certificate_chain_wrong_node_id` — node_id mismatch fails
- `test_verify_certificate_chain_unknown_ca` — CA not in trusted keys fails
- `test_verify_certificate_chain_tampered_leaf` — modified leaf cert fails
- `test_verify_certificate_chain_tampered_signature` — modified sig fails

---

### Phase 2: Protocol — Cert Exchange in GlobalNodeAnnounce (Non-Breaking)

**Goal:** Extend `GlobalNodeAnnounce` to carry optional cert chain. Old nodes ignore the new fields.

**Extend `GlobalNodeAnnounce` in `src/mesh/protocol.rs`:**

```rust
GlobalNodeAnnounce {
    node_id: String,
    public_key: Vec<u8>,
    action: GlobalNodeAction,
    timestamp: u64,
    signature: Vec<u8>,
    key_exchange_endpoint: Option<String>,
    // NEW: Optional cert chain for PKI binding
    cert_chain: Option<CertChain>,
}
```

**Handler changes in `src/mesh/transport.rs`:**
When processing `GlobalNodeAnnounce` with a `cert_chain`:
1. Call `verify_certificate_chain(cert_chain, &node_id, &trusted_global_keys)`
2. If valid → register the binding in `global_node_public_keys` AND store the `NodeCertBinding`
3. If invalid → log warning, ignore the cert chain, fall back to existing behavior
4. If missing → existing behavior (backward compatible)

**Files to modify:**
- `src/mesh/protocol.rs` — Add `cert_chain: Option<CertChain>` to `GlobalNodeAnnounce`
- `src/mesh/transport.rs` — Update `GlobalNodeAnnounce` handler to verify cert chain

**Tests to add:**
- `test_global_node_announce_with_valid_cert_chain` — binding registered
- `test_global_node_announce_with_invalid_cert_chain` — falls back to existing behavior
- `test_global_node_announce_without_cert_chain` — backward compatible

---

### Phase 3: DHT — NodeCertBinding Record (Non-Breaking)

**Goal:** Store and distribute cert bindings via DHT.

**Add `NodeCertBinding` to `SignedRecordType` in `src/mesh/dht/signed.rs`:**

```rust
NodeCertBinding,  // Maps node_id → certified public key + CA key
```

**Store bindings in `MeshCertManager`:**
- Add field: `cert_bindings: Arc<RwLock<HashMap<String, NodeCertBinding>>>`
- Add method: `register_cert_binding(binding: NodeCertBinding)`
- Add method: `get_cert_binding(node_id: &str) -> Option<NodeCertBinding>`
- Populate from DHT records when received

**Files to modify:**
- `src/mesh/dht/signed.rs` — Add `NodeCertBinding` variant to `SignedRecordType`
- `src/mesh/cert.rs` — Add `cert_bindings` field and methods

**Tests to add:**
- `test_register_and_retrieve_cert_binding` — roundtrip
- `test_cert_binding_dht_record_serialization` — postcard roundtrip

---

### Phase 4: Enforcement — PKI Binding in DHT Handlers (Breaking, Config-Gated)

**Goal:** When `require_pki_binding=true`, verify source_node_id against cert chain.

**Changes to `validate_peer_node_id_binding()` in `src/mesh/transport_peer.rs`:**

```rust
pub(crate) fn validate_peer_node_id_binding(
    &self,
    peer_id: &str,
    source_node_id: &str,
) -> Result<(), ()> {
    // Existing in-memory check
    if let Some(peer) = self.peer_connections.get(peer_id) {
        if peer.node_id != source_node_id {
            return Err(());
        }
    }

    // NEW: If require_pki_binding enabled, verify against cert chain
    if self.require_pki_binding {
        if let Some(cert_mgr) = &self.cert_manager {
            if let Some(binding) = cert_mgr.get_cert_binding(source_node_id) {
                // Verify the TLS peer's public key matches the certified key
                if let Some(peer_pubkey) = cert_mgr.get_peer_public_key(peer_id) {
                    if peer_pubkey != binding.certified_public_key {
                        return Err(());
                    }
                } else {
                    // No public key registered for this peer — reject
                    return Err(());
                }
            } else {
                // No cert binding for this node_id — reject
                return Err(());
            }
        }
    }

    Ok(())
}
```

**Changes to DHT message handlers in `src/mesh/transport_dht.rs`:**
When `require_pki_binding=true`:
- `handle_dht_sync_request`: After signature verification, verify `node_id` has a cert binding
- `handle_dht_anti_entropy_request`: Same
- Record push handlers: Verify `from_node` has a cert binding

**Files to modify:**
- `src/mesh/transport_peer.rs` — Update `validate_peer_node_id_binding()`
- `src/mesh/transport_dht.rs` — Add cert binding checks to handlers
- `src/mesh/transport.rs` — Pass `require_pki_binding` config to handlers

**Tests to add:**
- `test_pki_binding_rejects_unbound_node` — node without cert binding rejected
- `test_pki_binding_accepts_bound_node` — node with valid cert binding accepted
- `test_pki_binding_disabled_allows_all` — backward compatible when disabled

---

### Phase 5: Migration — Backward Compatibility + Integration Tests

**Goal:** Ensure smooth rollout across existing deployments.

**Migration steps:**
1. Deploy with `require_pki_binding: false` (default) — no behavior change
2. Global nodes update to include `cert_chain` in `GlobalNodeAnnounce` — old nodes ignore it
3. DHT records propagate `NodeCertBinding` — old nodes ignore unknown record types
4. Once all nodes are updated, set `require_pki_binding: true` — enforcement activates

**Integration tests:**
- `test_backward_compat_old_node_rejects_pki_binding` — old node ignores new fields
- `test_mixed_cluster_with_and_without_pki` — mixed cluster works when flag is off
- `test_enforcement_rejects_self_signed_for_global_node` — self-signed cert rejected when PKI required
- `test_cert_rotation_with_pki_binding` — key rotation updates binding correctly

---

## Files Modified (Summary)

| File | Phase | Changes |
|------|-------|---------|
| `src/mesh/cert.rs` | 1, 3 | Add `CertChain`, `NodeCertBinding`, `verify_certificate_chain()`, `cert_bindings` field |
| `src/mesh/config.rs` | 1 | Add `require_pki_binding` to `MeshTlsConfig` |
| `src/mesh/protocol.rs` | 2 | Add `cert_chain: Option<CertChain>` to `GlobalNodeAnnounce` |
| `src/mesh/transport.rs` | 2, 4 | Update `GlobalNodeAnnounce` handler; pass config to handlers |
| `src/mesh/dht/signed.rs` | 3 | Add `NodeCertBinding` to `SignedRecordType` |
| `src/mesh/transport_peer.rs` | 4 | Update `validate_peer_node_id_binding()` |
| `src/mesh/transport_dht.rs` | 4 | Add cert binding checks |

## Risk Mitigation

- **All phases are backward-compatible until Phase 4** — Phase 4 is gated behind `require_pki_binding: false` by default
- **Cert chain verification is additive** — new code paths, no modification of existing verification
- **Tests verify no reversion** — each phase adds tests that verify existing behavior is preserved
- **Gradual rollout** — deploy → propagate → enforce (3 steps, not 1)
