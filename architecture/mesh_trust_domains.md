# Mesh Trust Domains — Design Note (Iteration 36)

**Status**: Iteration 36 — Doc drift cleanup, three-plane model, request/WAF audit boundary.  
**Date**: 2026-06-11  
**Scope**: `crates/synvoid-mesh` (re-exported via `src/mesh`).  
**Goal**: Define trust-domain boundaries and invariants before any internal module split.  
**Key Invariant** (from plan):

> DHT answers "what has been advertised?" Raft/canonical state answers "what is trusted?" Policy answers "what may be acted on?" Transport answers "how do peers communicate?" Services consume policy outputs, not raw advisory records, when security decisions are involved.

This document is the deliverable for `plans/mesh_trust_domain_design_iteration_7.md`.

---

## Non-Goals (per plan)

- Do not split `synvoid-mesh` into multiple crates.
- Do not rewrite DHT, Raft, peer discovery, identity, transport, threat-intel, YARA, WASM, or reputation.
- Do not change network behavior, record propagation, trust decisions, node roles, certificates, or Raft membership.
- Do not remove the DHT record-store compatibility global.
- Do not make feature defaults stricter.
- Do not fully reorganize `crates/synvoid-mesh/src/mesh/`.
- Do not perform unrelated cleanup.

---

## Phase 1 — Inventory and Classification

### Inventory Commands Executed

```bash
find crates/synvoid-mesh/src -maxdepth 4 -type f | sort
rg "Raft|openraft|DHT|Kademlia|RecordStore|ThreatIntel|...|signature" crates/synvoid-mesh/src architecture docs
rg "get_global_record_store|set_global_record_store|RECORD_STORE_GLOBAL|get_record_store" crates/synvoid-mesh src crates
```

Full file list (Rust sources) and term matches were captured. Key hotspots: `mesh/mod.rs` (compat globals), `transports/manager.rs`, `transport.rs`, `proxy.rs`, `threat_intel.rs`, `behavioral_intel.rs`, `backend.rs`, `dht/record_store*.rs`, `dht/signed.rs`, `dht/key_policy.rs`, `raft/*`, `peer_auth.rs`, `organization.rs`, `cert.rs`.

### Module Classification by Trust Domain

Classification uses the exact domain definitions from the plan (Phase 1):

1. **transport**: peer connections, QUIC transport, wire protocol, retry/reachability, transport manager.
2. **advisory_dht**: DHT/Kademlia storage, TTL-bound records, DHT record validation, discovery records, eventually consistent announcements.
3. **canonical**: Raft/global-node authority records, organization public keys, revocation, global node CA/trust state, canonical threat-intel attestations.
4. **identity**: node identity, certificates, signing, peer auth, key exchange, org identity, crypto material lifecycle.
5. **policy**: trust decisions, record acceptance/activation decisions, canonical-vs-advisory resolution, authorization gates.
6. **services**: YARA/WASM distribution, threat intelligence consumers, reputation, proxy/service discovery, serverless mesh wiring, audit/event consumers.
7. **compat**: legacy globals, transitional shims, APIs kept for root/backward compatibility.

#### Full Mapping

##### transport
| File | Primary | Secondary | Justification |
|------|---------|-----------|---------------|
| crates/synvoid-mesh/src/mesh/transport.rs | transport | (none) | Core MeshTransport: peer connections, QUIC sessions, message dispatch, reachability. |
| crates/synvoid-mesh/src/mesh/transport_connection.rs | transport | (none) | Connection lifecycle and state for transport layer. |
| crates/synvoid-mesh/src/mesh/transport_core/mod.rs | transport | (none) | Transport error and time primitives. |
| crates/synvoid-mesh/src/mesh/transport_core/error.rs | transport | (none) | Transport-specific error types. |
| crates/synvoid-mesh/src/mesh/transport_core/time.rs | transport | (none) | Transport timestamp validation. |
| crates/synvoid-mesh/src/mesh/transport_dht.rs | transport | advisory_dht | DHT message transport over mesh (wire path, not storage). |
| crates/synvoid-mesh/src/mesh/transport_dns.rs | transport | (none) | DNS-over-mesh transport. |
| crates/synvoid-mesh/src/mesh/transport_global.rs | transport | (none) | Global-node transport paths. |
| crates/synvoid-mesh/src/mesh/transport_org.rs | transport | (none) | Org-scoped transport. |
| crates/synvoid-mesh/src/mesh/transport_peer.rs | transport | identity | Per-peer session handshake and auth (transport owns I/O). |
| crates/synvoid-mesh/src/mesh/transport_rate_limit.rs | transport | (none) | Transport-level rate limiting. |
| crates/synvoid-mesh/src/mesh/transport_routing.rs | transport | (none) | Route query transport. |
| crates/synvoid-mesh/src/mesh/transport_serverless.rs | transport | services | Serverless function transport wiring. |
| crates/synvoid-mesh/src/mesh/transport_types.rs | transport | (none) | Transport type enums and hints. |
| crates/synvoid-mesh/src/mesh/transports/mod.rs | transport | (none) | Transport trait and manager facade. |
| crates/synvoid-mesh/src/mesh/transports/manager.rs | transport | advisory_dht | MeshTransportManager: peer selection, retry, reachability (owns record_store handle for advisory use only). |
| crates/synvoid-mesh/src/mesh/transports/quic.rs | transport | (none) | QUIC implementation. |
| crates/synvoid-mesh/src/mesh/transports/stack.rs | transport | (none) | Transport stack composition. |
| crates/synvoid-mesh/src/mesh/protocol.rs | transport | identity | MeshMessage wire format + MeshMessageSigner (signing primitive only). |
| crates/synvoid-mesh/src/mesh/protocol_message.rs | transport | (none) | Message category and encoding. |
| crates/synvoid-mesh/src/mesh/protocol_proto_decode.rs | transport | (none) | Protobuf decode path. |
| crates/synvoid-mesh/src/mesh/protocol_proto_encode.rs | transport | (none) | Protobuf encode path. |
| crates/synvoid-mesh/src/mesh/protocol_types.rs | transport | (none) | Protocol enums. |
| crates/synvoid-mesh/src/mesh/backend.rs | transport | advisory_dht, identity | create_mesh_backend + transport init (certs for identity, record store injection). |
| crates/synvoid-mesh/src/mesh/discovery.rs | transport | advisory_dht | Peer discovery announcements over transport. |

##### advisory_dht
| File | Primary | Secondary | Justification |
|------|---------|-----------|---------------|
| crates/synvoid-mesh/src/mesh/dht/mod.rs | advisory_dht | (none) | DHT module facade, RecordStoreManager re-exports, TTL/rate-limiter storage. |
| crates/synvoid-mesh/src/mesh/dht/record_store.rs | advisory_dht | (none) | RecordStoreManager: pure advisory DHT storage, TTL, sharded map, no trust decisions. |
| crates/synvoid-mesh/src/mesh/dht/record_store_crud.rs | advisory_dht | (none) | CRUD on advisory records. |
| crates/synvoid-mesh/src/mesh/dht/record_store_disk.rs | advisory_dht | (none) | Disk persistence for advisory records. |
| crates/synvoid-mesh/src/mesh/dht/record_store_dns.rs | advisory_dht | (none) | DNS advisory record handling in DHT. |
| crates/synvoid-mesh/src/mesh/dht/record_store_message.rs | advisory_dht | policy | Ingress path + envelope verification for advisory records (still stores as advisory). |
| crates/synvoid-mesh/src/mesh/dht/record_store_persist.rs | advisory_dht | (none) | Persistence for advisory store. |
| crates/synvoid-mesh/src/mesh/dht/record_store_sync.rs | advisory_dht | (none) | Sync of advisory records. |
| crates/synvoid-mesh/src/mesh/dht/keys.rs | advisory_dht | (none) | DhtKey enum for advisory keyspace. |
| crates/synvoid-mesh/src/mesh/dht/store.rs | advisory_dht | (none) | Legacy DhtRecordStore (advisory-only). |
| crates/synvoid-mesh/src/mesh/dht/signed.rs | advisory_dht | identity, policy | SignedDhtRecord + verify functions for advisory records (signing/TTL only; quorum calls are advisory-side). |
| crates/synvoid-mesh/src/mesh/dht/routing/mod.rs | advisory_dht | (none) | Kademlia routing table. |
| crates/synvoid-mesh/src/mesh/dht/routing/node_id.rs | advisory_dht | identity | NodeId + PoW (advisory DHT identity primitive). |
| crates/synvoid-mesh/src/mesh/dht/routing/table.rs | advisory_dht | (none) | KBucket table. |
| crates/synvoid-mesh/src/mesh/dht/routing/contact.rs | advisory_dht | (none) | PeerContact. |
| crates/synvoid-mesh/src/mesh/dht/routing/manager.rs | advisory_dht | (none) | DhtRoutingManager. |
| crates/synvoid-mesh/src/mesh/dht/routing/bucket.rs | advisory_dht | (none) | Bucket impl. |
| crates/synvoid-mesh/src/mesh/dht/routing/query.rs | advisory_dht | (none) | Lookup queries. |
| crates/synvoid-mesh/src/mesh/dht/routing/regional_hubs.rs | advisory_dht | (none) | Regional hub hints (advisory). |
| crates/synvoid-mesh/src/mesh/dht/routing/geo_distance.rs | advisory_dht | (none) | Geo hints (advisory). |
| crates/synvoid-mesh/src/mesh/dht/merkle.rs | advisory_dht | (none) | Merkle for advisory record sets. |
| crates/synvoid-mesh/src/mesh/dht/stake.rs | advisory_dht | (none) | Stake for advisory reputation hints. |
| crates/synvoid-mesh/src/mesh/dht/capability_attestation.rs | advisory_dht | (none) | Capability attestation records (advisory). |
| crates/synvoid-mesh/src/mesh/dht/edge_attestation.rs | advisory_dht | (none) | EdgeAttestation records (advisory). |
| crates/synvoid-mesh/src/mesh/dht/capability_access.rs | advisory_dht | policy | Capability verifier used at advisory ingress. |

##### canonical
| File | Primary | Secondary | Justification |
|------|---------|-----------|---------------|
| crates/synvoid-mesh/src/mesh/raft/mod.rs | canonical | (none) | Raft module re-exports for canonical authority. |
| crates/synvoid-mesh/src/mesh/raft/state_machine.rs | canonical | (none) | GlobalRegistryStateMachine: Raft canonical state (Org, Intel, Revocation, AuthorizedGlobalNodes). |
| crates/synvoid-mesh/src/mesh/raft/instance.rs | canonical | (none) | RaftInstance for canonical consensus. |
| crates/synvoid-mesh/src/mesh/raft/client.rs | canonical | (none) | RaftAwareClient for canonical reads. |
| crates/synvoid-mesh/src/mesh/raft/consensus.rs | canonical | (none) | ConsensusTransport + RecordReader for canonical. |
| crates/synvoid-mesh/src/mesh/raft/network.rs | canonical | transport | MeshRaftNetwork (canonical over transport). |
| crates/synvoid-mesh/src/mesh/raft/edge_replica.rs | canonical | (none) | Edge replica for canonical snapshots. |
| crates/synvoid-mesh/src/mesh/raft/regression_tests.rs | canonical | (none) | Canonical Raft tests. |
| crates/synvoid-mesh/src/mesh/dht/quorum.rs | canonical | policy | QuorumRequest required_signatures (canonical decision math). |

##### identity
| File | Primary | Secondary | Justification |
|------|---------|-----------|---------------|
| crates/synvoid-mesh/src/mesh/cert.rs | identity | canonical | MeshCertManager, CertChain, NodeCertBinding, global CA/trust material. |
| crates/synvoid-mesh/src/mesh/organization.rs | identity | canonical | OrgKey, OrgPublicKey, MemberCertificate, quorum signatures (org identity + canonical binding). |
| crates/synvoid-mesh/src/mesh/org_key_manager.rs | identity | canonical | Org key lifecycle (identity + canonical issuance). |
| crates/synvoid-mesh/src/mesh/peer_auth.rs | identity | policy, canonical | validate_peer_role, GlobalNodeRevocationList, SignedRaftAttestation, cert validation (peer identity + policy gates + canonical attest). |
| crates/synvoid-mesh/src/mesh/hybrid_signature.rs | identity | (none) | Hybrid Ed25519+ML-DSA signing. |
| crates/synvoid-mesh/src/mesh/ml_dsa.rs | identity | (none) | ML-DSA primitives. |
| crates/synvoid-mesh/src/mesh/ml_kem_key_exchange.rs | identity | (none) | ML-KEM exchange. |
| crates/synvoid-mesh/src/mesh/passover_key_exchange.rs | identity | (none) | Key exchange service. |
| crates/synvoid-mesh/src/mesh/kem/mod.rs | identity | (none) | KEM facade. |
| crates/synvoid-mesh/src/mesh/kem/kem_trait.rs | identity | (none) | KEM trait. |
| crates/synvoid-mesh/src/mesh/kem/ml_kem.rs | identity | (none) | ML-KEM impl. |
| crates/synvoid-mesh/src/mesh/crypto_verification.rs | identity | (none) | CryptoVerificationPool for identity. |
| crates/synvoid-mesh/src/mesh/tier_key_encryption.rs | identity | (none) | Tier key crypto material. |
| crates/synvoid-mesh/src/mesh/verification.rs | identity | (none) | VerificationTaskManager (identity). |
| crates/synvoid-mesh/src/mesh/config_identity.rs | identity | (none) | NodeIdentityConfig. |

##### policy
| File | Primary | Secondary | Justification |
|------|---------|-----------|---------------|
| crates/synvoid-mesh/src/mesh/dht/key_policy.rs | policy | advisory_dht | DhtKeyPolicyTable + DhtRecordAuthorityClass (canonical-vs-advisory resolution, remote_writes, RaftOrQuorumGlobal). |
| crates/synvoid-mesh/src/mesh/dht/network_policy.rs | policy | advisory_dht | NetworkPolicy min_reputation + blocked_nodes (authorization gates). |
| crates/synvoid-mesh/src/mesh/config.rs | policy | (none) | AuthorityFreshnessConfig + MeshConfig (stale canonical policy). |
| crates/synvoid-mesh/src/mesh/security.rs | policy | (none) | SecureConfigManager, security events (policy decisions). |
| crates/synvoid-mesh/src/mesh/security_challenge.rs | policy | services | MeshAttackDetector, challenge (policy + detection). |
| crates/synvoid-mesh/src/mesh/network_security.rs | policy | transport | AccessDecision, NetworkAccessControl (policy gates on transport). |

##### services
| File | Primary | Secondary | Justification |
|------|---------|-----------|---------------|
| crates/synvoid-mesh/src/mesh/threat_intel.rs | services | advisory_dht | ThreatIntelligenceManager: consumes advisory DHT + reputation for blocking (service consumer, not policy). |
| crates/synvoid-mesh/src/mesh/yara_rules.rs | services | advisory_dht | YaraRulesManager: WASM/YARA dist + DHT publish (service). |
| crates/synvoid-mesh/src/mesh/wasm_dist.rs | services | (none) | WasmDistManager + get_global_wasm_dist_manager (service distribution). |
| crates/synvoid-mesh/src/mesh/reputation.rs | services | (none) | ReputationManager (service consumer of threats). |
| crates/synvoid-mesh/src/mesh/proxy.rs | services | transport, advisory_dht | MeshProxy: service discovery, route query, record_store for policy hints only (no trust decisions). |
| crates/synvoid-mesh/src/mesh/behavioral.rs | services | (none) | Behavioral fingerprint (service). |
| crates/synvoid-mesh/src/mesh/behavioral_intel.rs | services | (none) | BehavioralIntelligenceManager (service). |
| crates/synvoid-mesh/src/mesh/audit.rs | services | (none) | AuditLogger (event consumer). |
| crates/synvoid-mesh/src/mesh/audit_session.rs | services | (none) | AuditSessionManager (service). |
| crates/synvoid-mesh/src/mesh/client_audit.rs | services | (none) | ClientAuditManager (service). |
| crates/synvoid-mesh/src/mesh/hierarchical_routing.rs | services | (none) | HierarchicalRoutingManager (service routing). |
| crates/synvoid-mesh/src/mesh/rate_limit.rs | services | transport | Rate limiting service. |
| crates/synvoid-mesh/src/mesh/topology.rs | services | (none) | MeshTopology (service discovery state). |
| crates/synvoid-mesh/src/mesh/topology/types.rs | services | (none) | Topology types. |
| crates/synvoid-mesh/src/mesh/session/mod.rs | services | (none) | Session types. |
| crates/synvoid-mesh/src/mesh/session/manager.rs | services | (none) | SessionManager (service). |
| crates/synvoid-mesh/src/mesh/cert_dist.rs | services | identity | Cert distribution service. |

##### compat
| File | Primary | Secondary | Justification |
|------|---------|-----------|---------------|
| crates/synvoid-mesh/src/lib.rs | compat | (none) | Thin re-export facade. |
| crates/synvoid-mesh/src/stubs.rs | compat | (none) | All root-crate shims (metrics, http, block_store, etc.). |
| crates/synvoid-mesh/src/mesh/mod.rs | compat | (none) | Public facade + RECORD_STORE_GLOBAL/get_global_record_store (explicit legacy compat). |
| crates/synvoid-mesh/src/mesh/cli.rs | compat | (none) | Mesh CLI shims. |
| crates/synvoid-mesh/src/mesh/config_defaults.rs | compat | policy | Default config shims. |
| crates/synvoid-mesh/src/mesh/config_conversion.rs | compat | policy | Config conversion shims. |
| crates/synvoid-mesh/src/mesh/config_mesh.rs | compat | policy | MeshConfig shims. |

#### Risky Cross-Domain Files
- `peer_auth.rs`: identity + policy + canonical (role validation + attestations perform trust decisions).
- `dht/signed.rs`: advisory_dht + identity + policy (quorum proof + envelope binding).
- `proxy.rs`, `threat_intel.rs`, `transports/manager.rs`, `backend.rs`, `organization.rs`, `cert.rs`, `dht/key_policy.rs`, `dht/record_store_message.rs`: multiple crossings at boundaries.

#### Import Relationships to Prevent (Phase 3 Targets)
- `services/threat_intel` (and `yara_rules`, `wasm_dist`) must not directly read raw Raft state or call `get_record_store` for security decisions; must go through policy (or future `CanonicalTrustReader` + `AdvisoryRecordSource`).
- `services/proxy` must not directly consume advisory `RecordStoreManager` or `dht/signed` records for security decisions; must receive policy outputs only.
- `advisory_dht/signed` (or `record_store_message`) must not perform quorum/canonical authority decisions; callers must be in policy.
- `transport/transports/manager` must not import `canonical/raft` or `policy`; only identity for peer-auth primitives.
- `identity/peer_auth` must not import advisory_dht internals for trust; only use identity primitives + policy for role decisions.

#### Compatibility Globals (Marked Transitional)
- `crates/synvoid-mesh/src/mesh/mod.rs:161`: `RECORD_STORE_GLOBAL` + `set_global_record_store`/`get_global_record_store`. Explicit comment: "Legacy compatibility global — do NOT use in new production paths. All production code should receive RecordStoreManager via explicit injection (DataPlaneServices, MeshTransportManager::get_record_store(), or constructor)."
- Call sites in `threat_intel.rs`, `proxy.rs`, `backend.rs`, `behavioral_intel.rs`, `transports/manager.rs`, root `src/*`, and `src/worker/*` are compat fallbacks. `RECORD_STORE_GLOBAL` is legacy/fallback only.

Every major mesh file is classified. The classification distinguishes advisory DHT state from canonical trust state. Compatibility globals are explicitly marked as transitional.

**Acceptance Criteria (Phase 1) met.**

---

## Phase 2 — Trust Invariants

### Advisory DHT Invariants
- DHT records are advisory unless backed by canonical attestation.
- DHT records are TTL-bound or freshness-bound.
- DHT records may aid discovery, routing hints, cache warmup, and distribution, but must not decide authority.
- A DHT record must not silently grant trust, ownership, global-node status, organization authority, or revocation status.
- DHT data may be stale, missing, duplicated, or maliciously advertised.

### Canonical/Raft Invariants
- Canonical trust state comes from Raft/global-node consensus or cryptographically verifiable canonical attestations derived from that state.
- Organization public keys, global-node membership, revocation lists, trusted CA state, and canonical threat-intel attestations belong to the canonical domain.
- Canonical state may be cached locally, but cache consumers must know whether they are reading a snapshot, a stale snapshot, or a live consensus result.

### Identity Invariants
- Node identity and organization identity are separate concepts.
- Peer authentication proves who is speaking; policy decides what the peer is allowed to influence.
- Signing/verifying records should be separate from deciding whether records are actionable.

### Policy Invariants
- Security-sensitive consumers must depend on policy outputs, not raw DHT records.
- Policy is the only layer allowed to combine advisory DHT data with canonical state to produce an actionable decision.
- If canonical state is unavailable, policy must explicitly choose fail-open, fail-closed, or degraded behavior by decision type.

### Service Invariants
- Service modules may consume discovery/advisory records for non-security-critical hints.
- Service modules must not treat advisory records as trust decisions.
- Threat intel/YARA/WASM distribution must distinguish untrusted advertisement, signed package metadata, and canonical approval.

**Acceptance Criteria (Phase 2) met**: The document makes it possible to review future mesh code by checking which invariant it crosses. Language is normative (`must`, `must not`, `may`, `should`).

---

## Phase 3 — Import Direction and Internal Module Target Shape

### Target Internal Module Shape (Design Target, Before Movement)

```
crates/synvoid-mesh/src/
  lib.rs
  mesh/
    mod.rs              # public facade and compatibility exports only
    transport/          # transport manager, protocol, wire IO
    advisory_dht/       # DHT records, TTL store, discovery announcements
    canonical/          # Raft/global-node authority interfaces and attestations
    identity/           # node/org identity, cert/key/signature verification
    policy/             # trust resolution and actionable decisions
    services/           # YARA/WASM/threat-intel/reputation/proxy consumers
    compat/             # transitional globals/shims if needed
```

### Allowed Import Direction (Design Rule)

- `transport` → identity only for peer-auth primitives, not policy.
- `advisory_dht` → identity for signature verification primitives only.
- `canonical` → identity for canonical signer/verifier primitives.
- `policy` → advisory_dht + canonical + identity.
- `services` → policy + transport APIs, but not raw advisory_dht internals for security decisions.
- `compat` → may import old paths temporarily, but new code must not import compat.

Import direction is a design target. Do not enforce mechanically unless easy.

**Acceptance Criteria (Phase 3) met**: The design note names target modules and allowed dependencies. It identifies at least three imports or module relationships that should be prevented in future work (see Phase 1 list above, plus the explicit examples in the plan).

---

## Phase 4 — First Low-Risk Code Boundary

### Chosen First Implementation Seam

**Preferred**: `CanonicalTrustReader` / `CanonicalTrustSnapshot` (narrow interface for reading canonical trust state).

**Why this seam (lower risk than alternatives)**:
- Read-only by nature: consumers ask "is this record/key/node/intel item canonical/trusted?" instead of reading Raft internals or quorum math directly. No mutation, no wire protocol change.
- Directly supports the core invariant ("Raft/canonical answers what is trusted").
- Easy to implement initially as a thin adapter over existing `RaftAwareClient` + `EdgeReplicaManager` + `DhtKeyPolicyTable` + authorized global key sets, with a snapshot type carrying freshness metadata.
- Lowest blast radius: can be introduced in `canonical/` (or a narrow `policy/` reader) without touching DHT storage, transport, or service distribution paths.
- Enables future policy and service consumers to depend on the seam rather than raw Raft or `dht/quorum`.
- Compared to alternatives:
  - `AdvisoryRecordSource`: Useful but secondary; still requires knowing "what is canonical" to combine safely.
  - `MeshTrustPolicy`: Good long-term target, but requires enumerating all decision types and inputs first (higher surface area for this pass).
  - `RecordTrustLevel` enum: A useful marker for docs/tests, but not a seam or boundary interface.

**Why not broader movement**: This seam can be added as a small new module/trait + impl with no refactoring of existing Raft/DHT code. It satisfies "exactly one preferred first implementation boundary" and "the next implementation pass can start from a concrete chosen seam. No broad code movement is required in this design pass."

**Acceptance Criteria (Phase 4) met**.

---

## Phase 5 — Boundary Review Checklist

Reviewers of future mesh PRs must ask (maps directly to invariants):

- Does this code consume raw DHT/advisory records?
  - If yes, is the use non-security-critical?
  - If security-critical, does it pass through policy?
- Does this code treat a signature as authorization?
- Does this code distinguish peer identity from organization/global authority?
- Does this code distinguish canonical state from cached canonical snapshot?
- What is the failure mode when canonical state is unavailable?
- Does this code introduce a new global or compatibility bypass?
- Is TTL/freshness enforced where advisory state is consumed?
- Are service-level consumers prevented from bypassing policy?

**Acceptance Criteria (Phase 5) met**: The checklist is concrete enough to use during code review and maps directly back to the invariants.

---

## Phase 6 — Lightweight Source Comments (Optional)

**Decision for this pass**: No source comments were added.

Rationale: This is a design/doc-only iteration. Adding even lightweight markers would constitute a code change outside the minimal "if helpful" allowance and risks noisy diffs before the implementation pass that actually creates the seams. Future implementation passes (starting with the chosen `CanonicalTrustReader` seam) may add short domain markers only at the highest-risk boundaries:

- `RECORD_STORE_GLOBAL` / `get_global_record_store` sites in `mesh/mod.rs`, `transports/manager.rs`, `threat_intel.rs`, `proxy.rs`, `backend.rs`.
- `DhtKeyPolicyTable` / `DhtRecordAuthorityClass` decision points.
- `peer_auth.rs` role/attestation validation entry points.
- `dht/signed.rs` quorum and envelope paths (advisory side only).

Example style (for later use only):

```rust
// Domain: compat. Transitional global; new production paths should receive explicit handles.
```

```rust
// Domain: advisory_dht. Records here are not authoritative unless policy verifies canonical attestation.
```

**Acceptance Criteria (Phase 6) met**: Any future comments will clarify trust-domain intent and will not claim code movement has already happened.

---

## Validation

Lightweight checks (no code changes in this pass beyond the new doc):

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo check --workspace --all-targets --features mesh
```

(Executed post-doc creation; see task log. If no Rust changes were required for the doc itself, no compile validation beyond documentation review was needed per plan.)

---

## Completion Criteria

This iteration is complete when:

- `architecture/mesh_trust_domains.md` exists; ✅
- current mesh files/modules are classified by trust domain; ✅
- advisory DHT, canonical/Raft, identity, policy, transport, services, and compat invariants are documented; ✅
- target internal module shape and import direction are documented; ✅
- exactly one first implementation seam is chosen for the next pass (`CanonicalTrustReader`/`CanonicalTrustSnapshot`); ✅
- the review checklist exists; ✅
- no broad code movement has occurred. ✅

### Iteration 8 Implementation Seam

`CanonicalTrustReader` is the first concrete canonical boundary. It is read-only and snapshot-oriented. Services and future policy code should depend on this seam instead of importing Raft internals when they need canonical trust answers.

### Iteration 9 Consumer Migration

`peer_auth.rs` now has a reader-backed canonical status helper (`validate_peer_canonical_status`). It still owns identity verification, but canonical authorization/revocation answers can flow through `CanonicalTrustReader`. This is the first consumer-oriented use of the canonical seam. This pass added the helper + focused tests only; no production call sites to `validate_peer_role` (or leaf validators) were rewired, and old revocation-list / authorized-key paths remain in place for this iteration.

### Iteration 10 Canonical Helper Semantics

`peer_auth::validate_peer_canonical_status` is now test-covered as a staged consumer of `CanonicalTrustReader`. It checks canonical revocation for all roles and canonical global-node authorization for the configured global-role cases (`is_global() && !is_origin()`, i.e. `GLOBAL` and `GLOBAL_EDGE`; `GLOBAL_ORIGIN` and other origin-carrying composites are exempt in this helper because their origin claim requires separate attestation from a real authorized global node). It does not perform signature, certificate, PoW, timestamp, or full policy validation. Freshness is surfaced but not yet policy-enforcing; unavailable revocation preserves legacy permissive behavior, while unavailable global authorization fails closed for global-node authorization checks.

The current guard and `GLOBAL_ORIGIN` exemption behavior is intentional and matches the legacy `validate_peer_role` path + role bitmask design ("origins are not global nodes; origin nodes cannot self-attest as global nodes"). Tests explicitly cover authorized/unauthorized/revoked (all roles + composites), unavailable, stale, edge non-global, and `GLOBAL_ORIGIN` exemption cases using `StaticCanonicalTrustReader`. The helper has precise rustdoc explaining its narrow scope, what it does and does not validate, freshness semantics, and its staged nature before broader consumer migration (e.g. `dht/key_policy.rs`).

No production call sites were rewired; no module reorganization; no legacy `validate_peer_role` behavior removed.

### Iteration 11 DHT Key Policy Canonical Reader

`dht/key_policy.rs` now has a reader-backed policy helper (`classify_key_authority_with_canonical_reader`) that uses `CanonicalTrustReader` for canonical authority questions while preserving advisory DHT mechanics. Advisory records remain advisory; signed records are not automatically authorized; unknown/unavailable canonical answers are explicit and are not silently treated as trust. Revocation is checked before global authorization (revoked wins). Threat-intel keys use `is_threat_intel_canonical()` for canonical trust; all other `CapabilityAttested` keys remain advisory. This pass added helper-level tests (advisory-only, global-authorized, unauthorized, revoked, unavailable, stale, unknown canonical) and did not broadly rewire record propagation/storage paths.

### Iteration 12 Key Policy Ingress Preparation

The key-policy canonical helper now explicitly tests `CanonicalUnavailable` defer branches and has an ingress adapter preserving accept/reject/defer distinctions. No DHT propagation/storage behavior changed.

### Iteration 13 DHT Ingress Policy Context Seam

`dht/ingress_policy.rs` introduced `DhtIngressPolicyContext`, a small injectable context carrying an optional `Arc<dyn CanonicalTrustReader>`. The `check_dht_ingress_authority` entry point delegates to the key-policy adapter and produces `DhtIngressGateOutcome` (Accepted, Rejected, Deferred, NotConfigured). The context is cloned into `DhtRecordIngressContext.policy_context` at creation time. No production wiring was active in this iteration.

### Iteration 14 DHT Ingress Context Wiring Cleanup

`RecordStoreManager` now carries an optional `DhtIngressPolicyContext` and attaches it to direct client Push/Announce ingress contexts in both `record_store_message.rs` and `transport_peer.rs`. The existing `store_record_from_ingress` gate is therefore active for all configured Push/Announce paths and remains inactive by default. Disabled context preserves legacy behavior. Sync/replay/local/quorum/Raft apply paths remain outside this gate.

### Iteration 15 Final Status

The canonical trust-domain seam is now staged through peer auth, DHT key policy, and direct DHT Push/Announce ingress. Canonical trust answers flow through `CanonicalTrustReader`; DHT policy and ingress consume the trait, not concrete Raft internals. Disabled ingress policy context preserves legacy behavior. Configured Push/Announce ingress rejects canonical-required records on unauthorized, revoked, unavailable, or unknown canonical state. Advisory-only records remain advisory. Sync/replay/local/quorum/Raft apply paths were intentionally not broadened into this gate.

This track stops here. The advisory source seam is complete; Iteration 20 completed the injection seam for the threat-intel consumer.

### Iteration 16 AdvisoryRecordSource Seam

`AdvisoryRecordSource` introduces a read-only seam for advisory DHT observations. It exposes present/missing/expired/unavailable advisory records and prefix reads without exposing mutation, replication, quorum, or canonical trust decisions. The record-store adapter preserves existing read behavior and does not validate authority. This seam complements `CanonicalTrustReader`; future policy code should compose both rather than letting service consumers read raw DHT records as authority.

### Iteration 17 Advisory Source Hardening

`RecordStoreAdvisorySource` now has focused tests against a real `RecordStoreManager`, covering present, missing, expired, prefix-limit, and expired-prefix filtering behavior. The seam remains read-only and advisory-only; no service consumers were migrated and no canonical trust behavior was added. Freshness/status semantics (single-key lookup can return `Expired` explicitly; prefix lookup filters expired entries before mapping) are consistent with the adapter's implementation and documented via test names + existing rustdoc. Follow-up still points to policy composition before service-consumer migration.

### Iteration 18 Threat Intel Policy Composition

A small threat-intel policy helper now composes `CanonicalTrustReader` with `AdvisoryRecordSource`. Advisory records provide observations; canonical state provides trust; the helper returns explicit actionability, rejection, or defer decisions. Tests cover present/missing/expired/unavailable advisory records and trusted/not-trusted/unknown/unavailable canonical state. No service consumers were migrated in this pass.

### Iteration 19 Threat Intel Consumer Migration

`ThreatIntelligenceManager` now has an `evaluate_indicator_actionability` method that uses the threat-intel policy composition helper. This is the first production consumer migration: the method composes advisory DHT observations with canonical Raft trust to produce an explicit `ThreatIntelPolicyDecision`. The old raw lookup paths (`lookup_local_indicator`, `lookup_local_indicator_by_ip`, `lookup_threat_indicator_in_dht`) remain available for comparison and fallback.

Policy-composed behavior requires both advisory observation and canonical trust before treating an indicator as actionable. Advisory-only records are never actionable. No proxy, YARA/WASM, routing, or broader service consumers were migrated. The method takes `&dyn CanonicalTrustReader` and `&dyn AdvisoryRecordSource` as parameters; production injection of both seams remains deferred pending higher-level composition.

Tests cover: actionable when both present and trusted, advisory-only not actionable, advisory missing not actionable, canonical not trusted not actionable, canonical unavailable deferred, legacy path still works, comparison verifying advisory-only never actionable, and no DHT/Raft/networking required.

### Iteration 20 Threat Intel Policy Injection

`ThreatIntelligenceManager` now carries an optional `ThreatIntelPolicyContext` containing `Arc<dyn CanonicalTrustReader>` and `Arc<dyn AdvisoryRecordSource>`. Default `None` preserves legacy behavior. A configured policy-composed lookup/evaluation path can now use the injected seams without deep construction or globals.

New methods:
- `set_policy_context(Option<ThreatIntelPolicyContext>)` — injects or clears the context.
- `evaluate_indicator_actionability_configured(indicator_value, threat_type)` — uses the injected context; returns `None` if no context is set.
- `lookup_threat_indicator_policy_composed(indicator_value, threat_type)` — policy-composed sibling to `lookup_threat_indicator_in_dht`. Falls back to legacy raw DHT lookup when no context is configured. When configured, gates the DHT result on the policy decision: `Actionable` returns the indicator, all other decisions return `None`.

The old raw lookup paths (`lookup_local_indicator`, `lookup_local_indicator_by_ip`, `lookup_threat_indicator_in_dht`) remain available for comparison and fallback. The manual `evaluate_indicator_actionability(canonical, advisory, ...)` method also remains available.

No proxy, YARA/WASM, routing, or broader service consumers were migrated. Exactly one policy-composed read path was added as a sibling method.

Tests cover: default has no context, set context enables configured evaluation, actionable only when both advisory present and canonical trusted, advisory-only/advisory missing/canonical not trusted/canonical unavailable all not actionable or deferred, policy-composed lookup returns None for non-actionable, legacy path unchanged, no DHT/Raft/networking required.

### Iteration 21 Second Threat Intel Consumer Migration

A second read-only threat-intel path now has a policy-composed sibling using the injected `ThreatIntelPolicyContext`. New methods:

- `lookup_local_indicator_policy_composed(indicator_value, threat_type)` — policy-composed sibling to `lookup_local_indicator`. Falls back to legacy raw local lookup when no context is configured. When configured, gates the result on the policy decision: `Actionable` returns the indicator, all other decisions return `None`.
- `lookup_local_indicator_by_ip_policy_composed(ip)` — convenience wrapper delegating to the generic method with `ThreatType::IpBlock`.

Raw local/DHT lookup methods remain available and unchanged. No enforcement hot paths, proxy, YARA/WASM, routing, DHT sync, or ingestion paths were migrated.

Tests cover: no context falls back to legacy, Actionable returns indicator, advisory present + canonical unknown returns None, advisory missing returns None, canonical not trusted returns None, canonical unavailable returns None, raw lookup still works, IP wrapper delegates correctly, no DHT/Raft/networking required.

### Iteration 22 Threat Intel Policy Cleanup

The two policy-composed threat-intel lookup paths now share a single decision-to-actionability helper (`is_policy_actionable`), keeping `Actionable` as the only policy result that returns an indicator. Raw local/DHT lookup APIs remain compatibility/diagnostic paths; policy-composed methods are the preferred API for new actionability-sensitive reads. No proxy, YARA/WASM, routing, DHT sync, ingestion, or enforcement hot paths were migrated.

### Iteration 23 Threat Intel Policy Reassessment

The threat-intel policy-composed lookup track is staged and stable. Two read-only composed lookup APIs exist for DHT and local indicators, both gated by shared `is_policy_actionable` semantics. A call-graph review found no low-risk caller that should migrate before broader proxy/YARA/WASM/routing design work. The track is paused; raw lookup APIs remain compatibility/diagnostic paths.

### Iteration 33 — Shadow/Observability Consumers

Selected and implemented the first low-risk consumers of policy-composed
threat-intel decisions. These are shadow/observability consumers that answer
"what would policy composition decide?" without changing enforcement behavior.

**New types** (`crates/synvoid-mesh/src/mesh/threat_intel_policy.rs`):

- `ThreatIntelPolicyDecisionClass` — compact 6-variant enum for metrics/labeling
- `ThreatIntelPolicyShadowDecision` — diagnostic DTO for admin/logging
- `ThreatIntelPolicyShadowDisagreement` — raw vs composed disagreement classifier

**New helpers**:

- `classify_threat_intel_policy_decision()` — maps policy decision to decision class
- `threat_intel_policy_shadow_decision()` — builds shadow DTO
- `classify_shadow_disagreement()` — classifies raw/composed disagreement

**New method on `ThreatIntelligenceManager`**:

- `evaluate_indicator_policy_shadow()` — evaluates policy composition, increments
  metrics, tracks disagreement, returns shadow DTO

**New admin endpoints**:

- `GET /mesh/threat-intel/policy-shadow?indicator=...&type=...` — per-indicator shadow evaluation
- `GET /mesh/threat-intel/policy-shadow/stats` — aggregated metrics counters

**Metrics counters** (via `synvoid-metrics`):

- `threat_intel_policy_shadow_actionable_total`
- `threat_intel_policy_shadow_advisory_only_total`
- `threat_intel_policy_shadow_not_actionable_total`
- `threat_intel_policy_shadow_deferred_total`
- `threat_intel_policy_shadow_not_configured_total`
- `threat_intel_policy_shadow_raw_disagreement_total`
- `threat_intel_policy_shadow_canonical_unavailable_total`
- `threat_intel_policy_shadow_advisory_missing_total`

**Classification**:

- Class A (safe, implemented): admin diagnostics, metrics counters, structured logging
- Class B (design only, not implemented): request blocking, YARA/WASM, routing, bot/challenge
- Class C (out of scope): Raft consensus, DHT ingress, peer auth, canonical export

**Non-goals honored**: No enforcement behavior changed. Raw lookup APIs remain
compatibility/diagnostic. No proxy/WAF/YARA/WASM/routing consumers migrated.
No global canonical readers introduced. No `StaticCanonicalTrustReader` in production.

### Iteration 34 — Consumer Enforcement Gate

The threat-intel consumer enforcement migration advances from shadow/observability
to enforcement. Advisory DHT records alone can no longer cause enforcement
mutations; all enforcement paths now require policy-composed approval.

**Consumer classification** (`crates/synvoid-mesh/src/mesh/threat_intel_policy.rs`):

- `ThreatIntelConsumerKind` — classifies consumers by enforcement impact
  (`Observation`, `Advisory`, `Enforcement`)
- `ThreatIntelConsumerAction` — maps consumer kind + policy decision to allow/deny/defer
- `ThreatIntelDeferredMode` — controls deferred-result behavior per consumer
- `classify_consumer_action()` — pure classifier, no I/O; returns
  `ThreatIntelConsumerAction` from consumer kind + policy decision

**Enforcement gate in `handle_incoming_threat()`** (`crates/synvoid-mesh/src/mesh/threat_intel.rs`):

- Enforcement mutations (blocking, reputation decay, YARA rule activation) are
  now gated by the consumer classification and policy decision.
- Advisory DHT records without canonical trust produce `AdvisoryOnly` decisions,
  which the enforcement gate maps to deny for enforcement consumers.
- Advisory-only records alone cannot cause enforcement; both advisory observation
  and canonical trust are required before enforcement mutations proceed.
- Non-enforcement consumers (observation, advisory) continue to receive their
  results without the enforcement gate.

**Strict policy-composed lookup wrappers**:

- `lookup_threat_indicator_policy_strict(indicator_value, threat_type)` — wraps
  `lookup_threat_indicator_policy_composed` with the consumer enforcement gate;
  returns `None` for non-actionable policy decisions.
- `lookup_local_indicator_policy_strict(indicator_value, threat_type)` — wraps
  `lookup_local_indicator_policy_composed` with the enforcement gate.
- `lookup_local_indicator_by_ip_policy_strict(ip)` — IP convenience wrapper
  delegating to the generic strict method.

**Inheritance**:

- `apply_sync` and `handle_hot_threat_gossip` inherit the enforcement gate via
  delegation to `handle_incoming_threat`. No additional gating logic is needed in
  those paths; they pass through the same consumer classification and policy
  decision as direct callers.

**Metrics stubs** (via `synvoid-metrics`):

- `threat_intel_enforcement_gate_allowed_total`
- `threat_intel_enforcement_gate_denied_total`
- `threat_intel_enforcement_gate_deferred_total`
- `threat_intel_enforcement_gate_not_configured_total`

**Tests** (23 new):

- Consumer classification matrix: all `ThreatIntelConsumerKind` ×
  `ThreatIntelPolicyDecision` combinations, deferred-mode variants,
  strict lookup wrappers returning `None` for non-actionable decisions,
  strict lookup wrappers returning indicator for `Actionable`,
  enforcement gate blocking advisory-only enforcement,
  enforcement gate allowing actionable enforcement,
  enforcement gate deferring when canonical unavailable,
  inheritance via `apply_sync` and `handle_hot_threat_gossip`,
  raw lookup methods returning results without enforcement gating,
  metrics counter increments for all gate outcomes.

**Raw lookup methods**: Now documented as "not for enforcement." The raw
`lookup_local_indicator`, `lookup_local_indicator_by_ip`, and
`lookup_threat_indicator_in_dht` methods remain for compatibility and diagnostics
but bypass the enforcement gate. Callers requiring enforcement guarantees must
use the strict wrappers.

**Non-goals honored**: No proxy, YARA/WASM, routing, or WAF consumers were
migrated beyond the enforcement gate in `handle_incoming_threat`. No global
canonical readers introduced. No `StaticCanonicalTrustReader` in production.
The consumer classification matrix is extensible but only enforcement consumers
are gated in this pass.

- Iteration 35: Enforcement semantic cleanup (AsnBlock observational relabel, IncomingThreatPolicyGate, suppression metric classifier, ThreatIntelDeferredMode dispatch, mutation helper preconditions, raw consumer audit)

### Iteration 36 — Doc Drift, Three-Plane Model, Request/WAF Audit

Documentation drift cleanup for the now-stable threat-intel enforcement model. Changes:

- Fixed `AsnBlock` local action in `THREAT_INTEL.md` table (observational/advisory, not attack logging)
- Updated architecture diagram to reflect policy-gated threat sync (not blind "apply threats")
- Tightened strict vs legacy API guidance: strict is required for enforcement, legacy is for diagnostics
- Added "Current Integration Status" table for all indicator types
- Added three-plane threat-intel model (advisory, canonical, enforcement) to mesh trust domains
- Documented request/WAF boundary: WAF reads BlockStore, not ThreatIntelligenceManager directly

**Request/WAF audit findings:**
- WAF request path (`check_block_store`, `check_early`, `maybe_escalate_and_block`) reads BlockStore state, not threat-intel directly
- Strict/composed lookup wrappers have zero external production callers — defined but not yet consumed
- All mesh enforcement gating is centralized in `handle_incoming_threat`
- No migration needed; the existing WAF/BlockStore boundary is correct

### Iteration 24 Threat Intel Policy Verification

The shared `is_policy_actionable` helper remains in place and both policy-composed lookup paths continue to use it. Focused verification (`cargo check -p synvoid-mesh --features mesh`, `cargo test -p synvoid-mesh threat_intel --features mesh`, `cargo test -p synvoid-mesh threat_intel_policy --features mesh`) passed. No additional consumer migration or hot-path change was added; raw lookup APIs remain compatibility/diagnostic paths.

### Iteration 25 Data-Plane Policy Context Cleanup

`DataPlaneServices` now carries an optional `ThreatIntelPolicyContext` and exposes a low-risk `apply_threat_intel_policy_context()` helper for `ThreatIntelligenceManager`. The default remains `None`, preserving legacy behavior. This pass establishes ownership and wiring for policy context only; it does not migrate proxy, YARA/WASM, routing, WAF enforcement, DHT sync, ingestion, or Raft behavior. A root-side helper now constructs the context from explicit canonical/advisory handles. The Supervisor-to-worker IPC export path for canonical snapshots is implemented in Iterations 28-30.

### Iteration 26 Root-Side Context Construction

`ThreatIntelPolicyContext` construction is now explicit at the root. The helper only accepts direct `CanonicalTrustReader` and `AdvisoryRecordSource` handles, so advisory-source construction stays tied to explicit handles instead of any global fallback. Worker bootstrap leaves the canonical field `None` because canonical snapshots arrive after bootstrap via IPC (`CanonicalTrustSnapshotUpdate`); the snapshot is applied through `DataPlaneServices::update_threat_intel_policy_context()` in the IPC message loop.

### Iteration 27 Canonical Reader Ownership Assessment

The data-plane composition root is ready to carry a populated `ThreatIntelPolicyContext`, and advisory construction is available from the explicit record-store handle. The Supervisor now exports a bounded `CanonicalTrustSnapshot` via IPC, completing the canonical reader export path (Iteration 28).

Canonical trust state (Raft consensus, `EdgeReplicaManager`) is owned by the Supervisor process. Workers are data-planes explicitly disconnected from the mesh control plane (`init_mesh.rs` returns `None` for `transport_manager` in worker mode). Workers receive a bounded `CanonicalTrustSnapshot` via IPC which implements `CanonicalTrustReader` directly — `SnapshotCanonicalTrustReader` wraps `EdgeReplicaManager` and is used only on the Supervisor side.

The ownership boundary was documented in `init_mesh.rs`, `mod.rs`, and `services.rs`. Iteration 28-30 resolved this by exposing canonical snapshots from the Supervisor to workers via IPC (`CanonicalTrustSnapshotUpdate`), without introducing globals or test-only static readers.

No production code synthesizes canonical trust. No proxy, YARA/WASM, routing, WAF, DHT sync, ingestion, or Raft consumers were migrated.

### Iteration 28 Supervisor Canonical Snapshot Export

Supervisor/control-plane code now exports a bounded `CanonicalTrustSnapshot` for worker data-plane use.

**Export path:**
- `EdgeReplicaManager::canonical_trust_snapshot()` reads from the SQLite replica and produces a `CanonicalTrustSnapshot`
- The Supervisor sends `CanonicalTrustSnapshotUpdate` IPC message to workers when they become ready
- Workers receive and store the snapshot; `CanonicalTrustSnapshot` itself implements `CanonicalTrustReader`

**Worker consumption:**
- Worker stores the snapshot in `UnifiedServerWorkerState.canonical_snapshot`
- Snapshot arrives after bootstrap via IPC (`CanonicalTrustSnapshotUpdate`); the worker deserializes it and stores it read-only
- `DataPlaneServices::update_threat_intel_policy_context()` applies the snapshot + advisory source to refresh the `ThreatIntelligenceManager` policy context
- At bootstrap, `canonical_snapshot` is `None` and the policy context is unset; it is populated when the IPC snapshot arrives

**Invariants preserved:**
- Workers do not own Raft or EdgeReplicaManager
- Workers cannot mutate canonical state
- Snapshot is read-only and bounded
- No private key material or signer secrets in the snapshot
- `ThreatIntelPolicyContext` remains optional
- No proxy/YARA/WASM/routing/WAF consumers were migrated

### Iteration 31 Canonical Snapshot Freshness Policy

Canonical snapshots are authoritative only within a configured freshness window. `CanonicalSnapshotFreshnessPolicy` defines thresholds for classifying snapshot age, and `classify_canonical_snapshot()` produces a `CanonicalSnapshotFreshness` state (Fresh, StaleWithinGrace, Expired, Invalid, Missing). `FreshnessBoundCanonicalReader` wraps `CanonicalTrustReader` and enforces the freshness policy: trust decisions are deferred or denied when the snapshot is expired, invalid, or stale beyond grace.

**Types:**
- `CanonicalSnapshotFreshnessPolicy`: configurable thresholds (fresh_max_age_ms, stale_grace_max_age_ms) + stale mode (`CanonicalSnapshotStaleMode`)
- `CanonicalSnapshotStaleMode`: `FailOpenDefer` (default) | `FailClosedNotActionable` | `AllowStaleWithWarning`
- `classify_canonical_snapshot()`: pure classifier, no I/O
- `FreshnessBoundCanonicalReader`: wrapper implementing `CanonicalTrustReader`, delegating only when freshness is acceptable

**Config fields** in `AuthorityFreshnessConfig`:
- `canonical_snapshot_fresh_max_age_ms` (default: 60_000)
- `canonical_snapshot_stale_grace_max_age_ms` (default: 300_000)
- `canonical_snapshot_stale_mode` (default: fail_open_defer)

### Iteration 32 Config Wiring

The worker IPC handler now reads runtime configuration instead of using hardcoded defaults. A `From<&AuthorityFreshnessConfig> for CanonicalSnapshotFreshnessPolicy` conversion in `canonical.rs` bridges the config surface to the freshness policy. Invalid configurations (stale_grace < fresh_max_age) are normalized at conversion time.

**Stale-mode live behavior (canonical):**
- `Fresh`: install `FreshnessBoundCanonicalReader`, apply policy context
- `StaleWithinGrace + AllowStaleWithWarning`: install `FreshnessBoundCanonicalReader`, apply policy context
- `StaleWithinGrace + FailOpenDefer`: clear policy context (`None`), defer to raw lookups
- `StaleWithinGrace + FailClosedNotActionable`: install `FreshnessBoundCanonicalReader`, which returns `NotTrusted { ExpiredSnapshot }` for all trust queries
- `Expired` / `Invalid` / `Missing`: clear policy context, log warning

**Malformed/invalid/expired snapshot semantics:**
- Malformed postcard payload: reject update, preserve previous valid snapshot/context
- Invalid timestamp: store raw snapshot for diagnostics, clear policy context
- Expired timestamp: store raw snapshot for diagnostics, clear policy context

**Worker flow:**
1. IPC `CanonicalTrustSnapshotUpdate` received
2. Deserialize snapshot (malformed → reject, preserve previous)
3. Store raw snapshot for diagnostics
4. Read freshness policy from `config.main.tunnel.mesh.authority_freshness` (fallback to defaults)
5. Classify freshness via `classify_canonical_snapshot()`
6. Based on classification + stale mode: install reader or clear context (see stale-mode table above)
7. No proxy/YARA/WASM/routing/WAF consumers were migrated in this pass.

**Files:**
- `crates/synvoid-mesh/src/mesh/canonical.rs` — types, classifier, wrapper, `From` conversion, normalization
- `src/worker/unified_server/lifecycle.rs` — worker integration (config read, classify, apply)
- `crates/synvoid-mesh/src/mesh/config.rs` — config fields in `AuthorityFreshnessConfig`

## Three-Plane Threat-Intel Model

Threat-intel data flows through three logical planes. Each plane has clear ownership and invariant constraints.

### Advisory Plane

The advisory plane stores and distributes threat-intel observations. Data in this plane is untrusted for enforcement purposes.

- **DHT records** — `threat_indicator:*` keys, TTL-bound, eventually consistent
- **Gossip** — `handle_hot_threat_gossip`, `ThreatSync`/`ThreatSyncResponse` mesh messages
- **Sync** — `sync_from_dht`, `re_announce_local_indicators`
- **Local bookkeeping** — `lookup_local_indicator`, `lookup_threat_indicator_in_dht` (raw APIs)

**Invariant**: Advisory data may be stored, observed, logged, and compared, but must not directly cause enforcement mutations (block, rate-limit, WAF deny).

### Canonical Plane

The canonical plane holds Raft-derived trust state that determines whether advisory observations may become enforcement.

- **Raft consensus** — `EdgeReplicaManager`, `RaftAwareClient`, `GlobalRegistryStateMachine`
- **Canonical snapshots** — `CanonicalTrustSnapshot` exported via IPC to workers
- **Freshness policy** — `CanonicalSnapshotFreshnessPolicy`, `FreshnessBoundCanonicalReader`
- **Key policy** — `DhtKeyPolicyTable`, `classify_key_authority_with_canonical_reader`

**Invariant**: Canonical state answers "what is trusted?" It never directly mutates enforcement state; it is consumed by the policy plane to gate enforcement decisions.

### Enforcement Plane

The enforcement plane applies policy-gated mutations to local enforcement state (block-store, rate-limit, WAF deny lists).

- **`handle_incoming_threat`** — single entry point for mesh-sourced enforcement, gated by `evaluate_incoming_threat_policy`
- **`classify_consumer_action`** — maps consumer kind + policy decision to `PermitAction`/`SuppressAction`/`ShadowOnly`/`RawCompatibilityOnly`
- **Block-store mutations** — `block_ip` gated by `PermitAction` in mesh threat-intel path
- **Rate-limit mutations** — gated by `PermitAction` in mesh threat-intel path

**Invariant**: Enforcement mutations require `ThreatIntelConsumerAction::PermitAction` from the policy plane. When no policy context is configured, enforcement is suppressed by default.

### Request/WAF Boundary

The WAF request path does not query `ThreatIntelligenceManager` directly. Instead:

1. **Mesh enforcement** (`handle_incoming_threat`) populates `BlockStore` state through the enforcement plane.
2. **WAF request code** (`check_block_store`, `check_early`, `maybe_escalate_and_block`) reads `BlockStore` as local enforcement state.
3. **Raw DHT/local advisory lookups** are not on the request/WAF hot path.

This boundary is correct and must be preserved. New threat-intel integrations that want to affect WAF behavior should either:
- Route through `handle_incoming_threat` (enforcement plane), or
- Use strict/composed lookup wrappers for read-only policy-gated decisions.

Do not add raw advisory lookups to request/WAF hot paths.

## Follow-Up Recommendation

After Iteration 35, the enforcement semantic cleanup is complete. Key invariants:
- `handle_incoming_threat` evaluates policy via `IncomingThreatPolicyGate` (carrying action + decision)
- Suppression metrics classify by actual policy outcome (advisory-only, not-actionable, deferred, not-configured)
- `ThreatIntelDeferredMode` dispatches to the correct action (FailOpenNoAction/FailClosedNoAction → SuppressAction, ShadowOnly → ShadowOnly)
- `AsnBlock` is observational only — no enforcement gate, no block-store mutation
- Private mutation helpers (`apply_rate_limit_mesh_action`, `apply_suspicious_mesh_action`) have documented preconditions requiring PermitAction

Raw consumer audit conclusions:
- All mesh-sourced enforcement paths are gated via `handle_incoming_threat`
- One raw `lookup_local_indicator` in `feed_client.rs` is bookkeeping/dedup, not enforcement
- One raw `lookup_local_indicator` in `evaluate_indicator_policy_shadow` is shadow/observability only
- No external callers of composed/strict lookup wrappers in production code
- `announce_honeypot_threat` block_ip is local-origin, correctly ungated

The trust-domain/freshness/enforcement track is a reasonable stopping point. Move to a different architecture track next; do not expand proxy, YARA/WASM, routing, or WAF consumers without a separate design pass.

---

## References

- Plan: `plans/mesh_trust_domain_design_iteration_7.md`
- Current mesh architecture: `architecture/mesh.md`, `architecture/mesh_deep_dive.md`
- AGENTS.md (mesh facts, RECORD_STORE_GLOBAL notes, verification commands)
- `crates/synvoid-mesh/src/mesh/mod.rs` (compat globals)
- `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` (authority classes)
- `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` (Namespaces: Org, Intel, Revocation, AuthorizedGlobalNodes)
- `crates/synvoid-mesh/src/mesh/peer_auth.rs` (validate_peer_role + validate_peer_canonical_status + SignedRaftAttestation v2)
- `crates/synvoid-mesh/src/mesh/raft/consensus.rs` (ConsensusTransport, RecordReader)

(End of document)
