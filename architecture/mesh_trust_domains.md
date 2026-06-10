# Mesh Trust Domains — Design Note (Iteration 7)

**Status**: Design-only pass. No broad code movement.  
**Date**: 2026-06-10  
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

## Follow-Up Recommendation

The next pass should implement the chosen first seam only (`CanonicalTrustReader` + explicit advisory record types + snapshot freshness). Defer any module reorganization or broader movement. After this pass, migrate the next narrow policy-facing seam (likely `dht/key_policy.rs`).

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
