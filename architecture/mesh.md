# Mesh Module Architecture

The Mesh module (`crates/synvoid-mesh/src/mesh/`, re-exported via `src/mesh/mod.rs`) is SynVoid's peer-to-peer networking subsystem that provides encrypted inter-node communication, DHT-based service discovery, organizational multi-tenancy, post-quantum cryptography, and distributed DNS with DNSSEC support. It is the core infrastructure enabling SynVoid's global control plane and multi-tenant routing mesh.

---

## 1. Purpose and Responsibility

The Mesh module is responsible for:

- **Peer-to-peer connectivity**: Establishing encrypted QUIC/WireGuard tunnels between SynVoid nodes across the internet, even behind NATs.
- **Service discovery via DHT**: Distributing signed or Raft-attested records (routing policies, provider info, DNS records) via a Kademlia-style distributed hash table. DHT records are advisory and TTL-bound; DHT does not decide trust, ownership, or global policy.
- **Distributed consensus**: Global nodes participate in a Raft cluster to commit canonical authority records (OrgPublicKey, ThreatIntel, GlobalNodeRevocationList) with strong consistency guarantees. Raft is the only source of canonical global trust state.
- **Organization management**: Managing multi-tenant isolation using tiered keys, member certificates, and capability attestations.
- **Post-quantum cryptography**: Hybrid Ed25519+ML-DSA signatures and ML-KEM-768 key exchange to protect against quantum adversaries.
- **Distributed DNS**: DNSSEC-validated DNS resolution over the mesh with per-tenant zone ownership.
- **Behavioral intelligence**: Fingerprinting and reputation tracking of peers and upstreams.
- **Security event handling**: Attack detection, challenge-response security, and threat intelligence distribution.

A trust-domain classification and invariants document exists at `architecture/mesh_trust_domains.md` (advisory DHT vs. canonical Raft, policy as decision layer) for future reviews. See `CanonicalTrustReader` in `crates/synvoid-mesh/src/mesh/canonical.rs` (Iteration 8) and `architecture/mesh_trust_domains.md`. Canonical snapshot freshness policy (`classify_canonical_snapshot()`, `FreshnessBoundCanonicalReader`) enforces age bounds on trust decisions — see Iteration 31 in `architecture/mesh_trust_domains.md`. Config wiring (Iteration 32) sources freshness thresholds from `AuthorityFreshnessConfig` at runtime.

---

## 2. Module Structure

The module root is `crates/synvoid-mesh/src/mesh/mod.rs` (re-exported via `src/mesh/mod.rs`), which declares all public submodules and re-exports key types. The module is organized into the following major areas:

### Core Exports (from `crates/synvoid-mesh/src/mesh/mod.rs`)

```
crates/synvoid-mesh/src/mesh/
├── mod.rs               # Submodule declarations + public re-exports
├── transport.rs         # Main QUIC transport (MeshTransport, MeshPeerConnection)
├── transports/          # Transport abstraction layer (MeshTransportManager, QuicMeshTransport)
├── transport_*.rs      # Feature-gated transport extensions (DHT, DNS, Org, peer, etc.)
├── proxy.rs             # Mesh proxy for request forwarding between peers
├── backend.rs           # Backend pool and initialization helpers
├── topology.rs          # Network topology, routing cache, peer state
├── protocol.rs          # MeshMessage, signing, serialization
├── config.rs            # MeshConfig, MeshNodeRole, transport preferences
├── session/             # Session management for KEM key rotation
├── dht/                 # Distributed hash table (full submod tree below)
├── raft/                # Raft consensus for global control plane
├── organization.rs      # Organization, tier keys, member certificates
├── cert.rs              # MeshCertManager for TLS certificates
├── security.rs          # SecureConfigManager for encrypted config storage
├── threat_intel.rs      # Threat intelligence distribution
├── reputation.rs        # Peer reputation tracking
├── behavioral.rs        # Behavioral fingerprinting
├── behavioral_intel.rs  # Behavioral intelligence
├── audit.rs             # Audit event logging
├── audit_session.rs     # Session-based audit
├── client_audit.rs      # Client-side audit reporting
├── yara_rules.rs        # YARA rule distribution for threat detection
├── wasm_dist.rs         # WASM module distribution
├── hybrid_signature.rs  # Hybrid Ed25519+ML-DSA signatures
├── ml_dsa.rs            # ML-DSA-44 signing wrapper
├── ml_kem_key_exchange.rs # ML-KEM-768 gRPC key exchange service
├── kem/                 # KEM abstraction (KemSession, MlKem768)
├── tier_key_encryption.rs # Encrypted tier key serialization
├── network_security.rs  # Network access control rules
├── security_challenge.rs # Attack detection via challenge-response
├── verification.rs      # Message signature verification tasks
├── crypto_verification.rs # Crypto verification pool
├── peer_auth.rs         # Node authentication and revocation
├── org_key_manager.rs  # Organization key management
├── passover_key_exchange.rs # PASEO key exchange
├── hierarchical_routing.rs # Geo-distributed routing with bloom filters
├── discovery.rs         # Peer discovery
├── rate_limit.rs        # Rate limiting infrastructure
├── cli.rs               # CLI argument parsing
├── config*.rs           # Configuration helpers, defaults, identity, conversion
```

### DHT Submodule Tree (under `crates/synvoid-mesh/src/mesh/dht/`)

```
crates/synvoid-mesh/src/mesh/dht/
├── mod.rs               # DhtError, DhtConfig, DhtRateLimiter, DhtConsistencyLevel
├── keys.rs              # DhtKey, DhtRecordEntry
├── merkle.rs            # MerkleNode, MerkleProof, MerkleTree
├── record_store.rs      # RecordStoreManager (in-memory DHT storage)
├── record_store_disk.rs # DiskRecordStore (persistent DHT storage)
├── record_store_sync.rs # RecordStoreManager sync helpers
├── record_store_message.rs # Message types for record sync
├── record_store_crud.rs # CRUD operations on record store
├── record_store_dns.rs  # DNS-specific record store
├── record_store_persist.rs # Persistent record storage to disk
├── routing/             # K-bucket routing table implementation
│   ├── mod.rs           # RoutingTable, KBucket, PeerContact, NodeId
│   ├── table.rs         # RoutingTable impl
│   ├── bucket.rs       # KBucket impl
│   ├── node_id.rs      # NodeId type
│   ├── contact.rs       # PeerContact type
│   ├── query.rs        # DhtQuery, LookupQuery, QueryResponse
│   ├── manager.rs       # DhtRoutingManager (routing orchestration)
│   ├── geo_distance.rs  # Geo-based routing
│   └── regional_hubs.rs # Regional hub info
├── quorum.rs            # Quorum verification logic for DHT records
├── signed.rs            # SignedDhtRecord, RecordSigner, TtlManager, QuorumVerifierContext
├── stake.rs             # StakeManager for node staking/Slashing
├── capability_attestation.rs # CapabilityAttestation
├── capability_access.rs # CapabilityAccessVerifier
├── edge_attestation.rs  # EdgeAttestation
├── network_policy.rs    # GlobalAiBotList, GlobalNodeBlocklist, NetworkPolicy
└── store.rs             # Additional store types
```

### Raft Submodule Tree (under `crates/synvoid-mesh/src/mesh/raft/`)

```
crates/synvoid-mesh/src/mesh/raft/
├── mod.rs               # MeshRaftNetwork, RaftCommitNotification
├── instance.rs         # RaftInstance (Raft lifecycle management)
├── network.rs          # MeshRaftNetwork + MeshRaftNetworkFactory (raft network impl)
├── state_machine.rs    # GlobalRegistryStateMachine, GlobalNodeRevocationList, Namespace
├── client.rs           # RaftAwareClient (consistent read client)
├── edge_replica.rs     # EdgeReplicaManager (edge node replica caching)
└── regression_tests.rs # Raft regression tests
```

### KEM Submodule Tree (under `crates/synvoid-mesh/src/mesh/kem/`)

```
crates/synvoid-mesh/src/mesh/kem/
├── mod.rs              # MlKem768, MlKem768PublicKey, MlKem768SecretKey, MlKem768SharedSecret
├── ml_kem.rs          # ML-KEM-768 implementation
└── kem_trait.rs      # KemSession, KemError (trait + stub for algorithm abstraction)
```

---

## Lifecycle Management

Mesh transport uses structured lifecycle management (Iterations 68–74):

- `MeshTaskGroup` owns all spawned tasks with classification; `new_with_forward_and_id_gen(exit_tx, id_gen)` creates groups that forward exits to a stable broadcast sender on `MeshTransport` with globally unique task IDs across generations
- `MeshLifecycleState` provides a state machine (Stopped/Starting/Running/Stopping/Failed) with validated transitions; `can_start()` allows `Stopped` only (not `Failed`), `can_stop()` allows `Running` only
- **Failed state recovery (Iterations 72, 74)**: `Failed` means incomplete rollback — not safe to restart. `recover_failed_state(timeout)` acquires lifecycle lock, re-runs cleanup, **applies retained `FailedStartupResidue` via `restore_peer_logical_state()` before clearing** (Iteration 74), verifies no owned resources remain, transitions to `Stopped`. Recovery outcomes tracked via `RecoveryReport` (Iteration 74)
- `lifecycle_op: tokio::sync::Mutex<()>` serializes start/stop transitions — no concurrent lifecycle mutations
- Transactional startup via `MeshStartupStage` with rollback on failure — clean rollback returns to `Stopped` (safe to retry), incomplete rollback returns to `Failed` (requires `recover_failed_state()`)
- **Commit ordering (Iteration 71)**: `commit_startup()` transfers task group ownership → transitions lifecycle to `Running` → sets `running_projection` — ensuring the task group is installed before the state is visible. **Hard rejection of non-empty task group (Iteration 73)**: returns `LifecycleConflict` error if old task group is non-empty (checked before `std::mem::replace`).
- `rollback_and_return()` (Iteration 71) centralizes rollback error propagation, constructing `StartupRollbackFailed` when cleanup is incomplete; merges verification issues before lifecycle selection (Iteration 72); `verify_rollback_complete()` checks post-rollback invariants
- **FailedStartupResidue (Iterations 73, 74)**: retained on `MeshTransport` when rollback is incomplete; recovery now applies residue via `restore_peer_logical_state()` before clearing (Iteration 74) — restores topology and DHT entries, closes connections. Partially restored peers retain residue for subsequent attempts.
- **Shared `restore_peer_logical_state()` (Iteration 74)**: used by both `rollback_startup()` and `recover_failed_state()` for deduplicated topology/DHT restoration. Restores topology via `restore_peer_state()` (native `PeerState`) and DHT via `restore_peer()` from `DhtPeerSnapshot`.
- `StagedPeerResource` (Iterations 71–74) tracks exact peer mutations (`session_id`, `node_id`, `topology_existed_before`, `connection_inserted`, `session_task_created`, `dht_registration_created`, `dht_mutation`, `session_generation`) for precise rollback
- **Topology snapshots (Iterations 72, 74)**: `StagedTopologySnapshot` captures native `PeerState` (Iteration 74 — replaces lossy `MeshPeerInfo` + `PeerStatus`); rollback uses `restore_peer_state()` for exact prior state. `get_peer()` captured before `add_peer()` in outbound connection path.
- **Selective peer-session ownership (Iteration 72)**: `HashMap<String, PeerSessionTask>` keyed registry replaces global `JoinSet<()>`; rollback targets only staged sessions
- **DHT mutation tracking (Iterations 72, 74)**: `dht_mutation: DhtPeerMutation` on `StagedPeerResource` derived from pre-mutation snapshot comparison; `DhtPeerMutation` enum simplified (Iteration 74): `None`, `Created`, `Previous(DhtPeerSnapshot)` — captures all contact fields (geo, latency, trust, PoW nonce, public key) for lossless restoration
- **Auxiliary task ownership (Iterations 73, 74)**: preflight tasks tracked in `auxiliary_tasks: HashMap<MeshTaskId, AuxiliaryTask>` during steady-state; `AuxiliaryTaskKind::PreflightRoute` variant. Shutdown aborts and awaits all auxiliary tasks. **Auxiliary task reaper (Iteration 74)**: `spawn_auxiliary_reaper()` runs as critical background task, using `AuxiliaryTaskExit` channel events; handles awaited outside lock; broadcast lag recovery scans for finished handles.
- **Peer-session exit classification (Iteration 73)**: `PeerSessionExitReason` enum (`Clean`, `ConnectionClosed`, `Cancelled`, `Error(String)`, `Panic(String)`, `Aborted`) with generation counter to prevent stale completions. `MeshShutdownReport.failed_peer_sessions` tracks panic/error exits.
- **Session reaper improvements (Iteration 74)**: cancellation-aware via `tokio::select!` with `session_reaper_shutdown` watch signal; handles awaited outside the `peer_sessions` lock; broadcast lag recovery scans for `is_finished()` handles.
- **One global session-generation domain (Iteration 74)**: all sessions (outbound and inbound) use a single `session_generation: Arc<AtomicU64>` on `MeshTransport`, replacing split stage/zero counters for globally unique generations.
- **Abort-and-await pattern (Iteration 73)**: all `.abort()` calls followed by `.await` to reap task resources.
- **Preflight tasks (Iteration 72)**: `preflight_peer_routes` runs as bounded child during startup, tracked in auxiliary registry during steady-state
- **Abort accounting (Iteration 72)**: `tasks_aborted` derived from `MeshTaskExitReason::Aborted` exit metadata, not `active_count()`
- Shared rollback deadline (`startup_rollback_timeout_secs`, default 15s) governs all rollback phases
- `start_with_policy(policy)` is the primary startup API; `start()` is a compatibility wrapper using default policy
- `MeshStartupPolicy` controls required vs optional bootstrap (seed connectivity, configured peers, DHT bootstrap); default is all-optional (degraded startup allowed)
- `MeshStartupReport` communicates bootstrap outcome (degraded reasons, peers connected, DHT status)
- Bounded shutdown with shared deadline — `shutdown_with_timeout(timeout)` derives one deadline for all phases; truthful `MeshShutdownReport` reflects actual state
- **Accept-loop report freshness (Iteration 74)**: `MeshShutdownReport.accept_loop_report` is `Option<MeshAcceptLoopReport>` — stale reports (generation mismatch or no prior startup) are `None` instead of potentially misattributed counts
- `MeshShutdownReport.failed_peer_sessions` (Iteration 73) tracks panic/error session exits
- Peer sessions (`HashMap<String, PeerSessionTask>`, Iteration 72) are owned separately from handshake children; shutdown drains sessions after closing connections
- `mesh_exit_tx: broadcast::Sender<MeshTaskExit>` on `MeshTransport` survives task group replacement; `subscribe_exits()` is synchronous and valid before `start()`
- `running_projection: Arc<AtomicBool>` provides lock-free `is_running()` observation — set on commit, cleared on shutdown entry
- Per-peer children bounded by `max_concurrent_handshakes`
- All periodic loops are cancellation-aware via `watch::Receiver<bool>`
- Worker mesh supervision is staged but **explicitly deferred** (Outcome B from Iteration 70)

See `architecture/mesh_transport_lifecycle.md` for the full task inventory and iteration details.

---

## 3. Major Exported Types

### Transport Layer

| Type | Location | Purpose |
|------|----------|---------|
| `MeshTransport` | `crates/synvoid-mesh/src/mesh/transport.rs:93` | Core QUIC-based transport. Owns peer connections, message dispatch, DHT query dedup, pending snapshots, org managers, and optionally Raft instance. |
| `MeshPeerConnection` | `crates/synvoid-mesh/src/mesh/transport_types.rs` | Per-peer connection state, message handlers, handshake state. |
| `MeshTransportManager` | `crates/synvoid-mesh/src/mesh/transports/manager.rs` | Selection/caching layer wrapping `MeshTransport`. Provides peer selection strategies, connection pooling, health-check routing. |
| `QuicMeshTransport` | `crates/synvoid-mesh/src/mesh/transports/quic.rs` | QUIC-specific transport implementation. |
| `MeshTransportError` | `crates/synvoid-mesh/src/mesh/transport_core/error.rs` | Transport-level errors. |
| `MeshGlobalRateLimiter` | `crates/synvoid-mesh/src/mesh/transport_types.rs` | Global rate limiter for mesh messages. |

### Proxy

| Type | Location | Purpose |
|------|----------|---------|
| `MeshProxy` | `crates/synvoid-mesh/src/mesh/proxy.rs:63` | Request forwarding between mesh peers. Maintains policy cache, provider stats, failed provider cooldown, tiered transform cache. |

### DHT

| Type | Location | Purpose |
|------|----------|---------|
| `RecordStoreManager` | `crates/synvoid-mesh/src/mesh/dht/record_store.rs` | In-memory DHT record storage with rate limiting and access control. |
| `DiskRecordStore` | `crates/synvoid-mesh/src/mesh/dht/record_store_disk.rs` | Persistent DHT storage on disk. |
| `RoutingTable` | `crates/synvoid-mesh/src/mesh/dht/routing/table.rs` | K-bucket routing table for peer contact management. |
| `DhtRoutingManager` | `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs` | Orchestrates DHT queries, bootstrapping, and routing. |
| `DhtConfig` | `crates/synvoid-mesh/src/mesh/dht/mod.rs:161` | DHT configuration (quorum sizes, timeouts, ports, rate limits). |
| `DhtError` | `crates/synvoid-mesh/src/mesh/dht/mod.rs:108` | DHT-level errors (NotFound, StoreError, NetworkError, etc.). |
| `TierKeyStore` | `crates/synvoid-mesh/src/mesh/dht/mod.rs:850` | Tier key storage derived from DHT records. |
| `MerkleTree` | `crates/synvoid-mesh/src/mesh/dht/merkle.rs` | Merkle tree for DHT record proofs. |
| `SignedDhtRecord` | `crates/synvoid-mesh/src/mesh/dht/signed.rs` | Signed DHT record wrapper. |
| `NodeInfo` | `crates/synvoid-mesh/src/mesh/dht/mod.rs:342` | Node information for DHT records. |
| `StakeManager` | `crates/synvoid-mesh/src/mesh/dht/stake.rs` | Node staking and slashing logic. |
| `GlobalNodeBlocklist` | `crates/synvoid-mesh/src/mesh/dht/network_policy.rs` | Global blocklist for misbehaving nodes. |
| `DhtAccessControl` | `crates/synvoid-mesh/src/mesh/dht/mod.rs:689` | Access control checks on DHT operations. |

### Raft

| Type | Location | Purpose |
|------|----------|---------|
| `RaftInstance` | `crates/synvoid-mesh/src/mesh/raft/instance.rs:32` | Lifecycle manager for a Raft node. Owns the `openraft::Raft` instance, state machine, network factory, and shutdown sender. |
| `MeshRaftNetwork` | `crates/synvoid-mesh/src/mesh/raft/network.rs` | Network implementation for Raft (wraps MeshBackendPool). |
| `MeshRaftNetworkFactory` | `crates/synvoid-mesh/src/mesh/raft/network.rs` | Factory for creating per-peer Raft network handlers. |
| `GlobalRegistryStateMachine` | `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` | State machine for global registry (OrgPublicKey, ThreatIntel, Revocation). |
| `GlobalNodeRevocationList` | `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` | Revocation list stored in Raft state machine. |
| `Namespace` | `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` | Namespace enum (Org, Intel, Revocation, AuthorizedGlobalNodes) for state machine keys. |
| `RaftAwareClient` | `crates/synvoid-mesh/src/mesh/raft/client.rs` | Client for performing ConsistentRead RPCs against Raft cluster. |
| `EdgeReplicaManager` | `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs` | Manages edge node replicas of Raft state. |
| `RaftCommitNotification` | `crates/synvoid-mesh/src/mesh/raft/mod.rs:42` | Notification emitted when Raft commits a value. |

### PKI and Organization

| Type | Location | Purpose |
|------|----------|---------|
| `MeshCertManager` | `crates/synvoid-mesh/src/mesh/cert.rs` | TLS certificate management (loading, caching, pinned fingerprints, post-quantum TLS verification). |
| `OrganizationManager` | `crates/synvoid-mesh/src/mesh/organization.rs` | Organization lifecycle (creation, member management, tier claims). |
| `Organization` | `crates/synvoid-mesh/src/mesh/organization.rs` | Organization entity with tier structure. |
| `TierKey` | `crates/synvoid-mesh/src/mesh/organization.rs` | Tiered key for multi-tenant isolation. |
| `TierClaim` | `crates/synvoid-mesh/src/mesh/organization.rs` | Claim of tier membership. |
| `OrgPublicKey` | `crates/synvoid-mesh/src/mesh/organization.rs` | Organization public key record signed by quorum. |
| `MemberCertificate` | `crates/synvoid-mesh/src/mesh/organization.rs` | Member identity certificate within an organization. |
| `OrgKeyManager` | `crates/synvoid-mesh/src/mesh/org_key_manager.rs` | Organization key lifecycle management. |

### Post-Quantum Cryptography

| Type | Location | Purpose |
|------|----------|---------|
| `HybridSignature` | `crates/synvoid-mesh/src/mesh/hybrid_signature.rs:17` | Combined Ed25519 + ML-DSA-44 signature. Contains both signature components and public keys. |
| `HybridSigner` | `crates/synvoid-mesh/src/mesh/hybrid_signature.rs` (reexport from `crate::integrity`) | Signs data with both Ed25519 and ML-DSA. |
| `MeshMlDsaSigner` | `crates/synvoid-mesh/src/mesh/ml_dsa.rs:18` | ML-DSA-44 signing wrapper with key generation, signing, verification. |
| `MeshMlDsaVerifier` | `crates/synvoid-mesh/src/mesh/ml_dsa.rs:97` | ML-DSA-44 verification wrapper. |
| `MlKem768` | `crates/synvoid-mesh/src/mesh/kem/ml_kem.rs` | ML-KEM-768 key encapsulation. |
| `MlKem768PublicKey` / `MlKem768SecretKey` | `crates/synvoid-mesh/src/mesh/kem/ml_kem.rs` | Key types for ML-KEM-768. |
| `MlKem768SharedSecret` | `crates/synvoid-mesh/src/mesh/kem/ml_kem.rs` | Shared secret from ML-KEM-768 encapsulation. |
| `KemSession` | `crates/synvoid-mesh/src/mesh/kem/kem_trait.rs` | Session abstraction for key encapsulation with rotation support. |
| `MlKemKeyExchangeService` | `crates/synvoid-mesh/src/mesh/ml_kem_key_exchange.rs:35` | gRPC service for ML-KEM key exchange with proof-of-possession. |
| `KeyExchangeService` | `crates/synvoid-mesh/src/mesh/passover_key_exchange.rs` | PASEO key exchange (alternate KEM). |
| `MeshMessageSigner` | `crates/synvoid-mesh/src/mesh/protocol.rs:33` | Signs mesh messages with Ed25519, optionally producing hybrid signatures via ML-DSA signer. |
| `MeshHybridSigner` | `crates/synvoid-mesh/src/mesh/ml_dsa.rs` | Trait/object for hybrid signing operations. |

### Security and Intelligence

| Type | Location | Purpose |
|------|----------|---------|
| `SecureConfigManager` | `crates/synvoid-mesh/src/mesh/security.rs` | AES-256-GCM encrypted config value storage. |
| `MeshSecurityChallengeManager` | `crates/synvoid-mesh/src/mesh/security_challenge.rs` | Challenge-response attack detection. |
| `MeshAttackDetector` | `crates/synvoid-mesh/src/mesh/security_challenge.rs` | Pattern-based attack detection. |
| `ThreatIntelligenceManager` | `crates/synvoid-mesh/src/mesh/threat_intel.rs` | Threat indicator distribution, caching, and policy-composed read staging. |
| `ReputationManager` | `crates/synvoid-mesh/src/mesh/reputation.rs` | Peer reputation scoring and event tracking. |
| `BehavioralFingerprint` | `crates/synvoid-mesh/src/mesh/behavioral.rs` | Per-peer behavioral fingerprint. |
| `BehavioralIntelligenceManager` | `crates/synvoid-mesh/src/mesh/behavioral_intel.rs` | Behavioral intelligence coordination. |
| `CryptoVerificationPool` | `crates/synvoid-mesh/src/mesh/crypto_verification.rs` | Thread pool for concurrent signature verification. |
| `VerificationTaskManager` | `crates/synvoid-mesh/src/mesh/verification.rs` | Verification task scheduling. |
| `GlobalNodeRevocationList` | `crates/synvoid-mesh/src/mesh/peer_auth.rs` | Node revocation list for peer authentication. |

### Topology

| Type | Location | Purpose |
|------|----------|---------|
| `MeshTopology` | `crates/synvoid-mesh/src/mesh/topology.rs:28` | Network topology state: peer store, routing cache, verified upstream cache, blocked upstreams, degraded mode tracking. |
| `MeshBloomFilter` | `crates/synvoid-mesh/src/mesh/hierarchical_routing.rs` | Bloom filter for efficient route advertisement. |
| `HierarchicalRoutingManager` | `crates/synvoid-mesh/src/mesh/hierarchical_routing.rs` | Geo-distributed routing with regional hub info. |

### Other Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `MeshConfig` | `crates/synvoid-mesh/src/mesh/config.rs` | Root mesh configuration (node role, DHT, transport, global node keys). |
| `MeshNodeRole` | `crates/synvoid-mesh/src/mesh/config.rs` | Bitmask struct (u8): GLOBAL (0b010), EDGE (0b001), ORIGIN (0b100), GLOBAL_EDGE (0b011), GLOBAL_ORIGIN (0b110), EDGE_ORIGIN (0b101), ALL (0b111), SERVERLESS_ORIGIN (0b1000). |
| `MeshArgs` / `MeshCommand` | `crates/synvoid-mesh/src/mesh/cli.rs` | CLI argument parsing. |
| `AuditLogger` | `crates/synvoid-mesh/src/mesh/audit.rs` | Audit event logging. |
| `AuditSession` | `crates/synvoid-mesh/src/mesh/audit_session.rs` | Session-scoped audit context. |
| `SessionManager<T>` | `crates/synvoid-mesh/src/mesh/session/manager.rs` | Generic session manager for KEM key rotation. |
| `WasmDistManager` | `crates/synvoid-mesh/src/mesh/wasm_dist.rs` | WASM module distribution. |
| `YaraRulesManager` | `crates/synvoid-mesh/src/mesh/yara_rules.rs` | YARA rule distribution. |

---

## 4. DHT and Raft Integration

### Dataflow

DHT and Raft serve distinct roles but share infrastructure:

1. **DHT (Kademlia)** is responsible for **eventual consistency** across the broader mesh network. All nodes participate in the DHT for storing and retrieving records (routing policies, provider info, DNS records). DHT uses a routing table with k-buckets and parallel queries to locate records across the network. DHT records are soft-state: advisory, TTL-bound, and never a source of canonical authority. Authority-adjacent DHT records (e.g., org keys, verified upstreams) require a signed Raft attestation or quorum proof for acceptance.

2. **Raft** is responsible for **strong consistency** within the Global Node tier only. Global nodes form a Raft cluster to commit canonical authority records: `Namespace::Org` (OrgPublicKey), `Namespace::Intel` (ThreatIntel), and `Namespace::Revocation` (GlobalNodeRevocationList). Raft is the only source of canonical global trust state — it decides ownership, trust, and revocation. Raft provides linearizable reads via ConsistentRead RPC. Edge nodes cache and gossip Raft-derived artifacts but independently verify them against the Raft state machine.

### Integration Points

| Integration Point | File | Details |
|------------------|------|---------|
| `MeshTransport.raft_instance` field | `crates/synvoid-mesh/src/mesh/transport.rs:159` | `MeshTransport` holds `Arc<RwLock<Option<Arc<RaftInstance>>>>`. The transport coordinates with Raft for committed-value hooks. |
| `RaftAwareClient` | `crates/synvoid-mesh/src/mesh/raft/client.rs` | Edge/Origin nodes use this client to perform ConsistentRead RPCs against the Raft cluster instead of DHT for strongly-consistent reads. |
| `EdgeReplicaManager` | `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs` | Edge nodes cache Raft state machine snapshots locally to serve consistent reads without querying the Raft cluster. |
| Raft commit hooks | `crates/synvoid-mesh/src/mesh/raft/instance.rs` | `RaftInstance` integrates with `MeshProxy` to publish committed values to the DHT and propagate to peers. |
| `ConsistentReadResult` | `crates/synvoid-mesh/src/mesh/raft/client.rs` | Result type carrying data plus `RaftCommitNotification` metadata. |
| `GlobalNodeRevocationList` | both | Stored in Raft state machine AND distributed via DHT for fast revocation checks. |

### Quorum in DHT vs Raft

- **DHT quorum** (`DhtConfig.write_quorum` / `read_quorum`) is the number of DHT peers that must acknowledge a read/write before it is considered complete. The `QuorumVerifierContext` in `crates/synvoid-mesh/src/mesh/dht/signed.rs:12` provides context for threshold signature verification of DHT records.

- **Raft quorum** is handled by the `openraft` library internally (majority of cluster nodes). Raft commits are persisted to the state machine, which then publishes to DHT.

### Record Signing Pipeline

Records in DHT follow this signing flow:
1. `RecordSigner` (from `crates/synvoid-mesh/src/mesh/dht/signed.rs`) signs records with the node's Ed25519 key.
2. Global nodes additionally sign with ML-DSA (`MeshMlDsaSigner`) for post-quantum hybrid signatures.
3. `TtlManager` handles TTL enforcement on signed records.
4. Quorum verification (for org-level records) routes to either DHT quorum verification or Raft consistent read depending on record namespace.

---

## 5. Post-Quantum Cryptography Components

### HybridSignature (`crates/synvoid-mesh/src/mesh/hybrid_signature.rs`)

Provides dual signatures combining classical Ed25519 with post-quantum ML-DSA-44:

```rust
pub struct HybridSignature {
    pub ed25519_signature: Vec<u8>,      // 64 bytes
    pub ml_dsa_signature: Vec<u8>,       // 2420 bytes (ML-DSA-44)
    pub ed25519_public_key: String,
    pub ml_dsa_public_key: Option<String>,
}
```

- `serialized_size()` computes total wire size including length prefixes.
- `to_bytes()` / `from_bytes()` for stable wire format (postcard-compatible length prefixes).
- `has_ml_dsa()` indicates whether the post-quantum component is present.
- `ED25519_SIGNATURE_SIZE = 64`, `ML_DSA_SIGNATURE_SIZE = 2420`.

### MeshMessageSigner (`crates/synvoid-mesh/src/mesh/protocol.rs:33`)

Signs mesh messages. Optionally wraps an `MlDsaSigner`:

```rust
pub struct MeshMessageSigner {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key_bytes: Vec<u8>,
    ml_dsa_signer: Option<Arc<MeshMlDsaSigner>>,
    verification_pool: Option<Arc<CryptoVerificationPool>>,
}
```

- `sign()` produces a pure Ed25519 signature if no ML-DSA signer is configured; otherwise calls `sign_hybrid()` which produces a `HybridSignature`.
- `sign_hybrid()` creates a `HybridSignature` with both components.

### MeshMlDsaSigner (`crates/synvoid-mesh/src/mesh/ml_dsa.rs:18`)

Wrapper around `pqc::MlDsa44` with key generation, signing, and verification:

- `new(signing_key)` / `from_config(config)` / `generate()` constructors.
- `sign(message)` -> `Option<Vec<u8>>` using ML-DSA-44.
- `verify(message, signature)` -> `bool` for verification.
- `verifying_key_base64()` / `signing_key_base64()` for serialization.
- Exposes `MlDsaSigningKeyType = SigningKey` and `MlDsaVerifyingKeyType = VerifyingKey`.

### MeshMlDsaVerifier (`crates/synvoid-mesh/src/mesh/ml_dsa.rs:97`)

Verification-side counterpart using `pqc::MlDsa44`.

### ML-KEM-768 (`crates/synvoid-mesh/src/mesh/kem/`)

Abstraction over post-quantum key encapsulation:

| Type | File | Purpose |
|------|------|---------|
| `MlKem768` | `crates/synvoid-mesh/src/mesh/kem/ml_kem.rs` | Key generation, encapsulation, decapsulation. |
| `MlKem768PublicKey` | `crates/synvoid-mesh/src/mesh/kem/ml_kem.rs` | Public key type. |
| `MlKem768SecretKey` | `crates/synvoid-mesh/src/mesh/kem/ml_kem.rs` | Secret key type (zeroize-on-drop). |
| `MlKem768SharedSecret` | `crates/synvoid-mesh/src/mesh/kem/ml_kem.rs` | Shared secret output. |
| `KemSession` | `crates/synvoid-mesh/src/mesh/kem/kem_trait.rs` | Session abstraction with rotation and expiry. |
| `KemError` | `crates/synvoid-mesh/src/mesh/kem/kem_trait.rs` | KEM-level errors. |

### MlKemKeyExchangeService (`crates/synvoid-mesh/src/mesh/ml_kem_key_exchange.rs:35`)

gRPC service implementing ML-KEM key exchange with proof-of-possession:

- `generate_node_keypair()` generates a node keypair.
- `get_public_key()` / `get_public_key_base64()` expose the public key.
- `get_key_health()` reports stale/expired session counts.
- Implements `MlKemKeyExchangeService` gRPC service with `KeyOffer`, `KeyRequest`, `KeyConfirm`, and `KeyConfirmResponse` messages.
- BUG-L3 fix (key exchange proof-of-possession) ensures the client can decapsulate the returned ciphertext.

### Session Manager (`crates/synvoid-mesh/src/mesh/session/`)

```rust
pub struct SessionManager<T: Kem> {
    // Manages sessions for a specific KEM algorithm with:
    // - Automatic rotation based on config (key_max_age_secs)
    // - Session expiry checking (is_expired, should_rotate)
    // - Thread-safe storage via Arc+RwLock
}
```

Used by `MlKemKeyExchangeService` to track in-flight key exchange sessions.

---

## 6. Feature Gates

The mesh module is controlled by Cargo feature flags in `Cargo.toml`:

```toml
[features]
# Default features (enabled unless overridden)
default = ["socket-handoff", "mesh", "dns", "erased_pool", "swagger-ui"]

# Core mesh networking (REQUIRED for any mesh functionality)
mesh = ["synvoid-config/mesh", "dep:openraft"]

# DNS subsystem (enables DNS transport, DNSSEC, TSIG)
dns = ["synvoid-config/dns", "dep:hickory-proto", "dep:hickory-resolver", ...]

# Post-quantum TLS verification (verifies PQ capability at startup)
verify-pq = []

# WireGuard tunnel support
wireguard = ["dep:defguard_boringtun"]

# Post-quantum mesh message signatures (enables ML-DSA-44 for mesh messages)
pqc-mesh = []

# Post-quantum TLS (enables rustls-post-quantum provider)
post-quantum = ["dep:rustls-post-quantum"]
```

### Feature-Gated Submodules

Submodules gated on features are conditionally compiled:

| Submodule | Feature Gate | Purpose |
|----------|-------------|---------|
| `transport_connection` | `mesh` | Per-connection QUIC handling |
| `transport_dht` | `mesh` | DHT transport integration |
| `transport_dns` | `mesh + dns` | DNS over mesh transport |
| `transport_global` | `mesh` | Global node transport |
| `transport_org` | `mesh` | Organization transport |
| `transport_peer` | `mesh` | Peer-to-peer transport |
| `transport_rate_limit` | `mesh` | Rate limiting for transport |
| `transport_routing` | `mesh` | Routing-aware transport |
| `transport_serverless` | `mesh` | Serverless function invocation transport |
| `topology/types` | none | Topology types (always compiled) |
| `transports/mod` | none | Transport abstraction (always compiled) |
| `transport_core` | none | Transport error/time (always compiled) |

> **Note**: The `mesh` feature is part of `default`, so most mesh submodules are compiled by default. The `dns` feature is also in `default`. Disabling both with `--no-default-features --features ""` would leave only the core transport types and no transport implementations.

### Feature Gates for Post-Quantum

| Feature | Effect |
|---------|--------|
| `pqc-mesh` | Enables ML-DSA-44 signing for mesh messages (`MeshMlDsaSigner` usage in `MeshMessageSigner`). |
| `post-quantum` | Enables `rustls-post-quantum` TLS provider. |
| `verify-pq` | Runs post-quantum TLS verification at startup (`verify_post_quantum_tls()` in `cert.rs`). |
| `mesh` | Enables `openraft` dependency for Raft consensus. |

---

## 7. Key Architectural Patterns

### Global Record Store Pattern

`MeshTransport` and `MeshProxy` share the `RecordStoreManager` via `Arc`. The global record store is a lazy static:

```rust
static RECORD_STORE_GLOBAL: LazyLock<RwLock<Option<Arc<RecordStoreManager>>>> = ...;

pub fn set_global_record_store(store: Arc<RecordStoreManager>) { ... }
pub fn get_global_record_store() -> Option<Arc<RecordStoreManager>> { ... }
```

### Transport Initialization Chain

`create_mesh_backend_from_config()` and `initialize_mesh_transports()` (both in `backend.rs`) coordinate the initialization order:

1. Create `MeshTransportManager` (QUIC transport pool).
2. Create `MeshProxy`.
3. Create `MeshTopology`.
4. Create `MeshTransport` with all dependencies.
5. Optionally create Raft instance via `RaftInstance::new()`.
6. Wire transport into proxy and topology.

### DHT + Raft Chaining

When a value is committed through Raft:
1. `RaftInstance` gets a commit notification.
2. Value is written to `GlobalRegistryStateMachine`.
3. Committed value is published to the DHT via `MeshTransport` for broader distribution.
4. `MeshProxy` receives the update and propagates to peers.
5. Edge nodes cache Raft-derived artifacts (via `EdgeReplicaManager`) and independently verify them.

When a value is written via DHT (for non-Raft namespaces):
1. `MeshTransport` writes to `RecordStoreManager`.
2. `TtlManager` tracks expiry.
3. Quorum verification confirms sufficient DHT peer acknowledgments.
4. Value is usable by all mesh peers, but remains soft-state (advisory and TTL-bound).

Remote DHT writes require explicit ingress validation (node-ID binding, message signatures, envelope verification). `DhtAntiEntropyRequest` and `DhtRecordPush` are fully signed/bound at the transport layer. Raw `store_record()` is `pub(crate)`; remote paths use `store_record_from_ingress()` which enforces key-policy and proof requirements.

### Constant-Time Comparison

Per [`AGENTS.md`](../../AGENTS.md), constant-time comparison using `subtle::ConstantTimeEq` is used for:
- Secret keys, MACs, auth tokens, passwords
- NOT for puzzle verification (`security_challenge.rs:196` uses simple `!=`) as the challenge data is publicly known

### Binary Serialization

For DHT records and Raft state machine values, Postcard is preferred over JSON:
- `#[derive(Archive, RkyvSerialize, RkyvDeserialize)]` on key structs
- `Serialize`, `Deserialize` from `serde` for JSON paths
- Binary signatures operate on `&[u8]` via `MeshMessageSigner::sign/verify`

### Unix Timestamps

All persisted and network timestamps use `u64` Unix epoch via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`. Duration arithmetic uses `.saturating_sub()`.

---

## 8. Concurrency Model

| Component | Concurrency | Notes |
|-----------|-------------|-------|
| `MeshTransport` | `Arc<RwLock<...>>` for most fields | Allows concurrent read-access to config/cert_manager/org_manager |
| `MeshTopology` | `tokio::sync::RwLock` + `moka::future::Cache` | Async-friendly with ShardedPeerStore |
| `MeshProxy` | `Arc<RwLock<Option<Arc<MeshTransport>>>>` | Write-locked during transport swap |
| `MeshCertManager` | `Arc<RwLock<MeshCertManager>>` | Certificate cache guarded by parking_lot::RwLock |
| `RecordStoreManager` | `Arc<RwLock<...>>` | Access via global static |
| `SessionManager<MlKem768>` | `Arc<SessionManager<MlKem768>>` | Thread-safe via interior mutability |
| DHT routing table | `Arc<DashMap<...>>` | Concurrent k-bucket access |
| Raft `MeshRaftNetwork` | `Arc<MeshBackendPool>` | Network factory is cloneable |

The single-threaded I/O model for QUIC is handled by `QuicRuntime` from `crate::tunnel::quic::runtime`.

---

## 9. Dependencies Summary

Key external dependencies in the mesh module:

| Dependency | Version | Purpose |
|------------|---------|---------|
| `openraft` | via `synvoid-config/mesh` | Raft consensus implementation |
| `quinn` | (via tunnel) | QUIC transport |
| `rustls` + `rustls-native-certs` | TLS/certificates | TLS 1.3+ with post-quantum groups |
| `ed25519-dalek` | Signature schemes | Ed25519 signing/verification |
| `pqc` (local crate) | Post-quantum crypto | ML-DSA-44, ML-KEM-768 |
| `dashmap` | ConcurrentMaps | Sharded concurrent hash maps |
| `moka` | Caches | Async-aware LRU caches |
| `lru_time_cache` | TTL caches | Time-expiring LRU entries |
| `rkyv` | Zero-copy serialization | High-performance archive/deserialize |
| `prost` | Protobuf | gRPC message encoding |

---

## 10. File Listing

For reference, here is the complete file tree of `crates/synvoid-mesh/src/mesh/` (excluding test files):

```
crates/synvoid-mesh/src/mesh/
├── mod.rs
├── transport.rs                        (3834 lines - core transport)
├── transports/
│   ├── mod.rs
│   ├── manager.rs
│   ├── quic.rs
│   └── stack.rs
├── transport_types.rs
├── transport_core/
│   ├── mod.rs
│   ├── error.rs
│   └── time.rs
├── proxy.rs                           (1996 lines - mesh proxy)
├── topology.rs                        (1807 lines - network topology)
├── protocol.rs                        (2110 lines - messages, signing)
├── config.rs
├── config_mesh.rs
├── config_defaults.rs
├── config_identity.rs
├── config_conversion.rs
├── backend.rs                        (492 lines - initialization)
├── session/
│   ├── mod.rs
│   └── manager.rs
├── dht/
│   ├── mod.rs                        (937 lines - DHT root)
│   ├── keys.rs
│   ├── merkle.rs
│   ├── record_store.rs
│   ├── record_store_disk.rs
│   ├── record_store_sync.rs
│   ├── record_store_message.rs
│   ├── record_store_crud.rs
│   ├── record_store_dns.rs
│   ├── store.rs
│   ├── routing/
│   │   ├── mod.rs
│   │   ├── table.rs
│   │   ├── bucket.rs
│   │   ├── node_id.rs
│   │   ├── contact.rs
│   │   ├── query.rs
│   │   ├── manager.rs
│   │   ├── geo_distance.rs
│   │   └── regional_hubs.rs
│   ├── quorum.rs
│   ├── signed.rs
│   ├── stake.rs
│   ├── record_store_persist.rs
│   ├── capability_attestation.rs
│   ├── capability_access.rs
│   ├── edge_attestation.rs
│   └── network_policy.rs
├── raft/
│   ├── mod.rs                        (65 lines - Raft root)
│   ├── instance.rs
│   ├── network.rs
│   ├── state_machine.rs
│   ├── edge_replica.rs
│   ├── client.rs
│   └── regression_tests.rs
├── organization.rs                    (1594 lines - org management)
├── cert.rs                           (1280 lines - cert manager)
├── security.rs                       (474 lines - secure config)
├── threat_intel.rs
├── reputation.rs
├── behavioral.rs
├── behavioral_intel.rs
├── audit.rs
├── audit_session.rs
├── client_audit.rs
├── yara_rules.rs
├── wasm_dist.rs
├── hybrid_signature.rs               (251 lines - hybrid sig)
├── ml_dsa.rs                         (290 lines - ML-DSA)
├── ml_kem_key_exchange.rs            (265 lines - KEM exchange)
├── kem/
│   ├── mod.rs                        (10 lines - KEM root)
│   ├── ml_kem.rs
│   └── kem_trait.rs
├── tier_key_encryption.rs
├── network_security.rs
├── security_challenge.rs
├── verification.rs
├── crypto_verification.rs
├── peer_auth.rs
├── org_key_manager.rs
├── passover_key_exchange.rs
├── hierarchical_routing.rs
├── discovery.rs
├── rate_limit.rs
├── cli.rs
├── proto/                          # Protocol definitions (mesh.proto)
├── transport_connection.rs            [mesh]
├── transport_dht.rs                  [mesh]
├── transport_dns.rs                  [mesh+dns]
├── transport_global.rs               [mesh]
├── transport_org.rs                  [mesh]
├── transport_peer.rs                 [mesh]
├── transport_rate_limit.rs           [mesh]
├── transport_routing.rs              [mesh]
├── transport_serverless.rs          [mesh]
├── protocol_types.rs
├── protocol_message.rs
├── protocol_proto_encode.rs
└── protocol_proto_decode.rs
```

---

## 11. Relationship to Other Modules

| Module | Relationship |
|--------|-------------|
| `src/proxy/` | `MeshProxy` wraps `MeshTransport` and uses it to forward requests between peers. The proxy's `BackendType` enum includes `Mesh` variant for mesh-based routing. |
| `src/dns/` | The `dns` feature enables `MeshDnsRegistry` and `transport_dns.rs` for DNS over mesh. DHT stores DNS records. `DnsConfig.validate()` is called from `MainConfig::validate()`. |
| `src/config/` | `MeshConfig` lives here; `ConfigManager` in `crates/synvoid-config/src/lib.rs`. |
| `src/supervisor/` | Supervisor manages `UnifiedServerWorker` which uses mesh transport for inter-node communication. |
| `src/platform/` | Platform layer provides sandboxing, TUN device, and OS-level primitives used by mesh transport. |
| `src/plugin/` | WASM plugins are distributed via `WasmDistManager`. |
| `src/serverless/` | Serverless function invocation goes over mesh via `transport_serverless.rs`. |
| `src/tunnel/` | QUIC runtime (`crate::tunnel::quic::runtime`) is used by `MeshTransport` for actual I/O. |
| `src/wasm_pow/` | WASM-based proof-of-work used for edge node PoW requirements. |
| `crates/synvoid-config/` | Provides `MeshConfig` types, feature-gated `mesh` and `dns` features. |
