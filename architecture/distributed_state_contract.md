# Distributed State Consistency and Partition-Semantics Contract

**Status**: Phase 23 authoritative contract. This document is the single binding matrix for authority, consistency, versioning, TTL/expiry, conflict, partition-read/write, and enforcement semantics of every security-relevant replicated namespace.

**Non-goals**: This phase does not replace the mesh architecture, does not introduce a second consensus protocol, does not weaken canonical trust for availability, and does not broaden request-path capabilities.

**Authority rule (binding)**:
- DHT answers "what has been advertised?" Raft/canonical state answers "what is trusted?" Policy answers "what may be acted on?" Transport answers "how do peers communicate?"
- Services consume policy outputs, not raw advisory records, for security decisions.
- DHT/advisory state must never become implicit fallback authority for canonical records during partition.
- Source: `architecture/mesh_trust_domains.md` (trust-domain invariants), `crates/synvoid-mesh/src/mesh/canonical.rs` (`CanonicalTrustReader`), `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` (policy composition).

Other documents (`architecture/mesh_deep_dive.md`, `architecture/mesh_trust_domains.md`, blocklist convergence docs, `docs/THREAT_INTEL.md`, `architecture/admin_control_plane_authority.md`, `architecture/layer_3_5_deep_dive.md`, `architecture/runtime_operations_drill.md`, release/final-surface residual-risk sections) link here instead of redefining consistency semantics independently.

---

## 1. Authority taxonomy (binding)

Every namespace below is exactly one of:

| Authority | Meaning | Examples |
|-----------|---------|----------|
| `local-authoritative` | Local node owns state; replication is informational/best-effort. Remote copies must not overwrite local authority unless the contract explicitly grants that power. | BlockStore IP/mesh blocks, peer cursors, reputation scores, rate-limiter windows, sessions, topology, proxy policy cache, `SecureConfigManager`, local cert manager, org private keys, challenge/PoW state |
| `advisory-distributed` | Remote data may inform policy but cannot directly establish canonical trust. Enforcement use is gated by local policy/provenance. | Threat-indicator DHT records, YARA/WASM manifests and chunks, behavioral fingerprints, node telemetry, upstream/DNS/provider caches, capability attestations, blocklist gossip observations |
| `canonical-consensus-backed` | Only committed canonical state is authoritative. Reads may use last committed state per an explicit freshness policy; writes without quorum fail typed/fail-closed. | Raft `Namespace::{Org, Intel, Revocation, AuthorizedGlobalNodes}` |
| `derived-cache` | May be reconstructed only from an authoritative source; carries freshness/version metadata; never an independent authority during partition. | `EdgeReplicaManager` tables, `CanonicalTrustSnapshot` (IPC), `RaftCommitNotification` (`raft_commit:*` DHT keys), DHT `RaftOrQuorumGlobal` / `RaftAttestedGlobal` records (require attestation or quorum proof) |

Code-level authority markers:
- `DistributedNamespaceAuthority` in `crates/synvoid-mesh/src/mesh/canonical.rs` — the code equivalent of this taxonomy (`LocalAuthoritative`, `AdvisoryDistributed`, `CanonicalConsensusBacked`, `DerivedCacheMaterialization`).
- `DhtRecordAuthorityClass` in `crates/synvoid-mesh/src/mesh/dht/key_policy.rs` — per-key DHT admission class (`RaftOrQuorumGlobal`, `RaftAttestedGlobal`, `CapabilityAttested`, `SignedByRecordOwner`, `SoftLocal`, `LocalOnly`, `QuorumSignedGlobal`).
- `ThreatIntelConsumerKind` / `ThreatIntelConsumerAction` in `crates/synvoid-mesh/src/mesh/threat_intel.rs` — enforcement gating (`Enforcement` requires `PermitAction`).
- `BlockProvenanceKind` in `crates/synvoid-core/src/block_store.rs` — block-write provenance (`MeshThreatIntelPolicyGated` for mesh enforcement; `LegacyUnknown` only for compat/tests/mocks).
- `AdminMutationAuthority` in `crates/synvoid-core/src/admin_mutation.rs` — mutation attribution.

If a future namespace does not fit, define a precise additional category rather than allowing ambiguous mixed authority.

---

## 2. Raft canonical behavior (reconciled with code)

Implementation: `openraft 0.10.0-alpha.18` in `crates/synvoid-mesh/src/mesh/raft/` (`instance.rs`, `network.rs`, `state_machine.rs`, `client.rs`, `edge_replica.rs`). Evidence below was verified against code and regression tests (`regression_tests.rs`).

| Question | Behavior | Evidence |
|----------|----------|----------|
| Leader/election | Standard openraft leader election over `MeshMessage::Raft` transport. No custom quorum logic. | `raft/instance.rs:61-68` (`Raft::new`), `211-213` (`is_leader`), `251-274` (`current_leader`, `wait_for_leader`); `raft/network.rs:106-267` (`RaftNetworkV2`) |
| Quorum definition / membership | Standard openraft majority (N/2+1), not a hardcoded 2/3. Membership source is the Raft log itself (committed membership entries, persisted in SQLite `snapshot_metadata.last_membership`). `change_membership` requires leader. | `raft/instance.rs:170-184`, `raft/state_machine.rs:526-532,557-560` |
| Commit index / term | Persisted per entry (`id, term, payload`); `get_log_state` returns `last_log_id` + `last_purged_log_id`; `apply` advances `last_applied_log_id`; `client_write` returns `log_id.index`. | `raft/state_machine.rs:759-771,1074-1092,1204`; `raft/instance.rs:144-146` |
| Read without quorum | Consistent reads are linearizable via `ReadPolicy::ReadIndex` on the leader. Non-leader Global nodes return `NotLeader`; edge/origin clients follow `NotLeader` hints; if all Global nodes unreachable, `RaftUnreachable`. `stale_read_cache` (DHT) is explicitly labeled stale and is never a canonical answer. Edge nodes may serve their local `EdgeReplicaManager` snapshot per the freshness policy below — classified as snapshot/stale, never as live canonical. | `raft/instance.rs:195-205`; `raft/client.rs:492-605,607-627`; `raft/edge_replica.rs:480-527` |
| Write without quorum | Writes require a functioning leader with quorum. Global-local writes require `is_leader`; remote writes find the leader and propose with a 5s timeout. Without quorum: typed failure (`QuorumUnavailable` / `RaftUnreachable` / `NotLeader` / `Timeout`). No degraded-mode canonical write path exists. Callers must not report success or queued canonical commit. | `raft/client.rs:247-339`; `mesh/canonical.rs` (`CanonicalWriteOutcome::QuorumUnavailable`); `synvoid_core::admin_mutation::PropagationStatus::QuorumUnavailable` |
| Membership / node loss | `add_learner` / `change_membership` delegate to openraft; legacy `add_node` / `remove_node` are deprecated errors. Node loss follows standard Raft semantics: majority partition elects a new leader; minority partition becomes unavailable (fail-closed for writes). Observer/learner nodes replicate without voting. | `raft/instance.rs:100-138,170-184`; skill `raft_consensus` (observer nodes) |
| DHT canonical namespaces derived? | Canonical truth lives in the Raft state machine + `EdgeReplicaManager` replicas, read via `CanonicalTrustReader`. Raft commits broadcast a `raft_commit:<namespace>:<key>` **notification** (metadata), not an independent copy of canonical data. DHT keys in `RaftOrQuorumGlobal` / `RaftAttestedGlobal` namespaces require Raft attestation or quorum proof at ingress (`DhtKeyPolicyTable`, `DhtIngressPolicyContext`); they do not become independent authority during partition. Threat-indicator DHT records are `CapabilityAttested` (any holder of the capability may advertise); canonical threat trust comes only from `Namespace::Intel` via policy composition. | `mesh/org_key_manager.rs:300-341`; `mesh/dht/key_policy.rs:90-146`; `mesh/canonical.rs:569-655`; `mesh/raft/edge_replica.rs:480-527`; `mesh/dht/ingress_policy.rs` |

### MESH-15 reconciliation (CLOSED as stale, replaced)

Original MESH-15 text (in `architecture/layer_3_5_deep_dive.md` and `architecture/mesh_deep_dive.md:40`) described "a purely DHT-based system without a consensus leader" requiring manual "2/3 Quorum" signatures, warning that "1/3 of global nodes offline" deadlocks onboarding/key rotation.

**Verdict**: MESH-15 as worded is **stale and CLOSED**. The system has had openraft consensus since Waves 6–11; there is a consensus leader; quorum is N/2+1 majority, not manual 2/3 signing. The stale wording must not be repeated as a current vulnerability.

**Precise current limitation (replaces MESH-15)**: during a network partition where the Global cluster loses Raft majority, canonical writes (org onboarding, key rotation, revocation, canonical threat commits, membership changes) become **unavailable** (typed `QuorumUnavailable`, fail-closed). This is standard Raft unavailability, not a deadlock bug and not a DHT fallback opportunity. Edge nodes continue serving data-plane traffic from last committed snapshots within the freshness policy (`Fresh` → delegate; `StaleWithinGrace` → per `stale_mode`; `Expired`/`Invalid`/`Missing` → defer/deny). Operational response: ensure Global-node deployment topology preserves majority (odd cluster size, independent failure domains); treat `QuorumUnavailable` as a capacity/partition signal, not as permission to accept unsigned/advisory/DHT writes as canonical; on heal, committed state converges via Raft log + snapshot, and `EdgeReplicaManager` refreshes from notifications (stale divergent writes are never accepted).

---

## 3. Binding namespace matrix

Conventions used below:
- **Version/order key**: preferred explicit metadata. Raft `(term, index)` for canonical; source identity + monotonic sequence for source-scoped streams; content/version digest for immutable records. Wall-clock timestamps are never the conflict arbiter for trust/revocation; they are used only for TTL/freshness with skew bounds.
- **TTL/expiry**: who sets it, max accepted, replication behavior, skew bounds, cleanup, and unblock/revocation interaction.
- **Partition read/write**: exact behavior during partition. Canonical writes without quorum → typed `QuorumUnavailable` (never success). Advisory/local may proceed per policy; propagation is best-effort.
- **Enforcement effect**: whether the namespace can directly mutate enforcement, and through which gate.

### 3a. Canonical consensus-backed (Raft log → SQLite state machine)

| Namespace | Authority | Transport / replica | Consistency | Version / order key | TTL / expiry | Conflict rule | Partition read | Partition write | Enforcement effect |
|-----------|-----------|---------------------|-------------|---------------------|--------------|---------------|----------------|-----------------|--------------------|
| `Namespace::Org` (`OrgPublicKey`, `org_id:key_id`) | canonical-consensus-backed | Raft log → `GlobalRegistryStateMachine` SQLite; derived replicas only | Linearizable (leader `ReadIndex`); committed log order | Raft `(term, index)`; `key_id` UUID primary key; `ClientProposalPayload{nonce, timestamp, protocol_version=1}` + `ReplayProtectionCache(source_node_id, nonce)` dedup | No expiry; explicit `Delete` only. DHT material derived from commits carries its own TTL (30d signed) but is not authority. | Last committed log entry wins (`INSERT OR REPLACE`); replayed/non-committed mutations never masquerade as canonical | Last committed state only, per freshness policy; stale beyond grace is classified (`StaleWithinGrace`/`Expired`) and observable, never silently trusted for new trust decisions | Without quorum: `QuorumUnavailable` (fail-closed). Caller must not report success or queued canonical commit. | None directly. Trust answers flow via `CanonicalTrustReader.is_org_key_trusted`; enforcement via policy gates only |
| `Namespace::Intel` (canonical `ThreatIntel`, `indicator_id`) | canonical-consensus-backed | Raft log → SQLite; edge replicas; IPC snapshots to workers | Linearizable commits; edge/replica reads are snapshot-classified | Raft `(term, index)`; `indicator_id` key; `expires_at: Option<u64>` for record TTL | `expires_at` set by committer; expired records are `NotActionable` and never resurrect after rejoin (policy checks expiry before actionability; `handle_incoming_threat` checks TTL before policy gate). Clock skew bounded via `safe_unix_timestamp` + saturating math; future-dated immortality is rejected (60s future-skew tolerance on snapshots; 300s record-timestamp window on DHT ingress). | Committed log order; `INSERT OR REPLACE` by `indicator_id` | Last committed snapshot per freshness policy; `CanonicalUnavailable`/`CanonicalUnknown` → `Deferred`, never `Actionable` | Without quorum: `QuorumUnavailable`. No advisory/DHT write is accepted as canonical. | None directly. Actionability requires advisory presence **and** canonical trust via `evaluate_threat_intel_policy` → `Actionable` + `Enforcement/PermitAction` |
| `Namespace::Revocation` (`RevocationInfo`, `node_id`) | canonical-consensus-backed | Raft log → SQLite; `GlobalNodeRevocationList`; edge replicas; persisted revocation file (postcard, `version=1`) | Linearizable commits; append-only semantics | Raft `(term, index)`; `node_id` key; `revoked_at: u64` | Permanent (no expiry); revocation wins over authorization and over expiry. Un-revocation requires explicit canonical `Delete` (operator action), never TTL lapse. | Append-only; revoked wins over concurrent authorization; replayed revocations dedup by `event_id`/nonce | Last committed revocation set; stale revocation snapshots fail safe: within grace per `stale_mode`, beyond grace → defer/deny new trust (never fail-open to trust a possibly-revoked node). `StaleHardLimit` updates are silently rejected (no silent rollback). | Without quorum: `QuorumUnavailable`. Revocation cannot be forged via DHT. | None directly. `node_revocation_status: NotTrusted{Revoked}` feeds peer-auth and key-policy gates; enforcement (refuse route/trust) via policy |
| `Namespace::AuthorizedGlobalNodes` (`AuthorizedGlobalNode`, `public_key`) | canonical-consensus-backed | Raft log → SQLite; edge replicas; IPC snapshots | Linearizable commits | Raft `(term, index)`; `public_key` key; `authorized_at: u64` | No expiry; explicit membership change only (`change_membership` via leader). | Committed log order | Last committed set per freshness policy; unavailable → global-auth checks fail closed (`NotTrusted`/`Unknown`, never `Trusted`) | Without quorum: `QuorumUnavailable`; membership changes require leader | None directly. `is_global_node_authorized` feeds peer-auth (`validate_peer_canonical_status`) and key-policy ingress |

Raft transport notes: `RaftCommand::{Set, Delete}` are WAL-logged with `(term, index)`; snapshots stream in binary (`SRMS` magic, `ENTRY_COUNT`, length-prefixed postcard entries) with JSON fallback for rolling upgrades; `SnapshotCanonicalTrustReader` (Supervisor) and `CanonicalTrustSnapshot` (IPC to workers) are the only worker-visible canonical surfaces — workers never own Raft or `EdgeReplicaManager`.

### 3b. Derived caches / materializations (must carry freshness/version; never independent authority)

| Namespace | Authority | Transport / replica | Consistency | Version / order key | TTL / expiry | Conflict rule | Partition read | Partition write | Enforcement effect |
|-----------|-----------|---------------------|-------------|---------------------|--------------|---------------|----------------|-----------------|--------------------|
| `EdgeReplicaManager` tables (`org_keys`, `threat_intel`, `revocation_list`, `authorized_global_nodes`; SQLite + moka 300s) | derived-cache | `RaftCommitNotification` via DHT `raft_commit:{ns}:{key}` → `update_from_notification` | Follows committed Raft state; local snapshot with `last_sync_index: u64`, `last_replica_refresh_unix` | `last_sync_index`; per-record freshness check (`Fresh` / `StaleWithinGrace` / `StaleHardLimit` per `AuthorityFreshnessConfig`: `global_policy_grace_secs`, `revocation_hard_limit_secs`) | Moka 300s; per-namespace hard limits; `StaleHardLimit` revocations rejected without update (fail-safe) | `INSERT OR REPLACE` only from commit notifications; stale notifications rejected; no local mutation masquerades as canonical | Serve snapshot with freshness classification; `Expired`/`Invalid`/`Missing` → defer/deny | Local replica is read-only for trust; writes go through Raft client only | Via `SnapshotCanonicalTrustReader` → `CanonicalTrustReader` only |
| `CanonicalTrustSnapshot` (Supervisor → worker IPC `CanonicalTrustSnapshotUpdate`, postcard) | derived-cache | Supervisor IPC; bounded, no key material | Snapshot of committed state at `generated_at_unix: u64` | `generated_at_unix`; classified by `CanonicalSnapshotFreshnessPolicy{fresh_max_age_ms=60s, stale_grace_max_age_ms=5m, stale_mode}` via `classify_canonical_snapshot` | Fresh ≤60s; grace ≤5m; beyond → `Expired`; zero/future(>60s skew) → `Invalid`; `None` → `Missing`. `normalize` clamps `stale_grace >= fresh_max`. | Newer snapshot replaces older; `Future` timestamps rejected; `Expired`/`Invalid`/`Missing` clears worker policy context (defers to raw diagnostics, never enforces) | Worker enforces via `FreshnessBoundCanonicalReader`: `Fresh` delegates; `StaleWithinGrace+AllowStaleWithWarning` delegates as `Stale`; `FailOpenDefer` → `Unknown{CanonicalUnavailable}`; `FailClosedNotActionable` → `NotTrusted{ExpiredSnapshot}`; `Expired`/`Invalid`/`Missing` → defer/deny | Workers cannot mutate canonical state; snapshot is read-only | Via `FreshnessBoundCanonicalReader` → threat-intel policy context; never direct enforcement |
| `RaftCommitNotification` (`raft_commit:{ns}:{key}` DHT keys) | derived-cache | DHT gossip (notification metadata, not canonical data) | Eventually delivered; best-effort | `commit_index: u64`, `namespace`, `key_id`, `timestamp`, `leader_id`; v2 `SignedRaftAttestation{commit_index, value_hash=SHA-256, protocol_version=2, Ed25519}` | Notification TTL per DHT defaults; value binding via `value_hash` (v1 without hash rejected by default; `allow_v1_raft_attestations` only for migration) | Attestation verifies signer is authorized global node (constant-time); envelope signer-to-node binding enforced on global nodes | Notifications inform replica refresh; they do not authorize trust by themselves | Notifications are emitted only after commit; no pre-commit notification is trusted | None directly; replica update path only |
| DHT `RaftOrQuorumGlobal` / `RaftAttestedGlobal` keys (`Organization`, `OrgPublicKey`, `TierKey`, `MemberCertificate`, `GlobalNodeList`, `OrgNameReservation`, `VerifiedUpstream`, `TierClaim`, `DnsDomainRegistration`, `GlobalNodeProof`, `NodeCertBinding`, `GenesisKeyTransition`, `RevokedGlobalNode{immutable}`) | derived-cache (admission requires canonical proof) | DHT announce/sync; `DhtKeyPolicyTable` + `DhtIngressPolicyContext` gate | Advisory transport; canonical admission | `sequence_number`; `GenesisKeyTransition.sequence: u32`; quorum proofs / `SignedRaftAttestation` | TTLs: org 7d, tier_key 30d, member_cert 365d, node binding/revocation/genesis 86400s, verified upstream/tier claim/DNS registration 3600s. Stale authority records beyond `max_authority_staleness_secs` rejected when `freshness_check_enabled`. | Quorum or attestation required; `immutable_after_create` for revocations; concurrent writes require proof, otherwise `Defer`/`Reject` (never silent trust) | During partition: without attestation/proof → `Defer`/`Reject`; cached entries served only with freshness classification | Remote writes not allowed (`remote_writes_allowed=false`); local writes require proof | None directly; policy-gated reads only |

### 3c. Advisory-distributed (may inform policy; never directly enforce)

| Namespace | Authority | Transport / replica | Consistency | Version / order key | TTL / expiry | Conflict rule | Partition read | Partition write | Enforcement effect |
|-----------|-----------|---------------------|-------------|---------------------|--------------|---------------|----------------|-----------------|--------------------|
| Threat-indicator DHT (`ThreatIndicator{indicator_id, type}`, `SignedFeed`) | advisory-distributed | DHT announce/sync + `HotThreatGossip` mesh gossip + bloom diff | Eventual; duplicate-tolerant | `sequence_number`; gossip `timestamp` + `ttl_seconds`; `seen_announces` moka (1000/3600s) dedup; `ThreatIntelligenceManager.local_version: u64` monotonic | Per-indicator `ttl_seconds`; 300s gossip freshness window; expired → `NotActionable`, never resurrected. Max TTL enforced at ingress; TTL survives replication unchanged (absolute `expires_at` derived locally via saturating add). | Reputation-gated acceptance + signature verification + dedup; duplicate/replay → suppressed (observable). Policy composes advisory + canonical; advisory-only → `AdvisoryOnly` (deny for enforcement). | Local operation may proceed where policy allows; propagation best-effort | Local detector may publish; enforcement mutation only via `handle_incoming_threat` policy gate (`PermitAction` + `MeshThreatIntelPolicyGated` provenance) | Gated: `lookup_*_policy_strict` for enforcement; raw `lookup_local_indicator*` / `lookup_threat_indicator_in_dht` are diagnostic-only |
| YARA/WASM distribution (`YaraRuleSubmission`, `YaraRulesManifest`, `YaraRuleContent`/`YaraCompiledRuleContent` + `YaraChunk`/`YaraCompiledChunk`, `WasmModuleInfo{version: u64}`, `ServerlessFunction`) | advisory-distributed (content-addressed chunks are immutable) | DHT chunked transfer + manifest | Eventual; version-ordered | `content_hash` / `compiled_hash` (SHA-256) for chunks (immutable); `version: u64` monotonic for modules/manifests | 7-day submission expiry (YARA); in-memory WASM versions; content-addressed chunks immutable (no TTL conflict) | Checksum verification; 2/3 quorum for YARA approval; latest-version lookup; stale versions never overwrite newer | Serve latest verified; stale/unknown → defer | Edge submit, global approve; no enforcement without approval gate | None directly; scanner activation via approval/policy |
| Behavioral / reputation observations (`BehavioralFingerprint`, `PeerReputation{score 0-100}`, `OriginPenalty`, `OriginReachability`, `VerificationTask`) | advisory-distributed | DHT + local observation | Eventual; similarity-thresholded | `local_version: u64`; LSH bucketing, similarity 0.85; reputation `last_updated` + 3600s decay; role-based base scores | `fingerprint_ttl_secs` default 3600; reputation decays periodically; telemetry 300s | Version ordering; LSH similarity; bonus/penalty events; periodic decay; no quorum | Local policy may use as hints; enforcement requires separate gate | Local observation writes allowed | Hints only; never direct blocks |
| Node/peer telemetry (`NodeInfo`, `NodeHealth`, `NodeLoad`, `GlobalNodeHeartbeat`, `GlobalNodePublicKey`, `NodeCapability`, `CapabilityAttestation`, `EdgeAttestation`, `TierClaim` gossip, `OrgPendingRequest`, `OrgInvitation{expires_at}`, `QuorumSignature`) | advisory-distributed (self-authored or ephemeral) | DHT announce (self) / mesh gossip | Eventual; last-writer-wins within strict bounds | `sequence_number`; `timestamp` + `nonce`; `cert_id`/`key_id` UUIDs; HMAC proofs for invitations | 300s (telemetry/attestation), 3600s (public caches), invitation hours-based `expires_at`. Future-dated beyond window rejected. | Self-authored only (`NodeSelf`); last-writer-wins for ephemeral telemetry only — never for trust/revocation (those are canonical). `validate_peer_role` + `validate_tier_claim` enforce role boundaries. | Hints for routing/discovery; never trust/ownership/revocation | Self writes only; cannot overwrite others' telemetry or canonical namespaces | None for trust; routing hints only |
| Upstream/DNS/provider caches (`Upstream`, `DnsZone`, `DnsRecord`, `AnycastNode`, `UpstreamImageProtection/Minification/Compression/ProxyCachePreferences`, `SiteImagePoisonConfig`, `SiteContentVersion`, `UpstreamOwnershipChallenge`, `TransformedContent`, `PoisonedImage`, `SiteScoped{inner}`) | advisory-distributed (public cache) or content-addressed | DHT announce | Eventual (public cache) | `sequence_number`; content hash for transformed/poisoned (SHA-256, immutable) | 3600s (public caches); content-addressed immutable (no expiry conflict) | Public-cache LWW only for non-security hints; `SiteScoped` inherits inner authority; ownership challenges require proof | Cache hints; authoritative DNS/zone ownership resolved via canonical/attested paths, not cache alone | Any node may advertise cache entries; authority-adjacent writes require proof | Routing/cache hints only |
| Routing / topology / proxy hints (`RouteAdvertisement`, `MeshTopology{topology_version: u64}`, `MeshProxy` policy cache 3600s, failed-provider cooldown 10s, health window 300s, block broadcast at 5 failures) | advisory-distributed | Mesh gossip + DHT queries | Eventual | `topology_version: u64`; `timestamp` | Route cache 3600s; verified-upstream cache 60s; policy cache 3600s; cooldown 10s | Weighted provider selection; health metrics; sharded peer store; degraded-mode toggle | Hints; degraded mode explicit | Local writes only | Routing only; blocking via `handle_incoming_threat` gate, not proxy hints |

### 3d. Local-authoritative (local node owns; replication informational)

| Namespace | Authority | Transport / replica | Consistency | Version / order key | TTL / expiry | Conflict rule | Partition read | Partition write | Enforcement effect |
|-----------|-----------|---------------------|-------------|---------------------|--------------|---------------|----------------|-----------------|--------------------|
| BlockStore IP blocks (`BlockRecord{site_scope, ip}`), Mesh blocks (`MeshBlockEntry{site_scope, mesh_id}`) | local-authoritative | Local shards (64×`RwLock`); mesh gossip exports observations; snapshots/cursors for convergence | Local linearizable; cross-node eventual via gossip + snapshot repair | `blocked_at: u64`, `version`, `source_sequence` (per-source monotonic), `logical_time` (HLC), `event_id` (UUID dedup). Ordering: `version` → `source_sequence` (same source) → `logical_time` → timestamp fallback. | `ban_expire_seconds` set by committer (0 = permanent); max TTL enforced; TTL survives replication unchanged; expiry derived locally (`blocked_at + ban` with saturating math); expired records never resurrect (apply/snapshot paths count `expired_records_ignored`); unblock/revocation is an explicit event that wins over concurrent block at same version via ordering rule; cleanup via background expiry + LRU eviction. Clock skew bounded: ordering prefers `source_sequence`/`logical_time` over wall-clock; `test_ordering_source_sequence_describe_clock_skew` pins this. | `event_id` dedup (`seen_events` 10k FIFO); per-target stale suppression (`target_state` 10k LWW) → `IgnoredStale`; `(site_scope, ip)` / `(site_scope, mesh_id)` composite keys; `INSERT OR REPLACE` only if newer per `is_newer_than`. | Always available locally (partition-independent); remote copies never overwrite newer local state | Local authority may block/unblock; remote events applied only if newer + policy-gated (mesh enforcement uses `block_ip_with_provenance{MeshThreatIntelPolicyGated}`); worker admission reads BlockStore (not `ThreatIntelligenceManager`) | Direct enforcement (worker admission). Mesh-ID blocks are admin/control-plane only (`is_mesh_id_blocked` never in WAF/request/proxy/HTTP/3 paths — guard-enforced). |
| Blocklist events / cursors / snapshots (`BlocklistEvent{event_id, version, source_sequence, logical_time, ttl_secs?}`, `BlocklistEventCursor{since_sequenceExclusive, max_events}`, `BlocklistTargetStateRecord{version, recorded_at, expires_at?, source_sequence, logical_time}`, `Snapshot{blocked_at, ban_expire_seconds}`) | local-authoritative (event log) + advisory gossip | `MeshMessage::BlocklistEventGossip`; catchup query (`since_sequence` exclusive); snapshot export/apply (paginated, `max_items`) | Per-source ordered streams; snapshot fallback on gaps | `source_sequence` gaps trigger snapshot/fallback (`SnapshotRepairRequired`); duplicate `event_id` → `NoopDuplicate`/`DuplicateIgnored`; stale → `IgnoredStale`/`StaleIgnored` | `ttl_secs?` / `expires_at?` per record; zero/max TTL boundary-tested; replay of expired state rejected + counted; restart hydration via `blocklist_peer_cursors.json` + persisted event log (`peer_cursor_loaded` observable) | Deterministic: version → source_sequence → HLC → timestamp; snapshot apply counts `applied/updated/stale/invalid/expired` separately | Local log always readable; catchup during partition returns `history_complete=false` + `snapshot_required=true` where defined | Local append; remote catchup is pull-based; unblock ordering preserved across disconnect/rejoin via `(version, source_sequence, logical_time)` (tests pin this) | Via BlockStore apply (above) |
| Reputation / rate-limit / session / topology local state (`PeerReputation`, `MeshPeerRateLimiter{1s/60s/3600s windows}`, `SessionManager{KEM rotation}`, `MeshTopology`, `MeshDiscovery` seed bootstrap 30s, `HierarchicalRoutingManager` bloom advertisements) | local-authoritative | In-process (+ seed/gossip hints) | Local | Atomic counters; `session_generation: u64` global; `topology_version: u64` | Sliding windows; key rotation intervals; route/verified caches as above | Local decision; no cross-node conflict | Always available | Local only | Local policy/hints |
| Identity private material (`OrgKey` private, `TierKeyEncryption`, `MeshCertManager` local cache, `SessionKeys`, `CertDistManager` per-site AES-256-GCM + HKDF) | local-authoritative | Never distributed (private); cert distribution is session-encrypted per-site | Local | `key_id` UUID; `created_at`/`valid_from`/`valid_until`; 25-day rotation check; TOFU pinning (30d max fingerprint age); CRL by serial | Validity windows enforced; rotation re-encrypts; expiry is local derivation, not replication | Private keys never leave owner; cert identity binding verified (SHA-256 fingerprint) | Local only | Local only | Identity issuance/verification (policy-gated use) |
| Challenge/PoW mesh state | local-authoritative (not replicated) | In-process only (`MeshSecurityChallenge{challenge_id}`, HMAC-derived key, PoW/TimeBased/Crypto) | Local | `challenge_id`; 60s timeout; max 3 attempts | 60s challenge timeout; no replication TTL | HMAC verification; no cross-node conflict | Local only | Local only | Challenge issuance/verification (local policy) |
| Config / admin local state + propagation queue | local-authoritative (local commit) + best-effort propagation | Admin API → local store → mesh queue (`QueuedBestEffort`) / supervisor IPC → workers (`SupervisorSync`) / Raft client for canonical namespaces | Local commit is synchronous; propagation async best-effort; canonical commit synchronous via Raft (when applicable) | `event_id` (distributed dedup); Raft `(term, index)` for canonical; `AdminMutationResult{status, propagation, event_id, audit_id}` | No TTL on local commit; propagation queue bounded with `FailedToQueue`/`Deferred` on pressure; canonical snapshot TTL as in 3b | Local commit wins locally; remote propagation never overwrites newer local state unless contract grants it | Local reads always available | Local writes always allowed where policy permits; canonical writes require quorum; propagation failures never retroactively fail the local commit (but must be reported truthfully — see §5) | Via typed mutation APIs only (never raw store writes from remote) |
| Certificate distribution (`CertChain`, `NodeCertBinding`, `EncryptedCertData`, `CrlEntry{revocation_time}`) | local-authoritative (issuance) + derived-cache (distribution) | TLS handshake (chains); DHT (bindings); mesh session (encrypted certs) | Issuer-authoritative; distribution eventual | Cert fingerprint (SHA-256); serial (`node_id`) for CRL | Leaf validity windows; rotation intervals; CRL permanent until superseded | X.509 chain verification; TOFU + CRL + identity binding; session-key rotation re-encrypts | Local trust store + freshness policy for bindings | Issuer-only writes | TLS/peer-auth (policy-gated) |

---

## 4. Versioning, conflict, and clock rules (binding)

1. Prefer explicit version/order metadata: Raft `(term, index)` for canonical; source identity + monotonic `source_sequence` for source-scoped streams (blocklist, gossip); content/version digests (`content_hash`, `version: u64`, `sequence: u32`) for immutable/versioned records.
2. No security-critical last-writer-wins by wall-clock. Wall-clock timestamps are used only for TTL/freshness, with:
   - `u64` Unix seconds via `safe_unix_timestamp` (never panics) and `saturating_sub`/`saturating_add` throughout;
   - accepted future skew: 60s for canonical snapshots (`classify_canonical_snapshot`), 300s (`DHT_RECORD_TIMESTAMP_WINDOW_SECS`) for DHT record timestamps, 60s for peer-auth timestamps;
   - expired records are never resurrected (threat `NotActionable`, block snapshot `expired_records_ignored`, YARA submission expiry, revocation permanence);
   - future timestamps beyond the window → `Invalid`/`Rejected` (never immortal: max TTL enforced at ingress; TTL survives replication unchanged, converted to absolute expiry locally).
3. Conflict rules are deterministic and tested: block ordering (`version` → `source_sequence` → `logical_time` → timestamp fallback), Raft log order, `event_id`/nonce dedup, quorum/attestation proof requirements, `immutable_after_create` for revocations, `INSERT OR REPLACE` only when newer.
4. Source-sequence gaps use snapshot/fallback: blocklist catchup returns `snapshot_required=true` + `SnapshotRepairRequired` propagation status; `record_blocklist_snapshot_fallback` is metered.

---

## 5. Expiry semantics (binding)

For every expiring enforcement/advisory record:

| Record | Who sets TTL | Max accepted TTL | Replication | Skew bound | Cleanup | Expiry replication | Unblock/revocation vs expiry |
|--------|--------------|------------------|-------------|------------|---------|--------------------|------------------------------|
| Block IP/mesh (`ban_expire_seconds`, 0=permanent) | Committer (admin/detector/policy-gated mesh) | Enforced at admission (`DenyListLimitsConfig` + ingress max) | TTL survives unchanged; absolute expiry derived locally | Ordering prefers sequence/HLC over wall-clock | Background expiry + LRU eviction; `is_expired` checked on read | Expiry derived locally; unblock is an explicit event (wins per ordering), not TTL lapse | Unblock/revocation event supersedes TTL; expired blocks never resurrect via replay/snapshot (counted) |
| Threat indicator (`ttl_seconds` → `expires_at`) | Publisher (detector/feed) | Enforced at ingress; gossip 300s freshness window | TTL unchanged; `expires_at` derived locally | `safe_unix_timestamp` + saturating math; future immortality rejected | TTL check before policy gate in `handle_incoming_threat`; expired → `NotActionable` | Derived locally; rejoin never resurrects expired advisories | Canonical expiry and revocation both deny actionability |
| DHT advisory records | Publisher within `TtlManager::ttl_for(record_type)` | Per-type maxima (telemetry 300s, upstream/cache 3600s, org 7d, tier_key 30d, member_cert 365d, heartbeat 90s, etc.) | TTL unchanged; `expires_at_for = safe_now + ttl` | 300s record-timestamp window; 60s snapshot skew | `TtlManager` + shard expiry; prefix reads filter expired | Derived locally | Revocation/attestation state independent of advisory TTL |
| Canonical snapshot | Supervisor (`generated_at_unix`) | Fresh 60s / grace 5m (configurable via `AuthorityFreshnessConfig`, normalized) | Snapshot carries `generated_at_unix`; workers classify locally | 60s future-skew → `Invalid` | Worker clears policy context on `Expired`/`Invalid`/`Missing` | Age derived locally from `generated_at_unix` | Revocation permanence overrides snapshot staleness (stale snapshots defer/deny, never trust) |
| YARA submissions / challenges / invitations / sessions | Submitter/issuer | 7-day YARA expiry; 60s challenge timeout + 3 attempts; invitation hours; session rotation intervals | Unchanged | Same timestamp helpers | Explicit expiry sweeps | Derived locally | Approval/revocation independent of TTL |

Boundary tests required (and present in `crates/synvoid-mesh/tests/distributed_state_partition.rs` + `canonical.rs` + block-store suites): zero TTL, max TTL, just-expired vs just-fresh, 60s future-skew boundary, replay of expired state, restart hydration (`blocklist_peer_cursors.json` + event-log stats).

---

## 6. Policy gate (binding, preserved)

No newly received advisory datum may directly invoke an enforcement mutation without passing through the established trust/provenance/policy gate. Do not broaden request-path capabilities.

- Threat/mesh enforcement: `handle_incoming_threat` verifies signature → reputation gate → TTL expiry → duplicate check → `evaluate_incoming_threat_policy` → only `PermitAction` mutates BlockStore with `BlockProvenanceKind::MeshThreatIntelPolicyGated`. `apply_sync` and `handle_hot_threat_gossip` inherit the gate by delegation. Strict wrappers (`lookup_threat_indicator_policy_strict`, `lookup_local_indicator_policy_strict`, `lookup_local_indicator_by_ip_policy_strict`) are the only enforcement-safe reads; raw `lookup_local_indicator*` / `lookup_threat_indicator_in_dht` are diagnostic-only. Guard: `manual_enforcement_provenance_guard`, `request_path_capability_boundary_guard`.
- Worker admission: reads BlockStore, not `ThreatIntelligenceManager`. The WAF pipeline queries no block/threat state and mutates none (`maybe_escalate_and_block` records violations without mutating the store). Mesh-ID blocks are admin/control-plane only.
- DHT ingress: `DhtIngressPolicyContext` (optional `Arc<dyn CanonicalTrustReader>`) → `check_dht_ingress_authority` → `AcceptAdvisory` / `AcceptCanonical{freshness}` / `Reject{reason}` / `Defer{reason}`. Disabled context preserves legacy behavior; configured Push/Announce paths reject canonical-required records on unauthorized/revoked/unavailable/unknown. Sync/replay/local/quorum/Raft-apply paths are intentionally outside this gate (they follow Raft/log ordering, not DHT admission).
- New consumers need `ThreatIntelConsumerKind::Enforcement` + `ThreatIntelConsumerAction::PermitAction` before mutating state; `ThreatIntelDeferredMode` controls deferred behavior per consumer (`FailOpenNoAction` / `FailClosedNoAction` / `ShadowOnly`).

Call-graph audit (Phase 23): strict/composed wrappers have no bypassing production callers; all mesh enforcement gating is centralized in `handle_incoming_threat`; WAF/BlockStore boundary is correct (no migration needed).

---

## 7. Typed mutation / propagation outcomes (binding)

Control-plane/admin/mesh APIs reuse `AdminMutationResult` / `PropagationStatus` (`crates/synvoid-core/src/admin_mutation.rs`). Operator-visible success must never imply distributed/canonical completion unless proven.

| Outcome | `AdminMutationStatus` | `PropagationStatus` | Meaning |
|---------|----------------------|---------------------|---------|
| Local mutation applied | `Applied` (`local_store_mutated=true`) | `NotApplicable` or `AppliedLocalOnly` | Local store mutated; no distributed claim |
| Local mutation rejected | `InvalidRejected` / `UnauthorizedRejected` / `Failed` | `NotApplicable` | Nothing mutated |
| Canonical commit completed | `Applied` | `CanonicalCommitted` | Raft commit proven (`term`, `index` known). Only for canonical namespaces. |
| Propagation queued / best-effort | `Applied` | `QueuedBestEffort` | Local commit done; mesh propagation queued. NOT a delivery guarantee. |
| Propagation failed / partial | `Applied` (local still applied) or `Failed` | `FailedToQueue` / `SnapshotRepairRequired` / `Deferred` | Truthful partial-failure signal; `SnapshotRepairRequired` triggers snapshot path |
| Quorum unavailable | `Failed` (`local_store_mutated=false`) | `QuorumUnavailable` | Canonical write failed for lack of quorum. Must not be reported as success or as queued canonical commit. Helpers: `AdminMutationResult::quorum_unavailable`, `RaftAwareClientError::QuorumUnavailable`, `CanonicalWriteOutcome::QuorumUnavailable`. |
| Stale / not-authoritative rejected | `StaleIgnored` / `DuplicateIgnored` / `NoOpAlreadyPresent` / `NoOpAlreadyAbsent` | `NotApplicable` (or `Deferred` for `CanonicalUnknown`) | Duplicate/stale/unknown-authority suppression; `Unknown` canonical answers are never treated as trust |

Rules:
- `QueuedBestEffort` must never be presented as `CanonicalCommitted`.
- `QuorumUnavailable` must never carry `local_store_mutated=true`.
- Canonical DHT material must never be presented as independently authoritative during partition (serve only with freshness classification via `CanonicalTrustReader.freshness()`).
- Helpers: `AdminMutationResult::applied_with_propagation`, `::quorum_unavailable`, `::canonical_committed`; `CanonicalWriteOutcome::propagation_status()`; `RaftAwareClientError::is_quorum_unavailable()` / `to_propagation_status()`.

---

## 8. Partition / rejoin behavior (binding)

Canonical consensus-backed:
- Writes without quorum → typed `QuorumUnavailable`, fail-closed, no success/queued-canonical report.
- Reads use last committed state only per freshness policy; stale canonical state is classified (`Fresh` / `StaleWithinGrace` / `Expired` / `Invalid` / `Missing`) and observable; uncommitted local mutations never masquerade as canonical.

Advisory/eventual:
- Local operation may proceed where policy allows; propagation best-effort; conflicts/duplicates handled deterministically (dedup + version/sequence/HLC ordering); enforcement gated by local policy/provenance.

Local-authoritative:
- Remote copies must not overwrite local authority unless explicitly granted. BlockStore applies remote events only when newer per `is_newer_than`; cursors/snapshots repair gaps without rollback of newer local state.

Rejoin convergence:
- Raft log + snapshot converge committed state; `EdgeReplicaManager` refreshes from commit notifications (stale divergent writes rejected).
- Blocklist catchup (`since_sequence` exclusive) + snapshot fallback converge without accepting stale divergent writes; `peer_cursors` persist across restarts.
- Expired advisories never resurrect; revocations persist; unblock ordering preserved via `(version, source_sequence, logical_time)`.

Deterministic tests (`crates/synvoid-mesh/tests/distributed_state_partition.rs`, plus `canonical.rs`, block-store, threat-policy suites; no large external cluster required):
- quorum available → write commits and derived replicas update;
- quorum lost → write fails typed/fail-closed (`QuorumUnavailable`, `local_store_mutated=false`);
- reads during partition follow freshness policy (`Fresh` delegates; `StaleWithinGrace` per `stale_mode`; `Expired`/`Invalid`/`Missing` defer/deny);
- heal → committed state converges without accepting stale divergent writes;
- duplicate/replayed events do not reapply;
- source-sequence gaps use snapshot/fallback (`SnapshotRepairRequired`);
- stale canonical snapshot classified and cannot authorize new trust;
- expired advisory/enforcement records do not resurrect after rejoin;
- remote advisory remains policy-gated (`AdvisoryOnly` never enforces);
- unblock/revocation ordering preserved across disconnect/rejoin.

---

## 9. Observability (bounded, no secrets)

All signals use bounded labels/counters (no key material, raw tokens, peer-specific high-cardinality labels, or payload digests as labels). Label helpers live in `crates/synvoid-mesh/src/mesh/canonical.rs` (`canonical_snapshot_freshness_label`, `distributed_authority_label`, `propagation_outcome_label`, `canonical_write_outcome_label`); counters live in `synvoid-metrics` with stub mirrors in `synvoid-mesh/src/stubs.rs`.

| Signal | Source | Labels / values (bounded) |
|--------|--------|---------------------------|
| Canonical quorum availability | `record_distributed_canonical_outcome("committed" \| "quorum_unavailable" \| "not_leader" \| "deferred" \| "rejected_stale")`, `record_global_node_quorum_lost`, `record_global_node_liveness_count`, `record_dht_quorum_success/failure` | outcomes from allowlist only |
| Current term / commit index | Exposed as numeric gauges/counters where safe (u64 term/index, no keys); `RaftCommitNotification{commit_index}` metadata; `EdgeReplicaManager.last_sync_index` | numeric only |
| Canonical snapshot age / freshness class | `record_canonical_snapshot_freshness("fresh" \| "stale_within_grace" \| "expired" \| "invalid" \| "missing")` + `classify_canonical_snapshot` state | 5 classes only |
| Rejected stale / untrusted | `record_distributed_stale_rejected`, `record_blocklist_stale_replay_ignored`, `record_blocklist_event_apply("stale")`, `record_threat_intel_enforcement_suppressed_*`, `record_dht_verification_failure`, edge `stale_records_rejected` | reason classes only |
| Replay / duplicate suppression | `record_distributed_replay_suppressed`, `record_blocklist_event_apply("duplicate")`, `seen_announces` dedup, `record_blocklist_catchup_event_*` | outcome classes only |
| Propagation partial / failure | `record_distributed_propagation_outcome("queued_best_effort" \| "canonical_committed" \| "quorum_unavailable" \| "failed_to_queue" \| "deferred" \| "applied_local_only" \| "not_applicable")`, `record_blocklist_snapshot_fallback`, `record_dht_quorum_failure` | 7 outcomes only |
| Convergence lag | `record_blocklist_cursor_update/load`, `peer_cursor_*`, `record_blocklist_catchup_event_applied/noop/stale`, `EdgeReplicaManager.last_sync_index` lag vs commit index | numeric only |

---

## 10. Document map (this contract is authoritative)

- Trust domains and review checklist: `architecture/mesh_trust_domains.md` (advisory vs canonical vs policy vs services; `CanonicalTrustReader` seam; Iterations 8–36). This contract is the binding namespace matrix; trust-domains remains the design/invariant companion.
- Mesh transport/lifecycle: `architecture/mesh.md`, `architecture/mesh_transport_lifecycle.md`, skill `synvoid_mesh`.
- Raft detail: skill `raft_consensus` (Waves 6–11, W15 attestation hardening); `architecture/mesh_deep_dive.md` (topology + Raft summary, links here for quorum semantics).
- Blocklist convergence: `architecture/block_store.md`, `architecture/blocklist_reconciliation.md`, `architecture/blocklist_provenance_preservation.md`, `architecture/blocklist_remove_consistency.md`, `architecture/blockstore_admin_observability.md` (ordering, cursors, snapshots, provenance).
- Threat intel: `docs/THREAT_INTEL.md` (three-plane model, consumer gate, strict vs legacy), `architecture/threat_intel_consumer_actionability.md`, `architecture/threat_intel_request_waf_audit.md`.
- Admin/control plane: `architecture/admin_control_plane_authority.md` (typed mutation/propagation/audit; links here for `CanonicalCommitted` / `QuorumUnavailable`).
- Operations: `architecture/runtime_operations_drill.md` (Drill 5 mesh + Drill 8 partitionunas? see §11), `architecture/layer_3_5_deep_dive.md` (MESH-15 closure note).
- Release risk: `architecture/final_surface_audit.md`, `architecture/release_hardening_report.md` (residual risk references this contract for partition unavailability).

---

## 11. Operator drill (partition)

1. Single-node mesh drill (`runtime_operations_drill.md` Drill 5) remains the smoke path.
2. Partition drill (no external cluster): stop a majority of Global nodes (or isolate them via firewall/namespace), then:
   - canonical write (org create / key rotation / revocation) must return typed `QuorumUnavailable` (not success);
   - edge reads must report freshness class (`StaleWithinGrace`/`Expired`) and defer/deny new trust per `stale_mode`;
   - advisory threat gossip may continue locally but must not enforce without canonical trust (`AdvisoryOnly`);
   - local blocks/unblocks continue (local authority) with `QueuedBestEffort` propagation;
   - on heal, verify `last_sync_index` advances, cursors converge, no stale resurrection, revocations intact.
3. Metrics to watch: `distributed_canonical_outcome`, `canonical_snapshot_freshness`, `distributed_propagation_outcome`, `blocklist_catchup_event_*`, `global_node_quorum_lost`.

---

## Appendix A. Verification (Phase 23 minimum)

```bash
cargo fmt --all -- --check
cargo check --features mesh
cargo test -p synvoid-mesh
cargo test --test request_path_capability_boundary_guard --features mesh
cargo test --test manual_enforcement_provenance_guard --features mesh
```

Plus: existing blocklist convergence, canonical trust/freshness, threat-intel policy-gate, and admin mutation propagation tests, plus the new `distributed_state_partition` scenarios (§8). Routine CI remains `cargo xtask verify` (frozen contract in `docs/testing/verification-contract.md`); broader suites via `cargo xtask verify-full`.

## Appendix B. Acceptance mapping

| Phase 23 acceptance criterion | Where proven |
|-------------------------------|--------------|
| Every security-relevant namespace in matrix | §3a–3d |
| Authority/consistency/ordering/expiry/conflict/partition/enforcement explicit | §3–§5, §8 |
| Canonical DHT material cannot become independent authority | §2–§3b, §6–§7 |
| Quorum-unavailable writes fail typed, never success | §2, §7–§8; `PropagationStatus::QuorumUnavailable`, `CanonicalWriteOutcome`, `RaftAwareClientError::QuorumUnavailable` + tests |
| Raft vs MESH-15 reconciled with evidence | §2 |
| Advisory remains policy-gated | §6 + guards |
| Expiry/replay/rejoin tested | §4–§5, §8 + tests |
| Admin responses distinguish local/best-effort/canonical | §7 |
| Metrics bounded, no secret leak | §9 + label-allowlist tests |
| Phase 5 blocklist invariants green | Existing convergence suites (untouched ordering) |
