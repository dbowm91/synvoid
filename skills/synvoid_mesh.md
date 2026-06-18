# SynVoid Mesh & DHT Architecture Skill

## Overview

SynVoid uses a mesh network architecture with DHT-based service discovery for multi-origin routing. This skill provides context for working with the mesh transport, DHT keys, and upstream routing.

**Trust domains (advisory vs. canonical)**: DHT provides advisory, TTL-bound records (discovery, announcements). Raft provides canonical authority state (OrgPublicKey, ThreatIntel, revocation). Policy layer (key_policy, peer_auth decisions) resolves advisory+canonical into actionable trust; services consume policy outputs, not raw advisory records. See `architecture/mesh_trust_domains.md` for classification, invariants, and review checklist. **Canonical seam** (Iterations 7-15, complete): `CanonicalTrustReader` in `crates/synvoid-mesh/src/mesh/canonical.rs`; `validate_peer_canonical_status` in `peer_auth.rs`; `classify_key_authority_with_canonical_reader` in `dht/key_policy.rs`; `validate_dht_key_authority_for_ingress` adapter; `DhtIngressPolicyContext` wired for Push/Announce via `RecordStoreManager`. Ingress gate active for configured Push/Announce paths; disabled context preserves legacy. **Iteration 16: AdvisoryRecordSource seam** — `AdvisoryRecordSource` trait + `RecordStoreAdvisorySource` adapter + `StaticAdvisoryRecordSource` in `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`. **Iteration 17: Advisory source hardening** — `RecordStoreAdvisorySource` has focused real-store tests (present/missing/expired/prefix); architecture/docs updated; no service migration. **Iteration 18: Policy composition helper** — `evaluate_threat_intel_policy()` in `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` composes `AdvisoryRecordSource` + `CanonicalTrustReader` into explicit threat-intel policy decisions (Actionable/AdvisoryOnly/NotActionable/Deferred). Tests cover all advisory + canonical state combinations. **Iteration 19: First consumer migration** — `ThreatIntelligenceManager::evaluate_indicator_actionability` wraps the policy helper, taking trait objects as parameters. Tests cover all policy-composed and legacy paths. **Iteration 20: Injection seam** — `ThreatIntelPolicyContext` carrier with `set_policy_context()`, `evaluate_indicator_actionability_configured()`, and `lookup_threat_indicator_policy_composed()`. **Iteration 21: Second consumer migration** — `lookup_local_indicator_policy_composed` and `lookup_local_indicator_by_ip_policy_composed` added. Two threat-intel read paths now use the composed policy seam. Raw methods remain for compatibility. No proxy, YARA/WASM, or routing consumers migrated. **Iteration 22: Policy cleanup** — shared `is_policy_actionable` helper consolidates duplicate DHT/local gating; policy-composed methods documented as preferred; raw methods documented as compatibility/diagnostic. **Iteration 23: Policy reassessment** — the track is staged and stable after call-graph review. No low-risk caller was migrated, no proxy/YARA/WASM/routing/enforcement hot path was touched, and raw lookup APIs remain compatibility/diagnostic paths. **Iteration 24: Verification** — the shared helper remains in place and focused mesh checks passed; raw lookup APIs remain compatibility/diagnostic paths. **Iterations 25-26: Root wiring** — `DataPlaneServices` carries optional `ThreatIntelPolicyContext`; a root-side helper builds it from explicit canonical/advisory handles. **Iteration 27** assessed canonical reader ownership; workers are data-planes without direct access to Raft/EdgeReplicaManager. **Iteration 28: Supervisor exports `CanonicalTrustSnapshot` via IPC to workers** — `EdgeReplicaManager::canonical_trust_snapshot()` produces the snapshot, Supervisor sends `CanonicalTrustSnapshotUpdate` IPC, workers store it and apply the snapshot via `DataPlaneServices::update_threat_intel_policy_context()` in the IPC message loop. `CanonicalTrustSnapshot` implements `CanonicalTrustReader`. `DataPlaneServices::update_threat_intel_policy_context()` enables live policy context updates when snapshots arrive via IPC. **Iteration 31: Canonical snapshot freshness policy** — `CanonicalSnapshotFreshnessPolicy` and `classify_canonical_snapshot()` in `crates/synvoid-mesh/src/mesh/canonical.rs` classify snapshots as fresh (≤60s), stale-within-grace (≤5min), expired, invalid, or missing. `FreshnessBoundCanonicalReader` wrapper enforces freshness on `CanonicalTrustReader` trust decisions. Workers classify snapshot freshness before applying; expired/invalid snapshots are not applied. **Iteration 32: Config wiring** — `From<&AuthorityFreshnessConfig>` conversion with normalization; worker reads config at runtime; `FailClosedNotActionable` installs reader. No proxy/YARA/WASM/routing/WAF consumers were migrated. **Iteration 33: Shadow/observability consumers** — `ThreatIntelPolicyShadowDecision` DTO, `ThreatIntelPolicyDecisionClass`, `ThreatIntelPolicyShadowDisagreement` enums; `evaluate_indicator_policy_shadow()` with metrics counters; admin endpoints for diagnostics. **Shadow/observability only — no enforcement behavior changed.**

## Node Roles

| Role | Purpose | Key Identifier | Authentication |
|------|---------|---------------|----------------|
| **Global** | CA/signer, coordination, DNS authority | `node_id` | Ed25519 signature + authorized key |
| **Edge** | Proxy requests, route to origins | `node_id` | Ed25519 self-signature |
| **Origin** | Host sites, register upstreams with global | `node_id` | Ed25519 self-signature + Global attestation (must be from REAL global node, not self) |

**Critical insight**: Origins are NOT global nodes. Global nodes are CAs/coordinators. Origins are separate nodes that register with global nodes. **Origin nodes cannot self-attest as global nodes** - they must obtain attestation from an actual configured global node via a separate registration flow.

### Role Authentication (W1.3 - Fixed)

All node types now require Ed25519 signature verification:

```rust
// crates/synvoid-mesh/src/mesh/peer_auth.rs
pub fn validate_peer_role(
    role: &MeshNodeRole,
    authorized_global_pubkeys: &[String],
    peer_node_id: &str,
    peer_public_key: Option<&str>,           // Node's own Ed25519 public key
    peer_signature: Option<&str>,             // Self-signature
    timestamp: u64,
    max_age_secs: u64,
    revoked_nodes: Option<&GlobalNodeRevocationList>,
    global_node_attestation_key: Option<&str>, // For Origin: Global's key
    global_node_attestation_sig: Option<&str>, // For Origin: Global's signature
    pow_nonce: Option<u64>,                    // For Edge: PoW nonce (required for Edge)
    pow_public_key: Option<&str>,              // For Edge: PoW public key (required for Edge)
    member_certificate: Option<&MemberCertificate>, // For Edge: member certificate
    org_public_key: Option<&OrgPublicKey>,          // For Edge: org public key
    raft_attestation: Option<&SignedRaftAttestation>, // For Edge: value-bound Raft attestation
    allow_v1_raft_attestations: bool,               // Allow legacy v1 attestations without value_hash
) -> Result<(), String>
```

| Role | Challenge Format | Verification |
|------|-----------------|---------------|
| Global | `"{node_id}:{timestamp}"` | Check pubkey in authorized list, verify signature |
| Edge | `"edge:{node_id}:{timestamp}"` | Verify self-signature. If `member_certificate` + `org_public_key` provided: try `validate_member_certificate_with_raft_attestation()` (quorum signatures OR value-bound Raft attestation); if `raft_attestation` is None, falls back to quorum-only `validate_member_certificate()`; if `raft_attestation` is Some but validation fails, returns error immediately (no PoW fallback). If no certificate, requires PoW (`pow_nonce` + `pow_public_key`). |
| Origin | `"origin:{node_id}:{timestamp}"` | Verify self-signature + Global attestation |

## Upstream ID Format

**Current format**: `http://host:port`

Examples:
- `http://example.com:80`
- `https://api.example.com:443`
- `irc://example.com:6667`

**Old format** (deprecated): `router_id.service_id` like `origin-1.shop-api`

## Mesh Local Upstreams Config

```toml
[mesh.local_upstreams]
# Domain-based keys with local backend URL
"http://example.com:80" = { 
    upstream_url = "http://127.0.0.1:5001",
    supported_ports = [80, 443],  # Optional: advertise supported ports
    geo = "us-east"
}
```

**Breaking change**: Keys are now domain-based, NOT service-based like `shop-api`.

## DHT Key Types

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `verified_upstream:{upstream_id}` | Verified origin registration | 30 days |
| `upstream:{upstream_id}` | Route announcement | 5 min |
| `node_capability:{node_id}` | Node capabilities | 5 min |
| `origin_reachability:{upstream_id}:{provider}` | Reachability status | 60 sec |
| `origin_penalty:{upstream_id}:{provider}` | Route penalty score | 600 sec |
| `capability_attestation:{node_id}:{capability}` | Signed capability attestation | 24 hours |
| `genesis_key_transition:{sequence}` | Genesis key rotation record | 24 hours |
| `revoked_global_node:{node_id}` | Revoked global node | 24 hours |
| `serverless_function:{name}` | Serverless function registration | 1 hour |
| `yara_chunk:{content_hash}:{index}` | Compressed YARA rule chunk (for large rulesets) | 24 hours |

## DHT Key Types - ThreatIntel & YARA

### 1. Edge Receives Request
```
Client → Edge: GET http://example.com/api
```

### 2. Extract Upstream ID
```rust
// crates/synvoid-mesh/src/mesh/proxy.rs:extract_upstream_id()
upstream_id = format!("http://{}:{}", host, port)
// Result: "http://example.com:80"
```

### 3. Query for Providers
```rust
// crates/synvoid-mesh/src/mesh/proxy.rs:get_providers_for_upstream()
transport.send_route_query(upstream_id)
// Returns: Vec<ProviderInfo> from DHT
```

### 4. DHT Lookup
```rust
// crates/synvoid-mesh/src/mesh/topology.rs:find_verified_upstreams_for_site()
record_store.get_all_records()
    .filter(|r| r.key.starts_with("verified_upstream:"))
    .filter(|r| r.value.upstream_id == site)
// Returns all origins verified for this domain+port
```

### 5. Weighted Random Selection
```rust
// crates/synvoid-mesh/src/mesh/proxy.rs:weighted_shuffle_providers()
// Providers shuffled by score for load balancing
// Higher score = more likely to be selected first
```

### 6. Route to Origin
```rust
transport.proxy_http_request(peer_node_id, &target_url, req)
```

## VerifiedUpstream Structure

```rust
// crates/synvoid-mesh/src/mesh/dht/mod.rs
pub struct VerifiedUpstream {
    pub upstream_id: String,        // "http://example.com:80"
    pub origin_node_id: String,     // Which origin has this
    pub upstream_url: String,      // Backend URL on origin
    pub org_id: Option<String>,
    pub global_node_id: String,    // Which global verified
    pub global_node_signature: Vec<u8>,
    pub registered_at: u64,
    pub expires_at: u64,
}
```

## Key Discovery Patterns

### Finding All Origins for a Site
```rust
// 1. Check local mesh.local_upstreams (domain match)
local_origins = local_upstreams.get(site).map(|info| info.owner_node_id)

// 2. Query DHT for verified_upstream records
verified = find_verified_upstreams_for_site(site)

// 3. Merge results
all_origins = local_origins ∪ verified.map(|v| v.origin_node_id)
```

### Origin Registration Flow
```
Origin → Global: UpstreamAnnounce
Global stores: verified_upstream:{upstream_id} → VerifiedUpstream{origin_node_id, ...}
```

## Common Issues

### Issue: Route Query Returns No Providers

**Causes**:
1. `extract_upstream_id` produces wrong format (should be `http://host:port`)
2. Origin not registered with global (no VerifiedUpstream in DHT)
3. upstream_id mismatch between edge query and origin registration

**Debug**:
```bash
# Check DHT records
curl -s http://localhost:8080/api/mesh/dht/records | jq '.[] | select(.key | startswith("verified_upstream"))'
```

### Issue: Origin Not Found in Route Query

**Causes**:
1. Origin not connected to mesh
2. Announce not sent to global nodes
3. `mesh.local_upstreams` key doesn't match query upstream_id

**Debug**:
```rust
// Check what upstream_id is being announced
tracing::debug!("Announcing upstream: {}", upstream_id);

// Check local_upstreams keys
tracing::debug!("Local upstreams: {:?}", local_upstreams.keys());
```

## Architecture Notes

### Origin Local Backend Selection

### Origin Local Backend Selection

When origin receives proxied request:
- `proxy_http_request` sends raw HTTP to origin
- **Gap**: Origin has no handler to route based on Host header to local backend
- Origin needs to: parse Host header → lookup `mesh.local_upstreams` → forward to correct backend

### Port Validation

- DHT key includes port: `http://example.com:80` ≠ `http://example.com:8080`
- `supported_ports` field in config for advertising (not required for routing)
- Edge can reject port scans early if origin advertises supported ports

## Capability Attestation (W2.8)

Global nodes can attest to other nodes' capabilities after verification.

### DHT Key Type

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `capability_attestation:{node_id}:{capability}` | Signed attestation of node capability | 24 hours |

### Capability Types

- `dns_server` - Node runs a DNS server
- `waf` - Node has WAF enabled
- `edge_proxy` - Node can proxy requests
- `origin` - Node has registered upstreams

### Attestation Flow

```
Node claims capability → Global verifies → Global signs attestation → Stored in DHT
```

### Verification Functions

```rust
// crates/synvoid-mesh/src/mesh/transport.rs

// Global node attests a node's capability
attest_capability(node_id, capability)

// Verify a node has a claimed capability (checks actual state)
verify_node_capability(peer_state, capability)

// Retrieve attestation from DHT
get_capability_attestation(node_id, capability)

// Verify attestation signature against known global keys
verify_capability_attestation(attestation)
```

### Implementation Files

| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/dht/capability_attestation.rs` | Attestation struct and verification |
| `crates/synvoid-mesh/src/mesh/dht/capability_access.rs` | `CapabilityAccessVerifier` for DHT write authorization |
| `crates/synvoid-mesh/src/mesh/dht/keys.rs` | `CapabilityAttestation` DHT key type |
| `crates/synvoid-mesh/src/mesh/transport.rs` | `attest_capability()`, `verify_node_capability()` |

**DHT Write Authorization**: `CapabilityAccessVerifier` is called in `store_record()` before allowing a node to store a capability-gated record (YARA rules, ThreatIntel indicators). Use `RecordStoreManager::set_capability_verifier()` to enable.

## Edge Node PoW Authentication (W2.6)

Edge nodes authenticate with BOTH Ed25519 signature AND Proof-of-Work. PoW is **required**, not optional.

### Authentication Flow

```
Edge connects → Ed25519 signature validation → PoW validation (BOTH required) → Authenticated
```

**Note**: Edge nodes must provide BOTH `pow_nonce` AND `pow_public_key`. If either is missing, authentication fails.

### Optional: Edge Node Attestation

Edge nodes can optionally be attested by global nodes for enhanced trust:

1. Global node creates `EdgeAttestation` record in DHT at `edge_attestation:{node_id}`
2. Attestation signed by global node's Ed25519 key over `edge:{node_id}:{global_node_id}:{attested_at}`
3. Other nodes verify via `validate_edge_node_with_attestation()` in `crates/synvoid-mesh/src/mesh/peer_auth.rs`

### PoW Validation

```rust
// crates/synvoid-mesh/src/mesh/peer_auth.rs

validate_edge_node_pow(pow_public_key, pow_nonce) {
    // 1. Derive node_id from pow_public_key using NodeId::from_public_key()
    // 2. Verify PoW using NodeId::verify_pow(nonce)
    // 3. If valid, node is authenticated
}
```

### Parameters

- `pow_public_key`: 32-byte Ed25519 public key (required)
- `pow_nonce`: Nonce that makes the PoW solution valid (required)

### Implementation Files

| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/peer_auth.rs` | `validate_edge_node_pow()`, `validate_peer_role()` with PoW + certificate + Raft attestation params |
| `crates/synvoid-mesh/src/mesh/transport.rs` | Pass `pow_nonce`, `pow_public_key`, `member_certificate`, `org_public_key`, `raft_attestation` to validation |
| `crates/synvoid-mesh/src/mesh/discovery.rs` | Pass PoW credentials and attestation from peer hello |

## Multi-Genesis Key Support (W2.2)

The system supports multiple authorized genesis keys for key rotation and disaster recovery.

### Config Structure

```rust
// crates/synvoid-mesh/src/mesh/config.rs
pub struct GenesisKeyConfig {
    pub authorized_genesis_keys: Vec<String>,  // Multiple authorized public keys
    pub previous_genesis_key_base64: Option<String>,  // For rotation
    pub rotation_sequence: u32,
    // ...
}
```

### Authorization Methods

```rust
// crates/synvoid-mesh/src/mesh/config_identity.rs

// Check if genesis key is authorized
is_genesis_key_authorized(public_key: &str) -> bool

// Add a key to authorized list
authorize_genesis_key(public_key: String)

// Remove a key from authorized list
revoke_genesis_key(public_key: &str)
```

### Key Rotation Flow

1. New genesis key generated
2. `GenesisKeyTransition` announced via DHT: `genesis_key_transition:{sequence}`
3. All global nodes update `previous_genesis_key_base64`
4. Old key retained for verification during transition

### Behavior

- Empty `authorized_genesis_keys` = deny all remote immutable records (secure default)
- Non-empty list = genesis key must be in the list
- Key rotation tracked via `rotation_sequence` and `GenesisKeyTransition` DHT records

## Mesh Transport Lifecycle (Iterations 68–76, updated 86)

### Adding a New Background Task

1. Determine the task class:
   - `CriticalService` — core mesh functionality
   - `RestartableBackground` — periodic maintenance
   - `BoundedChild` — per-connection work
   - `OneShotStartup` — initialization-only tasks (Iteration 84)

2. For transport-owned tasks, spawn via the task group in `MeshTransport::start_with_policy()`:
```rust
let mut shutdown_rx = group.shutdown_receiver();
group.spawn_background("task_name", async move {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = interval.tick() => { /* work */ }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }
    }
});
```

3. For topology/DHT maintenance tasks (Iteration 86), use `build_background_tasks()` + `register_background_specs()`:
```rust
// After mesh startup succeeds
let specs = topology.build_background_tasks();
group.register_background_specs(specs);
let dht_specs = dht_routing_manager.build_background_tasks();
group.register_background_specs(dht_specs);
```

4. NEVER use bare `tokio::spawn` for long-lived tasks in transport code.

### Lifecycle API

- `MeshTransport::start_with_policy(policy)` — primary staged transactional startup via `MeshStartupStage` with explicit `MeshStartupPolicy`
- `MeshTransport::start()` — compatibility wrapper using `MeshStartupPolicy::default()` (all-optional)
- `MeshTransport::shutdown_with_timeout(timeout)` — bounded shutdown returning truthful `MeshShutdownReport`; all phases share one deadline
- `MeshTransport::recover_failed_state(timeout)` (Iterations 72, 74, 75) — recovery from `Failed` state: acquires lifecycle lock, re-runs cleanup, **applies retained residue via `restore_and_verify_peer_logical_state()` before clearing** (Iteration 75), verifies no owned resources remain, transitions to `Stopped`. Recovery outcomes tracked via `RecoveryReport`.
- `MeshTransport::subscribe_exits()` — stable exit subscription (valid before `start()`, survives task group replacement)
- `MeshTransport::lifecycle_state()` — query current state
- `MeshTransport::rollback_and_return()` (Iteration 71) — rollback a failed startup and return an appropriate error, constructing `StartupRollbackFailed` when cleanup is incomplete
- `MeshTransport::verify_rollback_complete()` (Iteration 71) — check post-rollback invariants after rollback

### Failed State Recovery (Iterations 72, 74)

`Failed` means incomplete rollback — some resources may still be owned. **`can_start()` only allows `Stopped`, not `Failed`.** The transport must recover before it can restart.

- `recover_failed_state(timeout)` acquires lifecycle lock, re-runs cleanup, **applies retained residue via `restore_and_verify_peer_logical_state()` before clearing** (Iteration 75) — restores topology and DHT entries, closes connections, retains partially restored peers in residue for subsequent attempts
- If recovery fails (timeout or verification issues), transport transitions back to `Failed`
- Multiple recovery attempts are safe
- Recovery outcomes tracked via `RecoveryReport` (Iteration 74)

### Staged Startup/Rollback

`MeshStartupStage` owns every task and resource from a single startup attempt. On failure, `rollback_and_return()` (Iteration 71) centralizes rollback error propagation — it calls `rollback_startup()`, then `verify_rollback_complete()`, merges verification issues into the report before `finish_failed_startup()`, and constructs `StartupRollbackFailed` when cleanup is incomplete.

- Peer resources tracked via `StagedPeerResource` with exact mutation metadata (`session_id`, `node_id`, `topology_existed_before`, `connection_inserted`, `session_task_created`, `dht_registration_created`)
- **`restore_and_verify_peer_logical_state()` (Iteration 75)**: combined helper used by both `rollback_startup()` and `recover_failed_state()` for restoration + verification in one call
- Topology snapshots (`StagedTopologySnapshot`) capture native `PeerState` (Iteration 74 — replaces lossy `MeshPeerInfo` + `PeerStatus`); rollback uses `restore_peer_state()` for exact prior state; `restore_peer_state()` bidirectionally updates `global_nodes` (Iteration 75)
- Selective peer-session ownership via `HashMap<String, PeerSessionTask>` keyed registry; rollback targets only staged sessions
- DHT routing entries restored from `DhtPeerSnapshot` via `restore_peer()` using force-replacement (`force_restore_contact()`) — unconditionally replaces existing contacts (Iteration 75)
- `rollback_startup()` stops all peer sessions and auxiliary tasks **before** logical restoration (Iteration 75)
- `tasks_aborted` derived from `MeshTaskExitReason::Aborted` exit metadata (authoritative, not `active_count()`)
- `commit_startup()` logs warning when replacing non-empty old task group
- Shared rollback deadline (`startup_rollback_timeout_secs`, default 15s)
- `verify_rollback_complete()` checks post-rollback invariants
- **Clean rollback** → `Stopped` state (safe to retry immediately)
- **Error rollback** → `Failed` state (requires `recover_failed_state()` to recover)

The lifecycle operation lock (`lifecycle_op: tokio::sync::Mutex<()>`) serializes start/stop transitions.

### MeshStartupPolicy

Controls required vs optional bootstrap:
- `require_seed_connectivity` (default: false)
- `require_configured_peers` (default: false)
- `require_dht_bootstrap` (default: false)

Default is all-optional (degraded startup allowed). A required failure triggers rollback.

**Iteration 86**: `build_mesh_supervision_policy()` returns `Result<Option<MeshSupervisionPolicy>, String>` — rejects `restart_enabled = true` with an error. This is a hard error, not a warning override.

### MeshStartupReport

Returned after startup:
- `degraded_reasons: Vec<String>` — non-fatal reasons for degraded state
- `connected_seed_count: usize` — seeds connected during startup
- `connected_configured_peer_count: usize` — configured peers connected
- `dht_bootstrapped: bool` — DHT bootstrap status

### Stable Exit Subscription

`mesh_exit_tx: broadcast::Sender<MeshTaskExit>` on `MeshTransport` survives task group replacement. Task groups are created with `MeshTaskGroup::new_with_forward_and_id_gen(exit_tx, id_gen)` to forward exits to the stable sender with globally unique task IDs. `subscribe_exits()` is synchronous and valid before `start()`.

### Task ID/Dedup

`MeshTaskIdGenerator` provides globally unique `MeshTaskId(u64)` across task-group generations. Each `MeshTransport` owns one `Arc<MeshTaskIdGenerator>` and passes it to every new `MeshTaskGroup`. Broadcast delivery is for runtime observation only; join-returned exit is authoritative for shutdown reports. No duplicate accounting between broadcast and join.

### Handshake/Session Ownership Split (Iteration 72)

- Handshake children: bounded, short-lived, semaphore-limited (in `JoinSet`)
- Peer sessions: long-lived, stored in `peer_sessions: HashMap<String, PeerSessionTask>` keyed by `session_id` (Iteration 72 — replaces global `JoinSet<()>`)
- Rollback targets only staged sessions via the keyed registry
- Shutdown drains peer sessions after closing connections

### Truthful Shutdown Report

`MeshShutdownReport` includes:
- `peers_at_shutdown_start` — captured at shutdown begin
- `remaining_peers` — measured after connection close/drain
- `drained_peer_sessions` / `aborted_peer_sessions` / `failed_peer_sessions` — from session drain
- `accept_loop_report: Option<MeshAcceptLoopReport>` (Iteration 74) — `None` when stale or unavailable, `Some` when from current generation
- `MeshAcceptLoopReport` includes `generation: u64` (Iteration 72) — distinguishes reports across startup cycles; reset at each `start_with_policy()`

### Worker Integration

- `ManagedMeshService::subscribe_critical_exits()` delegates to stable `subscribe_exits()`
- `is_running()` reads `running_projection: Arc<AtomicBool>` — lock-free, no Tokio contention
- `MeshServiceExit(MeshTaskExit)` variant on `WorkerShutdownCause` for mesh task failures
- **Worker mesh supervision pipeline** (Iteration 82–84): fully implemented in `src/worker/mesh_supervision.rs`. See [Worker Mesh Supervision](#worker-mesh-supervision-iterations-82-84) below.

### Iteration 73 Lifecycle Semantics

**Hard rejection of non-empty task group replacement**: `commit_startup()` returns `LifecycleConflict` error if old task group is non-empty (checked before `std::mem::replace`). This prevents orphaning running tasks during lifecycle transitions.

**Pre-mutation snapshots for topology and DHT**: The outbound `connect_to_peer` path captures state before mutation:
- `self.topology.get_peer(&node_id)` before `self.topology.add_peer(...)`
- `rm.snapshot_peer(&peer_node_id)` before `self.dht_on_peer_connected(...)`

These snapshots feed into `StagedPeerResource` for precise rollback.

**Explicit DHT mutation tracking**: `DhtPeerMutation` enum (`None`, `Created`, `Replaced(snapshot)`, `UpdatedInPlace(snapshot)`) is derived from pre-mutation snapshot comparison, not from `rm.is_enabled()` alone. This ensures rollback can accurately restore prior DHT state.

**Retained failed-startup residue**: When rollback is incomplete, `rollback_and_return()` stores `FailedStartupResidue` on the transport — consumed and cleared by `recover_failed_state()`.

**Full recovery with timeout consumption**: `recover_failed_state(timeout)` derives a deadline from the timeout parameter, uses it for bounded operations (session drain, auxiliary task cleanup), and performs full verification (task group empty, sessions empty, auxiliary tasks empty, connections empty, residue cleared). All abort calls are followed by `.await` to reap task resources. **Iteration 77**: `session_errors` from peer session drain are merged into `issues` for recovery diagnostics.

**Session exit classification**: `PeerSessionExitReason` enum classifies peer session exits (`Clean`, `ConnectionClosed`, `Cancelled`, `Error(String)`, `Panic(String)`, `Aborted`). `PeerSessionExit` struct carries the reason with a `generation` counter to prevent stale completions from removing newer entries.

**Auxiliary task ownership**: Preflight tasks tracked in `auxiliary_tasks: HashMap<MeshTaskId, AuxiliaryTask>` during steady-state (`AuxiliaryTaskKind::PreflightRoute`). During startup, preflight runs as a bounded child in the staged task group. Shutdown aborts and awaits all auxiliary tasks.

**Shutdown report extension**: `MeshShutdownReport.failed_peer_sessions: usize` tracks panic/error session exits (distinct from `aborted_peer_sessions`).

**Session reaper implementation (Phases 15–18, Iteration 74 hardening)**: After lifecycle commit, `spawn_session_reaper()` runs as a critical background task on the transport's task group. It subscribes to `session_exit_tx: broadcast::Sender<PeerSessionExit>` and watches for session exit events. On receiving an exit, it checks the `generation` field: if `task.generation == exit.generation` (or exit generation is 0 for legacy paths), the entry is removed from `peer_sessions`. Stale entries (generation mismatch) are skipped with debug logging. **Cancellation-aware** (Iteration 74, Phase 14): uses `tokio::select!` with `session_reaper_shutdown: watch::Sender<bool>` signal for clean shutdown exit. **Handle awaiting outside lock** (Phase 15): after removing an entry, the `JoinHandle` is awaited **outside** the `peer_sessions` lock. **Broadcast lag recovery** (Phase 17): on `RecvError::Lagged`, scans `peer_sessions` for `is_finished()` handles and removes/joins them outside the lock. The reaper exits cleanly when the broadcast channel closes (transport dropped).

**Auxiliary task session binding and rollback cancellation (Phase 14)**: Each `AuxiliaryTask` carries an optional `session_id` field linking it to the peer session it was spawned for. During rollback, `rollback_startup()` collects session IDs from `StagedPeerResource.session_task_id` and calls `cancel_auxiliary_tasks_for_sessions(&session_ids)`. This filters `auxiliary_tasks` by matching `task.session_id`, then aborts and awaits each matching task. Ensures preflight queries do not outlive the peer sessions they were spawned for.

**Auxiliary task reaper (Iteration 74, Phase 20–21)**: `spawn_auxiliary_reaper()` runs as a critical background task after lifecycle commit, mirroring the session reaper's design. Auxiliary tasks signal completion via `AuxiliaryTaskExit` events on `auxiliary_exit_tx: broadcast::Sender<AuxiliaryTaskExit>`. The reaper removes completed entries from `auxiliary_tasks` and awaits handles **outside** the lock. Uses `tokio::select!` with the same `session_reaper_shutdown` signal for clean shutdown exit. Broadcast lag recovery scans for `is_finished()` handles.

**Accept-loop generation verification (Phase 19, Iteration 74)**: `MeshTransport` carries `startup_generation: Arc<AtomicU64>` (initialized to 0). Each `start_with_policy()` increments it via `fetch_add(1, SeqCst) + 1` before any startup phases run, and writes the new generation into the accept-loop report. At shutdown, `shutdown_with_timeout()` compares `accept_loop_report.generation` against the current `startup_generation`. **Iteration 74 (Phase 29–30)**: stale reports are suppressed — `MeshShutdownReport.accept_loop_report` is `None` when the report is stale or no startup has occurred, preventing misattributed handshake counts.

**One global session-generation domain (Iteration 74, Phase 25)**: All sessions — both outbound (startup-created) and inbound (accept-loop) — now use a single `session_generation: Arc<AtomicU64>` counter on `MeshTransport`. This replaces the previous split where outbound sessions used the stage counter and inbound sessions used a separate zero-based counter. Outbound sessions call `self.session_generation.fetch_add(1) + 1` before spawning; inbound sessions do the same in `handle_incoming_peer_connection()`. The unified domain ensures generation values are globally unique across all session origins.

**Generation field wiring from stage to PeerSessionTask (Phase 18)**: When a peer session is created during startup, `next_session_generation()` is called before spawning the session task. The same generation value is used for both `PeerSessionTask.generation` (used by the session reaper) and `StagedPeerResource.session_generation` (used by rollback). This ensures the reaper and rollback share consistent generation semantics — a session created during startup A cannot be erroneously reaped by startup B's reaper.

### Iteration 74 Lifecycle Semantics

**Shared `restore_peer_logical_state()` helper**: Used by both `rollback_startup()` and `recover_failed_state()` for deduplicated topology/DHT restoration. Restores topology via `restore_peer_state()` (native `PeerState`, not lossy conversion) and DHT via `restore_peer()` from `DhtPeerSnapshot`. Idempotent. **Iteration 75**: Combined into `restore_and_verify_peer_logical_state()` which adds verification in the same call.

**Lossless DHT snapshots**: `DhtPeerSnapshot` expanded (Iteration 74, Phase 10) to capture all `PeerContact` fields. **Iteration 75**: Now stores `pub contact: PeerContact` (a clone of the native `PeerContact`) instead of individual fields — eliminates field drift entirely. `restore_peer()` uses `force_restore_contact()` which unconditionally replaces existing contacts.

**DhtPeerMutation simplified**: `Replaced` and `UpdatedInPlace` collapsed into single `Previous(DhtPeerSnapshot)` variant (Iteration 74, Phase 9). Both cases carry the same prior-state snapshot for lossless restoration.

**Native topology restoration**: `StagedTopologySnapshot` now stores native `PeerState` (not `MeshPeerInfo` + `PeerStatus`). Rollback uses `restore_peer_state()` instead of lossy conversion.

**Residue application during recovery**: `recover_failed_state()` now applies `FailedStartupResidue` via `restore_and_verify_peer_logical_state()` before clearing (Iteration 75) — restores topology and DHT entries, closes connections, retains partially restored peers in residue for subsequent attempts.

**Session reaper cancellation-awareness**: Uses `tokio::select!` with `session_reaper_shutdown: watch::Sender<bool>` signal (Iteration 74, Phase 14). Handles are awaited **outside** the `peer_sessions` lock (Phase 15). Broadcast lag recovery scans for `is_finished()` handles (Phase 17).

**Auxiliary task reaper**: `spawn_auxiliary_reaper()` runs as critical background task (Iteration 74, Phase 20–21). `AuxiliaryTaskExit` type for exit events. Same `select!` + lag-recovery pattern as session reaper. Handles awaited outside lock.

**One global session-generation domain**: `session_generation: Arc<AtomicU64>` on `MeshTransport` used by both outbound (startup-created) and inbound (accept-loop) sessions (Iteration 74, Phase 25). Replaces split stage/zero counters for globally unique generations.

**Accept-loop report freshness**: `MeshShutdownReport.accept_loop_report` is now `Option<MeshAcceptLoopReport>` (Iteration 74, Phase 29–30). Stale reports (generation mismatch or no prior startup) are `None` instead of potentially misattributed counts.

**RecoveryReport**: Internal accounting struct (Iteration 74, Phase 35) tracking `tasks_joined`, `sessions_joined`, `auxiliary_joined`, `topology_restored`, `dht_restored`, `errors`.

### Iteration 75 Lifecycle Semantics

**Force-replacement DHT restoration**: `DhtRoutingManager::restore_peer()` now returns `Result<(), String>` and uses `RoutingTable::force_restore_contact()` which unconditionally replaces existing contacts. No more silent failures on full buckets.

**Complete PeerContact snapshot**: `DhtPeerSnapshot` now stores `pub contact: PeerContact` (a clone of the native `PeerContact`) instead of individual fields. This eliminates field drift — any future `PeerContact` additions are automatically captured. `restore_peer()` inserts the contact with all fields from the snapshot.

**Topology secondary-index restoration**: `restore_peer_state()` now bidirectionally updates `global_nodes` — inserts when global, removes when non-global. `remove_peer()` also clears `global_nodes` to prevent stale entries.

**Teardown-before-restoration ordering**: `rollback_startup()` stops all peer sessions and auxiliary tasks **before** logical restoration, preventing late writes from invalidating restored state.

**Combined restore-and-verify**: `restore_and_verify_peer_logical_state()` combines restoration and verification in one call, ensuring atomicity. Used by both `rollback_startup()` and `recover_failed_state()`.

**Residue retention through verification failure**: Failed peers are retained in `FailedStartupResidue` for retry. `rollback_and_return()` stores only unresolved peers (not all staged peers) in the residue. Successfully restored peers do not pollute the residue.

**Session-local stream handler ownership**: `peer_message_loop()` uses a `JoinSet` for per-stream handlers. Handlers are reaped during the session, capacity-limited via `max_concurrent_peer_streams` config (default 32), timeout-wrapped via `peer_message_timeout_secs` (default 30s), and drained before session exit.

**`PeerStreamDrainReport`**: New type tracking stream drain statistics: `drained_streams`, `aborted_streams`, `timed_out_streams`.

**Worker mesh supervision**: implemented in Iteration 82–83. See dedicated section below.

### Failure Injection Hooks (Phase 20)

Test-only (`#[cfg(test)]`) failure injection for deterministic startup testing:

```rust
transport.set_startup_failure_hook(|point| match point {
    StartupFailurePoint::BeforeLifecycleCommit => Err("injected failure".into()),
    _ => Ok(()),
});
```

Hook checks at 6 phases in `start()`. `BeforeLifecycleCommit` (renamed from `AfterLifecycleCommit`) runs before state publication. Returns `Err` → rollback triggered (post-accept) or error propagated (pre-accept).

## Forced-Cleanup Corrective Pass (Iterations 76–77)

Iteration 76 corrects three classes of bugs that survived Iteration 75 and
adds mechanical guardrails to prevent regression. The full architecture
inventory lives in `architecture/mesh_transport_lifecycle.md`; this section
summarizes the contracts agents should follow when editing mesh lifecycle
code.

### Part A — Always finalize `MeshTaskGroup`

`rollback_startup()` and `recover_failed_state()` MUST always call
`MeshTaskGroup::join_all(remaining(deadline))`. A zero remaining budget
changes cleanup from drain to forced abort — it never permits skipping
ownership finalization. The pre-fix call site did
`if task_remaining.is_zero() { Vec::new() }`, which left tasks orphaned in
the registry without exit reporting. **Never reintroduce that skip.**

`join_all(Duration::ZERO)` itself takes the zero-budget branch internally
(`handle.abort()` + `handle.await` + synthetic `Aborted` exit). The
contract is verified by `tests/mesh_task_ownership_guard.rs` and
`tests/mesh_startup_rollback.rs`.

### Part B — Cooperative peer-session cancellation

`PeerSessionTask` carries a `shutdown_tx: watch::Sender<bool>` field. The
session's `peer_message_loop` selects on the cooperative signal via:

```rust
tokio::select! {
    biased;
    _ = shutdown_rx.changed() => { /* cooperative drain */ }
    stream = accept_bi() => { ... }
}
```

The `biased` keyword is mandatory — without it, a session starved by
incoming events would never observe the shutdown signal. A shared
`stop_peer_session_task()` helper classifies cleanup as
`PeerSessionStopOutcome::{Drained, ForcedParentAbort, Failed}`. Callers
should always send the cooperative signal **before** delegating to the
helper, and surface `ForcedParentAbort` as an incomplete-cleanup error
because the child stream-handler `JoinSet` was not drained through the
normal path.

### Part C — Safe DHT force restoration

`KBucket::force_replace` returns
`Result<Option<PeerContact>, ForceRestoreError>`. A full bucket with an
absent target fails closed with `BucketFullTargetAbsent` rather than
silently evicting an unrelated contact. Restoration paths must always
check the `Err` arm and surface the conflict rather than discarding it.
`RoutingTable::force_restore_contact` propagates the bucket-level error
as `Result<PeerContact, ForceRestoreContactError>`.

### Part D — DHT snapshot boundary

`DhtPeerSnapshot` is a **logical** snapshot. The `last_seen` field is
intentionally refreshed to `now()` during restore. Callers that need
recency must use the freshly-snapshotted `PeerContact` (which is
restored verbatim), not `DhtPeerSnapshot.last_seen`. Restoration
verification compares the post-restore `PeerContact` to the snapshot
via `peer_matches_snapshot()`.

### Part E — Refined stream timeout semantics

Two independent timeout fields replace the single per-message read timeout:

| Field | Default | Scope | Use case |
|-------|---------|-------|----------|
| `peer_message_timeout_secs` | 30s | Per-message read/framing | Bounds I/O stall on a single message |
| `peer_stream_total_timeout_secs` | 0 (disabled) | Total stream lifetime | Optional cap for long-lived streams |

`peer_message_loop` must apply the per-message read timeout via
`apply_read_timeouts` and the optional total stream lifetime timeout at
the JoinSet spawn level. Conflating the two timeouts is a regression.

**Iteration 77**: `apply_read_timeouts()` was removed. The wrapper was
misleadingly a total handler lifetime timeout when applied at the future
level. Per-message reads now use `read_exact_with_timeout()` and
`read_to_end_with_timeout()` directly, applying the timeout to the actual
I/O operation.

### Part F — Deadline-aware stream drain (Iteration 77)

`drain_peer_stream_handlers()` now uses `tokio::time::timeout(left, handlers.join_next()).await`
so no cooperative wait exceeds the supplied timeout. A hung stream handler can no longer block
session finalization indefinitely.

### Part G — Datagram handler ownership (Iteration 77)

`start_datagram_handler()` now owns incoming datagram handlers in a bounded `JoinSet`
(`max_concurrent_datagram_handlers`, default 32) instead of bare `tokio::spawn()`. This
closes the last visible detached mesh task path. The `JoinSet` is drained on shutdown.

### Part H — Forced abort classification (Iteration 77)

`stop_peer_session_task()` zero-budget branch now correctly returns `ForcedParentAbort`
instead of `Failed("parent cancelled")`. A new `force_abort_peer_session()` helper wraps
the cooperative abort + await pattern for callers that need to forcibly terminate a session.

### New Config Fields (Iteration 77)

| Field | Default | Description |
|-------|---------|-------------|
| `peer_stream_drain_timeout_secs` | 5 | Timeout for draining per-stream handlers before forced abort |
| `max_concurrent_datagram_handlers` | 32 | Bounded concurrency for datagram handler tasks |

### New Helpers (Iteration 77)

- `force_abort_peer_session()` — cooperative abort + await for forcibly terminating a session
- `classify_stream_join()` / `classify_forced_stream_join()` — classify join results for stream handlers
- `read_exact_with_timeout()` / `read_to_end_with_timeout()` — deadline-aware reads replacing the removed `apply_read_timeouts` wrapper

## Iteration 78 — HTTP Framing and Nested Ownership

Iteration 78 corrects HTTP-over-mesh request framing, closes the remaining edge-replica ownership exception, preserves nested failure diagnostics, and replaces simulated tests with implementation-level tests.

**HTTP-over-mesh contract**: One QUIC bidirectional stream carries exactly one HTTP/1.x request + response. Supported framing: headers via `\r\n\r\n`, fixed-length body via `Content-Length`. Rejected: chunked encoding (501), CONNECT/upgrade (503), pipelining, ambiguous Content-Length.

**Framing helpers** (in `transport_peer.rs`):
- `read_http_request_head()` — generic `AsyncRead` helper, enforces remaining-capacity header cap, idle + total deadlines, parses Content-Length/Transfer-Encoding
- `read_fixed_http_body()` — bounded fixed-body read with idle + total deadlines
- `parse_http_body_framing()` — strict Content-Length and Transfer-Encoding parser

**Config fields** (both `synvoid-mesh` and `synvoid-config` crates):
- `peer_http_header_total_timeout_secs` (default 30) — total header framing deadline
- `max_peer_http_body_bytes` (default 65536) — body size limit
- `peer_http_body_total_timeout_secs` (default 60) — total body framing deadline
- `peer_http_backend_idle_timeout_secs` (default 30) — backend response idle timeout

**Edge-replica ownership**: `RaftCommitNotification` refresh tasks now register as `AuxiliaryTaskKind::EdgeReplicaRefresh` in the auxiliary task registry, bounded and drained during shutdown/recovery. Edge-replica refresh tasks are capped at 8 concurrent (`MAX_CONCURRENT_EDGE_REPLICA_REFRESH`); excess tasks are dropped (fire-and-forget contract).

**Diagnostics**: `PeerSessionExit` now carries `stream_drain: PeerStreamDrainReport` with actual drain/abort/failure counts. `ChildTaskFailed` variant in `PeerSessionExitReason` surfaces non-zero drain failures. `MeshShutdownReport` carries `stream_handler_drain` aggregate field. `MeshTransport` tracks aggregate handler counters (`aggregate_handler_drained`, `aggregate_handler_aborted`, `aggregate_handler_failed`).

**Edge-replica deduplication**: Tasks are deduplicated by `(namespace, key_id)` via `dedup_key` field on `AuxiliaryTask`. Prevents duplicate edge-replica refresh tasks for the same key when multiple `RaftCommitNotification` events arrive concurrently.

**Config validation**: `max_peer_http_header_bytes >= 4` enforced at runtime. Serde tests (`http_framing_config_defaults` in `config.rs`) verify default values for all HTTP framing fields.

**Test visibility (Iteration 79)**: `stop_peer_session_task_for_test` adapter was removed entirely — module-local tests now call the private `stop_peer_session_task()` directly. `drain_peer_stream_handlers_for_test` and `drain_datagram_handlers_for_test` remain `pub(crate)`.

**Tests**: 13 HTTP framing unit tests, 1 real drain test, 23 guardrail assertions.

## Iteration 79 — HTTP Response Framing and Auxiliary Ownership Corrective Pass

Iteration 79 completes the HTTP-over-mesh framing contract with proper backend response framing, replaces substring-based upgrade detection with parsed header analysis, and centralizes auxiliary task spawning.

### Parts A-B: Backend HTTP Response Framing

Backend responses are now parsed with proper HTTP/1.1 framing instead of EOF-only detection:

- **`FramedHttpResponseHead`**: Parsed response head with `status_code: u16`, `content_length: Option<usize>`, `chunked: bool`, `connection_close: bool`
- **`HttpResponseFramingError`**: Typed error enum covering `HeaderTooLarge`, `HeaderFramingTimeout`, `MalformedStatusLine`, `InvalidStatusCode`, `InvalidContentLength`, `UnsupportedTransferEncoding`, `BackendClosedBeforeCompleteResponse`, `PrematureEof`, `BodyTooLarge`, `MalformedChunkedBody`, `Io`
- **`read_http_response_head()`**: Generic `AsyncRead` helper with idle/total timeouts. Enforces `max_peer_http_response_header_bytes` capacity
- **`read_fixed_http_response_body()`**: Reads exact Content-Length bytes with `max_peer_http_response_body_bytes` limit. Returns after declared body, ignoring any trailing bytes
- **`read_chunked_http_response_body()`**: Parses chunked Transfer-Encoding with trailer support. Enforces `max_peer_http_response_trailer_bytes`

**No-body response semantics**: HEAD requests, 1xx, 204, and 304 status codes produce empty bodies. The `is_no_body_status()` and `is_head` checks handle this before attempting body reads.

### Parts C-D: Request Metadata Parsing

- **`ParsedHttpRequestMeta`**: Header-only metadata extraction (method, target, host, upgrade flags). Bodies are not parsed — binary bodies no longer affect host/path extraction
- **`parse_http_request_meta()`**: Extracts method, target, host, and upgrade detection from raw header bytes only
- **Upgrade detection**: Uses exact parsed header names/tokens (`Connection` header + `Upgrade` value), not substring matching on lowercased full request bytes
- **Trailing byte rejection**: Requests with trailing bytes after headers and body are rejected

### Parts E-F: Auxiliary Task Ownership

- **`spawn_auxiliary_task()`**: Shared helper wrapping auxiliary task futures with `AuxiliaryTaskExit` publication, deduplication, and capacity gating
- **Edge-replica refresh**: Now uses `spawn_auxiliary_task()` with `AuxiliaryTaskKind::EdgeReplicaRefresh` and `dedup_key` for `(namespace, key_id)` deduplication
- **Deduplication**: Stale tasks with the same `dedup_key` are aborted AND awaited before inserting the replacement
- **Capacity**: Rejection happens before spawning, creating no orphan handles

### Part G: Test-Only API Surface

- `stop_peer_session_task_for_test`: **removed** (tests call private `stop_peer_session_task()` directly)
- `drain_peer_stream_handlers_for_test`: `pub` → `pub(crate)`
- `drain_datagram_handlers_for_test`: `pub` → `pub(crate)`

### HTTP-over-mesh Response Framing Contract

| Framing | Supported | Handling |
|---------|-----------|----------|
| Fixed-length (Content-Length) | Yes | `read_fixed_http_response_body()` reads exact bytes |
| Chunked Transfer-Encoding | Yes | `read_chunked_http_response_body()` with trailer support |
| Connection-close delimited | Yes | Reads until EOF, returns remaining bytes |
| No-body (HEAD, 1xx, 204, 304) | Yes | Skips body read entirely |

### Config Fields

| Field | Default | Description |
|-------|---------|-------------|
| `max_peer_http_response_header_bytes` | 8192 | Max response header size |
| `max_peer_http_response_body_bytes` | 65536 | Max response body size |
| `peer_http_response_header_total_timeout_secs` | 30 | Total header framing deadline |
| `peer_http_response_body_total_timeout_secs` | 60 | Total body framing deadline |
| `max_peer_http_response_trailer_bytes` | 4096 | Max chunked response trailer size |

## Iteration 80 — Response Sequence Parsing, Auxiliary Registration, and PrefixReader

Iteration 80 hardens HTTP response sequence handling (1xx informational responses, close-delimited bodies), introduces an atomic auxiliary task registration pattern, and adds a `PrefixReader` adapter for efficient chunked response parsing.

### Parts A-B: HTTP Response Sequence and Encoding

Backend responses may include informational responses (1xx) before the final response. `read_http_response_sequence()` reads response heads in a loop, consuming 1xx responses until a final response (status >= 200) is obtained. This prevents informational responses from being treated as the final response.

- **`read_http_response_sequence()`**: Generic `AsyncRead` helper. Reads `read_http_response_head()` in a loop. Yields each `FramedHttpResponseHead` for informational statuses (1xx). Terminates when status >= 200 is reached. Enforces `max_informational_response_count` (default 10) to prevent infinite loops from misbehaving backends.

**HttpVersion**: Enum (`Http10`, `Http11`) stored in `FramedHttpResponseHead`. Parsed from the response status line HTTP version field. Used for downstream protocol selection.

**HttpResponseBodyEncoding**: Enum (`None`, `FixedLength`, `Chunked`, `CloseDelimited`) stored in `FramedHttpResponseHead`. Determined during response head parsing:
- `None` — no-body status (HEAD, 1xx, 204, 304)
- `FixedLength` — valid `Content-Length` present
- `Chunked` — `Transfer-Encoding: chunked` detected
- `CloseDelimited` — no `Content-Length` or `Transfer-Encoding`; body read until connection close

Used to skip transforms for chunked responses and select the correct body read strategy.

**header_contains_token**: Case-insensitive helper for checking tokens in comma-separated header values. Used for `Connection: close` parsing in response headers. Performs case-insensitive token matching against a header value that may contain comma-separated tokens.

**ResponseBodyPrefixExceedsContentLength**: New error variant in `HttpResponseFramingError`. Returned when the body prefix consumed by `PrefixReader` exceeds the declared `Content-Length`, indicating a protocol violation.

### Part C: PrefixReader

**PrefixReader**: Internal adapter struct combining a prefix byte buffer with an async reader. Used by `read_chunked_http_response_body()` to consume `body_prefix` bytes before delegating to socket reads. The prefix contains bytes already read from the socket during response head/body framing. Implements `tokio::io::AsyncRead` by first draining the prefix buffer synchronously via `std::io::Read`, then forwarding reads to the inner async reader.

```rust
pub(crate) struct PrefixReader<R> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: R,
}
```

This avoids re-reading prefix bytes from the socket and keeps the chunked body parser operating on a contiguous byte stream.

### Part D: Atomic Auxiliary Registration

The auxiliary task registry now uses an atomic registration pattern to prevent races between deduplication and insertion.

**AuxiliaryRegistryEntry**: Enum in `lifecycle.rs` with two variants:
- `Reserved` — gated, not yet running. Created when `spawn_auxiliary_task()` acquires the registry slot. The actual future is pending submission to the task group.
- `Running` — active join handle. Set after the future is successfully spawned.

This two-phase pattern ensures that capacity checks, deduplication, and slot reservation are atomic with respect to concurrent auxiliary task spawns.

**auxiliary_submission_lock**: `Arc<tokio::sync::Mutex<()>>` on `MeshTransport`. Serializes the critical section of auxiliary task registration: deduplication check, capacity check, `Reserved` slot insertion, spawn, and upgrade to `Running`. Without this lock, two concurrent callers could both pass the capacity check and insert, exceeding the configured maximum.

```rust
// Registration flow (simplified)
let _guard = self.auxiliary_submission_lock.lock().await;
// 1. Check dedup_key — abort existing task if present
// 2. Check capacity — reject if at max
// 3. Insert Reserved entry
// 4. Spawn future, upgrade to Running(JoinHandle)
```

### Config Fields

| Field | Default | Description |
|-------|---------|-------------|
| `max_informational_response_count` | 10 | Max informational (1xx) responses before final response |

### New Helpers

- `read_http_response_sequence()` — reads response heads in a loop, consuming 1xx informational responses until status >= 200
- `header_contains_token()` — case-insensitive token check in comma-separated header values
- `PrefixReader` — internal adapter combining prefix byte buffer with async reader for chunked response parsing

## Iteration 81 — Mesh Transport Subsystem Closure

Iteration 81 closes the HTTP response parsing pipeline with persistent buffered parsing, a standalone close-delimited body reader, independent trailer accounting, strict response-head validation, and serialized auxiliary submission with documented lock ordering.

### Part A: Persistent Buffered Response-Sequence Parsing

`read_http_response_sequence()` now uses a single persistent `Vec<u8>` buffer across all response heads. Previously, leftover bytes after parsing an informational response could be re-read from the socket or lost; now partial heads after informational responses are preserved in the buffer and appended to on subsequent reads. This eliminates duplicated status/version/header parsing logic between leftover and socket paths.

- **`try_parse_http_response_head()`**: Pure parser taking `&[u8]`, returns `Option<(FramedHttpResponseHead, usize)>`. Returns `None` when the buffer does not yet contain a complete head (`\r\n\r\n` terminator not found). Returns `Some((head, consumed))` with the parsed head and number of bytes consumed. No I/O, no side effects.
- **`read_http_response_head()`**: Rewritten to call `try_parse_http_response_head()` after every `read_exact` into the persistent buffer. The buffer is grown as needed and never truncated between reads. This ensures a partially-read head from a previous iteration is completed by the next socket read.
- **`read_http_response_sequence()`**: Rewritten with one persistent `Vec<u8>` buffer shared across the entire loop. Informational response heads are parsed and consumed from the buffer; any trailing bytes after the final head are retained for body reading. No duplicated status/version/header logic — all parsing is delegated to `try_parse_http_response_head()`.

### Part B: Close-Dimited Body Reader

`read_close_delimited_http_response_body()` is extracted as a standalone function, separate from the fixed-length and chunked body readers.

- Enforces both per-read idle timeout (`body_idle_timeout`) and total body deadline (`body_total_timeout`)
- Returns error on body-limit overflow (`max_peer_http_response_body_bytes`) or timeout — never silently truncates output
- Reads until EOF (connection close), returning all bytes received
- Validates that total body size does not exceed the configured limit before returning

### Part C: Independent Trailer Byte Accounting

Trailer bytes in chunked responses are now tracked independently from body bytes.

- **`TrailerTooLarge { limit, observed }`**: New error variant in `HttpResponseFramingError`. Returned when the cumulative trailer byte count exceeds `max_peer_http_response_trailer_bytes`
- Trailer bytes are counted separately from body bytes after the zero-size chunk (`0\r\n\r\n`) terminator
- `max_peer_http_response_trailer_bytes` is enforced independently of `max_peer_http_response_body_bytes` — a large trailer does not consume body budget and vice versa

### Part D: Strict Response-Head Parsing

Response-head parsing is tightened with exact header-name splitting and strict status-line validation.

- **`parse_http_response_status_line()`**: Validates the HTTP version field is exactly `HTTP/1.0` or `HTTP/1.1` (case-sensitive). Status code must be exactly 3 ASCII digits in the range 100..=599. Returns `Err` on any deviation — no partial or lenient parsing.
- **`parse_http_response_framing()`**: Rewritten with exact `split_once(':')` on header names instead of substring or lowercased matching. Header names are compared case-insensitively after splitting. Prevents ambiguous parsing when header values contain colons.
- **`parse_http_body_framing()`**: Same pattern — `split_once(':')` for exact header-name extraction, case-insensitive comparison for `Content-Length` and `Transfer-Encoding`.

### Part E: Auxiliary Submission Serialized With Cleanup

Auxiliary task submission is now lifecycle-aware and serialized with shutdown/recovery cleanup.

- **`auxiliary_submission_allowed()`**: Helper checking `MeshTransportState` and `AuxiliaryTaskKind`. Returns whether submission is permitted in the current lifecycle state. Prevents auxiliary task spawning after shutdown has begun.
- **`spawn_auxiliary_task()`**: Rechecks lifecycle state under `auxiliary_submission_lock` before proceeding. The previous pattern checked state before acquiring the lock; a shutdown could begin between the check and the lock acquisition, resulting in a task being spawned into a draining registry.
- **Shutdown and recovery**: Both `shutdown_with_timeout()` and `recover_failed_state()` now acquire `auxiliary_submission_lock` before draining the auxiliary task registry. This serializes with concurrent `spawn_auxiliary_task()` calls and prevents new tasks from being registered during cleanup.
- **`AuxiliaryRegistryEntry::Reserved` removed**: Only the `Running` variant remains. The two-phase Reserved→Running pattern was necessary when the spawn could fail after reservation; with lifecycle-aware gating, rejection happens before any registry mutation.

### Part F: Lock Ordering

The following lock ordering is documented and enforced:

```text
lifecycle operation lock (lifecycle_op)
  -> auxiliary_submission_lock
    -> auxiliary_tasks lock
```

All code paths acquiring multiple locks must follow this order. `shutdown_with_timeout()` and `recover_failed_state()` acquire `lifecycle_op` first, then `auxiliary_submission_lock`, then drain `auxiliary_tasks`. `spawn_auxiliary_task()` acquires `auxiliary_submission_lock` only. Violations are caught by deadlock-detection CI runs.

### New/Modified Types

| Type | Location | Purpose |
|------|----------|---------|
| `parse_http_response_status_line()` | `transport_peer.rs` | Strict status-line parser (version, status code) |
| `try_parse_http_response_head()` | `transport_peer.rs` | Pure buffer-oriented head parser (no I/O) |
| `read_close_delimited_http_response_body()` | `transport_peer.rs` | Extracted close-delimited body reader |
| `HttpResponseFramingError::TrailerTooLarge` | `transport_peer.rs` | Independent trailer error with `limit`/`observed` fields |
| `auxiliary_submission_allowed()` | `transport.rs` | Lifecycle-state gate for auxiliary submissions |
| `MeshTransportState` | `transport.rs` | Simple enum for submission eligibility checks |

### Config Fields (unchanged)

| Field | Default | Description |
|-------|---------|-------------|
| `peer_http_backend_idle_timeout_secs` | 30 | Backend response idle timeout |
| `peer_http_response_body_total_timeout_secs` | 60 | Total body framing deadline |
| `max_peer_http_response_trailer_bytes` | 4096 | Max chunked response trailer size |

### Lock Ordering Invariant

```text
lifecycle_op -> auxiliary_submission_lock -> auxiliary_tasks
```

`shutdown_with_timeout()` and `recover_failed_state()` hold `lifecycle_op` while acquiring `auxiliary_submission_lock` and draining `auxiliary_tasks`. `spawn_auxiliary_task()` acquires only `auxiliary_submission_lock`. The ordering prevents deadlocks and ensures no auxiliary task is spawned during shutdown/recovery cleanup.

## Worker Mesh Supervision (Iterations 82–84)

Worker-level mesh supervision is implemented in `src/worker/mesh_supervision.rs`. The mesh service reports facts (start result, task exit, lifecycle state, shutdown report); the worker decides policy (ready, degraded, restart, shutdown, exit code).

### Config-Driven Policy (Iteration 84, updated Iteration 86)

`MeshSupervisionPolicy` is now derived from `MeshSupervisionConfig` (TOML-deserializable in `crates/synvoid-config/src/mesh.rs`) via `build_mesh_supervision_policy()`. Returns `None` when mesh is disabled — no observer, coordinator, startup task, or decision channel is created. **Iteration 86**: Returns `Result<Option<MeshSupervisionPolicy>, String>` — rejects `restart_enabled = true` with an error (restart is not implemented and must not be configured).

```rust
pub fn build_mesh_supervision_policy(
    mesh_enabled: bool,
    config: &MeshSupervisionConfig,
) -> Result<Option<MeshSupervisionPolicy>, String>
```

Restart is disabled by default: `restart_enabled=false` → `restart_limit=0`. `MeshFailureAction::RestartMesh` is treated as `ShutdownWorker` when restart is not enabled.

### Required vs Optional Startup (Iteration 84)

- **Required mesh**: `start_mesh_generation()` is awaited inline before the worker sends its ready signal. Worker startup blocks on mesh readiness.
- **Optional mesh**: Mesh starts asynchronously; worker proceeds without waiting.

### Critical Observer/Coordinator (Iteration 84)

Both `mesh_exit_observer` and `mesh_supervision_coordinator` are registered as `spawn_critical` (not `spawn_background`). A critical exit triggers the shutdown pipeline rather than being silently ignored.

### Supervision Pipeline

The pipeline consists of three components wired by the composition root:

1. **Observer** (`run_mesh_exit_observer`): Receives mesh exit events from the broadcast channel, handles lag/closure explicitly, forwards typed `MeshSupervisionEvent` to the coordinator. Registered in `WorkerTaskRegistry` for lifecycle management.
2. **Coordinator** (`MeshSupervisionCoordinator`): Receives events from the observer, applies event-level status transitions **before** consulting the pure policy classifier, applies budget gating, and produces typed `MeshSupervisorDecision` for the composition root.
3. **Composition root**: Processes decisions (degrade, restart, shutdown) in the supervision select loop.

### Authoritative Status Allocation

A single `WorkerMeshStatus` (`Arc<RwLock<WorkerMeshStatus>>`) is shared between the observer and coordinator. The composition root clones this `Arc` for its own reads. The coordinator writes via `apply_mesh_event_to_status()` and `apply_mesh_decision_to_status()`.

### Event-Level Transitions Before Policy Decisions

The coordinator applies event-level status mutations (`apply_mesh_event_to_status`) **before** calling the pure policy classifier (`decide_mesh_action`). This ensures the `WorkerMeshPhase` snapshot used by the policy reflects the event that just arrived. A separate decision-level mutation (`apply_mesh_decision_to_status`) is applied after the policy returns.

### Pure Policy Classifier: `decide_mesh_action()`

```rust
pub fn decide_mesh_action(
    policy: &MeshSupervisionPolicy,
    phase: &WorkerMeshPhase,   // snapshot taken after event-level transition
    event: &MeshSupervisionEvent,
    worker_shutdown_started: bool,
) -> MeshSupervisorDecision
```

Operates on `WorkerMeshPhase` snapshots — not the live `WorkerMeshStatus` reference. The coordinator takes a `status.phase` snapshot after applying the event, then passes it to this pure function. This makes the policy decision deterministic and testable without I/O.

### `MeshSupervisionPolicy`

**Iteration 84**: Policy is now config-driven via `MeshSupervisionConfig`. Use `build_mesh_supervision_policy()` instead of `MeshSupervisionPolicy::required()` / `MeshSupervisionPolicy::optional()`.

| Field | `required()` default | `optional()` default | Purpose |
|-------|---------------------|---------------------|---------|
| `required` | `true` | `false` | Whether mesh participation is required |
| `startup_failure` | `ShutdownWorker` | `Degrade` | Action on startup failure |
| `critical_exit` | `ShutdownWorker` | `Degrade` | Action on critical task exit |
| `restartable_exit` | `Degrade` | `Degrade` | Action on restartable task exit |
| `restart_limit` | `0` | `3` | Max restart attempts in window |
| `allow_degraded_readiness` | `false` | `true` | Whether degraded mesh satisfies readiness |

**`allow_degraded_readiness`**: When `readiness_requires_mesh` is true, this field controls whether a degraded mesh still satisfies worker readiness. `required()` defaults to `false` (degraded mesh blocks readiness); `optional()` defaults to `true`.

### Typed Cause Conversion: `mesh_failure_to_worker_cause()`

Converts `MeshFailureCause` into `WorkerShutdownCause` preserving the specific mesh failure type:

| `MeshFailureCause` | → `WorkerShutdownCause` |
|---------------------|------------------------|
| `CriticalServiceExit(exit)` | `MeshServiceExit(exit)` |
| `StartupFailed(reason)` | `MeshStartupFailed(reason)` |
| `ShutdownTimeout { .. }` | `MeshShutdownIncomplete(msg)` |

### `MeshRestartExhausted`

The coordinator gates `RestartMesh` decisions against the `RestartBudget`. When the budget is exhausted, the coordinator downgrades to `ShutdownWorker(MeshFailureCause::StartupFailed("restart budget exhausted"))`. The composition root converts this to `WorkerShutdownCause::MeshRestartExhausted { attempts, last_error }` which is classified as fatal (`is_fatal_exit()` returns true). **Iteration 86**: `MeshRestartExhausted` is replaced by `MeshStartupFailed` in the RestartMesh handler since restart is disabled and `restart_enabled = true` is now rejected at config validation time.

### No Outer Timeout on Mesh Startup

Mesh startup (`start_with_policy()`) has no outer `tokio::time::timeout` wrapping it. Cancellation safety is handled by mesh-internal stage deadlines (`MeshStartupStage`). The composition root does not impose an additional timeout layer.

### Real Shutdown Deadline

The composition root computes a real deadline: `shutdown_deadline = shutdown_started_at + drain_timeout`. The `remaining_budget()` closure computes `shutdown_deadline.saturating_duration_since(Instant::now())` — not `state.start_time.elapsed()`. Incomplete mesh shutdown accumulates into the final cause via `merge_worker_shutdown_cause()`.

### Priority-Based Cause Accumulation: `merge_worker_shutdown_cause()`

When multiple shutdown causes arise during a single shutdown sequence, the highest-priority cause is retained:

| Priority | Cause |
|----------|-------|
| 1 (highest) | Process infrastructure (`ServerExitedUnexpectedly`, `CriticalTaskExit`, `RegistryExitChannelClosed`) |
| 2 | Critical runtime mesh failure (`MeshServiceExit`) |
| 3 | Startup/restart exhaustion (`MeshStartupFailed`, `MeshRestartExhausted`) |
| 4 | Incomplete mesh shutdown (`MeshShutdownIncomplete`) |
| 5 (lowest) | Expected shutdown (`SupervisorShutdown`, `ExternalStop`, `WorkerResize`) |

### MeshShutdownDisposition

`classify_mesh_shutdown_report()` maps `MeshShutdownReport` to a disposition:

| Disposition | Condition |
|-------------|-----------|
| `Clean` | No failed tasks, no remaining peers, no aborted sessions |
| `ForcedButComplete` | Aborted tasks/sessions present but no failures or remaining peers |
| `Incomplete(MeshFailureCause)` | Failed tasks, remaining peers, or failed peer sessions |

### Files

| File | Purpose |
|------|---------|
| `src/worker/mesh_supervision.rs` | Policy types, pure classifiers, coordinator, observer, pipeline creation, `build_mesh_supervision_policy()`, `start_mesh_generation()` |
| `crates/synvoid-config/src/mesh.rs` | `MeshSupervisionConfig` TOML-deserializable config |
| `src/worker/unified_server/mod.rs` | Composition root integration, decision processing, `remaining_budget()` |
| `src/worker/task_registry.rs` | `WorkerShutdownCause`, `SupervisionOutcome`, exit code derivation, `TaskClass::OneShot` |

## Iteration 86 — Background Task Registration and Config Validation

### Background Task Specs

`MeshBackgroundTaskSpec` (`lifecycle.rs`) is a declarative specification for mesh background tasks. Replaces imperative `start_background_tasks()` methods with a data-driven approach.

```rust
pub struct MeshBackgroundTaskSpec {
    pub class: MeshTaskClass,
    pub name: String,
    pub future: Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>,
}
```

**`build_background_tasks()`**: Implemented on both `MeshTopology` and `DhtRoutingManager`. Returns `Vec<MeshBackgroundTaskSpec>` describing tasks to be registered after mesh startup. Replaces `start_background_tasks()` which previously spawned tasks during construction.

**`register_background_specs()`**: Added to `MeshTaskGroup`. Accepts a `Vec<MeshBackgroundTaskSpec>` and registers each as a background task in the task group.

This ensures background tasks are owned by the task group from the moment they are registered, preventing detached tasks during startup rollback.

### YARA Broadcast Loop Extraction

`run_yara_broadcast_loop()` is extracted from inline logic in `init_mesh.rs`. The function:

- Takes ownership of YARA broadcast components (receiver, shutdown signal)
- Uses deadline-bounded drain to ensure no hung YARA operations block worker shutdown
- Returns a `YaraBroadcastReport` with drain statistics
- Is registered as a `RestartableBackground` task in `WorkerTaskRegistry`

### Configuration Validation

`validate_mesh_runtime_inputs()` is called during mesh init to validate configuration before constructing transport/topology/DHT objects. On validation failure, a `MeshConfigurationInvariant(String)` cause is returned on `WorkerShutdownCause`. This catches configuration invariant violations early, before any runtime objects are created.

### Config Rejection

`build_mesh_supervision_policy()` now returns `Result<Option<MeshSupervisionPolicy>, String>` — rejects `restart_enabled = true` with an error. This is a hard error, not a warning override, since restart is not implemented and must not be configured.

## Iteration 87 — DHT Routing Init in Startup, Generation-Support Bundles, YARA Metrics

### Part A: DHT Routing Initialization Moved Into Transactional Startup (Phase 3.5)

`DhtRoutingManager` initialization (routing table creation and seeding) is now part of the transactional `MeshStartupStage` rather than a separate worker-owned one-shot task. This ensures the routing table exists before any bootstrap phase that depends on it.

**New lifecycle integration**: `MeshStartupStage` now includes a `dht_routing_initialized: bool` field set to `true` after the routing manager is initialized. `MeshStartupReport` exposes this field for diagnostic consumption.

**`MeshStartupPolicy.require_dht_initialization`** (new field, default `false`): When `true`, a failure during DHT routing initialization is treated as a fatal startup failure (triggers rollback). When `false`, initialization failure is logged as a warning and recorded in `degraded_reasons`.

### Part B: Bootstrap Precondition Check

`dht_bootstrap_from_seeds()` now requires the routing table to exist before executing. If the routing manager has not been initialized, the bootstrap call is rejected with a clear error rather than silently panicking on a missing table. This is enforced by a precondition check at the top of the bootstrap path.

### Part C: Worker-Owned `MeshGenerationSupport` Bundles

The worker now constructs `MeshGenerationSupport` bundles that group generation-specific resources for lifecycle management. Each bundle captures:
- The generation counter value
- A generation-scoped cancellation token
- The mesh startup report (if available)

This ensures that generation-specific resources (e.g., background tasks, observer handles) are cleanly scoped and can be cancelled when a new generation starts.

When optional mesh degrades, the supervision loop calls `active_mesh_support.take()` to atomically cancel the generation's DNS/YARA support tasks and clear the bundle. This prevents generation-specific support work from continuing against a failed transport while leaving unrelated worker tasks running.

### Part D: `register_mesh_generation_support()` Return Type

`register_mesh_generation_support()` now returns `Result<MeshGenerationSupport, WorkerShutdownCause>` instead of `()`. The `MeshGenerationSupport` value contains the registered generation's cancellation token and metadata. Callers that need per-generation cleanup can hold the returned bundle.

### Part E: YARA Broadcast Metrics

New atomic counters for YARA broadcast operations:

| Counter | Meaning |
|---------|---------|
| `yara_mesh_broadcast_sent_total` | YARA rules broadcast to mesh peers |
| `yara_mesh_broadcast_received_total` | YARA rule broadcasts received from peers |
| `yara_mesh_broadcast_applied_total` | Received broadcasts successfully applied to local store |
| `yara_mesh_broadcast_dropped_total` | Received broadcasts dropped (dedup, parse error, capacity) |

### Part F: `YaraBroadcastReport.dropped` Field

`YaraBroadcastReport` now includes a `dropped: u64` field counting broadcasts that were received but not applied (due to dedup, parse failure, or capacity limits). This complements the existing `applied` and `failed` fields.

### Part G: `MeshStartupReport.dht_routing_initialized` Field

New field on `MeshStartupReport`:
- `dht_routing_initialized: bool` — set to `true` when `DhtRoutingManager` initialization completes successfully within the transactional startup stage

### Part H: `MeshStartupPolicy.require_dht_initialization` Field

New field on `MeshStartupPolicy`:
- `require_dht_initialization: bool` — when `true`, DHT routing initialization failure is fatal (triggers rollback); when `false` (default), failure is non-fatal (degraded mode)

### Part I: `DhtRoutingManager` New Methods

- `is_initialized() -> bool`: Returns whether the routing table has been created and seeded. Used by the bootstrap precondition check.
- `add_peer_checked(node_id, contact)`: Adds a peer to the routing table only if initialization is complete. Returns `false` without panicking if called before initialization.

### Part J: `MeshBackgroundTaskSpec` Documentation Correction

The `future` field in `MeshBackgroundTaskSpec` is now documented as **fully constructed by the builder** — the `FnOnce` closure is expected to produce a complete, ready-to-run `Pin<Box<dyn Future>>`. No further setup or wrapping is applied by `register_background_specs()`. This clarifies that the builder is responsible for all future configuration, not just the body.

### Part K: Removed `dht_routing_init` One-Shot Worker Task (Phase 3.5)

The worker-owned `dht_routing_init` one-shot task has been removed. DHT routing initialization now occurs within `MeshStartupStage::start()` as Phase 3.5, before seed/peer/DHT bootstrap phases. This eliminates the ordering dependency between the one-shot task and the bootstrap phases.

### Part L: Removed `dht_routing_manager` from `MeshInit` and `MeshSupportTasks`

`dht_routing_manager` is no longer a field on `MeshInit` or `MeshSupportTasks`. The routing manager is now owned exclusively by `MeshTransport` and initialized during the transactional startup stage. Worker composition roots no longer hold a reference to the routing manager — all DHT routing operations go through the transport.

## Iteration 88 — Worker Mesh Final Corrective Pass

**Part A — DHT initialization ordering**: DHT routing table initialization moved from Phase 5.5 (after peer connections) to Phase 3.5 (before any peer connections). This ensures the routing table exists before any seed or configured-peer connection callback can mutate it via `dht_on_peer_connected()`. The `dht_ready` flag gates DHT bootstrap (Phase 6) and DHT background maintenance (Phase 7) on actual initialization state. Startup peer insertion now uses `add_peer_checked()` which returns an error instead of silently no-oping.

**Part B — Cooperative support teardown**: Optional mesh degradation now performs cooperative cancellation followed by bounded join with abort fallback via `stop_mesh_generation_support()`. The `cancel_then_join_tasks()` registry method replaces `cancel_and_join_tasks()`, accepting cooperative and forced timeouts plus `expected_during_shutdown` context. `MeshSupportStopReport` tracks cooperative/aborted/failed counts. Dead `retain()` block removed from registry.

**Part C — YARA bridge task removal**: The detached `tokio::spawn` bridge that combined worker shutdown and generation cancel signals into a single watch channel has been removed. `run_yara_broadcast_loop()` now accepts `worker_shutdown_rx` and `generation_shutdown_rx` directly, selecting on both. Already-true receivers are checked at loop entry to prevent missed signals.

**Part D — DHT degraded reporting**: `report.dht_routing_initialized` now reflects actual `is_initialized()` state instead of unconditional `true`. `DhtInitializationSnapshot.was_initialized_this_attempt` correctly captures `!was_initialized && initialized`. DHT maintenance is skipped with a warning when initialization failed.

**Part E — Documentation**: MeshSupportTasks doc comments no longer reference DHT routing init. Final ownership model documented.

## Testing Commands

> **Note**: The mesh transport and lifecycle subsystem is closed as of Iteration 81. Worker mesh supervision is config-driven as of Iteration 84. All HTTP response framing, auxiliary task ownership, and lock ordering invariants are complete. Guardrail tests enforce the boundaries below.

```bash
# Run integration tests
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test mesh_forced_cleanup --features mesh,dns
cargo test --test mesh_http_framing --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns  # includes iter88_* guardrails

# Unit tests
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh task_group
cargo test -p synvoid-mesh --features mesh auxiliary

# Mesh transport closure verification
cargo test -p synvoid-mesh --features mesh http_response_parsing
cargo test -p synvoid-mesh --features mesh auxiliary_submission

# Lock ordering verification (deadlock detection)
cargo test --test mesh_lock_ordering --features mesh,dns

# Check DHT records (if admin API available)
curl http://localhost:8080/api/mesh/dht/records

# Trace mesh messages
RUST_LOG=debug cargo run -- --mesh-id node-1
```

## File Reference

| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/proxy.rs` | Route requests, extract upstream_id |
| `crates/synvoid-mesh/src/mesh/transport.rs` | Announce upstreams, proxy HTTP |
| `crates/synvoid-mesh/src/mesh/topology.rs` | Local upstream storage, DHT queries |
| `crates/synvoid-mesh/src/mesh/dht/keys.rs` | DHT key type definitions |
| `crates/synvoid-mesh/src/mesh/dht/mod.rs` | DHT value structures |
| `crates/synvoid-mesh/src/mesh/transport_org.rs` | Handle registration requests |
| `crates/synvoid-mesh/src/mesh/transport_peer.rs` | Peer message handling |
| `crates/synvoid-mesh/src/mesh/verification.rs` | Reachability tracking |
| `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` | Pure composition helper combining AdvisoryRecordSource + CanonicalTrustReader into threat-intel policy decisions |


## TierKey Encryption


- `crates/synvoid-mesh/src/mesh/tier_key_encryption.rs` - `TierKeyEncryption` struct with AES-256-GCM
- Master key derived from `node_identity.private_key` via HKDF("synvoid-tier-key-master")
- `handle_tier_key_announce` encrypts before DHT storage on global nodes
- Non-global nodes skip encryption (they don't store tier keys in DHT)


- Session key from ML-KEM session used to derive transmission key via HKDF("synvoid-tier-key-transmit")
- `encrypt_for_transmission()` / `decrypt_for_transmission()` methods added
- Both send and receive paths handle encrypted tier keys with fallback to plaintext

## Global Node Bootstrap

**Purpose**: Global nodes derive their signing key from a shared genesis key, enabling secure bootstrap without manual key distribution.

**Key Derivation**:
```rust
signing_key = HKDF-SHA256(
    IKM = genesis_key (32 bytes),
    info = "synvoid-global-node-signing-key",
    salt = node's public_key (32 bytes)
)
```

**Why salt with public_key?** Ensures two nodes derive different signing keys even if they share the same identity.

**Startup Behavior**:
| Config | Result |
|--------|--------|
| No `genesis_key_base64` | Start as EDGE, warning logged |
| `genesis_key_base64` set | Derive signing key, start as GLOBAL |
| signing_key unavailable | Tier key encryption disabled, warning logged |

**CLI Commands**:
| Command | Description |
|---------|-------------|
| `--genesis` | Generate genesis key, print config snippet |
| `--show-node-info` | Show node ID, role, genesis status, signing key |

**Usage**:
```bash
# First node - generate genesis key
$ synvoid --genesis
Genesis key generated. Add to config:
  [mesh.node_identity]
  genesis_key_base64 = "..."

# Start first node (derives signing key, starts as global)
$ synvoid

# Second node - copy genesis from first node, add to config, start
$ synvoid
```

**Verification on Global Node Announce**:
- `GlobalNodeAnnounce(Add/Remove)` - verified with genesis signature
- `GlobalNodeAnnounce(UpdateKeyExchange)` - verified with node's own public key (self-signed)

**Files**:
- `crates/synvoid-mesh/src/mesh/config_identity.rs` - `derive_signing_key_from_genesis()`
- `crates/synvoid-mesh/src/mesh/config.rs` - `genesis_key_base64` field
- `crates/synvoid-mesh/src/mesh/config_mesh.rs` - `load_node_identity()` derives from genesis
- `src/config/main.rs` - calls `load_node_identity()` during config load
- `src/main.rs` - `--genesis` and `--show-node-info` flags

## Origin Reachability System

**Purpose**: Edge nodes report route failures, global nodes coordinate verification, penalties applied to unreliable origins.

**Key Components**:

1. **VerificationTaskManager** (`crates/synvoid-mesh/src/mesh/verification.rs`):
   - `report_reachability()` - Called when edge detects failure
   - `initiate_verification_if_needed()` - Creates verification task
   - `process_pending_tasks()` - Background task processing
   - `get_pending_dispatch_tasks()` - Returns tasks needing queries
   - `mark_task_in_progress()` - Updates task with selected node IDs
   - `record_verification_result()` - Records verification response

2. **Handlers** (`crates/synvoid-mesh/src/mesh/transport_peer.rs`):
   - `handle_upstream_verification_query()` - Receives query, verifies TCP reachability, responds
   - `handle_upstream_verification_response()` - Receives response, calls record_verification_result()

3. **Query Dispatching** (`crates/synvoid-mesh/src/mesh/transports/manager.rs`):
   - `start_verification_processing()` - Background task on global nodes
   - Runs every 30 seconds
   - Selects 3 random peers (config.verification_nodes_count)
   - Dispatches UpstreamVerificationQuery to selected peers

**Verification Flow**:
```
Edge reports failure → report_reachability()
    → Global creates VerificationTask (status=Pending)
        → Background task finds pending tasks
            → Selects 3 random peers
                → Dispatches UpstreamVerificationQuery
                    → Nodes verify TCP reachability
                        → Respond with UpstreamVerificationResponse
                            → Global records result
                                → Penalty applied if multiple failures
```

**DHT Keys**:
- `origin_reachability:{upstream_id}:{provider_node_id}` - Reachability status
- `verification_task:{upstream_id}:{provider_node_id}` - Verification task
- `origin_penalty:{upstream_id}:{provider_node_id}` - Penalty record

**Penalty Mechanism**:
- Initial penalty: -20
- Recovery: +5 every 10 minutes
- Self-healing after ~40 minutes

**Threshold Logic** (2026-04-09):
- `record_verification_result()` tracks results per task, not immediate penalty
- `threshold = min(verification_nodes_count, total_expected)`
- Penalty only applied when `failure_count >= threshold`
- Handles small networks (1 global + 1 non-global) by adjusting threshold to number of queried nodes
- `MAX_PENALTIES_PER_TTL` constant defined but not yet enforced |

## Origin Local Backend Selection (IMPLEMENTED)

**Problem**: When origin receives proxied HTTP request from edge via QUIC stream, there was no handler to route based on Host header to the correct local backend.

**Root Cause**: Mesh QUIC transport only connected to peers via `connect_to_peer()`, but did NOT accept incoming connections.

**Solution Implemented**:

1. **QUIC server accept loop** (`crates/synvoid-mesh/src/mesh/transport.rs`):
   - `MeshTransport::start()` calls `runtime.start_server()` to accept incoming connections
   - `mesh_accept_loop()` handles incoming connections
   - `handle_incoming_peer_connection()` performs Hello/HelloAck handshake

2. **HTTP stream detection** (`crates/synvoid-mesh/src/mesh/transport_peer.rs`):
   - `handle_peer_message` detects HTTP vs mesh protocol by first byte
   - HTTP method indicators: 'G', 'P', 'H', 'D', 'O', 'T', 'C'
   - Routes HTTP to `handle_http_proxy_stream`

3. **HTTP forwarding to local backends** (`crates/synvoid-mesh/src/mesh/transport_peer.rs`):
   - Parses Host header, looks up `local_upstreams`
   - Connects to backend via TCP, forwards raw HTTP bytes
   - Streams response back on QUIC send_stream

4. **On-demand connection** (`crates/synvoid-mesh/src/mesh/transport.rs`):
   - `proxy_http_request` attempts connection if peer not in `peer_connections`
   - Looks up peer address from topology

## Rule Distribution (YARA & ThreatIntel) - DHT Primary

**Architecture**: Both YARA rules and ThreatIntel use DHT as the primary propagation mechanism. Mesh broadcast is retained as fallback only (to be removed in future).

### DHT-Based Propagation Flow

```
GLOBAL NODE updates rules
         │
         ▼
   apply_rules() via Local/Feed/AdminAPI
         │
         ├──▶ publish_rules_to_dht() ──▶ store rule content + manifest
         │
         └──▶ broadcast_pending_records() ──▶ DhtRecordAnnounce to k closest peers
                           │
                           ▼
              PEERS receive and store in local DHT cache
                           │
                           ▼
   NON-GLOBAL: sync_from_dht() iterates local cache, applies newest version
```

### Key Characteristics

| Aspect | Finding |
|--------|---------|
| DHT announce | One-hop broadcast to k closest peers (NOT recursive Kademlia) |
| Who announces | Global nodes only |
| Who receives | All node types (global, edge, origin) |
| Re-announce | YARA and ThreatIntel use `re_announce_interval_secs` |
| Peer selection | k closest peers by XOR distance (any role) |
| Transport | Both DHT and mesh use same QUIC transport via `send_datagram_to_peer()` |

### YARA Rules

**DHT Keys**:
| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `yara_rule:{content_hash}` | Actual rule content (content-addressed) | 24 hours |
| `yara_rules_manifest:{node_id}` | Global node's current ruleset metadata | 24 hours |

**DHT Value Structure**:
```json
{
    "version": "...",
    "content_hash": "sha256...",
    "node_id": "node-uuid",
    "timestamp": 1744567890,
    "signature": "base64-ed25519-signature",
    "signer_public_key": "base64-public-key"
}
```

**Signature Verification**:
- Manifest signed over: `version:content_hash:node_id:timestamp`
- Rule content signed over: `version:rules:content_hash:node_id:timestamp`
- During `sync_from_dht()`, signatures are verified before accepting rules
- Records without signatures are accepted for backward compatibility

**Files**:
| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/yara_rules.rs` | `publish_rules_to_dht()`, `sync_from_dht()` |
| `crates/synvoid-mesh/src/mesh/dht/keys.rs` | `YaraRuleContent`, `YaraRulesManifest` key types |

**Sync Mechanism**:
- `sync_from_dht()` replaces `send_sync_request_to_global()`
- Queries local DHT cache (populated by DHT announces)
- Compares timestamp with peer manifests (not lexicographic - uses numeric comparison)
- Fetches if different and signature verification passes

### ThreatIntel

**DHT Keys**:
| Key Pattern | Purpose |
|------------|---------|
| `threat_indicator:{ip}:{threat_type}` | Per-type indicator (composite key, e.g., `threat_indicator:1.2.3.4:IpBlock`) |

**Important**: ThreatIntel uses composite keys with threat_type suffix to prevent collision between different threat types for the same IP. A key without threat_type (e.g., `threat_indicator:1.2.3.4`) will NOT match.

**User-facing documentation**: `docs/THREAT_INTEL.md` covers full ThreatIntel architecture for humans.

**Signature Verification**:
ThreatIntel indicators are signed using Ed25519. The signature content format is:
```
{indicator_value}:{threat_type as u8}:{severity as u8}:{timestamp}:{source_node_id}
```

**Re-announcement**:
- Global nodes periodically re-announce local indicators via `re_announce_local_indicators()`
- Interval controlled by `re_announce_interval_secs` (default: 300s)
- ALL non-expired indicators are re-announced (not just `local_origin=true` indicators)
- Respects `hub_only_mode` (non-global nodes do not re-announce)

**Sync Mechanism**:
- `sync_from_dht()` replaces mesh broadcast sync
- Uses `get_by_prefix("threat_indicator:")` to efficiently retrieve threat indicator records
- Imports indicators not already present locally

### Historical Context

**Before (mesh-based)**: 
- YARA used `YaraRuleAnnounce` broadcast + `YaraRuleSyncRequest/Response` 
- ThreatIntel used `ThreatSyncRequest` broadcast
- DHT was "backup only"

**After (DHT-primary)**:
- Global nodes publish to DHT on rule changes
- Non-global nodes query local DHT cache (populated by announces)
- Mesh broadcast kept as fallback only

## DHT Routing Improvements (2026-04-13)

### DHT Churn Handling (M2.1)

**Location**: `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs:483-557`, `crates/synvoid-mesh/src/mesh/transport.rs`

**Problem**: `pending_pings` HashMap was populated but no background task sent PINGs to peers.

**Solution**: `ping_peers_loop()` background task:
```rust
async fn ping_peers_loop(&self, transport: Arc<dyn PingTransport>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let peers = self.get_peers_to_ping();
        for peer in peers {
            transport.send_ping(&peer.node_id, request_id.clone(), local_id.clone()).await;
        }
    }
}
```

**Flow**:
1. Loop runs every 60 seconds
2. Queries routing table for stale peers (no pong received)
3. Sends `MeshMessage::Ping` via datagram
4. Tracks pending pings in `pending_pings` HashMap
5. `mark_peer_responded()` called when `Pong` received

---

### Bucket Refresh (M2.2)

**Location**: `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs:455-492`, `crates/synvoid-mesh/src/mesh/dht/routing/node_id.rs`

**Problem**: `BUCKET_REFRESH_INTERVAL = 60` was defined but never triggered.

**Solution**: `refresh_sparse_buckets()` loop:
1. `get_sparse_bucket_indices()` returns buckets with < K contacts
2. For each sparse bucket, generates random NodeId in that bucket's range
3. Triggers `iterative_find_node()` to discover peers in that range

```rust
fn get_sparse_bucket_indices(&self, k: usize) -> Vec<usize> {
    self.buckets.iter()
        .enumerate()
        .filter(|(_, bucket)| bucket.len() < k)
        .map(|(idx, _)| idx)
        .collect()
}
```

---

### find_closest() Fix (M2.3)

**Location**: `crates/synvoid-mesh/src/mesh/dht/routing/table.rs:274`

**Problem**: Algorithm broke early when K candidates found, potentially missing closer peers in unscanned buckets.

**Solution**: Removed premature `break`. Now scans ALL buckets before returning, ensuring K closest peers are found.

---

### Edge Resync Multi-Homed (M2.4)

**Location**: `crates/synvoid-mesh/src/mesh/transport_dht.rs:386-397`

**Problem**: Resync only tried `global_nodes[0]` with no fallback.

**Solution**: Iterate all global nodes, continue on failure:
```rust
let mut all_failed = true;
for peer_id in &global_nodes {
    if self.send_datagram_to_peer(peer_id, &request).await.is_ok() {
        all_failed = false;
        break;
    }
}
if all_failed {
    tracing::warn!("DHT resync failed: all global nodes unreachable");
}
```

---

### Access Control Enforcement (M3.1)

**Location**: `crates/synvoid-mesh/src/mesh/dht/record_store_crud.rs:79-90`

**Problem**: `DhtAccessControl::require_global_node()` was never invoked.

**Solution**: Wired into `store_record()` for edge nodes storing privileged records:
```rust
if dht_key.is_privileged() {
    if let Err(e) = self.access_control.require_global_node() {
        tracing::warn!("Record store: {} cannot store privileged record", record.source_node_id);
        return false;
    }
}
```

**Effect**: Only global nodes can now store privileged records (Organization, TierKey, MemberCertificate, etc.) when `require_global_for_privileged` is `true` (default).

---

## Recent Architectural Refinements

### Threat Intel Key Format Standardization (T.I)

**Problem**: Three different key formats were used inconsistently: `IpBlock:1.2.3.4`, `1.2.3.4:IpBlock`, `threat_indicator:1.2.3.4:IpBlock`.

**Solution**: Added `make_indicator_key()` helper at `crates/synvoid-mesh/src/mesh/threat_intel.rs:25-27`:
```rust
fn make_indicator_key(ip: &str, threat_type: ThreatType) -> String {
    format!("threat_indicator:{}:{:?}", ip, threat_type)
}
```
All local storage now uses the composite key format `threat_indicator:{ip}:{threat_type}`.

### Threat Intel O(n) Iteration Optimization (M16.8)

**Problem**: `sync_from_dht()` used `get_all_records()` then filtered by prefix, iterating all DHT records.

**Solution**: Added `get_by_prefix()` method to `ShardedRecordStore` and `RecordStoreManager`. Changed `sync_from_dht` to use `record_store.get_by_prefix("threat_indicator:")`.

### Peer Score Decay Wired (M16.12)

**Problem**: `apply_periodic_decay()` existed in `ReputationManager` but was never called.

**Solution**: Added call to `reputation.apply_periodic_decay()` in `start_background_tasks()` loop at `crates/synvoid-mesh/src/mesh/threat_intel.rs:1590`.

### TOFU Expiry Reduced (M16.13)

**Problem**: TOFU certificate fingerprints expired after 90 days.

**Solution**: Reduced `MAX_TOOF_FINGERPRINT_AGE_DAYS` from 90 to 30 days at `crates/synvoid-mesh/src/mesh/cert.rs:81-82`.

---

## ACME HTTP-01 Challenge Serving (M.2)

### Overview

The mesh supports ACME HTTP-01 challenges across edge/origin topologies. When an origin needs a certificate from Let's Encrypt (or similar ACME CA), the HTTP-01 challenge response must be reachable at the edge node's IP address — not just the origin's IP.

### Protocol Flow

```
1. Origin initiates ACME order
       ↓
2. Global Node issues UpstreamOwnershipChallenge{Http01{token, key_authorization}}
       ↓ (mesh QUIC, HMAC signed)
3. All registered edge nodes store token → key_authorization
       ↓
4. ACME Server probes: GET /.well-known/acme-challenge/{token}
       ↓ (standard HTTP/TCP port 80, resolves to edge IP)
5. Edge serves key_authorization directly from challenge store
```

### Two Serving Paths

**Path A — Direct HTTP server** (`src/http/server.rs:551-579`):
The edge node's own HTTP server handles ACME requests. This path serves requests that arrive via the normal HTTP/TCP flow (ACME server → edge node directly).

**Path B — Mesh QUIC stream** (`crates/synvoid-mesh/src/mesh/transport_peer.rs:2345-2366`):
The edge node's mesh accept loop receives QUIC streams from global nodes. When the stream contains an HTTP request with `Host: origin-host`, `handle_http_proxy_stream()` now checks for ACME paths first before attempting backend proxy.

### Why Both Paths?

- Path A covers the case where the edge node IS the HTTP endpoint visible to the ACME server
- Path B covers the case where a global node is proxying the ACME request through mesh QUIC

The challenge store on the edge must be populated BEFORE the ACME server probes. Global nodes push `UpstreamOwnershipChallenge` messages to all registered edges immediately when a challenge is initiated.

### Threat Model

| Assumption | Implication |
|-----------|-------------|
| Mesh messages are HMAC authenticated | Attackers cannot inject fake challenges |
| Edges receive challenges before ACME probes | Race condition possible if edge is offline |
| Edge only serves challenges it received | Cannot forge — only has public key_authz |

**Not suitable for**: scenarios where edges should have zero knowledge of origin private keys, or where the `Host` header is untrusted without additional verification.

### Key Code Locations

| File | Line | Purpose |
|------|------|---------|
| `crates/synvoid-mesh/src/mesh/transport.rs` | 478-491 | `store_http01_challenge()` stores to LRU cache |
| `crates/synvoid-mesh/src/mesh/transport.rs` | 493-497 | `get_http01_challenge()` retrieves (dns-gated) |
| `crates/synvoid-mesh/src/mesh/transport_peer.rs` | 2345-2366 | ACME path check in proxy stream handler |
| `src/http/server.rs` | 551-579 | Direct HTTP server challenge serving |
| `crates/synvoid-mesh/src/mesh/transport_peer.rs` | 1870-1884 | Receiving `UpstreamOwnershipChallenge` from mesh |

---

## Serverless-as-Origin (2026-04-22)

### Overview

Origin nodes can now serve serverless functions over mesh QUIC connections. The `handle_serverless_proxy_stream()` function (`crates/synvoid-mesh/src/mesh/transport_peer.rs:2884-2992`) handles serverless invocations.

### Routing Flow

```
Edge receives request for serverless function
    ↓
extract_upstream_id() produces "serverless:{function_name}"
    ↓
MeshTransport detects "serverless:" prefix
    ↓
Acquires ServerlessManager from transport
    ↓
Parses HTTP request (method, path, headers, body)
    ↓
Invokes via invoke_for_mesh()
    ↓
Returns WASM response as HTTP response
```

### Key Implementation Details

- `serverless_manager: Arc<RwLock<Option<Arc<ServerlessManager>>>>` field in `MeshTransport`
- Set during worker initialization via `unified_server.rs:1095-1097`
- Serverless functions can be registered in DHT via `serverless_function:{name}` keys

---

## DHT Regional Quorum (W11.1)

### Overview

DHT quorum supports two modes via `QuorumMode` in `crates/synvoid-mesh/src/mesh/dht/quorum.rs`:

| Mode | Quorum Calculation | Use Case |
|------|--------------------|----------|
| **Full** (default) | 2/3+1 of ALL global nodes | Small clusters (< 100 global nodes) |
| **Regional** | 2/3+1 of closest N global nodes by latency | Large clusters (100+ global nodes) |

### Regional Mode

When `regional_quorum_enabled = true` in `RecordStoreConfig`:
1. `start_quorum_request()` calls `select_regional_nodes()` to pick closest nodes by latency
2. Quorum messages are sent only to the regional subset (not all global nodes)
3. Threshold is computed from the regional subset size, not total global count

```rust
// Enable regional quorum (20-node subset, minimum 3)
let config = RecordStoreConfig {
    regional_quorum_enabled: true,
    regional_quorum_max_nodes: 20,
    regional_quorum_min_nodes: 3,
    ..Default::default()
};
```

### Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/dht/quorum.rs` | `QuorumMode`, `select_regional_nodes()`, `GlobalNodeInfo` |
| `crates/synvoid-mesh/src/mesh/dht/record_store.rs` | `RecordStoreConfig` regional quorum fields |
| `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs` | `start_quorum_request()` regional node selection |

### Testing Verification

```bash
# Verify YARA rules in DHT
curl -s http://localhost:8080/api/mesh/dht/records | jq '.[] | select(.key | startswith("yara_rule"))'

# Verify YARA manifests
curl -s http://localhost:8080/api/mesh/dht/records | jq '.[] | select(.key | startswith("yara_rules_manifest"))'

# Verify ThreatIntel in DHT
curl -s http://localhost:8080/api/mesh/dht/records | jq '.[] | select(.key | startswith("threat_indicator"))'
```

## Cryptographically-Enforced Quorum Gossip (W12.2)

Records in sensitive namespaces require a `quorum_proof` to be accepted via gossip/sync/commit. This prevents a single compromised node from promoting a `PendingQuorum` record to `Live` without quorum approval.

### Sensitive Namespaces

The following key prefixes require quorum proof for gossip/sync acceptance:
- `verified_upstream:` — Verified upstream registration records
- `tier_claim:` — Organization tier claims

Configured in `DhtAccessControl::global_signature_required_keys`.

### Quorum Proof Flow

1. **Origin**: `store_record_global()` stores record as `PendingQuorum`, starts quorum request
2. **Quorum**: Global nodes sign and return quorum signatures
3. **Commit**: `commit_record_after_quorum()` attaches `quorum_proof` (the collected signatures) to the record
4. **Propagation**: Commit notification is sent to peers; receiving nodes verify against Raft state machine
5. **Sync/Gossip**: Records in sensitive namespaces carry `quorum_proof` via sync responses

### Key APIs

```rust
// Verify quorum proof (in crates/synvoid-mesh/src/mesh/dht/signed.rs)
use crate::mesh::dht::signed::{verify_quorum_proof, MIN_QUORUM_PROOF_SIGNATURES};

// Check if namespace requires proof (in DhtAccessControl)
let requires = access_control.requires_quorum_proof("verified_upstream:example.com");

// Record now has quorum_proof field
let record = DhtRecord {
    // ... standard fields ...
    quorum_proof: vec![QuorumSignatureProto { node_id, signature, timestamp }],
};
```

### Enforcement Points

| Location | Enforcement |
|----------|------------|
| `store_record_global()` | Rejects remote records in sensitive namespaces without valid proof |
| `apply_sync()` | Skips sync records in sensitive namespaces without valid proof |
| `handle_record_commit()` | Verifies quorum proof before accepting commit for sensitive namespaces |

### Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/protocol.rs` | `DhtRecord.quorum_proof` field, `QuorumSignatureProto` |
| `crates/synvoid-mesh/src/mesh/dht/signed.rs` | `verify_quorum_proof()`, `MIN_QUORUM_PROOF_SIGNATURES` |
| `crates/synvoid-mesh/src/mesh/dht/record_store_crud.rs` | Quorum-proof enforcement in `store_record_global()`, `apply_sync()` |
| `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs` | `commit_record_after_quorum()` attaches proof, `handle_record_commit()` verifies |

---

## DHT/Raft Boundary Hardening (2026-06)

### DHT Key Policy Table

**Location**: `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`

Centralizes key family authority policies for DHT ingress validation. Each DHT key prefix (e.g., `verified_upstream:`, `threat_indicator:`, `yara_rule:`) has an associated policy defining which key families are authorized to write records under that prefix.

```rust
pub struct DhtKeyPolicyTable {
    policies: HashMap<String, KeyFamilyPolicy>,
}

pub struct KeyFamilyPolicy {
    pub allowed_key_families: Vec<KeyFamily>,
    pub require_signature: bool,
    pub require_quorum_proof: bool,
}
```

**Purpose**: Replaces scattered validation logic with a single lookup table. All remote DHT writes consult the policy table before acceptance.

**Iteration 11 — Canonical Reader Migration**: The `classify_key_authority_with_canonical_reader` helper uses `CanonicalTrustReader` for canonical authority questions while preserving advisory DHT mechanics. Advisory records remain advisory; signed records are not automatically authorized; unknown/unavailable canonical answers are explicit and are not silently treated as trust. Tests cover advisory-only, global-authorized, unauthorized, revoked, unavailable, stale, and unknown canonical cases.

**Iteration 12 — Ingress Preparation**: The key-policy canonical helper now explicitly tests `CanonicalUnavailable` defer branches. An ingress adapter (`validate_dht_key_authority_for_ingress`) maps canonical helper decisions to `Result<(), DhtIngressPolicyError>` while preserving accept/reject/defer distinctions. The carrier was added and Push/Announce paths wired in Iteration 14 (per `architecture/mesh_trust_domains.md`); **Iteration 15: trust-domain track complete** — ingress gate active for configured Push/Announce paths. **Iteration 16: AdvisoryRecordSource seam** introduced — read-only advisory DHT observations. **Iteration 17**: `RecordStoreAdvisorySource` hardened with real-store tests; no consumer migration; docs updated. **Iteration 18: Policy composition helper** — `evaluate_threat_intel_policy()` in `crates/synvoid-mesh/src/mesh/threat_intel_policy.rs` composes `AdvisoryRecordSource` + `CanonicalTrustReader` into explicit threat-intel policy decisions (Actionable/AdvisoryOnly/NotActionable/Deferred). Tests cover all advisory + canonical state combinations. **Iteration 19: First consumer migration** — `ThreatIntelligenceManager::evaluate_indicator_actionability` wraps the policy helper, taking trait objects as parameters. Tests cover all policy-composed and legacy paths. **Iteration 20: Injection seam** — `ThreatIntelPolicyContext` carrier with `set_policy_context()`, `evaluate_indicator_actionability_configured()`, and `lookup_threat_indicator_policy_composed()`. **Iteration 21: Second consumer migration** — `lookup_local_indicator_policy_composed` and `lookup_local_indicator_by_ip_policy_composed` added. Two threat-intel read paths now use the composed policy seam. Raw methods remain for compatibility. **Iteration 22: Policy cleanup** — shared `is_policy_actionable` helper consolidates duplicate DHT/local gating; policy-composed methods documented as preferred; raw methods documented as compatibility/diagnostic. **Iteration 23: Policy reassessment** — the track is staged and stable after call-graph review. No low-risk caller was migrated, no proxy/YARA/WASM/routing/enforcement hot path was touched, and raw lookup APIs remain compatibility/diagnostic paths. **Iteration 24: Verification** — the shared helper remains in place and focused mesh checks passed; raw lookup APIs remain compatibility/diagnostic paths. **Iterations 25-26: Root wiring** — `DataPlaneServices` carries optional `ThreatIntelPolicyContext`; a root-side helper builds it from explicit canonical/advisory handles. **Iteration 27** assessed canonical reader ownership; workers are data-planes without direct access to Raft/EdgeReplicaManager. **Iteration 28: Supervisor exports `CanonicalTrustSnapshot` via IPC to workers** — `EdgeReplicaManager::canonical_trust_snapshot()` produces the snapshot, Supervisor sends `CanonicalTrustSnapshotUpdate` IPC, workers store it and apply the snapshot via `DataPlaneServices::update_threat_intel_policy_context()` in the IPC message loop. `CanonicalTrustSnapshot` implements `CanonicalTrustReader`. `DataPlaneServices::update_threat_intel_policy_context()` enables live policy context updates when snapshots arrive via IPC. No proxy/YARA/WASM/routing/WAF consumers were migrated. **Iteration 33: Shadow/observability consumers** — `ThreatIntelPolicyShadowDecision` DTO, `ThreatIntelPolicyDecisionClass`, `ThreatIntelPolicyShadowDisagreement` enums; `evaluate_indicator_policy_shadow()` with metrics counters; admin endpoints for diagnostics. **Shadow/observability only — no enforcement behavior changed.**

### SignedRaftAttestation

**Location**: `crates/synvoid-mesh/src/mesh/peer_auth.rs`

Raft consensus attestations now require cryptographic proof, not just structural attestation:

```rust
pub struct SignedRaftAttestation {
    pub attestation: RaftAttestation,
    pub signer_node_id: String,
    pub signer_public_key: String,
    pub signature: Vec<u8>,
    pub protocol_version: u32,  // v2: RAFT_ATTESTATION_PROTOCOL_VERSION = 2
}

pub struct RaftAttestation {
    pub leader_id: String,
    pub commit_index: u64,
    pub namespace: Namespace,
    pub key_id: String,
    pub timestamp: u64,
    #[serde(default)]
    pub value_hash: Option<Vec<u8>>,  // v2: binds attestation to value digest
}
```

**Before**: Raft attestation was structural-only (any node could assert membership). **After (v2)**: Attestation carries an Ed25519 signature over `(namespace, key_id, leader_id, commit_index, timestamp, protocol_version, value_hash)`, verified against authorized global node keys. The `value_hash` field (SHA-256 of the value) binds the attestation to a specific DHT value, preventing replay across different values. V1 attestations without `value_hash` are **rejected by default** — set `allow_v1_raft_attestations=true` in config to permit them during migration.

### ConsensusTransport Trait

**Location**: `crates/synvoid-mesh/src/mesh/raft/consensus.rs`

Decouples Raft consensus logic from the mesh transport layer. Previously, Raft state machine operations were tightly coupled to `MeshTransport`. The new trait provides a clean interface:

```rust
#[async_trait]
pub trait ConsensusTransport: Send + Sync {
    async fn send_vote_request(&self, target: &str, request: VoteRequest) -> Result<VoteResponse>;
    async fn send_append_entries(&self, target: &str, request: AppendEntriesRequest) -> Result<AppendEntriesResponse>;
    async fn send_install_snapshot(&self, target: &str, request: InstallSnapshotRequest) -> Result<InstallSnapshotResponse>;
}
```

**Benefit**: Raft consensus can be tested independently of mesh networking. The mesh transport implements this trait, but the Raft state machine no longer depends on mesh internals.

### AuthorityFreshnessConfig

**Location**: `crates/synvoid-mesh/src/mesh/config.rs`

Defines stale-state behavior for authority records in DHT:

```rust
pub struct AuthorityFreshnessConfig {
    pub max_authority_staleness_secs: u64,      // Default: 3600 (1 hour)
    pub require_freshness_for_critical_keys: bool, // Default: true
    pub freshness_check_enabled: bool,           // Default: true
}
```

**Purpose**: Prevents acceptance of stale authority records (e.g., outdated genesis key transitions, revoked node records) in DHT sync and anti-entropy. Records older than `max_authority_staleness_secs` are rejected when `freshness_check_enabled` is true.

### DhtAntiEntropyRequest and DhtRecordPush Verification (MR-4 Resolved)

The MR-4 gaps have been closed for all DHT message types:

- **`DhtSyncRequest`**: Envelope signature verified — signs `(request_id, node_id, local_root_hash, timestamp, nonce)` and verifies against the sender's public key. Signer-to-node binding enforced via `verify_envelope_signer_binding()`. Unsigned requests accepted only during config-controlled compatibility window (off by default).
- **`DhtSyncResponse`**: Envelope signature verified — signs `(request_id, from_peer, responder_node_id, version, record_count, timestamp, record_set_digest)` and verifies against the responder's public key. Record-set digest recomputed and tampered sets rejected. Signer-to-node binding enforced before any records are stored. Unsigned compatibility path (when compat window is active) still stores via `store_record_from_ingress()` with `envelope_signature_valid=false`; per-record ingress validation is always enforced.
- **`DhtAntiEntropyRequest`**: Envelope signature verified via `verify_dht_anti_entropy_request_envelope_signature()` — signs `(request_id, node_id, local_root_hash, timestamp, nonce)` and verifies against the sender's public key. `signer_public_key` is also checked against the authorized global node key list. The request is rejected if the envelope signature is invalid or the signer is not an authorized global node.
- **`DhtAntiEntropyResponse`**: Envelope signature verified via `verify_dht_anti_entropy_response_envelope_signature()` — signs `(request_id, responder_node_id, root_hash, record_count, timestamp, record_set_digest)`. All responses (empty and non-empty) are verified when `require_signed_anti_entropy_requests=true` (outside the compat window).
- **`DhtRecordPush`**: Envelope signature verified via `verify_dht_record_push_envelope_signature_bytes()` — signs `(request_id, node_id, records, hop_count, nonce, timestamp)`. Records without valid envelope signatures are rejected during ingress.

**Note**: All message types have configurable unsigned compatibility windows (`unsigned_sync_compat_until_unix`, `unsigned_anti_entropy_compat_until_unix`, `unsigned_record_push_compat_until_unix`) for rolling upgrades. When `require_signed_*=false` or the compat window is active, unsigned messages are accepted with a warning log. The deprecated `handle_sync_response()` unsigned path has been removed; all sync response paths (signed and unsigned compat) now store through `store_record_from_ingress()` with per-record ingress validation.

These changes are breaking protocol changes — older nodes that send unsigned or incorrectly signed messages will be rejected by updated nodes.

### Verification Layer Distinction

DHT security operates on four distinct verification layers, each addressing a different threat:

| Layer | What It Proves | Threat Mitigated |
|-------|---------------|------------------|
| **Envelope Signature** | Sender possesses the private key | Spoofed messages from impersonators |
| **Signer-to-Node Binding** (`verify_envelope_signer_binding()`) | The signing key belongs to the claimed node ID | Stolen keys used from wrong nodes; key compromise isolation |
| **Per-Record Signature** | The record was authored by the signer | Tampered record content; unauthorized record creation |
| **Ingress Validation** (key-policy table) | The signer's key family is authorized for this DHT namespace | Cross-namespace privilege escalation; unauthorized writes to sensitive records |

All four layers are enforced for remote DHT writes on global nodes. Local writes (`store_local_record()`) skip envelope/signer verification since they originate from the node's own key.

## Canonical Snapshot Freshness Policy (Iteration 31, Config Wired Iteration 32)

Canonical snapshots are authoritative only within a configured freshness policy. Workers classify snapshots as fresh, stale-within-grace, expired, invalid, or missing. The freshness policy is now sourced from runtime config (`AuthorityFreshnessConfig`) instead of hardcoded defaults.

### Freshness States

| State | Condition | Behavior |
|-------|-----------|----------|
| Fresh | age ≤ fresh_max_age_ms (default 60s) | Install `FreshnessBoundCanonicalReader`, apply policy context |
| StaleWithinGrace | fresh < age ≤ stale_grace (default 5min) | Per stale mode (see below) |
| Expired | age > stale_grace | Clear policy context, log warning |
| Invalid | zero/future timestamp | Clear policy context, log error |
| Missing | no snapshot | Clear policy context, log error |

### Stale Mode Behavior

| Stale Mode | Worker Action | Reader Behavior |
|------------|--------------|-----------------|
| `FailOpenDefer` (default) | Clear policy context | `Unknown { CanonicalUnavailable }` |
| `FailClosedNotActionable` | Install `FreshnessBoundCanonicalReader` | `NotTrusted { ExpiredSnapshot }` |
| `AllowStaleWithWarning` | Install `FreshnessBoundCanonicalReader` | `Stale { age_ms }` freshness |

### Types

- `CanonicalSnapshotFreshnessPolicy`: configurable thresholds + stale mode
- `CanonicalSnapshotStaleMode`: `fail_open_defer` | `fail_closed_not_actionable` | `allow_stale_with_warning` (serde: snake_case)
- `classify_canonical_snapshot()`: pure classifier
- `FreshnessBoundCanonicalReader`: wrapper enforcing policy on `CanonicalTrustReader`
- `From<&AuthorityFreshnessConfig>`: config-to-policy conversion with normalization

### Config

Fields in `AuthorityFreshnessConfig`:
- `canonical_snapshot_fresh_max_age_ms` (default: 60_000)
- `canonical_snapshot_stale_grace_max_age_ms` (default: 300_000)
- `canonical_snapshot_stale_mode` (default: fail_open_defer)

Invalid configs (stale_grace < fresh_max_age) are normalized at conversion time.

### Worker Flow

1. IPC `CanonicalTrustSnapshotUpdate` received
2. Deserialize snapshot (malformed → reject, preserve previous valid snapshot/context)
3. Store raw snapshot for diagnostics
4. Read freshness policy from `config.main.tunnel.mesh.authority_freshness` (fallback to defaults)
5. Classify freshness via `classify_canonical_snapshot()`
6. Based on classification + stale mode: install reader or clear context (see stale mode table)
7. No proxy/YARA/WASM/routing/WAF consumers were migrated in this pass.

### Malformed/Invalid/Expired Snapshot Semantics

| Scenario | Behavior |
|----------|----------|
| Malformed postcard payload | Reject update, preserve previous valid snapshot/context |
| Invalid timestamp | Store raw snapshot for diagnostics, clear policy context |
| Expired timestamp | Store raw snapshot for diagnostics, clear policy context |

### Files

| File | Purpose |
|------|---------|
| `crates/synvoid-mesh/src/mesh/canonical.rs` | Types, classifier, wrapper, `From` conversion, normalization |
| `src/worker/unified_server/lifecycle.rs` | Worker integration (config read, classify, apply) |
| `crates/synvoid-mesh/src/mesh/config.rs` | Config fields in `AuthorityFreshnessConfig` |

## Threat-Intel Policy Shadow Consumers (Iteration 33)

Shadow/observability consumers for policy-composed threat-intel decisions.

### Types

- `ThreatIntelPolicyDecisionClass`: `Actionable | AdvisoryOnly | NotActionable | Deferred | NotConfigured | Error`
- `ThreatIntelPolicyShadowDecision`: diagnostic DTO with indicator_value, threat_type, decision_class, reason, advisory/canonical freshness, raw_lookup_present, composed_actionable
- `ThreatIntelPolicyShadowDisagreement`: `RawPresentComposedNotActionable | RawMissingComposedActionable | RawPresentComposedDeferred | RawMissingComposedDeferred`

### Helpers

- `classify_threat_intel_policy_decision(Option<&ThreatIntelPolicyDecision>) -> ThreatIntelPolicyDecisionClass`
- `threat_intel_policy_shadow_decision(indicator, threat_type, decision, raw_present) -> ThreatIntelPolicyShadowDecision`
- `classify_shadow_disagreement(raw_present, decision) -> Option<ThreatIntelPolicyShadowDisagreement>`

### Method

- `ThreatIntelligenceManager::evaluate_indicator_policy_shadow(indicator_value, threat_type) -> ThreatIntelPolicyShadowDecision`

Evaluates policy composition, increments per-class metrics, tracks canonical unavailability and advisory missing, classifies raw/composed disagreement, returns shadow DTO. **Does not block traffic or mutate enforcement state.**

### Admin Endpoints

- `GET /mesh/threat-intel/policy-shadow?indicator=<value>&type=<type>` — per-indicator evaluation
- `GET /mesh/threat-intel/policy-shadow/stats` — aggregated counters

### Metrics

All counters use `synvoid-metrics` atomic counters (no high-cardinality labels):

| Counter | Meaning |
|---------|---------|
| `shadow_actionable` | Policy says actionable |
| `shadow_advisory_only` | Advisory present but canonical not trusted |
| `shadow_not_actionable` | Policy rejects (missing advisory or canonical denial) |
| `shadow_deferred` | Policy defers (sources unavailable/unknown) |
| `shadow_not_configured` | No policy context set |
| `shadow_raw_disagreement` | Raw and composed lookups disagree |
| `shadow_canonical_unavailable` | Canonical snapshot unavailable |
| `shadow_advisory_missing` | No advisory record found |

### Decision semantics

| Class | Meaning | Traffic impact |
|-------|---------|---------------|
| Actionable | Advisory present + canonical trusts | None (shadow only) |
| AdvisoryOnly | Advisory exists, canonical absent/undecided | None |
| NotActionable | Missing advisory or canonical denial | None |
| Deferred | Sources unavailable or unknown | None |
| NotConfigured | No policy context injected | None |

## Threat-Intel Enforcement Gate (Iterations 34-36)

Enforcement consumers mutate block-store, rate-limit, or WAF deny state. All enforcement mutations are gated by the policy plane.

### Consumer Classification

`classify_consumer_action(consumer_kind, policy_decision)` maps consumer intent to an action:

| Consumer Kind | Policy Decision | Result |
|---------------|-----------------|--------|
| `Enforcement` | `Actionable` | `PermitAction` |
| `Enforcement` | `AdvisoryOnly` / `NotActionable` | `SuppressAction` |
| `Enforcement` | `Deferred` + `FailOpenNoAction` / `FailClosedNoAction` | `SuppressAction` |
| `Enforcement` | `Deferred` + `ShadowOnly` | `ShadowOnly` |
| `Enforcement` | `None` (no context) | `SuppressAction` |
| `ShadowOnly` | any | `ShadowOnly` |
| `RawCompatibility` | any | `RawCompatibilityOnly` |
| `AdvisoryCache` | any | `SuppressAction` |

### Strict Lookup Wrappers

For enforcement/actionability-sensitive consumers, use strict wrappers. They return `None` when no policy context is configured, preventing silent fallback to ungated data:

- `lookup_threat_indicator_policy_strict()` — DHT lookup
- `lookup_local_indicator_policy_strict()` — Local store lookup
- `lookup_local_indicator_by_ip_policy_strict()` — IP convenience wrapper

Legacy composed wrappers (`lookup_*_policy_composed`) fall back to raw lookups when no context exists. They are acceptable for diagnostics but not for enforcement.

### WAF/BlockStore Boundary (Iteration 58)

The WAF request path no longer holds a concrete `BlockStore` directly. `WafCore` and `AsnTracker` previously stored `Option<Arc<BlockStore>>` (concrete type); Iteration 58 removed this field, and the WAF block-store methods (`check_block_store`, `check_early`, `maybe_escalate_and_block`, `block_ip_for_honeypot`, `block_ip_with_threat_intel`) are now no-ops. The `BlockStoreAdapter` in `src/waf/adapters.rs` bridges `Arc<BlockStore>` to the `BlockListStore` trait for use in the extracted WAF crate. Concrete `BlockStore` ownership moved to `UnifiedServer` (composition root) via `with_block_store()`. This enforces the composition root invariant: request-path modules consume capabilities, not concrete infrastructure.

**Iteration 59**: Guardrail tightened — `src/worker/unified_server/` is no longer broadly exempt; each file is individually classified via `BoundaryRole`. Three token groups (construction, type-import, control-plane-op) catch concrete infrastructure at import level, not just constructor calls. `check_dht_threat_lookup()` and `get_threat_intel()` removed from `WafCore` (dead code referencing concrete `ThreatIntelligenceManager` on request path). WAF blocklist methods (`check_early`, `block_ip_for_honeypot`, `block_ip_with_threat_intel`) documented as no-op compatibility shims. Scoped `BoundaryException` table replaces file-level exemptions.

**Iteration 60**: `src/worker/unified_server/` is actively scanned via `boundary_scan_roots()`, not broadly exempt. Unknown files under mixed-role directories fail closed (`Unclassified` role). Every boundary exception must be live-audited; a liveness test ensures each exception corresponds to a current source occurrence. Exception liveness test prevents stale exceptions from authorizing regressions.

### AsnBlock Status

`AsnBlock` is observational/advisory only. No enforcement gate, no block-store mutation, no attack metric. The indicator is stored for bookkeeping; the handler logs an advisory message.

### Indicator Integration Status

| Indicator | Enforcement Wired |
|-----------|-------------------|
| `IpBlock` | Yes — gated via `handle_incoming_threat` |
| `RateLimitViolation` | Yes — gated via `handle_incoming_threat` |
| `SuspiciousActivity` | Yes — gated via `handle_incoming_threat` |
| `IpThrottle` | Yes — gated via `handle_incoming_threat` |
| `AsnBlock` | No — observational/advisory only |
| `DomainBlock` | No — reserved for future DNS-layer integration |
| `UrlBlock` | No — reserved for future URL-filter integration |
| `CertBlock` | No — reserved for future TLS-layer integration |

## Threat-Intel Consumer Actionability Audit (Iteration 54)

The consumer actionability audit inventoried every threat-intel consumer and classified them into explicit classes:

| Class | Can Mutate Enforcement? | Required API |
|-------|------------------------|-------------|
| Enforcement | YES (only with `PermitAction`) | `evaluate_incoming_threat_policy` / `classify_consumer_action` |
| Deferred | Only when policy permits | `classify_consumer_action` with `ThreatIntelDeferredMode` |
| ShadowOnly | NO | `evaluate_indicator_policy_shadow` |
| Diagnostic | NO | `lookup_*` (raw) or `diagnostic_lookup_*` |
| LocalOrigin | YES (operator/local authority) | Direct block-store writes |
| WorkerIPC | YES (control-plane authority) | Direct block-store writes with preserved provenance |

**Key invariants**:
- Raw lookup APIs are diagnostic-only; enforcement must use `lookup_*_policy_strict` or `evaluate_incoming_threat_policy`
- `ShadowOnly` paths never emit blocklist events or call block/unblock APIs
- Threat-intel enforcement uses `MeshThreatIntelPolicyGated` provenance
- `LegacyUnknown` is not used for new threat-intel blocklist writes
- `AsnBlock` is observational only (no block-store mutation)

**Canonical inventory**: `architecture/threat_intel_consumer_actionability.md`
**Guardrail test**: `tests/threat_intel_consumer_actionability_guard.rs`

## Iteration 36 — Doc Drift, Three-Plane Model, Request/WAF Audit

Documentation drift cleanup for the stable threat-intel enforcement model:

- Fixed `AsnBlock` local action in `THREAT_INTEL.md` (observational/advisory, not attack logging)
- Updated architecture diagram to reflect policy-gated threat sync
- Tightened strict vs legacy API guidance
- Added three-plane threat-intel model (advisory, canonical, enforcement) to mesh trust domains
- Request/WAF audit confirmed: WAF reads BlockStore, not ThreatIntelligenceManager directly
- Strict/composed wrappers defined but have zero external production callers (staged for future use)
- New audit note: `architecture/threat_intel_request_waf_audit.md`
