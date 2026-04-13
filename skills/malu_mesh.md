# MaluWAF Mesh & DHT Architecture Skill

## Overview

MaluWAF uses a mesh network architecture with DHT-based service discovery for multi-origin routing. This skill provides context for working with the mesh transport, DHT keys, and upstream routing.

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
// src/mesh/peer_auth.rs
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
) -> Result<(), String>
```

| Role | Challenge Format | Verification |
|------|-----------------|---------------|
| Global | `"{node_id}:{timestamp}"` | Check pubkey in authorized list, verify signature |
| Edge | `"edge:{node_id}:{timestamp}"` | Verify self-signature |
| Origin | `"origin:{node_id}:{timestamp}"` | Verify self-signature + Global attestation |

## Upstream ID Format

**Current format** (after Phase 7b): `http://host:port`

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

## Routing Flow

### 1. Edge Receives Request
```
Client → Edge: GET http://example.com/api
```

### 2. Extract Upstream ID
```rust
// src/mesh/proxy.rs:extract_upstream_id()
upstream_id = format!("http://{}:{}", host, port)
// Result: "http://example.com:80"
```

### 3. Query for Providers
```rust
// src/mesh/proxy.rs:get_providers_for_upstream()
transport.send_route_query(upstream_id)
// Returns: Vec<ProviderInfo> from DHT
```

### 4. DHT Lookup
```rust
// src/mesh/topology.rs:find_verified_upstreams_for_site()
record_store.get_all_records()
    .filter(|r| r.key.starts_with("verified_upstream:"))
    .filter(|r| r.value.upstream_id == site)
// Returns all origins verified for this domain+port
```

### 5. Weighted Random Selection
```rust
// src/mesh/proxy.rs:weighted_shuffle_providers()
// Providers shuffled by score for load balancing
// Higher score = more likely to be selected first
```

### 6. Route to Origin
```rust
transport.proxy_http_request(peer_node_id, &target_url, req)
```

## VerifiedUpstream Structure

```rust
// src/mesh/dht/mod.rs
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
// src/mesh/transport.rs

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
| `src/mesh/dht/capability_attestation.rs` | Attestation struct and verification |
| `src/mesh/dht/keys.rs` | `CapabilityAttestation` DHT key type |
| `src/mesh/transport.rs` | `attest_capability()`, `verify_node_capability()` |

## Edge Node PoW Authentication (W2.6)

Edge nodes can authenticate via Ed25519 signature OR Proof-of-Work.

### Authentication Flow

```
Edge connects → (If pow_nonce + pow_public_key provided) → PoW validation → Authenticated
              → (Otherwise) → Ed25519 signature validation → Authenticated
```

### PoW Validation

```rust
// src/mesh/peer_auth.rs

validate_edge_node_pow(pow_public_key, pow_nonce) {
    // 1. Derive node_id from pow_public_key using NodeId::from_public_key()
    // 2. Verify PoW using NodeId::verify_pow(nonce)
    // 3. If valid, node is authenticated
}
```

### Parameters

- `pow_public_key`: 32-byte Ed25519 public key
- `pow_nonce`: Nonce that makes the PoW solution valid

### Implementation Files

| File | Purpose |
|------|---------|
| `src/mesh/peer_auth.rs` | `validate_edge_node_pow()`, `validate_peer_role()` with PoW params |
| `src/mesh/transport.rs` | Pass `pow_nonce`, `pow_public_key` to validation |
| `src/mesh/discovery.rs` | Pass PoW credentials from peer hello |

## Multi-Genesis Key Support (W2.2)

The system supports multiple authorized genesis keys for key rotation and disaster recovery.

### Config Structure

```rust
// src/mesh/config.rs
pub struct GenesisKeyConfig {
    pub authorized_genesis_keys: Vec<String>,  // Multiple authorized public keys
    pub previous_genesis_key_base64: Option<String>,  // For rotation
    pub rotation_sequence: u32,
    // ...
}
```

### Authorization Methods

```rust
// src/mesh/config_identity.rs

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

- Empty `authorized_genesis_keys` = any genesis key allowed (backward compatible)
- Non-empty list = genesis key must be in the list
- Key rotation tracked via `rotation_sequence` and `GenesisKeyTransition` DHT records

## Testing Commands

```bash
# Run integration tests
cargo test --test integration_test

# Check DHT records (if admin API available)
curl http://localhost:8080/api/mesh/dht/records

# Trace mesh messages
RUST_LOG=debug cargo run -- --mesh-id node-1
```

## File Reference

| File | Purpose |
|------|---------|
| `src/mesh/proxy.rs` | Route requests, extract upstream_id |
| `src/mesh/transport.rs` | Announce upstreams, proxy HTTP |
| `src/mesh/topology.rs` | Local upstream storage, DHT queries |
| `src/mesh/dht/keys.rs` | DHT key type definitions |
| `src/mesh/dht/mod.rs` | DHT value structures |
| `src/mesh/transport_org.rs` | Handle registration requests |
| `src/mesh/transport_peer.rs` | Peer message handling |
| `src/mesh/verification.rs` | Reachability tracking |

## Phase Status

| Phase | Description | Status |
|-------|-------------|--------|
| 2.5.1-5 | Capability signaling | ✅ Complete |
| 2.5.6 | Origin Reachability System | ✅ Complete |
| 2.5.7 | Multi-Origin Discovery & Load Balancing | ✅ Complete |
| 2.5.7b | Nginx-like Domain Routing | ✅ Complete |
| 2.6 | TierKey Encryption for DHT | ✅ Complete |
| 2.7 | TierKey Encryption for Transmission | ✅ Complete |
| 2.8 | Global Node Bootstrap & Key Derivation | ✅ Complete |

## TierKey Encryption (Phase 2.6/2.7)

**Phase 2.6 (DHT Storage) - Complete**:
- `src/mesh/tier_key_encryption.rs` - `TierKeyEncryption` struct with AES-256-GCM
- Master key derived from `node_identity.private_key` via HKDF("maluwaf-tier-key-master")
- `handle_tier_key_announce` encrypts before DHT storage on global nodes
- Non-global nodes skip encryption (they don't store tier keys in DHT)

**Phase 2.7 (Transmission) - Complete**:
- Session key from ML-KEM session used to derive transmission key via HKDF("maluwaf-tier-key-transmit")
- `encrypt_for_transmission()` / `decrypt_for_transmission()` methods added
- Both send and receive paths handle encrypted tier keys with fallback to plaintext

## Global Node Bootstrap (Phase 2.8)

**Purpose**: Global nodes derive their signing key from a shared genesis key, enabling secure bootstrap without manual key distribution.

**Key Derivation**:
```rust
signing_key = HKDF-SHA256(
    IKM = genesis_key (32 bytes),
    info = "maluwaf-global-node-signing-key",
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
$ maluwaf --genesis
Genesis key generated. Add to config:
  [mesh.node_identity]
  genesis_key_base64 = "..."

# Start first node (derives signing key, starts as global)
$ maluwaf

# Second node - copy genesis from first node, add to config, start
$ maluwaf
```

**Verification on Global Node Announce**:
- `GlobalNodeAnnounce(Add/Remove)` - verified with genesis signature
- `GlobalNodeAnnounce(UpdateKeyExchange)` - verified with node's own public key (self-signed)

**Files**:
- `src/mesh/config_identity.rs` - `derive_signing_key_from_genesis()`
- `src/mesh/config.rs` - `genesis_key_base64` field
- `src/mesh/config_mesh.rs` - `load_node_identity()` derives from genesis
- `src/config/main.rs` - calls `load_node_identity()` during config load
- `src/main.rs` - `--genesis` and `--show-node-info` flags

## Origin Reachability System (Phase 2.5.6)

**Purpose**: Edge nodes report route failures, global nodes coordinate verification, penalties applied to unreliable origins.

**Key Components**:

1. **VerificationTaskManager** (`src/mesh/verification.rs`):
   - `report_reachability()` - Called when edge detects failure
   - `initiate_verification_if_needed()` - Creates verification task
   - `process_pending_tasks()` - Background task processing
   - `get_pending_dispatch_tasks()` - Returns tasks needing queries
   - `mark_task_in_progress()` - Updates task with selected node IDs
   - `record_verification_result()` - Records verification response

2. **Handlers** (`src/mesh/transport_peer.rs`):
   - `handle_upstream_verification_query()` - Receives query, verifies TCP reachability, responds
   - `handle_upstream_verification_response()` - Receives response, calls record_verification_result()

3. **Query Dispatching** (`src/mesh/transports/manager.rs`):
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

1. **QUIC server accept loop** (`src/mesh/transport.rs`):
   - `MeshTransport::start()` calls `runtime.start_server()` to accept incoming connections
   - `mesh_accept_loop()` handles incoming connections
   - `handle_incoming_peer_connection()` performs Hello/HelloAck handshake

2. **HTTP stream detection** (`src/mesh/transport_peer.rs`):
   - `handle_peer_message` detects HTTP vs mesh protocol by first byte
   - HTTP method indicators: 'G', 'P', 'H', 'D', 'O', 'T', 'C'
   - Routes HTTP to `handle_http_proxy_stream`

3. **HTTP forwarding to local backends** (`src/mesh/transport_peer.rs`):
   - Parses Host header, looks up `local_upstreams`
   - Connects to backend via TCP, forwards raw HTTP bytes
   - Streams response back on QUIC send_stream

4. **On-demand connection** (`src/mesh/transport.rs`):
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
| `src/mesh/yara_rules.rs` | `publish_rules_to_dht()`, `sync_from_dht()` |
| `src/mesh/dht/keys.rs` | `YaraRuleContent`, `YaraRulesManifest` key types |

**Sync Mechanism**:
- `sync_from_dht()` replaces `send_sync_request_to_global()`
- Queries local DHT cache (populated by DHT announces)
- Compares timestamp with peer manifests (not lexicographic - uses numeric comparison)
- Fetches if different and signature verification passes

### ThreatIntel

**DHT Keys**:
| Key Pattern | Purpose |
|-------------|---------|
| `threat_indicator:{ip}:{threat_type}` | Per-type indicator (composite key, e.g., `threat_indicator:1.2.3.4:IpBlock`) |

**Important**: ThreatIntel uses composite keys with threat_type suffix to prevent collision between different threat types for the same IP. A key without threat_type (e.g., `threat_indicator:1.2.3.4`) will NOT match.

**Signature Verification**:
ThreatIntel indicators are signed using Ed25519. The signature content format is:
```
{indicator_value}:{threat_type as u8}:{severity as u8}:{timestamp}:{source_node_id}
```

**Re-announcement**:
- Global nodes periodically re-announce local indicators via `re_announce_local_indicators()`
- Interval controlled by `re_announce_interval_secs` (default: 300s)
- Only non-expired local-origin indicators are re-announced
- Respects `hub_only_mode` (non-global nodes do not re-announce)

**Sync Mechanism**:
- `sync_from_dht()` replaces mesh broadcast sync
- Gets all `threat_indicator:*` records from local cache
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

### Testing Verification

```bash
# Verify YARA rules in DHT
curl -s http://localhost:8080/api/mesh/dht/records | jq '.[] | select(.key | startswith("yara_rule"))'

# Verify YARA manifests
curl -s http://localhost:8080/api/mesh/dht/records | jq '.[] | select(.key | startswith("yara_rules_manifest"))'

# Verify ThreatIntel in DHT
curl -s http://localhost:8080/api/mesh/dht/records | jq '.[] | select(.key | startswith("threat_indicator"))'
```
