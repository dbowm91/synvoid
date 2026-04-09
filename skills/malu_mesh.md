# MaluWAF Mesh & DHT Architecture Skill

## Overview

MaluWAF uses a mesh network architecture with DHT-based service discovery for multi-origin routing. This skill provides context for working with the mesh transport, DHT keys, and upstream routing.

## Node Roles

| Role | Purpose | Key Identifier |
|------|---------|---------------|
| **Global** | CA/signer, coordination, DNS authority | `node_id` |
| **Edge** | Proxy requests, route to origins | `node_id` |
| **Origin** | Host sites, register upstreams with global | `node_id` |

**Critical insight**: Origins are NOT global nodes. Global nodes are CAs/coordinators. Origins are separate nodes that register with global nodes.

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
Origin → Global: UpstreamAnnounce (or UpstreamRegistrationRequest)
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

### Why Two Registration Mechanisms?

1. **`UpstreamAnnounce`**: Simple broadcast, fire-and-forget, 5-min TTL
2. **`UpstreamRegistrationRequest`**: Request/response with ownership verification (not wired yet)

**Current state**: Only `UpstreamAnnounce` is used. `UpstreamRegistrationRequest` exists but is dead code (never sent).

### Origin Local Backend Selection

When origin receives proxied request:
- `proxy_http_request` sends raw HTTP to origin
- **Gap**: Origin has no handler to route based on Host header to local backend
- Origin needs to: parse Host header → lookup `mesh.local_upstreams` → forward to correct backend

### Port Validation

- DHT key includes port: `http://example.com:80` ≠ `http://example.com:8080`
- `supported_ports` field in config for advertising (not required for routing)
- Edge can reject port scans early if origin advertises supported ports

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
- Self-healing after ~40 minutes |

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
