# WAF Mesh Networking

SynVoid supports peer-to-peer mesh networking for distributed DDoS mitigation, threat intelligence sharing, and coordinated protection via QUIC-based communication.

## Opt-In by Default

**Mesh networking is disabled by default.** A standalone SynVoid instance operates completely independently without any WAF-to-WAF, server-WAF, or VPN-WAF connections.

To enable mesh networking:

```toml
[mesh]
enabled = true
role = "edge"  # or "global" for directory nodes

# Optional: customize connection settings
[mesh.connection]
min_peer_connections = 3
max_peer_connections = 20
```

## Overview

The WAF mesh enables multiple SynVoid instances to communicate directly using QUIC, forming an intelligent protection network.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         WAF Mesh Network                                    │
└─────────────────────────────────────────────────────────────────────────────┘

        ┌──────────────────────────────────────────────────────────────┐
        │                                                              │
        │   ┌────────┐     ┌────────┐     ┌────────┐                 │
        │   │  WAF   │◄───►│  WAF   │◄───►│  WAF   │                 │
        │   │ Node 1 │     │ Node 2 │     │ Node 3 │                 │
        │   └────────┘     └────────┘     └────────┘                   │
        │        │              │              │                       │
        │        │   QUIC Streams (Encrypted) │                       │
        │        │              │              │                       │
        │        ▼              ▼              ▼                       │
        │   ┌─────────────────────────────────────────┐               │
        │   │     Shared Threat Intelligence         │               │
        │   │     • IP Reputation Database           │               │
        │   │     • Attack Pattern Signatures       │               │
        │   │     • Bot Detection Results            │               │
        │   │     • Blocklist Synchronization       │               │
        │   └─────────────────────────────────────────┘               │
        │                                                              │
        └──────────────────────────────────────────────────────────────┘
```

## Key Capabilities

### 1. Distributed DDoS Mitigation

When one node detects an attack, all nodes benefit:

```toml
[mesh]
enabled = true
bind_address = "0.0.0.0"
port = 5001

# Connect to peers
[mesh.seeds]
"waf-2.internal" = "10.0.1.20:5001"
"waf-3.internal" = "10.0.1.30:5001"

# Share threat intelligence
[mesh.sync]
ip_reputation = true
blocklists = true
bot_signatures = true
```

### 2. Threat Intelligence Sharing

Attack information propagates across the mesh in real-time:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Threat Intelligence Flow                                  │
└─────────────────────────────────────────────────────────────────────────────┘

  Attack Detected at Node A
         │
         ▼
  ┌─────────────┐
  │  Analyze    │ ← Attack type, source IP, signature
  │  Attack     │
  └─────────────┘
         │
         ▼
  ┌─────────────┐
  │  Propagate  │ ──► All connected nodes
  │  to Mesh    │     receive updated blocklist
  └─────────────┘
         │
         ▼
  ┌─────────────┐
  │  Updated    │ ◄── Immediate protection
  │  IP Rep     │     against attack source
  └─────────────┘
```

### 3. Traffic Scrubbing

Deploy scrubbing centers that inspect and clean traffic:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DDoS Mitigation Architecture                              │
└─────────────────────────────────────────────────────────────────────────────┘

                   Attack Traffic
                        │
                        ▼
           ┌────────────────────────────┐
           │    Edge WAF Nodes          │
           │  (Traffic Aggregation)     │
           └────────────┬───────────────┘
                        │
                        ▼
           ┌────────────────────────────┐
           │    Scrubbing Center       │
           │  ┌────────────────────┐  │
           │  │  WAF Mesh Cluster │  │
           │  │                   │  │
           │  │  ┌───┐  ┌───┐    │  │
           │  │  │WAF│  │WAF│    │  │
           │  │  └───┘  └───┘    │  │
           │  │  ┌───┐  ┌───┐    │  │
           │  │  │WAF│  │WAF│    │  │
           │  │  └───┘  └───┘    │  │
           │  └────────────────────┘  │
           └────────────┬───────────────┘
                        │
                        ▼
           ┌────────────────────────────┐
           │   Clean Traffic            │
           │   to Origin Servers        │
           └────────────────────────────┘
```

### 4. DHT-Based Rule Distribution

YARA rules and threat intelligence are distributed via the mesh DHT for decentralized propagation:

#### YARA Rules Distribution

Global nodes publish signed YARA rules to the DHT:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      YARA Rule Distribution                        │
└─────────────────────────────────────────────────────────────────────┘

  Global Node publishes rules
         │
         ├──► publish_rules_to_dht()
         │        │
         │        └──► DHT key: yara_rule:{content_hash}
         │                     DHT key: yara_rules_manifest:{node_id}
         │
         └──► broadcast DhtRecordAnnounce to k closest peers
                      │
                      ▼
           Peers store in local DHT cache
                      │
                      ▼
           Non-global: sync_from_dht() → apply newest version
```

| DHT Key Pattern | Purpose | TTL |
|-----------------|---------|-----|
| `yara_rule:{content_hash}` | Actual rule content (content-addressed) | 24 hours |
| `yara_rules_manifest:{node_id}` | Global node's current ruleset metadata | 24 hours |

**Signature Verification:** YARA rules are signed using Ed25519. Both manifest and rule content signatures are verified during DHT sync before acceptance.

#### Threat Intelligence Distribution

Threat indicators use composite DHT keys for type-specific lookups:

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Threat Intelligence Distribution                   │
└─────────────────────────────────────────────────────────────────────┘

  Threat detected at node
         │
         ├──► Signed with Ed25519 (signer_public_key embedded)
         │
         ├──► DHT key: threat_indicator:{ip}:{threat_type}
         │        Example: threat_indicator:1.2.3.4:IpBlock
         │
         └──► One-hop broadcast to k closest peers
                      │
                      ▼
           Peers verify signature using from_node's public key
                      │
                      ▼
           Store if signature valid, skip if invalid
```

| DHT Key Pattern | Purpose |
|-----------------|---------|
| `threat_indicator:{ip}:{threat_type}` | Per-type indicator (composite key prevents collision) |

**Important:** The composite key format (`{ip}:{threat_type}`) is required. A key without threat_type will NOT match type-specific queries.

#### Re-announcement

Global nodes periodically re-announce active indicators:
- YARA rules: Every `re_announce_interval_secs` (default: 300s)
- ThreatIntel: Every `re_announce_interval_secs` (default: 300s)

Non-global nodes do not re-announce (respects `hub_only_mode`).

#### Configuration

```toml
[mesh.yara_rules]
enabled = true
sync_interval_secs = 3600
re_announce_interval_secs = 300
require_signature = true  # Verify Ed25519 signatures (default: true)
```

```toml
[mesh.threat_intel]
enabled = true
sync_interval_secs = 300
re_announce_interval_secs = 300
require_signature = true   # Verify threat indicator signatures
```

## Configuration

### Basic Mesh Setup

```toml
[mesh]
enabled = true
bind_address = "0.0.0.0"
port = 5001
role = "edge"

[mesh.seeds]
# Using DNS names (resolved at startup)
"waf-2.internal" = "10.0.1.20:5001"
"waf-3.internal" = "10.0.1.30:5001"

# Connection settings
[mesh.connection]
keepalive = 30
reconnect_interval = 5
max_reconnect_attempts = 10
```

### Synchronization Settings

```toml
[mesh.sync]
# What to share with peers
share_ip_reputation = true
share_blocklists = true
share_bot_signatures = true

# How often to sync
sync_interval = "5s"
full_sync_interval = "5m"
```

### Bandwidth Limits

```toml
[mesh.limits]
# Limit mesh traffic to preserve production bandwidth
max_bandwidth_mbps = 100
max_peers = 20
```

## Security

### Encryption

All mesh traffic is encrypted via QUIC with TLS 1.3:

```toml
[mesh.tls]
# Certificate verification
verify_certificates = true

# Post-quantum key exchange (recommended for long-term security)
enable_post_quantum = true
```

### TLS Passthrough and WAF Enforcement

By default, enabling `tls_passthrough = true` on a site bypasses all L7 WAF inspection (SQLi, XSS, RCE, etc.) since the WAF cannot decrypt the traffic. This is a security trade-off: encrypted traffic is forwarded directly to the origin without inspection.

To force WAF L7 inspection even with TLS passthrough enabled, use `tls_passthrough_enforce_waf`:

```toml
[[site.proxy]]
host = "example.com"
port = 443
tls_passthrough = true

# Force WAF L7 inspection despite TLS passthrough
tls_passthrough_enforce_waf = true
```

When enabled, the WAF will still apply layer 7 attack detection rules to passthrough traffic. Note that this requires additional configuration to terminate TLS at the WAF for inspection, then re-encrypt to the origin.

**Warning**: TLS passthrough without `tls_passthrough_enforce_waf` means attacks embedded in encrypted traffic will not be detected by the WAF. Only layer 3/4 protections (IP rate limiting, connection limits) apply.

### Authentication

SynVoid has transitioned from a shared-secret model to **Decentralized Admission (Consensus-Gated PKI)**. Nodes no longer derive their identity from a shared genesis key; instead, they generate unique local keys and request admission to the mesh.

```toml
[mesh.node_identity]
# Optional: Legacy genesis key (deprecated)
# genesis_key_base64 = "your-genesis-key-here"

# Authorized public keys of global nodes (seeds)
authorized_global_pubkeys = ["base64-encoded-public-key-..."]

# Invite tokens for new global nodes (used during JoinRequest)
invite_tokens = ["secure-one-time-token-1", "secure-one-time-token-2"]
```

### Decentralized Admission Workflow

1.  **Key Generation**: A candidate node generates a local Ed25519 keypair.
2.  **Join Request**: The node sends a `JoinRequest` to an existing Global node, including its public key and an `invite_token`.
3.  **Consensus**: The receiving Global node proposes the admission to the Raft cluster.
4.  **Authorization**: Once committed, the new node's public key is added to the `AuthorizedGlobalNodes` registry and synced across the mesh.

### Graduated Trust Levels

Trust is no longer binary. Nodes are assigned a `trust_level` based on their hardware and attestation:

| Level | Type | Description |
|-------|------|-------------|
| **1** | Software | Standard OS security. Default for all nodes. |
| **2** | TPM/HSM | Keys are bound to hardware (TPM 2.0). |
| **3** | TEE | Execution within a Secure Enclave (SGX, Nitro, SEV). |

Sensitive operations (e.g., signing Organization Tier Keys) can be gated to require a specific minimum trust level.

### Key Hierarchy (Updated)

```
Node Public Key (Ed25519)
    │
    ├──► Raft Admission (Authorized via Consensus)
    │        │
    │        └──► Global Node Status
    │
    └──► Capability Gating (based on Trust Level)
```

> **Note:** The legacy `genesis_key_base64` derivation is **deprecated** and will be removed in a future version. Operators are encouraged to migrate to the `JoinRequest` protocol.


### 0-RTT Configuration

QUIC 0-RTT allows clients to send data before the TLS handshake completes:

```toml
[mesh.tls]
quic_enable_0rtt = false  # Default: false (disabled for security)
```

**Warning:** 0-RTT has replay attack risks. Only enable when:
- The application handles replay detection
- Early data latency is critical
- Risk of replay attacks is acceptable

## Mesh Node Types

SynVoid mesh supports three node roles:

### Global Nodes

Global nodes maintain a complete view of the entire mesh network and serve as:
- **Seed sources** for new edge nodes joining the network
- **Directory servers** for discovering other peers
- **Route aggregators** for upstream service discovery
- **Certificate Authority** for signing node identities

```toml
[mesh]
enabled = true
role = "global"
bind_address = "0.0.0.0"
port = 5001

[mesh.node_identity]
genesis_key_base64 = "your-secret-genesis-key"
```

### Edge Nodes

Edge nodes are typical WAF instances that:
- Connect to global nodes for network discovery
- Share routes and upstream servers
- Participate in traffic routing

```toml
[mesh]
enabled = true
role = "edge"

[mesh.seeds]
- address = "global-1.mesh.example.com:5001"
  global_node_key = "your-genesis-key"
```

### Origin Nodes

Origin nodes are WAFs with direct upstream server connections:
- Announce their upstreams to the mesh
- Preferred routing targets for traffic

```toml
[mesh]
enabled = true
role = "origin"
```

## Network Isolation

### Network IDs

Multiple isolated mesh networks can coexist using `network_id`:

```toml
# Production network
[mesh]
network_id = "production"

[mesh.seeds]
- address = "global-1.mycompany.com:5001"
  network_id = "production"
```

```toml
# Staging network (separate from production)
[mesh]
network_id = "staging"

[mesh.seeds]
- address = "staging-global.mycompany.com:5001"
  network_id = "staging"
```

Nodes with different `network_id` values will not connect to each other, even if addresses are reachable.

---

## Admin API Endpoints

The mesh provides the following admin API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mesh/status` | GET | Get mesh status and node information |
| `/api/mesh/nodes` | GET | List all connected mesh nodes |
| `/api/mesh/nodes/{node_id}` | GET | Get specific node details |
| `/api/mesh/bans` | GET | List active IP bans |
| `/api/mesh/ban/ip` | POST | Ban an IP address |
| `/api/mesh/ban/mesh-id` | POST | Ban a mesh node ID |
| `/api/mesh/ban` | DELETE | Unban an IP or mesh ID |
| `/api/mesh/derive-signing-key` | POST | Derive signing key from genesis key |
| `/api/mesh/audit/report` | POST | Submit client audit report |

### Get Mesh Status

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/mesh/status
```

**Response:**
```json
{
  "is_global_node": true,
  "node_id": "node-abc123",
  "connected_peers": 5,
  "global_nodes": 2,
  "edge_nodes": 3,
  "genesis_key_configured": true,
  "genesis_public_key_fingerprint": "sha256:abc123...",
  "signing_key_derived": true,
  "signing_public_key": "abc123def456...",
  "quic_0rtt_enabled": false,
  "quic_0rtt_warning": null
}
```

### List Mesh Nodes

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/mesh/nodes
```

### Ban an IP

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "reason": "detected_attack",
    "duration_seconds": 3600,
    "site_scope": "global"
  }' \
  http://127.0.0.1:8081/api/mesh/ban/ip
```

### Derive Signing Key

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "genesis_key_base64": "YWJjZDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Ng=="
  }' \
  http://127.0.0.1:8081/api/mesh/derive-signing-key
```

---

## Per-Site Mesh Bandwidth

When using mesh proxying to route traffic through other WAF nodes, bandwidth is tracked per-site. Each site shows:

| Metric | Description |
|--------|-------------|
| `mesh_bytes_sent` | Request bytes sent to mesh peers |
| `mesh_bytes_received` | Response bytes received from mesh peers |

This is distinct from direct proxy bandwidth (`proxied_bytes_sent`/`proxied_bytes_received`) where the WAF connects directly to the origin server.

---

## When to Use Mesh vs Clustering

Choose the right architecture for your deployment:

| Feature | Master-Worker Clustering | WAF Mesh Network |
|---------|-------------------------|------------------|
| **Complexity** | Low (centralized) | Medium (distributed) |
| **Use Case** | Scale single WAF instance | Distribute across regions |
| **Threat Sharing** | No | Yes (blocklists, patterns) |
| **Origin Lookup** | Per-instance | Global across mesh |
| **Setup Effort** | Minutes | Hours |

### Use Master-Worker Clustering When:
- You need to scale a single WAF instance horizontally
- You want simple horizontal scaling within one datacenter
- You don't need threat intelligence sharing between nodes
- You prefer centralized configuration management

### Use WAF Mesh When:
- You have multiple geographic locations
- You want collaborative DDoS defense (shared blocklists)
- You need to hide origin servers behind edge WAFs
- You're building a private CDN or DDoS mitigation network
- You want automatic origin server discovery across nodes
