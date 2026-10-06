# WAF Mesh Networking

SynVoid supports peer-to-peer mesh networking for distributed DDoS mitigation, threat intelligence sharing, and coordinated protection via QUIC-based communication.

## Opt-In by Default

**Mesh networking is disabled by default.** A standalone SynVoid instance operates completely independently without any WAF-to-WAF, server-WAF, or VPN-WAF connections. (The `mesh` Cargo feature is compiled in by default, but runtime participation requires `enabled = true` below — `MeshConfig::enabled` defaults to `false`.)

> **Section location:** the mesh runtime is initialized from the nested `[tunnel.mesh]` section (`MainConfig::tunnel.mesh`, read by `init_mesh_control_plane`, the worker's `init_mesh_and_threat_intel`, and `--mesh-agent`). A top-level `[mesh]` section is also accepted by the parser and is what the HTTP server uses for mesh proxy config, but it does **not** by itself start the mesh subsystem. Write every example below under `[tunnel.mesh]`.

To enable mesh networking:

```toml
[tunnel.mesh]
enabled = true
# `role` is a numeric bitmask, not a string: EDGE=1, GLOBAL=2, ORIGIN=4,
# GLOBAL|EDGE=3. String values such as `role = "edge"` fail to parse.
role = 1  # or 2 for global/directory nodes

# Optional: customize connection settings
[tunnel.mesh.connection]
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
[tunnel.mesh]
enabled = true
bind_address = "0.0.0.0"
port = 50051  # MeshConfig default is 50051

# Connect to peers (seeds are a LIST of tables, not a key/value map)
[[tunnel.mesh.seeds]]
address = "waf-2.internal:50051"
public_key = "base64-encoded-global-node-public-key"

[[tunnel.mesh.seeds]]
address = "waf-3.internal:50051"
public_key = "base64-encoded-global-node-public-key"

# Share threat intelligence (opt-in; both default to `enabled = false`)
[tunnel.mesh.threat_intel]
enabled = true
push_enabled = true
sync_enabled = true

[tunnel.mesh.yara_rules]
enabled = true
```

### 2. Threat Intelligence Sharing

> **Authority split:** Raft is the canonical, authoritative replicated state (node admission, revocations, org/tier keys). The DHT is **advisory** — it distributes indicators, YARA manifests, and route hints, but it is never zone authority and never a resolution fallback. A write that cannot reach quorum reports `PropagationStatus::QuorumUnavailable`; mesh propagation is best-effort (`QueuedBestEffort`) and never silently reports success. See `architecture/distributed_state_contract.md`.

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
| `yara_rule:{content_hash}` | Actual rule content (content-addressed) | 24 hours (86400s) |
| `yara_rules_manifest:{node_id}` | Global node's current ruleset metadata | 24 hours (86400s) |
| `yara_chunk:{content_hash}:{index}` | Gzip-compressed chunk, used when the ruleset exceeds 32 KiB (`YARA_RULE_CHUNK_SIZE`) | 24 hours (86400s) |

Only **source text** is distributed. Compiled YARA artifacts are never published or fetched: a legacy `compiled_hash` on an inbound manifest is ignored, and `YaraCompiledRuleContentRecord` is retained for wire compatibility only (`crates/synvoid-mesh/src/mesh/yara_rules.rs`, "Phase 26: no compiled-blob publication").

**Signature Verification:** YARA rules are signed using Ed25519. Both manifest and rule content signatures are verified during DHT sync before acceptance. Manifests beyond the freshness window (`YARA_TIMESTAMP_PAST_BOUND_SECS` = 24h, `YARA_TIMESTAMP_FUTURE_BOUND_SECS` = 60s) are skipped, and multi-signature manifests must meet a 2/3 threshold of `trusted_signers`.

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
- YARA rules: every `yara_rules.re_announce_interval_secs` (default: 3600s)
- ThreatIntel: re-announce runs every 300s internally (`DEFAULT_RE_ANNOUNCE_INTERVAL_SECS`). This interval is **not** operator-configurable — `synvoid_config`'s `[mesh.threat_intel]` DTO has no `re_announce_interval_secs` field, so setting it in TOML is silently ignored.

Non-global nodes do not re-announce: both `publish_rules_to_dht()` and `re_announce_local_indicators()` return early for a non-global role, and both additionally skip while `hub_only_mode` is set.

#### Configuration

```toml
[tunnel.mesh.yara_rules]
enabled = true
sync_interval_secs = 3600
re_announce_interval_secs = 3600
require_signature = true  # Verify Ed25519 signatures (default: true)
trusted_signers = ["base64-encoded-global-node-public-key-..."]
max_rules_size_kb = 1024
hub_only_mode = false
```

```toml
[tunnel.mesh.threat_intel]
enabled = true
push_enabled = true
sync_enabled = true
sync_interval_secs = 300
threat_sync_interval_secs = 3600
push_severity_threshold = "high"
min_ttl_seconds = 60
max_indicators_per_message = 100
hub_only_mode = false
```

Threat-indicator signatures are gated by `trusted_signers` (the Ed25519 public keys accepted from peers); there is no `require_signature` toggle on `[mesh.threat_intel]`.

## Configuration

### Basic Mesh Setup

```toml
[tunnel.mesh]
enabled = true
bind_address = "0.0.0.0"
port = 50051          # default: 50051
role = 1              # EDGE; GLOBAL=2, ORIGIN=4, GLOBAL|EDGE=3

# Optional: human-readable node identity
# node_id = "edge-us-east-1"
# network_id = "production"

# Seeds are a LIST of tables (MeshSeedNode), not a key/value map.
# `public_key` supplies the authorized global-node key used for discovery.
[[tunnel.mesh.seeds]]
address = "global-1.example.com:50051"
public_key = "base64-encoded-global-node-public-key"
node_id = "global-1"
network_id = "production"

# Connection settings (MeshConnectionConfig)
[tunnel.mesh.connection]
keepalive_interval_secs = 10     # default: 10
announce_interval_secs = 30      # default: 30
health_check_interval_secs = 30  # default: 30
min_peer_connections = 3         # default: 3
max_peer_connections = 20        # default: 20
```

There is no `[mesh.sync]` or `[mesh.limits]` section. `MeshConfig` has no `sync`, `limits`, or bandwidth-cap fields; unknown TOML keys are silently ignored, so those examples were inert. Synchronization is configured per subsystem (`[tunnel.mesh.threat_intel]`, `[tunnel.mesh.yara_rules]`) and peer counts are bounded by `[tunnel.mesh.connection]`. Bandwidth sampling interval is `bandwidth_report_interval_secs` (default 60s).

### Routing Settings

```toml
[tunnel.mesh.routing]
enabled = true             # default: true
max_hops = 3               # default: 3
query_timeout_ms = 5000    # default: 5000
retry_attempts = 2         # default: 2
peer_query_count = 3       # default: 3
allow_all_services = true  # default: true
route_queries_per_minute = 6000     # default: 6000
mesh_messages_per_sec = 10000       # default: 10000
```

## Security

### Encryption

Mesh traffic runs over QUIC. `MeshTlsConfig` enforces mutual TLS by default and pins the minimum version to TLS 1.3; `strict_certificate_validation` and `enforce_mutual_tls` both default to `true`:

```toml
[tunnel.mesh.tls]
cert_path = "/etc/synvoid/certs/mesh.crt"
key_path = "/etc/synvoid/certs/mesh.key"
ca_path = "/etc/synvoid/certs/ca.crt"
auto_generate_certs = false   # default: false
ca_mode = false
min_tls_version = "1.3"       # default: "1.3"
enforce_mutual_tls = true     # default: true
strict_certificate_validation = true  # default: true
auto_monitor_expiration = true        # default: true
certificate_pin_public_keys = ["base64-encoded-spki-pin-..."]
```

There is no `verify_certificates` or `enable_post_quantum` field on `[mesh.tls]`. Certificate verification is not optional — it is `strict_certificate_validation` (default `true`); disabling it is an explicit operator downgrade.

### TLS Passthrough and WAF Enforcement

By default, enabling `tls_passthrough = true` keeps L7 WAF inspection enabled. Set `tls_passthrough_enforce_waf = false` only for an intentional bypass; encrypted traffic is then forwarded directly to the origin without inspection.

To force WAF L7 inspection even with TLS passthrough enabled, use `tls_passthrough_enforce_waf`. These keys live in the site file's top-level `[proxy]` section (`SiteConfig.proxy`), not in `main.toml`; the site is identified by `[site] domains` and listens via `[[site.listen]]`:

```toml
# config/sites/example.com.toml
[site]
domains = ["example.com"]

[site.upstream]
default = "http://127.0.0.1:8000"

[[site.listen]]
address = "0.0.0.0"
port = 443
ssl = true

[proxy]
tls_passthrough = true

# Force WAF L7 inspection despite TLS passthrough
tls_passthrough_enforce_waf = true
```

When enabled, the WAF will still apply layer 7 attack detection rules to passthrough traffic. Note that this requires additional configuration to terminate TLS at the WAF for inspection, then re-encrypt to the origin.

**Warning**: TLS passthrough with `tls_passthrough_enforce_waf = false` means attacks embedded in encrypted traffic will not be detected by the WAF. Only layer 3/4 protections (IP rate limiting, connection limits) apply.

To enforce that all TLS passthrough sites have either WAF enforcement or rate limiting configured, enable the strict policy:

```toml
[security]
strict_tls_passthrough_policy = true  # Default: false
```

When enabled, `validate_tls_passthrough_waf_policy()` returns an error for any TLS passthrough site that explicitly disables WAF enforcement and lacks rate limit configuration, preventing silently unprotected sites in production.

### Authentication

SynVoid has transitioned from a shared-secret model to **Decentralized Admission (Consensus-Gated PKI)**. Nodes no longer derive their identity from a shared genesis key; instead, they generate unique local keys and request admission to the mesh.

```toml
[tunnel.mesh.node_identity]
# Local node identity material (file-backed keys; see below)
private_key_path = "/etc/synvoid/mesh/node.key"
encryption_passphrase_path = "/etc/synvoid/mesh/passphrase"
is_trusted = false
genesis_org_id = "org-1"

# Legacy genesis key — still honored (has_genesis_key()), but not the
# admission path: see the Decentralized Admission Workflow below.
genesis_key_base64 = "base64-encoded-32-byte-genesis-key"

[tunnel.mesh.global_node]
# Invite tokens validated (constant-time) against an inbound JoinRequest.
# This lives under [mesh.global_node], NOT [mesh.node_identity].
invite_tokens = ["secure-one-time-token-1", "secure-one-time-token-2"]

# Optional key exchange material for global nodes
# x25519_private_key_base64 = "..."
# ed25519_private_key_base64 = "..."
key_exchange_enabled = false
```

There is no `authorized_global_pubkeys` config key. Authorized global-node keys are collected from the seeds themselves: `MeshDiscovery::get_authorized_global_pubkeys()` projects `seeds[].public_key`, so authorization is declared per seed via `[[mesh.seeds]] public_key = ...`.

### Decentralized Admission Workflow

1.  **Key Generation**: A candidate node generates a local Ed25519 keypair.
2.  **Join Request**: The node sends a `JoinRequest` to an existing Global node, including its public key and an `invite_token`.
3.  **Consensus**: The receiving Global node proposes the admission to the Raft cluster.
4.  **Authorization**: Once committed, the new node's public key is added to the `AuthorizedGlobalNodes` registry and synced across the mesh.

### Graduated Trust Levels

Admitted nodes carry a `trust_level` recorded in the Raft `authorized_global_nodes` registry. The JoinRequest handler assigns exactly two values today (`handle_join_request` in `crates/synvoid-mesh/src/mesh/transport_peer.rs`):

| Level | Assigned when | Description |
|-------|---------------|-------------|
| **0** | Admission rejected | No trust. Returned in `JoinResponse` for an invalid invite token or a failed Raft proposal. |
| **1** | Admission granted, no `attestation_report` | Software-only admission. This is also the DHT node default (`trust_level: 1`). |
| **2** | Admission granted with an `attestation_report` | The client presented an attestation report. |

Higher levels (hardware-bound TPM/HSM keys, TEE enclaves such as SGX/Nitro/SEV) are **not** assigned by any current code path, and no operation is gated on a minimum `trust_level` — including Organization Tier Key signing. Treat level 2 as "an attestation report was supplied", not as verified hardware binding.

### Key Hierarchy (Updated)

```
Node Public Key (Ed25519)
    │
    ├──► Raft Admission (Authorized via Consensus)
    │        │
    │        └──► Global Node Status (trust_level recorded)
    │
    └──► Discovery trust set (from seeds[].public_key)
```

> **Note:** `genesis_key_base64` is still a live configuration path (`MeshConfig::has_genesis_key()` reports it to `/api/mesh/status`), but it is the legacy identity model — the `JoinRequest` protocol is the admission path. The source does not mark the field deprecated, so no removal timeline is claimed here.


### 0-RTT Configuration

QUIC 0-RTT allows clients to send data before the TLS handshake completes:

```toml
[tunnel.mesh.tls]
quic_enable_0rtt = false  # Default: false (disabled for security)
```

When enabled, `/api/mesh/status` also returns a `quic_0rtt_warning` string alongside `quic_0rtt_enabled`.

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
[tunnel.mesh]
enabled = true
role = 2       # GLOBAL (EDGE=1, ORIGIN=4, GLOBAL|EDGE=3)
bind_address = "0.0.0.0"
port = 50051

[tunnel.mesh.node_identity]
genesis_key_base64 = "base64-encoded-32-byte-genesis-key"

# Invite tokens this global node will validate on inbound JoinRequests
[tunnel.mesh.global_node]
invite_tokens = ["secure-one-time-token-1"]
```

### Edge Nodes

Edge nodes are typical WAF instances that:
- Connect to global nodes for network discovery
- Share routes and upstream servers
- Participate in traffic routing

```toml
[tunnel.mesh]
enabled = true
role = 1       # EDGE

[[tunnel.mesh.seeds]]
address = "global-1.mesh.example.com:50051"
public_key = "base64-encoded-global-node-public-key"
# Optional per-seed fields: node_id, network_id, quic_port,
# pinned_cert_fingerprint, global_node_key
```

### Origin Nodes

Origin nodes are WAFs with direct upstream server connections:
- Announce their upstreams to the mesh
- Preferred routing targets for traffic

```toml
[tunnel.mesh]
enabled = true
role = 4       # ORIGIN

# Announced upstreams are declared explicitly; `peered_wafs` is the
# authorization list, so an unlisted node receives "route not found"
# rather than the real origin URL.
[tunnel.mesh.local_upstreams.web]
upstream_url = "http://10.0.1.10:8080"
priority_tier = 0
allowed_protocols = ["http"]

[[tunnel.mesh.local_upstreams.web.peered_wafs]]
node_id = "edge-us-east-1"
allowed = true
```

`MeshNodeRole` is a bitmask, not an enum, so `GLOBAL | EDGE` (3) and the other combinations in `MeshNodeRole` are also valid values.

## Network Isolation

### Network IDs

Multiple isolated mesh networks can coexist using `network_id` (set on both the node and each seed):

```toml
# Production network
[tunnel.mesh]
network_id = "production"

[[tunnel.mesh.seeds]]
address = "global-1.mycompany.com:50051"
network_id = "production"
```

```toml
# Staging network (separate from production)
[tunnel.mesh]
network_id = "staging"

[[tunnel.mesh.seeds]]
address = "staging-global.mycompany.com:50051"
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

The mutating endpoints (`ban/ip`, `ban/mesh-id`, `ban`, `derive-signing-key`) return a typed `AdminMutationResult` — never a generic `{"success": true}`. A block or unblock emits an `AdminAuditEvent`, quorum loss is reported as `PropagationStatus::QuorumUnavailable` rather than a silent success, and mesh propagation is best-effort `QueuedBestEffort`. Raw session tokens are never stored; `AdminActor.session_id_hash` holds a hash. Details: `architecture/admin_control_plane_authority.md`.

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

`BanIpRequest` fields: `ip` (required), `reason` (required; empty becomes `manual_admin_ban`), `duration_seconds`, `site_scope` (defaults to `global`). The write goes through `block_ip_with_provenance` with `BlockProvenanceKind::AdminManual`.

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

`genesis_key_base64` is decoded with `URL_SAFE_NO_PAD` (not standard base64 with padding) and must decode to exactly 32 bytes; otherwise the endpoint returns `AdminMutationStatus::InvalidRejected` with `Genesis key must be 32 bytes`.

```bash
curl -X POST \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "genesis_key_base64": "YWJjZDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Ng"
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

This is distinct from direct proxy bandwidth (`proxied_bytes_sent`/`proxied_bytes_received`) where the WAF connects directly to the origin server. Both pairs are `u64` fields on `SiteMetrics` (`crates/synvoid-admin/src/handlers/stats.rs:66`) and are exposed through the admin stats handlers.

---

## When to Use Mesh vs Clustering

Choose the right architecture for your deployment:

| Feature | Supervisor-Worker Clustering | WAF Mesh Network |
|---------|-------------------------|------------------|
| **Complexity** | Low (centralized) | Medium (distributed) |
| **Use Case** | Scale single WAF instance | Distribute across regions |
| **Threat Sharing** | No | Yes (blocklists, patterns) |
| **Origin Lookup** | Per-instance | Routed through the mesh routing layer (`[tunnel.mesh.routing]`, `local_upstreams`, `peered_wafs`) |
| **Setup Effort** | Minutes | Hours |

### Use Supervisor-Worker Clustering When:
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
