# Threat Intelligence in MaluWAF

This document describes the threat intelligence system in MaluWAF, including threat indicators, YARA rules for malware scanning, and the DHT-based distribution mechanism.

## Overview

MaluWAF implements a distributed threat intelligence system that operates across the mesh network. The system consists of two main components:

1. **ThreatIntel** - IP block lists, rate limiting indicators, and suspicious activity reports
2. **YARA Rules** - Malware scanning rules distributed via DHT

Both components use Ed25519 signatures for authenticity verification and the DHT for primary propagation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Global Node                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │ ThreatIntelMgr   │  │  YaraRulesMgr    │  │  RecordStore    │   │
│  │                  │  │                  │  │                  │   │
│  │ - announce_local  │  │ - publish_rules  │  │ - store_and_     │   │
│  │ - publish_to_dht  │  │ - sync_from_dht  │  │   announce       │   │
│  │ - sync_from_dht   │  │ - broadcast      │  │ - get_by_prefix  │   │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘   │
│           │                     │                      │              │
│           └─────────────────────┼──────────────────────┘              │
│                                 │                                     │
│                    ┌────────────▼────────────┐                      │
│                    │         DHT             │                       │
│                    │                         │                       │
│                    │  threat_indicator:*      │                       │
│                    │  yara_rule:*            │                       │
│                    │  yara_rules_manifest:*  │                       │
│                    └────────────┬────────────┘                       │
└─────────────────────────────────┼─────────────────────────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │   Edge Node     │ │   Edge Node     │ │   Origin Node   │
    │                 │ │                 │ │                 │
    │ - sync from DHT │ │ - sync from DHT │ │ - sync from DHT │
    │ - apply threats  │ │ - apply threats │ │ - apply threats  │
    └─────────────────┘ └─────────────────┘ └─────────────────┘
```

## ThreatIntel

ThreatIntel manages distributed threat indicators including IP blocks, rate limit violations, and suspicious activity reports.

### Threat Types

| Type | Description | Local Action |
|------|-------------|--------------|
| `IpBlock` | Malicious IP address | Block IP in BlockStore |
| `RateLimitViolation` | Excessive request rate | Apply rate limit |
| `SuspiciousActivity` | Anomalous behavior pattern | Block with severity-based TTL |
| `AsnBlock` | Entire ASN blocked | Log attack type |
| `DomainBlock` | Malicious domain | Not yet implemented |
| `UrlBlock` | Malicious URL | Not yet implemented |
| `CertBlock` | Malicious certificate | Not yet implemented |

### Composite Keys

Threat indicators use composite keys to prevent collision between different threat types for the same indicator:

```
threat_indicator:{indicator_value}:{threat_type}
```

Examples:
- `threat_indicator:192.168.1.100:IpBlock`
- `threat_indicator:10.0.0.1:RateLimitViolation`
- `threat_indicator:192.168.1.100:SuspiciousActivity`

The `make_indicator_key()` function in `src/mesh/threat_intel.rs:25-27` creates these keys.

### Indicator Structure

```rust
pub struct ThreatIndicator {
    pub threat_type: ThreatType,
    pub indicator_value: String,        // IP address, domain, URL, etc.
    pub severity: ThreatSeverity,        // Low, Medium, High, Critical
    pub reason: String,                  // Human-readable description
    pub ttl_seconds: u64,               // Time-to-live
    pub source_node_id: String,          // Originating node
    pub timestamp: u64,                 // Unix timestamp
    pub site_scope: String,              // Applicable sites
    pub rate_limit_requests: Option<u64>,
    pub rate_limit_window_secs: Option<u64>,
    pub suspicious_pattern: Option<String>,
    pub signature: Vec<u8>,              // Ed25519 signature
    pub signer_public_key: Option<String>,
}
```

### Signature Format

ThreatIntel indicators are signed using Ed25519 with the following content format:

```
{indicator_value}:{threat_type}:{severity}:{timestamp}:{source_node_id}
```

Example:
```
192.168.1.100:0:3:1713523200:node-abc123
```

Where threat_type and severity are their numeric enum values.

### Severity Levels

| Level | Numeric | TTL (Suspicious) | TTL (Rate Limit) |
|-------|---------|------------------|------------------|
| Unspecified | 0 | 300s | ttl_seconds |
| Low | 1 | 900s | ttl_seconds |
| Medium | 2 | 1800s | ttl_seconds |
| High | 3 | 3600s | ttl_seconds |
| Critical | 4 | 7200s | ttl_seconds |

### Local Announcements

Nodes can announce local threats that get propagated to the mesh:

- `announce_local_block()` - IP block from WAF detection
- `announce_honeypot_indicator()` - Threat detected by honeypot
- `announce_local_rate_limit()` - Rate limit exceeded
- `announce_local_suspicious()` - Suspicious activity pattern

#### HTTP Honeypot Integration

HTTP honeypot detections are announced via `announce_honeypot_indicator()` when a client accesses a honeypot trap path. The integration works as follows:

**By-Design Behavior:**

1. **Local blocking always works**: When `block_ip_for_honeypot()` is called, the IP is always blocked locally via `BlockStore`, regardless of whether threat intel is available. This ensures honeypot protection works in standalone mode.

2. **Mesh announcement is best-effort**: If threat intel is configured, the honeypot hit is announced to the mesh network via `announce_honeypot_indicator()`. If threat intel is unavailable, local blocking still proceeds normally.

3. **Per-IP trap isolation**: Trap paths are generated uniquely per IP address using random path segments. This prevents one IP from enumerating all trap paths and ensures bots cannotlearn trap locations from other clients' behavior.

4. **TTL-based trap expiration**: Generated traps expire after `ttl_secs` (default 3600s), preventing stale traps from accumulating.

**Flow:**
```
Bot accesses honeypot path /_waf_hp_xxxxxxxx/xxxxxxxx
    ↓
HoneypotTracker::is_honeypot_hit() detects trap hit
    ↓
WAF::block_ip_for_honeypot() called
    ↓
┌─────────────────────────────────────────────┐
│ 1. BlockStore.block_ip() - Always succeeds  │
│    (local IP blocking)                      │
└─────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────┐
│ 2. If threat_intel available:               │
│    threat_intel.announce_honeypot_indicator │
│    (mesh distribution)                      │
└─────────────────────────────────────────────┘
```

**Configuration**: HTTP honeypots are configured under `[defaults.bot.css_honeypot]` in the bot protection settings. See [BOT_PROTECTION.md](./BOT_PROTECTION.md) for details.

### DHT Propagation

When publishing to DHT:

1. Critical/High severity from global nodes uses `store_and_announce_critical()` for faster propagation
2. Other indicators use standard `store_and_announce()`
3. All indicators are stored with a 24-hour TTL

### Sync Behavior

Non-global nodes sync from DHT via `sync_from_dht()`:

1. Queries DHT for all records with prefix `threat_indicator:`
2. Verifies signature on each record
3. Skips records from local node (identified by node_id)
4. Applies newer records (based on timestamp)
5. Removes local indicators that no longer exist in DHT

### Configuration

```toml
[mesh.threat_intel]
enabled = true
push_enabled = true          # Broadcast threats to peers
sync_enabled = true          # Sync from DHT
sync_interval_secs = 300     # How often to sync
threat_sync_interval_secs = 60
push_severity_threshold = "medium"  # Minimum severity to push
min_ttl_seconds = 60
max_indicators_per_message = 50
hub_only_mode = false        # Only global nodes distribute
re_announce_interval_secs = 300  # Re-announce interval
```

### Pending Queue

The system uses a `VecDeque` with `MAX_PENDING_INDICATORS = 10000` to buffer indicators for broadcast. When the queue is full, the oldest indicator is dropped.

## YARA Rules

YARA rules are used for malware scanning, particularly on file uploads.

### Rule Distribution

YARA rules follow a content-addressed distribution model:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Global Node publishes:                                              │
│                                                                     │
│  1. Manifest: yara_rules_manifest:{node_id}                          │
│     {version, content_hash, node_id, timestamp, signature}          │
│                                                                     │
│  2. Rule Content: yara_rule:{content_hash}                          │
│     {version, rules, content_hash, node_id, timestamp, signature}    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DHT Record (24h TTL)                                               │
│                                                                     │
│  Key: yara_rule:{sha256_of_rules}                                   │
│  Value: JSON with rules content + metadata + signature               │
│                                                                     │
│  Key: yara_rules_manifest:{node_id}                                 │
│  Value: JSON with version + content_hash + signature                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Signature Formats

**Manifest signature content:**
```
{version}:{content_hash}:{node_id}:{timestamp}
```

**Rule content signature content:**
```
{version}:{rules}:{content_hash}:{node_id}:{timestamp}
```

### Manifest-Based Versioning

The system uses a manifest to track rule versions without storing full rules in the manifest:

1. Global node computes SHA-256 hash of rules
2. Publishes manifest with version and content_hash
3. Publishes rule content separately with same content_hash
4. Other nodes fetch manifest, then fetch rule content by hash

This allows efficient version comparison without downloading full rules.

### Rule Sources

| Source | Description |
|--------|-------------|
| `Local` | Rules applied directly on this node |
| `Feed` | Rules from external YARA rule feed |
| `MeshGlobal` | Rules synced from global node via mesh |
| `MeshEdgeApproved` | Edge-submitted rules approved by global |

### Edge Submissions

Edge nodes can submit rules for approval when `allow_edge_submissions = true`:

1. Edge submits via `submit_rule_for_approval()`
2. Global node receives and stores pending submission
3. Global operator approves/rejects via admin API
4. Approved rules are published to DHT with version `edge-{submission_id}:{timestamp}`

### Rule Validation

Before accepting rules:

1. Size check: must not exceed `max_rules_size_kb` (default 1MB)
2. Must contain at least one `rule ` declaration
3. YARA syntax validation via `yara_x::compile()`

### Sync Process

When syncing from DHT:

1. Query all `yara_rules_manifest:*` records
2. Skip own manifest
3. Verify manifest signature
4. Compare content_hash with local rules
5. Fetch rule content by hash
6. Verify rule content signature
7. Select newest version by timestamp
8. Apply rules if content differs

### File Upload Scanning

The FileManager integrates with YARA rules for malware scanning on upload:

```rust
// In src/static_files/file_manager.rs
fn reload_yara_rules_if_needed(&self) -> Result<(), YaraError> {
    // Sync with global YaraRulesManager
    // Reload scanner when version changes
}
```

When `scan_on_upload = true`, uploaded files are scanned before being stored.

### Configuration

```toml
[mesh.yara_rules]
enabled = true
sync_interval_secs = 3600         # How often to sync from DHT
re_announce_interval_secs = 300   # Re-publish interval for global nodes
allow_edge_submissions = false     # Allow edge nodes to submit rules
require_global_approval = true     # Submissions need approval
require_signature = true          # Reject unsigned rules
max_rules_size_kb = 1024           # Maximum rule size
trusted_signers = []              # Ed25519 public keys that can sign
```

## Global vs Edge Behavior

### Global Nodes

| Action | Behavior |
|--------|----------|
| Publish indicators | Yes - announces to DHT and broadcasts to peers |
| Sync indicators | Yes - syncs from DHT periodically |
| Publish YARA rules | Yes - publishes manifest and rule content to DHT |
| Re-announce indicators | Yes - every `re_announce_interval_secs` |
| Accept edge submissions | Yes - stores pending submissions for approval |

### Edge/Origin Nodes

| Action | Behavior |
|--------|----------|
| Publish indicators | Only if `hub_only_mode = false` |
| Sync indicators | Yes - syncs from DHT |
| Publish YARA rules | No - only global nodes publish |
| Re-announce indicators | No - only global nodes re-announce |
| Submit YARA rules | Yes, if `allow_edge_submissions = true` |

### `hub_only_mode`

When `hub_only_mode = true`:
- Non-global nodes do not publish indicators to DHT
- They still sync indicators from DHT
- Useful when only global nodes should distribute threat data

## Signature Verification

All signed records undergo Ed25519 signature verification:

1. Extract signature and signer public key from record
2. Reconstruct the signed content using known format
3. Verify signature using Ed25519 verify
4. Reject record if verification fails
5. For YARA rules: If `trusted_signers` is non-empty, verify signer is in the list

### Timestamp Bounds Checking

YARA rules sync enforces timestamp bounds to prevent replay attacks:

- **Future bound**: 60 seconds (handles clock skew)
- **Past bound**: 24 hours (allows for delayed propagation)

Records with timestamps outside these bounds are rejected with a warning log.

### Trusted Signers

When `trusted_signers` is configured with one or more Ed25519 public keys:
- Only rules signed by keys in the `trusted_signers` list are accepted
- When empty (default), any signer is accepted (backward compatible)

```toml
[mesh.yara_rules]
trusted_signers = [
    "base64_encoded_ed25519_pubkey_1",
    "base64_encoded_ed25519_pubkey_2"
]
```

### Verification Failure Handling

| Component | On Signature Failure |
|----------|---------------------|
| ThreatIntel (mesh message) | Log warning, do not apply indicator |
| ThreatIntel (DHT sync) | Skip indicator, do not apply |
| YARA manifest | Skip this manifest, try next |
| YARA rule content | Skip, do not apply rules |

## Troubleshooting

### Indicators Not Propagating

1. Check `mesh.threat_intel.enabled = true`
2. Verify node has a signer configured (`signer` not None)
3. Check logs for "Cannot publish threat indicator: no signer configured"
4. Verify transport is available ("Transport not available for DHT publish")

### YARA Rules Not Syncing

1. Check `mesh.yara_rules.enabled = true`
2. Verify global node has published rules (`publish_rules_to_dht`)
3. Check logs for "YARA DHT sync: signature verification failed"
4. Verify `require_signature = false` for testing without signatures

### Signature Verification Failures

1. Ensure sender has a valid Ed25519 signing key
2. Check that public key is properly encoded (base64)
3. Verify the content format matches expected structure
4. Check timestamp bounds (clock skew)

### High Memory Usage

- `MAX_PENDING_INDICATORS = 10000` limits indicator queue
- `VecDeque` automatically evicts oldest entries when full
- Consider reducing `max_indicators_per_message` if memory pressure

### DHT Lookup Misses

- DHT records have 24-hour TTL
- Records are not automatically refreshed
- Global nodes re-announce every `re_announce_interval_secs`
- Non-global nodes must sync periodically to get fresh records

## Metrics

The system records metrics for monitoring:

| Metric | Description |
|--------|-------------|
| `threat_intel_dht_publish` | Successful DHT publishes |
| `threat_intel_dht_publish_failed` | Failed DHT publishes |
| `threat_intel_dht_lookup_hit` | DHT lookup cache hits |
| `threat_intel_dht_lookup_miss` | DHT lookup cache misses |
| `threat_intel_dht_sync` | DHT sync attempts |
| `threat_intel_dht_sync_success` | Successful DHT syncs |
| `threat_intel_dht_sync_added` | Indicators added during sync |
| `threat_intel_dht_sync_removed` | Indicators removed during sync |

## Security Considerations

1. **Signature Required**: Enable `require_signature = true` to reject unsigned rules
2. **Trusted Signers**: Configure `trusted_signers` to accept rules only from specific keys
3. **Global Node Only Publishing**: Use `hub_only_mode = true` to prevent edge nodes from flooding
4. **Reputation System**: ThreatIntel includes a reputation manager that evaluates peer reliability
5. **No Global Node Blocking**: Indicators targeting global node IPs are rejected

## Key Files

| File | Description |
|------|-------------|
| `src/mesh/threat_intel.rs` | ThreatIntelligenceManager implementation |
| `src/mesh/yara_rules.rs` | YaraRulesManager implementation |
| `src/mesh/dht/keys.rs` | DHT key definitions and formats |
| `src/mesh/config.rs` | Configuration structures |
| `src/static_files/file_manager.rs` | YARA integration for file scanning |
| `src/block_store.rs` | IP blocking implementation |
