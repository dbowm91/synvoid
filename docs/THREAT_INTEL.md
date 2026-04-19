# Threat Intelligence in MaluWAF

MaluWAF implements a distributed threat intelligence system that shares indicators across mesh nodes to provide coordinated protection against malicious actors.

## Table of Contents

1. [Overview](#overview)
2. [ThreatIntel Indicators](#threatintel-indicators)
   - [Indicator Types](#indicator-types)
   - [Severity Levels](#severity-levels)
   - [Indicator Structure](#indicator-structure)
3. [YARA Rules and Malware Scanning](#yara-rules-and-malware-scanning)
   - [YARA Rule Format](#yara-rule-format)
   - [Rule Distribution via DHT](#rule-distribution-via-dht)
   - [File Upload Scanning](#file-upload-scanning)
   - [Rule Manifest and Content Hash Verification](#rule-manifest-and-content-hash-verification)
4. [DHT-Based Distribution](#dht-based-distribution)
   - [Publishing to DHT](#publishing-to-dht)
   - [Key Format](#key-format)
   - [TTL and Expiration](#ttl-and-expiration)
   - [Re-Announcement](#re-announcement)
5. [Global Node vs Edge Behavior](#global-node-vs-edge-behavior)
6. [Signature Verification](#signature-verification)
7. [Configuration](#configuration)
8. [Troubleshooting](#troubleshooting)
9. [Related Documentation](#related-documentation)

## Overview

The threat intelligence system consists of two main components:

1. **ThreatIntel** - Manages IP block lists, rate limiting indicators, and suspicious activity reports
2. **YARA Rules** - Malware scanning rules distributed via DHT for file upload scanning

Both components use Ed25519 signatures for authenticity verification and the DHT for primary propagation. The system is designed for high scalability, targeting 500K+ requests/second with minimal per-request allocations.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Global Node                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐│
│  │ ThreatIntelMgr    │  │  YaraRulesMgr    │  │  RecordStore     ││
│  │                  │  │                  │  │                  ││
│  │ - announce_local │  │ - publish_rules  │  │ - store_and_     ││
│  │ - publish_to_dht │  │ - sync_from_dht  │  │   announce       ││
│  │ - sync_from_dht  │  │ - broadcast      │  │ - get_by_prefix  ││
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘│
│           │                     │                      │           │
│           └─────────────────────┼──────────────────────┘           │
│                                 │                                   │
│                    ┌────────────▼────────────┐                     │
│                    │         DHT             │                     │
│                    │                         │                     │
│                    │  threat_indicator:*      │                     │
│                    │  yara_rule:*            │                     │
│                    │  yara_rules_manifest:*  │                     │
│                    └────────────┬────────────┘                     │
└─────────────────────────────────┼───────────────────────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │   Edge Node     │ │   Edge Node     │ │   Origin Node   │
    │                 │ │                 │ │                 │
    │ - sync from DHT │ │ - sync from DHT │ │ - sync from DHT │
    │ - apply threats │ │ - apply threats │ │ - apply threats │
    └─────────────────┘ └─────────────────┘ └─────────────────┘
```

## ThreatIntel Indicators

ThreatIntel manages distributed threat indicators that are shared across mesh nodes.

### Indicator Types

| Type | Value | Description | Local Action |
|------|-------|-------------|--------------|
| `IpBlock` | 0 | Malicious IP address | Block IP in BlockStore |
| `RateLimitViolation` | 1 | Excessive request rate | Apply rate limit |
| `SuspiciousActivity` | 2 | Anomalous behavior pattern | Block with severity-based TTL |
| `AsnBlock` | 3 | Entire ASN blocked | Log attack type |
| `DomainBlock` | 4 | Malicious domain | Reserved for future use |
| `UrlBlock` | 5 | Malicious URL | Reserved for future use |
| `CertBlock` | 6 | Malicious certificate | Reserved for future use |
| `Unspecified` | 7 | Unknown type | Log warning |

### Severity Levels

| Level | Value | SuspiciousActivity TTL | Description |
|-------|-------|----------------------|-------------|
| `Unspecified` | 0 | 300s | Unknown severity |
| `Low` | 1 | 900s | Minor threat |
| `Medium` | 2 | 1800s | Moderate threat |
| `High` | 3 | 3600s | Serious threat |
| `Critical` | 4 | 7200s | Severe threat requiring immediate action |

### Indicator Structure

```rust
pub struct ThreatIndicator {
    pub threat_type: ThreatType,           // Type of threat
    pub indicator_value: String,           // IP address, domain, URL, etc.
    pub severity: ThreatSeverity,           // Low, Medium, High, Critical
    pub reason: String,                     // Human-readable description
    pub ttl_seconds: u64,                   // Time-to-live in seconds
    pub source_node_id: String,             // Originating node ID
    pub timestamp: u64,                     // Unix timestamp
    pub site_scope: String,                 // Applicable sites ("*" for all)
    pub rate_limit_requests: Option<u64>,  // For rate limit violations
    pub rate_limit_window_secs: Option<u64>, // Window for rate limits
    pub suspicious_pattern: Option<String>, // Pattern that triggered detection
    pub signature: Vec<u8>,                  // Ed25519 signature
    pub signer_public_key: Option<String>, // Signer's public key (base64)
}
```

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

### Local Announcements

Nodes can announce local threats that get propagated to the mesh:

```rust
// Announce IP block from WAF detection
threat_intel.announce_local_block(ip, reason, ban_expire_seconds, site_scope);

// Announce threat detected by honeypot
threat_intel.announce_honeypot_indicator(ip, threat_type, severity, ttl, reason);

// Announce rate limit exceeded
threat_intel.announce_local_rate_limit(ip, requests, window_secs, ttl, reason);

// Announce suspicious activity pattern
threat_intel.announce_local_suspicious(ip, severity, pattern, ttl, reason, site_scope);
```

## YARA Rules and Malware Scanning

YARA rules are used for malware scanning, particularly on file uploads.

### YARA Rule Format

YARA rules follow the standard YARA format:

```yara
rule SuspiciousPEHeader {
    meta:
        description = "Detects PE file with suspicious characteristics"
        author = "MaluWAF Threat Intel"
        date = "2024-01-15"
    strings:
        $mz_header = "MZ"
        $pe_signature = "PE\0\0"
        $suspicious_section = "UPX" nocase
    condition:
        $mz_header at 0 and $pe_signature
}
```

### Rule Distribution via DHT

YARA rules follow a content-addressed distribution model:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Global Node publishes:                                              │
│                                                                       │
│  1. Manifest: yara_rules_manifest:{node_id}                          │
│     {version, content_hash, node_id, timestamp, signature}          │
│                                                                       │
│  2. Rule Content: yara_rule:{content_hash}                           │
│     {version, rules, content_hash, node_id, timestamp, signature}    │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DHT Record (24h TTL)                                               │
│                                                                       │
│  Key: yara_rule:{sha256_of_rules}                                    │
│  Value: JSON with rules content + metadata + signature                │
│                                                                       │
│  Key: yara_rules_manifest:{node_id}                                  │
│  Value: JSON with version + content_hash + signature                 │
└─────────────────────────────────────────────────────────────────────┘
```

### File Upload Scanning

The FileManager integrates with YARA rules for malware scanning on upload:

```rust
// In src/static_files/file_manager.rs
fn reload_yara_rules_if_needed(&self) -> Result<(), YaraError> {
    // Check version from YaraRulesManager
    // Reload scanner when version changes
}

if self.scan_on_upload {
    // Scan file with YARA before storing
    let matches = scanner.scan_file(&path)?;
    if !matches.is_empty() {
        return Err(YaraError::MalwareDetected(matches));
    }
}
```

Configuration:

```toml
[site.static]
scan_on_upload = true
```

### Rule Manifest and Content Hash Verification

The system uses SHA-256 content hashing for integrity verification:

```rust
// Compute content hash
let content_hash = sha256(&rules);

// Manifest signature content format:
// {version}:{content_hash}:{node_id}:{timestamp}
let manifest_content = format!(
    "{}:{}:{}:{}",
    version, content_hash, node_id, timestamp
);

// Rule content signature format:
// {version}:{rules}:{content_hash}:{node_id}:{timestamp}
let rule_content = format!(
    "{}:{}:{}:{}:{}",
    version, rules, content_hash, node_id, timestamp
);
```

### Rule Sources

| Source | Description |
|--------|-------------|
| `Local` | Rules applied directly on this node |
| `Feed` | Rules from external YARA rule feed |
| `MeshGlobal` | Rules synced from global node via mesh |
| `MeshEdgeApproved` | Edge-submitted rules approved by global |

## DHT-Based Distribution

### Publishing to DHT

Global nodes publish indicators and rules to DHT:

```rust
pub fn publish_indicator_to_dht(&self, indicator: &ThreatIndicator) {
    let key = DhtKey::threat_indicator(
        &indicator.indicator_value,
        &format!("{:?}", indicator.threat_type),
    );

    // Sign the indicator
    let content = format!(
        "{}:{}:{}:{}:{}",
        indicator.indicator_value,
        indicator.threat_type as u8,
        indicator.severity as u8,
        indicator.timestamp,
        indicator.source_node_id
    );
    let signature = signer.sign(&content);

    let value = serde_json::json!({
        "indicator_value": indicator.indicator_value,
        "threat_type": indicator.threat_type as u8,
        "severity": indicator.severity as u8,
        // ... other fields
        "signature": signature,
        "signer_public_key": signer.get_public_key(),
    });

    // Critical threats use faster propagation
    if is_critical && self.node_role.is_global() {
        record_store.store_and_announce_critical(key_str, bytes, ttl, replication_factor);
    } else {
        record_store.store_and_announce(key_str, bytes, ttl);
    }
}
```

### Key Format

| Data Type | Key Pattern | Example |
|-----------|-------------|---------|
| Threat Indicator | `threat_indicator:{ip}:{threat_type}` | `threat_indicator:1.2.3.4:IpBlock` |
| YARA Rule Content | `yara_rule:{content_hash}` | `yara_rule:a1b2c3d4...` |
| YARA Manifest | `yara_rules_manifest:{node_id}` | `yara_rules_manifest:node-abc123` |

### TTL and Expiration

| Data Type | Default TTL | Behavior |
|-----------|-------------|----------|
| Threat Indicators | `ttl_seconds` field (min 60s) | Expires after TTL |
| YARA Rules | 24 hours | Requires re-announcement |
| YARA Manifest | 24 hours | Requires re-announcement |

Expired indicators are cleaned up by `cleanup_expired()` which runs periodically.

### Re-Announcement

Global nodes periodically re-announce indicators:

- **Interval**: `re_announce_interval_secs` (default: 300 seconds)
- **Scope**: ALL non-expired indicators are re-announced (not just local_origin)
- **Behavior**: Respects `hub_only_mode` (non-global nodes do not re-announce)

```rust
// Background task for re-announcement
async fn re_announce_loop(&self) {
    let mut ticker = tokio::time::interval(Duration::from_secs(
        self.config.re_announce_interval_secs
    ));
    loop {
        ticker.tick().await;
        if self.node_role.is_global() {
            self.re_announce_local_indicators();
        }
    }
}
```

## Global Node vs Edge Behavior

### Global Nodes

| Action | Behavior |
|--------|----------|
| Publish indicators | Yes - announces to DHT and broadcasts to peers |
| Sync indicators | Yes - syncs from DHT periodically |
| Publish YARA rules | Yes - publishes manifest and rule content to DHT |
| Re-announce indicators | Yes - every `re_announce_interval_secs` |
| Accept edge submissions | Yes - stores pending submissions for approval |
| Critical threat propagation | Uses `store_and_announce_critical()` for faster spread |

### Edge/Origin Nodes

| Action | Behavior |
|--------|----------|
| Publish indicators | Only if `hub_only_mode = false` |
| Sync indicators | Yes - syncs from DHT via `sync_from_dht()` |
| Publish YARA rules | No - only global nodes publish |
| Re-announce indicators | No - only global nodes re-announce |
| Submit YARA rules | Yes, if `allow_edge_submissions = true` |

### `hub_only_mode`

When `hub_only_mode = true`:
- Non-global nodes do not publish indicators to DHT
- They still sync indicators from DHT
- Useful when only global nodes should distribute threat data

## Signature Verification

All signed records undergo Ed25519 signature verification.

### Signature Format

**ThreatIntel indicators:**
```
{indicator_value}:{threat_type as u8}:{severity as u8}:{timestamp}:{source_node_id}
```

Example:
```
192.168.1.100:0:3:1713523200:node-abc123
```

**YARA Manifest:**
```
{version}:{content_hash}:{node_id}:{timestamp}
```

**YARA Rule Content:**
```
{version}:{rules}:{content_hash}:{node_id}:{timestamp}
```

### Verification Process

```rust
fn verify_indicator_signature(
    indicator: &ThreatIndicator,
    signer: &MeshMessageSigner,
) -> bool {
    let content = format!(
        "{}:{}:{}:{}:{}",
        indicator.indicator_value,
        indicator.threat_type as u8,
        indicator.severity as u8,
        indicator.timestamp,
        indicator.source_node_id
    );

    let pk_bytes = base64::decode(&indicator.signer_public_key).unwrap();
    signer.verify(&content, &indicator.signature, &pk_bytes)
}
```

### Verification During sync_from_dht()

The `sync_from_dht()` method verifies signatures before accepting indicators:

1. Extract signature and signer public key from DHT record
2. Reconstruct signed content using known format
3. Verify Ed25519 signature
4. Reject record if verification fails
5. Log warning for missing signatures (if `require_signature` enabled)

### Timestamp Bounds (YARA Rules)

YARA rules sync enforces timestamp bounds to prevent replay attacks:

- **Future bound**: 60 seconds (handles clock skew)
- **Past bound**: 24 hours (allows for delayed propagation)

### Verification Failure Handling

| Component | On Signature Failure |
|-----------|---------------------|
| ThreatIntel (mesh message) | Log warning, do not apply indicator |
| ThreatIntel (DHT sync) | Skip indicator, continue with next |
| YARA manifest | Skip this manifest, try next |
| YARA rule content | Skip, do not apply rules |

## Configuration

### ThreatIntel Configuration

```toml
[mesh.threat_intel]
enabled = true
push_enabled = true                    # Broadcast threats to peers
sync_enabled = true                    # Sync from DHT
sync_interval_secs = 300               # How often to sync (seconds)
threat_sync_interval_secs = 60         # Internal sync interval
push_severity_threshold = "medium"     # Minimum severity to push
min_ttl_seconds = 60                   # Minimum TTL for indicators
max_indicators_per_message = 50        # Max indicators per sync
hub_only_mode = false                  # Only global nodes distribute
re_announce_interval_secs = 300        # Re-announce interval (seconds)

[mesh.threat_intel.reputation]
enabled = true
initial_score = 50
 decay_interval_secs = 3600
 min_score = 0
 max_score = 100
```

### YARA Rules Configuration

```toml
[mesh.yara_rules]
enabled = true
sync_interval_secs = 3600              # How often to sync from DHT
re_announce_interval_secs = 300        # Re-publish interval for global
allow_edge_submissions = false          # Allow edge nodes to submit rules
require_global_approval = true          # Submissions need approval
require_signature = true                # Reject unsigned rules
max_rules_size_kb = 1024               # Maximum rule size (KB)
trusted_signers = []                   # Ed25519 public keys that can sign
```

### Trusted Signers

When `trusted_signers` is configured, only rules signed by keys in the list are accepted:

```toml
[mesh.yara_rules]
trusted_signers = [
    "base64_encoded_ed25519_pubkey_1",
    "base64_encoded_ed25519_pubkey_2"
]
```

## Troubleshooting

### Indicators Not Propagating

1. Check `mesh.threat_intel.enabled = true`
2. Verify node has a signer configured (`signer` not None)
3. Check logs for "Cannot publish threat indicator: no signer configured"
4. Verify transport is available ("Transport not available for DHT publish")
5. Ensure node role is correctly configured (global nodes publish)

### YARA Rules Not Syncing

1. Check `mesh.yara_rules.enabled = true`
2. Verify global node has published rules
3. Check logs for "YARA DHT sync: signature verification failed"
4. Verify `require_signature = false` for testing without signatures
5. Check `sync_interval_secs` - rules sync every 3600s by default

### Signature Verification Failures

1. Ensure sender has a valid Ed25519 signing key
2. Check that public key is properly encoded (base64)
3. Verify the content format matches expected structure
4. Check timestamp bounds (clock skew between nodes)

### High Memory Usage

- `MAX_PENDING_INDICATORS = 10000` limits indicator queue
- `VecDeque` automatically evicts oldest entries when full
- Consider reducing `max_indicators_per_message` if memory pressure

### DHT Lookup Misses

- DHT records have 24-hour TTL for YARA, variable for indicators
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

## Related Documentation

- [WAF Mesh Networking](./WAF_MESH.md) - Mesh network architecture and configuration
- [Attack Detection](./ATTACK_DETECTION.md) - WAF detection pipeline and attack types
- [BOT_PROTECTION.md](./BOT_PROTECTION.md) - Bot detection including honeypots
- [UPLOADS.md](./UPLOADS.md) - File upload handling and scanning

## Key Source Files

| File | Description |
|------|-------------|
| `src/mesh/threat_intel.rs` | ThreatIntelligenceManager implementation |
| `src/mesh/yara_rules.rs` | YaraRulesManager implementation |
| `src/mesh/dht/keys.rs` | DHT key definitions and formats |
| `src/mesh/config.rs` | Configuration structures |
| `src/static_files/file_manager.rs` | YARA integration for file scanning |
| `src/block_store.rs` | IP blocking implementation |
