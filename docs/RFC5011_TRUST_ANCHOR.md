# RFC 5011 Trust Anchor Management in MaluWAF

> **Related Documentation:** [DNS & DNSSEC Architecture](dns-dnssec-architecture.md) | [WAF Mesh](WAF_MESH.md) | [Troubleshooting](TROUBLESHOOTING.md)

## Table of Contents

1. [What is RFC 5011?](#what-is-rfc-5011)
2. [Trust Anchor State Machine](#trust-anchor-state-machine)
3. [Configuration Options](#configuration-options)
4. [How It Works](#how-it-works)
5. [Debugging Trust Anchor Issues](#debugging-trust-anchor-issues)
6. [Security Considerations](#security-considerations)
7. [Relationship to DNSSEC Validation](#relationship-to-dnssec-validation)
8. [Initial Trust Anchor File Format](#initial-trust-anchor-file-format)

---

This document describes RFC 5011 automated trust anchor management implementation in MaluWAF for DNSSEC validation.

## What is RFC 5011?

RFC 5011 defines an automated mechanism for managing DNSSEC trust anchors without requiring manual intervention when keys are added, removed, or rotated in a secure zone.

Traditionally, DNSSEC required operators to manually update trust anchors whenever zone keys changed. RFC 5011 solves this by establishing a state machine that allows keys to be securely promoted to trusted status through a combination of:

- **Direct observation** of the DNSKEY RRset
- **Validation via CDS/CDNSKEY records** published by the zone itself
- **Time-based observation periods** to detect key compromises

MaluWAF implements RFC 5011 for the root zone by default, enabling automatic key management for DNSSEC validation.

## Trust Anchor State Machine

Keys progress through the following states based on RFC 5011:

```
                      ┌─────────────────────────────────────────────────────────────┐
                      │                                                             │
                      ▼                                                             │
    ┌─────────┐   observe   ┌─────────┐   trust_anchor   ┌───────────┐   observe   │
    │  Seen   │───DNSKEY────│  Seen   │───check()────────▶│  Pending  │──period────▶│
    └─────────┘             └─────────┘   (CDS digest     └───────────┘   complete   │
                                    matches)                 │                 │
                                                                │                 │
                                                                ▼                 ▼
                                                           ┌─────────┐     ┌─────────┐
                                                           │  Valid  │◀────│ Pending │
                                                           │ (trusted)│     └─────────┘
                                                           └─────────┘
                                                               │
                                                               │ REVOKE bit observed
                                                               ▼
                                                           ┌──────────┐   grace period   ┌─────────┐
                                                           │ Revoked  │───────30d─────────▶│ Removed │
                                                           └──────────┘                    └─────────┘
                                                                                                │
                                                                                         extended removal
                                                                                         period (60d default)
                                                                                                │
                                ┌───────────────────────────────────────────────────────────┘
                                │
                                ▼
                          ┌─────────┐
                          │ Purged  │ (removed from storage)
                          └─────────┘

    Also:
    ┌─────────┐   not seen for   ┌──────────┐   reappears   ┌───────────┐
    │  Valid  │───retention──────▶│  Missing │───DNSKEY─────▶│  Pending │
    └─────────┘   period          └──────────┘                └───────────┘
```

### State Descriptions

| State | Description |
|-------|-------------|
| **Seen** | Key observed in DNSKEY RRset but not yet validated via CDS/CDNSKEY (RFC 5011 Section 3). Not trusted for validation. |
| **Pending** | Key validated via CDS/CDNSKEY digest, awaiting the observation period (default: 30 days). Not yet trusted for validation. |
| **Valid** | Key is fully trusted and actively used for DNSSEC validation. |
| **Revoked** | Key has the REVOKE bit set (RFC 5011 Section 4). No longer used for validation but pending removal confirmation. |
| **Removed** | Key was removed from the zone, waiting for the extended removal confirmation period before purging. |
| **Missing** | A previously Valid key has not been seen for the retention period (default: 7 days). Can be automatically restored if the key reappears. |
| **Purged** | Key has been removed from storage after the extended removal period. A new instance would start as Seen if re-observed. |

### Supported Algorithms

MaluWAF only accepts modern DNSSEC algorithms. Deprecated algorithms are rejected:

| Algorithm | Name | Status |
|-----------|------|--------|
| 0 | DELETE | Rejected |
| 3 | DSA | Rejected |
| 5 | RSASHA1 | Rejected |
| 6 | DSA-NSEC3-SHA1 | Rejected |
| 8 | RSASHA256 | Accepted |
| 13 | ECDSAP256SHA256 | Accepted |
| 14 | ECDSAP384SHA384 | Accepted |
| 15 | ED25519 | Accepted |
| 16 | ED448 | Accepted |

## Configuration Options

Trust anchor behavior is controlled via the `TrustAnchorConfig` struct:

```toml
[dns.recursive.trust_anchors]
enabled = true
anchor_file_path = "/var/lib/maluwaf/dns/trusted-key.key"
db_path = "/var/lib/maluwaf/dns/trust_anchors.db"
refresh_interval_secs = 3600
pending_observation_days = 30
revocation_grace_days = 30
extended_removal_days = 60
trust_anchor_retention_days = 7
allow_key_rotation = true
```

### Configuration Fields

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable RFC 5011 trust anchor management |
| `anchor_file_path` | `/var/lib/maluwaf/dns/trusted-key.key` | Initial trust anchor file in RFC 5011 format (DNSKEY record format) |
| `db_path` | `/var/lib/maluwaf/dns/trust_anchors.db` | SQLite database path for persistent anchor storage |
| `refresh_interval_secs` | `3600` | How often to refresh and process anchor state transitions |
| `pending_observation_days` | `30` | Time a new key spends in Pending state before becoming Valid (RFC 5011 Section 3.2) |
| `revocation_grace_days` | `30` | Time after REVOKE bit before key is Removed (RFC 5011 Section 4) |
| `extended_removal_days` | `60` | Time after Removed before key is Purged from storage |
| `trust_anchor_retention_days` | `7` | Time a Valid key can be absent before being marked Missing |
| `allow_key_rotation` | `true` | Whether removed keys can be replaced (if false, removed keys are never purged) |

### Complete Configuration Example

```toml
[dns.recursive]
upstream_provider = "Recursive"
dnssec_validation = true

[dns.recursive.trust_anchors]
enabled = true
anchor_file_path = "/var/lib/maluwaf/dns/trusted-key.key"
db_path = "/var/lib/maluwaf/dns/trust_anchors.db"
refresh_interval_secs = 3600

# RFC 5011 timing parameters (all in days)
pending_observation_days = 30      # Time before new key becomes trusted
revocation_grace_days = 30         # Time after REVOKE before removal
extended_removal_days = 60        # Time before purged from storage
trust_anchor_retention_days = 7   # Time valid key can be absent

allow_key_rotation = true
```

## How It Works

### Initial Anchor Loading

On startup, MaluWAF loads initial trust anchors from the anchor file:

1. Reads the file at `anchor_file_path`
2. Parses DNSKEY records (expects format like `trusted-key.key` from IANA)
3. Keys with flags=257 and protocol=3 are loaded as Valid
4. Anchors are persisted to SQLite for subsequent runs

### Key Observation Flow

When MaluWAF receives DNSKEY responses:

1. **`observe_dnskey_at_root()`** is called for each DNSKEY
2. If key is new → enters **Seen** state
3. If key exists with different public key → rejected (key compromise indicator)
4. If REVOKE bit is set → transitions to **Revoked**

### Trust Anchor Check Flow

When CDS/CDNSKEY records are received:

1. **`trust_anchor_check()`** computes the expected DS digest
2. Compares against the published digest
3. If match → key transitions from **Seen** to **Pending**
4. If key was **Missing** and reappears → goes directly to **Pending**

### Background Processing

The `process_rfc5011_updates()` function runs periodically to handle:

- **Pending → Valid**: After `pending_observation_days` elapses and key still in DNSKEY RRset
- **Revoked → Removed**: After `revocation_grace_days` elapses
- **Removed → Purged**: After `extended_removal_days` elapses (if `allow_key_rotation=true`)
- **Valid → Missing**: If not seen for `trust_anchor_retention_days`

### Database Storage

Anchors are stored in SQLite with the following schema:

```sql
CREATE TABLE trust_anchors (
    key_id TEXT PRIMARY KEY,
    key_tag INTEGER NOT NULL,
    algorithm INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    state TEXT NOT NULL,
    added_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    trust_point INTEGER NOT NULL,
    first_seen_at INTEGER,
    pending_since INTEGER,
    revoked_at INTEGER,
    removed_at INTEGER
);
```

The `key_id` format is `{key_tag}-{algorithm}` (e.g., `20326-8`).

## Debugging Trust Anchor Issues

### Checking Trust Anchor Status

Use the `TrustAnchorManager::get_status()` method to retrieve:

```rust
let status = manager.get_status();
println!("Total: {}, Valid: {}, Revoked: {}, Pending: {}",
    status.total_anchors,
    status.valid_anchors,
    status.revoked_anchors,
    status.pending_anchors
);
```

### Key Log Messages

Watch for these log patterns when troubleshooting:

| Pattern | Meaning |
|---------|---------|
| `RFC 5011: New key {key_tag} observed (Seen state)` | New key detected in DNSKEY RRset |
| `RFC 5011: Key {key_tag} passed trust anchor check, entering Pending state` | Key validated via CDS, entering observation period |
| `RFC 5011: Key {key_tag} promoted to Valid` | Key is now trusted for validation |
| `RFC 5011: Key {key_tag} revoked` | REVOKE bit observed |
| `RFC 5011: Key {key_tag} expired (not seen for N days)` | Key marked Missing |
| `RFC 5011: Digest mismatch for key {key_tag}` | CDS digest doesn't match (possible attack) |
| `RFC 5011: Key {key_tag} uses deprecated algorithm {algo}, rejecting` | Key uses insecure algorithm |

### Common Issues and Solutions

#### No Valid Trust Anchors

**Symptom**: DNSSEC validation failing with "no trust anchors"

**Causes**:
- Initial anchor file not loaded
- Database corruption
- All keys transitioned to Revoked/Removed

**Solutions**:
1. Verify `anchor_file_path` exists and contains valid DNSKEY records
2. Delete `db_path` and restart to reload from anchor file
3. Check logs for anchor loading messages

#### Keys Stuck in Pending

**Symptom**: Key in Pending state beyond expected observation period

**Cause**: Key removed from DNSKEY RRset before observation period completed

**Solution**: The key will remain Pending until it either appears in DNSKEY (then becomes Valid) or is purged. This is correct RFC 5011 behavior—the key cannot be trusted if it wasn't observed continuously.

#### Digest Mismatch Warnings

**Symptom**: `RFC 5011: Digest mismatch for key {key_tag}`

**Cause**: The DS record in the parent zone doesn't match the DNSKEY

**Actions**:
1. Verify zone is properly signed
2. Check for key rollovers in progress
3. If zone is being compromised, this warning indicates attack

#### Deprecated Algorithm Rejection

**Symptom**: `RFC 5011: Key {key_tag} uses deprecated algorithm {algo}, rejecting`

**Cause**: Zone using outdated algorithms (DSA, RSASHA1, etc.)

**Solution**: Zone operator should migrate to modern algorithms (RSASHA256, ECDSAP256SHA256, or ED25519)

### Event Types

The system produces `Rfc5011Event` notifications for state transitions:

| Event | Description |
|-------|-------------|
| `NewKeySeen { key_tag }` | New key observed for first time |
| `KeySeen { key_tag }` | Known key observed again |
| `KeyPending { key_tag }` | Key validated via CDS, entering observation |
| `KeyWaiting { key_tag, remaining_secs }` | Key still in Pending, observation incomplete |
| `KeyPromoted { key_tag }` | Key became Valid after observation |
| `KeyRevoked { key_tag }` | Key has REVOKE bit set |
| `KeyRemoved { key_tag }` | Key removed from zone |
| `KeyPurged { key_tag }` | Key removed from storage |
| `KeyMissing { key_tag }` | Valid key not seen for retention period |
| `KeyIgnored { key_tag, reason }` | Key rejected (deprecated algo, mismatch, etc.) |

## Security Considerations

### Key Compromise Detection

If a key's public key changes while having the same key_tag/algorithm, it is rejected:

```
RFC 5011: Key {key_tag} public key mismatch - ignoring
```

This prevents an attacker from substituting keys during a rollover.

### Public Key Change Rejection

MaluWAF rejects any key whose public key doesn't match previously observed value. This includes:
- Different key material for same key-tag
- Re-use of key-tag with new key (potential attack)

### Algorithm Validation

Only IETF-recommended algorithms are accepted. This prevents downgrade attacks using deprecated algorithms with known weaknesses.

### Missing Key Handling

When a Valid key is not seen for `trust_anchor_retention_days`:
1. It transitions to **Missing** (not Revoked)
2. If it reappears, it goes to **Pending** (not directly Valid)
3. This prevents an attacker who gains access to the zone from immediately getting trust

## Relationship to DNSSEC Validation

RFC 5011 trust anchors are used exclusively by the **Recursive DNS provider**. Other providers (Google, Cloudflare, System, Custom) forward to upstream servers and do not perform local DNSSEC validation.

To enable RFC 5011 trust anchor management:

```toml
[dns.recursive]
upstream_provider = "Recursive"  # Required for DNSSEC validation
dnssec_validation = true          # Enable DNSSEC validation

[dns.recursive.trust_anchors]
enabled = true                     # Enable RFC 5011 management
```

## Initial Trust Anchor File Format

The anchor file should contain DNSKEY records in standard zone file format:

```
; This is a comment
. 3600 IN DNSKEY 257 3 8 AwEAAagAI... (base64 key data)
```

- Flags must be 257 (secure entry point / KSK)
- Protocol must be 3
- Algorithm can be 8 (RSASHA256), 13 (ECDSAP256SHA256), 15 (ED25519), or 16 (ED448)
- Multiple keys can be defined (for algorithm rollover)

MaluWAF provides bundled default anchors for the root zone that are updated with each release.

## See Also

- [DNS & DNSSEC Architecture](dns-dnssec-architecture.md) - Complete DNS and DNSSEC documentation
- [WAF Mesh](WAF_MESH.md) - Mesh networking for global node coordination
- [Troubleshooting](TROUBLESHOOTING.md) - General debugging techniques
- [skills/dns_dnssec.md](../../skills/dns_dnssec.md) - Detailed DNS architecture for developers