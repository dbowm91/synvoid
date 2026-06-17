# Signed Rule Feed - Design Document

## Overview

This document describes the design for automatic WAF rule updates using a signed rule feed system. Rules are distributed via HTTPS, signed cryptographically to ensure authenticity and integrity.

## Goals

1. **Automatic Updates**: Rules update automatically on a configurable schedule
2. **Cryptographic Verification**: All rules verified via Ed25519 signature before applying
3. **Delta Updates**: Support incremental updates to reduce bandwidth
4. **Rollback Capability**: Ability to revert to previous rule version
5. **Transparency**: Changelog included with each update

## Architecture

```
┌─────────────────┐     HTTPS      ┌──────────────────┐
│  Rule Provider  │ ──────────────▶│  SynVoid Client  │
│  (your server)  │                │                  │
│                 │◀───────────────│  - Fetch rules   │
│  - Rules JSON   │   JSON+Sig     │  - Verify sig    │
│  - Ed25519 sig  │                │  - Apply rules   │
│  - Changelog    │                │  - Store locally │
└─────────────────┘                └──────────────────┘
```

## Data Format

### Rule Feed Response

```json
{
  "version": "1.2.4",
  "previous_version": "1.2.3",
  "timestamp": "2026-03-03T12:00:00Z",
  "signature": "BASE64_ED25519_SIGNATURE",
  "rules": {
    "sqli": {
      "enabled": true,
      "threshold": 100,
      "patterns": ["...", "..."]
    },
    "xss": {
      "enabled": true,
      "threshold": 100
    },
    "cmd_injection": {
      "enabled": true,
      "patterns": ["...", "..."]
    },
    "path_traversal": {
      "enabled": true,
      "patterns": ["...", "..."]
    },
    "ssrf": {
      "enabled": true,
      "patterns": ["...", "..."]
    },
    "ssti": {
      "enabled": true,
      "patterns": ["...", "..."]
    },
    "open_redirect": {
      "enabled": true,
      "patterns": ["...", "..."]
    }
  },
  "changelog": [
    {"type": "added", "rule": "cmd_injection", "description": "Added 50 new patterns for Linux commands"},
    {"type": "changed", "rule": "sqli", "description": "Improved threshold calculation"},
    {"type": "removed", "rule": "legacy_pattern", "description": "Removed deprecated pattern"}
  ]
}
```

### Signature

- Algorithm: Ed25519 (Edwards-curve Digital Signature Algorithm)
- Signature covers: entire JSON payload (excluding signature field)
- Public key: embedded in binary at compile time

## Configuration

```toml
[rule_feed]
enabled = true
url = "https://rules.example.com/api/v1/rules"
update_interval_hours = 24
auto_apply = true
allow_downgrade = false

# Optional: custom public key (defaults to embedded)
# public_key = "BASE64_ED25519_PUBLIC_KEY"
```

## Components

### 1. Rule Feed Client (`src/waf/rule_feed/`)

- `mod.rs` - Main client, fetch/verify/apply logic
- `types.rs` - Rule feed JSON structures  
- `signature.rs` - Ed25519 verification
- `storage.rs` - Local rule persistence

### 2. Configuration (`crates/synvoid-config/src/`)

- Add `RuleFeedConfig` to main config
- Add to defaults

### 3. Admin API (`src/admin/`)

- `GET /api/rules/status` - Current rule version, last update
- `POST /api/rules/check` - Check for updates (manual trigger)
- `POST /api/rules/apply` - Apply downloaded rules
- `POST /api/rules/rollback` - Rollback to previous version

## Implementation Priority

1. **Phase 1**: Core infrastructure
   - Add `RuleFeedConfig` struct
   - Create `RuleFeedManager` with fetch/verify
   - Add Ed25519 signature verification
   - Add to main config

2. **Phase 2**: Rule application
   - Integrate with `DefaultPatterns` 
   - Support hot-reload of rules (no restart required)
   - Add version tracking

3. **Phase 3**: Admin API
   - Status endpoint
   - Manual trigger endpoints
   - Rollback support

4. **Phase 4**: Delta updates (optional optimization)
   - Track rule hashes
   - Only download changed rules

## Security Considerations

1. **Key Management**: Public key embedded in binary; private key kept offline
2. **HTTPS Required**: Only fetch over HTTPS
3. **Fail-Secure**: If verification fails, don't apply rules, log error
4. **Audit Logging**: Log all rule updates with version info

## Example Rule Provider API

### GET /api/v1/rules

Returns latest rules with signature.

### GET /api/v1/rules?current_version=1.2.3

Returns delta or full rules depending on version difference.

### GET /api/v1/rules/{version}

Returns specific version (for rollback).

## Future Enhancements

- Multiple signing keys (key rotation)
- Rule categories/tiers (core, extended, community)
- User-defined rule overrides
- Integration with existing IP feed system
