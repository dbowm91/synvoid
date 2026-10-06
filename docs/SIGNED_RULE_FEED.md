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
- Signature covers: entire JSON payload (excluding the `signature` field)
- Public key: supplied in config as `rule_feed.public_key` (base64, 32-byte verifying key). The default is `None`; without it the manager refuses to construct.

## Configuration

```toml
[rule_feed]
enabled = false                       # default: false
url = "https://rules.example.com/api/v1/rules"   # default: this placeholder URL
update_interval_hours = 24            # default: 24
auto_apply = true                     # default: true
allow_downgrade = false               # default: false

# REQUIRED when the feed is enabled: base64 Ed25519 public key.
# public_key = "BASE64_ED25519_PUBLIC_KEY"

# Optional: directory for local rule persistence. `save_to_disk` / `load_from_disk`
# are no-ops when this is unset, so nothing persists across restarts.
# storage_dir = "/var/lib/synvoid/rules"
```

`RuleFeedConfig` (`crates/synvoid-config/src/protection.rs:285`) carries two fields this document previously omitted: `public_key` and `storage_dir`. The section is `[rule_feed]` at the top level of `main.toml` (`MainConfig::rule_feed`); the error text inside `RuleFeedManager::new` refers to it as `[waf.rule_feed.public_key]`, which is stale wording — there is no `[waf]` section in `MainConfig`.

There is **no compiled-in fallback key**: `RuleFeedManager::new` returns `Err("RULE FEED SECURITY VIOLATION: No rule feed public key configured...")` when `public_key` is absent or empty. The feature is disabled by default and its default `url` is a non-functional placeholder, so an enabled feed requires both an explicit key and a real URL.

## Components

### 1. Rule Feed Manager (`src/waf/rule_feed.rs`)

- `RuleFeedManager` — fetch / verify / apply logic (there is no `RuleFeedClient` type); `new(config)` returns `Result<Arc<Self>, String>`
- Rule feed JSON structures: `RuleFeedResponse`, `RuleSet`, `RuleCategory`, `ChangelogEntry`, `ParsedRules`
- Pattern application surface: `get_global_patterns()`, `get_site_patterns(site_id)`, `update_from_rule_set()`, `clear_global_patterns()`
- Ed25519 signature verification
- Local rule persistence: `save_to_disk()` / `load_from_disk()` (both require `storage_dir`)

### 2. Configuration (`crates/synvoid-config/src/protection.rs`)

- `RuleFeedConfig`, exposed as `MainConfig::rule_feed` (`MainRuleFeedConfig` alias)

### 3. Admin API (`src/admin/`)

Registered in `infra_probes_threat_rules_routes()` (`src/admin/routes.rs:409`):

- `GET /api/rules/status` — current rule version, last update
- `POST /api/rules/check` — check for updates (manual trigger)
- `POST /api/rules/apply` — apply pending rules
- `POST /api/rules/discard` — discard pending rules

There is **no** `POST /api/rules/rollback` endpoint, and no `rollback` symbol in `src/waf/rule_feed.rs`. The rollback goal in the Goals section is unimplemented; the closest available action is `discard` of a pending update.

## Implementation Status

This document was written as a design record. Phases 1–3 are **implemented**: `RuleFeedConfig` exists in `crates/synvoid-config`, `RuleFeedManager` in `src/waf/rule_feed.rs` performs fetch/verify/apply, patterns are applied without restart (`start_background_fetching` + `set_on_apply_callback`), and the four admin endpoints above are registered.

Still unimplemented:

- **Rollback** — no rollback manager method, no `/api/rules/rollback` route.
- **Delta updates** — the client fetches the full feed; there is no per-category hash tracking and no `?current_version=` negotiation.
- **Changelog surfacing** — `ChangelogEntry` is part of the wire format, but there is no admin surface that returns it.

Treat the "Implementation Priority" list below as the original plan, not as a description of current state.

## Security Considerations

1. **Key Management**: Public key supplied via `rule_feed.public_key` (base64 Ed25519 verifying key) — there is no embedded fallback, and `new()` fails closed without it; private key kept offline
2. **HTTPS Required**: Only fetch over HTTPS
3. **Fail-Secure**: If verification fails, don't apply rules, log error
4. **Audit Logging**: Log all rule updates with version info
5. **Downgrade guard**: `allow_downgrade` defaults to `false`, so a feed publishing a lower version is rejected unless explicitly permitted

## Example Rule Provider API

The client issues a plain `GET` against `rule_feed.url`. The three endpoint shapes below describe the intended provider contract:

### GET /api/v1/rules

Returns latest rules with signature.

### GET /api/v1/rules?current_version=1.2.3

Intended to return a delta or full rules depending on version difference — **not implemented**; the client always requests the full feed.

### GET /api/v1/rules/{version}

Intended to return a specific version for rollback — **not implemented**.

## Future Enhancements

- Multiple signing keys (key rotation)
- Rule categories/tiers (core, extended, community)
- User-defined rule overrides
- Integration with existing IP feed system
