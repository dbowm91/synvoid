---
name: rule_feed_persistence
description: Signed rule feed persistence, hot-reload, and cross-worker WAF rule synchronization.
---

# Signed Rule Feed Persistence and Hot-Reload

This skill documents the implementation of dynamic WAF rule updates, local persistence, and cross-worker synchronization.

## Overview

SynVoid supports automatic rule updates via a signed feed. Rules are fetched, verified cryptographically (Ed25519), persisted locally for offline use, and synchronized across multiple worker processes without restarts.

## Key Components

### RuleFeedManager (`src/waf/rule_feed.rs`)

The `RuleFeedManager` handles the lifecycle of signed rules:
- **Fetching**: Background polling of configured HTTPS endpoints.
- **Verification**: Ed25519 signature verification using an embedded or configured public key.
- **Persistence**: Saving verified rules to `storage_dir` in JSON format.
- **Hot-Reload**: Broadcasting updates to workers via IPC callbacks.

### Cross-Process Synchronization

1. **Supervisor**: Runs the `RuleFeedManager` in background mode ("Master Process"
   in older docs = the Supervisor under the current process model).
2. **Apply Callback**: When new rules are verified, the manager triggers a callback.
3. **IPC Broadcast**: The supervisor sends a `RulePatternUpdate` message to all active workers.
4. **Worker Update**: Workers receive the message and reload their `AttackDetector` instances with the new patterns.

## Implementation Details

### Persistence Format

Rules are stored in `storage_dir/rules.json` with the following structure:
```json
{
  "version": "1.2.3",
  "timestamp": 1714150000,
  "rules": {
    "sqli": { "enabled": true, "patterns": ["...", "..."] },
    "xss": { "enabled": true, "patterns": ["...", "..."] }
  },
  "changelog": [...]
}
```

### Pattern Merging

The `get_merged_patterns` function combines three sources of rules:
1. **DefaultPatterns**: Built-in hardcoded patterns (`crates/synvoid-waf/src/attack_detection/patterns.rs`; `src/waf/` is a re-export facade only).
2. **Local Config**: Patterns defined in the site TOML configuration.
3. **Rule Feed**: Dynamic patterns fetched from the signed update server.

## Configuration

Top-level `[rule_feed]` section in `main.toml`
(`RuleFeedConfig` in `crates/synvoid-config/src/protection.rs`, wired as
`main_config.rule_feed` — NOT `[waf.rule_feed]`):

| Option | Location | Default |
|--------|----------|---------|
| `rule_feed.enabled` | main.toml | `false` |
| `rule_feed.url` | main.toml | `https://rules.example.com/...` |
| `rule_feed.public_key` | main.toml | `None` → falls back to compiled-in key (placeholder by default) |
| `rule_feed.storage_dir` | main.toml | `None` (Persistence disabled) |
| `rule_feed.auto_apply` | main.toml | `true` |
| `rule_feed.update_interval_hours` | main.toml | `24` |
| `rule_feed.allow_downgrade` | main.toml | `false` |

## Security Considerations

- **Fail-Closed**: If the public key is not configured or remains at the placeholder value, the system will refuse to start or apply updates.
- **Downgrade Protection**: By default, the system rejects rule versions older than the currently applied version.
- **Signature Scope**: The signature covers the entire rule payload including version and timestamp.

## Monitoring

- `synvoid.waf.rule_update_success`: Counter incremented on successful application.
- `synvoid.waf.rule_update_failure`: Counter incremented on verification or application failure.
- `current_version`: Exposed via Admin API /status endpoint.

---

Last updated: 2026-04-26
