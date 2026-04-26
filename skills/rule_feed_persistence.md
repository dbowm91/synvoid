# Signed Rule Feed Persistence and Hot-Reload

This skill documents the implementation of dynamic WAF rule updates, local persistence, and cross-worker synchronization.

## Overview

MaluWAF supports automatic rule updates via a signed feed. Rules are fetched, verified cryptographically (Ed25519), persisted locally for offline use, and synchronized across multiple worker processes without restarts.

## Key Components

### RuleFeedManager (`src/waf/rule_feed.rs`)

The `RuleFeedManager` handles the lifecycle of signed rules:
- **Fetching**: Background polling of configured HTTPS endpoints.
- **Verification**: Ed25519 signature verification using an embedded or configured public key.
- **Persistence**: Saving verified rules to `storage_dir` in JSON format.
- **Hot-Reload**: Broadcasting updates to workers via IPC callbacks.

### Cross-Process Synchronization

1. **Master Process**: Runs the `RuleFeedManager` in background mode.
2. **Apply Callback**: When new rules are verified, the manager triggers a callback.
3. **IPC Broadcast**: The master process sends a `RulePatternUpdate` message to all active workers.
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
1. **DefaultPatterns**: Built-in hardcoded patterns (src/waf/attack_detection/patterns.rs).
2. **Local Config**: Patterns defined in the site TOML configuration.
3. **Rule Feed**: Dynamic patterns fetched from the signed update server.

## Configuration

| Option | Location | Default |
|--------|----------|---------|
| `waf.rule_feed.enabled` | TOML | `false` |
| `waf.rule_feed.url` | TOML | `https://rules.example.com/...` |
| `waf.rule_feed.public_key` | TOML | (Must be configured) |
| `waf.rule_feed.storage_dir` | TOML | `None` (Persistence disabled) |
| `waf.rule_feed.auto_apply` | TOML | `true` |

## Security Considerations

- **Fail-Closed**: If the public key is not configured or remains at the placeholder value, the system will refuse to start or apply updates.
- **Downgrade Protection**: By default, the system rejects rule versions older than the currently applied version.
- **Signature Scope**: The signature covers the entire rule payload including version and timestamp.

## Monitoring

- `maluwaf.waf.rule_update_success`: Counter incremented on successful application.
- `maluwaf.waf.rule_update_failure`: Counter incremented on verification or application failure.
- `current_version`: Exposed via Admin API /status endpoint.

---

Last updated: 2026-04-26
