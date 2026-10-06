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
- **Fetching**: Background polling of configured HTTPS endpoints
  (`start_background_fetching` / `check_and_fetch`).
- **Verification**: Ed25519 signature verification using an embedded or configured public key.
- **Persistence**: Saving verified rules to `storage_dir` in JSON format.
- **Apply**: Updates the supervisor's in-process pattern globals via
  `apply_rules()`, then invokes an optional callback. Worker broadcast is
  wired on the worker side but the callback is never registered — see
  "Cross-Process Synchronization" below.

### Cross-Process Synchronization

The apply path is a callback, not a direct broadcast. Verified state:

1. **Supervisor**: `RuleFeedManager::start_background_fetching()` runs the
   poll loop ("Master Process" in older docs = the Supervisor under the
   current process model).
2. **Apply Callback**: `RuleFeedManager::set_on_apply_callback()` installs a
   closure typed `Fn(String, Vec<crate::process::ipc::RulePatternData>)` —
   the payload carries the new `version` plus the patterns.
3. **IPC Broadcast**: `IpcManager::broadcast_rule_patterns_update(version,
   patterns)` in `crates/synvoid-ipc/src/manager.rs` wraps them in
   `Message::RulePatternsUpdate { version, patterns }` and sends to every
   unified-server worker.
4. **Worker Update**: `src/worker/unified_server/lifecycle.rs` matches
   `Message::RulePatternsUpdate` and reloads the in-process pattern sets.

**Gap**: nothing in the repository calls `set_on_apply_callback()` outside
`src/waf/rule_feed.rs` itself, and `broadcast_rule_patterns_update()` has no
callers at all. Both halves of the chain are implemented and the worker side
is live, but the callback is never registered, so supervisor→worker rule
broadcast does not currently fire. `apply_rules()` still updates the
supervisor's own in-process pattern globals. Do not describe cross-worker
rule propagation as active.

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
1. **DefaultPatterns**: Built-in hardcoded patterns (`crates/synvoid-waf/src/attack_detection/patterns.rs`, passed in as `default_patterns`).
2. **Local Config**: Patterns defined in the site TOML configuration
   (`config_custom`).
3. **Rule Feed**: Dynamic patterns fetched from the signed update server
   (`get_custom_patterns_for_category`).

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

- `get_current_version()` — exposed via the admin rule-feed handler
  (`src/admin/handlers/rule_feed.rs`), which also reports `last_update` /
  `last_check` / pending-update state.
- No rule-feed `metrics::counter!` is emitted from `src/waf/rule_feed.rs`;
  observability is via `tracing` logs and the admin handler response.

---

Last updated: 2026-04-26
