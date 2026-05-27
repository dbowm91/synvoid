# Config Module - AGENTS.override.md

Specialized guidance for configuration management in `crates/synvoid-config/`.

## ConfigManager Location

`ConfigManager` is defined in `crates/synvoid-config/src/lib.rs:113-241`, NOT in `main_config.rs`. `MainConfig` is in `main_config.rs` but `ConfigManager` is a separate struct that wraps it.

## Feature-Gated Compilation

The config module uses standard Rust feature gates:

```rust
#[cfg(feature = "dns")]      // DNS support
#[cfg(feature = "mesh")]     // Mesh/DHT support
#[cfg(feature = "icmp-filter")] // ICMP filtering
```

## Config Propagation Patterns

When adding new fields to config structs, ensure they propagate through all layers:

1. `SiteAppServerConfig` (in `site/app_server.rs`)
2. → `AppServerConfig` (in `site/mod.rs`)  
3. → `GranianConfig` (in `site/mod.rs`)

Example (APP-17 `require_hashes` field):
- `crates/synvoid-config/src/site/app_server.rs:53` — `require_hashes: Option<bool>`
- `crates/synvoid-config/src/site/mod.rs:259` — propagates to `AppServerConfig`

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-config/src/lib.rs` | ConfigManager, MainConfig re-exports |
| `crates/synvoid-config/src/main_config.rs` | MainConfig struct with all settings |
| `crates/synvoid-config/src/site/mod.rs` | SiteConfig, AppServerConfig, GranianConfig |
| `crates/synvoid-config/src/site/app_server.rs` | App server-specific config |
| `crates/synvoid-config/src/http.rs` | HTTP protocol limits |
| `crates/synvoid-config/src/mesh.rs` | Mesh/mesh networking config |

## Validation Patterns

Config validation happens at multiple levels:
1. **Parse time**: TOML/JSON parsing validation
2. **Load time**: `ConfigManager::load_site()` calls `SiteConfig::from_file()` which validates
3. **Runtime**: Values are validated when applied (e.g., rate limits, timeouts)

## Hot Reload

Site configurations support hot reload via `ConfigManager::reload_site()` and `reload_all()`. Changes to site configs are detected and applied without restart.

## Known Config Bugs

### AppServerConfig Default Port

`crates/synvoid-config/src/site/app_server.rs:49` — `AppServerConfig::default()`:

```rust
port: Some(8000),
host: Some("127.0.0.1".to_string()),
```

**Issue**: Default port is 8000 on localhost - may not match production expectations. This may be intentional for dev mode but should be documented if not.