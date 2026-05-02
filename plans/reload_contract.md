# Config Reload Behavior Contract

This document classifies MaluWAF configuration fields by their reload behavior.

## Classification Summary

| Config Section | Hot Reload | Restart Required | Notes |
|---------------|-----------|------------------|-------|
| **Site routing** | ✅ Yes | - | Sites reload via `ConfigManager::reload_all()` |
| **Site upstream/proxy** | ✅ Yes | - | Proxy config rebuilt with site |
| **Site ratelimit** | ✅ Yes | - | Rate limit config per-site |
| **Site security headers** | ✅ Yes | - | Headers rebuilt with site |
| **Site static files** | ✅ Yes | - | Static handlers rebuilt |
| **Site attack_detection** | ✅ Yes | - | WAF rules per-site |
| **Main server.port** | - | ❌ Yes | Listener binding |
| **Main server.host** | - | ❌ Yes | Listener binding |
| **Main tls.port** | - | ❌ Yes | TLS listener binding |
| **Main http3.port** | - | ❌ Yes | QUIC listener binding |
| **Main admin.port** | - | ❌ Yes | Admin API binding |
| **Main process_manager workers** | - | ❌ Yes | Process count |
| **Main mesh** | - | ❌ Yes | Mesh identity/trust requires restart |
| **Main dns** | - | ❌ Yes | DNS listener mode |
| **Main plugins** | ⚠️ Limited | - | Only plugin directory changes |
| **Main mimes** | ✅ Yes | - | Mime types file |
| **Main logging** | ⚠️ Limited | - | Log level only |
| **Main tunnel** | - | ❌ Yes | Tunnel configuration |
| **Main overseer** | - | ❌ Yes | Overseer configuration |
| **Main supervisor** | - | ❌ Yes | Supervisor configuration |

## Detailed Field Classification

### Hot Reloadable Fields

#### Site-Level (per-site configs in `sites/` directory)
- `site.domains` - Site routing changes
- `site.upstream` - Proxy upstream configuration
- `site.proxy` - Proxy cache, headers, buffering settings
- `site.ratelimit` - Rate limiting rules
- `site.security` - Security headers, CORS, auth
- `site.static` - Static file serving configuration
- `site.attack_detection` - WAF rule patterns
- `site.error_pages` - Custom error pages
- `site.file_manager` - File manager settings
- `site.upload` - Upload configuration

#### Main-Level
- `mimes` - Mime types file (reloaded separately via `reload_mimes_from_file()`)
- `logging.level` - Log level (via dynamic log controller)

### Restart Required Fields

#### Listener Ports/Addresses
- `server.port`, `server.host`, `server.host_v6` - HTTP server binding
- `tls.port` - HTTPS server binding
- `http3.port` - HTTP/3 QUIC binding
- `admin.port`, `admin.bind_address` - Admin API binding
- `dns.port`, `dns.bind_address` - DNS server binding

#### Process Management
- `process_manager.workers` - Worker process count
- `process_manager.unified` - Unified vs separate workers
- `overseer` - Overseer process configuration
- `supervisor` - Supervisor configuration

#### Mesh/Identity
- `mesh` - Entire mesh configuration (identity, trust anchors, ports)
- `tunnel.mesh` - Mesh tunnel configuration

#### DNS
- `dns` - DNS server mode and configuration

#### Plugin Global Settings
- `plugins.global_memory_limit` - Global plugin memory budget
- `plugins.max_plugins` - Maximum plugin count
- `plugins.runtime` - Plugin runtime type

### Fields with Limited Reload Support

#### Plugins
- `plugins.directory` - Plugin directory path (supports hot-reload via file watching)
- Individual plugin `.wasm` files can be hot-reloaded when directory watching is enabled

#### Logging
- `logging.level` - Only the log level is dynamically reloadable
- Other logging settings (output files, formats) require restart

## Current Implementation Status

### What Currently Works

1. **`ConfigManager::reload_all()`** - Reloads all site configs from disk:
   - Calls `reload_site()` for each domain
   - Logs success/failure per site

2. **`UnifiedServer::reload_config()`** (src/server/mod.rs:1282):
   - Calls `cfg.reload_all()` on ConfigManager
   - Only updates ConfigManager state
   - **Does NOT rebuild Router or other derived state**

3. **Admin `/config/reload` endpoint** (src/admin/handlers/config.rs:165):
   - Reloads ConfigManager via `reload_all()`
   - Reloads mimes file if enabled
   - Broadcasts to workers via IPC
   - Returns success even if serving state not updated

4. **Worker IPC handling** (src/worker/unified_server.rs:1327):
   - Workers receive `MasterConfigReload` message
   - **Blocked entirely when mesh feature is enabled**
   - Reloads ConfigManager but not Router

### What Doesn't Work

1. **Router not rebuilt** - `Arc<Router>` is built once at startup and never updated on reload
2. **WAF config not updated** - Attack detection patterns may not change until restart
3. **Static handlers not rebuilt** - Static file serving config may be stale
4. **Site proxy settings not propagated** - Upstream changes don't take effect
5. **Mesh blocks all reload** - Even independent field changes are rejected when mesh is enabled

### Issues with Current Response Messages

The admin reload handler logs success and returns `"success"` status even when:
1. Only ConfigManager was updated (not serving state)
2. The mesh feature blocked the reload
3. No actual request-serving behavior will change

## Implementation Recommendations

### Phase 1: Accurate Reporting
1. Add reload result status types: `hot_reload_applied`, `restart_required`, `unsupported_in_profile`, `config_rejected`
2. Report restart_required when mesh is enabled
3. Don't log "success" when serving state unchanged

### Phase 2: Incremental Rebuild (Future)
1. Detect which config sections changed
2. Rebuild only affected derived state:
   - Site routing → rebuild Router entries
   - WAF config → rebuild/reload WafCore
   - Static config → rebuild static handlers

### Phase 3: Atomic Snapshot Swap (Future)
1. Create `RuntimeSnapshot` containing all derived serving state
2. Use `ArcSwap` or equivalent for atomic snapshot swapping
3. Ensure concurrent requests see either old or new snapshot, never partial state

## Test Cases

- [ ] Reloading site domain updates routing without restart (core profile)
- [ ] Reloading upstream URL updates proxy target
- [ ] Reloading listener port returns restart_required
- [ ] Reloading mesh identity returns restart_required
- [ ] Invalid config does not replace active snapshot
- [ ] Concurrent requests see either old or new snapshot, never partial state
