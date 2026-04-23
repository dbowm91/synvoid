# Admin Panel Configuration API Expansion - Implementation Plan

**Last updated**: 2026-04-23
**Status**: PENDING

## Overview

This plan addresses expanding the Admin API to expose all configuration options for complete programmatic control of the MaluWAF firewall. The goal is to make all TOML configuration accessible via the REST API while maintaining the existing overseer/master/worker architecture.

**Key finding**: Instead of creating hundreds of individual endpoints, use a tiered approach combining:
- Full config bundle (already exists)
- Section-level endpoints (30 exist)
- Site sub-config pattern (22+ to add)

---

## Current State Analysis

### Existing Admin API Coverage

| Category | Endpoints | Coverage |
|----------|-----------|----------|
| Global Config Sections | ~30 GET/PUT pairs | ~75% |
| Site Management | CRUD + 3 sub-configs | ~20% |
| System/Workers | Full | 100% |
| Mesh | Full | 100% |
| PHP Pools | List + Reload | 50% |
| Upstreams | List + Health Check | 30% (read-only) |

### Missing Global Config Sections

| Config | Current Status | Priority |
|--------|---------------|----------|
| `server` | **Missing** | High |
| `admin` | **Missing** | High |
| `persistence` | **Missing** | High |
| `tarpit` (defaults) | **Missing** | Medium |
| `icmp_filter` | **Missing** | Medium |
| `static_config` | **Missing** | Medium |

### Missing Site Sub-Configs

| Config | Current Status | Priority |
|--------|---------------|----------|
| `ratelimit` | **Missing** | High |
| `proxy` | **Missing** | High |
| `static` | **Missing** | High |
| `security` | **Missing** | High |
| `security_headers` | **Missing** | High |
| `upload` | **Missing** | High |
| `worker_pool` | **Missing** | High |
| `logging` | **Missing** | Medium |
| `blocked` | **Missing** | Medium |
| `whitelist` | **Missing** | Medium |
| `tarpit` | **Missing** | Medium |
| `honeypot_probe` | **Missing** | Medium |
| `tcp` | **Missing** | Medium |
| `udp` | **Missing** | Medium |
| `grpc` | **Missing** | Medium |
| `websocket` | **Missing** | Medium |
| `app_server` | **Missing** | Medium |
| `serverless` | **Missing** | Medium |
| `file_manager` | **Missing** | Medium |
| `attack_detection` | **Missing** | Medium |
| `css_challenge` | **Missing** | Low |
| `image_poison` | **Missing** | Low |

---

## Investigation Summary

### AdminState Structure

**Location**: `src/admin/state.rs:232-242`

```rust
pub struct AdminState {
    pub metrics: MetricsState,
    pub waf_tracking: WafTrackingState,
    pub security: SecurityState,
    pub mesh: MeshState,
    pub honeypot: HoneypotState,
    pub process: ProcessState,      // Key: holds config & process_manager
    pub plugins: PluginsState,
    pub audit: AuditState,
}
```

**ProcessState** contains:
- `config: Arc<TokioRwLock<ConfigManager>>` - Full config access
- `process_manager: Option<Arc<ProcessManager>>` - Worker management
- `alert_manager: Option<Arc<AlertManager>>`
- `plugin_manager: Option<Arc<PluginManager>>`

### Config Handler Pattern

**Location**: `src/admin/handlers/config.rs`

Each config section follows this pattern:

```rust
// 1. Response type
#[derive(Debug, Serialize)]
pub struct FooConfigResponse {
    pub config: crate::config::foo::FooConfig,
}

// 2. Request type  
#[derive(Debug, Deserialize)]
pub struct UpdateFooConfigRequest {
    pub config: crate::config::foo::FooConfig,
}

// 3. GET handler
#[utoipa::path(get, path = "/api/config/foo", ...)]
pub async fn get_foo_config(...) -> Result<Json<FooConfigResponse>, ...> {
    let config = state.process.config.read().await;
    Ok(Json(FooConfigResponse { config: config.main.foo.clone() }))
}

// 4. PUT handler
#[utoipa::path(put, path = "/api/config/foo", ...)]
pub async fn update_foo_config(...) -> Result<Json<StatusResponse>, ...> {
    // Validate
    req.config.validate()?;  // if validate() exists
    
    // Update in-memory
    {
        let mut config = state.process.config.write().await;
        config.main.foo = req.config;
    }
    
    // Persist and notify
    persist_main_config_and_notify(&state).await
}
```

### Site Sub-Config Pattern

**Location**: `src/admin/handlers/sites.rs`

**Critical**: Site sub-configs use a file-per-site pattern. Each site has its own TOML file in `sites_dir/{site_id}.toml`.

**Helper function** for getting config path:
```rust
// From sites.rs - common helper
fn config_path(sites_dir: &Path, site_id: &str) -> PathBuf {
    sites_dir.join(format!("{}.toml", site_id))
}
```

Existing pattern for site-specific endpoints:

```rust
// GET /api/sites/{site_id}/theme
pub async fn get_site_theme(...) -> Result<Json<SiteThemeResponse>, ...> {
    let config = state.process.config.read().await;
    let site = config.sites.get(&site_id).ok_or(StatusCode::NOT_FOUND)?;
    let theme = &site.error_pages.theme;
    // Return response
}

// PUT /api/sites/{site_id}/theme
pub async fn update_site_theme(...) -> Result<Json<SiteThemeResponse>, ...> {
    // Update in-memory
    site.error_pages.theme = Some(...);

    // Get config path helper
    let config_path = {
        let cfg = state.process.config.read().await;
        config_path(&cfg.sites_dir, &site_id)
    };

    // Persist site-specific TOML
    let toml_content = toml::to_string_pretty(&site_config)?;
    tokio::fs::write(&config_path, toml_content).await?;

    // Broadcast to mesh if applicable
    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        mesh_transport.broadcast_site_config_to_origins(...).await;
    }
}
```

---

## Implementation Plan

### Phase 1: Global Config Gaps (6 sections)

#### Task 1.1: Add Server Config Endpoint

**Files to modify**:
- `src/admin/handlers/config.rs` - Add handlers
- `src/admin/mod.rs` - Add routes
- `src/admin/openapi.rs` - Add to OpenAPI spec

**Implementation**:

```rust
// Response/Request types
#[derive(Debug, Serialize)]
pub struct ServerConfigResponse {
    pub config: crate::config::server::ServerConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateServerConfigRequest {
    pub config: crate::config::server::ServerConfig,
}

// Handlers (add to config.rs)
pub async fn get_server_config(...) -> ... {
    let config = state.process.config.read().await;
    Ok(Json(ServerConfigResponse { config: config.main.server.clone() }))
}

pub async fn update_server_config(...) -> ... {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.server = req.config;
    }
    persist_main_config_and_notify(&state).await
}
```

#### Task 1.2: Add Admin Config Endpoint

**Rationale**: Allow admin panel settings to be read/modified programmatically (CORS, rate limiting, token management).

**Note**: Token should be write-only (never returned in GET response).

#### Task 1.3: Add Persistence Config Endpoint

**Rationale**: Control state persistence settings (file paths, intervals).

#### Task 1.4: Add Tarpit Defaults Endpoint

**Rationale**: Global tarpit honeypot defaults.

#### Task 1.5: Add ICMP Filter Config Endpoint

**Feature-gated**: Only when `icmp-filter` feature enabled.

#### Task 1.6: Add Static Config Endpoint

**Rationale**: Global static file worker configuration.

---

### Phase 2: Site Sub-Config Endpoints (22 sections)

For each site config section, create a new handler file or extend `sites.rs`.

#### Task 2.1: Site Ratelimit

**Config struct**: `crate::config::site::SiteRateLimitConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/ratelimit`
- `PUT /api/sites/{site_id}/ratelimit`

**Validation**: `config.validate()` - checks mode ("shared"/"isolated")

**Note**: Unlike global config, site sub-configs validate using the site config's `validate()` method which calls `self.ratelimit.validate()`.

#### Task 2.2: Site Proxy

**Config struct**: `crate::config::site::SiteProxyConfig`

**Note**: Most complex site config - includes upstreams, caching, headers, retry, WASM.

**Endpoints**:
- `GET /api/sites/{site_id}/proxy`
- `PUT /api/sites/{site_id}/proxy`

#### Task 2.3: Site Static

**Config struct**: `crate::config::site::SiteStaticConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/static`
- `PUT /api/sites/{site_id}/static`

#### Task 2.4: Site Security

**Config struct**: `crate::config::site::SiteSecurityConfig`

**Nested configs**: `SiteAuthConfig`, `SiteCorsConfig`, `SiteBasicAuthConfig`, `SiteGeoipConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/security`
- `PUT /api/sites/{site_id}/security`

#### Task 2.5: Site Security Headers

**Config struct**: `crate::config::site::SiteSecurityHeadersConfig`

**Validation**: `validate()` - checks SameSite value

**Endpoints**:
- `GET /api/sites/{site_id}/security-headers`
- `PUT /api/sites/{site_id}/security-headers`

#### Task 2.6: Site Upload

**Config struct**: `crate::config::site::SiteUploadConfig`

**Validation**: `validate()` - parses size strings

**Endpoints**:
- `GET /api/sites/{site_id}/upload`
- `PUT /api/sites/{site_id}/upload`

#### Task 2.7: Site Worker Pool

**Config struct**: `crate::config::site::SiteWorkerPoolConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/worker-pool`
- `PUT /api/sites/{site_id}/worker-pool`

#### Task 2.8: Site Logging

**Config struct**: `crate::config::site::SiteLoggingConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/logging`
- `PUT /api/sites/{site_id}/logging`

#### Task 2.9: Site Blocked Paths

**Config struct**: `crate::config::site::SiteBlockedConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/blocked`
- `PUT /api/sites/{site_id}/blocked`

#### Task 2.10: Site Whitelist

**Config struct**: `crate::config::site::SiteWhitelistConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/whitelist`
- `PUT /api/sites/{site_id}/whitelist`

#### Task 2.11: Site Tarpit

**Config struct**: `crate::config::site::SiteTarpitConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/tarpit`
- `PUT /api/sites/{site_id}/tarpit`

#### Task 2.12: Site Honeypot Probe

**Config struct**: `crate::config::site::SiteProbeConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/honeypot-probe`
- `PUT /api/sites/{site_id}/honeypot-probe`

#### Task 2.13: Site TCP

**Config struct**: `crate::config::site::SiteTcpConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/tcp`
- `PUT /api/sites/{site_id}/tcp`

#### Task 2.14: Site UDP

**Config struct**: `crate::config::site::SiteUdpConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/udp`
- `PUT /api/sites/{site_id}/udp`

#### Task 2.15: Site gRPC

**Config struct**: `crate::config::site::SiteGrpcConfig`

**Validation**: Requires upstream if enabled

**Endpoints**:
- `GET /api/sites/{site_id}/grpc`
- `PUT /api/sites/{site_id}/grpc`

#### Task 2.16: Site WebSocket

**Config struct**: `crate::config::site::SiteWebSocketConfig`

**Validation**: Requires upstream if enabled

**Endpoints**:
- `GET /api/sites/{site_id}/websocket`
- `PUT /api/sites/{site_id}/websocket`

#### Task 2.17: Site App Server

**Config struct**: `crate::config::site::SiteAppServerConfig`

**Validation**: Requires app_path if enabled

**Endpoints**:
- `GET /api/sites/{site_id}/app-server`
- `PUT /api/sites/{site_id}/app-server`

#### Task 2.18: Site Serverless

**Config struct**: `Option<super::serverless::ServerlessConfig>`

**Endpoints**:
- `GET /api/sites/{site_id}/serverless`
- `PUT /api/sites/{site_id}/serverless`

#### Task 2.19: Site File Manager

**Config struct**: `crate::config::site::SiteFileManagerConfig`

**Validation**: Parses size strings

**Endpoints**:
- `GET /api/sites/{site_id}/file-manager`
- `PUT /api/sites/{site_id}/file-manager`

#### Task 2.20: Site Attack Detection

**Config struct**: `crate::config::site::SiteAttackDetectionConfig`

**Nested**: `SiteSqliConfig`, `SiteXssConfig`, `SitePathTraversalConfig`, `SiteRfiConfig`, `SiteSsrfConfig`

**Validation**: Action ("stall"/"block"/"log"), paranoia_level (1-3)

**Endpoints**:
- `GET /api/sites/{site_id}/attack-detection`
- `PUT /api/sites/{site_id}/attack-detection`

#### Task 2.21: Site CSS Challenge

**Config struct**: `crate::config::site::SiteCssChallengeConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/css-challenge`
- `PUT /api/sites/{site_id}/css-challenge`

#### Task 2.22: Site Image Poison

**Config struct**: `crate::config::site::SiteImagePoisonConfig`

**Endpoints**:
- `GET /api/sites/{site_id}/image-poison`
- `PUT /api/sites/{site_id}/image-poison`

---

### Site Sub-Config Implementation Notes

**Key difference from global config**: Site sub-configs are stored in individual TOML files per site (`sites/{site_id}.toml`), not in `main.toml`.

**Update pattern** (for each PUT handler):
1. Acquire `config_write_lock` for atomicity
2. Update in-memory config in `state.process.config.write().await`
3. Get site config path: `sites_dir.join("{sanitized_site_id}.toml")` - note: dots in domain are replaced with underscores
4. Serialize full site config (not just the section) to TOML
5. Write to file
6. Broadcast to mesh origins (if mesh enabled)
7. Release lock

**Helper function** (from `src/admin/handlers/common.rs`):
```rust
pub fn config_path(config_dir: &Path, site_id: &str) -> PathBuf {
    config_dir.join(format!("{}.toml", site_id.replace('.', "_")))
}
```

**Mesh broadcasting** example:
```rust
if let Some(ref mesh_transport) = state.mesh.mesh_transport {
    mesh_transport.broadcast_site_config_to_origins(
        &site_id,
        &toml_content,
        version,
        proxy_cache_preferences,
    ).await;
}
```

### Phase 3: Upstream CRUD Operations

#### Task 3.1: Add Upstream List for Site

**New endpoints**:
- `GET /api/sites/{site_id}/upstreams` - List all upstreams with status

#### Task 3.2: Add Upstream Create

- `POST /api/sites/{site_id}/upstreams` - Add upstream to site config

#### Task 3.3: Add Upstream Update

- `PUT /api/sites/{site_id}/upstreams/{name}` - Update specific upstream

#### Task 3.4: Add Upstream Delete

- `DELETE /api/sites/{site_id}/upstreams/{name}` - Remove upstream

#### Task 3.5: Add Upstream Health Detail

- `GET /api/sites/{site_id}/upstreams/{name}/health` - Detailed health check

---

### Phase 4: PHP Pool Management Enhancement

**Existing handlers**: `src/admin/handlers/php.rs`

Current: List pools + reload

#### Task 4.1: Add Pool Config Endpoint

- `GET /api/php/pools/{socket}/config` - Get FPM configuration

#### Task 4.2: Add Pool Config Update

- `PUT /api/php/pools/{socket}/config` - Update FPM settings

#### Task 4.3: Add Pool Status Detail

- `GET /api/php/pools/{socket}/stats` - Detailed pool statistics

---

### Phase 5: Additional Admin Features

#### Task 5.1: Configuration Change History

- `GET /api/config/history` - List recent config changes with timestamps
- `POST /api/config/rollback/{version}` - Rollback to previous config

#### Task 5.2: Configuration Diff

- `GET /api/config/compare` - Compare current config with previous version

#### Task 5.3: Site Quick Actions

- `POST /api/sites/{id}/enable` - Enable site
- `POST /api/sites/{id}/disable` - Disable site
- `POST /api/sites/{id}/reload` - Reload site config

---

## File Changes Summary

### New Files to Create

| File | Purpose |
|------|---------|
| `src/admin/handlers/sites_ratelimit.rs` | Site ratelimit handlers |
| `src/admin/handlers/sites_proxy.rs` | Site proxy handlers |
| `src/admin/handlers/sites_static.rs` | Site static file handlers |
| `src/admin/handlers/sites_security.rs` | Site security + headers |
| `src/admin/handlers/sites_upload.rs` | Site upload handlers |
| `src/admin/handlers/sites_worker_pool.rs` | Site worker pool |
| `src/admin/handlers/sites_logging.rs` | Site logging |
| `src/admin/handlers/sites_blocked.rs` | Site blocked paths |
| `src/admin/handlers/sites_whitelist.rs` | Site whitelist |
| `src/admin/handlers/sites_tarpit.rs` | Site tarpit |
| `src/admin/handlers/sites_network.rs` | Site TCP/UDP/port handlers |
| `src/admin/handlers/sites_protocols.rs` | Site gRPC/WebSocket |
| `src/admin/handlers/sites_app_server.rs` | Site app server |
| `src/admin/handlers/sites_serverless.rs` | Site serverless |
| `src/admin/handlers/sites_file_manager.rs` | Site file manager |
| `src/admin/handlers/sites_attack_detection.rs` | Site WAF rules |
| `src/admin/handlers/sites_defensive.rs` | Site CSS challenge, honeypot |

### Files to Modify

| File | Changes |
|------|---------|
| `src/admin/handlers/config.rs` | Add 6 global config handlers |
| `src/admin/handlers/sites.rs` | Potentially extend or delegate |
| `src/admin/handlers/upstreams.rs` | Add CRUD operations |
| `src/admin/handlers/php.rs` | Add config endpoints |
| `src/admin/mod.rs` | Add new routes |
| `src/admin/openapi.rs` | Add new endpoints to spec |

---

## Testing Checklist

- [ ] `cargo check` passes after each phase
- [ ] `cargo clippy --lib -- -D warnings` passes
- [ ] All new endpoints return proper JSON
- [ ] Config updates persist to TOML files
- [ ] Config changes broadcast to workers
- [ ] Site sub-configs validate before saving
- [ ] OpenAPI spec includes all new endpoints
- [ ] Integration tests cover new endpoints

---

## Architecture Compliance

**Critical**: The overseer/master/worker architecture must be maintained:

1. **Admin runs in master process** - Config changes originate here
2. **Config persisted to disk** - TOML files in config directory
3. **Workers notified via IPC** - `process_manager.broadcast_config_reload()`
4. **Overseer manages master** - For process-level config changes

**Pattern to follow**:
```rust
// 1. Update in-memory config
{
    let mut config = state.process.config.write().await;
    config.main.foo = req.config;
}

// 2. Persist to TOML
let toml_content = toml::to_string_pretty(&config.main)?;
tokio::fs::write(&main_config_path, toml_content).await?;

// 3. Notify workers
if let Some(ref pm) = state.process.process_manager {
    pm.broadcast_config_reload(config_dir).await;
}
```

---

## Dependencies

- **Existing config handlers**: Pattern to follow from `config.rs`
- **Site handlers**: Pattern from `sites.rs` (theme, bot_detection, error_pages)
- **Config validation**: Already exists in each config struct
- **Persistence**: Uses existing `toml` crate
- **No new external dependencies required**

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Endpoint explosion | Use consistent patterns; reuse code |
| Config validation bypass | Always call `.validate()` before persisting |
| Worker sync failures | Check broadcast result; log errors |
| Large config payload | Support partial updates (PATCH-like) |
| Breaking existing endpoints | Add new endpoints; don't modify existing |

---

## Priority Ordering

### High Priority (Phase 1-2)
1. Global: server, admin, persistence
2. Site: ratelimit, proxy, security, security_headers
3. Site: upload, worker_pool, attack_detection

### Medium Priority (Phase 2-3)
4. Site: static, logging, blocked, whitelist
5. Site: tcp, udp, grpc, websocket
6. Upstream CRUD operations
7. PHP pool config

### Low Priority (Phase 4-5)
8. Site: app_server, serverless, file_manager
9. Site: tarpit, honeypot_probe, css_challenge, image_poison
10. Config history/rollback features
11. Site quick actions

---

## Defer to Future Plans

The following are out of scope for this plan:

1. **GraphQL API** - Alternative query language for config
2. **Config validation service** - External validation endpoint
3. **Configuration versioning** - Git-like history for configs
4. **Multi-tenant isolation** - Advanced access control
5. **Config templates** - Pre-defined config snippets