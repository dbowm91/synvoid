# Admin Panel Enhancement Plan

> Generated: 2026-03-27
> Status: Draft

## Overview

This plan addresses gaps in the MaluWAF admin panel configuration coverage while preserving the overseer/master/worker architecture.

---

## 1. Executive Summary

The admin panel has comprehensive API coverage (50+ endpoints) but suffers from:
- Missing CRUD endpoints for 10+ config structs
- Hardcoded config schema that doesn't reflect runtime state
- Frontend pages not matching available backend APIs
- No config validation before saving
- No config versioning/rollback

**Impact**: Operators cannot configure TLS, HTTP, Security, Tunnel, DNS, and other critical settings via the admin panel.

---

## 2. Architecture Context

### Current Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Overseer                              │
│  (Master process lifecycle, health monitoring, upgrades)    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         Master                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Admin API (Port 8081)                   │    │
│  │  - Config handlers (main, overseer, process, sup)   │    │
│  │  - Sites, Upstreams, Stats, Logs                     │    │
│  │  - Threat Level, Probes, Alerts                     │    │
│  │  - Mesh, Honeypot                                   │    │
│  └─────────────────────────────────────────────────────┘    │
│  - ConfigManager (reads/writes config files)                │
│  - ProcessManager (worker lifecycle)                         │
│  - AlertManager, ProbeTracker                               │
└─────────────────────────────────────────────────────────────┘
                              │ IPC (Unix domain sockets)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        Workers                               │
│  (Handle HTTP requests, run WAF rules, proxy traffic)       │
└─────────────────────────────────────────────────────────────┘
```

### Architecture Constraints

1. **Config flows**: Master writes config to disk → signals reload → Workers read via IPC
2. **Dynamic updates**: Only ProcessManagerConfig supports hot-reload currently
3. **Admin runs in Master only**: No admin API in workers or overseer
4. **IPC uses Message enum**: All config changes should use existing IPC patterns

---

## 3. Gap Analysis

### 3.1 Missing Backend API Endpoints

| Priority | Config | File | Endpoints Needed | Status |
|----------|--------|------|------------------|--------|
| **HIGH** | TLS | `src/config/tls.rs` | GET/PUT `/config/tls` | Missing |
| **HIGH** | HTTP | `src/config/http.rs` | GET/PUT `/config/http` | Missing |
| **HIGH** | Security | `src/config/security.rs` | GET/PUT `/config/security` | Missing |
| **HIGH** | Tunnel | `src/config/tunnel.rs` | GET/PUT `/config/tunnel` | Missing |
| **MEDIUM** | Logging | `src/config/logging.rs` | GET/PUT `/config/logging` | Missing |
| **MEDIUM** | DNS | `src/config/dns.rs` | GET/PUT `/config/dns` | Missing |
| **MEDIUM** | Mesh | `src/config/mesh.rs` | GET/PUT `/config/mesh` | Missing |
| **MEDIUM** | Plugins | `src/config/plugins.rs` | GET/PUT `/config/plugins` | Missing |
| **EXISTING** | Overseer | `src/config/process.rs` | GET/PUT `/config/overseer` | ✅ Exists |
| **EXISTING** | Process Manager | `src/config/process.rs` | GET/PUT `/config/process-manager` | ✅ Exists |
| **EXISTING** | Supervisor | `src/config/process.rs` | GET/PUT `/config/supervisor` | ✅ Exists |

### 3.2 Schema Mismatch Issues

The `/config/schema` endpoint (950 lines hardcoded) lists fields that aren't editable:

```
Available in schema but NO dedicated endpoint:
├── defaults.ratelimit.*
├── defaults.blocked.*
├── defaults.bot.*
├── defaults.honeypot.*
├── defaults.pow_challenge.*
├── defaults.css_challenge.*
├── defaults.worker_pool.*
├── defaults.tcp.*
├── defaults.udp.*
├── defaults.upload.*
├── ip_feeds.*
├── rule_feed.*
├── yara_feed.*
└── threat_level.escalation.*
```

### 3.3 Frontend UI Gaps

Based on `admin-ui/src/pages/settings.rs` (currently 919 lines) and page analysis:

| Page | Status | Notes |
|------|--------|-------|
| Server | ✅ Exists | Settings page |
| HTTP | ✅ Exists | Settings page |
| Logging | ✅ Exists | Settings page |
| Metrics | ✅ Exists | Settings page |
| Rate Limits | ✅ Exists | Settings page |
| Bandwidth | ✅ Exists | Settings page |
| Bot Defaults | ✅ Exists | Settings page |
| Upload | ✅ Exists | Settings page |
| Theme | ✅ Exists | Settings page |
| Process Management | ✅ Exists | `process_management.rs` page with API integration |
| **TLS/SSL** | ❌ Missing | No page, but docs exist in `config_docs.rs` |
| **Security** | ❌ Missing | No page |
| **Tunnel/VPN** | ❌ Missing | No page |
| **DNS** | ❌ Missing | No page (conditional on `dns` feature) |
| **Mesh Network** | ❌ Missing | No dedicated page |
| **Plugin Management** | ❌ Missing | No page |
| **Rule Feeds** | ❌ Missing | No page |

**Correction:** The Process Management page already exists in `admin-ui/src/pages/process_management.rs` with full API integration for Overseer, ProcessManager, and Supervisor configs.

---

## 4. Implementation Plan

### Phase 1: Backend API Expansion (Weeks 1-2)

### Task 1.1: Add TLS Config Endpoint

**Priority:** HIGH
**Estimated effort:** 4 hours

**Code location:** `src/admin/handlers/config.rs`

**Implementation pattern:** Follow existing `/config/overseer` pattern in `config.rs:1242-1328`

**Note:** TLS documentation already exists in `admin-ui/src/config_docs.rs:189-219`. New UI section should use this as reference.

#### Task 1.2: Add HTTP Config Endpoint

**Files to modify:**
- `src/admin/handlers/config.rs` - Add handlers
- `src/admin/mod.rs` - Register routes

**Endpoints:**
```
GET    /config/http        → Returns HttpConfig
PUT    /config/http        → Updates HttpConfig
```

#### Task 1.3: Add Security Config Endpoint

**Files to modify:**
- `src/admin/handlers/config.rs` - Add handlers
- `src/admin/mod.rs` - Register routes
- `src/config/security.rs` - Verify MainSecurityConfig structure

**Endpoints:**
```
GET    /config/security    → Returns MainSecurityConfig
PUT    /config/security    → Updates MainSecurityConfig
```

#### Task 1.4: Add Tunnel Config Endpoint

**Files to modify:**
- `src/admin/handlers/config.rs` - Add handlers
- `src/admin/mod.rs` - Register routes

**Endpoints:**
```
GET    /config/tunnel     → Returns TunnelConfig
PUT    /config/tunnel     → Updates TunnelConfig
```

### Phase 2: Dynamic Schema Generation (Week 2)

#### Task 2.1: Replace Hardcoded Schema with Dynamic Generation

**Problem:** `/config/schema` has 950 lines of hardcoded fields that don't match runtime state

**Solution:** Generate schema from actual `MainConfig` struct using `serde` and `utoipa`

**Files to modify:**
- `src/admin/handlers/config.rs` - Rewrite `get_config_schema()`
- Optionally add `#[schema(..)]` attributes to config structs

**Benefits:**
- Schema always matches actual config
- New config fields automatically exposed
- Reduces maintenance burden

### Phase 3: Config Validation & Preview (Week 3)

#### Task 3.1: Add Config Validation Endpoint

**Files to modify:**
- `src/admin/handlers/config.rs` - Add validation handler
- `src/config/validation.rs` - Use existing validation

**Endpoints:**
```
POST   /config/validate    → Validates config without saving
                              Returns validation errors or success
```

#### Task 3.2: Add "Requires Restart" Detection

**Implementation:** Add metadata to config fields indicating whether they require restart:
```rust
#[schema(path = "server.port", requires_restart = true)]
```

**UI enhancement:** Display warning badges on fields requiring restart

### Phase 4: Frontend UI Expansion (Weeks 3-4)

#### Task 4.1: Add TLS Configuration Page

**Files to modify:**
- `admin-ui/src/pages/settings.rs` - Add TLS section or new page
- `admin-ui/src/services/api.rs` - Add API calls

**UI Elements:**
- Enable TLS toggle
- Certificate/Key file paths
- TLS version selection
- Client auth (mTLS) settings
- ACME configuration

#### Task 4.2: Add Security Settings Page

**Files to modify:**
- `admin-ui/src/pages/settings.rs` - Add Security section

**UI Elements:**
- IPC signing toggle
- Session key configuration
- Static file serving settings

#### Task 4.3: Add Process Management Page

**Files to modify:**
- `admin-ui/src/pages/process_management.rs` - Enhance existing or create new

**UI Elements:**
- Worker count display
- Min/Max workers configuration
- Health check settings
- Restart policies
- Current worker status

#### Task 4.4: Add Tunnel/VPN Page (if feature enabled)

**Files to modify:**
- `admin-ui/src/pages/tunnel.rs` - New file

**UI Elements:**
- WireGuard peer management
- Port mappings
- Tunnel status

### Phase 5: Advanced Features (Week 5)

#### Task 5.1: Config Versioning

**Features:**
- Store last N config versions in `data_dir`
- `/config/versions` - List versions
- `/config/versions/:id` - Get specific version
- `/config/rollback/:id` - Rollback to version

**Files to modify:**
- `src/admin/handlers/config.rs` - Version handlers
- `src/config/mod.rs` - Version storage logic

#### Task 5.2: Config Diff View

**UI enhancement:**
- Show before/after when editing config
- Highlight changed fields

---

## 5. Detailed Task Breakdown

### Task 1.1: TLS Config Endpoint (HIGH)

**Estimated effort:** 4 hours

**Code location:** `src/admin/handlers/config.rs`

**Implementation:**
```rust
// Add after existing config handlers (around line 1500)

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TlsConfigResponse {
    pub config: crate::config::tls::TlsConfig,
}

#[utoipa::path(
    get,
    path = "/config/tls",
    tag = "Config",
    responses(
        (status = 200, description = "TLS configuration", body = [TlsConfigResponse]),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_tls_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TlsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TlsConfigResponse {
        config: config.main.tls.clone(),
    }))
}

// PUT handler follows same pattern as update_overseer_config
```

**Route registration:** Add to `src/admin/mod.rs`:
```rust
.route("/config/tls", get(handlers::config::get_tls_config))
.route("/config/tls", put(handlers::config::update_tls_config))
```

### Task 1.2: HTTP Config Endpoint (HIGH)

**Estimated effort:** 4 hours

**Code location:** `src/admin/handlers/config.rs`

**Implementation:** Same pattern as TLS, using `crate::config::http::HttpConfig`

### Task 1.3: Security Config Endpoint (HIGH)

**Estimated effort:** 4 hours

**Code location:** `src/admin/handlers/config.rs`

**Implementation:** Same pattern, using `crate::config::security::MainSecurityConfig`

### Task 1.4: Tunnel Config Endpoint (HIGH)

**Estimated effort:** 4 hours

**Code location:** `src/admin/handlers/config.rs`

**Implementation:** Same pattern, using `crate::config::tunnel::TunnelConfig`

### Task 2.1: Dynamic Schema Generation (MEDIUM)

**Estimated effort:** 8 hours

**Implementation approach:**
1. Use `serde_json::to_value(&MainConfig::default())` to get all fields
2. Recursively build schema from JSON value
3. Add descriptions from existing hardcoded schema

**Alternative:** Add `#[schema]` attributes to config structs incrementally

---

## 6. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Config validation failures | Medium | High | Add /config/validate before save |
| Worker restart required | High | Medium | Document in UI, add warnings |
| Breaking existing API | Low | High | Version endpoints, add deprecation warnings |
| Schema/UI drift | Medium | Low | Automate schema generation |

---

## 7. Testing Plan

### Backend Tests

1. **Config endpoint tests:** Add handlers to `tests/integration_test.rs`
   ```rust
   #[test]
   fn test_tls_config_crud() {
       // GET, PUT, verify persistence
   }
   ```

2. **Config validation tests:** Verify invalid configs rejected
   ```rust
   #[test]
   fn test_invalid_tls_config() {
       // PUT invalid, expect 400
   }
   ```

### Frontend Tests

1. **Settings page tests:** Verify all sections load
2. **Form validation:** Verify field validation works
3. **Save/reset:** Verify save persists, reset reverts

---

## 8. Success Metrics

| Metric | Target |
|--------|--------|
| Config endpoint coverage | 100% of config structs have GET/PUT |
| Schema accuracy | 100% match (dynamic generation) |
| UI coverage | All endpoints accessible in UI |
| Config validation | 100% of configs validated before save |

---

## 9. Timeline

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1 | Backend Phase 1 | TLS, HTTP, Security, Tunnel endpoints |
| 2 | Backend Phase 2 | Dynamic schema generation |
| 3 | Validation + UI | Config validate, start UI expansion |
| 4 | Frontend | TLS, Security, Process pages |
| 5 | Advanced | Config versioning, diff view |

---

## 10. Open Questions

1. **Hot reload scope:** Should TLS changes require full restart, or can workers reload?
2. **Config validation:** How strict should validation be? Allow partial configs?
3. **Versioning:** How many versions to keep? Where to store?
4. **Feature flags:** Should new pages respect compile-time feature flags in UI?

---

## Appendix: File Reference

### Backend Files
- `src/admin/handlers/config.rs` - Config API handlers (1530+ lines)
- `src/admin/mod.rs` - Router registration
- `src/admin/state.rs` - AdminState with ConfigManager
- `src/config/*.rs` - All config structs

### Frontend Files
- `admin-ui/src/pages/settings.rs` - Settings page (919 lines)
- `admin-ui/src/pages/process_management.rs` - Process management
- `admin-ui/src/services/api.rs` - API client
- `admin-ui/src/components/forms/` - Form components
