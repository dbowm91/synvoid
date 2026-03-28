# Admin Panel Enhancement Plan: Config Accessibility & Usability

## Overview

This plan addresses gaps in the MaluWAF admin panel where available backend configurations are not accessible through the UI, and improves overall usability. **This plan is complementary to `plan_ui.md`** - while `plan_ui.md` focuses on security (authentication), architecture (global state), and general UI/UX, this plan focuses specifically on **making all backend config options accessible via the admin panel** and improving config-related usability.

The overseer/master/worker architecture must be maintained throughout.

---

## Relationship to plan_ui.md

| plan_ui.md | plan_ui2.md |
|------------|-------------|
| Authentication system | Settings page config load/save |
| Global state management | Config section completeness |
| Error boundaries | Config validation API |
| Form validation (general) | Config-specific validation |
| Accessibility improvements | Restart required indicators |
| Component refactoring | Dynamic schema rendering |

## Architecture Context

The admin panel consists of:
- **Backend**: Rust Axum API in `src/admin/` (16 handlers)
- **Frontend**: Yew/Trunk webapp in `admin-ui/` (14 pages)
- **API Base**: `/api` prefix, authenticated via Bearer token
- **State Management**: `AdminState` in `src/admin/state.rs` shared across handlers

### Key Backend Files
- `src/admin/handlers/config.rs` - Config endpoints (1,543 lines)
- `src/admin/handlers/mod.rs` - Handler module declarations
- `src/admin/state.rs` - AdminState with metrics, waf_tracking, process, mesh, honeypot
- `src/config/main.rs` - MainConfig with **34 top-level sections**

### Config Sections in MainConfig

| # | Config Section | Type | Current UI Coverage |
|---|----------------|------|---------------------|
| 1 | server | ServerConfig | Partial (host, port) |
| 2 | fallback | FallbackConfig | None |
| 3 | admin | AdminConfig | None |
| 4 | logging | LoggingConfig | Partial |
| 5 | metrics | MetricsConfig | Partial |
| 6 | tokio | TokioConfig | None |
| 7 | http | HttpConfig | None |
| 8 | tls | TlsConfig | None |
| 9 | http3 | Http3Config | None |
| 10 | defaults | DefaultsConfig | Partial |
| 11 | threat_level | ThreatLevelConfig | Via dedicated page |
| 12 | ip_feeds | IpFeedConfig | None |
| 13 | rule_feed | RuleFeedConfig | None |
| 14 | yara_feed | YaraRuleFeedConfig | None |
| 15 | rate_limit_memory | RateLimitMemoryConfig | None |
| 16 | proxy_limits | ProxyLimitsConfig | None |
| 17 | blocklist_limits | BlocklistLimitsConfig | None |
| 18 | tcp | TcpDefaults | None |
| 19 | udp | UdpDefaults | None |
| 20 | tarpit | TarpitDefaults | None |
| 21 | persistence | PersistenceConfig | None |
| 22 | traffic_shaping | TrafficShapingConfig | None |
| 23 | security | MainSecurityConfig | None |
| 24 | static_config | Option<MainStaticConfig> | None |
| 25 | tunnel | TunnelConfig | None |
| 26 | plugins | PluginConfig | None |
| 27 | upgrade | Option<UpgradeConfig> | None |
| 28 | icmp_filter | IcmpFilterConfig | None |
| 29 | mimes | MimesConfig | None |
| 30 | dns | DnsConfig | None |
| 31 | mesh | Option<MeshConfig> | None |
| 32 | overseer | OverseerConfig | Via process_management page |
| 33 | process_manager | ProcessManagerConfig | Via process_management page |
| 34 | supervisor | SupervisorConfig | Via process_management page |

**Current Coverage**: Only ~9 of 34 config sections (26%) are accessible via UI.

### Key Frontend Files
- `admin-ui/src/pages/settings.rs` - Settings page (hardcoded values)
- `admin-ui/src/pages/process_management.rs` - Working config UI (778 lines)
- `admin-ui/src/services/api.rs` - API client
- `admin-ui/src/types/mod.rs` - TypeScript equivalent types

---

## Phase 1: Fix Critical Gaps (Priority: HIGH)

### 1.1 Settings Page - Load Config from API

**Problem**: `admin-ui/src/pages/settings.rs` uses hardcoded values (lines 117-465) instead of loading from API.

**Reference**: The `process_management.rs` page demonstrates working config loading - use as template.

**Current State**:
- Input fields have hardcoded `value="0.0.0.0"`, `value="8080"`, etc.
- No API call to `/config/main` or `/config/schema`

**Implementation**:
1. Add `use_effect` to fetch config on mount
2. Add state for each config section: `server_config`, `http_config`, `logging_config`, etc.
3. Populate form fields from API response
4. Handle loading and error states

**Files to Modify**:
- `admin-ui/src/pages/settings.rs`

**API Endpoints to Use**:
- `GET /api/config/main` - Full main config
- `GET /api/config/schema` - Schema with field metadata (already exists!)

---

### 1.2 Settings Page - Save Config to API

**Problem**: Save button does nothing (lines 72-77).

**Implementation**:
1. Wire Save button to call `ApiService::update_config_main()`
2. Handle success/error responses with toast notifications
3. Show "Restart Required" indicator when needed

**Files to Modify**:
- `admin-ui/src/pages/settings.rs`
- `admin-ui/src/services/api.rs` (already has method at line 434)

---

## Phase 2: Add Missing Config Sections (Priority: HIGH)

### 2.1 Create New Settings Subsections

Add to Settings page navigation (after "Theme"):

| Section | Config Path | Fields |
|---------|-------------|--------|
| TLS/SSL | `tls.*` | enabled, port, cert_path, key_path, prefer_post_quantum, tls_1_3_only, acme.*, client_auth.* |
| Admin | `admin.*` | enabled, port, bind_address, token_env_var, cors.*, rate_limit.* |
| Security | `security.*` | ipc_enforce_signing, ipc_session_key_env, trusted_tokens |
| IP Feeds | `ip_feeds.*` | enabled, update_interval_hours, url, max_permanent_blocks |
| Rule Feed | `rule_feed.*` | enabled, update_interval_hours, sources |
| Persistence | `persistence.*` | enabled, data_dir, persist_interval_secs |
| Error Pages | `defaults.error_pages.*` | mode, directory |

### 2.2 Create Standalone Pages for Complex Config

For complex configs, create dedicated pages:

1. **TLS Settings Page** (`admin-ui/src/pages/tls_settings.rs`)
   - Certificate management
   - ACME configuration
   - Client auth (mTLS)
   - Cipher suites

2. **Security Settings Page** (`admin-ui/src/pages/security_settings.rs`)
   - IPC security
   - Session management
   - Trusted tokens

3. **Feeds Page** (`admin-ui/src/pages/feeds.rs`)
   - IP blocklist feeds
   - WAF rule feeds
   - YARA rule feeds

### 2.3 Add Handler Endpoints (if missing)

Review and add endpoints in `src/admin/handlers/config.rs`:

| Endpoint | Status | Notes |
|----------|--------|-------|
| GET/PUT /config/tls | Missing | Add for TLS-specific config |
| GET/PUT /config/security | Missing | Add for security settings |
| GET/PUT /config/feeds | Missing | Combine IP/rule feeds |
| GET/PUT /config/persistence | Missing | Persistence settings |
| GET/PUT /config/error-pages | Missing | Error page config |

---

## Phase 3: Usability Improvements (Priority: MEDIUM)

### 3.1 Dynamic Config Schema Rendering

**Problem**: Schema endpoint exists but frontend doesn't use it.

**Implementation**:
1. Create `admin-ui/src/components/forms/schema_form.rs`
2. Fetch `/config/schema` on load
3. Render form fields based on `field_type`, `options`, `default`, `description`
4. Support: string, integer, boolean, array, enum

**Benefits**:
- Auto-generates forms for new config fields
- Ensures UI always matches backend schema

### 3.2 Config Validation API

**Problem**: No pre-save validation.

**Implementation**:
1. Add `POST /api/config/validate` endpoint
2. Accept config and return validation errors
3. Frontend shows inline validation errors before save

**Backend Handler** (new in `src/admin/handlers/config.rs`):
```rust
pub async fn validate_config(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<ValidateConfigRequest>,
) -> Result<Json<ValidationResult>, StatusCode>
```

### 3.3 Restart Required Indicator

**Problem**: Users unclear which changes need restart.

**Implementation**:
1. Add field metadata: `requires_restart: bool` to schema
2. On save, check if any changed fields require restart
3. Show prominent banner: "Changes require restart to take effect"
4. Add "Restart Workers" button

### 3.4 Config Diff View

**Problem**: Hard to see what changed.

**Implementation**:
1. Before save, capture current config
2. After edit, show diff view
3. Highlight: added (green), removed (red), changed (yellow)

---

## Phase 4: Advanced Features (Priority: LOW)

### 4.1 Config Profiles

**Features**:
- Save current config as named profile
- Load profile to restore settings
- Export/import profiles

**API**:
- `GET /api/config/profiles` - List profiles
- `POST /api/config/profiles` - Save profile
- `DELETE /api/config/profiles/{name}` - Delete profile

### 4.2 Config Version History

**Features**:
- Track config changes over time
- View historical config
- Rollback to previous version

**Implementation**:
- Store versions in persistence directory
- Limit to last N versions (configurable)

### 4.3 Import/Export Enhancement

**Current**: `/config/export` returns TOML (exists but not in UI)

**Enhancement**:
- Add Import/Export buttons to Settings page
- Support JSON and TOML formats
- Validate before import

---

## Phase 5: Architecture Maintainability (Priority: MEDIUM)

### 5.1 Type Synchronization

**Problem**: Frontend types may drift from backend config.

**Current Types Location**: `admin-ui/src/types/mod.rs`

**Solution**:
1. Generate TypeScript types from Rust structs (or vice versa)
2. Document type sync process
3. Add CI check for type compatibility

### 5.2 Component Library

Extract reusable form components:
- `admin-ui/src/components/forms/schema_field.rs` - Dynamic field from schema
- `admin-ui/src/components/forms/toggle_field.rs` - Toggle with label/help
- `admin-ui/src/components/forms/number_field.rs` - Number with unit suffix
- `admin-ui/src/components/forms/array_field.rs` - Editable list

### 5.3 Shared API Service Improvements

Add to `admin-ui/src/services/api.rs`:
- Request/response interceptors for auth
- Automatic token refresh
- Retry logic with exponential backoff

---

## Implementation Order

```
Phase 1 (Week 1):
├── 1.1 Fix Settings page load config
└── 1.2 Fix Settings page save config

Phase 2 (Week 1-2):
├── 2.1 Add TLS subsection to Settings
├── 2.2 Add Admin subsection to Settings  
├── 2.3 Add Security subsection to Settings
├── 2.4 Add Feeds page
└── 2.5 Add missing API endpoints

Phase 3 (Week 2-3):
├── 3.1 Dynamic schema rendering
├── 3.2 Config validation
├── 3.3 Restart indicator
└── 3.4 Config diff view

Phase 4 (Week 3-4):
├── 4.1 Config profiles
├── 4.2 Config history
└── 4.3 Import/export UI

Phase 5 (Ongoing):
├── 5.1 Type sync documentation
├── 5.2 Component library
└── 5.3 API service improvements
```

---

## Files to Create

| File | Purpose |
|------|---------|
| `admin-ui/src/pages/tls_settings.rs` | TLS configuration page |
| `admin-ui/src/pages/security_settings.rs` | Security settings page |
| `admin-ui/src/pages/feeds.rs` | IP/Rule feeds page |
| `admin-ui/src/components/forms/schema_form.rs` | Dynamic form from schema |
| `admin-ui/src/components/forms/toggle_field.rs` | Reusable toggle component |

---

## Files to Modify

| File | Changes |
|------|---------|
| `admin-ui/src/pages/settings.rs` | Load/save config, add sections |
| `admin-ui/src/pages/mod.rs` | Register new pages |
| `admin-ui/src/app.rs` | Add routes |
| `admin-ui/src/services/api.rs` | Add API methods |
| `admin-ui/src/types/mod.rs` | Add config types |
| `admin-ui/src/components/layout/sidebar.rs` | Add nav items |
| `src/admin/handlers/config.rs` | Add missing endpoints |

---

## API Endpoints to Add

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/config/tls` | GET/PUT | TLS configuration |
| `/config/security` | GET/PUT | Security settings |
| `/config/feeds` | GET/PUT | IP/Rule feeds |
| `/config/persistence` | GET/PUT | Persistence settings |
| `/config/validate` | POST | Validate config before save |

---

## Constraints

1. **Architecture**: Must maintain overseer/master/worker separation
2. **Admin Panel**: Runs in separate process, communicates via IPC
3. **Config Changes**: Some require worker restart (document which)
4. **Backward Compatibility**: Don't break existing API contracts
5. **Performance**: Minimize API calls, use caching where appropriate

---

## Testing Plan

1. **Manual Testing**:
   - Load each config page with default values
   - Modify and save each config section
   - Verify changes persist after restart
   - Test restart required indicator

2. **API Testing**:
   - Test each new endpoint with valid/invalid data
   - Verify auth requirements
   - Test config validation

3. **Integration Testing**:
   - Verify config changes apply to workers
   - Test IPC communication for config propagation
   - Verify overseer handles config reload

---

## Success Metrics

- [ ] All 34 config sections accessible via UI (currently 26% coverage)
- [ ] Settings page loads current config from API
- [ ] Settings page saves config to API
- [ ] Restart indicator shows when required
- [ ] Config validation prevents invalid saves
- [ ] All new pages functional with working save/load
- [ ] Use existing `/config/schema` endpoint for dynamic form generation

---

## Reference: Existing Working Implementation

The `admin-ui/src/pages/process_management.rs` (778 lines) serves as a reference implementation for:
- Loading config via `ApiService::get_overseer_config()`, `get_process_manager_config()`, `get_supervisor_config()`
- Saving config via `ApiService::update_overseer_config()`, etc.
- Form state management with `use_state`
- Saving with toast notifications
- Reset to defaults functionality

The schema endpoint `GET /api/config/schema` already exists in `src/admin/handlers/config.rs` (lines 70-948) and returns ~90 configuration field definitions.
