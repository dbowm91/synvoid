# Plan 32: Admin Panel Improvements

## Context

During a comprehensive review of the MaluWAF admin panel, the following issues were identified:

| Category | Issues | Priority |
|----------|--------|----------|
| **Critical Bugs** | 2 | TCP/UDP page mock data, Tier Keys modal disconnected |
| **Missing Admin APIs** | 5 | rule_feed, yara_feed, tarpit (dedicated), honeypot_port, |
| **Missing UI** | 3 | YARA management, Rule Feed config, Site search improvements |
| **Usability** | 2 | Settings page navigation, Sites search debounce |

This plan addresses all identified issues in priority order.

---

## Background: Admin Panel Architecture

### Frontend Structure (`admin-ui/`)

| File | Purpose | Lines |
|------|---------|-------|
| `src/pages/settings.rs` | Main settings page with 26 sections | 5,914 |
| `src/pages/tier_keys.rs` | Tier key management (broken modal) | 263 |
| `src/pages/tcp_udp.rs` | TCP/UDP listeners (mock data) | 133 |
| `src/pages/sites.rs` | Sites listing with search | ~700 |
| `src/services/api.rs` | Frontend API client | ~900 |
| `src/components/layout/sidebar.rs` | Navigation sidebar with collapsible sections | ~400 |

### Backend Structure (`src/admin/`)

| File | Purpose |
|------|---------|
| `handlers/config.rs` | Config API handlers (GET/PUT for all config sections) |
| `handlers/tcp_udp.rs` | TCP/UDP listener handlers (partial implementation) |
| `handlers/yara_rules.rs` | YARA rules management (10 endpoints) |
| `handlers/honeypot.rs` | Honeypot runtime control |
| `handlers/rule_feed.rs` | Rule feed status/control |
| `mod.rs` | Router setup, 100+ endpoints |

### Configuration Structure (`src/config/`)

| Config | Location | Admin API |
|--------|----------|-----------|
| `RuleFeedConfig` | `protection.rs:285-326` | Status only, no config |
| `YaraRuleFeedConfig` | `protection.rs:331-385` | No dedicated endpoint |
| `TarpitDefaults` | `network.rs:253-300` | Via /config/main only |
| `HoneypotPortConfig` | `honeypot_port.rs` | No dedicated endpoint |

---

## Phase 1: Critical Bug Fixes

### Phase 1A: Remove TCP/UDP Listeners Page (CRITICAL)

#### Problem

The TCP/UDP Listeners page (`admin-ui/src/pages/tcp_udp.rs`) displays **hardcoded mock data** with no real backend implementation:

- All listener rows are static examples (ports 25, 587, 3306, 5432)
- "Add Listener" button has no `onclick` handler
- No API calls to fetch actual TCP/UDP listeners
- Backend `list_protocols()` returns only HTTP variants, not SMTP/MySQL/PostgreSQL

#### Investigation Findings

**Backend exists but is incomplete:**
- `TcpListenerPool` in `src/tcp/listener.rs` (827 lines) - generic TCP proxy infrastructure
- `UdpListenerPool` in `src/udp/listener.rs` (671 lines) - DNS and tunnel protocols
- Admin handlers in `src/admin/handlers/tcp_udp.rs` write to `site_config.tcp.ports`
- **BUT** `TcpListenerPool::add_listener()` is **never called** with site configurations

**Architecture mismatch:**
- MaluWAF is fundamentally an HTTP WAF, not a general TCP/UDP proxy
- The page conflates global TCP/UDP **defaults** (Settings) with per-site **listeners** (doesn't exist)
- No legitimate use case based on current site configs (TCP disabled everywhere)

#### Decision

**Remove the page entirely.** The feature is not applicable to MaluWAF's architecture.

#### Step 1A.1: Remove Route from App Router

**File**: `admin-ui/src/app.rs`

**Current** (lines 9, 35, 118):
```rust
use yew::prelude::*;
mod pages {
    // ...
    TcpUdp,
}

#[function_component(App)]
pub fn app() -> Html {
    // ...
    Route::TcpUdp => html! { <TcpUdp /> },
}
```

**Change**: Remove `TcpUdp` from imports, route matching, and module.

#### Step 1A.2: Remove from Sidebar

**File**: `admin-ui/src/components/layout/sidebar.rs`

**Current** (line 55):
```rust
<NavItem to={Route::TcpUdp} icon="network" label="TCP/UDP" />
```

**Change**: Remove this NavItem line.

#### Step 1A.3: Remove Module Declaration

**File**: `admin-ui/src/pages/mod.rs`

**Current** (lines 17, 40):
```rust
mod tcp_udp;
pub use tcp_udp::TcpUdp;
```

**Change**: Remove both lines.

#### Step 1A.4: Delete the Page File

**File**: `admin-ui/src/pages/tcp_udp.rs`

**Action**: Delete this file entirely.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 1A.1 Remove route | 5 min | Low |
| 1A.2 Remove sidebar | 2 min | Low |
| 1A.3 Remove module | 2 min | Low |
| 1A.4 Delete file | 1 min | Low |
| **Total** | **10 min** | **Trivial** |

#### Files to Modify

| File | Changes |
|------|---------|
| `admin-ui/src/app.rs` | Remove TcpUdp import and route |
| `admin-ui/src/components/layout/sidebar.rs` | Remove NavItem |
| `admin-ui/src/pages/mod.rs` | Remove module declaration |
| `admin-ui/src/pages/tcp_udp.rs` | **DELETE** |

---

### Phase 1B: Fix Tier Keys "Issue New Key" Modal (CRITICAL)

#### Problem

The "Issue New Key" modal in `admin-ui/src/pages/tier_keys.rs` has **disconnected form inputs**:

- org_id input has no `oninput` handler
- tier select has no `onchange` handler
- "Issue Key" button has no `onclick` handler
- Backend `POST /tier-keys/issue` **does not exist**

#### Investigation Findings

**Frontend state missing** (lines 25-30):
```rust
pub struct TierKeys {
    tier_keys: Vec<TierKeyInfo>,
    loading: bool,
    error: Option<String>,
    show_issue_modal: bool,
    // MISSING: issue_org_id: String,
    // MISSING: issue_tier: u32,
}
```

**Msg::IssueKey handler** (lines 91-98) correctly expects `(String, u32)` but is never called with actual values.

**Backend endpoint missing:**
- `MeshTransport::issue_tier_key()` exists in `src/mesh/proxy.rs:361-378`
- But no admin handler exposes it
- Routes for `/tier-keys/issue`, `/tier-keys/revoke`, `/tier-keys/unbind` do not exist

#### Step 1B.1: Add Form State Fields

**File**: `admin-ui/src/pages/tier_keys.rs`

**Add to TierKeys struct** (after line 29):
```rust
issue_org_id: String,
issue_tier: u32,
```

**Initialize in `create()`**:
```rust
Self {
    // ... existing fields ...
    issue_org_id: String::new(),
    issue_tier: 1,
}
```

#### Step 1B.2: Add Update Message Variants

**File**: `admin-ui/src/pages/tier_keys.rs`

**Current** (line 32-40):
```rust
pub enum Msg {
    LoadTierKeys,
    TierKeysLoaded(Vec<TierKeyInfo>),
    LoadError(String),
    ToggleIssueModal,
    IssueKey(String, u32),
    RevokeKey(String, String),
    UnbindKey(String, String),
}
```

**Change**:
```rust
pub enum Msg {
    LoadTierKeys,
    TierKeysLoaded(Vec<TierKeyInfo>),
    LoadError(String),
    ToggleIssueModal,
    UpdateIssueOrgId(String),
    UpdateIssueTier(u32),
    IssueKey(String, u32),
    RevokeKey(String, String),
    UnbindKey(String, String),
}
```

#### Step 1B.3: Wire org_id Input with oninput

**File**: `admin-ui/src/pages/tier_keys.rs`

**Current** (lines 135-139):
```rust
<input
    type="text"
    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg"
    placeholder="org_xxx"
/>
```

**Change**:
```rust
<input
    type="text"
    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg"
    placeholder="org_xxx"
    value={self.issue_org_id.clone()}
    oninput={ctx.link().callback(|e: InputEvent| {
        Msg::UpdateIssueOrgId(e.target().unwrap().value())
    })}
/>
```

#### Step 1B.4: Wire tier Select with onchange

**File**: `admin-ui/src/pages/tier_keys.rs`

**Current** (lines 143-147):
```rust
<select class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg">
    <option value="1">{ "Tier 1 - Basic" }</option>
    <option value="2">{ "Tier 2 - Standard" }</option>
    <option value="3">{ "Tier 3 - Premium" }</option>
</select>
```

**Change**:
```rust
<select
    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg"
    value={self.issue_tier.to_string()}
    onchange={ctx.link().callback(|e: Event| {
        let value = e.target().unwrap().value();
        Msg::UpdateIssueTier(value.parse().unwrap_or(1))
    })}
>
    <option value="1">{ "Tier 1 - Basic" }</option>
    <option value="2">{ "Tier 2 - Standard" }</option>
    <option value="3">{ "Tier 3 - Premium" }</option>
</select>
```

#### Step 1B.5: Wire "Issue Key" Button

**File**: `admin-ui/src/pages/tier_keys.rs`

**Current** (lines 153-155):
```rust
<button class="px-4 py-2 bg-accent text-white rounded-lg">
    { "Issue Key" }
</button>
```

**Change**:
```rust
<button
    onclick={{
        let link = ctx.link().clone();
        let org_id = self.issue_org_id.clone();
        let tier = self.issue_tier;
        move |_| {
            link.send_message(Msg::IssueKey(org_id.clone(), tier));
        }
    }}
    class="px-4 py-2 bg-accent text-white rounded-lg"
>
    { "Issue Key" }
</button>
```

#### Step 1B.6: Add Update Handlers in update()

**File**: `admin-ui/src/pages/tier_keys.rs`

**Add to match block**:
```rust
Msg::UpdateIssueOrgId(org_id) => {
    self.issue_org_id = org_id;
    true
}
Msg::UpdateIssueTier(tier) => {
    self.issue_tier = tier;
    true
}
```

#### Step 1B.7: Create Backend Handler

**File**: `src/admin/handlers/tier_keys.rs` (NEW)

**Note**: The frontend expects these endpoints:
- `GET /tier-keys` - returns list of tier keys
- `POST /tier-keys/issue` - issues new key
- `POST /tier-keys/revoke` - revokes a key
- `POST /tier-keys/unbind` - unbinds a key

The `revoke_tier_key` and `unbind_tier_key` methods are on `OrganizationManager`, not `MeshTransport` directly. The handler must access `mesh_transport.org_manager` for these operations.

```rust
use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueTierKeyRequest {
    pub org_id: String,
    pub tier: u32,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeUnbindRequest {
    pub org_id: String,
    pub key_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TierKeyInfo {
    pub key_id: String,
    pub tier: u32,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issued_by: String,
    pub bound_to: Option<String>,
    pub is_unspent: bool,
    pub revoked: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TierKeyListResponse {
    pub tier_keys: Vec<TierKeyInfo>,
    pub total: usize,
    pub unspent_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TierKeyResponse {
    pub success: bool,
    pub key_id: Option<String>,
    pub message: String,
}

// GET /tier-keys - List all tier keys
#[utoipa::path(
    get,
    path = "/api/tier-keys",
    responses(
        (status = 200, description = "List tier keys", body = TierKeyListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "tier-keys"
)]
pub async fn list_tier_keys(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TierKeyListResponse>, StatusCode> {
    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        let mgr = mesh_transport.org_manager.read().await;
        let tier_keys: Vec<TierKeyInfo> = mgr.list_tier_keys()
            .into_iter()
            .map(|tk| TierKeyInfo {
                key_id: tk.key_id,
                tier: tk.tier,
                valid_from: tk.valid_from,
                valid_until: tk.valid_until,
                issued_by: tk.issued_by,
                bound_to: tk.bound_to,
                is_unspent: tk.is_unspent,
                revoked: tk.revoked,
            })
            .collect();

        let total = tier_keys.len();
        let unspent_count = tier_keys.iter().filter(|tk| tk.is_unspent && !tk.revoked).count();

        Ok(Json(TierKeyListResponse {
            tier_keys,
            total,
            unspent_count,
        }))
    } else {
        Ok(Json(TierKeyListResponse {
            tier_keys: vec![],
            total: 0,
            unspent_count: 0,
        }))
    }
}

// POST /tier-keys/issue - Issue new tier key
#[utoipa::path(
    post,
    path = "/api/tier-keys/issue",
    request_body = IssueTierKeyRequest,
    responses(
        (status = 200, description = "Tier key issued", body = TierKeyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid request"),
    ),
    tag = "tier-keys"
)]
pub async fn issue_tier_key(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<IssueTierKeyRequest>,
) -> Result<Json<TierKeyResponse>, StatusCode> {
    if req.org_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        let now = crate::utils::current_timestamp();
        let valid_until = now.saturating_add(365 * 24 * 60 * 60);

        // Generate a random 32-byte key
        let key = (0..32).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        match mesh_transport.issue_tier_key(&req.org_id, req.tier, key, now, valid_until).await {
            Some(key) => Ok(Json(TierKeyResponse {
                success: true,
                key_id: Some(key.key_id),
                message: format!("Tier key issued for org {} at tier {}", req.org_id, req.tier),
            })),
            None => Ok(Json(TierKeyResponse {
                success: false,
                key_id: None,
                message: format!("Failed to issue tier key - organization {} may not exist", req.org_id),
            })),
        }
    } else {
        Ok(Json(TierKeyResponse {
            success: false,
            key_id: None,
            message: "Mesh transport not available".to_string(),
        }))
    }
}

// POST /tier-keys/revoke - Revoke a tier key
#[utoipa::path(
    post,
    path = "/api/tier-keys/revoke",
    request_body = RevokeUnbindRequest,
    responses(
        (status = 200, description = "Tier key revoked", body = TierKeyResponse),
    ),
    tag = "tier-keys"
)]
pub async fn revoke_tier_key(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<RevokeUnbindRequest>,
) -> Result<Json<TierKeyResponse>, StatusCode> {
    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        let mut mgr = mesh_transport.org_manager.write().await;
        match mgr.revoke_tier_key(&req.org_id, &req.key_id) {
            true => Ok(Json(TierKeyResponse {
                success: true,
                key_id: Some(req.key_id),
                message: "Tier key revoked".to_string(),
            })),
            false => Ok(Json(TierKeyResponse {
                success: false,
                key_id: None,
                message: "Failed to revoke tier key".to_string(),
            })),
        }
    } else {
        Ok(Json(TierKeyResponse {
            success: false,
            key_id: None,
            message: "Mesh transport not available".to_string(),
        }))
    }
}

// POST /tier-keys/unbind - Unbind a tier key
#[utoipa::path(
    post,
    path = "/api/tier-keys/unbind",
    request_body = RevokeUnbindRequest,
    responses(
        (status = 200, description = "Tier key unbound", body = TierKeyResponse),
    ),
    tag = "tier-keys"
)]
pub async fn unbind_tier_key(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<RevokeUnbindRequest>,
) -> Result<Json<TierKeyResponse>, StatusCode> {
    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        let mut mgr = mesh_transport.org_manager.write().await;
        match mgr.unbind_tier_key(&req.org_id, &req.key_id) {
            true => Ok(Json(TierKeyResponse {
                success: true,
                key_id: Some(req.key_id),
                message: "Tier key unbound".to_string(),
            })),
            false => Ok(Json(TierKeyResponse {
                success: false,
                key_id: None,
                message: "Failed to unbind tier key".to_string(),
            })),
        }
    } else {
        Ok(Json(TierKeyResponse {
            success: false,
            key_id: None,
            message: "Mesh transport not available".to_string(),
        }))
    }
}
```

**Note on OrganizationManager**: The `OrganizationManager` struct (`src/mesh/organization.rs`) must have `list_tier_keys()` method added if it doesn't exist. Check line ~920 for existing tier key methods.

#### Step 1B.8: Register Backend Routes

**File**: `src/admin/mod.rs`

**Add module declaration** (around line 148):
```rust
pub mod tier_keys;
```

**Add routes** in `build_router_from_state()`:
```rust
.route("/tier-keys", get(handlers::tier_keys::list_tier_keys))
.route("/tier-keys/issue", post(handlers::tier_keys::issue_tier_key))
.route("/tier-keys/revoke", post(handlers::tier_keys::revoke_tier_key))
.route("/tier-keys/unbind", post(handlers::tier_keys::unbind_tier_key))
```

#### Step 1B.9: Add list_tier_keys to OrganizationManager

**File**: `src/mesh/organization.rs`

**Check if `list_tier_keys()` exists** (around line 920). If not, add:

```rust
pub fn list_tier_keys(&self) -> Vec<TierKey> {
    let mut keys = Vec::new();
    for org in self.organizations.values() {
        for key in org.tier_keys.values() {
            keys.push(key.clone());
        }
    }
    keys
}
```

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 1B.1-1B.6 Frontend state/wiring | 30 min | Low |
| 1B.7 Backend handler (4 endpoints) | 60 min | Medium |
| 1B.8 Route registration | 10 min | Low |
| 1B.9 Add list_tier_keys method | 15 min | Low |
| **Total** | **~2 hours** | **Medium** |

#### Files to Modify

| File | Changes |
|------|---------|
| `admin-ui/src/pages/tier_keys.rs` | Add state, wire inputs, add handlers |
| `src/admin/handlers/tier_keys.rs` | **NEW** - 4 endpoint handlers |
| `src/admin/mod.rs` | Add module, register routes |
| `src/mesh/organization.rs` | Add `list_tier_keys()` method if missing |

---

## Phase 2: Missing Admin API Endpoints

### Phase 2A: Add Rule Feed Configuration API (HIGH)

#### Problem

`RuleFeedConfig` in `src/config/protection.rs:285-326` has status/control endpoints but no configuration management endpoint.

#### Investigation Findings

**Existing handlers** (`src/admin/handlers/rule_feed.rs`):
- `GET /api/rules/status` - Status only
- `POST /api/rules/check` - Manual trigger
- `POST /api/rules/apply` - Apply pending
- `POST /api/rules/discard` - Discard pending

**Config fields** (`RuleFeedConfig`):
```rust
pub struct RuleFeedConfig {
    pub enabled: bool,
    pub url: String,
    pub update_interval_hours: u32,
    pub auto_apply: bool,
    pub allow_downgrade: bool,
    pub public_key: Option<String>,
}
```

**Pattern to follow**: `IpFeedsConfig` at `src/admin/handlers/config.rs:1415-1457`

#### Step 2A.1: Add RuleFeedConfig Response Type

**File**: `src/admin/handlers/config.rs` (add near other config response types)

```rust
#[derive(Debug, Serialize)]
pub struct RuleFeedConfigResponse {
    pub config: crate::config::RuleFeedConfig,
}
```

#### Step 2A.2: Add GET Handler

**File**: `src/admin/handlers/config.rs`

```rust
#[utoipa::path(
    get,
    path = "/api/config/rule-feed",
    responses(
        (status = 200, description = "Rule feed configuration", body = RuleFeedConfigResponse),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "config"
)]
pub async fn get_rule_feed_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<RuleFeedConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(RuleFeedConfigResponse {
        config: config.main.rule_feed.clone(),
    }))
}
```

#### Step 2A.3: Add PUT Handler

**File**: `src/admin/handlers/config.rs`

```rust
#[derive(Debug, Deserialize)]
pub struct UpdateRuleFeedConfigRequest {
    pub config: crate::config::RuleFeedConfig,
}

#[utoipa::path(
    put,
    path = "/api/config/rule-feed",
    request_body = UpdateRuleFeedConfigRequest,
    responses(
        (status = 200, description = "Rule feed config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
    ),
    tag = "config"
)]
pub async fn update_rule_feed_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateRuleFeedConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.rule_feed = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Rule feed config updated")))
}
```

#### Step 2A.4: Register Routes

**File**: `src/admin/mod.rs`

Add to `build_router_from_state()`:
```rust
.route("/api/config/rule-feed", get(handlers::config::get_rule_feed_config))
.route("/api/config/rule-feed", put(handlers::config::update_rule_feed_config))
```

#### Step 2A.5: Add Frontend API Methods

**File**: `admin-ui/src/services/api.rs`

```rust
pub async fn get_rule_feed_config(&self) -> Result<serde_json::Value, String> {
    self.get("/config/rule-feed").await
}

pub async fn update_rule_feed_config(&self, config: &serde_json::Value) -> Result<serde_json::Value, String> {
    self.put("/config/rule-feed", config).await
}
```

#### Step 2A.6: Add Settings UI Section

**File**: `admin-ui/src/pages/settings.rs`

Add "rule_feed" to search index, sidebar buttons, and create `RuleFeedSection` component following the `IpFeedsSection` pattern.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 2A.1-2A.3 Backend handlers | 30 min | Low |
| 2A.4 Route registration | 10 min | Low |
| 2A.5 Frontend API | 15 min | Low |
| 2A.6 Frontend UI | 45 min | Medium |
| **Total** | **~2 hours** | **Medium** |

---

### Phase 2B: Fix Tarpit Hardcoded Values (HIGH)

#### Problem

`generate_tarpit_response()` in `src/waf/mod.rs:1405-1416` uses **hardcoded values** instead of config:
```rust
let max_depth = 10;      // HARDCODED
let links_per_page = 50; // HARDCODED
```

#### Investigation Findings

**Config exists but unused:**
- `TarpitDefaults` in `src/config/network.rs:253-300`
- `SiteTarpitConfig` in `src/config/site/defensive.rs:33-44`
- `TarpitManager` in `src/tarpit/mod.rs`

**Frontend already works:**
- `TarpitSection` in settings uses `/api/config/main`
- But no dedicated `/api/config/tarpit` endpoint

#### Step 2B.1: Store TarpitDefaults in WafCore

**File**: `src/waf/mod.rs`

**Add to WafCore struct** (around line 164-189):
```rust
pub tarpit_config: crate::config::network::TarpitDefaults,
```

**Initialize in `WafCore::new()`**:
```rust
tarpit_config: config.main.tarpit.clone(),
```

#### Step 2B.2: Use Config in generate_tarpit_response()

**File**: `src/waf/mod.rs`

**Current** (lines 1405-1408):
```rust
let mut rng = rand::rng();
let max_depth = 10;
let links_per_page = 50;
```

**Change**:
```rust
let mut rng = rand::rng();
let max_depth = self.tarpit_config.max_depth;
let links_per_page = self.tarpit_config.links_per_page;
```

#### Step 2B.3: Add Dedicated Config Endpoint

**File**: `src/admin/handlers/config.rs`

Add `get_tarpit_config` and `update_tarpit_config` handlers following the pattern from Phase 2A.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 2B.1 Store config in WafCore | 15 min | Low |
| 2B.2 Use config values | 5 min | Trivial |
| 2B.3 Add API endpoint | 30 min | Low |
| **Total** | **~50 min** | **Low** |

---

### Phase 2C: Add Honeypot Port Configuration API (MEDIUM)

#### Problem

`HoneypotPortConfig` in `src/config/honeypot_port.rs` has no dedicated admin API endpoint.

#### Investigation Findings

**Config structure** (`src/config/honeypot_port.rs`):
```rust
pub struct HoneypotPortConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub site_scope: String,
}
```

**Runtime integration** (`src/worker/unified_server.rs:457-505`):
- `HoneypotPortConfig` → `PortHoneypotConfig` transformation at startup
- `PortHoneypotRunner` spawns async task

**Frontend**:
- `/honeypot` page exists with enable/disable controls
- No config management UI

#### Step 2C.1: Add Backend Handlers

**File**: `src/admin/handlers/honeypot.rs` (extend existing)

Add `get_honeypot_port_config` and `update_honeypot_port_config` handlers.

#### Step 2C.2: Register Routes

**File**: `src/admin/mod.rs`

Add routes for `/api/config/honeypot-port`.

#### Step 2C.3: Add Frontend API and UI

**File**: `admin-ui/src/services/api.rs` and `admin-ui/src/pages/honeypot.rs`

Add config view/edit capabilities.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 2C.1 Backend handlers | 30 min | Medium |
| 2C.2 Route registration | 10 min | Low |
| 2C.3 Frontend | 45 min | Medium |
| **Total** | **~1.5 hours** | **Medium** |

**Note**: Dynamic reconfiguration is complex since `PortHoneypotRunner` spawns once at startup. Config updates may require restart indicator.

---

### Phase 2D: Add YARA Feed Status Endpoints (MEDIUM)

#### Problem

`YaraRuleFeedConfig` has minimal exposure. `GET /api/yara/status` returns `has_feed_manager: bool` but no feed-specific info.

#### Investigation Findings

**Feed-specific endpoints needed:**
- `GET /api/yara/feed/status` - Full feed state
- `GET /api/yara/feed/history` - Version history
- `POST /api/yara/feed/check` - Manual check
- `POST /api/yara/feed/apply` - Apply pending
- `POST /api/yara/feed/discard` - Discard pending
- `POST /api/yara/feed/rollback` - Rollback
- `GET/PUT /api/yara/feed/config` - Feed configuration

**Manager access** via `YaraRulesManager::get_feed_manager()` (line 1061).

#### Step 2D.1: Add Feed Manager Getter Methods

**File**: `src/mesh/yara_rules.rs`

Add methods to expose feed state:
```rust
pub fn get_feed_status(&self) -> YaraFeedStatus { ... }
pub fn get_feed_history(&self) -> Vec<FeedHistoryEntry> { ... }
```

#### Step 2D.2: Add Backend Handlers

**File**: `src/admin/handlers/yara_rules.rs`

Add 7 new endpoints for feed management.

#### Step 2D.3: Register Routes

**File**: `src/admin/mod.rs`

Add routes for `/api/yara/feed/*`.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 2D.1 Feed manager methods | 30 min | Medium |
| 2D.2 Backend handlers | 45 min | Medium |
| 2D.3 Route registration | 15 min | Low |
| **Total** | **~2 hours** | **Medium** |

---

## Phase 3: Missing UI / Usability Improvements

### Phase 3A: Settings Page Categorization (MEDIUM)

#### Problem

Settings page has 26 sections in a flat sidebar with no categorization.

#### Current Structure

All 26 sections in a flat vertical list:
```
server, http, logging, metrics, ratelimits, bandwidth, bot, tarpit,
ip_feeds, security, tls, acme, http3, tunnel, plugins, upload,
mime_types, tcp_udp_defaults, fallback, upgrade, theme, yara,
serverless, process, defaults, dns
```

#### Recommended Categories

| Category | Sections |
|---------|----------|
| **Network** | server, http, tunnel, tcp_udp_defaults, dns |
| **TLS & Certificates** | tls, acme, http3 |
| **Protection** | security, bot, tarpit, ip_feeds |
| **Rate & Bandwidth** | ratelimits, bandwidth |
| **Content** | upload, mime_types, fallback |
| **Extensibility** | plugins, serverless, yara |
| **Observability** | logging, metrics |
| **System** | upgrade, process, defaults, theme |

#### Pattern to Follow

`NavSection` in `admin-ui/src/components/layout/sidebar.rs` already has collapsible headers:

```rust
<NavSection title="Overview">
    <NavItem to={Route::Dashboard} ... />
</NavSection>
```

#### Step 3A.1: Create CategorySection Component

**File**: `admin-ui/src/components/settings/category_section.rs` (NEW)

Create a collapsible category wrapper similar to `NavSection`.

#### Step 3A.2: Restructure SectionButton Layout

**File**: `admin-ui/src/pages/settings.rs`

Group existing `SectionButton` components under `CategorySection` wrappers. No changes to individual section components needed.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 3A.1 Create CategorySection | 30 min | Medium |
| 3A.2 Restructure settings | 1 hour | Medium |
| **Total** | **~1.5 hours** | **Medium** |

---

### Phase 3B: YARA Rules Management UI (HIGH)

#### Problem

YARA has extensive backend API (10 endpoints) but frontend only shows status. 9 endpoints have no frontend integration.

#### Investigation Findings

**Backend completeness** (`src/admin/handlers/yara_rules.rs`):
- Full submission workflow (submit, approve, reject, delete)
- Broadcast and sync operations
- 10 endpoints total

**Frontend integration**:
- Only `get_yara_status()` is called
- `get_yara_submissions()` exists in `api.rs` but is **never called**

#### Priority Features

**Priority 1 - Global Node Operations:**
1. Submissions list with approve/reject buttons
2. View submission details with rules preview
3. Broadcast approved rules to mesh

**Priority 2 - Edge Node Operations:**
4. Submit Rules form (upload or paste)
5. Sync button to request from global

#### Step 3B.1: Add Missing API Methods

**File**: `admin-ui/src/services/api.rs`

```rust
pub async fn get_yara_submissions(&self) -> Result<serde_json::Value, String>
pub async fn get_yara_submission(&self, id: &str) -> Result<serde_json::Value, String>
pub async fn approve_yara_submission(&self, id: &str) -> Result<serde_json::Value, String>
pub async fn reject_yara_submission(&self, id: &str, notes: &str) -> Result<serde_json::Value, String>
pub async fn submit_yara_rules(&self, rules: &str, desc: &str) -> Result<serde_json::Value, String>
pub async fn broadcast_yara_rules(&self) -> Result<serde_json::Value, String>
pub async fn sync_yara_from_global(&self) -> Result<serde_json::Value, String>
```

#### Step 3B.2: Create YaraManagement Component

**File**: `admin-ui/src/pages/yara_management.rs` (NEW)

Create a comprehensive YARA management UI with:
- Status overview card
- Submissions table with actions
- Submit new rules form
- Version history

#### Step 3B.3: Add Route

**File**: `admin-ui/src/app.rs`

Add route for `/yara-management`.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 3B.1 API methods | 30 min | Low |
| 3B.2 Management UI | 6-8 hours | High |
| 3B.3 Route | 5 min | Trivial |
| **Total** | **~7-9 hours** | **High** |

---

### Phase 3C: Sites Page Search Debounce (LOW)

#### Problem

Sites page search filters on every keystroke with no debouncing.

#### Investigation Findings

**Current implementation** (`admin-ui/src/pages/sites.rs:66-80`):
```rust
let filtered: Vec<&SiteInfo> = sites
    .iter()
    .filter(|site| {
        // ... searches on every render
    })
    .collect();
```

**Pattern to follow**: Request logs page has debounce implementation.

#### Step 3C.1: Add Debounce Timer

**File**: `admin-ui/src/pages/sites.rs`

Add a debounce mechanism to delay filtering until user stops typing.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 3C.1 Add debounce | 30 min | Low |
| **Total** | **30 min** | **Low** |

---

## Phase 4: Backend Pagination for Sites (Optional)

### Phase 4A: Add Pagination to Sites API

#### Problem

Sites API returns all sites at once with no pagination.

#### Step 4A.1: Modify Backend Handler

**File**: `src/admin/handlers/sites.rs`

Accept `limit` and `offset` query parameters:
```rust
#[derive(Debug, Deserialize)]
pub struct ListSitesQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub search: Option<String>,
}
```

#### Step 4A.2: Update Response Format

**File**: `src/admin/handlers/sites.rs`

Return metadata:
```rust
pub struct SiteListResponse {
    pub sites: Vec<SiteInfo>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}
```

#### Step 4A.3: Update Frontend

**File**: `admin-ui/src/pages/sites.rs`

Add pagination controls and update API service.

#### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 4A.1 Backend pagination | 45 min | Medium |
| 4A.2 Response format | 15 min | Low |
| 4A.3 Frontend pagination | 1 hour | Medium |
| **Total** | **~2 hours** | **Medium** |

---

## Implementation Order

| Phase | Item | Priority | Effort | Reason |
|-------|------|----------|--------|--------|
| **1A** | Remove TCP/UDP page | **CRITICAL** | 10 min | Broken feature |
| **1B** | Fix Tier Keys modal + backend | **CRITICAL** | 2 hours | Broken feature |
| **2A** | Add rule_feed config API | HIGH | 2 hours | Missing functionality |
| **2B** | Fix tarpit hardcoded values | HIGH | 50 min | Bug fix |
| **2C** | Add honeypot_port config API | MEDIUM | 1.5 hours | Missing functionality |
| **2D** | Add yara_feed status endpoints | MEDIUM | 2 hours | Missing functionality |
| **3A** | Settings page categorization | MEDIUM | 1.5 hours | Usability |
| **3B** | YARA management UI | HIGH | 7-9 hours | Major missing feature |
| **3C** | Sites search debounce | LOW | 30 min | Usability |
| **4A** | Sites pagination | OPTIONAL | 2 hours | Performance at scale |

**Total estimated effort: ~19-21 hours**

---

## File Change Summary

### Phase 1 (Critical)

| File | Action | Phase |
|------|--------|-------|
| `admin-ui/src/app.rs` | Remove TcpUdp | 1A |
| `admin-ui/src/components/layout/sidebar.rs` | Remove NavItem | 1A |
| `admin-ui/src/pages/mod.rs` | Remove module | 1A |
| `admin-ui/src/pages/tcp_udp.rs` | **DELETE** | 1A |
| `admin-ui/src/pages/tier_keys.rs` | Fix form wiring | 1B |
| `src/admin/handlers/tier_keys.rs` | **NEW** | 1B |
| `src/admin/mod.rs` | Add tier_keys routes | 1B |
| `src/mesh/organization.rs` | Add `list_tier_keys()` method | 1B |

### Phase 2 (Missing APIs)

| File | Action | Phase |
|------|--------|-------|
| `src/admin/handlers/config.rs` | Add rule_feed handlers | 2A |
| `src/admin/handlers/config.rs` | Add tarpit handlers | 2B |
| `src/admin/handlers/honeypot.rs` | Add honeypot_port handlers | 2C |
| `src/admin/handlers/yara_rules.rs` | Add feed status handlers | 2D |
| `src/mesh/yara_rules.rs` | Add feed getter methods | 2D |
| `src/waf/mod.rs` | Use tarpit config | 2B |
| `admin-ui/src/services/api.rs` | Add API methods | 2A, 2C |
| `admin-ui/src/pages/settings.rs` | Add RuleFeedSection | 2A |

### Phase 3 (UI)

| File | Action | Phase |
|------|--------|-------|
| `admin-ui/src/components/settings/category_section.rs` | **NEW** | 3A |
| `admin-ui/src/pages/settings.rs` | Restructure | 3A |
| `admin-ui/src/pages/yara_management.rs` | **NEW** | 3B |
| `admin-ui/src/app.rs` | Add yara-management route | 3B |
| `admin-ui/src/pages/sites.rs` | Add debounce | 3C |

### Phase 4 (Optional)

| File | Action | Phase |
|------|--------|-------|
| `src/admin/handlers/sites.rs` | Add pagination | 4A |
| `admin-ui/src/pages/sites.rs` | Add pagination UI | 4A |

---

## Testing Strategy

### Phase 1 Verification

```bash
# 1A - TCP/UDP removal
cargo check
# Should compile without tcp_udp references

# 1B - Tier Keys modal
# Start admin UI
# Navigate to /tier-keys
# Click "Issue New Key"
# Fill form and submit
# Should call POST /api/tier-keys/issue
```

### Phase 2 Verification

```bash
# Rule Feed API
curl http://localhost:8081/api/config/rule-feed -H "Authorization: Bearer $TOKEN"
# Should return RuleFeedConfig JSON

curl -X PUT http://localhost:8081/api/config/rule-feed \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"config": {"enabled": true, "url": "https://example.com/rules"}}'
# Should update config

# Tarpit
# Make a request that triggers tarpit
# Verify response uses configured max_depth and links_per_page
```

### Phase 3 Verification

```bash
# Settings categorization
# Navigate to Settings
# Should see collapsible category headers
# Clicking category should expand/collapse sections

# YARA Management
# Navigate to /yara-management
# Should see submissions list
# Should be able to approve/reject/submit rules
```

---

## Rollback Plan

| Phase | Revert Action |
|-------|---------------|
| 1A | Restore tcp_udp.rs file, re-add imports/routes |
| 1B | Revert tier_keys.rs changes, remove handler file |
| 2A | Remove rule_feed handlers from config.rs |
| 2B | Revert WafCore changes, use hardcoded values again |
| 2C | Remove honeypot_port handlers |
| 2D | Remove feed handlers, revert yara_rules.rs |
| 3A | Remove CategorySection, flatten settings |
| 3B | Delete yara_management.rs, revert api.rs |
| 3C | Remove debounce logic |
| 4A | Remove pagination from sites handler |

---

## Related Work

### Dependencies

| Crate | Phase | Purpose |
|-------|-------|---------|
| None required | All | Uses existing dependencies |

### Existing Patterns

| Pattern | Location | Used By |
|---------|----------|---------|
| Config handlers | `handlers/config.rs` | Phases 2A, 2B |
| NavSection | `sidebar.rs` | Phase 3A |
| Form state | `tier_keys.rs` fix | Phase 1B |
| API methods | `api.rs` | Phases 2A, 3B |

---

## Open Questions

1. **TCP/UDP Page**: Confirm removal is acceptable. If the feature is needed in future, it requires significant architectural work.

2. **Tarpit Site-Level**: Should `generate_tarpit_response()` use site-level `SiteTarpitConfig` when available, or only global `TarpitDefaults`?

3. **Honeypot Port Restart**: Config updates may require worker restart. Should we add a `requires_restart` indicator to the response?

4. **YARA Feed Config**: The feed runs autonomously in background. Should config changes take effect immediately or require restart?

5. **Sites Pagination**: Is pagination needed now, or is the current "return all" approach sufficient for expected site counts (<100)?

---

## Security Considerations

### What This Plan Does NOT Change

1. **Admin authentication** - All admin API endpoints still require bearer token
2. **Admin bind address** - Still defaults to `127.0.0.1` (localhost only)
3. **Public exposure** - No admin endpoints become publicly accessible

### What This Plan Improves

1. **Broken features** - Tier Keys and TCP/UDP page become functional or removed
2. **Configuration visibility** - More config options accessible via API
3. **Consistency** - All config sections have dedicated endpoints
4. **Usability** - Better organized settings, working search, YARA management

### Security Reminder

MaluWAF is designed to be the **reverse proxy**, not something to be reverse-proxied. All admin panel improvements maintain the security-first design:
- Admin endpoints bound to localhost
- Bearer token authentication required
- No public exposure by default
