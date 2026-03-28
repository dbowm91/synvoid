# Admin Panel Completion Plan — plan_ui5

## Context

The MaluWAF admin panel (Yew/WASM frontend + Axum backend) has 14 pages and 87
config schema fields, but the Settings page uses hardcoded placeholder values
instead of loading/saving via the API. Several backend API endpoints have no
corresponding UI, and entire config domains (TLS, honeypot, blocked paths,
challenges, IP feeds, log exporters) have no admin access at all.

Known issues discovered during review:
- Settings page hardcodes all values; Save/Reset buttons are non-functional
- Workers page: `api.restart_worker()` calls `/system/worker/{id}/restart`
  (singular) but backend route is `/system/workers/{id}/restart` (plural)
- Upstreams page: 100% mock data, never calls `GET /api/upstreams`
- Backend `restart_worker` and `trigger_health_check` handlers return 501
- 87 config schema fields exist but are never used to render the UI

This plan completes the admin panel to expose all available configurations while
maintaining the overseer/master/worker architecture constraints.

## Architecture Constraints

All changes must respect these rules (from AGENTS.md + codebase analysis):

1. **Config writes** — acquire `config_write_lock` (`TokioRwLock`) before any
   file I/O. Already handled server-side in `config.rs:968`.
2. **Overseer config changes** — write `.overseer_reload` signal file
   (`config.rs:1312`). Already handled server-side.
3. **Supervisor config changes** — write `.worker_reload` + call
   `pm.reload_config()`. Already handled server-side.
4. **Worker operations** — go through `ProcessManager` (Arc reference), never
   direct IPC. Already handled server-side.
5. **No new IPC messages** — admin runs in the master process; it accesses
   `ProcessManager` directly via `Arc`.
6. **Feature gates** — DNS and ICMP pages must be behind `cfg` attributes or
   conditionally hidden based on `/api/system/info` features list.

---

## Phase 1: Fix Settings Page to Load/Save Real Values

**Problem:** Settings page hardcodes all values. The "Save Changes" button does
nothing. Values never reflect the running configuration.

### 1.1 Add API methods for config schema + export/import

**File:** `admin-ui/src/services/api.rs`

Add (note: `reload_config` already exists at line 441):
```rust
pub async fn get_config_schema(&self) -> Result<Vec<ConfigFieldSchema>, String>
pub async fn get_config_export(&self) -> Result<String, String>
pub async fn import_config(&self, toml: &str) -> Result<StatusResponse, String>
pub async fn get_log_level(&self) -> Result<StatusResponse, String>
pub async fn set_log_level(&self, level: &str) -> Result<StatusResponse, String>
```

Also fix existing bug: `restart_worker` at line 187 calls
`/system/worker/{id}/restart` (singular) — change to
`/system/workers/{id}/restart` (plural) to match backend route.

### 1.2 Refactor Settings page to load from API

**File:** `admin-ui/src/pages/settings.rs`

Replace all 9 hardcoded sections with data-driven rendering:

1. On mount: fetch `GET /api/config/main` to get current config as JSON
2. On mount: fetch `GET /api/config/schema` to get field metadata (labels,
   descriptions, options, defaults, impact warnings)
3. Store config as `serde_json::Value` in state
4. Group schema entries by their prefix (e.g. `server.*`, `http.*`,
   `tls.*`, `defaults.ratelimit.*`) and render each group into its section tab
5. For each schema field, navigate the config JSON using the dotted path
   (e.g. `server.host` → `config["server"]["host"]`) to read current value
6. "Save Changes" button: reconstruct the full nested JSON from modified
   flat-path values, then `PUT /api/config/main` with it
7. "Reset" button: re-fetch `GET /api/config/main`
8. Add "Reload from Disk" button: `POST /api/config/reload`

The schema endpoint returns 87 fields covering these config groups:
- `server.*` (4 fields), `tokio.*` (1), `http.*` (6)
- `tls.*` (11), `http3.*` (2), `fallback.*` (2)
- `logging.*` (5), `metrics.*` (2), `admin.*` (2)
- `defaults.ratelimit.*` (10), `defaults.blocked.*` (4)
- `defaults.bot.*` (4), `defaults.honeypot.*` (3), `defaults.honeypot_probe.*` (4)
- `defaults.css_challenge.*` (2), `defaults.pow_challenge.*` (2), `defaults.challenge.*` (1)
- `defaults.error_pages.*` (2), `defaults.worker_pool.*` (3), `defaults.persistence.*` (3)
- `ip_feeds.*` (3), `tcp.*` (3), `udp.*` (2), `tarpit.*` (1)
- `defaults.upload.*` (2), `traffic_shaping.*` (4)
- `rate_limit_memory.*` (1), `proxy_limits.*` (1), `blocklist_limits.*` (1)
- `rule_feed.*` (2), `yara_feed.*` (2)

### 1.3 Dynamic field rendering component

**File:** `admin-ui/src/components/forms/` (new file or extend existing)

Create a `DynamicField` component that takes a `ConfigFieldSchema` + current
`serde_json::Value` and renders the appropriate widget:
- `field_type: "string"` + no `options` → `<Input>` (text)
- `field_type: "string"` + has `options` → `<Select>`
- `field_type: "integer"` → `<Input type="number">`
- `field_type: "boolean"` → `<Toggle>`
- `field_type: "array"` → `<TagInput>` (comma-separated tags, stored as JSON array)

Each `DynamicField` emits `(path, new_value)` on change. The Settings page
collects these into a `HashMap<String, serde_json::Value>` of modifications.

### 1.4 Config path → nested JSON conversion

**File:** `admin-ui/src/services/` (new helper or in `api.rs`)

Add helper functions:
- `get_nested_value(config: &Value, path: &str) -> Option<Value>` — navigates
  `server.host` → `config["server"]["host"]`
- `set_nested_value(config: &mut Value, path: &str, value: Value)` — sets value
  at dotted path, creating intermediate objects as needed
- `flatten_schema(schema: &[ConfigFieldSchema]) -> HashMap<String, Vec<&ConfigFieldSchema>>`
  — groups fields by top-level prefix for section rendering

---

## Phase 2: Add Missing Pages and Fix Stubs

### 2.1 Honeypot page (new)

**File:** `admin-ui/src/pages/honeypot.rs` (new, ~200 LOC)
**Sidebar:** "Security" section, after "Probing Activity"

Layout (left-to-right, two columns):
- **Left: Status card** — enabled/disabled badge, endpoints loaded count,
  active trap count. Fetched from `GET /api/honeypot/status`.
- **Left: Control panel** — four buttons: Enable, Disable, Pause, Resume.
  Each calls `POST /api/honeypot/control` with `{ "action": "enable" }`.
- **Right: Configuration** — `defaults.honeypot.*` and
  `defaults.honeypot_probe.*` fields rendered as editable form (hardcoded
  Input/Toggle components, same pattern as Process Management page since
  these fields are NOT in the config schema). Save writes via
  `PUT /api/config/main`.

API methods to add in `api.rs`:
```rust
pub async fn get_honeypot_status(&self) -> Result<serde_json::Value, String>
pub async fn control_honeypot(&self, action: &str) -> Result<serde_json::Value, String>
```

Route: add `Honeypot` to `Route` enum in `app.rs`, add to sidebar nav.

### 2.2 Rule Feed page (new)

**File:** `admin-ui/src/pages/rule_feed.rs` (new, ~180 LOC)
**Sidebar:** "Security" section

Layout:
- **Status card** — feed enabled/disabled, last update time, current version,
  pending version (if any), auto_apply setting
- **Action buttons** — "Check for Updates" (`POST /api/rules/check`),
  "Apply Pending" (`POST /api/rules/apply`), "Discard Pending"
  (`POST /api/rules/discard`)
- **Configuration section** — `rule_feed.*` fields (url, update_interval_hours,
  auto_apply, allow_downgrade). Editable, save via `PUT /api/config/main`.

API methods to add in `api.rs`:
```rust
pub async fn get_rule_feed_status(&self) -> Result<serde_json::Value, String>
pub async fn check_rule_updates(&self) -> Result<serde_json::Value, String>
pub async fn apply_rule_updates(&self) -> Result<serde_json::Value, String>
pub async fn discard_rule_updates(&self) -> Result<serde_json::Value, String>
```

Route: add `RuleFeed` to `Route` enum in `app.rs`, add to sidebar nav.

### 2.3 Workers page: fix restart

**Frontend fix:** `admin-ui/src/services/api.rs`

Line 187: change `/system/worker/{id}/restart` to `/system/workers/{id}/restart`
to match the backend route definition.

**Backend fix:** `src/admin/handlers/system.rs` `restart_worker` (line 197)

The simplest approach that works with the existing architecture:
1. Look up the worker's PID from `ProcessManager`'s worker map
2. Send SIGTERM to that PID
3. The existing `reap_zombies` loop in `ProcessManager` (`manager.rs:1035`)
   detects the dead worker via `try_wait()` and triggers automatic restart
   with exponential backoff

This avoids adding a new drain protocol. The restart is not instant (depends on
`restart_cooldown_secs`), but the UI already shows "Restarting..." state and
polls for status.

```rust
pub async fn restart_worker(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(worker_id): Path<String>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let pm = state.process.process_manager.as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let id: usize = worker_id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    pm.restart_worker_by_id(id)
        .map_err(|e| {
            tracing::error!("Failed to restart worker {}: {}", id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(StatusResponse::success(
        &format!("Worker {} termination signal sent; restart in progress", id)
    )))
}
```

**ProcessManager method:** Add `restart_worker_by_id(id)` to
`src/process/manager.rs`:
```rust
pub fn restart_worker_by_id(&self, id: usize) -> Result<(), String> {
    let workers = self.workers.read().map_err(|_| "lock poisoned")?;
    let worker = workers.get(&id)
        .ok_or_else(|| format!("Worker {} not found", id))?;

    if let Some(pid) = worker.pid {
        #[cfg(unix)]
        unsafe { libc::kill(pid as i32, libc::SIGTERM); }
        // reap_zombies will detect exit and auto-restart
    }
    Ok(())
}
```

### 2.4 Upstream page: replace mock data with API calls

**File:** `admin-ui/src/pages/upstreams.rs`

The entire page (193 lines) uses hardcoded `mock_upstreams`. Rewrite to:
1. On mount: call `GET /api/upstreams` to get real upstream data
2. Render upstream servers from API response
3. Add "Health Check" button per site → `POST /api/upstreams/{site_id}/check`
4. Show real connection counts, failure counters, health status

**Backend:** `src/admin/handlers/upstreams.rs` `trigger_health_check`

The handler currently returns 501. Implement by:
1. Read the site config for `site_id`
2. Ping each upstream URL in the site's upstream list
3. Return health status per upstream

---

## Phase 3: Dashboard Enhancements

### 3.1 Attack breakdown, cache, bandwidth widgets

**Status: Already working.** The dashboard already:
- Fetches `blocked_by_type` from websocket and renders "Blocking by Type"
  stacked area chart (dashboard.rs:434-442)
- Fetches `GET /api/stats/cache` and renders "Cache Performance" section
  (dashboard.rs:480-500)
- Fetches `GET /api/stats/bandwidth` and renders "Bandwidth Usage" section
  (dashboard.rs:502-518)

No changes needed for these.

### 3.2 Add Config Export/Import UI to Settings

**File:** `admin-ui/src/pages/settings.rs`

Add to the Settings page header area (above the section nav), a toolbar with:
- **Export Config** button → fetches `GET /api/config/export` (returns TOML
  string), downloads as `maluwaf-config.toml` file using blob download pattern
  from `dashboard.rs:12-22`
- **Import Config** button → shows file picker (`<input type="file">`), reads
  file content, calls `POST /api/config/import` with `{ "config": "<toml>" }`,
  shows success/error toast
- **Reload from Disk** button → calls `POST /api/config/reload`, refreshes
  all section values from the reloaded config

---

## Phase 4: Sidebar Reorganization

### 4.1 Updated sidebar structure

```
Overview
  ├── Dashboard
  ├── WAF Logs
  └── Request Logs

Security
  ├── Probing Activity
  ├── Honeypot              ← NEW
  └── Rule Feed             ← NEW

Management
  ├── Workers
  ├── Upstreams
  ├── Sites
  ├── TCP/UDP
  └── Tier Keys

Configuration
  ├── Settings
  ├── Process Management
  └── Alerts
```

### 4.2 Feature-gated items

Check `GET /api/system/info.features` array and conditionally show/hide sidebar
items. Implementation: fetch system info in sidebar or app-level context, pass
features list down, filter nav items.

Items to gate:
- **Rule Feed** — always show (not feature-gated in binary, controlled by config)
- **DNS** (future) — show only if `"dns"` in features list
- **ICMP** (future) — show only if `"icmp-filter"` in features list
- **Mesh Tier Keys** — show only if `"mesh"` in features list

---

## Phase 5: Settings Section Expansion (New Tabs)

These sections use **hardcoded** Input/Toggle components (same pattern as the
working Process Management page) because their fields are NOT in the config
schema endpoint. Each section reads its values from `GET /api/config/main` JSON
and writes back via `PUT /api/config/main`.

### 5.1 Blocked Paths tab

Fields from `defaults.blocked.*`:
| Field | Type | Widget |
|-------|------|--------|
| `paths` | array | TagInput (one path pattern per line) |
| `use_regex` | boolean | Toggle |
| `block_methods` | array | MultiSelect (GET, POST, PUT, DELETE, PATCH) |
| `block_response_code` | integer | Select (403 Forbidden, 404 Not Found, 444 Connection Closed) |

### 5.2 Auth Defaults tab

Fields from `defaults.auth.*`:
| Field | Type | Widget |
|-------|------|--------|
| `enabled` | boolean | Toggle |
| `session_duration_secs` | integer | Input (number) |
| `max_login_attempts` | integer | Input (number) |
| `lockout_duration_secs` | integer | Input (number) |
| `login_path` | string | Input (text) |

### 5.3 TLS tab

Fields from `tls.*`:
| Field | Type | Widget |
|-------|------|--------|
| `enabled` | boolean | Toggle |
| `cert_path` | string | Input (text) |
| `key_path` | string | Input (text) |
| `port` | integer | Input (number) |
| `prefer_post_quantum` | boolean | Toggle |
| `tls_1_3_only` | boolean | Toggle |
| `acme.enabled` | boolean | Toggle |
| `acme.email` | string | Input (text) |
| `acme.staging` | boolean | Toggle |
| `acme.domains` | array | TagInput |
| `client_auth.enabled` | boolean | Toggle |

### 5.4 IP Feeds tab

Fields from `ip_feeds.*`:
| Field | Type | Widget |
|-------|------|--------|
| `enabled` | boolean | Toggle |
| `url` | string | Input (text) |
| `update_interval_hours` | integer | Input (number) |
| `max_permanent_blocks` | integer | Input (number) |

### 5.5 Log Exporters tab

Fields from `logging.exporter.*`:
| Field | Type | Widget |
|-------|------|--------|
| `enabled` | boolean | Toggle |
| `elasticsearch.url` | string | Input |
| `elasticsearch.index` | string | Input |
| `elasticsearch.api_key` | string | Input (password type) |
| `elasticsearch.batch_size` | integer | Input (number) |
| `loki.url` | string | Input |
| `loki.tenant_id` | string | Input |
| `loki.batch_size` | integer | Input (number) |

### 5.6 Traffic Shaping tab

Fields from `traffic_shaping.*` (supplement schema fields already shown):
| Field | Type | Widget |
|-------|------|--------|
| `enabled` | boolean | Toggle |
| `global.ingress_max_mb_s` | integer | Input |
| `global.egress_max_mb_s` | integer | Input |
| `global.burst_allowance_mb` | integer | Input |
| `global.burst_refill_ms` | integer | Input |
| `global.attack_mode_multiplier` | number | Input (decimal) |
| `connection_limits.max_connections` | integer | Input |
| `connection_limits.max_connections_per_ip` | integer | Input |
| `connection_limits.connection_burst` | integer | Input |
| `connection_limits.connection_queue_size` | integer | Input |
| `connection_limits.connection_queue_timeout_ms` | integer | Input |

### 5.7 Rate Limits: add missing fields to existing section

Current section has per-5min and per-day. Add to existing Rate Limits tab:
| Field | Source | Widget |
|-------|--------|--------|
| `ip.per_10min` | `defaults.ratelimit.ip.per_10min` | Input (number) |
| `global.per_5min` | `defaults.ratelimit.global.per_5min` | Input (number) |

---

## Implementation Order

```
Step 1: API methods + URL fix (Phase 1.1)
        Files: api.rs
        ~8 new methods, 1 bug fix (restart URL)
        Risk: Low

Step 2: Dynamic field component (Phase 1.3)
        Files: admin-ui/src/components/forms/dynamic_field.rs (new)
        ~150 LOC
        Risk: Low — isolated component

Step 3: Settings refactor — load/save/dynamic rendering (Phase 1.2, 1.4)
        Files: settings.rs, types/mod.rs
        Major rewrite of settings.rs (~900→~500 LOC for existing sections)
        Risk: Medium — largest change, touches core Settings page
        Verify: load Settings, check values match main.toml, save, check file

Step 4: Settings — Export/Import/Reload toolbar (Phase 3.2)
        Files: settings.rs
        ~80 LOC, adds toolbar to existing page
        Risk: Low

Step 5: Honeypot page (Phase 2.1)
        Files: honeypot.rs (new), pages/mod.rs, app.rs, sidebar.rs, api.rs
        ~250 LOC
        Risk: Low — new page, existing API

Step 6: Rule Feed page (Phase 2.2)
        Files: rule_feed.rs (new), pages/mod.rs, app.rs, sidebar.rs, api.rs
        ~200 LOC
        Risk: Low — new page, existing API

Step 7: Settings — new tabs expansion (Phase 5.1–5.7)
        Files: settings.rs
        ~300 LOC, adds 7 new section tabs with hardcoded Input/Toggle
        Risk: Low — follows Process Management pattern

Step 8: Worker restart fix (Phase 2.3)
        Files: api.rs (URL fix from Step 1), system.rs, manager.rs
        ~50 LOC backend, SIGTERM + reap_zombies pattern
        Risk: Medium — process lifecycle
        Verify: cargo test --test integration_test

Step 9: Upstreams page rewrite (Phase 2.4)
        Files: upstreams.rs, upstreams handler, api.rs
        ~150 LOC (rewrite from mock to API-driven)
        Risk: Low — replace mock data

Step 10: Sidebar reorg + feature gating (Phase 4.1–4.2)
         Files: sidebar.rs, app.rs
         ~60 LOC
         Risk: Low — nav restructure
```

---

## Files Modified Summary

| File | Step | Change Type |
|------|------|-------------|
| `admin-ui/src/services/api.rs` | 1, 5, 6, 8, 9 | Add ~15 methods, fix restart URL |
| `admin-ui/src/components/forms/dynamic_field.rs` | 2 | New file (~150 LOC) |
| `admin-ui/src/pages/settings.rs` | 3, 4, 7 | Major refactor + toolbar + 7 new tabs |
| `admin-ui/src/pages/honeypot.rs` | 5 | New file (~200 LOC) |
| `admin-ui/src/pages/rule_feed.rs` | 6 | New file (~180 LOC) |
| `admin-ui/src/pages/upstreams.rs` | 9 | Rewrite from mock to API (~150 LOC) |
| `admin-ui/src/pages/workers.rs` | 8 | Restart button fix (URL in api.rs) |
| `admin-ui/src/pages/mod.rs` | 5, 6 | Export new page modules |
| `admin-ui/src/app.rs` | 5, 6, 10 | Add routes, update switch |
| `admin-ui/src/components/layout/sidebar.rs` | 5, 6, 10 | Add nav items, reorg, feature gating |
| `admin-ui/src/types/mod.rs` | 3 | Add missing type defs if needed |
| `src/admin/handlers/system.rs` | 8 | Implement restart_worker (~30 LOC) |
| `src/admin/handlers/upstreams.rs` | 9 | Implement trigger_health_check (~20 LOC) |
| `src/process/manager.rs` | 8 | Add restart_worker_by_id (~15 LOC) |

---

## Verification

After each step:
1. `cargo build` — verify backend compiles
2. `cd admin-ui && trunk build` — verify frontend compiles (if admin-ui files changed)
3. `cargo test --test integration_test` — verify no regressions

After Steps 3 (Settings refactor):
1. Open Settings page → verify all 87 schema fields show live values from
   `config/main.toml` (not hardcoded defaults)
2. Change a value (e.g., server port) → click Save → verify `main.toml`
   is updated on disk
3. Click Reset → verify values revert to current config
4. Click Reload from Disk → verify values refresh from file

After Step 4 (Export/Import):
1. Click Export Config → verify `.toml` file downloads with correct content
2. Edit the downloaded file → click Import → verify config updates

After Step 5-6 (Honeypot, Rule Feed):
1. Navigate to Honeypot page → verify status loads from API
2. Click Enable/Disable → verify honeypot state changes
3. Navigate to Rule Feed page → verify status loads

After Step 7 (Settings tabs):
1. Verify each new tab (Blocked Paths, Auth, TLS, IP Feeds, Log Exporters,
   Traffic Shaping) loads correct values from config
2. Modify values in each tab → Save → verify main.toml updates

After Step 8 (Worker restart):
1. Workers page → click Restart on a running worker → verify "Restarting..."
   state appears → verify worker PID changes after restart completes

After Step 9 (Upstreams rewrite):
1. Upstreams page → verify real upstream data loads (not mock)
2. Click Health Check on a site → verify result displayed
