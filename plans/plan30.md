# Plan 30: OpenAPI/Swagger UI Integration Improvements

## Context

During architecture review, the OpenAPI implementation was identified as incomplete or suboptimal in several areas:

1. **Critical Version Mismatch**: `utoipa-swagger-ui = "7"` in Cargo.toml requires `axum ^0.7`, but project uses `axum = "0.8"`
2. **No Embedded Swagger UI**: `/api/docs` returns custom HTML with external third-party links instead of embedded UI
3. **Hardcoded Wrong Port**: OpenAPI spec says port 8080 but admin defaults to 8081
4. **Generic Server URLs**: OpenAPI spec has meaningless localhost URLs that don't reflect actual deployment
5. **No Public Health Endpoint**: `/health` requires auth, limiting utility for external monitoring

**Security Design Philosophy**: This codebase IS the reverse proxy. Admin endpoints should not be exposed publicly by default. The defaults heavily nudge users toward secure local management with port forwarding (SSH, Tailscale, WireGuard). Exposing admin endpoints to the public internet is a massive security risk that should be avoided by design.

---

## Background: Current Architecture

### OpenAPI Files

| File | Purpose |
|------|---------|
| `src/admin/openapi.rs` | OpenAPI spec generation using utoipa derive macros |
| `src/admin/mod.rs` | Router setup including `/api/openapi.json` and `/api/docs` routes |
| `Cargo.toml:205` | `utoipa-swagger-ui = { version = "7", features = ["axum"] }` |

### Current Endpoint Behavior

| Endpoint | Current Behavior | Issue |
|----------|-----------------|-------|
| `/api/openapi.json` | Returns valid OpenAPI 3.0 JSON | Works, but spec has wrong port |
| `/api/docs` | Custom HTML → external petstore.swagger.io | Users leave your site |
| `/health` | Returns `{"status": "ok"}` | Requires auth (by global security) |

### OpenAPI Spec Server Array (WRONG)

```rust
// src/admin/openapi.rs:43-46
servers(
    (url = "http://localhost:8080", description = "Local development server"),
    (url = "https://localhost:8080", description = "Production server")
)
```

**Problems:**
- Default admin port is **8081** (see `src/config/admin.rs:180-181`), not 8080
- `localhost` URLs are meaningless for remote API clients
- HTTPS entry is misleading - doesn't reflect actual TLS configuration

### Security Architecture

```
                    PUBLIC INTERNET
                           │
                           ▼
              ┌────────────────────────┐
              │   MaluWAF Reverse Proxy │
              │  (Frontend / Edge)      │
              └───────────┬────────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
    Localhost:8081              Sites/Upstreams
    (Admin API)                 (Reverse Proxied)
            │
            ├── Users access via SSH tunnel / Tailscale / WireGuard
            ├── No direct public exposure
            └── This is INTENTIONAL for security
```

---

## Phase 1: Fix utoipa-swagger-ui Version Mismatch (CRITICAL)

### Problem

```
utoipa-swagger-ui 7.x → depends on axum ^0.7
Project uses axum 0.8
```

Running `cargo build` should warn about this dependency mismatch. Version 9.x of utoipa-swagger-ui supports axum 0.8.

### Step 1.1: Update Cargo.toml

**File**: `Cargo.toml:205`

**Current:**
```toml
utoipa-swagger-ui = { version = "7", features = ["axum"] }
```

**Change to:**
```toml
utoipa-swagger-ui = { version = "9", features = ["axum"] }
```

### Step 1.2: Verify Dependency Resolution

```bash
cargo update utoipa-swagger-ui
cargo tree -p utoipa-swagger-ui
```

Verify output shows axum 0.8 compatibility.

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 1.1 Update Cargo.toml | 5 min | Trivial |
| 1.2 Verify | 5 min | Trivial |
| **Total** | **10 min** | **Trivial** |

### Files to Modify

| File | Changes |
|------|---------|
| `Cargo.toml` | Change version from "7" to "9" |

---

## Phase 2: Add Embedded Swagger UI (HIGH)

### Problem

`/api/docs` returns custom HTML that links externally to `petstore.swagger.io`. Users must leave the admin panel to view API documentation.

### Current Custom HTML

```rust
// src/admin/openapi.rs:374-405
async fn get_docs() -> Html<String> {
    Html(r#"<!DOCTYPE html>
<html lang="en">
...
<a href="https://petstore.swagger.io/?url=/api/openapi.json" target="_blank">Swagger UI</a>
<a href="https://redocly.com/docs/react-doc-viewer/" target="_blank">Redoc</a>
...
"#.to_string())
}
```

### Important Architecture Discovery

**`MaluWafOpenApi::router()` is dead code** - it is never called by the server.

The actual routing is:
1. `build_router_from_state()` in `src/admin/mod.rs:555-575` builds the main admin router
2. It directly registers `.route("/api/openapi.json", get(openapi::get_openapi_json))`
3. The `MaluWafOpenApi::router()` method at `openapi.rs:363-368` is never invoked

Therefore, SwaggerUi must be integrated into the **main admin router** in `build_router_from_state()`, not into `MaluWafOpenApi::router()`.

### Step 2.1: Add SwaggerUi Merge to Main Router

**File**: `src/admin/mod.rs`

**Current** (lines 555-574):
```rust
Router::new()
    .nest("/api", api_routes)
    .route("/api/openapi.json", get(openapi::get_openapi_json))
    .route("/health", get(health_check))
    .fallback_service(ServeDir::new("admin-ui/dist"))
    .layer(create_cors_layer(&admin_cors_config))
    .layer(axum::middleware::from_fn(
        middleware::extract_client_ip_middleware,
    ))
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        middleware::auth_middleware_with_state,
    ))
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        middleware::csrf_middleware,
    ))
    .layer(yara_rate_limit_layer)
    .layer(rate_limit_layer)
    .with_state(state)
```

**Add** `use utoipa_swagger_ui::SwaggerUi;` at the top of the file (check existing imports).

**Change** the router building:
```rust
use utoipa_swagger_ui::SwaggerUi;

Router::new()
    .nest("/api", api_routes)
    .route("/api/openapi.json", get(openapi::get_openapi_json))
    .merge(SwaggerUi::new("/api/docs")
        .url("/api/openapi.json", openapi::MaluWafOpenApi::openapi()))
    .route("/health", get(health_check))
    .fallback_service(ServeDir::new("admin-ui/dist"))
    // ... rest of layers unchanged
```

**Key points:**
- `SwaggerUi::new("/api/docs")` creates routes at `/api/docs`, `/api/docs/`, `/api/docs/swagger-ui.css`, etc.
- `.url("/api/openapi.json", ...)` tells Swagger UI where to fetch the OpenAPI spec
- The actual `/api/openapi.json` route still serves the spec (line 557)
- No routes need to be removed - SwaggerUi adds its own routes

### Step 2.2: Clean Up Dead Code in openapi.rs

**File**: `src/admin/openapi.rs`

**Remove**:
1. The `get_docs()` function (lines 374-405)
2. The `router()` method on `MaluWafOpenApi` (lines 363-368)
3. The `get_openapi()` method (lines 370-372) - only used by dead `router()`

**Keep**:
- `get_openapi_json()` function (line 353) - used by mod.rs:557
- `MaluWafOpenApi::openapi()` derive - used at compile time for spec generation
- All the `#[utoipa::path]` and `#[derive(ToSchema)]` attributes on handlers - used for spec generation

**Why**: These functions/methods are dead code that served the never-used `MaluWafOpenApi::router()`. Removing them reduces confusion.

### Step 2.3: Handle Trailing Slash

`SwaggerUi::new("/api/docs")` will:
- Redirect `/api/docs` → `/api/docs/` (301)
- Serve UI at `/api/docs/`
- Serve assets at `/api/docs/swagger-ui.css`, etc.

This is standard Swagger UI behavior and acceptable.

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 2.1 Add SwaggerUi to main router | 10 min | Low |
| 2.2 Clean up dead code | 10 min | Low |
| 2.3 Test integration | 10 min | Low |
| **Total** | **30 min** | **Low** |

### Files to Modify

| File | Changes |
|------|---------|
| `src/admin/mod.rs` | Import and merge SwaggerUi |
| `src/admin/openapi.rs` | Remove dead functions (`get_docs()`, `router()`, `get_openapi()`) |

---

## Phase 3: Fix Hardcoded Server Port (MEDIUM)

### Problem

OpenAPI spec says port 8080 but admin actually runs on 8081 by default.

### Step 3.1: Change Server URL

**File**: `src/admin/openapi.rs:43-46`

**Current:**
```rust
servers(
    (url = "http://localhost:8080", description = "Local development server"),
    (url = "https://localhost:8080", description = "Production server")
)
```

**Options:**

**Option A - Generic (Recommended for security design):**
```rust
servers(
    (url = "/", description = "API root")
)
```

**Rationale**: The admin API is accessed via tunnel/forwarding, so the actual host:port is irrelevant. Using "/" follows OpenAPI spec default behavior and works regardless of how the admin is accessed.

**Option B - Use actual config (more complex):**
```rust
// In get_openapi_json() or a new endpoint:
let mut openapi = MaluWafOpenApi::openapi();
openapi.servers = Some(vec![
    Server::new(&format!("http://{}:{}", cfg.bind_address, cfg.port))
]);
```

**Option C - Accept both HTTP/HTTPS based on config:**
```rust
servers(
    (url = "http://127.0.0.1:8081", description = "Local admin API"),
)
```

### Recommendation

**Use Option A** (generic "/"). This is the most honest approach:
1. Admin is not meant to be directly internet-accessible
2. Actual URL depends on however the user connects (SSH tunnel, Tailscale, etc.)
3. Generic root avoids misleading information in the spec

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 3.1 Update servers array | 5 min | Trivial |
| **Total** | **5 min** | **Trivial** |

### Files to Modify

| File | Changes |
|------|---------|
| `src/admin/openapi.rs` | Change servers array |

---

## Phase 4: Add Optional Public Health Endpoint (LOW)

### Problem

`/health` requires authentication (global bearer_auth). This prevents external monitoring systems from checking if MaluWAF is alive without credentials.

### Security Design Consideration

From user requirements:
- Admin endpoints should NOT be publicly accessible
- Health endpoints could be **optionally** public but default to local access

### Current Health Endpoint

```rust
// src/admin/mod.rs:577-584
async fn health_check() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok"
        })),
    )
}
```

This is a simple function, not a utoipa path, so it's not in the OpenAPI spec at all.

### Step 4.1: Create Public Health Endpoint

**Option A - Create a new `/api/public/health` endpoint with no security:**

```rust
// In src/admin/handlers/health.rs (new file)
#[utoipa::path(
    get,
    path = "/api/public/health",
    security(()),  // Empty = no security required
    responses(
        (status = 200, description = "Service is healthy")
    ),
    tag = "health"
)]
pub async fn public_health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok"
    }))
}
```

**Option B - Keep only `/health` (no auth, not in OpenAPI):**

The existing `/health` endpoint at `mod.rs:558` already works without OpenAPI documentation. External monitoring can hit it directly.

### Recommendation

**Use Option B** - The existing `/health` endpoint at `mod.rs:558` already:
- Requires no authentication (it's before the auth middleware in the router chain)
- Works for health checks
- Is not in OpenAPI spec (which is fine - it's an operational endpoint)

No code changes needed for this phase if we're satisfied with `/health`.

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 4.1 Document existing /health behavior | 5 min | Trivial |
| **Total** | **5 min** | **Trivial** |

---

## Phase 5: Per-Path Security for Future Public Endpoints (INFORMATIONAL)

### Context

The utoipa `security(...)` attribute on `#[utoipa::path]` allows marking individual endpoints as:
- **No security**: `security(())` - empty tuple
- **Different auth**: `security(("other_auth" = ["scope"]))`

Currently all 100+ admin endpoints use global bearer_auth. If future endpoints need to be public, they can opt-out with `security(())`.

### Example Pattern

```rust
#[utoipa::path(
    get,
    path = "/api/public/status",
    security(()),  // Public - no auth required
    responses(
        (status = 200, description = "Public status info")
    ),
    tag = "public"
)]
pub async fn get_public_status() -> Json<PublicStatus> {
    // ...
}
```

### Current State

No admin endpoints currently use per-path security. All inherit global `bearer_auth`.

This phase is informational only - no code changes required.

---

## Implementation Order

| Phase | Item | Priority | Effort | Reason |
|-------|------|----------|--------|--------|
| **1** | Fix utoipa-swagger-ui version | **CRITICAL** | 10 min | Dependency mismatch blocking |
| **2** | Add embedded Swagger UI | **HIGH** | 30 min | Core functionality |
| **3** | Fix server port | MEDIUM | 5 min | Quick fix, more accurate spec |
| **4** | Public health endpoint | LOW | 5 min | Already works, document only |
| **5** | Per-path security info | INFO | 0 min | No action needed |

**Total estimated effort: ~50 minutes**

---

## File Change Summary

| File | Phase | Changes |
|------|-------|---------|
| `Cargo.toml` | 1 | Upgrade utoipa-swagger-ui to "9" |
| `src/admin/mod.rs` | 2 | Add `use utoipa_swagger_ui::SwaggerUi;`, merge SwaggerUi into main router |
| `src/admin/openapi.rs` | 2 | Remove dead `get_docs()`, `router()`, `get_openapi()` functions |
| `src/admin/openapi.rs` | 3 | Change servers array to generic "/" |

**Files NOT needing modification:**
- `src/admin/handlers/` - No changes needed
- `src/config/admin.rs` - No changes needed

---

## Testing Strategy

### Phase 1 Verification
```bash
cargo check
# Should complete without utoipa-swagger-ui version warnings
```

### Phase 2 Verification
```bash
cargo build
# Start server, then:

curl -I http://localhost:8081/api/docs
# Should return 301 redirect to /api/docs/

curl http://localhost:8081/api/docs/
# Should return Swagger UI HTML

curl http://localhost:8081/api/docs/swagger-ui.css
# Should return Swagger UI CSS (200 OK)

curl http://localhost:8081/api/openapi.json | jq '.info.title'
# Should return "MaluWAF Admin API"
```

### Phase 3 Verification
```bash
curl http://localhost:8081/api/openapi.json | jq '.servers'
# Should show [{"url": "/"}] or corrected port
```

### Browser Testing
1. Navigate to `http://localhost:8081/api/docs`
2. Should see embedded Swagger UI (not redirected to petstore.swagger.io)
3. Click "Authorize" and enter bearer token
4. Click "Try it out" on any endpoint
5. Execute request - should work with auth

---

## Rollback Plan

| Phase | Revert Action |
|-------|---------------|
| 1 | Revert `Cargo.toml` to version "7" |
| 2 | Remove `.merge(SwaggerUi::...)` from mod.rs, restore removed functions to openapi.rs |
| 3 | Revert servers array to original |

---

## Related Work

### Dependencies

| Crate | Phase | Purpose |
|-------|-------|---------|
| `utoipa` | 1-3 | OpenAPI derive macros |
| `utoipa-swagger-ui` | 1-2 | Swagger UI integration (upgrade to v9) |

### Existing Patterns

| Pattern | Location | Used By |
|---------|----------|---------|
| `#[utoipa::path]` | All handler files | Phase 2 (no change) |
| `#[derive(ToSchema)]` | All handler files | Phase 2 (no change) |
| Router merge | N/A | Phase 2 new pattern |

---

## Open Questions

1. **Server URL Strategy**: Do you want generic "/" (recommended) or actual `127.0.0.1:8081`?

2. **Swagger UI Customization**: Any branding changes needed (title, colors)? For now we use defaults.

3. **Public Health Endpoint**: Is the existing `/health` endpoint sufficient, or do you want a documented `/api/public/health` in OpenAPI?

4. **Debug Embed**: By default, utoipa-swagger-ui doesn't embed assets in debug builds. Add `debug-embed` feature if you want `cargo run` to work without `--release`:
   ```toml
   utoipa-swagger-ui = { version = "9", features = ["axum", "debug-embed"] }
   ```
   Without this, Swagger UI assets come from a CDN in debug mode. In production (release), assets are always embedded.

---

## Security Considerations

### What This Plan Does NOT Change

1. **Admin authentication** - All admin API endpoints still require bearer token
2. **Admin bind address** - Still defaults to `127.0.0.1` (localhost only)
3. **Public exposure** - No admin endpoints become publicly accessible

### What This Plan Improves

1. **Usability** - Embedded Swagger UI instead of external redirect
2. **Reliability** - API docs available even if petstore.swagger.io is down
3. **Accuracy** - OpenAPI spec reflects actual port
4. **Simplicity** - Removes misleading localhost URLs from spec

### Security Reminder

MaluWAF is designed to be the **reverse proxy**, not something to be reverse-proxied. The admin panel is intentionally bound to localhost to prevent direct public exposure. Users who need remote admin access should use:
- SSH tunnels
- Tailscale Funnel
- WireGuard VPN
- Similar secure tunneling solutions

This is a design philosophy, not a limitation.
