# OpenAPI Improvement Plan (Phase 3)

**Status**: Planning
**Created**: 2026-04-27
**Last Updated**: 2026-04-27

## Background

Review of the OpenAPI implementation in MaluWAF identified several areas for improvement. The codebase uses utoipa v5 with a code-first approach where the OpenAPI spec is generated from handler functions and schemas via derive macros. This provides strong schema drift prevention by construction.

## Current State

| Component | Location | Notes |
|-----------|----------|-------|
| OpenAPI spec | `src/admin/openapi.rs` | ~365 paths, 100+ schemas via `#[derive(OpenApi)]` |
| Schema definitions | `src/admin/schema.rs` | Custom `ToSchema` implementations |
| API handlers | `src/admin/handlers/*.rs` | 21 handler modules |
| Router/middleware | `src/admin/mod.rs:712-730` | Middleware stack |
| OpenAPI JSON | `/api/openapi.json` | ✅ Working |
| Swagger UI | `/api/docs` | ❌ Not implemented |

**Dependencies in Cargo.toml:**
```toml
utoipa = "5"
utoipa-swagger-ui = { version = "9", features = ["axum"] }
```

## Issues Identified

1. **Swagger UI Not Integrated** - `utoipa-swagger-ui` crate is a dependency but no route serves it
2. **No Machine-Readable Discovery** - No `GET /api` endpoint for SDK generators and CLI tools
3. **Hardcoded Server URLs** - OpenAPI spec contains `http://localhost:8080` which doesn't reflect actual deployment

## Implementation Phases

---

### Phase 1: Enable Swagger UI (Low Effort, High Impact)

**Objective**: Add interactive API documentation at `/api/docs`

**Changes**:

1. **File**: `src/admin/mod.rs`
   - Add import: `use utoipa_swagger_ui::SwaggerUi;`
   - Modify router builder (around line 712) to merge SwaggerUi routes:

   ```rust
   Router::new()
       .merge(SwaggerUi::new("/api/docs")
           .url("/api/openapi.json", openapi::MaluWafOpenApi::openapi()))
       .nest("/api", api_routes)
       .route("/api/openapi.json", get(openapi::get_openapi_json))
       // ... remaining routes and layers
   ```

2. **Rationale**:
   - `utoipa-swagger-ui` with `axum` feature already in Cargo.toml
   - No new dependencies required
   - Minimal code change
   - Order matters: `.merge()` before `.nest("/api", ...)` ensures `/api/docs` is not nested under `/api`

3. **Testing**:
   - Add integration test to verify `/api/docs` returns HTML
   - Add test to verify Swagger UI loads and displays OpenAPI spec

**Files affected**: `src/admin/mod.rs`

**Estimated effort**: Low (1-2 hours)

---

### Phase 2: Add `GET /api` Discovery Endpoint (Medium Effort)

**Objective**: Provide machine-readable API metadata for SDK generators, CLI tools, and integration with other software

**New files**:
- `src/admin/handlers/api_discovery.rs`
- Update `src/admin/handlers/mod.rs` to export new module

**Endpoint design**:

`GET /api` returns:
```json
{
  "name": "MaluWAF Admin API",
  "version": "1.0.0",
  "description": "REST API for managing MaluWAF",
  "openapi_url": "/api/openapi.json",
  "docs_url": "/api/docs",
  "servers": ["https://actual-host:port"],
  "categories": [
    {"name": "stats", "description": "System statistics", "endpoint_count": 7},
    {"name": "sites", "description": "Site configuration", "endpoint_count": 8},
    {"name": "config", "description": "Configuration management", "endpoint_count": 90},
    {"name": "mesh", "description": "Mesh networking", "endpoint_count": 15},
    {"name": "system", "description": "System management", "endpoint_count": 12},
    {"name": "health", "description": "Health checks", "endpoint_count": 3}
  ],
  "total_endpoints": 150
}
```

**Implementation approach**:

1. Create `ApiDiscoveryResponse` struct with `#[derive(Serialize, ToSchema)]`
2. Create handler `get_api_discovery()` that:
   - Reads from `MaluWafOpenApi::openapi()` to extract paths grouped by tags
   - Counts endpoints per tag/category
   - Constructs response with dynamic server detection
3. Add route in `src/admin/mod.rs`: `.route("/api", get(api_discovery::get_api_discovery))`

**Dynamic server detection**:
- Extract from incoming request `Host` header
- Support `X-Forwarded-Proto` for proxy environments
- Fall back to configured bind address

**Schema** (in `api_discovery.rs`):
```rust
#[derive(Serialize, ToSchema)]
pub struct ApiDiscoveryResponse {
    pub name: String,
    pub version: String,
    pub description: String,
    pub openapi_url: String,
    pub docs_url: String,
    pub servers: Vec<String>,
    pub categories: Vec<CategoryInfo>,
    pub total_endpoints: usize,
}

#[derive(Serialize, ToSchema)]
pub struct CategoryInfo {
    pub name: String,
    pub description: String,
    pub endpoint_count: usize,
}
```

**Files affected**:
- `src/admin/handlers/api_discovery.rs` (new)
- `src/admin/handlers/mod.rs` (update exports)
- `src/admin/mod.rs` (add route)

**Estimated effort**: Medium (4-6 hours)

---

### Phase 3: Dynamic Server URLs in OpenAPI Spec (Medium Effort)

**Objective**: Replace hardcoded `localhost:8080` with actual deployment server URLs

**Current state**: Servers hardcoded at `src/admin/openapi.rs:40-43`:
```rust
servers(
    (url = "http://localhost:8080", description = "Local development server"),
    (url = "https://localhost:8080", description = "Production server")
),
```

**Challenge**: utoipa's `#[derive(OpenApi)]` is compile-time macro; `MaluWafOpenApi::openapi()` returns a frozen spec at creation time. Server URLs are baked into the spec at compile time.

**Implementation approach**:

Since Swagger UI fetches `/api/openapi.json` dynamically, we can modify the `get_openapi_json()` handler to inject actual servers at runtime:

1. **Add `AdminApiState` access to handler**: Modify `get_openapi_json()` to accept `State<AdminApiState>`:
   ```rust
   pub async fn get_openapi_json(
       State(state): State<AdminApiState>,
   ) -> Json<openapi::OpenApi> {
       let mut openapi = MaluWafOpenApi::openapi();
       // servers field is a Vec<openapi::Server>; update URLs here
       Json(openapi)
   }
   ```

2. **Server extraction logic**:
   - Get bind address from config manager
   - Support `X-Forwarded-Proto` and `X-Forwarded-Host` headers for proxy setups
   - Construct actual server URL from request context

3. **Alternative for Swagger UI**: Since Swagger UI calls `/api/openapi.json` to get the spec, updating that handler automatically updates what Swagger UI displays. No separate changes needed for Swagger UI.

4. **Simplified approach (Phase 3 alternative)**: Update the hardcoded servers in `openapi.rs` to be more generic placeholder values (e.g., just `http://localhost:8080`) since Swagger UI users will typically use the "Try it out" feature which sends requests to actual servers via browser.

**Files affected**:
- `src/admin/openapi.rs` (servers annotation)
- `src/admin/mod.rs` (route change for state access)

**Estimated effort**: Medium (3-4 hours) if doing full runtime injection; Low (30 min) if using simplified approach

**Recommendation**: Implement simplified approach first (remove production server from spec to avoid misleading users), defer full runtime injection to Phase 4 if needed.

---

## Testing Strategy

### Phase 1 Tests
```rust
#[tokio::test]
async fn test_swagger_ui_endpoint() {
    // Start admin server
    // GET /api/docs
    // Assert response Content-Type is text/html
    // Assert body contains swagger-ui
}
```

### Phase 2 Tests
```rust
#[tokio::test]
async fn test_api_discovery_endpoint() {
    // GET /api
    // Assert valid JSON with required fields
    // Assert categories array is non-empty
    // Assert total_endpoints matches sum of categories
}
```

---

## Verification Commands

```bash
# Verify code compiles
cargo check --lib -p maluwaf

# Run tests
cargo test --lib -- openapi
cargo test --test integration_test api_discovery

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```

---

## Rollout Sequence

1. **Phase 1**: Implement Swagger UI (quick win, validates infrastructure)
2. **Phase 2**: Add API discovery endpoint (after Phase 1 completes)
3. **Phase 3**: Optional - dynamic server URLs (low priority, defer if complex)

---

## Dependencies

- No new dependencies required (utoipa-swagger-ui already in Cargo.toml)
- No database migrations
- No configuration changes
- Backward compatible - existing `/api/openapi.json` continues to work

---

## Security Considerations

1. **Swagger UI** - Currently, the auth middleware only exempts `/health` and `/ws/*`. The merged SwaggerUI routes would require Bearer token auth like other `/api/*` routes. This creates a usability concern (chicken-and-egg: need token to see docs, docs explain how to get token). **Recommendation**: Add exemption for `/api/docs` and `/api/openapi.json` in `auth_middleware_with_state()` to allow anonymous access to API documentation.

2. **API Discovery** - Returns only metadata, no sensitive data. Should remain under auth or open depending on preference.

3. **Rate limiting** - Existing admin rate limit applies to new endpoints.

**Proposed auth exemption changes** (in `src/admin/middleware.rs`):
```rust
// Around line 58-64
if request.uri().path() == "/health" {
    return next.run(request).await;
}

if request.uri().path().starts_with("/ws/") {
    return next.run(request).await;
}

// NEW: Allow anonymous access to API docs
if request.uri().path() == "/api/docs"
    || request.uri().path() == "/api/openapi.json"
    || request.uri().path().starts_with("/api/docs/")  // Swagger UI assets
{
    return next.run(request).await;
}
```

---

## Future Enhancements (Out of Scope)

- ReDoc alternative UI (separate endpoint)
- OpenAPI spec export as downloadable file
- API changelog/versioning endpoint
- SDK generation pipeline
- Contract tests for response validation (code-first utoipa sufficient for now)