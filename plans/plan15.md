# Plan 15: OpenAPI Documentation Enhancement

**Date**: 2026-04-23
**Author**: opencode
**Status**: Draft

## Overview

This plan addresses identified improvements to the MaluWAF OpenAPI documentation implementation. Analysis found 165+ endpoints properly annotated, but schema examples are nearly absent, and a few other minor opportunities exist.

### Quick Summary

| # | Area | Status | Recommendation |
|---|------|--------|----------------|
| 1 | **Schema Examples** | 128/130 missing | HIGH - Add examples to all schemas |
| 2 | **Request Body Referencing** | ✅ PASS | No changes needed |
| 3 | **Tag Assignments** | ✅ 100% coverage | Minor: remove unused `health` tag |
| 4 | **operation_id** | Optional | LOW - Skip unless external SDK needed |
| 5 | **Response Descriptions** | ✅ Intentionally minimal | Keep as-is (security hardening) |

### Decision Required

Before implementation, decide:
- [ ] **Health tag**: Keep for future health-check endpoints, or remove?
- [ ] **operation_id**: Required for external SDK generation?

---

## Issue 1: Missing Schema Examples 🔴 HIGH PRIORITY

### Finding

The codebase has **130 schemas** but only **2 have example values** defined. This affects API documentation quality in tools like Swagger UI, ReDoc, and auto-generated SDKs.

| File | Schemas | With Examples | Missing |
|------|---------|---------------|---------|
| mesh_admin.rs | 17 | 0 | 17 |
| yara_rules.rs | 14 | 0 | 14 |
| probes.rs | 13 | 0 | 13 |
| sites.rs | 10 | 0 | 10 |
| config.rs | 8 | 0 | 8 |
| threat_level.rs | 9 | 0 | 9 |
| system.rs | 9 | 0 | 9 |
| stats.rs | 8 | 2 | 6 |
| logs.rs | 7 | 0 | 7 |
| icmp.rs | 7 | 0 | 7 |
| theme.rs | 6 | 0 | 6 |
| tcp_udp.rs | 5 | 0 | 5 |
| upstreams.rs | 4 | 0 | 4 |
| plugins.rs | 4 | 0 | 4 |
| honeypot.rs | 3 | 0 | 3 |
| alerting.rs | 3 | 0 | 3 |
| rule_feed.rs | 3 | 0 | 3 |
| serverless.rs | 3 | 0 | 3 |
| php.rs | 2 | 0 | 2 |
| **TOTAL** | **130** | **2** | **128** |

### Current Examples (Only 2)

From `src/admin/handlers/stats.rs:19,24`:
```rust
#[schema(example = 0.05)]
pub blocked_per_second: f64,

#[schema(example = 12.5)]
pub cpu_usage_percent: f32,
```

### Example Values by Type

For consistency, use these patterns:

| Field Type | Example Pattern | Example Value |
|------------|-----------------|---------------|
| `String` (ID) | `"<type>_<random>"` | `"site_abc123"`, `"node_xyz789"` |
| `String` (domain) | `"example.<TLD>"` | `"example.com"`, `"test.example.org"` |
| `String` (IP) | `"X.X.X.X"` | `"192.0.2.1"` (TEST-NET-1) |
| `u64` (count) | Realistic number | `150`, `1000`, `999999` |
| `u64` (timestamp) | Unix epoch | `1700000000` |
| `f64` (rate) | Decimal | `0.05`, `42.5` |
| `bool` | `true` or `false` | `true` |
| `Vec<String>` | Array | `json!(["example.com", "www.example.com"])` |
| `HashMap` | Object | `json!({"/": "/", "/api": "/api"})` |

### Concrete Examples for Tier 1 Schemas

#### SystemStats Example (`src/admin/handlers/stats.rs`)

```rust
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[schema(example = json!({
    "uptime_secs": 86400,
    "total_requests": 1500000,
    "requests_per_second": 42.5,
    "blocked_per_second": 0.05,
    "active_connections": 25,
    "memory_used_mb": 512,
    "memory_total_mb": 4096,
    "cpu_usage_percent": 12.5,
    "sites_loaded": 5,
    "healthy_backends": 8,
    "unhealthy_backends": 1,
    "blocked_total": 1234,
    "challenged_total": 5678,
    "proxied_total": 1499088,
    "errors_total": 100,
    "avg_latency_ms": 45.2,
    "p50_latency_ms": 32.1,
    "p95_latency_ms": 150.0,
    "p99_latency_ms": 500.0,
    "peak_concurrent": 150,
    "time_validation_errors": 0
}))]
pub struct SystemStats {
    pub uptime_secs: u64,
    pub total_requests: u64,
    // ... all fields
}
```

#### SiteInfo Example (`src/admin/handlers/sites.rs`)

```rust
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({
    "id": "example_com",
    "domains": ["example.com", "www.example.com"],
    "default_upstream": "upstream_main",
    "routes": {"/": "/", "/api": "/api"}
}))]
pub struct SiteInfo {
    pub id: String,
    pub domains: Vec<String>,
    pub default_upstream: String,
    pub routes: std::collections::HashMap<String, String>,
}
```

#### CreateSiteRequest Example

```rust
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "domains": ["newsite.example.com"],
    "default_upstream": "upstream_main"
}))]
pub struct CreateSiteRequest {
    pub domains: Vec<String>,
    pub default_upstream: String,
}
```

### utoipa Syntax Patterns

Based on [utoipa Schema derive documentation](https://docs.rs/utoipa/latest/utoipa/derive.Schema.html):

#### Pattern 1: Simple Numeric Examples
```rust
#[derive(ToSchema)]
pub struct SiteStats {
    #[schema(example = 42)]
    pub requests_per_second: f64,
    #[schema(example = 150)]
    pub blocked_requests: u64,
}
```

#### Pattern 2: String Examples
```rust
#[derive(ToSchema)]
pub struct SiteInfo {
    #[schema(example = "example.com-abc123")]
    pub id: String,
    #[schema(example = json!(["example.com", "www.example.com"]))]
    pub domains: Vec<String>,
}
```

#### Pattern 3: Object Examples with `json!` Macro
```rust
#[derive(ToSchema)]
#[schema(example = json!({
    "id": "site1",
    "domains": ["example.com"],
    "default_upstream": "upstream1",
    "routes": {"/": "/"}
}))]
pub struct SiteInfo {
    pub id: String,
    pub domains: Vec<String>,
    pub default_upstream: String,
    pub routes: std::collections::HashMap<String, String>,
}
```

#### Pattern 4: Array Examples
```rust
#[derive(ToSchema)]
#[schema(example = json!(["value1", "value2", "value3"]))]
pub struct VecOfStrings(pub Vec<String>);
```

#### Pattern 5: Enum Examples
```rust
#[derive(ToSchema)]
pub enum ThreatLevel {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
}

// Use #[schema(example = "high")] on the field
```

### Files to Modify

| File | Schemas to Update | Priority Order |
|------|------------------|----------------|
| `src/admin/handlers/mesh_admin.rs` | 17 | 1 |
| `src/admin/handlers/yara_rules.rs` | 14 | 2 |
| `src/admin/handlers/probes.rs` | 13 | 3 |
| `src/admin/handlers/sites.rs` | 10 | 4 |
| `src/admin/handlers/threat_level.rs` | 9 | 5 |
| `src/admin/handlers/system.rs` | 9 | 6 |
| `src/admin/handlers/config.rs` | 8 | 7 |
| `src/admin/handlers/logs.rs` | 7 | 8 |
| `src/admin/handlers/icmp.rs` | 7 | 9 |
| `src/admin/handlers/theme.rs` | 6 | 10 |
| `src/admin/handlers/tcp_udp.rs` | 5 | 11 |
| `src/admin/handlers/upstreams.rs` | 4 | 12 |
| `src/admin/handlers/plugins.rs` | 4 | 13 |
| `src/admin/handlers/honeypot.rs` | 3 | 14 |
| `src/admin/handlers/alerting.rs` | 3 | 15 |
| `src/admin/handlers/rule_feed.rs` | 3 | 16 |
| `src/admin/handlers/serverless.rs` | 3 | 17 |
| `src/admin/handlers/stats.rs` | 6 | 18 (add 4 more) |

### Implementation Details

**Step 1**: Add `use serde_json::json;` to handler files (if not already present)

**Step 2**: Add `#[schema(example = ...)]` to each struct field or use class-level `#[schema(example = json!(...))]`

**Step 3**: Run `cargo test --lib test_openapi` to verify OpenAPI spec generates correctly

**Step 4**: Optionally export spec with `--export-openapi` to verify JSON output

### Security Considerations

Examples should be **non-sensitive** values:
- Use `example.com`, `example.org` for domains
- Use generic IDs like `site1`, `node_abc123`
- Avoid real-looking IPs, credentials, or secrets
- Use placeholder values like `PLACEHOLDER_*`

### Effort Estimate

- **Time**: 4-6 hours for all 128 schemas
- **Scope**: 19 handler files
- **Testing**: Run existing OpenAPI tests + manual verification in Swagger UI

### Risk

- **Low**: Examples are purely documentation
- **Testing**: Existing tests verify structure; new examples won't break anything

---

## Issue 2: Request Body Schema Referencing ✅ PASS

### Finding

All **52 handlers** using `request_body = SomeStruct` have proper `#[derive(ToSchema)]` on their request types. No issues found.

### Verified Request Types

| Type | Location | Status |
|------|----------|--------|
| CreateSiteRequest | sites.rs:89 | ✅ ToSchema |
| UpdateSiteRequest | sites.rs:247 | ✅ ToSchema |
| UpdateMainConfigRequest | config.rs:52 | ✅ ToSchema |
| SetLogLevelRequest | config.rs:246 | ✅ ToSchema |
| BanIpRequest | mesh_admin.rs:110 | ✅ ToSchema |
| BanMeshIdRequest | mesh_admin.rs:118 | ✅ ToSchema |
| DeriveSigningKeyRequest | mesh_admin.rs:164 | ✅ ToSchema |
| All 24 Update*ConfigRequest | config.rs | ✅ ToSchema |
| 52 total request types | Various | ✅ All have ToSchema |

### Generated OpenAPI Output

`request_body = TypeName` generates:
```json
"requestBody": {
  "content": {
    "application/json": {
      "schema": { "$ref": "#/components/schemas/TypeName" }
    }
  }
}
```

### Recommendation

**No changes needed.** Continue following established pattern:
```rust
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewRequestType {
    pub field: String,
}

#[utoipa::path(
    post,
    path = "/api/path",
    request_body = NewRequestType,
    ...
)]
```

---

## Issue 3: Unused `health` Tag 🟡 MEDIUM

### Finding

The `health` tag is defined in `src/admin/openapi.rs:331` but **no handlers use it**. All 165 endpoints use other tags.

### Current Tag Definitions (lines 328-348)

```rust
tags(
    (name = "stats", description = "System statistics endpoints"),
    (name = "sites", description = "Site configuration management"),
    (name = "health", description = "Health check endpoints"),  // <-- UNUSED
    (name = "config", description = "Configuration management"),
    // ... 16 more tags
)
```

### Recommendation

**Option A**: Remove the unused `health` tag definition

**Option B**: Keep it for future health-check endpoints

### Decision: Health Tag

The `health` tag exists in the OpenAPI spec but no handlers use it. Two options:

**Option A: Remove the tag** (Recommended if no health endpoints planned)
- Simpler spec without dead code
- No future confusion

**Option B: Keep the tag** (Recommended if health endpoints are planned)
- Reserve the tag for future `/health`, `/ready`, `/live` endpoints
- Aligns with Kubernetes-style health checks

**Decision**: [ ] Remove  [ ] Keep

If kept, future endpoints would use:
```rust
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "OK"),
        (status = 503, description = "Unavailable")
    ),
    tag = "health"
)]
```

---

## Issue 4: operation_id ⚠️ LOW (OPTIONAL)

### Finding

None of the 165 handlers use `operation_id = "..."` in their `#[utoipa::path]` annotations. All rely on the default behavior (function name becomes operationId).

### Benefits of operation_id

| Use Case | Why operation_id Matters |
|----------|-------------------------|
| **SDK Generation** | Client SDK generators use operationId for method names |
| **Swagger UI** | Modern versions use operationId to call handlers |
| **Collision Prevention** | Prevents issues if same function name exists in different modules |
| **Stable Contracts** | Function names are internal; operationId is stable for consumers |

### Current Behavior vs with operation_id

| Aspect | Current (function name) | With operation_id |
|--------|-------------------------|-------------------|
| `list_sites` | `list_sites` | `listSites` (camelCase) |
| `get_site` | `get_site` | `getSite` |
| `create_site` | `create_site` | `createSite` |
| SDK method | `client.list_sites()` | `client.listSites()` |

### utoipa Syntax

```rust
#[utoipa::path(
    get,
    path = "/api/sites",
    operation_id = "listSites",  // camelCase recommended
    tag = "sites"
)]
pub async fn list_sites(...) -> ... { }
```

### Naming Convention (if implemented)

Recommended pattern: **camelCase** matching client SDK conventions:
- `listSites` (GET /api/sites)
- `getSite` (GET /api/sites/{site_id})
- `createSite` (POST /api/sites)
- `deleteSite` (DELETE /api/sites/{site_id})
- `updateSite` (PUT /api/sites/{site_id})

### Decision: operation_id

**Recommendation**: Skip unless external SDK generation is planned.

**Decision**: [ ] Skip (default)  [ ] Implement

If implemented, estimated time: 2-3 hours for all 165 handlers.

---

## Issue 5: Response Descriptions ✅ INTENTIONAL

### Finding

Response descriptions are intentionally minimal for WAF security hardening:
- "Unauthorized" instead of "Missing or invalid Bearer token"
- "Internal server error" instead of detailed error messages

### Rationale (from user)

Minimal error disclosure reduces information available to attackers doing reconnaissance on protected sites.

### Recommendation

**Keep as-is.** No changes recommended.

### Future Consideration

Could add a comment in the code explaining this is intentional:
```rust
#[utoipa::path(
    get,
    path = "/api/config",
    responses(
        (status = 401, description = "Unauthorized"),  // Minimal for security
        (status = 500, description = "Internal server error")  // No details
    ),
    // ...
)]
```

---

## Implementation Order

| # | Issue | Priority | Effort | Status |
|---|-------|----------|--------|--------|
| 1 | Schema Examples | HIGH | 4-6 hrs | **TODO** |
| 2 | Request Body Refs | N/A | - | No changes needed |
| 3 | Unused `health` tag | MEDIUM | 5 min | **DECISION PENDING** |
| 4 | operation_id | LOW | 2-3 hrs | **DECISION PENDING** |
| 5 | Response Descriptions | N/A | - | Keep as-is |

### Implementation Checklist

- [ ] **Schema Examples**: Add `#[schema(example = ...)]` to all schemas (128 total)
- [ ] **Health Tag**: [ ] Remove from spec  [ ] Keep for future
- [ ] **operation_id**: [ ] Skip  [ ] Implement for all handlers |

### Recommended First Steps

1. **Add schema examples** to high-value schemas first:
   - `SiteInfo`, `SiteDetail` (commonly used)
   - `SystemStats`, `SiteStats` (dashboard visible)
   - Request types (`CreateSiteRequest`, `UpdateSiteRequest`)

2. **Remove or keep `health` tag** based on future roadmap

3. **Decide on operation_id** based on SDK generation plans

---

## Testing Strategy

### Existing Tests to Run

```bash
cargo test --lib test_openapi
```

All 14 existing OpenAPI tests verify:
- Required fields (title, version, description)
- Paths exist
- Operations present
- Components schemas defined
- Tags defined
- Security scheme present

### New Tests to Add

```rust
#[test]
fn test_openapi_schemas_have_examples() {
    let openapi = MaluWafOpenApi::openapi();
    let components = openapi.components.expect("Components should exist");

    // At least 50% of schemas should have examples
    let total_schemas = components.schemas.len();
    // Note: utoipa doesn't expose example metadata in public API
    // This test would need manual verification or schema inspection
}
```

### Manual Verification

1. Start MaluWAF with admin API
2. Visit `http://localhost:8080/api/docs`
3. Click "OpenAPI JSON Specification"
4. Verify examples appear in Swagger UI

---

## Rollback Plan

| Change | Rollback Approach |
|--------|-------------------|
| Schema examples | Remove `#[schema(example = ...)]` annotations |
| Remove `health` tag | Re-add to `#[derive(OpenApi)]` tags list |
| Add operation_id | Remove `operation_id = "..."` from all handlers |

---

## Success Metrics

After implementation:

1. **Schema Examples**: 80%+ of schemas have example values
2. **Tag Consistency**: All tags in use, no undefined tags
3. **API Documentation**: Swagger UI shows meaningful example data
4. **Security**: Response descriptions remain minimal

---

## Dependencies

| Change | Depends On | Affected Files |
|--------|-----------|----------------|
| Schema examples | None | 19 handler files |
| Health tag | None | `openapi.rs` |
| operation_id | None | All handler files |

---

## Verification Steps

After implementation, verify the OpenAPI spec:

### 1. Run Existing Tests
```bash
cargo test --lib test_openapi
```
Expected: All 14 tests pass.

### 2. Verify Schema Count
```bash
# Build and export spec
cargo run -- --export-openapi > /tmp/openapi.json

# Check schema count
cat /tmp/openapi.json | jq '.components.schemas | length'
```
Expected: 130+ schemas.

### 3. Verify Examples Present
```bash
# Check if examples exist in spec
cat /tmp/openapi.json | jq '.components.schemas.SystemStats.example'
```
Expected: Example object is present.

### 4. Manual Verification (Optional)
1. Start MaluWAF: `cargo run --`
2. Visit `http://localhost:8080/api/docs`
3. Expand "Stats" → "GET /api/stats/summary"
4. Verify "Example Value" shows populated data

---

## Notes

- Security hardening (minimal error disclosure) is intentional - keep response descriptions minimal
- Examples should use non-sensitive placeholder values
- operation_id is optional - only needed if external SDK generation is planned
- The `health` tag is unused - decide whether to keep or remove based on roadmap
- The `health` tag is unused - decide whether to keep or remove based on roadmap