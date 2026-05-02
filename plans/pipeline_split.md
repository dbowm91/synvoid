# HTTP Server Pipeline Split Analysis

**Status**: PLANNING
**File**: `src/http/server.rs` (~4561 lines)
**Reference**: ADR-004 (`docs/adr/ADR-004-module-split-pattern.md`)

## ADR-004 Summary

ADR-004 currently states:
- Large files like `http/server.rs` and `tls/server.rs` should NOT be split
- "Cohesive request pipelines" are better organized with section comments
- Splitting introduces risk without meaningful benefit since phases are sequential and interdependent

**Key quote**: "For these files, prefer section comments over refactoring for readability."

**The problem with this approach**: At 4561 lines, `http/server.rs` is difficult to audit for security and performance. Unrelated responsibilities accumulate (e.g., image poisoning, WebSocket handling, body collection, multiple backend dispatch types).

## Current Sections in `handle_request()`

| Section | Lines | Responsibility | Risk Level |
|---------|-------|---------------|------------|
| 1 | 649-664 | Connection limiting (semaphore acquire) | Low (stateful, wait) |
| 2 | 669-680 | IP extraction & sanitization | Medium |
| 3 | 689-715 | Internal endpoint handling (drain/health/ready) | Low (isolated) |
| 4 | 719-738 | Key exchange request handling (global nodes) | Medium (security-sensitive) |
| 4.5 | 741-768 | Mesh ownership challenge serving (HTTP-01) | Medium |
| 5 | 771-806 | Connection limiting (per-site) | Low (stateful) |
| 6 | 816-830 | Bandwidth limiting | Medium |
| 7 | 833-840 | WebSocket upgrade detection | Low (pure check) |
| 8 | 843-865 | Request parsing (headers, body extraction) | Medium |
| 9 | 869-988 | WAF early decision checks | High (security-critical) |
| 10 | 991-1112 | Body collection (with chunk-based WAF) | High (security-critical) |
| 11 | 1114-1176 | Honeypot & challenge asset handling | Medium |
| 12 | 1310-1435 | Routing & site resolution | Medium |
| 13 | 1439-1468 | WAF full request check | High (security-critical) |
| 14 | 1470-1669 | WAF decision handling | High (security-critical) |
| 15 | 1671-2580 | Backend dispatch (WebSocket, AppServer, AxumDynamic, Static, Serverless, Spin, FastCGI, PHP, CGI, Mesh) | High (complex) |

## Helper Functions

| Function | Lines | Responsibility | Extract Risk |
|----------|-------|---------------|--------------|
| `HttpServer::serve()` | 454-621 | Main listener loop | Do not move |
| `HttpServer::new()` + builders | 351-452 | Construction | Do not move |
| `HttpServer::handle_request()` | 624-3405 | Main handler (one giant fn) | Split internally |
| `HttpServer::inject_security_headers()` | 3407-3412 | Delegating wrapper | Medium |
| `HttpServer::apply_security_headers()` | 3414-3441 | Response header injection | Low |
| `HttpServer::handle_drain_request()` | 3444-3466 | Internal endpoint | Low |
| `HttpServer::handle_drain_status_request()` | 3468-3484 | Internal endpoint | Low |
| `HttpServer::handle_health_request()` | 3486-3529 | Internal endpoint | Low |
| `HttpServer::handle_ready_request()` | 3531-3574 | Internal endpoint | Low |
| `HttpServer::build_response_with_alt_svc()` | 3576-3590 | Response construction | Low |
| `HttpServer::build_response_with_cookie()` | 3592-3608 | Response construction | Low |
| `HttpServer::handle_websocket_tunnel()` | 3610-3821 | WebSocket tunnel handling | Medium (complex state) |
| `HttpServer::handle_websocket_to_appserver()` | 3823-4031 | WebSocket to AppServer | Medium |
| `HttpServer::is_websocket_upgrade()` | 4033-4035 | Delegating wrapper | Low |
| `HttpServer::compute_websocket_accept_key()` | 4037-4039 | Delegating wrapper | Low |
| `HttpServer::build_websocket_response()` | 4041-4066 | Response construction | Low |
| `HttpServer::handle_axum_dynamic_request()` | 4068-4103 | Plugin backend | Medium |
| `HttpServer::check_bandwidth_limit()` | 4105-4159 | Bandwidth limiting | Medium |
| `HttpServer::handle_key_exchange_request()` | 4161-4251 | Mesh key exchange | Medium |
| `HttpServer::apply_image_poisoning()` | 4253-4320 | Image transformation | Low |
| `HttpServer::collect_body_with_chunk_waf()` | 4322-4353 | Body collection | High |
| `HttpServer::send_request_log_if_enabled()` | 4355-4432 | Request logging | Low |

## Stateless Helpers (Safe to Extract First)

These helpers are pure/stateless and can be moved to sibling modules with low risk:

1. **`apply_security_headers()`** (3414-3441)
   - Pure function: takes builder, target, main_config, returns modified builder
   - No state captured
   - Can become a standalone function in `http/response_helpers.rs`

2. **`build_response_with_alt_svc()`** (3576-3590)
   - Delegates to `crate::http::response_builder::build_response_with_alt_svc`
   - Already a wrapper, low risk

3. **`build_response_with_cookie()`** (3592-3608)
   - Delegates to `crate::http::response_builder::build_response_with_cookie`
   - Already a wrapper, low risk

4. **`build_websocket_response()`** (4041-4066)
   - Pure response construction
   - Can move to `http/websocket_helpers.rs`

5. **`check_bandwidth_limit()`** (4105-4159)
   - Stateless check, returns None or Some(response)
   - Can become a standalone function

6. **`is_websocket_upgrade()`** (4033-4035) / **`compute_websocket_accept_key()`** (4037-4039)
   - Already delegating to `crate::http::headers` functions
   - Remove wrapper and use directly

## Stateful/Security-Sensitive (Wait)

These require more consideration:

1. **`handle_request()`** - The entire pipeline is stateful. Splitting requires careful refactoring to preserve request context.

2. **`collect_body_with_chunk_waf()`** - Security-critical, involves WAF interaction

3. **WebSocket handlers** - Complex state machines with concurrent bidirectional proxies

4. **Internal endpoint handlers** - Simple but depend on drain_state context

5. **Backend dispatch logic** - Multiple backend types with different protocols (FastCGI, PHP, CGI, AppServer, Serverless, Spin, Mesh, etc.)

## Recommended Split Order

### Phase 1: Response Construction Helpers (Lowest Risk)
Create `src/http/response_helpers.rs`:
- `apply_security_headers()` 
- `build_websocket_response()`

### Phase 2: Request Validation Helpers
Create `src/http/validation_helpers.rs`:
- `is_websocket_upgrade()` (use existing from headers module directly)
- `is_valid_http_request_start()`
- `is_tls_client_hello()`

### Phase 3: Internal Endpoint Handlers
Create `src/http/internal_handlers.rs`:
- `handle_drain_request()`
- `handle_drain_status_request()`
- `handle_health_request()`
- `handle_ready_request()`

### Phase 4: WebSocket Tunnel Handling
Create `src/http/websocket_tunnel.rs`:
- `handle_websocket_tunnel()`
- `handle_websocket_to_appserver()`
- Note: These are complex state machines, requires careful refactoring

### Phase 5: Image/Response Transformation
Create `src/http/response_transform_helpers.rs`:
- `apply_image_poisoning()`

### Phase 6: Body Collection
Create `src/http/body_collection.rs`:
- `collect_body_with_chunk_waf()`
- Note: Security-critical, requires thorough testing

### Phase 7: Backend Dispatch
Keep in main file but consider extracting each backend type to separate functions first before moving to a module.

## ADR-004 Amendment Recommendation

Replace the "Do NOT split" guidance with:

> Large files should be split when:
> - The module contains multiple distinct protocol/responsibility boundaries
> - The module is difficult to audit for security (approaching 2000+ lines)
> - Pure helper functions exist that do not depend on request context
> 
> Use sibling files (`foo_bar.rs`) not subdirectories. Keep the request pipeline in the parent module but extract coherent helper groups.

## Issues/Deferred Items

1. **`handle_request()`** is one giant async function (~2780 lines). Splitting this requires careful refactoring to pass context explicitly rather than relying on closure capture.

2. **Multiple backend dispatch types** in Section 15 are tightly coupled to the WAF decision and response transformation logic. Extracting them requires defining clear interfaces.

3. **Test coverage** for extracted modules needs to be added before moving code.

4. **Breaking change risk**: Even though we're preserving behavior, changing module structure could affect any external callers that depend on current imports.

5. **Circular dependency risk**: Need to verify extracted modules don't create circular deps with WAF, proxy, or router modules.