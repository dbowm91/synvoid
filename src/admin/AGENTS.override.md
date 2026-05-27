# Admin API Module - AGENTS.override.md

Specialized guidance for Admin API patterns.

## Security Patterns

### Constant-Time Comparison

Always use `subtle::ConstantTimeEq` for comparing secrets, tokens, keys, MACs:

**Location requiring constant-time comparison**:
- Session ID comparison (`src/admin/state.rs`)
- Cache purge token comparison

### Session Timing Normalization (2026-05-23)

Admin auth now includes timing normalization to prevent session enumeration attacks:

- Dummy bcrypt verify with minimum 200ms delay on invalid tokens
- Pattern: `verify_dummy_admin_token()` at `src/admin/handlers/auth.rs:14-22`
- Applied before both `UNAUTHORIZED` returns in `create_session()`

### Middleware Stack

The Admin API middleware stack (in order):
1. Client IP Extraction (`src/admin/middleware.rs:61-101`)
2. Auth Middleware (`src/admin/middleware.rs:103-183`)
3. CSRF Middleware (`src/admin/middleware.rs:185-266`)
4. Admin Rate Limit Layer (`src/admin/rate_limit.rs`)

**Note**: CORS implementation status:
- CORS layer IS implemented via `create_cors_layer()` at `src/admin/mod.rs:50-97`
- CORS is applied to outer router at line 806 in `build_router_from_state()` (`.layer(create_cors_layer(&admin_cors_config))`)
- Nested `/api` routes (lines 179-189) do NOT have CORS applied
- Since Admin API uses bearer/session tokens rather than browser-based cross-origin requests, this gap may be intentional
- BUG-CORS-1 was fixed by removing dead code (`let _cors_config = cfg.cors.clone()`) at `src/admin/mod.rs:860`

### CORS Configuration Bug (BUG-CORS-1 - P0)

`src/admin/mod.rs:860`:

```rust
let _cors_config = cfg.cors.clone();  // underscore = dropped!
```

**Problem**: The CORS config is cloned into `_cors_config`, but the underscore prefix means it is immediately dropped. The CORS layer is only applied to the outer router at line 806 in `build_router_from_state()`, but nested `/api` routes (lines 179-189) do NOT have CORS.

**Impact**: Even when `cfg.cors` is configured, CORS headers may not be properly applied to nested routes if they use a different router builder.

**Fix Direction**: Ensure `create_admin_router_with_state()` applies CORS layer consistently, or clarify whether CORS is intentionally not applied to nested routes.

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.