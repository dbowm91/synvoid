# Admin API Module - AGENTS.override.md

Specialized guidance for Admin API patterns.

## Security Patterns

### Constant-Time Comparison

Always use `subtle::ConstantTimeEq` for comparing secrets, tokens, keys, MACs:

**Location requiring constant-time comparison**:
- Session ID comparison (`src/admin/state.rs`)

### CSRF Token Validation

See `src/auth/mod.rs` for CSRF token validation patterns.

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.