# Auth Module - AGENTS.override.md

Specialized guidance for authentication patterns.

## Security Patterns

### Constant-Time Comparison

Always use `subtle::ConstantTimeEq` for comparing secrets, tokens, keys, MACs:

```rust
use subtle::ConstantTimeEq;

// BEFORE (timing attack vulnerable)
let mut diff = 0u8;
for (a, b) in computed.iter().zip(original.iter()) {
    diff |= a ^ b;
}
if diff == 0 { ... }

// AFTER (constant-time)
if bool::from(computed.ct_eq(&original)) { ... }
```

**Locations requiring constant-time comparison**:
- CSRF token validation (`crates/synvoid-auth/src/lib.rs`; `src/auth/mod.rs` is a thin `pub use synvoid_auth::*;` facade)

Canonical implementation lives in `crates/synvoid-auth`. New code must import `synvoid_auth` directly; do not add domain logic under `src/auth/`.

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.