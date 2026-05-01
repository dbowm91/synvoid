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
- CSRF token validation (`src/auth/mod.rs`)

## Skills Reference

See `skills/admin_api.md` for Admin API patterns.