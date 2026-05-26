# DNS Module - AGENTS.override.md

Specialized guidance for DNS server, DNSSEC, and TSIG.

## DNSSEC RFC 5011 Trust Anchor States

Keys transition through states: **Valid → Seen → Pending → Revoked → Removed → Missing**

Only keys that were **previously Valid** (`trust_point != 0`) can auto-restore via `observe_dnskey_at_root()`. Keys never Valid (`trust_point == 0`) must go through digest verification via `trust_anchor_check()`.

## Security Patterns

### Constant-Time Comparison

Always use `subtle::ConstantTimeEq` for comparing secrets, tokens, keys, MACs:

**Locations requiring constant-time comparison**:
- DNS TSIG MAC verification (`src/dns/tsig.rs`) - already uses `ConstantTimeEq` at line 238
- DNS cookie MAC verification (`src/dns/cookie.rs`)

### NSEC3 SHA-1 Fallback

When NSEC3 encounters an unsupported algorithm, it logs a warning and falls back to SHA-1:

```rust
tracing::warn!(
    "Unsupported NSEC3 algorithm {}, falling back to SHA-1",
    config.algorithm
);
```

This is informational - the fallback is RFC-compliant but may indicate a need to upgrade NSEC3 algorithm support.

### Cookie Validation Toggle (API Note)

The `with_validation(_enable: bool)` method in `src/dns/cookie.rs:40-42` ignores the enable parameter - cookie validation is always enabled. This is an intentional API design.

### Edge Node PoW Authentication

Edge nodes must provide BOTH `pow_nonce` AND `pow_public_key`:

```rust
if let (Some(nonce), Some(pk)) = (pow_nonce, pow_public_key) {
    validate_edge_node_pow(pubkey, nonce)?;
} else {
    return Err("Edge node did not provide PoW nonce and public key - PoW is required");
}
```

### File Permissions for Private Keys

Always set restrictive permissions on private key files:

```rust
use std::fs;
use std::os::unix::fs::PermissionsExt;

let temp_path = path.with_extension("tmp");
fs::write(&temp_path, &key_data)?;
fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
fs::rename(&temp_path, path)?;
```