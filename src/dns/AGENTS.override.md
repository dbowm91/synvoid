# DNS Module - AGENTS.override.md

Specialized guidance for DNS server, DNSSEC, and TSIG.

## DNSSEC RFC 5011 Trust Anchor States

Keys transition through states: **Seen → Pending → Valid → Revoked → Removed → Missing**

Only keys that were **previously Valid** (`trust_point != 0`) can auto-restore via `observe_dnskey_at_root()`. Keys never Valid (`trust_point == 0`) must go through digest verification via `trust_anchor_check()`.

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
- DNS TSIG MAC verification (`src/dns/tsig.rs`)
- DNS cookie MAC verification (`src/dns/cookie.rs`)

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

## Known Integration Gaps

### DNS Cookie Server Not Wired (DNS-1 - P1)

`DnsCookieServer` is implemented at `src/dns/cookie.rs:11-50` with full RFC 8905/RFC 7873 support:
- `validate_cookie()` at lines 66-87
- `create_response_cookie()` at lines 89-118

The server is created at `src/dns/server/mod.rs:850` and passed to `QueryContext`, but **`validate_cookie()` is NEVER CALLED** in `src/dns/server/query.rs`.

**Fix needed**: Call `validate_cookie()` when `cookie_server.is_some()` and query contains EDNS cookie option. Set response cookies via `create_response_cookie()` in outgoing responses.

### Query Coalescer max_wait_ms Unused (DNS-2 - P2)

At `src/dns/query_coalesce.rs:117`, the parameter `_max_wait_ms` is marked as unused. The `get_or_wait()` method doesn't use this parameter to control broadcast timeout behavior.