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

## Known Integration Gaps (Fixed)

### DNS Cookie Server Wiring (DNS-1 - FIXED 2026-05-27)

`DnsCookieServer` is now wired into query validation at `src/dns/server/query.rs:640-658`:

```rust
let mut cookie_valid = false;
let mut cookie_absent = false;
let client_ip_for_log = client_ip.unwrap_or(IpAddr::from([127, 0, 0, 1]));
if let (Some(cs), Some(edns)) = (ctx.cookie_server, &edns_options) {
    if let Some(ref cookie) = edns.cookie {
        if cookie.server_cookie.is_some() {
            cookie_valid = cs.validate_cookie(client_ip_for_log, &cookie.client_cookie, cookie.server_cookie.as_ref().unwrap());
        } else {
            cookie_absent = true;
        }
    } else {
        cookie_absent = true;
    }
    if !cookie_valid && !cookie_absent {
        tracing::debug!("Invalid DNS cookie from {}", client_ip_for_log);
    }
}
```

Cookie validation follows RFC 7873 pattern using constant-time comparison from `validate_cookie()`.

### Query Coalescer max_wait_ms Unused (DNS-2 - P2)

At `src/dns/query_coalesce.rs:117`, the parameter `_max_wait_ms` is marked as unused. The `get_or_wait()` method doesn't use this parameter to control broadcast timeout behavior.
