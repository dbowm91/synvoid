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

## DNSSEC Validation by Provider Type

### Recursive Resolver (HickoryRecursor) - DNSSEC Enabled

When `enable_dnssec=true` and `upstream_provider = "Recursive"`:

```rust
// src/dns/resolver.rs:693-702
let dnssec_policy = if enable_dnssec {
    let trust_anchors = Self::build_trust_anchors(trust_anchor_path, trust_anchor_manager.as_ref());
    let mut config = hickory_resolver::recursor::DnssecConfig::default();
    config.trust_anchor = Some(std::sync::Arc::new(trust_anchors));
    hickory_resolver::recursor::DnssecPolicy::ValidateWithStaticKey(config)
} else {
    hickory_resolver::recursor::DnssecPolicy::SecurityUnaware
};
```

HickoryRecursor correctly uses `ValidateWithStaticKey` when DNSSEC is enabled, performing actual DNSSEC validation.

### Forwarder Resolver (HickoryResolver) - DNSSEC Disabled by Design

**Important**: Forwarder mode (Google/Cloudflare/System/Custom) does NOT perform DNSSEC validation. This is by design, not a bug:

- Google (8.8.8.8) and Cloudflare (1.1.1.1) are stub resolvers that forward queries
- They do their own DNSSEC validation internally
- We cannot re-validate their chain-of-trust without becoming a true recursive resolver
- The `is_dnssec_validated: false` in forwarder mode reflects this limitation

**To get DNSSEC validation**, use `upstream_provider = "Recursive"` with `dnssec_validation = true`.

See `skills/dns_dnssec.md:130-146` for detailed explanation.

## Known Integration Points

### DNS Cookie Server Wiring (FIXED 2026-05-27)

`DnsCookieServer` is wired into query validation at `src/dns/server/query.rs:640-658`:

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

### Query Coalescer max_wait_ms (DNS-QUERY - ✅ FIXED 2026-05-27)

The `max_wait_ms` parameter is now used. At `src/dns/query_coalesce.rs`:
- Added `max_wait: Duration` field to `QueryCoalescer` struct
- Changed `get_or_wait()` from sync to async fn
- Uses `tokio::time::timeout(max_wait, receiver.recv())` instead of non-blocking `try_recv()`
- Callers updated to use `.await`

## Verified Fixes (2026-05-27)

| Bug ID | Issue | Status |
|--------|-------|--------|
| BUG-DNS-1 | HickoryRecursor DNSSEC policy SecurityUnaware | ✅ FIXED - now uses ValidateWithStaticKey |
| BUG-DNS-4 | HickoryResolver always false | ✅ DONE - by design (hickory-resolver API limitation) |