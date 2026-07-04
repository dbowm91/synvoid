# DNS Module - AGENTS.override.md

Specialized guidance for DNS server, DNSSEC, and TSIG.

## Milestone 2 Phase 1 Workstream

M2 Phase 1 hardened the DNS transport lifecycle and protocol behavior. Key invariants:

### Bind Fail-Fast (`server/startup.rs`)
- `configured_bind_addr()` validates address and port at startup
- Returns `Err` immediately on invalid address or port zero
- No silent fallback to `0.0.0.0`

### TCP One-Query-Per-Connection (`server/query.rs`)
- RFC 7766 §4 semantics: read one length-prefixed message, respond, close
- AXFR/IXFR is the exception (multi-message over same connection)
- Persistent TCP (pipelining) is **deferred** to future milestone

### UDP/EDNS Truncation (`server/response.rs`)
- `build_truncated_tc_response()`: TC=1, RCODE=0, question echoed
- EDNS payload size from OPT CLASS field; default 1232 if unreadable
- Clients should retry over TCP

### TCP Hard-Limit SERVFAIL (`server/query.rs:390-479`)
- Response exceeds `max_response_size` → SERVFAIL with echoed question
- RA=0, AD=0, RD echoed, RCODE=2
- SERVFAIL itself validated to fit within hard limit

### Shutdown (`server/startup.rs`)
- `shutdown_runtime()` is idempotent — safe to call multiple times
- Three channels: `shutdown_tx` (UDP), `shutdown_watcher_tx` (coalescer), `connection_limits.initiate_graceful_shutdown()` (TCP)
- Sockets dropped on task exit for port reuse
- Fire-and-forget tasks (key rotation, recursive server, coalescer cleanup) exit via shutdown channels or runtime drop

### Transport Class (`cache.rs`)
- `TransportClass` enum: `Udp512`, `UdpEdns(u16)`, `Tcp`, `Http`, `Quic`
- Separates cache and coalescing keys by transport type
- Prevents cross-contamination of wire-format responses

## Test Patterns

```bash
# Transport class separation (cache keys differ by transport)
cargo test -p synvoid-dns -- transport

# Transport lifecycle (bind, startup, shutdown ordering)
cargo test -p synvoid-dns -- transport_lifecycle

# Bind fail-fast (invalid address, port zero)
cargo test -p synvoid-dns -- configured_bind_addr

# Shutdown idempotency
cargo test -p synvoid-dns -- shutdown_runtime

# TCP hard-limit SERVFAIL
cargo test -p synvoid-dns -- tcp_hard_limit

# SERVFAIL response behavior (question echo, RD bit, RA/AD semantics)
cargo test -p synvoid-dns -- servfail_response

# UDP/EDNS truncation (TC bit, question echoed)
cargo test -p synvoid-dns -- truncation
```

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
- DNS TSIG MAC verification (`crates/synvoid-dns/src/tsig.rs`)
- DNS cookie MAC verification (`crates/synvoid-dns/src/cookie.rs`)

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
// crates/synvoid-dns/src/resolver.rs:693-702
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

`DnsCookieServer` is wired into query validation at `crates/synvoid-dns/src/server/query.rs:640-658`:

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

The `max_wait_ms` parameter is now used. At `crates/synvoid-dns/src/query_coalesce.rs`:
- Added `max_wait: Duration` field to `QueryCoalescer` struct
- Changed `get_or_wait()` from sync to async fn
- Uses `tokio::time::timeout(max_wait, receiver.recv())` instead of non-blocking `try_recv()`
- Callers updated to use `.await`

## Verified Fixes (2026-05-27)

| Bug ID | Issue | Status |
|--------|-------|--------|
| BUG-DNS-1 | HickoryRecursor DNSSEC policy SecurityUnaware | ✅ FIXED - now uses ValidateWithStaticKey |
| BUG-DNS-4 | HickoryResolver always false | ✅ DONE - by design (hickory-resolver API limitation) |

## Milestone 2 Phase 4: Query Coalescing Policy Closure (2026-06-09)

### QueryKey Alignment
- Removed `edns_udp_size: u16` from `QueryKey` — redundant with `TransportClass::UdpEdns(u16)`
- Added `namespace: CacheNamespace` field — separates authoritative vs recursive coalescing scope
- Key is now 7-dimensional: `name`, `qtype`, `qclass`, `dnssec_ok`, `client_ip`, `transport_class`, `namespace`

### Metrics Correction
- 7 monotonic statics changed from `Gauge`/`metrics::gauge!` to `Counter`/`metrics::counter!`: hits, misses, evictions, timeouts, lagged, broadcasts, cancels
- `COALESCER_IN_FLIGHT` remains a `Gauge` (correct — it tracks current count, not cumulative)

### Exclusions
- AXFR (qtype 252), IXFR (qtype 251), NOTIFY (opcode 4), UPDATE (opcode 5) bypass coalescing entirely
- Malformed queries that fail key parsing return `None` and bypass coalescing