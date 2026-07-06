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

# DNSSEC live signing (Ed25519 roundtrip, RRSIG construction, NSEC chain)
cargo test -p synvoid-dns --test dnssec_live_signing

# TSIG success fixtures (sign+verify roundtrips, multi-key, add/remove)
cargo test -p synvoid-dns --test tsig_success_fixtures

# IXFR record-by-record delta validation
cargo test -p synvoid-dns --test ixfr_record_delta

# UPDATE atomicity and rollback proof
cargo test -p synvoid-dns --test update_atomicity_rollback

# NOTIFY scheduling and cache invalidation semantics
cargo test -p synvoid-dns --test notify_scheduling_semantics

# Control-plane cache/coalescing exclusion completion
cargo test -p synvoid-dns --test control_plane_cache_completion
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

## Milestone 2 Phase 5: Verification & Release Gate (2026-07-04)

### Gate Results

| Gate | Status | Notes |
|------|--------|-------|
| Compile and test baseline | PASS | 576 tests pass, fmt clean, workspace compiles |
| Deleted duplicate DNS tree | PASS | `src/dns/` is re-export shim only; canonical in `crates/synvoid-dns/` |
| Config-runtime matrix | PASS | Summary stats updated; internal contradictions fixed |
| Transport/runtime behavior | PASS | All 8 behaviors tested |
| Cache behavior | PASS | All 9 behaviors tested |
| Coalescing behavior | PASS | 47 tests covering key dimensions and lifecycle |
| Recursive isolation | PASS | 31 tests covering open-resolver prevention and NOTIMP |
| Documentation | PASS | All docs updated |

### Corrections Applied

1. **Config matrix summary**: Updated from ~110 to ~170 total fields (tables grew but summary was stale).
2. **Deferred features table**: Removed `query_timeout_secs` and `default_ttl` (they are implemented per Phase 2).
3. **Formatting**: `query_coalesce.rs` reformatted (long macro lines).

### Known Limitations

- DoT/DoH/DoQ fields (28) wired but untested
- Rate limiter fields (9) wired but untested
- Firewall fields (3 security controls) wired but untested
- DoQ `bind_address` partially implemented (hardcoded to 0.0.0.0)
- Full DNSSEC production validation deferred
- RPZ, Trust Anchors, Prefetch, Anycast, Padding, QNAME Privacy deferred

## Milestone 3 Phase 1: Zone Lifecycle & Hardening

### Zone Lifecycle State Machine

`ZoneState` (`server/mod.rs:245`) governs which operations are permitted per zone. Transitions are enforced by `Zone::set_state()` — invalid transitions return `Err`.

```
                 ┌──────────┐
       ┌────────►│ Loading  │◄────────┐
       │         └────┬─────┘         │
       │              │               │
       │         success          reload
       │              │               │
       │              ▼               │
       │         ┌─────────┐         │
       │         │ Active  │────┐    │
       │         └────┬────┘    │    │
       │              │         │    │
       │     ┌────────┼────┐    │    │
       │     │        │    │    │    │
       │  disable   reload│  delete  │
       │     │        │    │    │    │
       │     ▼        ▼    │    ▼    │
       │ ┌──────────┐│  ┌────────┐│  │
       │ │ Disabled ││  │Failed  ││  │
       │ └────┬─────┘│  └───┬────┘│  │
       │      │       │      │     │  │
       │   enable   error  retry   │  │
       │      │       │      │     │  │
       │      └───────┘      └─────┘  │
       │                              │
       └──────── Deleting ────────────┘
```

**Valid transitions:**
- `Loading → Active` (success), `Loading → Failed` (error)
- `Active → Reloading`, `Active → Disabled`, `Active → Deleting`, `Active → Failed`
- `Reloading → Active` (success), `Reloading → Failed` (error)
- `Disabled → Active` (re-enable), `Disabled → Deleting`
- `Failed → Loading` (retry), `Failed → Deleting`, `Failed → Disabled`
- `Deleting → Loading` (re-create after delete)

### Zone Health Metadata

`ZoneHealth` (`server/mod.rs:275`) tracks per-zone operational state:
- `state`: Current `ZoneState`
- `last_load_time`: Unix timestamp of last successful load
- `last_error`: Error message if state is `Failed`
- `record_count`: Number of resource records
- `dnssec_state`: `Unsigned | KeyGeneration | Signed | KeyRollover | SigningFailed`

`Zone::is_serving()` returns `true` only when `state == Active`.

### SOA Validation

- `Zone::validate_single_soa()` (`server/mod.rs:511`) — exactly 1 SOA at apex (RFC 1035 §3.3.13)
- `Zone::count_apex_soa()` counts SOA records matching normalized origin
- `Zone::normalize_origin()` trims trailing dots and lowercases
- Missing SOA at query time → SERVFAIL (fail-closed)

### Serial Correctness

- `Zone::serial_is_more_recent(s1, s2)` — RFC 1982 comparison with wrap-around at 0x80000000
- `Zone::increment_serial_rfc1982(current)` — uses timestamp when possible, else `wrapping_add(1)`
- `Zone::increment_serial_with_limit(max_history)` — caps `ZoneHistory` at `max_history` entries
- Default history limit: 200 entries

### Dynamic UPDATE Hardening (`update.rs`)

- Disabled by default (`enabled: false`) → returns NOTIMP when disabled
- TSIG authentication required by default (`require_tsig: true`)
- IP allowlist enforcement (`allowed_ips` supports CIDR notation)
- Per-update metrics via `DnsMetrics`
- Audit-safe logging: MAC values never logged

### NOTIFY Hardening (`notify.rs`)

- Disabled by default (`enabled: false`) → returns NOTIMP when disabled
- Per-zone serial check: skips NOTIFY if serial unchanged
- Source allowlist: unknown sources silently ignored
- TSIG enforcement optional

### AXFR Hardening (`transfer.rs`)

- **Disabled by default** (`axfr_enabled: false`) — security-sensitive
- **TCP-only** (`tcp_only: true`) — RFC 5936 §2
- TSIG authentication required by default
- Wildcard `*` in allowlist requires explicit `allow_wildcard_transfer: true`
- SOA bracketing validation (AXFR must begin/end with SOA)

### IXFR Correctness (`transfer.rs`)

- History retention: `max_history_size` (default 200)
- Fallback to AXFR when history insufficient (`ixfr_fallback_to_axfr: true`)
- RFC 1982 serial comparison for delta applicability

### Store Persistence (`store.rs`)

- SQLite-backed with atomic transactions
- Volatile mode: `ZoneStore::new_volatile()` — in-memory only
- Corrupt records: graceful skip with logging

### Cache Invalidation Reasons (11)

`InvalidationReason` enum (`cache.rs:18`) tracks per-reason counters:
- `ZoneLoad`, `ZoneLoadFromStore`, `RecordAdd`, `ZoneDelete`, `DynamicUpdate`, `NotifyReceived`, `ManualFlush`, `DnssecKeyRollover`, `RpzZoneRemoval`, `ZoneTransferAxfr`, `ZoneTransferIxfr`

All 12 invalidation call sites pass typed reasons. Per-reason Prometheus counters via `invalidations_by_reason`.

### Test Commands

```bash
cargo test -p synvoid-dns -- zone_lifecycle
cargo test -p synvoid-dns -- zone_health
cargo test -p synvoid-dns -- validate_single_soa
cargo test -p synvoid-dns -- normalize_origin
cargo test -p synvoid-dns -- serial_rfc1982
cargo test -p synvoid-dns -- update_metrics
cargo test -p synvoid-dns -- update_max_size
cargo test -p synvoid-dns -- notify_rate_limit
cargo test -p synvoid-dns -- notify_source_allowlist
cargo test -p synvoid-dns -- axfr_tcp_only
cargo test -p synvoid-dns -- axfr_disabled_by_default
cargo test -p synvoid-dns -- ixfr_history
cargo test -p synvoid-dns -- store_volatile
cargo test -p synvoid-dns -- store_atomic_write
cargo test -p synvoid-dns -- cache_invalidation_axfr
```

## Milestone 3 Corrective Semantics Pass

### Production Helpers

- **`Zone::validate_zone_for_activation()`** (`server/mod.rs`): Unified pre-publish gate. Enforces: exactly one apex SOA, non-empty/normalized/printable origin (rejects control chars, NUL, whitespace, `/`, `\`). All production code paths (config load, store reload, dynamic UPDATE, zone transfer) MUST pass this gate before a zone becomes `Active`.
- **`DnsServer::replace_zone_with_validation(candidate: Zone)`** (`server/zone.rs`): Atomic replacement API for production-safe reload. Calls `validate_zone_for_activation()`, marks active, inserts into `ShardedZoneStore`, invalidates cache. On failure, the previous zone in the store is left untouched. `load_zones` and `load_zones_from_store` now call `validate_zone_for_activation()` (was just `validate_single_soa()`).

## Milestone 3 Tightening Follow-up: Deepened Zone Validation

### `ZoneValidationError` Variants

`validate_zone_for_activation()` returns `ZoneValidationError` (defined in `server/mod.rs:116`) with these variants:

| Variant | Description |
|---------|-------------|
| `EmptyOrigin { raw }` | Origin is empty after normalization |
| `IllegalOriginCharacters { origin }` | Origin contains control chars (≤0x20), NUL, `/`, or `\` |
| `NoSoaRecord` | Zone has zero apex SOA records |
| `MultipleSoaRecords { count }` | Zone has more than one apex SOA |
| `OwnerLabelTooLong { name, len }` | Owner name label exceeds 63 bytes |
| `EmptyInteriorLabel { name }` | Owner name contains empty interior label (consecutive dots) |
| `NameOutsideZone { name, zone }` | Owner name is not a subdomain of the zone origin and not a relative label |
| `UnsupportedNullRecord { name }` | Record type NULL (`Other`) not permitted |
| `InvalidTtl { name, ttl }` | TTL is 0 or exceeds 2^31-1 |
| `MxPriorityOutOfRange { name, priority }` | MX priority exceeds u16::MAX |
| `SrvPriorityOutOfRange { name, priority }` | SRV priority exceeds u16::MAX |
| `InvalidSoaField { name, field, value }` | SOA numeric field (serial, refresh, retry, expire, minimum) is not parseable as u32 |
| `SoaTooFewFields { name, count }` | SOA rdata has fewer than 7 whitespace-delimited fields |
| `InvalidARecordAddress { name, value }` | A record value does not parse as Ipv4Addr |
| `InvalidAaaaRecordAddress { name, value }` | AAAA record value does not parse as Ipv6Addr |
| `CnameCoexistsWithOtherData { name, conflicting }` | CNAME coexists with A/AAAA/MX/TXT/SRV/PTR/NS/SOA/CAA/TLSA/SVCB/HTTPS/NAPTR/SSHFP at same owner |
| `InvalidTargetName { name, record_type, target }` | NS/MX/CNAME/SRV target name has empty labels or labels exceeding 63 bytes |

### CNAME Exclusivity Rules

When an owner has a CNAME record, it cannot coexist with any of: A, AAAA, MX, TXT, SRV, PTR, NS, SOA, CAA, TLSA, SVCB, HTTPS, NAPTR, SSHFP. DNSSEC types (DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM) are exempt from this check.

### SOA Field Validation

`validate_soa_record_value()` (`server/mod.rs:688`) validates that the SOA rdata has at least 7 whitespace-delimited fields and that the serial, refresh, retry, expire, and minimum fields all parse as u32.

### Test Commands

```bash
# Zone validation error variants
cargo test -p synvoid-dns -- validate_zone_for_activation
cargo test -p synvoid-dns -- invalid_a_record_rejected
cargo test -p synvoid-dns -- invalid_aaaa_record_rejected
cargo test -p synvoid-dns -- invalid_owner_label_rejected
cargo test -p synvoid-dns -- cname_coexists_with_other_data
cargo test -p synvoid-dns -- unsupported_null_record_rejected
cargo test -p synvoid-dns -- mx_priority_out_of_range
cargo test -p synvoid-dns -- srv_priority_out_of_range
cargo test -p synvoid-dns -- name_outside_zone
cargo test -p synvoid-dns -- invalid_ttl_rejected
cargo test -p synvoid-dns -- soa_field_validation
cargo test -p synvoid-dns -- target_name_validation
```

### Dynamic UPDATE Re-Validation

Dynamic UPDATE re-validates post-mutation invariants. If a crafted UPDATE removes the final SOA or creates a duplicate SOA, it is refused with RCODE NOTAUTH (RCODE 9). State is not committed on failure.

### New Test Files

- **`tests/control_plane_authorization.rs`** (10 tests): Deny-by-default UPDATE/NOTIFY/AXFR/IXFR behavior. Tests: `update_disabled_by_default_refuses_mutation`, `update_malformed_message_does_not_mutate_zone`, `update_enabled_invalid_zone_returns_error_rcode`, `notify_disabled_by_default_refused`, `notify_unknown_source_ignored`, `axfr_denied_by_default_returns_no_zone_data`, `ixfr_denied_by_default_returns_no_data`, `axfr_query_type_is_252_and_ixfr_query_type_is_251`, `transfer_disabled_when_axfr_enabled_false`, `axfr_allowed_client_gets_soa_bracketed_transfer`.
- **`tests/verification_gate.rs`** (strengthened, ~40 tests): Replaced documentation-grade tests with behavior tests: `successful_reload_swaps_zone_atomically`, `failed_reload_preserves_previous_active_zone`, `validate_zone_for_activation_rejects_duplicate_soa`, `validate_zone_for_activation_rejects_bad_origin`, `successful_reload_invalidates_cache_for_zone`. Plus 15 protocol-semantics tests across gates 7/8/9 (DNSSEC flags, RRSIG validity window, DS digest lengths, recursive safety config invariants, ECS default, encrypted transport cache isolation).

### Tightening Follow-up Test Files (Milestone 3 Tightening)

- **`tests/axfr_ixfr_transfer_semantics.rs`** (~650 lines): AXFR/IXFR response assertions — SOA-bracketed transfer validation, TCP-only enforcement, require-TSIG refusal, unauthorized client refusal, unknown zone refusal, IXFR current-serial no-op, older-serial ordered deltas, too-old serial fallback/refusal, serial wraparound comparison, malformed IXFR SOA rejection.
- **`tests/notify_behavior.rs`** (~233 lines): NOTIFY behavior — authorized newer serial accepted, stale serial ignored, unknown zone refused, unauthorized source refused, require-TSIG absent refused.
- **`tests/update_authorized_semantics.rs`** (~437 lines): UPDATE authorized semantics — add/delete record success, prerequisite NXRRSET/YXRRSET failure, final SOA deletion refusal, duplicate SOA add refusal, invalid record value refusal, TSIG-required absent refusal, successful update cache invalidation, serial policy.
- **`tests/dnssec_known_vectors.rs`** (~430 lines): DNSSEC known-vector verification — key tag for Ed25519 KSK/ZSK and RSA (RFC 4034 §A.2), DS digest length enforcement (SHA-1=20, SHA-256=32, SHA-384=48), canonical name/rdata for A/AAAA/CNAME/MX, response shape verification (AD/CD/RA/DO flag encoding, NXDOMAIN), DNSKEY canonical format.
- **`tests/control_plane_exclusion.rs`** (~746 lines): Cache/coalescing exclusion proof — AXFR/IXFR/UPDATE/NOTIFY bypass query cache and coalescer, successful UPDATE invalidates cache, failed update does not invalidate cache, cache invalidation on record creation/deletion.

### CI Changes

The `dns-tests` job in `.github/workflows/ci.yml` now also runs:
- `cargo test -p synvoid-dns --test encrypted_transport --release`
- `cargo test -p synvoid-dns --test verification_gate --release`
- `cargo test -p synvoid-dns --test control_plane_authorization --release`
- `cargo check -p synvoid-dns --all-features`

### Deferred / Known Limitations

- DoQ is wired but not production-validated; ALPN/quinn adapter is tested in unit tests only.
- Persistent DNS-over-TCP (pipelining) remains deferred.
- EDNS keepalive remains parsed-only.
- Full NSEC3 closest-encloser proofs remain deferred.
- External DNSSEC tooling (dig, ldns-verify-zone, named-checkzone) is not in CI.
- Bailiwick checks are observability-only (not enforced).

### Test Commands

```bash
cargo test -p synvoid-dns --test control_plane_authorization
cargo test -p synvoid-dns --test verification_gate
cargo test -p synvoid-dns --test encrypted_transport
cargo check -p synvoid-dns --all-features
```

## Milestone 3 Phase 4: Recursive Resolver Isolation (2026-07-05)

### Client ACL (`RecursiveClientAcl`)

CIDR-based client access control on the recursive server:

- **Config**: `dns.recursive.client_acl.allowed_clients` (Vec of CIDR strings) + `action` ("reject" or "allow")
- **Behavior**: Empty `allowed_clients` = allow all (open). When populated, each client IP is checked against CIDRs.
  - `action = "reject"`: matching clients are REFUSED, non-matching are allowed
  - `action = "allow"`: matching clients are allowed, non-matching are REFUSED
- **Check point**: Applied in `handle_packet()` and `handle_tcp_connection()` before rate limiter
- **Response**: RCODE_REFUSED via `build_error_response()`
- **IPv6**: Full CIDR support via `ipnetwork` crate

### Circuit Breaker

Per-upstream failure tracking with automatic recovery:

- **Config**: `failure_threshold` (default 5), `recovery_timeout_secs` (default 30), `success_threshold` (default 2)
- **State machine**: Closed → Open (after N failures) → Half-Open (after timeout) → Closed (after M successes)
- **Atomic**: `CircuitBreaker` uses atomics (Send+Sync), no mutex needed
- **Effect**: When open, `resolve_upstream()` returns `CircuitBreakerOpen` immediately (no upstream query)

### CNAME Depth Limit

Prevents CNAME loops and deep chains:

- **Config**: `max_cname_depth` (default 10, 0 = unlimited)
- **Check point**: `resolve_query_with_depth()` increments depth on each CNAME resolution
- **Response**: SERVFAIL when depth exceeded

### Recursion Depth Limit

Limits NS referral depth:

- **Config**: `max_recursion_depth` (default 16, 0 = unlimited)
- **Check point**: `resolve_query_with_depth()` tracks referral depth alongside CNAME depth

### Per-Client Outstanding Query Limit

Prevents single-client DoS:

- **Config**: `max_per_client_queries` (default 100, 0 = unlimited)
- **Implementation**: Per-IP `Semaphore` in `client_semaphores: Arc<Mutex<HashMap<IpAddr, Arc<Semaphore>>>>`
- **Timeout**: 1s acquire timeout — returns REFUSED if limit reached

### CD Bit + AD Gating

DNSSEC checking-disabled and authentic-data handling:

- **CD bit**: When CD=1 from client, `effective_dnssec_validated = false` (skip validation). CD echoed in response.
- **AD bit**: Gated on DO bit: `authentic_data = effective_dnssec_validated && dnssec_ok`. AD only set when client supports DNSSEC (DO=1).
- **Wire**: `checking_disabled` field added to `MessageFlags` in `wire.rs`

### Cache DNSSEC Validation State

`RecursiveCacheKey` now includes `dnssec_ok` dimension. `PositiveCacheEntry` uses `DnssecValidationState` enum (Secure/Insecure/Bogus/Unchecked) instead of boolean.

### Bailiwick Validation (Observability Only)

Authority and additional section bailiwick checks:

- `is_in_bailiwick(name, zone_origin)` — checks descendant relationship
- `validate_authority_bailiwick()` — all NS records must be in-bailiwick
- `validate_additional_bailiwick()` — glue records must be in-bailiwick of at least one NS
- **Effect**: Observability only (`log::warn!` + `bailiwick_violations` metric counter)

### ECS Forwarding Policy

Configurable EDNS Client Subnet forwarding:

- **Policies**: `Never` (default), `Always`, `CdnOnly`, `IfPresent`
- **Prefix truncation**: `truncate_ecs_prefix()` caps prefix length per address family
- **Config**: `dns.recursive.ecs.*` fields

### Routing Metrics

5 new counters in `DnsMetrics`: `recursive_queries`, `recursive_cache_hits`, `recursive_cache_misses`, `recursive_upstream_forwards`, `recursive_upstream_failures`

### Test Commands

```bash
# Recursive isolation (all Phase 4 workstreams)
cargo test -p synvoid-dns --test dns_recursive_isolation

# Recursive cache (DNSSEC validation state, DO bit separation)
cargo test -p synvoid-dns -- recursive_cache

# Full recursive DNS test suite
cargo test -p synvoid-dns --release
```

## Milestone 3 Final Validation Hardening (2026-07-06)

### New Integration Test Files (6)

- **`tests/dnssec_live_signing.rs`** (10 tests): Ed25519 live signing roundtrip, RRSIG construction (type_covered/algorithm/labels/original_ttl/sig_expiration>sig_inception/key_tag/signer_name/embedded_signature), NSEC wire format + type bitmap + chain construction, DNSKEY RDATA computation, DS digest determinism, key tag properties, canonical name/rdata (Option<u32> params). Validates that signing produces wire-correct output.
- **`tests/tsig_success_fixtures.rs`** (19 tests): SHA-256/512/1/384 sign+verify roundtrips, two keys coexist, add_key at runtime, remove_key, UnknownKey error, empty verifier, error codes (BADTIME=15), different algorithms produce different RDATA lengths, key name embedded in RDATA (raw bytes + null, NOT wire format). Validates TSIG success paths end-to-end.
- **`tests/ixfr_record_delta.rs`** (7 tests): Single add/delete/modification/multi-record IXFR deltas (record-by-record verification), RFC 1982 serial comparison, current serial SOA-only, disabled error. Modification test uses structural assertions (2 messages, SOA-bracketed, total answers ≥3). Validates IXFR delta builder correctness.
- **`tests/update_atomicity_rollback.rs`** (13 tests): Atomic add/delete, prerequisite failures (NXRRSET/YXRRSET), SOA deletion → NOTAUTH, CNAME coexistence preservation, cache invalidation on success, failed prerequisite preserves cache, TSIG absent preserves serial, unknown zone, multi-record add, delete removes record. Validates UPDATE atomic clone-modify-validate-insert pattern.
- **`tests/notify_scheduling_semantics.rs`** (7 tests): Response shape (QR=1, AA=1, opcode=4), cache invalidation, unknown zone preserves other cache, source allowlist (empty=allow all, specific IP, wildcard `*`), rate limiting (rapid second still NOERROR, long interval both succeed), disabled handler, TSIG enforcement, multi-zone independence. Validates NOTIFY handler behavior.
- **`tests/control_plane_cache_completion.rs`** (8 tests): Cache key dimensions (TransportClass::Udp512/Tcp, CacheNamespace::Authoritative/Recursive), UPDATE/NOTIFY invalidation, AXFR reads from zone store not cache, concurrent AXFR independence, invalidation reason labels (DynamicUpdate, NotifyReceived, ZoneLoad, ZoneTransferAxfr, ManualFlush), zone-scoped invalidation, clear removes all. Validates cache/coalescing exclusion completeness.

### Production Bug Fix: `update.rs` Prerequisite Parsing

Fixed 3 bugs in `crates/synvoid-dns/src/update.rs`:

1. **`parse_rr_with_rdata()`**: Was reading everything after CLASS as rdata, but RR wire format has TTL(4)+RDLENGTH(2) before RDATA. Fixed to read rdlength from `end_pos+8..end_pos+10` and return only actual RDATA bytes.
2. **`skip_rr_with_rdata()`**: Was skipping only NAME+TYPE+CLASS (`end_pos+4`), not the full RR. Fixed to skip `end_pos + 10 + rdlen`.
3. **`check_prerequisite()` for `Exists`/`ExistsRRset`**: Had inverted logic — returned `Ok(false)` when records existed. Fixed: `Exists` uses match with value comparison; `ExistsRRset` uses `records.is_some_and(|r| !r.is_empty())`.

### Test Totals

- **18 integration test files** in `crates/synvoid-dns/tests/`
- **1001 tests** pass (unit + integration, `cargo test -p synvoid-dns`)
- All 6 new test files compile and pass
- `cargo fmt --all` clean
- Pre-existing clippy warnings in DNS source (not in test files)

### Test Commands

```bash
# Final validation hardening (new test files)
cargo test -p synvoid-dns --test dnssec_live_signing
cargo test -p synvoid-dns --test tsig_success_fixtures
cargo test -p synvoid-dns --test ixfr_record_delta
cargo test -p synvoid-dns --test update_atomicity_rollback
cargo test -p synvoid-dns --test notify_scheduling_semantics
cargo test -p synvoid-dns --test control_plane_cache_completion

# All integration tests
cargo test -p synvoid-dns

# Full suite including unit tests
cargo test -p synvoid-dns --release --no-fail-fast
```

### Deferral Lock-Down

| Feature | Status | Reason |
|---------|--------|--------|
| NSEC3 closest-encloser proofs | Deferred | Requires NSEC3 chain walking; RFC 5155 compliance partial |
| Persistent TCP pipelining | Deferred | RFC 7766 §4 compliance requires connection reuse |
| EDNS keepalive | Deferred | Parsed but not wired into connection management |
| Trust anchors (RFC 5011) | Deferred | Config fields exist, not consumed at server construction |
| External DNSSEC tooling | Deferred | dig/ldns-verify-zone not in CI pipeline |
| Bailiwick enforcement | Deferred | Observability-only (log + metric), not enforced |
| RPZ (Response Policy Zones) | Deferred | Documented but unsupported |
| DNS Padding / QNAME Privacy | Deferred | Structures exist, not wired into query path |
| DoQ production validation | Deferred | ALPN/quinn adapter tested in unit tests only |
| Prefetch | Deferred | Documented but unsupported |
| ECDSAP256SHA256 (algorithm 13) | Deferred | Only Ed25519 (15) and RSA-SHA256 (8) supported |

## M4 Phase 1: Observability and Operations

### Metrics Taxonomy

- All metrics use stable, low-cardinality names. No per-domain or per-query-type labels.
- Transport-labeled: `dns_transport_queries{transport=udp|tcp|dot|doh|doq}`
- Operation-labeled: `dns_operation_counts{operation=query|update|notify|axfr|ixfr}`
- Recursive metrics now emit `metrics::counter!` (previously internal-only).
- High-cardinality fields (`top_queried_domains`, `top_blocked_domains`, `query_types`) removed.

### Health Status

- `DnsHealthChecker` in `health.rs` provides liveness/readiness.
- Liveness: listener bound. Readiness: listener + zones + cache + no recent failures.
- Wire into server startup: `health_checker.set_listener_bound(true)` after bind.

### Structured Logging

- `dot.rs` and `doh.rs` now emit `tracing` logs (previously zero).
- `transfer.rs`, `notify.rs`, `update.rs` enhanced with structured fields.
- Convention: `info!` lifecycle, `warn!` degraded/refused, `error!` failures, `debug!` detail.
- Never log TSIG secrets, private keys, full client IPs.

### Testing

```bash
cargo test -p synvoid-dns metrics
cargo test -p synvoid-dns health
```

## Milestone 4 Phase 2: Performance and Load Testing

### Benchmark Suites

5 criterion benchmark suites under `crates/synvoid-dns/benches/`:
- `cache_bench.rs` — DnsCache and ShardedDnsCache: insert, lookup, miss, transport classes, invalidation
- `wire_bench.rs` — Wire format: parse_query_name, parse_dns_message, ParsedDnsQuery, message ID/flags
- `zone_bench.rs` — Zone: creation, record insertion, authoritative lookup, NXDOMAIN, serial increment, ZoneTrie
- `coalescer_bench.rs` — QueryCoalescer: new, with_config, key creation, should_skip_coalescing
- `limits_bench.rs` — ConnectionLimits: new, try_acquire_connection/query, validate sizes, degradation level

### Running Benchmarks

```bash
cargo bench -p synvoid-dns                                          # All suites
cargo bench -p synvoid-dns --bench cache_bench                      # Cache only
cargo bench -p synvoid-dns --bench wire_bench -- --test             # Dry-run (no baseline save)
./scripts/dns/run_benchmarks.sh                                     # Orchestration with env capture
```

### Stress and Resource Limit Tests

28 tests in `tests/dns_stress_resource_limits.rs` (Workstream 7):
- Query/response/record-count size boundary validation (6 tests)
- TCP connection and concurrent query limit enforcement with guard drop semantics (4 tests)
- Graceful degradation activation, deactivation, shutdown flag, load factor (5 tests)
- Cache capacity enforcement, large entry rejection, clear under load (4 tests)
- Coalescer bounded entry handling, AXFR/NOTIFY/UPDATE skip rules (3 tests)
- Zone trie 10K insertions and lookup-miss stability (2 tests)
- Cache memory stability through 100 insert-lookup-clear cycles, concurrent inserts (2 tests)
- Deterministic rejection under overload, zero-capacity edge case (2 tests)

```bash
cargo test -p synvoid-dns --test dns_stress_resource_limits -- --test-threads=1
./scripts/dns/stress_tests.sh
```