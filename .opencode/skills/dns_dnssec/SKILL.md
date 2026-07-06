---
name: dns_dnssec
description: DNS server, DNSSEC validation, TSIG authentication, and dual-mode DNS architecture patterns.
---

# SynVoid DNS & DNSSEC Architecture Skill

## Overview

SynVoid implements a dual-mode DNS system:
1. **Recursive Resolver** - For resolving external domains (uses hickory-dns)
2. **Authoritative Server** - For hosting zones with DNSSEC signing

## DNS Module Structure

```
crates/synvoid-dns/src/
├── mod.rs                    # Module exports
├── parsed_query.rs           # Canonical query parser (ParsedDnsQuery, QueryFlags, build_response_flags)
├── recursive.rs              # RecursiveDnsServer with caching
├── recursive_cache.rs        # Cache implementation with DNSSEC tracking
├── resolver.rs              # HickoryRecursor, HickoryResolver, TrustAnchorManager
├── trust_anchor.rs          # RFC 5011 trust anchor state machine
├── dnssec.rs                # DNSSEC types and re-exports
├── dnssec_signing.rs        # RRSIG creation, NSEC/NSEC3 generation
├── dnssec_validation.rs     # Key tag calculation, DS digest, canonicalization
├── server/
│   ├── mod.rs              # DnsServer, DnsHandler
│   ├── dnssec_impl.rs      # Authoritative DNSSEC implementation
│   ├── query.rs             # Query handling with NSEC/NSEC3
│   ├── response.rs          # Response building with AD bit
│   └── response_encoder.rs  # Typed wire-format response encoder
└── config/
    ├── dns_recursive.rs     # Recursive DNS config
    └── dns_dnssec.rs        # DNSSEC and trust anchor config
```

## Resolver Types

### HickoryRecursor (Recursive Mode)

Performs full DNSSEC validation when `enable_dnssec: true`.

```rust
// crates/synvoid-dns/src/resolver.rs:605
HickoryRecursor::from_paths(root_hints_path, trust_anchor_path, enable_dnssec)
```

**Validation path:**
- Creates `TrustAnchorManager` for RFC 5011 key management
- Creates `hickory_recursor::Recursor` with `DnssecPolicy::ValidateWithStaticKey`
- Passes `enable_dnssec` to `resolve()` method
- Sets `is_dnssec_validated` based on `proven_record.proof().is_secure()`

### HickoryResolver (Forwarder Mode)

Does NOT perform DNSSEC validation - simply forwards to upstream.

```rust
// crates/synvoid-dns/src/resolver.rs:141
// NOTE: is_dnssec_validated is ALWAYS false for HickoryResolver
```

### GlobalNodeResolver

Resolves via configured global mesh nodes.

## DNSSEC Chain-of-Trust

### Recursive Validation Flow

```
Query for example.com
    ↓
HickoryRecursor (if Recursive provider)
    ↓
Query root server for .com NS
    ↓
Query .com server for example.com A
    ↓
Validate DNSKEY chain up to trust anchor
    ↓
If all validated → is_dnssec_validated = true
If validation fails → SERVFAIL or Bogus
```

### AD Bit Setting

The AD (Authentic Data) bit is set based on validation status:

**Authoritative server** (`crates/synvoid-dns/src/server/response.rs`):
```rust
let records_signed = dnssec_ok && !records.is_empty() && zsk.is_some();
if records_signed {
    qr_aa |= 0x0020;  // AD bit
}
```

**Recursive server** (`crates/synvoid-dns/src/recursive.rs`):
```rust
authentic_data: is_dnssec_validated,  // From upstream resolver
```

## Configuration

### Recursive DNS Config (`crates/synvoid-config/src/dns/dns_recursive.rs`)

| Option | Default | Description |
|--------|---------|-------------|
| `upstream_provider` | `System` | `Recursive`, `Google`, `Cloudflare`, `GlobalNodes`, `Custom` |
| `dnssec_validation` | `true` | Enable DNSSEC validation (ONLY works with `Recursive` provider) |
| `qname_minimization` | `true` | Privacy-friendly query pattern |
| `root_hints_path` | `"root.hints"` | Root server hints |
| `trust_anchor_path` | `"trusted-key.key"` | Trust anchor file |

### Trust Anchor Config (`crates/synvoid-config/src/dns/dns_dnssec.rs`)

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable trust anchor management |
| `pending_observation_days` | `30` | RFC 5011 Pending→Valid period |
| `revocation_grace_days` | `30` | Post-revocation grace period |
| `extended_removal_days` | `60` | Extended removal waiting |
| `trust_anchor_retention_days` | `7` | Valid key absent retention |
| `allow_key_rotation` | `true` | Allow RFC 5011 key rotation |

### Authoritative DNSSEC Config

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable DNSSEC signing |
| `algorithm` | `Ed25519` | Signing algorithm |
| `ksk_key_size` | `4096` | KSK RSA key size |
| `rsa_key_size` | `2048` | ZSK RSA key size |
| `nsec3_enabled` | `true` | Use NSEC3 (not NSEC) |

## Important: DNSSEC Validation by Design Limitation

**Forwarder mode (Google/Cloudflare/System/Custom) does NOT perform DNSSEC validation.**

This is by design, not a bug:
- Google/Cloudflare are stub resolvers that forward queries
- They perform their own validation and return results
- We cannot re-validate their chain-of-trust without becoming a true recursive resolver

**To get DNSSEC validation:**
```toml
[dns.recursive]
upstream_provider = "Recursive"  # MUST be Recursive
dnssec_validation = true         # Enable validation
trust_anchors.enabled = true     # Enable trust anchor management
trust_anchor_path = "trusted-key.key"  # Root DNSKEY file
```

## RFC 5011 Trust Anchor State Machine

Keys transition through states:
1. **Seen** → Key observed in DNSKEY RRset
2. **Pending** → Validated via CDS/CDNSKEY, awaiting observation
3. **Valid** → Trusted for DNSSEC validation
4. **Revoked** → REVOKE bit set
5. **Removed** → Revoked, waiting for extended confirmation
6. **Missing** → Valid key not seen for retention period
7. **Purged** → Removed from storage

## Recursive DNS Cache Implementation

**Location**: `crates/synvoid-dns/src/recursive_cache.rs`

The `RecursiveDnsCache` uses Moka with weighted entries (via `weigher` callback) AND time-to-live expiration. When using these together:

- `entry_count()` may return 0 even when entries exist
- Use `iter().count()` instead for accurate count of entries
- Use `len()`, `positive_len()`, `negative_len()` methods which correctly use `iter().count()`

**Example from** `crates/synvoid-dns/src/recursive_cache.rs:326-342`:
```rust
pub fn len(&self) -> usize {
    let inner = &self.inner;
    inner.positive_cache.iter().count() + inner.negative_cache.iter().count()
}
```

---

## Authoritative DNSSEC Signing

### Zone Signing Flow

1. Generate KSK (flags=257) and ZSK (flags=256)
2. Publish DNSKEY records
3. Create DS records for parent zone
4. Sign all records with RRSIGs
5. Include NSEC/NSEC3 for authenticated denial

### RRSIG Validity

- **Inception**: now - 86400 (1 day past, for clock skew)
- **Expiration**: now + 604800 (7 days)

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-dns/src/resolver.rs` | HickoryRecursor, HickoryResolver, TrustAnchorManager |
| `crates/synvoid-dns/src/recursive.rs` | RecursiveDnsServer with caching |
| `crates/synvoid-dns/src/trust_anchor.rs` | RFC 5011 state machine |
| `crates/synvoid-dns/src/dnssec_signing.rs` | RRSIG creation, NSEC/NSEC3 |
| `crates/synvoid-dns/src/dnssec_validation.rs` | Key tag, DS digest, canonicalization |
| `crates/synvoid-dns/src/server/dnssec_impl.rs` | Authoritative DNSSEC |
| `crates/synvoid-dns/src/server/query.rs` | Query handling |
| `crates/synvoid-dns/src/server/response.rs` | Response building |

## Milestone 1 Corrective Pass Changes

### Response Flag Policy (Phase A)

`ResponsePolicy` (in `parsed_query.rs`) centralizes authoritative response flag semantics:

```rust
pub struct ResponsePolicy {
    pub authoritative: bool,       // AA bit
    pub recursion_available: bool, // RA bit
    pub authentic_data: bool,      // AD bit
    pub checking_disabled_allowed: bool, // CD bit
}
```

`build_response_flags_with_policy(parsed, policy, trunc, rcode)` derives flags from the parsed query and policy. **All authoritative paths** use this:

- **RA=false** for authoritative-only answers
- **RD echoed** from query (not hard-coded)
- **AD=false** even when RRSIGs are present — AD is only for validated recursive data

### Byte-Size Truncation (Phase B)

Truncation is now driven by byte size, not record count:

- `EncodedRecord::wire_len()` — wire-length of a single record
- `ResponseEnvelope::total_wire_len()` — exact assembled packet size
- `build_truncated_tc_response(max_size)` — builds minimal TC response when packet exceeds UDP payload size

The `build_response` function assembles the full packet, checks `packet.len() > max_size`, and emits a TC response if over limit.

### Parser Propagation — Parse Once (Phase C)

TCP and UDP paths now parse each query once via `ParsedDnsQuery::parse()`, then pass the parsed state downward:

```rust
// Handler entry points
handle_parsed_query(ctx, parsed, client_ip)
handle_parsed_query_with_cache(ctx, parsed, cache, cache_key, client_ip)
```

`QueryKey::from_parsed()` derives coalescing/cache keys from parsed state. Transfer detection uses `parsed.is_axfr()` / `parsed.is_ixfr()` directly. Raw packet bytes remain available via `parsed.raw` for TSIG, UPDATE, and NOTIFY.

### Authoritative NODATA/NXDOMAIN (Phase D)

`Zone::lookup_authoritative(name, qtype)` returns `AuthoritativeLookupOutcome`:

```rust
pub enum AuthoritativeLookupOutcome {
    Positive(Vec<DnsZoneRecord>),
    Cname(Vec<DnsZoneRecord>),
    NoData { soa: DnsZoneRecord },     // owner exists, qtype absent
    NxDomain { soa: DnsZoneRecord },   // owner absent
    NoAuthoritativeZone,
}
```

Unsigned negative responses include SOA from the zone. The `.example` synthetic shortcut is removed from production flow.

### Encoder Strictness (Phase E)

The response encoder now reports skipped records via `EncodeReport`:

```rust
pub struct SkippedRecord {
    pub owner: String,
    pub record_type: u16,
    pub reason: String,
}

pub struct EncodeReport {
    pub total_records: usize,
    pub encoded_records: usize,
    pub skipped: Vec<SkippedRecord>,
}
```

Validation rules enforced at encode time:
- MX priority > `u16::MAX` → rejected
- CAA tag > 255 bytes → rejected
- TLSA fields validated for numeric range
- SOA encode failure → SERVFAIL
- `encode_failures` metric incremented for observability

### Query Coalescing Broadcast (Phase F)

After the owner computes a response, it broadcasts to all waiters:

```rust
coalescer.broadcast_response(key, response.clone());
```

On failure, `cancel_in_flight()` cleans up. Negative responses (NXDOMAIN/NODATA) are also broadcast when key dimensions match. Coalescing key includes DO bit, qclass, qtype, qname, and client dimensions.

**QueryKey 7-Dimensional Key** (`crates/synvoid-dns/src/query_coalesce.rs`):
| Dimension | Type | Description |
|-----------|------|-------------|
| `name` | `String` | Lowercased qname |
| `qtype` | `u16` | Query type (A, AAAA, MX, etc.) |
| `qclass` | `u16` | Query class (IN, CH, etc.) |
| `dnssec_ok` | `bool` | DO bit from EDNS |
| `client_ip` | `Option<String>` | Client subnet for per-client coalescing |
| `transport_class` | `TransportClass` | Transport variant (UDP/TCP/DoH/DoQ) |
| `namespace` | `CacheNamespace` | Authoritative vs Recursive scope |

**Coalescer Metrics** (lazy static gauges):
- `dns_query_coalescer_hits_total` — Waiter received coalesced response
- `dns_query_coalescer_misses_total` — Query became new owner
- `dns_query_coalescer_broadcasts_total` — Owner broadcast response to waiters
- `dns_query_coalescer_cancels_total` — Owner cancelled in-flight entry (failure path)
- `dns_query_coalescer_evictions_total` — LRU eviction due to max_entries
- `dns_query_coalescer_timeouts_total` — Waiter timed out waiting
- `dns_query_coalescer_lagged_total` — Waiter lagged on broadcast channel
- `dns_query_coalescer_in_flight` — Current in-flight query count

### Runtime Correctness (Phase G)

- Bind address from `DnsSettings.bind_address` is honored for UDP/TCP listeners.
- DNS64 translator is passed through `DnsHandlerState` into query context (no longer `None`).
- TCP connection limit guard is held inside the `tokio::spawn` closure for the lifetime of the task.

---

## Common Patterns

### Checking DNSSEC Validation Status

```rust
use crate::dns::resolver::{HickoryRecursor, IpRecord};

let ip_record: IpRecord = resolver.lookup_ip("example.com").await?;
if ip_record.is_dnssec_validated {
    // DNSSEC chain validated
}
```

### RFC 5011 Events

```rust
use crate::dns::trust_anchor::{TrustAnchorManager, TrustAnchorConfig, Rfc5011Event};

let config = TrustAnchorConfig {
    enabled: true,
    pending_observation_days: 30,
    // ...
};
let manager = TrustAnchorManager::new(config);

// Observe new DNSKEY
let event = manager.observe_dnskey_at_root(key_tag, algorithm, &public_key, false);

// Check via CDS digest
let event = manager.trust_anchor_check(key_tag, algorithm, digest_type, &digest);

// Process state transitions
let events = manager.process_rfc5011_updates();
```

### Missing→Pending Restoration

Per RFC 5011 Section 3.3, only keys that were previously Valid can auto-restore:

```rust
// In observe_dnskey_at_root():
TrustAnchorState::Missing => {
    if anchor.trust_point == 0 {
        // Never valid - require DS digest verification via trust_anchor_check()
        return Rfc5011Event::KeyIgnored { key_tag, reason: "..." };
    }
    // Was previously Valid - transition to Pending
    anchor.state = TrustAnchorState::Pending;
    Rfc5011Event::KeyPending { key_tag }
}
```

Keys with `trust_point == 0` (never valid) must use `trust_anchor_check()` with a DS digest from CDS/CDNSKEY records to transition to Pending.

## Milestone 3 Corrective Semantics Pass

### Production Helpers

- **`Zone::validate_zone_for_activation()`** (`server/mod.rs`): Unified pre-publish gate enforced by all production code paths before a zone becomes `Active`. Checks: exactly one apex SOA, non-empty/normalized/printable origin (rejects control chars, NUL, whitespace, `/`, `\`).
- **`DnsServer::replace_zone_with_validation(candidate: Zone)`** (`server/zone.rs`): Atomic zone replacement API. Validates via `validate_zone_for_activation()`, marks active, inserts into store, invalidates cache. On failure, previous zone is left untouched. `load_zones` and `load_zones_from_store` now call `validate_zone_for_activation()` instead of just `validate_single_soa()`.

### Dynamic UPDATE Re-Validation

Dynamic UPDATE now re-validates post-mutation invariants. If a crafted UPDATE removes the final SOA or creates a duplicate, it is refused with RCODE NOTAUTH (9). State is not committed on failure.

### New Test Files

- **`tests/control_plane_authorization.rs`** (10 tests): Deny-by-default behavior for UPDATE/NOTIFY/AXFR/IXFR. Covers disabled-by-default refusal, malformed message non-mutation, invalid zone error RCODE, unknown NOTIFY source ignored, AXFR/IXFR denied by default, query type constants (251/252), transfer disabled when axfr_enabled=false, allowed-client SOA-bracketed transfer.
- **`tests/verification_gate.rs`** (strengthened): Replaced documentation-grade tests with behavior tests: `successful_reload_swaps_zone_atomically`, `failed_reload_preserves_previous_active_zone`, `validate_zone_for_activation_rejects_duplicate_soa`, `validate_zone_for_activation_rejects_bad_origin`, `successful_reload_invalidates_cache_for_zone`. Plus 15 new protocol-semantics tests across gates 7/8/9 (DNSSEC flags, RRSIG validity window, DS digest lengths, recursive safety config invariants, ECS default, encrypted transport cache isolation).

### Deferred / Known Limitations

- DoQ is wired but not production-validated; ALPN/quinn adapter is tested in unit tests only.
- Persistent DNS-over-TCP (pipelining) remains deferred.
- EDNS keepalive remains parsed-only.
- Full NSEC3 closest-encloser proofs remain deferred.
- External DNSSEC tooling (dig, ldns-verify-zone, named-checkzone) is not in CI.
- Bailiwick checks are observability-only (not enforced).

## Known Limitations

1. **Forwarder mode ignores `dnssec_validation`** - Google/Cloudflare providers don't validate
2. **TrustAnchorManager and hickory_proto::TrustAnchors are separate** - Synchronization between RFC 5011 manager and hickory's internal anchors
3. **NSEC3 uses SHA-1** - RFC 9276 suggests SHA-1 is acceptable for NSEC3 hashing
4. **NSEC3 Hash Length Encoding** - When creating NSEC3 records, the hash must be prefixed with its length as a single byte per RFC 5155 Section 3.2. The `create_nsec3_record()` function in `crates/synvoid-dns/src/dnssec_signing.rs` handles this correctly.
5. **QNAME Privacy and DNS Padding are deferred** - `sanitize_qname()` (`dns_settings.rs:244`) and `DnsPadding` (`edns.rs:540`) exist but are not wired into the query path.
6. **DoQ bind_address is partially implemented** - Config field exists but `startup.rs:580` hardcodes bind to `0.0.0.0:{port}`.

## Encrypted Transport Adapters (Milestone 3 Phase 3)

DoT, DoH, and DoQ are thin adapters over the core authoritative query engine. All three share the same `handle_parsed_query_with_cache` pipeline, ensuring rate limiting, firewall, DNSSEC, coalescing, and cache semantics are applied identically.

| Protocol | RFC | TransportClass | Default Port | Key Characteristics |
|----------|-----|----------------|--------------|---------------------|
| DoT | RFC 7858 | `Tcp` | 853 | TCP+TLS 1.3, length-prefixed framing, shares TCP cache namespace |
| DoH | RFC 8484 | `Http` | 443 | HTTP/2+TLS 1.3, `application/dns-message` content-type enforced, separate cache namespace |
| DoQ | RFC 9250 | `Quic` | 853 | QUIC+TLS 1.3, bidirectional streams, separate cache namespace |

**Transport-class propagation**: `TransportClass` is included in `CacheKey` and `QueryKey`, preventing cross-contamination of wire-format responses between transport types.

**DoH content-type enforcement**: POST requests must include `Content-Type: application/dns-message`. Wrong or missing content type returns HTTP 415.

**Per-transport metrics**: `dns_queries_total{transport}`, `dns_responses_total{transport}`, `dns_errors_total{transport,kind}`, `dns_active_connections{transport}`, `dns_response_latency_seconds{transport}`.

See `architecture/dns.md` § "Encrypted Transport Adapters" for the full shared query pipeline diagram and `plans/dns_milestone_3_phase_03_encrypted_transport_adapters.md` for the phase specification.

## Milestone 2 Phase 2 Changes

### Open-Resolver Prevention (`dns_recursive.rs`)
`RecursiveDnsConfig::validate()` rejects `0.0.0.0` or `::` as `bind_address` when recursive DNS is enabled. Returns `DnsConfigError::InvalidRecursive` with an explicit open-resolver prevention message.

### NOTIMP for Disabled Zone Mutation (`server/query.rs`)
When zone mutation handlers (NOTIFY, UPDATE, AXFR, IXFR) are `None` in `DnsServer::new()`, the server now returns RCODE 4 (NOTIMP) instead of silently dropping the query. This follows RFC 1035/2136/1996 conventions for unsupported operations.

### Query Timeout Wiring (`resolver.rs`, `recursive.rs`)
`query_timeout_secs` from `RecursiveDnsConfig` is now passed to `HickoryResolver` constructors. Previously hardcoded to `Duration::from_secs(5)`.

### Config-to-Runtime Fidelity
- `serve_stale.max_stale_count` wired from config to `DnsCache::with_serve_stale()`
- `enable_graceful_degradation` wired from `DnsLimitsConfig` to `ConnectionLimits`
- `default_ttl` confirmed consumed at `server/zone.rs:137` as zone record fallback TTL

## Security Notes

### DS Digest Comparison (2026-05-23)

**Location**: `crates/synvoid-dns/src/dnssec_validation.rs:272`

DS digest comparison MUST use constant-time comparison to prevent timing attacks:

```rust
use subtle::ConstantTimeEq;

// BEFORE (vulnerable to timing attack)
Ok(computed == expected_digest)

// AFTER (constant-time)
Ok(bool::from(computed.ct_eq(expected_digest)))
```

This matches the pattern used in `tsig.rs:238` and `cookie.rs:86`.

## Milestone 2 Phase 1 Changes

### Bind Fail-Fast (`server/startup.rs`)
`configured_bind_addr()` validates the bind address and port at startup, returning `Err` immediately on invalid input. No silent fallback.

### TCP One-Query-Per-Connection (`server/query.rs`)
RFC 7766 §4: read one length-prefixed DNS message, respond, close. AXFR/IXFR transfers send multiple messages but still close after completion. Persistent TCP (pipelining) is deferred.

### UDP/EDNS Truncation (`server/response.rs`)
When a response exceeds the EDNS UDP payload size (512 without EDNS, OPT CLASS field with EDNS, default 1232), the server emits TC=1 with the question section. Clients retry over TCP.

### TCP Hard-Limit SERVFAIL (`server/query.rs:390-479`)
TCP responses exceeding `max_response_size` produce a protocol-correct SERVFAIL: echoed query ID, question section, RD bit, RA=0, AD=0, RCODE=2. The SERVFAIL is self-validated to fit within the hard limit.

### Shutdown (`server/startup.rs`)
`shutdown_runtime()` is idempotent. Three shutdown channels: `shutdown_tx` (UDP), `shutdown_watcher_tx` (coalescer), `connection_limits` drain (TCP). Sockets are dropped on task exit for port reuse. Fire-and-forget tasks (key rotation, recursive server, coalescer cleanup) exit via channels or runtime drop.

### Transport Class (`cache.rs`)
`TransportClass` enum (`Udp512`, `UdpEdns(u16)`, `Tcp`, `Http`, `Quic`) separates cache and coalescing keys by transport type, preventing cross-contamination of wire-format responses.

## Testing

```bash
# Run DNS tests
cargo test --lib dns

# Run with DNS feature
cargo test --features dns

# Response encoder tests (Phase E: EncodeReport, wire_len, truncation)
cargo test -p synvoid-dns -- response_encoder

# Canonical query parser tests (Phase C: parse-once, QueryKey::from_parsed)
cargo test -p synvoid-dns -- parsed_query

# Authoritative negative response tests (Phase D: NODATA/NXDOMAIN with SOA)
cargo test --test authoritative_negative

# Query coalescing tests (Phase F: key dimensions, owner/waiter lifecycle, metrics)
cargo test -p synvoid-dns -- query_coalesce

# DNS Phase 7 cache tests (cache key redesign, serve-stale, negative TTL, poisoning, invalidation)
cargo test -p synvoid-dns -- phase7_cache_tests

# Recursive cache tests (TTL overrides, isolation, moka config wiring)
cargo test -p synvoid-dns -- recursive_cache

# Config-to-runtime fidelity tests (cache, DNS64, ECS, serve-stale)
cargo test -p synvoid-dns --test dns_config_fidelity

# Recursive isolation + zone mutation feature flag tests (31 tests)
cargo test -p synvoid-dns --test dns_recursive_isolation

# M2 Phase 2: Open-resolver guard, NOTIMP responses, query timeout
cargo test -p synvoid-dns -- open_resolver
cargo test -p synvoid-dns -- query_timeout
cargo test -p synvoid-dns --test dns_recursive_isolation -- open_resolver

# M2 Phase 1: Transport class separation (cache/coalescing keys by transport)
cargo test -p synvoid-dns -- transport

# M2 Phase 1: Transport lifecycle (bind, startup, shutdown ordering)
cargo test -p synvoid-dns -- transport_lifecycle

# M2 Phase 1: Bind fail-fast (invalid address, port zero)
cargo test -p synvoid-dns -- configured_bind_addr

# M2 Phase 1: Shutdown idempotency
cargo test -p synvoid-dns -- shutdown_runtime

# M2 Phase 1: TCP hard-limit SERVFAIL
cargo test -p synvoid-dns -- tcp_hard_limit

# M2 Phase 1: SERVFAIL response behavior (question echo, RD bit, RA/AD semantics)
cargo test -p synvoid-dns -- servfail_response

# M2 Phase 1: UDP/EDNS truncation (TC bit, question echoed)
cargo test -p synvoid-dns -- truncation

# M3 Phase 3: Encrypted transport adapters (DoT, DoH, DoQ)
cargo test -p synvoid-dns --test encrypted_transport
cargo test -p synvoid-dns -- dot
cargo test -p synvoid-dns -- doh
cargo test -p synvoid-dns -- doq
```

## Milestone 2 Phase 5: Verification & Release Gate

All 8 gate areas verified:

| Gate | Status | Command |
|------|--------|---------|
| Compile/test baseline | PASS | `cargo test -p synvoid-dns` (576 tests) |
| Duplicate DNS tree | PASS | `src/dns/` is re-export only |
| Config-runtime matrix | PASS | Summary stats fixed, contradictions resolved |
| Transport behavior | PASS | Bind fail-fast, TCP lifecycle, shutdown idempotency |
| Cache behavior | PASS | 7-dimension keys, namespace separation, invalidation |
| Coalescing behavior | PASS | Key dimensions, exclusions, owner/waiter lifecycle |
| Recursive isolation | PASS | Open-resolver prevention, NOTIMP responses |
| Documentation | PASS | All docs updated |

### Known Limitations

- DoT/DoH/DoQ (28 fields) wired but untested
- Rate limiter (9 fields) wired but untested
- Firewall (3 security controls) wired but untested
- DoQ `bind_address` partially implemented (hardcoded to 0.0.0.0)
- Full DNSSEC production validation deferred to later milestone
