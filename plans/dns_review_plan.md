# DNS Architecture Review Plan

## Verified Correct

### Key Files (All Exist)
- All 44 files listed in the document exist at `src/dns/`:
  - `store.rs`, `server/mod.rs`, `server/startup.rs`, `server/query.rs`, `server/zone.rs`, `server/rate_limit.rs`, `server/sharded_store.rs`
  - `dnssec.rs`, `dnssec_signing.rs`, `dnssec_validation.rs`, `dnssec_key_mgmt.rs`
  - `tsig.rs`, `recursive.rs`, `recursive_cache.rs`, `trust_anchor.rs`, `hsm.rs`, `cookie.rs`
  - `update.rs`, `transfer.rs`, `doh.rs`, `dot.rs`, `doq.rs`, `cache.rs`
  - `firewall.rs`, `wire.rs`, `messages.rs`, `anycast.rs`, `anycast_sync.rs`
  - `qname.rs`, `zone_manager.rs`, `zone_file.rs`, `rpz.rs`, `edns.rs`, `limits.rs`

### Query Coalescing
- Implemented at `src/dns/query_coalesce.rs` - CONFIRMED
- `QueryCoalescer::with_config()` in `DnsServer::new()` at `src/dns/server/mod.rs:634-644` - CONFIRMED
- Passed to query handler via `QueryContext` at `src/dns/server/mod.rs:440` - CONFIRMED

### DNSSEC Signing Algorithms
- Ed25519 (Algorithm 15) and RSA/SHA-256 (Algorithm 8) - CONFIRMED at `dnssec.rs:128-155`
- NSEC3 Algorithm 1 (SHA-1) and Algorithm 2 (SHA-256) - CONFIRMED at `dnssec_signing.rs:192-212`

### GOST DS Digest
- GOST R 34.11-94 (type 3) returns error - CONFIRMED at `dnssec_validation.rs:260`

### DNSSEC Key Rotation
- Default KSK: 30 days, ZSK: 7 days - CONFIRMED at `dnssec.rs:64-73`

### TSIG
- All 4 algorithms (HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512) - CONFIRMED at `tsig.rs:16-19`
- Constant-time MAC comparison via `subtle::ConstantTimeEq` - CONFIRMED at `tsig.rs:238`
- Replay cache: 5-minute TTL, 10K entries - CONFIRMED at `tsig.rs:21-22`
- Default fudge of 300s - CONFIRMED at `tsig.rs:262`

### RFC 5011 Trust Anchors
- All states (Seen, Pending, Valid, Revoked, Removed, Missing) - CONFIRMED at `trust_anchor.rs:30-64`

### Zone Transfer Constants
- AXFR_QUERY_TYPE = 252 at `transfer.rs:8`
- IXFR_QUERY_TYPE = 251 at `transfer.rs:9`

### ShardedZoneStore
- 64 shards - CONFIRMED at `sharded_store.rs:7`

### Query Flow Components
- All verified: `DnsRateLimiter`, `DnsQueryValidator`, `DnsFirewall`, `DnsCache` exist and are used

### DNSSEC Limitations
- Manual wire format construction, no built-in compression - CONFIRMED at `dnssec.rs:1-13`

### DNSSEC Signature Validity
- 7 days (sig_expire = now + 7*86400) - CONFIRMED at `dnssec_signing.rs:53`

### DNS Cookie Implementation
- RFC 8905/RFC 7873 implementation exists at `src/dns/cookie.rs`

### DoT/DoH/DoQ Protocol Servers
- All started in `start_standard_mode()` after standard mode at `startup.rs:932-969`

### Recursive Resolver
- Uses `hickory_resolver::TokioResolver` - CONFIRMED at `resolver.rs:201`

### AXFR Record Type Coverage
- Documented record types: A, AAAA, CNAME, NS, SOA, TXT, MX, SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA - CONFIRMED at `transfer.rs:829-1029`
- Unsupported types (NAPTR, CERT, S/MIME, DNAME) correctly fall through with `_ => continue` - CONFIRMED

## Discrepancies Found

### Cookie Server Not Integrated (AGENTS.md Known Issue)
- **Documentation says**: Cookie server provides client authentication via EDNS cookie exchange
- **Code reality**: `DnsCookieServer` is created at `server/mod.rs:850` and passed to `QueryContext`, but the query handler (`query.rs`) never calls `validate_cookie()` or `should_require_cookie()`. The cookie server exists but is not wired into the validation flow.
- **Status**: This is a **known issue** tracked in AGENTS.md

### Query Coalescing Configuration
- **Documentation says**: `QueryCoalescer::with_config()` created with `config.settings.query_coalescing` parameters
- **Code reality**: The `max_wait_ms` parameter is unused (`_max_wait_ms`) in the `with_config()` method at `query_coalesce.rs:117`
- **Impact**: Low - The coalescer works but max_wait_ms is ignored

## Bugs Identified

### High: DNS Cookie Server Not Validated in Query Path
- **Location**: `src/dns/server/query.rs` (cookie validation not called)
- **Issue**: Complete implementation exists (`src/dns/cookie.rs`) but is never invoked during query processing
- **AGENTS.md status**: Known issue, marked as "not integrated"

## Suggested Improvements

### 1. Wire DNS Cookie Server into Query Validation
- The cookie server needs to be integrated into the query handling flow in `query.rs`
- Should call `validate_cookie()` when `cookie_server.is_some()` and query contains cookie option
- Should set response cookies in outgoing responses via `create_response_cookie()`

### 2. Fix Query Coalescer max_wait_ms Parameter
- Currently marked as unused (`_max_wait_ms`)
- Could be used to control broadcast timeout behavior in `get_or_wait()`

### 3. Update Documentation for Additional DNSSEC Algorithms
- Consider mentioning that algorithm 13 (ECDSAP256SHA256) and algorithm 14 (ECDSAP384SHA384) could be added
- Current implementation only supports Ed25519 and RSA/SHA-256

### 4. Add NAPTR/CERT/SMMEA/DNAME Support to AXFR
- These record types currently fall through unsupported
- Consider adding support for completeness

### 5. Document DNSSEC Validation Trust Chain
- The document mentions DS -> DNSKEY -> RRSIG -> Zone data chain
- Could benefit from more detail on RFC 4035 validation steps
