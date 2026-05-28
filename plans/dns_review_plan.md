# DNS Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/dns.md`, `architecture/dns_deep_dive.md`

## Verified Correct Items

- **File paths**: All files listed in both documents exist in `src/dns/`
- **DnsServer struct**: Correctly located at `server/mod.rs:447` (dns.md:99)
- **Zone struct**: Correctly located at `server/mod.rs:129` (dns.md:129)
- **DnsResolver trait**: Correctly located at `resolver.rs:131` (dns.md:198)
- **HickoryRecursor impl block**: Correctly located at `resolver.rs:628` (dns.md:246)
- **TsigVerifier struct**: Located at `tsig.rs:113`, documented at line 118 (minor offset)
- **TrustAnchorManager impl**: Correctly located at `trust_anchor.rs:191` (dns.md:276)
- **TrustAnchorState enum**: Correctly located at `trust_anchor.rs:30` (dns.md:160)
- **RecursiveDnsServer struct**: Correctly located at `recursive.rs:52` (dns.md:145)
- **DnsServer::new()**: Correctly located at `server/mod.rs:573` (dns.md:224)
- **QueryCoalescer::with_config()**: Called at `server/mod.rs:634-644` (dns_deep_dive:68)
- **QueryContext**: Located at `server/mod.rs:419-445` (dns_deep_dive:69)
- **Cookie validation call site**: In `server/query.rs:645-662` (dns.md claims 640-658 — minor offset)
- **BUG-DNS-1 fix verified**: `resolver.rs:693-702` uses `ValidateWithStaticKey` when `enable_dnssec=true` (AGENTS.md)
- **BUG-DNS-4 verified**: `resolver.rs:420-429` HickoryResolver always returns `is_dnssec_validated: false` — documented as by design (AGENTS.md)
- **Cookie server integration verified**: `validate_cookie()` called in `server/query.rs:648` (AGENTS.md)
- **Constant-time comparison**: Cookie validation uses `subtle::ConstantTimeEq` at `cookie.rs:86` ✓
- **Constant-time comparison**: TSIG verification uses `subtle::ConstantTimeEq` ✓
- **Constant-time comparison**: `verify_ds_digest` uses `subtle::ConstantTimeEq` at `dnssec_validation.rs:274` ✓
- **DNSSEC algorithms**: Ed25519 (15) and RSA/SHA-256 (8) correctly documented
- **NSEC3 algorithms**: SHA-1 (1) and SHA-256 (2) supported — correct per `dnssec.rs:206-214`
- **DS digest types**: SHA-1 (1), SHA-256 (2), SHA-384 (4), GOST unsupported (returns error at `dnssec_validation.rs:260`) — correct
- **TSIG algorithms**: HMAC-SHA1, SHA256, SHA384, SHA512 — correct per `tsig.rs:16-19`
- **TrustAnchorConfig fields**: Match between `trust_anchor.rs:147` and config crate `dns_dnssec.rs:237`
- **RecursiveDnsConfig fields**: Match actual struct at `crates/synvoid-config/src/dns/dns_recursive.rs:97`
- **Feature gates**: `anycast_sync` and `mesh_sync` correctly gated with `#[cfg(feature = "mesh")]`
- **acme_dns_challenges**: Correctly gated with `#[cfg(feature = "dns")]`
- **RFC 5011 state machine**: TrustAnchorState variants (Valid, Seen, Pending, Revoked, Removed, Missing) match exactly
- **Zone serial RFC 1982**: `increment_serial_rfc1982()` at `server/mod.rs:185` — correct
- **RecursiveDnsServer methods**: `start()` at recursive.rs:171, `stop()` at 382, `is_running()` at 391, `cache()` at 828, `cache_stats()` at 832 — all verified
- **Wire format functions**: `parse_dns_message()`, `parse_query_name()`, `build_question()`, `build_response_header()`, `build_error_response()` all exist in `wire.rs`
- **DNSSEC signing functions**: `sign_data()`, `create_rrsig_record()`, `create_nsec_record()`, `create_nsec3_record()` all exist in `dnssec_signing.rs`
- **DNSSEC validation functions**: `calculate_key_tag()`, `canonical_rdata()`, `compute_dnskey()`, `compute_ds_digest()`, `verify_ds_digest()` all exist in `dnssec_validation.rs`
- **TrustAnchorManager methods**: `add_anchor()`, `remove_anchor()`, `get_anchors()`, `get_trusted_anchors()`, `observe_dnskey_at_root()`, `trust_anchor_check()`, `process_rfc5011_updates()`, `load_initial_anchors_from_file()` all verified
- **HickoryRecursor methods**: `start_rfc5011_updates()` at 773, `stop_rfc5011_updates()` at 837, `get_trust_anchor_status()` at 844, `lookup_dnskey()` at 1076, `lookup_cds()` at 1155, `perform_rfc5011_trust_anchor_check()` at 1211 — all verified
- **TsigVerifier methods**: `new()`, `add_key()`, `remove_key()`, `verify()`, `sign()` — all verified in `tsig.rs`

## Discrepancies Found

- **dns.md:107** — `zone_index_btree: Arc RwLock<BTreeMap<String, String>>` missing `<` in type. Actual: `zone_index_btree: Arc<RwLock<BTreeMap<String, String>>>` at `server/mod.rs:452`
- **dns.md:226** — `with_cookie_server` documented without `#[cfg(feature = "dns")]` but actual code at `server/mod.rs:863` has `#[cfg(feature = "dns")]`
- **dns.md:341** — Cookie validation claimed at `cookie.rs:640-658` but `validate_cookie()` method is at `cookie.rs:66-86`. Call site is at `server/query.rs:645-662`
- **dns.md:790** — Claims `query_coalesce.rs:117` has `_max_wait_ms` parameter marked unused. The `with_max_wait_time` at line 111 takes `max_wait_ms` (used), and `with_config` at line 121 takes `max_wait_ms` (used). No `_max_wait_ms` exists. This is stale.
- **dns.md:246** — HickoryRecursor `new()` shown at resolver.rs:628 but `impl` block starts at 628, method at 629 (minor)
- **dns.md:265** — TsigVerifier `new()` shown at tsig.rs:118 but actual struct at 113, impl at 118 ✓ (correct for impl block)
- **dns.md:276** — TrustAnchorManager `new()` shown at trust_anchor.rs:191 ✓ (correct)
- **dns.md:224** — `with_acme_dns_challenges` shown at server/mod.rs:573 but that line is `new()`. The builder method is at 855.
- **dns.md:3.1** — DnsServer struct shown with only 16 fields but actual struct has ~30 fields. Missing: `zone_index_dirty`, `geoip_lookup`, `shutdown_tx`, `signer_name`, `rrl_enabled`, `zone_transfer`, `ecs_filter_config`, `hsm_manager`, `anycast_manager`, `mesh_transport`, `acme_dns_challenges` (cfg)
- **dns.md:3.5** — `ZoneSigningKey` shown missing `key_size: Option<u32>` field (actual at `dnssec.rs:124`)
- **dns_deep_dive:70** — Claims `_max_wait_ms` parameter is unused (DNS-2). Actual code shows `max_wait` IS used for timeout at `query_coalesce.rs:145`. The DNS-2 issue appears to be fixed.
- **dns.md:790** vs **dns_deep_dive:70** — Stale `_max_wait_ms`/DNS-2 reference. The coalescer now uses `tokio::timeout` with the configured `max_wait` value.
- **dns_deep_dive:39** — Claims `cookie.rs` implements "RFC 8905/RFC 7873 DNS cookies". RFC 8905 is DNS-over-TLS, not cookies. Should be "RFC 7873 DNS cookies".

## Bugs Identified

- **[low] BUG-DNS-DOC-1**: dns.md:107 has syntax error in type annotation — `Arc RwLock<BTreeMap>` missing angle brackets. Should be `Arc<RwLock<BTreeMap<String, String>>>`.
- **[low] BUG-DNS-DOC-2**: dns.md:790 claims `_max_wait_ms` is unused (DNS-2) but the issue is fixed — `max_wait` is used for `tokio::timeout`. The doc entry is stale.
- **[low] BUG-DNS-DOC-3**: dns_deep_dive:39 incorrectly references "RFC 8905" for DNS cookies. RFC 8905 is "DNS over TLS". The correct RFC for DNS cookies is RFC 7873.
- **[low] BUG-DNS-DOC-4**: dns.md:224 shows `with_acme_dns_challenges` at line 573 but that is `new()`. The builder is at line 855.
- **[low] BUG-DNS-DOC-5**: dns.md:226 shows `with_cookie_server` without `#[cfg(feature = "dns")]` but actual code has it.

## Suggested Improvements

### Missing Module Documentation

| File | Description | Present in docs? |
|------|-------------|-----------------|
| `mesh_dnssec.rs` | `MeshDnsSecValidator`, `MeshTrustAnchor`, `DsRecord` — mesh DNSSEC validation | Not in either doc |
| `platform.rs` | `AnycastSocketPlatform` trait, Linux/FreeBSD/macOS implementations | Not in either doc |
| `prefetch.rs` | `PrefetchConfig`, cache prefetching for popular domains | Not in either doc |
| `secure_server.rs` | `SecureDnsServerBase`, TLS DNS server base abstraction | Not in either doc |
| `sharded_cache.rs` | `ShardedDnsCache` — high-performance sharded DNS cache | Not in either doc |
| `config.rs` | `DnsSettings` helper for DNS configuration | Not in either doc |
| `zone_manager.rs` | Zone index management, `rebuild_zone_index()` | Not in dns.md; mentioned in deep_dive |

### Missing Type Documentation

| Type | File | Description |
|------|------|-------------|
| `DsDigestType` | `dnssec.rs:173` | DS record digest types (SHA-1, SHA-256, SHA-384) |
| `DnsSecKeyStatus` | `dnssec.rs:99` | Status summary for KSK/ZSK |
| `KeyInfo` | `dnssec.rs:88` | Key metadata (type, algorithm, tag, age) |
| `KeyRotationResult` | `dnssec.rs:76` | Result of key rotation operation |
| `RolloverState` | `dnssec.rs:104` | KSK/ZSK rollover state tracking |
| `CryptoRngAdapter` | `dnssec.rs:33` | RNG adapter for rand_core 0.6 compatibility |
| `ShardedDnsCache` | `sharded_cache.rs:22` | Sharded cache for high concurrency |
| `SecureDnsServerBase` | `secure_server.rs:21` | TLS DNS server base |
| `DnsSettings` | `config.rs:7` | DNS configuration helper |
| `PrefetchConfig` | `prefetch.rs:9` | Cache prefetch configuration |

### Code Quality Observations

- **TrustAnchorConfig duplication**: Two identical `TrustAnchorConfig` structs exist — one in `src/dns/trust_anchor.rs:147` and one in `crates/synvoid-config/src/dns/dns_dnssec.rs:237`. Consider consolidating.
- **DnsServer struct**: 30+ fields — consider grouping into sub-structs (e.g., `DnsServerNetworking`, `DnsServerSecurity`, `DnsServerMesh`) for maintainability.
- **`zone_manager.rs`**: Contains `DnsServer` methods (`reverse_domain`, `rebuild_zone_index`) but is separate from `server/mod.rs` — consider merging into `server/zone.rs` or documenting the split.

## Stale Content

- **dns.md:790** — `_max_wait_ms` parameter marked unused. This was fixed via DNS-QUERY (AGENTS.md:232): "Async redesign with tokio::timeout". The coalescer now uses `tokio::timeout(self.max_wait, receiver.recv())` at `query_coalesce.rs:145`.
- **dns_deep_dive:70** — Same stale DNS-2 reference. The `_max_wait_ms` is no longer unused.
- **dns.md:3.1 DnsServer struct** — Incomplete field listing. Missing ~14 fields that exist in the actual struct.
- **dns.md:9.5 RecursiveCacheKey** — Shows `client_subnet: Option<IpAddr>` which matches actual code ✓ but this is the only cache key shown — the `RecursiveRecordType` field is also present.

## Cross-Reference Status

| AGENTS.md Item | Status | Notes |
|----------------|--------|-------|
| BUG-DNS-1 (DNSSEC policy always SecurityUnaware) | ✅ FIXED | `resolver.rs:693-702` now uses `ValidateWithStaticKey` — verified |
| BUG-DNS-4 (HickoryResolver always false) | ✅ DONE | By design — hickory-resolver API doesn't expose validation status. Documented correctly in both docs |
| DNS Cookie Server not integrated | ✅ FIXED | `validate_cookie()` wired in `server/query.rs:648` — verified |
| DNS-QUERY (QueryCoalescer max_wait_ms) | ✅ FIXED | Async redesign with `tokio::timeout` — verified at `query_coalesce.rs:145` |
| DnsConfig.validate() called in MainConfig | ✅ FIXED | Verified in AGENTS.md verified items |
| HickoryRecursor DNSSEC | ✅ FIXED | Uses `ValidateWithStaticKey` with trust anchors when `enable_dnssec=true` |
| DNSSEC Limitations (dnssec.rs:1-13) | Still accurate | Manual wire format construction, no compression support — matches actual code comments |
