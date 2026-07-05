# synvoid-dns Skill

DNS server, DNSSEC validation, TSIG authentication, and dual-mode DNS architecture patterns.

## Verification Gate Tests (Phase 5)

20 tests in `tests/verification_gate.rs` covering gate areas 2–6:

### Gate 2: Zone Lifecycle / Mutation Safety
- `zone_load_reload_is_atomic` — failed reload leaves existing zone data intact
- `store_write_failure_cannot_silently_acknowledge` — SOA-less zone rejected by validate_single_soa
- `all_zone_mutations_invalidate_cache` — DynamicUpdate invalidation scoped to zone

### Gate 3: DNSSEC Correctness
- `dnssec_types_constants_are_correct` — Algorithm/DsDigestType IANA values, NSEC3 defaults
- `nsec_wildcard_no_data_no_match` — NSEC RDATA wire format and type bitmap encoding
- `dnskey_query_returns_expected_structure` — DNSKEY flags/protocol/algorithm/public-key layout
- `rrsig_creation_with_valid_key` — RRSIG wire format, type-covered, labels, TTL, key-tag

### Gate 4: Encrypted Transport Adapters
- `dot_config_all_fields_roundtrip` — DoT serde roundtrip
- `doh_config_all_fields_roundtrip` — DoH serde roundtrip
- `doq_config_all_fields_roundtrip` — DoQ serde roundtrip
- `transport_class_isolation_all_variants` — Udp512/UdpEdns/Tcp/Http/Quic key separation
- `encrypted_transport_config_defaults` — default port/path/streams/timeout values

### Gate 5: Recursive Resolver Safety
- `recursive_disabled_by_default` — default enabled=false, loopback bind, non-standard port
- `recursive_cache_key_shape_isolation` — RecursiveCacheKey vs CacheKey type separation
- `dnssec_validation_state_cache_separation` — Secure/Unchecked/Bogus/Insecure state isolation
- `cname_depth_limit_enforced` — max_cname_depth validation
- `recursive_config_validation` — timeout>0, concurrency>0, negative<=max, open-resolver guard

### Gate 6: Cache / Coalescing Under Advanced Features
- `cache_invalidation_by_name_comprehensive` — zone-scoped invalidation across subdomains
- `recursive_cache_independent_from_authoritative` — cross-cache isolation on invalidate
- `transport_class_cache_isolation` — same query through UDP/TCP/DoH/DoQ returns own data
