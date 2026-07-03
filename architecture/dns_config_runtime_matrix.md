# DNS Config–Runtime Matrix

Phase 5 deliverable — maps every public DNS config field to its runtime consumer, status, test coverage, and recommended action.

---

## Table Conventions

| Column | Description |
|--------|-------------|
| **Config path** | Serde path (e.g. `dns.port`) |
| **Default** | Value from `Default` impl in `crates/synvoid-config/src/dns/` |
| **Runtime consumer** | Struct/function that reads the value at runtime |
| **Status** | `implemented` / `partially implemented` / `validation-only` / `documented-only` / `unsupported` / `deferred` |
| **Tests** | Existing test coverage (blank = none) |
| **Action** | What remains for full Phase 5 completeness |

---

## 1. DnsConfig (root)

Source: `crates/synvoid-config/src/dns/mod.rs:75`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.enabled` | `false` | `DnsServer::new()` startup gate | implemented | startup tests | none |
| `dns.bind_address` | `"0.0.0.0"` | `configured_bind_addr()` | implemented | startup bind tests | none |
| `dns.port` | `53` | `configured_bind_addr()` | implemented | startup bind tests | none |
| `dns.mode` | `Standalone` | `validate()` checks Mesh only; standalone path implicit | validation-only | none | document as validation-only; no runtime dispatch on mode |
| `dns.ratelimit.mode` | `Shared` | `DnsRateLimiter::new()` | implemented | none | add rate-limit mode tests |
| `dns.ratelimit.per_second` | `500` | `DnsRateLimiter::new()` | implemented | none | add rate-limit tests |
| `dns.ratelimit.per_minute` | `5000` | `DnsRateLimiter::new()` | implemented | none | add rate-limit tests |
| `dns.rrl.enabled` | `true` | `DnsRrl` flag on `DnsServer` | implemented | none | add RRL tests |
| `dns.rrl.responses_per_second` | `100` | `DnsRrl` config | implemented | none | add RRL tests |
| `dns.rrl.window_secs` | `5` | `DnsRrl` config | implemented | none | add RRL tests |
| `dns.rrl.max_responses` | `1000` | `DnsRrl` config | implemented | none | add RRL tests |
| `dns.rrl.ttl` | `300` | `DnsRrl` config | implemented | none | add RRL tests |
| `dns.firewall.enabled` | `false` | `DnsFirewall::new()` | implemented | none | add firewall tests |
| `dns.firewall.block_internal_ips` | `true` | `DnsFirewall::new()` — adds 8 subnet rules | implemented | none | add test |
| `dns.firewall.block_zone_transfers` | `true` | `DnsFirewall::new()` — adds AXFR block rule | implemented | none | add test |
| `dns.firewall.default_action` | `Allow` | not consumed | unsupported | none | document or wire |
| `dns.firewall.max_rules` | `1000` | not consumed | unsupported | none | document or wire |
| `dns.firewall.rebinding_protection.enabled` | `true` | `rebinding_protection()` exists, not wired | partially implemented | none | wire or document |
| `dns.firewall.rebinding_protection.min_ttl_for_internal` | `1800` | not consumed | unsupported | none | document or wire |
| `dns.firewall.rebinding_protection.allowed_internal_domains` | `[]` | not consumed | unsupported | none | document or wire |
| `dns.firewall.rebinding_protection.block_short_ttl_internal` | `false` | not consumed | unsupported | none | document or wire |
| `dns.settings` | see §2 | see §2 | implemented | see §2 | see §2 |
| `dns.mesh` | see §6 | validated in mesh mode only | validation-only | none | document as deferred |
| `dns.zones` | `[]` | external zone loading via `DnsZonesConfig` | documented-only | none | document as external integration point |
| `dns.limits` | see §7 | see §7 | implemented | see §7 | see §7 |
| `dns.dnssec.enabled` | `false` | `DnsSecKeyManager::new()` | implemented | dnssec tests | none |
| `dns.dnssec.domain` | `""` | `DnsSecKeyManager::new()` | implemented | dnssec tests | none |
| `dns.dnssec.key_path` | `"/var/lib/synvoid/dns/keys"` | `DnsSecKeyManager::new()` | implemented | dnssec tests | none |
| `dns.dnssec.rollover_interval_days` | `30` | key rotation scheduler | implemented | dnssec tests | none |
| `dns.dnssec.algorithm` | `Ed25519` | key generation | implemented | dnssec tests | none |
| `dns.dnssec.rsa_key_size` | `2048` | RSA key generation | implemented | dnssec tests | none |
| `dns.dnssec.ksk_key_size` | `4096` | KSK generation | implemented | dnssec tests | none |
| `dns.dnssec.nsec3_enabled` | `true` | NSEC3 chain building | implemented | dnssec tests | none |
| `dns.dnssec.nsec_enabled` | `false` | NSEC chain building | implemented | dnssec tests | none |
| `dns.dnssec.nsec3_iterations` | `50` | NSEC3 hash iterations | implemented | dnssec tests | none |
| `dns.dnssec.nsec3_algorithm` | `1` | NSEC3 hash algorithm | implemented | dnssec tests | none |
| `dns.dnssec.tsig_keys` | `[]` | TSIG authentication | implemented | tsig tests | none |
| `dns.dnssec.hsm.enabled` | `false` | HSM integration | implemented | hsm tests | none |
| `dns.dot.enabled` | `false` | `DotServer::new()` | implemented | none | add DoT tests |
| `dns.dot.port` | `853` | `DotServer::new()` | implemented | none | add DoT tests |
| `dns.dot.bind_address` | `""` | `DotServer::new()` | implemented | none | add DoT tests |
| `dns.dot.tls_cert_path` | `None` | `DotServer::new()` | implemented | none | add DoT tests |
| `dns.dot.tls_key_path` | `None` | `DotServer::new()` | implemented | none | add DoT tests |
| `dns.dot.use_system_cert_store` | `true` | TLS config | implemented | none | add DoT tests |
| `dns.doh.enabled` | `false` | `DohServer::new()` | implemented | none | add DoH tests |
| `dns.doh.port` | `443` | `DohServer::new()` | implemented | none | add DoH tests |
| `dns.doh.bind_address` | `""` | `DohServer::new()` | implemented | none | add DoH tests |
| `dns.doh.path` | `"/dns-query"` | `DohServer::new()` | implemented | none | add DoH tests |
| `dns.doh.json_path` | `""` | `DohServer::new()` | implemented | none | add DoH tests |
| `dns.doh.tls_cert_path` | `None` | TLS config | implemented | none | add DoH tests |
| `dns.doh.tls_key_path` | `None` | TLS config | implemented | none | add DoH tests |
| `dns.doh.use_system_cert_store` | `true` | TLS config | implemented | none | add DoH tests |
| `dns.doq.enabled` | `false` | `DoqServer::new()` | implemented | none | add DoQ tests |
| `dns.doq.port` | `853` | `DoqServer::new()` | implemented | none | add DoQ tests |
| `dns.doq.bind_address` | `""` | `DoqServer::new()` | implemented | none | add DoQ tests |
| `dns.doq.tls_cert_path` | `None` | TLS config | implemented | none | add DoQ tests |
| `dns.doq.tls_key_path` | `None` | TLS config | implemented | none | add DoQ tests |
| `dns.doq.use_system_cert_store` | `true` | TLS config | implemented | none | add DoQ tests |
| `dns.doq.max_concurrent_streams` | `100` | QUIC stream config | implemented | none | add DoQ tests |
| `dns.doq.idle_timeout_secs` | `30` | QUIC idle timeout | implemented | none | add DoQ tests |
| `dns.rpz.enabled` | `false` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.rpz.primary_zone` | `""` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.rpz.allow_transfer` | `[]` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.rpz.refresh_interval_secs` | `0` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.rpz.retry_interval_secs` | `0` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.rpz.expire_interval_secs` | `0` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.rpz.min_ttl` | `0` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.rpz.max_ttl` | `0` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.rpz.default_action` | `""` | not consumed | unsupported | none | document as deferred to Phase 7 |
| `dns.dns64.enabled` | `false` | `Dns64Translator::new()` | implemented | dns64 tests | none |
| `dns.dns64.prefix` | `"64:ff9b::"` | `Dns64Translator::new()` | implemented | dns64 tests | none |
| `dns.dns64.exclude_aaaa_synthesis` | `false` | not in runtime struct | partially implemented | none | wire or document |
| `dns.prefetch.enabled` | `false` | not consumed | unsupported | none | document as deferred |
| `dns.prefetch.min_query_count` | `10` | not consumed | unsupported | none | document as deferred |
| `dns.prefetch.prefetch_ttl_threshold` | `300` | not consumed | unsupported | none | document as deferred |
| `dns.prefetch.max_prefetched_names` | `1000` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.enabled` | `false` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.db_path` | `"/var/lib/synvoid/dns/trust_anchors.db"` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.anchor_file_path` | `"/var/lib/synvoid/dns/trusted-key.key"` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.refresh_interval_secs` | `3600` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.pending_observation_days` | `30` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.revocation_grace_days` | `30` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.extended_removal_days` | `60` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.trust_anchor_retention_days` | `7` | not consumed | unsupported | none | document as deferred |
| `dns.trust_anchors.allow_key_rotation` | `true` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.enabled` | `false` | feature gate check only | validation-only | none | document feature-gate behavior |
| `dns.anycast.bind_addresses` | `[]` | not consumed | unsupported | none | document as deferred to mesh integration |
| `dns.anycast.port` | `53` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.use_pktinfo` | `true` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.health_check_domain` | `"_healthcheck.local"` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.health_check_interval_secs` | `5` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.capacity` | `10000` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.mesh_based_sync` | `true` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.sync_interval_secs` | `300` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.geo` | `None` | not consumed | unsupported | none | document as deferred |
| `dns.anycast.sync_trigger_on_update` | `true` | not consumed | unsupported | none | document as deferred |
| `dns.recursive` | see §5 | see §5 | implemented | see §5 | see §5 |

---

## 2. DnsSettingsConfig

Source: `crates/synvoid-config/src/dns/dns_settings.rs:9`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.settings.default_ttl` | `300` | not consumed | unsupported | none | wire or document |
| `dns.settings.min_geo_ttl` | `60` | `DnsHandlerState.min_geo_ttl` | implemented | none | add test |
| `dns.settings.allow_transfer` | `[]` | not consumed | deferred | none | document as deferred to Phase 7 |
| `dns.settings.cache_enabled` | `true` | `DnsCache::new()` | implemented | cache tests | none |
| `dns.settings.cache_size` | `100000` | `DnsCache::new()` capacity | implemented | cache tests | document as entry count |
| `dns.settings.cache_max_ttl` | `3600` | `DnsCache::new()` | implemented | cache tests | none |
| `dns.settings.cache_min_ttl` | `60` | `DnsCache::new()` | implemented | cache tests | none |
| `dns.settings.negative_cache_ttl` | `300` | `DnsHandlerState.negative_cache_ttl` | implemented | none | add negative TTL test |
| `dns.settings.allow_wildcard_transfer` | `false` | not consumed | deferred | none | document as deferred |
| `dns.settings.wildcard_transfer_requires_tsig` | `true` | not consumed | deferred | none | document as deferred |
| `dns.settings.require_tsig` | `true` | not consumed | deferred | none | document as deferred |
| `dns.settings.serve_stale.enabled` | `false` | `DnsCache::new()` hardcodes false | partially implemented | none | wire `with_serve_stale()` constructor |
| `dns.settings.serve_stale.max_stale_secs` | `86400` | stale expiry | partially implemented | none | wire from config |
| `dns.settings.serve_stale.max_stale_count` | `100` | stale eviction | partially implemented | none | wire from config |
| `dns.settings.ixfr_history_size` | `200` | not consumed | deferred | none | document as deferred |
| `dns.settings.ixfr_enabled` | `true` | not consumed | deferred | none | document as deferred |
| `dns.settings.ixfr_fallback_to_axfr` | `true` | not consumed | deferred | none | document as deferred |
| `dns.settings.ecs_filtering.enabled` | `false` | `EcsFilterConfig::from_settings()` | implemented | ecs tests | none |
| `dns.settings.ecs_filtering.prefix_v4` | `24` | ECS filtering | implemented | ecs tests | none |
| `dns.settings.ecs_filtering.prefix_v6` | `48` | ECS filtering | implemented | ecs tests | none |
| `dns.settings.ecs_filtering.allow_private_prefix` | `false` | ECS filtering | implemented | ecs tests | none |
| `dns.settings.padding.enabled` | `false` | `DnsPadding` struct exists, not wired | partially implemented | none | wire from config or document deferred |
| `dns.settings.padding.block_size` | `128` | not consumed | partially implemented | none | wire or document deferred |
| `dns.settings.padding.mode` | `Normal` | not consumed | partially implemented | none | wire or document deferred |
| `dns.settings.query_coalescing.enabled` | `false` | `QueryCoalescer::with_config()` | implemented | coalescing tests | none |
| `dns.settings.query_coalescing.max_wait_ms` | `500` | `QueryCoalescer` | implemented | coalescing tests | none |
| `dns.settings.query_coalescing.max_entries` | `10000` | `QueryCoalescer` | implemented | coalescing tests | none |
| `dns.settings.query_coalescing.entry_ttl_secs` | `30` | `QueryCoalescer` | implemented | coalescing tests | none |
| `dns.settings.query_coalescing.cleanup_interval_secs` | `10` | `QueryCoalescer` | implemented | coalescing tests | none |
| `dns.settings.dynamic_update.enabled` | `false` | handler exists, set to `None` | partially implemented | none | document as deferred |
| `dns.settings.dynamic_update.allow_any` | `false` | not consumed | deferred | none | document as deferred |
| `dns.settings.dynamic_update.require_tsig` | `false` | not consumed | deferred | none | document as deferred |
| `dns.settings.notify.enabled` | `false` | handler exists, set to `None` | partially implemented | none | document as deferred |
| `dns.settings.notify.also_notify` | `[]` | not consumed | deferred | none | document as deferred |
| `dns.settings.qname_privacy.enabled` | `false` | `sanitize_qname()` exists, not wired | partially implemented | none | document as deferred |
| `dns.settings.qname_privacy.mode` | `ZoneOnly` | not consumed | partially implemented | none | document as deferred |
| `dns.settings.qname_privacy.log_level` | `Zone` | not consumed | partially implemented | none | document as deferred |

---

## 3. DNS Firewall Config (DnsFirewallConfig)

Source: `crates/synvoid-config/src/dns/dns_firewall.rs:131`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.firewall.enabled` | `false` | `DnsFirewall::new()` | implemented | none | add firewall tests |
| `dns.firewall.block_internal_ips` | `true` | adds 8 subnet rules | implemented | none | add test |
| `dns.firewall.block_zone_transfers` | `true` | adds AXFR block rule | implemented | none | add test |
| `dns.firewall.default_action` | `Allow` | not consumed | unsupported | none | document or wire |
| `dns.firewall.max_rules` | `1000` | not consumed | unsupported | none | document or wire |
| `dns.firewall.rebinding_protection.enabled` | `true` | function exists, not wired | partially implemented | none | wire or document |
| `dns.firewall.rebinding_protection.min_ttl_for_internal` | `1800` | not consumed | unsupported | none | document or wire |
| `dns.firewall.rebinding_protection.allowed_internal_domains` | `[]` | not consumed | unsupported | none | document or wire |
| `dns.firewall.rebinding_protection.block_short_ttl_internal` | `false` | not consumed | unsupported | none | document or wire |

---

## 4. DnsLimitsConfig

Source: `crates/synvoid-config/src/dns/dns_firewall.rs:7`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.limits.max_tcp_connections` | `500` | TCP listener config | implemented | none | add test |
| `dns.limits.max_concurrent_queries` | `2500` | semaphore permits | implemented | none | add test |
| `dns.limits.max_query_size` | `65535` | `DnsQueryValidator` | implemented | validator tests | none |
| `dns.limits.max_response_size` | `65535` | `DnsQueryValidator` | implemented | validator tests | none |
| `dns.limits.max_records_per_response` | `1000` | `DnsQueryValidator` | implemented | validator tests | none |
| `dns.limits.max_tcp_idle_time_secs` | `300` | TCP idle timeout | implemented | none | add test |
| `dns.limits.max_tcp_query_time_secs` | `30` | TCP query timeout | implemented | none | add test |
| `dns.limits.udp_buffer_size` | `65535` | UDP recv buffer | implemented | startup tests | none |
| `dns.limits.enable_graceful_degradation` | `false` | load shedding | implemented | none | add test |

---

## 5. Recursive DNS Config

Source: `crates/synvoid-config/src/dns/dns_recursive.rs:97`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.recursive.enabled` | `false` | `RecursiveDnsServer::new()` | implemented | recursive tests | none |
| `dns.recursive.bind_address` | `"127.0.0.1"` | UDP/TCP bind | implemented | recursive tests | none |
| `dns.recursive.port` | `1053` | UDP/TCP bind | implemented | recursive tests | none |
| `dns.recursive.upstream_provider` | `System` | provider selection | implemented | recursive tests | none |
| `dns.recursive.upstream_servers` | `[]` | custom upstreams | implemented | recursive tests | none |
| `dns.recursive.cache.capacity` | `1000000` | recursive cache size | implemented | recursive cache tests | none |
| `dns.recursive.cache.negative_ttl_secs` | `300` | negative cache TTL | implemented | recursive cache tests | none |
| `dns.recursive.cache.stale_ttl_secs` | `86400` | not consumed | unsupported | none | document or wire |
| `dns.recursive.cache.max_ttl_secs` | `86400` | not consumed | unsupported | none | document or wire |
| `dns.recursive.cache.min_ttl_secs` | `0` | not consumed | unsupported | none | document or wire |
| `dns.recursive.dnssec_validation` | `true` | passed to HickoryRecursor | implemented | recursive tests | none |
| `dns.recursive.qname_minimization` | `true` | `HickoryResolver` config | implemented | recursive tests | none |
| `dns.recursive.max_concurrent_queries` | `10000` | `Semaphore` permits | implemented | recursive tests | none |
| `dns.recursive.query_timeout_secs` | `5` | only used for DNSSEC warning | partially implemented | none | wire actual timeout |
| `dns.recursive.root_hints_path` | `"root.hints"` | `HickoryRecursor` init | implemented | recursive tests | none |
| `dns.recursive.trust_anchor_path` | `"trusted-key.key"` | `HickoryRecursor` init | implemented | recursive tests | none |
| `dns.recursive.ratelimit.mode` | `Shared` | recursive rate limiter | implemented | none | add test |
| `dns.recursive.ratelimit.per_second` | `500` | recursive rate limiter | implemented | none | add test |
| `dns.recursive.ratelimit.per_minute` | `5000` | recursive rate limiter | implemented | none | add test |
| `dns.recursive.firewall.enabled` | `false` | recursive firewall | implemented | none | add test |
| `dns.recursive.firewall.block_internal_ips` | `true` | recursive firewall | implemented | none | add test |
| `dns.recursive.firewall.block_zone_transfers` | `true` | recursive firewall | implemented | none | add test |
| `dns.recursive.firewall.default_action` | `Allow` | not consumed | unsupported | none | document or wire |
| `dns.recursive.firewall.max_rules` | `1000` | not consumed | unsupported | none | document or wire |
| `dns.recursive.firewall.rebinding_protection.enabled` | `true` | not consumed | unsupported | none | document or wire |

---

## 6. DnsMeshConfig

Source: `crates/synvoid-config/src/dns/dns_mesh.rs:9`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.mesh.register_to_global` | `true` | validated only (mesh mode) | validation-only | none | document as deferred to mesh integration |
| `dns.mesh.registration_interval_secs` | `60` | validated only | validation-only | none | document as deferred |
| `dns.mesh.accept_registrations` | `true` | validated only | validation-only | none | document as deferred |
| `dns.mesh.sync_interval_secs` | `30` | validated only | validation-only | none | document as deferred |
| `dns.mesh.upstream_dns_servers` | `[]` | validated only | validation-only | none | document as deferred |
| `dns.mesh.verification_retry_interval_secs` | `30` | validated only | validation-only | none | document as deferred |
| `dns.mesh.verification_timeout_secs` | `600` | validated only | validation-only | none | document as deferred |
| `dns.mesh.qname_minimization` | `true` | validated only | validation-only | none | document as deferred |
| `dns.mesh.require_cert_chain_verification` | `false` | validated only | validation-only | none | document as deferred |

---

## 7. DnsZonesConfig

Source: `crates/synvoid-config/src/dns/dns_zones.rs:6`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.zones` | `[]` | external zone loading | documented-only | none | document as external integration point |

---

## 8. DnsSecConfig Sub-fields

Source: `crates/synvoid-config/src/dns/dns_dnssec.rs:10`

All DNSSEC fields are covered in §1 root table. Key sub-structs:

| Sub-struct | Default | Runtime consumer | Status |
|---|---|---|---|
| `DnsSecConfig.hsm` | disabled | HSM key storage | implemented |
| `DnsSecConfig.tsig_keys` | `[]` | TSIG authentication | implemented |

---

## 9. Encrypted DNS Sub-fields

Source: `crates/synvoid-config/src/dns/dns_encrypted.rs`

All DoT/DoH/DoQ fields are covered in §1 root table.

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total config fields** | ~110 |
| **Fully implemented** | ~60 |
| **Partially implemented** | ~10 |
| **Validation-only** | ~10 |
| **Deferred (planned for future phases)** | ~15 |
| **Unsupported / documentation-only** | ~15 |

---

## Deferred Features (Phase 7+)

| Feature | Config fields | Notes |
|---------|---------------|-------|
| RPZ (Response Policy Zones) | `dns.rpz.*` (10 fields) | No runtime consumer exists |
| Dynamic Update | `dns.settings.dynamic_update.*` (3 fields) | Handler stub exists, set to `None` |
| Notify | `dns.settings.notify.*` (2 fields) | Handler stub exists, set to `None` |
| Zone Transfer (AXFR/IXFR) | `dns.settings.ixfr_*`, `dns.settings.allow_transfer` | Config only, no runtime |
| Trust Anchors (custom) | `dns.trust_anchors.*` (9 fields) | Config struct exists, no runtime consumer |
| Prefetch | `dns.prefetch.*` (4 fields) | Config struct exists, no runtime consumer |
| Anycast | `dns.anycast.*` (11 fields) | Requires mesh integration |
| Padding | `dns.settings.padding.*` (3 fields) | `DnsPadding` struct exists, not wired |
| QNAME Privacy | `dns.settings.qname_privacy.*` (3 fields) | `sanitize_qname()` exists, not wired |

---

## Phase 5 Changes Applied

### Changes Made

1. **serve_stale wiring** (`crates/synvoid-dns/src/server/mod.rs`): `DnsServer::new()` now uses `DnsCache::with_serve_stale()` when `config.settings.serve_stale.enabled` is true, passing `max_stale_secs` from config. Previously, `DnsCache::new()` hardcoded `serve_stale_enabled: false`.

2. **DNS64 exclude_aaaa_synthesis** (`crates/synvoid-dns/src/dns64.rs`, `crates/synvoid-dns/src/server/mod.rs`): Added `exclude_aaaa_synthesis: bool` to runtime `Dns64Config`. When true, `should_synthesize()` returns false and AAAA synthesis is skipped. Wired from `config.dns64.exclude_aaaa_synthesis`.

3. **New integration test suite** (`crates/synvoid-dns/tests/dns_config_fidelity.rs`): 12+ tests covering cache serve_stale, min/max TTL, DNS64 synthesis/disable/custom prefix/exclude flag, ECS filter behavior, and firewall rules.

4. **Recursive isolation tests** (`crates/synvoid-dns/tests/dns_recursive_isolation.rs`): 25 tests covering recursive mode bind address independence, cache isolation, authoritative REFUSED without zones, anycast/mesh feature gate validation, config validation guards, and deferred feature behavior documentation.

### Deferred Features (Confirmed Phase 7+)

The following features have config fields but are confirmed deferred. They do NOT alter runtime behavior and are documented as such:

| Feature | Config Fields | Reason Deferred |
|---------|--------------|-----------------|
| RPZ (Response Policy Zones) | `dns.rpz.*` | Requires rule database engine |
| Dynamic Update | `dns.settings.dynamic_update` | Handler exists but not wired; security-sensitive |
| Notify | `dns.settings.notify` | Handler exists but not wired |
| Zone Transfer (AXFR) | `dns.settings.allow_transfer`, `allow_wildcard_transfer`, `wildcard_transfer_requires_tsig`, `require_tsig` | Security-sensitive; requires TSIG infrastructure |
| IXFR | `dns.settings.ixfr_enabled`, `ixfr_history_size`, `ixfr_fallback_to_axfr` | Requires delta encoding infrastructure |
| Trust Anchors (custom) | `dns.trust_anchors` | Uses system defaults via HickoryRecursor |
| Prefetch | `dns.prefetch.*` | Requires predictive cache warming logic |
| Anycast | `dns.anycast.*` | Requires mesh feature gate |
| QName Privacy | `dns.settings.qname_privacy` | Logging integration not wired |
| Padding | `dns.settings.padding` | EDNS padding struct exists but not wired from config |
| Firewall default_action | `dns.firewall.default_action` | Always Allow; configurable action deferred |
| Firewall max_rules | `dns.firewall.max_rules` | Rule count limit not enforced |
| Rebinding Protection | `dns.firewall.rebinding_protection` | Function exists, not wired into query path |
| Recursive cache TTL overrides | `dns.recursive.cache.stale_ttl_secs`, `max_ttl_secs`, `min_ttl_secs` | Not consumed in RecursiveDnsCache |
| Query timeout | `dns.recursive.query_timeout_secs` | Only used for DNSSEC warning, not actual timeout |
| Default TTL | `dns.settings.default_ttl` | Not consumed in runtime |

### Safe Default Profiles

#### Authoritative-only (safe default)
```toml
[dns]
enabled = true
bind_address = "0.0.0.0"
port = 53
mode = "Standalone"

[dns.settings]
cache_enabled = true
cache_size = 100000
serve_stale = { enabled = false }

[dns.recursive]
enabled = false

[dns.firewall]
enabled = true
block_internal_ips = true
block_zone_transfers = true
```

#### Recursive resolver (safe default)
```toml
[dns]
enabled = true
bind_address = "127.0.0.1"
port = 5353
mode = "Standalone"

[dns.recursive]
enabled = true
bind_address = "127.0.0.1"
port = 5353
upstream_provider = "SystemResolvConf"
dnssec_validation = true
qname_minimization = true
max_concurrent_queries = 100

[dns.settings]
cache_enabled = true
serve_stale = { enabled = false }

[dns.firewall]
enabled = true
block_internal_ips = true
```

### Dangerous Features (Operator Warning)

| Feature | Risk | Mitigation |
|---------|------|------------|
| `dns.recursive.enabled` on 0.0.0.0 | Open resolver amplification | Bind to 127.0.0.1 or firewall |
| `dns.settings.allow_transfer = true` | Zone data exfiltration | Require TSIG, restrict IPs |
| `dns.settings.dynamic_update = true` | Unauthorized zone modification | Require TSIG, restrict IPs |
| `dns.settings.allow_wildcard_transfer = true` | Broader zone exposure | Require TSIG |
| `dns.firewall.enabled = false` | No query filtering | Enable in production |

---

## Appendix: Source File Index

| Config struct | Source file |
|---------------|-------------|
| `DnsConfig` | `crates/synvoid-config/src/dns/mod.rs` |
| `DnsSettingsConfig` | `crates/synvoid-config/src/dns/dns_settings.rs` |
| `DnsFirewallConfig` | `crates/synvoid-config/src/dns/dns_firewall.rs` |
| `DnsLimitsConfig` | `crates/synvoid-config/src/dns/dns_firewall.rs` |
| `RecursiveDnsConfig` | `crates/synvoid-config/src/dns/dns_recursive.rs` |
| `DnsMeshConfig` | `crates/synvoid-config/src/dns/dns_mesh.rs` |
| `DnsSecConfig` | `crates/synvoid-config/src/dns/dns_dnssec.rs` |
| `DnsDotConfig`, `DnsDohConfig`, `DnsDoqConfig` | `crates/synvoid-config/src/dns/dns_encrypted.rs` |
| `DnsRateLimitConfig`, `DnsRrlConfig` | `crates/synvoid-config/src/dns/dns_rate_limit.rs` |
| `DnsAnycastConfig` | `crates/synvoid-config/src/dns/dns_anycast.rs` |
| `DnsRpzConfig`, `Dns64Config`, `DnsPrefetchConfig` | `crates/synvoid-config/src/dns/dns_misc.rs` |
| `DnsZonesConfig` | `crates/synvoid-config/src/dns/dns_zones.rs` |
| `TrustAnchorConfig` | `crates/synvoid-config/src/dns/dns_dnssec.rs` |
