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
| `dns.mode` | `Standalone` | `validate()` checks Mesh only; standalone path implicit | validation-only | verification_gate | document as validation-only; no runtime dispatch on mode |
| `dns.ratelimit.mode` | `Shared` | `DnsRateLimiter::new()` | implemented | verification_gate | add rate-limit mode tests |
| `dns.ratelimit.per_second` | `500` | `DnsRateLimiter::new()` | implemented | verification_gate | add rate-limit tests |
| `dns.ratelimit.per_minute` | `5000` | `DnsRateLimiter::new()` | implemented | verification_gate | add rate-limit tests |
| `dns.rrl.enabled` | `true` | `DnsRrl` flag on `DnsServer` | implemented | verification_gate | add RRL tests |
| `dns.rrl.responses_per_second` | `100` | `DnsRrl` config | implemented | verification_gate | add RRL tests |
| `dns.rrl.window_secs` | `5` | `DnsRrl` config | implemented | verification_gate | add RRL tests |
| `dns.rrl.max_responses` | `1000` | `DnsRrl` config | implemented | verification_gate | add RRL tests |
| `dns.rrl.ttl` | `300` | `DnsRrl` config | implemented | verification_gate | add RRL tests |
| `dns.firewall.enabled` | `false` | `DnsFirewall::new()` | implemented | verification_gate | add firewall tests |
| `dns.firewall.block_internal_ips` | `true` | `DnsFirewall::new()` — adds 8 subnet rules | implemented | verification_gate | add test |
| `dns.firewall.block_zone_transfers` | `true` | `DnsFirewall::new()` — adds AXFR block rule | implemented | verification_gate | add test |
| `dns.firewall.default_action` | `Allow` | not consumed | unsupported | verification_gate | document or wire |
| `dns.firewall.max_rules` | `1000` | not consumed | unsupported | verification_gate | document or wire |
| `dns.firewall.rebinding_protection.enabled` | `true` | `rebinding_protection()` exists, not wired | partially implemented | verification_gate | wire or document |
| `dns.firewall.rebinding_protection.min_ttl_for_internal` | `1800` | not consumed | unsupported | verification_gate | document or wire |
| `dns.firewall.rebinding_protection.allowed_internal_domains` | `[]` | not consumed | unsupported | verification_gate | document or wire |
| `dns.firewall.rebinding_protection.block_short_ttl_internal` | `false` | not consumed | unsupported | verification_gate | document or wire |
| `dns.settings` | see §2 | see §2 | implemented | see §2 | see §2 |
| `dns.mesh` | see §6 | validated in mesh mode only | validation-only | verification_gate | document as deferred |
| `dns.zones` | `[]` | external zone loading via `DnsZonesConfig` | documented-only | verification_gate | document as external integration point |
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
| `dns.dot.enabled` | `false` | `DotServer::new()` | implemented | verification_gate, phase45 (bind validation) | none |
| `dns.dot.port` | `853` | `DotServer::new()` + `DnsDotConfig::validate()` (non-zero required when enabled) | implemented | phase45_contract_tests | none |
| `dns.dot.bind_address` | `""` | `DotServer::new()` via `SecureDnsServerBase::start_server()` + `DnsDotConfig::validate()` (explicit parseable bind required when enabled; same semantics as UDP/TCP) | implemented | phase45_contract_tests, secure_server bind-collision test | none |
| `dns.dot.tls_cert_path` | `None` | `DotServer::new()` | implemented | verification_gate | add DoT tests |
| `dns.dot.tls_key_path` | `None` | `DotServer::new()` | implemented | verification_gate | add DoT tests |
| `dns.dot.use_system_cert_store` | `true` | TLS config | implemented | verification_gate | add DoT tests |
| `dns.doh.enabled` | `false` | `DohServer::new()` | implemented | verification_gate, phase45 (bind validation) | none |
| `dns.doh.port` | `443` | `DohServer::new()` + `DnsDohConfig::validate()` (non-zero required when enabled) | implemented | phase45_contract_tests | none |
| `dns.doh.bind_address` | `""` | `DohServer::new()` via `SecureDnsServerBase::start_server()` + `DnsDohConfig::validate()` (explicit parseable bind required when enabled) | implemented | phase45_contract_tests, secure_server bind-collision test | none |
| `dns.doh.path` | `"/dns-query"` | `DohServer::new()` | implemented | verification_gate | add DoH tests |
| `dns.doh.json_path` | `""` | `DohServer::new()` | implemented | verification_gate | add DoH tests |
| `dns.doh.tls_cert_path` | `None` | TLS config | implemented | verification_gate | add DoH tests |
| `dns.doh.tls_key_path` | `None` | TLS config | implemented | verification_gate | add DoH tests |
| `dns.doh.use_system_cert_store` | `true` | TLS config | implemented | verification_gate | add DoH tests |
| `dns.doq.enabled` | `false` | `DoqServer::new()` | implemented | verification_gate | add DoQ tests |
| `dns.doq.port` | `853` | `DoqServer::new()` | implemented | verification_gate | add DoQ tests |
| `dns.doq.bind_address` | `""` | `DoqServer::doq_bind_addr()` (+ `DnsDoqConfig::validate()` requires explicit parseable bind when enabled) | implemented | doq unit tests (IPv4/IPv6/invalid/empty/zero-port) | none (Phase 45 closed; matrix entry was stale) |
| `dns.doq.tls_cert_path` | `None` | TLS config | implemented | verification_gate | add DoQ tests |
| `dns.doq.tls_key_path` | `None` | TLS config | implemented | verification_gate | add DoQ tests |
| `dns.doq.use_system_cert_store` | `true` | TLS config | implemented | verification_gate | add DoQ tests |
| `dns.doq.max_concurrent_streams` | `100` | QUIC stream config | implemented | verification_gate | add DoQ tests |
| `dns.doq.idle_timeout_secs` | `30` | QUIC idle timeout | implemented | verification_gate | add DoQ tests |
| `dns.rpz.enabled` | `false` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.rpz.primary_zone` | `""` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.rpz.allow_transfer` | `[]` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.rpz.refresh_interval_secs` | `0` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.rpz.retry_interval_secs` | `0` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.rpz.expire_interval_secs` | `0` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.rpz.min_ttl` | `0` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.rpz.max_ttl` | `0` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.rpz.default_action` | `""` | not consumed | unsupported | verification_gate | document as deferred to Phase 7 |
| `dns.dns64.enabled` | `false` | `Dns64Translator::new()` | implemented | dns64 tests | none |
| `dns.dns64.prefix` | `"64:ff9b::"` | `Dns64Translator::new()` | implemented | dns64 tests | none |
| `dns.dns64.exclude_aaaa_synthesis` | `false` | `Dns64Translator::should_synthesize()` gate | implemented | dns64 tests | none |
| `dns.prefetch.enabled` | `false` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.prefetch.min_query_count` | `10` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.prefetch.prefetch_ttl_threshold` | `300` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.prefetch.max_prefetched_names` | `1000` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.enabled` | `false` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.db_path` | `"/var/lib/synvoid/dns/trust_anchors.db"` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.anchor_file_path` | `"/var/lib/synvoid/dns/trusted-key.key"` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.refresh_interval_secs` | `3600` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.pending_observation_days` | `30` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.revocation_grace_days` | `30` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.extended_removal_days` | `60` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.trust_anchor_retention_days` | `7` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.trust_anchors.allow_key_rotation` | `true` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.enabled` | `false` | feature gate check only | validation-only | verification_gate | document feature-gate behavior |
| `dns.anycast.bind_addresses` | `[]` | not consumed | unsupported | verification_gate | document as deferred to mesh integration |
| `dns.anycast.port` | `53` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.use_pktinfo` | `true` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.health_check_domain` | `"_healthcheck.local"` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.health_check_interval_secs` | `5` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.capacity` | `10000` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.mesh_based_sync` | `true` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.sync_interval_secs` | `300` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.geo` | `None` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.anycast.sync_trigger_on_update` | `true` | not consumed | unsupported | verification_gate | document as deferred |
| `dns.recursive` | see §5 | see §5 | implemented | see §5 | see §5 |

---

## 2. DnsSettingsConfig

Source: `crates/synvoid-config/src/dns/dns_settings.rs:9`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.settings.default_ttl` | `300` | `DnsServer::new()` fallback TTL during zone record loading (`server/zone.rs:137`) | implemented | verification_gate | none |
| `dns.settings.min_geo_ttl` | `60` | `DnsHandlerState.min_geo_ttl` | implemented | verification_gate | add test |
| `dns.settings.allow_transfer` | `[]` | `ZoneTransfer` struct exists; `zone_transfer` hardcoded to `None` in `DnsServer::new()` (line 950) | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.cache_enabled` | `true` | `DnsCache::new()` | implemented | cache tests | none |
| `dns.settings.cache_size` | `100000` | `DnsCache::new()` capacity | implemented | cache tests | document as weighted byte capacity (moka weigher) |
| `dns.settings.cache_max_ttl` | `3600` | `DnsCache::new()` | implemented | cache tests | none |
| `dns.settings.cache_min_ttl` | `60` | `DnsCache::new()` | implemented | cache tests | none |
| `dns.settings.negative_cache_ttl` | `300` | `DnsHandlerState.negative_cache_ttl` | implemented | `server/query.rs:1931` (`test_extract_ttl_nxdomain_with_soa`), `server/query.rs:1939` (`test_extract_ttl_nxdomain_no_soa_uses_negative_cache`) | none |
| `dns.settings.allow_wildcard_transfer` | `false` | `ZoneTransfer::with_security_config()` accepts this; not wired from config | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.wildcard_transfer_requires_tsig` | `true` | `ZoneTransfer::with_security_config()` accepts this; not wired from config (Phase 45: serde default fixed to match documented default; `= false` rejected) | deferred (activation rejected) | phase45_contract_tests | wire from config or document deferred |
| `dns.settings.require_tsig` | `true` | `ZoneTransfer::with_security_config()` accepts this; not wired from config | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.serve_stale.enabled` | `false` | `DnsCache::with_serve_stale()` | implemented | cache tests | none |
| `dns.settings.serve_stale.max_stale_secs` | `86400` | stale expiry via `DnsCache` | implemented | cache tests | none |
| `dns.settings.serve_stale.max_stale_count` | `100` | `DnsCache::with_serve_stale()` via `max_stale_count` parameter | implemented | cache tests | none |
| `dns.settings.ixfr_history_size` | `200` | not consumed | deferred | verification_gate | wire from config or document deferred |
| `dns.settings.ixfr_enabled` | `true` | IXFR handler exists in `handle_parsed_query_with_cache` but config toggle not consumed | partially implemented | zone mutation tests | wire config toggle or document deferred |
| `dns.settings.ixfr_fallback_to_axfr` | `true` | `ZoneTransfer::with_security_config()` accepts this; not wired from config | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.ecs_filtering.enabled` | `false` | `EcsFilterConfig::from_settings()` | implemented | ecs tests | none |
| `dns.settings.ecs_filtering.prefix_v4` | `24` | ECS filtering | implemented | ecs tests | none |
| `dns.settings.ecs_filtering.prefix_v6` | `48` | ECS filtering | implemented | ecs tests | none |
| `dns.settings.ecs_filtering.allow_private_prefix` | `false` | ECS filtering | implemented | ecs tests | none |
| `dns.settings.padding.enabled` | `false` | `DnsPadding` struct exists in `edns.rs:540`, not wired from config | deferred | verification_gate | wire from config or remove |
| `dns.settings.padding.block_size` | `128` | not consumed | deferred | verification_gate | wire from config or remove |
| `dns.settings.padding.mode` | `Normal` | not consumed | deferred | verification_gate | wire from config or remove |
| `dns.settings.query_coalescing.enabled` | `false` | `QueryCoalescer::with_config()` | implemented | coalescing tests | none |
| `dns.settings.query_coalescing.max_wait_ms` | `500` | `QueryCoalescer` | implemented | coalescing tests | none |
| `dns.settings.query_coalescing.max_entries` | `10000` | `QueryCoalescer` | implemented | coalescing tests | none |
| `dns.settings.query_coalescing.entry_ttl_secs` | `30` | `QueryCoalescer` | implemented | coalescing tests | none |
| `dns.settings.query_coalescing.cleanup_interval_secs` | `10` | `QueryCoalescer` | implemented | coalescing tests | none |
| `dns.settings.dynamic_update.enabled` | `false` | `DynamicUpdateHandler` struct exists; `update_handler` hardcoded to `None` in `DnsServer::new()` (line 952) | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.dynamic_update.allow_any` | `false` | `DynamicUpdateHandler::with_config()` accepts this; not wired from config | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.dynamic_update.require_tsig` | `false` | `DynamicUpdateHandler::with_config()` accepts this; not wired from config | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.notify.enabled` | `false` | `NotifyHandler` struct exists; `notify_handler` hardcoded to `None` in `DnsServer::new()` (line 953) | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.notify.also_notify` | `[]` | `NotifyHandler` struct exists; not wired from config | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
| `dns.settings.qname_privacy.enabled` | `false` | `sanitize_qname()` exists in `dns_settings.rs:245`, not called from DNS query path | deferred | verification_gate | wire into query path or remove |
| `dns.settings.qname_privacy.mode` | `ZoneOnly` | not consumed | deferred | verification_gate | wire into query path or remove |
| `dns.settings.qname_privacy.log_level` | `Zone` | not consumed | deferred | verification_gate | wire into query path or remove |

---

## 3. DNS Firewall Config (DnsFirewallConfig)

Source: `crates/synvoid-config/src/dns/dns_firewall.rs:131`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.firewall.enabled` | `false` | `DnsFirewall::new()` | implemented | verification_gate | add firewall tests |
| `dns.firewall.block_internal_ips` | `true` | adds 8 subnet rules | implemented | verification_gate | add test |
| `dns.firewall.block_zone_transfers` | `true` | adds AXFR block rule | implemented | verification_gate | add test |
| `dns.firewall.default_action` | `Allow` | not consumed | unsupported | verification_gate | document or wire |
| `dns.firewall.max_rules` | `1000` | not consumed | unsupported | verification_gate | document or wire |
| `dns.firewall.rebinding_protection.enabled` | `true` | function exists, not wired | partially implemented | verification_gate | wire or document |
| `dns.firewall.rebinding_protection.min_ttl_for_internal` | `1800` | not consumed | unsupported | verification_gate | document or wire |
| `dns.firewall.rebinding_protection.allowed_internal_domains` | `[]` | not consumed | unsupported | verification_gate | document or wire |
| `dns.firewall.rebinding_protection.block_short_ttl_internal` | `false` | not consumed | unsupported | verification_gate | document or wire |

---

## 4. DnsLimitsConfig

Source: `crates/synvoid-config/src/dns/dns_firewall.rs:7`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.limits.max_tcp_connections` | `500` | TCP listener config | implemented | verification_gate | add test |
| `dns.limits.max_concurrent_queries` | `2500` | semaphore permits | implemented | verification_gate | add test |
| `dns.limits.max_query_size` | `65535` | `DnsQueryValidator` | implemented | validator tests | none |
| `dns.limits.max_response_size` | `65535` | `DnsQueryValidator` | implemented | validator tests | none |
| `dns.limits.max_records_per_response` | `1000` | `DnsQueryValidator` | implemented | validator tests | none |
| `dns.limits.max_tcp_idle_time_secs` | `300` | TCP idle timeout (persistent-loop read deadline; zero rejected by `DnsLimitsConfig::validate()`) | implemented | tcp_lifecycle_tests, dns_phase45_contract | none |
| `dns.limits.max_tcp_query_time_secs` | `30` | TCP per-query body timeout (Phase 45: enforced in persistent loop; previously stored but unenforced on the authoritative path; zero rejected) | implemented | tcp_lifecycle_tests, dns_phase45_contract | none |
| `dns.limits.udp_buffer_size` | `65535` | UDP recv buffer | implemented | startup tests | none |
| `dns.limits.enable_graceful_degradation` | `false` | `ConnectionLimits::enable_graceful_degradation()` wired from config | implemented | verification_gate | add test |

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
| `dns.recursive.cache.stale_ttl_secs` | `86400` | `RecursiveDnsCache` TTL override | implemented | recursive cache tests | none |
| `dns.recursive.cache.max_ttl_secs` | `86400` | `RecursiveDnsCache` max TTL clamp | implemented | recursive cache tests | none |
| `dns.recursive.cache.min_ttl_secs` | `0` | `RecursiveDnsCache` min TTL clamp | implemented | recursive cache tests | none |
| `dns.recursive.dnssec_validation` | `true` | passed to HickoryRecursor | implemented | recursive tests | none |
| `dns.recursive.qname_minimization` | `true` | `HickoryResolver` config | implemented | recursive tests | none |
| `dns.recursive.max_concurrent_queries` | `10000` | `Semaphore` permits | implemented | recursive tests | none |
| `dns.recursive.query_timeout_secs` | `5` | `HickoryResolver` timeout via `create_resolver()` | implemented | recursive tests | none |
| `dns.recursive.root_hints_path` | `"root.hints"` | `HickoryRecursor` init | implemented | recursive tests | none |
| `dns.recursive.trust_anchor_path` | `"trusted-key.key"` | `HickoryRecursor` init | implemented | recursive tests | none |
| `dns.recursive.ratelimit.mode` | `Shared` | recursive rate limiter | implemented | verification_gate | add test |
| `dns.recursive.ratelimit.per_second` | `500` | recursive rate limiter | implemented | verification_gate | add test |
| `dns.recursive.ratelimit.per_minute` | `5000` | recursive rate limiter | implemented | verification_gate | add test |
| `dns.recursive.firewall.enabled` | `false` | recursive firewall | implemented | verification_gate | add test |
| `dns.recursive.firewall.block_internal_ips` | `true` | recursive firewall | implemented | verification_gate | add test |
| `dns.recursive.firewall.block_zone_transfers` | `true` | recursive firewall | implemented | verification_gate | add test |
| `dns.recursive.firewall.default_action` | `Allow` | not consumed | unsupported | verification_gate | document or wire |
| `dns.recursive.firewall.max_rules` | `1000` | not consumed | unsupported | verification_gate | document or wire |
| `dns.recursive.firewall.rebinding_protection.enabled` | `true` | not consumed | unsupported | verification_gate | document or wire |
| `dns.recursive.client_acl.allowed_clients` | `[]` | `RecursiveDnsServer` — CIDR matching in `handle_packet()`/`handle_tcp_connection()` | implemented | 12 ACL tests | none |
| `dns.recursive.client_acl.action` | `"reject"` | ACL match action (allow/reject) | implemented | 12 ACL tests | none |
| `dns.recursive.max_cname_depth` | `10` | `resolve_query_with_depth()` — CNAME chain depth limit | implemented | 9 CNAME/circuit tests | none |
| `dns.recursive.circuit_breaker.failure_threshold` | `5` | `CircuitBreaker` — opens after N failures | implemented | 9 CNAME/circuit tests | none |
| `dns.recursive.circuit_breaker.recovery_timeout_secs` | `30` | `CircuitBreaker` — timeout before half-open | implemented | 9 CNAME/circuit tests | none |
| `dns.recursive.circuit_breaker.success_threshold` | `2` | `CircuitBreaker` — closes after N successes | implemented | 9 CNAME/circuit tests | none |
| `dns.recursive.max_recursion_depth` | `16` | `resolve_query_with_depth()` — NS referral depth limit | implemented | 5 depth/per-client tests | none |
| `dns.recursive.max_per_client_queries` | `100` | `RecursiveDnsServer` — per-IP `Semaphore` in handlers | implemented | 5 depth/per-client tests | none |
| `dns.recursive.ecs.forwarding_policy` | `Never` | `evaluate_ecs_forwarding_policy()` — ECS upstream forwarding | implemented | 16 ECS tests | none |
| `dns.recursive.ecs.prefix_v4` | `24` | `truncate_ecs_prefix()` — IPv4 prefix cap | implemented | 16 ECS tests | none |
| `dns.recursive.ecs.prefix_v6` | `56` | `truncate_ecs_prefix()` — IPv6 prefix cap | implemented | 16 ECS tests | none |
| `dns.recursive.ecs.include_scope_in_response` | `false` | scope response in EDNS | validation-only | verification_gate | wire in recursive server |

---

## 6. DnsMeshConfig

Source: `crates/synvoid-config/src/dns/dns_mesh.rs:9`

| Config path | Default | Runtime consumer | Status | Tests | Action |
|---|---|---|---|---|---|
| `dns.mesh.register_to_global` | `true` | validated only (mesh mode) | validation-only | verification_gate | document as deferred to mesh integration |
| `dns.mesh.registration_interval_secs` | `60` | validated only | validation-only | verification_gate | document as deferred |
| `dns.mesh.accept_registrations` | `true` | validated only | validation-only | verification_gate | document as deferred |
| `dns.mesh.sync_interval_secs` | `30` | validated only | validation-only | verification_gate | document as deferred |
| `dns.mesh.upstream_dns_servers` | `[]` | validated only | validation-only | verification_gate | document as deferred |
| `dns.mesh.verification_retry_interval_secs` | `30` | validated only | validation-only | verification_gate | document as deferred |
| `dns.mesh.verification_timeout_secs` | `600` | validated only | validation-only | verification_gate | document as deferred |
| `dns.mesh.qname_minimization` | `true` | validated only | validation-only | verification_gate | document as deferred |
| `dns.mesh.require_cert_chain_verification` | `false` | validated only | validation-only | verification_gate | document as deferred |

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

All DoT/DoH/DoQ fields are covered in §1 root table. See `architecture/dns.md` § "Encrypted Transport Adapters" for protocol details, transport-class mapping, and shared query pipeline.

### DoT/DoH/DoQ Transport-Class Mapping

| Transport | Config Section | TransportClass | Cache Namespace |
|-----------|---------------|----------------|-----------------|
| DoT | `dns.dot.*` | `Tcp` | Shared with TCP |
| DoH | `dns.doh.*` | `Http` | Separate from TCP |
| DoQ | `dns.doq.*` | `Quic` | Separate from TCP |

### Known Limitations

| Field | Status | Notes |
|-------|--------|-------|
| `dns.doq.bind_address` | implemented (Phase 45) | Honored via `DoqServer::doq_bind_addr()`; explicit bind required when enabled; IPv6 literals supported |
| DoT/DoH/DoQ test coverage | wired, tests added | See `encrypted_transport` test suite, `dot`/`doh`/`doq` unit tests, `dns_phase45_contract`, secure-server bind-collision tests |

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total config fields** | ~170 |
| **Implemented** | ~102 (Phase 45: `dns.doq.bind_address` honored; `max_tcp_query_time_secs` enforced) |
| **Partially implemented** | 1 (`dns.settings.ixfr_enabled`: IXFR handler exists in `handle_parsed_query_with_cache` but the config toggle is not consumed; surrounding transfer activation is rejected) |
| **Validation-only** | 11 |
| **Deferred (no runtime consumer, activation rejected by Phase 45 validation)** | ~45 paths (see Phase 45 mapping) |
| **Fail-closed rejections (Phase 45)** | 30+ activation paths across RPZ, prefetch, trust anchors, anycast, transfers, UPDATE/NOTIFY, padding, QNAME privacy, firewall knobs, scope responses, encrypted binds |

Note: ~45 implemented fields lack dedicated test coverage (DoT/DoH/DoQ, rate limiter, firewall fields). These are wired and functional but not covered by unit/integration tests.

---

## Deferred Features (Phase 7+)

Phase 45 fail-closed rule: **every feature in this table rejects activation at
validation time** with `DnsConfigError::Unsupported { path, reason }` (typed
config path, e.g. `dns.rpz.enabled`). There are no "enabled but ignored"
settings left in supported profiles — defaults and disabled values stay
parseable, activation fails. The mapping is tabulated in "Phase 45 Changes
Applied" below. Future triggers per Workstream F follow each row.

| Feature | Config fields | Notes |
|---------|---------------|-------|
| RPZ (Response Policy Zones) | `dns.rpz.*` (10 fields) | No runtime consumer exists |
| Dynamic Update | `dns.settings.dynamic_update.*` (3 fields) | `DynamicUpdateHandler` struct exists; `update_handler` hardcoded to `None` in `DnsServer::new()` (line 952). Disabled handler returns NOTIMP. |
| Notify | `dns.settings.notify.*` (2 fields) | `NotifyHandler` struct exists; `notify_handler` hardcoded to `None` in `DnsServer::new()` (line 953). Disabled handler returns NOTIMP. |
| Zone Transfer (AXFR/IXFR) | `dns.settings.ixfr_*`, `dns.settings.allow_transfer` | `ZoneTransfer` struct exists; `zone_transfer` hardcoded to `None` in `DnsServer::new()`; IXFR handler exists in `handle_parsed_query_with_cache` but config toggle not consumed |
| Trust Anchors (custom) | `dns.trust_anchors.*` (9 fields) | Config struct exists, no runtime consumer |
| Prefetch | `dns.prefetch.*` (4 fields) | Config struct exists, no runtime consumer |
| Anycast | `dns.anycast.*` (11 fields) | Requires mesh integration |
| Padding | `dns.settings.padding.*` (3 fields) | `DnsPadding` struct exists, not wired |
| QNAME Privacy | `dns.settings.qname_privacy.*` (3 fields) | `sanitize_qname()` exists, not wired |
| Persistent DNS-over-TCP (sequential) | Implemented (Phase 45) | Bounded loop in `handle_tcp_query`: pre-allocation size cap, idle + per-query timeouts, 1000-query bound, permit held, graceful drain. Pipelining/reordering still deferred. Recursive TCP (`handle_tcp_connection`) still single-query — follow-up. |
| Persistent DNS-over-TCP (pipelining) | Deferred | At most one outstanding query per connection by design. |
| EDNS keepalive | Parsed only | `EdnsOptions.keepalive` parsed but not wired into connection management (no negotiated-timeout design yet). |
| Full NSEC3 closest-encloser proofs | N/A | Phase 2 fixed next-closer emission; full closest-encloser proof coverage remains deferred. |
| DoQ `bind_address` | `dns.doq.bind_address` | Implemented (Phase 45): honored via `doq_bind_addr()`, validated before startup. |
| Recursive persistent TCP | N/A | `RecursiveDnsServer::handle_tcp_connection` still serves one query per connection; aligning with the authoritative lifecycle is a follow-up. |
| Recursive validation limitations | N/A | Bailiwick checks are observability-only (not enforced). CD/AD gating tested but full RFC 4035 compliance deferred. |
| External DNSSEC tooling | N/A | dig, ldns-verify-zone, named-checkzone not in CI. External smoke tests require live server. |

---

## Phase 5 Changes Applied

### Changes Made

1. **serve_stale wiring** (`crates/synvoid-dns/src/server/mod.rs`): `DnsServer::new()` now uses `DnsCache::with_serve_stale()` when `config.settings.serve_stale.enabled` is true, passing `max_stale_secs` from config. Previously, `DnsCache::new()` hardcoded `serve_stale_enabled: false`.

2. **DNS64 exclude_aaaa_synthesis** (`crates/synvoid-dns/src/dns64.rs`, `crates/synvoid-dns/src/server/mod.rs`): Added `exclude_aaaa_synthesis: bool` to runtime `Dns64Config`. When true, `should_synthesize()` returns false and AAAA synthesis is skipped. Wired from `config.dns64.exclude_aaaa_synthesis`.

3. **New integration test suite** (`crates/synvoid-dns/tests/dns_config_fidelity.rs`): 17 tests covering cache serve_stale, weighted byte capacity, min/max TTL, max_entry_size, DNS64 synthesis/disable/custom prefix/exclude flag, and ECS filter behavior.

4. **Recursive isolation tests** (`crates/synvoid-dns/tests/dns_recursive_isolation.rs`): 109 tests covering recursive mode bind address independence, cache isolation, authoritative REFUSED without zones, anycast/mesh feature gate validation, config validation guards, zone mutation feature flags (UPDATE/NOTIFY/IXFR/wildcard transfer/TSIG), recursive default safety, deferred feature behavior documentation, client ACL (CIDR matching, IPv6, allow/reject actions), CNAME depth limits, circuit breaker state machine, CD/AD bit handling, DNSSEC validation state, bailiwick validation, routing metrics, ECS forwarding policy, and per-client query limits.

### Phase 2 Matrix Reconciliation Changes

5. **DNS64 `exclude_aaaa_synthesis` status corrected**: Changed from "partially implemented" to "implemented" — investigation confirmed the field is wired at `server/mod.rs:910-926` and `dns64.rs:331-336`.

6. **`cache_size` semantics documented**: Changed action from "document as entry count" to "weighted byte capacity (moka weigher)" — `DnsCache::new()` passes capacity to moka's `.max_capacity()` with a `.weigher()` returning `value.data.len()`.

7. **Zone mutation handler status corrected**: `dynamic_update.enabled` and `notify.enabled` changed from "partially implemented" to "deferred" — `DnsServer::new()` hardcodes `update_handler: None` (line 952) and `notify_handler: None` (line 953). Handler structs exist but are not wired from config.

8. **IXFR handler status corrected**: `ixfr_enabled` changed from "deferred" to "partially implemented" — IXFR handler exists in `handle_parsed_query_with_cache` but the config toggle is not consumed.

9. **Transfer config fields updated**: `allow_transfer`, `allow_wildcard_transfer`, `wildcard_transfer_requires_tsig`, `require_tsig` — `ZoneTransfer` struct exists with these parameters but `zone_transfer` is hardcoded to `None` in `DnsServer::new()` (line 950).

10. **QNAME Privacy and Padding confirmed deferred**: Both features have config structs and partial implementations (`sanitize_qname()` at `dns_settings.rs:245`, `DnsPadding` at `edns.rs:540`) but are not wired into the DNS query path.

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

---

## Milestone Status (Post-Milestone 2 Corrective Pass)

### Closed (Fully Implemented & Tested)

| Item | Details |
|------|---------|
| Cache key dimensions | 7 dimensions: qname, qtype, qclass, dnssec_ok, transport_class, namespace, client_subnet. `CacheKey::from_parsed_authoritative()` and `CacheKey::from_parsed_recursive()` constructors. |
| Cache key fingerprint poisoning | Composite fingerprint key `{qname}\|{qtype}\|{qclass}\|{dnssec_ok}\|{namespace}` prevents cross-type conflicts. |
| TTL extraction (compression-safe) | `skip_dns_name()`, `first_answer_ttl()`, `negative_soa_ttl()` handle compression pointers. Minimum TTL across all answer RRs. |
| TTL extraction (protocol-aware) | Negative TTL from SOA authority: `min(SOA_TTL, SOA_MINIMUM)` clamped to `[0, negative_cache_ttl]`. SERVFAIL/REFUSED not cached (TTL=0). Malformed responses not cached. |
| Cache invalidation on zone load | All zone mutation paths (config load, add_record, dynamic update, zone delete, clear) trigger `cache.invalidate_zone()`. |
| `invalidate_record` fingerprint cleanup | Fingerprint state cleared on authoritative zone mutation. |
| Coalescing exclusions | AXFR, IXFR, UPDATE, NOTIFY excluded from coalescing via `parsed.is_axfr()` / `parsed.is_ixfr()` checks. |
| TCP SERVFAIL response (hard limit) | Echoes original question, preserves RD bit. Byte-size enforced (not advisory). |
| Serve-stale wiring | `DnsCache::with_serve_stale()` used when `serve_stale.enabled = true`. `max_stale_secs` and `max_stale_count` from config. |
| DNS64 `exclude_aaaa_synthesis` | Runtime struct wired at `server/mod.rs:910-926`. Config fidelity test added. |
| Query coalescing metrics | 8 counters: hits, misses, broadcasts, cancels, evictions, timeouts, lagged, in_flight gauge. |
| Cache metrics integration | `InvalidationReason` enum (9 variants), per-reason counters, `DnsCache::with_metrics()` bridge to `DnsMetrics`, `metrics::counter!` calls in all recording methods → auto-collected on port 9090. Prometheus metrics: `dns_cache_hits`, `dns_cache_misses`, `dns_cache_stale_hits`, `dns_cache_negative_hits`, `dns_cache_insertions`, `dns_cache_invalidations`, `dns_cache_poisoned_rejections`, `dns_cache_size_rejections`. |

### Partial (Implemented, Tests Needed)

| Item | Details |
|------|---------|
| ECS/client subnet in cache key | Client IP stored in `CacheKey.client_subnet`. Full ECS prefix routing not yet implemented. |
| Recursive cache TTL overrides | `stale_ttl_secs`, `max_ttl_secs`, `min_ttl_secs` wired from config with tests. |

### Deferred (Config Fields Exist, No Runtime Consumer)

| Item | Config Fields |
|------|---------------|
| RPZ (Response Policy Zones) | `dns.rpz.*` (10 fields) |
| Dynamic Update | `dns.settings.dynamic_update.*` (3 fields) |
| Notify | `dns.settings.notify.*` (2 fields) |
| Zone Transfer (IXFR) | `dns.settings.ixfr_*` (3 fields) |
| Trust Anchors (custom) | `dns.trust_anchors.*` (9 fields) |
| Prefetch | `dns.prefetch.*` (4 fields) |
| Anycast | `dns.anycast.*` (11 fields) |
| Padding | `dns.settings.padding.*` (3 fields) |
| QNAME Privacy | `dns.settings.qname_privacy.*` (3 fields) |
| Firewall default_action | `dns.firewall.default_action` |
| Firewall max_rules | `dns.firewall.max_rules` |
| Rebinding Protection | `dns.firewall.rebinding_protection.*` (4 fields) |

---

## Phase 2 Changes Applied

### Matrix Corrections

1. **`dns.settings.default_ttl`** — Changed from `unsupported` to `implemented`. Field is consumed at `server/zone.rs:137` as fallback TTL during zone record loading.

2. **`dns.settings.negative_cache_ttl`** — Added existing test references: `server/query.rs:1931` (`test_extract_ttl_nxdomain_with_soa`) and `server/query.rs:1939` (`test_extract_ttl_nxdomain_no_soa_uses_negative_cache`).

3. **`dns.limits.enable_graceful_degradation`** — Updated status to `implemented`. Config field is now wired from `DnsServer::new()` to `ConnectionLimits::enable_graceful_degradation()`.

4. **`dns.doq.bind_address`** — Changed from `implemented` to `partially implemented`. `startup.rs:580` hardcodes bind to `0.0.0.0:{port}`; config field is never consumed.

5. **`dns.settings.serve_stale.max_stale_count`** — Updated runtime consumer to document explicit wiring from `DnsCache::with_serve_stale()` parameter.

6. **`dns.recursive.query_timeout_secs`** — Changed from `partially implemented` to `implemented`. Config value now passed to `HickoryResolver` timeout via `create_resolver()`.

### Code Changes

7. **`cache.rs`** — `with_serve_stale()` now accepts `serve_stale_max_stale_count: u64` parameter instead of hardcoding `100`.

8. **`limits.rs`** — `ConnectionLimits::new()` now accepts `enable_graceful_degradation: bool` parameter and calls `enable_graceful_degradation(0.1)` when true.

9. **`resolver.rs`** — `with_qname_minimization()` and `with_upstream_servers()` now accept `timeout_secs: u64` parameter instead of hardcoding `Duration::from_secs(5)`.

10. **`recursive.rs`** — `create_resolver()` passes `config.query_timeout_secs` to all resolver constructors.

11. **`dns_recursive.rs`** — `validate()` now rejects `0.0.0.0` or `::` as bind address with an open-resolver prevention error.

12. **`server/query.rs`** — Disabled zone mutation handlers (NOTIFY, UPDATE, AXFR, IXFR) now return NOTIMP responses instead of silent drops when handlers are `None`.

### New Tests

13. **`dns_config_fidelity`** — 17 tests (existing suite, all passing).
14. **`dns_recursive_isolation`** — 109 tests (existing suite, all passing). Covers open-resolver guard, NOTIMP responses, recursive config validation, client ACL, CNAME depth, circuit breaker, CD/AD bits, DNSSEC validation state, bailiwick, routing metrics, ECS forwarding, per-client limits.

---

## Phase 4 Changes Applied (Recursive Resolver Isolation)

### New Config Fields (13 fields)

1. **Client ACL**: `dns.recursive.client_acl.allowed_clients` (Vec<String>), `dns.recursive.client_acl.action` (String) — CIDR-based client access control
2. **CNAME depth**: `dns.recursive.max_cname_depth` (u8, default 10) — CNAME chain depth limit
3. **Circuit breaker**: `dns.recursive.circuit_breaker.failure_threshold` (u8, default 5), `dns.recursive.circuit_breaker.recovery_timeout_secs` (u64, default 30), `dns.recursive.circuit_breaker.success_threshold` (u8, default 2)
4. **Recursion depth**: `dns.recursive.max_recursion_depth` (u8, default 16) — NS referral depth limit
5. **Per-client limit**: `dns.recursive.max_per_client_queries` (u32, default 100) — per-IP concurrent query limit
6. **ECS forwarding**: `dns.recursive.ecs.forwarding_policy` (Never/Always/CdnOnly/IfPresent), `dns.recursive.ecs.prefix_v4` (u16, default 24), `dns.recursive.ecs.prefix_v6` (u16, default 56), `dns.recursive.ecs.include_scope_in_response` (bool, default false)

### Runtime Wiring

- **Client ACL**: `recursive.rs` `handle_packet()`/`handle_tcp_connection()` — CIDR matching via `ipnetwork` crate, RCODE_REFUSED on mismatch
- **CNAME depth**: `resolve_query_with_depth()` — depth counter on CNAME resolution, SERVFAIL when exceeded
- **Circuit breaker**: `CircuitBreaker` struct (atomics, Send+Sync) — `resolve_upstream()` checks `is_open()`, records success/failure
- **Recursion depth**: `resolve_query_with_depth()` — alongside CNAME depth check
- **Per-client semaphore**: `client_semaphores: Arc<Mutex<HashMap<IpAddr, Arc<Semaphore>>>>` — 1s acquire timeout in handlers
- **CD bit**: `wire.rs` `MessageFlags` — `checking_disabled` field parsed/built; `recursive.rs` CD=1 forces `effective_dnssec_validated = false`
- **AD gating**: `authentic_data = effective_dnssec_validated && dnssec_ok` — AD only set when DO=1
- **Cache DNSSEC state**: `RecursiveCacheKey` gains `dnssec_ok` dimension; `DnssecValidationState` enum (Secure/Insecure/Bogus/Unchecked) replaces boolean
- **Bailiwick**: `is_in_bailiwick()`, `validate_authority_bailiwick()`, `validate_additional_bailiwick()` — observability-only (log + metric)
- **ECS policy**: `evaluate_ecs_forwarding_policy()`, `truncate_ecs_prefix()` — config-driven ECS forwarding
- **Routing metrics**: 5 new `DnsMetrics` counters (recursive_queries, recursive_cache_hits/misses, upstream_forwards/failures)

### New Tests

- 109 `dns_recursive_isolation` tests (up from 31)
- 27 `recursive_cache` tests (DNSSEC state, DO bit separation)

---

## Phase 5 Changes Applied (Verification & Release Gate)

### Verification Results

All 8 gate areas verified on Milestone 2 completion:

| Gate | Result | Details |
|------|--------|---------|
| **Gate 1: Compile and test baseline** | PASS | `cargo fmt --check`, `cargo test -p synvoid-dns` (576 tests), `cargo check --workspace` all pass |
| **Gate 2: Deleted duplicate DNS tree** | PASS | `src/dns/mod.rs` is a clean re-export shim; canonical implementation in `crates/synvoid-dns/` |
| **Gate 3: Config-runtime matrix** | PASS | Summary statistics updated; internal contradictions fixed; deferred features table corrected |
| **Gate 4: Transport/runtime behavior** | PASS | All 8 behaviors tested: bind fail-fast, port zero, TCP lifecycle, TCP hard-limit, UDP truncation, shutdown idempotency, coalescer cleanup, connection guard lifetime |
| **Gate 5: Cache behavior** | PASS | All 9 behaviors tested: cache key dimensions, namespace separation, DO bit, qclass, transport class, TTL extraction, negative TTL, SERVFAIL/REFUSED not cached, mutation invalidation |
| **Gate 6: Coalescing behavior** | PASS | 47 tests covering key dimensions, exclusions, owner/waiter lifecycle, cancellation, timeout, metrics |
| **Gate 7: Recursive isolation** | PASS | 31 tests covering open-resolver prevention, bind address independence, cache isolation, NOTIMP responses, zone mutation feature flags |
| **Gate 8: Documentation** | PASS | All docs updated: config matrix, AGENTS.md, DNS override, skill file |

### Corrections Applied

1. **Summary statistics updated**: Changed from ~110 to ~170 total fields (tables grew but summary was stale).
2. **Internal contradiction fixed**: `dns.recursive.query_timeout_secs` and `dns.settings.default_ttl` removed from Deferred Features table (they are implemented per Phase 2 corrections).
3. **Formatting fix**: `crates/synvoid-dns/src/query_coalesce.rs` reformatted (long `assert_eq!` macros split across lines).

#---

## Milestone 3 Phase 1: Zone Lifecycle, Hardening & Transfer Correctness

Phase 3 introduced zone lifecycle management, hardened zone transfers (AXFR/IXFR), dynamic UPDATE, and NOTIFY. See `architecture/dns_zone_lifecycle.md` for the full state machine.

### Zone Lifecycle States (`server/mod.rs:245`)

`ZoneState` enum governs which operations are permitted per zone:

| State | Meaning | Serves Queries | Accepts Updates |
|-------|---------|---------------|-----------------|
| `Loading` | Zone loaded from config or persistence | No | No |
| `Active` | Fully loaded, serving queries | Yes | Yes |
| `Reloading` | Zone transfer or config reload in progress | No | No |
| `Disabled` | Administratively disabled | No | No |
| `Failed` | Fatal error (corrupt SOA, DNSSEC failure) | No | No |
| `Deleting` | Zone is being deleted | No | No |

State transitions are enforced by `Zone::set_state()` (`server/mod.rs:423`). Invalid transitions return `Err`. See `architecture/dns_zone_lifecycle.md` for the full transition diagram.

### Zone Health Metadata (`server/mod.rs:275`)

```rust
pub struct ZoneHealth {
    pub state: ZoneState,
    pub last_load_time: Option<u64>,   // Unix timestamp of last successful load
    pub last_error: Option<String>,     // Error message if state is Failed
    pub record_count: usize,            // Number of resource records
    pub dnssec_state: DnssecState,      // Unsigned | KeyGeneration | Signed | KeyRollover | SigningFailed
}
```

### SOA Validation (`server/mod.rs:493`)

- Exactly one SOA per zone apex (RFC 1035 §3.3.13)
- `Zone::validate_single_soa()` rejects zones with 0 or >1 SOA records at the apex
- Multi-SOA rejection happens at load time; runtime SERVFAIL if SOA absent (fail-closed)
- Origin normalization: trim trailing dots, lowercase (`Zone::normalize_origin()`)

### Serial Correctness (`server/mod.rs:386`)

- RFC 1982 serial comparison via `Zone::serial_is_more_recent(s1, s2)` — handles wrap-around at 0x80000000
- Monotonic increment via `Zone::increment_serial_rfc1982(current)` — uses timestamp when possible, falls back to `wrapping_add(1)`
- History retention limit: default 200 entries per zone, configurable via `Zone::increment_serial_with_limit(max_history)`
- `ZoneHistory` entries store previous serial, records snapshot, and timestamp for IXFR delta encoding

### Dynamic UPDATE Hardening (`update.rs`)

| Control | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Disabled by default; returns NOTIMP when disabled |
| `require_tsig` | `true` | TSIG authentication required for all updates |
| `allow_any` | `false` | IP allowlist enforcement (CIDR or `*`) |
| `allowed_ips` | `[]` | Client IP allowlist (CIDR notation supported) |
| Per-update metrics | — | Received/accepted/rejected counters via `DnsMetrics` |
| Audit-safe logging | — | MAC values never logged; only client IP and zone name |

`DynamicUpdateHandler` (`update.rs:228`) validates prerequisites, applies adds/deletes atomically, increments serial, stores history, and triggers cache invalidation.

### NOTIFY Hardening (`notify.rs`)

| Control | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Disabled unless explicitly configured |
| `also_notify` | `[]` | Secondary IPs to notify on zone changes |
| Source allowlist | — | Incoming NOTIFY from unknown sources is silently ignored |
| Rate-limiting | — | Per-zone cooldown: serial unchanged → skip NOTIFY (`notify_secondaries()`) |
| TSIG enforcement | optional | TSIG verification on incoming NOTIFY when configured |

### AXFR Hardening (`transfer.rs`)

| Control | Default | Description |
|---------|---------|-------------|
| `axfr_enabled` | `false` | AXFR disabled by default (security-sensitive) |
| `tcp_only` | `true` | AXFR requires TCP transport (RFC 5936 §2) |
| `require_tsig` | `true` | TSIG authentication required for all transfers |
| `allowed_transfers` | `[]` | IP allowlist for outbound transfers |
| `allow_wildcard_transfer` | `false` | Wildcard `*` in allowlist requires explicit opt-in |
| SOA bracketing | — | AXFR responses must begin and end with SOA record |

### IXFR Correctness (`transfer.rs`)

| Control | Default | Description |
|---------|---------|-------------|
| `ixfr_enabled` | `true` | IXFR handler enabled |
| `ixfr_fallback_to_axfr` | `true` | Fall back to AXFR when history is insufficient |
| `max_history_size` | `200` | Maximum IXFR history entries per zone |
| Serial comparison | — | RFC 1982 serial comparison determines if delta is可用 |

### Store Persistence (`store.rs`)

| Feature | Description |
|---------|-------------|
| Atomic writes | SQLite transactions ensure zone records are written atomically |
| Corrupt record handling | Graceful skip with logging; zone remains operational |
| Volatile mode | `ZoneStore::new_volatile()` — in-memory only, no SQLite persistence |
| Schema | `zones` table (id, origin, created_at, updated_at) + `records` table (zone_id, name, type, value, ttl, priority) |

### Cache Invalidation (11 reasons)

All zone mutation paths trigger `cache.invalidate_zone()` with a typed `InvalidationReason`:

| Reason | Trigger |
|--------|---------|
| `ZoneLoad` | Config zone loaded |
| `ZoneLoadFromStore` | Zone restored from SQLite persistence |
| `RecordAdd` | Record inserted into zone |
| `ZoneDelete` | Zone removed from in-memory store |
| `DynamicUpdate` | RFC 2136 update applied |
| `NotifyReceived` | Incoming NOTIFY processed |
| `ManualFlush` | Operator-triggered cache flush |
| `DnssecKeyRollover` | DNSSEC key rollover (full cache clear) |
| `RpzZoneRemoval` | RPZ zone removed (full cache clear) |
| `ZoneTransferAxfr` | Full zone transfer received |
| `ZoneTransferIxfr` | Incremental zone transfer received |

`InvalidationReason` labels are emitted as Prometheus counters via `invalidations_by_reason`.

### Config Fields (M3 Phase 1 additions)

| Config path | Default | Status | Notes |
|---|---|---|---|
| `dns.settings.dynamic_update.enabled` | `false` | wired | Returns NOTIMP when disabled |
| `dns.settings.dynamic_update.allow_any` | `false` | wired | IP allowlist enforcement |
| `dns.settings.dynamic_update.require_tsig` | `true` | wired | TSIG authentication required |
| `dns.settings.notify.enabled` | `false` | wired | Returns NOTIMP when disabled |
| `dns.settings.notify.also_notify` | `[]` | wired | Secondary notification list |
| `dns.settings.ixfr_history_size` | `200` | wired | History retention limit per zone |
| `dns.settings.ixfr_enabled` | `true` | wired | IXFR handler toggle |
| `dns.settings.ixfr_fallback_to_axfr` | `true` | wired | Fallback when history insufficient |

### Test Coverage (M3 Phase 1)

| Test suite | Count | Location |
|------------|-------|----------|
| Zone lifecycle | — | `zone_lifecycle` tests in `server/mod.rs` |
| SOA validation | — | `validate_single_soa` tests |
| Serial comparison | — | `serial_is_more_recent` tests |
| Dynamic UPDATE | — | `update.rs` handler-level tests |
| NOTIFY | — | `notify.rs` handler-level tests |
| AXFR/IXFR | — | `transfer.rs` handler-level tests |
| Store persistence | — | `store.rs` unit tests |
| Cache invalidation reasons | — | `cache.rs` invalidation tests |

---

## Known Limitations (Deferred)

| Item | Status | Notes |
|------|--------|-------|
| DoT/DoH/DoQ test coverage | Wired, no tests | 28 fields implemented but untested |
| Rate limiter test coverage | Wired, no tests | 9 fields implemented but untested |
| Firewall test coverage | Wired, no tests | 3 security controls untested |
| ECS client subnet | Partial | Full prefix routing not implemented |
| DoQ bind address | Partial | Config field ignored, hardcoded to 0.0.0.0 |
| RPZ, Trust Anchors, Prefetch, Anycast, Padding, QNAME Privacy | Deferred | Config fields exist, no runtime consumer |

---

## Milestone 4 Phase 1: Observability and Operations

### New Health Configuration

The `DnsHealthChecker` provides runtime health status. It is configured automatically based on server state:

| Field | Source | Description |
|-------|--------|-------------|
| `listener_bound` | Server startup | UDP/TCP listener successfully bound |
| `zones_loaded` | Zone load | Number of active zones |
| `zones_failed` | Zone load | Number of failed zone loads |
| `recursive_state` | RecursiveDnsServer | Healthy/Degraded/Disabled |
| `cache_operational` | DnsCache | Cache is accepting queries |
| `dnssec_state` | DnsSecKeyManager | Key count, signing status |
| `encrypted_transport_state` | DoT/DoH/DoQ | Cert validity, enabled state |
| `transfer_update_state` | Config | AXFR/IXFR/UPDATE policy |

### New Metrics Fields

All new metrics are emitted via the `metrics` crate and are available in Prometheus format:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `dns_transport_queries` | counter | `transport` | Queries by transport protocol |
| `dns_transport_errors` | counter | `transport` | Errors by transport protocol |
| `dns_operation_counts` | counter | `operation` | Operations by type |
| `dns_zones_loaded` | gauge | — | Currently loaded zones |
| `dns_zone_reload_successes` | counter | — | Successful zone reloads |
| `dns_zone_reload_failures` | counter | — | Failed zone reloads |
| `dns_recursive_circuit_breaker_opens_total` | counter | — | Circuit breaker open events |
| `dns_recursive_circuit_breaker_closes_total` | counter | — | Circuit breaker close events |
| `dnssec_key_rotations_total` | counter | — | DNSSEC key rotation events |
| `dnssec_signing_failures_total` | counter | — | DNSSEC signing failures |
| `dns_update_accepted` | counter | — | Accepted dynamic updates |
| `dns_update_rejected` | counter | — | Rejected dynamic updates |
| `dns_notify_sent` | counter | — | NOTIFY messages sent |
| `dns_notify_received` | counter | — | NOTIFY messages received |
| `dns_axfr_accepted` | counter | — | Accepted AXFR transfers |
| `dns_axfr_rejected` | counter | — | Rejected AXFR transfers |
| `dns_ixfr_accepted` | counter | — | Accepted IXFR transfers |
| `dns_ixfr_rejected` | counter | — | Rejected IXFR transfers |

---

## Phase 45 Changes Applied (Runtime Contract & Protocol Completeness)

### Matrix recomputation corrections (Workstream A)

1. **`dns.doq.bind_address`** — Changed from "partially implemented" to
   "implemented". Re-investigation showed `DoqServer::start()` already consumes
   the config field; the `startup.rs:580` hardcode reference was stale. Phase 45
   added validation (`DnsDoqConfig::validate()`), an IPv6 parsing fix, and
   bind-fidelity unit tests instead of wiring.
2. **`dns.limits.max_tcp_query_time_secs`** — Was stored in `ConnectionLimits`
   but never enforced on the authoritative TCP path. Now the per-query body
   timeout in the persistent loop (`handle_tcp_query`); zero values rejected.
3. **`dns.settings.wildcard_transfer_requires_tsig`** — Serde default fixed
   (`#[serde(default)]` → `#[serde(default =
   "default_wildcard_transfer_requires_tsig")]`) so parsed defaults match the
   documented default (`true`).
4. **DoT loop** — Was already persistent per connection but had no timeouts,
   query bound, or connection permit. Hardened, not newly built.

### Fail-closed validation mapping (Workstream B)

Every path below fails `DnsConfig::validate()` with
`DnsConfigError::Unsupported { path, reason }` when activated. Covered by
`phase45_contract_tests` in `crates/synvoid-config/src/dns/mod.rs`:

| Config path(s) | Reject when | Future trigger |
|---|---|---|
| `dns.rpz.enabled` | `true` | RPZ engine (security-policy product decision) |
| `dns.prefetch.enabled` | `true` | Correctness/security features first |
| `dns.trust_anchors.enabled` | `true` | RFC 5011 lifecycle manager (validating-resolver decision) |
| `dns.anycast.enabled` | `true` | Mesh-based anycast sync |
| `dns.settings.allow_transfer` | non-empty | Zone-transfer design gate (Workstream E) |
| `dns.settings.allow_wildcard_transfer` | `true` | Zone-transfer design gate |
| `dns.settings.wildcard_transfer_requires_tsig` | `false` | Zone-transfer design gate |
| `dns.settings.require_tsig` | `false` | Zone-transfer design gate |
| `dns.settings.ixfr_enabled` | `false` | Zone-transfer design gate |
| `dns.settings.ixfr_history_size` | != default (200) | Zone-transfer design gate |
| `dns.settings.ixfr_fallback_to_axfr` | `false` | Zone-transfer design gate |
| `dns.settings.dynamic_update.enabled` | `true` | Mutation design gate (Workstream E) |
| `dns.settings.notify.enabled` | `true` | Mutation design gate (Workstream E) |
| `dns.settings.padding.enabled` | `true` | Response-padding support |
| `dns.settings.qname_privacy.enabled` | `true` | Query-path privacy support |
| `dns.firewall.default_action` / `max_rules` / `rebinding_protection.enabled` | non-default while firewall enabled | Response-path enforcement design |
| `dns.recursive.firewall.*` (same three) | non-default while recursive firewall enabled | Same as above |
| `dns.recursive.ecs.include_scope_in_response` | `true` | Scope-response support |
| `dns.dot/doh/doq.bind_address` | empty/unparseable while enabled | — (implemented; validation is fail-fast) |
| `dns.dot/doh/doq.port` | zero while enabled | — (implemented; validation is fail-fast) |
| `dns.doq.max_concurrent_streams` / `idle_timeout_secs` | zero while enabled | — (implemented) |
| `dns.recursive.bind_address` | unparseable while enabled | — (implemented; open-resolver guard retained) |
| `dns.limits.max_tcp_idle_time_secs` / `max_tcp_query_time_secs` | zero | — (implemented) |

Gating note: firewall-knob rejections apply only while the enclosing firewall
is enabled; a disabled firewall keeps the whole section parseable. Defaults
(`DnsConfig::default()` and empty-TOML parses) validate clean.

### Protocol work (Workstreams C–D)

5. **DoQ bind fidelity** (`doq.rs::doq_bind_addr`): honors config, IPv6-safe,
   fail-fast. Unit tests: IPv4/IPv6/invalid/empty/zero-port.
6. **Encrypted bind parity**: `DnsDot/Doh/DoqConfig::validate()` requires an
   explicit parseable bind + non-zero port when enabled; `SecureDnsServerBase`
   bind collisions surface as startup errors (tested with an occupied port).
7. **Persistent sequential TCP** (`server/query.rs::handle_tcp_query`): bounded
   loop (pre-allocation size cap, idle + per-query timeouts, 1000-query bound,
   permit held, graceful drain). Unit tests rewritten from one-query to reuse
   semantics; new `dns_phase45_contract` integration tests (two queries one
   connection, zero-length close, oversize close, disabled transports).
8. **DoT alignment** (`dot.rs`): permit held for full lifetime, idle/query
   timeouts, per-connection query bound, graceful drain.

### Decisions (Workstreams E–F)

9. **Mutation stays rejected** (Workstream E): handlers hardcoded to `None`,
   NOTIMP answers, activation rejected. `transfer_primary.toml` demoted to a
   deferred design reference (parses, fails validation).
10. **Recursive tiers** (Workstream F): trust anchors → validating-resolver
    decision; RPZ → security-policy decision; QNAME privacy/padding → privacy
    goal; prefetch → last. Recursive TCP stays single-query (follow-up).

### Test suites added

| Suite | Location | Count |
|---|---|---|
| `phase45_contract_tests` | `crates/synvoid-config/src/dns/mod.rs` | 17 validation tests |
| `dns_phase45_contract` | `crates/synvoid-dns/tests/` | 4 integration tests |
| `doq_bind_addr` tests | `crates/synvoid-dns/src/doq.rs` | 5 unit tests |
| secure-server bind tests | `crates/synvoid-dns/src/secure_server.rs` | 2 tests |
| example profile validation | `crates/synvoid-dns/tests/example_configs_parse.rs` | 2 tests |

---

# Phase 125 Runtime-DTO Ownership and Projection Ledger

Added 2026-10-04. This section is the **merge gate** for Phases 126–128: every
persisted DNS field is classified, and its runtime destination (or explicit
absence) is named.

Binding documents:

- research authority: `architecture/dns_runtime_dto_conversion_research.md`;
- runtime DTO: `crates/synvoid-dns/src/runtime_config.rs`;
- conversion adapter: `src/server/dns_runtime_config.rs`;
- campaign: `plans/dns_runtime_dto_conversion_roadmap.md`.

`src/dns/` remains a pure re-export facade; conversion is application-owned
composition. `tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs`
enforces both.

## Classification vocabulary

| Class | Meaning |
|---|---|
| **RUNTIME** | Persisted value is projected into a DNS-owned runtime field and consumed at runtime. |
| **PROVIDER** | Consumed through composition/provider ownership (TLS, GeoIP, mesh). No runtime DTO field. Deferred to provider inversion (outside Phases 125–130). |
| **PERSISTENCE** | Persisted and validated, but no runtime consumer. Not projected. |
| **UNSUPPORTED** | Fail-closed: activation is rejected by `DnsConfig::validate()`. No runtime field, and no runtime field may ever be added without a new plan. |

The `Adapter normalization` column names what the adapter does with the value.
The default rule everywhere is **reject, never clamp or default** — except
where noted as an intentional fail-closed tightening.

## 1. `DnsConfig` root

| Config path | Validation | Runtime consumer | Runtime DTO destination | Adapter normalization | Class |
|---|---|---|---|---|---|
| `dns.enabled` | parsed | composition startup gate | `DnsRuntimeConfig::enabled` | verbatim | RUNTIME |
| `dns.bind_address` | `InvalidBindAddress` | `configured_bind_addr()` | `bind_address: SocketAddr` | parsed; wildcard `0.0.0.0`/`::` accepted | RUNTIME |
| `dns.port` | `InvalidPort` (non-zero) | `configured_bind_addr()` | `bind_address.port` | zero rejected | RUNTIME |
| `dns.mode` | `DnsMeshConfig::validate` in Mesh mode | none (Standalone is the implicit path) | — | — | PERSISTENCE |
| `dns.ratelimit` | `DnsRateLimitConfig::validate` | `DnsRateLimiter::new` | `rate_limit` | enum → `DnsRateLimitModeRuntime` | RUNTIME |
| `dns.rrl` | `DnsRrlConfig::validate` | `rrl_enabled` health flag only | `rrl.enabled` | verbatim | RUNTIME |
| `dns.firewall` | `DnsFirewallConfig::validate` | `DnsFirewall::new` | `firewall` | implemented controls only | RUNTIME / see §3 |
| `dns.settings` | `DnsSettingsConfig::validate` | many | see §2 | see §2 | RUNTIME |
| `dns.limits` | `DnsLimitsConfig::validate` | `ConnectionLimits`, `DnsQueryValidator` | `limits` | `_secs` → `Duration` | RUNTIME |
| `dns.dnssec` | `DnsSecConfig::validate` | `DnsSecKeyManager`, `HsmManager`, zone loader | `dnssec`, `hsm`, `tsig_keys` | see §8 | RUNTIME |
| `dns.dot` | `DnsDotConfig::validate` | `DotServer::new` | `dot` | bind parsed only when enabled | RUNTIME / see §9 |
| `dns.doh` | `DnsDohConfig::validate` | `DohServer::new` | `doh` | bind parsed only when enabled | RUNTIME / see §9 |
| `dns.doq` | `DnsDoqConfig::validate` | `DoqServer::new` | `doq` | bind parsed only when enabled | RUNTIME / see §9 |
| `dns.recursive` | `RecursiveDnsConfig::validate` | `RecursiveDnsServer` | `recursive` | see §5 | RUNTIME |
| `dns.mesh` | mesh-mode only | none in this crate | — | — | PERSISTENCE |
| `dns.zones` | item shape only | `DnsServer::load_zones` | `zones` | see §7 | RUNTIME |
| `dns.anycast` | `DnsAnycastConfig::validate` | `DnsServer::start` fail-closed | `anycast.enabled` | rejection signal only | RUNTIME (guard) |
| `dns.rpz` | fail-closed on activation | none | — | — | UNSUPPORTED |
| `dns.prefetch` | fail-closed on activation | none | — | — | UNSUPPORTED |
| `dns.trust_anchors` | fail-closed on activation | none | — | — | UNSUPPORTED |
| `dns.dns64` | shape only | `Dns64Translator::new` | `dns64: Option<Dns64RuntimeConfig>` | prefix parsed to `Ipv6Addr` | RUNTIME |

### `dns.dns64.prefix` — intentional fail-closed tightening

The pre-Phase-125 runtime parsed the prefix with
`parse().unwrap_or_else(|_| warn!(... default))`. The adapter now **rejects**
an unparseable prefix. This is a deliberate, recorded behavior change
required by the Phase 125 adapter contract ("reject conversion on invalid
values rather than clamp/fallback silently"): a malformed DNS64 prefix is an
operator error that must surface at conversion rather than silently produce
translation with the well-known prefix. Pinned by
`tests/dns_runtime_config_parity.rs::invalid_dns64_prefix_is_rejected_instead_of_defaulted`.

## 2. `DnsSettingsConfig`

| Config path | Runtime consumer | Runtime DTO destination | Class |
|---|---|---|---|
| `settings.default_ttl` | zone loader TTL fallback | `ttl.default_ttl` | RUNTIME |
| `settings.min_geo_ttl` | `DnsHandlerState::min_geo_ttl` | `ttl.min_geo_ttl` | RUNTIME |
| `settings.negative_cache_ttl` | `DnsHandlerState::negative_cache_ttl` | `ttl.negative_cache_ttl` | RUNTIME |
| `settings.allow_transfer` | `with_zone_transfer_config` | `zone_transfer.allow_transfer: Vec<IpNetwork>` | RUNTIME |
| `settings.cache_enabled` | `DnsCache` construction, health | `cache.enabled` | RUNTIME |
| `settings.cache_size` | `DnsCache::new` | `cache.capacity` | RUNTIME |
| `settings.cache_max_ttl` | `DnsCache`, `DnsQueryValidator` | `cache.max_ttl: Duration` | RUNTIME |
| `settings.cache_min_ttl` | `DnsCache` | `cache.min_ttl: Duration` | RUNTIME |
| `settings.allow_wildcard_transfer` | `ZoneTransfer` | `zone_transfer.allow_wildcard_transfer` | RUNTIME |
| `settings.wildcard_transfer_requires_tsig` | `ZoneTransfer` | `zone_transfer.wildcard_transfer_requires_tsig` | RUNTIME |
| `settings.require_tsig` | `ZoneTransfer`, health | `zone_transfer.require_tsig` | RUNTIME |
| `settings.serve_stale.*` | `DnsCache::with_serve_stale` | `cache.serve_stale` | RUNTIME |
| `settings.ixfr_enabled` | `ZoneTransfer`, health | `zone_transfer.ixfr_enabled` | RUNTIME |
| `settings.ixfr_fallback_to_axfr` | `ZoneTransfer` | `zone_transfer.ixfr_fallback_to_axfr` | RUNTIME |
| `settings.ixfr_history_size` | none | — | PERSISTENCE |
| `settings.ecs_filtering.*` | `EcsFilterConfig::from_settings` | `ecs` | RUNTIME |
| `settings.query_coalescing.*` | `QueryCoalescer`, cleanup task | `query_coalescing` | RUNTIME |
| `settings.dynamic_update.*` | `DynamicUpdateHandler` (inactive) | `dynamic_update` | RUNTIME |
| `settings.notify.*` | `NotifyHandler::from(&NotifyConfig)` | — | PERSISTENCE (fail-closed activation) |
| `settings.padding.*` | none | — | UNSUPPORTED |
| `settings.qname_privacy.*` | none | — | UNSUPPORTED |

`settings.dynamic_update` is fail-closed: `enabled = true` is rejected by
`DnsConfig::validate()`. The runtime DTO therefore carries the policy values
the handler would need, but no active setting, and no handler is wired.

## 3. `DnsFirewallConfig`

| Config path | Runtime consumer | Runtime DTO destination | Class |
|---|---|---|---|
| `firewall.enabled` | `DnsFirewall::new` | `firewall.enabled` | RUNTIME |
| `firewall.block_internal_ips` | 8 built-in subnet rules | `firewall.block_internal_ips` | RUNTIME |
| `firewall.block_zone_transfers` | AXFR opcode rule | `firewall.block_zone_transfers` | RUNTIME |
| `firewall.default_action` | none | — | PERSISTENCE |
| `firewall.max_rules` | none | — | PERSISTENCE |
| `firewall.rebinding_protection.*` | none (validation-only) | — | PERSISTENCE (fail-closed activation) |

`firewall.rebinding_protection.enabled = true` is rejected while the firewall
is on; the other sub-fields are never read. None may gain a runtime field
without response-path enforcement landing first.

## 4. `DnsLimitsConfig`

All eight fields project to `LimitsRuntimeConfig`. `max_tcp_idle_time_secs`
and `max_tcp_query_time_secs` become `Duration`s; the rest are verbatim.
`udp_buffer_size` is consumed by **both** the UDP and TCP authoritative
listeners (pre-existing behavior, unchanged).

## 5. `RecursiveDnsConfig`

| Config path | Runtime consumer | Runtime DTO destination | Class |
|---|---|---|---|
| `recursive.enabled` | `DnsServer::start`, health | `recursive.enabled` | RUNTIME |
| `recursive.bind_address` | recursive listener | `recursive.bind_address: SocketAddr` | RUNTIME |
| `recursive.port` | recursive listener | `recursive.bind_address.port` | RUNTIME |
| `recursive.upstream_provider` | `create_resolver` | `recursive.upstream` (normalized) | RUNTIME |
| `recursive.upstream_servers` | `upstream_ips()` | `CustomUpstreamEndpoint` list | RUNTIME |
| `recursive.cache.*` | `RecursiveDnsCache::new` | `recursive.cache` | RUNTIME |
| `recursive.dnssec_validation` | `HickoryRecursor` | `recursive.dnssec_validation` | RUNTIME |
| `recursive.qname_minimization` | `HickoryResolver` | `recursive.qname_minimization` | RUNTIME |
| `recursive.query_timeout_secs` | `HickoryResolver` | `recursive.query_timeout: Duration` | RUNTIME |
| `recursive.max_concurrent_queries` | `Semaphore` | `recursive.max_concurrent_queries` | RUNTIME |
| `recursive.ratelimit` | shared limiter | `recursive.rate_limit` | RUNTIME |
| `recursive.firewall` | firewall instance | `recursive.firewall` | RUNTIME |
| `recursive.root_hints_path` | `HickoryRecursor` | `upstream.root_hints: PathBuf` | RUNTIME |
| `recursive.trust_anchor_path` | `HickoryRecursor` | `upstream.trust_anchor: PathBuf` | RUNTIME |
| `recursive.client_acl` | `is_client_allowed` | `recursive.client_acl` (parsed networks + action enum) | RUNTIME |
| `recursive.max_cname_depth` | depth guard | `recursive.max_cname_depth` | RUNTIME |
| `recursive.max_recursion_depth` | depth guard | `recursive.max_recursion_depth` | RUNTIME |
| `recursive.max_per_client_queries` | per-client semaphore | `recursive.max_per_client_queries` | RUNTIME |
| `recursive.circuit_breaker.*` | `CircuitBreaker::new` | `recursive.circuit_breaker` | RUNTIME |
| `recursive.ecs.*` | recursive ECS policy | `recursive.ecs` | RUNTIME |

### Upstream normalization (Phase 127 Workstream B)

The persisted `upstream_provider` conflates `System` and `Custom`. The
runtime enum separates them:

| Persisted | Persisted endpoints | Runtime |
|---|---|---|
| `system` | none | `System` |
| `system` | ≥1 | `CustomEndpoints(..)` |
| `custom` | ≥1 (required by validation) | `CustomEndpoints(..)` |
| `google` | any | `Google` |
| `cloudflare` | any | `Cloudflare` |
| `recursive` | any | `Recursive { root_hints, trust_anchor }` |
| `global_nodes` | any | `GlobalNodes` (retained for parity until provider inversion) |

A literal IP endpoint and a hostname endpoint stay distinguishable
(`CustomUpstreamEndpoint::Literal` vs `::Hostname`).

### DNSSEC-provider truthfulness

`RecursiveRuntimeConfig::performs_local_dnssec_validation` is `true` **only**
for `RecursiveUpstreamRuntime::Recursive`. Forwarder modes project the
persisted `dnssec_validation` flag verbatim but must not claim local
validation; the existing startup warning is driven from this field so the
"forwarder does not validate" message stays truthful.

## 6. `DnsMeshConfig`

No runtime field. Mesh is a composition/control-plane concern and anycast
activation fails closed in the DNS crate. Class: **PROVIDER**.

## 7. `DnsZonesConfig`

| Config path | Runtime consumer | Runtime DTO destination | Class |
|---|---|---|---|
| `zones.items[].zone` | `load_zones_inner` | `ZoneSpec::origin` | RUNTIME |
| `zones.items[].records[].name` | `DnsZoneRecord` | `ZoneRecordSpec::name` | RUNTIME |
| `zones.items[].records[].record_type` | `RecordType` match | `ZoneRecordSpec::record_type: hickory RecordType` | RUNTIME |
| `zones.items[].records[].value` | `parse_record_value` | `ZoneRecordSpec::value` (text; validation stays in the loader) | RUNTIME |
| `zones.items[].records[].ttl` | `unwrap_or(default_ttl)` | `ZoneRecordSpec::ttl: Option<u32>` | RUNTIME |
| `zones.items[].records[].priority` | MX/SRV bounds | `ZoneRecordSpec::priority` | RUNTIME |
| `zones.items[].dnssec` | NSEC/NSEC3 chain build | `ZoneSpec::dnssec: Option<ZoneDnssecSpec>` | RUNTIME |

Record-text parsing and all zone validation (single apex SOA, owner names,
TTL bounds, MX/SRV priority bounds, CNAME exclusivity, target names) stay in
the authoritative zone loader. The adapter must not make invalid zone data
valid.

## 8. `DnsSecConfig`

| Config path | Runtime consumer | Runtime DTO destination | Class |
|---|---|---|---|
| `dnssec.enabled` | key manager, health, `start()` | `dnssec.enabled` | RUNTIME |
| `dnssec.domain` | KSK owner name | `dnssec.domain` | RUNTIME |
| `dnssec.key_path` | `DnsSecKeyManager::new` | `dnssec.key_path: PathBuf` | RUNTIME |
| `dnssec.algorithm` | key generation | `dnssec.algorithm: DnssecAlgorithmRuntime` | RUNTIME |
| `dnssec.rsa_key_size` | key generation | `dnssec.rsa_key_size` | RUNTIME |
| `dnssec.ksk_key_size` | key generation | `dnssec.ksk_key_size` | RUNTIME |
| `dnssec.rollover_interval_days` | rotation scheduler | `dnssec.rollover_interval: Duration` | RUNTIME |
| `dnssec.nsec_enabled` | NSEC chain | `dnssec.denial.nsec_enabled` | RUNTIME |
| `dnssec.nsec3_enabled` | NSEC3 chain | `dnssec.denial.nsec3_enabled` | RUNTIME |
| `dnssec.nsec3_iterations` | `Nsec3Config` | `dnssec.denial.nsec3_iterations` | RUNTIME |
| `dnssec.nsec3_algorithm` | `Nsec3Config` | `dnssec.denial.nsec3_algorithm` | RUNTIME |
| `dnssec.tsig_keys[].name` | `TsigVerifier` | `TsigRuntimeKey::name` | RUNTIME |
| `dnssec.tsig_keys[].algorithm` | MAC selection | `TsigRuntimeKey::algorithm` | RUNTIME |
| `dnssec.tsig_keys[].secret_base64` | MAC key | `TsigRuntimeKey::secret` (decoded) | RUNTIME |
| `dnssec.hsm.*` | `HsmManager::initialize` | `dnssec.hsm` (runtime-owned shape) | RUNTIME |

TSIG conversion rejects a non-base64 secret and any secret shorter than the
algorithm minimum, and the runtime key's `Debug` impl redacts the secret.
Conversion errors name the key and algorithm only.

Private-key generation, sealed storage, rotation, and signing dispatch remain
in `synvoid-dnssec-keystore`. No runtime type carries raw private key bytes.

## 9. Encrypted DNS sub-fields

| Config path | Runtime consumer | Runtime DTO destination | Class |
|---|---|---|---|
| `dot.enabled` | `DotServer::new` | `dot.enabled` | RUNTIME |
| `dot.bind_address` | `SecureDnsServerBase::start_server` | `dot.bind_address` (parsed when enabled) | RUNTIME |
| `dot.port` | `SecureDnsServerBase::start_server` | `dot.bind_address.port` | RUNTIME |
| `dot.tls_cert_path` | none | — | PROVIDER (`CertResolver`) |
| `dot.tls_key_path` | none | — | PROVIDER (`CertResolver`) |
| `dot.use_system_cert_store` | none | — | PROVIDER (`CertResolver`) |
| `doh.enabled` | `DohServer::new` | `doh.enabled` | RUNTIME |
| `doh.bind_address` / `doh.port` | `SecureDnsServerBase::start_server` | `doh.bind_address` | RUNTIME |
| `doh.path` | none — routes are protocol constants | — | PERSISTENCE |
| `doh.json_path` | none — routes are protocol constants | — | PERSISTENCE |
| `doh.tls_cert_path` / `tls_key_path` / `use_system_cert_store` | none | — | PROVIDER |
| `doh.enable_http2` | not a supported field | — | PERSISTENCE |
| `doq.enabled` | `DoqServer::new` | `doq.enabled` | RUNTIME |
| `doq.bind_address` / `doq.port` | `DoqServer::doq_bind_addr` | `doq.bind_address` | RUNTIME |
| `doq.max_concurrent_streams` | `TransportConfig` | `doq.max_concurrent_streams` | RUNTIME |
| `doq.idle_timeout_secs` | `quinn::IdleTimeout` | `doq.idle_timeout: Duration` | RUNTIME |
| `doq.tls_*` | none | — | PROVIDER |

### Correction: `doh.path` / `doh.json_path` are not runtime inputs

The Phase 5 matrix recorded these as "implemented → `DohServer::new()`".
Code inspection for Phase 125 shows `doh.rs` matches the fixed protocol
routes `/dns-query`, `/`, `/dns`, and `/dns-query/json` and never reads the
persisted fields. They are therefore reclassified **PERSISTENCE** and are
absent from the runtime DTO. Shipping them as runtime values would have
created a setting the runtime silently ignores — exactly the class of drift
this ledger exists to prevent.

## 10. Matrix reconciliation summary (Phase 125)

| Prior status | Count | Change |
|---|---|---|
| `implemented` | 96 | 89 confirmed RUNTIME |
| `implemented` | 7 | reclassified **PERSISTENCE** (`doh.path`, `doh.json_path`, `doh.enable_http2`, `dot/doh/doq` TLS fields consumed only via `CertResolver`) |
| `unsupported` / `partially implemented` | 21 | reclassified **UNSUPPORTED** (fail-closed) or **PERSISTENCE** with the reason recorded per field above |

Persisted schema, defaults, and the admin API are unchanged by this phase.

## 11. Phase 125 findings carried forward

### F-1 (pre-existing): `dns.firewall.max_rules` serde default ≠ Rust `Default`

`DnsFirewallConfig` uses `#[derive(Default, ...)]` with
`#[serde(default = "default_firewall_max_rules")]` on `max_rules`. The serde
default is `1000`; the derived Rust `Default` is `0`. `DnsFirewallConfig::validate_at()`
rejects any `max_rules != 1000` while the firewall is enabled, so a
**Rust-constructed** `DnsConfig` that enables the firewall fails validation
with `Unsupported DNS feature at dns.firewall.max_rules` unless the caller
restores the serde default.

This is not reachable from TOML (the serde default applies), so production is
unaffected. It is pinned rather than changed: persisted defaults are out of
scope for Phases 125–130, and Phase 130 forbids default drift without a
separately planned change.

Pinned by
`tests/dns_runtime_config_parity.rs::firewall_serde_default_disagrees_with_rust_default`.

**Follow-up required (not part of this campaign):** give `DnsFirewallConfig`
a manual `Default` impl so the Rust and serde defaults agree, and re-audit
every other `#[derive(Default)]` struct that mixes `#[serde(default = ...)]`
field attributes. `RebindingProtectionConfig::enabled` has the same shape
(`default_true` in serde, `false` via derive) but is unreachable behind the
same firewall gate.

### F-2: `doh.path` / `doh.json_path` are inert

See §9. The served routes are protocol constants; the persisted fields are
never read. Reclassified from `implemented` to `PERSISTENCE`.

### F-3: DNS64 prefix now fails closed

See §1. An unparseable `dns.dns64.prefix` previously warned and substituted
`64:ff9b::`. The adapter rejects it. Intentional, required by the Phase 125
adapter contract, and pinned by a parity fixture.

### F-4: `RecursiveDnsConfig::validate()` already owns ACL validation

Invalid `client_acl.allowed_clients` CIDRs and unknown `client_acl.action`
values are rejected by the persisted validation gate before conversion. The
adapter re-parses independently (defense in depth) but that path is not
reachable through `dns_runtime_config_from_persisted`. The parity fixtures
assert the validation-gate behavior and exercise `IpNetwork::parse` directly
for the projection semantics.

---

## Phase 128 findings

Added by `architecture/dns_runtime_dto_phase128_closeout.md`, which is where
each finding is written up in full. This section keeps the matrix the single
lookup for "what did the cutover find".

### F-5: the TSIG minimum-secret threshold was too low in Phase 125 (corrected)

Phase 125's `TsigAlgorithmRuntime::min_secret_len()` returned the HMAC *input*
block size (16/24/32), while the pre-cutover
`synvoid_config::dns::TsigAlgorithm::key_size()` rejected anything shorter than
the HMAC *output* length (32/48/64). The Phase 125 adapter therefore accepted
keys the old server rejected. Corrected to 32/48/64 in Phase 128 and pinned by
`test_tsig_algorithm_min_secret_len_matches_pre_cutover_key_size`. RFC 8945
§4.3.2 recommends the output length; the earlier citation was wrong.

### F-6: `[dns.zones]` is converted but never loaded

`DnsServer::new` discards the converted zone specs (`zones: _`), and
`load_zones(Vec<ZoneSpec>)` has no production caller. A shipped `[dns.zones]`
entry is validated and converted, then dropped; zones reach a running server
only via `load_zones_from_store` (the SQLite zone store). Pre-existing — before
Phase 125 the constructor took `DnsConfig` and equally ignored `config.zones` —
and deliberately not fixed here, because loading zones at startup is a
behavior change while this campaign's acceptance criteria require parity.

**Follow-up required (not part of this campaign):** either have composition
call `load_zones(runtime.zones)` explicitly, or drop `[dns.zones]` from the
shipped schema and document that zones come from the zone store. Until then,
`[dns.zones]` should be treated as non-functional in `architecture/dns.md`.

### F-7: TSIG keys are discarded by the constructor by design

Same `tsig_keys: _` destructuring, but wired: `src/server/resources.rs` reads
`runtime_cfg.tsig_keys` before constructing the server and feeds them to
`TsigVerifier` for zone transfers. Recorded so F-6 and F-7 are not confused —
one is a dead path, the other is a deliberate one.

---

## Phase 129 findings

Added by `architecture/dns_runtime_dto_phase129_closeout.md`, which is where
each finding is written up in full.

### F-8: `dns_ipv4_prefix_mask` diverged from the helper it replaces

The Phase 125/126 helper returned `0` for IPv4 prefixes above `/32`, while
`synvoid_core::net::ipv4_prefix_mask()` returns `u32::MAX`. The divergence
would have masked a client subnet to `0.0.0.0` rather than leaving it intact.

The only call site (`edns.rs` ECS truncation) cannot reach an out-of-range
length — it is guarded by `new_prefix < subnet.prefix_len`, and `prefix_len` is
at most 32 for IPv4 — so the divergence was unreachable, and the original test
*asserted* the wrong value. Corrected in Phase 129 to exact parity
(`0 => 0`, `1..=32 => u32::MAX << (32 - prefix)`, `_ => u32::MAX`) and the test
now covers `/0`, `/1`, `/8`, `/24`, `/31`, `/32`, `/33`, `/64`, `/255`.

Recorded because the same class of error is easy to reintroduce: a
"reasonable-looking" replacement helper that is subtly different at the
boundary is worse than no replacement at all.

### F-9: the two predecessor time helpers differed only in logging

`synvoid_core::time::current_timestamp_secs()` logs a warning on a pre-epoch
clock; `synvoid_utils::safe_unix_timestamp()` does not. Both return `0`. The
DNS helper `time::unix_timestamp_secs()` does not log.

No DNS code path branches on the warning, so this is not a behavior change —
recorded because "identical behavior" would otherwise be read as
byte-identical.

### F-10: `synvoid_utils::current_timestamp` is a plain alias for `safe_unix_timestamp`

```rust
pub fn current_timestamp() -> u64 { safe_unix_timestamp() }
```

So the eight mesh-gated files were already on identical semantics despite
using two different names. Both map to `unix_timestamp_secs()` with no
per-site judgment.
