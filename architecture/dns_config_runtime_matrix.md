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
| `dns.dot.enabled` | `false` | `DotServer::new()` | implemented | verification_gate | add DoT tests |
| `dns.dot.port` | `853` | `DotServer::new()` | implemented | verification_gate | add DoT tests |
| `dns.dot.bind_address` | `""` | `DotServer::new()` | implemented | verification_gate | add DoT tests |
| `dns.dot.tls_cert_path` | `None` | `DotServer::new()` | implemented | verification_gate | add DoT tests |
| `dns.dot.tls_key_path` | `None` | `DotServer::new()` | implemented | verification_gate | add DoT tests |
| `dns.dot.use_system_cert_store` | `true` | TLS config | implemented | verification_gate | add DoT tests |
| `dns.doh.enabled` | `false` | `DohServer::new()` | implemented | verification_gate | add DoH tests |
| `dns.doh.port` | `443` | `DohServer::new()` | implemented | verification_gate | add DoH tests |
| `dns.doh.bind_address` | `""` | `DohServer::new()` | implemented | verification_gate | add DoH tests |
| `dns.doh.path` | `"/dns-query"` | `DohServer::new()` | implemented | verification_gate | add DoH tests |
| `dns.doh.json_path` | `""` | `DohServer::new()` | implemented | verification_gate | add DoH tests |
| `dns.doh.tls_cert_path` | `None` | TLS config | implemented | verification_gate | add DoH tests |
| `dns.doh.tls_key_path` | `None` | TLS config | implemented | verification_gate | add DoH tests |
| `dns.doh.use_system_cert_store` | `true` | TLS config | implemented | verification_gate | add DoH tests |
| `dns.doq.enabled` | `false` | `DoqServer::new()` | implemented | verification_gate | add DoQ tests |
| `dns.doq.port` | `853` | `DoqServer::new()` | implemented | verification_gate | add DoQ tests |
| `dns.doq.bind_address` | `""` | hardcoded to `0.0.0.0` in `startup.rs:580`; config field not consumed | partially implemented | verification_gate | wire from config or document hardcoded |
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
| `dns.settings.wildcard_transfer_requires_tsig` | `true` | `ZoneTransfer::with_security_config()` accepts this; not wired from config | deferred | zone mutation tests (handler-level only) | wire from config or document deferred |
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
| `dns.limits.max_tcp_idle_time_secs` | `300` | TCP idle timeout | implemented | verification_gate | add test |
| `dns.limits.max_tcp_query_time_secs` | `30` | TCP query timeout | implemented | verification_gate | add test |
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
| `dns.doq.bind_address` | partially implemented | Hardcoded to `0.0.0.0:{port}` at `startup.rs:580`; config field not consumed |
| DoT/DoH/DoQ test coverage | wired, tests added | See `encrypted_transport` test suite and `dot`/`doh`/`doq` unit tests |

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total config fields** | ~170 |
| **Implemented** | ~101 |
| **Partially implemented** | 3 |
| **Validation-only** | 11 |
| **Deferred** | 17 |
| **Unsupported / documentation-only** | ~40 |

Note: ~45 implemented fields lack dedicated test coverage (DoT/DoH/DoQ, rate limiter, firewall fields). These are wired and functional but not covered by unit/integration tests.

---

## Deferred Features (Phase 7+)

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
| Persistent DNS-over-TCP (pipelining) | N/A | Requires framing state, per-query idle management, connection pool. One-query-per-connection per RFC 7766 §4. |
| EDNS keepalive | Parsed only | `EdnsOptions.keepalive` parsed but not wired into connection management (moot without persistent TCP). |
| Full NSEC3 closest-encloser proofs | N/A | Phase 2 fixed next-closer emission; full closest-encloser proof coverage remains deferred. |
| DoQ `bind_address` | `dns.doq.bind_address` | Partially implemented: `startup.rs:580` hardcodes bind to `0.0.0.0:{port}`; config field not consumed. DoQ is wired but not production-validated. |
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
