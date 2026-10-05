//! Phase 125 Workstream E — persisted-DNS-config → runtime-DTO parity fixtures.
//!
//! The application-owned adapter (`src/server/dns_runtime_config.rs`) is the
//! only conversion path. These fixtures construct persisted `DnsConfig`
//! values, convert them, and assert the *exact effective runtime values*.
//!
//! Where a value becomes a parsed type, the assertion compares the semantic
//! result (socket address, duration, network) rather than string formatting.
//!
//! Parity coverage: defaults, every shipped `examples/dns/*.toml` profile that
//! is supported today, authoritative-only, recursive, DNSSEC, DoT/DoH/DoQ,
//! cache + serve-stale, ECS, DNS64, rate limiting/RRL, limits, invalid
//! bind/port, open-resolver rejection, and the Phase-45 fail-closed
//! unsupported-activation paths.
//!
//! Production still constructs `DnsServer` from persisted config in this
//! phase; these tests prove the runtime projection is exact so the Phase 126
//! cutover is a behavior-preserving change of ownership.

#![cfg(feature = "dns")]

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use synvoid::server::dns_runtime_config::{
    dns_runtime_config_from_persisted, DnsRuntimeConversionError,
};
use synvoid_config::dns::{
    DnsConfig, DnsFirewallConfig, DnsRateLimitMode, DnsSecAlgorithm, RebindingProtectionConfig,
    TsigAlgorithm,
};
use synvoid_dns::runtime_config as rt;
use synvoid_dns::RecordType as HickoryRecordType;

/// Serde default for `dns.firewall.max_rules`.
///
/// `DnsFirewallConfig` derives `Default`, so the Rust-side default is `0`
/// while the TOML default (`#[serde(default = ...)]`) is `1000`. Enabling the
/// firewall from a Rust-constructed config therefore requires restoring the
/// serde default — see `firewall_serde_default_disagrees_with_rust_default`
/// and the Phase 125 closeout finding.
const FIREWALL_MAX_RULES_SERDE_DEFAULT: usize = 1000;

/// Enabled, valid, standalone authoritative baseline.
fn authoritative() -> DnsConfig {
    DnsConfig {
        enabled: true,
        ..DnsConfig::default()
    }
}

/// Enable the firewall with a config that passes the Phase 45 fail-closed
/// contract.
fn firewall_on() -> DnsFirewallConfig {
    DnsFirewallConfig {
        enabled: true,
        max_rules: FIREWALL_MAX_RULES_SERDE_DEFAULT,
        rebinding_protection: RebindingProtectionConfig {
            enabled: false,
            ..RebindingProtectionConfig::default()
        },
        ..DnsFirewallConfig::default()
    }
}

fn convert(config: &DnsConfig) -> rt::DnsRuntimeConfig {
    dns_runtime_config_from_persisted(config).expect("persisted config must convert")
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

#[test]
fn defaults_project_exact_runtime_values() {
    let config = authoritative();
    let runtime = convert(&config);

    assert!(runtime.enabled);
    assert_eq!(runtime.bind_address, SocketAddr::from(([0, 0, 0, 0], 53)));

    assert_eq!(runtime.ttl.default_ttl, config.settings.default_ttl);
    assert_eq!(runtime.ttl.min_geo_ttl, config.settings.min_geo_ttl);
    assert_eq!(
        runtime.ttl.negative_cache_ttl,
        config.settings.negative_cache_ttl
    );

    assert_eq!(runtime.cache.enabled, config.settings.cache_enabled);
    assert_eq!(runtime.cache.capacity, config.settings.cache_size);
    assert_eq!(
        runtime.cache.max_ttl,
        Duration::from_secs(config.settings.cache_max_ttl)
    );
    assert_eq!(
        runtime.cache.min_ttl,
        Duration::from_secs(config.settings.cache_min_ttl)
    );
    assert!(
        runtime.cache.serve_stale.is_none(),
        "serve-stale is off by default"
    );

    assert_eq!(runtime.rate_limit.mode, rt::DnsRateLimitModeRuntime::Shared);
    assert_eq!(runtime.rate_limit.per_second, config.ratelimit.per_second);
    assert_eq!(runtime.rrl.enabled, config.rrl.enabled);
    assert_eq!(runtime.firewall.enabled, config.firewall.enabled);
    assert_eq!(
        runtime.firewall.block_internal_ips,
        config.firewall.block_internal_ips
    );
    assert_eq!(
        runtime.firewall.block_zone_transfers,
        config.firewall.block_zone_transfers
    );

    assert!(runtime.dns64.is_none(), "DNS64 is off by default");
    assert!(!runtime.dot.enabled);
    assert!(!runtime.doh.enabled);
    assert!(!runtime.doq.enabled);
    assert!(!runtime.dnssec.enabled);
    assert!(!runtime.recursive.enabled);
    assert!(!runtime.anycast.enabled);
    assert!(runtime.zones.is_empty());
    assert!(runtime.tsig_keys.is_empty());
    assert!(!runtime.dnssec.hsm.enabled);
    assert!(runtime.is_axfr_enabled());
    // Health flags are a pure function of runtime config, so they mirror the
    // persisted values verbatim (IXFR ships enabled by default).
    assert_eq!(runtime.is_ixfr_enabled(), config.settings.ixfr_enabled);
    assert!(runtime.is_ixfr_enabled(), "IXFR ships enabled by default");
    assert_eq!(
        runtime.is_ixfr_enabled(),
        runtime.zone_transfer.ixfr_enabled
    );
    assert_eq!(
        runtime.is_update_enabled(),
        config.settings.dynamic_update.enabled
    );
    assert_eq!(runtime.is_tsig_required(), config.settings.require_tsig);
}

#[test]
fn disabled_dns_projects_enabled_false() {
    let config = DnsConfig::default();
    let runtime = convert(&config);
    assert!(!runtime.enabled);
}

// ---------------------------------------------------------------------------
// Authoritative groups
// ---------------------------------------------------------------------------

#[test]
fn authoritative_bind_and_limits_project_exactly() {
    let mut config = authoritative();
    config.bind_address = "127.0.0.1".to_string();
    config.port = 5353;
    config.limits.max_tcp_connections = 11;
    config.limits.max_concurrent_queries = 12;
    config.limits.max_query_size = 4096;
    config.limits.max_response_size = 8192;
    config.limits.max_records_per_response = 13;
    config.limits.max_tcp_idle_time_secs = 14;
    config.limits.max_tcp_query_time_secs = 15;
    config.limits.udp_buffer_size = 65535;
    config.limits.enable_graceful_degradation = true;

    let runtime = convert(&config);
    assert_eq!(
        runtime.bind_address,
        SocketAddr::from(([127, 0, 0, 1], 5353))
    );
    assert_eq!(runtime.limits.max_tcp_connections, 11);
    assert_eq!(runtime.limits.max_concurrent_queries, 12);
    assert_eq!(runtime.limits.max_query_size, 4096);
    assert_eq!(runtime.limits.max_response_size, 8192);
    assert_eq!(runtime.limits.max_records_per_response, 13);
    assert_eq!(runtime.limits.max_tcp_idle_time, Duration::from_secs(14));
    assert_eq!(runtime.limits.max_tcp_query_time, Duration::from_secs(15));
    assert_eq!(runtime.limits.udp_buffer_size, 65535);
    assert!(runtime.limits.enable_graceful_degradation);
}

#[test]
fn wildcard_authoritative_bind_is_accepted() {
    let mut config = authoritative();
    config.bind_address = "::".to_string();
    config.port = 53;
    let runtime = convert(&config);
    assert_eq!(
        runtime.bind_address,
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 53))
    );
}

#[test]
fn dedicated_rate_limit_mode_projects() {
    let mut config = authoritative();
    config.ratelimit.mode = DnsRateLimitMode::Dedicated;
    config.ratelimit.per_second = 42;
    let runtime = convert(&config);
    assert_eq!(
        runtime.rate_limit.mode,
        rt::DnsRateLimitModeRuntime::Dedicated
    );
    assert_eq!(runtime.rate_limit.per_second, 42);
}

#[test]
fn rrl_projects_only_the_activation_flag() {
    let mut config = authoritative();
    config.rrl.enabled = true;
    // Deliberately non-default; these must not become runtime settings.
    config.rrl.responses_per_second = 7;
    config.rrl.window_secs = 9;
    config.rrl.max_responses = 11;
    config.rrl.ttl = 13;
    let runtime = convert(&config);
    assert!(runtime.rrl.enabled);
}

#[test]
fn firewall_serde_default_disagrees_with_rust_default() {
    // Documented pre-existing inconsistency (Phase 125 finding): the serde
    // default is 1000 but the derived Rust `Default` is 0, so a
    // Rust-constructed config cannot enable the firewall until the operator
    // restores the serde default. Persisted defaults are out of scope for
    // Phases 125-130, so this is pinned rather than changed.
    let derived = DnsConfig::default();
    assert_eq!(derived.firewall.max_rules, 0);
    // Disabling the firewall keeps it inactive and therefore parseable.
    assert!(derived.validate().is_ok());

    let enabled = DnsConfig {
        enabled: true,
        firewall: firewall_on(),
        ..DnsConfig::default()
    };
    assert!(enabled.validate().is_ok());
}

#[test]
fn implemented_firewall_controls_project() {
    let mut config = authoritative();
    config.firewall = firewall_on();
    config.firewall.block_internal_ips = false;
    config.firewall.block_zone_transfers = true;
    let runtime = convert(&config);
    assert!(runtime.firewall.enabled);
    assert!(!runtime.firewall.block_internal_ips);
    assert!(runtime.firewall.block_zone_transfers);
}

#[test]
fn cache_serve_stale_projects_when_enabled() {
    let mut config = authoritative();
    config.settings.serve_stale.enabled = true;
    config.settings.serve_stale.max_stale_secs = 120;
    config.settings.serve_stale.max_stale_count = 7;
    let runtime = convert(&config);
    let serve_stale = runtime.cache.serve_stale.expect("serve-stale projects");
    assert_eq!(serve_stale.max_stale, Duration::from_secs(120));
    assert_eq!(serve_stale.max_stale_count, 7);
}

#[test]
fn ecs_filtering_projects_exact_prefixes() {
    let mut config = authoritative();
    config.settings.ecs_filtering.enabled = true;
    config.settings.ecs_filtering.prefix_v4 = 20;
    config.settings.ecs_filtering.prefix_v6 = 40;
    config.settings.ecs_filtering.allow_private_prefix = true;
    let runtime = convert(&config);
    assert!(runtime.ecs.enabled);
    assert_eq!(runtime.ecs.prefix_v4, 20);
    assert_eq!(runtime.ecs.prefix_v6, 40);
    assert!(runtime.ecs.allow_private_prefix);
}

#[test]
fn dns64_projects_a_parsed_prefix() {
    let mut config = authoritative();
    config.dns64.enabled = true;
    config.dns64.prefix = "64:ff9b::1".to_string();
    config.dns64.exclude_aaaa_synthesis = true;
    let runtime = convert(&config);
    let dns64 = runtime.dns64.expect("DNS64 projects when enabled");
    assert_eq!(
        dns64.prefix,
        "64:ff9b::1".parse::<std::net::Ipv6Addr>().unwrap()
    );
    assert!(dns64.exclude_aaaa_synthesis);
}

#[test]
fn query_coalescing_projects_durations() {
    let mut config = authoritative();
    config.settings.query_coalescing.enabled = true;
    config.settings.query_coalescing.max_wait_ms = 25;
    config.settings.query_coalescing.max_entries = 30;
    config.settings.query_coalescing.entry_ttl_secs = 35;
    config.settings.query_coalescing.cleanup_interval_secs = 40;
    let runtime = convert(&config);
    assert!(runtime.query_coalescing.enabled);
    assert_eq!(runtime.query_coalescing.max_wait, Duration::from_millis(25));
    assert_eq!(runtime.query_coalescing.max_entries, 30);
    assert_eq!(runtime.query_coalescing.entry_ttl, Duration::from_secs(35));
    assert_eq!(
        runtime.query_coalescing.cleanup_interval,
        Duration::from_secs(40)
    );
}

#[test]
fn ttl_group_projects_exact_values() {
    let mut config = authoritative();
    config.settings.default_ttl = 111;
    config.settings.min_geo_ttl = 222;
    config.settings.negative_cache_ttl = 333;
    let runtime = convert(&config);
    assert_eq!(runtime.ttl.default_ttl, 111);
    assert_eq!(runtime.ttl.min_geo_ttl, 222);
    assert_eq!(runtime.ttl.negative_cache_ttl, 333);
}

// ---------------------------------------------------------------------------
// Encrypted transports
// ---------------------------------------------------------------------------

#[test]
fn dot_doh_doq_project_typed_bind_addresses() {
    let mut config = authoritative();
    config.dot.enabled = true;
    config.dot.bind_address = "127.0.0.1".to_string();
    config.dot.port = 8853;
    config.doh.enabled = true;
    config.doh.bind_address = "::1".to_string();
    config.doh.port = 8443;
    config.doq.enabled = true;
    config.doq.bind_address = "127.0.0.2".to_string();
    config.doq.port = 8854;
    config.doq.max_concurrent_streams = 55;
    config.doq.idle_timeout_secs = 66;

    let runtime = convert(&config);
    assert_eq!(
        runtime.dot.bind_address,
        Some(SocketAddr::from(([127, 0, 0, 1], 8853)))
    );
    assert_eq!(
        runtime.doh.bind_address,
        Some(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8443)))
    );
    assert_eq!(
        runtime.doq.bind_address,
        Some(SocketAddr::from(([127, 0, 0, 2], 8854)))
    );
    assert_eq!(runtime.doq.max_concurrent_streams, 55);
    assert_eq!(runtime.doq.idle_timeout, Duration::from_secs(66));
    assert!(runtime.is_dot_enabled() && runtime.is_doh_enabled() && runtime.is_doq_enabled());
}

#[test]
fn disabled_transports_carry_no_bind_address() {
    let runtime = convert(&authoritative());
    assert!(runtime.dot.bind_address.is_none());
    assert!(runtime.doh.bind_address.is_none());
    assert!(runtime.doq.bind_address.is_none());
    assert!(runtime
        .transport_bind(rt::EncryptedTransport::Dot)
        .is_none());
}

#[test]
fn enabled_transport_with_unparseable_bind_is_rejected() {
    let mut config = authoritative();
    config.dot.enabled = true;
    config.dot.bind_address = "not-an-ip".to_string();
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    // Phase 45 rejects this first with a typed path.
    assert!(
        matches!(error, DnsRuntimeConversionError::Unsupported { .. }),
        "expected typed unsupported rejection, got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// DNSSEC / TSIG
// ---------------------------------------------------------------------------

#[test]
fn dnssec_policy_projects_exact_values() {
    let mut config = authoritative();
    config.dnssec.enabled = true;
    config.dnssec.domain = "example.com".to_string();
    config.dnssec.key_path = "/var/lib/synvoid/dns/keys".to_string();
    config.dnssec.algorithm = DnsSecAlgorithm::RsaSha256;
    config.dnssec.rsa_key_size = 3072;
    config.dnssec.ksk_key_size = 4096;
    config.dnssec.rollover_interval_days = 10;
    config.dnssec.nsec_enabled = true;
    config.dnssec.nsec3_enabled = false;
    config.dnssec.nsec3_iterations = 7;
    config.dnssec.nsec3_algorithm = 1;

    let runtime = convert(&config);
    assert!(runtime.dnssec.enabled);
    assert_eq!(runtime.dnssec.domain, "example.com");
    assert_eq!(
        runtime.dnssec.key_path,
        std::path::PathBuf::from("/var/lib/synvoid/dns/keys")
    );
    assert_eq!(runtime.dnssec.algorithm, rt::DnssecAlgorithmRuntime::Rsa);
    assert_eq!(runtime.dnssec.key_type, rt::DnssecKeyTypeRuntime::Ksk);
    assert_eq!(runtime.dnssec.rsa_key_size, 3072);
    assert_eq!(runtime.dnssec.ksk_key_size, 4096);
    assert_eq!(
        runtime.dnssec.rollover_interval,
        Duration::from_secs(10 * 86_400)
    );
    assert!(runtime.dnssec.denial.nsec_enabled);
    assert!(!runtime.dnssec.denial.nsec3_enabled);
    assert_eq!(runtime.dnssec.denial.nsec3_iterations, 7);
    assert_eq!(runtime.dnssec.denial.nsec3_algorithm, 1);
}

#[test]
fn tsig_secret_is_base64_decoded_and_length_checked() {
    // 32 raw bytes -> 44 base64 characters.
    let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let mut config = authoritative();
    config.dnssec.tsig_keys = vec![synvoid_config::dns::TsigKeyConfig {
        name: "transfer-key".to_string(),
        algorithm: TsigAlgorithm::HmacSha256,
        secret_base64: secret.to_string(),
    }];
    let runtime = convert(&config);
    assert_eq!(runtime.tsig_keys.len(), 1);
    assert_eq!(runtime.tsig_keys[0].name, "transfer-key");
    assert_eq!(runtime.tsig_keys[0].secret.len(), 32);
    assert_eq!(
        runtime.tsig_keys[0].algorithm,
        rt::TsigAlgorithmRuntime::HmacSha256
    );
}

#[test]
fn tsig_secret_that_is_not_base64_is_rejected_without_leaking_it() {
    let mut config = authoritative();
    config.dnssec.tsig_keys = vec![synvoid_config::dns::TsigKeyConfig {
        name: "transfer-key".to_string(),
        algorithm: TsigAlgorithm::HmacSha256,
        secret_base64: "!!!not-base64!!!".to_string(),
    }];
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    let rendered = error.to_string();
    assert!(rendered.contains("transfer-key"));
    assert!(
        !rendered.contains("not-base64"),
        "error must not echo the secret"
    );
}

#[test]
fn undersized_tsig_secret_is_rejected() {
    // 8 raw bytes is below the 16-byte HMAC-SHA256 minimum.
    let mut config = authoritative();
    config.dnssec.tsig_keys = vec![synvoid_config::dns::TsigKeyConfig {
        name: "weak".to_string(),
        algorithm: TsigAlgorithm::HmacSha256,
        secret_base64: "AAAAAAAAAAA=".to_string(),
    }];
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(matches!(
        error,
        DnsRuntimeConversionError::InvalidValue { .. }
    ));
}

#[test]
fn enabled_p11_hsm_requires_a_module_path() {
    let mut config = authoritative();
    config.dnssec.hsm.enabled = true;
    config.dnssec.hsm.module_path = String::new();
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(matches!(
        error,
        DnsRuntimeConversionError::InvalidValue { ref path, .. } if path == "dns.dnssec.hsm.module_path"
    ));
}

#[test]
fn enabled_p11_hsm_projects_fail_closed_settings() {
    let mut config = authoritative();
    config.dnssec.hsm.enabled = true;
    config.dnssec.hsm.module_path = "/usr/lib/pkcs11.so".to_string();
    config.dnssec.hsm.slot_id = Some(3);
    config.dnssec.hsm.pin = Some("1234".to_string());
    config.dnssec.hsm.key_label = Some("dns-ksk".to_string());
    let runtime = convert(&config);
    assert!(runtime.dnssec.hsm.enabled);
    assert_eq!(runtime.dnssec.hsm.provider, rt::HsmProviderRuntime::Pkcs11);
    assert_eq!(runtime.dnssec.hsm.module_path, "/usr/lib/pkcs11.so");
    assert_eq!(runtime.dnssec.hsm.slot_id, Some(3));
    assert!(runtime.dnssec.hsm.require_hsm, "PKCS#11 must fail closed");
}

// ---------------------------------------------------------------------------
// Zones
// ---------------------------------------------------------------------------

#[test]
fn zone_specs_map_record_types_to_hickory() {
    use synvoid_config::dns::{DnsRecordEntry, DnsRecordType, DnsZoneEntry};
    let mut config = authoritative();
    config.zones.items = vec![DnsZoneEntry {
        zone: "example.com".to_string(),
        records: vec![
            DnsRecordEntry {
                name: "example.com".to_string(),
                record_type: DnsRecordType::Soa,
                value: "ns1.example.com. admin.example.com. 1 7200 3600 604800 300".to_string(),
                ttl: Some(300),
                priority: None,
            },
            DnsRecordEntry {
                name: "www.example.com".to_string(),
                record_type: DnsRecordType::A,
                value: "192.0.2.1".to_string(),
                ttl: None,
                priority: None,
            },
            DnsRecordEntry {
                name: "uri.example.com".to_string(),
                record_type: DnsRecordType::Uri,
                value: "https://example.com".to_string(),
                ttl: Some(60),
                priority: None,
            },
        ],
        dnssec: None,
    }];

    let runtime = convert(&config);
    assert_eq!(runtime.zones.len(), 1);
    let zone = &runtime.zones[0];
    assert_eq!(zone.origin, "example.com");
    assert_eq!(zone.records.len(), 3);
    assert_eq!(zone.records[0].record_type, HickoryRecordType::SOA);
    assert_eq!(zone.records[0].ttl, Some(300));
    // A missing TTL must stay optional so the loader can apply default_ttl.
    assert_eq!(zone.records[1].ttl, None);
    assert_eq!(zone.records[1].record_type, HickoryRecordType::A);
    // Private-use code preserved numerically.
    assert_eq!(zone.records[2].record_type, HickoryRecordType::from(256));
    assert!(zone.dnssec.is_none());
}

// ---------------------------------------------------------------------------
// Recursive
// ---------------------------------------------------------------------------

#[test]
fn recursive_defaults_project_exact_runtime_values() {
    let runtime = convert(&authoritative());
    let recursive = &runtime.recursive;
    assert!(!recursive.enabled);
    assert_eq!(
        recursive.bind_address,
        SocketAddr::from(([127, 0, 0, 1], 1053))
    );
    assert_eq!(recursive.upstream, rt::RecursiveUpstreamRuntime::System);
    assert_eq!(recursive.cache.capacity, 1_000_000);
    assert_eq!(recursive.cache.negative_ttl, Duration::from_secs(300));
    assert_eq!(recursive.cache.stale_ttl, Duration::from_secs(86_400));
    assert_eq!(recursive.cache.max_ttl, Duration::from_secs(86_400));
    assert_eq!(recursive.cache.min_ttl, Duration::from_secs(0));
    assert!(recursive.dnssec_validation);
    assert!(recursive.qname_minimization);
    assert_eq!(recursive.query_timeout, Duration::from_secs(5));
    assert_eq!(recursive.max_concurrent_queries, 10_000);
    assert_eq!(recursive.max_cname_depth, 10);
    assert_eq!(recursive.max_recursion_depth, 16);
    assert_eq!(recursive.max_per_client_queries, 100);
    assert_eq!(recursive.circuit_breaker.failure_threshold, 5);
    assert_eq!(
        recursive.circuit_breaker.recovery_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(recursive.circuit_breaker.success_threshold, 2);
    assert_eq!(recursive.ecs.policy, rt::RecursiveEcsPolicyRuntime::Never);
    assert!(recursive.client_acl.is_none());
}

#[test]
fn recursive_upstream_modes_normalize_without_ambiguity() {
    use synvoid_config::dns::{RecursiveUpstreamProvider, RecursiveUpstreamServer};

    let mut config = authoritative();

    // System with no servers stays System.
    config.recursive.upstream_provider = RecursiveUpstreamProvider::System;
    assert_eq!(
        convert(&config).recursive.upstream,
        rt::RecursiveUpstreamRuntime::System
    );

    // System with explicit endpoints becomes CustomEndpoints.
    config.recursive.upstream_servers = vec![RecursiveUpstreamServer {
        address: String::new(),
        port: 5353,
        ip: Some(IpAddr::from([9, 9, 9, 9])),
    }];
    assert_eq!(
        convert(&config).recursive.upstream,
        rt::RecursiveUpstreamRuntime::CustomEndpoints(vec![rt::CustomUpstreamEndpoint::Literal {
            ip: IpAddr::from([9, 9, 9, 9]),
            port: 5353
        }])
    );

    // A hostname endpoint stays distinguishable from a literal IP.
    config.recursive.upstream_provider = RecursiveUpstreamProvider::Custom;
    config.recursive.upstream_servers = vec![RecursiveUpstreamServer {
        address: "resolver.internal".to_string(),
        port: 53,
        ip: None,
    }];
    assert_eq!(
        convert(&config).recursive.upstream,
        rt::RecursiveUpstreamRuntime::CustomEndpoints(vec![rt::CustomUpstreamEndpoint::Hostname {
            host: "resolver.internal".to_string(),
            port: 53
        }])
    );

    config.recursive.upstream_provider = RecursiveUpstreamProvider::Google;
    config.recursive.upstream_servers.clear();
    assert_eq!(
        convert(&config).recursive.upstream,
        rt::RecursiveUpstreamRuntime::Google
    );

    config.recursive.upstream_provider = RecursiveUpstreamProvider::Cloudflare;
    assert_eq!(
        convert(&config).recursive.upstream,
        rt::RecursiveUpstreamRuntime::Cloudflare
    );

    config.recursive.upstream_provider = RecursiveUpstreamProvider::GlobalNodes;
    assert_eq!(
        convert(&config).recursive.upstream,
        rt::RecursiveUpstreamRuntime::GlobalNodes
    );

    config.recursive.upstream_provider = RecursiveUpstreamProvider::Recursive;
    config.recursive.root_hints_path = "/etc/synvoid/root.hints".to_string();
    config.recursive.trust_anchor_path = "/etc/synvoid/anchor.key".to_string();
    assert_eq!(
        convert(&config).recursive.upstream,
        rt::RecursiveUpstreamRuntime::Recursive {
            root_hints: std::path::PathBuf::from("/etc/synvoid/root.hints"),
            trust_anchor: std::path::PathBuf::from("/etc/synvoid/anchor.key"),
        }
    );
}

#[test]
fn forwarder_modes_do_not_claim_local_dnssec_validation() {
    use synvoid_config::dns::RecursiveUpstreamProvider;

    let mut config = authoritative();
    config.recursive.enabled = true;
    config.recursive.dnssec_validation = true;

    for provider in [
        RecursiveUpstreamProvider::Google,
        RecursiveUpstreamProvider::Cloudflare,
        RecursiveUpstreamProvider::System,
    ] {
        config.recursive.upstream_provider = provider;
        let recursive = convert(&config).recursive;
        assert!(
            !recursive.performs_local_dnssec_validation,
            "{provider:?} must not claim local DNSSEC validation"
        );
        assert!(
            recursive.dnssec_validation,
            "the persisted flag still projects verbatim; the truthfulness \
             signal is performs_local_dnssec_validation"
        );
    }

    config.recursive.upstream_provider = RecursiveUpstreamProvider::Recursive;
    assert!(convert(&config).recursive.performs_local_dnssec_validation);
}

#[test]
fn recursive_acl_parses_cidrs_and_action_before_startup() {
    use synvoid_config::dns::RecursiveClientAcl;

    let mut config = authoritative();
    config.recursive.enabled = true;
    config.recursive.client_acl = Some(RecursiveClientAcl {
        allowed_clients: vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
        action: "reject".to_string(),
    });
    let runtime = convert(&config);
    let acl = runtime.recursive.client_acl.clone().expect("ACL projects");
    assert_eq!(acl.allowed_clients.len(), 2);
    assert_eq!(acl.action, rt::RecursiveAclActionRuntime::Reject);
    assert!(acl.is_client_allowed(IpAddr::from([10, 1, 2, 3])));
    assert!(!acl.is_client_allowed(IpAddr::from([11, 1, 2, 3])));

    config.recursive.client_acl.as_mut().unwrap().action = "allow".to_string();
    let acl = convert(&config).recursive.client_acl.unwrap();
    assert_eq!(acl.action, rt::RecursiveAclActionRuntime::Allow);
    assert!(acl.is_client_allowed(IpAddr::from([11, 1, 2, 3])));
}

#[test]
fn invalid_recursive_cidr_is_rejected_before_listener_startup() {
    use synvoid_config::dns::RecursiveClientAcl;

    // `RecursiveDnsConfig::validate()` is the operator-facing gate: it
    // rejects a malformed CIDR, so the recursive listener is never reached.
    // The adapter re-parses independently as defense in depth.
    let mut config = authoritative();
    config.recursive.enabled = true;
    config.recursive.client_acl = Some(RecursiveClientAcl {
        allowed_clients: vec!["10.0.0.0/33".to_string()],
        action: "reject".to_string(),
    });
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    match error {
        DnsRuntimeConversionError::InvalidPersistedConfig(ref reason) => {
            assert!(
                reason.contains("10.0.0.0/33"),
                "the operator must see the offending value: {reason}"
            );
        }
        other => panic!("expected the persisted-validation gate, got {other:?}"),
    }
    assert!(rt::IpNetwork::parse("10.0.0.0/33").is_err());
}

#[test]
fn unknown_recursive_acl_action_is_rejected() {
    use synvoid_config::dns::RecursiveClientAcl;

    let mut config = authoritative();
    config.recursive.enabled = true;
    config.recursive.client_acl = Some(RecursiveClientAcl {
        allowed_clients: Vec::new(),
        action: "sometimes".to_string(),
    });
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(
        matches!(error, DnsRuntimeConversionError::InvalidPersistedConfig(_)),
        "got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Invalid values and open-resolver gates
// ---------------------------------------------------------------------------

#[test]
fn zero_port_is_rejected() {
    let mut config = authoritative();
    config.port = 0;
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(matches!(
        error,
        DnsRuntimeConversionError::InvalidPersistedConfig(_)
    ));
}

#[test]
fn unparseable_authoritative_bind_is_rejected() {
    let mut config = authoritative();
    config.bind_address = "example.com".to_string();
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(matches!(
        error,
        DnsRuntimeConversionError::InvalidPersistedConfig(_)
    ));
}

#[test]
fn wildcard_recursive_bind_is_rejected_as_an_open_resolver() {
    for bind in ["0.0.0.0", "::"] {
        let mut config = authoritative();
        config.recursive.enabled = true;
        config.recursive.bind_address = bind.to_string();
        let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
        assert!(
            matches!(error, DnsRuntimeConversionError::InvalidPersistedConfig(_)),
            "recursive bind {bind} must be rejected"
        );
    }
}

#[test]
fn unparseable_recursive_bind_is_rejected() {
    let mut config = authoritative();
    config.recursive.enabled = true;
    config.recursive.bind_address = "resolver.internal".to_string();
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(matches!(
        error,
        DnsRuntimeConversionError::InvalidPersistedConfig(_)
    ));
}

#[test]
fn custom_upstream_requires_endpoints() {
    use synvoid_config::dns::RecursiveUpstreamProvider;

    let mut config = authoritative();
    config.recursive.enabled = true;
    config.recursive.upstream_provider = RecursiveUpstreamProvider::Custom;
    config.recursive.upstream_servers.clear();
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(matches!(
        error,
        DnsRuntimeConversionError::InvalidPersistedConfig(_)
    ));
}

#[test]
fn invalid_dns64_prefix_is_rejected_instead_of_defaulted() {
    let mut config = authoritative();
    config.dns64.enabled = true;
    config.dns64.prefix = "not-an-ipv6-prefix".to_string();
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(
        matches!(
            error,
            DnsRuntimeConversionError::InvalidValue { ref path, .. } if path == "dns.dns64.prefix"
        ),
        "an invalid DNS64 prefix must fail closed, not warn-and-default: {error:?}"
    );
}

#[test]
fn transfer_allowlist_activation_is_fail_closed() {
    // Phase 45: `dns.settings.allow_transfer` activation is rejected outright,
    // so the runtime transfer allowlist is always empty today. The parsed
    // `IpNetwork` machinery is still exercised directly below so the
    // projection stays correct when the transfer design gate lands.
    let mut config = authoritative();
    config.settings.allow_transfer = vec!["10.0.0.2".to_string()];
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    assert!(
        matches!(
            error,
            DnsRuntimeConversionError::Unsupported { ref path, .. }
                if path == "dns.settings.allow_transfer"
        ),
        "got {error:?}"
    );
}

#[test]
fn transfer_allowlist_cidr_projection_semantics() {
    // A bare address parses to a full-length prefix; a CIDR keeps its length.
    let bare = rt::IpNetwork::parse("10.0.0.2").expect("bare address parses");
    assert_eq!(bare.prefix_len(), 32);
    assert!(bare.contains(IpAddr::from([10, 0, 0, 2])));
    assert!(!bare.contains(IpAddr::from([10, 0, 0, 3])));

    let cidr = rt::IpNetwork::parse("10.0.0.0/24").expect("cidr parses");
    assert_eq!(cidr.prefix_len(), 24);
    assert!(cidr.contains(IpAddr::from([10, 0, 0, 255])));
    assert!(!cidr.contains(IpAddr::from([10, 0, 1, 0])));

    // IPv6 and out-of-range prefixes.
    let v6 = rt::IpNetwork::parse("2001:db8::/32").expect("v6 cidr parses");
    assert_eq!(v6.prefix_len(), 32);
    assert!(v6.contains("2001:db8:ffff::1".parse().unwrap()));
    assert!(rt::IpNetwork::parse("10.0.0.0/33").is_err());
    assert!(rt::IpNetwork::parse("10.0.0.0/abc").is_err());
    assert!(rt::IpNetwork::parse("not-an-address").is_err());
}

// ---------------------------------------------------------------------------
// Phase 45 fail-closed unsupported activation
// ---------------------------------------------------------------------------

#[test]
fn phase45_unsupported_activations_are_rejected_with_typed_paths() {
    use synvoid_config::dns::DnsConfigError;

    // RPZ
    let mut config = authoritative();
    config.rpz.enabled = true;
    assert_unsupported_path(&config, "dns.rpz");

    // Prefetch
    let mut config = authoritative();
    config.prefetch.enabled = true;
    assert_unsupported_path(&config, "dns.prefetch");

    // EDNS padding
    let mut config = authoritative();
    config.settings.padding.enabled = true;
    assert_unsupported_path(&config, "dns.settings.padding");

    // QNAME privacy
    let mut config = authoritative();
    config.settings.qname_privacy.enabled = true;
    assert_unsupported_path(&config, "dns.settings.qname_privacy");

    // Unwired rebinding protection (the rest of the firewall contract holds)
    let mut config = authoritative();
    config.firewall = firewall_on();
    config.firewall.rebinding_protection.enabled = true;
    assert_unsupported_path(&config, "dns.firewall.rebinding_protection");

    // Zone transfer activation
    let mut config = authoritative();
    config.settings.allow_transfer = vec!["10.0.0.2".to_string()];
    assert_unsupported_path(&config, "dns.settings.allow_transfer");

    // Dynamic update activation
    let mut config = authoritative();
    config.settings.dynamic_update.enabled = true;
    assert_unsupported_path(&config, "dns.settings.dynamic_update");

    // NOTIFY activation
    let mut config = authoritative();
    config.settings.notify.enabled = true;
    assert_unsupported_path(&config, "dns.settings.notify");

    // Ensure the error really is the typed Phase 45 variant, not a string match
    // on an unrelated failure.
    let mut config = authoritative();
    config.rpz.enabled = true;
    let direct = config.validate().expect_err("validate rejects");
    assert!(matches!(direct, DnsConfigError::Unsupported { .. }));
}

fn assert_unsupported_path(config: &DnsConfig, expected_path_fragment: &str) {
    let error = dns_runtime_config_from_persisted(config).expect_err("must reject");
    match error {
        DnsRuntimeConversionError::Unsupported { ref path, .. } => assert!(
            path.contains(expected_path_fragment),
            "expected an unsupported path containing `{expected_path_fragment}`, got `{path}`"
        ),
        other => panic!("expected Unsupported for {expected_path_fragment}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Shipped example profiles
// ---------------------------------------------------------------------------

fn load_example(name: &str) -> DnsConfig {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/dns")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let wrapper: ExampleDnsWrapper =
        toml::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    wrapper.dns
}

/// Wrapper to deserialize the `[dns]` section from the shipped example files.
#[derive(serde::Deserialize)]
struct ExampleDnsWrapper {
    dns: DnsConfig,
}

#[test]
fn shipped_authoritative_profile_projects_exactly() {
    let runtime = convert(&load_example("authoritative_public.toml"));
    assert!(runtime.enabled);
    assert_eq!(runtime.bind_address, SocketAddr::from(([0, 0, 0, 0], 53)));
    assert_eq!(runtime.ttl.default_ttl, 300);
    assert_eq!(runtime.cache.capacity, 100_000);
    assert_eq!(runtime.cache.max_ttl, Duration::from_secs(3600));
    assert_eq!(runtime.cache.min_ttl, Duration::from_secs(60));
    assert_eq!(runtime.ttl.negative_cache_ttl, 300);
    assert_eq!(runtime.rate_limit.mode, rt::DnsRateLimitModeRuntime::Shared);
    assert_eq!(runtime.rate_limit.per_second, 500);
    assert!(runtime.rrl.enabled);
    assert!(runtime.firewall.enabled);
    assert!(runtime.firewall.block_internal_ips);
    assert!(runtime.firewall.block_zone_transfers);
    assert_eq!(runtime.limits.max_tcp_connections, 500);
    assert_eq!(runtime.limits.max_concurrent_queries, 2500);
    assert_eq!(runtime.limits.max_query_size, 65_535);
    assert_eq!(runtime.limits.max_records_per_response, 1000);
    assert_eq!(runtime.zones.len(), 1);
    assert_eq!(runtime.zones[0].origin, "example.com");
    assert!(runtime.zones[0].records.is_empty());
    assert!(!runtime.recursive.enabled);
    assert!(!runtime.dot.enabled);
    assert!(!runtime.dnssec.enabled);
}

#[test]
fn shipped_dnssec_profile_projects_exactly() {
    let runtime = convert(&load_example("dnssec_signed.toml"));
    assert!(runtime.dnssec.enabled);
    assert_eq!(runtime.dnssec.domain, "example.com");
    assert_eq!(
        runtime.dnssec.key_path,
        std::path::PathBuf::from("/var/lib/synvoid/dns/keys")
    );
    assert_eq!(
        runtime.dnssec.algorithm,
        rt::DnssecAlgorithmRuntime::Ed25519
    );
    assert!(runtime.dnssec.denial.nsec3_enabled);
    assert_eq!(runtime.dnssec.denial.nsec3_iterations, 50);
    assert_eq!(runtime.dnssec.denial.nsec3_algorithm, 1);
    assert!(!runtime.dnssec.denial.nsec_enabled);
    assert!(runtime.firewall.enabled);
    assert_eq!(runtime.zones.len(), 1);
    assert!(
        runtime.tsig_keys.is_empty(),
        "TSIG entries are commented out"
    );
    assert!(!runtime.dnssec.hsm.enabled);
}

#[test]
fn shipped_encrypted_transport_profile_projects_exactly() {
    let runtime = convert(&load_example("encrypted_dot_doh.toml"));
    assert!(runtime.dot.enabled);
    assert_eq!(
        runtime.dot.bind_address,
        Some(SocketAddr::from(([0, 0, 0, 0], 853)))
    );
    assert!(runtime.doh.enabled);
    assert_eq!(
        runtime.doh.bind_address,
        Some(SocketAddr::from(([0, 0, 0, 0], 443)))
    );
    // DoQ is commented out in the shipped profile.
    assert!(!runtime.doq.enabled);
    assert!(runtime.doq.bind_address.is_none());
    // TLS material is composition/provider owned: the runtime DTO carries
    // only the parsed bind socket, never certificate paths.
    assert_eq!(
        runtime.dot.bind_address,
        Some(SocketAddr::from(([0, 0, 0, 0], 853)))
    );
    assert_eq!(
        runtime.doh.bind_address,
        Some(SocketAddr::from(([0, 0, 0, 0], 443)))
    );
}

#[test]
fn shipped_recursive_profile_projects_exactly() {
    let runtime = convert(&load_example("recursive_local.toml"));
    assert_eq!(runtime.bind_address, SocketAddr::from(([127, 0, 0, 1], 53)));
    let recursive = &runtime.recursive;
    assert!(recursive.enabled);
    assert_eq!(
        recursive.bind_address,
        SocketAddr::from(([127, 0, 0, 1], 1053))
    );
    assert_eq!(recursive.upstream, rt::RecursiveUpstreamRuntime::System);
    assert!(recursive.dnssec_validation);
    assert!(recursive.qname_minimization);
    assert_eq!(recursive.query_timeout, Duration::from_secs(5));
    assert_eq!(recursive.max_concurrent_queries, 10_000);
    assert_eq!(recursive.max_cname_depth, 10);
    assert_eq!(recursive.max_recursion_depth, 16);
    assert_eq!(recursive.max_per_client_queries, 100);
    assert_eq!(recursive.circuit_breaker.failure_threshold, 5);
    assert_eq!(
        recursive.circuit_breaker.recovery_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(recursive.circuit_breaker.success_threshold, 2);
    assert_eq!(recursive.ecs.policy, rt::RecursiveEcsPolicyRuntime::Never);
    assert!(!recursive.ecs.include_scope_in_response);
    assert_eq!(recursive.cache.capacity, 1_000_000);
    assert_eq!(runtime.limits.max_tcp_connections, 500);
    assert_eq!(runtime.limits.max_concurrent_queries, 2500);
}

#[test]
fn shipped_transfer_profile_is_rejected_by_the_fail_closed_contract() {
    // The shipped transfer profile documents the intended future shape; it is
    // explicitly not activatable today.
    let config = load_example("transfer_primary.toml");
    let error = dns_runtime_config_from_persisted(&config).expect_err("must reject");
    match error {
        DnsRuntimeConversionError::Unsupported { ref path, .. } => assert!(
            path.starts_with("dns.settings."),
            "expected a `dns.settings.*` unsupported path, got `{path}`"
        ),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
