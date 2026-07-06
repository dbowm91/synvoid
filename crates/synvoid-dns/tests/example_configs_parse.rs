//! Parse tests for the 5 example DNS config files.
//!
//! Ensures every example TOML deserializes into `DnsConfig` without error
//! and contains the expected structural values.

use synvoid_config::dns::{
    DnsConfig, DnsMode, DnsRateLimitMode, DnsSecAlgorithm, RecursiveUpstreamProvider, TsigAlgorithm,
};

fn example_path(name: &str) -> String {
    format!("{}/../../examples/dns/{}", env!("CARGO_MANIFEST_DIR"), name,)
}

/// Wrapper to deserialize `[dns]` section from the example TOML files.
#[derive(serde::Deserialize)]
struct DnsWrapper {
    dns: DnsConfig,
}

fn load_and_parse(name: &str) -> DnsConfig {
    let path = example_path(name);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    let wrapper: DnsWrapper =
        toml::from_str(&content).unwrap_or_else(|e| panic!("Failed to parse {}: {}", name, e));
    wrapper.dns
}

#[test]
fn authoritative_public_parses() {
    let cfg = load_and_parse("authoritative_public.toml");

    assert!(cfg.enabled);
    assert_eq!(cfg.bind_address, "0.0.0.0");
    assert_eq!(cfg.port, 53);
    assert_eq!(cfg.mode, DnsMode::Standalone);

    // ratelimit
    assert_eq!(cfg.ratelimit.mode, DnsRateLimitMode::Shared);
    assert_eq!(cfg.ratelimit.per_second, 500);
    assert_eq!(cfg.ratelimit.per_minute, 5000);

    // rrl
    assert!(cfg.rrl.enabled);
    assert_eq!(cfg.rrl.responses_per_second, 100);
    assert_eq!(cfg.rrl.window_secs, 5);
    assert_eq!(cfg.rrl.max_responses, 1000);
    assert_eq!(cfg.rrl.ttl, 300);

    // settings
    assert_eq!(cfg.settings.default_ttl, 300);
    assert!(cfg.settings.cache_enabled);
    assert_eq!(cfg.settings.cache_size, 100000);
    assert_eq!(cfg.settings.cache_max_ttl, 3600);
    assert_eq!(cfg.settings.cache_min_ttl, 60);
    assert_eq!(cfg.settings.negative_cache_ttl, 300);

    // firewall
    assert!(cfg.firewall.enabled);
    assert!(cfg.firewall.block_internal_ips);
    assert!(cfg.firewall.block_zone_transfers);
    assert!(cfg.firewall.rebinding_protection.enabled);
    assert_eq!(cfg.firewall.rebinding_protection.min_ttl_for_internal, 1800);

    // limits
    assert_eq!(cfg.limits.max_tcp_connections, 500);
    assert_eq!(cfg.limits.max_concurrent_queries, 2500);
    assert_eq!(cfg.limits.max_query_size, 65535);
    assert_eq!(cfg.limits.max_response_size, 65535);
    assert_eq!(cfg.limits.max_records_per_response, 1000);
    assert_eq!(cfg.limits.max_tcp_idle_time_secs, 300);
    assert_eq!(cfg.limits.max_tcp_query_time_secs, 30);

    // zones
    assert_eq!(cfg.zones.items.len(), 1);
    assert_eq!(cfg.zones.items[0].zone, "example.com");
}

#[test]
fn dnssec_signed_parses() {
    let cfg = load_and_parse("dnssec_signed.toml");

    assert!(cfg.enabled);
    assert_eq!(cfg.bind_address, "0.0.0.0");
    assert_eq!(cfg.port, 53);
    assert_eq!(cfg.mode, DnsMode::Standalone);

    // dnssec
    assert!(cfg.dnssec.enabled);
    assert_eq!(cfg.dnssec.domain, "example.com");
    assert_eq!(cfg.dnssec.key_path, "/var/lib/synvoid/dns/keys");
    assert_eq!(cfg.dnssec.algorithm, DnsSecAlgorithm::Ed25519);
    assert!(cfg.dnssec.nsec3_enabled);
    assert_eq!(cfg.dnssec.nsec3_iterations, 50);
    assert_eq!(cfg.dnssec.nsec3_algorithm, 1);

    // firewall
    assert!(cfg.firewall.enabled);
    assert!(cfg.firewall.block_zone_transfers);
    assert!(cfg.firewall.block_internal_ips);

    // zones
    assert_eq!(cfg.zones.items.len(), 1);
    assert_eq!(cfg.zones.items[0].zone, "example.com");
}

#[test]
fn encrypted_dot_doh_parses() {
    let cfg = load_and_parse("encrypted_dot_doh.toml");

    assert!(cfg.enabled);
    assert_eq!(cfg.bind_address, "0.0.0.0");
    assert_eq!(cfg.port, 53);

    // DoT
    assert!(cfg.dot.enabled);
    assert_eq!(cfg.dot.bind_address, "0.0.0.0");
    assert_eq!(cfg.dot.port, 853);
    assert_eq!(
        cfg.dot.tls_cert_path.as_deref(),
        Some("/etc/letsencrypt/live/dns.example.com/fullchain.pem")
    );
    assert_eq!(
        cfg.dot.tls_key_path.as_deref(),
        Some("/etc/letsencrypt/live/dns.example.com/privkey.pem")
    );

    // DoH
    assert!(cfg.doh.enabled);
    assert_eq!(cfg.doh.bind_address, "0.0.0.0");
    assert_eq!(cfg.doh.port, 443);
    assert_eq!(
        cfg.doh.tls_cert_path.as_deref(),
        Some("/etc/letsencrypt/live/dns.example.com/fullchain.pem")
    );
    assert_eq!(
        cfg.doh.tls_key_path.as_deref(),
        Some("/etc/letsencrypt/live/dns.example.com/privkey.pem")
    );
    assert_eq!(cfg.doh.path, "/dns-query");

    // zones
    assert_eq!(cfg.zones.items.len(), 1);
    assert_eq!(cfg.zones.items[0].zone, "example.com");
}

#[test]
fn recursive_local_parses() {
    let cfg = load_and_parse("recursive_local.toml");

    assert!(cfg.enabled);
    assert_eq!(cfg.bind_address, "127.0.0.1");
    assert_eq!(cfg.port, 53);
    assert_eq!(cfg.mode, DnsMode::Standalone);

    // recursive
    assert!(cfg.recursive.enabled);
    assert_eq!(cfg.recursive.bind_address, "127.0.0.1");
    assert_eq!(cfg.recursive.port, 1053);
    assert_eq!(
        cfg.recursive.upstream_provider,
        RecursiveUpstreamProvider::System
    );
    assert!(cfg.recursive.dnssec_validation);
    assert!(cfg.recursive.qname_minimization);
    assert_eq!(cfg.recursive.query_timeout_secs, 5);
    assert_eq!(cfg.recursive.max_concurrent_queries, 10000);
    assert_eq!(cfg.recursive.max_cname_depth, 10);
    assert_eq!(cfg.recursive.max_recursion_depth, 16);
    assert_eq!(cfg.recursive.max_per_client_queries, 100);

    // circuit breaker
    assert_eq!(cfg.recursive.circuit_breaker.failure_threshold, 5);
    assert_eq!(cfg.recursive.circuit_breaker.recovery_timeout_secs, 30);
    assert_eq!(cfg.recursive.circuit_breaker.success_threshold, 2);

    // ratelimit
    assert_eq!(cfg.ratelimit.mode, DnsRateLimitMode::Shared);
    assert_eq!(cfg.ratelimit.per_second, 500);
    assert_eq!(cfg.ratelimit.per_minute, 5000);

    // limits
    assert_eq!(cfg.limits.max_tcp_connections, 500);
    assert_eq!(cfg.limits.max_concurrent_queries, 2500);
}

#[test]
fn transfer_primary_parses() {
    let cfg = load_and_parse("transfer_primary.toml");

    assert!(cfg.enabled);
    assert_eq!(cfg.bind_address, "0.0.0.0");
    assert_eq!(cfg.port, 53);
    assert_eq!(cfg.mode, DnsMode::Standalone);

    // settings
    assert_eq!(cfg.settings.default_ttl, 300);
    assert!(cfg.settings.cache_enabled);
    assert_eq!(cfg.settings.allow_transfer, vec!["10.0.0.2", "10.0.0.3"]);
    assert!(cfg.settings.require_tsig);
    assert!(cfg.settings.wildcard_transfer_requires_tsig);

    // notify
    assert!(cfg.settings.notify.enabled);
    assert_eq!(
        cfg.settings.notify.also_notify,
        vec!["10.0.0.2:53", "10.0.0.3:53"]
    );

    // ixfr
    assert!(cfg.settings.ixfr_enabled);
    assert_eq!(cfg.settings.ixfr_history_size, 200);
    assert!(cfg.settings.ixfr_fallback_to_axfr);

    // firewall
    assert!(cfg.firewall.enabled);
    assert!(!cfg.firewall.block_zone_transfers);
    assert!(cfg.firewall.block_internal_ips);

    // ratelimit
    assert_eq!(cfg.ratelimit.mode, DnsRateLimitMode::Shared);
    assert_eq!(cfg.ratelimit.per_second, 500);
    assert_eq!(cfg.ratelimit.per_minute, 5000);

    // tsig keys
    assert_eq!(cfg.dnssec.tsig_keys.len(), 1);
    assert_eq!(cfg.dnssec.tsig_keys[0].name, "transfer-key");
    assert_eq!(cfg.dnssec.tsig_keys[0].algorithm, TsigAlgorithm::HmacSha256);
    assert_eq!(
        cfg.dnssec.tsig_keys[0].secret_base64,
        "<base64-encoded-secret>"
    );

    // zones
    assert_eq!(cfg.zones.items.len(), 1);
    assert_eq!(cfg.zones.items[0].zone, "example.com");
}
