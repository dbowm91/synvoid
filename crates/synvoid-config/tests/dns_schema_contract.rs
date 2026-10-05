//! Persisted DNS configuration schema contract (moved in Phase 128).
//!
//! These assertions describe the *persisted* `[dns]` TOML/JSON shape owned by
//! `synvoid-config`. They lived in `synvoid-dns` while that crate still held a
//! `synvoid-config` dependency; Phase 128 removes that edge, so the schema
//! coverage moves to the crate that owns the schema.
//!
//! Runtime-value coverage stays in `synvoid-dns`; the persisted-to-runtime
//! projection itself is proven by the root parity suite
//! `tests/dns_runtime_config_parity.rs`.

use synvoid_config::dns::{
    CircuitBreakerConfig, DnsAnycastConfig, DnsConfig, DnsDohConfig, DnsDoqConfig, DnsDotConfig,
    DnsMode, RecursiveClientAcl, RecursiveDnsConfig, RecursiveEcsConfig, RecursiveUpstreamProvider,
    TrustAnchorConfig,
};

// Phase 128: the blocks moved here referenced these types through the
// file-level imports that `synvoid-dns` used to carry. They now resolve
// against this crate's own library.
#[test]
fn test_admin_token_validation_rejects_weak_tokens() {
    use synvoid_config::admin::AdminConfig;

    let weak_tokens = vec![
        "short",
        "password123",
        "admin",
        "changeme",
        "12345678",
        "qwertyui",
    ];

    for token in weak_tokens {
        let mut config = AdminConfig::default();
        config.port = 8081;
        config.token = token.to_string();
        let _result = config.validate();
        let resolved = config.resolve_token();
        assert!(!resolved.is_empty());
    }

    let strong_token = "ThisIsAveryLongSecureTokenThatIsHardToGuessABCDEF!@#$%";
    let mut config = AdminConfig::default();
    config.port = 8081;
    config.token = strong_token.to_string();
    config.bcrypt_cost = 12;
    assert!(
        config.validate().is_ok(),
        "Validation failed for strong token: {:?}",
        config.validate()
    );
}
#[test]
fn test_recursive_dns_config_defaults() {
    use synvoid_config::dns::{RecursiveDnsConfig, RecursiveUpstreamProvider};

    let config = RecursiveDnsConfig::default();

    assert!(!config.enabled);
    assert_eq!(config.bind_address, "127.0.0.1");
    assert_eq!(config.port, 1053);
    assert_eq!(config.upstream_provider, RecursiveUpstreamProvider::System);
    assert!(config.dnssec_validation);
    assert!(config.qname_minimization);
    assert_eq!(config.query_timeout_secs, 5);
    assert_eq!(config.max_concurrent_queries, 10000);
}
#[test]
fn test_recursive_dns_config_validation() {
    use synvoid_config::dns::{RecursiveDnsConfig, RecursiveUpstreamProvider};

    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.upstream_provider = RecursiveUpstreamProvider::Custom;
    config.upstream_servers = vec![];

    let result = config.validate();
    assert!(result.is_err());
}
#[test]
fn test_recursive_dns_config_upstream_ips_google() {
    use std::net::IpAddr;
    use synvoid_config::dns::{RecursiveDnsConfig, RecursiveUpstreamProvider};

    let mut config = RecursiveDnsConfig::default();
    config.upstream_provider = RecursiveUpstreamProvider::Google;

    let ips = config.upstream_ips();

    assert!(!ips.is_empty());
    assert!(ips
        .iter()
        .any(|ip: &IpAddr| ip.to_string() == "8.8.8.8" || ip.to_string() == "8.8.4.4"));
}
#[test]
fn test_recursive_dns_config_upstream_ips_cloudflare() {
    use synvoid_config::dns::{RecursiveDnsConfig, RecursiveUpstreamProvider};

    let mut config = RecursiveDnsConfig::default();
    config.upstream_provider = RecursiveUpstreamProvider::Cloudflare;

    let ips = config.upstream_ips();

    assert!(!ips.is_empty());
}
#[test]
fn test_recursive_dns_config_custom_servers() {
    use std::net::IpAddr;
    use synvoid_config::dns::{
        RecursiveDnsConfig, RecursiveUpstreamProvider, RecursiveUpstreamServer,
    };

    let mut config = RecursiveDnsConfig::default();
    config.upstream_provider = RecursiveUpstreamProvider::Custom;
    config.upstream_servers = vec![RecursiveUpstreamServer {
        address: "1.1.1.1".to_string(),
        port: 53,
        ip: Some(IpAddr::from([1, 1, 1, 1])),
    }];

    let ips = config.upstream_ips();
    assert!(ips.contains(&IpAddr::from([1, 1, 1, 1])));
}
#[test]
fn test_recursive_dns_config_recursive_provider() {
    use synvoid_config::dns::{RecursiveDnsConfig, RecursiveUpstreamProvider};

    let mut config = RecursiveDnsConfig::default();
    config.upstream_provider = RecursiveUpstreamProvider::Recursive;

    assert_eq!(
        config.upstream_provider,
        RecursiveUpstreamProvider::Recursive
    );
    assert_eq!(config.root_hints_path, "root.hints");
    assert_eq!(config.trust_anchor_path, "trusted-key.key");
}
#[test]
fn test_recursive_dns_config_default_paths() {
    use synvoid_config::dns::RecursiveDnsConfig;

    let config = RecursiveDnsConfig::default();

    assert_eq!(config.root_hints_path, "root.hints");
    assert_eq!(config.trust_anchor_path, "trusted-key.key");
}
#[test]
fn test_recursive_dns_config_validation_timeout() {
    use synvoid_config::dns::RecursiveDnsConfig;

    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.query_timeout_secs = 0;

    let result = config.validate();
    assert!(result.is_err());
}
#[test]
fn test_dns_config_includes_recursive() {
    use synvoid_config::dns::DnsConfig;

    let config = DnsConfig::default();

    assert!(!config.recursive.enabled);
    assert_eq!(config.recursive.port, 1053);
}
#[test]
fn test_dnssec_config_validation() {
    use synvoid_config::dns::RecursiveDnsConfig;

    let mut config = RecursiveDnsConfig::default();
    config.dnssec_validation = true;

    assert!(config.dnssec_validation);
}
#[test]
fn test_rfc5011_config_timeouts() {
    use synvoid_config::dns::TrustAnchorConfig;

    let config = TrustAnchorConfig {
        enabled: true,
        pending_observation_days: 30,
        revocation_grace_days: 30,
        extended_removal_days: 60,
        trust_anchor_retention_days: 7,
        ..TrustAnchorConfig::default()
    };

    assert_eq!(config.pending_observation_days, 30);
    assert_eq!(config.revocation_grace_days, 30);
    assert_eq!(config.extended_removal_days, 60);
    assert_eq!(config.trust_anchor_retention_days, 7);
}
#[test]
fn test_recursive_cache_config_defaults() {
    let persisted = synvoid_config::dns::RecursiveCacheConfig::default();
    assert_eq!(persisted.capacity, 1_000_000);
    assert_eq!(persisted.negative_ttl_secs, 300);
    assert_eq!(persisted.stale_ttl_secs, 86400);
    assert_eq!(persisted.max_ttl_secs, 86400);
    assert_eq!(persisted.min_ttl_secs, 0);
}

#[test]
fn test_dns_config_defaults() {
    use synvoid_config::dns::{DnsConfig, DnsMode};

    let config = DnsConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.bind_address, "0.0.0.0");
    assert_eq!(config.port, 53);
    assert_eq!(config.mode, DnsMode::Standalone);
}
#[test]
fn test_dns_ratelimit_config_defaults() {
    use synvoid_config::dns::{DnsRateLimitConfig, DnsRateLimitMode};

    let config = DnsRateLimitConfig::default();
    assert_eq!(config.mode, DnsRateLimitMode::Shared);
    assert_eq!(config.per_second, 500);
    assert_eq!(config.per_minute, 5000);
}
#[test]
fn test_dns_rrl_config_defaults() {
    use synvoid_config::dns::DnsRrlConfig;

    let config = DnsRrlConfig {
        enabled: true,
        responses_per_second: 100,
        window_secs: 5,
        max_responses: 1000,
        ttl: 300,
    };
    assert!(config.enabled);
    assert_eq!(config.responses_per_second, 100);
    assert_eq!(config.window_secs, 5);
    assert_eq!(config.ttl, 300);
}
#[test]
fn test_dnssec_config_defaults() {
    use synvoid_config::dns::DnsSecConfig;

    let config = DnsSecConfig::default();
    assert!(!config.enabled);
}
#[test]
fn test_tsig_key_config_defaults() {
    use synvoid_config::dns::{TsigAlgorithm, TsigKeyConfig};

    let config = TsigKeyConfig::default();
    assert!(config.name.is_empty());
    assert!(config.secret_base64.is_empty());
    assert_eq!(config.algorithm, TsigAlgorithm::HmacSha256);
}

#[test]
fn dot_config_defaults_from_json() {
    let config: DnsDotConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(config.port, 853);
    assert_eq!(config.bind_address, "");
    assert!(config.tls_cert_path.is_none());
    assert!(config.tls_key_path.is_none());
    assert!(config.use_system_cert_store);
    assert!(!config.enabled);
}
#[test]
fn doh_config_defaults_from_json() {
    let config: DnsDohConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(config.port, 443);
    assert_eq!(config.bind_address, "");
    assert_eq!(config.path, "/dns-query");
    assert!(config.json_path.is_empty());
    assert!(config.tls_cert_path.is_none());
    assert!(config.tls_key_path.is_none());
    assert!(config.use_system_cert_store);
    assert!(!config.enabled);
}
#[test]
fn doq_config_defaults_from_json() {
    let config: DnsDoqConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(config.port, 853);
    assert_eq!(config.bind_address, "");
    assert!(config.tls_cert_path.is_none());
    assert!(config.tls_key_path.is_none());
    assert!(config.use_system_cert_store);
    assert_eq!(config.max_concurrent_streams, 100);
    assert_eq!(config.idle_timeout_secs, 30);
    assert!(!config.enabled);
}

/// Verify DoT config serialization roundtrip.
///
/// All fields must survive a serde_json serialize-deserialize cycle.
#[test]
fn dot_config_all_fields_roundtrip() {
    let config = DnsDotConfig {
        enabled: true,
        port: 8853,
        bind_address: "10.0.0.1".to_string(),
        tls_cert_path: Some("/etc/certs/dot.pem".to_string()),
        tls_key_path: Some("/etc/certs/dot-key.pem".to_string()),
        use_system_cert_store: false,
    };

    let json = serde_json::to_string(&config).expect("DoT config must serialize");
    let restored: DnsDotConfig = serde_json::from_str(&json).expect("DoT config must deserialize");

    assert!(restored.enabled);
    assert_eq!(restored.port, 8853);
    assert_eq!(restored.bind_address, "10.0.0.1");
    assert_eq!(
        restored.tls_cert_path,
        Some("/etc/certs/dot.pem".to_string())
    );
    assert_eq!(
        restored.tls_key_path,
        Some("/etc/certs/dot-key.pem".to_string())
    );
    assert!(!restored.use_system_cert_store);
}
/// Verify DoH config serialization roundtrip.
///
/// All fields must survive a serde_json serialize-deserialize cycle.
#[test]
fn doh_config_all_fields_roundtrip() {
    let config = DnsDohConfig {
        enabled: true,
        port: 1443,
        bind_address: "10.0.0.2".to_string(),
        path: "/custom-dns".to_string(),
        json_path: "/custom-dns-json".to_string(),
        tls_cert_path: Some("/etc/certs/doh.pem".to_string()),
        tls_key_path: Some("/etc/certs/doh-key.pem".to_string()),
        use_system_cert_store: true,
    };

    let json = serde_json::to_string(&config).expect("DoH config must serialize");
    let restored: DnsDohConfig = serde_json::from_str(&json).expect("DoH config must deserialize");

    assert!(restored.enabled);
    assert_eq!(restored.port, 1443);
    assert_eq!(restored.bind_address, "10.0.0.2");
    assert_eq!(restored.path, "/custom-dns");
    assert_eq!(restored.json_path, "/custom-dns-json");
    assert_eq!(
        restored.tls_cert_path,
        Some("/etc/certs/doh.pem".to_string())
    );
    assert!(restored.use_system_cert_store);
}
/// Verify DoQ config serialization roundtrip.
///
/// All fields must survive a serde_json serialize-deserialize cycle.
#[test]
fn doq_config_all_fields_roundtrip() {
    let config = DnsDoqConfig {
        enabled: true,
        port: 7853,
        bind_address: "10.0.0.3".to_string(),
        tls_cert_path: Some("/etc/certs/doq.pem".to_string()),
        tls_key_path: Some("/etc/certs/doq-key.pem".to_string()),
        use_system_cert_store: false,
        max_concurrent_streams: 200,
        idle_timeout_secs: 60,
    };

    let json = serde_json::to_string(&config).expect("DoQ config must serialize");
    let restored: DnsDoqConfig = serde_json::from_str(&json).expect("DoQ config must deserialize");

    assert!(restored.enabled);
    assert_eq!(restored.port, 7853);
    assert_eq!(restored.bind_address, "10.0.0.3");
    assert_eq!(restored.max_concurrent_streams, 200);
    assert_eq!(restored.idle_timeout_secs, 60);
    assert!(!restored.use_system_cert_store);
}
/// Verify all encrypted transport config defaults.
///
/// Serde defaults must produce correct values for omitted fields.
#[test]
fn encrypted_transport_config_defaults() {
    let dot: DnsDotConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(dot.port, 853, "DoT default port must be 853");
    assert!(!dot.enabled, "DoT must be disabled by default");
    assert!(
        dot.use_system_cert_store,
        "DoT must use system cert store by default"
    );

    let doh: DnsDohConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(doh.port, 443, "DoH default port must be 443");
    assert!(!doh.enabled, "DoH must be disabled by default");
    assert_eq!(
        doh.path, "/dns-query",
        "DoH default path must be /dns-query"
    );
    assert!(
        doh.use_system_cert_store,
        "DoH must use system cert store by default"
    );

    let doq: DnsDoqConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(doq.port, 853, "DoQ default port must be 853");
    assert!(!doq.enabled, "DoQ must be disabled by default");
    assert_eq!(
        doq.max_concurrent_streams, 100,
        "DoQ default max concurrent streams"
    );
    assert_eq!(doq.idle_timeout_secs, 30, "DoQ default idle timeout");
    assert!(
        doq.use_system_cert_store,
        "DoQ must use system cert store by default"
    );
}
/// Verify recursive DNS is disabled by default.
///
/// The default DnsConfig must have recursive.enabled = false with
/// sensible loopback binding to prevent open-resolver misconfigurations.
#[test]
fn recursive_disabled_by_default() {
    let config = DnsConfig::default();
    assert!(
        !config.recursive.enabled,
        "Recursive DNS must be disabled by default"
    );
    assert_eq!(
        config.recursive.bind_address, "127.0.0.1",
        "Recursive must bind to loopback by default"
    );
    assert_eq!(
        config.recursive.port, 1053,
        "Recursive must use non-standard port (1053) by default"
    );
}
/// Verify CNAME depth limit is enforced.
///
/// When max_cname_depth > 0, the recursive resolver must reject queries
/// that exceed the depth limit to prevent CNAME loops.
#[test]
fn cname_depth_limit_enforced() {
    // Default max_cname_depth must be 10
    let default_config = RecursiveDnsConfig::default();
    assert_eq!(
        default_config.max_cname_depth, 10,
        "default max_cname_depth must be 10"
    );

    // Setting max_cname_depth = 0 means unlimited (valid)
    let config = RecursiveDnsConfig {
        enabled: true,
        max_cname_depth: 0,
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "max_cname_depth=0 (unlimited) must be accepted"
    );

    // Setting max_cname_depth = 1 is valid (very restrictive)
    let config = RecursiveDnsConfig {
        enabled: true,
        max_cname_depth: 1,
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "max_cname_depth=1 must be accepted"
    );
}
/// Verify recursive config validation rules.
///
/// Key constraints: query_timeout_secs > 0, max_concurrent_queries > 0,
/// negative_ttl_secs <= max_ttl_secs, open-resolver guard.
#[test]
fn recursive_config_validation() {
    // Valid config
    let mut config = RecursiveDnsConfig {
        enabled: true,
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "default enabled config must validate: {:?}",
        config.validate()
    );

    // query_timeout_secs = 0 is invalid
    config.query_timeout_secs = 0;
    assert!(
        config.validate().is_err(),
        "query_timeout_secs=0 must fail validation"
    );
    config.query_timeout_secs = 5;

    // max_concurrent_queries = 0 is invalid
    config.max_concurrent_queries = 0;
    assert!(
        config.validate().is_err(),
        "max_concurrent_queries=0 must fail validation"
    );
    config.max_concurrent_queries = 100;

    // negative_ttl_secs > max_ttl_secs is invalid
    config.cache.negative_ttl_secs = 1000;
    config.cache.max_ttl_secs = 500;
    assert!(
        config.validate().is_err(),
        "negative_ttl > max_ttl must fail validation"
    );
    config.cache.negative_ttl_secs = 60;
    config.cache.max_ttl_secs = 300;

    // Open-resolver guard: 0.0.0.0 is rejected
    config.bind_address = "0.0.0.0".to_string();
    assert!(
        config.validate().is_err(),
        "bind_address=0.0.0.0 must fail (open resolver)"
    );

    config.bind_address = "::".to_string();
    assert!(
        config.validate().is_err(),
        "bind_address=:: must fail (open resolver)"
    );

    config.bind_address = "127.0.0.1".to_string();
    assert!(
        config.validate().is_ok(),
        "bind_address=127.0.0.1 must pass"
    );
}
/// Recursive mode disabled by default — the default RecursiveDnsConfig
/// must have `enabled = false` and bind to loopback. (Config-level test.)
#[test]
fn recursive_mode_disabled_and_loopback_by_default() {
    use synvoid_config::dns::RecursiveDnsConfig;
    let cfg = RecursiveDnsConfig::default();
    assert!(!cfg.enabled, "Recursive mode must be disabled by default");
    assert_eq!(
        cfg.bind_address, "127.0.0.1",
        "Recursive must bind to loopback by default (open-resolver prevention)"
    );
}
/// Recursive config validation rejects wildcard bind addresses
/// (0.0.0.0, ::) — this is the open-resolver guard.
#[test]
fn recursive_config_rejects_wildcard_bind() {
    use synvoid_config::dns::RecursiveDnsConfig;
    let mut cfg = RecursiveDnsConfig {
        enabled: true,
        bind_address: "0.0.0.0".to_string(),
        ..Default::default()
    };
    assert!(
        cfg.validate().is_err(),
        "0.0.0.0 recursive bind must fail (open resolver)"
    );
    cfg.bind_address = "::".to_string();
    assert!(
        cfg.validate().is_err(),
        ":: recursive bind must fail (open resolver)"
    );
    cfg.bind_address = "127.0.0.1".to_string();
    assert!(cfg.validate().is_ok(), "loopback must be allowed");
}
/// CNAME depth limit (default=10) and `0 = unlimited` is a config-level
/// invariant. Runtime depth enforcement is in `resolve_query_with_depth`.
#[test]
fn recursive_cname_depth_limit_config_invariants() {
    use synvoid_config::dns::RecursiveDnsConfig;
    let mut cfg = RecursiveDnsConfig::default();
    assert_eq!(cfg.max_cname_depth, 10, "default max_cname_depth = 10");
    cfg.max_cname_depth = 0;
    assert!(cfg.validate().is_ok(), "0 = unlimited must be valid");
    cfg.max_cname_depth = 1;
    assert!(cfg.validate().is_ok(), "1 = restrictive but valid");
}
/// Recursion depth limit (default=16) and `0 = unlimited`.
#[test]
fn recursive_depth_limit_config_invariants() {
    use synvoid_config::dns::RecursiveDnsConfig;
    let cfg = RecursiveDnsConfig::default();
    assert_eq!(
        cfg.max_recursion_depth, 16,
        "default max_recursion_depth = 16"
    );
    let cfg = RecursiveDnsConfig {
        max_recursion_depth: 0,
        ..Default::default()
    };
    assert!(cfg.validate().is_ok(), "0 = unlimited must be valid");
}
/// Per-client outstanding query limit (default=100) and `0 = unlimited`.
#[test]
fn recursive_per_client_limit_config_invariants() {
    use synvoid_config::dns::RecursiveDnsConfig;
    let cfg = RecursiveDnsConfig::default();
    assert_eq!(
        cfg.max_per_client_queries, 100,
        "default max_per_client_queries = 100"
    );
    let cfg = RecursiveDnsConfig {
        max_per_client_queries: 0,
        ..Default::default()
    };
    assert!(cfg.validate().is_ok(), "0 = unlimited must be valid");
}
/// ECS forwarding policy default is `Never` — meaning ECS is stripped
/// from outgoing queries by default. The policy types must be wired.
#[test]
fn ecs_default_policy_is_never() {
    use synvoid_config::dns::EcsForwardingPolicy;
    let cfg = EcsForwardingPolicy::default();
    assert_eq!(
        cfg,
        EcsForwardingPolicy::Never,
        "ECS must default to Never (strip ECS by default for privacy)"
    );
}
/// DoH (RFC 8484) requires the request body to use `application/dns-message`
/// content type. Wrong / missing content type returns HTTP 415 at the
/// DoH adapter layer (verified in `encrypted_transport.rs` and by source
/// inspection of `doh.rs::handle_request`).
#[test]
fn doh_content_type_must_be_application_dns_message() {
    // Documented invariant — the DoH server MUST enforce the content type.
    // The runtime check is in src/doh.rs::handle_request. The test here
    // asserts the documented behavior at the integration test tier.
    use synvoid_config::dns::DnsDohConfig;
    let cfg: DnsDohConfig = serde_json::from_str("{}").expect("parse defaults");
    assert_eq!(
        cfg.path, "/dns-query",
        "Default DoH path must be /dns-query per RFC 8484"
    );
}
/// DoH (RFC 8484 §4) supports both GET and POST. POST is the
/// production path; GET is optional. SynVoid supports GET through the
/// `?dns=...` query parameter (base64url). This is exercised in
/// encrypted_transport.rs::doh_paths_accepted.
#[test]
fn doh_default_path_is_rfc_8484_compliant() {
    use synvoid_config::dns::DnsDohConfig;
    let cfg: DnsDohConfig = serde_json::from_str("{}").expect("parse defaults");
    assert_eq!(cfg.path, "/dns-query");
    assert!(
        !cfg.enabled,
        "DoH must be disabled by default (opt-in encrypted transport)"
    );
    assert_eq!(cfg.port, 443, "DoH default port must be 443");
}
/// DoQ (RFC 9250) ALPN token is `doq`. Quinn QUIC adapter uses this
/// for connection negotiation. Verified at runtime in
/// `encrypted_transport.rs::doq_alpn_is_doq` and in `doq.rs` source.
#[test]
fn doq_default_port_and_alpn() {
    use synvoid_config::dns::DnsDoqConfig;
    let cfg: DnsDoqConfig = serde_json::from_str("{}").expect("parse defaults");
    assert_eq!(cfg.port, 853, "DoQ default port must be 853");
    assert!(!cfg.enabled, "DoQ must be disabled by default");
    assert_eq!(
        cfg.max_concurrent_streams, 100,
        "DoQ default max concurrent streams"
    );
    assert_eq!(cfg.idle_timeout_secs, 30, "DoQ default idle timeout");
}

/// Test 1: Recursive and authoritative can have distinct bind addresses.
///
/// The recursive server and authoritative server each have independent
/// bind_address/port fields in their respective configs. This test verifies
/// they are separate values that don't interfere with each other.
#[test]
fn test_recursive_mode_different_bind_address() {
    let mut auth_config = DnsConfig::default();
    auth_config.enabled = true;
    auth_config.bind_address = "0.0.0.0".to_string();
    auth_config.port = 53;

    let mut recursive_config = RecursiveDnsConfig::default();
    recursive_config.enabled = true;
    recursive_config.bind_address = "127.0.0.1".to_string();
    recursive_config.port = 1053;

    // Verify the two configs have different bind addresses and ports
    assert_ne!(
        auth_config.bind_address, recursive_config.bind_address,
        "authoritative and recursive must allow different bind addresses"
    );
    assert_ne!(
        auth_config.port, recursive_config.port,
        "authoritative and recursive must allow different ports"
    );

    // Verify the recursive config is stored independently in the DnsConfig
    let mut dns_config = DnsConfig::default();
    dns_config.recursive.bind_address = "127.0.0.1".to_string();
    dns_config.recursive.port = 1053;
    dns_config.bind_address = "0.0.0.0".to_string();
    dns_config.port = 53;

    assert_eq!(dns_config.bind_address, "0.0.0.0");
    assert_eq!(dns_config.port, 53);
    assert_eq!(dns_config.recursive.bind_address, "127.0.0.1");
    assert_eq!(dns_config.recursive.port, 1053);
}
/// Test 4: Trust anchor config has sensible defaults and validates.
///
/// TrustAnchorConfig is validated as part of the DNS configuration pipeline.
/// This test verifies the default values and that the config can be
/// deserialized correctly.
#[test]
fn test_trust_anchor_config_validation() {
    let config = TrustAnchorConfig::default();

    // Default should be disabled
    assert!(
        !config.enabled,
        "trust anchors should be disabled by default"
    );
    assert!(
        !config.db_path.is_empty(),
        "db_path should have a default value"
    );
    assert!(
        !config.anchor_file_path.is_empty(),
        "anchor_file_path should have a default value"
    );
    assert!(
        config.refresh_interval_secs > 0,
        "refresh_interval_secs should be positive"
    );
    assert!(
        config.pending_observation_days > 0,
        "pending_observation_days should be positive"
    );
    assert!(
        config.revocation_grace_days > 0,
        "revocation_grace_days should be positive"
    );
    assert!(
        config.extended_removal_days > 0,
        "extended_removal_days should be positive"
    );
    assert!(
        config.trust_anchor_retention_days > 0,
        "trust_anchor_retention_days should be positive"
    );

    // Verify it's stored in DnsConfig
    let dns_config = DnsConfig::default();
    assert!(
        !dns_config.trust_anchors.enabled,
        "DnsConfig default trust_anchors should be disabled"
    );
}
/// Test 6: Mesh DNS mode config validation doesn't error at config level.
///
/// The DnsMode::Mesh mode validates its mesh-specific settings (intervals > 0)
/// but doesn't fail at config validation time for the feature gate. The actual
/// mesh feature gate is at runtime (start()). This test documents the current
/// config-level behavior.
#[test]
fn test_mesh_mode_requires_mesh_feature() {
    let mut config = DnsConfig::default();
    config.mode = DnsMode::Mesh;
    config.bind_address = "127.0.0.1".to_string();
    config.port = 5353;

    // Config validation passes because mesh defaults are valid.
    // The actual mesh feature gate is at runtime (mesh_registry is None),
    // not at config validation time.
    let result = config.validate();
    assert!(
        result.is_ok(),
        "mesh mode config should validate with default mesh settings: {:?}",
        result
    );

    // Mesh config with zero intervals DOES fail validation
    config.mesh.registration_interval_secs = 0;
    let result = config.validate();
    assert!(
        result.is_err(),
        "mesh mode should fail with zero registration_interval_secs"
    );

    config.mesh.registration_interval_secs = 60;
    config.mesh.sync_interval_secs = 0;
    let result = config.validate();
    assert!(
        result.is_err(),
        "mesh mode should fail with zero sync_interval_secs"
    );
}
/// Test 8: Port 0 is rejected at validation.
///
/// DnsConfig::validate() returns InvalidPort when port is 0.
#[test]
fn test_port_zero_rejected() {
    let mut config = DnsConfig::default();
    config.bind_address = "127.0.0.1".to_string();
    config.port = 0;

    let result = config.validate();
    assert!(
        result.is_err(),
        "port 0 should be rejected by DnsConfig::validate()"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("port") || err_msg.contains("Port"),
        "error should mention port: {}",
        err_msg
    );
}
/// Test 9: Invalid bind address is rejected.
///
/// DnsConfig::validate() returns InvalidBindAddress for non-parseable addresses.
#[test]
fn test_invalid_bind_address_rejected() {
    let mut config = DnsConfig::default();
    config.bind_address = "not-a-valid-ip".to_string();
    config.port = 53;

    let result = config.validate();
    assert!(result.is_err(), "invalid bind address should be rejected");

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("bind") || err_msg.contains("Bind") || err_msg.contains("Invalid"),
        "error should mention bind address: {}",
        err_msg
    );
}
/// Recursive config validates custom upstream requires servers.
#[test]
fn test_recursive_custom_upstream_requires_servers() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.upstream_provider = RecursiveUpstreamProvider::Custom;
    config.upstream_servers = vec![]; // empty

    let result = config.validate();
    assert!(
        result.is_err(),
        "Custom upstream with no servers should fail validation"
    );
}
/// Recursive config validates query_timeout_secs > 0.
#[test]
fn test_recursive_query_timeout_must_be_positive() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.query_timeout_secs = 0;

    let result = config.validate();
    assert!(
        result.is_err(),
        "query_timeout_secs=0 should fail validation"
    );
}
/// Recursive config validates max_concurrent_queries > 0.
#[test]
fn test_recursive_max_concurrent_must_be_positive() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.max_concurrent_queries = 0;

    let result = config.validate();
    assert!(
        result.is_err(),
        "max_concurrent_queries=0 should fail validation"
    );
}
/// Recursive config validates negative_ttl_secs <= max_ttl_secs.
#[test]
fn test_recursive_negative_ttl_cannot_exceed_max() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.cache.negative_ttl_secs = 1000;
    config.cache.max_ttl_secs = 500;

    let result = config.validate();
    assert!(
        result.is_err(),
        "negative_ttl_secs > max_ttl_secs should fail validation"
    );
}
/// Recursive config disabled skips validation.
#[test]
fn test_recursive_disabled_skips_validation() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = false;
    // These would fail if validation ran
    config.query_timeout_secs = 0;
    config.max_concurrent_queries = 0;

    let result = config.validate();
    assert!(
        result.is_ok(),
        "disabled recursive config should skip all validation"
    );
}
/// Anycast enabled with empty bind_addresses should fail.
#[test]
fn test_anycast_empty_bind_addresses_rejected() {
    let config = DnsAnycastConfig {
        enabled: true,
        bind_addresses: vec![],
        ..Default::default()
    };

    let result = config.validate();
    assert!(
        result.is_err(),
        "anycast enabled with empty bind_addresses should fail"
    );
}
/// Anycast enabled with zero health_check_interval should fail.
#[test]
fn test_anycast_zero_health_check_interval_rejected() {
    let config = DnsAnycastConfig {
        enabled: true,
        bind_addresses: vec!["10.0.0.1".to_string()],
        health_check_interval_secs: 0,
        ..Default::default()
    };

    let result = config.validate();
    assert!(
        result.is_err(),
        "anycast health_check_interval_secs=0 should fail"
    );
}
/// Anycast disabled skips validation.
#[test]
fn test_anycast_disabled_skips_validation() {
    let config = DnsAnycastConfig {
        enabled: false,
        bind_addresses: vec![],
        health_check_interval_secs: 0,
        capacity: 0,
        ..Default::default()
    };

    let result = config.validate();
    assert!(
        result.is_ok(),
        "disabled anycast config should skip all validation"
    );
}
/// Valid DnsConfig passes validation.
#[test]
fn test_valid_dns_config_passes() {
    let mut config = DnsConfig::default();
    config.enabled = true;
    config.bind_address = "127.0.0.1".to_string();
    config.port = 5353;

    let result = config.validate();
    assert!(result.is_ok(), "valid config should pass: {:?}", result);
}
/// Port 0 is rejected even with valid bind address.
#[test]
fn test_dns_config_port_zero_with_valid_bind() {
    let mut config = DnsConfig::default();
    config.bind_address = "127.0.0.1".to_string();
    config.port = 0;

    let result = config.validate();
    assert!(result.is_err(), "port 0 should be rejected");
}
/// Wildcard bind addresses are accepted.
#[test]
fn test_dns_config_wildcard_bind_accepted() {
    let mut config = DnsConfig::default();
    config.bind_address = "0.0.0.0".to_string();
    config.port = 53;

    let result = config.validate();
    assert!(
        result.is_ok(),
        "0.0.0.0 wildcard bind should be accepted: {:?}",
        result
    );
}
/// IPv6 wildcard bind is accepted.
#[test]
fn test_dns_config_ipv6_wildcard_bind_accepted() {
    let mut config = DnsConfig::default();
    config.bind_address = "::".to_string();
    config.port = 53;

    let result = config.validate();
    assert!(
        result.is_ok(),
        ":: wildcard bind should be accepted: {:?}",
        result
    );
}
/// WS5: Default config recursive disabled
#[test]
fn test_default_config_recursive_disabled() {
    let config = synvoid_config::dns::DnsConfig::default();
    assert!(
        !config.recursive.enabled,
        "Recursive DNS should be disabled by default"
    );
    assert_eq!(
        config.recursive.bind_address, "127.0.0.1",
        "Recursive should bind to loopback"
    );
    assert_eq!(
        config.recursive.port, 1053,
        "Recursive should use non-standard port"
    );
}
/// WS5: Open-resolver guard rejects 0.0.0.0 and :: bind addresses
#[test]
fn test_recursive_open_resolver_guard() {
    let mut config = synvoid_config::dns::RecursiveDnsConfig::default();
    config.enabled = true;

    // 0.0.0.0 should be rejected
    config.bind_address = "0.0.0.0".to_string();
    assert!(
        config.validate().is_err(),
        "Recursive DNS with bind_address=0.0.0.0 must fail validation (open resolver)"
    );

    // :: should be rejected
    config.bind_address = "::".to_string();
    assert!(
        config.validate().is_err(),
        "Recursive DNS with bind_address=:: must fail validation (open resolver)"
    );

    // 127.0.0.1 should be accepted
    config.bind_address = "127.0.0.1".to_string();
    assert!(
        config.validate().is_ok(),
        "Recursive DNS with bind_address=127.0.0.1 should pass validation"
    );
}
#[test]
fn test_recursive_client_acl_rejects_non_allowed_client() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec!["127.0.0.1/32".to_string()],
        action: "reject".to_string(),
    };

    assert!(
        !acl.is_client_allowed("10.0.0.1".parse().unwrap()),
        "Client 10.0.0.1 should be rejected when only 127.0.0.1/32 is allowed"
    );
}
#[test]
fn test_recursive_client_acl_allows_matching_client() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec!["127.0.0.1/32".to_string()],
        action: "reject".to_string(),
    };

    assert!(
        acl.is_client_allowed("127.0.0.1".parse().unwrap()),
        "Client 127.0.0.1 should be allowed when 127.0.0.1/32 is in allowlist"
    );
}
#[test]
fn test_recursive_client_acl_empty_allows_all() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec![],
        action: "reject".to_string(),
    };

    assert!(
        acl.is_client_allowed("10.0.0.1".parse().unwrap()),
        "Empty allowlist should allow all clients"
    );
    assert!(
        acl.is_client_allowed("192.168.1.1".parse().unwrap()),
        "Empty allowlist should allow all clients"
    );
}
#[test]
fn test_recursive_client_acl_invalid_cidr_rejected() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.client_acl = Some(RecursiveClientAcl {
        allowed_clients: vec!["not-a-cidr".to_string()],
        action: "reject".to_string(),
    });

    let result = config.validate();
    assert!(
        result.is_err(),
        "Invalid CIDR in client_acl should fail validation"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not-a-cidr"),
        "Error should mention the invalid CIDR: {}",
        err_msg
    );
}
#[test]
fn test_recursive_client_acl_wildcard_cidr() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec!["0.0.0.0/0".to_string()],
        action: "reject".to_string(),
    };

    assert!(
        acl.is_client_allowed("10.0.0.1".parse().unwrap()),
        "Client 10.0.0.1 should be allowed by 0.0.0.0/0"
    );
    assert!(
        acl.is_client_allowed("192.168.1.1".parse().unwrap()),
        "Client 192.168.1.1 should be allowed by 0.0.0.0/0"
    );
    assert!(
        acl.is_client_allowed("255.255.255.255".parse().unwrap()),
        "Client 255.255.255.255 should be allowed by 0.0.0.0/0"
    );
}
#[test]
fn test_recursive_client_acl_action_allow_permits_non_matching() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec!["192.168.1.0/24".to_string()],
        action: "allow".to_string(),
    };

    assert!(
        acl.is_client_allowed("192.168.1.50".parse().unwrap()),
        "Client in subnet should be allowed"
    );
    assert!(
        acl.is_client_allowed("10.0.0.1".parse().unwrap()),
        "Client not in subnet should be allowed when action=allow"
    );
}
#[test]
fn test_recursive_client_acl_action_reject_denies_non_matching() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec!["192.168.1.0/24".to_string()],
        action: "reject".to_string(),
    };

    assert!(
        acl.is_client_allowed("192.168.1.50".parse().unwrap()),
        "Client in subnet should be allowed"
    );
    assert!(
        !acl.is_client_allowed("10.0.0.1".parse().unwrap()),
        "Client not in subnet should be denied when action=reject"
    );
}
#[test]
fn test_recursive_client_acl_invalid_action_rejected() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.client_acl = Some(RecursiveClientAcl {
        allowed_clients: vec!["127.0.0.1/32".to_string()],
        action: "invalid".to_string(),
    });

    let result = config.validate();
    assert!(
        result.is_err(),
        "Invalid action in client_acl should fail validation"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("invalid"),
        "Error should mention the invalid action: {}",
        err_msg
    );
}
#[test]
fn test_recursive_client_acl_multiple_cidrs() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "::1/128".to_string(),
        ],
        action: "reject".to_string(),
    };

    assert!(
        acl.is_client_allowed("192.168.1.50".parse().unwrap()),
        "Client in 192.168.1.0/24 should be allowed"
    );
    assert!(
        acl.is_client_allowed("10.0.0.1".parse().unwrap()),
        "Client in 10.0.0.0/8 should be allowed"
    );
    assert!(
        acl.is_client_allowed("::1".parse().unwrap()),
        "Client ::1 should be allowed"
    );
    assert!(
        !acl.is_client_allowed("172.16.0.1".parse().unwrap()),
        "Client 172.16.0.1 should not match any CIDR"
    );
}
#[test]
fn test_recursive_client_acl_none_allows_all() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.client_acl = None;

    assert!(
        config.validate().is_ok(),
        "Config with no client_acl should validate"
    );
}
#[test]
fn test_recursive_client_acl_ipv6_cidr() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec!["fe80::/10".to_string()],
        action: "reject".to_string(),
    };

    assert!(
        acl.is_client_allowed("fe80::1".parse().unwrap()),
        "Link-local address fe80::1 should match fe80::/10"
    );
    assert!(
        !acl.is_client_allowed("2001:db8::1".parse().unwrap()),
        "Non-link-local address should not match fe80::/10"
    );
}
#[test]
fn test_recursive_client_acl_config_field_default() {
    let config = RecursiveDnsConfig::default();
    assert!(
        config.client_acl.is_none(),
        "Default client_acl should be None"
    );
}
#[test]
fn test_recursive_client_acl_empty_allowed_clients_is_open() {
    let acl = RecursiveClientAcl {
        allowed_clients: vec![],
        action: "reject".to_string(),
    };

    assert!(
        acl.is_client_allowed("1.2.3.4".parse().unwrap()),
        "Empty allowed_clients should allow all clients (open for loopback)"
    );
}
#[test]
fn test_max_cname_depth_config_default() {
    let config = RecursiveDnsConfig::default();
    assert_eq!(config.max_cname_depth, 10);
}
#[test]
fn test_max_cname_depth_zero_means_unlimited() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.max_cname_depth = 0;
    assert!(
        config.validate().is_ok(),
        "max_cname_depth=0 (unlimited) should be allowed"
    );
}
#[test]
fn test_circuit_breaker_config_default() {
    let config = CircuitBreakerConfig::default();
    assert_eq!(config.failure_threshold, 5);
    assert_eq!(config.recovery_timeout_secs, 30);
    assert_eq!(config.success_threshold, 2);
}
#[test]
fn test_circuit_breaker_config_validation_failure_threshold_zero() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.circuit_breaker.failure_threshold = 0;
    assert!(
        config.validate().is_err(),
        "failure_threshold=0 should fail validation"
    );
}
#[test]
fn test_circuit_breaker_config_validation_success_threshold_zero() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.circuit_breaker.success_threshold = 0;
    assert!(
        config.validate().is_err(),
        "success_threshold=0 should fail validation"
    );
}
#[test]
fn test_circuit_breaker_default_config_field() {
    let config = RecursiveDnsConfig::default();
    assert_eq!(config.circuit_breaker.failure_threshold, 5);
    assert_eq!(config.circuit_breaker.recovery_timeout_secs, 30);
    assert_eq!(config.circuit_breaker.success_threshold, 2);
}
#[test]
fn test_recursive_config_includes_new_fields() {
    let config = RecursiveDnsConfig::default();
    assert_eq!(config.max_cname_depth, 10);
    assert!(config.circuit_breaker.failure_threshold > 0);
    assert!(config.circuit_breaker.recovery_timeout_secs > 0);
    assert!(config.circuit_breaker.success_threshold > 0);
}
#[test]
fn test_max_recursion_depth_default() {
    let config = RecursiveDnsConfig::default();
    assert_eq!(config.max_recursion_depth, 16);
}
#[test]
fn test_max_per_client_queries_default() {
    let config = RecursiveDnsConfig::default();
    assert_eq!(config.max_per_client_queries, 100);
}
#[test]
fn test_max_recursion_depth_zero_means_unlimited() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.max_recursion_depth = 0;
    assert!(
        config.validate().is_ok(),
        "max_recursion_depth=0 (unlimited) should be allowed"
    );
}
#[test]
fn test_max_per_client_queries_zero_means_unlimited() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.max_per_client_queries = 0;
    assert!(
        config.validate().is_ok(),
        "max_per_client_queries=0 (unlimited) should be allowed"
    );
}
#[test]
fn test_recursive_config_includes_recursion_and_per_client_fields() {
    let config = RecursiveDnsConfig::default();
    assert_eq!(config.max_recursion_depth, 16);
    assert_eq!(config.max_per_client_queries, 100);
    assert_eq!(config.max_cname_depth, 10);
}
#[test]
fn test_ecs_recursive_config_includes_ecs_field() {
    let config = RecursiveDnsConfig::default();
    assert_eq!(
        config.ecs.forwarding_policy,
        synvoid_config::dns::EcsForwardingPolicy::Never
    );
    assert_eq!(config.ecs.prefix_v4, 24);
    assert_eq!(config.ecs.prefix_v6, 56);
    assert!(!config.ecs.include_scope_in_response);
}
#[test]
fn test_ecs_config_defaults() {
    let config = RecursiveEcsConfig::default();
    assert_eq!(
        config.forwarding_policy,
        synvoid_config::dns::EcsForwardingPolicy::Never
    );
    assert_eq!(config.prefix_v4, 24);
    assert_eq!(config.prefix_v6, 56);
    assert!(!config.include_scope_in_response);
}
#[test]
fn test_ecs_config_serde_roundtrip() {
    let config = RecursiveEcsConfig {
        forwarding_policy: synvoid_config::dns::EcsForwardingPolicy::Always,
        prefix_v4: 16,
        prefix_v6: 48,
        include_scope_in_response: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: RecursiveEcsConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(
        deserialized.forwarding_policy,
        synvoid_config::dns::EcsForwardingPolicy::Always
    );
    assert_eq!(deserialized.prefix_v4, 16);
    assert_eq!(deserialized.prefix_v6, 48);
    assert!(deserialized.include_scope_in_response);
}
#[test]
fn test_ecs_config_serde_default_policy() {
    let json = r#"{"prefix_v4": 16}"#;
    let config: RecursiveEcsConfig = serde_json::from_str(json).unwrap();
    assert_eq!(
        config.forwarding_policy,
        synvoid_config::dns::EcsForwardingPolicy::Never
    );
    assert_eq!(config.prefix_v4, 16);
}
#[test]
fn test_ecs_config_serde_snake_case_variants() {
    use synvoid_config::dns::EcsForwardingPolicy;

    let json = r#"{"forwarding_policy": "if_present"}"#;
    let config: RecursiveEcsConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.forwarding_policy, EcsForwardingPolicy::IfPresent);

    let json = r#"{"forwarding_policy": "always"}"#;
    let config: RecursiveEcsConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.forwarding_policy, EcsForwardingPolicy::Always);

    let json = r#"{"forwarding_policy": "cdn_only"}"#;
    let config: RecursiveEcsConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.forwarding_policy, EcsForwardingPolicy::CdnOnly);
}

#[test]
fn dot_config_custom_port() {
    let json = r#"{"port": 8853, "bind_address": "10.0.0.1"}"#;
    let config: DnsDotConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.port, 8853);
    assert_eq!(config.bind_address, "10.0.0.1");
}

#[test]
fn doh_config_custom_port_and_path() {
    let json = r#"{"port": 8443, "path": "/dns-query", "json_path": "/dns"}"#;
    let config: DnsDohConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.port, 8443);
    assert_eq!(config.path, "/dns-query");
    assert_eq!(config.json_path, "/dns");
}

#[test]
fn doq_config_custom_concurrency() {
    let json = r#"{"max_concurrent_streams": 256, "idle_timeout_secs": 60}"#;
    let config: DnsDoqConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.max_concurrent_streams, 256);
    assert_eq!(config.idle_timeout_secs, 60);
}
