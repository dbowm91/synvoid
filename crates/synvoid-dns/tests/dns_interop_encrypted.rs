use synvoid_config::dns::{DnsDohConfig, DnsDoqConfig, DnsDotConfig};

fn default_dot_config() -> DnsDotConfig {
    DnsDotConfig {
        enabled: true,
        port: 853,
        bind_address: "127.0.0.1".to_string(),
        tls_cert_path: Some("/tmp/cert.pem".to_string()),
        tls_key_path: Some("/tmp/key.pem".to_string()),
        use_system_cert_store: true,
    }
}

fn default_doh_config() -> DnsDohConfig {
    DnsDohConfig {
        enabled: true,
        port: 443,
        bind_address: "127.0.0.1".to_string(),
        path: "/dns-query".to_string(),
        json_path: String::new(),
        tls_cert_path: Some("/tmp/cert.pem".to_string()),
        tls_key_path: Some("/tmp/key.pem".to_string()),
        use_system_cert_store: true,
    }
}

fn default_doq_config() -> DnsDoqConfig {
    DnsDoqConfig {
        enabled: true,
        port: 853,
        bind_address: "127.0.0.1".to_string(),
        tls_cert_path: Some("/tmp/cert.pem".to_string()),
        tls_key_path: Some("/tmp/key.pem".to_string()),
        use_system_cert_store: true,
        max_concurrent_streams: 100,
        idle_timeout_secs: 30,
    }
}

#[test]
fn test_dot_config_roundtrip() {
    let config = default_dot_config();
    let json = serde_json::to_string(&config).expect("DoT config must serialize");
    let restored: DnsDotConfig =
        serde_json::from_str(&json).expect("DoT config must deserialize from JSON");

    assert!(restored.enabled);
    assert_eq!(restored.port, 853);
    assert_eq!(restored.bind_address, "127.0.0.1");
    assert_eq!(restored.tls_cert_path, Some("/tmp/cert.pem".to_string()));
    assert_eq!(restored.tls_key_path, Some("/tmp/key.pem".to_string()));
    assert!(restored.use_system_cert_store);
}

#[test]
fn test_doh_config_roundtrip() {
    let config = default_doh_config();
    let json = serde_json::to_string(&config).expect("DoH config must serialize");
    let restored: DnsDohConfig =
        serde_json::from_str(&json).expect("DoH config must deserialize from JSON");

    assert!(restored.enabled);
    assert_eq!(restored.port, 443);
    assert_eq!(restored.bind_address, "127.0.0.1");
    assert_eq!(restored.path, "/dns-query");
    assert!(restored.json_path.is_empty());
    assert_eq!(restored.tls_cert_path, Some("/tmp/cert.pem".to_string()));
    assert_eq!(restored.tls_key_path, Some("/tmp/key.pem".to_string()));
    assert!(restored.use_system_cert_store);
}

#[test]
fn test_doq_config_roundtrip() {
    let config = default_doq_config();
    let json = serde_json::to_string(&config).expect("DoQ config must serialize");
    let restored: DnsDoqConfig =
        serde_json::from_str(&json).expect("DoQ config must deserialize from JSON");

    assert!(restored.enabled);
    assert_eq!(restored.port, 853);
    assert_eq!(restored.bind_address, "127.0.0.1");
    assert_eq!(restored.tls_cert_path, Some("/tmp/cert.pem".to_string()));
    assert_eq!(restored.tls_key_path, Some("/tmp/key.pem".to_string()));
    assert!(restored.use_system_cert_store);
    assert_eq!(restored.max_concurrent_streams, 100);
    assert_eq!(restored.idle_timeout_secs, 30);
}

#[test]
fn test_encrypted_transport_disabled_by_default() {
    let dot: DnsDotConfig = serde_json::from_str("{}").unwrap();
    let doh: DnsDohConfig = serde_json::from_str("{}").unwrap();
    let doq: DnsDoqConfig = serde_json::from_str("{}").unwrap();

    assert!(!dot.enabled, "DoT must be disabled by default");
    assert!(!doh.enabled, "DoH must be disabled by default");
    assert!(!doq.enabled, "DoQ must be disabled by default");
}

#[test]
fn test_tls_cert_config_validation() {
    // Valid config with cert paths
    let config = DnsDotConfig {
        enabled: true,
        port: 853,
        bind_address: "0.0.0.0".to_string(),
        tls_cert_path: Some("/etc/ssl/certs/dns.pem".to_string()),
        tls_key_path: Some("/etc/ssl/private/dns.key".to_string()),
        use_system_cert_store: false,
    };
    assert!(config.tls_cert_path.is_some());
    assert!(config.tls_key_path.is_some());

    // Config without cert paths (should still be valid struct, but won't work at runtime)
    let config_no_cert = DnsDotConfig {
        enabled: true,
        port: 853,
        bind_address: "0.0.0.0".to_string(),
        tls_cert_path: None,
        tls_key_path: None,
        use_system_cert_store: true,
    };
    assert!(config_no_cert.tls_cert_path.is_none());
    assert!(config_no_cert.tls_key_path.is_none());
    assert!(config_no_cert.use_system_cert_store);

    // Verify JSON roundtrip preserves None cert paths
    let json = serde_json::to_string(&config_no_cert).unwrap();
    let restored: DnsDotConfig = serde_json::from_str(&json).unwrap();
    assert!(restored.tls_cert_path.is_none());
    assert!(restored.tls_key_path.is_none());
    assert!(restored.use_system_cert_store);
}
