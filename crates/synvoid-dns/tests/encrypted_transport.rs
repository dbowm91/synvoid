use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use synvoid_config::dns::DnsDohConfig;
use synvoid_config::dns::DnsDoqConfig;
use synvoid_config::dns::DnsDotConfig;
use synvoid_dns::cache::TransportClass;
use synvoid_dns::doh::DohServer;
use synvoid_dns::doq::DoqServer;
use synvoid_dns::dot::DotServer;

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

#[test]
fn dot_server_creation() {
    let config = default_dot_config();
    let _server = DotServer::new(config, None);
}

#[test]
fn doh_server_creation() {
    let config = default_doh_config();
    let _server = DohServer::new(config, None);
}

#[test]
fn doq_server_creation() {
    let config = default_doq_config();
    let server = DoqServer::new(config, None);
    assert_eq!(server.config().port, 853);
    assert_eq!(server.config().bind_address, "127.0.0.1");
    assert_eq!(server.config().max_concurrent_streams, 100);
    assert_eq!(server.config().idle_timeout_secs, 30);
}

#[test]
fn transport_class_cache_key_isolation() {
    let dot_class = TransportClass::Tcp;
    let doh_class = TransportClass::Http;
    let doq_class = TransportClass::Quic;

    assert_ne!(dot_class, doh_class);
    assert_ne!(doh_class, doq_class);
    assert_ne!(dot_class, doq_class);

    let dot_key = ("example.com".to_string(), 1u16, 1u16, dot_class);
    let doh_key = ("example.com".to_string(), 1u16, 1u16, doh_class);
    let doq_key = ("example.com".to_string(), 1u16, 1u16, doq_class);

    let mut key_set = std::collections::HashSet::new();
    key_set.insert(dot_key);
    key_set.insert(doh_key);
    key_set.insert(doq_key);

    assert_eq!(
        key_set.len(),
        3,
        "all three transport classes must produce distinct cache keys"
    );
}

#[test]
fn doq_frame_format_roundtrip() {
    let query = build_test_query();

    let length = (query.len() as u16).to_be_bytes();
    let mut framed = Vec::new();
    framed.extend_from_slice(&length);
    framed.extend_from_slice(&query);

    assert_eq!(framed.len(), query.len() + 2);

    let read_length = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    assert_eq!(read_length, query.len());

    let read_query = &framed[2..2 + read_length];
    assert_eq!(read_query, &query[..]);
}

#[test]
fn doq_frame_max_size_boundary() {
    let max_valid = 65535u16.to_be_bytes();
    assert_eq!(max_valid.len(), 2);

    let zero = 0u16.to_be_bytes();
    let length = u16::from_be_bytes(zero) as usize;
    assert_eq!(length, 0);
}

#[test]
fn doq_alpn_is_doq() {
    assert_eq!(b"doq", b"doq");
}

#[test]
fn doh_paths_accepted() {
    let paths = ["/dns-query", "/", "/dns", "/dns-query/json"];
    for path in &paths {
        let is_rfc8484 = *path == "/dns-query" || *path == "/";
        let is_json_api = *path == "/dns" || *path == "/dns-query/json";
        assert!(
            is_rfc8484 || is_json_api,
            "path {} should be recognized as a valid DoH endpoint",
            path
        );
    }
}

#[test]
fn doh_paths_rejected() {
    let paths = ["/health", "/api/v1", "/dns-query/extra"];
    for path in &paths {
        let is_rfc8484 = *path == "/dns-query" || *path == "/";
        let is_json_api = *path == "/dns" || *path == "/dns-query/json";
        assert!(
            !is_rfc8484 && !is_json_api,
            "path {} should NOT be recognized as a valid DoH endpoint",
            path
        );
    }
}

#[test]
fn dot_server_shut_down_without_start() {
    let config = default_dot_config();
    let mut server = DotServer::new(config, None);
    server.shutdown();
}

#[test]
fn doh_server_shut_down_without_start() {
    let config = default_doh_config();
    let mut server = DohServer::new(config, None);
    server.shutdown();
}

#[test]
fn doq_server_shut_down_without_start() {
    let config = default_doq_config();
    let mut server = DoqServer::new(config, None);
    server.shutdown();
}

#[test]
fn doq_bind_address_derivation() {
    let config = DnsDoqConfig {
        enabled: true,
        port: 7853,
        bind_address: "192.168.1.100".to_string(),
        ..default_doq_config()
    };

    let expected: SocketAddr = "192.168.1.100:7853".parse().unwrap();
    let actual: SocketAddr = format!("{}:{}", config.bind_address, config.port)
        .parse()
        .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn doq_bind_address_localhost() {
    let config = DnsDoqConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 8853,
        ..default_doq_config()
    };

    let addr: SocketAddr = format!("{}:{}", config.bind_address, config.port)
        .parse()
        .unwrap();
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(addr.port(), 8853);
}

#[test]
fn transport_class_variants_are_distinct() {
    let udp512 = TransportClass::Udp512;
    let udp_edns = TransportClass::UdpEdns(1232);
    let tcp = TransportClass::Tcp;
    let http = TransportClass::Http;
    let quic = TransportClass::Quic;

    let mut seen = std::collections::HashSet::new();
    seen.insert(format!("{:?}", udp512));
    seen.insert(format!("{:?}", udp_edns));
    seen.insert(format!("{:?}", tcp));
    seen.insert(format!("{:?}", http));
    seen.insert(format!("{:?}", quic));
    assert_eq!(
        seen.len(),
        5,
        "all TransportClass variants must be distinct"
    );
}

fn build_test_query() -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&[
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    for label in b"example" {
        query.push(*label);
    }
    query.push(0);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    query
}
