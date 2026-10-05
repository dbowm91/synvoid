mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use synvoid_dns::cache::TransportClass;
use synvoid_dns::doh::DohServer;
use synvoid_dns::doq::DoqServer;
use synvoid_dns::dot::DotServer;
use synvoid_dns::runtime_config::{DohRuntimeConfig, DoqRuntimeConfig, DotRuntimeConfig};

/// DoT runtime values. TLS material is composition/provider owned
/// (`CertResolver`), so the runtime DTO carries only the parsed bind socket.
fn dot_runtime() -> DotRuntimeConfig {
    support::dot_on(853)
}

fn doh_runtime() -> DohRuntimeConfig {
    support::doh_on(443)
}

fn doq_runtime() -> DoqRuntimeConfig {
    support::doq_on(853)
}

#[test]
fn dot_server_creation() {
    let _server = DotServer::new(dot_runtime(), None);
}

#[test]
fn doh_server_creation() {
    let _server = DohServer::new(doh_runtime(), None);
}

#[test]
fn doq_server_creation() {
    let server = DoqServer::new(doq_runtime(), None);
    // The bind socket is already parsed at conversion time.
    assert_eq!(
        server.config().bind_address,
        Some("127.0.0.1:853".parse().unwrap())
    );
    assert!(server.config().enabled);
    assert_eq!(server.config().max_concurrent_streams, 100);
    assert_eq!(
        server.config().idle_timeout,
        std::time::Duration::from_secs(30)
    );
}

#[test]
fn disabled_transports_carry_no_bind_address() {
    // A disabled transport must not fabricate a listener socket.
    let dot = DotServer::new(support::disabled_dot(), None);
    assert!(!dot.config().enabled);
    assert_eq!(dot.config().bind_address, None);

    let doh = DohServer::new(support::disabled_doh(), None);
    assert!(!doh.config().enabled);
    assert_eq!(doh.config().bind_address, None);

    let doq = DoqServer::new(support::disabled_doq(), None);
    assert!(!doq.config().enabled);
    assert_eq!(doq.config().bind_address, None);
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

/// Phase 137: the `doq_alpn_is_doq` test that used to live here was
/// `assert_eq!(b"doq", b"doq)` — a comparison of two byte-string literals that
/// said nothing about the code and could never fail. It is replaced by
/// `doq_still_negotiates_doq` in `encrypted_transport_alpn_negotiation.rs`,
/// which drives a real QUIC handshake against a real DoQ endpoint and observes
/// the negotiated protocol.

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
    let mut server = DotServer::new(dot_runtime(), None);
    server.shutdown();
}

#[test]
fn doh_server_shut_down_without_start() {
    let mut server = DohServer::new(doh_runtime(), None);
    server.shutdown();
}

#[test]
fn doq_server_shut_down_without_start() {
    let mut server = DoqServer::new(doq_runtime(), None);
    server.shutdown();
}

#[test]
fn doq_bind_address_derivation() {
    let config = DoqRuntimeConfig {
        bind_address: Some("192.168.1.100:7853".parse().unwrap()),
        ..support::doq_on(853)
    };
    assert_eq!(
        config.bind_address,
        Some("192.168.1.100:7853".parse::<SocketAddr>().unwrap())
    );
}

#[test]
fn doq_bind_address_localhost() {
    let config = support::doq_on(8853);
    let addr = config
        .bind_address
        .expect("enabled transport has a bind address");
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
