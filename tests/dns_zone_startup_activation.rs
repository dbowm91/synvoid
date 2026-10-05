//! Phase 132 — authoritative zone startup activation, proven end to end.
//!
//! Before this phase, `[[dns.zones.items]]` in `main.toml` was parsed,
//! validated, converted record-by-record by the application adapter, handed to
//! `DnsServer::new` — and then discarded by the `zones: _` destructure. Neither
//! `load_zones` nor `load_zones_from_store` had a production caller, so an
//! operator copying a shipped example got an authoritative server that served
//! nothing for the zone it declared.
//!
//! These tests exercise the whole path and assert the *served answer*, not the
//! projection. Asserting on `DnsRuntimeConfig.zones` would only re-prove the
//! adapter, which the 43-fixture parity suite already covers.
//!
//! Coverage:
//! - a shipped example's declared zone becomes a served authoritative zone;
//! - a zone with no SOA fails config validation, and fails activation if it
//!   somehow gets past validation;
//! - no declared zones still starts and still answers.
//!
//! Wire format is hand-rolled on purpose: root has no hickory edge (0 root
//! `src/` uses), and this mirrors the proven TCP framing in
//! `crates/synvoid-dns/tests/dns_phase45_contract.rs`.

#![cfg(feature = "dns")]

use std::net::SocketAddr;
use std::time::Duration;

use synvoid::server::dns_runtime_config::dns_runtime_config_from_persisted;
use synvoid_config::dns::{
    DnsConfig, DnsFirewallConfig, DnsRecordEntry, DnsRecordType, DnsZoneEntry,
};
use synvoid_dns::server::DnsServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Attempts allowed before a test reports it could not win a loopback port.
const BIND_ATTEMPTS: usize = 8;

/// Build a query for `name`/`A` with the given message ID.
fn a_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.').filter(|s| !s.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
    q
}

/// DNS-over-TCP framing: a 16-bit length prefix.
fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

async fn read_frame(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .expect("read length timeout")
        .expect("read length");
    let len = u16::from_be_bytes(len_buf) as usize;
    assert!(len > 0, "server must not send an empty frame");
    let mut buf = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("read body timeout")
        .expect("read body");
    buf
}

/// Unwraps the `[dns]` section of a full SynVoid configuration file.
#[derive(serde::Deserialize)]
struct DnsSectionWrapper {
    dns: DnsConfig,
}

/// Loopback-bound defaults; the startup helper overrides the port per attempt.
fn loopback_config() -> DnsConfig {
    DnsConfig {
        bind_address: "127.0.0.1".to_string(),
        ..DnsConfig::default()
    }
}

/// A persisted config declaring `example.com` with the records the served-answer
/// assertions below expect.
fn config_with_zone() -> DnsConfig {
    let mut config = loopback_config();
    config.zones.items = vec![DnsZoneEntry {
        zone: "example.com".to_string(),
        records: vec![
            DnsRecordEntry {
                name: "example.com".to_string(),
                record_type: DnsRecordType::Soa,
                value: "ns1.example.com. admin.example.com. 2026100501 3600 900 604800 3600"
                    .to_string(),
                ttl: None,
                priority: None,
            },
            DnsRecordEntry {
                name: "www.example.com".to_string(),
                record_type: DnsRecordType::A,
                value: "192.0.2.1".to_string(),
                ttl: None,
                priority: None,
            },
        ],
        dnssec: None,
    }];
    config
}

/// Convert, activate the declared zones, and start — exactly the sequence
/// `src/server/resources.rs` performs at startup — returning the port actually
/// bound.
///
/// Phase 131 established that a predicted port cannot be trusted: the server
/// binds UDP and TCP itself, so the port is verified by the real bind and a new
/// one is taken only when that bind is observed to have lost a race.
async fn start_with_zones(config: &DnsConfig) -> (DnsServer, u16) {
    let mut last_conflict = String::new();

    for _ in 0..BIND_ATTEMPTS {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("ask for an ephemeral port")
            .local_addr()
            .expect("local addr")
            .port();

        let attempt = DnsConfig {
            port,
            ..config.clone()
        };

        let runtime = dns_runtime_config_from_persisted(&attempt)
            .expect("persisted config converts to runtime")
            .clone();
        let zones = runtime.zones.clone();

        let mut server = DnsServer::new(runtime, None, None);

        // Phase 132: activate the declared zones, fail closed on error.
        server
            .load_zones(zones)
            .expect("a valid config must activate cleanly");

        match server.start().await {
            Ok(()) => return (server, port),
            Err(error)
                if (error.starts_with("Failed to bind DNS UDP socket:")
                    || error.starts_with("Failed to bind DNS TCP socket:"))
                    && error.contains("in use") =>
            {
                last_conflict = error;
            }
            Err(error) => panic!("DNS server start failed: {error}"),
        }
    }

    panic!("could not bind a loopback port in {BIND_ATTEMPTS} attempts: {last_conflict}");
}

/// Send `name`/`A` over TCP and return the raw response.
async fn query(server_port: u16, id: u16, name: &str) -> Vec<u8> {
    let mut stream =
        tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], server_port)))
            .await
            .expect("connect to the DNS server");
    stream
        .write_all(&frame(&a_query(id, name)))
        .await
        .expect("write query");
    read_frame(&mut stream).await
}

/// A shipped example's declared zone becomes a served authoritative zone.
///
/// Driven from the example profile rather than a hand-built config, so the
/// shipped file cannot drift back into advertising a zone that never loads.
#[tokio::test]
async fn shipped_example_zone_becomes_a_served_authoritative_zone() {
    // CARGO_MANIFEST_DIR is the repository root for the root crate.
    let path = format!(
        "{}/examples/dns/authoritative_public.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("shipped example is readable");
    // The example is a full configuration file, so `[dns]` is unwrapped first.
    let config: DnsSectionWrapper = toml::from_str(&text).expect("shipped example parses");
    let config = config.dns;
    config.validate().expect("shipped example validates");

    // A public authoritative profile blocks internal clients, and the firewall's
    // `block_internal_ips` includes `127.0.0.0/8` (see `server/mod.rs`). That is
    // correct behavior for this profile, and this test dials over loopback, so
    // the internal-client block is relaxed for the test only. The zone data
    // still comes from the shipped file unchanged.
    let config = DnsConfig {
        firewall: DnsFirewallConfig {
            block_internal_ips: false,
            ..config.firewall
        },
        ..config
    };

    // The example must actually declare a zone, otherwise this test would pass
    // vacuously on a profile that had its zone block removed.
    assert_eq!(
        config.zones.items.len(),
        1,
        "the shipped example must still declare a zone"
    );
    assert!(
        !config.zones.items[0].records.is_empty(),
        "the shipped example's zone must declare records"
    );

    let (mut server, port) = start_with_zones(&config).await;

    // The zone reached the *server*, not just the adapter.
    let zones = server.get_zones();
    assert!(
        zones.contains_key("example.com"),
        "declared zone must be activated on the server, got {:?}",
        zones.keys()
    );
    assert_eq!(zones.len(), 1, "exactly the declared zone must be active");

    let id = 0x2a2a;
    let response = query(port, id, "www.example.com").await;

    assert_eq!(
        u16::from_be_bytes([response[0], response[1]]),
        id,
        "response ID must echo the query ID"
    );
    let flags = u16::from_be_bytes([response[2], response[3]]);
    assert_eq!(
        flags & 0x000f,
        0,
        "a served zone must not answer an error rcode"
    );
    assert_ne!(
        flags & 0x0400,
        0,
        "a configured zone must answer authoritatively (AA set)"
    );
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    assert!(
        ancount >= 1,
        "the A record declared for www.example.com must be answered, ancount={ancount}"
    );
    // The declared A rdata, 192.0.2.1, packed into four bytes.
    assert!(
        response.windows(4).any(|w| w == [192, 0, 2, 1]),
        "the answer must carry the declared 192.0.2.1 rdata"
    );

    server.shutdown_runtime();
}

/// A zone with no records is rejected by config validation, before it can ever
/// reach activation.
#[test]
fn zone_without_soa_fails_config_validation() {
    let mut config = config_with_zone();
    config.zones.items[0].records.clear();

    let error = config
        .validate()
        .expect_err("a zone with no records cannot be activated");
    let message = error.to_string();
    assert!(
        message.contains("SOA"),
        "the error must explain the SOA requirement, got: {message}"
    );
    assert!(
        message.contains("example.com"),
        "the error must name the offending zone, got: {message}"
    );
}

/// A zone that passes validation but still cannot be activated fails
/// `load_zones` rather than being silently skipped.
///
/// Validation only enforces "has at least one record"; the RFC 1035 requirement
/// is that one record is an SOA. This pins the second, later check so a zone can
/// never be dropped without an error.
#[test]
fn zone_that_cannot_activate_is_an_error_not_a_skip() {
    let mut config = config_with_zone();
    // Valid under the config rule (non-empty), invalid for the server (no SOA).
    config.zones.items[0].records = vec![DnsRecordEntry {
        name: "www.example.com".to_string(),
        record_type: DnsRecordType::A,
        value: "192.0.2.1".to_string(),
        ttl: None,
        priority: None,
    }];
    assert!(
        config.validate().is_ok(),
        "a non-empty zone passes config validation; the SOA rule is enforced at activation"
    );

    let runtime = dns_runtime_config_from_persisted(&config).expect("conversion succeeds");
    let zones = runtime.zones.clone();
    let server = DnsServer::new(runtime, None, None);

    let error = server
        .load_zones(zones)
        .expect_err("activation must fail closed, not skip the zone");
    assert!(
        error.contains("SOA"),
        "the failure must name the SOA requirement, got: {error}"
    );
}

/// A server with no declared zones still starts and still answers.
#[tokio::test]
async fn no_declared_zones_starts_and_answers_as_before() {
    let config = loopback_config();
    assert!(config.zones.items.is_empty());
    config.validate().expect("an empty zone list stays valid");

    let (mut server, port) = start_with_zones(&config).await;
    assert!(
        server.get_zones().is_empty(),
        "no declared zone must mean no activated zone"
    );

    let id = 0x3333;
    let response = query(port, id, "nothing.example.org").await;
    assert_eq!(
        u16::from_be_bytes([response[0], response[1]]),
        id,
        "a server with no zones must still answer queries"
    );

    server.shutdown_runtime();
}
