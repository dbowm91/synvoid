mod support;

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::notify::{NotifyConfig, NotifyHandler};
use synvoid_dns::server::ShardedZoneStore;
use synvoid_dns::wire;

use support::query::encode_qname;
use support::response::response_rcode;
use support::zone::zone_with_soa;

fn build_notify_query(zone_name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x9Au16.to_be_bytes());
    let flags: u16 = (4u16) << 11;
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&encode_qname(zone_name));
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf
}

#[test]
fn notify_authorized_newer_serial_accepted() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 10),
    );

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones.clone(), cfg).with_source_allowlist(vec!["10.0.0.1".to_string()]);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("example.test");

    let response = handler.handle_notify(&query, client);
    assert!(response.is_some(), "authorized NOTIFY must return Some");
    let bytes = response.unwrap();
    assert!(!bytes.is_empty(), "response must not be empty");
    let rcode = response_rcode(&bytes);
    assert_eq!(
        rcode,
        wire::RCODE_NOERROR,
        "response RCODE must be NOERROR (0), got {}",
        rcode
    );
}

#[test]
fn notify_authorized_stale_serial_ignored() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 50),
    );

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones.clone(), cfg).with_source_allowlist(vec!["10.0.0.1".to_string()]);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("example.test");

    let response = handler.handle_notify(&query, client);
    assert!(
        response.is_some(),
        "stale serial NOTIFY still returns a response"
    );
    let bytes = response.unwrap();
    let rcode = response_rcode(&bytes);
    assert_eq!(
        rcode,
        wire::RCODE_NOERROR,
        "stale serial still returns NOERROR per RFC 1996"
    );
    assert!(bytes.len() >= 12, "response must have DNS header");
}

#[test]
fn notify_unknown_zone_returns_nxdomain() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 10),
    );

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones.clone(), cfg).with_source_allowlist(vec!["10.0.0.1".to_string()]);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("nonexistent.test");

    let response = handler.handle_notify(&query, client);
    assert!(
        response.is_some(),
        "NOTIFY for unknown zone must return Some (with NXDOMAIN)"
    );
    let bytes = response.unwrap();
    let rcode = response_rcode(&bytes);
    assert_eq!(
        rcode,
        wire::RCODE_NXDOMAIN,
        "unknown zone must return NXDOMAIN (3), got {}",
        rcode
    );
}

#[test]
fn notify_unauthorized_source_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 10),
    );

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones.clone(), cfg).with_source_allowlist(vec!["192.0.2.1".to_string()]);
    let client: IpAddr = "10.0.0.99".parse().unwrap();
    let query = build_notify_query("example.test");

    let response = handler.handle_notify(&query, client);
    assert!(
        response.is_none(),
        "NOTIFY from non-allowed source must return None"
    );
}

#[test]
fn notify_tsig_required_absent_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 10),
    );

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones.clone(), cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_require_tsig(true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("example.test");

    let response = handler.handle_notify(&query, client);
    assert!(
        response.is_none(),
        "NOTIFY with require_tsig=true but no TSIG must return None"
    );
}

#[test]
fn notify_rate_limit_per_zone() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 10),
    );

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones.clone(), cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_min_notify_interval(std::time::Duration::from_secs(60));
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("example.test");

    let response1 = handler.handle_notify(&query, client);
    assert!(response1.is_some(), "first NOTIFY must succeed");
    let rcode1 = response_rcode(&response1.unwrap());
    assert_eq!(rcode1, wire::RCODE_NOERROR);

    let response2 = handler.handle_notify(&query, client);
    assert!(
        response2.is_some(),
        "rate-limited NOTIFY must still return Some (NOERROR)"
    );
    let rcode2 = response_rcode(&response2.unwrap());
    assert_eq!(
        rcode2,
        wire::RCODE_NOERROR,
        "rate-limited NOTIFY must return NOERROR per notify.rs:166"
    );
}
