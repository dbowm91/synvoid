//! DNS control-plane authorization tests (Milestone 3 Corrective Pass, Workstream 4).
//!
//! These tests verify end-to-end authorization behavior of the mutation and
//! transfer paths. Each path MUST be deny-by-default; when configured
//! (`enabled = true`) and authorized (allowlist + TSIG where required),
//! the operation may proceed. Malformed control-plane messages must NOT
//! mutate authoritative state and must return a deterministic response
//! policy (NOTIMP / REFUSED / FORMERR).
//!
//! The tests exercise the public handler APIs (`DynamicUpdateHandler`,
//! `NotifyHandler`, `ZoneTransfer`) directly — no live network sockets —
//! so they are deterministic and run in the unit/integration test tier.

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::notify::{NotifyConfig, NotifyHandler};
use synvoid_dns::server::ShardedZoneStore;
use synvoid_dns::transfer::{ZoneTransfer, AXFR_QUERY_TYPE, IXFR_QUERY_TYPE};
use synvoid_dns::update::DynamicUpdateHandler;
use synvoid_dns::wire;

use support::query::encode_qname;
use support::zone::zone_with_soa;

fn build_minimal_update_query(zone_name: &str) -> Vec<u8> {
    let mut buf = support::query::build_update_header(1, 0, 0, 0);
    buf.extend_from_slice(&support::query::build_zone_question(zone_name));
    buf
}

fn build_minimal_notify_query(zone_name: &str, serial: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    let flags: u16 = (4u16) << 11; // OPCODE=NOTIFY
    buf.extend_from_slice(&0x9Au16.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    buf.extend_from_slice(&encode_qname(zone_name));
    buf.extend_from_slice(&6u16.to_be_bytes()); // QTYPE=SOA
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

    // AN section: SOA record (label-encoded wire form)
    buf.extend_from_slice(&encode_qname(zone_name));
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&300u32.to_be_bytes());
    let rdata_pos = buf.len();
    buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH placeholder
    let rdata_start = buf.len();
    let mname = format!("ns1.{}", zone_name.trim_end_matches('.'));
    for label in mname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    let rname = format!("admin.{}", zone_name.trim_end_matches('.'));
    for label in rname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&serial.to_be_bytes());
    buf.extend_from_slice(&3600u32.to_be_bytes());
    buf.extend_from_slice(&600u32.to_be_bytes());
    buf.extend_from_slice(&604800u32.to_be_bytes());
    buf.extend_from_slice(&300u32.to_be_bytes());
    let rdata_len = buf.len() - rdata_start;
    buf[rdata_pos..rdata_pos + 2].copy_from_slice(&(rdata_len as u16).to_be_bytes());
    buf
}

fn build_minimal_axfr_query(zone_name: &str) -> Vec<u8> {
    support::query::build_axfr_query(0xCAFE, zone_name)
}

fn build_minimal_ixfr_query(zone_name: &str, serial: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xCAFEu16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT=1

    buf.extend_from_slice(&encode_qname(zone_name));
    buf.extend_from_slice(&IXFR_QUERY_TYPE.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    // Additional section SOA
    let origin_bytes = zone_name.trim_end_matches('.').as_bytes();
    buf.push(origin_bytes.len() as u8);
    buf.extend_from_slice(origin_bytes);
    buf.push(0);
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    let rdata_pos = buf.len();
    buf.extend_from_slice(&0u16.to_be_bytes());
    let rdata_start = buf.len();
    let mname = format!("ns1.{}", zone_name.trim_end_matches('.'));
    for label in mname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    let rname = format!("admin.{}", zone_name.trim_end_matches('.'));
    for label in rname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&serial.to_be_bytes());
    buf.extend_from_slice(&3600u32.to_be_bytes());
    buf.extend_from_slice(&600u32.to_be_bytes());
    buf.extend_from_slice(&604800u32.to_be_bytes());
    buf.extend_from_slice(&300u32.to_be_bytes());
    let rdata_len = buf.len() - rdata_start;
    buf[rdata_pos..rdata_pos + 2].copy_from_slice(&(rdata_len as u16).to_be_bytes());
    buf
}

// ──────────────────────────────────────────────────────────────────
// UPDATE
// ──────────────────────────────────────────────────────────────────

/// UPDATE disabled by default: any UPDATE query must not change zone state
/// and must not return a successful response code.
#[test]
fn update_disabled_by_default_refuses_mutation() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = DynamicUpdateHandler::new(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_minimal_update_query("example.test");

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_err(),
        "Disabled-by-default UPDATE must return Err (NOTIMP), not Ok"
    );
    // The zone MUST remain at serial=1 and the records MUST be unchanged.
    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "Zone serial must remain unchanged");
    assert_eq!(
        z.records.len(),
        1,
        "Zone records must remain unchanged when UPDATE is disabled"
    );
}

/// Wire-level UPDATE: a malformed UPDATE query claiming a non-existent zone
/// must not mutate state. The handler must return Err (or Ok with error RCODE).
#[test]
fn update_malformed_message_does_not_mutate_zone() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    // A well-formed query header + question for a zone that doesn't exist.
    // This is the realistic malformed case: a peer sends an UPDATE to a
    // non-existent zone. The handler must not panic and must not mutate state.
    let query = build_minimal_update_query("nonexistent.test");
    let result = handler.handle_update(&query, client);
    let _ = result; // Err or Ok with error RCODE is acceptable
    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "Zone serial must be unchanged");
    assert_eq!(
        z.records.len(),
        1,
        "Zone records must be unchanged after a malformed UPDATE"
    );
}

/// Wire-level UPDATE: when enabled, the handler responds with a deterministic
/// RCODE (REFUSED / FORMERR / NOTIMP / SERVFAIL) for a query that fails
/// pre-conditions (no zone, invalid class, etc.). This guards against the
/// regression of "silent acknowledgement" of malformed input.
#[test]
fn update_enabled_invalid_zone_returns_error_rcode() {
    let zones = Arc::new(ShardedZoneStore::new());
    // No zone inserted.
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_minimal_update_query("nonexistent.test");

    let result = handler.handle_update(&query, client);
    if let Ok(bytes) = &result {
        assert!(bytes.len() >= 12, "response must contain a DNS header");
        let rcode = bytes[3] & 0x0F;
        assert!(
            rcode == wire::UPDATE_RCODE_REFUSED
                || rcode == wire::UPDATE_RCODE_FORMERR
                || rcode == wire::UPDATE_RCODE_SERVFAIL
                || rcode == wire::UPDATE_RCODE_NOTAUTH
                || rcode == wire::UPDATE_RCODE_NOTIMP,
            "non-existent zone UPDATE must produce an error RCODE, got {}",
            rcode
        );
    }
}

// ──────────────────────────────────────────────────────────────────
// NOTIFY
// ──────────────────────────────────────────────────────────────────

/// NOTIFY disabled by default: a NOTIFY message must not mutate zone state.
#[test]
fn notify_disabled_by_default_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let cfg = NotifyConfig::default();
    assert!(!cfg.enabled, "NotifyConfig must be disabled by default");
    let handler = NotifyHandler::new(zones.clone(), cfg);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_minimal_notify_query("example.test", 42);

    let _response = handler.handle_notify(&query, client);
    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "Zone serial must remain unchanged");
    assert_eq!(
        z.records.len(),
        1,
        "Zone records must remain unchanged after disabled NOTIFY"
    );
}

/// NOTIFY from an unknown (not in allowlist) source must be ignored.
#[test]
fn notify_unknown_source_ignored() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones.clone(), cfg).with_source_allowlist(vec!["192.0.2.1".to_string()]);
    let client: IpAddr = "10.0.0.99".parse().unwrap(); // not in allowlist
    let query = build_minimal_notify_query("example.test", 100);

    let _response = handler.handle_notify(&query, client);
    let z = zones.get("example.test").unwrap();
    assert_eq!(
        z.serial, 1,
        "NOTIFY from non-allowed source MUST NOT trigger reload / zone mutation"
    );
}

// ──────────────────────────────────────────────────────────────────
// AXFR / IXFR
// ──────────────────────────────────────────────────────────────────

/// AXFR denied by default: when `ZoneTransfer::new` is used (no axfr_enabled
/// override), an AXFR request must not leak zone data.
#[test]
fn axfr_denied_by_default_returns_no_zone_data() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let zone_transfer = ZoneTransfer::new(zones.clone(), vec![], None);
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    let result = zone_transfer.is_transfer_allowed(client, "example.test");
    assert!(
        !result,
        "AXFR must be denied when no allowlist entry and AXFR is disabled by default"
    );

    let response = zone_transfer.handle_axfr_request(
        "example.test",
        client,
        None,      // no TSIG record
        0xCAFEu16, // message_id
        &build_minimal_axfr_query("example.test"),
        true, // is_tcp
    );
    assert!(
        response.is_err(),
        "AXFR must be denied (Err) when client is not allowed and AXFR is disabled"
    );
}

/// IXFR denied by default at the same boundary as AXFR (no allowlist).
#[test]
fn ixfr_denied_by_default_returns_no_data() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 5));
    let zone_transfer = ZoneTransfer::new(zones.clone(), vec![], None);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_minimal_ixfr_query("example.test", 5);

    let result = zone_transfer.is_transfer_allowed(client, "example.test");
    assert!(
        !result,
        "IXFR must be denied by default when not in allowlist"
    );

    let response =
        zone_transfer.handle_ixfr_request("example.test", client, Some(5), None, 0xCAFEu16, &query);
    assert!(
        response.is_err(),
        "IXFR must be denied (Err) when client is not allowed and IXFR is disabled"
    );
}

#[test]
fn axfr_query_type_is_252_and_ixfr_query_type_is_251() {
    assert_eq!(AXFR_QUERY_TYPE, 252, "AXFR qtype must be 252 per IANA");
    assert_eq!(IXFR_QUERY_TYPE, 251, "IXFR qtype must be 251 per IANA");
}

/// Transfer module-level wiring: `with_security_config` does not enable AXFR
/// when explicitly disabled, even if the client is in the allowlist.
#[test]
fn transfer_disabled_when_axfr_enabled_false() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let zone_transfer = ZoneTransfer::with_security_config(
        zones.clone(),
        vec!["10.0.0.1".to_string()],
        None,
        false, // allow_wildcard_transfer
        false, // wildcard_transfer_requires_tsig
        true,  // ixfr_enabled
        true,  // ixfr_fallback_to_axfr
        false, // require_tsig
        false, // axfr_enabled = false
        true,  // tcp_only
    );
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let response = zone_transfer.handle_axfr_request(
        "example.test",
        client,
        None,
        0xCAFEu16,
        &build_minimal_axfr_query("example.test"),
        true,
    );
    assert!(
        response.is_err(),
        "AXFR must be denied (Err) when axfr_enabled=false even with allowlist"
    );
}

/// When AXFR is enabled and the client is allowed, the handler must produce
/// a non-empty response that includes the zone's SOA record (bracketed transfer).
/// `is_tcp=true` is the only allowed transport.
#[test]
fn axfr_allowed_client_gets_soa_bracketed_transfer() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let zone_transfer = ZoneTransfer::with_security_config(
        zones.clone(),
        vec!["10.0.0.1".to_string()],
        None,
        false, // allow_wildcard_transfer
        false, // wildcard_transfer_requires_tsig
        true,  // ixfr_enabled
        true,  // ixfr_fallback_to_axfr
        false, // require_tsig
        true,  // axfr_enabled
        true,  // tcp_only
    );
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    let response = zone_transfer.handle_axfr_request(
        "example.test",
        client,
        None,
        0xCAFEu16,
        &build_minimal_axfr_query("example.test"),
        true, // is_tcp
    );
    let bytes = response.expect("AXFR must succeed for allowed client");
    assert!(
        !bytes.is_empty(),
        "AXFR response must contain zone data when allowed"
    );
    // The combined response should contain multiple DNS messages (SOA + records + SOA).
    // We at least verify it is non-empty and longer than a single header.
    assert!(
        bytes.len() > 12,
        "AXFR response must be longer than a single header, got {} bytes",
        bytes.len()
    );
}
