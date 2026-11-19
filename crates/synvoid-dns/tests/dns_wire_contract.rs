//! Wire-encoding contract: every name the server writes must parse as a name.
//!
//! The assertions here are written from the client's point of view: they decode
//! the bytes the server emitted (following compression pointers) instead of
//! inspecting internal record state. That is what the previous suites did not
//! do, which is how relative owners (`www`) and presentation-format names
//! (`example.com` written as ASCII label bytes) reached the wire unnoticed.
//!
//! Cases 1–6 and 8 of the phase-01 contract live here; case 7
//! (`build_question_section` is byte-identical to `wire::encode_owner`) is a
//! unit test in `recursive.rs` because the function is private.

mod support;

use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::wire::{encode_name, encode_owner, NameError};
use synvoid_dns::zone_trie::ZoneTrie;

use support::context::make_ctx;
use support::query::build_query;
use support::response::*;

const ORIGIN: &str = "example.com";
const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

fn record(name: &str, record_type: RecordType, value: &str) -> DnsZoneRecord {
    DnsZoneRecord {
        name: name.to_string(),
        record_type,
        value: value.to_string(),
        ttl: 300,
        priority: None,
    }
}

/// A zone whose records are stored the way `normalize_record_name` stores them:
/// origin-relative owners (`@`, `www`, `a.b`, `alias`).
fn build_zone() -> Zone {
    let mut zone = Zone::new(ORIGIN.to_string());
    zone.serial = 2026111601;
    zone.nsec_enabled = false;
    zone.nsec3_enabled = false;

    let entries: Vec<((&str, RecordType), DnsZoneRecord)> = vec![
        (
            ("@", RecordType::SOA),
            record(
                "@",
                RecordType::SOA,
                "ns1.example.com. hostmaster.example.com. 2026111601 3600 600 604800 300",
            ),
        ),
        (
            ("@", RecordType::A),
            record("@", RecordType::A, "192.0.2.1"),
        ),
        (
            ("www", RecordType::A),
            record("www", RecordType::A, "192.0.2.10"),
        ),
        (
            ("a.b", RecordType::A),
            record("a.b", RecordType::A, "192.0.2.11"),
        ),
        (
            ("alias", RecordType::CNAME),
            record("alias", RecordType::CNAME, "target.example.com."),
        ),
    ];

    for ((name, record_type), value) in entries {
        zone.records
            .insert((name.to_string(), record_type), vec![value]);
    }

    zone
}

fn setup() -> (
    Arc<ShardedZoneStore>,
    Arc<RwLock<ZoneTrie>>,
    EcsFilterConfig,
) {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(ORIGIN.to_string(), build_zone());
    let mut trie = ZoneTrie::new();
    trie.insert(ORIGIN);
    (
        zones,
        Arc::new(RwLock::new(trie)),
        EcsFilterConfig::default(),
    )
}

/// Query the server and return the raw response bytes.
fn query(name: &str, qtype: u16) -> Vec<u8> {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);
    let request = build_query(0x4242, name, qtype);

    DnsServer::handle_query(&ctx, &request, None)
        .expect("handle_query must answer a well-formed query")
        .as_ref()
        .clone()
}

/// Byte range of answer record `index`'s RDATA.
fn answer_rdata(resp: &[u8], index: usize) -> &[u8] {
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    assert!(
        index < ancount,
        "answer index {index} out of range (ANCOUNT={ancount})"
    );

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_wire_name(resp, pos) + 4;
    }
    for i in 0..=index {
        pos = skip_wire_name(resp, pos);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        let start = pos + 10;
        if i == index {
            return &resp[start..start + rdlength];
        }
        pos = start + rdlength;
    }
    unreachable!("index bounds checked above")
}

/// Owner name of the first authority record, decoded like a client would.
fn first_authority_owner(resp: &[u8]) -> String {
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_wire_name(resp, pos) + 4;
    }
    for _ in 0..ancount {
        pos = skip_wire_name(resp, pos);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }

    read_wire_name(resp, pos).expect("authority owner must decode as a wire name")
}

// ── Case 1: apex A answer owner is the origin ───────────────────────────────

#[test]
fn apex_a_answer_owner_is_the_origin() {
    let resp = query(ORIGIN, 1);

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(answer_owner(&resp, 0), ORIGIN);
}

// ── Case 2: subdomain A answer owner is the FQDN, not the relative name ─────

#[test]
fn subdomain_a_answer_owner_is_the_fqdn() {
    let resp = query("www.example.com", 1);

    assert_eq!(response_ancount(&resp), 1);
    let owner = answer_owner(&resp, 0);
    assert_eq!(owner, "www.example.com");
    assert_ne!(
        owner, "www",
        "a relative owner is out of zone and is discarded by resolvers"
    );
}

// ── Case 3: multi-label relative owner ──────────────────────────────────────

#[test]
fn multi_label_owner_is_the_fqdn() {
    let resp = query("a.b.example.com", 1);

    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(answer_owner(&resp, 0), "a.b.example.com");
}

// ── Case 4: CNAME target RDATA parses as a name ─────────────────────────────

#[test]
fn cname_target_rdata_parses_as_a_name() {
    let resp = query("alias.example.com", 1);

    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(answer_owner(&resp, 0), "alias.example.com");

    let rdata_offset = answer_rdata(&resp, 0).as_ptr() as usize - resp.as_ptr() as usize;
    assert_eq!(
        read_wire_name(&resp, rdata_offset).as_deref(),
        Some("target.example.com"),
        "CNAME RDATA must be a length-prefixed wire name"
    );
    // A client re-parses the whole message; the target must not be ASCII text.
    let message = synvoid_dns::wire::parse_dns_message(&resp)
        .expect("a client must be able to parse the response");
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].name.to_string(), "alias.example.com.");
}

// ── Case 5: question echo preserves the client's mixed case (0x20 encoding) ─

#[test]
fn question_echo_preserves_the_clients_case() {
    let mixed = "WwW.ExAmPle.CoM";
    let resp = query(mixed, 1);

    assert_eq!(
        question_name(&resp),
        mixed,
        "a resolver that verifies 0x20 case randomisation discards a rewritten question"
    );
    assert_eq!(
        answer_owner(&resp, 0),
        mixed,
        "the answer owner is a compression pointer into the echoed question"
    );
}

// ── Case 6: authoritative NXDOMAIN echoes the question with QDCOUNT 1 ───────

#[test]
fn nxdomain_echoes_the_question_with_qdcount_one() {
    let resp = query("absent.example.com", 1);

    assert_eq!(response_rcode(&resp), RCODE_NXDOMAIN);
    assert_eq!(
        u16::from_be_bytes([resp[4], resp[5]]),
        1,
        "QDCOUNT must be 1"
    );
    assert_eq!(question_name(&resp), "absent.example.com");
    assert_eq!(response_nscount(&resp), 1, "SOA in authority section");
    assert_eq!(
        first_authority_owner(&resp),
        ORIGIN,
        "the negative SOA owner is the zone apex"
    );
}

// ── Case 8: encode_owner is total, never silently lossy ─────────────────────

#[test]
fn encode_owner_rejects_a_label_over_63_octets() {
    let label = "a".repeat(64);

    assert_eq!(
        encode_owner(&label, ORIGIN),
        Err(NameError::LabelTooLong { len: 64 }),
        "a 64-octet label cannot be represented; it must not be dropped"
    );
}

#[test]
fn encode_owner_rejects_an_empty_interior_label() {
    assert_eq!(
        encode_owner("a..b", ORIGIN),
        Err(NameError::EmptyLabel),
        "an empty label must be rejected, not skipped"
    );
}

#[test]
fn encode_owner_rejects_a_name_over_255_octets() {
    // Five 50-octet labels encode to five length bytes plus a root byte:
    // 255 content octets + 6 = 261, over the RFC 1035 limit.
    let name = std::iter::repeat_n("a".repeat(50), 5)
        .collect::<Vec<_>>()
        .join(".");
    assert!(matches!(
        encode_owner(&name, ORIGIN),
        Err(NameError::NameTooLong { .. })
    ));

    // The boundary itself is accepted: three 63-octet labels plus one 61-octet
    // label encode to 3 * (1 + 63) + (1 + 61) + 1 (root) = 255 octets.
    let boundary = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let encoded = encode_owner(&boundary, "").expect("255-octet name must encode");
    assert_eq!(encoded.len(), 255);
    assert_eq!(encoded, encode_name(&boundary).unwrap());
}
