//! Response-envelope contract: the header counts, the question section, and the
//! OPT record must describe the bytes that follow them.
//!
//! Phase 01 fixed what a record's owner name means. This suite fixes the
//! envelope around those records: every field of the OPT pseudo-RR is read the
//! way a client reads it, the client's advertised UDP payload is honored rather
//! than raised to a 4 KiB floor, and an error response never claims a question
//! count that disagrees with its bytes.
//!
//! Each case asserts a wire property, not an internal value, so a regression in
//! `build_opt_encoded_record`, `response_size_limit`, or
//! `wire::build_error_response` fails here even if the unit tests still pass.

mod support;

use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::wire::{
    build_error_response, RCODE_FORMERR, RCODE_NOTIMP, RCODE_REFUSED, RCODE_SERVFAIL,
};
use synvoid_dns::zone_trie::ZoneTrie;
use synvoid_dns::TransportClass;

use support::context::make_ctx;
use support::query::{build_query, build_query_with_edns, build_query_with_edns_options};
use support::response::*;

const ORIGIN: &str = "example.com";
const TXT_SMALL_COUNT: usize = 6;
const TXT_LARGE_COUNT: usize = 20;
const TXT_VALUE_LEN: usize = 100;

fn record(name: &str, record_type: RecordType, value: &str) -> DnsZoneRecord {
    DnsZoneRecord {
        name: name.to_string(),
        record_type,
        value: value.to_string(),
        ttl: 300,
        priority: None,
    }
}

fn txt_records(count: usize) -> Vec<DnsZoneRecord> {
    (0..count)
        .map(|i| {
            record(
                "@",
                RecordType::TXT,
                // Distinct values keep the records from being deduplicated.
                &format!("{i:0>TXT_VALUE_LEN$}"),
            )
        })
        .collect()
}

/// A zone with a small and a large TXT RRset, so a response can be sized to
/// land between 512 and 1232 bytes or above 1232 bytes.
fn build_zone() -> Zone {
    let mut zone = Zone::new(ORIGIN.to_string());
    zone.serial = 2026111602;
    zone.nsec_enabled = false;
    zone.nsec3_enabled = false;

    zone.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![record(
            "@",
            RecordType::SOA,
            "ns1.example.com. hostmaster.example.com. 2026111602 3600 600 604800 300",
        )],
    );
    zone.records.insert(
        ("www".to_string(), RecordType::A),
        vec![record("www", RecordType::A, "192.0.2.10")],
    );
    zone.records.insert(
        ("@".to_string(), RecordType::TXT),
        txt_records(TXT_SMALL_COUNT),
    );
    zone.records.insert(("big".to_string(), RecordType::TXT), {
        let mut big = txt_records(TXT_LARGE_COUNT);
        for rec in &mut big {
            rec.name = "big".to_string();
        }
        big
    });

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

fn respond(
    zones: &Arc<ShardedZoneStore>,
    trie: &Arc<RwLock<ZoneTrie>>,
    ecs: &EcsFilterConfig,
    query: &[u8],
    transport: TransportClass,
) -> Vec<u8> {
    let ctx = make_ctx(zones, trie, ecs);
    DnsServer::handle_query_with_transport(&ctx, query, None, transport)
        .expect("a well-formed query must be answered")
        .as_ref()
        .clone()
}

fn flag_tc(resp: &[u8]) -> bool {
    response_flags(resp) & 0x0200 != 0
}

// ── Case 1: OPT fields are where a client reads them ────────────────────────

#[test]
fn edns_response_opt_has_payload_in_class_and_no_extended_rcode() {
    let (zones, trie, ecs) = setup();
    let query = build_query_with_edns(0x1001, "www.example.com", 1, 4096, 0, false);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(4096));

    let opt = parse_opt(&resp).expect("an EDNS query must receive an OPT record");
    assert_eq!(opt.payload, 4096, "CLASS must carry the advertised payload");
    assert_eq!(opt.ext_rcode, 0, "a normal answer has no extended RCODE");
    assert_eq!(opt.version, 0, "the response OPT version is 0");
    assert_eq!(opt.rdlen, 0, "no options are emitted, so RDLENGTH is 0");
    assert_eq!(
        opt.extended_rcode(response_rcode(&resp)),
        0,
        "the 12-bit extended RCODE of a NOERROR answer is 0"
    );
    assert_eq!(response_ancount(&resp), 1);
}

#[test]
fn an_oversized_advertisement_is_clamped_to_4096_not_raised() {
    let (zones, trie, ecs) = setup();
    let query = build_query_with_edns(0x1002, "www.example.com", 1, 8000, 0, false);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(8000));

    let opt = parse_opt(&resp).expect("an EDNS query must receive an OPT record");
    assert_eq!(
        opt.payload, 4096,
        "a 64 KiB advertisement is capped at the server's 4096-byte maximum"
    );
}

// ── Case 2: DO is echoed ────────────────────────────────────────────────────

#[test]
fn do_bit_is_echoed() {
    let (zones, trie, ecs) = setup();

    let query = build_query_with_edns(0x1003, "www.example.com", 1, 1232, 0, true);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(1232));
    let opt = parse_opt(&resp).expect("OPT expected");
    assert!(opt.dnssec_ok(), "DO=1 must be echoed in the response OPT");

    let query = build_query_with_edns(0x1004, "www.example.com", 1, 1232, 0, false);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(1232));
    let opt = parse_opt(&resp).expect("OPT expected");
    assert!(
        !opt.dnssec_ok(),
        "DO=0 must not become DO=1 in the response OPT"
    );
}

// ── Case 3: a 512-byte client is answered within 512 ────────────────────────

#[test]
fn client_advertising_512_gets_at_most_512_and_tc_when_the_answer_does_not_fit() {
    let (zones, trie, ecs) = setup();
    let query = build_query_with_edns(0x1005, ORIGIN, 16, 512, 0, false);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(512));

    assert!(
        resp.len() <= 512,
        "a client that advertised 512 must never receive more, got {}",
        resp.len()
    );
    assert!(flag_tc(&resp), "the answer does not fit, so TC must be set");
    let opt = parse_opt(&resp).expect("a TC response still carries the OPT");
    assert_eq!(
        opt.payload, 512,
        "the OPT must advertise the honored budget"
    );
    assert_eq!(response_ancount(&resp), 0, "TC responses carry no answers");
}

// ── Case 4: a 1232-byte client is honored in both directions ────────────────

#[test]
fn client_advertising_1232_receives_at_most_1232_and_can_be_answered_fully() {
    let (zones, trie, ecs) = setup();

    // This RRset fits in 1232 but not in 512: the response must be a real
    // answer, proving 1232 was honored rather than floored to 512 or raised.
    let query = build_query_with_edns(0x1006, ORIGIN, 16, 1232, 0, false);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(1232));
    assert!(
        resp.len() > 512,
        "the point of this case is a response that needs more than 512 bytes, got {}",
        resp.len()
    );
    assert!(
        resp.len() <= 1232,
        "a client that advertised 1232 must never receive more, got {}",
        resp.len()
    );
    assert!(
        !flag_tc(&resp),
        "the answer fits in 1232, so TC must be clear"
    );

    // This larger RRset does not fit, and the TC fallback must still respect
    // the same budget.
    let query = build_query_with_edns(0x1007, "big.example.com", 16, 1232, 0, false);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(1232));
    assert!(flag_tc(&resp), "the larger answer does not fit");
    assert!(
        resp.len() <= 1232,
        "the TC fallback must fit the advertised budget, got {}",
        resp.len()
    );
}

// ── Case 5: no EDNS means the legacy 512-byte limit and no OPT ──────────────

#[test]
fn non_edns_query_gets_at_most_512_and_no_opt() {
    let (zones, trie, ecs) = setup();
    let query = build_query(0x1008, ORIGIN, 16);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::Udp512);

    assert!(
        resp.len() <= 512,
        "a non-EDNS query must fit the 512-byte limit, got {}",
        resp.len()
    );
    assert!(flag_tc(&resp), "the answer does not fit in 512");
    assert!(
        parse_opt(&resp).is_none(),
        "a non-EDNS query must not receive an OPT record"
    );
    assert_eq!(response_arcount(&resp), 0);
}

// ── Case 5b: stream transports do not inherit the UDP budget ───────────────

#[test]
fn stream_transports_use_the_65535_budget_not_the_udp_budget() {
    let (zones, trie, ecs) = setup();
    // The client advertised 512, which would truncate on UDP.
    let query = build_query_with_edns(0x1010, ORIGIN, 16, 512, 0, false);

    let udp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(512));
    assert!(flag_tc(&udp), "the UDP response is truncated");

    let stream = respond(&zones, &trie, &ecs, &query, TransportClass::Tcp);
    assert!(
        !flag_tc(&stream),
        "a stream transport must not inherit the client's UDP budget"
    );
    assert!(
        stream.len() > 512,
        "the full answer exceeds 512 and is delivered on a stream, got {}",
        stream.len()
    );
    let opt = parse_opt(&stream).expect("the stream response still echoes EDNS");
    assert_eq!(opt.payload, 512, "the OPT describes the client's UDP size");
}

// ── Case 6: an unsupported EDNS version is BADVERS, not an answer ───────────

#[test]
fn edns_version_1_receives_badvers_with_an_opt_and_no_answer() {
    let (zones, trie, ecs) = setup();
    let query = build_query_with_edns(0x1009, "www.example.com", 1, 4096, 1, false);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(4096));

    let opt = parse_opt(&resp).expect("BADVERS must carry an OPT record");
    assert_eq!(
        opt.extended_rcode(response_rcode(&resp)),
        16,
        "the 12-bit extended RCODE must be BADVERS (16): header 0, OPT high byte 1"
    );
    assert_eq!(
        response_rcode(&resp),
        0,
        "the header RCODE is 0 for BADVERS"
    );
    assert_eq!(opt.ext_rcode, 1, "OPT TTL high byte carries 16 >> 4");
    assert_eq!(response_ancount(&resp), 0, "the question is not answered");
    assert_eq!(response_qdcount(&resp), 1, "the question is still echoed");
    assert_eq!(response_question(&resp).as_deref(), Some("www.example.com"));
}

// ── Case 7: a second OPT is a FORMERR ───────────────────────────────────────

#[test]
fn two_opt_records_receive_formerr() {
    let (zones, trie, ecs) = setup();
    let query = build_query_with_edns_options(0x100A, "www.example.com", 1, 4096, 0, false, 2);
    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::UdpEdns(4096));

    assert_eq!(
        response_rcode(&resp),
        1,
        "RFC 6891 §6.1.1: more than one OPT is a FORMERR"
    );
    assert_eq!(response_qdcount(&resp), 1);
    assert_eq!(response_question(&resp).as_deref(), Some("www.example.com"));
    assert_eq!(response_ancount(&resp), 0, "a FORMERR answers nothing");
}

// ── Case 8: ARCOUNT=0 means no EDNS, whatever follows the question ──────────

#[test]
fn opt_shaped_bytes_with_arcount_zero_are_not_edns() {
    let (zones, trie, ecs) = setup();
    let mut query = build_query_with_edns_options(0x100B, "www.example.com", 1, 4096, 0, true, 1);
    // Keep the OPT-shaped bytes but deny their existence in the header.
    query[10..12].copy_from_slice(&0u16.to_be_bytes());

    let resp = respond(&zones, &trie, &ecs, &query, TransportClass::Udp512);

    assert!(
        parse_opt(&resp).is_none(),
        "trailing OPT-shaped bytes with ARCOUNT=0 are not an EDNS request"
    );
    assert_eq!(
        response_arcount(&resp),
        0,
        "no OPT is emitted for a non-EDNS query"
    );
    assert_eq!(
        response_ancount(&resp),
        1,
        "the query is still answered as a plain DNS query"
    );
}

// ── Case 9: every error builder counts the questions it wrote ───────────────

#[test]
fn error_responses_agree_with_the_question_they_write() {
    let (zones, trie, ecs) = setup();
    let query = build_query(0x100C, "www.example.com", 1);

    for rcode in [RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NOTIMP, RCODE_REFUSED] {
        let resp = build_error_response(&query, rcode).expect("a 12-byte header is enough");
        assert_eq!(response_rcode(&resp), rcode);
        assert_eq!(
            response_qdcount(&resp),
            1,
            "QDCOUNT must be 1 when the question is copied (rcode {rcode})"
        );
        assert_eq!(
            response_question(&resp).as_deref(),
            Some("www.example.com"),
            "the error response must echo the parsed question (rcode {rcode})"
        );
        assert_eq!(response_ancount(&resp), 0);
    }

    // The live REFUSED path (no zone covers the name) uses the same rule.
    let outside = build_query(0x100D, "outside.example.org", 1);
    let resp = respond(&zones, &trie, &ecs, &outside, TransportClass::Udp512);
    assert_eq!(response_rcode(&resp), RCODE_REFUSED);
    assert_eq!(response_qdcount(&resp), 1);
    assert_eq!(
        response_question(&resp).as_deref(),
        Some("outside.example.org")
    );
}

// ── Case 10: a truncated question never panics and is never half-copied ─────

#[test]
fn build_error_response_on_a_truncated_question_does_not_panic() {
    let query = build_query(0x100E, "example.com", 1);

    // Header plus a label that claims more bytes than are present.
    let truncated = &query[..15];
    let resp = build_error_response(truncated, RCODE_FORMERR).expect("the header is intact");
    assert_eq!(
        response_qdcount(&resp),
        0,
        "a question that does not parse is not written"
    );
    assert_eq!(resp.len(), 12, "no partial question bytes may follow");

    // A complete name with no QTYPE/QCLASS is equally unrepresentable.
    let no_type = &query[..query.len() - 2];
    let resp = build_error_response(no_type, RCODE_FORMERR).expect("the header is intact");
    assert_eq!(response_qdcount(&resp), 0);
    assert_eq!(resp.len(), 12);

    // Compression pointers are not allowed in a question name.
    let mut compressed = query.clone();
    compressed[12] = 0xC0;
    compressed[13] = 0x0C;
    let resp = build_error_response(&compressed, RCODE_FORMERR).expect("the header is intact");
    assert_eq!(response_qdcount(&resp), 0);
    assert_eq!(resp.len(), 12);
}
