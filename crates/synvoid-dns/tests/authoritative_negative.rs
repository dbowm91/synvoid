use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::RecordType;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, QueryContext, ShardedZoneStore, Zone};
use synvoid_dns::zone_trie::ZoneTrie;

/// Build a raw DNS query in wire format.
fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 256 + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    if qname.is_empty() || qname == "." {
        q.push(0);
    } else {
        for label in qname.split('.').filter(|s| !s.is_empty()) {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
    }

    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN

    q
}

/// Build the test zone: test.local with standard records.
fn build_test_zone() -> Zone {
    let mut zone = Zone::new("test.local".to_string());
    zone.serial = 2026070201;
    zone.nsec_enabled = false;
    zone.nsec3_enabled = false;

    zone.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns1.test.local. admin.test.local. 2026070201 3600 600 604800 300".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("@".to_string(), RecordType::NS),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NS,
            value: "ns1.test.local.".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("ns1".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "ns1".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.53".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("alias".to_string(), RecordType::CNAME),
        vec![DnsZoneRecord {
            name: "alias".to_string(),
            record_type: RecordType::CNAME,
            value: "www.test.local.".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("_txt".to_string(), RecordType::TXT),
        vec![DnsZoneRecord {
            name: "_txt".to_string(),
            record_type: RecordType::TXT,
            value: "hello".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone
}

/// Set up the minimal QueryContext for testing.
///
/// Returns the Arc-wrapped stores so they outlive the context.
fn setup() -> (
    Arc<ShardedZoneStore>,
    Arc<RwLock<ZoneTrie>>,
    EcsFilterConfig,
) {
    let zone = build_test_zone();

    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone);

    let mut trie = ZoneTrie::new();
    trie.insert("test.local");
    let zone_trie = Arc::new(RwLock::new(trie));

    let ecs_config = EcsFilterConfig::default();

    (zones, zone_trie, ecs_config)
}

fn make_ctx<'a>(
    zones: &'a Arc<ShardedZoneStore>,
    zone_trie: &'a Arc<RwLock<ZoneTrie>>,
    ecs_filter_config: &'a EcsFilterConfig,
) -> QueryContext<'a> {
    QueryContext {
        zones,
        zone_trie,
        geoip_lookup: None,
        min_geo_ttl: 0,
        negative_cache_ttl: 300,
        cache: None,
        dnssec: None,
        signer_name: None,
        query_validator: None,
        firewall: None,
        connection_limits: None,
        max_idle_time: None,
        zone_transfer: None,
        ecs_filter_config,
        rate_limiter: None,
        rrl_enabled: false,
        update_handler: None,
        notify_handler: None,
        query_coalescer: None,
        dns64_translator: None,
        acme_dns_challenges: None,
        cookie_server: None,
        #[cfg(feature = "mesh")]
        mesh_registry: None,
    }
}

// ── Response parsing helpers ────────────────────────────────────────────

/// Skip past a DNS wire-format name (handles compression pointers).
/// Returns the byte position after the terminating zero/pointer.
fn skip_wire_name(resp: &[u8], start: usize) -> usize {
    let mut pos = start;
    while pos < resp.len() {
        let len = resp[pos] as usize;
        if len == 0 {
            return pos + 1;
        }
        // Compression pointer: top 2 bits are 11
        if (len & 0xC0) == 0xC0 {
            return pos + 2;
        }
        pos += 1 + len;
    }
    pos
}

/// Skip past the question section in a DNS response.
/// Returns the byte offset of the first answer record (after the header).
fn skip_question_section(resp: &[u8]) -> usize {
    let mut pos = 12; // skip header
    pos = skip_wire_name(resp, pos);
    pos += 4; // qtype + qclass
    pos
}

/// Find the first answer record's type field in the response.
/// Returns the u16 record type of the first answer record, or None if absent.
fn first_answer_rr_type(resp: &[u8]) -> Option<u16> {
    let ancount = response_ancount(resp) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = skip_question_section(resp);
    // Skip answer record name
    pos = skip_wire_name(resp, pos);
    if pos + 10 > resp.len() {
        return None;
    }
    Some(u16::from_be_bytes([resp[pos], resp[pos + 1]]))
}

/// Parse the first answer record's A record RDATA as an Ipv4Addr.
fn first_answer_a_rdata(resp: &[u8]) -> Option<std::net::Ipv4Addr> {
    let ancount = response_ancount(resp) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = skip_question_section(resp);
    pos = skip_wire_name(resp, pos);
    if pos + 10 > resp.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
    let rdata_start = pos + 10;
    if rdata_start + rdlength > resp.len() {
        return None;
    }
    if rdlength != 4 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        resp[rdata_start],
        resp[rdata_start + 1],
        resp[rdata_start + 2],
        resp[rdata_start + 3],
    ))
}

/// Parse the first answer record's CNAME RDATA as a label-encoded name string.
fn first_answer_cname_rdata(resp: &[u8]) -> Option<String> {
    let ancount = response_ancount(resp) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = skip_question_section(resp);
    pos = skip_wire_name(resp, pos);
    if pos + 10 > resp.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
    let rdata_start = pos + 10;
    if rdata_start + rdlength > resp.len() {
        return None;
    }
    // Decode the CNAME wire-format name from rdata
    decode_wire_name(resp, rdata_start)
}

/// Decode a wire-format DNS name starting at `start` into a dotted string.
fn decode_wire_name(resp: &[u8], start: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut jump_pos = None;
    let max_jumps = 10; // safety limit

    for _ in 0..max_jumps {
        if pos >= resp.len() {
            return None;
        }
        let len = resp[pos] as usize;
        if len == 0 {
            if !jumped {
                jump_pos = Some(pos + 1);
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer
            if pos + 1 >= resp.len() {
                return None;
            }
            let offset = ((len & 0x3F) as usize) << 8 | resp[pos + 1] as usize;
            if !jumped {
                jump_pos = Some(pos + 2);
            }
            pos = offset;
            jumped = true;
            continue;
        }
        pos += 1;
        if pos + len > resp.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&resp[pos..pos + len]).to_string());
        pos += len;
    }

    let _ = jump_pos; // We don't need the return position for now
    Some(parts.join("."))
}

fn response_id(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[0], resp[1]])
}

fn response_flags(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[2], resp[3]])
}

fn response_rcode(resp: &[u8]) -> u8 {
    (response_flags(resp) & 0x000F) as u8
}

fn response_qdcount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[4], resp[5]])
}

fn response_ancount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

fn response_nscount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[8], resp[9]])
}

fn response_arcount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[10], resp[11]])
}

fn is_authoritative(resp: &[u8]) -> bool {
    response_flags(resp) & 0x0400 != 0
}

fn is_response(resp: &[u8]) -> bool {
    response_flags(resp) & 0x8000 != 0
}

// ── RCODE constants ────────────────────────────────────────────────────

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

// ── Tests ──────────────────────────────────────────────────────────────

/// Test 1: Query for a name with no matching zone returns REFUSED (RCODE=5).
///
/// The trie only contains "test.local", so querying "nonexistent.example.com"
/// should yield REFUSED.
#[test]
fn no_matching_zone_returns_refused() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0xAAAA, "nonexistent.example.com", 1); // A record
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for valid query");

    assert!(is_response(&resp), "response bit must be set");
    assert!(is_authoritative(&resp), "AA bit must be set");
    assert_eq!(response_id(&resp), 0xAAAA, "query ID must be preserved");
    assert_eq!(
        response_rcode(&resp),
        RCODE_REFUSED,
        "RCODE must be REFUSED (5) for unknown zone"
    );
    assert_eq!(
        response_qdcount(&resp),
        1,
        "question section must be echoed"
    );
    assert_eq!(
        response_ancount(&resp),
        0,
        "answer count must be 0 for REFUSED"
    );
}

/// Test 2: Query for a CNAME loop returns REFUSED (RCODE=5).
///
/// A CNAME record pointing to itself is detected as a loop and the server
/// returns REFUSED rather than generating a response.
#[test]
fn cname_loop_returns_refused() {
    let (zones, zone_trie, ecs_filter_config) = setup();

    // Add a self-referencing CNAME record for "loop.test.local"
    zones.update_zone("test.local", |zone| {
        zone.records.insert(
            ("loop".to_string(), RecordType::CNAME),
            vec![DnsZoneRecord {
                name: "loop".to_string(),
                record_type: RecordType::CNAME,
                value: "loop.test.local.".to_string(),
                ttl: 300,
                priority: None,
            }],
        );
    });

    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // Query type A — triggers CNAME path (qtype == A)
    let query = build_query(0xBBBB, "loop.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for CNAME loop");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0xBBBB);
    assert_eq!(
        response_rcode(&resp),
        RCODE_REFUSED,
        "CNAME loop must return REFUSED (RCODE=5)"
    );
    assert_eq!(
        response_ancount(&resp),
        0,
        "answer count must be 0 for REFUSED"
    );
}

/// Test 3: Positive query for an existing A record returns NOERROR with answer.
///
/// Querying "www.test.local" type A should return the A record 192.0.2.10.
#[test]
fn positive_a_record_returns_noerror_with_answer() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0x1111, "www.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for existing record");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0x1111);
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "RCODE must be NOERROR for existing record"
    );
    assert_eq!(
        response_ancount(&resp),
        1,
        "must have exactly 1 answer record"
    );
    assert_eq!(
        response_qdcount(&resp),
        1,
        "question section must be present"
    );

    // Verify the answer contains the expected A record
    let rr_type = first_answer_rr_type(&resp).expect("answer record must exist");
    assert_eq!(rr_type, 1, "answer record type must be A (1)");

    let ip = first_answer_a_rdata(&resp).expect("A record RDATA must be present");
    assert_eq!(
        ip,
        std::net::Ipv4Addr::new(192, 0, 2, 10),
        "A record must contain 192.0.2.10"
    );
}

/// Test 4: Query for an existing name but wrong type returns NODATA with SOA in authority.
///
/// "www.test.local" has an A record but no MX record. Querying type MX should
/// return NOERROR with 0 answers and SOA in the authority section.
#[test]
fn existing_name_wrong_type_returns_nodata_with_soa() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // MX = 15
    let query = build_query(0x2222, "www.test.local", 15);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for NODATA");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0x2222);
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "RCODE must be NOERROR for NODATA"
    );
    assert_eq!(
        response_ancount(&resp),
        0,
        "answer count must be 0 for NODATA"
    );
    assert!(
        response_nscount(&resp) >= 1,
        "authority section must contain at least SOA record"
    );

    // Verify the authority section contains a SOA record.
    let mut pos = skip_question_section(&resp);
    // Skip answer records (ancount = 0)
    // Now at authority section: look for SOA (type 6)
    let nscount = response_nscount(&resp) as usize;
    let mut found_soa = false;
    for _ in 0..nscount {
        pos = skip_wire_name(&resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        if rr_type == 6 {
            found_soa = true;
        }
        pos += 10 + rdlength;
    }

    assert!(found_soa, "authority section must contain SOA record");
}

/// Test 5: Query for a non-existent name under the zone returns NXDOMAIN with SOA in authority.
///
/// "nonexistent.test.local" does not exist. Querying it should return NXDOMAIN
/// with SOA in the authority section per RFC 2308.
#[test]
fn nonexistent_name_returns_nxdomain_with_soa() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0x3333, "nonexistent.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for NXDOMAIN");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0x3333);
    assert_eq!(
        response_rcode(&resp),
        RCODE_NXDOMAIN,
        "RCODE must be NXDOMAIN (3)"
    );
    assert_eq!(
        response_ancount(&resp),
        0,
        "answer count must be 0 for NXDOMAIN"
    );
    assert!(
        response_nscount(&resp) >= 1,
        "authority section must contain at least SOA record"
    );

    // Verify SOA in authority section
    let mut pos = skip_question_section(&resp);
    // Skip answer records (ancount = 0)

    let nscount = response_nscount(&resp) as usize;
    let mut found_soa = false;
    for _ in 0..nscount {
        pos = skip_wire_name(&resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        if rr_type == 6 {
            found_soa = true;
        }
        pos += 10 + rdlength;
    }

    assert!(
        found_soa,
        "NXDOMAIN authority section must contain SOA record"
    );
}

/// Test 6: CNAME resolution returns the target's A record.
///
/// "alias.test.local" has a CNAME to "www.test.local", which has A 192.0.2.10.
/// Querying alias for type A should resolve through the CNAME.
#[test]
fn cname_resolution_returns_target_a_record() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0x4444, "alias.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for CNAME resolution");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0x4444);
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "RCODE must be NOERROR for CNAME resolution"
    );
    assert_eq!(
        response_ancount(&resp),
        1,
        "answer count must be 1 (CNAME record)"
    );

    // Verify the answer is a CNAME record (type 5)
    let rr_type = first_answer_rr_type(&resp).expect("answer record must exist");
    assert_eq!(rr_type, 5, "answer record type must be CNAME (5)");

    // Verify the CNAME target
    let cname = first_answer_cname_rdata(&resp).expect("CNAME RDATA must be present");
    assert_eq!(
        cname, "www.test.local",
        "CNAME target must be www.test.local"
    );
}

/// Test 7: Query for the zone origin returns the SOA record.
///
/// Querying "test.local" type SOA should return the SOA record.
#[test]
fn zone_origin_soa_query_returns_soa() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0x5555, "test.local", 6); // SOA = 6
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for SOA query");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0x5555);
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "RCODE must be NOERROR for SOA query"
    );
    assert_eq!(
        response_ancount(&resp),
        1,
        "answer count must be 1 (SOA record)"
    );

    // Verify the answer is a SOA record (type 6)
    let rr_type = first_answer_rr_type(&resp).expect("answer record must exist");
    assert_eq!(rr_type, 6, "answer record type must be SOA (6)");
}

/// Test 8: TXT record query returns NOERROR with TXT answer.
#[test]
fn txt_record_query_returns_noerror() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0x6666, "_txt.test.local", 16); // TXT = 16
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for TXT query");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0x6666);
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "RCODE must be NOERROR for TXT query"
    );
    assert_eq!(
        response_ancount(&resp),
        1,
        "answer count must be 1 (TXT record)"
    );

    // Verify the answer is a TXT record (type 16)
    let rr_type = first_answer_rr_type(&resp).expect("answer record must exist");
    assert_eq!(rr_type, 16, "answer record type must be TXT (16)");

    // Verify TXT RDATA contains "hello"
    let ancount = response_ancount(&resp) as usize;
    assert!(ancount >= 1);
    let mut pos = skip_question_section(&resp);
    pos = skip_wire_name(&resp, pos); // skip owner name
                                      // type(2) + class(2) + ttl(4) + rdlength(2)
    pos += 10;
    if pos < resp.len() {
        let chunk_len = resp[pos] as usize;
        assert_eq!(
            chunk_len, 5,
            "TXT first chunk length must be 5 (len of 'hello')"
        );
        assert_eq!(
            &resp[pos + 1..pos + 1 + chunk_len],
            b"hello",
            "TXT content must be 'hello'"
        );
    }
}

/// Test 9: NS record query for the zone origin returns NOERROR.
#[test]
fn ns_record_query_returns_noerror() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0x7777, "test.local", 2); // NS = 2
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for NS query");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0x7777);
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "RCODE must be NOERROR for NS query"
    );
    assert_eq!(
        response_ancount(&resp),
        1,
        "answer count must be 1 (NS record)"
    );

    // Verify the answer is an NS record (type 2)
    let rr_type = first_answer_rr_type(&resp).expect("answer record must exist");
    assert_eq!(rr_type, 2, "answer record type must be NS (2)");
}

/// Test 10: Query for the zone origin A record returns NODATA (origin has no direct A).
///
/// "test.local" has SOA and NS but no A record at the origin. Querying type A
/// should return NOERROR with SOA in authority (NODATA).
#[test]
fn zone_origin_a_query_returns_nodata() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0x8888, "test.local", 1); // A = 1
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for NODATA");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_id(&resp), 0x8888);
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "RCODE must be NOERROR for NODATA"
    );
    assert_eq!(
        response_ancount(&resp),
        0,
        "answer count must be 0 for NODATA"
    );
    assert!(
        response_nscount(&resp) >= 1,
        "authority section must contain SOA"
    );
}

/// Test 11: Query ID is always preserved in responses.
#[test]
fn query_id_preserved_in_all_responses() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let test_ids: Vec<u16> = vec![0x0001, 0x1234, 0xABCD, 0xFEED, 0xFFFF];
    for id in &test_ids {
        let query = build_query(*id, "www.test.local", 1);
        let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
            .expect("handle_query should return Some");
        assert_eq!(
            response_id(&resp),
            *id,
            "query ID {} must be preserved in response",
            id
        );
    }
}

/// Test 12: REFUSED response for a completely unrelated domain.
#[test]
fn unrelated_domain_returns_refused() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0x9999, "google.com", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for REFUSED");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_REFUSED);
    assert_eq!(response_ancount(&resp), 0);
}

/// Test 13: Subdomain query for a name under the zone but not in records
/// returns NXDOMAIN.
#[test]
fn subdomain_not_in_records_returns_nxdomain() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0xAAAA, "deep.sub.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(
        response_rcode(&resp),
        RCODE_NXDOMAIN,
        "RCODE must be NXDOMAIN for non-existent subdomain"
    );
    assert_eq!(response_ancount(&resp), 0);
    assert!(
        response_nscount(&resp) >= 1,
        "authority section must contain SOA"
    );
}

// ── Phase D tests ────────────────────────────────────────────────────────

/// Phase D: Negative response section counts match emitted authority records.
///
/// NSCOUNT in the header must exactly equal the number of authority RRs
/// written to the wire. We verify this for both NODATA and NXDOMAIN.
#[test]
fn nodata_nscount_matches_authority_records() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // www exists but has no MX → NODATA
    let query = build_query(0xD1A0, "www.test.local", 15); // MX
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    let nscount = response_nscount(&resp) as usize;
    assert!(nscount >= 1, "NSCOUNT must be ≥1 for NODATA (SOA)");

    // Walk the authority section and count actual RRs
    let mut pos = skip_question_section(&resp);
    // Skip answer records
    for _ in 0..response_ancount(&resp) as usize {
        pos = skip_wire_name(&resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10 + rdlen;
    }
    let mut actual_authority = 0usize;
    for _ in 0..nscount {
        pos = skip_wire_name(&resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10 + rdlen;
        actual_authority += 1;
    }
    assert_eq!(
        nscount, actual_authority,
        "NSCOUNT must equal number of authority RRs on the wire"
    );
}

#[test]
fn nxdomain_nscount_matches_authority_records() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // nonexistent.test.local does not exist → NXDOMAIN
    let query = build_query(0xD1A1, "nonexistent.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    let nscount = response_nscount(&resp) as usize;
    assert!(nscount >= 1, "NSCOUNT must be ≥1 for NXDOMAIN (SOA)");

    let mut pos = skip_question_section(&resp);
    for _ in 0..response_ancount(&resp) as usize {
        pos = skip_wire_name(&resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10 + rdlen;
    }
    let mut actual_authority = 0usize;
    for _ in 0..nscount {
        pos = skip_wire_name(&resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10 + rdlen;
        actual_authority += 1;
    }
    assert_eq!(
        nscount, actual_authority,
        "NSCOUNT must equal number of authority RRs on the wire"
    );
}

/// Phase D: Negative response TTL policy is deterministic.
///
/// The negative cache TTL is taken from ctx.negative_cache_ttl (300 in test setup).
/// Both NODATA and NXDOMAIN SOA authority records must carry a TTL equal to
/// the SOA minimum, which the zone defines as 300.
#[test]
fn negative_response_ttl_is_deterministic() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // NODATA: www exists, MX absent
    let query_nodata = build_query(0xD1A2, "www.test.local", 15);
    let resp_nodata =
        DnsServer::handle_query(&ctx, &query_nodata, Some(IpAddr::from([127, 0, 0, 1])))
            .expect("handle_query should return Some for NODATA");

    // NXDOMAIN: nonexistent name
    let query_nxdomain = build_query(0xD1A3, "nonexistent.test.local", 1);
    let resp_nxdomain =
        DnsServer::handle_query(&ctx, &query_nxdomain, Some(IpAddr::from([127, 0, 0, 1])))
            .expect("handle_query should return Some for NXDOMAIN");

    // Verify SOA TTL is present and deterministic for both
    for (label, resp) in [("NODATA", &resp_nodata), ("NXDOMAIN", &resp_nxdomain)] {
        let nscount = response_nscount(&resp) as usize;
        let mut pos = skip_question_section(&resp);
        // skip answers
        for _ in 0..response_ancount(&resp) as usize {
            pos = skip_wire_name(&resp, pos);
            if pos + 10 > resp.len() {
                break;
            }
            let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }
        for _ in 0..nscount {
            pos = skip_wire_name(&resp, pos);
            if pos + 10 > resp.len() {
                break;
            }
            let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
            let ttl =
                u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
            let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10 + rdlen;

            if rr_type == 6 {
                // SOA record: TTL must be the SOA minimum (300 in test zone)
                assert_eq!(
                    ttl, 300,
                    "{}: SOA authority TTL must be deterministic (expected 300, got {})",
                    label, ttl
                );
            }
        }
    }
}

/// Phase D: `.example` does not receive synthetic NXDOMAIN treatment in production.
///
/// When no zone for `.example` is loaded, querying `foo.example` returns
/// REFUSED (no matching zone), not a synthetic NXDOMAIN. This confirms the
/// `.example` shortcut was removed from the production query flow.
#[test]
fn example_domain_not_loaded_returns_refused_not_synthetic_nxdomain() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // foo.example has no zone loaded → should be REFUSED, not NXDOMAIN
    let query = build_query(0xD1A4, "foo.example", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(
        response_rcode(&resp),
        RCODE_REFUSED,
        " unloaded .example must return REFUSED (5), not synthetic NXDOMAIN (3)"
    );
    assert_eq!(response_ancount(&resp), 0);
}

/// Phase D: `.example` receives proper treatment when a test zone IS loaded.
///
/// Loading a zone for `example` allows normal NXDOMAIN/NODATA for names
/// under that zone, confirming the zone-based path works.
#[test]
fn example_domain_with_loaded_zone_returns_nxdomain() {
    let (zones, zone_trie, ecs_filter_config) = setup();

    // Insert a zone for "example" with SOA
    let mut example_zone = Zone::new("example".to_string());
    example_zone.serial = 2026070301;
    example_zone.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns1.example. admin.example. 2026070301 3600 600 604800 300".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    example_zone.records.insert(
        ("@".to_string(), RecordType::NS),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NS,
            value: "ns1.example.".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zones.insert("example".to_string(), example_zone);
    zone_trie.write().insert("example");

    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // nonexistent.example → NXDOMAIN with SOA (zone is loaded)
    let query = build_query(0xD1A5, "nonexistent.example", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(
        response_rcode(&resp),
        RCODE_NXDOMAIN,
        "loaded .example zone must return NXDOMAIN (3) for missing names"
    );
    assert_eq!(response_ancount(&resp), 0);
    assert!(
        response_nscount(&resp) >= 1,
        "authority section must contain SOA"
    );
}

/// Phase D: CNAME owner queried for A returns CNAME (not NODATA/NXDOMAIN).
///
/// "alias.test.local" has a CNAME record. Querying it for type A should
/// return the CNAME record in the answer section.
#[test]
fn cname_owner_queried_for_a_returns_cname() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_query(0xD1A6, "alias.test.local", 1); // A record
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_response(&resp));
    assert!(is_authoritative(&resp));
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "CNAME owner queried for A must return NOERROR"
    );
    assert_eq!(
        response_ancount(&resp),
        1,
        "answer count must be 1 (CNAME record)"
    );

    let rr_type = first_answer_rr_type(&resp).expect("answer record must exist");
    assert_eq!(rr_type, 5, "answer record type must be CNAME (5)");

    let cname = first_answer_cname_rdata(&resp).expect("CNAME RDATA must be present");
    assert_eq!(
        cname, "www.test.local",
        "CNAME target must be www.test.local"
    );
}
