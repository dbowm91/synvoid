//! Authoritative completeness: wildcards, referrals, empty non-terminals,
//! DNAME, the single zone-state writer, and the `Arc<Zone>` snapshot API
//! (phase 09, R1-R4).
//!
//! Every assertion is read from the **wire** bytes the server produced, not
//! from internal state, except where the case is explicitly about the store
//! (`Arc::ptr_eq`, the record map the writer installed).

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::runtime_config::{ZoneRecordSpec, ZoneSpec};
use synvoid_dns::server::{
    DnsServer, DnsZoneRecord, RecordType, SerialPolicy, ShardedZoneStore, Zone,
};
use synvoid_dns::store::ZoneStore;
use synvoid_dns::zone_file::parse_zone_content;
use synvoid_dns::zone_trie::ZoneTrie;

use support::context::make_ctx;
use support::query::build_query;
use support::response::*;

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn record(name: &str, record_type: RecordType, value: &str, ttl: u32) -> DnsZoneRecord {
    DnsZoneRecord {
        name: name.to_string(),
        record_type,
        value: value.to_string(),
        ttl,
        priority: None,
    }
}

fn insert(zone: &mut Zone, name: &str, record_type: RecordType, value: &str) {
    zone.records
        .entry((name.to_string(), record_type))
        .or_default()
        .push(record(name, record_type, value, 300));
}

fn insert_ttl(zone: &mut Zone, name: &str, record_type: RecordType, value: &str, ttl: u32) {
    zone.records
        .entry((name.to_string(), record_type))
        .or_default()
        .push(record(name, record_type, value, ttl));
}

/// A minimal valid zone: apex SOA + NS and the nameserver's address.
fn base_zone(origin: &str) -> Zone {
    let mut zone = Zone::new(origin.to_string());
    zone.serial = 1;
    insert(
        &mut zone,
        "@",
        RecordType::SOA,
        &format!("ns1.{origin}. hostmaster.{origin}. 1 3600 600 604800 300"),
    );
    insert(&mut zone, "@", RecordType::NS, &format!("ns1.{origin}."));
    insert(&mut zone, "ns1", RecordType::A, "192.0.2.1");
    zone
}

struct Fixture {
    zones: Arc<ShardedZoneStore>,
    trie: Arc<RwLock<ZoneTrie>>,
    ecs: EcsFilterConfig,
}

impl Fixture {
    fn publish(zone: Zone) -> Self {
        let origin = zone.origin.clone();
        let zones = Arc::new(ShardedZoneStore::new());
        zones.insert(origin.clone(), zone);
        let mut trie = ZoneTrie::new();
        trie.insert(&origin);
        Self {
            zones,
            trie: Arc::new(RwLock::new(trie)),
            ecs: EcsFilterConfig::default(),
        }
    }

    fn respond(&self, qname: &str, qtype: RecordType) -> Vec<u8> {
        let ctx = make_ctx(&self.zones, &self.trie, &self.ecs);
        DnsServer::handle_query(
            &ctx,
            &build_query(0x0909, qname, u16::from(qtype)),
            Some(IpAddr::from([127, 0, 0, 1])),
        )
        .expect("a well-formed query must be answered")
        .as_ref()
        .clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct WireRr {
    owner: String,
    rtype: u16,
    ttl: u32,
    rdata: Vec<u8>,
    rdata_offset: usize,
}

/// `(answer, authority, additional)` records, decoded from the wire.
fn sections(resp: &[u8]) -> (Vec<WireRr>, Vec<WireRr>, Vec<WireRr>) {
    let counts = [
        response_ancount(resp),
        response_nscount(resp),
        response_arcount(resp),
    ];
    let mut pos = 12;
    pos = skip_wire_name(resp, pos);
    pos += 4; // QTYPE + QCLASS

    let mut out: (Vec<WireRr>, Vec<WireRr>, Vec<WireRr>) = (Vec::new(), Vec::new(), Vec::new());
    for (section, count) in counts.iter().enumerate() {
        for _ in 0..*count {
            let owner = read_wire_name(resp, pos).unwrap_or_default();
            pos = skip_wire_name(resp, pos);
            assert!(pos + 10 <= resp.len(), "truncated record header");
            let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
            let ttl =
                u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
            let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            let rdata_offset = pos + 10;
            assert!(rdata_offset + rdlen <= resp.len(), "truncated RDATA");
            let rr = WireRr {
                owner,
                rtype,
                ttl,
                rdata: resp[rdata_offset..rdata_offset + rdlen].to_vec(),
                rdata_offset,
            };
            match section {
                0 => out.0.push(rr),
                1 => out.1.push(rr),
                _ => out.2.push(rr),
            }
            pos = rdata_offset + rdlen;
        }
    }
    out
}

fn rdata_name(resp: &[u8], rr: &WireRr) -> String {
    read_wire_name(resp, rr.rdata_offset).expect("RDATA name must decode")
}

/// Assert a NOERROR answer with no RRset and a SOA proving the empty answer.
fn assert_nodata(resp: &[u8], qname: &str) {
    assert_eq!(
        response_rcode(resp),
        RCODE_NOERROR,
        "{qname}: a name that exists must not be a name error"
    );
    assert_eq!(
        response_ancount(resp),
        0,
        "{qname}: NODATA has no answer RRset"
    );
    let (_, authority, _) = sections(resp);
    assert!(
        authority
            .iter()
            .any(|rr| rr.rtype == u16::from(RecordType::SOA)),
        "{qname}: NODATA must carry the SOA for negative caching"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. RFC 4592 §2.2.1: the wildcard matrix
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rfc4592_2_2_1_matrix() {
    let mut zone = base_zone("example");
    insert(&mut zone, "*", RecordType::TXT, "this is a wildcard");
    insert_ttl(&mut zone, "*", RecordType::MX, "host1.example.", 300);
    zone.records
        .get_mut(&("*".to_string(), RecordType::MX))
        .unwrap()[0]
        .priority = Some(10);
    insert(
        &mut zone,
        "sub.*",
        RecordType::TXT,
        "this is not a wildcard",
    );
    insert(&mut zone, "host1", RecordType::A, "192.0.2.1");
    // `_tcp.host1` exists as an empty non-terminal because a name below it
    // does; `_tcp.host2` likewise.
    insert(&mut zone, "_ssh._tcp.host1", RecordType::TXT, "srv1");
    insert(&mut zone, "_ssh._tcp.host2", RecordType::TXT, "srv2");
    // `b.example` is an empty non-terminal, so the apex wildcard cannot match
    // a name below it: `a.b.example` sees `*.b.example`, which does not exist.
    insert(&mut zone, "x.b", RecordType::A, "192.0.2.11");
    insert(&mut zone, "subdel", RecordType::NS, "ns.example.");
    let fixture = Fixture::publish(zone);
    let resp = |name: &str, qtype: RecordType| fixture.respond(name, qtype);

    // A wildcard answers a name one label below the closest encloser.
    let wildcard = resp("host3.example", RecordType::MX);
    assert_eq!(response_rcode(&wildcard), RCODE_NOERROR);
    assert_eq!(response_ancount(&wildcard), 1);
    let (answers, _, _) = sections(&wildcard);
    assert_eq!(answers[0].owner, "host3.example");
    assert_eq!(answers[0].rtype, u16::from(RecordType::MX));

    // ...and a name several labels below, when no closer name exists.
    let deep_wildcard = resp("foo.bar.example", RecordType::TXT);
    assert_eq!(response_rcode(&deep_wildcard), RCODE_NOERROR);
    assert_eq!(response_ancount(&deep_wildcard), 1);
    assert_eq!(sections(&deep_wildcard).0[0].owner, "foo.bar.example");

    // The wildcard's other RRset does not exist, so this is NODATA.
    assert_nodata(&resp("host3.example", RecordType::A), "host3.example");

    // An existing owner is never answered by the wildcard.
    assert_nodata(&resp("host1.example", RecordType::MX), "host1.example");

    // A literal subdomain of the wildcard owner is an owner itself.
    assert_nodata(&resp("sub.*.example", RecordType::MX), "sub.*.example");

    // `_tcp.host1.example` is an empty non-terminal, so the wildcard at the
    // apex is not consulted for a name below it (RFC 4592 §2.2.1/§2.2.2).
    // The qname itself does not exist, so the answer is a name error — never
    // a wildcard synthesis.
    let ent_blocks = resp("_telnet._tcp.host1.example", RecordType::TXT);
    assert_eq!(
        response_ancount(&ent_blocks),
        0,
        "the apex wildcard must not synthesize below an empty non-terminal"
    );
    assert_eq!(
        response_rcode(&ent_blocks),
        RCODE_NXDOMAIN,
        "the qname itself does not exist"
    );

    // The plan's explicit case: `*.example` matches `a.example` but not
    // `a.b.example` once `b.example` exists, and never `example` itself.
    // `a.b.example` itself does not exist (only its enclosing `b.example`
    // does), so the answer is a name error with no synthesized RRset.
    let below_closer = resp("a.b.example", RecordType::A);
    assert_eq!(
        response_ancount(&below_closer),
        0,
        "the apex wildcard must not match below a closer existing name"
    );
    assert_eq!(response_rcode(&below_closer), RCODE_NXDOMAIN);
    assert_nodata(&resp("example", RecordType::MX), "example");

    // A wildcard does not match names below itself ("ghost.*.example"): the
    // wildcard owner exists, so it also blocks its own subdomains.
    let below_wildcard = resp("ghost.*.example", RecordType::MX);
    assert_eq!(response_ancount(&below_wildcard), 0);
    assert_eq!(response_rcode(&below_wildcard), RCODE_NXDOMAIN);

    // A wildcard does not match at or below a delegation.
    let referral = resp("host.subdel.example", RecordType::A);
    assert_eq!(response_rcode(&referral), RCODE_NOERROR);
    assert!(!is_authoritative(&referral), "a referral is not AA");
    assert_eq!(response_ancount(&referral), 0);

    // The literal wildcard owner is queryable like any other owner.
    let literal = resp("*.example", RecordType::TXT);
    assert_eq!(response_rcode(&literal), RCODE_NOERROR);
    assert_eq!(response_ancount(&literal), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Wildcard CNAME synthesis, and no wildcard at a delegation point
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn wildcard_cname_and_delegation_boundary() {
    let mut zone = base_zone("example");
    insert(&mut zone, "*", RecordType::CNAME, "target.example.");
    insert(&mut zone, "target", RecordType::A, "192.0.2.20");
    insert(&mut zone, "child", RecordType::NS, "ns1.child.example.");
    insert(&mut zone, "ns1.child", RecordType::A, "192.0.2.53");
    let fixture = Fixture::publish(zone);

    // CNAME-at-wildcard: the synthesized owner is the qname.
    let resp = fixture.respond("anything.example", RecordType::A);
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    let (answers, _, _) = sections(&resp);
    assert_eq!(answers[0].owner, "anything.example");
    assert_eq!(answers[0].rtype, u16::from(RecordType::CNAME));
    assert_eq!(rdata_name(&resp, &answers[0]), "target.example");

    // The wildcard does not match at the delegation point...
    let at_cut = fixture.respond("child.example", RecordType::A);
    assert_eq!(response_rcode(&at_cut), RCODE_NOERROR);
    assert!(!is_authoritative(&at_cut));
    assert_eq!(response_ancount(&at_cut), 0);
    let (_, authority, _) = sections(&at_cut);
    assert!(authority
        .iter()
        .any(|rr| rr.rtype == u16::from(RecordType::NS) && rr.owner == "child.example"));

    // ...or below it: the parent never answers the child's names.
    let below_cut = fixture.respond("x.child.example", RecordType::A);
    assert_eq!(response_rcode(&below_cut), RCODE_NOERROR);
    assert!(!is_authoritative(&below_cut));
    assert_eq!(response_ancount(&below_cut), 0);

    // At the cut the parent is authoritative for the delegation NS RRset.
    let ns_at_cut = fixture.respond("child.example", RecordType::NS);
    assert!(is_authoritative(&ns_at_cut));
    assert_eq!(response_ancount(&ns_at_cut), 1);
    assert_eq!(sections(&ns_at_cut).0[0].rtype, u16::from(RecordType::NS));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Delegation referral: AA=0, NS in authority, glue in additional
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn delegation_referral_carries_ns_and_in_bailiwick_glue() {
    let mut zone = base_zone("example");
    insert(&mut zone, "child", RecordType::NS, "ns1.child.example.");
    insert(&mut zone, "child", RecordType::NS, "ns.elsewhere.test.");
    insert(&mut zone, "ns1.child", RecordType::A, "192.0.2.53");
    insert(&mut zone, "ns1.child", RecordType::AAAA, "2001:db8::53");
    // Child data the parent must not answer from its own zone.
    insert(&mut zone, "www.child", RecordType::A, "192.0.2.99");
    let fixture = Fixture::publish(zone);

    let resp = fixture.respond("www.child.example", RecordType::A);
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 0, "no answer below a zone cut");
    assert!(!is_authoritative(&resp), "a referral must clear AA");

    let (_, authority, additional) = sections(&resp);
    let ns: Vec<&WireRr> = authority
        .iter()
        .filter(|rr| rr.rtype == u16::from(RecordType::NS))
        .collect();
    assert_eq!(ns.len(), 2, "both delegation NS records are in authority");
    assert!(ns.iter().all(|rr| rr.owner == "child.example"));

    let glue_a: Vec<&WireRr> = additional
        .iter()
        .filter(|rr| rr.rtype == u16::from(RecordType::A))
        .collect();
    assert_eq!(glue_a.len(), 1, "one in-bailiwick A glue record");
    assert_eq!(glue_a[0].owner, "ns1.child.example");
    assert_eq!(glue_a[0].rdata, vec![192, 0, 2, 53]);
    assert!(
        !glue_a.iter().any(|rr| rr.rdata == vec![192, 0, 2, 99]),
        "the child's own data must never be answered by the parent"
    );

    let glue_aaaa: Vec<&WireRr> = additional
        .iter()
        .filter(|rr| rr.rtype == u16::from(RecordType::AAAA))
        .collect();
    assert_eq!(glue_aaaa.len(), 1, "one in-bailiwick AAAA glue record");
    assert_eq!(glue_aaaa[0].owner, "ns1.child.example");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Empty non-terminal
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_non_terminal_is_nodata_not_nxdomain() {
    let mut zone = base_zone("example");
    insert(&mut zone, "a.b", RecordType::A, "192.0.2.7");
    let fixture = Fixture::publish(zone);

    // `b.example` owns no RRset but exists because `a.b` does.
    assert_nodata(&fixture.respond("b.example", RecordType::A), "b.example");
    // The owner itself answers.
    let answer = fixture.respond("a.b.example", RecordType::A);
    assert_eq!(response_ancount(&answer), 1);
    // A sibling that exists nowhere is still a name error.
    assert_eq!(
        response_rcode(&fixture.respond("c.example", RecordType::A)),
        RCODE_NXDOMAIN
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. DNAME
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dname_at_an_ancestor_synthesizes_the_cname() {
    let mut zone = base_zone("example");
    insert(&mut zone, "alias", RecordType::DNAME, "target.example.net.");
    let fixture = Fixture::publish(zone);

    let resp = fixture.respond("host.sub.alias.example", RecordType::A);
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(
        response_ancount(&resp),
        2,
        "DNAME plus the synthesized CNAME"
    );
    let (answers, _, _) = sections(&resp);
    assert_eq!(answers[0].rtype, u16::from(RecordType::DNAME));
    assert_eq!(answers[0].owner, "alias.example");
    assert_eq!(answers[1].rtype, u16::from(RecordType::CNAME));
    assert_eq!(answers[1].owner, "host.sub.alias.example");
    assert_eq!(
        rdata_name(&resp, &answers[1]),
        "host.sub.target.example.net",
        "the prefix above the DNAME owner is preserved"
    );

    // A DNAME query at the owner is an ordinary exact answer.
    let at_owner = fixture.respond("alias.example", RecordType::DNAME);
    assert_eq!(response_ancount(&at_owner), 1);
    assert_eq!(sections(&at_owner).0[0].rtype, u16::from(RecordType::DNAME));

    // The DNAME does not redirect its own owner for another type.
    assert_nodata(
        &fixture.respond("alias.example", RecordType::A),
        "alias.example",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. The single writer: dedupe and one TTL per RRset
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn commit_records_deduplicates_and_normalizes_rrset_ttls() {
    let mut records = synvoid_dns::server::RecordMap::new();
    records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![record(
            "@",
            RecordType::SOA,
            "ns1.example. hostmaster.example. 5 3600 600 604800 300",
            300,
        )],
    );
    let key = ("www".to_string(), RecordType::A);
    records.insert(
        key.clone(),
        vec![
            record("www", RecordType::A, "192.0.2.1", 300),
            // Same RDATA: one record survives.
            record("www", RecordType::A, "192.0.2.1", 300),
            // Different RDATA, shorter TTL: the RRset keeps the smallest TTL.
            record("www", RecordType::A, "192.0.2.2", 60),
        ],
    );

    let mut zone = Zone::new("example".to_string());
    zone.commit_records(records, SerialPolicy::Keep)
        .expect("valid record set");
    let rrset = zone.records.get(&key).expect("www A RRset");
    assert_eq!(rrset.len(), 2, "the duplicate A record is gone");
    assert!(
        rrset.iter().all(|record| record.ttl == 60),
        "an RRset has one TTL, the smallest configured"
    );
    assert_eq!(rrset.iter().filter(|r| r.value == "192.0.2.1").count(), 1);

    // The same rule is visible on the wire.
    let fixture = Fixture::publish(zone);
    let resp = fixture.respond("www.example", RecordType::A);
    assert_eq!(response_ancount(&resp), 2);
    let (answers, _, _) = sections(&resp);
    assert!(answers.iter().all(|rr| rr.ttl == 60));
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. add_record normalization and TTL consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn add_record_normalizes_and_rejects_a_mixed_ttl() {
    let server = DnsServer::new(support::dns_runtime(), None, None);
    server
        .load_zones(vec![ZoneSpec {
            origin: "example.com".to_string(),
            records: vec![
                ZoneRecordSpec {
                    name: "@".to_string(),
                    record_type: RecordType::SOA,
                    ttl: Some(300),
                    value: "ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"
                        .to_string(),
                    priority: None,
                },
                ZoneRecordSpec {
                    name: "@".to_string(),
                    record_type: RecordType::NS,
                    ttl: Some(300),
                    value: "ns1.example.com.".to_string(),
                    priority: None,
                },
            ],
            dnssec: None,
        }])
        .expect("zone loads");

    server
        .add_record(
            "example.com",
            DnsZoneRecord {
                name: "WWW.Example.COM.".to_string(),
                record_type: RecordType::A,
                value: "192.0.2.7".to_string(),
                ttl: 60,
                priority: None,
            },
        )
        .expect("mixed-case FQDN is accepted and normalized");

    let stored = server.get_zones().get("example.com").expect("zone");
    assert!(
        stored
            .records
            .contains_key(&("www".to_string(), RecordType::A)),
        "the record is stored under the relative key the lookup uses"
    );

    let ctx = server.query_context();
    let resp = DnsServer::handle_query(
        &ctx,
        &build_query(0x0907, "www.example.com", 1),
        Some(IpAddr::from([127, 0, 0, 1])),
    )
    .expect("query answered")
    .as_ref()
    .clone();
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(sections(&resp).0[0].rdata, vec![192, 0, 2, 7]);

    // RFC 2181 §5.2: a record whose TTL disagrees with the RRset is refused.
    let error = server
        .add_record(
            "example.com",
            DnsZoneRecord {
                name: "www".to_string(),
                record_type: RecordType::A,
                value: "192.0.2.8".to_string(),
                ttl: 120,
                priority: None,
            },
        )
        .expect_err("a mixed-TTL RRset must be rejected");
    assert!(error.contains("TTL"), "unexpected error: {error}");

    // A name outside the zone is refused at the same boundary.
    assert!(server
        .add_record(
            "example.com",
            DnsZoneRecord {
                name: "www.other.test.".to_string(),
                record_type: RecordType::A,
                value: "192.0.2.9".to_string(),
                ttl: 60,
                priority: None,
            },
        )
        .is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Arc<Zone>: get() shares a pointer; history is not cloned
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn get_returns_a_shared_arc_and_history_is_shared_too() {
    let mut zone = base_zone("example");
    insert(&mut zone, "www", RecordType::A, "192.0.2.10");
    for _ in 0..200 {
        zone.increment_serial_with_limit(200);
    }
    assert_eq!(zone.history.len(), 200);

    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example".to_string(), zone);

    let first = zones.get("example").expect("zone");
    let second = zones.get("example").expect("zone");
    assert!(
        Arc::ptr_eq(&first, &second),
        "two queries must share the served zone snapshot"
    );
    for index in 0..first.history.len() {
        assert!(
            Arc::ptr_eq(
                &first.history[index].records,
                &second.history[index].records
            ),
            "history entry {index} must not be copied by a query"
        );
    }

    // A mutation replaces the snapshot; the in-flight reader keeps the old one.
    zones.update_zone("example", |zone| {
        zone.records.insert(
            ("extra".to_string(), RecordType::A),
            vec![record("extra", RecordType::A, "192.0.2.11", 300)],
        );
    });
    let third = zones.get("example").expect("zone");
    assert!(
        !Arc::ptr_eq(&first, &third),
        "a writer publishes a new snapshot"
    );
    assert!(
        !first
            .records
            .contains_key(&("extra".to_string(), RecordType::A)),
        "the reader that started earlier keeps its stable snapshot"
    );
    assert!(third
        .records
        .contains_key(&("extra".to_string(), RecordType::A)));
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Zone file: $ORIGIN scoping, inherited owners, multi-token NAPTR
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_file_origin_is_parse_scoped_and_owners_inherit() {
    let content = r#"$TTL 3600
$ORIGIN example.com.
@       IN  SOA     ns1.example.com. admin.example.com. 42 3600 600 604800 300
@       IN  NS      ns1.example.com.
www     IN  A       192.0.2.1
        IN  AAAA    2001:db8::1
sub     IN  A       192.0.2.2
$ORIGIN lab.example.com.
host    IN  A       192.0.2.3
_next   IN  NAPTR   100 10 S SIP+D2U _sip._udp.example.com .
"#;
    let zone = parse_zone_content(content, "example.com").expect("zone file parses");

    // `$ORIGIN` changed the parse scope, not the zone identity.
    assert_eq!(zone.origin, "example.com");
    assert_eq!(zone.serial, 42, "the SOA serial is adopted");
    assert_eq!(
        zone.records
            .get(&("@".to_string(), RecordType::SOA))
            .map(|rrset| rrset.len()),
        Some(1),
        "the file's SOA is the only apex SOA"
    );

    // The indented line inherits `www`, not a record named after its type.
    assert!(zone
        .records
        .contains_key(&("www".to_string(), RecordType::AAAA)));
    assert!(!zone
        .records
        .keys()
        .any(|(name, _)| name.eq_ignore_ascii_case("IN")));

    // A name written under the second $ORIGIN is stored relative to the zone.
    assert!(zone
        .records
        .contains_key(&("host.lab".to_string(), RecordType::A)));

    // The NAPTR RDATA is the whole multi-token value, not one token.
    let naptr = zone
        .records
        .get(&("_next.lab".to_string(), RecordType::NAPTR))
        .expect("NAPTR record");
    assert_eq!(
        naptr[0].value.split_whitespace().count(),
        6,
        "NAPTR RDATA keeps every token: {:?}",
        naptr[0].value
    );
    assert!(naptr[0].value.contains("SIP+D2U"));

    // The parsed zone is servable: both the inherited owner and the scoped
    // name answer.
    let fixture = Fixture::publish(zone);
    assert_eq!(
        response_ancount(&fixture.respond("www.example.com", RecordType::AAAA)),
        1
    );
    assert_eq!(
        response_ancount(&fixture.respond("host.lab.example.com", RecordType::A)),
        1
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Store round-trip: DNAME/TLSA/SVCB survive, serial is restored
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn store_round_trip_preserves_types_and_serial() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ZoneStore::new(dir.path().to_path_buf()).expect("store");

    let records = vec![
        (
            "@".to_string(),
            RecordType::SOA,
            "ns1.example. hostmaster.example. 777 3600 600 604800 300".to_string(),
            300u32,
            None,
        ),
        (
            "@".to_string(),
            RecordType::NS,
            "ns1.example.".to_string(),
            300,
            None,
        ),
        (
            "alias".to_string(),
            RecordType::DNAME,
            "target.example.net.".to_string(),
            300,
            None,
        ),
        (
            "_443._tcp".to_string(),
            RecordType::TLSA,
            "3 1 1 0123456789abcdef".to_string(),
            300,
            None,
        ),
        (
            "svc".to_string(),
            RecordType::SVCB,
            "1 svc.example. alpn=h2".to_string(),
            300,
            None,
        ),
        (
            "www".to_string(),
            RecordType::A,
            "192.0.2.10".to_string(),
            300,
            None,
        ),
    ];
    store.save_zone("example", &records).expect("save");

    let loaded = store.load_zones().expect("load");
    let zone = loaded.get("example").expect("zone round-trips");
    assert_eq!(zone.serial, 777, "the serial is restored from the SOA");
    assert!(zone
        .records
        .contains_key(&("alias".to_string(), RecordType::DNAME)));
    assert!(
        !zone
            .records
            .contains_key(&("alias".to_string(), RecordType::CNAME)),
        "DNAME must not load as CNAME"
    );
    assert!(zone
        .records
        .contains_key(&("_443._tcp".to_string(), RecordType::TLSA)));
    assert!(zone
        .records
        .contains_key(&("svc".to_string(), RecordType::SVCB)));

    // A second save replaces the record set (the zone row is upserted).
    store
        .save_zone(
            "example",
            &[(
                "@".to_string(),
                RecordType::SOA,
                "ns1.example. hostmaster.example. 778 3600 600 604800 300".to_string(),
                300u32,
                None,
            )],
        )
        .expect("replace");
    let reloaded = store.load_zones().expect("reload");
    let zone = reloaded.get("example").expect("zone");
    assert_eq!(zone.serial, 778);
    assert!(!zone
        .records
        .contains_key(&("alias".to_string(), RecordType::DNAME)));
}

/// A cache hit must echo the *current* query's transaction ID.
///
/// The authoritative cache stores complete response bytes. Returning them
/// unchanged made the second query for the same name carry the first query's
/// ID, so a real client discarded it and waited for its timeout. The key binds
/// qname (case included), qtype, qclass, DO, transport and client, so only the
/// two ID bytes differ.
#[tokio::test]
async fn authoritative_cache_hit_returns_the_current_transaction_id() {
    use std::time::Duration;
    use tokio::net::UdpSocket;

    let mut bound = support::start_bound_dns_server(|runtime| {
        runtime.recursive.enabled = false;
        runtime.authoritative.cache.enabled = true;
    })
    .await;

    let spec = ZoneSpec {
        origin: "example.com".to_string(),
        records: vec![
            ZoneRecordSpec {
                name: "@".to_string(),
                record_type: RecordType::SOA,
                ttl: Some(300),
                value: "ns1.example.com. hostmaster.example.com. 2026111901 3600 600 604800 300"
                    .to_string(),
                priority: None,
            },
            ZoneRecordSpec {
                name: "@".to_string(),
                record_type: RecordType::NS,
                ttl: Some(300),
                value: "ns1.example.com.".to_string(),
                priority: None,
            },
            ZoneRecordSpec {
                name: "www".to_string(),
                record_type: RecordType::A,
                ttl: Some(300),
                value: "192.0.2.10".to_string(),
                priority: None,
            },
        ],
        dnssec: None,
    };
    bound
        .server
        .load_zones(vec![spec])
        .expect("the cache fixture zone must load");

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp socket");
    socket
        .connect(("127.0.0.1", bound.port))
        .await
        .expect("connect to the listener");

    // Three different IDs: the first populates the cache, the next two are
    // hits. Every response must carry its own ID and the answer.
    for id in [0x1111u16, 0x2222, 0x3333] {
        let request = build_query(id, "www.example.com", 1);
        socket.send(&request).await.expect("send query");

        let mut buffer = [0u8; 512];
        let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .expect("a cached response must arrive within the timeout")
            .expect("receive response");

        assert_eq!(
            u16::from_be_bytes([buffer[0], buffer[1]]),
            id,
            "response ID must match the current query, not the cached one"
        );
        assert_eq!(response_rcode(&buffer[..len]), 0);
        assert_eq!(response_ancount(&buffer[..len]), 1);
    }

    bound.server.shutdown_runtime();
}
