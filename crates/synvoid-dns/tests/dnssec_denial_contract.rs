//! Denial-of-existence contract (phase 05).
//!
//! Every denial record a signed zone serves is derived from the zone, not
//! synthesized per query (D6): the NSEC chain is the canonical owner index in
//! RFC 4034 §6.1 order, and the NSEC3 chain is the hash-sorted owner set with
//! the raw next-hash bytes (D5, D38, L5).
//!
//! The oracles are external to the code under test:
//!
//! - hickory parses the response and its NSEC/NSEC3 RDATA (owner, next name,
//!   next hash, type bitmap, salt, iterations, Opt-Out);
//! - the RFC 5155 Appendix A/B values are literal constants copied from the
//!   RFC — expected hashes are never produced by `hash_name_nsec3`;
//! - the canonical order and the "owner < qname < next" coverage relation are
//!   re-implemented here from RFC 4034 §6.1;
//! - the without-salt hashes are recomputed here from RFC 5155 §5 with SHA-1.
//!
//! Cases: RFC 5155 hashes, owner-name/hash-length shape, canonical coverage,
//! NXDOMAIN, NODATA, wildcard answer, NSEC3 proofs with Opt-Out, reload,
//! key-rotation honesty, and a proptest invariant.

mod support;

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC, NSEC3};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record};
use parking_lot::RwLock;
use sha1::{Digest, Sha1};
use synvoid_dns::denial::{DenialKind, DenialMode, ZoneDenial};
use synvoid_dns::dnssec::{Algorithm, KeyType, Nsec3Config, ZoneSigningKey};
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::zone_trie::ZoneTrie;

use support::context::make_ctx;
use support::dnssec::{
    decode_response, verify_authority, verify_rrset, verify_wildcard_rrset, DnskeyParts, Section,
};
use support::query::build_query_with_do_bit;
use support::response::{is_authoritative, response_ancount, response_nscount, response_rcode};

const ORIGIN: &str = "example.com";
const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

// ─────────────────────────────────────────────────────────────────────────────
// Oranges: RFC 5155 Appendix A, salt aabbccdd, 12 iterations.
// ─────────────────────────────────────────────────────────────────────────────

const RFC_SALT_HEX: &str = "aabbccdd";
/// `H(example) = 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom` (Appendix A).
const H_EXAMPLE: &str = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom";
/// `H(a.example) = 35mthgpgcu1qg68fab165klnsnk3dpvl`.
const H_A: &str = "35mthgpgcu1qg68fab165klnsnk3dpvl";
/// `H(ai.example) = gjeqe526plbf1g8mklp59enfd789njgi`.
const H_AI: &str = "gjeqe526plbf1g8mklp59enfd789njgi";
/// `H(ns1.example) = 2t7b4g4vsa5smi47k61mv5bv1a22bojr`.
const H_NS1: &str = "2t7b4g4vsa5smi47k61mv5bv1a22bojr";
/// `H(ns2.example) = q04jkcevqvmu85r014c7dkba38o0ji5r`.
const H_NS2: &str = "q04jkcevqvmu85r014c7dkba38o0ji5r";
/// `H(w.example) = k8udemvp1j2f7eg6jebps17vp3n8i58h`.
const H_W: &str = "k8udemvp1j2f7eg6jebps17vp3n8i58h";
/// `H(*.w.example) = r53bq7cc2uvmubfu5ocmm6pers9tk9en`.
const H_STAR_W: &str = "r53bq7cc2uvmubfu5ocmm6pers9tk9en";
/// `H(x.w.example) = b4um86eghhds6nea196smvmlo4ors995`.
const H_X_W: &str = "b4um86eghhds6nea196smvmlo4ors995";
/// `H(y.w.example) = ji6neoaepv8b5o6k4ev33abha8ht9fgc`.
const H_Y_W: &str = "ji6neoaepv8b5o6k4ev33abha8ht9fgc";
/// `H(x.y.w.example) = 2vptu5timamqttgl4luu9kg21e0aor3s`.
const H_XY_W: &str = "2vptu5timamqttgl4luu9kg21e0aor3s";
/// `H(xx.example) = t644ebqk9bibcna874givr6joj62mlhv`.
const H_XX: &str = "t644ebqk9bibcna874givr6joj62mlhv";

const RFC_NAMES: &[(&str, &str)] = &[
    ("ai.example", H_AI),
    ("ns1.example", H_NS1),
    ("w.example", H_W),
    ("*.w.example", H_STAR_W),
    ("x.w.example", H_X_W),
    ("y.w.example", H_Y_W),
    ("x.y.w.example", H_XY_W),
    ("xx.example", H_XX),
];

fn rfc_params(opt_out: bool) -> Nsec3Config {
    Nsec3Config {
        algorithm: 1,
        flags: u8::from(opt_out),
        iterations: 12,
        salt: hex::decode(RFC_SALT_HEX).expect("valid salt hex"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn record(name: &str, record_type: RecordType, value: &str) -> DnsZoneRecord {
    DnsZoneRecord {
        name: name.to_string(),
        record_type,
        value: value.to_string(),
        ttl: 300,
        priority: None,
    }
}

fn insert(zone: &mut Zone, name: &str, record_type: RecordType, value: &str) {
    zone.records
        .entry((name.to_string(), record_type))
        .or_default()
        .push(record(name, record_type, value));
}

fn ephemeral(key_type: KeyType) -> ZoneSigningKey {
    ZoneSigningKey::generate_ephemeral(Algorithm::Ed25519, key_type)
        .expect("ephemeral Ed25519 key must generate")
}

/// A signed zone with a canonical owner index and the requested denial mode.
struct Fixture {
    origin: String,
    zones: Arc<ShardedZoneStore>,
    trie: Arc<RwLock<ZoneTrie>>,
    ecs: EcsFilterConfig,
    zsk: ZoneSigningKey,
}

impl Fixture {
    fn assemble(origin: &str, mut zone: Zone) -> Self {
        let zsk = ephemeral(KeyType::ZSK);
        zone.ksk_key = Some(Arc::new(ephemeral(KeyType::KSK)));
        zone.zsk_key = Some(Arc::new(zsk.clone()));

        let zones = Arc::new(ShardedZoneStore::new());
        zones.insert(origin.to_string(), zone);
        let mut trie = ZoneTrie::new();
        trie.insert(origin);

        Self {
            origin: origin.to_string(),
            zones,
            trie: Arc::new(RwLock::new(trie)),
            ecs: EcsFilterConfig::default(),
            zsk,
        }
    }

    fn new(nsec: bool, nsec3: Option<Nsec3Config>, build: impl FnOnce(&mut Zone)) -> Self {
        let mut zone = Zone::new(ORIGIN.to_string());
        zone.serial = 2026111701;
        zone.dnskey_ttl = Some(3600);
        zone.nsec_enabled = nsec;
        zone.nsec3_enabled = nsec3.is_some();
        zone.nsec3param = nsec3;

        insert(
            &mut zone,
            "@",
            RecordType::SOA,
            "ns1.example.com. hostmaster.example.com. 2026111701 3600 600 604800 300",
        );
        insert(&mut zone, "@", RecordType::NS, "ns1.example.com.");
        insert(&mut zone, "@", RecordType::A, "192.0.2.1");
        insert(&mut zone, "www", RecordType::A, "192.0.2.10");
        build(&mut zone);

        Self::assemble(ORIGIN, zone)
    }

    fn plain_nsec() -> Self {
        Self::new(true, None, |_| {})
    }

    /// RFC 5155 Appendix A's zone: origin `example`, salt `aabbccdd`, 12
    /// iterations. Only authoritative names are inserted; the RFC's glue below
    /// the delegations is not part of the hash chain.
    fn rfc_nsec3(opt_out: bool) -> Self {
        let mut zone = Zone::new("example".to_string());
        zone.serial = 1;
        zone.dnskey_ttl = Some(3600);
        zone.nsec_enabled = false;
        zone.nsec3_enabled = true;
        zone.nsec3param = Some(rfc_params(opt_out));

        insert(
            &mut zone,
            "@",
            RecordType::SOA,
            "ns1.example. bugs.x.w.example. 1 3600 300 3600000 3600",
        );
        insert(&mut zone, "@", RecordType::NS, "ns1.example.");
        insert(&mut zone, "@", RecordType::MX, "1 xx.example.");
        insert(&mut zone, "a", RecordType::NS, "ns1.a.example.");
        // The DS RDATA is opaque to the chain; this delegation is secure, so
        // it stays in an Opt-Out chain (unlike c.example).
        insert(&mut zone, "a", RecordType::DS, "e3c6");
        insert(&mut zone, "ai", RecordType::A, "192.0.2.9");
        insert(&mut zone, "c", RecordType::NS, "ns1.c.example.");
        insert(&mut zone, "ns1", RecordType::A, "192.0.2.1");
        insert(&mut zone, "ns2", RecordType::A, "192.0.2.2");
        insert(&mut zone, "*.w", RecordType::MX, "1 ai.example.");
        insert(&mut zone, "x.w", RecordType::MX, "1 xx.example.");
        insert(&mut zone, "x.y.w", RecordType::MX, "1 xx.example.");
        insert(&mut zone, "xx", RecordType::A, "192.0.2.10");

        Self::assemble("example", zone)
    }

    fn denial(&self) -> Arc<ZoneDenial> {
        Arc::clone(self.zones.get(&self.origin).expect("fixture zone").denial())
    }

    fn respond(&self, name: &str, qtype: u16) -> Vec<u8> {
        let ctx = make_ctx(&self.zones, &self.trie, &self.ecs);
        let query = build_query_with_do_bit(0xBEEF, name, qtype);
        DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
            .expect("a well-formed query must be answered")
            .as_ref()
            .clone()
    }

    fn zsk_parts(&self) -> DnskeyParts {
        DnskeyParts::from_key(&self.zsk)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Independent decoding helpers (hickory + RFC 4034 §6.1, never the crate)
// ─────────────────────────────────────────────────────────────────────────────

fn authority(message: &Message) -> &[Record] {
    &message.authorities
}

fn nsec_of(record: &Record) -> Option<&NSEC> {
    match &record.data {
        RData::DNSSEC(DNSSECRData::NSEC(nsec)) => Some(nsec),
        _ => None,
    }
}

fn nsec3_of(record: &Record) -> Option<&NSEC3> {
    match &record.data {
        RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some(nsec3),
        _ => None,
    }
}

fn single_nsec(resp: &[u8]) -> (String, NSEC) {
    let message = decode_response(resp);
    let records: Vec<&Record> = authority(&message)
        .iter()
        .filter(|record| nsec_of(record).is_some())
        .collect();
    let names: Vec<String> = records
        .iter()
        .map(|record| record.name.to_string())
        .collect();
    assert_eq!(
        records.len(),
        1,
        "exactly one NSEC proves a single range, got {names:?}"
    );
    let record = records[0];
    (
        record.name.to_string().to_ascii_lowercase(),
        nsec_of(record).unwrap().clone(),
    )
}

/// The owner of the NSEC whose canonical interval covers `qname`.
fn covering_nsec_owner(resp: &[u8], qname: &str) -> String {
    let message = decode_response(resp);
    let mut covering = Vec::new();
    for record in &message.authorities {
        let Some(nsec) = nsec_of(record) else {
            continue;
        };
        let owner = record.name.to_string();
        let next = nsec.next_domain_name().to_string();
        if covers(&owner, &next, qname) {
            covering.push(owner);
        }
    }
    assert_eq!(
        covering.len(),
        1,
        "exactly one NSEC covers {qname}, got {covering:?}"
    );
    covering.remove(0).to_ascii_lowercase()
}

fn nsec3_proof(resp: &[u8]) -> Vec<(String, NSEC3)> {
    decode_response(resp)
        .authorities
        .iter()
        .filter_map(|record| {
            nsec3_of(record)
                .map(|nsec3| (record.name.to_string().to_ascii_lowercase(), nsec3.clone()))
        })
        .collect()
}

/// RFC 4034 §6.1: the label sequence compared from the root, case-folded.
fn canonical_key(name: &str) -> Vec<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut labels: Vec<String> = name
        .split('.')
        .filter(|label| !label.is_empty())
        .map(str::to_string)
        .collect();
    labels.reverse();
    labels
}

fn canonical_cmp(a: &str, b: &str) -> Ordering {
    canonical_key(a).cmp(&canonical_key(b))
}

/// `owner < name < next` in canonical order, wrapping at the apex.
fn covers(owner: &str, next: &str, name: &str) -> bool {
    let owner = canonical_key(owner);
    let next = canonical_key(next);
    let name = canonical_key(name);
    if owner < next {
        owner < name && name < next
    } else {
        owner < name || name < next
    }
}

fn base32hex_decode(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut bits: u32 = 0;
    let mut bit_count = 0u32;
    let mut out = Vec::new();
    for byte in input.to_ascii_uppercase().bytes() {
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .unwrap_or_else(|| panic!("invalid base32hex digit '{}'", byte as char))
            as u32;
        bits = (bits << 5) | value;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    out
}

/// RFC 5155 §5, recomputed here: `IH(salt, x, 0) = H(x || salt)`, then
/// `IH(salt, x, k) = H(IH(salt, x, k-1) || salt)`.
fn rfc5155_hash(name: &str, salt: &[u8], iterations: u16) -> Vec<u8> {
    let mut fqdn = name.trim_end_matches('.').to_ascii_lowercase();
    if !fqdn.is_empty() {
        fqdn.push('.');
    }
    let mut wire = Vec::new();
    if !fqdn.is_empty() {
        for label in fqdn.split('.').filter(|label| !label.is_empty()) {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
    }
    wire.push(0);

    let mut input = wire;
    input.extend_from_slice(salt);
    let mut hash = Sha1::digest(&input).to_vec();
    for _ in 1..=iterations {
        let mut next = hash.clone();
        next.extend_from_slice(salt);
        hash = Sha1::digest(&next).to_vec();
    }
    hash
}

fn type_set(nsec: &NSEC) -> BTreeSet<u16> {
    nsec.type_bit_maps().map(u16::from).collect()
}

fn nsec3_type_set(nsec3: &NSEC3) -> BTreeSet<u16> {
    nsec3.type_bit_maps().map(u16::from).collect()
}

fn nsec3_owner_label(owner: &str) -> String {
    owner
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. RFC 5155 §B hashes, with and without salt
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nsec3_hashes_match_rfc5155_appendix_b() {
    let salted = rfc_params(false);

    for (name, expected) in RFC_NAMES {
        let hash = synvoid_dns::dnssec::hash_name_nsec3(name, &salted);
        assert_eq!(hash.len(), 20, "{name}: SHA-1 is 20 octets");
        assert_eq!(
            synvoid_dns::dnssec::base32_encode(&hash).to_ascii_lowercase(),
            *expected,
            "{name}: H must match RFC 5155 Appendix A"
        );

        // The same hash, recomputed here from RFC 5155 §5, so a vector typo
        // cannot hide behind the implementation.
        assert_eq!(
            hash,
            rfc5155_hash(name, &salted.salt, salted.iterations),
            "{name}: the crate hash must equal the RFC §5 construction"
        );
    }

    // Without salt: the RFC publishes no constants for this case, so the
    // independent §5 construction is the oracle.
    for (name, _) in RFC_NAMES {
        let no_salt = Nsec3Config {
            salt: Vec::new(),
            ..rfc_params(false)
        };
        assert_eq!(
            synvoid_dns::dnssec::hash_name_nsec3(name, &no_salt),
            rfc5155_hash(name, &[], no_salt.iterations),
            "{name}: iteration 0 is still one hash of the canonical wire name"
        );
    }

    // The default (iterations 0) must not be the plaintext name + salt.
    let default = Nsec3Config::default();
    let hash = synvoid_dns::dnssec::hash_name_nsec3("example.com.", &default);
    assert_eq!(hash.len(), 20);
    assert_ne!(hash, b"example.com.".to_vec());
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. NSEC3 owner name and RDATA shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nsec3_owner_name_and_hash_length_are_the_wire_values() {
    let params = rfc_params(false);
    let hash = base32hex_decode(H_AI);
    assert_eq!(hash.len(), 20);
    let owner = synvoid_dns::dnssec::create_nsec3_owner_name(ORIGIN, &hash);
    let label = owner.split('.').next().expect("a hash label");
    assert_eq!(
        label.to_ascii_lowercase(),
        H_AI,
        "the owner label is the base32 hex hash"
    );
    assert_eq!(
        label.len(),
        32,
        "SHA-1's 20 octets encode to 32 characters; a 52-byte prefix was D38"
    );
    assert!(owner.ends_with(&format!(".{ORIGIN}")));
    assert!(
        label.chars().any(|c| c.is_ascii_alphabetic()),
        "the first label cannot be a decimal length prefix"
    );

    let next = [0x5Au8; 20];
    let rdata = synvoid_dns::dnssec::create_nsec3_record(&params, &next, &[1, 46]);
    assert_eq!(rdata[0], 1, "hash algorithm");
    assert_eq!(rdata[1], 0, "flags");
    assert_eq!(u16::from_be_bytes([rdata[2], rdata[3]]), 12);
    assert_eq!(rdata[4], 4, "salt length is the raw salt octets");
    assert_eq!(&rdata[5..9], &[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(rdata[9], 20, "Hash Length is 20 for SHA-1, never 32 or 52");
    assert_eq!(
        &rdata[10..30],
        &next,
        "the next-hash field is the next hash bytes, not a second hash"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. The NSEC chain covers every qname exactly once
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nsec_chain_covers_every_qname_exactly_once() {
    let fixture = Fixture::new(true, None, |zone| {
        insert(zone, "txt", RecordType::TXT, "hello");
        insert(zone, "mail", RecordType::MX, "10 mx.example.com.");
        insert(zone, "a.b", RecordType::A, "192.0.2.20");
        insert(zone, "deep.a.b", RecordType::A, "192.0.2.21");
    });
    let denial = fixture.denial();
    let owners: Vec<(String, String)> = denial
        .owners()
        .iter()
        .map(|(_, display)| {
            let nsec = denial.nsec_at(display).expect("every owner has an NSEC");
            let decoded = decode_nsec_rdata(&nsec.value);
            (display.clone(), decoded.next)
        })
        .collect();

    // Deterministic xorshift sample: names under the zone, a mix of depths.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut checked = 0usize;
    for _ in 0..200 {
        let depth = 1 + (next() % 3) as usize;
        let mut labels = Vec::with_capacity(depth);
        for _ in 0..depth {
            let len = 1 + (next() % 9) as usize;
            let mut label = String::with_capacity(len);
            for _ in 0..len {
                label.push((b'a' + (next() % 26) as u8) as char);
            }
            labels.push(label);
        }
        let qname = format!("{}.{ORIGIN}", labels.join("."));
        if denial.is_owner(&qname) {
            continue;
        }
        checked += 1;
        let covering: Vec<&(String, String)> = owners
            .iter()
            .filter(|(owner, next)| covers(&format!("{owner}."), &format!("{next}."), &qname))
            .collect();
        assert_eq!(
            covering.len(),
            1,
            "{qname} must be covered by exactly one NSEC range, got {covering:?}"
        );
    }
    assert!(checked > 100, "the sample must exercise real gaps");
}

/// The NSEC RDATA layout of RFC 4034 §4.1.2, decoded here.
struct DecodedNsec {
    next: String,
    types: BTreeSet<u16>,
}

fn decode_nsec_rdata(value_hex: &str) -> DecodedNsec {
    let rdata = hex::decode(value_hex).expect("NSEC RDATA is hex");
    let mut offset = 0;
    let mut labels = Vec::new();
    while offset < rdata.len() && rdata[offset] != 0 {
        let len = rdata[offset] as usize;
        labels.push(String::from_utf8_lossy(&rdata[offset + 1..offset + 1 + len]).to_string());
        offset += 1 + len;
    }
    offset += 1;
    let types = decode_bitmap(&rdata, offset);
    DecodedNsec {
        next: labels.join("."),
        types,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. NXDOMAIN selects the predecessor NSEC and signs it
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nxdomain_carries_the_canonical_predecessor_and_a_verifying_rrsig() {
    let fixture = Fixture::plain_nsec();
    let resp = fixture.respond("nope.example.com", u16::from(RecordType::A));

    assert_eq!(response_rcode(&resp), RCODE_NXDOMAIN);
    assert_eq!(response_nscount(&resp), 4, "SOA + RRSIG + NSEC + RRSIG");

    let (owner, nsec) = single_nsec(&resp);
    let next = nsec.next_domain_name().to_string().to_ascii_lowercase();

    assert_ne!(
        owner, "nope.example.com.",
        "the NSEC owner is an existing name, not the queried (nonexistent) one"
    );
    assert!(
        fixture.denial().is_owner(&owner),
        "{owner} must be an owner in the zone's canonical index"
    );
    assert!(
        covers(&owner, &next, "nope.example.com"),
        "the NSEC must cover the qname: {owner} < nope.example.com < {next}"
    );
    assert!(
        !nsec
            .type_bit_maps()
            .any(|record_type| record_type == RecordType::CNAME),
        "the predecessor does not hold a CNAME; the old bitmap asserted one"
    );

    // A validator's checks: the SOA and the NSEC RRsets carry signatures that
    // verify against the served DNSKEY, over the owner actually served.
    let zsk = fixture.zsk_parts();
    verify_authority(&resp, &zsk)
        .unwrap_or_else(|e| panic!("every authority RRset must verify: {e}"));
    verify_rrset(&resp, Section::Authority, &owner, RecordType::NSEC, &zsk)
        .unwrap_or_else(|e| panic!("the selected NSEC RRSIG must verify: {e}"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. NODATA carries the owner's exact bitmap
// ─────────────────────────────────────────────────────────────────────────────

fn expected_bitmap(
    records: &HashMap<(String, RecordType), Vec<DnsZoneRecord>>,
    origin: &str,
    owner: &str,
    nsec: bool,
) -> BTreeSet<u16> {
    let mut types = BTreeSet::new();
    for ((name, record_type), values) in records {
        if values.is_empty() {
            continue;
        }
        let display = if name == "@" || name.is_empty() {
            origin.to_string()
        } else if name.ends_with(&format!(".{origin}")) {
            name.clone()
        } else {
            format!("{name}.{origin}")
        };
        if display.eq_ignore_ascii_case(owner.trim_end_matches('.')) {
            types.insert(u16::from(*record_type));
        }
    }
    if nsec {
        types.insert(47);
    }
    types.insert(46);
    let delegation = types.contains(&2) && !types.contains(&6);
    if !delegation {
        types.remove(&43);
    }
    types
}

#[test]
fn nodata_carries_exactly_the_types_present_at_the_owner() {
    let fixture = Fixture::plain_nsec();
    let resp = fixture.respond("www.example.com", u16::from(RecordType::TXT));

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(
        support::response::response_ancount(&resp),
        0,
        "NODATA has no answer"
    );

    let (owner, nsec) = single_nsec(&resp);
    assert_eq!(owner, "www.example.com.");
    let zone = fixture.zones.get(ORIGIN).expect("fixture zone");
    let expected = expected_bitmap(&zone.records, ORIGIN, &owner, true);
    assert_eq!(
        type_set(&nsec),
        expected,
        "the bitmap is {expected:?}: the RRsets at www plus NSEC/RRSIG"
    );
    assert!(
        !type_set(&nsec).contains(&u16::from(RecordType::TXT)),
        "TXT does not exist at www and must not be asserted"
    );

    verify_authority(&resp, &fixture.zsk_parts())
        .unwrap_or_else(|e| panic!("the NODATA proof must verify: {e}"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Wildcard answer: the next-closer non-existence proof
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn wildcard_answer_selects_the_next_closer_proof() {
    let fixture = Fixture::new(true, None, |zone| {
        insert(zone, "*", RecordType::A, "192.0.2.99");
    });
    let denial = fixture.denial();

    // RFC 4035 §3.1.3.3: a wildcard answer for `foo.example.com` must carry an
    // NSEC proving that no closer match exists — the NSEC that covers the next
    // closer name, never one at the queried name. Phase 09 wires the RFC 4592
    // lookup that consumes this proof; phase 05 supplies it from the zone.
    let proof = denial
        .proof(
            DenialMode::Nsec,
            DenialKind::WildcardAnswer,
            "foo.example.com",
        )
        .expect("a wildcard answer needs a next-closer proof");
    assert_eq!(proof.len(), 1);
    assert_eq!(proof[0].name, "*.example.com");

    let decoded = decode_nsec_rdata(&proof[0].value);
    assert!(
        covers(
            "*.example.com.",
            &format!("{}.", decoded.next),
            "foo.example.com"
        ),
        "the wildcard owner's NSEC covers the next closer name"
    );
    assert_eq!(
        decoded.types,
        BTreeSet::from([u16::from(RecordType::A), 46, 47]),
        "the proof is the wildcard owner's real bitmap"
    );
}

/// Phase 09 R1: a name under an existing wildcard is answered by the
/// wildcard, not by a fabricated NXDOMAIN (and not by the phase-05
/// fail-closed SERVFAIL that preceded the lookup).
#[test]
fn wildcard_answer_is_served_with_a_verifying_next_closer_proof() {
    let fixture = Fixture::new(true, None, |zone| {
        insert(zone, "*", RecordType::A, "192.0.2.99");
    });
    let resp = fixture.respond("foo.example.com", u16::from(RecordType::A));

    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "*.example.com must answer foo.example.com"
    );
    let message = decode_response(&resp);
    assert_eq!(message.answers.len(), 2, "A RRset plus its RRSIG");
    let answer = &message.answers[0];
    assert_eq!(
        answer.name.to_string().to_ascii_lowercase(),
        "foo.example.com.",
        "the synthesized owner is the qname"
    );
    assert!(matches!(answer.data, RData::A(_)));
    let rrsig = message
        .answers
        .iter()
        .find(|record| record.record_type() == RecordType::RRSIG)
        .expect("the wildcard answer is signed");
    assert_eq!(
        rrsig.name.to_string().to_ascii_lowercase(),
        "*.example.com.",
        "the RRSIG keeps the wildcard owner (RFC 4035 §3.1.3.3)"
    );

    // The next-closer proof: exactly the NSEC at the wildcard owner.
    let (owner, nsec) = single_nsec(&resp);
    assert_eq!(owner, "*.example.com.");
    let decoded_next = nsec.next_domain_name().to_string();
    assert!(
        covers("*.example.com.", &decoded_next, "foo.example.com"),
        "the wildcard owner's NSEC covers the next closer name"
    );
    verify_wildcard_rrset(
        &resp,
        "foo.example.com",
        "*.example.com",
        RecordType::A,
        &fixture.zsk_parts(),
    )
    .expect("the wildcard RRSIG must verify against the wildcard owner");
    verify_authority(&resp, &fixture.zsk_parts()).expect("the next-closer proof must verify");
}

/// The same rule for a wildcard that exists but lacks the qtype: wildcard
/// NODATA (NOERROR, no answer) with the RFC 5155 proof, not a name error.
#[test]
fn wildcard_nodata_is_served_with_a_verifying_proof() {
    let fixture = Fixture::rfc_nsec3(true);
    let resp = fixture.respond("zz.w.example", u16::from(RecordType::A));

    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "*.w.example exists, so the name is not an error"
    );
    assert!(response_nscount(&resp) > 0, "the proof is present");
    assert!(
        !nsec3_proof(&resp).is_empty(),
        "wildcard NODATA carries NSEC3 records"
    );
    verify_authority(&resp, &fixture.zsk_parts()).expect("the wildcard NODATA proof must verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6b. Signed referral: DS when secure, the no-DS proof when insecure
// ─────────────────────────────────────────────────────────────────────────────

/// RFC 4035 §3.1.4.1: a referral from a signed parent carries the delegation
/// NS RRset and either the child's DS RRset (secure) or the NSEC/NSEC3 proof
/// that no DS exists (insecure), every RRset signed.
#[test]
fn signed_referral_carries_ds_or_the_no_ds_proof() {
    // A valid DS RDATA in the zone's internal (hex) form: key tag, algorithm,
    // digest type, 32-byte SHA-256 digest.
    let ds_hex = format!("12340802{}", "ab".repeat(32));
    let fixture = Fixture::new(true, None, |zone| {
        insert(zone, "child", RecordType::NS, "ns1.example.com.");
        insert(zone, "secure", RecordType::NS, "ns1.example.com.");
        insert(zone, "secure", RecordType::DS, &ds_hex);
    });

    let secure = fixture.respond("host.secure.example.com", u16::from(RecordType::A));
    assert_eq!(response_rcode(&secure), RCODE_NOERROR);
    assert!(
        !is_authoritative(&secure),
        "a referral is not authoritative"
    );
    assert_eq!(response_ancount(&secure), 0);
    let message = decode_response(&secure);
    assert!(
        message
            .authorities
            .iter()
            .any(|record| record.record_type() == hickory_proto::rr::RecordType::NS),
        "the delegation NS RRset is in authority"
    );
    assert!(
        message
            .authorities
            .iter()
            .any(|record| record.record_type() == hickory_proto::rr::RecordType::DS),
        "a secure delegation carries its DS RRset"
    );
    verify_authority(&secure, &fixture.zsk_parts()).expect("the signed referral must verify");

    let insecure = fixture.respond("host.child.example.com", u16::from(RecordType::A));
    assert!(!is_authoritative(&insecure));
    assert_eq!(response_ancount(&insecure), 0);
    let message = decode_response(&insecure);
    assert!(
        !message
            .authorities
            .iter()
            .any(|record| record.record_type() == hickory_proto::rr::RecordType::DS),
        "an insecure delegation has no DS to serve"
    );
    let (_, nsec) = single_nsec(&insecure);
    assert!(
        !type_set(&nsec).contains(&u16::from(RecordType::DS)),
        "the NSEC at the cut must not assert a DS RRset"
    );
    verify_authority(&insecure, &fixture.zsk_parts()).expect("the no-DS proof must verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. NSEC3 mode: RFC 5155 §B responses and Opt-Out
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nsec3_nodata_selects_the_matching_rfc_record() {
    let fixture = Fixture::rfc_nsec3(true);
    let resp = fixture.respond("ns1.example", u16::from(RecordType::MX));

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    let proof = nsec3_proof(&resp);
    assert_eq!(proof.len(), 1, "NODATA has one matching NSEC3");
    let (owner, nsec3) = &proof[0];
    assert_eq!(
        nsec3_owner_label(owner),
        H_NS1,
        "ns1.example hashes to 2t7b4g4vsa5smi47k61mv5bv1a22bojr"
    );
    assert_eq!(nsec3.iterations(), 12);
    assert_eq!(nsec3.salt(), &hex::decode(RFC_SALT_HEX).unwrap()[..]);
    assert_eq!(
        nsec3_type_set(nsec3),
        BTreeSet::from([u16::from(RecordType::A), 46]),
        "A exists at ns1; MX does not"
    );
    assert_eq!(
        nsec3.next_hashed_owner_name(),
        &base32hex_decode(H_XY_W)[..],
        "the next hash is 2vptu5timamqttgl4luu9kg21e0aor3s, copied as bytes"
    );

    verify_authority(&resp, &fixture.zsk_parts())
        .unwrap_or_else(|e| panic!("the NSEC3 NODATA proof must verify: {e}"));
}

#[test]
fn nsec3_name_error_returns_the_closest_encloser_next_closer_and_wildcard_proofs() {
    let fixture = Fixture::rfc_nsec3(true);
    // RFC 5155 Appendix B.1: a.c.x.w.example is a name error.
    let resp = fixture.respond("a.c.x.w.example", u16::from(RecordType::A));

    assert_eq!(response_rcode(&resp), RCODE_NXDOMAIN);
    let proof = nsec3_proof(&resp);
    let owners: BTreeSet<String> = proof
        .iter()
        .map(|(owner, _)| nsec3_owner_label(owner))
        .collect();
    assert_eq!(
        owners,
        BTreeSet::from([H_EXAMPLE.to_string(), H_X_W.to_string(), H_A.to_string(),]),
        "Appendix B.1: covering next closer, closest encloser, wildcard cover"
    );

    let closest = proof
        .iter()
        .find(|(owner, _)| nsec3_owner_label(owner).eq_ignore_ascii_case(H_X_W))
        .map(|(_, nsec3)| nsec3)
        .expect("the closest encloser x.w.example must match");
    assert_eq!(
        closest.next_hashed_owner_name(),
        &base32hex_decode(H_AI)[..],
        "x.w.example's next hash is gjeqe526plbf1g8mklp59enfd789njgi"
    );

    verify_authority(&resp, &fixture.zsk_parts())
        .unwrap_or_else(|e| panic!("every NSEC3 RRSIG must verify: {e}"));
}

#[test]
fn nsec3_empty_non_terminal_is_nodata_with_an_empty_bitmap() {
    let fixture = Fixture::rfc_nsec3(true);
    // RFC 5155 Appendix B.2.1: y.w.example is an empty non-terminal.
    let resp = fixture.respond("y.w.example", u16::from(RecordType::A));

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    let proof = nsec3_proof(&resp);
    assert_eq!(proof.len(), 1);
    let (owner, nsec3) = &proof[0];
    assert_eq!(
        nsec3_owner_label(owner),
        H_Y_W,
        "y.w.example hashes to ji6neoaepv8b5o6k4ev33abha8ht9fgc"
    );
    assert!(
        nsec3_type_set(nsec3).is_empty(),
        "an empty non-terminal publishes an empty bitmap (Appendix A)"
    );
    assert_eq!(
        nsec3.next_hashed_owner_name(),
        &base32hex_decode(H_W)[..],
        "y.w.example's next hash is w.example"
    );

    verify_authority(&resp, &fixture.zsk_parts())
        .unwrap_or_else(|e| panic!("the ENT NSEC3 proof must verify: {e}"));
}

#[test]
fn nsec3_wildcard_answer_and_no_data_select_the_rfc_proofs() {
    let fixture = Fixture::rfc_nsec3(true);
    let denial = fixture.denial();

    // B.4: a.z.w.example is answered from *.w.example; the proof is the NSEC3
    // covering the next closer z.w.example, which is ns2.example's record.
    let answer_proof = denial
        .proof(
            DenialMode::Nsec3,
            DenialKind::WildcardAnswer,
            "a.z.w.example",
        )
        .expect("wildcard answer proof");
    assert_eq!(answer_proof.len(), 1);
    let nsec3 = decode_nsec3_rdata(&answer_proof[0]);
    assert_eq!(nsec3_owner_label(&nsec3.owner), H_NS2);
    assert_eq!(nsec3.iterations, 12);
    assert_eq!(nsec3.salt, hex::decode(RFC_SALT_HEX).unwrap());
    assert_eq!(
        nsec3.next_hash,
        base32hex_decode(H_STAR_W),
        "B.4: q04jk... points at r53bq... and lists A RRSIG"
    );
    assert_eq!(nsec3.types, BTreeSet::from([u16::from(RecordType::A), 46]));

    // B.5: a.z.w.example/AAAA is wildcard NODATA: closest encloser (w),
    // covering next closer (z.w), and the wildcard itself (*.w).
    let nodata_proof = denial
        .proof(
            DenialMode::Nsec3,
            DenialKind::WildcardNoData,
            "a.z.w.example",
        )
        .expect("wildcard NODATA proof");
    let owners: BTreeSet<String> = nodata_proof
        .iter()
        .map(|record| {
            let decoded = decode_nsec3_rdata(record);
            nsec3_owner_label(&decoded.owner)
        })
        .collect();
    assert_eq!(
        owners,
        BTreeSet::from([H_W.to_string(), H_NS2.to_string(), H_STAR_W.to_string()]),
        "B.5: w.example, the next closer cover, and *.w.example"
    );
}

#[test]
fn nsec3_opt_out_omits_the_insecure_delegation_and_flags_its_cover() {
    let fixture = Fixture::rfc_nsec3(true);
    let denial = fixture.denial();
    let chain = denial.nsec3().expect("NSEC3 chain");

    assert!(
        chain.record_for_name("c.example").is_none(),
        "an Opt-Out chain omits the insecure delegation c.example"
    );
    let hash = chain
        .hash_bytes("c.example")
        .expect("H(c.example) is computable");
    let cover = chain
        .covering_hash(&hash)
        .expect("the excluded delegation is covered");
    let nsec3 = decode_nsec3_rdata(&cover);
    assert_eq!(
        nsec3_owner_label(&nsec3.owner),
        H_A,
        "B.3: 35mthgpg... (a.example) covers c.example"
    );
    assert!(
        nsec3.opt_out(),
        "the covering record must carry the Opt-Out flag"
    );

    // Without Opt-Out the same delegation is a chain member with no DS bit,
    // which is how a validator proves the delegation is insecure.
    let strict = Fixture::rfc_nsec3(false);
    let strict_chain = strict.denial();
    let chain = strict_chain.nsec3().unwrap();
    let record = chain
        .record_for_name("c.example")
        .expect("without Opt-Out c.example is in the chain");
    let nsec3 = decode_nsec3_rdata(&record);
    assert!(!nsec3.opt_out());
    assert!(
        !nsec3.types.contains(&u16::from(RecordType::DS)),
        "an insecure delegation must not claim a DS RRset"
    );
}

/// The NSEC3 RDATA layout of RFC 5155 §3.2, decoded here.
struct DecodedNsec3 {
    owner: String,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
    next_hash: Vec<u8>,
    types: BTreeSet<u16>,
}

impl DecodedNsec3 {
    fn opt_out(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

fn decode_nsec3_rdata(record: &DnsZoneRecord) -> DecodedNsec3 {
    let rdata = hex::decode(&record.value).expect("NSEC3 RDATA is hex");
    assert_eq!(rdata[0], 1, "SHA-1");
    let flags = rdata[1];
    let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
    let salt_len = rdata[4] as usize;
    let salt = rdata[5..5 + salt_len].to_vec();
    let hash_offset = 5 + salt_len;
    let hash_len = rdata[hash_offset] as usize;
    assert_eq!(hash_len, 20, "SHA-1 hash length");
    let next_hash = rdata[hash_offset + 1..hash_offset + 1 + hash_len].to_vec();
    let types = decode_bitmap(&rdata, hash_offset + 1 + hash_len);
    DecodedNsec3 {
        owner: record.name.clone(),
        flags,
        iterations,
        salt,
        next_hash,
        types,
    }
}

fn decode_bitmap(rdata: &[u8], start: usize) -> BTreeSet<u16> {
    let mut offset = start;
    let mut types = BTreeSet::new();
    while offset + 2 <= rdata.len() {
        let window = rdata[offset] as u16;
        let len = rdata[offset + 1] as usize;
        for byte in 0..len {
            for bit in 0..8 {
                if rdata[offset + 2 + byte] & (0x80 >> bit) != 0 {
                    types.insert(window * 256 + (byte as u16) * 8 + bit as u16);
                }
            }
        }
        offset += 2 + len;
    }
    types
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Reload rebuilds the chain and invalidates the response cache
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_reload_rebuilds_the_chain_and_invalidates_the_cache() {
    use synvoid_dns::cache::CacheKey;
    use synvoid_dns::runtime_config::{RecordType as RuntimeRecordType, ZoneRecordSpec, ZoneSpec};

    fn apex_record(record_type: RuntimeRecordType) -> ZoneRecordSpec {
        ZoneRecordSpec {
            name: "@".to_string(),
            record_type,
            ttl: Some(300),
            value: "ns1.example.com. hostmaster.example.com. 1 7200 3600 604800 300".to_string(),
            priority: None,
        }
    }

    fn spec_with(extra: &str) -> ZoneSpec {
        ZoneSpec {
            origin: ORIGIN.to_string(),
            records: vec![
                apex_record(RuntimeRecordType::SOA),
                ZoneRecordSpec {
                    name: extra.to_string(),
                    record_type: RuntimeRecordType::A,
                    ttl: Some(300),
                    value: "192.0.2.200".to_string(),
                    priority: None,
                },
            ],
            dnssec: None,
        }
    }

    let mut runtime = support::dns_runtime();
    runtime.authoritative.bind_address =
        std::net::SocketAddr::from(([127, 0, 0, 1], support::UNBOUND_TEST_PORT));
    runtime.recursive.enabled = false;
    let server = DnsServer::new(runtime, None, None);

    server
        .load_zones(vec![spec_with("new")])
        .expect("load the zone");
    let ctx = server.query_context();
    let query = build_query_with_do_bit(0x5151, "mmm.example.com", 1);
    let first = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("answered")
        .as_ref()
        .clone();
    let first_owner = covering_nsec_owner(&first, "mmm.example.com");
    assert_eq!(
        first_owner, "example.com.",
        "with owners {{example.com, new.example.com}} the predecessor of mmm is the apex"
    );

    let cache = server.get_cache().expect("the fixture enables the cache");
    let key = CacheKey::new("mmm.example.com".to_string(), RecordType::A, None);
    cache.insert(key.clone(), vec![0u8; 20], 300);
    assert!(cache.get(&key).is_some(), "the entry is cached");

    // Reload with an owner that sorts between the apex and `mmm`.
    server
        .load_zones(vec![spec_with("aaa")])
        .expect("reload the zone");
    assert!(
        cache.get(&key).is_none(),
        "a zone load must invalidate the response cache"
    );

    let ctx = server.query_context();
    let second = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("answered")
        .as_ref()
        .clone();
    let second_owner = covering_nsec_owner(&second, "mmm.example.com");
    assert_eq!(
        second_owner, "aaa.example.com.",
        "the reloaded zone's chain is derived from the new owner set"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Key rotation is manual; no task may rotate unserved keys
// ─────────────────────────────────────────────────────────────────────────────

/// Age every active key's metadata so an automatic rotation check would fire.
fn age_active_keys(keys: &std::path::Path, days: u64) {
    let now = synvoid_dns::time::unix_timestamp_secs();
    for sub in ["ksk", "zsk"] {
        let dir = keys.join(sub);
        let entries = std::fs::read_dir(&dir).expect("key directory");
        for entry in entries {
            let path = entry.expect("key entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("key") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("key metadata");
            let mut meta: serde_json::Value = serde_json::from_str(&text).expect("key JSON");
            if meta.get("standby").and_then(|v| v.as_bool()) == Some(true) {
                continue;
            }
            meta["created_at"] = serde_json::Value::from(now.saturating_sub(days * 86_400));
            std::fs::write(&path, serde_json::to_vec_pretty(&meta).expect("encode"))
                .expect("write");
        }
    }
}

#[tokio::test(start_paused = true)]
async fn key_rotation_is_not_automated() {
    let dir = tempfile::tempdir().expect("temp key dir");
    let mut keystore = synvoid_dns::dnssec::DnssecKeystore::new(dir.path().to_path_buf());
    keystore.initialize().expect("initialize keystore");
    keystore
        .generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
        .expect("generate KSK");
    keystore
        .generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
        .expect("generate ZSK");
    let ksk_tag = keystore.active_ksk().unwrap().key_tag();
    let zsk_tag = keystore.active_zsk().unwrap().key_tag();
    drop(keystore);
    age_active_keys(dir.path(), 40);

    let bound = support::start_bound_dns_server(|runtime| {
        runtime.recursive.enabled = false;
        runtime.dnssec.enabled = true;
        runtime.dnssec.key_path = dir.path().to_path_buf();
    })
    .await;
    let mut server = bound.server;

    // Phase 05 R4: rotation is a manual runbook operation. If a task still
    // called `check_and_rotate` on an interval, the aged keys would start a
    // rollover as soon as the task ticked — the observable this asserts.
    tokio::time::advance(std::time::Duration::from_secs(2 * 86_400)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    let manager = server.get_dnssec().expect("DNSSEC manager");
    let guard = manager.read();
    let status = guard.rollover_status();
    assert_eq!(
        status["ksk_in_rollover"], false,
        "no automatic KSK rollover may start: the served zone would still publish the old key"
    );
    assert_eq!(
        status["zsk_in_rollover"], false,
        "no automatic ZSK rollover may start: the served zone would still publish the old key"
    );
    assert_eq!(guard.active_ksk().unwrap().key_tag(), ksk_tag);
    assert_eq!(guard.active_zsk().unwrap().key_tag(), zsk_tag);
    drop(guard);

    server.shutdown();
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Property: NSEC next is the canonical successor; bitmap is the RRsets
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_pre_fix_fabricated_proof_fails_the_new_contract() {
    // Captured from the pre-fix server (phase 04 wiring, before this change):
    // NXDOMAIN for absent.example.com in a signed example.com zone whose
    // owners are {example.com, www.example.com, *.example.com}. The old
    // builder put the NSEC at the queried name and listed A/NS/CNAME/SOA/
    // MX/TXT/AAAA/SRV there (D6).
    let captured = "beef8503000100000004000106616273656e74076578616d706c6503636f6d0000010001076578616d706c6503636f6d00000600010000012c003d036e7331076578616d706c6503636f6d000a686f73746d6173746572076578616d706c6503636f6d0078c402d500000e100000025800093a800000012c076578616d706c6503636f6d00002e00010000012c005f00060f020000012c6b04f8a36afa6ca300d8076578616d706c6503636f6d0007ffc478ebee11eb477b5589660aaef3e7d0d62011cf703b0e8ae3dcbb539bfa8c97f5496b44876c1226fe781a6ec23656eb8ccbe78bc91c05287580450b1d0806616273656e74076578616d706c6503636f6d00002f000100000e100016012a076578616d706c6503636f6d000005660180084006616273656e74076578616d706c6503636f6d00002e000100000e10005f002f0f0300000e106b04f8a36afa6ca300d8076578616d706c6503636f6d00c5cdc718eb2e0c1663029c94b7989fae9e1f713edf722031f1dd5bf2d42090fc8a9a823929c86b84aff279936a62c22b44d4f3d681c87f562ca58640c2a29c030000291000000080000000";
    let message = Message::from_vec(&hex::decode(captured).expect("captured hex"))
        .expect("the pre-fix response is a DNS message");
    let records: Vec<&Record> = message
        .authorities
        .iter()
        .filter(|record| nsec_of(record).is_some())
        .collect();
    assert_eq!(records.len(), 1);
    let (owner, nsec) = (
        records[0].name.to_string().to_ascii_lowercase(),
        nsec_of(records[0]).unwrap(),
    );

    assert_eq!(
        owner, "absent.example.com.",
        "the pre-fix builder named the NSEC after the nonexistent qname"
    );
    let captured_types: BTreeSet<u16> = nsec.type_bit_maps().map(u16::from).collect();
    assert!(
        captured_types.contains(&u16::from(RecordType::CNAME)),
        "control: the pre-fix bitmap asserted a CNAME at a name with no data"
    );
    assert!(
        captured_types.contains(&u16::from(RecordType::NS)),
        "control: the pre-fix bitmap asserted NS at a name with no data"
    );

    // The new contract's predicates reject it: an NSEC owner must be a real
    // owner in the canonical index, must not be the qname, and its bitmap must
    // equal the RRsets actually present.
    let fixture = Fixture::plain_nsec();
    let denial = fixture.denial();
    assert!(
        !denial.is_owner("absent.example.com"),
        "the queried name is not a zone owner; an NSEC cannot be published there"
    );
    let covering = denial
        .nsec_covering("absent.example.com")
        .expect("a real predecessor exists");
    assert_ne!(
        covering.name, "absent.example.com",
        "the selected proof is the predecessor, not the qname"
    );
    let zone = fixture.zones.get(ORIGIN).expect("fixture zone");
    let real_bitmap = expected_bitmap(&zone.records, ORIGIN, "absent.example.com.", true);
    assert!(
        !real_bitmap.contains(&u16::from(RecordType::CNAME)),
        "there is no CNAME at the nonexistent owner"
    );
    assert_ne!(
        captured_types, real_bitmap,
        "the captured (fabricated) bitmap is not the bitmap of the owner it names"
    );
}

fn expected_successor(owners: &[String], name: &str) -> String {
    let mut sorted = owners.to_vec();
    sorted.sort_by(|a, b| canonical_cmp(a, b));
    let index = sorted
        .iter()
        .position(|candidate| candidate.eq_ignore_ascii_case(name))
        .expect("the name is an owner");
    sorted[(index + 1) % sorted.len()].clone()
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 64,
        ..proptest::prelude::ProptestConfig::default()
    })]

    /// Every owner's NSEC `next` is its canonical successor (wrapping to the
    /// apex) and its bitmap equals the RRsets at that owner plus NSEC/RRSIG,
    /// with DS only at a delegation.
    #[test]
    fn every_nsec_points_at_its_canonical_successor_and_lists_its_rrsets(
        names in proptest::collection::btree_set("[a-z]{1,8}(\\.[a-z]{1,8}){0,2}", 1..10),
    ) {
        let mut records: HashMap<(String, RecordType), Vec<DnsZoneRecord>> = HashMap::new();
        let mut apex = |record_type| {
            records.insert(
                ("@".to_string(), record_type),
                vec![record("@", record_type, "0")],
            );
        };
        apex(RecordType::SOA);
        apex(RecordType::NS);

        for name in &names {
            records.insert(
                (name.clone(), RecordType::A),
                vec![record(name, RecordType::A, "192.0.2.1")],
            );
            match name.as_bytes()[0] % 4 {
                0 => {
                    records.insert(
                        (name.clone(), RecordType::NS),
                        vec![record(name, RecordType::NS, "ns.example.com.")],
                    );
                }
                1 => {
                    records.insert(
                        (name.clone(), RecordType::NS),
                        vec![record(name, RecordType::NS, "ns.example.com.")],
                    );
                    records.insert(
                        (name.clone(), RecordType::DS),
                        vec![record(name, RecordType::DS, "e3c6")],
                    );
                }
                2 => {
                    records.insert(
                        (name.clone(), RecordType::DS),
                        vec![record(name, RecordType::DS, "e3c6")],
                    );
                }
                _ => {
                    records.insert(
                        (name.clone(), RecordType::MX),
                        vec![record(name, RecordType::MX, "1 mail.example.com.")],
                    );
                }
            }
        }

        let denial = ZoneDenial::build(ORIGIN, &records, None, 300);
        let displays: Vec<String> = denial.owners().iter().map(|(_, d)| d.clone()).collect();

        // Expected index: the apex plus every generated name that is not glue
        // below a zone cut. A name with an NS RRset and no SOA is a delegation;
        // names strictly below it are not authoritative data and must not be
        // asserted by an NSEC record (RFC 4035 §2.3).
        let is_delegation = |name: &str| matches!(name.as_bytes()[0] % 4, 0 | 1);
        let is_glue = |name: &str| {
            names.iter().any(|delegation| {
                is_delegation(delegation)
                    && name.len() > delegation.len()
                    && name.ends_with(&format!(".{delegation}"))
            })
        };
        let expected_owner_count = 1 + names.iter().filter(|name| !is_glue(name)).count();
        proptest::prop_assert_eq!(displays.len(), expected_owner_count);

        // Canonical order is non-decreasing.
        for window in displays.windows(2) {
            proptest::prop_assert!(canonical_cmp(&window[0], &window[1]).is_le());
        }

        for owner in &displays {
            let nsec_record = denial.nsec_at(owner).expect("every owner has an NSEC");
            let expected_next = expected_successor(&displays, owner);
            let actual_next = decode_nsec_rdata(&nsec_record.value).next;
            proptest::prop_assert_eq!(
                canonical_key(&actual_next),
                canonical_key(&expected_next),
                "NSEC next for {}",
                owner
            );

            let expected = expected_bitmap(&records, ORIGIN, &format!("{owner}."), true);
            let actual: BTreeSet<u16> = {
                let rdata = hex::decode(&nsec_record.value).expect("hex");
                let mut offset = 0;
                while offset < rdata.len() && rdata[offset] != 0 {
                    offset += 1 + rdata[offset] as usize;
                }
                offset += 1;
                let mut types = BTreeSet::new();
                while offset + 2 <= rdata.len() {
                    let window = rdata[offset] as u16;
                    let len = rdata[offset + 1] as usize;
                    for byte in 0..len {
                        for bit in 0..8 {
                            if rdata[offset + 2 + byte] & (0x80 >> bit) != 0 {
                                types.insert(window * 256 + (byte as u16) * 8 + bit as u16);
                            }
                        }
                    }
                    offset += 2 + len;
                }
                types
            };
            proptest::prop_assert_eq!(actual, expected, "NSEC bitmap for {}", owner);
        }
    }
}
