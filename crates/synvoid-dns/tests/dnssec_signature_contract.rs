//! Signature contract: every RRSIG the server emits must verify against the
//! DNSKEY it serves, over the name it actually serves.
//!
//! The previous suites asserted RRSIG *shape*: a 2-byte type, an algorithm
//! byte, a label byte, a length. A signature over the relative storage name
//! (`www`, `@`) has exactly the same shape and none of the meaning, so the
//! zone was bogus end-to-end while every test passed. Every case here decodes
//! the response, reconstructs the RFC 4034 §3.1.2 signed data from the FQDN,
//! and verifies the signature with hickory's `dnssec-ring` verifier against
//! the public DNSKEY — i.e. it asks the only question a resolver asks.
//!
//! Cases (phase 04 R7):
//! 1. apex `A` and `www` `A` RRSIGs verify against the served DNSKEY;
//! 2. `Labels` equals the FQDN label count, and 2 for `*.example.com`;
//! 3. the DNSKEY RRSIG is made by the KSK (the key the DS points at);
//! 4. DS, NSEC and NSEC3PARAM RRSIGs verify;
//! 5. NXDOMAIN carries a verifying SOA RRSIG directly after the SOA, and a
//!    verifying NSEC RRSIG;
//! 6. a TXT value whose first byte is a printable digit verifies;
//! 7. a zone with a missing ZSK answers SERVFAIL and counts the failure;
//! 8. the old signing input (the relative storage name) does not verify.

mod support;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hickory_proto::rr::RData;
use metrics::{Key, KeyName, Recorder};
use parking_lot::RwLock;
use synvoid_dns::dnssec::{Algorithm, KeyType, ZoneSigningKey};
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::zone_trie::ZoneTrie;

use support::context::make_ctx;
use support::dnssec::{
    decode_response, relative_owner_signature_is_rejected, rrsig, served_dnskeys, verify_answer,
    verify_authority, verify_rrset, DnskeyParts, Section,
};
use support::query::build_query_with_do_bit;
use support::response::{
    question_name, response_ancount, response_nscount, response_qdcount, response_rcode,
};

const ORIGIN: &str = "example.com";
const RCODE_NOERROR: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;

/// A TXT value whose first byte is a printable digit (`9` = 0x39 = 57) and
/// whose length (60) is greater than that byte. The old presentation-string
/// heuristic read the first byte as a length prefix and signed 57 bytes plus a
/// second, bogus string instead of the 60 bytes it served (finding L1).
fn digit_leading_txt() -> String {
    let mut value = String::from("9");
    value.push_str(&"d".repeat(59));
    value
}

fn record(name: &str, record_type: RecordType, value: &str) -> DnsZoneRecord {
    DnsZoneRecord {
        name: name.to_string(),
        record_type,
        value: value.to_string(),
        ttl: 300,
        priority: None,
    }
}

fn ephemeral(key_type: KeyType) -> ZoneSigningKey {
    ZoneSigningKey::generate_ephemeral(Algorithm::Ed25519, key_type)
        .expect("ephemeral Ed25519 key must generate")
}

/// A signed `example.com` zone plus the key handles configured on it.
struct SignedZone {
    zones: Arc<ShardedZoneStore>,
    trie: Arc<RwLock<ZoneTrie>>,
    ecs: EcsFilterConfig,
    ksk: Option<ZoneSigningKey>,
    zsk: Option<ZoneSigningKey>,
}

impl SignedZone {
    fn new() -> Self {
        Self::with_keys(Some(ephemeral(KeyType::KSK)), Some(ephemeral(KeyType::ZSK)))
    }

    /// A zone that carries only a ZSK (the reverse half-configuration).
    fn without_ksk() -> Self {
        Self::with_keys(None, Some(ephemeral(KeyType::ZSK)))
    }

    /// A zone whose ZSK handle holds no private material, so signing fails.
    fn with_unusable_zsk() -> Self {
        let real = ephemeral(KeyType::ZSK);
        let public_only = ZoneSigningKey::from_public_parts(
            "public-only-zsk".to_string(),
            Algorithm::Ed25519,
            KeyType::ZSK,
            real.public_key().to_vec(),
            real.key_tag(),
            256,
        );
        Self::with_keys(Some(ephemeral(KeyType::KSK)), Some(public_only))
    }

    fn with_keys(ksk: Option<ZoneSigningKey>, zsk: Option<ZoneSigningKey>) -> Self {
        let mut zone = Zone::new(ORIGIN.to_string());
        zone.serial = 2026111701;
        // NSEC proofs exercise the authority section; NSEC3PARAM exercises the
        // apex key material path without asking for a chain (phase 05).
        zone.nsec_enabled = true;
        zone.nsec3_enabled = false;
        zone.nsec3param = Some(synvoid_dns::dnssec::Nsec3Config::new(0, vec![0xAB, 0xCD]));

        let entries = [
            (
                ("@", RecordType::SOA),
                record(
                    "@",
                    RecordType::SOA,
                    "ns1.example.com. hostmaster.example.com. 2026111701 3600 600 604800 300",
                ),
            ),
            (
                ("@", RecordType::A),
                record("@", RecordType::A, "192.0.2.1"),
            ),
            (
                ("@", RecordType::NS),
                record("@", RecordType::NS, "ns1.example.com."),
            ),
            (
                ("www", RecordType::A),
                record("www", RecordType::A, "192.0.2.10"),
            ),
            (
                ("*", RecordType::A),
                record("*", RecordType::A, "192.0.2.99"),
            ),
            (
                ("txt", RecordType::TXT),
                record("txt", RecordType::TXT, &digit_leading_txt()),
            ),
        ];
        for ((name, record_type), value) in entries {
            zone.records
                .insert((name.to_string(), record_type), vec![value]);
        }

        zone.ksk_key = ksk.as_ref().map(|key| Arc::new(key.clone()));
        zone.zsk_key = zsk.as_ref().map(|key| Arc::new(key.clone()));

        let zones = Arc::new(ShardedZoneStore::new());
        zones.insert(ORIGIN.to_string(), zone);
        let mut trie = ZoneTrie::new();
        trie.insert(ORIGIN);

        Self {
            zones,
            trie: Arc::new(RwLock::new(trie)),
            ecs: EcsFilterConfig::default(),
            ksk,
            zsk,
        }
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
        DnskeyParts::from_key(self.zsk.as_ref().expect("fixture has a ZSK"))
    }

    fn ksk_parts(&self) -> DnskeyParts {
        DnskeyParts::from_key(self.ksk.as_ref().expect("fixture has a KSK"))
    }
}

/// The served DNSKEY that the RRSIG for `(section, owner, record_type)` names.
fn served_dnskey_for(
    fixture: &SignedZone,
    resp: &[u8],
    section: Section,
    owner: &str,
    record_type: RecordType,
) -> DnskeyParts {
    let dnskey_resp = fixture.respond(ORIGIN, u16::from(RecordType::DNSKEY));
    let served = served_dnskeys(&dnskey_resp);
    let signature = rrsig(resp, section, owner, record_type)
        .unwrap_or_else(|e| panic!("{owner} {record_type}: {e}"));
    served
        .iter()
        .find(|key| key.key_tag() == signature.input().key_tag)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "no served DNSKEY has key tag {} (RRSIG for {owner} {record_type})",
                signature.input().key_tag
            )
        })
}

fn answer_types(resp: &[u8]) -> Vec<u16> {
    decode_response(resp)
        .answers
        .iter()
        .map(|record| u16::from(record.record_type()))
        .collect()
}

fn authority_types(resp: &[u8]) -> Vec<u16> {
    decode_response(resp)
        .authorities
        .iter()
        .map(|record| u16::from(record.record_type()))
        .collect()
}

// ── Case 1: apex and www A RRSIGs verify against the served DNSKEY ──────────

#[test]
fn apex_a_rrsig_verifies_against_the_served_dnskey() {
    let fixture = SignedZone::new();
    let resp = fixture.respond(ORIGIN, u16::from(RecordType::A));

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 2, "A plus its RRSIG");

    let dnskey = served_dnskey_for(&fixture, &resp, Section::Answer, ORIGIN, RecordType::A);
    assert_eq!(
        dnskey.key_tag(),
        fixture.zsk_parts().key_tag(),
        "ordinary zone data must be signed by the ZSK"
    );
    verify_answer(&resp, &dnskey).unwrap_or_else(|e| panic!("apex A signature must verify: {e}"));
}

#[test]
fn www_a_rrsig_verifies_against_the_served_dnskey() {
    let fixture = SignedZone::new();
    let resp = fixture.respond("www.example.com", u16::from(RecordType::A));

    assert_eq!(response_ancount(&resp), 2, "A plus its RRSIG");
    let dnskey = served_dnskey_for(
        &fixture,
        &resp,
        Section::Answer,
        "www.example.com",
        RecordType::A,
    );
    verify_answer(&resp, &dnskey)
        .unwrap_or_else(|e| panic!("www.example.com A signature must verify: {e}"));
}

// ── Case 2: Labels is the FQDN label count, 2 for a wildcard ───────────────

#[test]
fn rrsig_labels_follow_the_fqdn_and_the_wildcard_rule() {
    let fixture = SignedZone::new();

    let apex = fixture.respond(ORIGIN, u16::from(RecordType::A));
    let apex_sig = rrsig(&apex, Section::Answer, ORIGIN, RecordType::A).unwrap();
    assert_eq!(apex_sig.input().num_labels, 2, "example.com has 2 labels");

    let www = fixture.respond("www.example.com", u16::from(RecordType::A));
    let www_sig = rrsig(&www, Section::Answer, "www.example.com", RecordType::A).unwrap();
    assert_eq!(
        www_sig.input().num_labels,
        3,
        "the storage key 'www' must not become the label count (that was 1)"
    );

    // RFC 4034 §3.1.3: the leading wildcard label is not counted, and RFC 4035
    // §5.3.2 reconstructs `*.example.com` from that field — so the signature
    // still verifies.
    let wildcard = fixture.respond("*.example.com", u16::from(RecordType::A));
    assert_eq!(response_ancount(&wildcard), 2);
    let wildcard_sig = rrsig(&wildcard, Section::Answer, "*.example.com", RecordType::A).unwrap();
    assert_eq!(
        wildcard_sig.input().num_labels,
        2,
        "*.example.com has 2 labels"
    );
    verify_answer(
        &wildcard,
        &served_dnskey_for(
            &fixture,
            &wildcard,
            Section::Answer,
            "*.example.com",
            RecordType::A,
        ),
    )
    .unwrap_or_else(|e| panic!("wildcard signature must verify: {e}"));
}

// ── Case 3: the DNSKEY RRset is signed by the KSK ──────────────────────────

#[test]
fn dnskey_rrsig_is_made_by_the_ksk() {
    let fixture = SignedZone::new();
    let resp = fixture.respond(ORIGIN, u16::from(RecordType::DNSKEY));

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    // Two DNSKEYs (KSK + ZSK) and one RRSIG covering the RRset — not one
    // signature per key.
    assert_eq!(
        answer_types(&resp),
        vec![48, 48, 46],
        "DNSKEY RRset and exactly one covering RRSIG"
    );

    let ksk = fixture.ksk_parts();
    let zsk = fixture.zsk_parts();
    let signature = rrsig(&resp, Section::Answer, ORIGIN, RecordType::DNSKEY).unwrap();

    assert_eq!(
        signature.input().key_tag,
        ksk.key_tag(),
        "the DNSKEY RRset must be signed by the KSK whose key tag the parent DS carries"
    );
    assert_ne!(
        signature.input().key_tag,
        zsk.key_tag(),
        "signing the DNSKEY RRset with the ZSK (finding D36) is a broken chain of trust"
    );
    assert!(
        served_dnskeys(&resp)
            .iter()
            .any(|key| key.key_tag() == ksk.key_tag() && key.is_secure_entry_point()),
        "the KSK (SEP bit set) must be published in the DNSKEY RRset"
    );

    verify_rrset(&resp, Section::Answer, ORIGIN, RecordType::DNSKEY, &ksk)
        .unwrap_or_else(|e| panic!("DNSKEY RRSIG must verify with the KSK: {e}"));
    assert!(
        verify_rrset(&resp, Section::Answer, ORIGIN, RecordType::DNSKEY, &zsk).is_err(),
        "the DNSKEY RRSIG must not verify with the ZSK"
    );
}

// ── Case 4: DS, NSEC and NSEC3PARAM RRSIGs verify ──────────────────────────

#[test]
fn ds_rrsig_verifies_with_the_zsk_and_covers_the_ksk() {
    let fixture = SignedZone::new();
    let resp = fixture.respond(ORIGIN, u16::from(RecordType::DS));

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(answer_types(&resp), vec![43, 46], "DS plus its RRSIG");

    let dnskey = served_dnskey_for(&fixture, &resp, Section::Answer, ORIGIN, RecordType::DS);
    assert_eq!(
        dnskey.key_tag(),
        fixture.zsk_parts().key_tag(),
        "DS is ordinary zone data and is signed by the ZSK"
    );
    verify_rrset(&resp, Section::Answer, ORIGIN, RecordType::DS, &dnskey)
        .unwrap_or_else(|e| panic!("DS RRSIG must verify: {e}"));

    let ds_key_tag = decode_response(&resp)
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::DS(ds)) => Some(ds.key_tag()),
            _ => None,
        })
        .expect("a DS answer must decode");
    assert_eq!(
        ds_key_tag,
        fixture.ksk_parts().key_tag(),
        "the published DS must point at the KSK"
    );
}

#[test]
fn nsec_rrsig_verifies_in_a_negative_answer() {
    let fixture = SignedZone::new();
    // The fixture has `*.example.com`, so a name error for `absent.example.com`
    // would need a wildcard answer (phase 09) and cannot be proven. Query
    // below `www`, where no wildcard exists: the proof is `www`'s NSEC, the
    // canonical predecessor the zone actually contains (phase 05).
    let resp = fixture.respond("absent.www.example.com", u16::from(RecordType::A));

    assert_eq!(response_rcode(&resp), RCODE_NXDOMAIN);
    let dnskey = served_dnskey_for(
        &fixture,
        &resp,
        Section::Authority,
        "www.example.com",
        RecordType::NSEC,
    );
    verify_rrset(
        &resp,
        Section::Authority,
        "www.example.com",
        RecordType::NSEC,
        &dnskey,
    )
    .unwrap_or_else(|e| panic!("NSEC RRSIG must verify: {e}"));
}

#[test]
fn nsec3param_rrsig_verifies() {
    let fixture = SignedZone::new();
    let resp = fixture.respond(ORIGIN, u16::from(RecordType::NSEC3PARAM));

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(
        answer_types(&resp),
        vec![51, 46],
        "NSEC3PARAM plus its RRSIG"
    );

    let dnskey = served_dnskey_for(
        &fixture,
        &resp,
        Section::Answer,
        ORIGIN,
        RecordType::NSEC3PARAM,
    );
    verify_rrset(
        &resp,
        Section::Answer,
        ORIGIN,
        RecordType::NSEC3PARAM,
        &dnskey,
    )
    .unwrap_or_else(|e| panic!("NSEC3PARAM RRSIG must verify: {e}"));
}

// ── Case 5: NXDOMAIN carries a verifying SOA RRSIG and NSEC RRSIG ──────────

#[test]
fn nxdomain_signs_the_soa_and_keeps_the_nsec_signature() {
    let fixture = SignedZone::new();
    // Below `www` there is no wildcard, so the name error is provable (see
    // `nsec_rrsig_verifies_in_a_negative_answer`).
    let resp = fixture.respond("absent.www.example.com", u16::from(RecordType::A));

    assert_eq!(response_rcode(&resp), RCODE_NXDOMAIN);
    assert_eq!(response_ancount(&resp), 0);
    assert_eq!(
        authority_types(&resp),
        vec![6, 46, 47, 46],
        "SOA, its RRSIG directly after it, then NSEC and its RRSIG (finding D37)"
    );
    assert_eq!(response_nscount(&resp), 4);

    let zsk = fixture.zsk_parts();
    verify_rrset(&resp, Section::Authority, ORIGIN, RecordType::SOA, &zsk)
        .unwrap_or_else(|e| panic!("NXDOMAIN SOA RRSIG must verify with the ZSK: {e}"));
    verify_authority(&resp, &zsk)
        .unwrap_or_else(|e| panic!("every NXDOMAIN authority RRset must verify: {e}"));
}

// ── Case 6: a TXT value whose first byte is a printable digit ──────────────

#[test]
fn txt_value_starting_with_a_digit_verifies() {
    let fixture = SignedZone::new();
    let resp = fixture.respond("txt.example.com", u16::from(RecordType::TXT));

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(answer_types(&resp), vec![16, 46], "TXT plus its RRSIG");

    let message = decode_response(&resp);
    let txt = message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::TXT(txt) => Some(txt),
            _ => None,
        })
        .expect("a TXT answer must decode");
    let strings: Vec<&[u8]> = txt.txt_data.iter().map(|s| s.as_ref()).collect();
    assert_eq!(
        strings.len(),
        1,
        "the served TXT value is one character-string"
    );
    assert_eq!(strings[0].len(), digit_leading_txt().len());
    assert_eq!(
        strings[0],
        digit_leading_txt().as_bytes(),
        "the served bytes are the value, not a length-prefixed reinterpretation"
    );

    let dnskey = served_dnskey_for(
        &fixture,
        &resp,
        Section::Answer,
        "txt.example.com",
        RecordType::TXT,
    );
    verify_answer(&resp, &dnskey)
        .unwrap_or_else(|e| panic!("TXT signature must cover the served bytes: {e}"));
}

// ── Case 7: a missing ZSK fails closed and is counted ──────────────────────

type CounterStore = Arc<parking_lot::Mutex<Vec<(String, Arc<AtomicU64>)>>>;

#[derive(Clone)]
struct TestRecorder {
    store: CounterStore,
}

impl TestRecorder {
    fn new() -> (Self, CounterStore) {
        let store: CounterStore = Arc::new(parking_lot::Mutex::new(Vec::new()));
        (
            TestRecorder {
                store: Arc::clone(&store),
            },
            store,
        )
    }
}

impl Recorder for TestRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
    fn register_counter(&self, key: &Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        let name = key.name().to_string();
        let mut store = self.store.lock();
        if let Some((_, handle)) = store.iter().find(|(n, _)| n == &name) {
            return metrics::Counter::from_arc(handle.clone());
        }
        let handle = Arc::new(AtomicU64::new(0));
        store.push((name, handle.clone()));
        metrics::Counter::from_arc(handle)
    }
    fn register_gauge(&self, _: &Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }
    fn register_histogram(&self, _: &Key, _: &metrics::Metadata<'_>) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

fn read_counter(store: &CounterStore, name: &str) -> u64 {
    store
        .lock()
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, handle)| handle.load(Ordering::Relaxed))
        .unwrap_or(0)
}

#[test]
fn missing_zsk_returns_servfail_and_counts_the_failure() {
    let (recorder, store) = TestRecorder::new();
    let _guard = metrics::set_default_local_recorder(&recorder);

    let fixture = SignedZone::with_keys(Some(ephemeral(KeyType::KSK)), None);
    let resp = fixture.respond("www.example.com", u16::from(RecordType::A));

    assert_eq!(
        response_rcode(&resp),
        RCODE_SERVFAIL,
        "a signed zone that cannot sign must not answer with unsigned data"
    );
    assert_eq!(response_ancount(&resp), 0);
    assert_eq!(
        response_qdcount(&resp),
        1,
        "the question is echoed, so the client can match the failure"
    );
    assert_eq!(question_name(&resp), "www.example.com");
    assert!(
        read_counter(&store, "dns_dnssec_signing_failures_total") >= 1,
        "a fail-closed signing response must increment dns_dnssec_signing_failures_total"
    );
}

#[test]
fn missing_ksk_returns_servfail_and_counts_the_failure() {
    let (recorder, store) = TestRecorder::new();
    let _guard = metrics::set_default_local_recorder(&recorder);

    // The reverse half-configuration: a ZSK without a KSK cannot sign the
    // DNSKEY RRset, so the zone is not served at all.
    let fixture = SignedZone::without_ksk();
    let resp = fixture.respond(ORIGIN, u16::from(RecordType::DNSKEY));

    assert_eq!(response_rcode(&resp), RCODE_SERVFAIL);
    assert_eq!(response_ancount(&resp), 0);
    assert_eq!(question_name(&resp), ORIGIN);
    assert!(
        read_counter(&store, "dns_dnssec_signing_failures_total") >= 1,
        "a half-configured signed zone must be counted"
    );
}

#[test]
fn a_signing_error_returns_servfail_instead_of_an_unsigned_rrset() {
    let (recorder, store) = TestRecorder::new();
    let _guard = metrics::set_default_local_recorder(&recorder);

    // A public-only ZSK handle cannot produce a signature: this is a signing
    // error (not a missing key), and it must abort the whole response rather
    // than leave the A RRset in the answer without its RRSIG (finding L4).
    let fixture = SignedZone::with_unusable_zsk();
    let resp = fixture.respond("www.example.com", u16::from(RecordType::A));

    assert_eq!(response_rcode(&resp), RCODE_SERVFAIL);
    assert_eq!(response_ancount(&resp), 0);
    assert_eq!(response_qdcount(&resp), 1);
    assert_eq!(question_name(&resp), "www.example.com");
    assert!(
        read_counter(&store, "dns_dnssec_signing_failures_total") >= 1,
        "a failed signature must increment dns_dnssec_signing_failures_total"
    );
}

// ── Case 8: the old signing input must not verify ───────────────────────────

#[test]
fn the_relative_name_signing_input_does_not_verify() {
    let fixture = SignedZone::new();
    let resp = fixture.respond("www.example.com", u16::from(RecordType::A));

    let dnskey = served_dnskey_for(
        &fixture,
        &resp,
        Section::Answer,
        "www.example.com",
        RecordType::A,
    );

    // The served signature authenticates the FQDN.
    verify_answer(&resp, &dnskey).unwrap_or_else(|e| panic!("FQDN must verify: {e}"));

    // Reconstructing the pre-fix signed data — owner `www`, Labels = 1 — must
    // fail. If this ever succeeds, the signer regressed to the storage key and
    // the zone is bogus to every validator again.
    relative_owner_signature_is_rejected(
        &resp,
        Section::Answer,
        "www.example.com",
        RecordType::A,
        &dnskey,
        "www",
    )
    .expect("the old, origin-less signing input must not verify");

    // The apex is covered by the same property from the other side: the
    // pre-fix signer used the literal `@` label, which cannot verify against
    // the FQDN `example.com.` (case 1). hickory's `Name` parser rejects `@`
    // as a label, so the apex variant cannot be reconstructed here.
}
