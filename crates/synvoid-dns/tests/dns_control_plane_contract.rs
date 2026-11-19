//! Phase 07 control-plane contract: TSIG, transfer ACL, IXFR, UPDATE,
//! NOTIFY, and DNS cookies.
//!
//! Every TSIG digest here is computed **independently** with `hmac`/`sha2`
//! over the RFC 8945 byte layout. Nothing in this file calls `tsig.rs` to build
//! the bytes it then checks, so a non-canonical implementation cannot pass by
//! agreeing with itself.

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

use synvoid_dns::cache::TransportClass;
use synvoid_dns::cookie::DnsCookieServer;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::notify::{NotifyConfig, NotifyHandler};
use synvoid_dns::runtime_config::{TsigAlgorithmRuntime, TsigRuntimeKey};
use synvoid_dns::server::{DnsServer, DnsZoneRecord, QueryContext, RecordType, ShardedZoneStore};
use synvoid_dns::transfer::{TransferAcl, ZoneTransfer, AXFR_QUERY_TYPE, IXFR_QUERY_TYPE};
use synvoid_dns::tsig::{parse_tsig_from_query, TsigError, TsigVerifier};
use synvoid_dns::update::DynamicUpdateHandler;
use synvoid_dns::wire;

use support::query::{build_rr, build_update_header, build_zone_question, encode_qname};
use support::response::response_rcode;
use support::zone::{zone_with_records, zone_with_soa};

// ══════════════════════════════════════════════════════════════════════
// Independent RFC 8945 wire construction (no calls into tsig.rs)
// ══════════════════════════════════════════════════════════════════════

const KEY_NAME: &str = "control-plane-key";
const SECRET: &[u8] =
    b"phase-07-independent-digest-secret-material-0123456789-abcdefghijklmnopqrstuvwxyz-0123456789";
const TSIG_TYPE: u16 = 250;
const TSIG_CLASS_ANY: u16 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl TestAlg {
    fn name(self) -> &'static str {
        match self {
            TestAlg::Sha256 => "hmac-sha256.",
            TestAlg::Sha384 => "hmac-sha384.",
            TestAlg::Sha512 => "hmac-sha512.",
        }
    }

    fn runtime(self) -> TsigAlgorithmRuntime {
        match self {
            TestAlg::Sha256 => TsigAlgorithmRuntime::HmacSha256,
            TestAlg::Sha384 => TsigAlgorithmRuntime::HmacSha384,
            TestAlg::Sha512 => TsigAlgorithmRuntime::HmacSha512,
        }
    }
}

fn hmac(algorithm: TestAlg, secret: &[u8], data: &[u8]) -> Vec<u8> {
    match algorithm {
        TestAlg::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TestAlg::Sha384 => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(secret).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TestAlg::Sha512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Canonical wire form: uncompressed, lowercase, root-terminated.
fn canonical_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(&label.to_ascii_lowercase().into_bytes());
    }
    out.push(0);
    out
}

/// RFC 8945 §4.3.3 TSIG variables.
fn tsig_variables(
    key_name: &str,
    algorithm: TestAlg,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) -> Vec<u8> {
    let mut variables = Vec::new();
    variables.extend_from_slice(&canonical_name(key_name));
    variables.extend_from_slice(&TSIG_CLASS_ANY.to_be_bytes());
    variables.extend_from_slice(&0u32.to_be_bytes());
    variables.extend_from_slice(&canonical_name(algorithm.name()));
    variables.extend_from_slice(&time_signed.to_be_bytes()[2..8]);
    variables.extend_from_slice(&fudge.to_be_bytes());
    variables.extend_from_slice(&error.to_be_bytes());
    variables.extend_from_slice(&(other.len() as u16).to_be_bytes());
    variables.extend_from_slice(other);
    variables
}

/// RFC 8945 §5.2 request digest over the message without its TSIG RR.
#[allow(clippy::too_many_arguments)]
fn request_digest(
    secret: &[u8],
    message_without_tsig: &[u8],
    key_name: &str,
    algorithm: TestAlg,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) -> Vec<u8> {
    let mut data = message_without_tsig.to_vec();
    data.extend_from_slice(&tsig_variables(
        key_name,
        algorithm,
        time_signed,
        fudge,
        error,
        other,
    ));
    hmac(algorithm, secret, &data)
}

/// RFC 8945 §5.3 response digest: the request MAC is length-prefixed and
/// prepended.
#[allow(clippy::too_many_arguments)]
fn response_digest(
    secret: &[u8],
    request_mac: &[u8],
    message_without_tsig: &[u8],
    key_name: &str,
    algorithm: TestAlg,
    time_signed: u64,
    fudge: u16,
    error: u16,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&(request_mac.len() as u16).to_be_bytes());
    data.extend_from_slice(request_mac);
    data.extend_from_slice(message_without_tsig);
    data.extend_from_slice(&tsig_variables(
        key_name,
        algorithm,
        time_signed,
        fudge,
        error,
        &[],
    ));
    hmac(algorithm, secret, &data)
}

/// Build the whole TSIG RR from a MAC.
#[allow(clippy::too_many_arguments)]
fn build_tsig_rr(
    key_name: &str,
    algorithm: TestAlg,
    time_signed: u64,
    fudge: u16,
    mac: &[u8],
    original_id: u16,
    error: u16,
) -> Vec<u8> {
    let mut rdata = canonical_name(algorithm.name());
    rdata.extend_from_slice(&time_signed.to_be_bytes()[2..8]);
    rdata.extend_from_slice(&fudge.to_be_bytes());
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(mac);
    rdata.extend_from_slice(&original_id.to_be_bytes());
    rdata.extend_from_slice(&error.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes());

    let mut rr = canonical_name(key_name);
    rr.extend_from_slice(&TSIG_TYPE.to_be_bytes());
    rr.extend_from_slice(&TSIG_CLASS_ANY.to_be_bytes());
    rr.extend_from_slice(&0u32.to_be_bytes());
    rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    rr.extend_from_slice(&rdata);
    rr
}

fn set_arcount(message: &mut [u8], count: u16) {
    message[10..12].copy_from_slice(&count.to_be_bytes());
}

fn base_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&encode_qname(qname));
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

/// Append an independently computed TSIG to a message whose ARCOUNT is 0.
#[allow(clippy::too_many_arguments)]
fn sign_message(
    message: &mut Vec<u8>,
    key_name: &str,
    algorithm: TestAlg,
    secret: &[u8],
    time_signed: u64,
    fudge: u16,
    mac_override: Option<Vec<u8>>,
) -> Vec<u8> {
    let digest = request_digest(
        secret,
        message,
        key_name,
        algorithm,
        time_signed,
        fudge,
        0,
        &[],
    );
    let mac = mac_override.unwrap_or(digest);
    let id = u16::from_be_bytes([message[0], message[1]]);
    let rr = build_tsig_rr(key_name, algorithm, time_signed, fudge, &mac, id, 0);
    set_arcount(message, 1);
    message.extend_from_slice(&rr);
    mac
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

// ── Independent RR parser ────────────────────────────────────────────

fn read_name(buf: &[u8], start: usize) -> (String, usize) {
    let mut name = String::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            return (name, end.unwrap_or(pos));
        }
        if len & 0xC0 == 0xC0 {
            if end.is_none() {
                end = Some(pos + 2);
            }
            let second = buf[pos + 1] as usize;
            let offset = ((len & 0x3F) << 8) | second;
            jumps += 1;
            assert!(jumps <= 10, "compression loop");
            pos = offset;
            continue;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&buf[pos + 1..pos + 1 + len]));
        pos += 1 + len;
    }
}

#[derive(Debug, Clone)]
struct ParsedTsig {
    rr_start: usize,
    key_name: String,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlen: usize,
    algorithm_name: String,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
}

/// Parse any TSIG RR starting at `start`.
fn parse_tsig_rr(buf: &[u8], start: usize) -> ParsedTsig {
    let (key_name, pos) = read_name(buf, start);
    let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let class = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
    let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
    let rdata_start = pos + 10;
    let rdata = &buf[rdata_start..rdata_start + rdlen];

    let (algorithm_name, alg_end) = read_name(rdata, 0);
    let time_signed = rdata[alg_end..alg_end + 6]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let fudge = u16::from_be_bytes([rdata[alg_end + 6], rdata[alg_end + 7]]);
    let mac_size = u16::from_be_bytes([rdata[alg_end + 8], rdata[alg_end + 9]]) as usize;
    let mac_start = alg_end + 10;
    let mac = rdata[mac_start..mac_start + mac_size].to_vec();
    let after_mac = mac_start + mac_size;
    let original_id = u16::from_be_bytes([rdata[after_mac], rdata[after_mac + 1]]);
    let error = u16::from_be_bytes([rdata[after_mac + 2], rdata[after_mac + 3]]);
    let other_len = u16::from_be_bytes([rdata[after_mac + 4], rdata[after_mac + 5]]) as usize;

    assert_eq!(
        after_mac + 6 + other_len,
        rdata.len(),
        "RDLENGTH must equal the TSIG RDATA it declares"
    );

    ParsedTsig {
        rr_start: start,
        key_name,
        rtype,
        class,
        ttl,
        rdlen,
        algorithm_name,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
    }
}

/// Record spans of one message: (start, rtype, rdlen, rd_start).
fn record_spans(message: &[u8]) -> Vec<(usize, u16, usize, usize)> {
    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let total = u16::from_be_bytes([message[6], message[7]]) as usize
        + u16::from_be_bytes([message[8], message[9]]) as usize
        + u16::from_be_bytes([message[10], message[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = read_name(message, pos);
        pos = next + 4;
    }

    let mut spans = Vec::new();
    for _ in 0..total {
        let start = pos;
        let (_, after_name) = read_name(message, pos);
        let rtype = u16::from_be_bytes([message[after_name], message[after_name + 1]]);
        let rdlen = u16::from_be_bytes([message[after_name + 8], message[after_name + 9]]) as usize;
        let rd_start = after_name + 10;
        spans.push((start, rtype, rdlen, rd_start));
        pos = rd_start + rdlen;
    }
    spans
}

fn find_tsig(message: &[u8]) -> ParsedTsig {
    let spans = record_spans(message);
    let (start, rtype, _, _) = *spans.last().expect("at least one record");
    assert_eq!(rtype, TSIG_TYPE, "the last record must be TSIG");
    parse_tsig_rr(message, start)
}

/// The message a response digest covers: TSIG removed, ARCOUNT decremented.
fn strip_tsig(message: &[u8]) -> Vec<u8> {
    let tsig = find_tsig(message);
    let mut stripped = message[..tsig.rr_start].to_vec();
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    set_arcount(&mut stripped, arcount - 1);
    stripped
}

fn response_tsig_verifies(message: &[u8], request_mac: &[u8], secret: &[u8]) -> bool {
    let tsig = find_tsig(message);
    let expected = response_digest(
        secret,
        request_mac,
        &strip_tsig(message),
        &tsig.key_name,
        TestAlg::Sha256,
        tsig.time_signed,
        tsig.fudge,
        tsig.error,
    );
    assert_eq!(
        tsig.algorithm_name, "hmac-sha256",
        "response must name the configured algorithm"
    );
    expected == tsig.mac
}

fn tsig_verifier(algorithm: TestAlg) -> Arc<TsigVerifier> {
    Arc::new(
        TsigVerifier::new(vec![TsigRuntimeKey {
            name: KEY_NAME.to_string(),
            secret: SECRET.to_vec(),
            algorithm: algorithm.runtime(),
        }])
        .expect("test key"),
    )
}

// ══════════════════════════════════════════════════════════════════════
// 1. Request MAC equals the independent RFC 8945 digest
// ══════════════════════════════════════════════════════════════════════

#[test]
fn request_mac_matches_an_independently_computed_rfc8945_digest() {
    let algorithm = TestAlg::Sha256;
    let time_signed = now_secs();
    let mut query = base_query(0x1001, "example.test", AXFR_QUERY_TYPE);
    let qd_end = query.len();
    let expected = request_digest(
        SECRET,
        &query,
        KEY_NAME,
        algorithm,
        time_signed,
        300,
        0,
        &[],
    );

    let mac = sign_message(
        &mut query,
        KEY_NAME,
        algorithm,
        SECRET,
        time_signed,
        300,
        None,
    );
    assert_eq!(mac, expected, "the signed MAC is the RFC digest");

    let parsed = parse_tsig_from_query(&query, qd_end)
        .expect("a bounded parse")
        .expect("a TSIG is present");
    assert_eq!(parsed.mac, expected, "the parser returns the same MAC");

    // The server must agree with the independent digest.
    let verifier = tsig_verifier(algorithm);
    verifier
        .verify(&query, &parsed)
        .expect("verification uses the RFC 8945 digest");

    // sha384/sha512 take the same path with their own output length.
    for algorithm in [TestAlg::Sha384, TestAlg::Sha512] {
        let verifier = tsig_verifier(algorithm);
        let mut query = base_query(0x1002, "example.test", AXFR_QUERY_TYPE);
        let qd_end = query.len();
        let time_signed = now_secs();
        let expected = request_digest(
            SECRET,
            &query,
            KEY_NAME,
            algorithm,
            time_signed,
            300,
            0,
            &[],
        );
        let mac = sign_message(
            &mut query,
            KEY_NAME,
            algorithm,
            SECRET,
            time_signed,
            300,
            None,
        );
        assert_eq!(mac, expected, "{:?} digest mismatch", algorithm);
        let parsed = parse_tsig_from_query(&query, qd_end)
            .expect("parse")
            .expect("present");
        verifier
            .verify(&query, &parsed)
            .unwrap_or_else(|e| panic!("{:?} verification failed: {e}", algorithm));
    }
}

// ══════════════════════════════════════════════════════════════════════
// 2. Response MAC includes the request MAC
// ══════════════════════════════════════════════════════════════════════

#[test]
fn response_mac_includes_the_request_mac() {
    let verifier = tsig_verifier(TestAlg::Sha256);
    let request_mac = vec![0xA5u8; 32];

    let response = base_query(0x2001, "example.test", 1);
    let signed = verifier
        .sign_response(KEY_NAME, &response, Some(&request_mac), 0)
        .expect("sign");

    let tsig = parse_tsig_rr(&signed.rr, 0);
    assert_eq!(tsig.rtype, TSIG_TYPE);
    assert_eq!(tsig.class, TSIG_CLASS_ANY);
    assert_eq!(tsig.ttl, 0);
    assert_eq!(tsig.key_name, KEY_NAME);

    let expected = response_digest(
        SECRET,
        &request_mac,
        &response,
        KEY_NAME,
        TestAlg::Sha256,
        tsig.time_signed,
        tsig.fudge,
        0,
    );
    assert_eq!(
        tsig.mac, expected,
        "the response MAC must cover len||request MAC||message||variables"
    );

    // Without the request MAC the digest differs: the binding is real.
    let unbound = response_digest(
        SECRET,
        &[],
        &response,
        KEY_NAME,
        TestAlg::Sha256,
        tsig.time_signed,
        tsig.fudge,
        0,
    );
    assert_ne!(tsig.mac, unbound);
}

// ══════════════════════════════════════════════════════════════════════
// 3. A signed transfer response is a complete RR and verifies
// ══════════════════════════════════════════════════════════════════════

#[test]
fn signed_transfer_response_is_a_complete_rr_and_verifies() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_records("example.test", 1),
    );
    let verifier = tsig_verifier(TestAlg::Sha256);
    let transfer = ZoneTransfer::with_security_config(
        zones,
        TransferAcl::from_entries(&["10.0.0.1".to_string()]),
        Some(verifier),
        false,
        false,
        true,
        true,
        true, // require_tsig
        true, // axfr_enabled
        true, // tcp_only
    )
    .expect("require_tsig with a verifier constructs");

    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let mut query = base_query(0x3001, "example.test", AXFR_QUERY_TYPE);
    let qd_end = query.len();
    let request_mac = sign_message(
        &mut query,
        KEY_NAME,
        TestAlg::Sha256,
        SECRET,
        now_secs(),
        300,
        None,
    );
    let parsed = parse_tsig_from_query(&query, qd_end)
        .expect("parse")
        .expect("present");

    let messages = transfer
        .handle_axfr_request_messages("example.test", client, Some(&parsed), 0x3001, &query, true)
        .expect("signed AXFR must succeed");

    assert!(messages.len() >= 3, "SOA + records + SOA");

    let mut previous_mac = request_mac.clone();
    for (index, message) in messages.iter().enumerate() {
        let tsig = find_tsig(message);
        assert_eq!(tsig.rtype, 250, "message {index}: TYPE must be TSIG");
        assert_eq!(tsig.class, 255, "message {index}: CLASS must be ANY");
        assert_eq!(tsig.ttl, 0, "message {index}: TTL must be 0");
        assert_eq!(
            tsig.original_id, 0x3001,
            "message {index}: Original ID restores the request ID"
        );
        assert!(tsig.rdlen > 0, "message {index}: a full RR has RDATA");
        assert_eq!(tsig.mac.len(), 32, "message {index}: HMAC-SHA256 output");
        assert_eq!(
            u16::from_be_bytes([message[10], message[11]]),
            1,
            "message {index}: ARCOUNT counts the TSIG exactly once"
        );
        assert!(
            response_tsig_verifies(message, &previous_mac, SECRET),
            "message {index}: digest must chain from the previous MAC"
        );
        previous_mac = tsig.mac;
    }
}

// ══════════════════════════════════════════════════════════════════════
// 4. Rejections carry the RFC's error code
// ══════════════════════════════════════════════════════════════════════

#[test]
fn truncated_mac_is_rejected_as_badsig() {
    let verifier = tsig_verifier(TestAlg::Sha256);
    let mut query = base_query(0x4001, "example.test", 1);
    let qd_end = query.len();
    let mac = sign_message(
        &mut query,
        KEY_NAME,
        TestAlg::Sha256,
        SECRET,
        now_secs(),
        300,
        None,
    );
    assert_eq!(mac.len(), 32);

    // Rewrite the TSIG with a 4-byte MAC and consistent lengths.
    let tsig = find_tsig(&query);
    let truncated_mac = mac[..4].to_vec();
    let rr = build_tsig_rr(
        KEY_NAME,
        TestAlg::Sha256,
        tsig.time_signed,
        tsig.fudge,
        &truncated_mac,
        tsig.original_id,
        0,
    );
    query.truncate(tsig.rr_start);
    query.extend_from_slice(&rr);

    let parsed = parse_tsig_from_query(&query, qd_end)
        .expect("layout parses")
        .expect("present");
    let error = verifier.verify(&query, &parsed).expect_err("must reject");
    assert_eq!(
        error.tsig_error_code(),
        Some(16),
        "a MAC below the truncation floor is BADSIG, got {error:?}"
    );
}

#[test]
fn bad_time_is_rejected_as_badtime() {
    let verifier = tsig_verifier(TestAlg::Sha256);
    let stale_time = now_secs().saturating_sub(3600);
    let mut query = base_query(0x4002, "example.test", 1);
    let qd_end = query.len();
    // A valid digest for a stale time: the MAC passes, the clock does not.
    sign_message(
        &mut query,
        KEY_NAME,
        TestAlg::Sha256,
        SECRET,
        stale_time,
        300,
        None,
    );

    let parsed = parse_tsig_from_query(&query, qd_end)
        .expect("parse")
        .expect("present");
    let error = verifier.verify(&query, &parsed).expect_err("must reject");
    assert_eq!(
        error.tsig_error_code(),
        Some(18),
        "a stale time is BADTIME, got {error:?}"
    );
}

#[test]
fn mac_longer_than_the_algorithm_output_is_a_format_error() {
    let verifier = tsig_verifier(TestAlg::Sha256);
    let mut query = base_query(0x4005, "example.test", 1);
    let qd_end = query.len();
    let mac = sign_message(
        &mut query,
        KEY_NAME,
        TestAlg::Sha256,
        SECRET,
        now_secs(),
        300,
        None,
    );

    // Rewrite the TSIG with a 64-byte MAC: longer than HMAC-SHA256's output.
    let tsig = find_tsig(&query);
    let mut oversized = mac.clone();
    oversized.extend_from_slice(&[0u8; 32]);
    let rr = build_tsig_rr(
        KEY_NAME,
        TestAlg::Sha256,
        tsig.time_signed,
        tsig.fudge,
        &oversized,
        tsig.original_id,
        0,
    );
    query.truncate(tsig.rr_start);
    query.extend_from_slice(&rr);

    let parsed = parse_tsig_from_query(&query, qd_end)
        .expect("layout parses")
        .expect("present");
    let error = verifier.verify(&query, &parsed).expect_err("must reject");
    assert!(
        matches!(error, TsigError::MacTooLong { .. }),
        "an oversized MAC is a format error, got {error:?}"
    );
    assert_eq!(
        error.tsig_error_code(),
        None,
        "FORMERR is not a TSIG error code"
    );
}

#[test]
fn unknown_key_is_rejected_as_badkey() {
    let verifier = tsig_verifier(TestAlg::Sha256);
    let mut query = base_query(0x4003, "example.test", 1);
    let qd_end = query.len();
    sign_message(
        &mut query,
        "some-other-key",
        TestAlg::Sha256,
        SECRET,
        now_secs(),
        300,
        None,
    );

    let parsed = parse_tsig_from_query(&query, qd_end)
        .expect("parse")
        .expect("present");
    let error = verifier.verify(&query, &parsed).expect_err("must reject");
    assert!(
        matches!(error, TsigError::UnknownKey(_)),
        "unconfigured key must be UnknownKey, got {error:?}"
    );
    assert_eq!(error.tsig_error_code(), Some(17));
}

#[test]
fn replayed_mac_is_rejected() {
    let verifier = tsig_verifier(TestAlg::Sha256);
    let mut query = base_query(0x4004, "example.test", 1);
    let qd_end = query.len();
    sign_message(
        &mut query,
        KEY_NAME,
        TestAlg::Sha256,
        SECRET,
        now_secs(),
        300,
        None,
    );
    let parsed = parse_tsig_from_query(&query, qd_end)
        .expect("parse")
        .expect("present");

    verifier
        .verify(&query, &parsed)
        .expect("first use verifies");
    let error = verifier
        .verify(&query, &parsed)
        .expect_err("the same MAC must not verify twice");
    assert!(
        matches!(error, TsigError::ReplayAttack),
        "replay must be ReplayAttack, got {error:?}"
    );
    assert_eq!(error.tsig_error_code(), Some(16), "replay is BADSIG");
}

// ══════════════════════════════════════════════════════════════════════
// 5. require_tsig without a verifier fails construction
// ══════════════════════════════════════════════════════════════════════

#[test]
fn require_tsig_without_a_verifier_fails_construction() {
    let zones = Arc::new(ShardedZoneStore::new());

    let transfer = ZoneTransfer::with_security_config(
        zones.clone(),
        TransferAcl::from_entries(&["10.0.0.1".to_string()]),
        None,
        false,
        false,
        true,
        true,
        true, // require_tsig
        true,
        true,
    );
    let error = transfer.err().expect("must refuse to construct");
    assert!(error.contains("TSIG"), "error must name TSIG: {error}");

    let update = DynamicUpdateHandler::new(zones).with_config(true, true, true);
    let error = update.err().expect("must refuse to construct");
    assert!(error.contains("TSIG"), "error must name TSIG: {error}");
}

// ══════════════════════════════════════════════════════════════════════
// 6. Transfer ACL matrix
// ══════════════════════════════════════════════════════════════════════

fn acl_transfer(
    acl: TransferAcl,
    allow_wildcard_transfer: bool,
    verifier: Option<Arc<TsigVerifier>>,
    require_tsig: bool,
) -> ZoneTransfer {
    ZoneTransfer::with_security_config(
        Arc::new(ShardedZoneStore::new()),
        acl,
        verifier,
        allow_wildcard_transfer,
        true,
        true,
        true,
        require_tsig,
        true,
        true,
    )
    .expect("test policy is coherent")
}

#[test]
fn transfer_acl_requires_network_and_zone_jointly() {
    let client = "10.1.2.3".parse().unwrap();
    let other = "192.0.2.9".parse().unwrap();

    // CIDR only: the empty zone list means all zones.
    let cidr_only = acl_transfer(
        TransferAcl::from_entries(&["10.0.0.0/8".to_string()]),
        false,
        None,
        false,
    );
    assert!(cidr_only.is_transfer_allowed(client, "example.test"));
    assert!(cidr_only.is_transfer_allowed(client, "other.test"));
    assert!(!cidr_only.is_transfer_allowed(other, "example.test"));

    // Zone only, no client network: nobody is authorized (fail closed). This
    // is the D20 grant that used to authorize every client.
    let zone_only = acl_transfer(
        TransferAcl::from_entries(&["example.test".to_string()]),
        false,
        None,
        false,
    );
    assert!(
        !zone_only.is_transfer_allowed(client, "example.test"),
        "a zone entry alone must not authorize a client"
    );

    // Both: a match requires both conditions.
    let both = acl_transfer(
        TransferAcl::from_entries(&["10.0.0.0/8".to_string(), "example.test".to_string()]),
        false,
        None,
        false,
    );
    assert!(both.is_transfer_allowed(client, "example.test"));
    assert!(!both.is_transfer_allowed(client, "other.test"));
    assert!(!both.is_transfer_allowed(other, "example.test"));

    // Wildcard honours the policy bit.
    let wildcard_allowed = acl_transfer(
        TransferAcl::from_entries(&["*".to_string()]),
        true,
        None,
        false,
    );
    assert!(wildcard_allowed.is_transfer_allowed(other, "any.zone"));
    let wildcard_denied = acl_transfer(
        TransferAcl::from_entries(&["*".to_string()]),
        false,
        None,
        false,
    );
    assert!(!wildcard_denied.is_transfer_allowed(other, "any.zone"));

    // Key binding: the verified key must be the named one.
    let mut keyed = TransferAcl::from_entries(&["10.0.0.0/8".to_string()]);
    keyed.key = Some("transfer-key".to_string());
    let keyed_transfer = acl_transfer(keyed, false, Some(tsig_verifier(TestAlg::Sha256)), false);
    assert!(keyed_transfer.is_transfer_allowed_with_key(
        client,
        "example.test",
        Some("transfer-key")
    ));
    assert!(!keyed_transfer.is_transfer_allowed_with_key(
        client,
        "example.test",
        Some("another-key")
    ));
    assert!(
        !keyed_transfer.is_transfer_allowed_with_key(client, "example.test", None),
        "no verified key must not satisfy a named-key ACL"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 7. IXFR obeys AXFR: UDP truncation and the AXFR-enabled fallback
// ══════════════════════════════════════════════════════════════════════

fn ixfr_transfer(zones: Arc<ShardedZoneStore>, axfr_enabled: bool) -> ZoneTransfer {
    ZoneTransfer::with_security_config(
        zones,
        TransferAcl::from_entries(&["10.0.0.1".to_string()]),
        None,
        false,
        false,
        true, // ixfr_enabled
        true, // fallback
        false,
        axfr_enabled,
        true,
    )
    .expect("no TSIG required")
}

fn build_ixfr_request(zone: &str, serial: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xCAFEu16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&encode_qname(zone));
    buf.extend_from_slice(&IXFR_QUERY_TYPE.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    // Authority: the client's SOA.
    buf.extend_from_slice(&encode_qname(zone));
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    let mut rdata = encode_qname(&format!("ns1.{zone}"));
    rdata.extend_from_slice(&encode_qname(&format!("admin.{zone}")));
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata.extend_from_slice(&600u32.to_be_bytes());
    rdata.extend_from_slice(&604800u32.to_be_bytes());
    rdata.extend_from_slice(&300u32.to_be_bytes());
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rdata);
    buf
}

fn zone_with_history(origin: &str) -> synvoid_dns::server::Zone {
    let mut zone = zone_with_records(origin, 1);
    zone.increment_serial_with_limit(200);
    let serial = zone.serial;
    if let Some(soa) = zone.records.get_mut(&("@".to_string(), RecordType::SOA)) {
        soa[0].value = format!("ns1.{origin}. admin.{origin}. {serial} 3600 600 604800 300");
    }
    zone
}

#[test]
fn ixfr_over_udp_is_truncated_not_concatenated() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_history("example.test"),
    );
    let transfer = ixfr_transfer(zones, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_ixfr_request("example.test", 0);

    let response = transfer
        .handle_ixfr_request("example.test", client, Some(0), None, 0xCAFE, &query, false)
        .expect("UDP IXFR is answered, not dropped");

    let flags = u16::from_be_bytes([response[2], response[3]]);
    assert_eq!(flags & 0x0200, 0x0200, "TC must be set for UDP IXFR");
    assert_eq!(
        u16::from_be_bytes([response[6], response[7]]),
        0,
        "a truncated IXFR carries no answers"
    );
    assert_eq!(
        u16::from_be_bytes([response[4], response[5]]),
        1,
        "the question is echoed"
    );
}

#[test]
fn ixfr_fallback_requires_axfr_to_be_enabled() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_history("example.test"),
    );
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_ixfr_request("example.test", 0);

    let disabled = ixfr_transfer(zones.clone(), false);
    let error = disabled
        .handle_ixfr_request_messages("example.test", client, Some(0), None, 0xCAFE, &query, true)
        .expect_err("fallback without AXFR must be refused");
    assert!(
        error.message.contains("AXFR"),
        "error must name the AXFR gate: {error}"
    );
    assert_eq!(error.rcode, wire::RCODE_REFUSED);

    let enabled = ixfr_transfer(zones, true);
    let messages = enabled
        .handle_ixfr_request_messages("example.test", client, Some(0), None, 0xCAFE, &query, true)
        .expect("fallback with AXFR enabled serves the full zone");
    assert!(messages.len() >= 3, "SOA + records + SOA");
}

#[test]
fn transfer_byte_cap_refuses_an_oversized_zone() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_records("example.test", 1),
    );
    let transfer = ZoneTransfer::with_security_config(
        zones,
        TransferAcl::from_entries(&["10.0.0.1".to_string()]),
        None,
        false,
        false,
        true,
        true,
        false,
        true,
        true,
    )
    .expect("no TSIG required")
    .with_max_transfer_bytes(64);

    let error = transfer
        .handle_axfr_request_messages(
            "example.test",
            "10.0.0.1".parse().unwrap(),
            None,
            0xCAFE,
            &base_query(0xCAFE, "example.test", AXFR_QUERY_TYPE),
            true,
        )
        .expect_err("a zone over the cap must not be serialized");
    assert_eq!(error.rcode, wire::RCODE_SERVFAIL);
    assert!(error.message.contains("byte limit"), "got {error}");
}

// ══════════════════════════════════════════════════════════════════════
// 8. UPDATE: metavalue matrix, NOTZONE, apex guards, RRset add/delete
// ══════════════════════════════════════════════════════════════════════

const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;

fn update_handler(zones: Arc<ShardedZoneStore>) -> DynamicUpdateHandler {
    DynamicUpdateHandler::new(zones)
        .with_config(true, true, false)
        .expect("no TSIG required")
}

/// Send one UPDATE and return the RCODE the client would receive.
///
/// Protocol-level refusals (FORMERR/NOTZONE) travel as `UpdateDenied`, which
/// the dispatcher turns into the same error response; the rcode is the
/// observable outcome either way.
fn send_update(
    handler: &DynamicUpdateHandler,
    zone: &str,
    prereqs: &[(&str, u16, u16, Vec<u8>)],
    updates: &[(&str, u16, u16, u32, Vec<u8>)],
) -> u8 {
    let mut buf = build_update_header(1, prereqs.len() as u16, 0, updates.len() as u16);
    buf.extend_from_slice(&build_zone_question(zone));
    for (name, rtype, class, rdata) in prereqs {
        let mut rr = encode_qname(name);
        rr.extend_from_slice(&rtype.to_be_bytes());
        rr.extend_from_slice(&class.to_be_bytes());
        rr.extend_from_slice(&0u32.to_be_bytes());
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(rdata);
        buf.extend_from_slice(&rr);
    }
    for (name, rtype, class, ttl, rdata) in updates {
        let mut rr = encode_qname(name);
        rr.extend_from_slice(&rtype.to_be_bytes());
        rr.extend_from_slice(&class.to_be_bytes());
        rr.extend_from_slice(&ttl.to_be_bytes());
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(rdata);
        buf.extend_from_slice(&rr);
    }
    match handler.handle_update(&buf, "10.0.0.1".parse().unwrap()) {
        Ok(response) => response[3] & 0x0F,
        Err(denied) => denied.rcode,
    }
}

#[test]
fn update_prerequisite_metavalue_matrix() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut zone = zone_with_soa("example.test", 1);
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
    zones.insert("example.test".to_string(), zone);
    let handler = update_handler(zones.clone());

    // ANY+ANY on an existing name: "name is in use" holds.
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("www.example.test", 255, CLASS_ANY, vec![])],
            &[],
        ),
        wire::UPDATE_RCODE_NOERROR
    );

    // ANY+ANY on a missing name: NXDOMAIN.
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("absent.example.test", 255, CLASS_ANY, vec![])],
            &[],
        ),
        wire::UPDATE_RCODE_NXDOMAIN
    );

    // ANY+type on an existing RRset holds; on a missing one it is NXRRSET.
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("www.example.test", 1, CLASS_ANY, vec![])],
            &[],
        ),
        wire::UPDATE_RCODE_NOERROR
    );
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("missing.example.test", 1, CLASS_ANY, vec![])],
            &[],
        ),
        wire::UPDATE_RCODE_NXRRSET
    );

    // NONE+ANY on a missing name holds; on an existing name it is YXDOMAIN.
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("absent.example.test", 255, CLASS_NONE, vec![])],
            &[],
        ),
        wire::UPDATE_RCODE_NOERROR
    );
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("www.example.test", 255, CLASS_NONE, vec![])],
            &[],
        ),
        wire::UPDATE_RCODE_YXDOMAIN
    );

    // NONE+type on a missing RRset holds; on an existing one it is YXRRSET.
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("missing.example.test", 1, CLASS_NONE, vec![])],
            &[],
        ),
        wire::UPDATE_RCODE_NOERROR
    );
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("www.example.test", 1, CLASS_NONE, vec![])],
            &[],
        ),
        wire::UPDATE_RCODE_YXRRSET
    );

    // Value dependent: exact RRset equality on canonical wire RDATA.
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("www.example.test", 1, CLASS_IN, vec![192, 0, 2, 10])],
            &[],
        ),
        wire::UPDATE_RCODE_NOERROR
    );
    assert_eq!(
        send_update(
            &handler,
            "example.test",
            &[("www.example.test", 1, CLASS_IN, vec![192, 0, 2, 99])],
            &[],
        ),
        wire::UPDATE_RCODE_NXRRSET
    );

    // A prerequisite that is not TTL 0 is FORMERR.
    let mut buf = build_update_header(1, 1, 0, 0);
    buf.extend_from_slice(&build_zone_question("example.test"));
    buf.extend_from_slice(&{
        let mut rr = encode_qname("www.example.test");
        rr.extend_from_slice(&1u16.to_be_bytes());
        rr.extend_from_slice(&CLASS_ANY.to_be_bytes());
        rr.extend_from_slice(&300u32.to_be_bytes()); // not zero
        rr.extend_from_slice(&0u16.to_be_bytes());
        rr
    });
    let denied = handler
        .handle_update(&buf, "10.0.0.1".parse().unwrap())
        .expect_err("a non-zero prerequisite TTL is FORMERR");
    assert_eq!(denied.rcode, wire::UPDATE_RCODE_FORMERR);

    let zone = zones.get("example.test").unwrap();
    assert_eq!(zone.serial, 1, "prerequisites alone never mutate the zone");
}

#[test]
fn update_out_of_zone_owner_is_notzone() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let handler = update_handler(zones.clone());

    let response = send_update(
        &handler,
        "example.test",
        &[],
        &[("outside.example", 1, CLASS_IN, 300, vec![192, 0, 2, 1])],
    );
    assert_eq!(
        response,
        wire::UPDATE_RCODE_NOTZONE,
        "an out-of-zone owner is NOTZONE"
    );

    let zone = zones.get("example.test").unwrap();
    assert_eq!(zone.serial, 1, "nothing is committed");
}

#[test]
fn update_apex_guards_protect_soa_and_last_ns() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut zone = zone_with_soa("example.test", 1);
    zone.records.insert(
        ("@".to_string(), RecordType::NS),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NS,
            value: "ns1.example.test.".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zones.insert("example.test".to_string(), zone);
    let handler = update_handler(zones.clone());

    // Delete the SOA RRset (ANY + SOA + TTL 0 + RDLENGTH 0).
    let response = send_update(
        &handler,
        "example.test",
        &[],
        &[("@", 6, CLASS_ANY, 0, vec![])],
    );
    assert_eq!(response, wire::UPDATE_RCODE_NOERROR);

    // Delete the last NS by value (NONE + NS + target RDATA).
    let ns_rdata = encode_qname("ns1.example.test");
    let response = send_update(
        &handler,
        "example.test",
        &[],
        &[("@", 2, CLASS_NONE, 0, ns_rdata.clone())],
    );
    assert_eq!(response, wire::UPDATE_RCODE_NOERROR);

    // Delete the NS RRset wholesale.
    let response = send_update(
        &handler,
        "example.test",
        &[],
        &[("@", 2, CLASS_ANY, 0, vec![])],
    );
    assert_eq!(response, wire::UPDATE_RCODE_NOERROR);

    let zone = zones.get("example.test").unwrap();
    assert!(
        zone.records
            .contains_key(&("@".to_string(), RecordType::SOA)),
        "apex SOA must survive"
    );
    assert!(
        zone.records
            .contains_key(&("@".to_string(), RecordType::NS)),
        "the last apex NS must survive"
    );
}

#[test]
fn update_adds_to_an_rrset_and_deletes_one_member() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let handler = update_handler(zones.clone());

    // Two adds of the same <name,type> in one UPDATE must both land.
    let response = send_update(
        &handler,
        "example.test",
        &[],
        &[
            ("multi.example.test", 1, CLASS_IN, 300, vec![10, 0, 0, 1]),
            ("multi.example.test", 1, CLASS_IN, 300, vec![10, 0, 0, 2]),
        ],
    );
    assert_eq!(response, wire::UPDATE_RCODE_NOERROR);

    let zone = zones.get("example.test").unwrap();
    let rrset = zone
        .records
        .get(&("multi".to_string(), RecordType::A))
        .expect("RRset exists");
    let mut values: Vec<&str> = rrset.iter().map(|record| record.value.as_str()).collect();
    values.sort_unstable();
    assert_eq!(values, vec!["10.0.0.1", "10.0.0.2"]);

    // NONE deletes exactly one member by canonical wire RDATA.
    let response = send_update(
        &handler,
        "example.test",
        &[],
        &[("multi.example.test", 1, CLASS_NONE, 0, vec![10, 0, 0, 1])],
    );
    assert_eq!(response, wire::UPDATE_RCODE_NOERROR);

    let zone = zones.get("example.test").unwrap();
    let rrset = zone
        .records
        .get(&("multi".to_string(), RecordType::A))
        .expect("RRset still exists");
    assert_eq!(rrset.len(), 1);
    assert_eq!(rrset[0].value, "10.0.0.2");
}

#[test]
fn update_rejects_dnssec_record_writes_and_rolls_back() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let handler = update_handler(zones.clone());

    let mut buf = build_update_header(1, 0, 0, 2);
    buf.extend_from_slice(&build_zone_question("example.test"));
    buf.extend_from_slice(&build_rr("host.example.test", 1, &[192, 0, 2, 7], 300));
    buf.extend_from_slice(&build_rr("host.example.test", 48, &[1, 0, 3, 8, 1, 2], 300));

    let result = handler.handle_update(&buf, "10.0.0.1".parse().unwrap());
    let error = result.expect_err("DNSKEY writes are refused");
    assert_eq!(error.rcode, wire::UPDATE_RCODE_REFUSED);

    let zone = zones.get("example.test").unwrap();
    assert_eq!(zone.serial, 1, "the transaction rolled back");
    assert!(
        !zone
            .records
            .contains_key(&("host".to_string(), RecordType::A)),
        "no partial write may survive a refused transaction"
    );
}

#[test]
fn update_malformed_update_class_is_formerr_and_atomic() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let handler = update_handler(zones.clone());

    // Class 3 is neither the zone class, ANY, nor NONE.
    let response = send_update(
        &handler,
        "example.test",
        &[],
        &[
            ("first.example.test", 1, CLASS_IN, 300, vec![192, 0, 2, 1]),
            ("second.example.test", 1, 3, 300, vec![192, 0, 2, 2]),
        ],
    );
    assert_eq!(response, wire::UPDATE_RCODE_FORMERR);

    let zone = zones.get("example.test").unwrap();
    assert_eq!(zone.serial, 1);
    assert!(
        !zone
            .records
            .contains_key(&("first".to_string(), RecordType::A)),
        "the first update must not survive a later prescan failure"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 9. Concurrent updates serialize on the zone writer
// ══════════════════════════════════════════════════════════════════════

#[test]
fn concurrent_updates_serialize_and_both_land() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let handler = Arc::new(update_handler(zones.clone()));

    let build = |id: u16, name: &str, octet: u8| {
        let mut buf = build_update_header(1, 0, 0, 1);
        buf.extend_from_slice(&build_zone_question("example.test"));
        buf.extend_from_slice(&build_rr(name, 1, &[10, 0, 0, octet], 300));
        let _ = id;
        buf
    };

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for (name, octet) in [("one.example.test", 1u8), ("two.example.test", 2u8)] {
        let handler = handler.clone();
        let barrier = barrier.clone();
        let query = build(0, name, octet);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            handler
                .handle_update(&query, "10.0.0.1".parse().unwrap())
                .expect("update is answered")
        }));
    }

    for handle in handles {
        let response = handle.join().expect("thread");
        assert_eq!(response[3] & 0x0F, wire::UPDATE_RCODE_NOERROR);
    }

    let zone = zones.get("example.test").unwrap();
    assert!(
        zone.records
            .contains_key(&("one".to_string(), RecordType::A)),
        "the first concurrent update must not be lost"
    );
    assert!(
        zone.records
            .contains_key(&("two".to_string(), RecordType::A)),
        "the second concurrent update must not be lost"
    );
    assert!(
        zone.history.len() >= 2,
        "each commit leaves its own journal entry, got {}",
        zone.history.len()
    );
    let soa = &zone
        .records
        .get(&("@".to_string(), RecordType::SOA))
        .unwrap()[0];
    assert_eq!(
        soa.value.split_whitespace().nth(2),
        Some(zone.serial.to_string().as_str()),
        "the served SOA serial tracks the serialized commits"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 10. NOTIFY: bad MAC and non-allowlisted source
// ══════════════════════════════════════════════════════════════════════

fn notify_query(id: u16, zone: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&(4u16 << 11).to_be_bytes()); // opcode NOTIFY
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&encode_qname(zone));
    query.extend_from_slice(&6u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

#[test]
fn notify_rejects_bad_mac_and_non_allowlisted_source() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 10),
    );
    let cache = Arc::new(synvoid_dns::cache::DnsCache::new(1000, 300, 1));
    let cache_key =
        synvoid_dns::cache::CacheKey::new("example.test".to_string(), RecordType::SOA, None);
    cache.insert(cache_key.clone(), vec![0xAA], 300);

    let config = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones.clone(), config)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_require_tsig(true)
        .with_tsig_verifier(tsig_verifier(TestAlg::Sha256))
        .with_cache(cache.clone());

    let allowed: IpAddr = "10.0.0.1".parse().unwrap();
    let outsider: IpAddr = "192.0.2.66".parse().unwrap();

    // A valid signature from the allowlisted source is accepted.
    let mut good = notify_query(0x6001, "example.test");
    sign_message(
        &mut good,
        KEY_NAME,
        TestAlg::Sha256,
        SECRET,
        now_secs(),
        300,
        None,
    );
    let response = handler.handle_notify(&good, allowed).expect("answered");
    assert_eq!(response_rcode(&response), wire::RCODE_NOERROR);
    assert!(
        cache.get(&cache_key).is_none(),
        "an accepted NOTIFY invalidates the zone cache"
    );

    // A validly-shaped TSIG signed with the wrong secret is NOTAUTH.
    cache.insert(cache_key.clone(), vec![0xAA], 300);
    let mut bad = notify_query(0x6002, "example.test");
    sign_message(
        &mut bad,
        KEY_NAME,
        TestAlg::Sha256,
        b"a-different-secret-that-is-long-enough-000000",
        now_secs(),
        300,
        None,
    );
    let response = handler
        .handle_notify(&bad, allowed)
        .expect("a bad MAC is answered NOTAUTH");
    assert_eq!(
        response_rcode(&response),
        wire::UPDATE_RCODE_NOTAUTH,
        "a failed MAC must not be treated as signed"
    );
    assert!(
        cache.get(&cache_key).is_some(),
        "a refused NOTIFY must not invalidate the cache"
    );

    // A non-allowlisted source is dropped even with a valid signature.
    let mut signed = notify_query(0x6003, "example.test");
    sign_message(
        &mut signed,
        KEY_NAME,
        TestAlg::Sha256,
        SECRET,
        now_secs(),
        300,
        None,
    );
    assert!(
        handler.handle_notify(&signed, outsider).is_none(),
        "a non-allowlisted source must be dropped"
    );

    // An unknown zone is NOTAUTH and leaves the known zone's cache alone.
    let mut unknown = notify_query(0x6004, "unknown.test");
    sign_message(
        &mut unknown,
        KEY_NAME,
        TestAlg::Sha256,
        SECRET,
        now_secs(),
        300,
        None,
    );
    let response = handler.handle_notify(&unknown, allowed).expect("answered");
    assert_eq!(response_rcode(&response), wire::UPDATE_RCODE_NOTAUTH);
    assert!(
        cache.get(&cache_key).is_some(),
        "a NOTIFY for an unknown zone must not touch the cache"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 11. DNS cookies: BADCOOKIE, acceptance, tamper
// ══════════════════════════════════════════════════════════════════════

/// Build an EDNS query with an optional COOKIE option.
fn edns_query(id: u16, qname: &str, cookie: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut query = base_query(id, qname, 1);
    set_arcount(&mut query, 1);
    query.push(0); // root name
    query.extend_from_slice(&41u16.to_be_bytes()); // OPT
    query.extend_from_slice(&1232u16.to_be_bytes()); // payload
    query.extend_from_slice(&0u32.to_be_bytes()); // TTL
    let mut options = Vec::new();
    if let Some((client_cookie, server_cookie)) = cookie {
        options.extend_from_slice(&10u16.to_be_bytes());
        options
            .extend_from_slice(&((client_cookie.len() + server_cookie.len()) as u16).to_be_bytes());
        options.extend_from_slice(client_cookie);
        options.extend_from_slice(server_cookie);
    }
    query.extend_from_slice(&(options.len() as u16).to_be_bytes());
    query.extend_from_slice(&options);
    query
}

fn response_opt(response: &[u8]) -> (u8, u8, Vec<u8>) {
    let spans = record_spans(response);
    for (start, rtype, rdlen, rd_start) in spans {
        if rtype == 41 {
            let (_, after_name) = read_name(response, start);
            let ttl = u32::from_be_bytes([
                response[after_name + 4],
                response[after_name + 5],
                response[after_name + 6],
                response[after_name + 7],
            ]);
            return (
                (ttl >> 24) as u8,
                (ttl >> 16) as u8,
                response[rd_start..rd_start + rdlen].to_vec(),
            );
        }
    }
    panic!("response has no OPT record");
}

fn cookie_option_bytes(options: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 4 <= options.len() {
        let code = u16::from_be_bytes([options[pos], options[pos + 1]]);
        let len = u16::from_be_bytes([options[pos + 2], options[pos + 3]]) as usize;
        pos += 4;
        let data = options.get(pos..pos + len)?.to_vec();
        if code == 10 {
            return Some(data);
        }
        pos += len;
    }
    None
}

fn cookie_context<'a>(
    zones: &'a Arc<ShardedZoneStore>,
    zone_trie: &'a Arc<parking_lot::RwLock<synvoid_dns::zone_trie::ZoneTrie>>,
    ecs: &'a EcsFilterConfig,
    server: &'a Arc<DnsCookieServer>,
) -> QueryContext<'a> {
    let mut ctx = support::make_ctx(zones, zone_trie, ecs);
    ctx.cookie_server = Some(server);
    ctx
}

fn basic_zones() -> (
    Arc<ShardedZoneStore>,
    Arc<parking_lot::RwLock<synvoid_dns::zone_trie::ZoneTrie>>,
    EcsFilterConfig,
) {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_records("test.local", 1));
    let mut trie = synvoid_dns::zone_trie::ZoneTrie::new();
    trie.insert("test.local");
    (
        zones,
        Arc::new(parking_lot::RwLock::new(trie)),
        EcsFilterConfig::default(),
    )
}

#[test]
fn cookie_flow_requires_a_valid_server_cookie_on_udp() {
    let (zones, zone_trie, ecs) = basic_zones();
    let cookie_server = Arc::new(DnsCookieServer::new().with_required(true));
    let ctx = cookie_context(&zones, &zone_trie, &ecs, &cookie_server);
    let client: IpAddr = "203.0.113.7".parse().unwrap();

    // 1. No COOKIE option: BADCOOKIE (extended RCODE 23) plus a fresh cookie.
    let query = edns_query(0x7001, "www.test.local", None);
    let response = DnsServer::handle_query_with_transport(
        &ctx,
        &query,
        Some(client),
        TransportClass::UdpEdns(1232),
    )
    .expect("a BADCOOKIE challenge is a response");
    assert_eq!(
        response[3] & 0x0F,
        7,
        "the header carries the low nibble of BADCOOKIE"
    );
    let (ext_rcode, _, options) = response_opt(&response);
    assert_eq!(ext_rcode, 1, "the OPT TTL carries the high nibble");
    assert_eq!(
        (u16::from(ext_rcode) << 4) | u16::from(response[3] & 0x0F),
        23,
        "the full extended RCODE is BADCOOKIE"
    );
    let cookie = cookie_option_bytes(&options).expect("a COOKIE option is returned");
    assert_eq!(cookie.len(), 16, "8-byte client + 8-byte server cookie");

    // 2. A valid cookie lets the query through, with a refreshed cookie.
    let client_cookie = [0x11u8; 8];
    let server_cookie = cookie_server.generate_server_cookie(client, &client_cookie);
    let query = edns_query(
        0x7002,
        "www.test.local",
        Some((&client_cookie, &server_cookie)),
    );
    let response = DnsServer::handle_query_with_transport(
        &ctx,
        &query,
        Some(client),
        TransportClass::UdpEdns(1232),
    )
    .expect("a valid cookie is answered");
    assert_eq!(response_rcode(&response), wire::RCODE_NOERROR);
    assert!(
        u16::from_be_bytes([response[6], response[7]]) >= 1,
        "the question is answered"
    );
    let (ext_rcode, _, options) = response_opt(&response);
    let refreshed = cookie_option_bytes(&options).expect("the answer refreshes the cookie");
    assert_eq!(refreshed.len(), 16);
    assert_eq!(
        &refreshed[..8],
        &client_cookie,
        "the client cookie is echoed"
    );
    assert_eq!(
        &refreshed[8..],
        cookie_server
            .generate_server_cookie(client, &client_cookie)
            .as_slice(),
        "the refreshed server cookie is derived from this client"
    );
    assert_eq!(ext_rcode, 0);

    // 3. A tampered server cookie is BADCOOKIE again.
    let mut tampered = server_cookie.clone();
    tampered[0] ^= 0xFF;
    let query = edns_query(0x7003, "www.test.local", Some((&client_cookie, &tampered)));
    let response = DnsServer::handle_query_with_transport(
        &ctx,
        &query,
        Some(client),
        TransportClass::UdpEdns(1232),
    )
    .expect("a tampered cookie is refused, not answered");
    assert_eq!(response[3] & 0x0F, 7);
    let (ext_rcode, _, _) = response_opt(&response);
    assert_eq!((u16::from(ext_rcode) << 4) | 7, 23);

    // 4. No EDNS at all: the cookie cannot be returned, so REFUSED.
    let plain = base_query(0x7004, "www.test.local", 1);
    let response =
        DnsServer::handle_query_with_transport(&ctx, &plain, Some(client), TransportClass::Udp512)
            .expect("a refusal is a response");
    assert_eq!(response_rcode(&response), wire::RCODE_REFUSED);

    // 5. TCP is exempt: the handshake already proves the source.
    let query = edns_query(0x7005, "www.test.local", None);
    let response =
        DnsServer::handle_query_with_transport(&ctx, &query, Some(client), TransportClass::Tcp)
            .expect("TCP is answered");
    assert_eq!(response_rcode(&response), wire::RCODE_NOERROR);

    // 6. With enforcement off the query is answered as before.
    let lenient = Arc::new(DnsCookieServer::new());
    let ctx = cookie_context(&zones, &zone_trie, &ecs, &lenient);
    let query = edns_query(0x7006, "www.test.local", None);
    let response = DnsServer::handle_query_with_transport(
        &ctx,
        &query,
        Some(client),
        TransportClass::UdpEdns(1232),
    )
    .expect("cookies are optional by default");
    assert_eq!(response_rcode(&response), wire::RCODE_NOERROR);
}
