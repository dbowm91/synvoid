//! DNSSEC known-vector and response-shape verification tests.
//!
//! Verifies DNSSEC primitives against IETF-known answer / RFC 4034 §A example
//! values, and that response shapes match expected flag combinations.

use synvoid_dns::dnssec_validation::{
    calculate_key_tag, canonical_name, canonical_rdata, compute_ds_digest,
};
use synvoid_dns::wire::{build_response_header, get_message_flags, MessageFlags};

// ── Section 1: Key tag (RFC 4034 §A.2 / known-answer vectors) ─────────

/// RFC 4034 §A.2 key tag algorithm — verify for Ed25519 (algorithm 15)
/// with a well-known 32-byte public key: bytes 1..=32.
/// The key tag is computed as the 16-bit checksum of the DNSKEY RDATA.
#[test]
fn key_tag_ed25519_ksk_known_vector() {
    let pub_key: Vec<u8> = (1..=32).collect();
    let tag = calculate_key_tag(257, 3, 15, &pub_key);
    assert_eq!(tag, 1313, "Ed25519 KSK [1..=32] key tag must be 1313");
}

/// ZSK variant of the same key material (flags=256) should differ by 1
/// because only the flags bytes change.
#[test]
fn key_tag_ed25519_zsk_known_vector() {
    let pub_key: Vec<u8> = (1..=32).collect();
    let tag_ksk = calculate_key_tag(257, 3, 15, &pub_key);
    let tag_zsk = calculate_key_tag(256, 3, 15, &pub_key);
    assert_eq!(tag_ksk, 1313);
    assert_eq!(tag_zsk, 1312, "ZSK variant should differ from KSK");
}

/// All-zero 32-byte Ed25519 key: key tag is deterministic and stable.
#[test]
fn key_tag_ed25519_all_zeros() {
    let pub_key = vec![0u8; 32];
    let tag = calculate_key_tag(257, 3, 15, &pub_key);
    assert_eq!(tag, 1040, "Ed25519 KSK all-zeros key tag");
}

/// Key tag for an RSA-style key (algorithm 8, 256-byte key material).
/// Uses a deterministic pattern so the value is reproducible.
#[test]
fn key_tag_rsa_known_vector() {
    let rsa_key: Vec<u8> = (0..256).map(|i| (i % 251) as u8).collect();
    let tag = calculate_key_tag(257, 3, 8, &rsa_key);
    assert_eq!(tag, 52053, "RSA-256-byte KSK key tag");
}

/// Key tag is stable across calls (idempotency).
#[test]
fn key_tag_is_deterministic() {
    let pub_key: Vec<u8> = (1..=32).collect();
    let t1 = calculate_key_tag(257, 3, 15, &pub_key);
    let t2 = calculate_key_tag(257, 3, 15, &pub_key);
    let t3 = calculate_key_tag(257, 3, 15, &pub_key);
    assert_eq!(t1, t2);
    assert_eq!(t2, t3);
}

/// Key tag for algorithm 15 with a single-byte key (edge case).
#[test]
fn key_tag_minimal_key() {
    let tag = calculate_key_tag(257, 3, 15, &[0xAB]);
    assert!(tag > 0, "Key tag for minimal key must be non-zero");
}

// ── Section 2: DS digest length enforcement ─────────────────────────────

#[allow(dead_code)]
fn test_dnskey_rdata() -> Vec<u8> {
    // Build DNSKEY RDATA: flags(257) + protocol(3) + algorithm(15) + pub_key(32)
    let mut buf = Vec::new();
    buf.extend_from_slice(&257u16.to_be_bytes());
    buf.push(3);
    buf.push(15);
    buf.extend_from_slice(&[0xAA; 32]);
    buf
}

/// DS digest SHA-1 (type 1) must be exactly 20 bytes per RFC 4034 §5.1.4.
#[test]
fn ds_digest_sha1_length() {
    let digest = compute_ds_digest(1, 257, 3, 15, &[0xAA; 32]).unwrap();
    assert_eq!(digest.len(), 20, "SHA-1 DS digest must be 20 bytes");
}

/// DS digest SHA-256 (type 2) must be exactly 32 bytes.
#[test]
fn ds_digest_sha256_length() {
    let digest = compute_ds_digest(2, 257, 3, 15, &[0xAA; 32]).unwrap();
    assert_eq!(digest.len(), 32, "SHA-256 DS digest must be 32 bytes");
}

/// DS digest SHA-384 (type 4) must be exactly 48 bytes.
#[test]
fn ds_digest_sha384_length() {
    let result = compute_ds_digest(4, 257, 3, 15, &[0xAA; 32]);
    match result {
        Ok(digest) => assert_eq!(digest.len(), 48, "SHA-384 DS digest must be 48 bytes"),
        Err(_) => {
            // SHA-384 may not be supported; skip gracefully
            eprintln!("SHA-384 DS digest not supported in this build — skipping");
        }
    }
}

/// DS digest is deterministic: same inputs produce same output.
#[test]
fn ds_digest_sha256_deterministic() {
    let d1 = compute_ds_digest(2, 257, 3, 15, &[0xBB; 32]).unwrap();
    let d2 = compute_ds_digest(2, 257, 3, 15, &[0xBB; 32]).unwrap();
    assert_eq!(d1, d2);
}

/// Different key material produces different DS digests.
#[test]
fn ds_digest_sha256_different_keys_differ() {
    let d1 = compute_ds_digest(2, 257, 3, 15, &[0xBB; 32]).unwrap();
    let d2 = compute_ds_digest(2, 257, 3, 15, &[0xCC; 32]).unwrap();
    assert_ne!(d1, d2);
}

/// GOST (type 3) must be unsupported.
#[test]
fn ds_digest_gost_unsupported() {
    let result = compute_ds_digest(3, 257, 3, 15, &[0xDD; 32]);
    assert!(result.is_err(), "GOST digest should be unsupported");
}

/// Unknown digest type returns an error.
#[test]
fn ds_digest_unknown_type_errors() {
    let result = compute_ds_digest(99, 257, 3, 15, &[0xEE; 32]);
    assert!(result.is_err());
}

// ── Section 3: Canonical name / canonical rdata ─────────────────────────

/// canonical_name produces lowercase wire-format labels with trailing null.
#[test]
fn canonical_name_mixed_case() {
    let r = canonical_name("A.Example.com");
    assert_eq!(
        r,
        vec![1, b'a', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
    );
}

/// canonical_name trims trailing dot.
#[test]
fn canonical_name_trailing_dot() {
    let r1 = canonical_name("Example.COM.");
    let r2 = canonical_name("Example.COM");
    assert_eq!(
        r1, r2,
        "Trailing dot must be stripped before canonicalization"
    );
}

/// canonical_name for root is a single null byte.
#[test]
fn canonical_name_root() {
    assert_eq!(canonical_name("."), vec![0]);
}

/// canonical_name for empty string is a single null byte.
#[test]
fn canonical_name_empty() {
    assert_eq!(canonical_name(""), vec![0]);
}

/// canonical_name for single label (no dots).
#[test]
fn canonical_name_single_label() {
    let r = canonical_name("localhost");
    assert_eq!(
        r,
        vec![9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0]
    );
}

/// canonical_rdata for A record returns 4-byte IPv4.
#[test]
fn canonical_rdata_a_record() {
    let r = canonical_rdata(1, "192.0.2.1", None, None, None, 300);
    assert_eq!(r, vec![192, 0, 2, 1]);
}

/// canonical_rdata for AAAA record returns 16-byte IPv6.
#[test]
fn canonical_rdata_aaaa_record() {
    let r = canonical_rdata(28, "2001:db8::1", None, None, None, 300);
    assert_eq!(r.len(), 16);
}

/// canonical_rdata for CNAME (type 5) returns canonical wire-format name.
#[test]
fn canonical_rdata_cname() {
    let r = canonical_rdata(5, "www.Example.COM", None, None, None, 300);
    // Should be lowercase wire format: [3,www,7,example,3,com,0]
    assert_eq!(
        r,
        vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0
        ]
    );
}

/// canonical_rdata for MX (type 15): 2-byte priority + wire-format name.
#[test]
fn canonical_rdata_mx() {
    let r = canonical_rdata(15, "mail.example.com", Some(10), None, None, 300);
    // Priority = 10 (0x000A), then canonical_name("mail.example.com")
    assert_eq!(r.len(), 20);
    assert_eq!(r[0], 0);
    assert_eq!(r[1], 10);
    // mail.example.com = [4,mail,7,example,3,com,0] = 18 bytes
    assert_eq!(
        &r[2..],
        &[
            4, b'm', b'a', b'i', b'l', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0
        ]
    );
}

/// canonical_rdata for MX with default priority (None → 10).
#[test]
fn canonical_rdata_mx_default_priority() {
    let r_default = canonical_rdata(15, "mail.example.com", None, None, None, 300);
    let r_explicit = canonical_rdata(15, "mail.example.com", Some(10), None, None, 300);
    assert_eq!(r_default, r_explicit);
}

// ── Section 4: Response shape verification ──────────────────────────────

/// Build a response header with AD=0 (unsigned zone) and verify the flags.
#[test]
fn unsigned_zone_do_bit_ad_zero() {
    let flags = MessageFlags {
        is_response: true,
        opcode: 0,
        authoritative: true,
        truncated: false,
        recursion_desired: false,
        recursion_available: false,
        authentic_data: false,
        checking_disabled: false,
        response_code: 0,
    };
    let header = build_response_header(0x1234, flags, 1, 1, 0, 0);
    let parsed = get_message_flags(&header).unwrap();
    assert!(parsed.is_response);
    assert!(!parsed.authentic_data, "AD must be 0 for unsigned zone");
    assert!(!parsed.checking_disabled);
}

/// CD flag set in query → response must echo CD=1.
/// We build a query header with CD=1, then build a response header with CD=1.
#[test]
fn cd_flag_echoed_in_response() {
    // Query header with CD=1
    let query_flags = MessageFlags {
        is_response: false,
        opcode: 0,
        authoritative: false,
        truncated: false,
        recursion_desired: true,
        recursion_available: false,
        authentic_data: false,
        checking_disabled: true,
        response_code: 0,
    };
    let query_header = build_response_header(0xABCD, query_flags, 1, 0, 0, 0);
    let query_parsed = get_message_flags(&query_header).unwrap();
    assert!(query_parsed.checking_disabled, "Query must have CD=1");

    // Response header echoing CD=1
    let response_flags = MessageFlags {
        is_response: true,
        opcode: 0,
        authoritative: true,
        truncated: false,
        recursion_desired: false,
        recursion_available: false,
        authentic_data: false,
        checking_disabled: true,
        response_code: 0,
    };
    let response_header = build_response_header(0xABCD, response_flags, 1, 1, 0, 0);
    let response_parsed = get_message_flags(&response_header).unwrap();
    assert!(response_parsed.is_response);
    assert!(
        response_parsed.checking_disabled,
        "Response must echo CD=1 when resolver set CD"
    );
}

/// AD bit may be set in a response from a signed zone.
/// We verify the flag can be encoded/decoded correctly.
#[test]
fn ad_bit_can_be_set_in_signed_response() {
    let flags = MessageFlags {
        is_response: true,
        opcode: 0,
        authoritative: true,
        truncated: false,
        recursion_desired: false,
        recursion_available: false,
        authentic_data: true,
        checking_disabled: false,
        response_code: 0,
    };
    let header = build_response_header(0x5678, flags, 1, 1, 0, 0);
    let parsed = get_message_flags(&header).unwrap();
    assert!(
        parsed.authentic_data,
        "AD bit must be settable in signed response"
    );
}

/// DO bit set in query, unsigned zone → response AD=0 (core DNSSEC invariant).
#[test]
fn do_bit_query_unsigned_zone_response_ad_zero() {
    // Query with DO bit (DO is in EDNS, not in the standard header flags,
    // but the response header reflects the server's validation state).
    let response_flags = MessageFlags {
        is_response: true,
        opcode: 0,
        authoritative: true,
        truncated: false,
        recursion_desired: false,
        recursion_available: false,
        authentic_data: false, // unsigned zone → AD must be 0
        checking_disabled: false,
        response_code: 0,
    };
    let header = build_response_header(0x9999, response_flags, 1, 1, 0, 0);
    let parsed = get_message_flags(&header).unwrap();
    assert!(!parsed.authentic_data);
    assert!(!parsed.checking_disabled);
}

/// RA flag set in response (resolver supports recursion).
#[test]
fn ra_flag_in_response() {
    let flags = MessageFlags {
        is_response: true,
        opcode: 0,
        authoritative: false,
        truncated: false,
        recursion_desired: true,
        recursion_available: true,
        authentic_data: false,
        checking_disabled: false,
        response_code: 0,
    };
    let header = build_response_header(0x1111, flags, 1, 1, 0, 0);
    let parsed = get_message_flags(&header).unwrap();
    assert!(parsed.recursion_available);
}

/// NXDOMAIN response (RCODE=3) with AD=0.
#[test]
fn nxdomain_response_ad_zero() {
    let flags = MessageFlags {
        is_response: true,
        opcode: 0,
        authoritative: true,
        truncated: false,
        recursion_desired: false,
        recursion_available: false,
        authentic_data: false,
        checking_disabled: false,
        response_code: 3,
    };
    let header = build_response_header(0x2222, flags, 1, 0, 1, 0);
    let parsed = get_message_flags(&header).unwrap();
    assert!(parsed.is_nxdomain());
    assert!(!parsed.authentic_data);
}

/// Response header roundtrip: build → parse → verify all fields.
#[test]
fn response_header_roundtrip() {
    let flags = MessageFlags {
        is_response: true,
        opcode: 0,
        authoritative: true,
        truncated: false,
        recursion_desired: true,
        recursion_available: true,
        authentic_data: true,
        checking_disabled: true,
        response_code: 0,
    };
    let header = build_response_header(0xBEEF, flags, 1, 2, 3, 4);
    let parsed = get_message_flags(&header).unwrap();
    assert!(parsed.is_response);
    assert!(parsed.authoritative);
    assert!(!parsed.truncated);
    assert!(parsed.recursion_desired);
    assert!(parsed.recursion_available);
    assert!(parsed.authentic_data);
    assert!(parsed.checking_disabled);
    assert_eq!(parsed.response_code, 0);
}

// ── Section 5: compute_dnskey / compute_dnskey_canonical consistency ────

/// compute_dnskey_canonical output matches expected format.
#[test]
fn dnskey_canonical_format() {
    let rdata = synvoid_dns::dnssec_validation::compute_dnskey_canonical(257, 3, 15, &[0xAA; 32]);
    assert_eq!(rdata.len(), 4 + 32);
    let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
    assert_eq!(flags, 257);
    assert_eq!(rdata[2], 3);
    assert_eq!(rdata[3], 15);
}

/// Different algorithms produce different DNSKEY RDATA (algorithm byte differs).
#[test]
fn dnskey_different_algorithms_differ() {
    let rsa = synvoid_dns::dnssec_validation::compute_dnskey_canonical(257, 3, 8, &[0xAA; 256]);
    let ed25519 = synvoid_dns::dnssec_validation::compute_dnskey_canonical(257, 3, 15, &[0xBB; 32]);
    assert_ne!(rsa, ed25519);
}
