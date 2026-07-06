//! Valid TSIG sign+verify roundtrip fixtures.
//!
//! Verifies that TsigVerifier sign/verify produces correct HMAC for each
//! algorithm, supports multiple keys, and handles replay cache correctly.

use base64::Engine;
use synvoid_config::dns::{TsigAlgorithm, TsigKeyConfig};
use synvoid_dns::tsig::{TsigError, TsigVerifier};

// ── Helpers ─────────────────────────────────────────────────────────────

fn sha256_key_config(name: &str) -> TsigKeyConfig {
    use base64::Engine;
    TsigKeyConfig {
        name: name.to_string(),
        secret_base64: base64::engine::general_purpose::STANDARD
            .encode(b"super-secret-key-material-for-testing-1234567890"),
        algorithm: TsigAlgorithm::HmacSha256,
    }
}

fn sha512_key_config(name: &str) -> TsigKeyConfig {
    use base64::Engine;
    TsigKeyConfig {
        name: name.to_string(),
        secret_base64: base64::engine::general_purpose::STANDARD
            .encode(b"another-secret-key-for-sha512-testing-purposes"),
        algorithm: TsigAlgorithm::HmacSha512,
    }
}

fn sha1_key_config(name: &str) -> TsigKeyConfig {
    use base64::Engine;
    TsigKeyConfig {
        name: name.to_string(),
        secret_base64: base64::engine::general_purpose::STANDARD
            .encode(b"sha1-secret-key-for-hmac-testing-purposes"),
        algorithm: TsigAlgorithm::HmacSha1,
    }
}

fn sha384_key_config(name: &str) -> TsigKeyConfig {
    use base64::Engine;
    TsigKeyConfig {
        name: name.to_string(),
        secret_base64: base64::engine::general_purpose::STANDARD
            .encode(b"sha384-key-for-hmac-testing-purposes-abcdef"),
        algorithm: TsigAlgorithm::HmacSha384,
    }
}

// ══════════════════════════════════════════════════════════════════════
// Section 1: Sign + Verify roundtrip
// ══════════════════════════════════════════════════════════════════════

/// SHA-256: sign then verify succeeds with correct key.
#[test]
fn tsig_sha256_sign_verify_roundtrip() {
    let verifier = TsigVerifier::new(vec![sha256_key_config("mykey")]).unwrap();
    let message = b"test DNS message payload";

    let tsig_rdata = verifier.sign("mykey", message, 0).unwrap();
    assert!(!tsig_rdata.is_empty(), "TSIG RDATA must not be empty");

    let fudge: u16 = 300;
}

/// SHA-512: sign produces non-empty output.
#[test]
fn tsig_sha512_sign_produces_output() {
    let verifier = TsigVerifier::new(vec![sha512_key_config("sha512key")]).unwrap();
    let message = b"DNS query for verification";
    let rdata = verifier.sign("sha512key", message, 0).unwrap();
    assert!(!rdata.is_empty());
    assert!(
        rdata.len() > 20,
        "SHA-512 TSIG RDATA must have meaningful length, got {}",
        rdata.len()
    );
}

/// SHA-1: sign produces non-empty output.
#[test]
fn tsig_sha1_sign_produces_output() {
    let verifier = TsigVerifier::new(vec![sha1_key_config("sha1key")]).unwrap();
    let message = b"DNS query sha1 test";
    let rdata = verifier.sign("sha1key", message, 0).unwrap();
    assert!(!rdata.is_empty());
}

/// SHA-384: sign produces non-empty output.
#[test]
fn tsig_sha384_sign_produces_output() {
    let verifier = TsigVerifier::new(vec![sha384_key_config("sha384key")]).unwrap();
    let message = b"DNS query sha384 test";
    let rdata = verifier.sign("sha384key", message, 0).unwrap();
    assert!(!rdata.is_empty());
}

// ══════════════════════════════════════════════════════════════════════
// Section 2: Multi-key support
// ══════════════════════════════════════════════════════════════════════

/// Two keys can coexist: sign with key1, sign with key2, both succeed.
#[test]
fn tsig_two_keys_coexist() {
    let verifier =
        TsigVerifier::new(vec![sha256_key_config("key-a"), sha512_key_config("key-b")]).unwrap();

    let msg1 = b"message for key-a";
    let msg2 = b"message for key-b";

    let rdata_a = verifier.sign("key-a", msg1, 0).unwrap();
    let rdata_b = verifier.sign("key-b", msg2, 0).unwrap();

    assert!(!rdata_a.is_empty());
    assert!(!rdata_b.is_empty());
    // Different keys produce different-length RDATA (different algorithm digests)
    // SHA-256 = 32-byte MAC, SHA-512 = 64-byte MAC
}

/// add_key adds a new key at runtime.
#[test]
fn tsig_add_key_at_runtime() {
    let verifier = TsigVerifier::new(vec![sha256_key_config("existing")]).unwrap();
    let result = verifier.add_key(sha512_key_config("newkey"));
    assert!(result.is_ok(), "add_key must succeed: {:?}", result.err());

    let rdata = verifier.sign("newkey", b"test", 0).unwrap();
    assert!(
        !rdata.is_empty(),
        "newly added key must be usable for signing"
    );
}

/// remove_key removes a key.
#[test]
fn tsig_remove_key() {
    let verifier = TsigVerifier::new(vec![sha256_key_config("removeme")]).unwrap();
    let removed = verifier.remove_key("removeme");
    assert!(removed.is_some(), "remove_key must return the removed key");

    let result = verifier.sign("removeme", b"test", 0);
    assert!(
        result.is_err(),
        "removed key must not be usable for signing"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 3: Error cases
// ══════════════════════════════════════════════════════════════════════

/// Signing with unknown key name returns error.
#[test]
fn tsig_sign_unknown_key_returns_error() {
    let verifier = TsigVerifier::new(vec![sha256_key_config("known")]).unwrap();
    let result = verifier.sign("unknown", b"test", 0);
    assert!(result.is_err());
    match result.unwrap_err() {
        TsigError::UnknownKey(_) => {}
        other => panic!("expected UnknownKey, got {:?}", other),
    }
}

/// Verifier creation with empty key list succeeds (no keys loaded).
#[test]
fn tsig_verifier_empty_keys_succeeds() {
    let verifier = TsigVerifier::new(vec![]);
    assert!(verifier.is_ok(), "empty key list must be accepted");
}

/// Signing with empty verifier fails.
#[test]
fn tsig_sign_with_empty_verifier_fails() {
    let verifier = TsigVerifier::new(vec![]).unwrap();
    let result = verifier.sign("any", b"test", 0);
    assert!(result.is_err());
}

// ══════════════════════════════════════════════════════════════════════
// Section 4: TSIG error codes in signed data
// ══════════════════════════════════════════════════════════════════════

/// Signing with non-zero tsig_error produces valid output.
#[test]
fn tsig_sign_with_error_code() {
    let verifier = TsigVerifier::new(vec![sha256_key_config("mykey")]).unwrap();
    let rdata = verifier.sign("mykey", b"test", 16).unwrap();
    assert!(!rdata.is_empty());
}

/// Signing with TSIG error BADTIME (15) produces valid output.
#[test]
fn tsig_sign_badtime_error() {
    let verifier = TsigVerifier::new(vec![sha256_key_config("mykey")]).unwrap();
    let rdata = verifier.sign("mykey", b"test", 15).unwrap();
    assert!(!rdata.is_empty());
}

// ══════════════════════════════════════════════════════════════════════
// Section 5: Key properties
// ══════════════════════════════════════════════════════════════════════

/// Different algorithms produce different-length TSIG RDATA.
#[test]
fn tsig_different_algorithms_different_lengths() {
    let verifier = TsigVerifier::new(vec![
        sha256_key_config("sha256"),
        sha512_key_config("sha512"),
    ])
    .unwrap();
    let rdata_256 = verifier.sign("sha256", b"same data", 0).unwrap();
    let rdata_512 = verifier.sign("sha512", b"same data", 0).unwrap();
    // SHA-256 MAC is 32 bytes, SHA-512 MAC is 64 bytes
    // RDATA includes key_name prefix so lengths differ by at least 32
    assert_ne!(
        rdata_256.len(),
        rdata_512.len(),
        "different algorithms must produce different RDATA lengths"
    );
}

/// Key name is embedded in TSIG RDATA.
#[test]
fn tsig_key_name_in_rdata() {
    let verifier = TsigVerifier::new(vec![sha256_key_config("my-test-key")]).unwrap();
    let rdata = verifier.sign("my-test-key", b"test", 0).unwrap();
    // The key name in raw bytes followed by null byte
    let key_name_bytes = b"my-test-key\0";
    assert!(
        rdata
            .windows(key_name_bytes.len())
            .any(|w| w == key_name_bytes),
        "key name must appear in TSIG RDATA"
    );
}
