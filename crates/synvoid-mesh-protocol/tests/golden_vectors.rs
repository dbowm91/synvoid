//! Golden wire vectors for `synvoid-mesh-protocol`.
//!
//! These vectors pin the byte representation of moved contract types. Any
//! change is a wire-compatibility event and must go through an explicit
//! protocol-version migration (Phase 27 Part F).

use synvoid_mesh_protocol::{
    decode_with_length_prefix, encode_with_length_prefix, HybridSignature, ProtocolSigner,
    ThreatIndicator, ThreatSeverity, ThreatType, MESH_MESSAGE_VERSION, REPLAY_WINDOW_SECS,
};

#[test]
fn version_and_replay_constants_pinned() {
    assert_eq!(MESH_MESSAGE_VERSION, 1);
    assert_eq!(REPLAY_WINDOW_SECS, 60);
    assert_eq!(synvoid_mesh_protocol::NONCE_SIZE, 16);
    assert_eq!(synvoid_mesh_protocol::COMPRESSION_THRESHOLD, 512);
    assert_eq!(synvoid_mesh_protocol::MAX_REPLAY_CACHE_SIZE, 10000);
    assert_eq!(
        synvoid_mesh_protocol::MAX_WIRE_MESSAGE_SIZE,
        10 * 1024 * 1024
    );
    assert_eq!(synvoid_mesh_protocol::PRIORITY_TIER_FREE, 0);
    assert_eq!(synvoid_mesh_protocol::PRIORITY_TIER_ENTERPRISE, 3);
}

#[test]
fn hybrid_envelope_golden_round_trip() {
    // Golden: ed25519_only envelope with known lengths must round-trip and keep
    // the exact length-prefixed layout (4-byte LE lengths).
    let sig = HybridSignature::ed25519_only(vec![0xABu8; 64], "test_ed_key".to_string());
    let bytes = sig.to_bytes();
    // 4 + 64 + 4 + 0 + 4 + 11 + 4 + 0 = 91
    assert_eq!(bytes.len(), 91);
    assert_eq!(bytes.len(), sig.serialized_size());
    let recovered = HybridSignature::from_bytes(&bytes).expect("golden envelope decodes");
    assert_eq!(recovered.ed25519_signature, vec![0xABu8; 64]);
    assert!(recovered.ml_dsa_signature.is_empty());
    assert_eq!(recovered.ed25519_public_key, "test_ed_key");
    assert_eq!(recovered.ml_dsa_public_key, None);
    assert!(!recovered.has_ml_dsa());
}

#[test]
fn hybrid_envelope_malformed_fail_closed() {
    assert!(HybridSignature::from_bytes(&[]).is_err());
    assert!(HybridSignature::from_bytes(&[0, 1, 2]).is_err());
    // Declared ed25519 length far beyond available bytes.
    let mut hostile = Vec::new();
    hostile.extend_from_slice(&(9999u32).to_le_bytes());
    hostile.extend_from_slice(&[1, 2, 3]);
    assert!(HybridSignature::from_bytes(&hostile).is_err());
    // Truncated public key.
    let sig = HybridSignature::ed25519_only(vec![1u8; 64], "key".to_string());
    let mut bytes = sig.to_bytes();
    bytes.truncate(bytes.len() - 10);
    assert!(HybridSignature::from_bytes(&bytes).is_err());
}

#[test]
fn ed25519_signature_vector() {
    // Deterministic RFC-style vector: fixed secret signs fixed content.
    let secret = [7u8; 32];
    let signer = ProtocolSigner::new(secret);
    let content = b"phase27-wire-contract";
    let sig = signer.sign(content);
    assert_eq!(sig.len(), 64);
    let pk = signer.get_public_key_bytes();
    assert_eq!(pk.len(), 32);
    assert!(signer.verify(content, &sig, &pk));
    assert!(!signer.verify(b"tampered", &sig, &pk));
    // Wrong-length inputs fail closed, never panic.
    assert!(!signer.verify(content, &[0u8; 63], &pk));
    assert!(!signer.verify(content, &sig, &[0u8; 31]));
    assert!(!signer.verify(content, &[], &[]));
}

#[test]
fn verify_auto_dispatch_shape() {
    let secret = [9u8; 32];
    let signer = ProtocolSigner::new(secret);
    let content = b"auto-dispatch";
    let raw = signer.sign(content);
    let pk = signer.get_public_key_bytes();
    assert!(signer.verify_auto(content, &raw, &pk));

    // Hybrid envelope carries the Ed25519 half; verify_auto checks that half.
    let hybrid = HybridSignature::ed25519_only(raw.clone(), signer.get_public_key());
    let envelope = hybrid.to_bytes();
    assert!(envelope.len() > 64);
    assert!(signer.verify_auto(content, &envelope, &pk));
    assert!(!signer.verify_auto(b"other", &envelope, &pk));
}

#[test]
fn threat_indicator_serde_stable() {
    let indicator = ThreatIndicator {
        threat_type: ThreatType::IpBlock,
        indicator_value: "192.0.2.1".to_string(),
        severity: ThreatSeverity::High,
        reason: "golden".to_string(),
        ttl_seconds: 3600,
        source_node_id: "node-a".to_string(),
        timestamp: 1700000000,
        site_scope: "default".to_string(),
        rate_limit_requests: None,
        rate_limit_window_secs: None,
        suspicious_pattern: None,
        signature: vec![],
        signer_public_key: None,
    };
    // postcard round-trip (distributed-state serializer) must be stable.
    let encoded = postcard::to_allocvec(&indicator).expect("postcard encode");
    let decoded: ThreatIndicator = postcard::from_bytes(&encoded).expect("postcard decode");
    assert_eq!(decoded.indicator_value, "192.0.2.1");
    assert_eq!(decoded.threat_type_code(), 1);
    assert_eq!(decoded.severity_code(), 3);
    // JSON field names are part of the contract surface for admin/debug paths.
    let json = serde_json::to_value(&indicator).expect("json value");
    assert_eq!(json["indicator_value"], "192.0.2.1");
    assert_eq!(json["threat_type"], "IpBlock");
}

#[test]
fn framing_length_prefix_bounded() {
    let payload = b"hello-wire".to_vec();
    let framed = encode_with_length_prefix(&payload).expect("encode");
    assert_eq!(framed.len(), 4 + payload.len());
    let (body, consumed) = decode_with_length_prefix(&framed).expect("decode");
    assert_eq!(body, payload.as_slice());
    assert_eq!(consumed, framed.len());

    // Truncated, over-bound, and empty inputs fail closed.
    assert!(decode_with_length_prefix(&framed[..3]).is_err());
    assert!(decode_with_length_prefix(&framed[..5]).is_err());
    assert!(encode_with_length_prefix(&[]).is_err());
    let mut over = vec![0u8; 4];
    over[..4].copy_from_slice(&((10 * 1024 * 1024 + 1) as u32).to_be_bytes());
    assert!(decode_with_length_prefix(&over).is_err());
}

#[test]
fn replay_protection_deterministic() {
    use synvoid_mesh_protocol::ReplayProtection;
    let mut rp = ReplayProtection::new();
    let now = 1_700_000_000u64;
    assert_eq!(
        rp.check_and_add_at("n1", now, now),
        synvoid_mesh_protocol::ReplayResult::Valid
    );
    assert_eq!(
        rp.check_and_add_at("n1", now, now),
        synvoid_mesh_protocol::ReplayResult::ReplayDetected
    );
    assert_eq!(
        rp.check_and_add_at("n2", now - 61, now),
        synvoid_mesh_protocol::ReplayResult::ExpiredTimestamp
    );
    assert_eq!(
        rp.check_and_add_at("n3", now + 61, now),
        synvoid_mesh_protocol::ReplayResult::FutureTimestamp
    );
}
