//! Phase 27 differential contract: old `synvoid-mesh` paths vs new
//! `synvoid-mesh-protocol` primitives must agree byte-for-byte.
//!
//! Proves no authority-semantic change during extraction: Ed25519 verification,
//! hybrid envelope encoding, replay classification, threat serde, and
//! length-prefix framing behave identically through both import paths.

use synvoid_mesh::hybrid_signature::HybridSignature as MeshHybridSignature;
use synvoid_mesh::protocol::{
    AckStatus, AnnounceAction, MeshMessageSigner, MessageCategory,
    ReplayProtection as MeshReplayProtection, ThreatIndicator as MeshThreatIndicator,
    ThreatSeverity as MeshThreatSeverity, ThreatType as MeshThreatType,
};
use synvoid_mesh_protocol::{
    HybridSignature as ProtocolHybridSignature, ProtocolSigner, ReplayProtection as ProtocolReplay,
    ThreatIndicator as ProtocolThreatIndicator,
};

#[test]
fn ed25519_verify_differential() {
    let secret = [42u8; 32];
    let mesh_signer = MeshMessageSigner::new(secret);
    let proto_signer = ProtocolSigner::new(secret);
    let content = b"differential-wire-contract";
    let sig = mesh_signer.sign(content);
    // Protocol-only signer must verify mesh-produced signatures.
    let pk = mesh_signer.get_public_key_bytes();
    assert!(proto_signer.verify(content, &sig, &pk));
    assert!(mesh_signer.verify(content, &sig, &pk));
    // And vice versa.
    let sig2 = proto_signer.sign(content);
    assert!(mesh_signer.verify(content, &sig2, &pk));
    assert!(!mesh_signer.verify(b"tampered", &sig, &pk));
    assert!(!proto_signer.verify(b"tampered", &sig, &pk));
}

#[test]
fn hybrid_envelope_encoding_differential() {
    let sig = MeshHybridSignature::ed25519_only(vec![5u8; 64], "diff-key".to_string());
    let mesh_bytes = sig.to_bytes();
    let proto_sig = ProtocolHybridSignature::ed25519_only(vec![5u8; 64], "diff-key".to_string());
    let proto_bytes = proto_sig.to_bytes();
    assert_eq!(mesh_bytes, proto_bytes);
    let from_mesh = ProtocolHybridSignature::from_bytes(&mesh_bytes).unwrap();
    let from_proto = MeshHybridSignature::from_bytes(&proto_bytes).unwrap();
    assert_eq!(from_mesh.ed25519_public_key, from_proto.ed25519_public_key);
}

#[test]
fn replay_classification_differential() {
    let now = 1_700_000_000u64;
    let mut mesh = MeshReplayProtection::new();
    let mut proto = ProtocolReplay::new();
    for (nonce, ts) in [("a", now), ("a", now), ("b", now - 61), ("c", now + 61)] {
        let m = mesh.check_and_add_at(nonce, ts, now);
        let p = proto.check_and_add_at(nonce, ts, now);
        assert_eq!(
            format!("{:?}", m),
            format!("{:?}", p),
            "nonce={} ts={}",
            nonce,
            ts
        );
    }
}

#[test]
fn threat_serde_differential() {
    let mesh_indicator = MeshThreatIndicator {
        threat_type: MeshThreatType::IpBlock,
        indicator_value: "198.51.100.7".to_string(),
        severity: MeshThreatSeverity::Critical,
        reason: "diff".to_string(),
        ttl_seconds: 600,
        source_node_id: "n1".to_string(),
        timestamp: 1700000000,
        site_scope: String::new(),
        rate_limit_requests: None,
        rate_limit_window_secs: None,
        suspicious_pattern: None,
        signature: vec![],
        signer_public_key: None,
    };
    let proto_indicator = ProtocolThreatIndicator {
        threat_type: synvoid_mesh_protocol::ThreatType::IpBlock,
        indicator_value: "198.51.100.7".to_string(),
        severity: synvoid_mesh_protocol::ThreatSeverity::Critical,
        reason: "diff".to_string(),
        ttl_seconds: 600,
        source_node_id: "n1".to_string(),
        timestamp: 1700000000,
        site_scope: String::new(),
        rate_limit_requests: None,
        rate_limit_window_secs: None,
        suspicious_pattern: None,
        signature: vec![],
        signer_public_key: None,
    };
    let mesh_json = serde_json::to_value(&mesh_indicator).unwrap();
    let proto_json = serde_json::to_value(&proto_indicator).unwrap();
    assert_eq!(mesh_json, proto_json);
    let mesh_pc = postcard::to_allocvec(&mesh_indicator).unwrap();
    let proto_pc = postcard::to_allocvec(&proto_indicator).unwrap();
    assert_eq!(mesh_pc, proto_pc);
}

#[test]
fn wire_enum_codes_stable() {
    assert_eq!(AckStatus::Success.as_u8(), 0);
    assert_eq!(AckStatus::from_u8(6), AckStatus::InternalError);
    assert_eq!(AckStatus::from_u8(99), AckStatus::InternalError);
    assert_eq!(
        AnnounceAction::from_u8(2).unwrap(),
        synvoid_mesh::protocol::AnnounceAction::Remove
    );
    assert_eq!(MessageCategory::ThreatIntel.name(), "ThreatIntel");
    assert_eq!(synvoid_mesh_protocol::ThreatType::DomainBlock as i32, 6);
}

#[test]
fn framing_matches_mesh_length_prefix_semantics() {
    // Mesh `encode_with_length` = 4-byte BE length + payload. Protocol helper
    // must produce identical bytes for the same payload.
    let payload = b"framing-diff".to_vec();
    let proto_framed = synvoid_mesh_protocol::framing::encode_with_length_prefix(&payload).unwrap();
    let mut expected = (payload.len() as u32).to_be_bytes().to_vec();
    expected.extend_from_slice(&payload);
    assert_eq!(proto_framed, expected);
}
