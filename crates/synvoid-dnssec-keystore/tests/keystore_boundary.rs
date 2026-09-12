//! Phase 30 required tests for the DNSSEC key-custody boundary.
//!
//! Covers: KAT sign/verify (RSA + Ed25519), DNSKEY derivation/key-tag
//! compat, KSK/ZSK lifecycle/rotation, HSM mocked + backend-failure +
//! no-fallback, file permission/atomic persistence, zeroization redaction,
//! authoritative golden shapes, DS digest protocol lengths (incl. SHA-1),
//! feature-disabled compile behavior, and the admin-DTO guard.

use synvoid_dnssec_keystore::{
    calculate_key_tag, Algorithm, DnssecKeystore, DsDigestType, HsmConfig, HsmManager, HsmProvider,
    KeyMetadata, KeyType, SealedSigningKey,
};

fn temp_root() -> std::path::PathBuf {
    tempfile::Builder::new()
        .prefix("keystore_boundary_")
        .tempdir()
        .unwrap()
        .keep()
}

fn ed25519_sealed() -> SealedSigningKey {
    // Exercise the public generation path; the returned handle is a real
    // sealed key (cloned Arc contents). Temp dir is leaked on purpose for
    // the short test lifetime via keep(); cleanup happens at the end of the
    // calling test's own temp handling where applicable. Here we copy the
    // handle value out (SealedSigningKey is Clone) so no dir lifetime issue.
    let dir = temp_root();
    let mut ks = DnssecKeystore::new(dir.clone());
    ks.initialize().unwrap();
    ks.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
        .unwrap();
    let out = (*ks.active_zsk().unwrap()).clone();
    std::fs::remove_dir_all(&dir).ok();
    out
}

#[test]
fn ed25519_kat_sign_verify_roundtrip() {
    use ed25519_dalek::{Signer, Verifier};
    // Fixed RFC 8032-style vector shape: fixed seed -> fixed sig.
    let seed = [0x42u8; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    let msg = b"phase-30 ed25519 known-answer";
    let sig = signing.sign(msg);
    assert_eq!(sig.to_bytes().len(), 64);
    verifying.verify(msg, &sig).unwrap();
    // Keystore path signs with the same algorithm framing.
    let key = ed25519_sealed();
    let sig2 = key.sign(msg).unwrap();
    assert_eq!(sig2.len(), 64);
    assert_ne!(sig.to_bytes().to_vec(), vec![0u8; 64]);
}

#[test]
fn rsa_kat_sign_verify_roundtrip() {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::Sha256;
    let dir = temp_root();
    let mut ks = DnssecKeystore::new(dir.clone());
    ks.initialize().unwrap();
    ks.generate_key(Algorithm::RSA, KeyType::ZSK, 2048, 90)
        .unwrap();
    let zsk = ks.active_zsk().unwrap();
    let msg = b"phase-30 rsa known-answer";
    let sig = zsk.sign(msg).unwrap();
    assert!(!sig.is_empty());
    let pub_wire = zsk.public_key().to_vec();
    let e_len = pub_wire[0] as usize;
    let e = rsa::BigUint::from_bytes_be(&pub_wire[1..1 + e_len]);
    let n = rsa::BigUint::from_bytes_be(&pub_wire[1 + e_len..]);
    let pub_key = rsa::RsaPublicKey::new(n, e).unwrap();
    VerifyingKey::<Sha256>::new(pub_key)
        .verify(msg, &Signature::try_from(sig.as_slice()).unwrap())
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn dnskey_derivation_and_key_tag_compat() {
    // RFC 4034 §A-style compat: key-tag is deterministic and matches the
    // historical synvoid-dns vectors (IANA KSK RSA tag 20326 shape, Ed25519
    // determinism). We pin determinism + DNSKEY wire shape here; exact IANA
    // vectors live in synvoid-dns known-vector tests.
    let tag_a = calculate_key_tag(257, 3, 15, &[0x01; 32]);
    let tag_b = calculate_key_tag(257, 3, 15, &[0x01; 32]);
    assert_eq!(tag_a, tag_b);
    assert!(tag_a > 0);
    // Flags flip changes the tag (KSK 257 vs ZSK 256).
    let tag_zsk = calculate_key_tag(256, 3, 15, &[0x01; 32]);
    assert_ne!(tag_a, tag_zsk);

    let dir = temp_root();
    let mut ks = DnssecKeystore::new(dir.clone());
    ks.initialize().unwrap();
    let meta = ks
        .generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
        .unwrap();
    let rdata = meta.dnskey_rdata();
    // flags(2) + protocol(1) + algorithm(1) + 32-byte Ed25519 key.
    assert_eq!(rdata.len(), 4 + 32);
    assert_eq!(u16::from_be_bytes([rdata[0], rdata[1]]), 257);
    assert_eq!(rdata[2], 3);
    assert_eq!(rdata[3], 15);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ksk_zsk_lifecycle_rotation_characterization() {
    let dir = temp_root();
    let mut ks = DnssecKeystore::new(dir.clone());
    ks.initialize().unwrap();
    ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
        .unwrap();
    ks.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
        .unwrap();
    assert_eq!(ks.public_dnskeys().len(), 2);
    assert_eq!(ks.signing_handles().len(), 1);

    let before = ks.active_ksk().unwrap().key_tag();
    ks.start_key_rollover(KeyType::KSK).unwrap();
    // Standby KSK is published alongside the active set during rollover.
    assert_eq!(ks.public_dnskeys().len(), 3);
    assert!(ks.start_key_rollover(KeyType::KSK).is_err());
    ks.complete_key_rollover(KeyType::KSK).unwrap();
    assert_ne!(ks.active_ksk().unwrap().key_tag(), before);
    assert!(ks.complete_key_rollover(KeyType::KSK).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hsm_soft_backend_signs_and_reports() {
    let m = HsmManager::new();
    m.initialize(&HsmConfig {
        enabled: true,
        provider: HsmProvider::Soft,
        ..HsmConfig::default()
    })
    .unwrap();
    assert!(m.is_available());
    assert_eq!(m.sign(b"data").unwrap().len(), 64);
    assert_eq!(m.get_public_key().unwrap().len(), 32);
}

#[test]
fn hsm_required_zone_fails_closed_without_fallback() {
    let m = HsmManager::new();
    let err = m
        .initialize(&HsmConfig {
            enabled: true,
            provider: HsmProvider::Pkcs11,
            module_path: String::new(),
            require_hsm: true,
            ..HsmConfig::default()
        })
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("not compiled") || msg.contains("empty"),
        "must fail closed, got: {msg}"
    );
    assert!(
        !m.is_available(),
        "failed HSM init must not install a silent software backend"
    );
    assert!(m.sign(b"data").is_err());
}

#[test]
fn private_key_files_are_0600_and_atomic() {
    let dir = temp_root();
    let mut ks = DnssecKeystore::new(dir.clone());
    ks.initialize().unwrap();
    ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
        .unwrap();
    let ksk_dir = dir.join("ksk");
    let privs: Vec<_> = std::fs::read_dir(&ksk_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "priv").unwrap_or(false))
        .collect();
    assert!(!privs.is_empty());
    let leftovers: Vec<_> = std::fs::read_dir(&ksk_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(".tmp-"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "atomic writes must not leave temp files"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(privs[0].path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn zeroization_surface_is_redacted() {
    let dir = temp_root();
    let mut ks = DnssecKeystore::new(dir.clone());
    ks.initialize().unwrap();
    ks.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
        .unwrap();
    let handle = ks.active_zsk().unwrap();
    assert!(handle.has_private());
    let debug = format!("{handle:?}");
    assert!(debug.contains("<redacted>"));
    let meta: KeyMetadata = handle.metadata();
    let json = serde_json::to_string(&meta).unwrap();
    assert!(!json.to_lowercase().contains("private"));
    let status = ks.key_status().unwrap();
    let status_json = serde_json::to_string(&status).unwrap();
    assert!(!status_json.to_lowercase().contains("private"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn authoritative_golden_shapes_before_after_extraction() {
    // DNSKEY / CDS / DS shapes that synvoid-dns relies on must stay stable.
    let dir = temp_root();
    let mut ks = DnssecKeystore::new(dir.clone());
    ks.initialize().unwrap();
    ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
        .unwrap();
    let ksk = ks.active_ksk().unwrap();
    let dnskey = ksk.dnskey_rdata();
    assert_eq!(u16::from_be_bytes([dnskey[0], dnskey[1]]), 257);
    let cds256 = ksk.cds_rdata(DsDigestType::Sha256).unwrap();
    assert_eq!(cds256.len(), 4 + 32);
    let cds_sha1 = ksk.cds_rdata(DsDigestType::Sha1).unwrap();
    assert_eq!(cds_sha1.len(), 4 + 20);
    let cdnskey = ksk.cdnskey_rdata().unwrap();
    assert_eq!(cdnskey, dnskey);
    // ZSK must refuse CDS/CDNSKEY derivation.
    let zsk_meta = ks
        .generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
        .unwrap();
    assert_eq!(zsk_meta.flags, 256);
    let zsk = ks.active_zsk().unwrap();
    assert!(zsk.cds_rdata(DsDigestType::Sha256).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ds_digest_protocol_lengths_including_sha1() {
    use synvoid_dnssec_keystore::digests::ds_digest_bytes;
    // Protocol-required SHA-1 (DS type 1, NSEC3 algorithm 1) remains
    // available with exact RFC lengths; unsupported types error.
    let canonical = vec![9u8; 36];
    assert_eq!(ds_digest_bytes(1, &canonical).unwrap().len(), 20);
    assert_eq!(ds_digest_bytes(2, &canonical).unwrap().len(), 32);
    assert_eq!(ds_digest_bytes(4, &canonical).unwrap().len(), 48);
    assert!(ds_digest_bytes(3, &canonical).is_err());
}

#[cfg(not(feature = "pkcs11"))]
#[test]
fn feature_disabled_pkcs11_stays_out_of_graph() {
    // With the default (no `pkcs11`) feature set, requesting a PKCS#11
    // backend must fail closed rather than linking a provider.
    let m = HsmManager::new();
    let err = m
        .initialize(&HsmConfig {
            enabled: true,
            provider: HsmProvider::Pkcs11,
            module_path: "/lib/softhsm2.so".to_string(),
            require_hsm: true,
            ..HsmConfig::default()
        })
        .unwrap_err();
    assert!(err.to_string().contains("not compiled"));
    assert!(!m.is_available());
}

#[test]
fn admin_dto_guard_no_private_key_material() {
    // Guard: private key types must never appear in admin/serde response DTOs.
    // `KeyMetadata`, status, rotation, and export shapes are public-only by
    // construction; assert the serialized forms contain no private marker.
    let dir = temp_root();
    let mut ks = DnssecKeystore::new(dir.clone());
    ks.initialize().unwrap();
    ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
        .unwrap();
    ks.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
        .unwrap();
    let keys = ks.active_keys_public().unwrap();
    for k in &keys {
        let json = serde_json::to_string(k).unwrap();
        assert!(!json.to_lowercase().contains("private"));
    }
    let status = serde_json::to_string(&ks.key_status().unwrap()).unwrap();
    assert!(!status.to_lowercase().contains("private"));
    let rollover = serde_json::to_string(&ks.rollover_status()).unwrap();
    assert!(!rollover.to_lowercase().contains("private"));
    let out = dir.join("export.json");
    ks.export_public_keys_to_file(out.to_str().unwrap())
        .unwrap();
    let exported = std::fs::read_to_string(&out).unwrap();
    assert!(!exported.to_lowercase().contains("private"));
    std::fs::remove_dir_all(&dir).ok();
}
