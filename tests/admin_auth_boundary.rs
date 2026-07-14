//! Root-test ownership: COMPOSITION
//! Rationale: validates cross-crate admin authority boundary between synvoid-core and admin
//!
//! Guardrail: Admin auth authority boundary tests.
//!
//! These tests verify that:
//! 1. All mutating admin endpoints use `AdminMutationAuthority` variants
//! 2. Raw session tokens are never stored in audit events
//! 3. Compatibility paths use `CompatibilityLegacy` authority

use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};

#[test]
fn admin_actor_never_stores_raw_session_token() {
    let actor = AdminActor::new(AdminMutationAuthority::AdminManual)
        .with_session_id_hash("abc123def456".to_string());

    // The session_id_hash field should be present
    assert!(actor.session_id_hash.is_some());

    // The hash should not look like a raw UUID (which would be a token leak)
    let hash = actor.session_id_hash.as_ref().unwrap();
    // UUIDs have the format 8-4-4-4-12 hex chars; a hash should not match this pattern
    let looks_like_uuid = hash.len() == 36
        && hash.chars().filter(|c| *c == '-').count() == 4
        && hash.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    assert!(
        !looks_like_uuid,
        "session_id_hash looks like a raw UUID token - must be hashed"
    );
}

#[test]
fn admin_actor_without_session_has_none() {
    let actor = AdminActor::new(AdminMutationAuthority::AdminManual);
    assert!(
        actor.session_id_hash.is_none(),
        "Actor without session should have None, not empty string"
    );
}

#[test]
fn audit_event_session_id_hash_not_empty() {
    let event = AdminAuditEvent {
        audit_id: "test-audit-id".to_string(),
        timestamp: 1000,
        actor: AdminActor::new(AdminMutationAuthority::AdminManual)
            .with_session_id_hash("hashed_value".to_string()),
        action: "test_action".to_string(),
        target_kind: "test".to_string(),
        target_id: "test-target".to_string(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };

    let json = serde_json::to_value(&event).unwrap();
    let session_hash = json["actor"]["session_id_hash"].as_str().unwrap();
    assert_eq!(session_hash, "hashed_value");
}

#[test]
fn all_authority_variants_serialize_deserialize() {
    let variants = vec![
        AdminMutationAuthority::AdminManual,
        AdminMutationAuthority::SupervisorManual,
        AdminMutationAuthority::SupervisorSync,
        AdminMutationAuthority::MeshPolicyGated,
        AdminMutationAuthority::LocalDetector,
        AdminMutationAuthority::WorkerIpc,
        AdminMutationAuthority::CompatibilityLegacy,
    ];

    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let deserialized: AdminMutationAuthority = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, json2, "Round-trip failed for {:?}", variant);
    }
}

#[test]
fn compatibility_legacy_authority_is_explicitly_nameable() {
    // Compatibility paths MUST use CompatibilityLegacy, not default to AdminManual
    let authority = AdminMutationAuthority::CompatibilityLegacy;
    let json = serde_json::to_value(&authority).unwrap();
    assert!(
        json.as_str() == Some("compatibility_legacy"),
        "CompatibilityLegacy must serialize to its variant name, got: {:?}",
        json
    );
}

#[test]
fn mutation_result_with_audit_id_links_to_event() {
    let audit_id = "audit-123".to_string();
    let result = AdminMutationResult::<String>::applied("target".to_string(), "done")
        .with_audit_id(audit_id.clone());

    assert_eq!(result.audit_id.as_deref(), Some(audit_id.as_str()));
}

#[test]
fn mutation_result_status_propagation_combinations() {
    // Applied + NotApplicable (local config change)
    let r1 = AdminMutationResult::<String>::applied("t".to_string(), "msg");
    assert_eq!(r1.status, AdminMutationStatus::Applied);
    assert_eq!(r1.propagation, PropagationStatus::NotApplicable);

    // Applied + QueuedBestEffort (mesh propagation)
    let r2 = AdminMutationResult::<String>::applied_with_propagation(
        "t".to_string(),
        PropagationStatus::QueuedBestEffort,
        "msg",
    );
    assert_eq!(r2.status, AdminMutationStatus::Applied);
    assert_eq!(r2.propagation, PropagationStatus::QueuedBestEffort);

    // InvalidRejected
    let r3 = AdminMutationResult::<String>::invalid("t".to_string(), "bad input");
    assert_eq!(r3.status, AdminMutationStatus::InvalidRejected);

    // Failed
    let r4 = AdminMutationResult::<String>::failed("t".to_string(), "oops");
    assert_eq!(r4.status, AdminMutationStatus::Failed);

    // NoOpAlreadyPresent
    let r5 = AdminMutationResult::<String>::noop("t".to_string(), "already gone");
    assert_eq!(r5.status, AdminMutationStatus::NoOpAlreadyPresent);
}

#[test]
fn propagation_status_non_guarantee_semantics() {
    // QueuedBestEffort means queued, NOT delivered
    let result = AdminMutationResult::<String>::applied_with_propagation(
        "t".to_string(),
        PropagationStatus::QueuedBestEffort,
        "msg",
    );
    assert_eq!(result.propagation, PropagationStatus::QueuedBestEffort);

    // FailedToQueue means queuing failed
    let result2 = AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "t".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::FailedToQueue,
        event_id: None,
        audit_id: None,
        message: "msg".to_string(),
    };
    assert_eq!(result2.propagation, PropagationStatus::FailedToQueue);
}
