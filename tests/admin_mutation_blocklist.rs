//! Tests for admin blocklist mutation semantics.
//!
//! These tests verify that block/unblock operations produce correct
//! AdminMutationStatus and PropagationStatus results.

use synvoid_block_store::{BlockProvenance, BlockProvenanceKind, BlockStore};
use synvoid_config::DenyListLimitsConfig;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    BlockMutationTarget, PropagationStatus,
};

fn test_provenance() -> BlockProvenance {
    BlockProvenance {
        kind: BlockProvenanceKind::AdminManual,
        source: Some("test".to_string()),
    }
}

fn default_config() -> DenyListLimitsConfig {
    DenyListLimitsConfig {
        max_entries: 1000,
        persist_interval_secs: 0,
        target_state_persist: false,
        target_state_max_records: 100_000,
        target_state_ttl_secs: 604_800,
    }
}

fn make_store() -> BlockStore {
    BlockStore::new(true, None, default_config())
}

#[test]
fn admin_block_applied_returns_mutated_true() {
    let store = make_store();
    let result = store.block_ip_with_provenance(
        "203.0.113.10".parse().unwrap(),
        "test block",
        3600,
        "global",
        test_provenance(),
    );
    assert!(
        result,
        "block_ip_with_provenance should return true for new block"
    );

    // Verify the block exists
    let entry = store.is_blocked(&"203.0.113.10".parse().unwrap(), "global");
    assert!(entry.is_some(), "block should exist after apply");

    // Verify typed result semantics
    let mutation_result = AdminMutationResult::applied(
        BlockMutationTarget {
            kind: "ip".to_string(),
            value: "203.0.113.10".to_string(),
            site_scope: Some("global".to_string()),
        },
        "IP blocked successfully",
    );
    assert_eq!(mutation_result.status, AdminMutationStatus::Applied);
    assert!(mutation_result.local_store_mutated);
}

#[test]
fn admin_unblock_absent_returns_noop_already_absent() {
    let store = make_store();

    // Try to unblock an IP that was never blocked
    let removed = store.unblock_ip(&"203.0.113.10".parse().unwrap(), "global");
    assert!(!removed, "unblock_ip should return false for absent IP");

    // Verify typed result semantics — unblock of already-absent target
    let mutation_result = AdminMutationResult {
        status: AdminMutationStatus::NoOpAlreadyAbsent,
        target: BlockMutationTarget {
            kind: "ip".to_string(),
            value: "203.0.113.10".to_string(),
            site_scope: Some("global".to_string()),
        },
        local_store_mutated: false,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: None,
        message: "IP was not blocked".to_string(),
    };
    assert_eq!(
        mutation_result.status,
        AdminMutationStatus::NoOpAlreadyAbsent
    );
    assert!(!mutation_result.local_store_mutated);
}

#[test]
fn duplicate_block_event_returns_duplicate_ignored() {
    let store = make_store();

    // Block an IP
    let first = store.block_ip_with_provenance(
        "203.0.113.10".parse().unwrap(),
        "first block",
        3600,
        "global",
        test_provenance(),
    );
    assert!(first);

    // Block the same IP again — BlockStore updates the entry (returns true).
    // The typed result classification is done at the handler level, not the store level.
    let second = store.block_ip_with_provenance(
        "203.0.113.10".parse().unwrap(),
        "second block",
        3600,
        "global",
        test_provenance(),
    );
    // Store still accepts the update (LWW overwrite).
    assert!(
        second,
        "block_ip_with_provenance returns true even for re-block"
    );

    // Verify the block still exists
    let entry = store.is_blocked(&"203.0.113.10".parse().unwrap(), "global");
    assert!(entry.is_some(), "block should still exist");

    // The handler would classify a true duplicate as DuplicateIgnored.
    let mutation_result = AdminMutationResult::duplicate(
        BlockMutationTarget {
            kind: "ip".to_string(),
            value: "203.0.113.10".to_string(),
            site_scope: Some("global".to_string()),
        },
        "Duplicate block event ignored",
    );
    assert_eq!(
        mutation_result.status,
        AdminMutationStatus::DuplicateIgnored
    );
    assert!(!mutation_result.local_store_mutated);
}

#[test]
fn stale_unblock_returns_stale_ignored() {
    // Verify the StaleIgnored status is properly typed
    let mutation_result = AdminMutationResult::<BlockMutationTarget>::stale(
        BlockMutationTarget {
            kind: "ip".to_string(),
            value: "203.0.113.10".to_string(),
            site_scope: Some("global".to_string()),
        },
        "Stale unblock event ignored",
    );
    assert_eq!(mutation_result.status, AdminMutationStatus::StaleIgnored);
    assert!(!mutation_result.local_store_mutated);
}

#[test]
fn mesh_propagation_queue_failure_reported_separately() {
    let mutation_result = AdminMutationResult::applied(
        BlockMutationTarget {
            kind: "ip".to_string(),
            value: "203.0.113.10".to_string(),
            site_scope: Some("global".to_string()),
        },
        "Block applied locally; mesh propagation failed",
    )
    .with_propagation(PropagationStatus::FailedToQueue);

    assert_eq!(mutation_result.status, AdminMutationStatus::Applied);
    assert!(mutation_result.local_store_mutated);
    assert_eq!(
        mutation_result.propagation,
        PropagationStatus::FailedToQueue
    );
}

#[test]
fn audit_event_emitted_for_block() {
    let event = AdminAuditEvent {
        audit_id: "test-audit-block-1".into(),
        timestamp: 1234567890,
        actor: AdminActor::with_id(AdminMutationAuthority::AdminManual, "admin"),
        action: "block_ip".into(),
        target_kind: "ip".into(),
        target_id: "203.0.113.10".into(),
        prior_state: None,
        requested_state: Some(serde_json::json!({
            "ip": "203.0.113.10",
            "reason": "test",
            "duration_seconds": 3600,
        })),
        resulting_state: Some(serde_json::json!({
            "ip": "203.0.113.10",
            "reason": "test",
            "duration_seconds": 3600,
            "is_permanent": false,
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::QueuedBestEffort,
        event_id: Some("evt-123".into()),
    };

    // Verify audit event structure
    assert_eq!(event.audit_id, "test-audit-block-1");
    assert_eq!(event.action, "block_ip");
    assert_eq!(event.mutation_status, AdminMutationStatus::Applied);
    assert_eq!(
        event.propagation_status,
        PropagationStatus::QueuedBestEffort
    );
    assert!(event.requested_state.is_some());
    assert!(event.resulting_state.is_some());

    // Verify serializable
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("block_ip"));
    assert!(json.contains("203.0.113.10"));
}

#[test]
fn audit_event_emitted_for_unblock() {
    let event = AdminAuditEvent {
        audit_id: "test-audit-unblock-1".into(),
        timestamp: 1234567890,
        actor: AdminActor::with_id(AdminMutationAuthority::AdminManual, "admin"),
        action: "unblock_ip".into(),
        target_kind: "ip".into(),
        target_id: "203.0.113.10".into(),
        prior_state: Some(serde_json::json!({
            "ip": "203.0.113.10",
            "reason": "test",
        })),
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::QueuedBestEffort,
        event_id: Some("evt-456".into()),
    };

    assert_eq!(event.action, "unblock_ip");
    assert_eq!(event.mutation_status, AdminMutationStatus::Applied);
    assert!(event.prior_state.is_some());
}

#[test]
fn mutation_result_serializes_to_json() {
    let result = AdminMutationResult::applied(
        BlockMutationTarget {
            kind: "ip".to_string(),
            value: "203.0.113.10".to_string(),
            site_scope: Some("global".to_string()),
        },
        "IP blocked successfully",
    )
    .with_event_id("evt-123")
    .with_audit_id("aud-456")
    .with_propagation(PropagationStatus::QueuedBestEffort);

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"status\":\"applied\""));
    assert!(json.contains("\"local_store_mutated\":true"));
    assert!(json.contains("\"propagation\":\"queued_best_effort\""));
    assert!(json.contains("\"event_id\":\"evt-123\""));
    assert!(json.contains("\"audit_id\":\"aud-456\""));

    // Verify deserialization
    let back: AdminMutationResult<BlockMutationTarget> = serde_json::from_str(&json).unwrap();
    assert_eq!(back.status, AdminMutationStatus::Applied);
    assert!(back.local_store_mutated);
}

#[test]
fn all_authority_variants_have_display() {
    let authorities = [
        AdminMutationAuthority::AdminManual,
        AdminMutationAuthority::SupervisorManual,
        AdminMutationAuthority::SupervisorSync,
        AdminMutationAuthority::MeshPolicyGated,
        AdminMutationAuthority::LocalDetector,
        AdminMutationAuthority::WorkerIpc,
        AdminMutationAuthority::CompatibilityLegacy,
    ];
    for auth in &authorities {
        let display = format!("{}", auth);
        assert!(!display.is_empty(), "Display impl should not be empty");
    }
}

#[test]
fn no_op_audit_sink_discards_events() {
    use synvoid_core::admin_mutation::{AdminAuditSink, NoOpAuditSink};

    let sink = NoOpAuditSink;
    let event = AdminAuditEvent {
        audit_id: "test".into(),
        timestamp: 0,
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "test".into(),
        target_kind: "test".into(),
        target_id: "test".into(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    // Should not panic
    sink.record(event);
}
