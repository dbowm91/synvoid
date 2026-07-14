//! Root-test ownership: COMPOSITION
//! Rationale: validates mesh+admin composition edge cases
//!
//! Tests for mesh admin edge cases.
//!
//! These tests verify block/unblock mesh ID behavior and edge cases.

use synvoid_core::admin_mutation::{
    AdminMutationResult, AdminMutationStatus, BlockMutationTarget, PropagationStatus,
};

#[test]
fn block_mesh_id_target_serialization() {
    let target = BlockMutationTarget {
        kind: "mesh_id".to_string(),
        value: "node-abc-123".to_string(),
        site_scope: None,
    };
    let json = serde_json::to_value(&target).unwrap();
    assert_eq!(json["kind"], "mesh_id");
    assert_eq!(json["value"], "node-abc-123");
    assert!(json.get("site_scope").is_none());
}

#[test]
fn block_ip_target_serialization() {
    let target = BlockMutationTarget {
        kind: "ip".to_string(),
        value: "203.0.113.10".to_string(),
        site_scope: Some("global".to_string()),
    };
    let json = serde_json::to_value(&target).unwrap();
    assert_eq!(json["kind"], "ip");
    assert_eq!(json["value"], "203.0.113.10");
    assert_eq!(json["site_scope"], "global");
}

#[test]
fn block_mesh_id_result_applied_with_propagation() {
    let result = AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: BlockMutationTarget {
            kind: "mesh_id".to_string(),
            value: "node-abc-123".to_string(),
            site_scope: None,
        },
        local_store_mutated: true,
        propagation: PropagationStatus::QueuedBestEffort,
        event_id: Some("evt-001".to_string()),
        audit_id: Some("audit-001".to_string()),
        message: "Mesh ID blocked".to_string(),
    };

    assert_eq!(result.status, AdminMutationStatus::Applied);
    assert!(result.local_store_mutated);
    assert_eq!(result.propagation, PropagationStatus::QueuedBestEffort);
    assert!(result.event_id.is_some());
    assert!(result.audit_id.is_some());
}

#[test]
fn unblock_mesh_id_noop_already_present() {
    let result = AdminMutationResult::<BlockMutationTarget>::noop(
        BlockMutationTarget {
            kind: "mesh_id".to_string(),
            value: "nonexistent-node".to_string(),
            site_scope: None,
        },
        "Mesh ID not found in block list",
    );

    assert_eq!(result.status, AdminMutationStatus::NoOpAlreadyPresent);
    assert!(!result.local_store_mutated);
    assert_eq!(result.propagation, PropagationStatus::NotApplicable);
}

#[test]
fn block_mesh_id_with_event_id() {
    let result = AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: BlockMutationTarget {
            kind: "mesh_id".to_string(),
            value: "node-xyz".to_string(),
            site_scope: None,
        },
        local_store_mutated: true,
        propagation: PropagationStatus::QueuedBestEffort,
        event_id: Some("evt-999".to_string()),
        audit_id: None,
        message: "Mesh ID blocked".to_string(),
    };

    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["event_id"], "evt-999");
    assert_eq!(json["target"]["value"], "node-xyz");
}

#[test]
fn block_result_serializes_completely() {
    let result = AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: BlockMutationTarget {
            kind: "ip".to_string(),
            value: "198.51.100.5".to_string(),
            site_scope: Some("global".to_string()),
        },
        local_store_mutated: true,
        propagation: PropagationStatus::QueuedBestEffort,
        event_id: Some("evt-42".to_string()),
        audit_id: Some("audit-42".to_string()),
        message: "IP blocked with mesh propagation".to_string(),
    };

    let json = serde_json::to_value(&result).unwrap();

    assert_eq!(json["status"], "applied");
    assert_eq!(json["target"]["kind"], "ip");
    assert_eq!(json["target"]["value"], "198.51.100.5");
    assert_eq!(json["target"]["site_scope"], "global");
    assert_eq!(json["local_store_mutated"], true);
    assert_eq!(json["propagation"], "queued_best_effort");
    assert_eq!(json["event_id"], "evt-42");
    assert_eq!(json["audit_id"], "audit-42");
    assert_eq!(json["message"], "IP blocked with mesh propagation");
}

#[test]
fn propagation_failed_to_queue_still_applies_locally() {
    let result = AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: BlockMutationTarget {
            kind: "ip".to_string(),
            value: "10.0.0.1".to_string(),
            site_scope: None,
        },
        local_store_mutated: true,
        propagation: PropagationStatus::FailedToQueue,
        event_id: None,
        audit_id: None,
        message: "IP blocked locally but mesh queue failed".to_string(),
    };

    assert_eq!(result.status, AdminMutationStatus::Applied);
    assert!(result.local_store_mutated);
    assert_eq!(result.propagation, PropagationStatus::FailedToQueue);
}

#[test]
fn block_target_site_scope_optional() {
    let without_scope = BlockMutationTarget {
        kind: "ip".to_string(),
        value: "10.0.0.1".to_string(),
        site_scope: None,
    };
    let json = serde_json::to_value(&without_scope).unwrap();
    assert!(json.get("site_scope").is_none());

    let with_scope = BlockMutationTarget {
        kind: "ip".to_string(),
        value: "10.0.0.1".to_string(),
        site_scope: Some("mysite".to_string()),
    };
    let json = serde_json::to_value(&with_scope).unwrap();
    assert_eq!(json["site_scope"], "mysite");
}
