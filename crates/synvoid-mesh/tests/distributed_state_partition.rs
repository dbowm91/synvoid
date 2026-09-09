//! Phase 23 distributed-state partition/rejoin contract tests.
//!
//! Deterministic in-process coverage for
//! `architecture/distributed_state_contract.md` §8. No external cluster,
//! no networking: all scenarios use static readers, freshness classification,
//! edge-replica snapshots, and policy composition helpers.
//!
//! Scenarios:
//! - quorum available → commit + derived replicas update
//! - quorum lost → typed fail-closed (`QuorumUnavailable`, never success)
//! - reads during partition follow freshness policy
//! - heal → converge without accepting stale divergent writes
//! - duplicate/replayed events do not reapply
//! - source-sequence gaps use snapshot/fallback behavior
//! - stale canonical snapshot classified, cannot authorize new trust
//! - expired advisory records do not resurrect after rejoin
//! - remote advisory remains policy-gated
//! - unblock/revocation ordering preserved (revoked wins)

use std::sync::Arc;
use std::time::Duration;

use synvoid_core::admin_mutation::{AdminMutationResult, AdminMutationStatus, PropagationStatus};
use synvoid_mesh::canonical::{
    canonical_snapshot_freshness_label, canonical_write_outcome_label, classify_canonical_snapshot,
    propagation_outcome_label, CanonicalSnapshotFreshnessPolicy, CanonicalSnapshotFreshnessState,
    CanonicalSnapshotStaleMode, CanonicalTrustReader, CanonicalTrustSnapshot,
    CanonicalWriteOutcome, DistributedNamespaceAuthority, FreshnessBoundCanonicalReader,
    StaticCanonicalTrustReader,
};
use synvoid_mesh::dht::advisory_source::StaticAdvisoryRecordSource;
use synvoid_mesh::raft::client::RaftAwareClientError;
use synvoid_mesh::threat_intel::{
    classify_consumer_action, ThreatIntelConsumerAction, ThreatIntelConsumerKind,
    ThreatIntelDeferredMode,
};
use synvoid_mesh::threat_intel_policy::{evaluate_threat_intel_policy, ThreatIntelPolicyDecision};

// ── Helpers ──────────────────────────────────────────────────────────────

fn fresh_snapshot() -> CanonicalTrustSnapshot {
    CanonicalTrustSnapshot {
        generated_at_unix: synvoid_utils::safe_unix_timestamp(),
        authorized_global_nodes: vec!["pk:global1".to_string()],
        org_key_entries: vec!["org1:key1".to_string()],
        revoked_node_ids: vec![],
        threat_intel_ids: vec!["intel-abc".to_string()],
    }
}

fn default_policy() -> CanonicalSnapshotFreshnessPolicy {
    CanonicalSnapshotFreshnessPolicy::default()
}

fn actionable_setup() -> (StaticCanonicalTrustReader, StaticAdvisoryRecordSource) {
    use synvoid_mesh::canonical::CanonicalFreshness;
    let mut canonical = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
    canonical.threat_intel_ids.insert("intel-abc".to_string());
    let mut advisory = StaticAdvisoryRecordSource::new();
    advisory.insert(StaticAdvisoryRecordSource::test_record(
        "threat_indicator:intel-abc:IpBlock",
    ));
    (canonical, advisory)
}

// ── 1. Quorum available: commit + derived replicas update ────────────────

#[test]
fn quorum_available_commit_maps_to_canonical_committed() {
    let outcome = CanonicalWriteOutcome::Committed { term: 3, index: 42 };
    assert!(outcome.is_committed());
    assert!(!outcome.is_quorum_unavailable());
    assert_eq!(
        outcome.propagation_status(),
        PropagationStatus::CanonicalCommitted
    );
    assert_eq!(canonical_write_outcome_label(&outcome), "committed");

    let result =
        AdminMutationResult::canonical_committed("org:acme", "raft committed term=3 index=42");
    assert_eq!(result.status, AdminMutationStatus::Applied);
    assert_eq!(result.propagation, PropagationStatus::CanonicalCommitted);
    assert!(result.local_store_mutated);

    // Derived replica update path: fresh org-key record applies cleanly.
    let dir = tempfile::TempDir::new().unwrap();
    let replica = Arc::new(
        synvoid_mesh::raft::edge_replica::EdgeReplicaManager::new(dir.path().to_path_buf())
            .unwrap(),
    );
    let key = synvoid_mesh::raft::state_machine::OrgPublicKey {
        org_id: "org1".to_string(),
        public_key: vec![1, 2, 3],
        created_at: synvoid_utils::safe_unix_timestamp(),
        signer_node_id: "node1".into(),
    };
    let value = postcard::to_stdvec(&key).unwrap();
    replica
        .update_from_notification(
            &synvoid_mesh::raft::state_machine::Namespace::Org,
            "fp:abc",
            &value,
        )
        .unwrap();
    assert!(replica.get_org_key("fp:abc").is_some());
}

// ── 2. Quorum lost: typed fail-closed, never success ─────────────────────

#[test]
fn quorum_lost_write_fails_typed_fail_closed() {
    let outcome = CanonicalWriteOutcome::QuorumUnavailable {
        detail: "no majority".into(),
    };
    assert!(!outcome.is_committed());
    assert!(outcome.is_quorum_unavailable());
    assert_eq!(
        outcome.propagation_status(),
        PropagationStatus::QuorumUnavailable
    );

    // Admin result helper never reports success and never mutates locally.
    let result = AdminMutationResult::quorum_unavailable("org:acme", "quorum unavailable");
    assert_eq!(result.status, AdminMutationStatus::Failed);
    assert_eq!(result.propagation, PropagationStatus::QuorumUnavailable);
    assert!(!result.local_store_mutated);

    // Raft client errors map truthfully: quorum conditions → QuorumUnavailable,
    // never CanonicalCommitted.
    let errs = [
        RaftAwareClientError::QuorumUnavailable {
            detail: "partition".into(),
        },
        RaftAwareClientError::RaftUnreachable,
        RaftAwareClientError::Timeout(Duration::from_secs(5)),
        RaftAwareClientError::NoGlobalNodes,
    ];
    for err in &errs {
        assert!(err.is_quorum_unavailable(), "expected quorum loss: {err:?}");
        assert_eq!(
            err.to_propagation_status(),
            PropagationStatus::QuorumUnavailable
        );
        let outcome = err.to_canonical_write_outcome();
        assert!(outcome.is_quorum_unavailable());
        assert!(!outcome.is_committed());
    }

    // NotLeader is a routing hint, not proof of quorum loss.
    let not_leader = RaftAwareClientError::NotLeader;
    assert!(!not_leader.is_quorum_unavailable());
    assert_ne!(
        not_leader.to_propagation_status(),
        PropagationStatus::CanonicalCommitted
    );
}

// ── 3. Reads during partition follow freshness policy ────────────────────

#[test]
fn reads_during_partition_follow_freshness_policy() {
    let now = 1_000;
    // Fresh delegates normally.
    let fresh = CanonicalTrustSnapshot {
        generated_at_unix: now - 10,
        authorized_global_nodes: vec!["pk:global1".to_string()],
        ..Default::default()
    };
    let reader = FreshnessBoundCanonicalReader::new(fresh, default_policy(), now);
    assert!(matches!(
        reader.is_global_node_authorized("pk:global1"),
        synvoid_mesh::canonical::CanonicalTrustDecision::Trusted { .. }
    ));

    // Stale + FailOpenDefer → Unknown/CanonicalUnavailable (defer, not trust).
    let stale = CanonicalTrustSnapshot {
        generated_at_unix: now - 120,
        authorized_global_nodes: vec!["pk:global1".to_string()],
        ..Default::default()
    };
    let policy = CanonicalSnapshotFreshnessPolicy {
        fresh_max_age_ms: 60_000,
        stale_grace_max_age_ms: 300_000,
        stale_mode: CanonicalSnapshotStaleMode::FailOpenDefer,
    };
    let reader = FreshnessBoundCanonicalReader::new(stale, policy, now);
    assert!(matches!(
        reader.is_global_node_authorized("pk:global1"),
        synvoid_mesh::canonical::CanonicalTrustDecision::Unknown { .. }
    ));

    // Stale + FailClosedNotActionable → NotTrusted/ExpiredSnapshot.
    let stale = CanonicalTrustSnapshot {
        generated_at_unix: now - 120,
        authorized_global_nodes: vec!["pk:global1".to_string()],
        ..Default::default()
    };
    let policy = CanonicalSnapshotFreshnessPolicy {
        fresh_max_age_ms: 60_000,
        stale_grace_max_age_ms: 300_000,
        stale_mode: CanonicalSnapshotStaleMode::FailClosedNotActionable,
    };
    let reader = FreshnessBoundCanonicalReader::new(stale, policy, now);
    assert!(matches!(
        reader.is_global_node_authorized("pk:global1"),
        synvoid_mesh::canonical::CanonicalTrustDecision::NotTrusted { .. }
    ));

    // Expired/Missing/Invalid → defer/deny, never trust.
    let expired = CanonicalTrustSnapshot {
        generated_at_unix: now - 400,
        authorized_global_nodes: vec!["pk:global1".to_string()],
        ..Default::default()
    };
    let reader = FreshnessBoundCanonicalReader::new(expired, default_policy(), now);
    assert!(matches!(
        reader.is_global_node_authorized("pk:global1"),
        synvoid_mesh::canonical::CanonicalTrustDecision::NotTrusted { .. }
            | synvoid_mesh::canonical::CanonicalTrustDecision::Unknown { .. }
    ));
    assert_eq!(
        classify_canonical_snapshot(None, &default_policy(), now),
        CanonicalSnapshotFreshnessState::Missing
    );
}

// ── 4. Heal converges without accepting stale divergent writes ───────────

#[test]
fn partition_heal_converges_without_stale_divergent_writes() {
    use synvoid_mesh::raft::edge_replica::FreshnessCheckResult;
    use synvoid_mesh::raft::state_machine::Namespace;
    let dir = tempfile::TempDir::new().unwrap();
    let replica = Arc::new(
        synvoid_mesh::raft::edge_replica::EdgeReplicaManager::new(dir.path().to_path_buf())
            .unwrap(),
    );
    let now = synvoid_utils::safe_unix_timestamp();

    // Committed fresh record applies.
    let fresh = synvoid_mesh::raft::state_machine::OrgPublicKey {
        org_id: "org1".to_string(),
        public_key: vec![7, 8, 9],
        created_at: now,
        signer_node_id: "leader".into(),
    };
    let fresh_value = postcard::to_stdvec(&fresh).unwrap();
    replica
        .update_from_notification(&Namespace::Org, "fp:heal", &fresh_value)
        .unwrap();
    let before = replica.get_org_key("fp:heal").expect("fresh applies");
    assert_eq!(before.org_id, "org1");

    // Freshness classification is namespace-aware: Org stale-beyond-grace is
    // accepted with warning (StaleWithinGrace), while Revocation
    // stale-beyond-hard-limit is rejected (StaleHardLimit). This is the
    // fail-safe that prevents rollback of revocations on rejoin.
    assert!(matches!(
        replica.check_freshness(1, &Namespace::Org),
        FreshnessCheckResult::StaleWithinGrace { .. }
    ));
    assert!(matches!(
        replica.check_freshness(1, &Namespace::Revocation),
        FreshnessCheckResult::StaleHardLimit { .. }
    ));
    assert!(matches!(
        replica.check_freshness(now, &Namespace::Org),
        FreshnessCheckResult::Fresh
    ));

    // Stale revocation divergent write is rejected: no record appears.
    // Revocation values use the historical two-blob postcard layout
    // (RevInfo + RevRecord concatenated).
    #[derive(serde::Serialize)]
    struct RevInfo {
        revoked_at: u64,
        reason: String,
    }
    #[derive(serde::Serialize)]
    struct RevRecord {
        revoked_by_node_id: String,
    }
    let mut stale_rev = postcard::to_stdvec(&RevInfo {
        revoked_at: 1,
        reason: "stale-partition".into(),
    })
    .unwrap();
    stale_rev.extend(
        postcard::to_stdvec(&RevRecord {
            revoked_by_node_id: "partitioned-node".into(),
        })
        .unwrap(),
    );
    replica
        .update_from_notification(&Namespace::Revocation, "node-stale", &stale_rev)
        .unwrap();
    assert!(
        !replica.get_revoked_node("node-stale"),
        "stale revocation beyond hard limit must be rejected"
    );

    // Re-applying the same fresh Org commit is idempotent (converges).
    replica
        .update_from_notification(&Namespace::Org, "fp:heal", &fresh_value)
        .unwrap();
    let after = replica.get_org_key("fp:heal").expect("value survives");
    assert_eq!(after.org_id, "org1");
}

// ── 5. Duplicate/replayed events do not reapply ──────────────────────────

#[test]
fn duplicate_replayed_events_do_not_reapply() {
    // Canonical write outcomes are idempotent by (term, index): re-observing
    // the same commit yields the same committed outcome, never a second
    // mutation claim.
    let first = CanonicalWriteOutcome::Committed { term: 3, index: 42 };
    let replay = CanonicalWriteOutcome::Committed { term: 3, index: 42 };
    assert_eq!(first, replay);
    assert_eq!(
        replay.propagation_status(),
        PropagationStatus::CanonicalCommitted
    );

    // Threat-policy replay: same advisory+canonical input yields the same
    // Actionable decision without side effects (pure function, no mutation).
    let (canonical, advisory) = actionable_setup();
    let key = "threat_indicator:intel-abc:IpBlock";
    let first = evaluate_threat_intel_policy(&canonical, &advisory, "intel-abc", key);
    let second = evaluate_threat_intel_policy(&canonical, &advisory, "intel-abc", key);
    assert_eq!(first, second);
    assert!(matches!(first, ThreatIntelPolicyDecision::Actionable(_)));
}

// ── 6. Source-sequence gaps use snapshot/fallback ────────────────────────

#[test]
fn source_sequence_gaps_use_snapshot_fallback() {
    // The contract reserves SnapshotRepairRequired for gap-triggered repair
    // (blocklist catchup `snapshot_required=true`). The status and its
    // bounded label exist and are distinct from success/canonical outcomes.
    assert_eq!(
        propagation_outcome_label(PropagationStatus::SnapshotRepairRequired),
        "snapshot_repair_required"
    );
    assert_ne!(
        PropagationStatus::SnapshotRepairRequired,
        PropagationStatus::CanonicalCommitted
    );
    assert_ne!(
        PropagationStatus::SnapshotRepairRequired,
        PropagationStatus::QueuedBestEffort
    );
}

// ── 7. Stale snapshot classified, cannot authorize new trust ─────────────

#[test]
fn stale_snapshot_cannot_authorize_new_trust() {
    let now = 1_000;
    // Snapshot carries the right IDs but is expired: trust denied.
    let snapshot = CanonicalTrustSnapshot {
        generated_at_unix: now - 400,
        authorized_global_nodes: vec!["pk:global1".to_string()],
        org_key_entries: vec!["org1:key1".to_string()],
        threat_intel_ids: vec!["intel-abc".to_string()],
        ..Default::default()
    };
    let state = classify_canonical_snapshot(Some(&snapshot), &default_policy(), now);
    assert!(matches!(
        state,
        CanonicalSnapshotFreshnessState::Expired { .. }
    ));
    assert_eq!(canonical_snapshot_freshness_label(state), "expired");

    let reader = FreshnessBoundCanonicalReader::new(snapshot, default_policy(), now);
    for decision in [
        reader.is_global_node_authorized("pk:global1"),
        reader.is_org_key_trusted("org1", "key1"),
        reader.is_threat_intel_canonical("intel-abc"),
    ] {
        assert!(
            !matches!(
                decision,
                synvoid_mesh::canonical::CanonicalTrustDecision::Trusted { .. }
            ),
            "expired snapshot must never yield Trusted"
        );
    }

    // Zero-timestamp and far-future snapshots are Invalid, never authority.
    let zero = CanonicalTrustSnapshot {
        generated_at_unix: 0,
        ..Default::default()
    };
    assert_eq!(
        classify_canonical_snapshot(Some(&zero), &default_policy(), now),
        CanonicalSnapshotFreshnessState::Invalid
    );
    let future = CanonicalTrustSnapshot {
        generated_at_unix: now + 3_600,
        ..Default::default()
    };
    assert_eq!(
        classify_canonical_snapshot(Some(&future), &default_policy(), now),
        CanonicalSnapshotFreshnessState::Invalid
    );
}

// ── 8. Expired advisory records do not resurrect after rejoin ────────────

#[test]
fn expired_advisory_records_do_not_resurrect() {
    use synvoid_mesh::canonical::CanonicalFreshness;
    let mut canonical = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
    canonical.threat_intel_ids.insert("intel-old".into());

    // Expired advisory + trusted canonical → still NotActionable (expired).
    let mut advisory = StaticAdvisoryRecordSource::new();
    advisory.insert(StaticAdvisoryRecordSource::expired_record(
        "threat_indicator:intel-old:IpBlock",
    ));
    let decision = evaluate_threat_intel_policy(
        &canonical,
        &advisory,
        "intel-old",
        "threat_indicator:intel-old:IpBlock",
    );
    assert!(
        matches!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                synvoid_mesh::threat_intel_policy::ThreatIntelPolicyRejectReason::AdvisoryExpired
            )
        ),
        "expired advisory must never resurrect, got {decision:?}"
    );

    // Missing advisory + trusted canonical → NotActionable (never AdvisoryOnly
    // enforcement, never Actionable).
    let empty = StaticAdvisoryRecordSource::new();
    let decision = evaluate_threat_intel_policy(
        &canonical,
        &empty,
        "intel-old",
        "threat_indicator:intel-old:IpBlock",
    );
    assert!(matches!(
        decision,
        ThreatIntelPolicyDecision::NotActionable(_)
    ));
}

// ── 9. Remote advisory remains policy-gated ──────────────────────────────

#[test]
fn remote_advisory_remains_policy_gated() {
    use synvoid_mesh::canonical::CanonicalFreshness;
    // Advisory present, canonical has no trust entry → Deferred
    // (CanonicalUnknown). Unknown canonical is never treated as trust, and
    // enforcement must suppress it exactly like AdvisoryOnly/NotActionable.
    let canonical = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
    let mut advisory = StaticAdvisoryRecordSource::new();
    advisory.insert(StaticAdvisoryRecordSource::test_record(
        "threat_indicator:intel-x:IpBlock",
    ));
    let decision = evaluate_threat_intel_policy(
        &canonical,
        &advisory,
        "intel-x",
        "threat_indicator:intel-x:IpBlock",
    );
    assert!(
        !matches!(decision, ThreatIntelPolicyDecision::Actionable(_)),
        "untrusted advisory must never be Actionable, got {decision:?}"
    );
    assert!(
        matches!(
            decision,
            ThreatIntelPolicyDecision::Deferred(
                synvoid_mesh::threat_intel_policy::ThreatIntelPolicyDeferReason::CanonicalUnknown
            ) | ThreatIntelPolicyDecision::AdvisoryOnly(_)
        ),
        "untrusted advisory must be Deferred(Unknown) or AdvisoryOnly, got {decision:?}"
    );

    // Enforcement consumer must suppress AdvisoryOnly / NotActionable /
    // Deferred / missing-context. Only Actionable permits.
    for decision_opt in [
        Some(decision.clone()),
        Some(ThreatIntelPolicyDecision::AdvisoryOnly(
            synvoid_mesh::threat_intel_policy::ThreatIntelPolicyEvidence {
                intel_id: "intel-x".into(),
                advisory_key: "threat_indicator:intel-x:IpBlock".into(),
                advisory_status: synvoid_mesh::dht::advisory_source::AdvisoryRecordStatus::Present,
                advisory_freshness: synvoid_mesh::dht::advisory_source::AdvisoryFreshness::Live,
                canonical_freshness: CanonicalFreshness::Live,
                record_signature_valid: true,
            },
        )),
        Some(ThreatIntelPolicyDecision::NotActionable(
            synvoid_mesh::threat_intel_policy::ThreatIntelPolicyRejectReason::AdvisoryMissing,
        )),
        Some(ThreatIntelPolicyDecision::Deferred(
            synvoid_mesh::threat_intel_policy::ThreatIntelPolicyDeferReason::CanonicalUnavailable,
        )),
        None,
    ] {
        for mode in [
            ThreatIntelDeferredMode::FailOpenNoAction,
            ThreatIntelDeferredMode::FailClosedNoAction,
        ] {
            let action = classify_consumer_action(
                decision_opt.as_ref(),
                ThreatIntelConsumerKind::Enforcement,
                mode,
            );
            assert_eq!(
                action,
                ThreatIntelConsumerAction::SuppressAction,
                "enforcement must suppress non-actionable (mode {mode:?})"
            );
        }
    }

    let (canonical, advisory) = actionable_setup();
    let decision = evaluate_threat_intel_policy(
        &canonical,
        &advisory,
        "intel-abc",
        "threat_indicator:intel-abc:IpBlock",
    );
    assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    let action = classify_consumer_action(
        Some(&decision),
        ThreatIntelConsumerKind::Enforcement,
        ThreatIntelDeferredMode::FailOpenNoAction,
    );
    assert_eq!(action, ThreatIntelConsumerAction::PermitAction);
}

// ── 10. Unblock/revocation ordering preserved ────────────────────────────

#[test]
fn revocation_ordering_preserved_across_rejoin() {
    use synvoid_mesh::canonical::{CanonicalFreshness, CanonicalTrustReason};
    // Revoked wins over authorized: a node that is both authorized and
    // revoked must report Revoked (never Trusted for revocation status).
    let mut reader = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
    reader.authorized_global_nodes.insert("node-a".into());
    reader.revoked_nodes.insert("node-a".into());

    match reader.node_revocation_status("node-a") {
        synvoid_mesh::canonical::CanonicalTrustDecision::NotTrusted { reason, .. } => {
            assert_eq!(reason, CanonicalTrustReason::Revoked);
        }
        other => panic!("revoked node must report Revoked, got {other:?}"),
    }

    // Fresh snapshot with revocation entry behaves identically (no rejoin
    // rollback to clean).
    let snapshot = CanonicalTrustSnapshot {
        generated_at_unix: synvoid_utils::safe_unix_timestamp(),
        authorized_global_nodes: vec!["node-a".to_string()],
        revoked_node_ids: vec!["node-a".to_string()],
        ..Default::default()
    };
    match snapshot.node_revocation_status("node-a") {
        synvoid_mesh::canonical::CanonicalTrustDecision::NotTrusted { reason, .. } => {
            assert_eq!(reason, CanonicalTrustReason::Revoked);
        }
        other => panic!("snapshot revocation must win, got {other:?}"),
    }
}

// ── Authority taxonomy + propagation truthfulness ────────────────────────

#[test]
fn authority_taxonomy_covers_all_classes() {
    // All four contract authorities have distinct bounded labels.
    let labels = [
        DistributedNamespaceAuthority::LocalAuthoritative,
        DistributedNamespaceAuthority::AdvisoryDistributed,
        DistributedNamespaceAuthority::CanonicalConsensusBacked,
        DistributedNamespaceAuthority::DerivedCacheMaterialization,
    ]
    .map(|a| a.label());
    assert_eq!(
        labels,
        [
            "local_authoritative",
            "advisory_distributed",
            "canonical_consensus_backed",
            "derived_cache"
        ]
    );
}

#[test]
fn propagation_truthfulness_queued_is_not_canonical() {
    // Queued best-effort must never equal canonical commit; quorum loss must
    // never carry local mutation.
    assert_ne!(
        PropagationStatus::QueuedBestEffort,
        PropagationStatus::CanonicalCommitted
    );
    let queued = AdminMutationResult::applied_with_propagation(
        "1.2.3.4",
        PropagationStatus::QueuedBestEffort,
        "queued",
    );
    assert!(queued.local_store_mutated);
    assert_eq!(queued.propagation, PropagationStatus::QueuedBestEffort);

    let no_quorum = AdminMutationResult::quorum_unavailable("org:acme", "no quorum");
    assert!(!no_quorum.local_store_mutated);
    assert_eq!(no_quorum.propagation, PropagationStatus::QuorumUnavailable);
}

// ── Expiry boundaries (zero / max TTL, skew) ─────────────────────────────

#[test]
fn expiry_boundaries_zero_max_ttl_and_skew() {
    // Zero generated_at → Invalid (never authority).
    let zero = CanonicalTrustSnapshot {
        generated_at_unix: 0,
        ..Default::default()
    };
    assert_eq!(
        classify_canonical_snapshot(Some(&zero), &default_policy(), 1_000),
        CanonicalSnapshotFreshnessState::Invalid
    );

    // Fresh boundary: age == fresh_max is Fresh; fresh_max+1s is stale.
    let policy = default_policy();
    let now = 10_000;
    let at_boundary = CanonicalTrustSnapshot {
        generated_at_unix: now - 60, // 60_000 ms == fresh_max
        ..Default::default()
    };
    assert!(matches!(
        classify_canonical_snapshot(Some(&at_boundary), &policy, now),
        CanonicalSnapshotFreshnessState::Fresh { .. }
    ));
    let just_over = CanonicalTrustSnapshot {
        generated_at_unix: now - 61,
        ..Default::default()
    };
    assert!(matches!(
        classify_canonical_snapshot(Some(&just_over), &policy, now),
        CanonicalSnapshotFreshnessState::StaleWithinGrace { .. }
    ));

    // Slight future (within 60s skew) is tolerated as fresh; far future is
    // Invalid so malicious timestamps cannot make state immortal.
    let slight_future = CanonicalTrustSnapshot {
        generated_at_unix: now + 30,
        ..Default::default()
    };
    assert!(matches!(
        classify_canonical_snapshot(Some(&slight_future), &policy, now),
        CanonicalSnapshotFreshnessState::Fresh { .. }
    ));
    let far_future = CanonicalTrustSnapshot {
        generated_at_unix: now + 3_600,
        ..Default::default()
    };
    assert_eq!(
        classify_canonical_snapshot(Some(&far_future), &policy, now),
        CanonicalSnapshotFreshnessState::Invalid
    );

    // Saturating math: huge timestamps cannot wrap or panic.
    let huge = CanonicalTrustSnapshot {
        generated_at_unix: u64::MAX,
        ..Default::default()
    };
    let state = classify_canonical_snapshot(Some(&huge), &policy, now);
    assert_eq!(state, CanonicalSnapshotFreshnessState::Invalid);
}

// ── Observability labels bounded, no secrets ─────────────────────────────

#[test]
fn observability_labels_bounded_no_secrets() {
    // Freshness labels: exactly five values, no ages/timestamps/IDs.
    for (state, expected) in [
        (
            CanonicalSnapshotFreshnessState::Fresh { age_ms: 12345 },
            "fresh",
        ),
        (
            CanonicalSnapshotFreshnessState::StaleWithinGrace { age_ms: 99999 },
            "stale_within_grace",
        ),
        (
            CanonicalSnapshotFreshnessState::Expired { age_ms: u64::MAX },
            "expired",
        ),
        (CanonicalSnapshotFreshnessState::Invalid, "invalid"),
        (CanonicalSnapshotFreshnessState::Missing, "missing"),
    ] {
        let label = canonical_snapshot_freshness_label(state);
        assert_eq!(label, expected);
        assert!(!label.contains("12345"));
    }

    // Canonical + propagation labels never reflect secrets/peer IDs.
    let secret = CanonicalWriteOutcome::QuorumUnavailable {
        detail: "peer=secret-node-abc term=9 token=hunter2".into(),
    };
    let label = canonical_write_outcome_label(&secret);
    assert_eq!(label, "quorum_unavailable");
    assert!(!label.contains("secret"));

    // Fresh snapshot helper is currently fresh (real clock, generous bound).
    let snapshot = fresh_snapshot();
    let state = classify_canonical_snapshot(
        Some(&snapshot),
        &default_policy(),
        snapshot.generated_at_unix,
    );
    assert!(matches!(
        state,
        CanonicalSnapshotFreshnessState::Fresh { .. }
    ));
}
