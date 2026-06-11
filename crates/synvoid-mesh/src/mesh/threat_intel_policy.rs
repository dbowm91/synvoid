//! Threat-intel policy composition (Iteration 18).
//!
//! Composes advisory DHT observations (`AdvisoryRecordSource`) with canonical
//! Raft trust state (`CanonicalTrustReader`) to produce explicit actionability
//! decisions for threat-intel records.
//!
//! # Domain Distinction
//!
//! - **Advisory** (`AdvisoryRecordSource`): "what has been advertised?"
//! - **Canonical** (`CanonicalTrustReader`): "what is trusted?"
//! - **Policy** (this module): "what may be acted on?"
//!
//! This module is a pure composition layer. It does not fetch from DHT, Raft,
//! or `RecordStoreManager` directly. It does not mutate state. It does not
//! decode service-specific payloads.
//!
//! # Key Convention
//!
//! Advisory DHT keys for threat intel follow the format:
//! `threat_indicator:{indicator_id}:{threat_type}`
//!
//! The `intel_id` parameter to `evaluate_threat_intel_policy` corresponds to
//! the `indicator_id` portion (e.g., `"intel-1"`, `"1.2.3.4"`). The
//! `advisory_key` is the full DHT key used for advisory lookup.

use super::canonical::{CanonicalFreshness, CanonicalTrustDecision, CanonicalTrustReader};
use super::dht::advisory_source::{
    AdvisoryFreshness, AdvisoryRecordLookup, AdvisoryRecordSource, AdvisoryRecordStatus,
};

/// Policy decision for a threat-intel indicator.
///
/// Every variant carries evidence so callers can apply stricter freshness
/// policy or log detailed diagnostics. Advisory-only observations are never
/// treated as actionable — canonical trust is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatIntelPolicyDecision {
    /// Advisory record is present and canonical state trusts this indicator.
    /// Safe to act on.
    Actionable(ThreatIntelPolicyEvidence),
    /// Advisory record exists but canonical trust is absent or undecided.
    /// Must not be used as actionable security policy.
    AdvisoryOnly(ThreatIntelPolicyEvidence),
    /// Policy rejects this indicator. Missing advisory or canonical denial.
    NotActionable(ThreatIntelPolicyRejectReason),
    /// Policy defers — one or both sources are unavailable or unknown.
    Deferred(ThreatIntelPolicyDeferReason),
}

/// Evidence carried by actionable or advisory-only decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatIntelPolicyEvidence {
    /// The threat-intel indicator ID (e.g., `"intel-1"`).
    pub intel_id: String,
    /// The full advisory DHT key used for lookup.
    pub advisory_key: String,
    /// Status of the advisory record.
    pub advisory_status: AdvisoryRecordStatus,
    /// Freshness of the advisory observation.
    pub advisory_freshness: AdvisoryFreshness,
    /// Freshness of the canonical trust snapshot.
    pub canonical_freshness: CanonicalFreshness,
    /// Whether the advisory record's envelope signature was valid.
    /// This is identity/envelope information, not canonical authority.
    pub record_signature_valid: bool,
}

/// Reason a policy decision rejected the indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelPolicyRejectReason {
    /// No advisory record found for this key.
    AdvisoryMissing,
    /// Advisory record existed but has expired (TTL exceeded).
    AdvisoryExpired,
    /// Canonical state explicitly does not trust this indicator.
    CanonicalNotTrusted,
}

/// Reason a policy decision deferred action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelPolicyDeferReason {
    /// Advisory source is unavailable (store disabled or unreachable).
    AdvisoryUnavailable,
    /// Canonical source is unavailable (no snapshot, replica offline).
    CanonicalUnavailable,
    /// Canonical state has no opinion on this indicator.
    CanonicalUnknown,
}

/// Compose advisory and canonical sources into an explicit threat-intel
/// policy decision.
///
/// This is a pure, deterministic helper. It does not perform I/O, does not
/// fetch from DHT or Raft, does not inspect `RecordStoreManager` directly,
/// and does not mutate state.
///
/// # Arguments
///
/// * `canonical` — Canonical trust reader (Raft-derived snapshot).
/// * `advisory` — Advisory DHT record source.
/// * `intel_id` — The threat-intel indicator ID (e.g., `"intel-1"`).
/// * `advisory_key` — The full advisory DHT key for lookup
///   (e.g., `"threat_indicator:intel-1:IpBlock"`).
pub fn evaluate_threat_intel_policy(
    canonical: &dyn CanonicalTrustReader,
    advisory: &dyn AdvisoryRecordSource,
    intel_id: &str,
    advisory_key: &str,
) -> ThreatIntelPolicyDecision {
    // Step 1: Look up advisory record.
    let advisory_lookup = advisory.get_advisory_record(advisory_key);

    match advisory_lookup {
        // Advisory unavailable — defer regardless of canonical state.
        AdvisoryRecordLookup::Unavailable => {
            return ThreatIntelPolicyDecision::Deferred(
                ThreatIntelPolicyDeferReason::AdvisoryUnavailable,
            );
        }
        // Advisory missing — not actionable.
        AdvisoryRecordLookup::Missing => {
            return ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::AdvisoryMissing,
            );
        }
        // Advisory expired — not actionable.
        AdvisoryRecordLookup::Expired => {
            return ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::AdvisoryExpired,
            );
        }
        // Advisory present — continue to canonical check.
        AdvisoryRecordLookup::Present(record) => {
            // Step 2: Check canonical trust.
            let canonical_decision = canonical.is_threat_intel_canonical(intel_id);

            match canonical_decision {
                CanonicalTrustDecision::Trusted { freshness } => {
                    return ThreatIntelPolicyDecision::Actionable(ThreatIntelPolicyEvidence {
                        intel_id: intel_id.to_string(),
                        advisory_key: advisory_key.to_string(),
                        advisory_status: AdvisoryRecordStatus::Present,
                        advisory_freshness: record.freshness,
                        canonical_freshness: freshness,
                        record_signature_valid: record.record_signature_valid,
                    });
                }
                CanonicalTrustDecision::NotTrusted {
                    freshness: CanonicalFreshness::Unavailable,
                    ..
                } => {
                    return ThreatIntelPolicyDecision::Deferred(
                        ThreatIntelPolicyDeferReason::CanonicalUnavailable,
                    );
                }
                CanonicalTrustDecision::NotTrusted {
                    reason: super::canonical::CanonicalTrustReason::NotPresentInCanonicalState,
                    ..
                } => {
                    return ThreatIntelPolicyDecision::Deferred(
                        ThreatIntelPolicyDeferReason::CanonicalUnknown,
                    );
                }
                CanonicalTrustDecision::NotTrusted { .. } => {
                    return ThreatIntelPolicyDecision::NotActionable(
                        ThreatIntelPolicyRejectReason::CanonicalNotTrusted,
                    );
                }
                CanonicalTrustDecision::Unknown {
                    freshness: CanonicalFreshness::Unavailable,
                    ..
                } => {
                    return ThreatIntelPolicyDecision::Deferred(
                        ThreatIntelPolicyDeferReason::CanonicalUnavailable,
                    );
                }
                CanonicalTrustDecision::Unknown { .. } => {
                    return ThreatIntelPolicyDecision::Deferred(
                        ThreatIntelPolicyDeferReason::CanonicalUnknown,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{CanonicalFreshness, CanonicalTrustDecision, CanonicalTrustReader};
    use crate::dht::advisory_source::{
        AdvisoryFreshness, AdvisoryRecord, AdvisoryRecordLookup, AdvisoryRecordSource,
    };
    use std::collections::HashMap;

    // ---------------------------------------------------------------------------
    // Test-only static implementations
    // ---------------------------------------------------------------------------

    #[derive(Debug, Default, Clone)]
    struct TestAdvisorySource {
        records: HashMap<String, AdvisoryRecord>,
        unavailable: bool,
    }

    impl TestAdvisorySource {
        fn new() -> Self {
            Self::default()
        }

        fn unavailable() -> Self {
            Self {
                unavailable: true,
                ..Default::default()
            }
        }

        fn with_record(mut self, key: &str, record: AdvisoryRecord) -> Self {
            self.records.insert(key.to_string(), record);
            self
        }
    }

    impl AdvisoryRecordSource for TestAdvisorySource {
        fn get_advisory_record(&self, key: &str) -> AdvisoryRecordLookup {
            if self.unavailable {
                return AdvisoryRecordLookup::Unavailable;
            }
            match self.records.get(key) {
                Some(r) => {
                    let now = synvoid_utils::safe_unix_timestamp();
                    if r.ttl_seconds > 0 && now > r.timestamp + r.ttl_seconds {
                        AdvisoryRecordLookup::Expired
                    } else {
                        AdvisoryRecordLookup::Present(r.clone())
                    }
                }
                None => AdvisoryRecordLookup::Missing,
            }
        }

        fn get_advisory_records_by_prefix(
            &self,
            _prefix: &str,
            _limit: usize,
        ) -> Vec<AdvisoryRecord> {
            vec![]
        }
    }

    #[derive(Debug, Clone)]
    struct TestCanonicalReader {
        trust: HashMap<String, CanonicalTrustDecision>,
        default_freshness: CanonicalFreshness,
    }

    impl TestCanonicalReader {
        fn new(freshness: CanonicalFreshness) -> Self {
            Self {
                trust: HashMap::new(),
                default_freshness: freshness,
            }
        }

        fn with_trust(mut self, intel_id: &str, decision: CanonicalTrustDecision) -> Self {
            self.trust.insert(intel_id.to_string(), decision);
            self
        }
    }

    impl CanonicalTrustReader for TestCanonicalReader {
        fn freshness(&self) -> CanonicalFreshness {
            self.default_freshness
        }

        fn is_global_node_authorized(&self, _: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.default_freshness,
                reason: crate::canonical::CanonicalTrustReason::UnsupportedDecisionType,
            }
        }

        fn is_org_key_trusted(&self, _: &str, _: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.default_freshness,
                reason: crate::canonical::CanonicalTrustReason::UnsupportedDecisionType,
            }
        }

        fn is_node_revoked(&self, _: &str) -> CanonicalTrustDecision {
            self.node_revocation_status("_")
        }

        fn node_revocation_status(&self, _: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.default_freshness,
                reason: crate::canonical::CanonicalTrustReason::UnsupportedDecisionType,
            }
        }

        fn is_threat_intel_canonical(&self, intel_id: &str) -> CanonicalTrustDecision {
            self.trust
                .get(intel_id)
                .cloned()
                .unwrap_or(CanonicalTrustDecision::NotTrusted {
                    freshness: self.default_freshness,
                    reason: crate::canonical::CanonicalTrustReason::NotPresentInCanonicalState,
                })
        }
    }

    fn test_record(key: &str) -> AdvisoryRecord {
        let now = synvoid_utils::safe_unix_timestamp();
        AdvisoryRecord {
            key: key.to_string(),
            value: b"test".to_vec(),
            source_node_id: "test-node".to_string(),
            timestamp: now,
            ttl_seconds: 3600,
            freshness: AdvisoryFreshness::Live,
            status: AdvisoryRecordStatus::Present,
            record_signature_valid: true,
        }
    }

    fn expired_record(key: &str) -> AdvisoryRecord {
        AdvisoryRecord {
            key: key.to_string(),
            value: b"test".to_vec(),
            source_node_id: "test-node".to_string(),
            timestamp: 1000,
            ttl_seconds: 1,
            freshness: AdvisoryFreshness::Unknown,
            status: AdvisoryRecordStatus::Expired,
            record_signature_valid: false,
        }
    }

    const KEY: &str = "threat_indicator:intel-1:IpBlock";
    const INTEL_ID: &str = "intel-1";

    // ---------------------------------------------------------------------------
    // Required tests from plan Phase 5
    // ---------------------------------------------------------------------------

    #[test]
    fn advisory_present_canonical_trusted_actionable() {
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        match decision {
            ThreatIntelPolicyDecision::Actionable(evidence) => {
                assert_eq!(evidence.intel_id, INTEL_ID);
                assert_eq!(evidence.advisory_key, KEY);
                assert_eq!(evidence.advisory_status, AdvisoryRecordStatus::Present);
                assert_eq!(evidence.advisory_freshness, AdvisoryFreshness::Live);
                assert_eq!(evidence.canonical_freshness, CanonicalFreshness::Live);
                assert!(evidence.record_signature_valid);
            }
            other => panic!("expected Actionable, got {:?}", other),
        }
    }

    #[test]
    fn advisory_missing_canonical_trusted_not_actionable() {
        let advisory = TestAdvisorySource::new();
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::AdvisoryMissing
            )
        );
    }

    #[test]
    fn advisory_expired_canonical_trusted_not_actionable() {
        let mut advisory = TestAdvisorySource::new();
        advisory
            .records
            .insert(KEY.to_string(), expired_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::AdvisoryExpired
            )
        );
    }

    #[test]
    fn advisory_unavailable_deferred() {
        let advisory = TestAdvisorySource::unavailable();
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::AdvisoryUnavailable)
        );
    }

    #[test]
    fn advisory_present_canonical_not_trusted_not_actionable() {
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Live,
                reason: crate::canonical::CanonicalTrustReason::Revoked,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::CanonicalNotTrusted
            )
        );
    }

    #[test]
    fn advisory_present_canonical_unknown_deferred() {
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::Unknown {
                freshness: CanonicalFreshness::Live,
                reason: crate::canonical::CanonicalTrustReason::NotPresentInCanonicalState,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::CanonicalUnknown)
        );
    }

    #[test]
    fn advisory_present_canonical_unavailable_deferred() {
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Unavailable).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Unavailable,
                reason: crate::canonical::CanonicalTrustReason::CanonicalUnavailable,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::CanonicalUnavailable)
        );
    }

    #[test]
    fn evidence_includes_advisory_and_canonical_freshness() {
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Snapshot { age_ms: 500 })
            .with_trust(
                INTEL_ID,
                CanonicalTrustDecision::Trusted {
                    freshness: CanonicalFreshness::Snapshot { age_ms: 500 },
                },
            );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        match decision {
            ThreatIntelPolicyDecision::Actionable(evidence) => {
                assert_eq!(
                    evidence.advisory_freshness,
                    AdvisoryFreshness::Live,
                    "advisory freshness must be captured"
                );
                assert_eq!(
                    evidence.canonical_freshness,
                    CanonicalFreshness::Snapshot { age_ms: 500 },
                    "canonical freshness must be captured"
                );
            }
            other => panic!("expected Actionable, got {:?}", other),
        }
    }

    #[test]
    fn record_signature_valid_carry_only() {
        // Record with invalid signature is still present in advisory.
        // Canonical trust determines actionability, not signature validity.
        let mut rec = test_record(KEY);
        rec.record_signature_valid = false;
        let advisory = TestAdvisorySource::new().with_record(KEY, rec);
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        match decision {
            ThreatIntelPolicyDecision::Actionable(evidence) => {
                // Actionable even though signature is invalid — canonical trust decides.
                assert!(!evidence.record_signature_valid);
            }
            other => panic!("expected Actionable, got {:?}", other),
        }
    }

    #[test]
    fn no_dht_raft_or_networking_required() {
        // Pure test with static sources only.
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    #[test]
    fn advisory_only_not_actionable_without_canonical_trust() {
        // Advisory present but canonical has no opinion — deferred, not actionable.
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live);

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert!(matches!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::CanonicalUnknown)
        ));
    }

    #[test]
    fn canonical_not_trusted_with_not_present_in_state_is_deferred() {
        // NotPresentInCanonicalState maps to CanonicalUnknown defer, not rejection.
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Live,
                reason: crate::canonical::CanonicalTrustReason::NotPresentInCanonicalState,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::CanonicalUnknown)
        );
    }

    #[test]
    fn canonical_not_trusted_with_revoked_is_rejected() {
        // Revoked is a hard rejection, not a defer.
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Live).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Live,
                reason: crate::canonical::CanonicalTrustReason::Revoked,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::NotActionable(
                ThreatIntelPolicyRejectReason::CanonicalNotTrusted
            )
        );
    }

    #[test]
    fn canonical_unknown_with_unavailable_freshness_is_deferred_unavailable() {
        let advisory = TestAdvisorySource::new().with_record(KEY, test_record(KEY));
        let canonical = TestCanonicalReader::new(CanonicalFreshness::Unavailable).with_trust(
            INTEL_ID,
            CanonicalTrustDecision::Unknown {
                freshness: CanonicalFreshness::Unavailable,
                reason: crate::canonical::CanonicalTrustReason::CanonicalUnavailable,
            },
        );

        let decision = evaluate_threat_intel_policy(&canonical, &advisory, INTEL_ID, KEY);
        assert_eq!(
            decision,
            ThreatIntelPolicyDecision::Deferred(ThreatIntelPolicyDeferReason::CanonicalUnavailable)
        );
    }

    #[test]
    fn trait_is_object_safe() {
        fn _assert_advisory(_: &dyn AdvisoryRecordSource) {}
        fn _assert_canonical(_: &dyn CanonicalTrustReader) {}
        let a = TestAdvisorySource::new();
        let c = TestCanonicalReader::new(CanonicalFreshness::Live);
        _assert_advisory(&a);
        _assert_canonical(&c);
    }
}
