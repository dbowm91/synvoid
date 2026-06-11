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

use serde::{Deserialize, Serialize};

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

/// Shadow decision class for diagnostics/metrics reporting.
///
/// This is a simplified classification of `ThreatIntelPolicyDecision` for
/// use in metrics counters, admin diagnostics, and structured logging.
/// It does not carry full evidence to avoid high-cardinality labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIntelPolicyDecisionClass {
    /// Advisory record present and canonical trusts this indicator.
    Actionable,
    /// Advisory exists but canonical trust absent or undecided.
    AdvisoryOnly,
    /// Policy rejects: missing advisory or canonical denial.
    NotActionable,
    /// Policy defers: one or both sources unavailable or unknown.
    Deferred,
    /// No policy context configured; fell back to legacy raw paths.
    NotConfigured,
    /// Unexpected error during evaluation.
    Error,
}

/// Diagnostic shadow report for a policy-composed threat-intel decision.
///
/// Intended for admin diagnostics, metrics, and structured logging.
/// Does not carry raw payloads, signatures, or private keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelPolicyShadowDecision {
    /// The indicator value (e.g., IP address, domain).
    pub indicator_value: String,
    /// The threat type classification.
    pub threat_type: String,
    /// Simplified decision class for metrics/labeling.
    pub decision_class: ThreatIntelPolicyDecisionClass,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Advisory record status if available.
    pub advisory_status: Option<String>,
    /// Advisory freshness if available.
    pub advisory_freshness: Option<String>,
    /// Canonical freshness if available.
    pub canonical_freshness: Option<String>,
    /// Whether the raw lookup found the indicator.
    pub raw_lookup_present: Option<bool>,
    /// Whether the composed decision is actionable.
    pub composed_actionable: bool,
}

/// Classified disagreement between raw and composed lookups.
///
/// Diagnostic only — used for counting and sampling, not enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIntelPolicyShadowDisagreement {
    /// Raw lookup found indicator but composed says not actionable.
    RawPresentComposedNotActionable,
    /// Raw lookup missing but composed says actionable.
    RawMissingComposedActionable,
    /// Raw lookup found indicator but composed defers.
    RawPresentComposedDeferred,
    /// Raw lookup missing but composed defers.
    RawMissingComposedDeferred,
}

/// Map a `ThreatIntelPolicyDecision` to a compact decision class for
/// diagnostics and metrics.
///
/// `None` maps to `NotConfigured` (no policy context was available).
pub fn classify_threat_intel_policy_decision(
    decision: Option<&ThreatIntelPolicyDecision>,
) -> ThreatIntelPolicyDecisionClass {
    match decision {
        None => ThreatIntelPolicyDecisionClass::NotConfigured,
        Some(ThreatIntelPolicyDecision::Actionable(_)) => {
            ThreatIntelPolicyDecisionClass::Actionable
        }
        Some(ThreatIntelPolicyDecision::AdvisoryOnly(_)) => {
            ThreatIntelPolicyDecisionClass::AdvisoryOnly
        }
        Some(ThreatIntelPolicyDecision::NotActionable(_)) => {
            ThreatIntelPolicyDecisionClass::NotActionable
        }
        Some(ThreatIntelPolicyDecision::Deferred(_)) => ThreatIntelPolicyDecisionClass::Deferred,
    }
}

/// Build a shadow decision DTO from an indicator evaluation.
///
/// This is a pure helper for constructing diagnostic reports. It does not
/// perform I/O, does not look up indicators, and does not mutate state.
pub fn threat_intel_policy_shadow_decision(
    indicator_value: &str,
    threat_type: &str,
    decision: Option<&ThreatIntelPolicyDecision>,
    raw_lookup_present: Option<bool>,
) -> ThreatIntelPolicyShadowDecision {
    let decision_class = classify_threat_intel_policy_decision(decision);
    let composed_actionable = matches!(decision_class, ThreatIntelPolicyDecisionClass::Actionable);

    let (reason, advisory_status, advisory_freshness, canonical_freshness) = match decision {
        None => ("No policy context configured".to_string(), None, None, None),
        Some(ThreatIntelPolicyDecision::Actionable(evidence)) => (
            format!(
                "Advisory present, canonical trusted (intel_id={})",
                evidence.intel_id
            ),
            Some(format!("{:?}", evidence.advisory_status)),
            Some(format!("{:?}", evidence.advisory_freshness)),
            Some(format!("{:?}", evidence.canonical_freshness)),
        ),
        Some(ThreatIntelPolicyDecision::AdvisoryOnly(evidence)) => (
            format!(
                "Advisory present but canonical not trusted (intel_id={})",
                evidence.intel_id
            ),
            Some(format!("{:?}", evidence.advisory_status)),
            Some(format!("{:?}", evidence.advisory_freshness)),
            Some(format!("{:?}", evidence.canonical_freshness)),
        ),
        Some(ThreatIntelPolicyDecision::NotActionable(reason)) => {
            (format!("Policy rejected: {:?}", reason), None, None, None)
        }
        Some(ThreatIntelPolicyDecision::Deferred(reason)) => {
            (format!("Policy deferred: {:?}", reason), None, None, None)
        }
    };

    ThreatIntelPolicyShadowDecision {
        indicator_value: indicator_value.to_string(),
        threat_type: threat_type.to_string(),
        decision_class,
        reason,
        advisory_status,
        advisory_freshness,
        canonical_freshness,
        raw_lookup_present,
        composed_actionable,
    }
}

/// Classify a disagreement between raw and composed lookups.
///
/// Returns `None` when there is no disagreement (both present or both absent
/// with consistent actionability).
pub fn classify_shadow_disagreement(
    raw_present: bool,
    decision: Option<&ThreatIntelPolicyDecision>,
) -> Option<ThreatIntelPolicyShadowDisagreement> {
    let composed_actionable = matches!(decision, Some(ThreatIntelPolicyDecision::Actionable(_)));
    let composed_deferred = matches!(decision, Some(ThreatIntelPolicyDecision::Deferred(_)));

    match (raw_present, composed_actionable, composed_deferred) {
        (true, false, false) => {
            Some(ThreatIntelPolicyShadowDisagreement::RawPresentComposedNotActionable)
        }
        (false, true, false) => {
            Some(ThreatIntelPolicyShadowDisagreement::RawMissingComposedActionable)
        }
        (true, false, true) => {
            Some(ThreatIntelPolicyShadowDisagreement::RawPresentComposedDeferred)
        }
        (false, false, true) => {
            Some(ThreatIntelPolicyShadowDisagreement::RawMissingComposedDeferred)
        }
        _ => None,
    }
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

    // ---------------------------------------------------------------------------
    // Iteration 33: Shadow decision DTO and classifier tests
    // ---------------------------------------------------------------------------

    #[test]
    fn iteration33_actionable_maps_to_actionable_class() {
        let evidence = ThreatIntelPolicyEvidence {
            intel_id: "intel-1".to_string(),
            advisory_key: "threat_indicator:1.2.3.4:IpBlock".to_string(),
            advisory_status: AdvisoryRecordStatus::Present,
            advisory_freshness: AdvisoryFreshness::Live,
            canonical_freshness: CanonicalFreshness::Live,
            record_signature_valid: true,
        };
        let decision = Some(ThreatIntelPolicyDecision::Actionable(evidence));
        assert_eq!(
            classify_threat_intel_policy_decision(decision.as_ref()),
            ThreatIntelPolicyDecisionClass::Actionable
        );
    }

    #[test]
    fn iteration33_advisory_only_maps_to_advisory_only_class() {
        let evidence = ThreatIntelPolicyEvidence {
            intel_id: "intel-2".to_string(),
            advisory_key: "threat_indicator:5.6.7.8:IpBlock".to_string(),
            advisory_status: AdvisoryRecordStatus::Present,
            advisory_freshness: AdvisoryFreshness::Live,
            canonical_freshness: CanonicalFreshness::Live,
            record_signature_valid: true,
        };
        let decision = Some(ThreatIntelPolicyDecision::AdvisoryOnly(evidence));
        assert_eq!(
            classify_threat_intel_policy_decision(decision.as_ref()),
            ThreatIntelPolicyDecisionClass::AdvisoryOnly
        );
    }

    #[test]
    fn iteration33_not_actionable_maps_with_reason() {
        let decision = Some(ThreatIntelPolicyDecision::NotActionable(
            ThreatIntelPolicyRejectReason::AdvisoryMissing,
        ));
        let shadow = threat_intel_policy_shadow_decision(
            "1.2.3.4",
            "IpBlock",
            decision.as_ref(),
            Some(false),
        );
        assert_eq!(
            shadow.decision_class,
            ThreatIntelPolicyDecisionClass::NotActionable
        );
        assert!(shadow.reason.contains("AdvisoryMissing"));
        assert!(!shadow.composed_actionable);
    }

    #[test]
    fn iteration33_deferred_maps_with_reason() {
        let decision = Some(ThreatIntelPolicyDecision::Deferred(
            ThreatIntelPolicyDeferReason::CanonicalUnavailable,
        ));
        let shadow =
            threat_intel_policy_shadow_decision("1.2.3.4", "IpBlock", decision.as_ref(), None);
        assert_eq!(
            shadow.decision_class,
            ThreatIntelPolicyDecisionClass::Deferred
        );
        assert!(shadow.reason.contains("CanonicalUnavailable"));
        assert!(!shadow.composed_actionable);
    }

    #[test]
    fn iteration33_none_maps_to_not_configured() {
        let shadow = threat_intel_policy_shadow_decision("1.2.3.4", "IpBlock", None, Some(true));
        assert_eq!(
            shadow.decision_class,
            ThreatIntelPolicyDecisionClass::NotConfigured
        );
        assert!(!shadow.composed_actionable);
        assert_eq!(shadow.raw_lookup_present, Some(true));
    }

    #[test]
    fn iteration33_shadow_decision_excludes_raw_payloads() {
        let evidence = ThreatIntelPolicyEvidence {
            intel_id: "intel-1".to_string(),
            advisory_key: "threat_indicator:1.2.3.4:IpBlock".to_string(),
            advisory_status: AdvisoryRecordStatus::Present,
            advisory_freshness: AdvisoryFreshness::Live,
            canonical_freshness: CanonicalFreshness::Live,
            record_signature_valid: true,
        };
        let decision = Some(ThreatIntelPolicyDecision::Actionable(evidence));
        let shadow = threat_intel_policy_shadow_decision(
            "1.2.3.4",
            "IpBlock",
            decision.as_ref(),
            Some(true),
        );
        // Shadow DTO should not contain raw DHT record bytes or signatures
        let serialized = serde_json::to_string(&shadow).unwrap();
        assert!(!serialized.contains("record_signature"));
        assert!(serialized.contains("decision_class"));
        assert!(serialized.contains("composed_actionable"));
    }

    #[test]
    fn iteration33_shadow_decision_has_no_high_cardinality_labels() {
        let shadow = threat_intel_policy_shadow_decision("10.0.0.1", "IpBlock", None, None);
        let serialized = serde_json::to_string(&shadow).unwrap();
        // Verify the indicator value is present (for admin/diagnostic use)
        assert!(serialized.contains("10.0.0.1"));
        // Verify decision_class is a simple enum variant
        assert!(serialized.contains("not_configured"));
    }

    #[test]
    fn iteration33_disagreement_raw_present_composed_not_actionable() {
        let decision = Some(ThreatIntelPolicyDecision::NotActionable(
            ThreatIntelPolicyRejectReason::AdvisoryMissing,
        ));
        assert_eq!(
            classify_shadow_disagreement(true, decision.as_ref()),
            Some(ThreatIntelPolicyShadowDisagreement::RawPresentComposedNotActionable)
        );
    }

    #[test]
    fn iteration33_disagreement_raw_missing_composed_actionable() {
        let evidence = ThreatIntelPolicyEvidence {
            intel_id: "intel-1".to_string(),
            advisory_key: "threat_indicator:1.2.3.4:IpBlock".to_string(),
            advisory_status: AdvisoryRecordStatus::Present,
            advisory_freshness: AdvisoryFreshness::Live,
            canonical_freshness: CanonicalFreshness::Live,
            record_signature_valid: true,
        };
        let decision = Some(ThreatIntelPolicyDecision::Actionable(evidence));
        assert_eq!(
            classify_shadow_disagreement(false, decision.as_ref()),
            Some(ThreatIntelPolicyShadowDisagreement::RawMissingComposedActionable)
        );
    }

    #[test]
    fn iteration33_disagreement_no_disagreement_when_both_present_and_actionable() {
        let evidence = ThreatIntelPolicyEvidence {
            intel_id: "intel-1".to_string(),
            advisory_key: "threat_indicator:1.2.3.4:IpBlock".to_string(),
            advisory_status: AdvisoryRecordStatus::Present,
            advisory_freshness: AdvisoryFreshness::Live,
            canonical_freshness: CanonicalFreshness::Live,
            record_signature_valid: true,
        };
        let decision = Some(ThreatIntelPolicyDecision::Actionable(evidence));
        assert_eq!(classify_shadow_disagreement(true, decision.as_ref()), None);
    }

    #[test]
    fn iteration33_disagreement_no_disagreement_when_both_absent_and_not_configured() {
        assert_eq!(classify_shadow_disagreement(false, None), None);
    }

    #[test]
    fn iteration33_shadow_helper_does_not_mutate_state() {
        // Verify the helper is pure by calling it multiple times with same inputs
        let decision = Some(ThreatIntelPolicyDecision::Deferred(
            ThreatIntelPolicyDeferReason::CanonicalUnknown,
        ));
        let s1 = threat_intel_policy_shadow_decision("1.2.3.4", "IpBlock", decision.as_ref(), None);
        let s2 = threat_intel_policy_shadow_decision("1.2.3.4", "IpBlock", decision.as_ref(), None);
        assert_eq!(s1.decision_class, s2.decision_class);
        assert_eq!(s1.reason, s2.reason);
    }
}
