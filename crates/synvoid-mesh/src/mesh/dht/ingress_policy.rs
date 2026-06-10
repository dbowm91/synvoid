//! DHT ingress policy context (Iteration 13).
//!
//! Provides a small injectable handle that carries an optional `CanonicalTrustReader`
//! into remote DHT record ingress paths. When disabled (no reader), legacy behavior
//! is preserved. When configured, the gate delegates to the existing key-policy
//! adapter (`validate_dht_key_authority_for_ingress`) and produces explicit
//! accept/reject/defer outcomes for canonical-required keys.
//!
//! This is the dependency-injection seam for DHT ingress without globals or
//! deep construction of canonical state. The context is attached to
//! `DhtRecordIngressContext` at creation time for remote signed-record paths
//! (push, sync response, anti-entropy, announce, etc.). The central
//! `store_record_from_ingress` entry honors it for remote (!local-origin) writes.
//!
//! Non-goals: service consumer migration, full AdvisoryRecordSource seam,
//! broad record propagation changes, requiring live Raft in tests.

use std::sync::Arc;

use crate::dht::key_policy::{
    validate_dht_key_authority_for_ingress, DhtIngressPolicyError, DhtKeyAuthorityDeferReason,
    DhtKeyAuthorityRejectReason, DhtRecordAuthorityClass,
};
use crate::dht::keys::DhtKey;
use crate::mesh::canonical::CanonicalTrustReader;

/// Small injectable context for DHT ingress canonical-reader decisions.
///
/// `None` (via `disabled()`) means the canonical ingress gate is not wired for
/// this ingress event; callers must preserve existing/legacy behavior.
///
/// `Some(reader)` means canonical-required authority classes may be enforced
/// via the key-policy adapter. The reader is typically a `SnapshotCanonicalTrustReader`
/// (wrapping EdgeReplicaManager) in production or `StaticCanonicalTrustReader` in tests.
#[derive(Clone)]
pub struct DhtIngressPolicyContext {
    canonical_reader: Option<Arc<dyn CanonicalTrustReader>>,
}

// Manual Debug: the reader is an opaque trait object; we only report presence.
impl std::fmt::Debug for DhtIngressPolicyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtIngressPolicyContext")
            .field("has_reader", &self.canonical_reader.is_some())
            .finish()
    }
}

impl DhtIngressPolicyContext {
    /// Returns a disabled context (no reader). All checks will return `NotConfigured`.
    pub fn disabled() -> Self {
        Self {
            canonical_reader: None,
        }
    }

    /// Returns a context configured with the given canonical reader.
    pub fn with_canonical_reader(reader: Arc<dyn CanonicalTrustReader>) -> Self {
        Self {
            canonical_reader: Some(reader),
        }
    }

    /// Returns the reader if configured, else None.
    pub fn canonical_reader(&self) -> Option<&dyn CanonicalTrustReader> {
        self.canonical_reader.as_deref()
    }
}

/// Outcome of an optional ingress authority gate check.
///
/// Mirrors the accept/reject/defer distinctions from the key-policy adapter,
/// plus an explicit `NotConfigured` for the disabled case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtIngressGateOutcome {
    /// Record may proceed (advisory key, or canonical-accepted with freshness).
    Accepted,
    /// Record explicitly rejected by canonical policy (e.g. revoked, not authorized).
    Rejected(DhtKeyAuthorityRejectReason),
    /// Canonical state unavailable or ambiguous; caller should apply fallback
    /// (typically treat as rejection for remote ingress unless a retry queue exists).
    Deferred(DhtKeyAuthorityDeferReason),
    /// Context was disabled (no reader). Caller must preserve legacy behavior.
    NotConfigured,
}

/// Entry point that accepts an optional ingress policy context.
///
/// When the context is disabled, returns `NotConfigured` immediately (no reader
/// lookup, no policy change).
///
/// When configured, delegates to `validate_dht_key_authority_for_ingress` and
/// maps `Ok` → `Accepted`, `Rejected`/`Deferred` errors to the corresponding
/// outcomes. Preserves the exact accept/reject/defer distinctions.
pub fn check_dht_ingress_authority(
    ctx: &DhtIngressPolicyContext,
    key: &DhtKey,
    signer_node_id: Option<&str>,
    authority_hint: Option<DhtRecordAuthorityClass>,
) -> DhtIngressGateOutcome {
    let Some(reader) = ctx.canonical_reader() else {
        return DhtIngressGateOutcome::NotConfigured;
    };

    match validate_dht_key_authority_for_ingress(reader, key, signer_node_id, authority_hint) {
        Ok(()) => DhtIngressGateOutcome::Accepted,
        Err(DhtIngressPolicyError::Rejected(r)) => DhtIngressGateOutcome::Rejected(r),
        Err(DhtIngressPolicyError::Deferred(d)) => DhtIngressGateOutcome::Deferred(d),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::dht::keys::DhtKey;
    use crate::mesh::canonical::{
        CanonicalFreshness, CanonicalTrustDecision, CanonicalTrustReader, CanonicalTrustReason,
        StaticCanonicalTrustReader,
    };

    fn make_base_reader(freshness: CanonicalFreshness) -> StaticCanonicalTrustReader {
        let mut r = StaticCanonicalTrustReader::new(freshness);
        r.authorized_global_nodes.insert("pk:global1".into());
        r.threat_intel_ids.insert("intel-1".into());
        r
    }

    // Reader that forces CanonicalUnavailable for revocation/global checks (to exercise Defer).
    struct ForceUnavailableReader {
        inner: StaticCanonicalTrustReader,
    }
    impl CanonicalTrustReader for ForceUnavailableReader {
        fn freshness(&self) -> CanonicalFreshness {
            self.inner.freshness()
        }
        fn is_global_node_authorized(&self, _node_id: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Unavailable,
                reason: CanonicalTrustReason::CanonicalUnavailable,
            }
        }
        fn is_org_key_trusted(&self, o: &str, k: &str) -> CanonicalTrustDecision {
            self.inner.is_org_key_trusted(o, k)
        }
        fn is_node_revoked(&self, _n: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Unavailable,
                reason: CanonicalTrustReason::CanonicalUnavailable,
            }
        }
        fn node_revocation_status(&self, _n: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Unavailable,
                reason: CanonicalTrustReason::CanonicalUnavailable,
            }
        }
        fn is_threat_intel_canonical(&self, id: &str) -> CanonicalTrustDecision {
            self.inner.is_threat_intel_canonical(id)
        }
    }

    // Reader that forces Unknown for revocation/global (to exercise Defer CanonicalUnknown).
    struct ForceUnknownReader {
        inner: StaticCanonicalTrustReader,
    }
    impl CanonicalTrustReader for ForceUnknownReader {
        fn freshness(&self) -> CanonicalFreshness {
            self.inner.freshness()
        }
        fn is_global_node_authorized(&self, _n: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.inner.freshness(),
                reason: CanonicalTrustReason::UnsupportedDecisionType,
            }
        }
        fn is_org_key_trusted(&self, o: &str, k: &str) -> CanonicalTrustDecision {
            self.inner.is_org_key_trusted(o, k)
        }
        fn is_node_revoked(&self, _n: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.inner.freshness(),
                reason: CanonicalTrustReason::UnsupportedDecisionType,
            }
        }
        fn node_revocation_status(&self, _n: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::Unknown {
                freshness: self.inner.freshness(),
                reason: CanonicalTrustReason::UnsupportedDecisionType,
            }
        }
        fn is_threat_intel_canonical(&self, id: &str) -> CanonicalTrustDecision {
            self.inner.is_threat_intel_canonical(id)
        }
    }

    // Reader that forces threat intel to unavailable while keeping other answers from inner.
    struct ForceThreatUnavailableReader {
        inner: StaticCanonicalTrustReader,
    }
    impl CanonicalTrustReader for ForceThreatUnavailableReader {
        fn freshness(&self) -> CanonicalFreshness {
            CanonicalFreshness::Unavailable
        }
        fn is_global_node_authorized(&self, n: &str) -> CanonicalTrustDecision {
            self.inner.is_global_node_authorized(n)
        }
        fn is_org_key_trusted(&self, o: &str, k: &str) -> CanonicalTrustDecision {
            self.inner.is_org_key_trusted(o, k)
        }
        fn is_node_revoked(&self, n: &str) -> CanonicalTrustDecision {
            self.inner.is_node_revoked(n)
        }
        fn node_revocation_status(&self, n: &str) -> CanonicalTrustDecision {
            self.inner.node_revocation_status(n)
        }
        fn is_threat_intel_canonical(&self, _id: &str) -> CanonicalTrustDecision {
            CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Unavailable,
                reason: CanonicalTrustReason::CanonicalUnavailable,
            }
        }
    }

    #[test]
    fn disabled_context_returns_not_configured() {
        let ctx = DhtIngressPolicyContext::disabled();
        let key = DhtKey::from_str("org_pubkey:myorg");
        let out = check_dht_ingress_authority(&ctx, &key, Some("signer"), None);
        assert_eq!(out, DhtIngressGateOutcome::NotConfigured);
    }

    #[test]
    fn configured_context_accepts_advisory_key() {
        let reader = Arc::new(make_base_reader(CanonicalFreshness::Live));
        let ctx = DhtIngressPolicyContext::with_canonical_reader(reader);
        // node_info is advisory (SignedByRecordOwner or SoftLocal path in policy).
        let key = DhtKey::from_str("node_info:foo");
        let out = check_dht_ingress_authority(&ctx, &key, Some("any"), None);
        assert_eq!(out, DhtIngressGateOutcome::Accepted);
    }

    #[test]
    fn configured_context_accepts_canonical_required_key_with_authorized_signer() {
        let reader = Arc::new(make_base_reader(CanonicalFreshness::Live));
        let ctx = DhtIngressPolicyContext::with_canonical_reader(reader);
        // GlobalNodeProof is RaftOrQuorumGlobal; signer "pk:global1" is authorized in base reader.
        let key = DhtKey::GlobalNodeProof {
            node_id: "n1".into(),
        };
        let out = check_dht_ingress_authority(&ctx, &key, Some("pk:global1"), None);
        assert_eq!(out, DhtIngressGateOutcome::Accepted);
    }

    #[test]
    fn configured_context_rejects_canonical_required_key_with_unauthorized_signer() {
        let reader = Arc::new(make_base_reader(CanonicalFreshness::Live));
        let ctx = DhtIngressPolicyContext::with_canonical_reader(reader);
        let key = DhtKey::GlobalNodeProof {
            node_id: "n1".into(),
        };
        let out = check_dht_ingress_authority(&ctx, &key, Some("pk:unknown"), None);
        assert!(matches!(
            out,
            DhtIngressGateOutcome::Rejected(
                DhtKeyAuthorityRejectReason::SignerNotGloballyAuthorized
            )
        ));
    }

    #[test]
    fn configured_context_rejects_revoked_signer() {
        let mut base = make_base_reader(CanonicalFreshness::Live);
        base.authorized_global_nodes.insert("pk:bad".into());
        base.revoked_nodes.insert("pk:bad".into());
        let reader = Arc::new(base);
        let ctx = DhtIngressPolicyContext::with_canonical_reader(reader);
        let key = DhtKey::GlobalNodeProof {
            node_id: "n1".into(),
        };
        let out = check_dht_ingress_authority(&ctx, &key, Some("pk:bad"), None);
        assert!(matches!(
            out,
            DhtIngressGateOutcome::Rejected(DhtKeyAuthorityRejectReason::SignerRevoked)
        ));
    }

    #[test]
    fn configured_context_defers_unavailable_canonical_state() {
        let reader = Arc::new(ForceUnavailableReader {
            inner: make_base_reader(CanonicalFreshness::Unavailable),
        });
        let ctx = DhtIngressPolicyContext::with_canonical_reader(reader);
        let key = DhtKey::GlobalNodeProof {
            node_id: "n1".into(),
        };
        let out = check_dht_ingress_authority(&ctx, &key, Some("pk:global1"), None);
        assert!(matches!(
            out,
            DhtIngressGateOutcome::Deferred(DhtKeyAuthorityDeferReason::CanonicalUnavailable)
        ));
    }

    #[test]
    fn configured_context_defers_unknown_canonical_state() {
        let reader = Arc::new(ForceUnknownReader {
            inner: make_base_reader(CanonicalFreshness::Live),
        });
        let ctx = DhtIngressPolicyContext::with_canonical_reader(reader);
        let key = DhtKey::GlobalNodeProof {
            node_id: "n1".into(),
        };
        let out = check_dht_ingress_authority(&ctx, &key, Some("pk:global1"), None);
        assert!(matches!(
            out,
            DhtIngressGateOutcome::Deferred(DhtKeyAuthorityDeferReason::CanonicalUnknown)
        ));
    }

    #[test]
    fn threat_intel_canonical_accept_reject_defer_still_maps_correctly() {
        // Accept when present
        let mut base = make_base_reader(CanonicalFreshness::Live);
        base.threat_intel_ids.insert("intel-1".into());
        let ctx = DhtIngressPolicyContext::with_canonical_reader(Arc::new(base));
        let key = DhtKey::ThreatIndicator("intel-1".into(), "ip".into());
        assert_eq!(
            check_dht_ingress_authority(&ctx, &key, Some("s"), None),
            DhtIngressGateOutcome::Accepted
        );

        // Reject when not present in canonical (ThreatIntelNotCanonical)
        let ctx2 = DhtIngressPolicyContext::with_canonical_reader(Arc::new(make_base_reader(
            CanonicalFreshness::Live,
        )));
        let key2 = DhtKey::ThreatIndicator("unknown-intel".into(), "ip".into());
        let out2 = check_dht_ingress_authority(&ctx2, &key2, Some("s"), None);
        assert!(matches!(
            out2,
            DhtIngressGateOutcome::Rejected(DhtKeyAuthorityRejectReason::ThreatIntelNotCanonical)
        ));

        // Defer when canonical unavailable for threat
        let ctx3 = DhtIngressPolicyContext::with_canonical_reader(Arc::new(
            ForceThreatUnavailableReader {
                inner: make_base_reader(CanonicalFreshness::Unavailable),
            },
        ));
        let out3 = check_dht_ingress_authority(&ctx3, &key, Some("s"), None);
        assert!(matches!(
            out3,
            DhtIngressGateOutcome::Deferred(DhtKeyAuthorityDeferReason::CanonicalUnavailable)
        ));
    }
}
