//! Canonical trust reader seam (Iteration 8).
//!
//! Provides a narrow, read-only interface over Raft-derived canonical authority
//! state (global nodes, org keys, revocations, threat intel) without exposing
//! Raft, snapshot, or DHT internals to callers.
//!
//! Domain distinction: canonical answers "what is trusted per Raft consensus?";
//! advisory DHT answers "what has been advertised?"; policy decides action.
//!
//! This seam is the first concrete boundary chosen in mesh trust domains.
//! Consumers should depend on `CanonicalTrustReader` (or a `dyn` reference)
//! when they need canonical answers, rather than importing `raft::` types.

use std::collections::HashSet;
use std::sync::Arc;

use crate::raft::edge_replica::EdgeReplicaManager;

/// Freshness classification for a canonical read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalFreshness {
    /// Data is live from authoritative source.
    Live,
    /// Data comes from a local snapshot of known age.
    Snapshot { age_ms: u64 },
    /// Data is stale beyond grace but was accepted under policy.
    Stale { age_ms: u64 },
    /// No canonical snapshot or source available.
    Unavailable,
}

impl Default for CanonicalFreshness {
    fn default() -> Self {
        CanonicalFreshness::Unavailable
    }
}

/// Outcome of a canonical trust query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalTrustDecision {
    Trusted {
        freshness: CanonicalFreshness,
    },
    NotTrusted {
        freshness: CanonicalFreshness,
        reason: CanonicalTrustReason,
    },
    Unknown {
        freshness: CanonicalFreshness,
        reason: CanonicalTrustReason,
    },
}

/// Reason for a trust decision (or lack of decision).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalTrustReason {
    PresentInCanonicalState,
    NotPresentInCanonicalState,
    Revoked,
    ExpiredSnapshot,
    CanonicalUnavailable,
    UnsupportedDecisionType,
}

/// Read-only seam for canonical (Raft) trust state.
///
/// Consumers (policy, peer auth, key policy, etc.) should depend on this
/// trait rather than importing Raft state machine or EdgeReplicaManager
/// directly when a trust/freshness answer is required.
///
/// - All answers include freshness.
/// - `Unknown` is used for unsupported query types or when canonical state
///   cannot answer (do not confuse with `NotTrusted`).
/// - This trait does not perform signature verification or policy enforcement.
/// - Implementations are snapshot-oriented and synchronous (no I/O or network
///   in the trait methods).
/// - `Unknown` for any decision type not yet supported by the underlying
///   canonical surface.
pub trait CanonicalTrustReader: Send + Sync {
    fn freshness(&self) -> CanonicalFreshness;

    fn is_global_node_authorized(&self, node_id: &str) -> CanonicalTrustDecision;

    fn is_org_key_trusted(
        &self,
        org_id: &str,
        key_id_or_fingerprint: &str,
    ) -> CanonicalTrustDecision;

    fn is_node_revoked(&self, node_id: &str) -> CanonicalTrustDecision;

    fn is_threat_intel_canonical(&self, intel_id: &str) -> CanonicalTrustDecision;
}

/// Static, pure-data implementation for tests and offline scenarios.
/// No Raft, no DB, fully deterministic.
#[derive(Debug, Default, Clone)]
pub struct StaticCanonicalTrustReader {
    pub authorized_global_nodes: HashSet<String>,
    pub trusted_org_keys: HashSet<String>, // "org_id:key_id_or_fingerprint"
    pub revoked_nodes: HashSet<String>,
    pub threat_intel_ids: HashSet<String>,
    pub freshness: CanonicalFreshness,
}

impl StaticCanonicalTrustReader {
    pub fn new(freshness: CanonicalFreshness) -> Self {
        Self {
            freshness,
            ..Default::default()
        }
    }
}

impl CanonicalTrustReader for StaticCanonicalTrustReader {
    fn freshness(&self) -> CanonicalFreshness {
        self.freshness
    }

    fn is_global_node_authorized(&self, node_id: &str) -> CanonicalTrustDecision {
        let f = self.freshness();
        if self.authorized_global_nodes.contains(node_id) {
            CanonicalTrustDecision::Trusted { freshness: f }
        } else {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::NotPresentInCanonicalState,
            }
        }
    }

    fn is_org_key_trusted(
        &self,
        org_id: &str,
        key_id_or_fingerprint: &str,
    ) -> CanonicalTrustDecision {
        let f = self.freshness();
        let key = format!("{}:{}", org_id, key_id_or_fingerprint);
        if self.trusted_org_keys.contains(&key) {
            CanonicalTrustDecision::Trusted { freshness: f }
        } else {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::NotPresentInCanonicalState,
            }
        }
    }

    fn is_node_revoked(&self, node_id: &str) -> CanonicalTrustDecision {
        let f = self.freshness();
        if self.revoked_nodes.contains(node_id) {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::Revoked,
            }
        } else {
            CanonicalTrustDecision::Trusted { freshness: f }
        }
    }

    fn is_threat_intel_canonical(&self, intel_id: &str) -> CanonicalTrustDecision {
        let f = self.freshness();
        if self.threat_intel_ids.contains(intel_id) {
            CanonicalTrustDecision::Trusted { freshness: f }
        } else {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::NotPresentInCanonicalState,
            }
        }
    }
}

/// Snapshot-backed implementation wrapping an EdgeReplicaManager.
/// Reads directly from the replica's canonical tables (no duplication).
/// Freshness is reported as Snapshot (age tracking via replica metadata can be
/// refined later without API change).
#[derive(Clone)]
pub struct SnapshotCanonicalTrustReader {
    replica: Arc<EdgeReplicaManager>,
}

impl SnapshotCanonicalTrustReader {
    pub fn new(replica: Arc<EdgeReplicaManager>) -> Self {
        Self { replica }
    }
}

impl CanonicalTrustReader for SnapshotCanonicalTrustReader {
    fn freshness(&self) -> CanonicalFreshness {
        // No direct age_ms on replica snapshot exposed in narrow surface yet.
        // Use Snapshot{0} as placeholder; real age can be derived from
        // last_sync or config in future without changing trait.
        CanonicalFreshness::Snapshot { age_ms: 0 }
    }

    fn is_global_node_authorized(&self, node_id: &str) -> CanonicalTrustDecision {
        let f = self.freshness();
        if self.replica.get_authorized_global_node(node_id).is_some() {
            CanonicalTrustDecision::Trusted { freshness: f }
        } else {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::NotPresentInCanonicalState,
            }
        }
    }

    fn is_org_key_trusted(
        &self,
        org_id: &str,
        key_id_or_fingerprint: &str,
    ) -> CanonicalTrustDecision {
        let f = self.freshness();
        if let Some(key) = self.replica.get_org_key(key_id_or_fingerprint) {
            if key.org_id == org_id {
                CanonicalTrustDecision::Trusted { freshness: f }
            } else {
                CanonicalTrustDecision::NotTrusted {
                    freshness: f,
                    reason: CanonicalTrustReason::NotPresentInCanonicalState,
                }
            }
        } else {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::NotPresentInCanonicalState,
            }
        }
    }

    fn is_node_revoked(&self, node_id: &str) -> CanonicalTrustDecision {
        let f = self.freshness();
        if self.replica.get_revoked_node(node_id) {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::Revoked,
            }
        } else {
            CanonicalTrustDecision::Trusted { freshness: f }
        }
    }

    fn is_threat_intel_canonical(&self, intel_id: &str) -> CanonicalTrustDecision {
        let f = self.freshness();
        if self.replica.get_threat_intel(intel_id).is_some() {
            CanonicalTrustDecision::Trusted { freshness: f }
        } else {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::NotPresentInCanonicalState,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::edge_replica::EdgeReplicaManager;
    use crate::raft::state_machine::{AuthorizedGlobalNode, OrgPublicKey, ThreatIntel};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_temp_replica() -> (Arc<EdgeReplicaManager>, TempDir) {
        let dir = TempDir::new().unwrap();
        let mgr = EdgeReplicaManager::new(dir.path().to_path_buf()).unwrap();
        (Arc::new(mgr), dir)
    }

    fn make_authorized_value(pk: &str) -> Vec<u8> {
        let node = AuthorizedGlobalNode {
            public_key: pk.to_string(),
            trust_level: 1,
            attestation_report: None,
            authorized_at: 1000,
        };
        postcard::to_stdvec(&node).unwrap()
    }

    fn make_org_key_value(org_id: &str, key_id: &str) -> Vec<u8> {
        let key = OrgPublicKey {
            org_id: org_id.to_string(),
            public_key: vec![1, 2, 3],
            created_at: 1000,
            signer_node_id: "node1".into(),
        };
        postcard::to_stdvec(&key).unwrap()
    }

    fn make_threat_value(id: &str) -> Vec<u8> {
        let intel = ThreatIntel {
            indicator_id: id.to_string(),
            indicator_type: "malware".into(),
            pattern: "evil".into(),
            severity: "high".into(),
            created_at: 1000,
            expires_at: None,
            source_node_id: "node1".into(),
        };
        postcard::to_stdvec(&intel).unwrap()
    }

    // Must match the exact two-blob format expected by EdgeReplicaManager::update_revocation
    // (historical: two separate postcard structs concatenated).
    fn make_revocation_value(_node_id: &str) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct RevInfo {
            revoked_at: u64,
            reason: String,
        }
        #[derive(serde::Serialize)]
        struct RevRecord {
            revoked_by_node_id: String,
        }
        let mut out = postcard::to_stdvec(&RevInfo {
            revoked_at: 1000,
            reason: "compromise".into(),
        })
        .unwrap();
        let rec = postcard::to_stdvec(&RevRecord {
            revoked_by_node_id: "admin".into(),
        })
        .unwrap();
        out.extend(rec);
        out
    }

    #[test]
    fn test_static_trusted_global_node() {
        let mut r = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        r.authorized_global_nodes.insert("pk:global1".into());
        let d = r.is_global_node_authorized("pk:global1");
        assert!(matches!(
            d,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Live
            }
        ));
    }

    #[test]
    fn test_static_not_trusted_absent_global() {
        let r = StaticCanonicalTrustReader::new(CanonicalFreshness::Snapshot { age_ms: 42 });
        let d = r.is_global_node_authorized("pk:absent");
        match d {
            CanonicalTrustDecision::NotTrusted { freshness, reason } => {
                assert!(matches!(
                    freshness,
                    CanonicalFreshness::Snapshot { age_ms: 42 }
                ));
                assert_eq!(reason, CanonicalTrustReason::NotPresentInCanonicalState);
            }
            _ => panic!("expected NotTrusted"),
        }
    }

    #[test]
    fn test_static_trusted_org_key() {
        let mut r = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        r.trusted_org_keys.insert("org1:key1".into());
        let d = r.is_org_key_trusted("org1", "key1");
        assert!(matches!(d, CanonicalTrustDecision::Trusted { .. }));
    }

    #[test]
    fn test_static_revoked_node() {
        let mut r = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        r.revoked_nodes.insert("badnode".into());
        let d = r.is_node_revoked("badnode");
        match d {
            CanonicalTrustDecision::NotTrusted { reason, .. } => {
                assert_eq!(reason, CanonicalTrustReason::Revoked);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_static_unknown_and_freshness_propagation() {
        // Cover Unknown variant + Unsupported + freshness propagation.
        let d: CanonicalTrustDecision = CanonicalTrustDecision::Unknown {
            freshness: CanonicalFreshness::Unavailable,
            reason: CanonicalTrustReason::UnsupportedDecisionType,
        };
        match d {
            CanonicalTrustDecision::Unknown { freshness, reason } => {
                assert!(matches!(freshness, CanonicalFreshness::Unavailable));
                assert_eq!(reason, CanonicalTrustReason::UnsupportedDecisionType);
            }
            _ => panic!(),
        }
        let r = StaticCanonicalTrustReader::new(CanonicalFreshness::Stale { age_ms: 999 });
        let d = r.is_threat_intel_canonical("no-such");
        match d {
            CanonicalTrustDecision::NotTrusted { freshness, .. } => {
                assert!(matches!(
                    freshness,
                    CanonicalFreshness::Stale { age_ms: 999 }
                ));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_static_not_revoked_is_trusted() {
        let r = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        let d = r.is_node_revoked("clean");
        assert!(matches!(d, CanonicalTrustDecision::Trusted { .. }));
    }

    #[test]
    fn test_snapshot_global_authorized() {
        let (replica, _dir) = make_temp_replica();
        let val = make_authorized_value("pk:global1");
        replica
            .update_authorized_global_node("pk:global1", &val)
            .unwrap();
        let r = SnapshotCanonicalTrustReader::new(replica.clone());
        let d = r.is_global_node_authorized("pk:global1");
        assert!(matches!(
            d,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Snapshot { age_ms: 0 }
            }
        ));
        let d2 = r.is_global_node_authorized("missing");
        assert!(matches!(d2, CanonicalTrustDecision::NotTrusted { .. }));
    }

    #[test]
    fn test_snapshot_org_key() {
        let (replica, _dir) = make_temp_replica();
        let val = make_org_key_value("org42", "fp:abc");
        replica.update_org_key("fp:abc", &val).unwrap();
        let r = SnapshotCanonicalTrustReader::new(replica);
        let d = r.is_org_key_trusted("org42", "fp:abc");
        assert!(matches!(d, CanonicalTrustDecision::Trusted { .. }));
        let d2 = r.is_org_key_trusted("org42", "nope");
        assert!(matches!(d2, CanonicalTrustDecision::NotTrusted { .. }));
    }

    #[test]
    fn test_snapshot_revoked_and_not() {
        let (replica, _dir) = make_temp_replica();
        // Populate via cache (bypasses update_revocation double-deser for this test;
        // get_revoked_node short-circuits on cache hit for "revocation:<id>").
        // This exercises the CanonicalTrustReader revocation path without relying on
        // the internal revocation value layout assumptions in EdgeReplicaManager.
        let val = make_revocation_value("evil1");
        replica.cache_key(
            crate::raft::state_machine::Namespace::Revocation,
            "evil1",
            val,
        );
        let r = SnapshotCanonicalTrustReader::new(replica);
        let d = r.is_node_revoked("evil1");
        match d {
            CanonicalTrustDecision::NotTrusted { reason, .. } => {
                assert_eq!(reason, CanonicalTrustReason::Revoked)
            }
            _ => panic!(),
        }
        let d2 = r.is_node_revoked("good1");
        assert!(matches!(d2, CanonicalTrustDecision::Trusted { .. }));
    }

    #[test]
    fn test_snapshot_threat_and_freshness() {
        let (replica, _dir) = make_temp_replica();
        let val = make_threat_value("intel-xyz");
        replica.update_threat_intel("intel-xyz", &val).unwrap();
        let r = SnapshotCanonicalTrustReader::new(replica);
        let d = r.is_threat_intel_canonical("intel-xyz");
        assert!(matches!(
            d,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Snapshot { .. }
            }
        ));
    }

    #[test]
    fn test_freshness_always_present() {
        let r1 = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        assert_eq!(r1.freshness(), CanonicalFreshness::Live);
        let r2 = StaticCanonicalTrustReader::new(CanonicalFreshness::Unavailable);
        let d = r2.is_global_node_authorized("x");
        match d {
            CanonicalTrustDecision::NotTrusted { freshness, .. } => {
                assert!(matches!(freshness, CanonicalFreshness::Unavailable))
            }
            _ => panic!(),
        }
    }

    // Phase 7 low-risk consumer compile check (plan requirement).
    // Demonstrates that code can depend on `dyn CanonicalTrustReader`
    // without importing any Raft, EdgeReplicaManager, or state machine types.
    fn _consumer_accepts_trait(r: &dyn CanonicalTrustReader) {
        let _ = r.freshness();
        let _ = r.is_global_node_authorized("demo");
        let _ = r.is_org_key_trusted("org", "key");
        let _ = r.is_node_revoked("node");
        let _ = r.is_threat_intel_canonical("intel");
    }

    #[test]
    fn test_low_risk_consumer_uses_dyn_trait() {
        let r = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        _consumer_accepts_trait(&r);
        let b: Box<dyn CanonicalTrustReader> = Box::new(r);
        _consumer_accepts_trait(&*b);
    }
}
