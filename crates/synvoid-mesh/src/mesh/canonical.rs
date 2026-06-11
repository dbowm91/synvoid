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

/// Policy for how stale canonical snapshots are treated.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalSnapshotStaleMode {
    /// Stale snapshots cause deferred/canonical-unavailable behavior.
    FailOpenDefer,
    /// Stale snapshots cause not-actionable/rejected behavior.
    FailClosedNotActionable,
    /// Stale snapshots are accepted with a warning log.
    AllowStaleWithWarning,
}

impl Default for CanonicalSnapshotStaleMode {
    fn default() -> Self {
        CanonicalSnapshotStaleMode::FailOpenDefer
    }
}

/// Freshness policy for canonical snapshots exported via IPC.
///
/// Defines how the worker-side classification treats snapshots of different ages.
/// The policy is applied before the snapshot is used as canonical trust authority.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanonicalSnapshotFreshnessPolicy {
    /// Maximum age in milliseconds for a snapshot to be considered fresh.
    /// Default: 60_000 (60 seconds).
    #[serde(default = "default_fresh_max_age_ms")]
    pub fresh_max_age_ms: u64,
    /// Maximum age in milliseconds for a snapshot to be considered stale-but-grace.
    /// Beyond this, the snapshot is expired/unavailable. Default: 300_000 (5 minutes).
    #[serde(default = "default_stale_grace_max_age_ms")]
    pub stale_grace_max_age_ms: u64,
    /// How stale snapshots are handled. Default: FailOpenDefer.
    #[serde(default)]
    pub stale_mode: CanonicalSnapshotStaleMode,
}

fn default_fresh_max_age_ms() -> u64 {
    60_000
}
fn default_stale_grace_max_age_ms() -> u64 {
    300_000
}

impl Default for CanonicalSnapshotFreshnessPolicy {
    fn default() -> Self {
        Self {
            fresh_max_age_ms: 60_000,
            stale_grace_max_age_ms: 300_000,
            stale_mode: CanonicalSnapshotStaleMode::default(),
        }
    }
}

impl From<&crate::config::AuthorityFreshnessConfig> for CanonicalSnapshotFreshnessPolicy {
    fn from(cfg: &crate::config::AuthorityFreshnessConfig) -> Self {
        let mut policy = Self {
            fresh_max_age_ms: cfg.canonical_snapshot_fresh_max_age_ms,
            stale_grace_max_age_ms: cfg.canonical_snapshot_stale_grace_max_age_ms,
            stale_mode: cfg.canonical_snapshot_stale_mode,
        };
        policy.normalize();
        policy
    }
}

impl CanonicalSnapshotFreshnessPolicy {
    /// Normalize invalid configurations.
    ///
    /// Ensures `stale_grace_max_age_ms >= fresh_max_age_ms`. If the stale grace
    /// is less than the fresh threshold, it is clamped to `fresh_max_age_ms`.
    fn normalize(&mut self) {
        if self.stale_grace_max_age_ms < self.fresh_max_age_ms {
            tracing::warn!(
                "Canonical snapshot stale_grace_max_age_ms ({}) < fresh_max_age_ms ({}), clamping stale_grace to fresh_max_age",
                self.stale_grace_max_age_ms,
                self.fresh_max_age_ms,
            );
            self.stale_grace_max_age_ms = self.fresh_max_age_ms;
        }
    }
}

/// Classified freshness state of a canonical snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalSnapshotFreshnessState {
    /// No snapshot available.
    Missing,
    /// Snapshot is fresh (within fresh_max_age_ms).
    Fresh { age_ms: u64 },
    /// Snapshot is stale but within grace period.
    StaleWithinGrace { age_ms: u64 },
    /// Snapshot has expired beyond grace period.
    Expired { age_ms: u64 },
    /// Snapshot has invalid data (zero timestamp or future timestamp).
    Invalid,
}

/// Classify a canonical snapshot against a freshness policy.
///
/// This is a pure, deterministic helper. It does not perform I/O.
///
/// Rules:
/// - `None` snapshot → `Missing`
/// - `generated_at_unix == 0` → `Invalid`
/// - Future timestamp (beyond 60s skew) → `Invalid`
/// - Age ≤ fresh_max_age_ms → `Fresh`
/// - Age ≤ stale_grace_max_age_ms → `StaleWithinGrace`
/// - Age > stale_grace_max_age_ms → `Expired`
///
/// Uses saturating math throughout.
pub fn classify_canonical_snapshot(
    snapshot: Option<&CanonicalTrustSnapshot>,
    policy: &CanonicalSnapshotFreshnessPolicy,
    now_unix: u64,
) -> CanonicalSnapshotFreshnessState {
    let Some(snapshot) = snapshot else {
        return CanonicalSnapshotFreshnessState::Missing;
    };

    if snapshot.generated_at_unix == 0 {
        return CanonicalSnapshotFreshnessState::Invalid;
    }

    // Treat future timestamps (beyond 60s clock skew) as invalid.
    if now_unix + 60 < snapshot.generated_at_unix {
        return CanonicalSnapshotFreshnessState::Invalid;
    }

    let age_secs = now_unix.saturating_sub(snapshot.generated_at_unix);
    let age_ms = age_secs.saturating_mul(1000);

    if age_ms <= policy.fresh_max_age_ms {
        CanonicalSnapshotFreshnessState::Fresh { age_ms }
    } else if age_ms <= policy.stale_grace_max_age_ms {
        CanonicalSnapshotFreshnessState::StaleWithinGrace { age_ms }
    } else {
        CanonicalSnapshotFreshnessState::Expired { age_ms }
    }
}

/// A `CanonicalTrustReader` wrapper that enforces freshness policy.
///
/// Delegates all trust decisions to the underlying snapshot, but adjusts
/// the reported `CanonicalFreshness` and trust decisions based on the
/// snapshot's classified freshness state and the configured stale mode.
///
/// # Behavior
///
/// - **Fresh**: delegates normally with `CanonicalFreshness::Snapshot { age_ms }`.
/// - **StaleWithinGrace + AllowStaleWithWarning**: delegates with `CanonicalFreshness::Stale { age_ms }`.
/// - **StaleWithinGrace + FailOpenDefer**: returns `Unknown { CanonicalUnavailable }`.
/// - **StaleWithinGrace + FailClosedNotActionable**: returns `NotTrusted { ExpiredSnapshot }`.
/// - **Expired/Missing/Invalid**: returns `Unknown` or `NotTrusted` per policy.
///
/// # Live Application in Worker Lifecycle
///
/// The worker IPC handler installs this reader for `Fresh`, `AllowStaleWithWarning`,
/// and `FailClosedNotActionable` stale modes. For `FailOpenDefer`, the worker clears
/// the policy context (passing `None`) so threat-intel evaluation defers to raw lookups.
/// For `Expired`/`Invalid`/`Missing` snapshots, the worker clears the policy context.
pub struct FreshnessBoundCanonicalReader {
    snapshot: CanonicalTrustSnapshot,
    policy: CanonicalSnapshotFreshnessPolicy,
    state: CanonicalSnapshotFreshnessState,
}

impl FreshnessBoundCanonicalReader {
    /// Create a new freshness-bound reader from a snapshot and policy.
    ///
    /// The snapshot is classified at construction time using the provided
    /// `now_unix` timestamp.
    pub fn new(
        snapshot: CanonicalTrustSnapshot,
        policy: CanonicalSnapshotFreshnessPolicy,
        now_unix: u64,
    ) -> Self {
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, now_unix);
        Self {
            snapshot,
            policy,
            state,
        }
    }

    /// Returns the classified freshness state.
    pub fn freshness_state(&self) -> CanonicalSnapshotFreshnessState {
        self.state
    }

    /// Returns a reference to the underlying snapshot.
    pub fn snapshot(&self) -> &CanonicalTrustSnapshot {
        &self.snapshot
    }

    fn map_freshness(&self, _base_freshness: CanonicalFreshness) -> CanonicalFreshness {
        match self.state {
            CanonicalSnapshotFreshnessState::Fresh { age_ms } => {
                CanonicalFreshness::Snapshot { age_ms }
            }
            CanonicalSnapshotFreshnessState::StaleWithinGrace { age_ms } => {
                match self.policy.stale_mode {
                    CanonicalSnapshotStaleMode::AllowStaleWithWarning => {
                        CanonicalFreshness::Stale { age_ms }
                    }
                    CanonicalSnapshotStaleMode::FailOpenDefer
                    | CanonicalSnapshotStaleMode::FailClosedNotActionable => {
                        CanonicalFreshness::Unavailable
                    }
                }
            }
            CanonicalSnapshotFreshnessState::Expired { .. }
            | CanonicalSnapshotFreshnessState::Missing
            | CanonicalSnapshotFreshnessState::Invalid => CanonicalFreshness::Unavailable,
        }
    }

    fn policy_defer(&self) -> CanonicalTrustDecision {
        match self.state {
            CanonicalSnapshotFreshnessState::StaleWithinGrace { age_ms } => {
                match self.policy.stale_mode {
                    CanonicalSnapshotStaleMode::FailOpenDefer => CanonicalTrustDecision::Unknown {
                        freshness: CanonicalFreshness::Stale { age_ms },
                        reason: CanonicalTrustReason::CanonicalUnavailable,
                    },
                    CanonicalSnapshotStaleMode::FailClosedNotActionable => {
                        CanonicalTrustDecision::NotTrusted {
                            freshness: CanonicalFreshness::Stale { age_ms },
                            reason: CanonicalTrustReason::ExpiredSnapshot,
                        }
                    }
                    CanonicalSnapshotStaleMode::AllowStaleWithWarning => {
                        unreachable!("AllowStaleWithWarning should delegate, not defer")
                    }
                }
            }
            CanonicalSnapshotFreshnessState::Expired { .. }
            | CanonicalSnapshotFreshnessState::Invalid => CanonicalTrustDecision::NotTrusted {
                freshness: CanonicalFreshness::Unavailable,
                reason: CanonicalTrustReason::ExpiredSnapshot,
            },
            CanonicalSnapshotFreshnessState::Missing => CanonicalTrustDecision::Unknown {
                freshness: CanonicalFreshness::Unavailable,
                reason: CanonicalTrustReason::CanonicalUnavailable,
            },
            CanonicalSnapshotFreshnessState::Fresh { .. } => {
                unreachable!("Fresh should delegate, not defer")
            }
        }
    }

    fn apply_freshness_to_decision(
        &self,
        decision: CanonicalTrustDecision,
    ) -> CanonicalTrustDecision {
        match decision {
            CanonicalTrustDecision::Trusted { .. } => CanonicalTrustDecision::Trusted {
                freshness: self.freshness(),
            },
            CanonicalTrustDecision::NotTrusted { reason, .. } => {
                CanonicalTrustDecision::NotTrusted {
                    freshness: self.freshness(),
                    reason,
                }
            }
            CanonicalTrustDecision::Unknown { reason, .. } => CanonicalTrustDecision::Unknown {
                freshness: self.freshness(),
                reason,
            },
        }
    }
}

impl CanonicalTrustReader for FreshnessBoundCanonicalReader {
    fn freshness(&self) -> CanonicalFreshness {
        self.map_freshness(self.snapshot.freshness())
    }

    fn is_global_node_authorized(&self, node_id: &str) -> CanonicalTrustDecision {
        match self.state {
            CanonicalSnapshotFreshnessState::Fresh { .. } => {
                let d = self.snapshot.is_global_node_authorized(node_id);
                self.apply_freshness_to_decision(d)
            }
            CanonicalSnapshotFreshnessState::StaleWithinGrace { .. } => {
                match self.policy.stale_mode {
                    CanonicalSnapshotStaleMode::AllowStaleWithWarning => {
                        let d = self.snapshot.is_global_node_authorized(node_id);
                        self.apply_freshness_to_decision(d)
                    }
                    _ => self.policy_defer(),
                }
            }
            _ => self.policy_defer(),
        }
    }

    fn is_org_key_trusted(
        &self,
        org_id: &str,
        key_id_or_fingerprint: &str,
    ) -> CanonicalTrustDecision {
        match self.state {
            CanonicalSnapshotFreshnessState::Fresh { .. } => {
                let d = self
                    .snapshot
                    .is_org_key_trusted(org_id, key_id_or_fingerprint);
                self.apply_freshness_to_decision(d)
            }
            CanonicalSnapshotFreshnessState::StaleWithinGrace { .. } => {
                match self.policy.stale_mode {
                    CanonicalSnapshotStaleMode::AllowStaleWithWarning => {
                        let d = self
                            .snapshot
                            .is_org_key_trusted(org_id, key_id_or_fingerprint);
                        self.apply_freshness_to_decision(d)
                    }
                    _ => self.policy_defer(),
                }
            }
            _ => self.policy_defer(),
        }
    }

    fn is_node_revoked(&self, node_id: &str) -> CanonicalTrustDecision {
        self.node_revocation_status(node_id)
    }

    fn node_revocation_status(&self, node_id: &str) -> CanonicalTrustDecision {
        match self.state {
            CanonicalSnapshotFreshnessState::Fresh { .. } => {
                let d = self.snapshot.node_revocation_status(node_id);
                self.apply_freshness_to_decision(d)
            }
            CanonicalSnapshotFreshnessState::StaleWithinGrace { .. } => {
                match self.policy.stale_mode {
                    CanonicalSnapshotStaleMode::AllowStaleWithWarning => {
                        let d = self.snapshot.node_revocation_status(node_id);
                        self.apply_freshness_to_decision(d)
                    }
                    _ => self.policy_defer(),
                }
            }
            _ => self.policy_defer(),
        }
    }

    fn is_threat_intel_canonical(&self, intel_id: &str) -> CanonicalTrustDecision {
        match self.state {
            CanonicalSnapshotFreshnessState::Fresh { .. } => {
                let d = self.snapshot.is_threat_intel_canonical(intel_id);
                self.apply_freshness_to_decision(d)
            }
            CanonicalSnapshotFreshnessState::StaleWithinGrace { .. } => {
                match self.policy.stale_mode {
                    CanonicalSnapshotStaleMode::AllowStaleWithWarning => {
                        let d = self.snapshot.is_threat_intel_canonical(intel_id);
                        self.apply_freshness_to_decision(d)
                    }
                    _ => self.policy_defer(),
                }
            }
            _ => self.policy_defer(),
        }
    }
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
///
/// # Revocation vs. Authorization
///
/// `node_revocation_status` (and legacy `is_node_revoked`) returning `Trusted`
/// means only that the node has **no revocation record** in canonical (Raft)
/// state. It is **not** equivalent to "the node is fully trusted or authorized".
/// Callers must combine with `is_global_node_authorized`, org key checks,
/// and higher-level policy to determine overall trust.
pub trait CanonicalTrustReader: Send + Sync {
    fn freshness(&self) -> CanonicalFreshness;

    fn is_global_node_authorized(&self, node_id: &str) -> CanonicalTrustDecision;

    fn is_org_key_trusted(
        &self,
        org_id: &str,
        key_id_or_fingerprint: &str,
    ) -> CanonicalTrustDecision;

    /// Legacy name; prefer `node_revocation_status` for clarity.
    /// 'Trusted' result means 'not present in revocation set'.
    fn is_node_revoked(&self, node_id: &str) -> CanonicalTrustDecision;

    /// Returns the revocation status of the node according to canonical (Raft) state.
    ///
    /// `Trusted` means the node has no revocation record in canonical state
    /// (i.e. it is not known to be revoked by consensus).
    /// This is **not** equivalent to "the node is fully trusted or authorized".
    /// Callers must combine with `is_global_node_authorized`, org key checks,
    /// and higher-level policy to determine overall trust.
    ///
    /// Freshness is always reported.
    fn node_revocation_status(&self, node_id: &str) -> CanonicalTrustDecision;

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
        // Legacy name; prefer `node_revocation_status` for clarity.
        // 'Trusted' result means 'not present in revocation set'.
        self.node_revocation_status(node_id)
    }

    fn node_revocation_status(&self, node_id: &str) -> CanonicalTrustDecision {
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
///
/// Freshness is derived from the replica's last_replica_refresh_unix metadata
/// (recorded on construction and on every successful data-bearing update:
/// org keys, intel, revocations, authorized global nodes). This replaces the
/// prior placeholder age_ms:0.
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
        // Age derived from last_replica_refresh_unix recorded on updates and construction.
        if let Some(ts) = self.replica.get_last_replica_refresh_unix() {
            let now = synvoid_utils::safe_unix_timestamp();
            let age_ms = now.saturating_sub(ts) * 1000;
            CanonicalFreshness::Snapshot { age_ms }
        } else {
            // Rare: metadata absent even after construction sets it.
            CanonicalFreshness::Unavailable
        }
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
        // Legacy name; prefer `node_revocation_status` for clarity.
        // 'Trusted' result means 'not present in revocation set' (not full authorization).
        self.node_revocation_status(node_id)
    }

    fn node_revocation_status(&self, node_id: &str) -> CanonicalTrustDecision {
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

/// Bounded, serializable snapshot of canonical trust state for IPC transport.
///
/// This struct captures the subset of `EdgeReplicaManager` state needed to
/// construct a `CanonicalTrustReader` on the worker side without requiring
/// access to the Supervisor's Raft/SQLite infrastructure.
///
/// # Serialization
///
/// The struct derives `Serialize`/`Deserialize` for postcard IPC transport.
/// No private key material or signer secrets are included.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CanonicalTrustSnapshot {
    /// Unix timestamp (seconds) when this snapshot was generated.
    pub generated_at_unix: u64,
    /// Public keys of authorized global nodes.
    pub authorized_global_nodes: Vec<String>,
    /// Org key entries as "org_id:key_id_or_fingerprint" strings.
    pub org_key_entries: Vec<String>,
    /// Revoked node IDs.
    pub revoked_node_ids: Vec<String>,
    /// Threat intel indicator IDs that are canonical.
    pub threat_intel_ids: Vec<String>,
}

impl CanonicalTrustReader for CanonicalTrustSnapshot {
    fn freshness(&self) -> CanonicalFreshness {
        if self.generated_at_unix == 0 {
            return CanonicalFreshness::Unavailable;
        }
        let now = synvoid_utils::safe_unix_timestamp();
        let age_ms = now.saturating_sub(self.generated_at_unix) * 1000;
        CanonicalFreshness::Snapshot { age_ms }
    }

    fn is_global_node_authorized(&self, node_id: &str) -> CanonicalTrustDecision {
        let f = self.freshness();
        if self.authorized_global_nodes.iter().any(|pk| pk == node_id) {
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
        if self.org_key_entries.iter().any(|k| k == &key) {
            CanonicalTrustDecision::Trusted { freshness: f }
        } else {
            CanonicalTrustDecision::NotTrusted {
                freshness: f,
                reason: CanonicalTrustReason::NotPresentInCanonicalState,
            }
        }
    }

    fn is_node_revoked(&self, node_id: &str) -> CanonicalTrustDecision {
        self.node_revocation_status(node_id)
    }

    fn node_revocation_status(&self, node_id: &str) -> CanonicalTrustDecision {
        let f = self.freshness();
        if self.revoked_node_ids.iter().any(|id| id == node_id) {
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
        if self.threat_intel_ids.iter().any(|id| id == intel_id) {
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
    fn test_static_node_revocation_status_not_revoked_is_trusted() {
        let r = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        // Legacy alias
        let d = r.is_node_revoked("clean");
        assert!(matches!(d, CanonicalTrustDecision::Trusted { .. }));
        // New explicit method: not revoked == Trusted (but NOT full authorization)
        let d2 = r.node_revocation_status("clean");
        assert!(matches!(d2, CanonicalTrustDecision::Trusted { .. }));
        // Revoked node yields NotTrusted{Revoked}
        let mut r2 = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        r2.revoked_nodes.insert("bad".into());
        let d3 = r2.node_revocation_status("bad");
        match d3 {
            CanonicalTrustDecision::NotTrusted { ref reason, .. } => {
                assert_eq!(reason, &CanonicalTrustReason::Revoked);
            }
            _ => panic!("expected NotTrusted Revoked"),
        }
        // Alias and new method produce identical results
        let d_alias = r2.is_node_revoked("bad");
        assert_eq!(d3, d_alias);
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
        // Freshness is now a real Snapshot variant (age small but non-zero in practice).
        assert!(matches!(
            d,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Snapshot { .. }
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
        // Legacy alias
        let d = r.is_node_revoked("evil1");
        match d {
            CanonicalTrustDecision::NotTrusted { reason, .. } => {
                assert_eq!(reason, CanonicalTrustReason::Revoked)
            }
            _ => panic!(),
        }
        let d2 = r.is_node_revoked("good1");
        assert!(matches!(d2, CanonicalTrustDecision::Trusted { .. }));

        // New explicit method: same outcomes + freshness present.
        let d3 = r.node_revocation_status("evil1");
        match d3 {
            CanonicalTrustDecision::NotTrusted {
                ref reason,
                freshness,
            } => {
                assert_eq!(reason, &CanonicalTrustReason::Revoked);
                assert!(matches!(freshness, CanonicalFreshness::Snapshot { .. }));
            }
            _ => panic!("expected NotTrusted Revoked"),
        }
        let d4 = r.node_revocation_status("good1");
        assert!(matches!(d4, CanonicalTrustDecision::Trusted { .. }));

        // Alias and new method produce identical results
        let d_alias = r.is_node_revoked("evil1");
        assert_eq!(d3, d_alias);
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

    #[test]
    fn test_snapshot_freshness_derives_real_age() {
        let (replica, _dir) = make_temp_replica();
        let val = make_authorized_value("pk:global1");
        replica
            .update_authorized_global_node("pk:global1", &val)
            .unwrap();
        let r = SnapshotCanonicalTrustReader::new(replica.clone());
        // Freshness must be Snapshot variant (real age derived, not hardcoded 0).
        let f = r.freshness();
        match f {
            CanonicalFreshness::Snapshot { age_ms } => {
                // Age >=0; in practice small since test is fast. Upper bound generous.
                assert!(age_ms < 5000, "age_ms too large for fresh test: {}", age_ms);
            }
            other => panic!("expected Snapshot freshness, got {:?}", other),
        }
        // Also verify a decision carries the same real freshness.
        let d = r.is_global_node_authorized("pk:global1");
        assert!(matches!(
            d,
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Snapshot { .. }
            }
        ));
    }

    // Phase 7 low-risk consumer compile check (plan requirement).
    // Demonstrates that code can depend on `dyn CanonicalTrustReader`
    // without importing any Raft, EdgeReplicaManager, or state machine types.
    fn _consumer_accepts_trait(r: &dyn CanonicalTrustReader) {
        let _ = r.freshness();
        let _ = r.is_global_node_authorized("demo");
        let _ = r.is_org_key_trusted("org", "key");
        let _ = r.is_node_revoked("node");
        let _ = r.node_revocation_status("node");
        let _ = r.is_threat_intel_canonical("intel");
    }

    #[test]
    fn test_low_risk_consumer_uses_dyn_trait() {
        let r = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        _consumer_accepts_trait(&r);
        let b: Box<dyn CanonicalTrustReader> = Box::new(r);
        _consumer_accepts_trait(&*b);
    }

    #[test]
    fn test_snapshot_from_canonical_trust_snapshot() {
        let snapshot = CanonicalTrustSnapshot {
            generated_at_unix: synvoid_utils::safe_unix_timestamp(),
            authorized_global_nodes: vec!["pk:global1".to_string()],
            org_key_entries: vec!["org1:key1".to_string()],
            revoked_node_ids: vec!["badnode".to_string()],
            threat_intel_ids: vec!["intel-abc".to_string()],
        };
        let d = snapshot.is_global_node_authorized("pk:global1");
        assert!(matches!(d, CanonicalTrustDecision::Trusted { .. }));
        let d2 = snapshot.is_global_node_authorized("missing");
        assert!(matches!(d2, CanonicalTrustDecision::NotTrusted { .. }));
    }

    #[test]
    fn test_snapshot_from_canonical_trust_snapshot_org_key() {
        let snapshot = CanonicalTrustSnapshot {
            generated_at_unix: synvoid_utils::safe_unix_timestamp(),
            org_key_entries: vec!["org1:key1".to_string()],
            ..Default::default()
        };
        let d = snapshot.is_org_key_trusted("org1", "key1");
        assert!(matches!(d, CanonicalTrustDecision::Trusted { .. }));
        let d2 = snapshot.is_org_key_trusted("org1", "missing");
        assert!(matches!(d2, CanonicalTrustDecision::NotTrusted { .. }));
    }

    #[test]
    fn test_snapshot_from_canonical_trust_snapshot_revoked() {
        let snapshot = CanonicalTrustSnapshot {
            generated_at_unix: synvoid_utils::safe_unix_timestamp(),
            revoked_node_ids: vec!["badnode".to_string()],
            ..Default::default()
        };
        let d = snapshot.node_revocation_status("badnode");
        match d {
            CanonicalTrustDecision::NotTrusted { reason, .. } => {
                assert_eq!(reason, CanonicalTrustReason::Revoked);
            }
            _ => panic!("expected NotTrusted Revoked"),
        }
        let d2 = snapshot.node_revocation_status("clean");
        assert!(matches!(d2, CanonicalTrustDecision::Trusted { .. }));
    }

    #[test]
    fn test_snapshot_from_canonical_trust_snapshot_freshness() {
        let snapshot = CanonicalTrustSnapshot {
            generated_at_unix: synvoid_utils::safe_unix_timestamp(),
            ..Default::default()
        };
        let f = snapshot.freshness();
        match f {
            CanonicalFreshness::Snapshot { age_ms } => {
                assert!(age_ms < 5000);
            }
            other => panic!("expected Snapshot freshness, got {:?}", other),
        }
    }

    #[test]
    fn test_snapshot_from_canonical_trust_snapshot_unavailable_when_zero_ts() {
        let snapshot = CanonicalTrustSnapshot::default();
        assert!(matches!(
            snapshot.freshness(),
            CanonicalFreshness::Unavailable
        ));
    }

    #[test]
    fn test_snapshot_from_canonical_trust_snapshot_threat_intel() {
        let snapshot = CanonicalTrustSnapshot {
            generated_at_unix: synvoid_utils::safe_unix_timestamp(),
            threat_intel_ids: vec!["intel-xyz".to_string()],
            ..Default::default()
        };
        let d = snapshot.is_threat_intel_canonical("intel-xyz");
        assert!(matches!(d, CanonicalTrustDecision::Trusted { .. }));
        let d2 = snapshot.is_threat_intel_canonical("missing");
        assert!(matches!(d2, CanonicalTrustDecision::NotTrusted { .. }));
    }

    // =========================================================================
    // Phase 8: CanonicalSnapshotFreshnessPolicy tests
    // =========================================================================

    fn default_policy() -> CanonicalSnapshotFreshnessPolicy {
        CanonicalSnapshotFreshnessPolicy::default()
    }

    fn policy_with(
        fresh_ms: u64,
        stale_ms: u64,
        mode: CanonicalSnapshotStaleMode,
    ) -> CanonicalSnapshotFreshnessPolicy {
        CanonicalSnapshotFreshnessPolicy {
            fresh_max_age_ms: fresh_ms,
            stale_grace_max_age_ms: stale_ms,
            stale_mode: mode,
        }
    }

    fn make_snapshot(generated_at_unix: u64) -> CanonicalTrustSnapshot {
        CanonicalTrustSnapshot {
            generated_at_unix,
            authorized_global_nodes: vec!["pk:global1".to_string()],
            org_key_entries: vec!["org1:key1".to_string()],
            revoked_node_ids: vec![],
            threat_intel_ids: vec!["intel-abc".to_string()],
        }
    }

    // 1. Missing snapshot classifies as Missing
    #[test]
    fn classify_missing_snapshot() {
        let policy = default_policy();
        let now = 1000;
        let state = classify_canonical_snapshot(None, &policy, now);
        assert_eq!(state, CanonicalSnapshotFreshnessState::Missing);
    }

    // 2. Zero timestamp classifies as Invalid
    #[test]
    fn classify_zero_timestamp_is_invalid() {
        let snapshot = make_snapshot(0);
        let policy = default_policy();
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, 1000);
        assert_eq!(state, CanonicalSnapshotFreshnessState::Invalid);
    }

    // 3. Fresh timestamp classifies as Fresh
    #[test]
    fn classify_fresh_snapshot() {
        let now = 1000;
        let snapshot = make_snapshot(now - 30); // 30 seconds old = 30_000 ms
        let policy = default_policy(); // fresh_max_age_ms = 60_000
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, now);
        assert!(matches!(
            state,
            CanonicalSnapshotFreshnessState::Fresh { age_ms: 30_000 }
        ));
    }

    // 4. Stale within grace classifies as StaleWithinGrace
    #[test]
    fn classify_stale_within_grace() {
        let now = 1000;
        let snapshot = make_snapshot(now - 120); // 120 seconds old = 120_000 ms
        let policy = default_policy(); // fresh=60_000, stale_grace=300_000
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, now);
        assert!(matches!(
            state,
            CanonicalSnapshotFreshnessState::StaleWithinGrace { age_ms: 120_000 }
        ));
    }

    // 5. Expired timestamp classifies as Expired
    #[test]
    fn classify_expired_snapshot() {
        let now = 1000;
        let snapshot = make_snapshot(now - 400); // 400 seconds old = 400_000 ms
        let policy = default_policy(); // stale_grace=300_000
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, now);
        assert!(matches!(
            state,
            CanonicalSnapshotFreshnessState::Expired { age_ms: 400_000 }
        ));
    }

    // 6. Future timestamp (beyond 60s skew) classifies as Invalid
    #[test]
    fn classify_future_timestamp_is_invalid() {
        let now = 1000;
        let snapshot = make_snapshot(now + 120); // 120 seconds in the future
        let policy = default_policy();
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, now);
        assert_eq!(state, CanonicalSnapshotFreshnessState::Invalid);
    }

    // 6b. Slight future timestamp (within 60s skew) is treated as fresh
    #[test]
    fn classify_slight_future_is_fresh() {
        let now = 1000;
        let snapshot = make_snapshot(now + 30); // 30 seconds in the future (within 60s skew)
        let policy = default_policy();
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, now);
        assert!(matches!(
            state,
            CanonicalSnapshotFreshnessState::Fresh { .. }
        ));
    }

    // 7. Policy-bound reader returns normal trust decisions for fresh snapshot
    #[test]
    fn freshness_bound_reader_fresh_delegates_normally() {
        let now = 1000;
        let snapshot = make_snapshot(now - 10); // 10 seconds old
        let policy = default_policy();
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        assert!(matches!(
            reader.freshness(),
            CanonicalFreshness::Snapshot { .. }
        ));
        assert!(matches!(
            reader.is_global_node_authorized("pk:global1"),
            CanonicalTrustDecision::Trusted { .. }
        ));
        assert!(matches!(
            reader.is_org_key_trusted("org1", "key1"),
            CanonicalTrustDecision::Trusted { .. }
        ));
        assert!(matches!(
            reader.is_threat_intel_canonical("intel-abc"),
            CanonicalTrustDecision::Trusted { .. }
        ));
    }

    // 8a. Stale + FailOpenDefer returns Unknown/CanonicalUnavailable
    #[test]
    fn freshness_bound_reader_stale_fail_open_defer() {
        let now = 1000;
        let snapshot = make_snapshot(now - 120); // 120 seconds old = stale
        let policy = policy_with(60_000, 300_000, CanonicalSnapshotStaleMode::FailOpenDefer);
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        // reader.freshness() returns Unavailable for FailOpenDefer
        assert_eq!(reader.freshness(), CanonicalFreshness::Unavailable);
        match reader.is_global_node_authorized("pk:global1") {
            CanonicalTrustDecision::Unknown { freshness, reason } => {
                // The decision embeds the stale age, not Unavailable
                assert!(matches!(
                    freshness,
                    CanonicalFreshness::Stale { age_ms: 120_000 }
                ));
                assert_eq!(reason, CanonicalTrustReason::CanonicalUnavailable);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    // 8b. Stale + FailClosedNotActionable returns NotTrusted/ExpiredSnapshot
    #[test]
    fn freshness_bound_reader_stale_fail_closed() {
        let now = 1000;
        let snapshot = make_snapshot(now - 120);
        let policy = policy_with(
            60_000,
            300_000,
            CanonicalSnapshotStaleMode::FailClosedNotActionable,
        );
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        // reader.freshness() returns Unavailable for FailClosedNotActionable
        assert_eq!(reader.freshness(), CanonicalFreshness::Unavailable);
        match reader.is_global_node_authorized("pk:global1") {
            CanonicalTrustDecision::NotTrusted { freshness, reason } => {
                // The decision embeds the stale age, not Unavailable
                assert!(matches!(
                    freshness,
                    CanonicalFreshness::Stale { age_ms: 120_000 }
                ));
                assert_eq!(reason, CanonicalTrustReason::ExpiredSnapshot);
            }
            other => panic!("expected NotTrusted, got {:?}", other),
        }
    }

    // 8c. Stale + AllowStaleWithWarning delegates with Stale freshness
    #[test]
    fn freshness_bound_reader_stale_allow_with_warning() {
        let now = 1000;
        let snapshot = make_snapshot(now - 120);
        let policy = policy_with(
            60_000,
            300_000,
            CanonicalSnapshotStaleMode::AllowStaleWithWarning,
        );
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        assert!(matches!(
            reader.freshness(),
            CanonicalFreshness::Stale { age_ms: 120_000 }
        ));
        assert!(matches!(
            reader.is_global_node_authorized("pk:global1"),
            CanonicalTrustDecision::Trusted {
                freshness: CanonicalFreshness::Stale { .. }
            }
        ));
    }

    // 9. Expired snapshot returns NotTrusted/ExpiredSnapshot
    #[test]
    fn freshness_bound_reader_expired_returns_not_trusted() {
        let now = 1000;
        let snapshot = make_snapshot(now - 400);
        let policy = default_policy();
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        assert_eq!(reader.freshness(), CanonicalFreshness::Unavailable);
        match reader.is_global_node_authorized("pk:global1") {
            CanonicalTrustDecision::NotTrusted { reason, .. } => {
                assert_eq!(reason, CanonicalTrustReason::ExpiredSnapshot);
            }
            other => panic!("expected NotTrusted, got {:?}", other),
        }
    }

    // 10. Invalid snapshot (zero timestamp) returns NotTrusted/ExpiredSnapshot
    #[test]
    fn freshness_bound_reader_invalid_returns_not_trusted() {
        let snapshot = CanonicalTrustSnapshot::default(); // generated_at_unix = 0
        let policy = default_policy();
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, 1000);

        assert_eq!(reader.freshness(), CanonicalFreshness::Unavailable);
        match reader.is_threat_intel_canonical("intel-abc") {
            CanonicalTrustDecision::NotTrusted { reason, .. } => {
                assert_eq!(reason, CanonicalTrustReason::ExpiredSnapshot);
            }
            other => panic!("expected NotTrusted, got {:?}", other),
        }
    }

    // 13. Raw CanonicalTrustSnapshot still implements CanonicalTrustReader
    #[test]
    fn raw_snapshot_still_implements_reader() {
        let snapshot = make_snapshot(synvoid_utils::safe_unix_timestamp());
        let r: &dyn CanonicalTrustReader = &snapshot;
        assert!(matches!(r.freshness(), CanonicalFreshness::Snapshot { .. }));
        assert!(matches!(
            r.is_global_node_authorized("pk:global1"),
            CanonicalTrustDecision::Trusted { .. }
        ));
    }

    // Additional: freshness_state accessor
    #[test]
    fn freshness_bound_reader_state_accessor() {
        let now = 1000;
        let snapshot = make_snapshot(now - 10);
        let policy = default_policy();
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);
        assert!(matches!(
            reader.freshness_state(),
            CanonicalSnapshotFreshnessState::Fresh { .. }
        ));
    }

    // Additional: snapshot accessor
    #[test]
    fn freshness_bound_reader_snapshot_accessor() {
        let now = 1000;
        let snapshot = make_snapshot(now - 10);
        let policy = default_policy();
        let reader = FreshnessBoundCanonicalReader::new(snapshot.clone(), policy, now);
        assert_eq!(
            reader.snapshot().generated_at_unix,
            snapshot.generated_at_unix
        );
    }

    // Additional: custom policy thresholds
    #[test]
    fn classify_custom_policy_thresholds() {
        let now = 1000;
        let snapshot = make_snapshot(now - 5); // 5 seconds old
        let policy = policy_with(3_000, 10_000, CanonicalSnapshotStaleMode::FailOpenDefer);
        // 5_000 ms > 3_000 ms fresh threshold → stale
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, now);
        assert!(matches!(
            state,
            CanonicalSnapshotFreshnessState::StaleWithinGrace { age_ms: 5_000 }
        ));
    }

    // Additional: policy-bound reader with revoked node under stale mode
    #[test]
    fn freshness_bound_reader_revoked_under_stale_mode() {
        let now = 1000;
        let mut snapshot = make_snapshot(now - 120);
        snapshot.revoked_node_ids.push("badnode".to_string());
        let policy = policy_with(60_000, 300_000, CanonicalSnapshotStaleMode::FailOpenDefer);
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        // Under FailOpenDefer, stale returns Unknown with Stale freshness, not per-record decisions.
        match reader.node_revocation_status("badnode") {
            CanonicalTrustDecision::Unknown { reason, freshness } => {
                assert_eq!(reason, CanonicalTrustReason::CanonicalUnavailable);
                assert!(matches!(
                    freshness,
                    CanonicalFreshness::Stale { age_ms: 120_000 }
                ));
            }
            other => panic!("expected Unknown for stale FailOpenDefer, got {:?}", other),
        }
    }

    // Additional: AllowStaleWithWarning propagates revocation decisions
    #[test]
    fn freshness_bound_reader_revoked_under_allow_stale() {
        let now = 1000;
        let mut snapshot = make_snapshot(now - 120);
        snapshot.revoked_node_ids.push("badnode".to_string());
        let policy = policy_with(
            60_000,
            300_000,
            CanonicalSnapshotStaleMode::AllowStaleWithWarning,
        );
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        // Under AllowStaleWithWarning, stale delegates to underlying snapshot.
        match reader.node_revocation_status("badnode") {
            CanonicalTrustDecision::NotTrusted { reason, freshness } => {
                assert_eq!(reason, CanonicalTrustReason::Revoked);
                assert!(matches!(freshness, CanonicalFreshness::Stale { .. }));
            }
            other => panic!("expected NotTrusted Revoked, got {:?}", other),
        }
    }

    // =========================================================================
    // Iteration 32: Config conversion and normalization tests
    // =========================================================================

    // Config defaults produce conservative CanonicalSnapshotFreshnessPolicy
    #[test]
    fn authority_freshness_config_defaults_produce_conservative_policy() {
        let cfg = crate::config::AuthorityFreshnessConfig::default();
        let policy = crate::canonical::CanonicalSnapshotFreshnessPolicy::from(&cfg);
        assert_eq!(policy.fresh_max_age_ms, 60_000);
        assert_eq!(policy.stale_grace_max_age_ms, 300_000);
        assert_eq!(policy.stale_mode, CanonicalSnapshotStaleMode::FailOpenDefer);
    }

    // Explicit config values convert correctly
    #[test]
    fn authority_freshness_config_explicit_values_convert() {
        let mut cfg = crate::config::AuthorityFreshnessConfig::default();
        cfg.canonical_snapshot_fresh_max_age_ms = 120_000;
        cfg.canonical_snapshot_stale_grace_max_age_ms = 600_000;
        cfg.canonical_snapshot_stale_mode = CanonicalSnapshotStaleMode::FailClosedNotActionable;
        let policy = crate::canonical::CanonicalSnapshotFreshnessPolicy::from(&cfg);
        assert_eq!(policy.fresh_max_age_ms, 120_000);
        assert_eq!(policy.stale_grace_max_age_ms, 600_000);
        assert_eq!(
            policy.stale_mode,
            CanonicalSnapshotStaleMode::FailClosedNotActionable
        );
    }

    // Invalid config where stale grace < fresh threshold is normalized
    #[test]
    fn authority_freshness_config_stale_less_than_fresh_is_normalized() {
        let mut cfg = crate::config::AuthorityFreshnessConfig::default();
        cfg.canonical_snapshot_fresh_max_age_ms = 120_000;
        cfg.canonical_snapshot_stale_grace_max_age_ms = 60_000; // stale < fresh
        let policy = crate::canonical::CanonicalSnapshotFreshnessPolicy::from(&cfg);
        // stale_grace should be clamped to fresh_max_age
        assert_eq!(policy.fresh_max_age_ms, 120_000);
        assert_eq!(policy.stale_grace_max_age_ms, 120_000);
    }

    // Config normalization is idempotent
    #[test]
    fn canonical_snapshot_freshness_policy_normalize_idempotent() {
        let mut policy = CanonicalSnapshotFreshnessPolicy {
            fresh_max_age_ms: 120_000,
            stale_grace_max_age_ms: 60_000, // invalid
            stale_mode: CanonicalSnapshotStaleMode::FailOpenDefer,
        };
        policy.normalize();
        assert_eq!(policy.stale_grace_max_age_ms, 120_000);
        // Normalize again - should be a no-op
        policy.normalize();
        assert_eq!(policy.stale_grace_max_age_ms, 120_000);
    }

    // FailClosedNotActionable installs reader that returns NotTrusted for stale queries
    #[test]
    fn fail_closed_not_actionable_stale_reader_returns_not_trusted() {
        let now = 1000;
        let snapshot = make_snapshot(now - 120); // stale
        let policy = policy_with(
            60_000,
            300_000,
            CanonicalSnapshotStaleMode::FailClosedNotActionable,
        );
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        // All trust queries should return NotTrusted with ExpiredSnapshot
        assert!(matches!(
            reader.is_global_node_authorized("pk:global1"),
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::ExpiredSnapshot,
                ..
            }
        ));
        assert!(matches!(
            reader.is_org_key_trusted("org1", "key1"),
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::ExpiredSnapshot,
                ..
            }
        ));
        assert!(matches!(
            reader.is_threat_intel_canonical("intel-abc"),
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::ExpiredSnapshot,
                ..
            }
        ));
        // Revocation status also returns NotTrusted (snapshot delegation, then freshness overlay)
        assert!(matches!(
            reader.node_revocation_status("unknown"),
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::ExpiredSnapshot,
                ..
            }
        ));
    }

    // Expired snapshot does not silently remain active as fresh authority
    #[test]
    fn expired_snapshot_does_not_return_trusted_decisions() {
        let now = 1000;
        let snapshot = make_snapshot(now - 400); // expired
        let policy = default_policy();
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);

        // Even though the snapshot has valid data, expired classification prevents trust
        assert!(matches!(
            reader.is_global_node_authorized("pk:global1"),
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::ExpiredSnapshot,
                ..
            }
        ));
        assert!(matches!(
            reader.freshness(),
            CanonicalFreshness::Unavailable
        ));
    }

    // Serde round-trip for CanonicalSnapshotStaleMode matches snake_case names
    #[test]
    fn stale_mode_serde_names_match_snake_case() {
        let modes = [
            (
                CanonicalSnapshotStaleMode::FailOpenDefer,
                "\"fail_open_defer\"",
            ),
            (
                CanonicalSnapshotStaleMode::FailClosedNotActionable,
                "\"fail_closed_not_actionable\"",
            ),
            (
                CanonicalSnapshotStaleMode::AllowStaleWithWarning,
                "\"allow_stale_with_warning\"",
            ),
        ];
        for (mode, expected_json) in modes {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected_json, "serde name mismatch for {:?}", mode);
            let deserialized: CanonicalSnapshotStaleMode = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, mode);
        }
    }

    // Missing snapshot reader returns Unknown/CanonicalUnavailable
    #[test]
    fn missing_snapshot_reader_returns_unknown() {
        let now = 1000;
        let policy = default_policy();
        // We can't create a FreshnessBoundCanonicalReader with None snapshot,
        // but classify_canonical_snapshot handles it correctly.
        let state = classify_canonical_snapshot(None, &policy, now);
        assert_eq!(state, CanonicalSnapshotFreshnessState::Missing);
    }

    // Verify the full lifecycle path: config → policy → classification → reader
    #[test]
    fn config_to_reader_lifecycle_path() {
        let mut cfg = crate::config::AuthorityFreshnessConfig::default();
        cfg.canonical_snapshot_fresh_max_age_ms = 5_000;
        cfg.canonical_snapshot_stale_grace_max_age_ms = 15_000;
        cfg.canonical_snapshot_stale_mode = CanonicalSnapshotStaleMode::FailClosedNotActionable;

        let policy = crate::canonical::CanonicalSnapshotFreshnessPolicy::from(&cfg);
        assert_eq!(policy.fresh_max_age_ms, 5_000);
        assert_eq!(policy.stale_grace_max_age_ms, 15_000);

        let now = 1000;
        let snapshot = make_snapshot(now - 10); // 10s = 10_000ms old

        // With fresh=5_000ms, stale_grace=15_000ms, 10_000ms is stale
        let state = classify_canonical_snapshot(Some(&snapshot), &policy, now);
        assert!(matches!(
            state,
            CanonicalSnapshotFreshnessState::StaleWithinGrace { age_ms: 10_000 }
        ));

        // FailClosedNotActionable reader returns NotTrusted for stale
        let reader = FreshnessBoundCanonicalReader::new(snapshot, policy, now);
        assert!(matches!(
            reader.is_global_node_authorized("pk:global1"),
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::ExpiredSnapshot,
                ..
            }
        ));
    }
}
