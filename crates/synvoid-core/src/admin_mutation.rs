//! Admin and control-plane mutation authority, outcome, and audit types.
//!
//! These types classify who performed a mutation, what the outcome was,
//! and whether the mutation was audited. They live in `synvoid-core`
//! to avoid circular dependencies between admin handlers, block-store,
//! mesh, and supervisor crates.

use serde::{Deserialize, Serialize};

/// Classifies who or what initiated a mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminMutationAuthority {
    /// An administrator manually triggered the mutation via the admin API.
    AdminManual,
    /// The supervisor process triggered the mutation via gRPC or IPC.
    SupervisorManual,
    /// The supervisor triggered an automatic sync (e.g., config propagation to workers).
    SupervisorSync,
    /// A mesh policy rule triggered the mutation (e.g., threat-intel policy gate).
    MeshPolicyGated,
    /// A local detector (WAF, honeypot, ASN tracker) triggered the mutation.
    LocalDetector,
    /// A worker process triggered the mutation via IPC to the supervisor.
    WorkerIpc,
    /// A legacy compatibility path triggered the mutation.
    /// Compatibility paths must use this variant explicitly rather than
    /// silently defaulting to admin authority.
    CompatibilityLegacy,
}

impl std::fmt::Display for AdminMutationAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdminManual => write!(f, "Admin Manual"),
            Self::SupervisorManual => write!(f, "Supervisor Manual"),
            Self::SupervisorSync => write!(f, "Supervisor Sync"),
            Self::MeshPolicyGated => write!(f, "Mesh Policy Gated"),
            Self::LocalDetector => write!(f, "Local Detector"),
            Self::WorkerIpc => write!(f, "Worker IPC"),
            Self::CompatibilityLegacy => write!(f, "Compatibility Legacy"),
        }
    }
}

/// Metadata about the actor who initiated a mutation.
///
/// Raw session tokens must never be stored here. If a session ID is
/// included, it must be hashed or replaced with a safe identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminActor {
    /// The authority classification of the actor.
    pub authority: AdminMutationAuthority,
    /// Optional actor identifier (username, node ID, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    /// Optional source IP address of the actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Optional user agent string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Optional hashed session ID (never raw tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id_hash: Option<String>,
}

impl AdminActor {
    /// Create a minimal actor with just an authority classification.
    pub fn new(authority: AdminMutationAuthority) -> Self {
        Self {
            authority,
            actor_id: None,
            source_ip: None,
            user_agent: None,
            session_id_hash: None,
        }
    }

    /// Create an actor with authority and actor ID.
    pub fn with_id(authority: AdminMutationAuthority, actor_id: impl Into<String>) -> Self {
        Self {
            authority,
            actor_id: Some(actor_id.into()),
            source_ip: None,
            user_agent: None,
            session_id_hash: None,
        }
    }

    /// Builder method to set source IP.
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Builder method to set user agent.
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Builder method to set hashed session ID.
    pub fn with_session_id_hash(mut self, hash: impl Into<String>) -> Self {
        self.session_id_hash = Some(hash.into());
        self
    }
}

/// Classifies the outcome of a mutation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AdminMutationStatus {
    /// The mutation was applied to the local store.
    Applied,
    /// No-op: the target was already in the requested state (e.g., block already present).
    NoOpAlreadyPresent,
    /// No-op: the target was already absent (e.g., unblock of something not blocked).
    NoOpAlreadyAbsent,
    /// The event was a duplicate and was ignored.
    DuplicateIgnored,
    /// The event was stale and was ignored.
    StaleIgnored,
    /// The request was invalid and was rejected.
    InvalidRejected,
    /// The request was unauthorized and was rejected.
    UnauthorizedRejected,
    /// The mutation failed.
    Failed,
}

impl std::fmt::Display for AdminMutationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Applied => write!(f, "Applied"),
            Self::NoOpAlreadyPresent => write!(f, "No-op: Already Present"),
            Self::NoOpAlreadyAbsent => write!(f, "No-op: Already Absent"),
            Self::DuplicateIgnored => write!(f, "Duplicate Ignored"),
            Self::StaleIgnored => write!(f, "Stale Ignored"),
            Self::InvalidRejected => write!(f, "Invalid Rejected"),
            Self::UnauthorizedRejected => write!(f, "Unauthorized Rejected"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Status of mesh propagation after a local mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PropagationStatus {
    /// Propagation is not applicable (e.g., local-only operation).
    NotApplicable,
    /// The mutation was queued for best-effort mesh propagation.
    /// This does NOT guarantee delivery to all peers.
    QueuedBestEffort,
    /// The mutation was applied locally only; no propagation was attempted.
    AppliedLocalOnly,
    /// A snapshot repair is required to bring peers into consistency.
    SnapshotRepairRequired,
    /// The mutation was queued but queuing failed.
    FailedToQueue,
    /// Propagation was deferred to a later time.
    Deferred,
}

impl std::fmt::Display for PropagationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplicable => write!(f, "Not Applicable"),
            Self::QueuedBestEffort => write!(f, "Queued Best-Effort"),
            Self::AppliedLocalOnly => write!(f, "Applied Local Only"),
            Self::SnapshotRepairRequired => write!(f, "Snapshot Repair Required"),
            Self::FailedToQueue => write!(f, "Failed to Queue"),
            Self::Deferred => write!(f, "Deferred"),
        }
    }
}

/// The result of a typed admin or control-plane mutation.
///
/// This type is returned by mutating admin endpoints to provide structured,
/// auditable outcome information. It replaces ad-hoc `{"success": true}` responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AdminMutationResult<T = serde_json::Value> {
    /// The outcome status of the mutation.
    pub status: AdminMutationStatus,
    /// The target of the mutation (e.g., IP address, config section, mesh ID).
    pub target: T,
    /// Whether the local store was actually mutated.
    pub local_store_mutated: bool,
    /// Status of mesh propagation (if applicable).
    pub propagation: PropagationStatus,
    /// Optional distributed event ID for mesh-replicated mutations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Optional audit event ID linking to the audit log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_id: Option<String>,
    /// A safe operator-facing message describing the result.
    pub message: String,
}

impl<T> AdminMutationResult<T> {
    /// Create a successful applied result.
    pub fn applied(target: T, message: impl Into<String>) -> Self {
        Self {
            status: AdminMutationStatus::Applied,
            target,
            local_store_mutated: true,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: message.into(),
        }
    }

    /// Create an applied result with propagation queued.
    pub fn applied_with_propagation(
        target: T,
        propagation: PropagationStatus,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status: AdminMutationStatus::Applied,
            target,
            local_store_mutated: true,
            propagation,
            event_id: None,
            audit_id: None,
            message: message.into(),
        }
    }

    /// Create a no-op result (already in requested state).
    pub fn noop(target: T, message: impl Into<String>) -> Self {
        Self {
            status: AdminMutationStatus::NoOpAlreadyPresent,
            target,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: message.into(),
        }
    }

    /// Create a duplicate-ignored result.
    pub fn duplicate(target: T, message: impl Into<String>) -> Self {
        Self {
            status: AdminMutationStatus::DuplicateIgnored,
            target,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: message.into(),
        }
    }

    /// Create a stale-ignored result.
    pub fn stale(target: T, message: impl Into<String>) -> Self {
        Self {
            status: AdminMutationStatus::StaleIgnored,
            target,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: message.into(),
        }
    }

    /// Create an invalid-rejected result.
    pub fn invalid(target: T, message: impl Into<String>) -> Self {
        Self {
            status: AdminMutationStatus::InvalidRejected,
            target,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: message.into(),
        }
    }

    /// Create a failed result.
    pub fn failed(target: T, message: impl Into<String>) -> Self {
        Self {
            status: AdminMutationStatus::Failed,
            target,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: message.into(),
        }
    }

    /// Set the event ID.
    pub fn with_event_id(mut self, id: impl Into<String>) -> Self {
        self.event_id = Some(id.into());
        self
    }

    /// Set the audit ID.
    pub fn with_audit_id(mut self, id: impl Into<String>) -> Self {
        self.audit_id = Some(id.into());
        self
    }

    /// Set the propagation status.
    pub fn with_propagation(mut self, propagation: PropagationStatus) -> Self {
        self.propagation = propagation;
        self
    }
}

/// Target information for a block/unblock mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMutationTarget {
    /// The kind of target (IP or mesh ID).
    pub kind: String,
    /// The identifier value (IP address or mesh ID string).
    pub value: String,
    /// Optional site scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_scope: Option<String>,
}

/// A structured audit event for a mutating admin action.
///
/// Raw session tokens must never be stored in audit events.
/// If a session ID is included, it must be hashed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEvent {
    /// Unique audit event ID.
    pub audit_id: String,
    /// Unix timestamp of the event.
    pub timestamp: u64,
    /// The actor who performed the action.
    pub actor: AdminActor,
    /// The action performed (e.g., "block_ip", "unblock_ip", "config_update").
    pub action: String,
    /// The kind of target (e.g., "ip", "mesh_id", "config_section").
    pub target_kind: String,
    /// The specific target identifier.
    pub target_id: String,
    /// The state before the mutation (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_state: Option<serde_json::Value>,
    /// The requested state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_state: Option<serde_json::Value>,
    /// The resulting state after mutation (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resulting_state: Option<serde_json::Value>,
    /// The outcome status of the mutation.
    pub mutation_status: AdminMutationStatus,
    /// The propagation status.
    pub propagation_status: PropagationStatus,
    /// Optional distributed event ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

/// A sink for recording admin audit events.
///
/// Initial implementations may use tracing or in-memory buffers.
/// Durable audit storage is future work.
pub trait AdminAuditSink: Send + Sync {
    /// Record an audit event.
    fn record(&self, event: AdminAuditEvent);
}

/// A no-op audit sink that discards all events.
pub struct NoOpAuditSink;

impl AdminAuditSink for NoOpAuditSink {
    fn record(&self, _event: AdminAuditEvent) {}
}

/// A tracing-backed audit sink for development and logging.
pub struct TracingAuditSink;

impl AdminAuditSink for TracingAuditSink {
    fn record(&self, event: AdminAuditEvent) {
        tracing::info!(
            audit_id = %event.audit_id,
            actor = ?event.actor.authority,
            action = %event.action,
            target_kind = %event.target_kind,
            target_id = %event.target_id,
            status = ?event.mutation_status,
            propagation = ?event.propagation_status,
            "Admin audit event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_mutation_status_serializes_stably() {
        let statuses = [
            AdminMutationStatus::Applied,
            AdminMutationStatus::NoOpAlreadyPresent,
            AdminMutationStatus::NoOpAlreadyAbsent,
            AdminMutationStatus::DuplicateIgnored,
            AdminMutationStatus::StaleIgnored,
            AdminMutationStatus::InvalidRejected,
            AdminMutationStatus::UnauthorizedRejected,
            AdminMutationStatus::Failed,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).expect("serialize");
            let back: AdminMutationStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*status, back);
        }
    }

    #[test]
    fn propagation_status_serializes_stably() {
        let statuses = [
            PropagationStatus::NotApplicable,
            PropagationStatus::QueuedBestEffort,
            PropagationStatus::AppliedLocalOnly,
            PropagationStatus::SnapshotRepairRequired,
            PropagationStatus::FailedToQueue,
            PropagationStatus::Deferred,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).expect("serialize");
            let back: PropagationStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*status, back);
        }
    }

    #[test]
    fn legacy_authority_is_explicit() {
        let actor = AdminActor::new(AdminMutationAuthority::CompatibilityLegacy);
        assert_eq!(actor.authority, AdminMutationAuthority::CompatibilityLegacy);
        let json = serde_json::to_string(&actor).expect("serialize");
        assert!(json.contains("compatibility_legacy"));
    }

    #[test]
    fn audit_event_omits_raw_secret_tokens() {
        let event = AdminAuditEvent {
            audit_id: "test-audit-1".into(),
            timestamp: 1234567890,
            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
            action: "block_ip".into(),
            target_kind: "ip".into(),
            target_id: "203.0.113.10".into(),
            prior_state: None,
            requested_state: None,
            resulting_state: None,
            mutation_status: AdminMutationStatus::Applied,
            propagation_status: PropagationStatus::QueuedBestEffort,
            event_id: None,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(!json.contains("token"));
        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn mutation_result_applied() {
        let result = AdminMutationResult::applied("test", "done");
        assert_eq!(result.status, AdminMutationStatus::Applied);
        assert!(result.local_store_mutated);
    }

    #[test]
    fn mutation_result_noop() {
        let result = AdminMutationResult::noop("test", "already present");
        assert_eq!(result.status, AdminMutationStatus::NoOpAlreadyPresent);
        assert!(!result.local_store_mutated);
    }

    #[test]
    fn mutation_result_builder_chaining() {
        let result = AdminMutationResult::applied("test", "done")
            .with_event_id("evt-123")
            .with_audit_id("aud-456")
            .with_propagation(PropagationStatus::QueuedBestEffort);
        assert_eq!(result.event_id.as_deref(), Some("evt-123"));
        assert_eq!(result.audit_id.as_deref(), Some("aud-456"));
        assert_eq!(result.propagation, PropagationStatus::QueuedBestEffort);
    }
}
