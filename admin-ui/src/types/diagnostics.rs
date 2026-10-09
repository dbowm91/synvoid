//! Response types for the admin diagnostics surfaces.
//!
//! These back the Observability, Audit Log and Error Page pages. Every struct
//! mirrors a backend handler verbatim — the backend derives only
//! `Serialize` with **no** `rename_all`, so the JSON keys are the literal Rust
//! field names and nothing here may be renamed.
//!
//! One contract detail drives several `Option` choices below: the backend
//! structs carry no `skip_serializing_if`, so an `Option<T>` field is always
//! present in the JSON as `null` rather than being omitted. That makes these
//! `Option` types load-bearing — treating them as "absent" would render a blank
//! cell where the backend sent an explicit null.

use serde::{Deserialize, Serialize};

// ── GET /api/observability/security-summary ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityObservabilitySummary {
    pub runtime_tasks: RuntimeTaskSummary,
    pub blocklist_convergence: BlocklistConvergenceSummary,
    pub feature_profile: FeatureProfileSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTaskSummary {
    pub unified_server_registered: u64,
    pub unified_server_shutdown_count: u64,
    pub unified_server_critical_failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistConvergenceSummary {
    pub event_apply_applied: u64,
    pub event_apply_duplicate: u64,
    pub event_apply_stale: u64,
    pub snapshot_fallbacks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureProfileSummary {
    pub mesh_enabled: bool,
    pub dns_enabled: bool,
}

// ── GET /api/observability/tasks ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTasksDiagnostics {
    pub unified_server: UnifiedServerTaskStats,
    pub worker: WorkerTaskStats,
    pub supervisor: SupervisorTaskStats,
}

/// Field names here (`exit_completed`) deliberately differ from
/// `WorkerTaskStats` (`tasks_completed_cleanly`) and `SupervisorTaskStats`
/// (`completed`). The backend names are not uniform, so these stay three
/// separate structs rather than one shared row type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedServerTaskStats {
    pub registered: u64,
    pub exit_completed: u64,
    pub exit_failed: u64,
    pub exit_aborted: u64,
    pub exit_timed_out: u64,
    pub critical_failures: u64,
    pub shutdown_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerTaskStats {
    pub tasks_started: u64,
    pub tasks_completed_cleanly: u64,
    pub tasks_cancelled: u64,
    pub tasks_panicked: u64,
    pub tasks_aborted: u64,
    pub tasks_errored: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorTaskStats {
    pub registered: u64,
    pub completed: u64,
    pub failed: u64,
    pub aborted: u64,
    pub timed_out: u64,
}

// ── GET /api/observability/blocklist-health ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistHealthDiagnostics {
    pub event_apply_applied: u64,
    pub event_apply_duplicate: u64,
    pub event_apply_stale: u64,
    pub event_apply_invalid: u64,
    pub stale_replay_ignored: u64,
    pub cursor_update: u64,
    pub cursor_load: u64,
    pub snapshot_apply: u64,
    pub snapshot_fallback: u64,
    pub ordering_path_source_sequence: u64,
    pub ordering_path_timestamp: u64,
}

// ── GET /api/observability/plugins ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDiagnostics {
    pub loaded_count: usize,
    /// Always an array, never null — the handler returns `Vec::new()` when no
    /// plugin manager is wired.
    pub plugins: Vec<PluginInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub invocations: u64,
    pub errors: u64,
    /// The backend serialises a bare `f64` with no non-finite guard, so this
    /// must not be assumed renderable as a finite number.
    pub avg_duration_ms: f64,
}

// ── GET /api/observability/features ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesDiagnostics {
    pub mesh_enabled: bool,
    pub dns_enabled: bool,
    pub erased_pool_enabled: bool,
    pub swagger_ui_enabled: bool,
    pub socket_handoff_enabled: bool,
    pub icmp_filter_enabled: bool,
}

// ── GET /api/observability/threat-intel ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelDiagnostics {
    pub dht_publish_total: u64,
    pub dht_publish_failed: u64,
    pub dht_lookup_hits: u64,
    pub dht_lookup_misses: u64,
    pub dht_sync_total: u64,
    pub dht_sync_success: u64,
    pub dht_sync_failed: u64,
    pub dht_sync_added: u64,
    pub dht_sync_removed: u64,
    pub policy_shadow_actionable: u64,
    pub policy_shadow_advisory_only: u64,
    pub policy_shadow_not_actionable: u64,
    pub policy_shadow_deferred: u64,
    pub policy_shadow_not_configured: u64,
}

// ── GET /api/audit-logs ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogsResponse {
    /// Newest-first: the backend iterates its ring buffer in reverse.
    pub logs: Vec<AuditLog>,
    /// The **unfiltered** ring-buffer length, bounded at 10 000 entries.
    pub total: usize,
    /// Computed as `offset + limit < total` against that unfiltered total, so
    /// it over-reports while a filter is active. The UI recomputes paging from
    /// `logs.len()` instead of trusting this.
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: String,
    /// RFC 3339 with offset (`chrono::DateTime<Utc>`).
    pub timestamp: String,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub action: String,
    /// Formed as `"{target_kind}:{target_id}"` by the backend.
    pub target_resource: String,
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub details: Option<String>,
    pub success: bool,
}

// ── GET /api/error-pages and /api/error-pages/{code} ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPageResponse {
    pub code: u16,
    pub name: String,
    pub description: String,
    /// Always `null` in the current build — both `list()` and `from_code()`
    /// hardcode it, so the UI must not offer to render it.
    pub html_preview: Option<String>,
}

/// Request body for `PUT /api/error-pages/{code}`.
///
/// All fields are optional and unknown keys are ignored. Only `content` affects
/// the rendered page: `title` is recorded on the audit event and `message` is
/// never read at all (`#[allow(dead_code)]`).
///
/// Note the response is **not** an `ErrorPageResponse`: the handler returns an
/// `AdminMutationResult` (see `super::AdminMutationResult`), whose `target` is
/// the numeric status code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateErrorPageRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}
