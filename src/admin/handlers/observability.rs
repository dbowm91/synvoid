use crate::admin::AdminState;
use axum::extract::State;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct SecurityObservabilitySummary {
    pub runtime_tasks: RuntimeTaskSummary,
    pub blocklist_convergence: BlocklistConvergenceSummary,
    pub feature_profile: FeatureProfileSummary,
}

#[derive(Serialize)]
pub struct RuntimeTaskSummary {
    pub unified_server_registered: u64,
    pub unified_server_shutdown_count: u64,
    pub unified_server_critical_failures: u64,
}

#[derive(Serialize)]
pub struct BlocklistConvergenceSummary {
    pub event_apply_applied: u64,
    pub event_apply_duplicate: u64,
    pub event_apply_stale: u64,
    pub snapshot_fallbacks: u64,
}

#[derive(Serialize)]
pub struct FeatureProfileSummary {
    pub mesh_enabled: bool,
    pub dns_enabled: bool,
}

/// GET /admin/observability/security-summary
/// Returns a bounded summary of security-relevant observability state.
pub async fn security_observability_summary(
    State(_state): State<Arc<AdminState>>,
) -> Json<SecurityObservabilitySummary> {
    Json(SecurityObservabilitySummary {
        runtime_tasks: RuntimeTaskSummary {
            unified_server_registered: synvoid_metrics::collection::get_runtime_task_registered(),
            unified_server_shutdown_count: synvoid_metrics::collection::get_runtime_shutdown_total(
            ),
            unified_server_critical_failures:
                synvoid_metrics::collection::get_runtime_task_critical_failures(),
        },
        blocklist_convergence: BlocklistConvergenceSummary {
            event_apply_applied: synvoid_metrics::collection::get_blocklist_event_apply_applied(),
            event_apply_duplicate: synvoid_metrics::collection::get_blocklist_event_apply_duplicate(
            ),
            event_apply_stale: synvoid_metrics::collection::get_blocklist_event_apply_stale(),
            snapshot_fallbacks: synvoid_metrics::collection::get_blocklist_snapshot_fallback_total(
            ),
        },
        feature_profile: FeatureProfileSummary {
            mesh_enabled: cfg!(feature = "mesh"),
            dns_enabled: cfg!(feature = "dns"),
        },
    })
}
