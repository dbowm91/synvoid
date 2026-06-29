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

// ── Phase 9 Diagnostics Endpoints ────────────────────────────────────────────

#[derive(Serialize)]
pub struct RuntimeTasksDiagnostics {
    pub unified_server: UnifiedServerTaskStats,
    pub worker: WorkerTaskStats,
    pub supervisor: SupervisorTaskStats,
}

#[derive(Serialize)]
pub struct UnifiedServerTaskStats {
    pub registered: u64,
    pub exit_completed: u64,
    pub exit_failed: u64,
    pub exit_aborted: u64,
    pub exit_timed_out: u64,
    pub critical_failures: u64,
    pub shutdown_count: u64,
}

#[derive(Serialize)]
pub struct WorkerTaskStats {
    pub tasks_started: u64,
    pub tasks_completed_cleanly: u64,
    pub tasks_cancelled: u64,
    pub tasks_panicked: u64,
    pub tasks_aborted: u64,
    pub tasks_errored: u64,
}

#[derive(Serialize)]
pub struct SupervisorTaskStats {
    pub registered: u64,
    pub completed: u64,
    pub failed: u64,
    pub aborted: u64,
    pub timed_out: u64,
}

/// GET /admin/observability/tasks
/// Returns runtime task registry state across all owners.
pub async fn runtime_tasks_diagnostics(
    State(_state): State<Arc<AdminState>>,
) -> Json<RuntimeTasksDiagnostics> {
    Json(RuntimeTasksDiagnostics {
        unified_server: UnifiedServerTaskStats {
            registered: synvoid_metrics::collection::get_runtime_task_registered(),
            exit_completed: synvoid_metrics::collection::get_runtime_task_exit_completed(),
            exit_failed: synvoid_metrics::collection::get_runtime_task_exit_failed(),
            exit_aborted: synvoid_metrics::collection::get_runtime_task_exit_aborted(),
            exit_timed_out: synvoid_metrics::collection::get_runtime_task_exit_timed_out(),
            critical_failures: synvoid_metrics::collection::get_runtime_task_critical_failures(),
            shutdown_count: synvoid_metrics::collection::get_runtime_shutdown_total(),
        },
        worker: WorkerTaskStats {
            tasks_started: synvoid_metrics::collection::get_worker_tasks_started(),
            tasks_completed_cleanly:
                synvoid_metrics::collection::get_worker_tasks_completed_cleanly(),
            tasks_cancelled: synvoid_metrics::collection::get_worker_tasks_cancelled(),
            tasks_panicked: synvoid_metrics::collection::get_worker_tasks_panicked(),
            tasks_aborted: synvoid_metrics::collection::get_worker_tasks_aborted(),
            tasks_errored: synvoid_metrics::collection::get_worker_tasks_errored(),
        },
        supervisor: SupervisorTaskStats {
            registered: synvoid_metrics::collection::get_supervisor_tasks_registered(),
            completed: synvoid_metrics::collection::get_supervisor_tasks_completed(),
            failed: synvoid_metrics::collection::get_supervisor_tasks_failed(),
            aborted: synvoid_metrics::collection::get_supervisor_tasks_aborted(),
            timed_out: synvoid_metrics::collection::get_supervisor_tasks_timed_out(),
        },
    })
}

#[derive(Serialize)]
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

/// GET /admin/observability/blocklist-health
/// Returns blocklist convergence health counters.
pub async fn blocklist_health_diagnostics(
    State(_state): State<Arc<AdminState>>,
) -> Json<BlocklistHealthDiagnostics> {
    Json(BlocklistHealthDiagnostics {
        event_apply_applied: synvoid_metrics::collection::get_blocklist_event_apply_applied(),
        event_apply_duplicate: synvoid_metrics::collection::get_blocklist_event_apply_duplicate(),
        event_apply_stale: synvoid_metrics::collection::get_blocklist_event_apply_stale(),
        event_apply_invalid: synvoid_metrics::collection::get_blocklist_event_apply_invalid(),
        stale_replay_ignored: synvoid_metrics::collection::get_blocklist_stale_replay_ignored_total(
        ),
        cursor_update: synvoid_metrics::collection::get_blocklist_cursor_update_total(),
        cursor_load: synvoid_metrics::collection::get_blocklist_cursor_load_total(),
        snapshot_apply: synvoid_metrics::collection::get_blocklist_snapshot_apply_total(),
        snapshot_fallback: synvoid_metrics::collection::get_blocklist_snapshot_fallback_total(),
        ordering_path_source_sequence:
            synvoid_metrics::collection::get_blocklist_ordering_path_source_sequence_total(),
        ordering_path_timestamp:
            synvoid_metrics::collection::get_blocklist_ordering_path_timestamp_total(),
    })
}

#[derive(Serialize)]
pub struct PluginDiagnostics {
    pub loaded_count: usize,
    pub plugins: Vec<PluginInfo>,
}

#[derive(Serialize)]
pub struct PluginInfo {
    pub name: String,
    pub invocations: u64,
    pub errors: u64,
    pub avg_duration_ms: f64,
}

/// GET /admin/observability/plugins
/// Returns plugin runtime state with per-plugin metrics.
pub async fn plugin_diagnostics(State(state): State<Arc<AdminState>>) -> Json<PluginDiagnostics> {
    let plugins = if let Some(ref pm) = state.process.plugin_manager {
        let wasm_mgr = pm.wasm_manager();
        let plugin_names = wasm_mgr.list_plugins();
        let all_metrics = synvoid_plugin_runtime::wasm_metrics::get_all_wasm_metrics();
        plugin_names
            .into_iter()
            .map(|name| {
                let metrics = all_metrics.get(&name);
                PluginInfo {
                    name,
                    invocations: metrics.map(|m| m.invocations).unwrap_or(0),
                    errors: metrics.map(|m| m.errors).unwrap_or(0),
                    avg_duration_ms: metrics.map(|m| m.avg_duration_ms()).unwrap_or(0.0),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    let loaded_count = plugins.len();
    Json(PluginDiagnostics {
        loaded_count,
        plugins,
    })
}

#[derive(Serialize)]
pub struct FeaturesDiagnostics {
    pub mesh_enabled: bool,
    pub dns_enabled: bool,
    pub erased_pool_enabled: bool,
    pub swagger_ui_enabled: bool,
    pub socket_handoff_enabled: bool,
    pub icmp_filter_enabled: bool,
}

/// GET /admin/observability/features
/// Returns active feature flags and compile-time profile.
pub async fn features_diagnostics(
    State(_state): State<Arc<AdminState>>,
) -> Json<FeaturesDiagnostics> {
    Json(FeaturesDiagnostics {
        mesh_enabled: cfg!(feature = "mesh"),
        dns_enabled: cfg!(feature = "dns"),
        erased_pool_enabled: cfg!(feature = "erased_pool"),
        swagger_ui_enabled: cfg!(feature = "swagger-ui"),
        socket_handoff_enabled: cfg!(feature = "socket-handoff"),
        icmp_filter_enabled: cfg!(feature = "icmp-filter"),
    })
}

#[derive(Serialize)]
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

/// GET /admin/observability/threat-intel
/// Returns threat-intel policy config and actionability summary.
pub async fn threat_intel_diagnostics(
    State(_state): State<Arc<AdminState>>,
) -> Json<ThreatIntelDiagnostics> {
    Json(ThreatIntelDiagnostics {
        dht_publish_total: synvoid_metrics::collection::get_threat_intel_dht_publish_total(),
        dht_publish_failed: synvoid_metrics::collection::get_threat_intel_dht_publish_failed(),
        dht_lookup_hits: synvoid_metrics::collection::get_threat_intel_dht_lookup_hits(),
        dht_lookup_misses: synvoid_metrics::collection::get_threat_intel_dht_lookup_misses(),
        dht_sync_total: synvoid_metrics::collection::get_threat_intel_dht_sync_total(),
        dht_sync_success: synvoid_metrics::collection::get_threat_intel_dht_sync_success(),
        dht_sync_failed: synvoid_metrics::collection::get_threat_intel_dht_sync_failed(),
        dht_sync_added: synvoid_metrics::collection::get_threat_intel_dht_sync_added(),
        dht_sync_removed: synvoid_metrics::collection::get_threat_intel_dht_sync_removed(),
        policy_shadow_actionable:
            synvoid_metrics::collection::get_threat_intel_policy_shadow_actionable(),
        policy_shadow_advisory_only:
            synvoid_metrics::collection::get_threat_intel_policy_shadow_advisory_only(),
        policy_shadow_not_actionable:
            synvoid_metrics::collection::get_threat_intel_policy_shadow_not_actionable(),
        policy_shadow_deferred:
            synvoid_metrics::collection::get_threat_intel_policy_shadow_deferred(),
        policy_shadow_not_configured:
            synvoid_metrics::collection::get_threat_intel_policy_shadow_not_configured(),
    })
}
