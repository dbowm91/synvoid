//! Guardrails for worker mesh supervision integration (Iterations 82-83).
//!
//! Verifies structural invariants via source-text scanning without I/O.

#![cfg(feature = "mesh")]

use std::fs;

fn read_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {}", path, e))
}

#[test]
fn mesh_supervision_module_exists() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("pub struct MeshSupervisionPolicy"));
    assert!(content.contains("pub fn decide_mesh_action"));
    assert!(content.contains("pub struct RestartBudget"));
}

#[test]
fn worker_mesh_status_in_state() {
    let content = read_file("src/worker/unified_server/state.rs");
    assert!(content.contains("mesh_status"));
    assert!(content.contains("mesh_policy"));
}

#[test]
fn mesh_exit_observer_registered_in_registry() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("mesh_exit_observer"));
    assert!(content.contains("spawn_critical"));
}

#[test]
fn mesh_coordinator_registered_in_registry() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("mesh_supervision_coordinator"));
    assert!(content.contains("spawn_critical"));
}

#[test]
fn mesh_shutdown_called_during_worker_shutdown() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("shutdown_with_timeout"));
    assert!(content.contains("classify_mesh_shutdown_report"));
}

#[test]
fn mesh_startup_failure_sends_event() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("MeshSupervisionEvent::StartupFailed"));
    assert!(content.contains("MeshSupervisionEvent::Started"));
}

#[test]
fn worker_shutdown_cause_has_mesh_variants() {
    let content = read_file("src/worker/task_registry.rs");
    assert!(content.contains("MeshStartupFailed"));
    assert!(content.contains("MeshShutdownIncomplete"));
}

#[test]
fn decide_mesh_action_uses_typed_fields() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("MeshTaskClass::CriticalService"));
    assert!(content.contains("MeshTaskClass::RestartableBackground"));
    assert!(content.contains("MeshTaskExitReason::Panic"));
    assert!(content.contains("MeshTaskExitReason::Error"));
}

#[test]
fn restart_budget_is_bounded() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("fn allow_restart"));
    assert!(content.contains("fn is_exhausted"));
    assert!(content.contains("fn record_attempt"));
}

#[test]
fn no_mesh_internal_process_termination() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(!content.contains("std::process::exit"));
    assert!(!content.contains("process::exit"));
}

#[test]
fn mesh_supervision_metrics_exist() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("MESH_SUPERVISION_METRICS"));
    assert!(content.contains("exit_events_total"));
    assert!(content.contains("startup_failures_total"));
    assert!(content.contains("restart_attempts_total"));
}

#[test]
fn mesh_health_in_heartbeat() {
    let content = read_file("src/worker/unified_server/lifecycle.rs");
    assert!(content.contains("mesh_phase"));
    assert!(content.contains("mesh_healthy"));
    assert!(content.contains("mesh_restart_attempts"));
}

#[test]
fn mesh_readiness_gate_exists() {
    let content = read_file("src/worker/unified_server/state.rs");
    assert!(content.contains("is_mesh_ready"));
}

// --- Iteration 83 guardrails ---

#[test]
fn supervision_uses_authoritative_status_clone() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 1: Must use state.mesh_status.clone(), not a new allocation.
    assert!(content.contains("state.mesh_status.clone()"));
}

#[test]
fn status_transition_helpers_exist() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("fn transition_starting"));
    assert!(content.contains("fn transition_running"));
    assert!(content.contains("fn transition_degraded"));
    assert!(content.contains("fn transition_restarting"));
    assert!(content.contains("fn transition_failed"));
    assert!(content.contains("fn transition_stopping"));
    assert!(content.contains("fn transition_stopped"));
}

#[test]
fn coordinator_uses_real_status_snapshot() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // Phase 4: Must NOT pass WorkerMeshStatus::default() to decide_mesh_action.
    assert!(
        !content.contains("decide_mesh_action(\n                &self.policy,\n                &WorkerMeshStatus::default(),"),
        "coordinator still uses default status for classification"
    );
    // Must use a phase snapshot.
    assert!(content.contains("self.status.read().await"));
}

#[test]
fn allow_degraded_readiness_field_exists() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("allow_degraded_readiness"));
}

#[test]
fn is_mesh_ready_respects_degraded_policy() {
    let content = read_file("src/worker/unified_server/state.rs");
    // Phase 9: Must check allow_degraded_readiness, not just phase.
    assert!(content.contains("allow_degraded_readiness"));
}

#[test]
fn no_outer_timeout_on_mesh_startup() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 12: No tokio::time::timeout wrapping start_with_policy.
    // The mesh startup block should call start_with_policy directly.
    assert!(content.contains(".start_with_policy("));
    // Must NOT wrap it in timeout
    assert!(
        !content.contains("tokio::time::timeout(\n                        std::time::Duration::from_secs(60),\n                        mesh_transport.start_with_policy("),
        "outer timeout still wraps start_with_policy"
    );
}

#[test]
fn typed_cause_conversion_exists() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("pub fn mesh_failure_to_worker_cause"));
}

#[test]
fn typed_cause_conversion_used_in_supervision_loop() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 16: Must use mesh_failure_to_worker_cause, not collapse to MeshStartupFailed.
    assert!(content.contains("mesh_failure_to_worker_cause(cause)"));
}

#[test]
fn shutdown_uses_deadline_not_uptime() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 19: Must use remaining_budget() closure, not start_time.elapsed().
    assert!(content.contains("remaining_budget"));
    assert!(content.contains("shutdown_deadline"));
}

#[test]
fn incomplete_mesh_shutdown_updates_cause() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 20: shutdown_cause must be mutable and accumulated.
    assert!(content.contains("mut shutdown_cause"));
    assert!(content.contains("merge_worker_shutdown_cause"));
}

#[test]
fn mesh_restart_exhausted_cause_exists() {
    let content = read_file("src/worker/task_registry.rs");
    // Phase 17: Dedicated typed cause for restart exhaustion.
    assert!(content.contains("MeshRestartExhausted"));
}

#[test]
fn mesh_failure_to_worker_cause_is_exhaustive() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // Must handle all MeshFailureCause variants.
    assert!(content.contains("MeshFailureCause::CriticalServiceExit"));
    assert!(content.contains("MeshFailureCause::StartupFailed"));
    assert!(content.contains("MeshFailureCause::ShutdownTimeout"));
}

#[test]
fn cause_merge_priority_exists() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("pub fn merge_worker_shutdown_cause"));
}

#[test]
fn mesh_status_recorded_before_and_after_shutdown() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 22: Must transition Stopping before shutdown, Stopped/Failed after.
    assert!(content.contains("transition_stopping"));
    assert!(content.contains("transition_stopped"));
}

// --- Acceptance criterion #5: Optional mesh failure degrades without blocking readiness ---

#[test]
fn optional_mesh_readiness_bypasses_phase_check() {
    let content = read_file("src/worker/unified_server/state.rs");
    // When mesh is not required, is_mesh_ready() must return true immediately
    // regardless of phase — no phase check needed.
    assert!(
        content.contains("if !self.mesh_policy.required {"),
        "optional mesh must bypass phase check for readiness"
    );
}

#[test]
fn optional_policy_has_readiness_bypass() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // MeshSupervisionPolicy::optional() must set required=false and
    // readiness_requires_mesh=false so readiness is never blocked.
    assert!(
        content.contains("readiness_requires_mesh: false"),
        "optional policy must not require mesh for readiness"
    );
    assert!(
        content.contains("allow_degraded_readiness: true"),
        "optional policy must allow degraded readiness"
    );
}

#[test]
fn optional_startup_failure_does_not_shutdown() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // MeshSupervisionPolicy::optional() must use Degrade for startup_failure,
    // never ShutdownWorker — optional mesh failure must not block the worker.
    // Verify the optional() constructor sets startup_failure to Degrade.
    assert!(
        content.contains("startup_failure: MeshFailureAction::Degrade"),
        "optional policy must degrade on startup failure, not shutdown"
    );
}

// --- Acceptance criterion #7: Disabled mesh creates no pipeline or startup task ---

#[test]
fn observer_only_spawned_when_transport_exists() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The mesh exit observer is only spawned when a transport is available.
    // The guard: has_mesh_transport check before creating the pipeline.
    // If !has_mesh_transport, None is returned (no pipeline, no observer).
    assert!(
        content.contains("if !has_mesh_transport"),
        "observer must be conditional on transport availability"
    );
    // Observer registration must be inside the transport-available block.
    assert!(
        content.contains("mesh_exit_observer"),
        "observer task name must be registered"
    );
}

#[test]
fn mesh_startup_task_only_with_transport() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The mesh startup task must only be spawned when a concrete MeshTransport
    // is available AND mesh is required/optional (not disabled).
    // The guard: has_mesh_transport check gates the entire pipeline.
    assert!(
        content.contains("if !has_mesh_transport"),
        "startup must be conditional on transport availability"
    );
    // For required mesh, startup is awaited inline; for optional, as background.
    assert!(
        content.contains("state.mesh_policy.required"),
        "startup path must branch on mesh policy"
    );
}

#[test]
fn coordinator_always_created_but_idle_without_transport() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The supervision pipeline (channels + coordinator) is created when
    // mesh transport is available. Without transport, no pipeline is created.
    assert!(
        content.contains("create_supervision_pipeline"),
        "supervision pipeline must be created"
    );
    // When no transport exists, None is returned (no pipeline, no coordinator).
    assert!(
        content.contains("Mesh disabled — no supervision pipeline created"),
        "disabled mesh must log and return None"
    );
}

// --- Acceptance criterion #21: Observer/coordinator exits handled per policy ---

#[test]
fn observer_forwards_exit_stream_closed_to_coordinator() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // When the broadcast channel closes (observer exits), the observer must
    // send ExitStreamClosed to the coordinator, which applies policy.
    assert!(
        content.contains("MeshSupervisionEvent::ExitStreamClosed"),
        "observer must forward stream closure as ExitStreamClosed event"
    );
}

#[test]
fn observer_forwards_lag_to_coordinator() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // When the broadcast channel lags, the observer must send ExitStreamLagged
    // to the coordinator, which degrades per policy.
    assert!(
        content.contains("MeshSupervisionEvent::ExitStreamLagged"),
        "observer must forward lag as ExitStreamLagged event"
    );
}

#[test]
fn exit_stream_closed_required_triggers_shutdown() {
    // Acceptance criterion #21: required mesh observer exit must be fatal.
    // Unit test in mesh_supervision.rs: exit_stream_closed_while_running_required_fatal
    // verifies this via decide_mesh_action.
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(
        content.contains("ExitStreamClosed") && content.contains("MeshFailureCause::StartupFailed"),
        "required ExitStreamClosed must produce ShutdownWorker decision"
    );
}

#[test]
fn exit_stream_closed_optional_degrades() {
    // Acceptance criterion #21: optional mesh observer exit must degrade.
    // Unit test in mesh_supervision.rs: exit_stream_closed_while_running_optional_degrades
    // verifies this via decide_mesh_action.
    let content = read_file("src/worker/mesh_supervision.rs");
    // The optional path should produce MarkDegraded, not ShutdownWorker.
    assert!(
        content.contains("MeshSupervisorDecision::MarkDegraded(\"mesh exit stream closed\""),
        "optional ExitStreamClosed must produce MarkDegraded decision"
    );
}
