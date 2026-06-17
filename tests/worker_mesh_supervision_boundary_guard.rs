//! Guardrails for worker mesh supervision integration (Iteration 82).
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
    assert!(content.contains("spawn_background"));
}

#[test]
fn mesh_coordinator_registered_in_registry() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("mesh_supervision_coordinator"));
    assert!(content.contains("spawn_background"));
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
